import assert from 'node:assert/strict';
import os from 'node:os';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import {
  aggregate, combine, combinePartials, deal, dealingSize, encapsulate, evaluate, lagrange, partial, point, randomScalar,
  seatCommitment, validDealings, verifyPartial, type Dealing, type G1Point,
} from '../src/pvss.js';

// Phase 0: one member's work per epoch for the pairing re-sharing prototype, single-threaded.
const time = <T>(f: () => T): [T, number] => { const s = performance.now(); return [f(), performance.now() - s]; };
const fr = bls.fields.Fr;

/** An honest dealing built from known scalars (bench shortcut: same output distribution, fewer operations). */
function fastDeal(dealer: number, sigma: bigint, commitment: G1Point, next: bigint[], t: number): Dealing {
  const a = [0n, ...Array.from({ length: t - 1 }, () => randomScalar())];
  return {
    dealer, commitments: [commitment, ...a.slice(1).map(point.g1)],
    subshares: next.map((x, i) => {
      const r = randomScalar();
      return { r1: point.g1(r), r2: point.g2(r), b: point.g2(fr.create(sigma + evaluate(a, BigInt(i + 1)) + r * x)) };
    }),
  };
}

const rows = [];
for (const [C, t] of [[64, 16], [120, 44], [200, 72]] as const) {
  const F = Array.from({ length: t }, () => randomScalar());
  const sigma = Array.from({ length: C }, (_, j) => evaluate(F, BigInt(j + 1)));
  const prior = new Map(sigma.map((s, j) => [j + 1, point.g1(s)]));
  const next = Array.from({ length: C }, () => randomScalar());
  const epks = next.map(point.g2);

  const [first, dealMs] = time(() => deal(1, point.g2(sigma[0]!), prior.get(1)!, epks, t));
  const dealings = [first, ...sigma.slice(1).map((s, i) => fastDeal(i + 2, s, prior.get(i + 2)!, next, t))];
  const [valid, verifyMs] = time(() => validDealings(dealings, epks, t, { prior }));
  assert.equal(valid.length, C);
  const bad = dealings.map((d, j) => (j === C >> 1 ? { ...d, subshares: d.subshares.map((s, k) => (k === 0 ? { ...s, b: s.b.add(point.g2(1n)) } : s)) } : d));
  const [kept, verifyBadMs] = time(() => validDealings(bad, epks, t, { prior }));
  assert.equal(kept.length, C - 1);

  const chosen = valid.slice(0, t), weights = lagrange(chosen.map(d => d.dealer));
  const [held, combineMs] = time(() => ({ share: combine(1, next[0]!, chosen, weights), commitment: seatCommitment(aggregate(chosen, weights), 1) }));
  assert.ok(bls.fields.Fp12.eql(bls.pairing(point.g1(1n), held.share), bls.pairing(held.commitment, point.g2(1n))));

  const enc = encapsulate(point.g1(F[0]!), Buffer.from('label'));
  const [part, partialMs] = time(() => partial(held.share, held.commitment, enc.u));
  const [ok, verifyPartialMs] = time(() => verifyPartial(held.commitment, enc.u, part));
  assert.ok(ok);
  // Timing only: t copies of one partial cost the same as t distinct ones.
  const [, combinePartialsMs] = time(() => combinePartials(Array.from({ length: t }, (_, i) => ({ seat: i + 1, d: part.d }))));

  const bytes = dealingSize(C, t, false);
  rows.push({ C, t, dealMs, verifyMs, verifyBadMs, combineMs, partialMs, verifyPartialMs, combinePartialsMs, dealingKB: bytes / 1024, epochMB: (C * bytes) / 2 ** 20 });
  console.error(`C = ${C} done`);
}

const s = (ms: number) => (ms / 1000).toFixed(ms < 1000 ? 2 : 1);
console.log(`Node ${process.version}, ${os.cpus()[0]?.model}, single-threaded. Times in seconds.\n`);
console.log('| C | t | Deal (one member) | Verify all C dealings | Same, one cheater | Combine own share | Partial + proof | Verify partial | Recipient combine (t) | Dealing size | Epoch data |');
console.log('| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |');
for (const r of rows) {
  console.log(`| ${r.C} | ${r.t} | ${s(r.dealMs)} | ${s(r.verifyMs)} | ${s(r.verifyBadMs)} | ${s(r.combineMs)} | ${s(r.partialMs)} | ${s(r.verifyPartialMs)} | ${s(r.combinePartialsMs)} | ${r.dealingKB.toFixed(1)} KB | ${r.epochMB.toFixed(2)} MiB |`);
}
