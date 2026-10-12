import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import {
  aggregate, basis, combine, combinePartials, deal, decodeDealing, encapsulate, encodeDealing, lagrange, partial, point,
  proveG1, randomScalar, seatCommitment, validDealings, verifyG1, verifyPartial, type Dealing, type G1Point, type G2Point,
} from '../src/pvss.js';

const n = 7, t = 4;
const committee = () => Array.from({ length: n }, () => { const x = randomScalar(); return { x, epk: point.g2(x) }; });
type Held = { share: G2Point; commitment: G1Point };
const interpolate = (held: Held[], seats: number[]) => {
  const w = lagrange(seats);
  return seats.reduce((acc, seat, i) => acc.add(held[seat - 1]!.share.multiply(w[i]!)), point.g2(0n));
};
const reshare = (held: Held[], keys: ReturnType<typeof committee>, mutate?: (d: Dealing[]) => void) => {
  const dealings = held.map((h, i) => deal(i + 1, [h], keys.map(k => k.epk), t));
  mutate?.(dealings);
  const prior = new Map(held.map((h, i) => [i + 1, [h.commitment]]));
  const chosen = validDealings(dealings, keys.map(k => k.epk), t, { prior }).slice(0, t);
  return { held: next(keys, chosen, lagrange(chosen.map(d => d.dealer))), chosen };
};

const next = (keys: ReturnType<typeof committee>, chosen: Dealing[], weights: bigint[]) => {
  const poly = aggregate(chosen, weights);
  return keys.map((k, i) => ({ share: combine(i + 1, k.x, chosen, weights), commitment: seatCommitment(poly, i + 1) }));
};

// Genesis: five dealers each contribute a fresh z; the new key is the sum of the first t valid contributions.
function genesis() {
  const keys = committee();
  const z = Array.from({ length: 5 }, () => randomScalar());
  const dealings = z.map((zj, j) => deal(j + 1, [{ share: point.g2(zj), commitment: point.g1(zj), z: zj }], keys.map(k => k.epk), t));
  const chosen = validDealings(dealings, keys.map(k => k.epk), t, { contexts: [new Uint8Array()] }).slice(0, t);
  const s = z.slice(0, t).reduce((a, b) => a + b, 0n);
  return { held: next(keys, chosen, chosen.map(() => 1n)), S: point.g2(s), P: point.g1(s) };
}

test('a committee-generated key survives re-sharing; shares from different epochs do not combine', () => {
  const g = genesis();
  assert.ok(interpolate(g.held, [1, 2, 3, 4]).equals(g.S));
  assert.ok(interpolate(g.held, [7, 3, 5, 2]).equals(g.S));
  const next = reshare(g.held, committee()).held;
  assert.ok(interpolate(next, [2, 4, 6, 7]).equals(g.S));
  const third = reshare(next, committee()).held;
  assert.ok(interpolate(third, [1, 3, 5, 7]).equals(g.S));
  // Public commitments interpolate to the public key P = s·g1.
  const w = lagrange([1, 2, 3, 4]);
  assert.ok([1, 2, 3, 4].reduce((acc, seat, i) => acc.add(third[seat - 1]!.commitment.multiply(w[i]!)), point.g1(0n)).equals(g.P));
  // Seats 1–2 from one epoch with seats 3–4 from the next interpolate to garbage.
  assert.ok(!interpolate([next[0]!, next[1]!, third[2]!, third[3]!], [1, 2, 3, 4]).equals(g.S));
});

test('a tampered subshare, a wrong commitment or a missing proof drops only that dealing', () => {
  const g = genesis();
  const { held, chosen } = reshare(g.held, committee(), d => {
    d[0]!.subshares[2]!.b = d[0]!.subshares[2]!.b.add(point.g2(1n)); // Dealer 1 lies to seat 3.
    d[1]!.commitments[0] = point.g1(randomScalar()); // Dealer 2 re-shares something other than its share.
  });
  assert.deepEqual(chosen.map(d => d.dealer), [3, 4, 5, 6]);
  assert.ok(interpolate(held, [1, 2, 3, 4]).equals(g.S));

  const keys = committee(), z = randomScalar();
  const contribution = deal(1, [{ share: point.g2(z), commitment: point.g1(z), z, context: Buffer.from('ctx') }], keys.map(k => k.epk), t);
  const prepared = keys.map(k => k.epk), ctx = { contexts: [Buffer.from('ctx')] };
  assert.equal(validDealings([{ ...contribution, proofs: [proveG1(randomScalar(), point.g1(z), Buffer.alloc(4))] }], prepared, t, ctx).length, 0);
  assert.equal(validDealings([{ ...contribution, proofs: [] }], prepared, t, ctx).length, 0);
  assert.equal(validDealings([contribution, contribution], prepared, t, ctx).length, 1); // Duplicate dealer.
  assert.equal(validDealings([contribution], prepared, t, { contexts: [Buffer.from('other')] }).length, 0); // Proof bound to its context.

  // Encoding round-trips; decoding rejects a wrong length and a point off the subgroup or at infinity.
  const bytes = encodeDealing(contribution);
  assert.equal(validDealings([decodeDealing(bytes, 1, n, t, 1)], prepared, t, ctx).length, 1);
  assert.throws(() => decodeDealing(bytes.subarray(1), 1, n, t, 1), /length/);
  const zero = Buffer.from(bytes); zero.set(point.g1(0n).toBytes(), 0);
  assert.throws(() => decodeDealing(zero, 1, n, t, 1), /Identity/);
  const junk = Buffer.from(bytes); junk[5]! ^= 0xff;
  assert.throws(() => decodeDealing(junk, 1, n, t, 1));
});

test('capsule KEM: verified partials of t holders give the sender key; bad partials and replayed capsules fail', () => {
  const g = genesis();
  const held = reshare(g.held, committee()).held;
  const label = Buffer.from('policy-hash-A'), enc = encapsulate(g.P, label);
  assert.ok(verifyG1(enc.u, enc.proof, label));
  assert.ok(!verifyG1(enc.u, enc.proof, Buffer.from('policy-hash-B'))); // Someone else's capsule U under a new policy.

  const parts = [2, 3, 5, 7].map(seat => ({ seat, ...partial(held[seat - 1]!.share, held[seat - 1]!.commitment, enc.u) }));
  assert.ok(parts.every(p => verifyPartial(held[p.seat - 1]!.commitment, enc.u, p)));
  assert.ok(bls.fields.Fp12.eql(combinePartials(parts), enc.key));

  const forged = { ...parts[0]!, d: bls.fields.Fp12.mul(parts[0]!.d, parts[0]!.d) };
  assert.ok(!verifyPartial(held[1]!.commitment, enc.u, forged));
  assert.ok(!verifyPartial(held[2]!.commitment, enc.u, parts[0]!)); // Seat 2's partial checked against seat 3's commitment.
});

test('evaluation form: one dealing packs several shares, each recoverable at its own point', () => {
  // Lagrange weights over −1..−m reproduce a polynomial's values and sum to 1.
  const m = 5, values = Array.from({ length: m }, () => randomScalar()), k = 9n;
  const at = (x: bigint) => lagrange([-1, -2, -3, -4, -5], x).reduce((s, w, i) => (s + w * values[i]!) % bls.fields.Fr.ORDER, 0n);
  assert.equal(basis('evaluations', m, k).reduce((s, w, i) => (s + w * values[i]!) % bls.fields.Fr.ORDER, 0n), at(k));
  assert.deepEqual(basis('evaluations', m, -3n), [0n, 0n, 1n, 0n, 0n]);

  // A dealer packs shares of three secrets plus one contribution, with t − 1 random values: t + 3 values in all.
  const g = [genesis(), genesis(), genesis()], keys = committee(), epks = keys.map(k => k.epk), size = t + 3, z = randomScalar();
  const heads = [...g.map(x => x.held[0]!), { share: point.g2(z), commitment: point.g1(z), z, context: Buffer.from('new') }];
  const packed = deal(1, heads, epks, size, 'evaluations');
  assert.ok(packed.expected!.every((e, i) => e.equals(seatCommitment(packed.commitments, i + 1, 'evaluations'))));
  const o = { form: 'evaluations' as const, prior: new Map([[1, g.map(x => x.held[0]!.commitment)]]), contexts: [Buffer.from('new')] };
  assert.equal(validDealings([packed], epks, size, o).length, 1);
  assert.equal(validDealings([packed], epks, size, { ...o, form: 'coefficients' }).length, 0); // Read in the wrong form.
  assert.equal(validDealings([packed], epks, size, { ...o, prior: new Map([[1, [g[1]!.held[0]!.commitment, ...o.prior.get(1)!.slice(1)]]]) }).length, 0);
  const lied = { ...packed, subshares: packed.subshares.map((s, i) => (i === 4 ? { ...s, b: s.b.add(point.g2(1n)) } : s)) };
  assert.equal(validDealings([lied], epks, size, o).length, 0);

  // Any t + 3 recipients interpolate each packed value at its point: the dealer's share of each secret, and z·g2.
  const shares = keys.map((key, i) => combine(i + 1, key.x, [packed], [1n]));
  const seats = [2, 3, 4, 5, 6, 7, 1];
  heads.forEach((h, j) => {
    const w = lagrange(seats, -BigInt(j + 1));
    assert.ok(seats.reduce((acc, s, i) => acc.add(shares[s - 1]!.multiply(w[i]!)), point.g2(0n)).equals(h.share));
  });
});
