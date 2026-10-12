import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import os from 'node:os';
import {
  dealerGenesis, decodeMessage, encodeMessage, handover, handoverPlan, receive, seatKeys, shareCommitment, validSeats, type Holder, type Message, type Public,
} from '../src/ecpss.js';
import { deal, dealingSize, point, validDealings, type Dealing } from '../src/pvss.js';

// Packed epochs (docs/design.md): one member's handover and everyone's verification for one epoch, plain
// (one dealing per bucket) against a pack and an unpack, single-threaded. L live buckets and one created per epoch.
const C = Number(process.env.C ?? 64), t = Number(process.env.T ?? 16), L = 4;
const time = <T>(f: () => T): [T, number] => { const s = performance.now(); return [f(), performance.now() - s]; };
const committee = () => Array.from({ length: C }, (_, i) => ({ seat: i + 1, ...seatKeys(randomBytes(32)) }));
const live = Array.from({ length: L }, (_, i) => BigInt(i + 1));

// Committee 1 holds L buckets unpacked, each from an honest dealer.
const c1 = committee(), epks1 = c1.map(s => s.epk);
const pub1: Public = new Map(), holders1: Holder[] = c1.map(s => ({ seat: s.seat, x: s.x, shares: new Map() }));
for (const b of live) {
  const r = receive(dealerGenesis(b, epks1, t).messages, new Map(), 0n, { live: [], create: [b] }, epks1, t, c1);
  pub1.set(b, r.pub.get(b)!);
  r.holders.forEach((h, i) => holders1[i]!.shares.set(b, h.shares.get(b)!));
}
console.error('state ready');

const c2 = committee(), epks2 = c2.map(s => s.epk), c3 = committee(), epks3 = c3.map(s => s.epk);
const rows: { mode: string; dealings: number; dealMs: number; bytes: number; verifyMs: number }[] = [];
const decodeAll = (raw: Map<number, Buffer>, n: number) => new Map([...raw].map(([s, bytes]) => [s, decodeMessage(bytes, s, n, t)]));

// Plain: what committee 1 would post without packing (ℓ re-sharings and a contribution each), verified per bucket.
{
  const plain = (h: Holder): Message => ({
    reshares: new Map(live.map(b => [b, deal(h.seat, [{ share: h.shares.get(b)!, commitment: shareCommitment(pub1.get(b)!, h.seat) }], epks2, t)])),
    contributions: new Map([[9n, deal(h.seat, [{ share: point.g2(1n), commitment: point.g1(1n), z: 1n, context: Buffer.from('bench') }], epks2, t)]]),
  });
  const [, dealMs] = time(() => plain(holders1[0]!));
  const raw = new Map(holders1.map(h => [h.seat, encodeMessage(plain(h))]));
  const [, verifyMs] = time(() => {
    const m = decodeAll(raw, C), of = (get: (x: Message) => Dealing | undefined) => [...m.values()].map(get).filter((d): d is Dealing => !!d);
    for (const b of live) {
      const prior = new Map(c1.map(s => [s.seat, [shareCommitment(pub1.get(b)!, s.seat)]]));
      assert.equal(validDealings(of(x => x.reshares.get(b)), epks2, t, { prior }).length, C);
    }
    validDealings(of(x => x.contributions.get(9n)), epks2, t, { contexts: [Buffer.from('bench')] });
  });
  rows.push({ mode: 'plain', dealings: L + 1, dealMs, bytes: raw.get(1)!.length, verifyMs });
  console.error('plain done');
}

// Pack (committee 1 to 2), then unpack (committee 2 to 3), through ecpss.
const buckets1 = { live, create: [BigInt(L + 1)] }, buckets2 = { live: [...live, BigInt(L + 1)], create: [BigInt(L + 2)] };
assert.equal(handoverPlan(pub1, buckets1, t, C).mode, 'pack');
const [, packMs] = time(() => handover(holders1[0]!, pub1, 1n, buckets1, epks2, t));
const raw1 = new Map(holders1.map(h => [h.seat, encodeMessage(handover(h, pub1, 1n, buckets1, epks2, t))]));
const [valid1, verify1] = time(() => validSeats(decodeAll(raw1, C), pub1, 1n, buckets1, epks2, t));
assert.equal(valid1.get(1n)!.length, C);
rows.push({ mode: 'pack', dealings: 1, dealMs: packMs, bytes: raw1.get(1)!.length, verifyMs: verify1 });
console.error('pack done');

const second = receive(decodeAll(raw1, C), pub1, 1n, buckets1, epks2, t, c2);
assert.equal(handoverPlan(second.pub, buckets2, t, C).mode, 'unpack');
const [, unpackMs] = time(() => handover(second.holders[0]!, second.pub, 2n, buckets2, epks3, t));
const raw2 = new Map(second.holders.map(h => [h.seat, encodeMessage(handover(h, second.pub, 2n, buckets2, epks3, t))]));
const [valid2, verify2] = time(() => validSeats(decodeAll(raw2, C), second.pub, 2n, buckets2, epks3, t));
assert.equal(valid2.get(1n)!.length, C);
rows.push({ mode: 'unpack', dealings: 2, dealMs: unpackMs, bytes: raw2.get(1)!.length, verifyMs: verify2 });

const s = (ms: number) => (ms / 1000).toFixed(1);
console.log(`Node ${process.version}, ${os.cpus()[0]?.model}. C = ${C}, t = ${t}, ${L} live buckets + 1 created per epoch; single-threaded seconds.\n`);
console.log('| Handover | Dealings per member | Deal (one member) | Message | Decode + verify all C |');
console.log('| --- | --- | --- | --- | --- |');
for (const r of rows) console.log(`| ${r.mode} | ${r.dealings} | ${s(r.dealMs)} | ${(r.bytes / 1024).toFixed(0)} KB | ${s(r.verifyMs)} |`);

// At production sizes, message sizes follow from the wire format.
console.log('\nMessage size per member at production sizes (state copy excluded):\n');
console.log('| C | t | Live + new | Plain | Pack | Unpack | Saving (two epochs) |');
console.log('| --- | --- | --- | --- | --- | --- | --- |');
for (const [n, k, l] of [[210, 79, 4], [216, 80, 4], [220, 81, 5], [226, 82, 8]] as const) {
  const plain = l * dealingSize(n, k, 0) + dealingSize(n, k, 1);
  const pack = dealingSize(n, k + l, 1), unpack = dealingSize(n, k, 0) + dealingSize(n, k, 1);
  console.log(`| ${n} | ${k} | ${l} + 1 | ${(plain / 1024).toFixed(0)} KB | ${(pack / 1024).toFixed(0)} KB | ${(unpack / 1024).toFixed(0)} KB | ${Math.round(100 * (1 - (pack + unpack) / (2 * plain)))}% |`);
}
