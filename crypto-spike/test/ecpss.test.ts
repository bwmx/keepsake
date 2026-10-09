import assert from 'node:assert/strict';
import { createPublicKey, randomBytes, randomInt, verify } from 'node:crypto';
import { test } from 'node:test';
import {
  capsulePartial, dealerGenesis, decodeMessage, encodeMessage, handover, openCapsuleKey, receive, reconstruct,
  sealCapsuleKey, seatKeys, type Holder, type Message, type Public,
} from '../src/ecpss.js';
import { dealingSize, lagrange, point, proveG1, randomScalar, seatCommitment, type G2Point } from '../src/pvss.js';

const t = 3;
/** Mock committee selection (the chain does the real one): n seats with one-time keys from fresh seeds. */
const committee = (n: number) => Array.from({ length: n }, (_, i) => ({ seat: i + 1, ...seatKeys(randomBytes(32)) }));
type Seats = ReturnType<typeof committee>;
const shuffle = <T>(xs: T[]) => xs.map(x => [Math.random(), x] as const).sort((a, b) => a[0] - b[0]).map(([, x]) => x);
const interpolate = (holders: Holder[], bucket: bigint, seats: number[]) => {
  const w = lagrange(seats);
  return seats.reduce((acc, s, i) => acc.add(holders.find(h => h.seat === s)!.shares.get(bucket)!.multiply(w[i]!)), point.g2(0n));
};

/** Corrupt dealers: stay silent, lie to one seat, re-share a different value, or forge a contribution's proof. */
function misbehave(m: Message): Message | undefined {
  const pick = randomInt(5);
  if (pick === 0) return undefined;
  const reshares = new Map([...m.reshares].map(([b, d]) => [b, { ...d, commitments: [...d.commitments], subshares: [...d.subshares] }]));
  const contributions = new Map([...m.contributions].map(([b, d]) => [b, { ...d }]));
  for (const d of reshares.values()) {
    if (pick === 1) d.subshares[0] = { ...d.subshares[0]!, b: d.subshares[0]!.b.add(point.g2(1n)) };
    if (pick === 2) d.commitments[0] = point.g1(randomScalar());
  }
  for (const d of contributions.values()) if (pick === 3) d.pok = proveG1(randomScalar(), d.commitments[0]!, Buffer.alloc(8));
  return { reshares, contributions }; // pick 4: behaves honestly (its shares are still the adversary's).
}

function epoch(holders: Holder[], pub: Public, no: bigint, buckets: { live: bigint[]; create: bigint[] }, corrupt: Set<number>, next: Seats) {
  const keys = next.map(s => s.epk);
  const messages = new Map<number, Message>();
  for (const h of holders) {
    const m = handover(h, pub, no, buckets, keys, t);
    const sent = corrupt.has(h.seat) ? misbehave(m) : m;
    if (sent) messages.set(h.seat, sent);
  }
  return { messages, ...receive(messages, pub, no, buckets, keys, t, next) };
}

test('ten handovers with random committees and cheaters keep every live bucket; created keys are stable; dropped ones vanish', () => {
  let seats = committee(6);
  const genesis = dealerGenesis(1n, seats.map(s => s.epk), t);
  let state = receive(genesis.messages, new Map(), 0n, { live: [], create: [1n] }, seats.map(s => s.epk), t, seats);
  const secrets = new Map<bigint, G2Point>([[1n, genesis.secret]]);
  const publicKeys = new Map([[1n, state.pub.get(1n)![0]!]]);
  let live = [1n];
  let previous: Holder[] | undefined;

  for (let no = 1n; no <= 10n; no++) {
    const create = no === 2n ? [2n] : no === 5n ? [3n] : [];
    if (no === 7n) live = live.filter(b => b !== 1n); // Bucket 1 expires: committee 7 does not re-share it.
    const next = committee(5 + randomInt(4)); // 5–8 seats; at most t − 1 corrupt, so at least t honest.
    const corrupt = new Set(shuffle(seats.map(s => s.seat)).slice(0, randomInt(t)));
    const result = epoch(state.holders, state.pub, no, { live, create }, corrupt, next);
    assert.deepEqual(result.lost, []);
    for (const [b, used] of result.used) {
      for (const s of used) assert.ok(!corrupt.has(s) || result.messages.get(s) !== undefined, `bucket ${b} used a silent seat`);
    }
    if (no === 7n) {
      assert.ok([...result.messages.values()].every(m => !m.reshares.has(1n)), 'no dealing of bucket 1 ever reaches the chain again');
      assert.ok(!result.pub.has(1n) && result.holders.every(h => !h.shares.has(1n)));
      secrets.delete(1n);
    }
    live = [...live, ...create];
    for (const b of create) {
      secrets.set(b, interpolate(result.holders, b, [1, 2, 3]));
      publicKeys.set(b, result.pub.get(b)![0]!);
    }
    for (const b of live) {
      const seatsUsed = shuffle(next.map(s => s.seat)).slice(0, t);
      assert.ok(interpolate(result.holders, b, seatsUsed).equals(secrets.get(b)!), `bucket ${b} after committee ${no}`);
      assert.ok(result.pub.get(b)![0]!.equals(publicKeys.get(b)!), 'the public key never changes');
      assert.ok(reconstruct(result.pub.get(b)!, result.holders.map(h => ({ seat: h.seat, share: h.shares.get(b)! })), t).equals(secrets.get(b)!));
    }
    // Shares from two different committees do not combine.
    if (previous?.[0]?.shares.has(2n)) assert.ok(!interpolate([previous[0]!, ...result.holders.slice(1, t)].map((h, i) => ({ ...h, seat: i + 1 })), 2n, [1, 2, 3]).equals(secrets.get(2n)!));
    previous = result.holders;
    seats = next;
    state = result;
  }
  assert.deepEqual([...state.pub.keys()].sort(), [2n, 3n]);
});

test('capsule KEM: t verified partials open the key; a bad partial is skipped; a replayed u under another policy is refused', () => {
  const seats = committee(6), keys = seats.map(s => s.epk);
  const { messages } = dealerGenesis(9n, keys, t);
  const { pub, holders } = receive(messages, new Map(), 0n, { live: [], create: [9n] }, keys, t, seats);
  const poly = pub.get(9n)!;
  const label = Buffer.from('policy-hash-A');
  const sealed = sealCapsuleKey(poly[0]!, label);
  const parts = holders.map(h => ({ seat: h.seat, p: capsulePartial(h.shares.get(9n)!, seatCommitment(poly, h.seat), sealed.u, sealed.proof, label) }));
  parts[0] = { ...parts[0]!, p: parts[1]!.p }; // Seat 1 sends seat 2's partial.
  assert.deepEqual(openCapsuleKey(poly, sealed.u, label, parts, t), sealed.key);
  assert.throws(() => capsulePartial(holders[0]!.shares.get(9n)!, seatCommitment(poly, 1), sealed.u, sealed.proof, Buffer.from('policy-hash-B')), /not bound/);
  assert.throws(() => openCapsuleKey(poly, sealed.u, label, parts.slice(0, t), t), /Not enough/); // Only two valid among the first three.
});

test('handover messages survive the wire; decoding is strict', () => {
  const seats = committee(5), next = committee(4), keys = next.map(s => s.epk);
  const { messages } = dealerGenesis(4n, seats.map(s => s.epk), t);
  const { pub, holders } = receive(messages, new Map(), 0n, { live: [], create: [4n] }, seats.map(s => s.epk), t, seats);
  const m = handover(holders[0]!, pub, 1n, { live: [4n], create: [5n] }, keys, t);
  const bytes = encodeMessage(m);
  const decoded = new Map(holders.map(h => [h.seat, decodeMessage(encodeMessage(handover(h, pub, 1n, { live: [4n], create: [5n] }, keys, t)), h.seat, 4, t)]));
  const out = receive(decoded, pub, 1n, { live: [4n], create: [5n] }, keys, t);
  assert.deepEqual(out.lost, []);
  assert.ok(out.pub.get(4n)![0]!.equals(pub.get(4n)![0]!));

  assert.throws(() => decodeMessage(bytes.subarray(0, bytes.length - 1), 1, 4, t), /Truncated/);
  assert.throws(() => decodeMessage(Buffer.concat([bytes, Buffer.alloc(1)]), 1, 4, t), /Trailing/);
  assert.throws(() => decodeMessage(bytes, 1, 5, t)); // Wrong committee size: misaligned, so a length or point check fails.
  const kind = Buffer.from(bytes); kind[10] = 7;
  assert.throws(() => decodeMessage(kind, 1, 4, t), /Unknown entry kind/);
  const dup = Buffer.from(bytes); dup.writeUInt16BE(2, 0);
  const entry = bytes.subarray(2, 2 + 9 + dealingSize(4, t, false)); // The re-share entry.
  assert.throws(() => decodeMessage(Buffer.concat([dup.subarray(0, 2), entry, entry]), 1, 4, t), /Duplicate entry/);
});

test('seat keys are deterministic per seed, distinct across seeds, and sign', () => {
  const seed = randomBytes(32), a = seatKeys(seed), b = seatKeys(seed), c = seatKeys(randomBytes(32));
  assert.equal(a.x, b.x);
  assert.ok(a.epk.equals(b.epk) && !a.epk.equals(c.epk));
  assert.deepEqual(a.sigKey, b.sigKey);
  const message = Buffer.from('claim');
  const spki = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), a.sigKey]), format: 'der', type: 'spki' });
  assert.ok(verify(null, message, spki, a.sign(message)));
  assert.throws(() => seatKeys(randomBytes(31)), /32-byte/);
});
