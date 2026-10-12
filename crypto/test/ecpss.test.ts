import assert from 'node:assert/strict';
import { createPublicKey, randomBytes, randomInt, verify } from 'node:crypto';
import { test } from 'node:test';
import {
  capsulePartial, dealerGenesis, decodeMessage, decodeState, encodeMessage, encodeState, handover, handoverPlan, openCapsuleKey, publicKey,
  receive, reconstruct, sealCapsuleKey, seatKeys, shareCommitment, stateDigest, type Holder, type Message, type Public,
} from '../src/ecpss.js';
import {
  decodePartial, dealingSize, encodePartial, partial, point, proveG1, randomScalar, type Dealing, type G2Point,
} from '../src/pvss.js';

const t = 3;
/** Mock committee selection (the chain does the real one): n seats with one-time keys from fresh seeds. */
const committee = (n: number) => Array.from({ length: n }, (_, i) => ({ seat: i + 1, ...seatKeys(randomBytes(32)) }));
type Seats = ReturnType<typeof committee>;
const shuffle = <T>(xs: T[]) => xs.map(x => [Math.random(), x] as const).sort((a, b) => a[0] - b[0]).map(([, x]) => x);
const sharesOf = (holders: Holder[], bucket: bigint) => holders.map(h => ({ seat: h.seat, share: h.shares.get(bucket)! }));
const dealings = (m: Message) => [...m.reshares.values(), ...m.contributions.values(), ...(m.pack ? [m.pack] : []), ...(m.unpack ? [m.unpack] : [])];

/** Corrupt dealers: stay silent, lie to one seat, deal a different value, or forge a contribution's proof. */
function misbehave(m: Message): Message | undefined {
  const pick = randomInt(5);
  if (pick === 0) return undefined;
  const copy = (d: Dealing) => ({ ...d, commitments: [...d.commitments], subshares: [...d.subshares], proofs: [...d.proofs] });
  const out: Message = { reshares: new Map([...m.reshares].map(([b, d]) => [b, copy(d)])), contributions: new Map([...m.contributions].map(([b, d]) => [b, copy(d)])),
    ...(m.pack ? { pack: copy(m.pack) } : {}), ...(m.unpack ? { unpack: copy(m.unpack) } : {}) };
  for (const d of dealings(out)) {
    if (pick === 1) d.subshares[0] = { ...d.subshares[0]!, b: d.subshares[0]!.b.add(point.g2(1n)) };
    if (pick === 2 && !d.proofs.length) d.commitments[0] = point.g1(randomScalar());
    if (pick === 3 && d.proofs.length) d.proofs[0] = proveG1(randomScalar(), d.commitments.at(-1)!, Buffer.alloc(8));
  }
  return out; // pick 4: behaves honestly (its shares are still the adversary's).
}

function epoch(holders: Holder[], pub: Public, no: bigint, buckets: { live: bigint[]; create: bigint[] }, corrupt: Set<number>, next: Seats) {
  const keys = next.map(s => s.epk);
  const messages = new Map<number, Message>();
  for (const h of holders) {
    const m = handover(h, pub, no, buckets, keys, t);
    const sent = corrupt.has(h.seat) ? misbehave(m) : m;
    if (sent) messages.set(h.seat, sent);
  }
  return { messages, plan: handoverPlan(pub, buckets, t, keys.length), ...receive(messages, pub, no, buckets, keys, t, next) };
}

test('ten handovers with random committees and cheaters keep every live bucket, packing and unpacking in turn', () => {
  let seats = committee(7);
  const genesis = dealerGenesis(1n, seats.map(s => s.epk), t);
  let state = receive(genesis.messages, new Map(), 0n, { live: [], create: [1n] }, seats.map(s => s.epk), t, seats);
  const secrets = new Map<bigint, G2Point>([[1n, genesis.secret]]);
  const publicKeys = new Map([[1n, publicKey(state.pub.get(1n)!)]]);
  let live = [1n];
  const modes: string[] = [];

  for (let no = 1n; no <= 10n; no++) {
    const create = no === 2n ? [2n] : no === 5n ? [3n] : [];
    if (no === 7n) live = live.filter(b => b !== 1n); // Bucket 1 expires: committee 7 does not carry it on.
    // 7–9 seats with at most t − 1 corrupt: at least t + ℓ − 1 = 5 honest for every unpack (ℓ ≤ 3 here).
    const next = committee(7 + randomInt(3));
    const corrupt = new Set(shuffle(seats.map(s => s.seat)).slice(0, randomInt(t)));
    const result = epoch(state.holders, state.pub, no, { live, create }, corrupt, next);
    modes.push(result.plan.mode);
    assert.deepEqual(result.lost, []);
    for (const [b, recipe] of result.used) {
      for (const s of recipe.seats) assert.ok(result.messages.has(s), `bucket ${b} used a silent seat`);
    }
    // One dealing per holder for all live buckets once packing starts, instead of one per bucket.
    const expected = result.plan.mode === 'pack' ? 1 : result.plan.mode === 'unpack' ? 1 + create.length : result.plan.live.length + create.length;
    for (const h of state.holders) if (!corrupt.has(h.seat)) assert.equal(dealings(result.messages.get(h.seat)!).length, expected);
    if (no === 7n) {
      assert.ok(!result.pub.has(1n) && result.holders.every(h => !h.shares.has(1n)));
      secrets.delete(1n);
    }
    live = [...live, ...create];
    for (const b of create) {
      secrets.set(b, reconstruct(result.pub.get(b)!, sharesOf(result.holders, b)));
      publicKeys.set(b, publicKey(result.pub.get(b)!));
    }
    for (const b of live) {
      const s = result.pub.get(b)!, enough = shuffle(sharesOf(result.holders, b)).slice(0, s.poly.length);
      assert.ok(reconstruct(s, enough).equals(secrets.get(b)!), `bucket ${b} after committee ${no}`);
      assert.ok(publicKey(s).equals(publicKeys.get(b)!), 'the public key never changes');
      if (s.slot) assert.throws(() => reconstruct(s, enough.slice(1)), /Not enough/); // A pack needs t + ℓ − 1 shares.
    }
    seats = next;
    state = result;
  }
  assert.deepEqual(modes, ['plain', 'pack', 'unpack', 'pack', 'unpack', 'pack', 'unpack', 'pack', 'unpack', 'pack']);
  assert.deepEqual([...state.pub.keys()].sort(), [2n, 3n]);
});

test('capsule KEM: t verified partials open the key; a bad partial is skipped; a replayed u under another policy is refused', () => {
  const seats = committee(6), keys = seats.map(s => s.epk);
  const { messages } = dealerGenesis(9n, keys, t);
  const { pub, holders } = receive(messages, new Map(), 0n, { live: [], create: [9n] }, keys, t, seats);
  const s = pub.get(9n)!;
  const label = Buffer.from('policy-hash-A');
  const sealed = sealCapsuleKey(publicKey(s), label);
  const parts = holders.map(h => ({ seat: h.seat, p: capsulePartial(h.shares.get(9n)!, shareCommitment(s, h.seat), sealed.u, sealed.proof, label) }));
  parts[0] = { ...parts[0]!, p: parts[1]!.p }; // Seat 1 sends seat 2's partial.
  assert.deepEqual(openCapsuleKey(s, sealed.u, label, parts), sealed.key);
  assert.throws(() => capsulePartial(holders[0]!.shares.get(9n)!, shareCommitment(s, 1), sealed.u, sealed.proof, Buffer.from('policy-hash-B')), /not bound/);
  assert.throws(() => openCapsuleKey(s, sealed.u, label, parts.slice(0, t)), /Not enough/); // Only two valid among the first three.
});

test('capsule KEM on a packed state: t + ℓ − 1 partials open each bucket', () => {
  const seats = committee(5), keys = seats.map(s => s.epk), next = committee(6);
  const g = dealerGenesis(1n, keys, t);
  const first = receive(g.messages, new Map(), 0n, { live: [], create: [1n] }, keys, t, seats);
  const buckets = { live: [1n], create: [2n, 3n] };
  const messages = new Map(first.holders.map(h => [h.seat, handover(h, first.pub, 1n, buckets, next.map(s => s.epk), t)]));
  const { pub, holders } = receive(messages, first.pub, 1n, buckets, next.map(s => s.epk), t, next);
  assert.deepEqual([...pub.values()].map(s => [s.slot, s.poly.length]), [[1, t + 2], [2, t + 2], [3, t + 2]]);
  const state = encodeState(pub);
  assert.ok(decodeState(state, t).get(3n)!.poly.every((p, i) => p.equals(pub.get(3n)!.poly[i]!)));
  assert.equal(state.length, 2 + 4 + 3 * 10 + (t + 2) * 48); // One group: the packed polynomial is encoded once.
  const mixed = Buffer.concat([Buffer.from([0, 2]), state.subarray(2), encodeState(first.pub).subarray(2)]);
  assert.throws(() => decodeState(mixed, t), /shape/); // A pack plus an unpacked bucket: no handover produces that.
  assert.ok(reconstruct(pub.get(1n)!, sharesOf(holders, 1n)).equals(g.secret));
  for (const b of [1n, 2n, 3n]) {
    const s = pub.get(b)!, label = Buffer.from(`capsule-${b}`), sealed = sealCapsuleKey(publicKey(s), label);
    const parts = holders.map(h => ({ seat: h.seat, p: capsulePartial(h.shares.get(b)!, shareCommitment(s, h.seat), sealed.u, sealed.proof, label) }));
    assert.deepEqual(openCapsuleKey(s, sealed.u, label, shuffle(parts).slice(0, t + 2)), sealed.key);
    assert.throws(() => openCapsuleKey(s, sealed.u, label, parts.slice(0, t + 1)), /Not enough/);
  }
});

test('handover messages survive the wire; decoding is strict', () => {
  const seats = committee(5), next = committee(4), keys = next.map(s => s.epk);
  const { messages } = dealerGenesis(4n, seats.map(s => s.epk), t);
  const { pub, holders } = receive(messages, new Map(), 0n, { live: [], create: [4n] }, seats.map(s => s.epk), t, seats);
  for (const buckets of [{ live: [4n], create: [] }, { live: [4n], create: [5n] }]) { // A plain handover, then a pack.
    const decoded = new Map(holders.map(h => [h.seat, decodeMessage(encodeMessage(handover(h, pub, 1n, buckets, keys, t)), h.seat, 4, t)]));
    const out = receive(decoded, pub, 1n, buckets, keys, t);
    assert.deepEqual(out.lost, []);
    assert.ok(publicKey(out.pub.get(4n)!).equals(publicKey(pub.get(4n)!)));
  }

  const bytes = encodeMessage(handover(holders[0]!, pub, 1n, { live: [4n], create: [5n] }, keys, t));
  assert.equal(bytes[10], 4); // A single pack entry.
  assert.throws(() => decodeMessage(bytes.subarray(0, bytes.length - 1), 1, 4, t), /Truncated/);
  assert.throws(() => decodeMessage(Buffer.concat([bytes, Buffer.alloc(1)]), 1, 4, t), /Trailing/);
  assert.throws(() => decodeMessage(bytes, 1, 5, t)); // Wrong committee size: misaligned, so a length or point check fails.
  const kind = Buffer.from(bytes); kind[10] = 7;
  assert.throws(() => decodeMessage(kind, 1, 4, t), /Unknown entry kind/);
  const id = Buffer.from(bytes); id[9] = 1;
  assert.throws(() => decodeMessage(id, 1, 4, t), /Bad entry id/);
  const dup = Buffer.from(bytes); dup.writeUInt16BE(2, 0);
  const entry = bytes.subarray(2, 2 + 9 + 4 + dealingSize(4, t + 1, 1)); // The pack: t + 1 commitments, one proof.
  assert.throws(() => decodeMessage(Buffer.concat([dup.subarray(0, 2), entry, entry]), 1, 4, t), /Duplicate entry/);
});

test('messages carry sealed releases and the attested state; partials and states decode strictly', () => {
  const seats = committee(4), keys = seats.map(s => s.epk);
  const { messages } = dealerGenesis(7n, keys, t);
  const { pub, holders } = receive(messages, new Map(), 0n, { live: [], create: [7n] }, keys, t, seats);
  const state = encodeState(pub), sealed = randomBytes(752);
  const m = { ...handover(holders[0]!, pub, 1n, { live: [7n], create: [] }, keys, t), releases: new Map([[42n, sealed]]), state };
  const back = decodeMessage(encodeMessage(m), 1, 4, t);
  assert.deepEqual(back.releases.get(42n), sealed);
  assert.deepEqual(stateDigest(back.state!), stateDigest(state));
  assert.ok(decodeState(back.state!, t).get(7n)!.poly.every((p, l) => p.equals(pub.get(7n)!.poly[l]!)));
  assert.throws(() => decodeState(state.subarray(0, state.length - 1), t), /Truncated/);
  assert.throws(() => decodeState(state, t + 1), /shape/);
  const moved = Buffer.from(state); moved[13] = 8; // Bucket 7 renamed 8: the bucket number is attested too.
  assert.ok(decodeState(moved, t).has(8n));
  assert.notDeepEqual(stateDigest(moved), stateDigest(state));

  const u = point.g1(randomScalar()), p = partial(holders[0]!.shares.get(7n)!, shareCommitment(pub.get(7n)!, 1), u);
  const bytes = encodePartial(p);
  assert.ok(decodePartial(bytes).proof.z.equals(p.proof.z));
  const notGT = Buffer.from(bytes); notGT[3]! ^= 1; // Almost surely outside the order-r subgroup of Fp12*.
  assert.throws(() => decodePartial(notGT), /GT/);
  assert.throws(() => decodePartial(bytes.subarray(1)), /length/);
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
