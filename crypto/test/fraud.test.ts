import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { dealerGenesis, decodeMessage, encodeMessage, handover, receive, seatKeys, validSeats, type Message } from '../src/ecpss.js';
import { avmG1, avmG2, dealingsRoot, findBadDealing, fromAvmG1, fromAvmG2, merklePath, merkleRoot, messageLeaves, subshareValid } from '../src/fraud.js';
import { point, seatCommitment } from '../src/pvss.js';

const sha = (...parts: Uint8Array[]) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
/** What the contract does with a proof's path: walk it with the leaf index's bits. */
const walk = (leaf: Buffer, index: number, path: Buffer) => {
  let node = leaf;
  for (let d = 0; d < path.length / 32; d++) {
    const sibling = path.subarray(d * 32, (d + 1) * 32);
    node = (index >> d) & 1 ? sha(sibling, node) : sha(node, sibling);
  }
  return node;
};
const u64 = (n: bigint | number) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };

test('fraud proofs: opcode encodings round-trip, Merkle paths verify, a bad subshare is found and proven, honest dealings are not', () => {
  const p1 = point.g1(123n), p2 = point.g2(456n);
  assert.ok(fromAvmG1(avmG1(p1)).equals(p1) && fromAvmG2(avmG2(p2)).equals(p2));
  const leaves = Array.from({ length: 5 }, () => randomBytes(32) as Buffer), root = merkleRoot(leaves);
  leaves.forEach((l, i) => assert.ok(walk(l, i, Buffer.concat(merklePath(leaves, i))).equals(root)));

  // Committee 1 holds bucket 1; each holder packs it with a contribution to bucket 2 for committee 2 (one dealing).
  const t = 3, committee = (n: number) => Array.from({ length: n }, (_, i) => ({ seat: i + 1, ...seatKeys(randomBytes(32)) }));
  const seats = committee(5), next = committee(4), epks = next.map(s => s.epk), encoded = epks.map(avmG2);
  const state = receive(dealerGenesis(1n, seats.map(s => s.epk), t).messages, new Map(), 0n, { live: [], create: [1n] }, seats.map(s => s.epk), t, seats);
  const buckets = { live: [1n], create: [2n] };
  const honest = handover(state.holders[0]!, state.pub, 1n, buckets, epks, t), honestRoot = dealingsRoot(honest, encoded);
  assert.ok(honest.pack && messageLeaves(honest, encoded).length === 4);
  assert.equal(findBadDealing(honest, epks, honestRoot), undefined);
  // The dealer's root (from its own record of each E) is the one anyone rebuilds from the posted message.
  assert.ok(dealingsRoot(decodeMessage(encodeMessage(honest), 1, 4, t), encoded).equals(honestRoot));

  // Holder 2 lies to recipient 3, yet commits to a root over what it posted.
  const cheat = handover(state.holders[1]!, state.pub, 1n, buckets, epks, t);
  const d = cheat.pack!;
  d.subshares[2] = { ...d.subshares[2]!, b: d.subshares[2]!.b.add(point.g2(1n)) };
  const E = (k: number) => seatCommitment(d.commitments, k, 'evaluations');
  assert.ok(!subshareValid(d.subshares[2]!, E(3), epks[2]!) && subshareValid(d.subshares[1]!, E(2), epks[1]!));
  const cheatRoot = dealingsRoot(cheat, encoded), proof = findBadDealing(cheat, epks, cheatRoot)!;
  assert.deepEqual([proof.id, proof.kind, proof.k, proof.index], [0n, 4, 3, 2]);
  assert.ok(proof.expected.equals(avmG1(E(3))));
  const leaf = sha(Buffer.from('ecpss/leaf/v2'), u64(0), Buffer.from([4]), u64(3), proof.epk, proof.expected, proof.r1, proof.r2, proof.b);
  assert.ok(walk(leaf, proof.index, proof.path).equals(cheatRoot), 'the proof leads to the root the cheater signed');
  // A cheater that signs some other root cannot be proven: its message is only dropped.
  assert.equal(findBadDealing(cheat, epks, randomBytes(32)), undefined);
  const messages = new Map<number, Message>([[1, decodeMessage(encodeMessage(honest), 1, 4, t)], [2, decodeMessage(encodeMessage(cheat), 2, 4, t)]]);
  assert.deepEqual(validSeats(messages, state.pub, 1n, buckets, epks, t).get(1n), [1]);
});
