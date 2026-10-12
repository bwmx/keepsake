import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { dealerGenesis, decodeMessage, encodeMessage, handover, receive, seatKeys, type Message } from '../src/ecpss.js';
import { VerifyPool, receiveParallel } from '../src/parallel.js';
import { point } from '../src/pvss.js';

test('verifying on a thread pool gives the same committee, commitments and shares as one thread', async () => {
  const t = 3, committee = (n: number) => Array.from({ length: n }, (_, i) => ({ seat: i + 1, ...seatKeys(randomBytes(32)) }));
  const seats = committee(7), next = committee(6);
  const { messages: genesis } = dealerGenesis(1n, seats.map(s => s.epk), t);
  const state = receive(genesis, new Map(), 0n, { live: [], create: [1n] }, seats.map(s => s.epk), t, seats);
  const buckets = { live: [1n], create: [2n] }, epks = next.map(s => s.epk);
  const raw = new Map(state.holders.map(h => [h.seat, encodeMessage(handover(h, state.pub, 1n, buckets, epks, t))]));
  const tampered = decodeMessage(raw.get(2)!, 2, 6, t); // Seat 2 lies to one seat; seat 4 posts garbage.
  const d = tampered.pack!; // Two buckets for six seats: each holder packs both into one dealing.
  d.subshares[0] = { ...d.subshares[0]!, b: d.subshares[0]!.b.add(point.g2(1n)) };
  raw.set(2, encodeMessage(tampered));
  raw.set(4, randomBytes(raw.get(4)!.length));

  const decoded = new Map<number, Message>();
  for (const [s, bytes] of raw) try { decoded.set(s, decodeMessage(bytes, s, 6, t)); } catch { /* Seat 4. */ }
  const one = receive(decoded, state.pub, 1n, buckets, epks, t, next);
  const pool = new VerifyPool(3);
  try {
    const many = await receiveParallel(pool, raw, state.pub, 1n, buckets, epks, t, next);
    assert.deepEqual(many.used, one.used);
    assert.ok(!many.used.get(1n)!.seats.includes(2) && !many.used.get(1n)!.seats.includes(4));
    for (const b of [1n, 2n]) {
      assert.ok(many.pub.get(b)!.poly.every((p, l) => p.equals(one.pub.get(b)!.poly[l]!)));
      assert.ok(many.holders.every((h, i) => h.shares.get(b)!.equals(one.holders[i]!.shares.get(b)!)));
    }
  } finally {
    await pool.close();
  }
});
