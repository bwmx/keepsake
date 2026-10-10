import assert from 'node:assert/strict';
import { microAlgo } from '@algorandfoundation/algokit-utils';
import { lastRound, stepAll, type Env, type Workers } from '../src/epoch-sim.js';

// Test helpers for the EpochCommittee tests; the LocalNet environment itself is src/epoch-sim.ts.
export * from '../src/epoch-sim.js';
export const rejects = (p: Promise<unknown>, message: string) => assert.rejects(p, new RegExp(message));
export const cover = { coverAppCallInnerTransactionFees: true, maxFee: microAlgo(20_000) } as const;
/** A 10-round validity window from the next round, so `block` can still read the seed (cached params may be stale). */
export const shortWindow = async () => ({ firstValidRound: (await lastRound()) + 1n, validityWindow: 10 });

/** Lockstep until `done` (at most `limit` rounds). */
export async function runUntil(env: Env, workers: Workers, done: () => Promise<boolean> | boolean, limit = 5_000n, online = (_i: number, _epoch: bigint) => true) {
  const start = await lastRound();
  while (!(await done())) {
    assert.ok((await lastRound()) - start < limit, 'Timed out');
    await stepAll(env, workers, online);
  }
}
