import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { microAlgo } from '@algorandfoundation/algokit-utils';
import vrf from '@bwmx/algorand-vrf-utils-ts';
import { seal } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/crypto.js';
import { Custodian } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/protocol.js';
import { STAGE, ackBody, nominationAlpha, nominationContext, vrfRank } from '../src/chain.js';
import { LocalNetSim, type CapsuleTerms, type Member, type SimOptions } from '../src/sim.js';

export { LocalNetSim, STAGE, type CapsuleTerms, type Member };
type App = LocalNetSim['app'];

export const rejects = (p: Promise<unknown>, message: string) => assert.rejects(p, new RegExp(message));

/** A fresh LocalNet environment for one test; always stopped (beacon daemon, workers) afterwards. */
export async function withSim(o: SimOptions, body: (sim: LocalNetSim) => Promise<void>) {
  const sim = await LocalNetSim.create(o);
  try {
    await body(sim);
  } finally {
    await sim.stop();
  }
}

export async function waitFor(what: string, ready: () => Promise<boolean>, tries = 240) {
  for (let i = 0; i < tries; i++) {
    if (await ready()) return;
    await sleep(250);
  }
  assert.fail(`Timed out waiting for ${what}`);
}

export const record = (sim: LocalNetSim, capsuleId: bigint, target: App = sim.app) => target.getCapsule({ args: { capsuleId } });
export const slot = (sim: LocalNetSim, capsuleId: bigint, k: bigint) => sim.app.getSlot({ args: { capsuleId, slot: k } });
export const waitStage = (sim: LocalNetSim, capsuleId: bigint, stage: bigint, target: App = sim.app) =>
  waitFor(`stage ${stage}`, async () => (await record(sim, capsuleId, target)).stage >= stage);

/** Commit the seed round, then wait for the beacon daemon's proof + fulfillment (it lands in the next block). */
export async function seed(sim: LocalNetSim, c: CapsuleTerms, target: App = sim.app) {
  await sim.advancePast(c.seedRound);
  await waitStage(sim, c.capsuleId, STAGE.NOMINATING, target);
}

/** Exact only while nothing else (beacon daemon, workers) is sending: the next transaction executes in lastRound + 1. */
export async function nextRoundIs(sim: LocalNetSim, target: bigint) {
  await sim.advancePast(target - 1n);
  assert.equal((await sim.lastRound()) + 1n, target, 'Target round already passed');
}

export async function closeAt(sim: LocalNetSim, c: CapsuleTerms) {
  await sim.advancePast(c.deadline - 1n);
  await sim.close(c.capsuleId);
}

/** Member m's private sortition result for (capsule, slot). */
export async function sortition(sim: LocalNetSim, m: Member, capsuleId: bigint, k: bigint, target: App = sim.app) {
  const { randomness } = await record(sim, capsuleId, target);
  const { proof, output } = vrf.prove(m.vrfSecretKey, nominationAlpha(target.appId, capsuleId, k, randomness));
  return { proof, rank: vrfRank(output) };
}

/** Lowest-ranked eligible member per slot, or undefined when nobody is eligible. */
export async function winners(sim: LocalNetSim, capsuleId: bigint, slots: number, threshold: bigint) {
  return Promise.all(Array.from({ length: slots }, async (_, k) => {
    const ranked = await Promise.all(sim.members.map(async m => ({ m, rank: (await sortition(sim, m, capsuleId, BigInt(k))).rank })));
    const eligible = ranked.filter(r => r.rank < threshold);
    return eligible.length ? eligible.reduce((a, b) => (b.rank < a.rank ? b : a)).m.index : undefined;
  }));
}

/** The test plays nominator: one-time holder keys from a fresh seed, sealed to `holder`. Returns the seed. */
export async function nominate(sim: LocalNetSim, m: Member, capsuleId: bigint, k: bigint, o: { holder?: Member;
  sender?: Member['account']; proof?: Uint8Array; index?: number; target?: App } = {}) {
  const target = o.target ?? sim.app;
  const seedBytes = randomBytes(32);
  const keys = await Custodian.fromSeed(`slot-${k}`, seedBytes);
  const sealed = await seal((o.holder ?? m).nomination.publicKey, seedBytes, nominationContext({ ...sim.pins, appId: target.appId }, capsuleId, k));
  await target.send.nominate({ coverAppCallInnerTransactionFees: true, maxFee: microAlgo(20_000), sender: o.sender ?? m.account, args: {
    capsuleId, slot: k, nominator: o.index ?? m.index, proof: o.proof ?? (await sortition(sim, m, capsuleId, k, target)).proof,
    holderEncKey: Buffer.from(keys.descriptor.encryptionPublicKey, 'base64url'),
    holderSigKey: Buffer.from(keys.descriptor.signingPublicKey, 'base64url').subarray(12),
    sealedSeed: Buffer.concat([Buffer.from(sealed.enc, 'base64url'), Buffer.from(sealed.ciphertext, 'base64url')]) } });
  return seedBytes;
}

/** The test plays holder: sign with the one-time key derived from the slot seed; the relayer submits. */
export async function ack(sim: LocalNetSim, capsuleId: bigint, k: bigint, seedBytes: Uint8Array, signAs = k) {
  const holder = await Custodian.fromSeed(`slot-${signAs}`, seedBytes);
  const signature = holder.signChainMessage('ack', ackBody(sim.app.appId, capsuleId, signAs, await record(sim, capsuleId)));
  return sim.app.send.acknowledgeCustody({ coverAppCallInnerTransactionFees: true, maxFee: microAlgo(20_000), sender: sim.relayer,
    args: { capsuleId, slot: k, signature } });
}

/** Sender posts random commitments/deposits for the given slots (the contract cannot check their content). */
export const postDeposits = (sim: LocalNetSim, capsuleId: bigint, slots: bigint[], sender = sim.sender) =>
  sim.app.send.postDeposits({ sender, coverAppCallInnerTransactionFees: true, maxFee: microAlgo(5_000), args: {
    capsuleId, slotIndexes: slots, commitments: slots.map(() => randomBytes(32)), deposits: slots.map(() => randomBytes(81)) } });
