import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { AlgorandClient, Config, algo, microAlgo } from '@algorandfoundation/algokit-utils';
import { nullLogger } from '@algorandfoundation/algokit-utils/types/logging';
import vrf from '@bwmx/algorand-vrf-utils-ts';
import type { EphemeralKeyPair } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/crypto.js';
import { EpochCommitteeFactory } from '../smart_contracts/artifacts/epoch_committee/EpochCommitteeClient.js';
import { EpochReader } from '../src/epochs.js';

// LocalNet environment for the EpochCommittee tests: one app, admitted and enrolled members, and a round ticker.
Config.configure({ logger: nullLogger });
export const algorand = AlgorandClient.defaultLocalNet();
export const algod = algorand.client.algod;
export const rejects = (p: Promise<unknown>, message: string) => assert.rejects(p, new RegExp(message));
export const lastRound = async () => (await algod.status().do()).lastRound;
export const cover = { coverAppCallInnerTransactionFees: true, maxFee: microAlgo(20_000) } as const;
/** A 10-round validity window from the next round, so `block` can still read the seed (cached params may be stale). */
export const shortWindow = async () => ({ firstValidRound: (await lastRound()) + 1n, validityWindow: 10 });

export type Env = Awaited<ReturnType<typeof deploy>>;
export type Member = Env['members'][number];

export async function deploy(o: { members: number; epochRounds: bigint; nominationRounds: bigint; handoverRounds: bigint; threshold: bigint;
  shareThreshold?: bigint; bucketRounds?: bigint; bucketLead?: bigint; genesisCommittee?: bigint }) {
  await vrf.init();
  const dispenser = await algorand.account.localNetDispenser();
  const fund = async (amount = 20) => { const a = algorand.account.random(); await algorand.account.ensureFunded(a, dispenser, algo(amount)); return a; };
  const [admin, ticker] = [await fund(50), await fund()];
  const params = { epochRounds: o.epochRounds, nominationRounds: o.nominationRounds, handoverRounds: o.handoverRounds,
    shareThreshold: o.shareThreshold ?? 3n, bucketRounds: o.bucketRounds ?? 2n * o.epochRounds, bucketLead: o.bucketLead ?? o.epochRounds,
    genesisCommittee: o.genesisCommittee ?? (await lastRound()) / o.epochRounds + 3n };
  const { appClient: app } = await algorand.client.getTypedAppFactory(EpochCommitteeFactory, { defaultSender: admin.addr }).send.create
    .createApplication({ args: { ...params, nominatorThreshold: o.threshold } });
  await algorand.send.payment({ sender: admin, receiver: app.appAddress, amount: algo(20) });
  const { genesisHash } = await algorand.client.network();
  const pins = { genesisHash, appId: app.appId, beaconAppId: 0n, maxRoundAgeMs: 0 };
  const reader = new EpochReader(algod, pins, params, app.appClient.getABIMethod('postChunk').getSelector());
  const addMember = async (index: number) => {
    const account = await fund(), vrfSecretKey = vrf.generateKeyPair().secretKey;
    await app.send.admitMember({ args: { account: account.toString() } });
    await app.send.enroll({ sender: account, args: { vrfKey: vrfSecretKey.subarray(32) } });
    return { index: BigInt(index), account, vrfSecretKey, keys: new Map<bigint, EphemeralKeyPair>() };
  };
  const members = [];
  for (let i = 0; i < o.members; i++) members.push(await addMember(i));
  const tick = () => algorand.send.payment({ sender: ticker, receiver: ticker, amount: microAlgo(0), note: randomBytes(8) });
  /** Advances so that the next transaction executes in `round`. */
  const nextRoundIs = async (round: bigint) => {
    while ((await lastRound()) + 1n < round) await tick();
    assert.equal((await lastRound()) + 1n, round, 'Target round already passed');
  };
  /** Moves to the start of a fresh epoch and returns the next one, whose keys members can now post in good time. */
  const nextEpoch = async () => {
    const current = (await lastRound()) / o.epochRounds + 1n;
    await nextRoundIs(current * o.epochRounds + 1n);
    return current + 1n;
  };
  return { app, admin, members, pins, params, reader, addMember, tick, nextRoundIs, nextEpoch };
}
