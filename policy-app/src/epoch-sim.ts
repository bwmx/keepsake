import { randomBytes } from 'node:crypto';
import { AlgorandClient, Config, algo, microAlgo } from '@algorandfoundation/algokit-utils';
import { nullLogger } from '@algorandfoundation/algokit-utils/types/logging';
import vrf from '@bwmx/algorand-vrf-utils-ts';
import { secretKeyToMnemonic } from 'algosdk';
import type { EphemeralKeyPair } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/crypto.js';
import type { VerifyPool } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/parallel.js';
import { EpochCommitteeFactory } from '../smart_contracts/artifacts/epoch_committee/EpochCommitteeClient.js';
import { startEpochWorker } from './epoch-worker.js';
import { EpochReader } from './epochs.js';

/**
 * LOCALNET ONLY. The EpochCommittee app with admitted, enrolled members and a round ticker, plus in-process member
 * workers on a shared thread pool, for tests and Capsule Lab. Accounts are generated throwaways and never printed.
 */
Config.configure({ logger: nullLogger }); // The default logger prints generated LocalNet account mnemonics.
export const algorand = AlgorandClient.defaultLocalNet();
export const algod = algorand.client.algod;
export const lastRound = async () => (await algod.status().do()).lastRound;

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
    if ((await lastRound()) + 1n !== round) throw new Error('Target round already passed');
  };
  /** Moves to the start of a fresh epoch and returns the next one, whose keys members can now post in good time. */
  const nextEpoch = async () => {
    const current = (await lastRound()) / o.epochRounds + 1n;
    await nextRoundIs(current * o.epochRounds + 1n);
    return current + 1n;
  };
  return { app, admin, members, pins, params, reader, fund, addMember, tick, nextRoundIs, nextEpoch };
}

export type WorkerEvent = { member: number; round: bigint } & Record<string, string | number | bigint>;
export type Workers = Awaited<ReturnType<typeof startWorkers>>;

/** One in-process epoch worker per member, stepped by the caller (pollMs 0), logging events with the current round. */
export async function startWorkers(env: Env, pool: VerifyPool, events: WorkerEvent[]) {
  const ALGOD = { server: 'http://localhost', port: 4001, token: 'a'.repeat(64) };
  return Promise.all(env.members.map(m => startEpochWorker({
    pins: env.pins, algod: ALGOD, memberMnemonic: secretKeyToMnemonic(m.account.account.sk), vrfSecretKey: m.vrfSecretKey, pool, pollMs: 0,
    event: e => void lastRound().then(round => events.push({ member: Number(m.index), round, ...e })),
  })));
}

/** Steps every online worker once at the current round (lockstep), then advances the chain by a round. */
export async function stepAll(env: Env, workers: Workers, online = (_i: number, _epoch: bigint) => true) {
  const epoch = (await lastRound()) / env.params.epochRounds;
  await Promise.all(workers.filter((_, i) => online(i, epoch)).map(w => w.step()));
  await env.tick();
}
