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
 * LOCALNET ONLY. The EpochCommittee app with bonded members that are online for consensus (dummy participation keys)
 * and a round ticker, plus in-process member workers on a shared thread pool, for tests and Capsule Lab. Accounts are
 * generated throwaways and never printed.
 */
Config.configure({ logger: nullLogger }); // The default logger prints generated LocalNet account mnemonics.
export const algorand = AlgorandClient.defaultLocalNet();
export const algod = algorand.client.algod;
export const lastRound = async () => (await algod.status().do()).lastRound;

export type Env = Awaited<ReturnType<typeof deploy>>;
export type Member = Env['members'][number];

/** Online stake counts in `voter_params_get` this many rounds after it changes (measured). */
export const BALANCE_LOOKBACK = 320n;

/**
 * Members bond `stakes` Algos each (default 1) and keep 20 more online, so their weight is their bond. The bonded
 * stake is cut into `tickets` sortition tickets (default one per Algo), each winning below `threshold` / 2^64.
 */
export async function deploy(o: { members: number; epochRounds: bigint; nominationRounds: bigint; handoverRounds: bigint; threshold: bigint;
  stakes?: number[]; tickets?: bigint; shareThreshold?: bigint; bucketRounds?: bigint; bucketLead?: bigint; genesisCommittee?: bigint }) {
  await vrf.init();
  const dispenser = await algorand.account.localNetDispenser();
  const fund = async (amount = 20) => { const a = algorand.account.random(); await algorand.account.ensureFunded(a, dispenser, algo(amount)); return a; };
  const [creator, ticker] = [await fund(), await fund()];
  const tick = () => algorand.send.payment({ sender: ticker, receiver: ticker, amount: microAlgo(0), note: randomBytes(8) });
  const stakes = o.stakes ?? Array.from({ length: o.members }, () => 1);
  /** A funded account, online for consensus with throwaway participation keys. */
  const online = async (algos: number) => {
    const account = await fund(algos), round = await lastRound();
    await algorand.send.onlineKeyRegistration({ sender: account, voteKey: randomBytes(32), selectionKey: randomBytes(32),
      stateProofKey: randomBytes(64), voteFirst: round, voteLast: round + 10_000_000n, voteKeyDilution: 10_000n });
    return account;
  };
  const accounts = [];
  for (const stake of stakes) accounts.push({ account: await online(stake + 20), stake });
  for (const end = (await lastRound()) + BALANCE_LOOKBACK; (await lastRound()) < end;) await tick();

  const params = { epochRounds: o.epochRounds, nominationRounds: o.nominationRounds, handoverRounds: o.handoverRounds,
    shareThreshold: o.shareThreshold ?? 3n, bucketRounds: o.bucketRounds ?? 2n * o.epochRounds, bucketLead: o.bucketLead ?? o.epochRounds,
    genesisCommittee: o.genesisCommittee ?? (await lastRound()) / o.epochRounds + 3n };
  const { appClient: app } = await algorand.client.getTypedAppFactory(EpochCommitteeFactory, { defaultSender: creator.addr }).send.create
    .createApplication({ args: { ...params, totalTickets: o.tickets ?? BigInt(stakes.reduce((a, b) => a + b, 0)), ticketThreshold: o.threshold } });
  // The creator funds only the app account's own minimum balance: members pay for every box.
  await algorand.send.payment({ sender: creator, receiver: app.appAddress, amount: microAlgo(100_000) });
  const [enrollDeposit, seatDeposit] = await app.deposits();
  const { genesisHash } = await algorand.client.network();
  const pins = { genesisHash, appId: app.appId, maxRoundAgeMs: 0 };
  const reader = new EpochReader(algod, pins, params, app.appClient.getABIMethod('postChunk').getSelector());
  const enroll = async (index: number, account: Awaited<ReturnType<typeof fund>>, stake: number) => {
    const vrfSecretKey = vrf.generateKeyPair().secretKey;
    await app.send.enroll({ sender: account, args: { vrfKey: vrfSecretKey.subarray(32),
      payment: algorand.createTransaction.payment({ sender: account, receiver: app.appAddress, amount: microAlgo(enrollDeposit + algo(stake).microAlgo) }) } });
    return { index: BigInt(index), account, vrfSecretKey, keys: new Map<bigint, EphemeralKeyPair>() };
  };
  const members = [];
  for (const [i, a] of accounts.entries()) members.push(await enroll(i, a.account, a.stake));
  /** A late member, bonded now, so it counts from the next epoch; online stake counts after the lookback. */
  const addMember = async (index: number, stake = 1, isOnline = true) => enroll(index, isOnline ? await online(stake + 20) : await fund(stake + 20), stake);
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
  return { app, creator, members, pins, params, reader, fund, online, addMember, tick, nextRoundIs, nextEpoch, enrollDeposit, seatDeposit };
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
