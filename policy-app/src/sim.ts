import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AlgorandClient, Config, algo, microAlgo } from '@algorandfoundation/algokit-utils';
import { nullLogger } from '@algorandfoundation/algokit-utils/types/logging';
import vrf from '@bwmx/algorand-vrf-utils-ts';
import { secretKeyToMnemonic } from 'algosdk';
import { deriveEphemeralKey, type EphemeralKeyPair } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/crypto.js';
import {
  createAccessRequest, createCapsule, recover, type AccessRequest, type Capsule,
} from 'algorand-ephemeral-capsule-crypto-spike/dist/src/protocol.js';
import { CapsulePolicyFactory } from '../smart_contracts/artifacts/capsule_policy/CapsulePolicyClient.js';
import {
  BATCH, ChainReader, committeeSlots, depositBytes, hiddenSelection, manifestFromChain, releaseFromSlot, slotRange,
  type ChainPins,
} from './chain.js';
import { startWorker } from './worker.js';

/**
 * LOCALNET ONLY. One process plays every party (beacon operator, admin, sender, recipient, relayer, members) with
 * generated throwaway accounts, for tests and the demo UI. Members run as in-process workers.
 */
Config.configure({ logger: nullLogger }); // The default logger prints generated LocalNet account mnemonics.

const BEACON_DIR = path.resolve(process.env.RANDOMNESS_BEACON_DIR
  ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../randomness-beacon'));
const ALGOD = { server: 'http://localhost', port: 4001, token: 'a'.repeat(64) };
export const SELECTION_DELAY = 8n;
export const ANY_RANK = 2n ** 64n - 1n; // nominatorThreshold that makes every member eligible for every slot.

// Protocol MBR: 2500 + 400/byte of key + value. Capsule: 'c' + u64, 321 bytes. Slot: 's' + u64 + u64, 419 bytes.
export const boxMbr = (slots: number) => 2_500 + 400 * (1 + 8 + 321) + slots * (2_500 + 400 * (1 + 16 + 419));

type Funded = Awaited<ReturnType<LocalNetSim['fund']>>;
export interface Member {
  index: number;
  account: Funded;
  vrfSecretKey: Uint8Array;
  nominationSeed: Uint8Array;
  nomination: EphemeralKeyPair;
  worker?: Awaited<ReturnType<typeof startWorker>>;
}
export interface CapsuleTerms { capsuleId: bigint; slots: number; seedRound: bigint; deadline: bigint; openRound: bigint; expiresRound: bigint }
export type WorkerEvent = { at: number; member: number } & Record<string, string | number>;

export interface SimOptions {
  members?: number;
  nominationRounds?: bigint;
  nominatorThreshold?: bigint;
  beaconDaemon?: boolean;
  staleRequestTimeout?: bigint;
  pollMs?: number;
}

export class LocalNetSim {
  readonly algorand = AlgorandClient.fromConfig({
    algodConfig: ALGOD,
    kmdConfig: { server: 'http://localhost', port: 4002, token: 'a'.repeat(64) },
    indexerConfig: { server: 'http://localhost', port: 8980, token: 'a'.repeat(64) }
  });
  readonly events: WorkerEvent[] = [];
  beacon!: { appId: bigint; client: Awaited<ReturnType<typeof deployBeacon>>['client']; stop: () => void };
  app!: Awaited<ReturnType<LocalNetSim['deployPolicy']>>;
  pins!: ChainPins;
  reader!: ChainReader;
  admin!: Funded;
  sender!: Funded;
  recipient!: Funded;
  outsider!: Funded;
  relayer!: Funded;
  members: Member[] = [];
  costs!: { fees: bigint; boxMbr: bigint };
  #pollMs = 500;

  static async create(o: SimOptions = {}): Promise<LocalNetSim> {
    await vrf.init();
    const sim = new LocalNetSim();
    sim.#pollMs = o.pollMs ?? 500;
    const fund = (amount = 50) => sim.fund(amount);
    [sim.admin, sim.sender, sim.recipient, sim.outsider, sim.relayer] = await Promise.all([fund(), fund(), fund(), fund(), fund(200)]);
    sim.beacon = await deployBeacon(sim, o.beaconDaemon ?? true, o.staleRequestTimeout ?? 1000n);
    sim.app = await sim.deployPolicy(o.nominationRounds ?? 30n, o.nominatorThreshold ?? ANY_RANK);
    const { genesisHash } = await sim.algorand.client.network();
    sim.pins = { genesisHash, appId: sim.app.appId, beaconAppId: sim.beacon.appId, maxRoundAgeMs: 0 };
    sim.reader = new ChainReader(sim.algorand.client.algod, sim.pins);
    sim.costs = (await sim.beacon.client.send.call({ method: 'getCosts', args: [] })).return as unknown as { fees: bigint; boxMbr: bigint };
    for (let i = 0; i < (o.members ?? 8); i++) await sim.addMember();
    return sim;
  }

  async fund(amount = 50) {
    const account = this.algorand.account.random();
    await this.algorand.account.ensureFunded(account, await this.algorand.account.localNetDispenser(), algo(amount));
    return account;
  }

  async deployPolicy(nominationRounds: bigint, nominatorThreshold: bigint) {
    const factory = this.algorand.client.getTypedAppFactory(CapsulePolicyFactory, { defaultSender: this.admin });
    const { appClient } = await factory.send.create.createApplication({
      args: { beacon: this.beacon.appId, nominationRounds, nominatorThreshold }
    });
    await this.algorand.send.payment({ sender: this.admin, receiver: appClient.appAddress, amount: algo(5) });
    return appClient;
  }

  /** A new member with fresh VRF and nomination keys, admitted by the admin and self-enrolled. */
  async addMember(target = this.app): Promise<Member> {
    const nominationSeed = randomBytes(32);
    const m: Member = {
      index: this.members.length, account: await this.fund(), vrfSecretKey: vrf.generateKeyPair().secretKey,
      nominationSeed, nomination: await deriveEphemeralKey(nominationSeed)
    };
    await this.enroll(m, target);
    this.members.push(m);
    return m;
  }

  async enroll(m: Member, target = this.app) {
    await target.send.admitCustodian({ args: { account: m.account.toString() } });
    await target.send.enroll({
      sender: m.account, args: {
        vrfKey: m.vrfSecretKey.subarray(32),
        nominationKey: Buffer.from(m.nomination.publicKey, 'base64url')
      }
    });
  }

  // --- Member workers (in-process; each has only its own keys plus the shared relayer) ---

  async startMember(m: Member) {
    if (m.worker) return;
    m.worker = await startWorker({
      pins: this.pins, algod: ALGOD, memberMnemonic: secretKeyToMnemonic(m.account.account.sk),
      vrfSecretKey: m.vrfSecretKey, nominationSeed: m.nominationSeed,
      relayerMnemonic: secretKeyToMnemonic(this.relayer.account.sk), pollMs: this.#pollMs,
      event: e => this.events.push({ at: Date.now(), member: m.index, ...e }),
    });
  }

  async stopMember(m: Member) {
    await m.worker?.stop();
    delete m.worker;
    this.events.push({ at: Date.now(), member: m.index, offline: 'true' });
  }

  async startMembers(members = this.members) { await Promise.all(members.map(m => this.startMember(m))); }

  async stop() {
    await Promise.all(this.members.map(m => m.worker?.stop()));
    this.beacon.stop();
  }

  /** Slots each member holds for a capsule, from operator-local worker events (not chain data). */
  holdings(capsuleId: bigint): Map<number, string[]> {
    const map = new Map<number, string[]>();
    for (const e of this.events) {
      if (e.custody === capsuleId.toString()) map.set(e.member, [...(map.get(e.member) ?? []), String(e.slot)]);
    }
    return map;
  }

  // --- Rounds (dev-mode LocalNet seals one block per transaction) ---

  async lastRound() { return (await this.algorand.client.algod.status().do()).lastRound; }
  tick() { return this.algorand.send.payment({ sender: this.outsider, receiver: this.outsider, amount: microAlgo(0), note: randomBytes(8) }); }
  async advancePast(round: bigint) { while ((await this.lastRound()) < round) await this.tick(); }

  // --- Sender ---

  payment(slots: number) { return boxMbr(slots) + Number(this.costs.fees + this.costs.boxMbr); }

  async register(o: {
    slots?: number; minHolders?: number; openIn?: bigint; length?: bigint; recipient?: string;
    amount?: number; receiver?: string; openRound?: bigint; expiresRound?: bigint; target?: LocalNetSim["app"]
  } = {}): Promise<CapsuleTerms> {
    const target = o.target ?? this.app;
    const slots = o.slots ?? 5;
    const nominationRounds = (await target.state.global.nominationRounds())!;
    const executes = (await this.lastRound()) + 1n;
    const seedRound = executes + SELECTION_DELAY;
    const deadline = seedRound + nominationRounds;
    const openRound = o.openRound ?? deadline + (o.openIn ?? 20n);
    const expiresRound = o.expiresRound ?? openRound + (o.length ?? 10n);
    const result = await target.send.register({
      sender: this.sender, coverAppCallInnerTransactionFees: true, maxFee: microAlgo(20_000),
      args: {
        recipient: o.recipient ?? this.recipient.toString(), openRound, expiresRound, slotCount: slots,
        minHolders: o.minHolders ?? Math.min(slots, 3),
        payment: this.algorand.createTransaction.payment({
          sender: this.sender, receiver: o.receiver ?? target.appAddress,
          amount: microAlgo(o.amount ?? this.payment(slots))
        })
      },
    });
    return { capsuleId: result.return!, slots, seedRound, deadline, openRound, expiresRound };
  }

  async close(capsuleId: bigint) {
    await this.app.send.closeNominations({ args: { capsuleId }, sender: this.outsider });
  }

  /**
   * Sender: committee from on-chain slot keys → capsule → anchor hash → commitments and deposits in batches.
   * `tamper` anchors a hash that does not match the chain data, which holders must refuse.
   */
  async anchor(capsuleId: bigint, plaintext: Uint8Array, { tamper = false } = {}) {
    const { record } = await this.reader.capsule(capsuleId);
    const slots = await this.reader.slots(capsuleId, slotRange(record));
    const { capsule, deposits, anchor } = await createCapsule(plaintext, {
      network: this.pins.genesisHash, applicationId: this.pins.appId.toString(), capsuleId: capsuleId.toString(),
      recipient: record.recipient, openRound: record.openRound.toString(), expiresRound: record.expiresRound.toString(),
    }, { select: () => hiddenSelection(this.pins, capsuleId, record, slots) });
    await this.app.send.anchorManifest({
      sender: this.sender, args: {
        capsuleId,
        manifestHash: tamper ? randomBytes(32) : Buffer.from(anchor, 'hex'), payloadHash: Buffer.from(capsule.manifest.payloadHash, 'hex')
      }
    });
    const committee = committeeSlots(slots);
    for (let i = 0; i < committee.length; i += BATCH) {
      const batch = committee.slice(i, i + BATCH);
      await this.app.send.postDeposits({
        sender: this.sender, coverAppCallInnerTransactionFees: true, maxFee: microAlgo(5_000), args: {
          capsuleId, slotIndexes: batch.map(({ k }) => BigInt(k)),
          commitments: batch.map((_, j) => Buffer.from(capsule.manifest.commitments[i + j]!, 'hex')),
          deposits: batch.map((_, j) => depositBytes(deposits[i + j]!))
        }
      });
    }
    return { capsule, anchor };
  }

  /** Anyone, after expiry: delete slot boxes in batches, then the capsule box (refunds the sender). */
  async cleanup(capsuleId: bigint) {
    const record = await this.app.getCapsule({ args: { capsuleId } });
    const all = slotRange(record);
    for (let i = 0; i < all.length; i += BATCH) {
      await this.app.send.deleteSlots({ args: { capsuleId, slotIndexes: all.slice(i, i + BATCH) }, sender: this.outsider });
    }
    await this.app.send.cleanup({ args: { capsuleId }, sender: this.outsider, extraFee: microAlgo(1000) });
  }

  // --- Recipient (in a real deployment this runs in the recipient's own client) ---

  /** A fresh X25519 request key, bound on-chain by `as` (default: the recipient wallet). */
  async request(capsuleId: bigint, anchor: string, o: { as?: Funded; bind?: AccessRequest } = {}) {
    const { request, keys } = await createAccessRequest(anchor);
    const bound = o.bind ?? request;
    await this.app.send.requestAccess({
      sender: o.as ?? this.recipient, args: {
        capsuleId, manifestHash: Buffer.from(anchor, 'hex'),
        requestId: Buffer.from(bound.requestId, 'base64url'), recipientKey: Buffer.from(bound.recipientPublicKey, 'base64url')
      }
    });
    return { request, keys };
  }

  /** Rebuild the manifest from chain data, collect on-chain releases and decrypt locally. */
  async recover(capsuleId: bigint, anchor: string, payload: Capsule['payload'], request: AccessRequest, privateKey: CryptoKey) {
    const { record } = await this.reader.capsule(capsuleId);
    const slots = await this.reader.slots(capsuleId, slotRange(record));
    const manifest = manifestFromChain(this.pins, capsuleId, record, slots);
    const releases = slots.flatMap((s, k) => (s.released ? [releaseFromSlot(k, s, record)] : []));
    return { plaintext: await recover({ manifest, payload }, anchor, request, privateKey, releases), releases: releases.length };
  }
}

async function deployBeacon(sim: LocalNetSim, daemon: boolean, staleRequestTimeout: bigint) {
  const { publicKey, secretKey } = vrf.generateKeyPair();
  const operator = await sim.fund(100);
  const factory = sim.algorand.client.getAppFactory({
    appSpec: readFileSync(path.join(BEACON_DIR, 'smart_contracts/artifacts/randomness_beacon/RandomnessBeacon.arc56.json'), 'utf8'),
    defaultSender: operator, updatable: false,
  });
  const { appClient } = await factory.send.create({ method: 'createApplication', args: [publicKey, 128n, 100n, staleRequestTimeout] });
  await sim.algorand.send.payment({ sender: operator, receiver: appClient.appAddress, amount: algo(1) });
  let child: ChildProcess | undefined;
  if (daemon) {
    child = spawn(process.execPath, ['dist/index.js'], {
      cwd: path.join(BEACON_DIR, 'daemon'), stdio: ['ignore', 'ignore', 'inherit'], env: {
        PATH: process.env.PATH ?? '', ALGOD_SERVER: ALGOD.server, ALGOD_PORT: String(ALGOD.port), ALGOD_TOKEN: ALGOD.token,
        BEACON_APP_ID: appClient.appId.toString(), MANAGER_MNEMONIC: secretKeyToMnemonic(operator.account.sk),
        VRF_PRIVATE_KEY: Buffer.from(secretKey).toString('base64'), ROLE: 'both', LOG_LEVEL: 'error'
      }
    });
  }
  return { appId: appClient.appId, client: appClient, stop: () => child?.kill('SIGTERM') };
}
