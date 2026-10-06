import { randomBytes, randomInt } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { AlgorandClient, Config, microAlgo } from '@algorandfoundation/algokit-utils';
import { nullLogger } from '@algorandfoundation/algokit-utils/types/logging';
import vrf from '@bwmx/algorand-vrf-utils-ts';
import { check, deriveEphemeralKey, open, seal } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/crypto.js';
import { Custodian, type AuthorizationSource } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/protocol.js';
import { CapsulePolicyClient } from '../smart_contracts/artifacts/capsule_policy/CapsulePolicyClient.js';
import {
  ChainReader, STAGE, ackBody, b64url, chainAuthorization, depositFromSlot, hex, manifestFromChain, nominationAlpha,
  nominationContext, releaseBody, requestFromChain, slotRange, vrfRank, type CapsuleRecord, type ChainPins,
} from './chain.js';
import type { Manifest } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/protocol.js';

interface Held { custodian: Custodian; capsuleId: bigint; slot: bigint; expiresRound: bigint; source: AuthorizationSource }

export interface WorkerConfig {
  pins: ChainPins;
  algod: { server: string; port?: number; token: string };
  memberMnemonic: string; // Registry account: signs nominations only. Never used for custody.
  vrfSecretKey: Uint8Array; // 64-byte VRF key (seed || public key) enrolled for this member.
  nominationSeed: Uint8Array; // 32 bytes; derives the X25519 key that receives holder nominations.
  relayerMnemonic: string; // Shared account that submits acknowledgments and releases, so holders stay unnamed.
  pollMs: number;
  event?: (e: Record<string, string>) => void; // Operator-local log: names this member's slots, never secrets.
}

/**
 * One registry member. It talks only to its own algod node; there is no network API.
 * - Nominator: proves VRF eligibility per slot and, if it beats the current rank, nominates a uniformly chosen
 *   member with fresh one-time holder keys, then erases the seed.
 * - Holder: finds its slots by trial decryption, rebuilds the manifest from chain data, accepts its deposit, and
 *   acknowledges and releases through the relayer, signed only by the one-time key.
 * Shares live only in memory; disposal happens at expiresRound by polling confirmed rounds.
 */
export async function startWorker(cfg: WorkerConfig) {
  Config.configure({ logger: nullLogger }); // Expected rejections (outranked nominations) are not errors.
  await vrf.init();
  const algorand = AlgorandClient.fromConfig({ algodConfig: cfg.algod });
  const member = algorand.account.fromMnemonic(cfg.memberMnemonic);
  const relayer = algorand.account.fromMnemonic(cfg.relayerMnemonic);
  const reader = new ChainReader(algorand.client.algod, cfg.pins);
  const asMember = new CapsulePolicyClient({ algorand, appId: cfg.pins.appId, defaultSender: member.addr });
  const asRelayer = new CapsulePolicyClient({ algorand, appId: cfg.pins.appId, defaultSender: relayer.addr });
  const nominationKey = await deriveEphemeralKey(cfg.nominationSeed);
  const event = cfg.event ?? (() => {});

  // The app's beacon is fixed at creation; refuse to serve if our pin disagrees. Find our enrolled index.
  check((await asMember.state.global.beacon()) === cfg.pins.beaconAppId, 'Beacon pin mismatch');
  await reader.lastRound();
  const threshold = (await asMember.state.global.nominatorThreshold())!;
  let index: bigint | undefined;
  for (let i = 0n; i < (await asMember.state.global.registrySize())!; i++) {
    const m = await reader.member(i);
    if (m.account !== member.addr.toString()) continue;
    check(b64url(m.vrfKey) === b64url(cfg.vrfSecretKey.subarray(32)) && b64url(m.nominationKey) === nominationKey.publicKey,
      'Enrolled keys differ from configured keys');
    index = i;
  }
  check(index !== undefined, 'Not enrolled');
  const myIndex = index;

  const held = new Map<string, Held>();
  const decided = new Set<string>(); // capsule:slot pairs already evaluated (nominated, or trial-decrypted).
  const cover = { coverAppCallInnerTransactionFees: true, maxFee: microAlgo(20_000) } as const;

  async function nominate(id: bigint, record: CapsuleRecord) {
    if (myIndex >= record.registrySize) return; // Enrolled after this capsule's snapshot.
    const pending = slotRange(record).filter(k => !decided.has(`n:${id}:${k}`));
    if (!pending.length) return;
    const slots = await reader.slots(id, pending);
    for (const [i, k] of pending.entries()) {
      decided.add(`n:${id}:${k}`);
      const { proof, output } = vrf.prove(cfg.vrfSecretKey, nominationAlpha(cfg.pins.appId, id, k, record.randomness));
      const rank = vrfRank(output);
      if (rank >= threshold || (slots[i]!.filled && slots[i]!.rank <= rank)) continue;
      // ponytail: randomInt caps the registry at 2^48 members.
      const holder = await reader.member(BigInt(randomInt(Number(record.registrySize))));
      const seed = randomBytes(32);
      const keys = await Custodian.fromSeed(`slot-${k}`, seed);
      try {
        const sealed = await seal(b64url(holder.nominationKey), seed, nominationContext(cfg.pins, id, k));
        await asMember.send.nominate({ ...cover, args: {
          capsuleId: id, slot: k, nominator: myIndex, proof,
          holderEncKey: Buffer.from(keys.descriptor.encryptionPublicKey, 'base64url'),
          holderSigKey: Buffer.from(keys.descriptor.signingPublicKey, 'base64url').subarray(12),
          sealedSeed: Buffer.concat([Buffer.from(sealed.enc, 'base64url'), Buffer.from(sealed.ciphertext, 'base64url')]),
        } });
        event({ nominated: id.toString(), slot: k.toString() });
      } catch {
        // Outranked or closed meanwhile: harmless.
      } finally {
        seed.fill(0); // Erase the nominator's knowledge of the holder keys and choice.
        keys.dispose();
      }
    }
  }

  // Custody is rebuilt from chain data alone, so a restarted member regains its slots while the capsule is live.
  async function takeCustody(id: bigint, record: CapsuleRecord) {
    const undecided = slotRange(record).filter(k => !decided.has(`h:${id}:${k}`));
    if (undecided.length) {
      const slots = await reader.slots(id, slotRange(record));
      let manifest: Manifest | undefined;
      for (const k of undecided) {
        decided.add(`h:${id}:${k}`);
        const s = slots[Number(k)]!;
        if (!s.filled) continue;
        let seed: Uint8Array;
        try {
          seed = await open(nominationKey.privateKey,
            { enc: b64url(s.sealedSeed.subarray(0, 32)), ciphertext: b64url(s.sealedSeed.subarray(32)) },
            nominationContext(cfg.pins, id, k));
        } catch {
          continue; // Not nominated to us.
        }
        const custodian = await Custodian.fromSeed(`slot-${k}`, seed);
        seed.fill(0);
        try {
          check(custodian.descriptor.encryptionPublicKey === b64url(s.holderEncKey), 'Holder key mismatch');
          manifest ??= manifestFromChain(cfg.pins, id, record, slots);
          await custodian.accept(manifest, depositFromSlot(Number(k), s), hex(record.manifestHash));
        } catch (e) {
          custodian.dispose();
          throw e;
        }
        held.set(`${id}:${k}`, { custodian, capsuleId: id, slot: k, expiresRound: record.expiresRound, source: chainAuthorization(reader, id) });
        event({ custody: id.toString(), slot: k.toString() });
      }
    }
    const mine = [...held.values()].filter(h => h.capsuleId === id);
    const states = await reader.slots(id, mine.map(h => h.slot));
    for (const [i, h] of mine.entries()) {
      if (states[i]!.acknowledged) continue;
      const signature = h.custodian.signChainMessage('ack', ackBody(cfg.pins.appId, id, h.slot, record));
      await asRelayer.send.acknowledgeCustody({ ...cover, args: { capsuleId: id, slot: h.slot, signature } });
    }
  }

  async function release(id: bigint, record: CapsuleRecord) {
    const mine = [...held.values()].filter(h => h.capsuleId === id);
    const states = await reader.slots(id, mine.map(h => h.slot));
    for (const [i, h] of mine.entries()) {
      if (!states[i]!.acknowledged || states[i]!.released) continue;
      const r = await h.custodian.release(requestFromChain(record), h.source);
      const [enc, ciphertext, signature] = [r.enc, r.ciphertext, r.signature].map(v => Buffer.from(v, 'base64url'));
      const chainSignature = h.custodian.signChainMessage('release',
        releaseBody(cfg.pins.appId, id, h.slot, record, enc!, ciphertext!, signature!));
      await asRelayer.send.postRelease({ ...cover, args: {
        capsuleId: id, slot: h.slot, enc: enc!, ciphertext: ciphertext!, signature: signature!, chainSignature } });
      event({ released: id.toString(), slot: h.slot.toString() });
    }
  }

  async function tick() {
    const round = await reader.lastRound();
    for (const [key, h] of held) {
      if (round >= h.expiresRound) {
        h.custodian.dispose();
        held.delete(key);
        event({ disposed: h.capsuleId.toString(), slot: h.slot.toString() });
      }
    }
    for (const id of await reader.capsuleIds()) {
      try {
        const { record } = await reader.capsule(id);
        if (round >= record.expiresRound) continue;
        // The next transaction executes in round + 1, which must precede the deadline.
        if (record.stage === STAGE.NOMINATING && round + 1n < record.nominationDeadline) await nominate(id, record);
        if (record.stage >= STAGE.ANCHORED) await takeCustody(id, record);
        if (record.stage === STAGE.ACTIVE && record.requested) await release(id, record);
      } catch (e) {
        if (process.env.DEBUG) console.error(`capsule ${id}:`, e instanceof Error ? e.message : e);
      }
    }
  }

  let running = true;
  const loop = (async () => {
    while (running) {
      await tick().catch(e => { if (process.env.DEBUG) console.error(e instanceof Error ? e.message : e); });
      await sleep(cfg.pollMs);
    }
  })();

  return {
    address: member.addr.toString(),
    async stop() {
      running = false;
      await loop;
      for (const h of held.values()) h.custodian.dispose();
      held.clear();
    },
  };
}

function env(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const worker = await startWorker({
    pins: {
      genesisHash: env('GENESIS_HASH'), appId: BigInt(env('APP_ID')), beaconAppId: BigInt(env('BEACON_APP_ID')),
      maxRoundAgeMs: Number(process.env.MAX_ROUND_AGE_MS ?? 30_000),
    },
    algod: { server: env('ALGOD_SERVER'), token: process.env.ALGOD_TOKEN ?? '',
      ...(process.env.ALGOD_PORT ? { port: Number(process.env.ALGOD_PORT) } : {}) },
    memberMnemonic: env('MEMBER_MNEMONIC'),
    vrfSecretKey: Buffer.from(env('VRF_SECRET_KEY'), 'base64'),
    nominationSeed: Buffer.from(env('NOMINATION_SEED'), 'base64'),
    relayerMnemonic: env('RELAYER_MNEMONIC'),
    pollMs: Number(process.env.POLL_MS ?? 2_000),
    event: e => console.log(JSON.stringify(e)),
  });
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.on(signal, () => void worker.stop().then(() => process.exit(0)));
  }
  console.log(JSON.stringify({ ready: worker.address }));
}
