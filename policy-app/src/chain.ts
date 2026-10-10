import { createHash } from 'node:crypto';
import { ABIType, type Algodv2, encodeUint64 } from 'algosdk';
import { SUITE, check, encode } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/crypto.js';
import {
  manifestHash,
  type AccessRequest, type AuthorizationSource, type CommitteeSelection, type CustodianDescriptor, type Deposit,
  type Manifest, type Release,
} from 'algorand-ephemeral-capsule-crypto-spike/dist/src/protocol.js';
import {
  APP_SPEC, CapsuleRecordFromTuple, MemberFromTuple, SlotFromTuple, type CapsuleRecord, type Member, type Slot,
} from '../smart_contracts/artifacts/capsule_policy/CapsulePolicyClient.js';

export type { CapsuleRecord, Member, Slot };
export const STAGE = { AWAITING_SEED: 0n, NOMINATING: 1n, SELECTED: 2n, DEPOSITING: 3n, ANCHORED: 4n, ACTIVE: 5n } as const;
export const HIDDEN_MODE = 'algorand-hidden-v1';
export const BATCH = 7; // Slots per postDeposits / deleteSlots call.
export const slotRange = (record: { slotCount: bigint }) => Array.from({ length: Number(record.slotCount) }, (_, k) => BigInt(k));

const struct = (name: string) => ABIType.from(`(${APP_SPEC.structs[name]!.map(f => f.type).join(',')})`);
const RECORD = struct('CapsuleRecord');
const SLOT = struct('Slot');
const MEMBER = struct('Member');
const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');
const u64 = (n: bigint) => Buffer.from(encodeUint64(n));
export const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
export const b64url = (b: Uint8Array) => Buffer.from(b).toString('base64url');

/** Values a custodian or client pins out of band; never taken from the data it is checking. */
export interface ChainPins {
  genesisHash: string; // base64, as algod reports it
  appId: bigint;
  beaconAppId: bigint;
  maxRoundAgeMs: number; // 0 disables the staleness check (dev-mode LocalNet only produces blocks on demand)
}

/**
 * Reads confirmed policy state from ONE algod node the operator trusts. Fails closed on a wrong network, a node
 * that is catching up or stale, or a missing box. Not a light client: a lying node can still lie.
 */
export class ChainReader {
  constructor(readonly algod: Algodv2, readonly pins: ChainPins) {}

  async lastRound(): Promise<bigint> {
    const [version, status] = await Promise.all([this.algod.versionsCheck().do(), this.algod.status().do()]);
    check(Buffer.from(version.genesisHashB64).toString('base64') === this.pins.genesisHash, 'Wrong network');
    check(status.catchupTime === 0n && !status.stoppedAtUnsupportedRound, 'Node not synced');
    check(this.pins.maxRoundAgeMs === 0 || Number(status.timeSinceLastRound / 1_000_000n) <= this.pins.maxRoundAgeMs,
      'Node state is stale');
    return status.lastRound;
  }

  protected box(...parts: Uint8Array[]) {
    return this.algod.getApplicationBoxByName(this.pins.appId, Buffer.concat(parts)).do();
  }

  /** The capsule record and the confirmed round algod read it at. */
  async capsule(capsuleId: bigint): Promise<{ record: CapsuleRecord; round: bigint }> {
    await this.lastRound();
    const box = await this.box(Buffer.from('c'), u64(capsuleId));
    return { record: CapsuleRecordFromTuple(RECORD.decode(box.value) as never), round: box.round };
  }

  /** Slots by index (default: all of them); a slot box that does not exist (never nominated) reads as empty. */
  async slots(capsuleId: bigint, indexes: readonly bigint[]): Promise<Slot[]> {
    await this.lastRound();
    return Promise.all(indexes.map(async k => {
      const value = await this.box(Buffer.from('s'), u64(capsuleId), u64(k)).then(b => b.value, (e: { response?: { status?: number } }) => {
        if (e.response?.status === 404) return new Uint8Array(SLOT.byteLen());
        throw e;
      });
      return SlotFromTuple(SLOT.decode(value) as never);
    }));
  }

  async member(index: bigint): Promise<Member> {
    return MemberFromTuple(MEMBER.decode((await this.box(Buffer.from('m'), u64(index))).value) as never);
  }

  /** Member `index`'s nomination key for `epoch`, or undefined if it never posted one (or it was rotated out). */
  async nominationKey(epoch: bigint, index: bigint): Promise<Uint8Array | undefined> {
    const value = await this.box(Buffer.from('k'), u64(index), u64(epoch % 3n)).then(b => Buffer.from(b.value),
      (e: { response?: { status?: number } }) => { if (e.response?.status !== 404) throw e; });
    return value && value.readBigUInt64BE(0) === epoch ? value.subarray(8, 40) : undefined; // EpochKey: uint64 || byte[32]
  }

  // ponytail: lists every box on each call; use an indexer or event feed beyond a demo-sized app.
  async capsuleIds(): Promise<bigint[]> {
    await this.lastRound();
    const { boxes } = await this.algod.getApplicationBoxes(this.pins.appId).do();
    return boxes.map(b => Buffer.from(b.name)).filter(n => n.length === 9 && n[0] === 0x63 /* c */)
      .map(n => n.readBigUInt64BE(1)).sort((a, b) => (a < b ? -1 : 1));
  }
}

/** Per-capsule authorization from fresh chain state: the anchored manifest and the one bound recipient request. */
export function chainAuthorization(reader: ChainReader, capsuleId: bigint): AuthorizationSource {
  return {
    async assertAuthorized(anchor, request) {
      const { record, round } = await reader.capsule(capsuleId);
      check(hex(record.manifestHash) === anchor, 'Wrong capsule');
      check(record.stage === STAGE.ACTIVE && record.requested, 'No on-chain request');
      check(b64url(record.requestId) === request.requestId, 'Request ID not bound on-chain');
      check(b64url(record.recipientKey) === request.recipientPublicKey, 'Recipient key not bound on-chain');
      return round;
    },
  };
}

// --- Messages shared by members, holders, the sender and the contract ---

/** VRF input for member sortition on (capsule, slot); must match `nominate` in the contract. */
export const nominationAlpha = (appId: bigint, capsuleId: bigint, slot: bigint, randomness: Uint8Array) =>
  createHash('sha256').update('capsule/nominate/v1').update(u64(appId)).update(u64(capsuleId)).update(u64(slot))
    .update(randomness).digest();

/** VRF output → rank compared with a contract's threshold (nominatorThreshold, ticketThreshold); lower wins. */
export const vrfRank = (output: Uint8Array) => Buffer.from(output).readBigUInt64BE(0);

/** HPKE info/AAD for the holder-key seed sealed to a member's nomination key. */
export const nominationContext = (pins: ChainPins, capsuleId: bigint, slot: bigint) => encode([
  'capsule/nomination/v1', pins.genesisHash, pins.appId.toString(), capsuleId.toString(), slot.toString(),
]);

const slotHeader = (appId: bigint, capsuleId: bigint, slot: bigint) => Buffer.concat([u64(appId), u64(capsuleId), u64(slot)]);

/** Bodies for Custodian.signChainMessage; the contract prepends the same text prefixes. */
export const ackBody = (appId: bigint, capsuleId: bigint, slot: bigint, record: CapsuleRecord) =>
  Buffer.concat([slotHeader(appId, capsuleId, slot), record.manifestHash]);
export const releaseBody = (appId: bigint, capsuleId: bigint, slot: bigint, record: CapsuleRecord,
  enc: Uint8Array, ciphertext: Uint8Array, signature: Uint8Array) =>
  Buffer.concat([slotHeader(appId, capsuleId, slot), record.requestId, record.recipientKey, enc, ciphertext, signature]);

// --- Spike objects reconstructed from chain state ---

const slotId = (k: number) => `slot-${k}`;

/** The committee is the filled slots, in slot order; `slots` is every slot of the capsule. */
export const committeeSlots = (slots: readonly Slot[]) => slots.flatMap((s, k) => (s.filled ? [{ k, s }] : []));

export function hiddenSelection(pins: ChainPins, capsuleId: bigint, record: CapsuleRecord, slots: readonly Slot[]): CommitteeSelection {
  check(record.stage >= STAGE.SELECTED && slots.length === Number(record.slotCount), 'Nominations not closed');
  const custodians: CustodianDescriptor[] = committeeSlots(slots).map(({ k, s }) => ({
    id: slotId(k), encryptionPublicKey: b64url(s.holderEncKey), signingPublicKey: b64url(Buffer.concat([SPKI_ED25519, s.holderSigKey])),
  }));
  return { mode: HIDDEN_MODE, epoch: record.seedRound.toString(), custodians,
    registryReference: `beacon:${pins.beaconAppId};request:${capsuleId};registry:${record.registrySize};randomness:${hex(record.randomness)}` };
}

/**
 * The full manifest from chain data alone. Throws unless it hashes to the anchored manifest hash, so holders and
 * recipients never trust a manifest supplied by the sender or a storage server.
 */
export function manifestFromChain(pins: ChainPins, capsuleId: bigint, record: CapsuleRecord, slots: readonly Slot[]): Manifest {
  check(record.stage >= STAGE.ANCHORED, 'Manifest not anchored');
  const m: Manifest = {
    suite: SUITE, threshold: Number(record.threshold),
    policy: { network: pins.genesisHash, applicationId: pins.appId.toString(), capsuleId: capsuleId.toString(),
      recipient: record.recipient, openRound: record.openRound.toString(), expiresRound: record.expiresRound.toString() },
    committee: hiddenSelection(pins, capsuleId, record, slots),
    commitments: committeeSlots(slots).map(({ s }) => hex(s.commitment)), payloadHash: hex(record.payloadHash),
  };
  check(manifestHash(m) === hex(record.manifestHash), 'Anchored hash does not match chain data');
  return m;
}

export const depositFromSlot = (k: number, s: Slot): Deposit =>
  ({ custodianId: slotId(k), enc: b64url(s.deposit.subarray(0, 32)), ciphertext: b64url(s.deposit.subarray(32)) });

export const depositBytes = (d: Deposit) => Buffer.concat([Buffer.from(d.enc, 'base64url'), Buffer.from(d.ciphertext, 'base64url')]);

export const requestFromChain = (record: CapsuleRecord): AccessRequest =>
  ({ manifestHash: hex(record.manifestHash), requestId: b64url(record.requestId), recipientPublicKey: b64url(record.recipientKey) });

export const releaseFromSlot = (k: number, s: Slot, record: CapsuleRecord): Release => ({
  ...requestFromChain(record), custodianId: slotId(k),
  enc: b64url(s.releaseEnc), ciphertext: b64url(s.releaseCiphertext), signature: b64url(s.releaseSignature),
});
