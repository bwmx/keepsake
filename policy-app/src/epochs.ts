import { createHash } from 'node:crypto';
import { ABIType, encodeUint64 } from 'algosdk';
import { encode } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/crypto.js';
import { microAlgo } from '@algorandfoundation/algokit-utils';
import {
  APP_SPEC, CommitteeFromTuple, SeatFromTuple, type Committee, type EpochCommitteeClient, type Seat,
} from '../smart_contracts/artifacts/epoch_committee/EpochCommitteeClient.js';
import { ChainReader, hex, type ChainPins } from './chain.js';

/**
 * Off-chain side of the EpochCommittee app (PAPER_ALIGNMENT_PLAN.md Phase 1): its round windows, shared message
 * formats, seat ordering, and handover messages posted as chunks and rebuilt from block data.
 */
export type { Committee, Seat };
export interface EpochParams {
  epochRounds: bigint; nominationRounds: bigint; handoverRounds: bigint;
  shareThreshold: bigint; bucketRounds: bigint; bucketLead: bigint; genesisCommittee: bigint;
}

const u64 = (n: bigint) => Buffer.from(encodeUint64(n));
const sha = (...parts: Uint8Array[]) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
const struct = (name: string) => ABIType.from(`(${APP_SPEC.structs[name]!.map(f => f.type).join(',')})`);
const SEAT = struct('Seat'), COMMITTEE = struct('Committee');

/** Inclusive round windows of epoch e: nominations for committee e + 1, then committee e's handover. */
export const windows = (p: EpochParams, epoch: bigint) => {
  const start = epoch * p.epochRounds;
  return { seedRound: start, nominate: [start + 1n, start + p.nominationRounds] as const,
    handover: [start + p.nominationRounds + 1n, start + p.nominationRounds + p.handoverRounds] as const };
};

/**
 * Buckets committee k must hold: those whose window [b·W, (b+1)·W) has not ended when epoch k starts and that start
 * before epoch k + 1 ends plus the lead, so senders can encrypt to a bucket before its window opens.
 */
export function bucketsNeeded(p: EpochParams, k: bigint): bigint[] {
  const first = (k * p.epochRounds) / p.bucketRounds, last = ((k + 1n) * p.epochRounds + p.bucketLead - 1n) / p.bucketRounds;
  return Array.from({ length: Number(last - first + 1n) }, (_, i) => first + BigInt(i));
}

/**
 * What committee c's handover carries: buckets still needed are re-shared, newly needed ones created, and the rest
 * dropped, never re-dealt. The genesis committee holds nothing and creates. A lost bucket is never recreated.
 */
export function handoverBuckets(p: EpochParams, c: bigint) {
  const next = bucketsNeeded(p, c + 1n);
  if (c === p.genesisCommittee) return { live: [], create: next };
  const now = new Set(bucketsNeeded(p, c));
  return { live: next.filter(b => now.has(b)), create: next.filter(b => !now.has(b)) };
}

/** VRF input for a member's sortition for committee c; must match `nominate`. */
export const nominationAlpha = (appId: bigint, committee: bigint, seed: Uint8Array) =>
  sha(Buffer.from('ecpss/nominate/v1'), u64(appId), u64(committee), seed);

/** HPKE info/AAD for a seat's seed, sealed to the nominee's epoch key. */
export const seatSeedContext = (pins: ChainPins, committee: bigint, nominator: bigint) => encode([
  'ecpss/seat-seed/v1', pins.genesisHash, pins.appId.toString(), committee.toString(), nominator.toString(),
]);

/** What a seat's one-time key signs to claim it for `holder` (a 32-byte account public key); must match `claim`. */
export const claimMessage = (appId: bigint, committee: bigint, nominator: bigint, holder: Uint8Array) =>
  Buffer.concat([Buffer.from('ecpss/claim/v1'), u64(appId), u64(committee), u64(nominator), holder]);

// A chunk is four argument parts and the note. Arguments total 16,384 bytes: selector 4 + two uint64 16 + four
// 2-byte length prefixes 8 leave 16,356 bytes of data; the note holds 4,096.
const PART = 4_089, NOTE = 4_096;
export const CHUNK = 4 * PART + NOTE;

/** The fee measured on LocalNet in Phase 0: 1,000 µAlgo plus 0.1 µAlgo per byte beyond 2,048 argument and 1,024 note bytes. */
// ponytail: measured on an idle LocalNet; read the network's actual fee rule before TestNet.
export const chunkFee = (argBytes: number, noteBytes: number) =>
  1_000 + Math.ceil((Math.max(0, argBytes - 2_048) + Math.max(0, noteBytes - 1_024)) / 10);

const chunks = (message: Uint8Array) => Array.from({ length: Math.max(1, Math.ceil(message.length / CHUNK)) }, (_, i) => {
  const c = message.subarray(i * CHUNK, (i + 1) * CHUNK);
  const parts = [0, 1, 2, 3].map(j => c.subarray(j * PART, (j + 1) * PART));
  return { parts, note: c.subarray(4 * PART) };
});

/** Posts a claimed seat's message in chunks (16 calls per group), then finalizes it. The caller is the seat's holder. */
export async function postMessage(app: EpochCommitteeClient, sender: string, committee: bigint, nominator: bigint, message: Uint8Array) {
  const calls = chunks(message);
  for (let i = 0; i < calls.length; i += 16) {
    const group = app.newGroup(); // Typed composer methods add to the group in place.
    for (const { parts, note } of calls.slice(i, i + 16)) {
      group.postChunk({ sender, note, staticFee: microAlgo(chunkFee(28 + parts.reduce((n, p) => n + p.length, 0), note.length)),
        args: { committee, nominator, a: parts[0]!, b: parts[1]!, c: parts[2]!, d: parts[3]! } });
    }
    await group.send();
  }
  await app.send.finalize({ sender, args: { committee, nominator } });
}

/** A seat in committee order: seats are numbered 1..n by their one-time signing keys. */
export interface OrderedSeat { seat: number; nominator: bigint; value: Seat }

export class EpochReader extends ChainReader {
  constructor(algod: ChainReader['algod'], pins: ChainPins, readonly params: EpochParams, readonly postChunkSelector: Uint8Array) {
    super(algod, pins);
  }

  async committee(committee: bigint): Promise<Committee | undefined> {
    await this.lastRound();
    return this.box(Buffer.from('c'), u64(committee)).then(b => CommitteeFromTuple(COMMITTEE.decode(b.value) as never),
      (e: { response?: { status?: number } }) => { if (e.response?.status !== 404) throw e; return undefined; });
  }

  /**
   * Committee c's seats in key order. Seats that repeat another seat's signing key or ElGamal key are all dropped:
   * a nominator copying an honest seat's keys can only spend its own nomination to cancel that seat.
   */
  async seats(committee: bigint): Promise<OrderedSeat[]> {
    const all = await Promise.all((await this.nominators(committee)).map(async nominator =>
      ({ nominator, value: SeatFromTuple(SEAT.decode((await this.box(Buffer.from('n'), u64(committee), u64(nominator))).value) as never) })));
    const keys = all.flatMap(s => [hex(s.value.sigKey), hex(s.value.epk)]);
    const unique = (k: Uint8Array) => keys.indexOf(hex(k)) === keys.lastIndexOf(hex(k));
    return all.filter(s => unique(s.value.sigKey) && unique(s.value.epk))
      .sort((a, b) => Buffer.compare(Buffer.from(a.value.sigKey), Buffer.from(b.value.sigKey)))
      .map((s, i) => ({ seat: i + 1, ...s }));
  }

  /** Every nominator with a seat box in committee c, including seats dropped from the ordering (for deletion). */
  async nominators(committee: bigint): Promise<bigint[]> {
    await this.lastRound();
    const prefix = Buffer.concat([Buffer.from('n'), u64(committee)]);
    const { boxes } = await this.algod.getApplicationBoxes(this.pins.appId).do();
    return boxes.map(b => Buffer.from(b.name)).filter(n => n.length === 17 && n.subarray(0, 9).equals(prefix)).map(n => n.readBigUInt64BE(9));
  }

  /**
   * Committee c's finalized messages, rebuilt from the blocks of its handover window through algod alone (one scan
   * for all seats) and checked against each seat's on-chain running digest. Seats whose message does not match are
   * left out. Non-archival nodes keep only recent blocks, so read promptly.
   */
  async messages(committee: bigint, seats: OrderedSeat[]): Promise<Map<number, Buffer>> {
    const [from, to] = windows(this.params, committee).handover;
    const last = await this.lastRound();
    const log = new Map<bigint, { digest: Buffer; pieces: Buffer[] }>();
    for (let r = from; r <= (to < last ? to : last); r++) {
      for (const s of (await this.algod.block(r).do()).block.payset) {
        const txn = s.signedTxn.signedTxn.txn, call = txn.applicationCall;
        if (call?.appIndex !== this.pins.appId || call.appArgs.length !== 7) continue;
        const [selector, c, n, ...parts] = call.appArgs.map(a => Buffer.from(a));
        if (!selector!.equals(Buffer.from(this.postChunkSelector)) || c!.readBigUInt64BE(0) !== committee) continue;
        const data = parts.map(p => p.subarray(2)); // byte[] arguments carry a 2-byte length prefix.
        const entry = log.get(n!.readBigUInt64BE(0)) ?? { digest: Buffer.alloc(32), pieces: [] };
        entry.digest = sha(entry.digest, ...data.map(p => sha(p)), sha(txn.note));
        entry.pieces.push(...data, Buffer.from(txn.note));
        log.set(n!.readBigUInt64BE(0), entry);
      }
    }
    const out = new Map<number, Buffer>();
    for (const s of seats) {
      const entry = log.get(s.nominator);
      if (s.value.finalized && entry?.digest.equals(Buffer.from(s.value.digest))) out.set(s.seat, Buffer.concat(entry.pieces));
    }
    return out;
  }
}
