import { sha256 } from '@noble/hashes/sha2.js';
import { ABIType, encodeUint64 } from 'algosdk';
import { encode } from 'keepsake-crypto/dist/src/crypto.js';
import { microAlgo } from '@algorandfoundation/algokit-utils';
import {
  APP_SPEC, CapsuleRecordFromTuple, MemberFromTuple, SeatFromTuple, type CapsuleRecord, type EpochCommitteeClient, type Member, type Seat,
} from '../smart_contracts/artifacts/epoch_committee/EpochCommitteeClient.js';
import { ChainReader, hex, type ChainPins } from './chain.js';

/**
 * Off-chain side of the EpochCommittee app (docs/design.md): its round windows, shared message
 * formats, seat ordering, and handover messages posted as chunks and rebuilt from block data.
 */
export type { CapsuleRecord, Member, Seat };
export interface EpochParams {
  epochRounds: bigint; nominationRounds: bigint; handoverRounds: bigint;
  shareThreshold: bigint; bucketRounds: bigint; bucketLead: bigint; genesisCommittee: bigint;
}

const u64 = (n: bigint) => Buffer.from(encodeUint64(n));
const sha = (...parts: Uint8Array[]) => { const h = sha256.create(); for (const p of parts) h.update(p); return Buffer.from(h.digest()); };
const struct = (name: string) => ABIType.from(`(${APP_SPEC.structs[name]!.map(f => f.type).join(',')})`);
const SEAT = struct('Seat'), MEMBER = struct('Member'), CAPSULE = struct('CapsuleRecord');

/** `f` over `items`, at most `limit` at a time: a committee's worth of box reads at once trips public nodes' rate limits. */
async function mapLimited<T, R>(items: T[], f: (item: T) => Promise<R>, limit = 8): Promise<R[]> {
  const out: R[] = [];
  for (let i = 0; i < items.length; i += limit) out.push(...await Promise.all(items.slice(i, i + limit).map(f)));
  return out;
}

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

/** VRF input for one sortition ticket of a member for committee c; must match `nominate`. */
export const nominationAlpha = (appId: bigint, committee: bigint, ticket: bigint, seed: Uint8Array) =>
  sha(Buffer.from('ecpss/nominate/v2'), u64(appId), u64(committee), u64(ticket), seed);

/** A member's bond counted in epoch e's nominations: changes count from the epoch after they were made. */
export const bondAt = (m: Member, epoch: bigint) => (m.bondEpoch < epoch ? m.nextBond : m.bond);

/** How many tickets weight w holds out of `total` bond: one per total / totalTickets, the last one partial. */
export const ticketCount = (w: bigint, total: bigint, totalTickets: bigint) => (total === 0n ? 0n : (w * totalTickets + total - 1n) / total);

/** Whether ticket j wins with VRF rank `rank`; must match `nominate`. A partial ticket wins in proportion. */
export function ticketWins(rank: bigint, ticket: bigint, w: bigint, total: bigint, totalTickets: bigint, threshold: bigint) {
  const units = w * totalTickets, used = ticket * total;
  if (used >= units) return false;
  return rank * total < threshold * (units - used < total ? units - used : total);
}

/** HPKE info/AAD for a seat's seed, sealed to the nominee's epoch key. */
export const seatSeedContext = (pins: ChainPins, committee: bigint, nominator: bigint, ticket: bigint) => encode([
  'ecpss/seat-seed/v2', pins.genesisHash, pins.appId.toString(), committee.toString(), nominator.toString(), ticket.toString(),
]);

/**
 * What a seat's one-time key signs to claim it for `holder` (a 32-byte account public key): the committee's public
 * state it received (ecpss `stateDigest`) and its message's dealings root (fraud.ts), which it answers for with its
 * bond; must match `claim`. Without the root, the prefix a vault signs once it has built the dealings.
 */
export const claimMessage = (appId: bigint, committee: bigint, nominator: bigint, ticket: bigint, holder: Uint8Array, stateDigest: Uint8Array,
  dealingsRoot: Uint8Array = new Uint8Array()) =>
  Buffer.concat([Buffer.from('ecpss/claim/v3'), u64(appId), u64(committee), u64(nominator), u64(ticket), holder, stateDigest, dealingsRoot]);

// A chunk is four argument parts and the note. Arguments total 16,384 bytes: selector 4 + three uint64 24 + four
// 2-byte length prefixes 8 leave 16,348 bytes of data; the note holds 4,096.
const ARG_OVERHEAD = 36, PART = 4_087, NOTE = 4_096;
const SIG_BUDGET = 2_500; // The contract's ensureBudget before ed25519verify_bare in `claim`.
export const CHUNK = 4 * PART + NOTE;

/** The fee measured on LocalNet (docs/results.md): 1,000 µAlgo plus 0.1 µAlgo per byte beyond 2,048 argument and 1,024 note bytes. */
// ponytail: measured on an idle LocalNet; read the network's actual fee rule before TestNet.
export const chunkFee = (argBytes: number, noteBytes: number) =>
  1_000 + Math.ceil((Math.max(0, argBytes - 2_048) + Math.max(0, noteBytes - 1_024)) / 10);

const chunks = (message: Uint8Array) => Array.from({ length: Math.max(1, Math.ceil(message.length / CHUNK)) }, (_, i) => {
  const c = message.subarray(i * CHUNK, (i + 1) * CHUNK);
  const parts = [0, 1, 2, 3].map(j => c.subarray(j * PART, (j + 1) * PART));
  return { parts, note: c.subarray(4 * PART) };
});

/**
 * Posts a seat's message in chunks and finalizes it, as the seat's holder. With `claim`, the seat is claimed first in
 * the same atomic group: the claim sets the holder the chunks check. Up to 16 calls per group, so a message of up to 14
 * chunks (about 280 KB) takes a single group: one round and one confirmation per seat.
 */
export async function postMessage(app: EpochCommitteeClient, sender: string, seat: SeatId & { committee: bigint }, message: Uint8Array,
  claim?: { holder: string; stateDigest: Uint8Array; dealingsRoot: Uint8Array; signature: Uint8Array }) {
  const { committee, nominator, ticket } = seat;
  type Group = ReturnType<EpochCommitteeClient['newGroup']>;
  // The claim's signature check needs SIG_BUDGET; a group pools 700 opcodes per app call, and each budget top-up the
  // contract adds is an inner call the claim's fee pays for.
  const groupCalls = Math.min(16, 2 + chunks(message).length);
  const claimFee = 1_000 * (1 + Math.max(0, Math.ceil((SIG_BUDGET + 110 - 700 * groupCalls) / 700)));
  const calls: ((g: Group) => void)[] = [
    ...(claim ? [(g: Group) => void g.claim({ sender, staticFee: microAlgo(claimFee), args: { committee, nominator, ticket, ...claim } })] : []),
    ...chunks(message).map(({ parts, note }) => (g: Group) => void g.postChunk({ sender, note,
      staticFee: microAlgo(chunkFee(ARG_OVERHEAD + parts.reduce((n, p) => n + p.length, 0), note.length)),
      args: { committee, nominator, ticket, a: parts[0]!, b: parts[1]!, c: parts[2]!, d: parts[3]! } })),
    (g: Group) => void g.finalize({ sender, args: { committee, nominator, ticket } }),
  ];
  for (let i = 0; i < calls.length; i += 16) {
    const group = app.newGroup(); // Typed composer methods add to the group in place.
    for (const add of calls.slice(i, i + 16)) add(group);
    await group.send();
  }
}

/** A seat on chain: its nominator's winning ticket. */
export interface SeatId { nominator: bigint; ticket: bigint }
/** A seat in committee order: seats are numbered 1..n by their one-time signing keys. */
export interface OrderedSeat extends SeatId { seat: number; value: Seat }
const seatName = (s: SeatId) => `${s.nominator}:${s.ticket}`;

export class EpochReader extends ChainReader {
  constructor(algod: ChainReader['algod'], pins: ChainPins, readonly params: EpochParams, readonly postChunkSelector: Uint8Array) {
    super(algod, pins);
  }

  /** Committee c's sortition seed: the block seed of its nomination epoch's first round, as `nominate` reads it. */
  async seed(committee: bigint): Promise<Uint8Array> {
    return (await this.algod.block((committee - 1n) * this.params.epochRounds).do()).block.header.seed;
  }

  /** Every enrolled member, by index. */
  async members(): Promise<Member[]> {
    await this.lastRound();
    const { boxes } = await this.algod.getApplicationBoxes(this.pins.appId).do();
    const indexes = boxes.map(b => Buffer.from(b.name)).filter(n => n.length === 9 && n[0] === 0x6d /* m */).map(n => n.readBigUInt64BE(1));
    const all = await mapLimited(indexes, async i => [i, MemberFromTuple(MEMBER.decode((await this.box(Buffer.from('m'), u64(i))).value) as never)] as const);
    return all.sort((a, b) => Number(a[0] - b[0])).map(([, m]) => m);
  }

  /**
   * Committee c's seats in key order. Seats that repeat another seat's signing key or ElGamal key are all dropped:
   * a nominator copying an honest seat's keys can only spend its own nomination to cancel that seat.
   */
  async seats(committee: bigint): Promise<OrderedSeat[]> {
    const all = await mapLimited(await this.seatIds(committee), async id =>
      ({ ...id, value: SeatFromTuple(SEAT.decode((await this.box(Buffer.from('n'), u64(committee), u64(id.nominator), u64(id.ticket))).value) as never) }));
    const keys = all.flatMap(s => [hex(s.value.sigKey), hex(s.value.epk)]);
    const unique = (k: Uint8Array) => keys.indexOf(hex(k)) === keys.lastIndexOf(hex(k));
    return all.filter(s => unique(s.value.sigKey) && unique(s.value.epk))
      .sort((a, b) => Buffer.compare(Buffer.from(a.value.sigKey), Buffer.from(b.value.sigKey)))
      .map((s, i) => ({ seat: i + 1, ...s }));
  }

  /** One seat's record. */
  async seat(committee: bigint, id: SeatId): Promise<Seat> {
    await this.lastRound();
    return SeatFromTuple(SEAT.decode((await this.box(Buffer.from('n'), u64(committee), u64(id.nominator), u64(id.ticket))).value) as never);
  }

  async capsuleRecord(id: bigint): Promise<CapsuleRecord> {
    await this.lastRound();
    return CapsuleRecordFromTuple(CAPSULE.decode((await this.box(Buffer.from('x'), u64(id))).value) as never);
  }

  /** Every registered capsule still on chain (deleted after expiry). */
  async capsuleRecords(): Promise<{ id: bigint; record: CapsuleRecord }[]> {
    await this.lastRound();
    const { boxes } = await this.algod.getApplicationBoxes(this.pins.appId).do();
    const ids = boxes.map(b => Buffer.from(b.name)).filter(n => n.length === 9 && n[0] === 0x78 /* x */).map(n => n.readBigUInt64BE(1));
    return mapLimited(ids, async id => ({ id, record: await this.capsuleRecord(id) }));
  }

  /** Every seat box of committee c (or of every committee), including seats dropped from the ordering: for deletion. */
  async seatIds(committee?: bigint): Promise<(SeatId & { committee: bigint })[]> {
    await this.lastRound();
    const { boxes } = await this.algod.getApplicationBoxes(this.pins.appId).do();
    return boxes.map(b => Buffer.from(b.name)).filter(n => n.length === 25 && n[0] === 0x6e /* n */)
      .map(n => ({ committee: n.readBigUInt64BE(1), nominator: n.readBigUInt64BE(9), ticket: n.readBigUInt64BE(17) }))
      .filter(s => committee === undefined || s.committee === committee);
  }

  /**
   * Committee c's finalized messages, rebuilt from the blocks of its handover window through algod alone (one scan
   * for all seats) and checked against each seat's on-chain running digest. Seats whose message does not match are
   * left out. Non-archival nodes keep only recent blocks, so read promptly.
   */
  async messages(committee: bigint, seats: OrderedSeat[]): Promise<Map<number, Buffer>> {
    const [from, to] = windows(this.params, committee).handover;
    const last = await this.lastRound();
    const log = new Map<string, { digest: Buffer; pieces: Buffer[] }>();
    for (let r = from; r <= (to < last ? to : last); r++) {
      for (const s of (await this.algod.block(r).do()).block.payset) {
        const txn = s.signedTxn.signedTxn.txn, call = txn.applicationCall;
        if (call?.appIndex !== this.pins.appId || call.appArgs.length !== 8) continue;
        const [selector, c, n, k, ...parts] = call.appArgs.map(a => Buffer.from(a));
        if (!selector!.equals(Buffer.from(this.postChunkSelector)) || c!.readBigUInt64BE(0) !== committee) continue;
        const data = parts.map(p => p.subarray(2)); // byte[] arguments carry a 2-byte length prefix.
        const name = seatName({ nominator: n!.readBigUInt64BE(0), ticket: k!.readBigUInt64BE(0) });
        const entry = log.get(name) ?? { digest: Buffer.alloc(32), pieces: [] };
        entry.digest = sha(entry.digest, ...data.map(p => sha(p)), sha(txn.note));
        entry.pieces.push(...data, Buffer.from(txn.note));
        log.set(name, entry);
      }
    }
    const out = new Map<number, Buffer>();
    for (const s of seats) {
      const entry = log.get(seatName(s));
      if (s.value.finalized && entry?.digest.equals(Buffer.from(s.value.digest))) out.set(s.seat, Buffer.concat(entry.pieces));
    }
    return out;
  }
}
