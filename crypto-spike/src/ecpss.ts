import { createPrivateKey, createPublicKey, hkdfSync, sign, type KeyObject } from 'node:crypto';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { check } from './crypto.js';
import {
  ORDER, aggregate, combine, combinePartials, deal, dealingSize, decodeDealing, encapsulate, encodeDealing, lagrange,
  partial, point, randomScalar, seatCommitment, validDealings, verifyG1, verifyPartial,
  type Dealing, type G1Point, type G2Point, type Partial, type Proof,
} from './pvss.js';

/**
 * UNREVIEWED. Evolving-committee proactive secret sharing (eprint 2020/464 §3) over the pairing re-sharing in pvss.ts,
 * holding bucket keys as PAPER_ALIGNMENT_PLAN.md proposes: committee-generated keys, one handover message per holder
 * per epoch, reconstruction, and the capsule KEM. Chain-agnostic; policy-app carries the messages.
 *
 * Committees are numbered; committee c hands over to committee c + 1. A seat is a holder's evaluation point: seats are
 * numbered 1..n in the order of their one-time signing keys (§3.1.2 step 5 orders by ephemeral key).
 */

/** Per live bucket, the committee's polynomial commitments A_0..A_(t-1). A_0 is the bucket's public key P = s·g1. */
export type Public = Map<bigint, G1Point[]>;
/** A holder's private state: its seat, its ephemeral ElGamal scalar and one share per live bucket. */
export interface Holder { seat: number; x: bigint; shares: Map<bigint, G2Point> }
/** One holder's handover: a re-sharing per live bucket it holds and a fresh contribution per bucket being created. */
export interface Message { reshares: Map<bigint, Dealing>; contributions: Map<bigint, Dealing> }

const u64 = (n: bigint | number) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
/** Binds a new-key contribution's proof of knowledge to its committee and bucket (the dealer seat is added by pvss). */
const context = (committee: bigint, bucket: bigint) => Buffer.concat([Buffer.from('ecpss/contribution/v1'), u64(committee), u64(bucket)]);

/** A seat's one-time keys, derived from the nominator's 32-byte seed: the BLS ElGamal key pair and an Ed25519 key. */
export function seatKeys(seed: Uint8Array) {
  check(seed.length === 32, 'Expected a 32-byte seed');
  const okm = (info: string, length: number) => Buffer.from(hkdfSync('sha256', seed, 'ecpss/seat-keys/v1', info, length));
  const x = BigInt(`0x${okm('bls12-381', 48).toString('hex')}`) % ORDER;
  check(x !== 0n, 'Degenerate seed');
  const signingKey: KeyObject = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), okm('ed25519', 32)]), format: 'der', type: 'pkcs8',
  });
  const sigKey = createPublicKey(signingKey).export({ format: 'der', type: 'spki' }).subarray(12);
  return { x, epk: point.g2(x), sigKey, sign: (message: Uint8Array) => sign(null, message, signingKey) };
}

/** The holder's single message for this epoch (§3.1.3). Afterwards the holder must erase its state. */
export function handover(h: Holder, pub: Public, committee: bigint, buckets: { live: bigint[]; create: bigint[] },
  next: G2Point[], t: number): Message {
  const reshares = new Map<bigint, Dealing>(), contributions = new Map<bigint, Dealing>();
  for (const b of buckets.live) {
    const share = h.shares.get(b), poly = pub.get(b);
    if (share && poly) reshares.set(b, deal(h.seat, share, seatCommitment(poly, h.seat), next, t));
  }
  for (const b of buckets.create) {
    const z = randomScalar();
    contributions.set(b, deal(h.seat, point.g2(z), point.g1(z), next, t, z, context(committee, b)));
  }
  return { reshares, contributions };
}

export interface Buckets { live: bigint[]; create: bigint[] }
const dealingsFor = (messages: Map<number, Message>, b: bigint, kind: keyof Message) => {
  const seats = [...messages.keys()].sort((x, y) => x - y);
  return seats.map(s => messages.get(s)![kind].get(b)).filter((d, i): d is Dealing => d?.dealer === seats[i]);
};

/**
 * The costly half of receiving committee `committee`'s handover (§3.1.3): per bucket, the seats whose dealings pass, in
 * seat order. Re-sharings are checked against the committee's commitments, new-key contributions against their proofs.
 * Dealings are independent, so callers may check disjoint groups of seats in parallel and merge.
 */
export function validSeats(messages: Map<number, Message>, pub: Public, committee: bigint, buckets: Buckets, next: G2Point[], t: number) {
  const valid = new Map<bigint, number[]>();
  for (const b of buckets.live) {
    const poly = pub.get(b), dealings = dealingsFor(messages, b, 'reshares');
    const prior = new Map(dealings.map(d => [d.dealer, seatCommitment(poly ?? [], d.dealer)] as const));
    valid.set(b, poly ? validDealings(dealings, next, t, { prior }).map(d => d.dealer) : []);
  }
  for (const b of buckets.create) {
    valid.set(b, validDealings(dealingsFor(messages, b, 'contributions'), next, t, { context: context(committee, b) }).map(d => d.dealer));
  }
  return valid;
}

/**
 * The cheap half: per bucket, the first t valid dealings in seat order give the next committee's commitments and, for
 * each of `mine` (next-committee seats this caller holds; a worker passes its own), a share. A live bucket with fewer
 * than t valid re-sharings is lost; an expired bucket is not in `live`, so nobody receives it. `messages` may be
 * partially decoded (commitments and the caller's subshares) once `valid` is known.
 */
export function adopt(messages: Map<number, Message>, valid: Map<bigint, number[]>, buckets: Buckets, t: number, mine: { seat: number; x: bigint }[] = []) {
  const result = { pub: new Map() as Public, lost: [] as bigint[], used: new Map<bigint, number[]>(),
    holders: mine.map(m => ({ seat: m.seat, x: m.x, shares: new Map<bigint, G2Point>() }) as Holder) };
  for (const [kind, list] of [['reshares', buckets.live], ['contributions', buckets.create]] as const) {
    for (const b of list) {
      const seats = (valid.get(b) ?? []).slice(0, t); // A contribution set of t includes at least one honest dealer.
      if (seats.length < t) { result.lost.push(b); continue; }
      const dealings = seats.map(s => messages.get(s)![kind].get(b)!);
      const weights = kind === 'reshares' ? lagrange(seats) : seats.map(() => 1n);
      result.pub.set(b, aggregate(dealings, weights));
      result.used.set(b, seats);
      for (const h of result.holders) h.shares.set(b, combine(h.seat, h.x, dealings, weights));
    }
  }
  return result;
}

/** Everyone's view of committee `committee`'s handover, in this thread: `validSeats` then `adopt`. */
export const receive = (messages: Map<number, Message>, pub: Public, committee: bigint, buckets: Buckets, next: G2Point[], t: number,
  mine: { seat: number; x: bigint }[] = []) => adopt(messages, validSeats(messages, pub, committee, buckets, next, t), buckets, t, mine);

/** §3.1.1: an honest dealer plays t first-committee roles to create a bucket; it must erase the secret it returns. */
export function dealerGenesis(bucket: bigint, next: G2Point[], t: number) {
  const z = Array.from({ length: t }, () => randomScalar());
  const messages = new Map(z.map((zj, j) => [j + 1, {
    reshares: new Map(), contributions: new Map([[bucket, deal(j + 1, point.g2(zj), point.g1(zj), next, t, zj, context(0n, bucket))]]),
  } as Message]));
  return { messages, secret: point.g2(z.reduce((a, b) => a + b, 0n)) };
}

const shareMatches = (share: G2Point, commitment: G1Point) => {
  try {
    return bls.fields.Fp12.eql(bls.pairingBatch([{ g1: point.g1(1n), g2: share }, { g1: commitment.negate(), g2: point.g2(1n) }]), bls.fields.Fp12.ONE);
  } catch {
    return false;
  }
};

/** §3.1.4: the secret from the first t shares that match their public commitments. */
export function reconstruct(poly: G1Point[], shares: { seat: number; share: G2Point }[], t: number): G2Point {
  const valid = shares.filter(s => shareMatches(s.share, seatCommitment(poly, s.seat))).slice(0, t);
  check(valid.length === t, 'Not enough valid shares');
  const w = lagrange(valid.map(s => s.seat));
  return valid.reduce((acc, s, i) => acc.add(s.share.multiply(w[i]!)), point.g2(0n));
}

// --- Capsule KEM over a bucket key ---

const capsuleKey = (k: ReturnType<typeof combinePartials>, u: G1Point, label: Uint8Array) =>
  Buffer.from(hkdfSync('sha256', bls.fields.Fp12.toBytes(k), u.toBytes(), Buffer.concat([Buffer.from('ecpss/capsule-key/v1'), label]), 32));

/** Sender: a 32-byte payload key for a capsule under bucket key P, with u and a proof of r bound to the policy label. */
export function sealCapsuleKey(publicKey: G1Point, label: Uint8Array): { u: G1Point; proof: Proof; key: Buffer } {
  const { u, proof, key } = encapsulate(publicKey, label);
  return { u, proof, key: capsuleKey(key, u, label) };
}

/** Holder: its partial for an authorized capsule. Refuses a u whose proof is not bound to this policy label (replay). */
export function capsulePartial(share: G2Point, commitment: G1Point, u: G1Point, proof: Proof, label: Uint8Array): Partial {
  check(verifyG1(u, proof, label), 'Capsule not bound to this policy');
  return partial(share, commitment, u);
}

/** Recipient: the payload key from the first t partials that verify against the bucket's public commitments. */
export function openCapsuleKey(poly: G1Point[], u: G1Point, label: Uint8Array, parts: { seat: number; p: Partial }[], t: number): Buffer {
  const valid = parts.filter(x => verifyPartial(seatCommitment(poly, x.seat), u, x.p)).slice(0, t);
  check(valid.length === t, 'Not enough valid partials');
  return capsuleKey(combinePartials(valid.map(x => ({ seat: x.seat, d: x.p.d }))), u, label);
}

// --- Wire format: entry count (u16), then per entry bucket (u64), kind (0 re-share, 1 contribution), dealing ---

export function encodeMessage(m: Message): Buffer {
  const entries = [...[...m.reshares].map(([b, d]) => [b, 0, d] as const), ...[...m.contributions].map(([b, d]) => [b, 1, d] as const)];
  const head = Buffer.alloc(2);
  head.writeUInt16BE(entries.length);
  return Buffer.concat([head, ...entries.flatMap(([b, kind, d]) => [u64(b), Buffer.from([kind]), encodeDealing(d)])]);
}

/** Strict decoding of an untrusted message posted for `seat`; n is the next committee's size. `keep`: see decodeDealing. */
export function decodeMessage(bytes: Uint8Array, seat: number, n: number, t: number, keep?: number[]): Message {
  const buf = Buffer.from(bytes);
  check(buf.length >= 2, 'Truncated message');
  const m: Message = { reshares: new Map(), contributions: new Map() };
  let at = 2;
  for (let i = 0; i < buf.readUInt16BE(0); i++) {
    check(buf.length >= at + 9, 'Truncated message');
    const bucket = buf.readBigUInt64BE(at), kind = buf[at + 8];
    check(kind === 0 || kind === 1, 'Unknown entry kind');
    const target = kind === 0 ? m.reshares : m.contributions;
    check(!target.has(bucket), 'Duplicate entry');
    const size = dealingSize(n, t, kind === 1);
    check(buf.length >= at + 9 + size, 'Truncated message');
    target.set(bucket, decodeDealing(buf.subarray(at + 9, at + 9 + size), seat, n, t, kind === 1, keep));
    at += 9 + size;
  }
  check(at === buf.length, 'Trailing bytes');
  return m;
}
