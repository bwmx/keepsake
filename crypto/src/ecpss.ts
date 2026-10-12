import { ed25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { check } from './crypto.js';
import {
  ORDER, aggregate, combinePartials, deal, dealingSize, decodeDealing, decodeG1, encapsulate, encodeDealing, lagrange, openSubshares,
  partial, point, randomScalar, seatCommitment, validDealings, verifyG1, verifyPartial, weightedG2,
  type Dealing, type Form, type G1Point, type G2Point, type Head, type Partial, type Proof,
} from './pvss.js';

/**
 * UNREVIEWED. Evolving-committee proactive secret sharing (eprint 2020/464 §3) over the pairing re-sharing in pvss.ts,
 * holding bucket keys as PAPER_ALIGNMENT_PLAN.md proposes: committee-generated keys, one handover message per holder
 * per epoch, reconstruction, and the capsule KEM. Chain-agnostic; chain carries the messages.
 *
 * Committees are numbered; committee c hands over to committee c + 1. A seat is a holder's evaluation point: seats are
 * numbered 1..n in the order of their one-time signing keys (§3.1.2 step 5 orders by ephemeral key).
 */

/**
 * A bucket's public sharing: commitments to a polynomial whose value at the bucket's point is its secret. Slot 0: the
 * bucket's own polynomial in coefficient form (A_0..A_(t-1), A_0 = P = s·g1), secret at 0. Slot s ≥ 1: a packed
 * polynomial in evaluation form over −1..−m (pvss Form), shared by every bucket of the pack, with bucket s's secret at
 * −s and its key P = C_(s-1). Either way, poly.length shares (or capsule partials) recover the secret.
 */
export interface Sharing { poly: G1Point[]; slot: number }
export type Public = Map<bigint, Sharing>;
export const formOf = (s: Sharing): Form => (s.slot ? 'evaluations' : 'coefficients');
/** Where the sharing keeps the bucket's secret. */
export const secretAt = (s: Sharing) => -BigInt(s.slot);
export const publicKey = (s: Sharing) => s.poly[s.slot ? s.slot - 1 : 0]!;
/** Seat k's public share commitment. In a packed state every bucket of the pack has the same one. */
export const shareCommitment = (s: Sharing, seat: number) => seatCommitment(s.poly, seat, formOf(s));

/** A holder's private state: its seat, its ephemeral ElGamal scalar and one share per live bucket (packed: all equal). */
export interface Holder { seat: number; x: bigint; shares: Map<bigint, G2Point> }
/**
 * One holder's handover (see handoverPlan): a re-sharing per live bucket and a fresh contribution per bucket being
 * created; or one dealing packing all of them; or one re-sharing of its packed share plus the contributions.
 * Optionally also: per authorized capsule, its decryption partial sealed to the recipient's request key; and its view of
 * the committee's public state (encodeState), which it attests by signing the digest when it claims its seat.
 */
export interface Message {
  reshares: Map<bigint, Dealing>; contributions: Map<bigint, Dealing>; pack?: Dealing; unpack?: Dealing;
  releases?: Map<bigint, Uint8Array>; state?: Uint8Array;
}

/**
 * A committee's public state on the wire: groups of buckets that share one polynomial (one bucket unpacked, or a
 * whole pack), ordered by first bucket. u16 group count; per group u16 m, u16 bucket count, each bucket as u64 id and
 * u16 slot (in slot order), then m compressed G1 points.
 */
export function encodeState(pub: Public): Buffer {
  const groups = new Map<string, { poly: G1Point[]; members: [bigint, number][] }>();
  for (const b of [...pub.keys()].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0))) {
    const s = pub.get(b)!, key = s.slot ? Buffer.concat(s.poly.map(p => p.toBytes())).toString('hex') : `bucket:${b}`;
    if (!groups.has(key)) groups.set(key, { poly: s.poly, members: [] });
    groups.get(key)!.members.push([b, s.slot]);
  }
  return Buffer.concat([u16(groups.size), ...[...groups.values()].flatMap(g => [u16(g.poly.length), u16(g.members.length),
    ...g.members.sort((x, y) => x[1] - y[1]).flatMap(([b, slot]) => [u64(b), u16(slot)]), ...g.poly.map(p => p.toBytes())])]);
}
/** What holders attest: SHA-256 over the encoded state. */
export const stateDigest = (state: Uint8Array) => Buffer.from(sha256.create().update(utf8ToBytes('ecpss/state/v2')).update(state).digest());
/**
 * Strict decoding of an attested state: valid, non-identity G1 points; each bucket once; either unpacked buckets, each
 * with t points at slot 0, or a single pack of ℓ buckets with t + ℓ − 1 points at slots 1..ℓ (handovers produce no mix).
 */
export function decodeState(state: Uint8Array, t: number): Public {
  const buf = Buffer.from(state), pub: Public = new Map();
  let at = 0;
  const take = (len: number) => { check(buf.length >= at + len, 'Truncated state'); return buf.subarray(at, (at += len)); };
  const groups = take(2).readUInt16BE(0);
  for (let g = groups; g > 0; g--) {
    const m = take(2).readUInt16BE(0), count = take(2).readUInt16BE(0);
    const members = Array.from({ length: count }, () => [take(8).readBigUInt64BE(0), take(2).readUInt16BE(0)] as const);
    const packed = members.some(([, slot]) => slot > 0);
    check(count > 0 && (packed ? groups === 1 && members.every(([, slot], i) => slot === i + 1) && m === t + count - 1 : count === 1 && m === t), 'Bad state shape');
    const poly = Array.from({ length: m }, () => decodeG1(take(48)));
    for (const [b, slot] of members) { check(!pub.has(b), 'Duplicate bucket'); pub.set(b, { poly, slot }); }
  }
  check(at === buf.length, 'Trailing bytes');
  return pub;
}

const u64 = (n: bigint | number) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
/** Binds a new-key contribution's proof of knowledge to its committee and bucket (the dealer seat is added by pvss). */
const context = (committee: bigint, bucket: bigint) => Buffer.concat([Buffer.from('ecpss/contribution/v1'), u64(committee), u64(bucket)]);

/** A seat's one-time keys, derived from the nominator's 32-byte seed: the BLS ElGamal key pair and an Ed25519 key. */
export function seatKeys(seed: Uint8Array) {
  check(seed.length === 32, 'Expected a 32-byte seed');
  const okm = (info: string, length: number) => Buffer.from(hkdf(sha256, seed, utf8ToBytes('ecpss/seat-keys/v1'), utf8ToBytes(info), length));
  const x = BigInt(`0x${okm('bls12-381', 48).toString('hex')}`) % ORDER;
  check(x !== 0n, 'Degenerate seed');
  const signingKey = okm('ed25519', 32); // An RFC 8032 Ed25519 seed.
  const sigKey = Buffer.from(ed25519.getPublicKey(signingKey));
  return { x, epk: point.g2(x), sigKey, sign: (message: Uint8Array) => Buffer.from(ed25519.sign(message, signingKey)) };
}

export interface Buckets { live: bigint[]; create: bigint[] }
/**
 * How committee `committee` hands over (PAPER_ALIGNMENT_PLAN.md, packed epochs), from public data only:
 * - plain: one dealing per live bucket (re-sharing) and per bucket being created (contribution);
 * - pack: from an unpacked state, one dealing per holder that packs every bucket it carries (live, then created) into
 *   one polynomial of t + ℓ − 1 values; the next committee holds one packed share. Only with ℓ ≥ 2, and only if the
 *   next committee has the t + ℓ − 1 seats its own handover will need;
 * - unpack: from a packed state, one re-sharing per holder of its packed share, which the next committee interpolates
 *   into each live bucket's own share, plus one contribution per bucket being created. A bucket that expires here
 *   still rides in the packed shares being re-shared, so it is gone only once the next committee erases: one epoch
 *   later than when unpacked.
 * Packing and unpacking alternate, so every epoch carries one dealing per holder for the live buckets, not ℓ.
 */
export interface Plan extends Buckets { mode: 'plain' | 'pack' | 'unpack'; slots: bigint[] }
export function handoverPlan(pub: Public, buckets: Buckets, t: number, n: number): Plan {
  const live = buckets.live.filter(b => pub.has(b)), create = buckets.create;
  if ([...pub.values()].some(s => s.slot > 0)) return { mode: 'unpack', live, create, slots: [] };
  const slots = [...live, ...create];
  return { mode: slots.length >= 2 && n >= t + slots.length - 1 ? 'pack' : 'plain', live, create, slots };
}

/** The holder's single message for this epoch (§3.1.3). Afterwards the holder must erase its state. */
export function handover(h: Holder, pub: Public, committee: bigint, buckets: Buckets, next: G2Point[], t: number): Message {
  const plan = handoverPlan(pub, buckets, t, next.length), m: Message = { reshares: new Map(), contributions: new Map() };
  const held = (b: bigint): Head | undefined => {
    const share = h.shares.get(b);
    return share && { share, commitment: shareCommitment(pub.get(b)!, h.seat) };
  };
  const contribution = (b: bigint): Head => {
    const z = randomScalar();
    return { share: point.g2(z), commitment: point.g1(z), z, context: context(committee, b) };
  };
  if (plan.mode === 'pack') {
    const heads = plan.live.map(held);
    if (heads.every(x => x)) m.pack = deal(h.seat, [...heads as Head[], ...plan.create.map(contribution)], next, t + plan.slots.length - 1, 'evaluations');
    return m;
  }
  if (plan.mode === 'unpack') {
    const head = plan.live.map(held).find(x => x); // The one packed share, whichever live bucket names it.
    if (head) m.unpack = deal(h.seat, [head], next, t);
  } else {
    for (const b of plan.live) { const head = held(b); if (head) m.reshares.set(b, deal(h.seat, [head], next, t)); }
  }
  for (const b of plan.create) m.contributions.set(b, deal(h.seat, [contribution(b)], next, t));
  return m;
}

/** Each seat's dealing of one kind (per bucket, or the holder's single one), in seat order; absent or misfiled ones left out. */
const dealingsOf = (messages: Map<number, Message>, get: (m: Message) => Dealing | undefined) => {
  const seats = [...messages.keys()].sort((x, y) => x - y);
  return seats.map(s => get(messages.get(s)!)).filter((d, i): d is Dealing => d?.dealer === seats[i]);
};

/**
 * The costly half of receiving committee `committee`'s handover (§3.1.3): per bucket of the plan, the seats whose
 * dealings pass, in seat order (a pack's or an unpack's buckets all share one list). Re-sharings are checked against
 * the committee's commitments, new-key contributions against their proofs. Dealings are independent, so callers may
 * check disjoint groups of seats in parallel and merge.
 */
export function validSeats(messages: Map<number, Message>, pub: Public, committee: bigint, buckets: Buckets, next: G2Point[], t: number) {
  const plan = handoverPlan(pub, buckets, t, next.length), valid = new Map<bigint, number[]>();
  const prior = (dealings: Dealing[], heads: (seat: number) => G1Point[]) => new Map(dealings.map(d => [d.dealer, heads(d.dealer)] as const));
  const seats = (dealings: Dealing[]) => dealings.map(d => d.dealer);
  if (plan.mode === 'pack') {
    const dealings = dealingsOf(messages, m => m.pack);
    const ok = seats(validDealings(dealings, next, t + plan.slots.length - 1, { form: 'evaluations',
      prior: prior(dealings, seat => plan.live.map(b => shareCommitment(pub.get(b)!, seat))), contexts: plan.create.map(b => context(committee, b)) }));
    for (const b of plan.slots) valid.set(b, ok);
    return valid;
  }
  if (plan.mode === 'unpack' && plan.live.length) {
    const packed = pub.get(plan.live[0]!)!, dealings = dealingsOf(messages, m => m.unpack);
    const ok = seats(validDealings(dealings, next, t, { prior: prior(dealings, seat => [shareCommitment(packed, seat)]) }));
    for (const b of plan.live) valid.set(b, ok);
  } else {
    for (const b of plan.live) {
      const dealings = dealingsOf(messages, m => m.reshares.get(b));
      valid.set(b, seats(validDealings(dealings, next, t, { prior: prior(dealings, seat => [shareCommitment(pub.get(b)!, seat)]) })));
    }
  }
  for (const b of plan.create) valid.set(b, seats(validDealings(dealingsOf(messages, m => m.contributions.get(b)), next, t, { contexts: [context(committee, b)] })));
  return valid;
}

/**
 * How the next committee gets one bucket: from which dealings (a message field, the dealers' seats), weighted by
 * Lagrange coefficients at `at` over those seats or, for summed contributions, all 1; and at which slot of the result.
 */
export interface Recipe { from: 'reshares' | 'contributions' | 'pack' | 'unpack'; seats: number[]; at?: bigint; slot: number }

/**
 * Per bucket of the plan, the first valid dealings it needs: t, or for unpacking the packed polynomial's size
 * (t + ℓ − 1). A bucket without enough is lost. `margin`: how far the valid dealings exceed the need at the tightest
 * kept bucket (at zero, one more silent seat loses buckets).
 */
export function choose(pub: Public, buckets: Buckets, valid: Map<bigint, number[]>, t: number, n: number) {
  const plan = handoverPlan(pub, buckets, t, n), used = new Map<bigint, Recipe>(), lost: bigint[] = [], spare: number[] = [];
  const take = (b: bigint, need: number, recipe: Omit<Recipe, 'seats'>) => {
    const list = valid.get(b) ?? [];
    if (list.length < need) lost.push(b);
    else { used.set(b, { ...recipe, seats: list.slice(0, need) }); spare.push(list.length - need); }
  };
  if (plan.mode === 'pack') plan.slots.forEach((b, i) => take(b, t, { from: 'pack', at: 0n, slot: i + 1 }));
  else {
    for (const b of plan.live) {
      const s = pub.get(b)!;
      take(b, s.poly.length, plan.mode === 'unpack' ? { from: 'unpack', at: secretAt(s), slot: 0 } : { from: 'reshares', at: 0n, slot: 0 });
    }
    for (const b of plan.create) take(b, t, { from: 'contributions', slot: 0 }); // t contributions include an honest one.
  }
  return { used, lost, margin: spare.length ? Math.min(...spare) : undefined };
}

/**
 * The cheap half: the next committee's public state from the chosen dealings and, for each of `mine` (next-committee
 * seats this caller holds; a worker passes its own), a share per bucket. `messages` may be partially decoded
 * (commitments and the caller's subshares) once the recipes are known.
 */
export function adopt(messages: Map<number, Message>, used: Map<bigint, Recipe>, mine: { seat: number; x: bigint }[] = []) {
  const pub: Public = new Map(), holders = mine.map(m => ({ seat: m.seat, x: m.x, shares: new Map<bigint, G2Point>() }) as Holder);
  const polys = new Map<string, G1Point[]>(), opened = new Map<string, G2Point[]>(), shares = new Map<string, G2Point>();
  for (const [b, r] of used) {
    const single = r.from === 'pack' || r.from === 'unpack'; // One dealing per holder serves every bucket.
    const dealings = r.seats.map(s => { const m = messages.get(s)!; return r.from === 'pack' || r.from === 'unpack' ? m[r.from]! : m[r.from].get(b)!; });
    const weights = r.at === undefined ? r.seats.map(() => 1n) : lagrange(r.seats, r.at);
    const source = single ? `${r.from}:${r.seats}` : `${r.from}:${b}`, key = `${source}:${r.at}`; // A pack's slots share one polynomial.
    if (!polys.has(key)) polys.set(key, aggregate(dealings, weights));
    pub.set(b, { poly: polys.get(key)!, slot: r.slot });
    for (const h of holders) {
      const at = `${h.seat}:${source}`;
      if (!opened.has(at)) opened.set(at, openSubshares(h.seat, h.x, dealings));
      if (!shares.has(`${at}:${r.at}`)) shares.set(`${at}:${r.at}`, weightedG2(opened.get(at)!, weights));
      h.shares.set(b, shares.get(`${at}:${r.at}`)!);
    }
  }
  return { pub, holders };
}

/** Everyone's view of committee `committee`'s handover, in this thread: `validSeats`, `choose`, then `adopt`. */
export function receive(messages: Map<number, Message>, pub: Public, committee: bigint, buckets: Buckets, next: G2Point[], t: number,
  mine: { seat: number; x: bigint }[] = []) {
  const valid = validSeats(messages, pub, committee, buckets, next, t), chosen = choose(pub, buckets, valid, t, next.length);
  return { ...adopt(messages, chosen.used, mine), ...chosen, valid };
}

/** §3.1.1: an honest dealer plays t first-committee roles to create a bucket; it must erase the secret it returns. */
export function dealerGenesis(bucket: bigint, next: G2Point[], t: number) {
  const z = Array.from({ length: t }, () => randomScalar());
  const messages = new Map(z.map((zj, j) => [j + 1, {
    reshares: new Map(), contributions: new Map([[bucket, deal(j + 1, [{ share: point.g2(zj), commitment: point.g1(zj), z: zj, context: context(0n, bucket) }], next, t)]]),
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

/** §3.1.4: the secret from the first poly.length shares that match their public commitments. */
export function reconstruct(s: Sharing, shares: { seat: number; share: G2Point }[]): G2Point {
  const valid = shares.filter(x => shareMatches(x.share, shareCommitment(s, x.seat))).slice(0, s.poly.length);
  check(valid.length === s.poly.length, 'Not enough valid shares');
  return weightedG2(valid.map(x => x.share), lagrange(valid.map(x => x.seat), secretAt(s)));
}

// --- Capsule KEM over a bucket key ---

const capsuleKey = (k: ReturnType<typeof combinePartials>, u: G1Point, label: Uint8Array) =>
  Buffer.from(hkdf(sha256, bls.fields.Fp12.toBytes(k), u.toBytes(), Buffer.concat([Buffer.from('ecpss/capsule-key/v1'), label]), 32));

/** Sender: a 32-byte payload key for a capsule under bucket key P, with u and a proof of r bound to the policy label. */
export function sealCapsuleKey(key: G1Point, label: Uint8Array): { u: G1Point; proof: Proof; key: Buffer } {
  const sealed = encapsulate(key, label);
  return { u: sealed.u, proof: sealed.proof, key: capsuleKey(sealed.key, sealed.u, label) };
}

/** Holder: its partial for an authorized capsule. Refuses a u whose proof is not bound to this policy label (replay). */
export function capsulePartial(share: G2Point, commitment: G1Point, u: G1Point, proof: Proof, label: Uint8Array): Partial {
  check(verifyG1(u, proof, label), 'Capsule not bound to this policy');
  return partial(share, commitment, u);
}

/**
 * Recipient: the payload key from the first poly.length partials that verify against the bucket's sharing. On a packed
 * state a partial e(u, F(k)) serves every bucket of the pack, so these partials also give e(u, S) for the pack's other
 * buckets: the key a capsule with this very u would have under them. Only this capsule's sender, who knows u's
 * discrete log, could make such a capsule, and it could compute that key itself.
 */
export function openCapsuleKey(s: Sharing, u: G1Point, label: Uint8Array, parts: { seat: number; p: Partial }[]): Buffer {
  const valid = parts.filter(x => verifyPartial(shareCommitment(s, x.seat), u, x.p)).slice(0, s.poly.length);
  check(valid.length === s.poly.length, 'Not enough valid partials');
  return capsuleKey(combinePartials(valid.map(x => ({ seat: x.seat, d: x.p.d })), secretAt(s)), u, label);
}

// --- Wire format: entry count (u16), then entries of id (u64), kind, body. Kinds: 0 re-share (bucket, dealing),
// 1 contribution (bucket, dealing with its proof), 2 release (capsule, u16 length, sealed partial), 3 state (id 0,
// u32 length, encodeState), 4 pack (id 0, u16 m, u16 proofs, evaluation-form dealing), 5 unpack (id 0, dealing).

const u16 = (n: number) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
export function encodeMessage(m: Message): Buffer {
  const entries = [
    ...[...m.reshares].map(([b, d]) => [b, 0, encodeDealing(d)] as const),
    ...[...m.contributions].map(([b, d]) => [b, 1, encodeDealing(d)] as const),
    ...(m.pack ? [[0n, 4, Buffer.concat([u16(m.pack.commitments.length), u16(m.pack.proofs.length), encodeDealing(m.pack)])] as const] : []),
    ...(m.unpack ? [[0n, 5, encodeDealing(m.unpack)] as const] : []),
    ...[...m.releases ?? []].map(([c, sealed]) => [c, 2, Buffer.concat([u16(sealed.length), sealed])] as const),
    ...(m.state ? [[0n, 3, Buffer.concat([u32(m.state.length), m.state])] as const] : []),
  ];
  return Buffer.concat([u16(entries.length), ...entries.flatMap(([id, kind, body]) => [u64(id), Buffer.from([kind]), body])]);
}

/**
 * A message's entries without decoding any point: kind, id (bucket or capsule, else 0) and body (without a length
 * prefix; a pack's keeps its m and proof count), with every length checked.
 */
export function messageEntries(bytes: Uint8Array, n: number, t: number) {
  const buf = Buffer.from(bytes);
  check(buf.length >= 2, 'Truncated message');
  const entries: { kind: number; id: bigint; body: Buffer }[] = [], seen = new Set<string>();
  let at = 2;
  const need = (len: number) => check(buf.length >= at + len, 'Truncated message');
  for (let i = 0; i < buf.readUInt16BE(0); i++) {
    need(9);
    const id = buf.readBigUInt64BE(at), kind = buf[at + 8]!;
    at += 9;
    check(kind <= 5, 'Unknown entry kind');
    check(kind <= 2 || id === 0n, 'Bad entry id');
    check(!seen.has(`${kind}:${id}`), 'Duplicate entry');
    seen.add(`${kind}:${id}`);
    let skip = 0, size: number;
    if (kind === 2) { need(2); [skip, size] = [2, buf.readUInt16BE(at)]; }
    else if (kind === 3) { need(4); [skip, size] = [4, buf.readUInt32BE(at)]; }
    else if (kind === 4) { need(4); size = 4 + dealingSize(n, buf.readUInt16BE(at), buf.readUInt16BE(at + 2)); }
    else size = dealingSize(n, t, kind === 1 ? 1 : 0);
    need(skip + size);
    entries.push({ kind, id, body: buf.subarray(at + skip, at + skip + size) });
    at += skip + size;
  }
  check(at === buf.length, 'Trailing bytes');
  return entries;
}

export type DecodedMessage = Message & { releases: Map<bigint, Uint8Array> };
/** Strict decoding of an untrusted message posted for `seat`; n is the next committee's size. `keep`: see decodeDealing. */
export function decodeMessage(bytes: Uint8Array, seat: number, n: number, t: number, keep?: number[]): DecodedMessage {
  const m: DecodedMessage = { reshares: new Map(), contributions: new Map(), releases: new Map() };
  for (const { kind, id, body } of messageEntries(bytes, n, t)) {
    if (kind <= 1) (kind === 0 ? m.reshares : m.contributions).set(id, decodeDealing(body, seat, n, t, kind === 1 ? 1 : 0, keep));
    else if (kind === 4) m.pack = decodeDealing(body.subarray(4), seat, n, body.readUInt16BE(0), body.readUInt16BE(2), keep);
    else if (kind === 5) m.unpack = decodeDealing(body, seat, n, t, 0, keep);
    // Releases are opened only by their recipient, and a state only once it is attested: both stay raw here.
    else if (kind === 2) m.releases.set(id, body);
    else m.state = body;
  }
  return m;
}
