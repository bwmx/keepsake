import { sha256 } from '@noble/hashes/sha2.js';
import { ALGORAND_ZERO_ADDRESS_STRING, decodeAddress, encodeUint64 } from 'algosdk';
import { check, decryptPayload, encode, encryptPayload, open, type EncryptedPayload } from 'keepsake-crypto/dist/src/crypto.js';
import { decodeState, handoverPlan, messageEntries, openCapsuleKey, publicKey, sealCapsuleKey, stateDigest, type Public } from 'keepsake-crypto/dist/src/ecpss.js';
import { decodeG1, decodePartial, decodeProof, encodeProof, type G1Point } from 'keepsake-crypto/dist/src/pvss.js';
import { b64url, hex, type ChainPins } from './chain.js';
import { handoverBuckets, windows, type CapsuleRecord, type EpochParams, type EpochReader, type OrderedSeat } from './epochs.js';

/**
 * Capsules on bucket keys (docs/design.md, Capsules): the label binding a capsule's KEM proof to its policy, the
 * attested public state, and the sender's and recipient's sides. Holders release from their handover messages.
 */

const u64 = (n: bigint) => Buffer.from(encodeUint64(n));
const sha = (...parts: Uint8Array[]) => { const h = sha256.create(); for (const p of parts) h.update(p); return Buffer.from(h.digest()); };

/**
 * The capsule's label: its KEM proof, payload key and payload AAD are bound to it. It covers the sender, so a u copied
 * into another capsule fails its proof. The payload hash is anchored separately (it depends on the key).
 */
export const capsuleLabel = (appId: bigint, r: Pick<CapsuleRecord, 'sender' | 'recipient' | 'openRound' | 'expiresRound'>) =>
  sha(Buffer.from('ecpss/capsule/v1'), u64(appId), decodeAddress(r.sender).publicKey, decodeAddress(r.recipient).publicKey,
    u64(r.openRound), u64(r.expiresRound));

/** HPKE info/AAD for a holder's partial, sealed to the recipient's request key. */
export const releaseContext = (pins: ChainPins, capsuleId: bigint, requestId: Uint8Array, committee: bigint, seat: number) => encode([
  'ecpss/release/v1', pins.genesisHash, pins.appId.toString(), capsuleId.toString(), b64url(requestId), committee.toString(), seat,
]);

export const proofBytes = encodeProof;
export const proofFromBytes = decodeProof;
export const payloadHash = (p: EncryptedPayload) => sha(encode(['ecpss/payload/v1', p.nonce, p.ciphertext, p.tag]));

/** How many claimed seats attest each state digest (hex). */
const attestations = (seats: OrderedSeat[]) => {
  const counts = new Map<string, number>();
  for (const s of seats) if (s.value.holder !== ALGORAND_ZERO_ADDRESS_STRING) counts.set(hex(s.value.stateDigest), (counts.get(hex(s.value.stateDigest)) ?? 0) + 1);
  return counts;
};

/** Committee c's public state as at least t of its holders attested it when claiming their seats. */
export async function attestedState(reader: EpochReader, committee: bigint, t: number): Promise<Public | undefined> {
  const seats = await reader.seats(committee);
  const agreed = [...attestations(seats)].find(([, n]) => n >= t)?.[0]; // Fewer than t holders are corrupt, so one honest one agrees.
  if (!agreed) return undefined;
  const n = (await reader.seats(committee + 1n)).length;
  for (const bytes of (await reader.messages(committee, seats)).values()) {
    try {
      const state = messageEntries(bytes, n, t).find(e => e.kind === 3)?.body;
      if (state && hex(stateDigest(state)) === agreed) return decodeState(state, t);
    } catch { /* A malformed message: try the next. */ }
  }
  return undefined;
}

/** A bucket's public key from the latest attested state that holds it, looking back a few committees from `from`. */
export async function bucketKey(reader: EpochReader, bucket: bigint, t: number, from: bigint): Promise<G1Point | undefined> {
  for (let c = from; c > from - 4n; c--) {
    const sharing = (await attestedState(reader, c, t))?.get(bucket);
    if (sharing) return publicKey(sharing);
  }
  return undefined;
}

/**
 * Valid dealings that the handovers of committees c, c + 1 and c + 2 each need, from c's public state (ecpss
 * `handoverPlan`): t, or t + ℓ − 1 for a committee that unpacks ℓ packed buckets. `sizes`: committees c + 1 and c + 2.
 */
export function handoverNeeds(p: EpochParams, pub: Public, c: bigint, t: number, sizes: number[]): number[] {
  const plan = handoverPlan(pub, handoverBuckets(p, c), t, sizes[0] ?? 0);
  const first = plan.mode === 'unpack' && plan.live.length ? pub.get(plan.live[0]!)!.poly.length : t;
  if (plan.mode === 'pack') return [first, t + plan.slots.length - 1, t]; // c + 1 unpacks, so c + 2 holds buckets unpacked.
  const next = handoverBuckets(p, c + 1n), l = next.live.length + next.create.length; // c + 1 may pack for c + 2.
  return [first, t, l >= 2 && (sizes[1] ?? 0) >= t + l - 1 ? t + l - 1 : t];
}

/**
 * Liveness margin at `round` (docs/design.md, Liveness): by how many seats the latest handover's agreeing
 * attestations, and the sizes of the committee in office and of the next one once nominated, exceed what their
 * handovers need (`handoverNeeds`). A handover with fewer honest seats speaking loses every live bucket. Undefined
 * before the first handover.
 */
export async function livenessMargin(reader: EpochReader, round: bigint, t: number): Promise<number | undefined> {
  const p = reader.params, epoch = round / p.epochRounds;
  const latest = round > windows(p, epoch).handover[1] ? epoch : epoch - 1n;
  if (latest < p.genesisCommittee) return undefined;
  const counts = [Math.max(0, ...attestations(await reader.seats(latest)).values()), (await reader.seats(latest + 1n)).length];
  if (round >= windows(p, latest + 1n).nominate[1]) counts.push((await reader.seats(latest + 2n)).length);
  const needs = handoverNeeds(p, (await attestedState(reader, latest, t)) ?? new Map(), latest, t, counts.slice(1));
  return Math.min(...counts.map((n, i) => n - needs[i]!));
}

/** Sender: refuses to lock while the liveness margin is below `minMargin` seats. Choose it per deployment. */
export async function assertLive(reader: EpochReader, round: bigint, t: number, minMargin: number) {
  const margin = await livenessMargin(reader, round, t);
  check(margin !== undefined && margin >= minMargin, `Liveness margin too thin (${margin ?? 'no handover yet'} < ${minMargin} seats): not locking`);
}

/** Sender: encrypts under the bucket key for this label. The payload stays off-chain; its hash is anchored. */
export function sealCapsule(publicKey: G1Point, label: Buffer, plaintext: Uint8Array) {
  const { u, proof, key } = sealCapsuleKey(publicKey, label);
  try {
    const payload = encryptPayload(key, plaintext, label);
    return { u: u.toBytes(), proof: proofBytes(proof), payload, payloadHash: payloadHash(payload) };
  } finally {
    key.fill(0);
  }
}

/**
 * Recipient: looks through committees `from`…`to` for enough partials sealed to its request key that verify against
 * the attested state (t, or t + ℓ − 1 from a packed committee), then decrypts. Undefined until a handover has released
 * the capsule.
 */
export async function openCapsule(reader: EpochReader, pins: ChainPins, capsuleId: bigint, request: { requestId: Uint8Array; privateKey: CryptoKey },
  payload: EncryptedPayload, t: number, from: bigint, to: bigint): Promise<Uint8Array | undefined> {
  const record = await reader.capsuleRecord(capsuleId);
  check(hex(payloadHash(payload)) === hex(record.payloadHash), 'Payload does not match the anchored hash');
  const label = capsuleLabel(pins.appId, record), u = decodeG1(record.u);
  for (let c = from; c <= to; c++) {
    const sharing = (await attestedState(reader, c, t))?.get(record.bucket);
    if (!sharing) continue;
    const seats = await reader.seats(c), n = (await reader.seats(c + 1n)).length, parts = [];
    for (const [seat, bytes] of await reader.messages(c, seats)) {
      try {
        const body = messageEntries(bytes, n, t).find(e => e.kind === 2 && e.id === capsuleId)?.body;
        if (!body) continue;
        const plain = await open(request.privateKey, { enc: b64url(body.subarray(0, 32)), ciphertext: b64url(body.subarray(32)) },
          releaseContext(pins, capsuleId, request.requestId, c, seat));
        parts.push({ seat, p: decodePartial(plain) });
      } catch { /* Not for this request, or malformed: skipped. */ }
    }
    if (parts.length < sharing.poly.length) continue;
    const key = openCapsuleKey(sharing, u, label, parts); // Throws unless enough partials verify.
    try {
      return decryptPayload(key, payload, label);
    } finally {
      key.fill(0);
    }
  }
  return undefined;
}

/** The sender's exact deposit for a capsule box: 2,500 + 400 × (key 9 + record 281) µAlgo, refunded after expiry. */
export const CAPSULE_DEPOSIT = 118_500;
