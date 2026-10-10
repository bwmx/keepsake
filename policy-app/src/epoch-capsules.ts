import { createHash } from 'node:crypto';
import { ALGORAND_ZERO_ADDRESS_STRING, decodeAddress, encodeUint64 } from 'algosdk';
import { check, decryptPayload, encode, encryptPayload, open, type EncryptedPayload } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/crypto.js';
import { decodeState, messageEntries, openCapsuleKey, sealCapsuleKey, stateDigest, type Public } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/ecpss.js';
import { decodeG1, decodePartial, type G1Point, type Proof } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/pvss.js';
import { b64url, hex, type ChainPins } from './chain.js';
import type { CapsuleRecord, EpochReader } from './epochs.js';

/**
 * Capsules on bucket keys (PAPER_ALIGNMENT_PLAN.md Phase 4): the label binding a capsule's KEM proof to its policy, the
 * attested public state, and the sender's and recipient's sides. Holders release from their handover messages.
 */

const u64 = (n: bigint) => Buffer.from(encodeUint64(n));
const sha = (...parts: Uint8Array[]) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
const scalar = (x: bigint) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex');
const big = (b: Uint8Array) => BigInt(`0x${Buffer.from(b).toString('hex')}`);

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

export const proofBytes = (p: Proof) => Buffer.concat([scalar(p.c), scalar(p.z)]);
export const proofFromBytes = (b: Uint8Array): Proof => ({ c: big(b.subarray(0, 32)), z: big(b.subarray(32, 64)) });
export const payloadHash = (p: EncryptedPayload) => sha(encode(['ecpss/payload/v1', p.nonce, p.ciphertext, p.tag]));

/** Committee c's public state as at least t of its holders attested it when claiming their seats. */
export async function attestedState(reader: EpochReader, committee: bigint, t: number): Promise<Public | undefined> {
  const seats = await reader.seats(committee), counts = new Map<string, number>();
  for (const s of seats) if (s.value.holder !== ALGORAND_ZERO_ADDRESS_STRING) counts.set(hex(s.value.stateDigest), (counts.get(hex(s.value.stateDigest)) ?? 0) + 1);
  const agreed = [...counts].find(([, n]) => n >= t)?.[0]; // Fewer than t holders are corrupt, so one honest one agrees.
  if (!agreed) return undefined;
  const n = (await reader.seats(committee + 1n)).length;
  for (const bytes of (await reader.messages(committee, seats)).values()) {
    try {
      const state = new Map(messageEntries(bytes, n, t).filter(e => e.kind === 3).map(e => [e.id, e.body] as const));
      if (hex(stateDigest(state)) === agreed) return decodeState(state, t);
    } catch { /* A malformed message: try the next. */ }
  }
  return undefined;
}

/** A bucket's public key from the latest attested state that holds it, looking back a few committees from `from`. */
export async function bucketKey(reader: EpochReader, bucket: bigint, t: number, from: bigint): Promise<G1Point | undefined> {
  for (let c = from; c > from - 4n; c--) {
    const poly = (await attestedState(reader, c, t))?.get(bucket);
    if (poly) return poly[0];
  }
  return undefined;
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
 * Recipient: looks through committees `from`…`to` for t partials sealed to its request key that verify against the
 * attested state, then decrypts. Undefined until a handover has released the capsule.
 */
export async function openCapsule(reader: EpochReader, pins: ChainPins, capsuleId: bigint, request: { requestId: Uint8Array; privateKey: CryptoKey },
  payload: EncryptedPayload, t: number, from: bigint, to: bigint): Promise<Uint8Array | undefined> {
  const record = await reader.capsuleRecord(capsuleId);
  check(hex(payloadHash(payload)) === hex(record.payloadHash), 'Payload does not match the anchored hash');
  const label = capsuleLabel(pins.appId, record), u = decodeG1(record.u);
  for (let c = from; c <= to; c++) {
    const poly = (await attestedState(reader, c, t))?.get(record.bucket);
    if (!poly) continue;
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
    if (parts.length < t) continue;
    const key = openCapsuleKey(poly, u, label, parts, t); // Throws unless t partials verify.
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
