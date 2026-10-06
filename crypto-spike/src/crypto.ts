import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';

export const SUITE = 'capsule-v1/X25519/HKDF-SHA256/AES-256-GCM/Ed25519';
const hpke = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm(),
});

export function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

export const encode = (value: unknown): Buffer => Buffer.from(JSON.stringify(value), 'utf8');
export const b64 = (value: Uint8Array | ArrayBuffer): string =>
  Buffer.from(value instanceof ArrayBuffer ? new Uint8Array(value) : value).toString('base64url');

export function unb64(value: string, size?: number): Buffer {
  check(typeof value === 'string' && /^[A-Za-z0-9_-]*$/.test(value), 'Invalid base64url');
  const bytes = Buffer.from(value, 'base64url');
  check(b64(bytes) === value && (size === undefined || bytes.length === size), 'Invalid byte encoding/length');
  return bytes;
}

export const hash = (value: Uint8Array): string => createHash('sha256').update(value).digest('hex');
export const newId = (): string => b64(randomBytes(16));

export interface Envelope { enc: string; ciphertext: string }
export interface EphemeralKeyPair { publicKey: string; privateKey: CryptoKey }

export async function generateEphemeralKey(): Promise<EphemeralKeyPair> {
  const keys = await hpke.kem.generateKeyPair();
  return { publicKey: b64(await hpke.kem.serializePublicKey(keys.publicKey)), privateKey: keys.privateKey };
}

/** RFC 9180 DeriveKeyPair: the same 32-byte secret always yields the same X25519 key pair. */
export async function deriveEphemeralKey(ikm: Uint8Array): Promise<EphemeralKeyPair> {
  check(ikm.length === 32, 'Expected 32-byte key material');
  const keys = await hpke.kem.deriveKeyPair(ikm);
  return { publicKey: b64(await hpke.kem.serializePublicKey(keys.publicKey)), privateKey: keys.privateKey };
}

// Each call establishes a new one-message HPKE context. No reused context/sequence state.
export async function seal(publicKey: string, plaintext: Uint8Array, context: Buffer): Promise<Envelope> {
  const recipientPublicKey = await hpke.kem.deserializePublicKey(unb64(publicKey, 32));
  const sealed = await hpke.seal({ recipientPublicKey, info: context }, plaintext, context);
  return { enc: b64(sealed.enc), ciphertext: b64(sealed.ct) };
}

export async function open(privateKey: CryptoKey, envelope: Envelope, context: Buffer): Promise<Uint8Array> {
  return new Uint8Array(await hpke.open(
    { recipientKey: privateKey, enc: unb64(envelope.enc, 32), info: context },
    unb64(envelope.ciphertext), context,
  ));
}

export interface EncryptedPayload { nonce: string; ciphertext: string; tag: string }

export function encryptPayload(key: Uint8Array, plaintext: Uint8Array, aad: Buffer): EncryptedPayload {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { nonce: b64(nonce), ciphertext: b64(ciphertext), tag: b64(cipher.getAuthTag()) };
}

export function decryptPayload(key: Uint8Array, payload: EncryptedPayload, aad: Buffer): Uint8Array {
  const cipher = createDecipheriv('aes-256-gcm', key, unb64(payload.nonce, 12));
  cipher.setAAD(aad);
  cipher.setAuthTag(unb64(payload.tag, 16));
  // Do not return unauthenticated partial plaintext, even on a final-tag failure.
  const partial = cipher.update(unb64(payload.ciphertext));
  try {
    return new Uint8Array(Buffer.concat([partial, cipher.final()]));
  } finally {
    partial.fill(0);
  }
}
