import {
  createHash, createPrivateKey, createPublicKey, generateKeyPairSync, hkdfSync, sign, verify, type KeyObject,
} from 'node:crypto';
import { combine, split } from 'shamir-secret-sharing';
import {
  SUITE, b64, check, decryptPayload, deriveEphemeralKey, encode, encryptPayload, generateEphemeralKey,
  hash, newId, open, seal, unb64,
  type EncryptedPayload, type Envelope, type EphemeralKeyPair,
} from './crypto.js';

// Committees of n custodians use a majority threshold, so fixed-demo's five custodians stay 3-of-5.
export const MIN_COMMITTEE = 3;
export const MAX_COMMITTEE = 64;
export const thresholdFor = (n: number): number => Math.floor(n / 2) + 1;

export interface Policy {
  network: string;
  applicationId: string;
  capsuleId: string;
  recipient: string;
  openRound: string;
  expiresRound: string;
}

export interface CustodianDescriptor {
  id: string;
  encryptionPublicKey: string;
  signingPublicKey: string; // Ed25519 SPKI DER, base64url; not an Algorand address.
}

// 'algorand-hidden-v1': holders are anonymous one-time keys nominated through beacon-seeded VRF sortition;
// registryReference carries the evidence (beacon app, request, registry snapshot, randomness).
export const SELECTION_MODES = ['fixed-demo', 'algorand-hidden-v1'] as const;

export interface CommitteeSelection {
  mode: (typeof SELECTION_MODES)[number];
  epoch: string;
  registryReference: string;
  custodians: readonly CustodianDescriptor[];
}

// Selection happens before capsule creation. No simulated VRF proof.
export interface CommitteeSelector { select(): CommitteeSelection }

export class FixedCommitteeSelector implements CommitteeSelector {
  constructor(private readonly members: readonly CustodianDescriptor[]) {}
  select(): CommitteeSelection {
    return snapshot({ mode: 'fixed-demo', epoch: '0', registryReference: 'local-fixture', custodians: this.members });
  }
}

export interface Manifest {
  suite: typeof SUITE;
  threshold: number; // Always thresholdFor(committee size).
  policy: Policy;
  committee: CommitteeSelection;
  commitments: readonly string[];
  payloadHash: string;
}

export interface Capsule { manifest: Manifest; payload: EncryptedPayload }
export interface Deposit extends Envelope { custodianId: string }
export interface AccessRequest {
  manifestHash: string;
  requestId: string;
  recipientPublicKey: string;
}
export interface Release extends Envelope {
  custodianId: string;
  manifestHash: string;
  requestId: string;
  recipientPublicKey: string;
  signature: string;
}

// An implementation must authenticate finalized state and bind the entire request, failing closed.
// A bare caller-supplied round or boolean is NOT authorization. Returns the confirmed round it checked.
export interface AuthorizationSource {
  assertAuthorized(manifestHash: string, request: AccessRequest): bigint | Promise<bigint>;
}

export function snapshot<T>(value: T): T {
  const copy: T = structuredClone(value);
  const freeze = (item: unknown): void => {
    if (item && typeof item === 'object') {
      for (const child of Object.values(item)) freeze(child);
      Object.freeze(item);
    }
  };
  freeze(copy);
  return copy;
}

function text(value: unknown): asserts value is string {
  check(typeof value === 'string' && value.length > 0 && value.length <= 256, 'Invalid text field');
}

export function round(value: string): bigint {
  check(typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value), 'Invalid uint64');
  const result = BigInt(value);
  check(result <= 0xffff_ffff_ffff_ffffn, 'uint64 overflow');
  return result;
}

function policyFields(p: Policy): unknown[] {
  for (const field of [p.network, p.capsuleId, p.recipient]) text(field);
  round(p.applicationId);
  check(round(p.openRound) < round(p.expiresRound), 'Invalid access window');
  return [p.network, p.applicationId, p.capsuleId, p.recipient, p.openRound, p.expiresRound];
}

function descriptorFields(d: CustodianDescriptor): string[] {
  text(d.id);
  unb64(d.encryptionPublicKey, 32);
  const key = createPublicKey({ key: unb64(d.signingPublicKey), format: 'der', type: 'spki' });
  check(key.asymmetricKeyType === 'ed25519', 'Expected Ed25519 signing key');
  return [d.id, d.encryptionPublicKey, d.signingPublicKey];
}

function committeeFields(c: CommitteeSelection): unknown[] {
  check(SELECTION_MODES.includes(c.mode), 'Unimplemented committee selection mode');
  round(c.epoch);
  text(c.registryReference);
  const n = c.custodians.length;
  check(n >= MIN_COMMITTEE && n <= MAX_COMMITTEE, 'Committee size out of range');
  for (const field of ['id', 'encryptionPublicKey', 'signingPublicKey'] as const) {
    check(new Set(c.custodians.map(d => d[field])).size === n, 'Duplicate custodian identity/key');
  }
  return [c.mode, c.epoch, c.registryReference, c.custodians.map(descriptorFields)];
}

function contextFields(m: Pick<Manifest, 'policy' | 'committee'>): unknown[] {
  return [SUITE, thresholdFor(m.committee.custodians.length), policyFields(m.policy), committeeFields(m.committee)];
}

function payloadContext(m: Pick<Manifest, 'policy' | 'committee'>): Buffer {
  return encode(['capsule/payload/v1', ...contextFields(m)]);
}

function payloadHash(p: EncryptedPayload): string {
  unb64(p.nonce, 12);
  unb64(p.tag, 16);
  check(unb64(p.ciphertext).length <= 65_536, 'Payload too large');
  return hash(encode(['capsule/ciphertext/v1', p.nonce, p.ciphertext, p.tag]));
}

export function manifestHash(m: Manifest): string {
  const n = m.committee.custodians.length;
  check(m.suite === SUITE && m.threshold === thresholdFor(n), 'Unsupported suite or threshold');
  check(m.commitments.length === n, 'Invalid commitment count');
  for (const digest of [...m.commitments, m.payloadHash]) {
    check(typeof digest === 'string' && /^[a-f0-9]{64}$/.test(digest), 'Invalid SHA-256 digest');
  }
  return hash(encode(['capsule/manifest/v1', ...contextFields(m), m.commitments, m.payloadHash]));
}

function validateCapsule(capsule: Capsule, trustedHash: string): void {
  check(manifestHash(capsule.manifest) === trustedHash, 'Manifest does not match trusted anchor');
  check(payloadHash(capsule.payload) === capsule.manifest.payloadHash, 'Ciphertext hash mismatch');
}

function commitment(m: Pick<Manifest, 'policy' | 'committee'>, id: string, share: Uint8Array): string {
  const prefix = encode(['capsule/share/v1', ...contextFields(m), id]);
  return createHash('sha256').update(prefix).update(share).digest('hex');
}

function validateShare(m: Manifest, id: string, share: Uint8Array): void {
  check(share.length === 33 && share[32] !== 0, 'Invalid share encoding');
  const index = m.committee.custodians.findIndex(c => c.id === id);
  check(index >= 0 && commitment(m, id, share) === m.commitments[index], 'Share commitment mismatch');
}

function depositContext(anchor: string, id: string): Buffer {
  return encode(['capsule/deposit/v1', SUITE, anchor, id]);
}

export function requestFields(request: AccessRequest): string[] {
  check(/^[a-f0-9]{64}$/.test(request.manifestHash), 'Invalid manifest hash');
  text(request.requestId);
  unb64(request.recipientPublicKey, 32);
  return [request.manifestHash, request.requestId, request.recipientPublicKey];
}

function releaseContext(request: AccessRequest, id: string): Buffer {
  return encode(['capsule/release/v1', SUITE, ...requestFields(request), id]);
}

function signatureMessage(release: Omit<Release, 'signature'>): Buffer {
  return encode(['capsule/response-signature/v1', b64(releaseContext(release, release.custodianId)),
    release.enc, release.ciphertext]);
}

export async function createCapsule(
  plaintext: Uint8Array, policy: Policy, selector: CommitteeSelector,
): Promise<{ capsule: Capsule; deposits: readonly Deposit[]; anchor: string }> {
  check(plaintext.length <= 65_536, 'Payload too large');
  const base = snapshot({ policy, committee: selector.select() });
  // The Shamir library deliberately requires a plain Uint8Array, not a Node Buffer.
  const key = crypto.getRandomValues(new Uint8Array(32));
  let shares: Uint8Array[] = [];
  try {
    const payload = encryptPayload(key, plaintext, payloadContext(base));
    const n = base.committee.custodians.length;
    shares = await split(key, n, thresholdFor(n));
    const manifest: Manifest = {
      suite: SUITE, threshold: thresholdFor(n), ...base, payloadHash: payloadHash(payload),
      commitments: shares.map((share, i) => commitment(base, base.committee.custodians[i]!.id, share)),
    };
    const anchor = manifestHash(manifest);
    const deposits: Deposit[] = [];
    // Sequential so the finally block never wipes inputs still used by pending promises.
    for (const [i, descriptor] of base.committee.custodians.entries()) {
      deposits.push({ custodianId: descriptor.id, ...await seal(
        descriptor.encryptionPublicKey, shares[i]!, depositContext(anchor, descriptor.id),
      ) });
    }
    return snapshot({ capsule: { manifest, payload }, deposits, anchor });
  } finally {
    key.fill(0);
    for (const share of shares) share.fill(0);
  }
}

export async function createAccessRequest(anchor: string): Promise<{
  request: AccessRequest; keys: EphemeralKeyPair;
}> {
  const keys = await generateEphemeralKey();
  return { keys, request: snapshot({ manifestHash: anchor, requestId: newId(), recipientPublicKey: keys.publicKey }) };
}

export class Custodian {
  readonly descriptor: CustodianDescriptor;
  #encryptionKey: CryptoKey | undefined;
  #signingKey: KeyObject | undefined;
  #share: Uint8Array | undefined;
  #manifest: Manifest | undefined;
  #anchor: string | undefined;
  #boundRequest: string | undefined;
  #disposed = false;
  #accepting = false;

  private constructor(id: string, keys: EphemeralKeyPair, privateKey: KeyObject, publicKey: KeyObject) {
    this.#encryptionKey = keys.privateKey;
    this.#signingKey = privateKey;
    this.descriptor = snapshot({ id, encryptionPublicKey: keys.publicKey,
      signingPublicKey: b64(publicKey.export({ format: 'der', type: 'spki' })) });
  }

  static async create(id: string): Promise<Custodian> {
    text(id);
    const signing = generateKeyPairSync('ed25519');
    return new Custodian(id, await generateEphemeralKey(), signing.privateKey, signing.publicKey);
  }

  /** One-time holder keys from a 32-byte seed: whoever holds the seed (nominator, then holder) gets the same keys. */
  static async fromSeed(id: string, seed: Uint8Array): Promise<Custodian> {
    text(id);
    check(seed.length === 32, 'Expected 32-byte seed');
    const derive = (info: string) => new Uint8Array(hkdfSync('sha256', seed, 'capsule/holder-keys/v1', info, 32));
    const ikm = derive('hpke');
    const signingSeed = derive('ed25519');
    try {
      const privateKey = createPrivateKey({ format: 'der', type: 'pkcs8',
        key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), signingSeed]) });
      return new Custodian(id, await deriveEphemeralKey(ikm), privateKey, createPublicKey(privateKey));
    } finally {
      ikm.fill(0);
      signingSeed.fill(0);
    }
  }

  get disposed(): boolean { return this.#disposed; }

  /** Signs a binary chain message. The text prefix can never collide with JSON signature messages, which start '['. */
  signChainMessage(label: 'ack' | 'release', body: Uint8Array): Uint8Array {
    check(this.#signingKey && !this.#disposed, 'Signing key unavailable');
    return sign(null, Buffer.concat([Buffer.from(`capsule/chain-${label}/v1`), body]), this.#signingKey);
  }

  // Custodians need only the anchored manifest; the payload is checked by the recipient in recover().
  async accept(manifest: Manifest, deposit: Deposit, trustedHash: string): Promise<void> {
    check(!this.#disposed && !this.#share && !this.#accepting, 'Custody unavailable or already initialized');
    this.#accepting = true;
    let share: Uint8Array | undefined;
    try {
      const m = snapshot(manifest);
      const stableDeposit = snapshot(deposit);
      check(manifestHash(m) === trustedHash, 'Manifest does not match trusted anchor');
      const descriptor = m.committee.custodians.find(c => c.id === this.descriptor.id);
      check(descriptor && encode(descriptorFields(descriptor)).equals(encode(descriptorFields(this.descriptor))),
        'Custodian key mismatch');
      check(stableDeposit.custodianId === this.descriptor.id, 'Wrong deposit recipient');
      check(this.#encryptionKey, 'Encryption key unavailable');
      share = await open(this.#encryptionKey, stableDeposit, depositContext(trustedHash, this.descriptor.id));
      validateShare(m, this.descriptor.id, share);
      check(!this.#disposed, 'Custody disposed during deposit');
      this.#share = share;
      share = undefined;
      this.#manifest = m;
      this.#anchor = trustedHash;
      this.#encryptionKey = undefined; // Deposit decryption key is no longer needed.
    } finally {
      share?.fill(0);
      this.#accepting = false;
    }
  }

  expire(currentRound: bigint): void {
    check(currentRound >= 0n, 'Invalid round');
    if (this.#manifest && currentRound >= round(this.#manifest.policy.expiresRound)) this.dispose();
  }

  dispose(): void {
    this.#share?.fill(0);
    this.#share = undefined;
    this.#encryptionKey = undefined;
    this.#signingKey = undefined;
    this.#disposed = true;
  }

  async #authorize(request: AccessRequest, source: AuthorizationSource): Promise<void> {
    check(!this.#disposed && this.#manifest && this.#anchor && this.#share, 'Custody unavailable/disposed');
    check(request.manifestHash === this.#anchor, 'Wrong capsule');
    const current = await source.assertAuthorized(this.#anchor, request);
    check(!this.#disposed && this.#share, 'Custody disposed during authorization');
    this.expire(current);
    check(!this.#disposed, 'Capsule expired');
    check(current >= round(this.#manifest.policy.openRound), 'Capsule not open');
  }

  async release(request: AccessRequest, source: AuthorizationSource): Promise<Release> {
    const stableRequest = snapshot(request);
    const requestDigest = hash(encode(requestFields(stableRequest)));
    await this.#authorize(stableRequest, source);
    check(!this.#boundRequest || this.#boundRequest === requestDigest, 'Different request already bound');
    this.#boundRequest = requestDigest;
    const share = this.#share!.slice();
    try {
      const sealed = await seal(stableRequest.recipientPublicKey, share,
        releaseContext(stableRequest, this.descriptor.id));
      // Disposal/expiry can occur while HPKE awaits. Re-read authorization before signing/returning.
      await this.#authorize(stableRequest, source);
      check(this.#signingKey, 'Signing key unavailable');
      const unsigned = { ...stableRequest, custodianId: this.descriptor.id, ...sealed };
      return snapshot({ ...unsigned, signature: b64(sign(null, signatureMessage(unsigned), this.#signingKey)) });
    } finally {
      share.fill(0);
    }
  }
}

// No current-round argument: a recipient can retain already delivered responses.
export async function recover(
  capsule: Capsule, trustedHash: string, request: AccessRequest, privateKey: CryptoKey,
  responses: readonly Release[],
): Promise<Uint8Array> {
  const stable = snapshot({ capsule, request, responses });
  validateCapsule(stable.capsule, trustedHash);
  check(stable.request.manifestHash === trustedHash, 'Wrong recovery request');
  const n = stable.capsule.manifest.committee.custodians.length;
  check(stable.responses.length >= thresholdFor(n) && stable.responses.length <= n,
    'Need at least a threshold and at most a committee of responses');
  const ids = new Set<string>();
  const shares: Uint8Array[] = [];
  let key: Uint8Array | undefined;
  try {
    for (const response of stable.responses) {
      check(!ids.has(response.custodianId), 'Duplicate custodian response');
      ids.add(response.custodianId);
      check(encode(requestFields(response)).equals(encode(requestFields(stable.request))), 'Response request mismatch');
      const descriptor = stable.capsule.manifest.committee.custodians.find(c => c.id === response.custodianId);
      check(descriptor, 'Unknown custodian');
      const signer = createPublicKey({ key: unb64(descriptor.signingPublicKey), type: 'spki', format: 'der' });
      check(verify(null, signatureMessage(response), signer, unb64(response.signature, 64)), 'Invalid response signature');
      const share = await open(privateKey, response, releaseContext(stable.request, response.custodianId));
      shares.push(share); // Ensure failure in validation still wipes this buffer.
      validateShare(stable.capsule.manifest, response.custodianId, share);
    }
    check(new Set(shares.map(s => s[32])).size === shares.length, 'Duplicate Shamir coordinate');
    key = await combine(shares);
    return decryptPayload(key, stable.capsule.payload, payloadContext(stable.capsule.manifest));
  } finally {
    key?.fill(0);
    for (const share of shares) share.fill(0);
  }
}
