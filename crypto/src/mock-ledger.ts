import { check, encode, hash } from './crypto.js';
import { manifestHash, requestFields, round, snapshot,
  type AccessRequest, type AuthorizationSource, type Manifest } from './protocol.js';

/** TRUSTED TEST DOUBLE. No Algorand connection, signatures, or consensus verification.
 * `caller` simulates a sender already authenticated by a future application call.
 * Registration simulates completed custody acknowledgments; demo code performs them first.
 */
export class MockConfirmedLedger implements AuthorizationSource {
  #currentRound: bigint;
  #capsules = new Map<string, Manifest>();
  #requests = new Map<string, string>();

  constructor(initialRound = 0n) {
    check(initialRound >= 0n, 'Invalid initial round');
    this.#currentRound = initialRound;
  }

  get currentRound(): bigint { return this.#currentRound; }

  advanceTo(nextRound: bigint): void {
    check(nextRound >= this.#currentRound && nextRound <= 0xffff_ffff_ffff_ffffn, 'Round must increase within uint64');
    this.#currentRound = nextRound;
  }

  register(manifest: Manifest): string {
    const stable = snapshot(manifest);
    const anchor = manifestHash(stable);
    check(!this.#capsules.has(anchor), 'Already registered');
    this.#capsules.set(anchor, stable);
    return anchor;
  }

  authorize(request: AccessRequest, caller: string): void {
    const fields = requestFields(request);
    const manifest = this.#capsules.get(request.manifestHash);
    check(manifest, 'Unregistered capsule');
    check(caller === manifest.policy.recipient, 'Unauthorized recipient');
    check(this.#currentRound >= round(manifest.policy.openRound), 'Capsule not open');
    check(this.#currentRound < round(manifest.policy.expiresRound), 'Capsule expired');
    const digest = hash(encode(fields));
    const existing = this.#requests.get(request.manifestHash);
    check(!existing || existing === digest, 'Another request already authorized');
    this.#requests.set(request.manifestHash, digest); // Same-request retries are idempotent.
  }

  assertAuthorized(anchor: string, request: AccessRequest): bigint {
    check(request.manifestHash === anchor && this.#capsules.has(anchor), 'Wrong authorization domain');
    check(this.#requests.get(anchor) === hash(encode(requestFields(request))), 'Request not authorized');
    // Custodian independently applies time eligibility and disposal using this confirmed round.
    return this.#currentRound;
  }
}
