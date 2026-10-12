# Legacy spike protocol v1

This specifies the per-capsule spike in `src/protocol.ts`: Keepsake's first milestone, with a fixed committee of five custodians and a trusted mock ledger. **The current design does not use it.** The epoch design's wire formats are defined in `src/pvss.ts` and `src/ecpss.ts`, and described in [docs/design.md](../docs/design.md).

Public objects may be stored indefinitely. Private material must remain off-chain.

## Representation and domains

- Canonical cryptographic preimages use UTF-8 `JSON.stringify` of explicitly ordered arrays, as constructed in `src/protocol.ts`. Object property order is not used for manifest hashes/signatures.
- Byte strings use unpadded canonical base64url. Hashes use lowercase SHA-256 hex.
- Rounds, application IDs, and epochs use canonical uint64 decimal strings; parse them as `bigint`, never JavaScript floating-point numbers.
- Suite identifier: `capsule-v1/X25519/HKDF-SHA256/AES-256-GCM/Ed25519`.
- HPKE: Base mode, KEM `0x0020`, KDF `0x0001`, AEAD `0x0002`. A fresh single-message sender context is created for every deposit/release. The context bytes below are both HPKE `info` and AEAD associated data.
- The encrypted payload uses Node's AES-256-GCM and separate nonce/ciphertext/tag fields.

`policyFields` order: `[network, applicationId, capsuleId, recipient, openRound, expiresRound]`.

`descriptorFields` order: `[id, encryptionPublicKey, signingPublicKey]`.

`committeeFields` order: `[mode, epoch, registryReference, orderedDescriptorArrays]`.

`contextFields` order: `[suite, threshold, policyFields, committeeFields]`.

Custodian order determines the matching position in the commitment array. The Shamir library encodes a 32-byte key share as 33 bytes, with its nonzero GF(256) coordinate in the final byte. The coordinate is not inferred from array position. Custodian identities, encryption keys and signing keys must each be unique across the five descriptors.

## Public objects

`Policy` contains the six policy fields above. During the spike `network = crypto:no-chain` and `applicationId = 0` explicitly identify an off-chain fixture. Real capsules must use the actual network genesis hash and application ID. The mock recipient string must be replaced by an authenticated Algorand account identity.

`CommitteeSelection` contains `mode = fixed-demo`, `epoch = 0`, `registryReference = local-fixture`, and five custodian descriptors. This is metadata, not proof of registry admission or randomized selection.

For `mode = algorand-hidden-v1` (built by the removed `CapsulePolicy` app):
- `epoch` is the beacon target round.
- `registryReference` is `beacon:<beaconAppId>;request:<capsuleId>;registry:<snapshotSize>;randomness:<hex>`.
- Descriptor `id`s are `slot-0`…`slot-4`. Their keys are one-time holder keys from `Custodian.fromSeed(id, seed)`: the seed goes through HKDF-SHA256 (salt `capsule/holder-keys/v1`, info `hpke` / `ed25519`), then RFC 9180 DeriveKeyPair for X25519 and an Ed25519 seed.

Holders rebuild this manifest from chain data and accept only if it hashes to the anchored value. Chain messages are signed with the one-time Ed25519 key over `"capsule/chain-ack/v1" ‖ body` or `"capsule/chain-release/v1" ‖ body`. These prefixes can never equal a JSON signature message, which starts with `[`.

`EncryptedPayload` contains `nonce`, `ciphertext`, and `tag`. Plaintext size is limited to 65,536 bytes in this internal API. Associated data is:

```text
["capsule/payload/v1", ...contextFields]
```

The encrypted payload digest is SHA-256 of:

```text
["capsule/ciphertext/v1", nonce, ciphertext, tag]
```

`Manifest` contains the suite, threshold `⌊n/2⌋ + 1` for a committee of n (3–64), the policy, committee, n share commitments and the payload digest. The fixed demo uses n = 5, t = 3, so its encoding is unchanged. For custodian `id`, the commitment hashes the concatenation of the encoded prefix below followed directly by the raw 33-byte share. Shares are uniformly random-key-derived values; no plaintext/password hashes are published.

```text
["capsule/share/v1", ...contextFields, id] || rawShare
```

The manifest anchor is SHA-256 of:

```text
["capsule/manifest/v1", ...contextFields, commitments, payloadHash]
```

The external trusted anchor authenticates all policy, committee and ciphertext fields. Payload AEAD checks are still required; a public hash alone does not authenticate who originated the manifest.

`Deposit` contains `custodianId`, HPKE encapsulated key `enc`, and HPKE `ciphertext`. Plaintext is the raw Shamir share. Context is:

```text
["capsule/deposit/v1", suite, manifestHash, custodianId]
```

Deposits use HPKE Base mode. Sender authenticity is supplied by the trusted manifest anchor and matching share commitment, not by HPKE Base mode. The spike assumes an honest dealer and does not prove polynomial consistency.

`AccessRequest` contains `manifestHash`, a fresh random `requestId`, and `recipientPublicKey`. An authenticated authorization source must bind all three fields to the authorized account. There is one request per capsule, with idempotent retries of that same request. A different request ID or key is rejected.

`Release` contains all request fields, `custodianId`, HPKE `enc` and `ciphertext`, and an Ed25519 `signature`. Release context is:

```text
["capsule/release/v1", suite, manifestHash, requestId, recipientPublicKey, custodianId]
```

The signature message is:

```text
["capsule/response-signature/v1", base64url(releaseContextBytes), enc, ciphertext]
```

Thus modifying recipient keys, request IDs, custodian labels, capsule domains, encapsulated keys or encrypted shares invalidates the response. The recipient must use signing keys from the anchored manifest.

## State and lifecycle

1. **Preparation:** Generate five independent capsule-specific custodian HPKE key pairs and Ed25519 signing pairs. An admission system is a future integration requirement; generation alone is not proof of independent operators.
2. **Dealer:** Generate a random 256-bit data key. Encrypt the payload, split the key 3-of-5, commit to the shares, build the manifest, and encrypt each deposit. Wipe locally owned key/share byte buffers in `finally` after completing or failing encryption. Caller-owned plaintext is the caller's responsibility.
3. **Custody:** Verify the trusted manifest hash, require the custodian's own registered descriptor, decrypt the deposit, and check its commitment. The payload is not needed; the recipient checks it during recovery. Retain the share and signing key, discard the deposit decryption-key reference. Reject a second initialization. Public descriptors remain available.
4. **Activation:** The demo registers the manifest only after custody setup succeeds. A future application must implement and authenticate actual acknowledgments.
5. **Authorization:** Recipient creates a fresh X25519 pair; its wallet authorizes the complete request during `[openRound, expiresRound)`. The mock ledger simulates this step with a trusted identity string.
6. **Release:** Snapshot request inputs before any await. Read authorization (possibly asynchronous) and re-check that custody still exists after awaiting it. Check domain and current round, and bind local custody to the request. Copy the share into a transient buffer; HPKE-encrypt it to the request key. Recheck authorization/expiry/disposal after encryption. Sign and return the encrypted response. Wipe the transient share buffer even on failure.
7. **Recovery:** Check the trusted manifest and payload hash. Require 3–5 distinct custodians and exact request binding. Verify each signature, decrypt, validate its share commitment, and reject duplicate Shamir coordinates. Combine, AEAD-decrypt the payload, and wipe reconstructed key/share buffers. Invalid input aborts this call; the client may retry with another valid subset.
8. **Expiry:** The caller/worker supplies confirmed rounds to `expire()`. At or past the expiry round, disposal wipes the stored share buffer and drops remaining private-key references. Already prepared copies are invalidated for release by the final disposal check. No proof of physical erasure is claimed.

The demo retains the recipient key long enough to demonstrate that old responses still decrypt after expiry. This is intentional. A recipient's retention policy is outside custodian enforcement.

## Status

The spike's on-chain side, `algorand-hidden-v1` (the `CapsulePolicy` app with beacon-seeded hidden committees and a relayer), was removed on 2026-10-10 in favour of the epoch design; see [docs/history.md](../docs/history.md). The spike itself still builds and passes its tests against the mock ledger. It was never meant for real secrets.
