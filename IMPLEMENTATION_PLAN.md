# Ephemeral secret capsules on Algorand

> **Status (2026-10-10).** This is the original plan. Its on-chain "Hidden committee design" (beacon-seeded per-capsule committees, a relayer) was built for milestones 2–3. It was then superseded by [PAPER_ALIGNMENT_PLAN.md](PAPER_ALIGNMENT_PLAN.md), the paper's evolving epoch committees, and removed from `policy-app`; it remains in Git history. The goals, stack choice and threat discussion below still apply.

## Purpose and agreed stack

Build a demonstrable, short-lived secret custody system inspired by [Can a Public Blockchain Keep a Secret?](https://eprint.iacr.org/2020/464.pdf). Algorand records the policy and authorizes access; off-chain custodians hold encrypted key shares. Never put plaintext, plaintext shares, or private keys on-chain.

**User-selected stack: AlgoKit + Algorand TypeScript compiled with Puya TS.** Do not replace this with Algorand Python, PyTeal, or TEALScript. Use ordinary TypeScript/Node.js for off-chain cryptography and custodian services. Algorand TypeScript is an AVM-targeting subset and cannot run the off-chain crypto libraries.

Current scope: implement the first crypto spike. **Milestone 1 is implemented and verified: strict TypeScript compilation, 26 passing tests, and a passing CLI demo (2026-10-06).** See `crypto-spike/README.md` and `crypto-spike/PROTOCOL.md`. **Milestones 2 and 3 are implemented on LocalNet only in `policy-app/`, with hidden, variable-size holder committees (paper-aligned VRF steps 1–5; 8 passing LocalNet tests, 2026-10-06), plus a local demo UI for milestone 4 (Capsule Lab); see `policy-app/README.md`.** TestNet/MainNet deployment, wallet integration, distributed services, and UI are later milestones. This document is a handoff reference; it does not authorize another agent to publish or deploy to MainNet.

## Product behavior

Default interpretation of ephemeral: a capsule can release its key shares privately to one authorized recipient during a fixed round window. Each capsule has a fresh random data-encryption key and fresh custodian encryption keys; each access request has a fresh recipient encryption key. Unreleased custody expires.

1. Sender encrypts a message with a fresh AES-256-GCM key.
2. Sender splits that random key into five Shamir shares; any three reconstruct it.
3. Sender encrypts each share to a different custodian's capsule-specific HPKE public key.
4. A public manifest binds the capsule ID, Algorand network/application domain, recipient identity, opening/expiry rounds, ciphertext, custodian public keys, and share commitments.
5. Custodians acknowledge verified custody. A future contract activates only after the required setup acknowledgments; initially require all five to match the advertised five-custodian setup.
6. The recipient registers a fresh encryption public key in an authenticated access request.
7. Each custodian verifies confirmed chain authorization independently, then encrypts its share to that request's recipient key and authenticates the response.
8. The recipient verifies three distinct responses and reconstructs/decrypts locally.
9. Custodians stop release and dispose of shares at expiry. Honest workers must check current confirmed rounds again after asynchronous preparation and before returning a response.

Use the half-open interval `openRound <= confirmedRound < expiresRound`. Both request authorization and share release must occur in this interval. Expiry does not prohibit later decryption of responses already collected during it.

## Security claims and exclusions

- Threshold confidentiality assumes fewer than three custodians are compromised over the **whole capsule lifetime**, not merely at the same instant.
- Three colluding custodians can reconstruct early or ignore chain policy. The smart contract cannot force off-chain secrecy or erasure.
- The sender initially knows the message and encryption key; sender deletion is an assumption. The recipient can retain recovered material forever.
- Expiry ends future service access. It cannot revoke plaintext, shares, encrypted responses, backups, or snapshots already obtained.
- JavaScript buffer wiping and dropping references are best effort. Garbage collection, native crypto state, copied memory, swap, and crash dumps prevent a claim of provable secure erasure.
- Require an honest dealer in milestone 1. Hash commitments authenticate dealer-issued random shares but are not verifiable secret sharing and do not prove that the dealer issued a consistent polynomial.
- A compromised or stale authorization source can break policy enforcement. The initial in-memory ledger is an explicitly trusted test double, not an Algorand verifier.
- Custodian identities and policy metadata are public. Known committees, static shares, and local process isolation do not implement the paper's ECPSS security theorem.
- Network storage remains public and historically observable. Deleting a box is not deletion of historical secrets.
- Loss of three custodians prevents recovery. Ephemeral non-persistent custody deliberately sacrifices restart recovery.
- Encryption keys are separate from Algorand transaction-signing keys. Do not use wallet rekeying as a substitute for share refresh.

## Architecture

| Component | Responsibility |
| --- | --- |
| Sender client | Fresh key generation, authenticated encryption, splitting, encrypted deposits, manifest creation |
| Algorand application (later) | Immutable active policy, custodian registry, manifest hash, custody acknowledgments, authenticated request and replay state |
| Custodian workers | Private in-memory shares, verified authorization, recipient-encrypted signed release, expiry disposal |
| Recipient client | Fresh request key pair, response verification, threshold recovery, local decryption |
| Ciphertext store | Public/untrusted encrypted payload storage; content integrity checked against the manifest |
| Demo UI (later) | Capsule status, round countdown, custody and request progress, local opening |

Bind every cryptographic message to a versioned domain, network, application, capsule, custodian, and request as appropriate. Anchor the complete manifest digest on-chain; do not trust a replacement manifest supplied by a storage server. Avoid hashes of low-entropy plaintext secrets.

## Milestones

### 1. Standalone TypeScript crypto spike — current deliverable

Location: `crypto-spike/` beside this document.

- AES-256-GCM payload encryption with random 256-bit keys and 96-bit nonces.
- 3-of-5 Shamir using `shamir-secret-sharing`; no handwritten finite-field arithmetic.
- HPKE using `@hpke/core`: X25519, HKDF-SHA256, AES-256-GCM.
- Custodian response authentication using Ed25519 signatures over explicit, versioned envelope fields.
- Domain-separated commitments to random shares and immutable manifest integrity.
- A trusted in-memory authorization test double with explicit confirmed rounds. No wallet-signature or blockchain verification claim.
- Capsule-specific custodian state, request-key binding, one recipient request per capsule, safe retries of that same request, and expiry checks.
- A CLI demonstration and automated positive/negative tests. No secret material in routine logs or saved demo output.

Acceptance: every three-of-five subset recovers the message; fewer shares are rejected; duplicate, modified, mismatched, wrong-recipient, unauthorized, and expired requests/responses fail; explicit disposal blocks future release; already delivered responses still decrypt after expiry. TypeScript compilation and tests must pass.

### 2. Algorand application with AlgoKit / Puya TS

**Status: implemented and tested on LocalNet** in `policy-app/` (algorand-typescript/puya-ts 1.3.1). It has been revised twice. First the sender stopped naming custodians, in favour of a public beacon draw. Then that draw was replaced by hidden committees; see the hidden committee design below. The app has an admin-gated, append-only registry where members enroll their own VRF keys and post a fresh nomination key every epoch. `register` commits the terms and the registry snapshot and requests beacon randomness atomically, with an exact payment. Members nominate one-time holder keys with VRF proofs checked on-chain. The sender anchors the manifest hash, commitments and deposits once. Custody acknowledgments are authenticated by one-time-key signatures, not `Txn.sender`, and activate the capsule after all five. One recipient request binds `requestId` and the X25519 key inside `[openRound, expiresRound)`. Cleanup and withheld-proof cancellation refund the sender. There is no update, delete or opt-in path. The contract cannot recompute the manifest hash, so custodians compare manifest fields with the on-chain record before acknowledging.

- Scaffold the official Algorand TypeScript project with AlgoKit and pin compiler/toolchain dependencies.
- Start on LocalNet. Use the current stable `@algorandfoundation/algorand-typescript` and `@algorandfoundation/puya-ts` compatibility pair; verify actual versions before installing.
- Implement registration, custody acknowledgment/activation, one authenticated request binding the recipient public key, and expiry/cleanup methods.
- Store compact records in boxes and anchor the full manifest hash. Include the network genesis hash and actual application ID in crypto domains; recreate demo capsules with these real values.
- Use `Txn.sender` for the authorized account; an off-chain string is not proof of wallet ownership. Prevent key substitution and second-request races on-chain.
- Prohibit active-policy mutation. Define update/delete authorization so administrative changes cannot silently bypass immutable policy guarantees.
- Define funding and cleanup of box minimum balances and transaction fees.
- Verify round boundaries, duplicate requests, missing custody acknowledgments, unauthorized senders, cross-app replay, and upgrade/delete paths with contract tests.

### 3. Custodian services and chain adapter

**Status: implemented and tested on LocalNet** in `policy-app/src/`:
- `ChainReader` pins genesis hash and app ID and fails closed on a wrong network, an unsynced or stale node, or missing state.
- Every release re-reads chain authorization, including after the HPKE await.
- Holder keys are authenticated by the nominator's VRF proof plus its `Txn.sender`. Holders are reached only through the chain: deposits, acknowledgments and releases are on-chain, and the manifest is rebuilt from chain data and hash-checked.
- Workers have no network API. They talk only to algod, submit custody messages through a shared relayer, retry until the chain shows success, and dispose at expiry by polling rounds.
- Eight member worker processes ran in the tests.

Remaining:
- Each operator's own algod node and host. The tests share one node and one host.
- Network-level privacy for chain reads and submissions.
- Production hardening.


- Replace the in-memory ledger with independently verified confirmed application state and manifest hashes from Algorand.
- Pin expected genesis hash/application ID; reject stale or unavailable state and fail closed.
- Use an authenticated registry for custodian signing and encryption public keys.
- Run five isolated workers, then separate hosts/operators. Five processes under one operator are a functional demo, not independent trust.
- Authenticate deposit transport and acknowledgments, validate all external JSON/wire data, impose size/rate limits, and handle concurrent requests.
- Monitor rounds and expire custody without waiting for the recipient to make another request. Chain methods do not execute automatically when a round arrives.
- Preserve enough replay/authorization state for safe retries while avoiding persistent secret shares. Specify failure and restart behavior explicitly.

### 4. UI and LocalNet demonstration

**Status: partly done (2026-10-06).** `policy-app/demo` (Capsule Lab, `npm run demo`) shows:
- private release;
- premature, wrong-wallet, replay and expired refusals;
- members taken offline;
- tampered anchors;
- the variable committee and threshold;
- an operator view of the hidden holders;
- a collusion-risk comparison.

All of it uses round-based windows. The gap is that one local server plays every party, with no wallet integration and no decryption in the browser.

- TypeScript UI with wallet integration and local encryption/decryption.
- Demonstrate successful private release, premature access refusal, wrong-wallet refusal, two unavailable custodians, replay/substitution rejection, and unopened expiry.
- Display round-based eligibility, not a guaranteed wall-clock deadline. Do not label on-chain status as proof of erasure or proof that a human read the plaintext.

### 5. TestNet validation

- Deploy the tested application and distribute custodians across hosts.
- Record actual transaction fees, box funding, response latency, and recovery/failure behavior.
- Publish reproducible demo instructions and a threat-model statement. Use synthetic secrets only.

### Later research track

See PAPER_ALIGNMENT_PLAN.md (2026-10-09) for the proposed design and phases.


Add proactive share refresh only with a reviewed protocol and implementation. Refresh actual shares, not just transport encryption keys. Test cross-epoch share accumulation and failed handovers. Hidden holding committees, anonymous nomination, selective-opening security, and the paper's ECPSS construction are a distinct research scope; ordinary HPKE is not a drop-in replacement for its anonymous encryption requirements.

## VRF integration decision

**Decision (2026-10-06): we run our own instance of [bwmx/randomness-beacon](https://github.com/bwmx/randomness-beacon) at commit `0e164c3`.** It is the public randomness beacon facility in the table below. It is used **only as the common sortition seed**. Selection itself uses participant-local VRF keys, as described in the hidden committee design below.

- **Operator:** a single operator (us) holds the VRF key.
- **Proofs:** the AVM `vrf_verify` (draft-03) checks proofs of each target round's block seed.
- **Delivery:** the beacon delivers per-request randomness to our app's `fulfillRandomness` callback. Its daemon proves and relays.
- **Implementation:** in `policy-app/`; see its README for the trust analysis.

This is useful for committee selection, not for keeping a key secret. Never derive capsule encryption keys or shares from public VRF outputs.

The paper explicitly discusses VRFs in section 2.3, "Verifiable Random Functions and Cryptographic Sortition" (PDF page 10), and uses sortition to choose **nominating committees**. Nominators establish anonymous channels to holding committees; directly publishing holding-member VRF proofs would reveal those holders and would not reproduce the paper's construction. Section 2.3 also discusses input grinding.

Distinguish three facilities:

| Available facility | Useful role | Limitation |
| --- | --- | --- |
| Public randomness beacon / VRF service | Reproducibly select a committee from a frozen eligible registry | Selection becomes public; operator withholding and seed timing need explicit handling |
| Participant-local VRF key pairs | Private self-selection followed by verifiable proof disclosure | Requires registered keys, unbiased/common input, admission controls, and a protocol for variable committee size |
| AVM `vrf_verify` opcode | Verify a compatible off-chain VRF proof on-chain | Does not generate proofs, provide a secret key, or automatically expose consensus committee membership |

Architecture addition: put `CommitteeSelector` before capsule creation. Milestone 1 uses `FixedCommitteeSelector`; the manifest binds the selection mode, epoch/registry reference, and selected custody keys. A later selector must validate VRF evidence and bind its digest into the manifest/chain record. The crypto layer still accepts exactly five explicitly selected custodians for this spike. Do not pretend selecting five from a five-member pool improves security.

Before implementing VRF selection (how each item was resolved is noted in parentheses):

- 1: beacon `0e164c3`; we operate the key; 80-byte proof, 64-byte output; seed = target round's block seed.
- 2: append-only admin registry with member-enrolled VRF keys; snapshot by size at registration.
- 3: terms, snapshot and beacon request are committed in one transaction, 8 rounds before the seed round, and the capsule ID is the beacon request ID. Abandon-and-re-register remains possible and is publicly visible.
- 4: private sortition per slot with a threshold; the lowest rank wins; an empty slot or a withheld proof leads only to expiry/cancellation and refund, never a fallback.
- 5: real daemon proofs verified on LocalNet.
- 6: the beacon pays its own op-ups; each nomination's `vrf_verify` needs nine op-ups (10,000 µAlgo).
- 7: worse than the public draw at 3-of-5, because of nominator control and draws with replacement. See the design section.


1. Identify the actual VRF service or library, key ownership, output/proof format, and seed source.
2. Freeze eligible identities, registered VRF keys, and stake/weights before a specified future seed is known. Prevent Sybil registrations and key grinding through explicit admission rules.
3. Domain-separate network genesis hash, application ID, protocol version, epoch, and selection purpose. Bind capsule enrollment before its future seed so a sender cannot retry IDs/seeds until it gets a favorable committee.
4. Specify unbiased sampling without replacement for public fixed-size selection, or probability/size handling for private sortition. Define no-proof/withholding behavior without creating a biased fallback.
5. Check AVM compatibility: Algorand's documented `VrfAlgorand` uses the draft-03 ECVRF suite, which is not automatically compatible with final RFC 9381 implementations. Validate real positive/negative vectors against LocalNet and Puya TS.
6. Budget the documented `vrf_verify` cost (5700 opcode units, subject to current protocol verification) using the appropriate AlgoKit/AVM budgeting mechanism; measure actual grouped transaction costs.
7. Reassess committee compromise probability. A 3-of-5 demo does not inherit the paper's large-population resilience bounds.

Recommended sequence: complete the fixed-committee crypto spike, integrate Algorand policy, then add verified VRF-based **public** committee selection if the available facility is a beacon. Reserve private nominating committees and anonymous holding committees for the research track. **Status: public beacon selection was built first, then superseded by hidden committees (`algorand-hidden-v1`).**

References: [paper §2.3](https://eprint.iacr.org/2020/464.pdf), [Algorand randomness](https://dev.algorand.co/concepts/protocol/randomness/), [AVM vrf_verify](https://dev.algorand.co/reference/algorand-teal/opcodes/), [draft/RFC compatibility](https://staging.dev.algorand.co/concepts/smart-contracts/cryptographic-tools/).

## Hidden committee design (paper-aligned VRF use)

**Status: implemented and tested on LocalNet (2026-10-06).**

The earlier public beacon draw (`algorand-beacon-v1`, now removed) published who holds the shares. In the paper, VRFs select **nominators** privately, and nominators hand **one-time holder keys** to holders anonymously. This design keeps the beacon only as the common seed and implements steps 1–4 below on unmodified Algorand. It replaces the public draw (`algorand-hidden-v1`).

1. **Registered VRF keys.** The admin admits an account (the Sybil gate). That account then enrolls its own VRF public key, once and immutably. A capsule only considers members enrolled before its registration (the snapshot), so nobody can pick keys after seeing a seed. Each member also posts a fresh X25519 nomination key for every epoch (`postNominationKey`, current or next epoch, never replaced), the paper's per-epoch PKI key (§2.1, §3.1.3). A capsule binds to its registration epoch. *Not implemented:* weighting by online stake via AVM `voter_params_get` / `online_stake`.
2. **Private sortition seeded by the beacon.** For capsule `c` and holder slot `k`, member `i` privately computes `VRF_i(sha256("capsule/nominate/v1" ‖ appId ‖ c ‖ k ‖ beaconRandomness))`. It is eligible if the first 8 output bytes, read as a uint64, fall below `nominatorThreshold`. Eligible members post their proof. The contract checks it with `vrf_verify` against the enrolled key, and requires `Txn.sender` to be that member so a copied proof can't be reused. The lowest output per slot wins. Nominations close at `seedRound + nominationRounds`. Nominators are public once they post. A slot left empty means the capsule can't proceed; there is no fallback.
3. **Anonymous nomination.** The winning nominator picks a holder uniformly, with private randomness, among snapshot members that posted a key for the capsule's epoch. It makes a fresh 32-byte seed from which both one-time holder keys derive (HPKE X25519 and Ed25519). It posts the two public keys plus the seed HPKE-sealed to the holder's key for that epoch, then erases the seed and its choice. Once nominations close, holders find their slots by trying to decrypt every nomination. Each member erases an epoch's private key once every capsule of that epoch has closed nominations.
4. **Hidden holders, chain as message board.**
   - The sender builds the manifest from the slot public keys (descriptor IDs `slot-0`…`slot-4`).
   - It anchors the manifest hash on-chain together with the payload hash, the five share commitments and the five HPKE deposits, so anyone can rebuild the manifest from chain data and check the hash.
   - Holders acknowledge with an Ed25519 signature from their one-time key, checked on-chain with `ed25519verify_bare`.
   - After the recipient's on-chain request, holders post their releases on-chain (the spike's signed release plus a chain signature).
   - A shared relayer account submits acknowledgments and releases, so no holder account appears on-chain. Holders read the chain through their own node, and custodian workers have no HTTP API.
   - The payload ciphertext stays off-chain; its hash is anchored.

Accepted consequences, stated plainly:
- **A corrupt nominator controls its slot.** It knows the one-time keys until it erases them. So a slot is corrupt if its nominator *or* its holder is, roughly `1 − (1 − f)²` for a corrupt fraction `f`. The paper has the same "double dip" (§1.2); it is why its tolerance stops at f < 1 − √0.5 ≈ 29%.
- **Holders are drawn with replacement.** One member can hold several slots. The paper also picks each nominee uniformly from all parties (§3.1.2).
- **Small 3-of-5 committees tolerate far less corruption than the public draw.** These risks shrink only with large committees (step 5).
- **Forward secrecy rests on erasure** (fixed 2026-10-09; previously a long-term nomination key decrypted every seed ever sealed to it). Deposits and sealed seeds stay on-chain forever, but each epoch's nomination key lives only in its worker's memory and is erased once the epoch's nominations close. `createApplication` requires `8 + nominationRounds < epochRounds`, so the 3-entry key ring never overwrites a key still in use. The paper erases before a holder posts because posting reveals the holder (§1.2). Here the relayer posts, so erasure at the end of the epoch suffices. A restarted member cannot reopen its seeds, so it loses custody.
- **Anonymity is not proven.** HPKE's ability to hide the recipient and its security when some holders are later exposed have not been reviewed against the paper's requirements.
- **Erasure, network-level privacy and liveness remain assumptions.**

Step 5 is implemented. The sender picks up to 64 slots and a minimum committee. The committee is the filled slots, with threshold `⌊n/2⌋ + 1`. Deposits and cleanup are batched, and activation needs a threshold of acknowledgments.

Not implemented:
- Step 6: re-sharing between epochs (ECPSS).
- Stake weighting.

## Handoff instructions

Read this file and `crypto-spike/README.md` before continuing. Run `npm ci`, `npm test`, and `npm run demo` inside `crypto-spike/`. Preserve the crypto/chain boundary and all security limitations. Do not infer successful Algorand integration from an in-memory authorization test. Record actual completed work and verification in the README; distinguish a tested demo from audited production security.

## References

- [Reference paper](https://eprint.iacr.org/2020/464.pdf)
- [Algorand TypeScript / Puya TS](https://dev.algorand.co/docs/algorand-typescript/typescript/latest/)
- [AlgoKit TypeScript compilation](https://dev.algorand.co/algokit/cli/compile/)
- [Algorand storage and public box visibility](https://dev.algorand.co/concepts/smart-contracts/storage/overview/)
- [HPKE, RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)
- [HPKE implementation](https://github.com/dajiaji/hpke-js)
- [Shamir implementation and its security considerations](https://github.com/privy-io/shamir-secret-sharing)
