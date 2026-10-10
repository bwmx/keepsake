# Ephemeral capsule crypto spike

Working milestone 1 for [the Algorand implementation plan](../IMPLEMENTATION_PLAN.md).

**Chain stack: AlgoKit + Algorand TypeScript / Puya TS.** This package implements the off-chain cryptography in ordinary TypeScript. There is no deployed contract, Algorand RPC connection, wallet verification, VRF implementation, or network service in this milestone. Those belong behind the explicit integration boundaries below.

## Run

Requires Node.js 24 or later and npm. Dependencies and transitive versions are pinned in `package-lock.json`.

```sh
cd crypto-spike
npm ci --ignore-scripts
npm test
npm run demo
npm run params   # Committee sizes for the paper alignment plan
npm run bench    # Pairing re-sharing prototype at C = 64, 120, 200 (a few minutes)
```

If handing the folder to another machine, use its own checkout path in the `cd` command. The code has no absolute-path dependencies and needs no `.env`, wallet seed, funded account, Docker, or network access after installing packages. Run only with synthetic secrets.

The demo generates fresh material on every invocation. It reports a public manifest hash and assertions, never plaintext, shares, private keys, or reconstructed encryption keys. It explicitly identifies its authorization source as a trusted mock ledger. It returns a nonzero exit code on failure.

## Implemented

- Fresh 32-byte random data key; AES-256-GCM with a 12-byte random nonce and 16-byte tag.
- Majority-threshold Shamir splitting/reconstruction via `shamir-secret-sharing@0.0.4`: committees of 3–64, `thresholdFor(n) = ⌊n/2⌋ + 1` (the fixed demo is 3-of-5).
- One fresh X25519 key pair per custodian per capsule; fresh request-recipient key pair.
- HPKE Base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM via `@hpke/core@1.9.0`.
- Independent fresh Ed25519 custodian signing keys, generated per capsule. These are demo protocol identities, not wallet addresses or consensus participation keys.
- Recipient-encrypted, signed responses bound to the exact manifest, request ID, recipient encryption key, and custodian.
- SHA-256 commitments to dealer-issued random shares, checked after decryption. This catches a correctly signed but corrupted share; it is not VSS.
- A versioned manifest binding network/application IDs, access window, recipient identity, committee keys and selection metadata, share commitments, and encrypted payload hash.
- Best-effort secret-buffer wiping, disposal of private-key references, and loss of the deposit decryption key immediately after successful custody acceptance.
- Same-request retries with fresh HPKE envelopes; duplicates cannot count toward the threshold.
- Round checks before and after asynchronous release encryption; disposal/expiry while waiting prevents release.
- An explicit fixed-committee selector and an authorization-source boundary. The selection mode also accepts `algorand-hidden-v1` (anonymous one-time holder keys, built by `../policy-app`). `Custodian.fromSeed()` derives one-time holder keys from a 32-byte seed. `accept()` needs only the anchored manifest, and the payload is checked by the recipient. `signChainMessage()` signs binary chain messages under a prefix that cannot collide with the JSON signatures. `AuthorizationSource` may be asynchronous; custody is re-checked after every await.

## Files

| File | Responsibility |
| --- | --- |
| `src/crypto.ts` | HPKE, AES-GCM, byte encodings and domain utilities |
| `src/protocol.ts` | Public message types, capsule/deposit/release/recovery, custodian lifecycle, committee selection boundary |
| `src/mock-ledger.ts` | Trusted in-memory confirmed-round/authorization test double |
| `src/demo.ts` | Executable end-to-end demonstration with synthetic data |
| `test/protocol.test.ts` | Integration and adversarial cases |
| `src/params.ts`, `test/params.test.ts` | Committee size and threshold for the paper's §3.2 process: the paper's bounds and exact tails (Phase 0 of `../PAPER_ALIGNMENT_PLAN.md`) |
| `src/ecpss.ts`, `test/ecpss.test.ts` | **Unreviewed** Phase 2–4 library. It covers seat keys from a nominator's seed and the per-epoch handover message: re-sharing every live bucket, new committee-generated buckets, sealed capsule releases, and the attested public state. It also covers receiving a handover, reconstruction, the capsule KEM with replay binding, and a strict wire format |
| `src/parallel.ts`, `src/parallel-worker.ts`, `test/parallel.test.ts` | `VerifyPool`, a work-queue thread pool, and `receiveParallel`. It decodes and checks handover messages on every core, then decodes only the chosen dealings' commitments and the caller's subshares. Its result matches the single-threaded `receive` |
| `src/pvss.ts`, `test/pvss.test.ts`, `bench/pvss.bench.ts` | **Unreviewed Phase 0 prototype** of the plan's pairing-based re-sharing, committee key generation and capsule KEM, with correctness tests and a benchmark. Not for real secrets |
| `PROTOCOL.md` | Message encoding, trust and key lifecycle specification |
| `../IMPLEMENTATION_PLAN.md` | Handoff roadmap including VRF decisions and Puya TS integration |

## Verification completed

Verified on 2026-10-06 with Node.js v24.15.0, TypeScript 5.9.3, `@types/node` 24.19.1, and the lockfile dependencies:

- `npm test`: strict TypeScript compilation and **26 passing tests**. On 2026-10-09 this grew to 31 with the Phase 0 committee-size and pairing-prototype tests, then to 35 with the Phase 2 library tests, 36 with the Phase 3 thread-pool test and 37 with the Phase 4 message-section test.
- `npm run demo`: all six behavioral assertions passed.
- All ten three-of-five subsets recover the exact original message; four and five responses also work in shuffled order.
- Insufficient and duplicate responses fail; two unavailable custodians leave three capable of recovery.
- Invalid signatures, wrong recipient keys, altered deposits/ciphertext, cross-capsule responses, changed domains/policy, and signed invalid shares are rejected.
- Tests cover round boundaries, unconfirmed requests, replacement recipient keys, retries, async request mutation, disposal during release, and expiry during release.
- Expired custody refuses future release; previously delivered responses still decrypt after expiry.

These tests exercise protocol behavior, not a proof of cryptographic secrecy or a security audit. The fewer-than-three check is an API guard; the confidentiality argument relies on the secret-sharing primitive and stated assumptions. This package itself has not been audited. The upstream Shamir project's published audit claims do not constitute an audit of this integration.

## Security and operational boundaries

The sender sees the original plaintext/key. Three custodians can collude at any time during the capsule lifetime. The recipient can retain everything received. Short lifetimes limit exposure; static shares do not provide proactive protection against accumulated compromises.

The complete manifest digest must arrive through a trusted channel. In this spike the sender passes it directly to clients/custodians and registers it in the mock ledger. A storage server supplying both a replacement manifest and its replacement hash is not a trust anchor. The eventual application must bind the manifest hash to authenticated registration.

`MockConfirmedLedger.authorize(request, caller)` takes a **trusted simulated identity string**. It does not authenticate a wallet. `register()` simulates activation after custody has been established; it does not validate on-chain custody acknowledgments. Do not expose either method as a production API.

In this package, the demo advances rounds manually and calls expiry explicitly. The chain-backed asynchronous adapter, which pins the network and fails closed, is in `../policy-app/src/chain.ts`. The worker with background expiry is in `../policy-app/src/worker.ts`.

The interval is `[openRound, expiresRound)`. Successful response delivery can be followed by decryption after that interval. No protocol here provides recall, self-destructing plaintext, trusted timestamps of human access, or proof of erasure.

JavaScript/native-library memory copies and garbage collection mean wiping is best effort. Fresh HPKE key objects are not hardware-protected. No shares are intentionally persisted; a restart loses custody. Implement storage, crash handling, backups and process isolation only after reviewing how each affects ephemeral guarantees.

`recover()` fails closed on any invalid supplied response. It does not automatically identify and discard bad responders; a client can retry with three other valid responses. Inputs are typed internal objects with targeted integrity/length checks, not a fully hardened JSON/network API. Before network exposure, add strict wire schemas, transport authentication, payload limits before allocation, rate limits, and concurrency/restart handling.

## How the VRF fits

The paper's section 2.3 explicitly defines VRF-based cryptographic sortition. In its construction, sortition selects nominators; those nominators arrange anonymous channels to secret-holding members. Publishing a holding member's own VRF proof reveals that member, so direct public selection does not reproduce the paper's hidden holding committees.

The `CommitteeSelector` returns five explicit descriptors and selection metadata before encryption. This package implements `FixedCommitteeSelector` / `fixed-demo`. `algorand-hidden-v1` is accepted for hidden committees nominated on-chain by `../policy-app`. Their descriptor IDs are `slot-0`…`slot-4`, and the `registryReference` binds the beacon app, request, registry snapshot and randomness into the manifest hash. Holders rebuild the whole manifest from chain data. Other modes are rejected.

- **Public beacon:** useful for reproducible public committee selection from a frozen larger registry.
- **Participant-local VRFs:** useful for private self-selection; require registration, seed/grinding defenses, and proof-disclosure rules.
- **`vrf_verify` alone:** a verifier, not a generator or secret randomness source. It has an AVM budget cost and suite compatibility requirements.

**Chosen (2026-10-06):** our own instance of [bwmx/randomness-beacon](https://github.com/bwmx/randomness-beacon), a public beacon, integrated in `../policy-app`. None is needed to run this spike. Never use a published VRF value as a secret data key, share, or supposedly private deterministic key seed.

## Next agent's starting point

1. Read `../IMPLEMENTATION_PLAN.md` and `PROTOCOL.md`; run the commands above.
2. Scaffold the contract with **AlgoKit's Algorand TypeScript / Puya TS tooling**, not Python or TEALScript. Keep these Node crypto modules outside the AVM compilation target.
3. Done on LocalNet in `../policy-app/`: immutable policy, custody activation, request-key binding and real genesis hash/application ID binding, with contract tests. Remaining: replace mock authorization in custodians with independently verified, fresh chain state (milestone 3).
4. Done: VRF provider identified (public beacon) and selection implemented on-chain in `../policy-app`. Milestones 2–3 are complete on LocalNet; the next is milestone 4.

## Sources

- [Reference paper](https://eprint.iacr.org/2020/464.pdf), especially sections 1.2, 2.3 and 3.
- [HPKE RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) and [hpke-js implementation](https://github.com/dajiaji/hpke-js).
- [Shamir library and security considerations](https://github.com/privy-io/shamir-secret-sharing).
- [Algorand TypeScript](https://dev.algorand.co/docs/algorand-typescript/typescript/latest/) and [AlgoKit compilation](https://dev.algorand.co/algokit/cli/compile/).
- [Algorand randomness](https://dev.algorand.co/concepts/protocol/randomness/) and [AVM opcode reference](https://dev.algorand.co/reference/algorand-teal/opcodes/).
