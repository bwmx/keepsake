# Keepsake crypto

The off-chain cryptography of Keepsake, in plain TypeScript. It knows nothing about Algorand: [`chain/`](../chain/README.md) carries its messages and imports it as `keepsake-crypto`. How the pieces fit together is in [docs/design.md](../docs/design.md).

**Unreviewed.** None of this has had a cryptographer's review. Do not use it for real secrets.

The shared modules (`crypto.ts`, `pvss.ts`, `ecpss.ts`, `fraud.ts`) use only `@noble/*` and `@hpke/core`, so they run in browsers as well as Node; Capsule Lab bundles them. The thread pool and the vaults are Node-only.

## Run

Needs Node.js 24+ and npm. No network, wallet or Docker after installing.

```sh
npm ci --ignore-scripts
npm test               # 43 tests, about 30 seconds
npm run params         # Committee size table
npm run bench          # Plain re-sharing at C = 64, 120 and 200 (a few minutes)
npm run bench:packed   # Plain against packed handovers
npm run demo           # The legacy per-capsule spike (see below)
```

## Modules

| File | What it does |
| --- | --- |
| `src/pvss.ts` | Pairing-based publicly verifiable re-sharing on BLS12-381: dealings (in coefficient or evaluation form), batch verification, combining shares, Schnorr proofs, the capsule KEM, and decryption partials with their proofs. Strict wire formats with subgroup checks |
| `src/ecpss.ts` | Evolving-committee secret sharing on top of `pvss.ts`. Seat keys from a nominator's seed; a holder's handover message (re-shares, new-bucket contributions, sealed releases, attested state); the pack and unpack schedule (`handoverPlan`); receiving a handover (`validSeats`, `choose`, `adopt`); reconstruction; and the capsule KEM with replay binding |
| `src/fraud.ts` | Fraud proofs for bad dealings. One Merkle leaf per (dealing, recipient), in the encodings Algorand's `ec_*` opcodes take, each carrying the commitment the subshare should open to. Finds the first bad subshare and builds the proof `reportBadDealing` checks |
| `src/parallel.ts`, `src/parallel-worker.ts` | `VerifyPool`, a thread pool that decodes and verifies handover messages on every core. `receiveParallel` matches the single-threaded `receive` and also returns the liveness margin |
| `src/vault.ts`, `src/vault-process.ts` | `SeatVault`: one short-lived child process per committee's secrets. It opens seats, combines shares, and builds messages, releases and claim signatures, then exits before anything is posted. It refuses to start with core dumps on, or with swap unencrypted (macOS) or on (Linux) |
| `src/params.ts` | Committee size and threshold for a corrupt fraction f: the paper's Chernoff bounds and exact Poisson tails, with packed epochs' t + ℓ − 1 liveness need |
| `src/crypto.ts` | Shared helpers: HPKE (X25519, HKDF-SHA256, AES-256-GCM), AES-256-GCM payloads, encodings and checks |

| Test | Covers |
| --- | --- |
| `test/pvss.test.ts` | The re-sharing algebra: keys survive handovers, bad dealings are dropped, epochs don't mix, partials reproduce the KEM key, evaluation-form dealings |
| `test/ecpss.test.ts` | Ten handovers through random committees with up to t − 1 cheaters, plain and packed; expired buckets are never re-dealt; the KEM on plain and packed states; replay refusal; strict wire and state decoding |
| `test/fraud.test.ts` | Proofs for bad subshares, and none for good ones |
| `test/parallel.test.ts` | The thread pool agrees with the single-threaded path |
| `test/vault.test.ts` | Secrets survive from vault to vault through plain, pack and unpack handovers; a vault refuses to start with core dumps on |
| `test/params.test.ts` | The paper's table, reproduced to within 2% |
| `test/protocol.test.ts` | The legacy spike (26 tests) |

## The legacy per-capsule spike

`src/protocol.ts`, `src/mock-ledger.ts`, `src/demo.ts` and `test/protocol.test.ts` are Keepsake's first milestone, kept because they still run and test cleanly. The epoch design does not use them; it shares only `crypto.ts`.

The spike locks a message for a fixed committee of five custodians:
- The sender encrypts with AES-256-GCM, splits the key 3-of-5 with Shamir (`shamir-secret-sharing`), and HPKE-encrypts each share to one custodian.
- A trusted in-memory ledger stands in for the chain and authorizes one recipient request inside `[openRound, expiresRound)`.
- Each custodian returns its share encrypted to the recipient's fresh key and signed with Ed25519, and the recipient combines any three.

`npm run demo` runs it end to end with synthetic data and six checks.

It has none of the paper's protections: the committee is fixed and known, the sender is a trusted dealer, shares are never refreshed, and the ledger is a test double. Its message formats are specified in [SPIKE_PROTOCOL.md](SPIKE_PROTOCOL.md), and its history is in [docs/history.md](../docs/history.md).
