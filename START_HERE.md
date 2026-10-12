# Keepsake: agent handoff

Keepsake is a proof of concept of "Can a Public Blockchain Keep a Secret?" (eprint 2020/464) on Algorand. See README.md for the one-page overview.


## Resume in one minute

1. Read this file, then IMPLEMENTATION_PLAN.md, then PAPER_ALIGNMENT_PLAN.md (the proposed route to the paper's ECPSS).
2. Read crypto/README.md, crypto/PROTOCOL.md and chain/README.md.
3. Inspect the TypeScript sources and tests before changing the protocol.

## User intent and decisions

Build an Algorand POC inspired by https://eprint.iacr.org/2020/464.pdf using ephemeral secrets/keys.

The user explicitly selected **AlgoKit + Algorand TypeScript / Puya TS**. The initial chat's Python suggestion is superseded. Off-chain cryptography uses ordinary TypeScript/Node.js, outside the AVM compilation target.

The user requested implementation of the first crypto package and a reusable Markdown plan. Both are complete. The first on-chain design (2026-10-06) used our own instance of https://github.com/bwmx/randomness-beacon for beacon-seeded per-capsule committees; see "Hidden committee design" in IMPLEMENTATION_PLAN.md. **Superseded 2026-10-10:** the user had the design brought closer to the paper (PAPER_ALIGNMENT_PLAN.md). Evolving epoch committees now seed sortition from Algorand's block seed, and the per-capsule design, its beacon submodule and its relayer were removed. They remain in Git history before that date.

Working product assumption: private release to one authorized recipient during a bounded round window, with expiry ending future service access. Public reveal and indefinite rotating custody were alternatives, not implemented features.

## Current implementation

| Package | State |
| --- | --- |
| `crypto/` | Off-chain cryptography. Milestone 1 (`protocol.ts`, its demo and tests) is the original per-capsule spike: AES-256-GCM payload, majority-threshold Shamir, HPKE deposits and responses, an anchored manifest, and a trusted in-memory ledger. The paper alignment added: the unreviewed pairing re-sharing and capsule KEM (`pvss.ts`, `ecpss.ts`); the verification thread pool (`parallel.ts`); per-committee vault processes (`vault.ts`); and the committee-size calculator (`params.ts`) |
| `chain/` | The `EpochCommittee` app (Algorand TypeScript/Puya TS) and its off-chain side. Evolving epoch committees are drawn by stake-weighted VRF sortition on the block seed; holders speak once per seat to re-share bucket keys to the next committee; capsules are released from handover messages. Members join without permission and pay their own deposits. It also has the member worker and CLI, the LocalNet environment, Capsule Lab (`npm run demo`) and the TestNet trial (`npm run trial`). See chain/README.md |
| Paper alignment (`PAPER_ALIGNMENT_PLAN.md`) | Phases 0–6 done 2026-10-09 and 2026-10-10, unreviewed; Phase 6 ran a five-member TestNet trial, not a full-size deployment. Phase 6: each committee's secrets live in a short-lived vault process that exits before its seats speak (`crypto/src/vault.ts`); senders refuse to lock when the liveness margin is thin; a new or restarted member joins from the attested state; `chain/src/epoch-worker.ts` runs as a member CLI. Accountability spike (2026-10-11): holders sign a Merkle root over their dealings, and anyone proves a bad subshare on chain (`reportBadDealing`, pairing checks with Algorand's BLS12-381 opcodes) to slash the holder's bond. Withdrawals now unbond over four epochs. TestNet trials (`npm run trial` in `chain/`): first five members with 5-seat committees, then 60-seat committees, where every handover posted all 60 messages once each seat posts as one atomic group. Capsule round trips worked, at about 0.023 Algo per seat per epoch. One run's cleanup bug stranded 17.32 TestNet Algo; it is fixed. Phase 5: stake-weighted, permissionless membership (anyone enrolls with a bond; weight is the bond capped by online stake; one seat per winning VRF ticket; members, nominators and senders pay for their own boxes; `chain/test/epoch-stake.test.ts`). Phase 4: capsules on bucket keys (`registerCapsule`, `requestAccess`; holders release partials sealed to the recipient in their handover messages and attest the public state; `chain/src/epoch-capsules.ts`), and Capsule Lab runs this design. Phase 3: `chain/src/epoch-worker.ts` runs the epochs (nominate, open seats, one handover message per seat from the holder's own account, verify on a thread pool, combine, clean up old committees). Phase 1: `chain`'s `EpochCommittee` app and `src/epochs.ts` (per-epoch committees from block-seed VRF sortition, seats in key order, a claimed seat posts one chunked handover message, readers rebuild it from blocks). Phase 2: `crypto/src/ecpss.ts` (pairing-based re-sharing, committee-generated bucket keys, the capsule KEM). The older per-capsule design (`CapsulePolicy`, the beacon submodule and the relayer) was removed 2026-10-10 |

Not built:
- A full-size TestNet deployment (only a five-member trial has run).
- Per-member nodes and hosts.
- A cryptographer's review.

## Verified state

Current, 2026-10-12: `crypto` 40 passing tests; `chain` 8 passing LocalNet tests (`epochs`, `epoch-workers`, `epoch-capsules`, `epoch-join`, `epoch-stake`, `epoch-slash`). Same toolchain as below, without pnpm for the beacon. Milestone 4 is done: Capsule Lab's senders and recipients use a wallet (LocalNet KMD or the Lute extension) and seal, request and decrypt in the page; the crypto package now runs in browsers too. Capsule Lab was driven end to end in headless Chrome on 2026-10-12 (`npm run browser-check` in `chain/`), with the KMD wallet and a check that the plaintext never reaches the server:
- the flow: start, lock once a key is attested, wrong wallet refused, request, a copied capsule refused by holders, decrypt;
- the operator view, and a member taken offline and back;
- desktop, phone width (no sideways scroll) and dark mode.

There were no page errors. The entries below are the history.

Verified 2026-10-06 on Node.js v24.15.0, AlgoKit 2.10.2, LocalNet algod 5.0.1, puya-ts 1.3.1/puya 5.10.1, pnpm 12.6.0 (beacon only):

- `crypto`: `npm test` gives 26 passing tests; `npm run demo` passes all six checks.
- `chain`: `npm test` gives 8 passing LocalNet tests: 5 contract tests and 3 worker tests, including a 24-member, 16-slot end-to-end run with the real beacon daemon. Capsule Lab was exercised in a browser, desktop and phone widths.

Re-verified 2026-10-09 after per-epoch nomination keys, same toolchain: `crypto` 26 passing; `chain` 8 passing, twice. The end-to-end test now also shows that a restarted member cannot reopen its seats and that online holders erase their epoch key while still holding custody. Capsule Lab was smoke-tested through its API: nominations, custody, epoch-key erasure, release and decryption. It was not re-checked in a browser.

Phase 0 of PAPER_ALIGNMENT_PLAN.md, 2026-10-09: `crypto` 31 passing tests (adds the committee-size calculator and the unreviewed pairing prototype). `npm run params` and `npm run bench` in `crypto/`, and `npm run probe` in `chain/`, reproduce the plan's numbers. `chain` still has 8 passing tests.

Phases 1–2, 2026-10-09: `crypto` 35 passing tests; `chain` 11 passing LocalNet tests (adds 3 for `EpochCommittee`, including an on-chain handover between two real committees).

Phase 3, 2026-10-09: `crypto` 36 passing tests; `chain` 12 passing LocalNet tests (adds a 22-handover run of ten member workers with outages, about 3 minutes; passed twice in a row).

Phase 4, 2026-10-09: `crypto` 37 passing tests; `chain` 13 passing LocalNet tests (adds a capsule run with eight member workers, about 80 seconds; passed twice). Capsule Lab was smoke-tested through its API (lock, wrong wallet, request, open, replay refused, no worker errors). It was not checked in a browser.

Setup from the bundle root (Node 24+, Docker, Git and network access for npm and GitHub; pnpm 12.6.0 is fetched for the VRF library's prepare step):

```sh
(cd crypto && npm ci --ignore-scripts && npm test && npm run demo)
algokit localnet start
(cd chain && npm exec --yes --package=pnpm@12.6.0 -- npm ci && npm test)
```

No wallet seed or funded account is needed for the tests. They generate LocalNet throwaway accounts and VRF keys. Only the TestNet trial needs a funded TestNet account, as `TESTNET_MNEMONIC` in the git-ignored `.env`. Archive integrity for our own files is in SHA256SUMS.txt.

## Next work

Per-epoch nomination keys are done (2026-10-09). The proposed next track is PAPER_ALIGNMENT_PLAN.md. Phases 0–5 are done (2026-10-09 and 2026-10-10; see the results sections there), and so is Phase 6, including a five-member TestNet trial. A full-size TestNet deployment is next. It needs committee parameters, a bonded population and a node per member. TestNet runs the same consensus version as LocalNet (checked 2026-10-10), so Phase 0's measured limits and fees apply. Separately: wallet integration and browser decryption for Capsule Lab. Before a full-size TestNet deployment, give each member its own algod node and host and a private network path to it.

## Security boundaries to preserve

- The sender knows the plaintext. Any t corrupt seats of one epoch's committee expose every live bucket, so every capsule under them.
- Security needs fewer than t corrupt seats per epoch; liveness needs t honest seats speaking per handover, or every live bucket is lost. Test and demo committees are small and tolerate little corruption.
- Public VRF output and block seeds are not secret keys.
- Forward secrecy rests on erasure: vault processes exit before their seats speak, but JavaScript erasure is not provable.
- The weight is bonded stake; f is the adversary's share of bonds. Nominators are public and know their seats' keys until they erase them.
- Each worker trusts its own algod node. A shared node sees which account reads what.
- Expiry blocks new releases, but releases already delivered can decrypt later.
- The cryptography (pairing re-sharing, KEM, proofs) is unreviewed, and RIND-SO and HPKE anonymity are open questions (PAPER_ALIGNMENT_PLAN.md).
- This integration is unaudited. No real secrets are supplied in the export.

## Bundle contents

- IMPLEMENTATION_PLAN.md: implementation milestones, architecture, threat model, VRF decisions.
- crypto/: off-chain crypto source, tests, package files, lockfile, README and protocol specification.
- chain/: contracts, chain reader, member worker, capsule client, LocalNet environment and tests, Capsule Lab, benches, package files, lockfile and README.
- PAPER_ALIGNMENT_PLAN.md: the route to the paper's design, with each phase's results.
- SHA256SUMS.txt: checksums of our own files (excludes dependencies and build output).

Dependencies (node_modules), generated dist/ and contract artifacts are excluded. Regenerate them with npm. The paper is referenced by URL, not included as a PDF.

