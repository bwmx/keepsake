# Agent handoff: Algorand ephemeral secret capsules


## Resume in one minute

1. Read this file, then IMPLEMENTATION_PLAN.md, then PAPER_ALIGNMENT_PLAN.md (the proposed route to the paper's ECPSS).
2. Read crypto-spike/README.md, crypto-spike/PROTOCOL.md and policy-app/README.md.
3. Inspect the TypeScript sources and tests before changing the protocol.

## User intent and decisions

Build an Algorand POC inspired by https://eprint.iacr.org/2020/464.pdf using ephemeral secrets/keys.

The user explicitly selected **AlgoKit + Algorand TypeScript / Puya TS**. The initial chat's Python suggestion is superseded. Off-chain cryptography uses ordinary TypeScript/Node.js, outside the AVM compilation target.

The user requested implementation of the first crypto spike and a reusable Markdown plan. Both are complete. The user also stated a VRF is available. **Resolved 2026-10-06:** use our own instance of https://github.com/bwmx/randomness-beacon (a public, single-operator VRF beacon, pinned at commit 0e164c3) as the common seed for private VRF sortition. Members nominate anonymous one-time holder keys, following the paper's nominating-committee idea. See "Hidden committee design" in IMPLEMENTATION_PLAN.md.

Working product assumption: private release to one authorized recipient during a bounded round window, with expiry ending future service access. Public reveal and indefinite rotating custody were alternatives, not implemented features.

## Current implementation

| Package | State |
| --- | --- |
| `crypto-spike/` | Milestone 1: AES-256-GCM payload, majority-threshold Shamir (3–64 custodians; fixed demo 3-of-5), HPKE deposits/responses, Ed25519 response signatures, anchored manifest/share commitments, request binding, best-effort disposal. Its own tests and demo use the trusted in-memory ledger and fixed committee. It now also supports the `algorand-hidden-v1` committee mode, one-time holder keys derived from a seed, manifest-only custody acceptance, domain-separated chain signatures and an async `AuthorizationSource` |
| `policy-app/` | Milestones 2–3 on LocalNet: the `CapsulePolicy` app (Algorand TypeScript/Puya TS) with hidden, variable-size holder committees (design steps 1–5). Members enroll VRF keys, post a fresh nomination key every epoch (erased once that epoch's nominations close, as the paper's per-epoch keys), and nominate one-time holder keys with on-chain-checked VRF proofs seeded by the beacon. Deposits, acknowledgments and releases go on-chain through a relayer, and one recipient request binds the key. Plus `src/`: a chain reader that fails closed and rebuilds the manifest, the chain-only member worker (no network API), and `src/sim.ts` for LocalNet orchestration. Plus `demo/`: Capsule Lab, a local web UI for milestone 4 (`npm run demo`) |
| Paper alignment (`PAPER_ALIGNMENT_PLAN.md`) | Phases 0–5 and Phase 6's erasure and liveness work done 2026-10-09 and 2026-10-10, unreviewed. Phase 6: each committee's secrets live in a short-lived vault process that exits before its seats speak (`crypto-spike/src/vault.ts`); senders refuse to lock when the liveness margin is thin; `policy-app/src/epoch-worker.ts` runs as a member CLI. TestNet is not started. Phase 5: stake-weighted, permissionless membership (anyone enrolls with a bond; weight is the bond capped by online stake; one seat per winning VRF ticket; members, nominators and senders pay for their own boxes; `policy-app/test/epoch-stake.test.ts`). Phase 4: capsules on bucket keys (`registerCapsule`, `requestAccess`; holders release partials sealed to the recipient in their handover messages and attest the public state; `policy-app/src/epoch-capsules.ts`), and Capsule Lab runs this design. Phase 3: `policy-app/src/epoch-worker.ts` runs the epochs (nominate, open seats, one handover message per seat from the holder's own account, verify on a thread pool, combine, clean up old committees). Phase 1: `policy-app`'s `EpochCommittee` app and `src/epochs.ts` (per-epoch committees from block-seed VRF sortition, seats in key order, a claimed seat posts one chunked handover message, readers rebuild it from blocks). Phase 2: `crypto-spike/src/ecpss.ts` (pairing-based re-sharing, committee-generated bucket keys, the capsule KEM). The older per-capsule design (`CapsulePolicy`) is still present and tested |
| `randomness-beacon/` | Git submodule pointing to bwmx/randomness-beacon at `0e164c3`. The tests deploy a fresh beacon and run its daemon. Maintained upstream; not modified here |

Not built:
- Wallet integration and decryption in the browser (milestone 4 remainder).
- TestNet deployment (milestone 5).
- Per-member nodes and hosts.
- Stake weighting and ECPSS re-sharing for the older per-capsule design (the epoch design has both).

## Verified state

Verified 2026-10-06 on Node.js v24.15.0, AlgoKit 2.10.2, LocalNet algod 5.0.1, puya-ts 1.3.1/puya 5.10.1, pnpm 12.6.0 (beacon only):

- `crypto-spike`: `npm test` gives 26 passing tests; `npm run demo` passes all six checks.
- `policy-app`: `npm test` gives 8 passing LocalNet tests: 5 contract tests and 3 worker tests, including a 24-member, 16-slot end-to-end run with the real beacon daemon. Capsule Lab was exercised in a browser, desktop and phone widths.

Re-verified 2026-10-09 after per-epoch nomination keys, same toolchain: `crypto-spike` 26 passing; `policy-app` 8 passing, twice. The end-to-end test now also shows that a restarted member cannot reopen its seats and that online holders erase their epoch key while still holding custody. Capsule Lab was smoke-tested through its API: nominations, custody, epoch-key erasure, release and decryption. It was not re-checked in a browser.

Phase 0 of PAPER_ALIGNMENT_PLAN.md, 2026-10-09: `crypto-spike` 31 passing tests (adds the committee-size calculator and the unreviewed pairing prototype). `npm run params` and `npm run bench` in `crypto-spike/`, and `npm run probe` in `policy-app/`, reproduce the plan's numbers. `policy-app` still has 8 passing tests.

Phases 1–2, 2026-10-09: `crypto-spike` 35 passing tests; `policy-app` 11 passing LocalNet tests (adds 3 for `EpochCommittee`, including an on-chain handover between two real committees).

Phase 3, 2026-10-09: `crypto-spike` 36 passing tests; `policy-app` 12 passing LocalNet tests (adds a 22-handover run of ten member workers with outages, about 3 minutes; passed twice in a row).

Phase 4, 2026-10-09: `crypto-spike` 37 passing tests; `policy-app` 13 passing LocalNet tests (adds a capsule run with eight member workers, about 80 seconds; passed twice). Capsule Lab was smoke-tested through its API (lock, wrong wallet, request, open, replay refused, no worker errors). It was not checked in a browser.

Setup from the bundle root (Node 24+, Docker, Git and network access for npm/pnpm/GitHub):

```sh
git submodule update --init --recursive
(cd randomness-beacon \
  && npx -y pnpm@12.6.0 install --frozen-lockfile && npx -y pnpm@12.6.0 run build:all)
(cd crypto-spike && npm ci --ignore-scripts && npm test && npm run demo)
algokit localnet start
(cd policy-app && npm exec --yes --package=pnpm@12.6.0 -- npm ci && npm test)
```

No wallet seed or funded account is needed. Tests generate LocalNet throwaway accounts and VRF keys. Archive integrity for our own files is in SHA256SUMS.txt. The beacon checkout is verified by its Git commit instead.

## Next work

Per-epoch nomination keys are done (2026-10-09). The proposed next track is PAPER_ALIGNMENT_PLAN.md. Phases 0–5 are done (2026-10-09 and 2026-10-10; see the results sections there), and so are Phase 6's erasure and liveness work. Phase 6's TestNet run is next. It needs deployment parameters, funded TestNet accounts and a node per member. TestNet runs the same consensus version as LocalNet (checked 2026-10-10), so Phase 0's measured limits and fees apply. Separately: wallet integration and browser decryption for Capsule Lab. Before any TestNet step, give each member its own algod node and host and a private network path to it.

## Security boundaries to preserve

- Sender initially knows the key/plaintext. Any three colluding custodians can bypass policy.
- Fewer than three compromised custodians must hold across the entire capsule lifetime; no proactive share refresh exists.
- Public VRF output is not a secret encryption key.
- Nomination forward secrecy rests on best-effort erasure. Each member's per-epoch nomination key lives only in worker memory and is dropped once its epoch's nominations close. Until then, and until expiry for one-time keys and shares, a member's stolen live state exposes what it holds. A restart loses custody.
- The beacon seed is public. The single beacon operator can learn it early and withhold it. The registry admin is the Sybil gate. Nominators are public and control their slot until they erase the seed. A 3-of-5 hidden committee drawn with replacement from a small registry tolerates little corruption. Each worker trusts its own algod node.
- The manifest hash needs an authenticated trust anchor, not merely a hash supplied by the same untrusted storage server.
- The mock caller string is not proof of wallet ownership; mock registration does not verify custody acknowledgments.
- Expiry blocks new releases, but previously delivered responses can decrypt later.
- Buffer wiping/reference disposal in JavaScript is not provable secure erasure.
- Known committees, fixed shares and this spike's tests do not establish the paper's ECPSS guarantees.
- This integration is unaudited. No real secrets are supplied in the export.

## Bundle contents

- IMPLEMENTATION_PLAN.md: implementation milestones, architecture, threat model, VRF decisions.
- crypto-spike/: off-chain crypto source, tests, package files, lockfile, README and protocol specification.
- policy-app/: contract, chain adapter, custodian worker, LocalNet tests, package files, lockfile and README.
- `randomness-beacon/`: Git submodule pointing to the upstream beacon at its pinned commit.
- SHA256SUMS.txt: checksums of our own files (excludes the submodule contents, dependencies and build output).

Dependencies (node_modules), generated dist/ and contract artifacts are excluded. Regenerate them with npm/pnpm. The paper is referenced by URL, not included as a PDF. The submodule commit is recorded by the parent Git repository.

