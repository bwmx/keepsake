# Agent handoff: Algorand ephemeral secret capsules


## Resume in one minute

1. Read this file, then IMPLEMENTATION_PLAN.md.
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
| `policy-app/` | Milestones 2–3 on LocalNet: the `CapsulePolicy` app (Algorand TypeScript/Puya TS) with hidden, variable-size holder committees (design steps 1–5). Members enroll VRF keys and nominate one-time holder keys with on-chain-checked VRF proofs seeded by the beacon. Deposits, acknowledgments and releases go on-chain through a relayer, and one recipient request binds the key. Plus `src/`: a chain reader that fails closed and rebuilds the manifest, the chain-only member worker (no network API), and `src/sim.ts` for LocalNet orchestration. Plus `demo/`: Capsule Lab, a local web UI for milestone 4 (`npm run demo`) |
| `randomness-beacon/` | Git submodule pointing to bwmx/randomness-beacon at `0e164c3`. The tests deploy a fresh beacon and run its daemon. Maintained upstream; not modified here |

Not built:
- Wallet integration and decryption in the browser (milestone 4 remainder).
- TestNet deployment (milestone 5).
- Per-member nodes and hosts.
- Forward-secure nomination keys.
- Stake weighting.
- ECPSS re-sharing (step 6).

## Verified state

Verified 2026-10-06 on Node.js v24.15.0, AlgoKit 2.10.2, LocalNet algod 5.0.1, puya-ts 1.3.1/puya 5.10.1, pnpm 12.6.0 (beacon only):

- `crypto-spike`: `npm test` gives 26 passing tests; `npm run demo` passes all six checks.
- `policy-app`: `npm test` gives 8 passing LocalNet tests: 5 contract tests and 3 worker tests, including a 24-member, 16-slot end-to-end run with the real beacon daemon. Capsule Lab was exercised in a browser, desktop and phone widths.

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

Highest priority: forward-secure nomination keys. Without them, on-chain deposits let a member's later key compromise expose shares after expiry; see the hidden committee design in IMPLEMENTATION_PLAN.md. Then wallet integration and browser decryption for Capsule Lab. Before any TestNet step, give each member its own algod node and host and a private network path to it.

## Security boundaries to preserve

- Sender initially knows the key/plaintext. Any three colluding custodians can bypass policy.
- Fewer than three compromised custodians must hold across the entire capsule lifetime; no proactive share refresh exists.
- Public VRF output is not a secret encryption key.
- Nominations have no forward secrecy yet: a member's long-term nomination key plus chain history recovers every share it held.
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

