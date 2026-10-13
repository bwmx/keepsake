# History: how the design got here

Keepsake started as a simpler design and was moved, step by step, toward the paper's. This page keeps the decisions and lessons from that work. The original planning documents (`IMPLEMENTATION_PLAN.md`, `PAPER_ALIGNMENT_PLAN.md`, `START_HERE.md`) hold the full detail, and remain in Git history up to commit `ef0152c`.

## Timeline

| Date | Commit | What happened |
| --- | --- | --- |
| 2026-10-06 | `6e3f198` | **First design.** A per-capsule crypto spike: AES-256-GCM, 3-of-5 Shamir and HPKE deposits to a fixed committee, against a trusted in-memory ledger. Then a `CapsulePolicy` app on LocalNet, with one hidden committee per capsule drawn by VRF sortition seeded from our own [randomness beacon](https://github.com/bwmx/randomness-beacon), a relayer for custody traffic, and the first Capsule Lab |
| 2026-10-09 | `4022cf4` | Per-epoch nomination keys, erased after use, for forward secrecy. The plan to align with the paper is drafted. **Phase 0:** committee sizing and feasibility. **Phases 1–2:** the `EpochCommittee` app (block-seed sortition, seats, a message log) and the off-chain re-sharing library |
| 2026-10-09 | `9b34014` | **Phase 3:** member workers run epochs on LocalNet, verifying on a thread pool. No relayer |
| 2026-10-10 | `8d4ea2d` | **Phase 4:** capsules on bucket keys, released inside handover messages |
| 2026-10-10 | `a34726c` | **Phase 5:** permissionless, stake-weighted membership with bonds |
| 2026-10-10 | `55ba36a` … `ceb9359` | **Phase 6:** vault processes, the liveness margin, a member CLI, joining from the attested state, and the first TestNet trial |
| 2026-10-10 | `453d5ee` | The per-capsule design, its beacon submodule and its relayer are removed. Capsule Lab is checked in a browser |
| 2026-10-11 | `ff3859c` | 60-seat committees on TestNet, after posting each seat as one atomic group |
| 2026-10-11 | `0166b63` | Fraud proofs and bond slashing for provably bad dealings |
| 2026-10-12 | `aafe141` | Renamed to Keepsake. Capsule Lab gains wallets, and senders and recipients encrypt and decrypt in the browser |
| 2026-10-12 | `ef0152c` | Packed epochs, and fraud proofs that work at production thresholds. Finding: the slashing is evadable |
| 2026-10-13 | — | Public at [github.com/bwmx/keepsake](https://github.com/bwmx/keepsake). A TestNet trial at production size: 216-seat committees, t = 80, four handovers and a capsule round trip |

## Why the first design was replaced

The per-capsule design gave every capsule its own static committee. That had three problems the paper solves:
- **No handover.** Security needed fewer than t corrupt holders over a capsule's whole life, not per epoch.
- **A dealer per capsule.** The sender dealt the shares, and nothing proved they were consistent.
- **A single-operator beacon** supplied the sortition seed.

The paper's design holds a few keys in one evolving committee for the whole system. Its cost grows with the number of live buckets rather than capsules, and every gap above closes:

| Gap in the first design | Closed by |
| --- | --- |
| No handover | Re-sharing every epoch (Phases 2–3) |
| Fixed slots, one winner each | Every sortition winner gets a seat, ordered by key (Phase 1) |
| Committee size and threshold from n alone | Sized from f with exact tails (Phase 0) |
| Shares not verifiable | Pairing-checked re-sharing (Phase 2), with selective-opening security still open |
| One committee and one dealer per capsule | Bucket keys created by the committee (Phases 1, 2 and 4) |
| Admin-admitted, unweighted members | Bonded, stake-capped weight (Phase 5) |
| Single-operator beacon | Algorand's block seed (Phase 1) |
| Relayer for custody traffic | Holders post from their own accounts after erasing (Phase 3) |
| Best-effort erasure | Per-committee vault processes (Phase 6); still not provable |

## Decisions

| # | Question | Chosen | Why |
| --- | --- | --- | --- |
| D1 | What the committee holds | **Bucket keys** | Per-capsule secrets would make handovers grow with the number of capsules. One master key could never expire |
| D2 | Verifiable re-sharing (§2.6) | **Pairing-based PVSS on BLS12-381** | Compact, checked with pairing equations, buildable on `@noble/curves`, and group-element shares suit a pairing KEM. Considered: Groth's chunked-ElGamal DKG, class groups, Paillier |
| D3 | Where handover data lives | **App-call arguments in blocks**, with an on-chain digest per seat | Boxes lock 400 µAlgo of deposit per byte. Off-chain storage would add a data-availability assumption the paper does not make |
| D4 | Committee size | **Exact tails** | About 45% smaller than the paper's Chernoff bounds at the same failure probability |
| D5 | Sortition seed | **Algorand's block seed** | Fits the paper's resettable sortition: proposers can redraw only by withholding blocks |
| D6 | Membership and weight | **Permissionless; weight is an escrowed bond capped by online stake** | Online stake alone can be counted twice by moving coins during a nomination window |
| D7 | Release timing | **Inside the handover message** (speak once) | A faster path would be a documented deviation |

The stack was fixed at the start: **AlgoKit with Algorand TypeScript compiled by Puya TS** for contracts, and ordinary TypeScript for everything off chain.

## Lessons from building it

- **Decoding, not verification, is the main cost.** Every received point needs a subgroup check, which Phase 0's benchmark missed. Batching those checks is unsound, so verification moved to a thread pool.
- **Cheaters were expensive to isolate.** One bad dealing cost 3.6 times an honest epoch, because each sub-batch repeats C pairings. Reusing pairing precomputation changed nothing measurable, so it was removed.
- **Online stake can be counted twice.** It led to the escrowed bond (D6).
- **Key posts crowded out nominations** on dev-mode LocalNet, where every transaction takes a round. Workers now post the next key after nominations close.
- **Old committees drained the app's balance** after about 15 epochs. Nominators now delete their old seats and recover the deposits.
- **Capsule Lab could step a worker twice at once,** from the clock and the button at the same time. Stepping is now queued.
- **Public nodes rate-limit.** Unbounded parallel reads got HTTP 429 on TestNet, and a worker that skipped failed stages lost its handover. Stages now count as done only on success.
- **Posting a seat as three separate transactions was too slow** for a 60-seat committee. One atomic group per seat fixed it.
- **A cleanup bug stranded 17.32 TestNet Algo** by closing accounts that still owned seats.
- **At production size, slow reads move deadlines.** Reading the attested state takes minutes, so the trial's capsule missed the opening round it had chosen before the read. The nomination window also has to grow with seats per member: 40 rounds lost about 5% of nominations at 43 seats each.
- **Fraud proofs did not fit production t.** Recomputing a commitment from t points overflowed the AVM's 4 KB value limit. Leaves now carry the commitment directly.
- **The slashing turned out to be evadable** (see [security.md](security.md#penalties-do-not-deter-yet)). The accountability work had overstated deterrence.

## What is left of the first design

The crypto package still contains the original per-capsule spike (`protocol.ts`, `mock-ledger.ts`, `demo.ts`, and their 26 tests), documented in [crypto/SPIKE_PROTOCOL.md](../crypto/SPIKE_PROTOCOL.md). The epoch design does not use it, apart from shared helpers in `crypto.ts`. The on-chain side of that design (`CapsulePolicy` in `policy-app/`, the beacon submodule and the relayer) was removed in commit `453d5ee` and is in the history before it. Until commit `aafe141`, `chain/` was named `policy-app/` and `crypto/` was `crypto-spike/`.
