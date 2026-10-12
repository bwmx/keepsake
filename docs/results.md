# Results: sizes, costs and trials

What has been measured, and how to reproduce it. Unless noted, timings come from an Apple M5 laptop (4 performance and 6 efficiency cores), Node.js v24.15.0 and LocalNet algod 5.0.1. The design is in [design.md](design.md).

| Command | What it reproduces |
| --- | --- |
| `npm run params` in `crypto/` | The committee size table |
| `npm run bench` in `crypto/` | Per-member compute cost of one plain handover at C = 64, 120 and 200 (a few minutes) |
| `npm run bench:packed` in `crypto/` | Plain against packed handovers |
| `npm run probe` in `chain/` | Chain limits and fees, posting an epoch of handover data and reading it back (LocalNet) |
| `npm run trial` in `chain/` | A TestNet run; needs a funded account (see [chain/README.md](../chain/README.md#testnet-trial)) |

## Committee size

How many seats C a committee needs, and its threshold t, so that an adversary with a fraction f of the bonded stake breaks neither secrecy nor liveness, per epoch. These are exact Poisson tails of the paper's §3.2 process, assuming the population N is much larger than C. The adversary may redraw the sortition seed 2^k1 times.

| Seed redraws | Failure per epoch | f = 1% | f = 5% | f = 10% | f = 20% |
| --- | --- | --- | --- | --- | --- |
| 2^64 (paper) | 2^-128 | C 256, t 75 | C 489, t 197 | C 952, t 438 | C 5,246, t 2,630 |
| 2^8 | 2^-64 | 111, 29 | 210, 79 | 402, 176 | 2,189, 1,075 |
| none | 2^-64 | 107, 27 | 198, 72 | 378, 162 | 2,060, 1,003 |
| none | 2^-40 | 64, 16 | 120, 44 | 230, 99 | 1,243, 605 |

The paper's own Chernoff bounds give C = 889 for its 5% row. Our implementation of those bounds reproduces the paper's table to within 2%, so exact tails save about 45%.

**Chosen parameters** (f = 5%, up to 2^8 seed redraws from withheld blocks):
- **TestNet scale:** failure 2^-40 per epoch gives C = 130, t = 50.
- **Production scale:** failure 2^-64 gives C = 210, t = 79. With packed epochs, liveness needs t + ℓ − 1, so C grows to 216 with four live buckets, 220 with five and 226 with eight.
- **LocalNet and the demo:** small overrides that test the mechanics, not the security.

## Chain limits and fees

From the LocalNet probe. TestNet runs the same consensus version (checked 2026-10-10), so these limits apply there too.
- **Per call.** One app call carries up to 16,384 bytes of arguments plus a 4,096-byte note; one byte more is rejected. The minimum fee covers 2,048 bytes of arguments and a 1,024-byte note. Beyond that, an idle network charged about 0.1 µAlgo per extra byte, so a full 20 KB call costs about 2,741 µAlgo.
- **Per handover.** An epoch of plain handover data for one bucket at C = 120 took 240 calls in 15 groups; at C = 200, 600 calls in 38 groups. A reader rebuilt every seat's running digest from raw blocks in 0.1–0.2 s.
- **Block seed.** `block BlkSeed` can read only about 990 rounds back with a 10-round validity window, so the contract copies the seed into state at the first nomination.
- **Retention.** Non-archival nodes keep only the last 1,000–1,321 blocks (from Algorand's docs, not measured). Members must read each handover before it ages out.

Plain handover data per live bucket per epoch, before packing, is 240·C² + 48·C·t bytes:

| C, t | Data per epoch | App calls | Fees at the idle rate |
| --- | --- | --- | --- |
| 120, 44 | 3.54 MiB | 240 | 0.66 Algo (measured) |
| 200, 72 | 9.81 MiB | 600 | 1.65 Algo (measured) |
| 490, 197 | 59.4 MiB | 3,430 | 9.4 Algo (computed) |
| 889, 425 (paper, 5%) | 198 MiB | 10,668 | 29 Algo (computed) |

At the paper's own parameters a shared chain could not carry the handovers. That is why the parameters above use exact tails and why handovers are packed.

## Compute per member

**Plain handover, one bucket, one thread** (`npm run bench`):

| C | t | Deal | Verify all C dealings | With one cheater | Combine own share | Partial + proof | Recipient combines t | Dealing size |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 64 | 16 | 0.40 s | 5.4 s | 23.5 s | 0.16 s | 0.03 s | 0.05 s | 15.8 KB |
| 120 | 44 | 0.84 s | 15.8 s | 59.2 s | 0.48 s | 0.02 s | 0.14 s | 30.2 KB |
| 200 | 72 | 1.3 s | 39.6 s | 142.5 s | 0.97 s | 0.02 s | 0.25 s | 50.3 KB |

**Decoding dominates in practice.** Every received point needs a subgroup check, which costs about 0.63 s per dealing at C = 200, or about 126 s per bucket per epoch on one thread. Batching those checks is not sound. So the worker decodes and verifies on every core (`VerifyPool`): decode plus verify takes 5.4, 15.9 and 40.7 s at C = 64, 120 and 200, about four times faster than one thread. The efficiency cores add little.

**Budget.** At C = 200 a member spends about 40 s of a 10-core laptop per live bucket per epoch, before packing. Epochs need to be several minutes long or more.

## Packed epochs

`npm run bench:packed`, one thread, C = 64, t = 16, four live buckets and one new per epoch:

| Handover | Dealings per member | Deal (one member) | Message | Decode and verify all 64 |
| --- | --- | --- | --- | --- |
| plain | 5 | 2.1 s | 79 KB | 91.2 s |
| pack | 1 | 1.4 s | 16 KB | 19.7 s |
| unpack | 2 | 0.9 s | 32 KB | 36.6 s |

Over a pack and an unpack, verification falls by 69% and message bytes by 70%. At production sizes, from the wire format:

| C, t | Live + new buckets | Plain | Pack | Unpack | Saving over two epochs |
| --- | --- | --- | --- | --- | --- |
| 210, 79 | 4 + 1 | 265 KB | 53 KB | 106 KB | 70% |
| 216, 80 | 4 + 1 | 272 KB | 55 KB | 109 KB | 70% |
| 220, 81 | 5 + 1 | 332 KB | 56 KB | 111 KB | 75% |
| 226, 82 | 8 + 1 | 511 KB | 57 KB | 114 KB | 83% |

A plain production message with four live buckets plus the attested state is about 286 KB, or 15 chunks, one more than fits in one atomic group. Packed, it needs 4 chunks on a pack and 6 on an unpack, which cuts chunk fees per seat by about two thirds.

## Fraud reports

`reportBadDealing` costs about 0.09 Algo at any t, almost all of it for opcode budget (two `ec_pairing_check`s and a Merkle walk). The opcode's cost grows with the bytes of its second argument, so the contract passes the G2 points first and the smaller G1 points second.

## Stake-weighted sortition

`chain/test/epoch-stake.test.ts` runs ten members with bonds of 1–6 Algo through ten committees. Over three runs, every member's seat count lay within 4 standard deviations of what its tickets predict, and the 6-Algo member drew 130 and 122 seats against 128 expected in two of them. A Monte Carlo run of the ticket functions matches the model to within 0.5%.

## TestNet trials

All trials ran on 2026-10-10 and 2026-10-11, with five throwaway members on the public AlgoNode node. They predate packed epochs and fraud proofs. Rounds took 2.69 s throughout.

| Run | App | Seats per committee | t | Epoch (nominate / handover) | Outcome | Fees | Net cost to funder |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 773987601 | 5 | 2 | 60 rounds (12 / 30) | Five handovers, every seat posted (margin 3). A capsule opened 250 s after its request | 0.56 Algo over 5 epochs, about 0.02 Algo per seat per epoch | 1.43 Algo |
| 2 | 774022281 | 60 | 20 | 150 rounds (15 / 40) | **Failed.** The node rate-limited (HTTP 429) the reader's parallel box reads, and the worker skipped stages after errors. A cleanup bug then stranded 17.32 Algo in the app | — | 18.7 Algo |
| 3 | 774029608 | 60 | 20 | 150 rounds (15 / 40) | Every handover held, but only 55, 41, 34 and 50 of 60 messages posted in the window: three confirmed transactions per seat, four seats at a time. A capsule opened 142 s after its request | 5.77 Algo over 4 epochs | 6.68 Algo |
| 4 | 774037027 | 60 | 20 | 150 rounds (15 / 40) | One atomic group per seat: 60 of 60 messages every handover (margin 40), the last landing 29–31 rounds into the window. About 47 KB per message. A capsule opened 138 s after its request | 5.54 Algo over 4 epochs, about 0.023 Algo per seat per epoch | 6.45 Algo |

Notes:
- **Fixes after run 2.** The reader now reads at most 8 boxes at a time, and a worker stage counts as done only once it succeeds. Cleanup reads the app's epoch length and closes an account only once none of its seats remain.
- **Where the fees go (run 4).** Nominations take 54% (0.01 Algo each, for the VRF check's opcode budget). Claims cost 0.001 Algo, since the group's pooled budget covers the signature check.
- **What the net cost is.** Fees, enrollment deposits (there is no exit from the registry) and the app's own minimum balance. Bonds, seat and capsule deposits and account balances all came back.
- **Total spent.** All trials took about 33 TestNet Algo.
- **The bottleneck was the shared node's rate limit,** not the network. With members on their own nodes, there is none to hit.
- **Not yet seen on TestNet:** committees of the planned size (130+), a real stake distribution, members on their own nodes, fees under congestion, adversarial members, packed epochs, and the retry of already-built messages after a network error.
