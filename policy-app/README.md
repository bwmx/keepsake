# Capsule policy app: evolving epoch committees on Algorand

This package is the Algorand side of [the paper alignment plan](../PAPER_ALIGNMENT_PLAN.md). It implements the evolving committees of "Can a Public Blockchain Keep a Secret?" (eprint 2020/464 §3):
- **Committees.** One committee per epoch, drawn by stake-weighted VRF sortition on Algorand's block seed. Its seats are anonymous until they speak.
- **Handover.** Each holder posts one handover message per seat (speak once) that re-shares every live bucket key to the next committee.
- **Capsules.** Capsules are encrypted to the key of the bucket their expiry falls in, and released to their recipient from the handover messages.

| Part | Contents |
| --- | --- |
| `smart_contracts/epoch_committee/` | `EpochCommittee`: Algorand TypeScript compiled with Puya TS through AlgoKit |
| `src/epochs.ts` | Round windows, the bucket schedule, sortition tickets, message chunking, and a reader that rebuilds messages from blocks and checks them against the on-chain digests |
| `src/epoch-worker.ts` | Member worker: keys, nominations, seats, one handover message per seat, verification and cleanup; secrets in per-committee vault processes. Talks only to algod; also runs as a CLI |
| `src/epoch-capsules.ts` | Capsule sender and recipient, the attested public state, and the liveness margin |
| `src/epoch-sim.ts` | LocalNet environment: members online with throwaway participation keys, bonded and enrolled; in-process workers |
| `src/chain.ts` | Chain reader that fails closed, and shared helpers |
| `demo/` | **Capsule Lab**: a local web UI for the design |
| `smart_contracts/broadcast_probe/`, `bench/broadcast-probe.ts` | Phase 0 probe: argument and note limits and fees, an epoch of handover data posted and rebuilt from blocks, block-seed lookback, stake opcodes (`npm run probe`) |
| `bench/testnet-trial.ts` | Phase 6 TestNet trial (`npm run trial`, TestNet only). It funds five throwaway members from `TESTNET_MNEMONIC` in `../.env` (git-ignored) and runs them through a public node. It runs handovers and a capsule round trip, reports timings and fees, then returns what it can to the funder. Keys of an interrupted run are kept in the git-ignored `.testnet-trial.json`; `npm run trial -- cleanup` recovers them |

It runs on LocalNet, and a five-member trial has run on TestNet. All cryptography stays in the [crypto spike](../crypto-spike/README.md). The earlier per-capsule design (`CapsulePolicy`, beacon-seeded slots and a relayer) was removed on 2026-10-10; it is in the Git history before that date.

## Run

Requires Node.js 24+, AlgoKit CLI 2.10+, Docker, Git and npm. The VRF library (`@bwmx/algorand-vrf-utils-ts`) is installed directly from its pinned upstream Git commit. Its upstream prepare step uses pnpm 12.6.0, supplied by the install command below.

```sh
(cd crypto-spike && npm ci --ignore-scripts)
cd policy-app && npm exec --yes --package=pnpm@12.6.0 -- npm ci
algokit localnet start
npm test        # 7 LocalNet tests, about 6 minutes
npm run demo    # Capsule Lab at http://127.0.0.1:8787
```

LocalNet must be in its default dev mode, where a block is sealed per transaction. All accounts, VRF keys and nomination keys are generated LocalNet throwaways and are never printed.

## Capsule Lab (demo UI)

`npm run demo` serves a single page at `127.0.0.1:8787` for the paper-aligned design: `EpochCommittee` with its member workers, with capsules on bucket keys. One local server plays every party, and the workers step in lockstep with the round clock. In a real deployment each member, sender and recipient would run its own client and node. What you can do:

1. **Start an environment.** Choose the number of members, the expected committee size (up to 12) and the threshold t. Each member's account goes online for consensus with throwaway participation keys. After Algorand's 320-round stake lookback, the app is deployed and members enroll with bonds of 1, 2, 3 and 5 Algo in turn. Their workers then start. The genesis committee creates the first buckets, and their keys are attested about two epochs later.
2. **Watch the epochs.** The epoch panel shows the nomination window and the handover window, the committee in office, the messages posted, and recent handovers: messages checked, the liveness margin, buckets held with their public keys, and whether all members agree. Locking refuses while the margin is 0, when one more silent seat would lose every bucket. Each member's secrets live in its own vault processes.
3. **Lock a capsule.** The sender encrypts under the key of the bucket its expiry falls in, taken from the state the committee attested. It registers u, a proof bound to the policy, and the payload hash. There is no dealer and no per-capsule committee.
4. **Play the recipient.**
   - Request access with a fresh key.
   - At the next handover every holder seals a partial to that key. The recipient checks the partials against the attested commitments and decrypts.
   - You can also try requesting early, from another wallet, again with a new key, or after expiry.
5. **Replay attack.** Copy a capsule's u under another policy. Every holder refuses it, because its proof is bound to the original policy.
6. **Members.** Each card shows the member's bond and how many seats it nominated for the next committee: seats follow bonds. The demo uses about one ticket per expected seat, each almost sure to win, so committee sizes stay near the target. Take members offline (an outage: they keep their memory and catch up when back). A committee hands over as long as t of its seats post.
7. **Operator view.** This toggle shows which seats each member holds and its private worker log, both taken from the workers rather than the chain.
8. **Committee security.** For the committee in office, it shows the per-epoch chance that a corrupt fraction f exposes the key or stalls a handover, using the exact-tail model from Phase 0.

Checked in headless Chrome on 2026-10-10: the full capsule flow, the operator view, member outages, phone width and dark mode, with no page errors. The clock and the advance button share one queue, so a worker never runs two steps at once. The server binds to 127.0.0.1 only. The recipient's decryption happens inside the server process, standing in for the recipient's own client, and there is no wallet integration.

## Protocol

`EpochCommittee` implements the paper's evolving committees (eprint 2020/464 §3), and capsules are released from its handover messages (Phase 4). Epoch e spans rounds `[e·E, (e+1)·E)`. Committee c is nominated in epoch c − 1 from the block seed of that epoch's first round, and hands over in epoch c.

**Membership and sortition (Phase 5).** Anyone may join; there is no admin. A member enrolls with a payment that covers its own boxes, and the rest of the payment is its bond.
- **Weight.** A member's sortition weight is its bond, capped by its online stake (`voter_params_get`, which reads balances 320 rounds back). A bond change counts from the next epoch's nominations, after a seed nobody knew when making it. The bond is escrowed because online stake alone can be counted twice: moving coins between accounts during a nomination window counts them once per account. A withdrawal is paid at once; the coins still count in the current epoch's nominations, and bonded again elsewhere they count only from the next.
- **Tickets.** The total bond is cut into `totalTickets` tickets, so a member holds ⌈w · totalTickets / total⌉ of them, the last one partial. Ticket j wins when the rank of `VRF(sha256("ecpss/nominate/v2" ‖ appId ‖ committee ‖ j ‖ seed))` is below `ticketThreshold`, scaled down for a partial ticket. This is Algorand's binomial sortition with tickets as sub-users. Each winning ticket is one seat, so a committee has about `totalTickets · ticketThreshold / 2^64` seats. Splitting stake across accounts does not change a member's expected seats.
- **Nominees.** A nominator seals each seat to a member drawn at random by bond, so accounts without a bond attract no seats.
- **Deposits.** Everyone pays for the boxes they need: a member for its registry entry and three key slots (139,300 µAlgo), a nominator for each seat (137,700 µAlgo, refunded when it deletes the seat), and a sender for each capsule. The creator funds only the app account's 0.1 Algo minimum. The app holds bonds and box deposits, nothing else.

| Rounds of epoch e | Call | Who | Checks |
| --- | --- | --- | --- |
| Any | `enroll(vrfKey, pay)` once; `addBond(pay)`; `withdrawBond(amount)`; `postNominationKey(epoch, key)` for the current or next epoch, never replaced | Anyone; member | `Txn.sender`; the enrollment payment covers the deposits |
| 1…`nominationRounds` (under 320) | `nominate(index, ticket, proof, epk, sigKey, sealedSeed, pay)`, once per winning ticket, for committee e + 1 | Member with weight | Exact seat deposit. The first nomination copies the seed with `block BlkSeed`, so nominations use a validity window ending within about 1,000 rounds of the seed round. The ticket exists for the member's weight, `vrf_verify` with the enrolled key, the rank wins, and the member enrolled before the seed round |
| Next `handoverRounds` | `claim(e, nominator, ticket, holder, stateDigest, sig)`, then `postChunk(e, nominator, ticket, a, b, c, d)` with the note, then `finalize` | Committee e's holders | The seat's one-time Ed25519 key signs the claim; after that, `Txn.sender` must be the claimed holder. Each chunk is folded into the seat's on-chain running digest |
| After epoch e | `deleteSeats(e, tickets[])` (batches of 7) | The nominator (workers do it three committees back) | Refunds the seat deposits to the nominator |
| Any (from committee genesis + 1) | `registerCapsule(recipient, openRound, expiresRound, u, proof, payloadHash, pay)` under bucket `expiresRound / bucketRounds`, which must exist by schedule; the window must span ≥ 2 epochs | Sender | Exact payment of the 118,500 µAlgo box deposit |
| `[openRound, expiresRound)` | `requestAccess(capsule, requestId, recipientKey)` once | Recipient | `Txn.sender` |
| After `expiresRound` | `deleteCapsule(capsule)` refunds the deposit | Anyone | — |

`createApplication` also fixes the parameters every member must agree on:
- the sharing threshold t;
- the bucket schedule: bucket b covers rounds `[b·bucketRounds, (b+1)·bucketRounds)` and is created `bucketLead` rounds early;
- the genesis committee, which holds nothing and creates the first buckets.

The member worker ([`src/epoch-worker.ts`](src/epoch-worker.ts)) handles each epoch:
- **Keys.** It posts its nomination keys.
- **Nomination.** It reads its weight as the contract does, draws a VRF for each of its tickets, and nominates one seat per winning ticket. Each seat is sealed to a member drawn by bond.
- **Seats.** It opens its seats when nominations close, then erases that epoch's key.
- **Handover.** As a holder, it builds its single handover message and its secrets are erased. Then it claims the seat and posts the message from its own account. There is no relayer.
- **Processing.** It processes every closed handover in order and catches up after an outage. Messages are verified on a shared thread pool (`VerifyPool` from the crypto spike), and it combines shares for its seats in the next committee.
- **Cleanup.** It deletes the seats it nominated three committees back and recovers their deposits.
- **Liveness.** Each `received` event reports the handover's margin: by how many valid dealings the worst kept bucket exceeds t.

**Secrets (Phase 6).** Secrets live in one short-lived vault process per committee (`SeatVault` from the crypto spike).
- **Contents.** A vault starts when the member posts the nomination key that opens the committee's seats, and holds:
  - that key, as wipeable bytes;
  - the seats' one-time keys;
  - their shares, combined from the dealings everyone chose.
- **Lifetime.** It builds the seats' messages, releases and claim signatures, then exits before any of them is posted. A vault whose member holds no seat exits as soon as the seats are opened.
- **Host checks.** Vaults run with core dumps off, checked from inside, and refuse to start where swap is unencrypted (macOS) or on at all (Linux; `ECPSS_ALLOW_SWAP=1` overrides).
- **What the worker keeps.** Only public data, its own seat numbers, and what it posts.
- **Limits.** JavaScript can neither wipe bigints nor pin memory, so erasure is not provable: the process exit ends the secrets.

**Joining after genesis (Phase 6).** A worker that starts after the genesis committee cannot replay from genesis, because old seat records are deleted. This covers a newly enrolled member and one restarted with nothing in memory.
- **Join.** The worker takes the latest committee's public state that at least t of its seats attested; fewer than t are corrupt, so an honest seat agrees. It follows every handover from there.
- **Lost seats.** Seats nominated to keys the member posted before a restart stay closed to it.
- **Deposits.** It deletes the old seats it nominated in an earlier run and recovers their deposits.

**Running a member.** `node dist/src/epoch-worker.js` runs one member against its own algod node. It is configured by:
- `ALGOD_SERVER`, `ALGOD_PORT`, `ALGOD_TOKEN`;
- `GENESIS_HASH`, `APP_ID`, `MAX_ROUND_AGE_MS`;
- `MEMBER_MNEMONIC` (an enrolled, bonded account);
- `VRF_SECRET_KEY` (base64, 64 bytes: seed ‖ public key);
- `POLL_MS`.

It checks the host by starting a vault before anything else, and writes JSON event lines that name the member's own seats, so keep them private.

**Liveness (Phase 6).** `livenessMargin` in [`src/epoch-capsules.ts`](src/epoch-capsules.ts) measures by how many seats each of these exceeds t:
- the latest handover's agreeing attestations;
- the committee in office;
- the next committee, once nominated.

`assertLive` refuses to lock a capsule while that margin is below a sender's minimum. One handover with fewer than t honest seats speaking loses every live bucket.

**Capsules (Phase 4).** A holder's handover message also carries:
- a decryption partial, sealed to the recipient's request key, for each capsule that is requested, still open, and under a bucket it holds;
- its view of the committee's public commitments, whose digest it signs when it claims its seat.

Senders and recipients take the state that at least t seats attest, so at least one honest seat agrees with it ([`src/epoch-capsules.ts`](src/epoch-capsules.ts)). Senders get a bucket's public key from it, and recipients check partials against it. A holder refuses a capsule whose proof is bound to another policy. A bucket must be created and attested before senders need it, so `bucketLead` must cover the capsule horizon plus about two epochs.

Off-chain, [`src/epochs.ts`](src/epochs.ts):
- orders seats by their one-time signing key and drops any seat whose keys repeat another's;
- posts a message in chunks of 20,452 bytes, at the fee measured in Phase 0;
- rebuilds a message from the blocks of the handover window through algod, and checks it against the on-chain digest.

The cryptography lives in [`crypto-spike/src/ecpss.ts`](../crypto-spike/src/ecpss.ts) and is unreviewed.

## Tests

`test/epoch-workers.test.ts` (1 test, Phase 3, about 3 minutes): ten member workers, driven in lockstep, run 22 handovers with four outages.
- **Agreement:** every member, including the ones that were offline, processes every handover, and all agree on each bucket's public key.
- **No losses:** no bucket is lost, and a bucket's key and reconstructed secret never change.
- **Schedule:** buckets appear and disappear exactly as scheduled.
- **Indexer:** each seat's claim and finalize happen once, from its own holder (a member, never a relayer), after that member posted its key for the next epoch. Nobody speaks while offline.
- **Cleanup:** nominators delete their old seats, and the app holds only bonds beyond its boxes' deposits. Workers report no errors.

`test/epoch-capsules.test.ts` (1 test, Phases 4 and 6, about 105 seconds): with eight member workers running, it shows:
- a capsule locked under an attested bucket key is privately released at the next handover and decrypts;
- requests are refused from another wallet, before opening, for a second key and after expiry;
- a capsule reusing another's u under its own policy is refused by every holder, without errors;
- the deposit is refunded;
- after its last handover the expired capsule's bucket is held by nobody and re-dealt by nobody;
- liveness: members go silent through one handover so that as few seats as possible, but at least t, speak. Every worker reports the resulting margin, the sender refuses to lock below its minimum, and the margin recovers after the next full handover.

`test/epoch-join.test.ts` (1 test, Phase 6, about 25 seconds): six members run. After two handovers one crashes, losing its process, vaults and history, and a new member enrolls and starts at once. The crashed member restarts an epoch later with nothing in memory. The test shows that:
- both join from the attested state and agree with everyone on every later handover, and no bucket is lost;
- every seat either holds after joining speaks, and the new member nominates once its stake counts;
- every old seat, including those the crashed run nominated, is deleted with its deposit returned.

`test/epoch-stake.test.ts` (1 test, Phase 5, about 80 seconds): ten member workers, eight with bonds of 1–6 Algo, run ten committees.
- **Seats track bonds:** each member's seat count lies within 4 standard deviations of the expectation from its tickets, and the fit's slope is between 0.8 and 1.2.
- **No weight, no seats:** an online member with no bond and a bonded member with no online stake hold no ticket. Their nominations are rejected, and they never nominate.
- **Bond timing:** a new bond counts from the next epoch's nominations. A withdrawal is paid at once and stops counting at the next epoch.
- **Several seats per member:** holders with several seats speak once per seat, and no bucket is lost.
- **Deposits:** the app holds bonds beyond its boxes' deposits and nothing else.

`test/epochs.test.ts` (3 tests, Phases 1–2; equal bonds, one ticket each):
- **Sortition:** the captured seed equals the block's seed. Exactly the VRF-eligible members nominate, once each. Ineligible, late-enrolled, copied-proof, duplicate, nonexistent-ticket, underpaid and out-of-window nominations are rejected. Seats are numbered in signing-key order and each opens only for its nominee.
- **Handover on chain:** two real committees. The first holds an honest dealer's bucket. Each holder claims its seat with its one-time key and posts one encoded handover message (re-share plus a new committee-generated bucket); one holder posts 50 KB of garbage instead. Readers rebuild every message from blocks, the next committee drops the cheater and reconstructs the original secret, and after the epoch each nominator deletes its seat and gets the deposit back. Early, forged, repeated or outsider claims and posts are rejected.
- **Creation and immutability:** epoch-length and nomination-window checks; no update, delete or opt-in.

## What is and isn't protected

**Hidden:** which member holds which seat, until the seat speaks. A seat's holder posts from its own account only after its vault has erased the seat's secrets, as in the paper.

**Not hidden or not guaranteed:**
- **The cryptography is unreviewed.** The pairing-based re-sharing, the capsule KEM and their proofs (`crypto-spike/src/pvss.ts`, `ecpss.ts`) have had no cryptographer's review. Plain ElGamal is not known to meet the paper's selective-opening requirement (RIND-SO), and HPKE's anonymity rests on the paper's unproven Conjecture 1.
- **Committees here are small.** Security needs fewer than t corrupt seats per epoch, and liveness needs t honest seats speaking. The plan's sizes (C ≈ 130–210) come from exact tails at f = 5%. Demo and test committees of 5–20 seats tolerate little corruption.
- **A seat is corrupt if its nominator or its holder is,** about 2f. Nominators are public and know a seat's keys until they erase them.
- **Weight is bonded stake.** f is the adversary's share of the bonds, not of Algorand's online stake. The online-stake cap can be worked around by moving online coins between bonded accounts.
- **Forward secrecy rests on erasure.** Sealed seeds and handover messages stay on-chain forever. Each committee's secrets live in a vault process that exits before its seats speak, but JavaScript cannot wipe bigints or pin memory, so erasure is not provable. Until a vault exits, stealing a member's live state exposes what that vault holds.
- **One failed handover loses every live bucket.** That happens when fewer than t honest seats speak. Senders can check the liveness margin before locking, but nothing can rescue a bucket once a handover fails.
- **Network traffic can identify holders.** Members should each use their own node; a shared node sees which account reads what. Each worker trusts its own algod node, since this is not a light client.
- **Expiry is coarse,** with the granularity of the bucket width plus an epoch. It does not revoke releases already delivered.
- **Releases wait for the next handover,** up to an epoch.
- **Status: LocalNet tests and a small TestNet trial only.** Unaudited; use synthetic secrets only.
