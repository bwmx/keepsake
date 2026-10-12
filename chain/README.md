# Keepsake chain: evolving epoch committees on Algorand

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
| `demo/` | **Capsule Lab**: a local web UI for the design. Senders and recipients act from their own wallet in the page (`demo/client.ts`, bundled by esbuild), so the server never sees a plaintext or a request key |
| `smart_contracts/broadcast_probe/`, `bench/broadcast-probe.ts` | Phase 0 probe: argument and note limits and fees, an epoch of handover data posted and rebuilt from blocks, block-seed lookback, stake opcodes (`npm run probe`) |
| `bench/browser-check.ts` | Capsule Lab in headless Chrome (`npm run browser-check`, LocalNet). It starts its own server, connects LocalNet's KMD wallet and drives the page through the whole capsule flow: lock, request and decrypt in the page, plus the attacks. It also covers the operator view, a member outage, phone width and dark mode. It fails on any page error, or if anything the page sends the server contains the plaintext. Screenshots go to the git-ignored `browser-shots/`; `CHROME_PATH` overrides the browser |
| `bench/testnet-trial.ts` | Phase 6 TestNet trial (`npm run trial`, TestNet only). It funds throwaway members from `TESTNET_MNEMONIC` in `../.env` (git-ignored) and runs them through a public node. It runs handovers and a capsule round trip, reports timings, data and fees, then returns what it can to the funder. The sizes are set by `TRIAL_MEMBERS`, `TRIAL_TICKETS` (seats per committee), `TRIAL_T`, `TRIAL_EPOCH`, `TRIAL_NOMINATION`, `TRIAL_HANDOVER`, `TRIAL_LEAD_EPOCHS`, `TRIAL_BOND` and `TRIAL_FUND`. Keys of an interrupted run are kept in the git-ignored `.testnet-trial.json`, and `npm run trial -- cleanup` recovers them. Cleanup closes an account only once none of its seats remain |

It runs on LocalNet, and a five-member trial has run on TestNet. All cryptography stays in the [crypto package](../crypto/README.md). The earlier per-capsule design (`CapsulePolicy`, beacon-seeded slots and a relayer) was removed on 2026-10-10; it is in the Git history before that date.

## Run

Requires Node.js 24+, AlgoKit CLI 2.10+, Docker, Git and npm. The VRF library (`@bwmx/algorand-vrf-utils-ts`) is installed directly from its pinned upstream Git commit. Its upstream prepare step uses pnpm 12.6.0, supplied by the install command below.

```sh
(cd crypto && npm ci --ignore-scripts)
cd chain && npm exec --yes --package=pnpm@12.6.0 -- npm ci
algokit localnet start
npm test        # 8 LocalNet tests, about 9 minutes
npm run demo    # Capsule Lab at http://127.0.0.1:8787
npm run browser-check   # Capsule Lab in headless Chrome (needs Chrome installed)
```

LocalNet must be in its default dev mode, where a block is sealed per transaction. All accounts, VRF keys and nomination keys are generated LocalNet throwaways and are never printed.

## Capsule Lab (demo UI)

`npm run demo` serves a single page at `127.0.0.1:8787` for the paper-aligned design: `EpochCommittee` with its member workers, with capsules on bucket keys. The server runs the committee's members, stepped in lockstep with the round clock; in a real deployment each member runs its own client and node. Senders and recipients are you: the page connects a wallet and does their cryptography itself. What you can do:

1. **Start an environment.** Choose the number of members, the expected committee size (up to 12) and the threshold t. Each member's account goes online for consensus with throwaway participation keys. After Algorand's 320-round stake lookback, the app is deployed and members enroll with bonds of 1, 2, 3 and 5 Algo in turn. Their workers then start. The genesis committee creates the first buckets, and their keys are attested about two epochs later.
2. **Watch the epochs.** The epoch panel shows the nomination window and the handover window, the committee in office, the messages posted, and recent handovers: messages checked, the liveness margin, buckets held with their public keys, and whether all members agree. Locking refuses while the margin is 0, when one more silent seat would lose every bucket. Each member's secrets live in its own vault processes.
3. **Connect a wallet.** "Connect wallet (KMD)" uses LocalNet's own wallet. "Lute" uses the Lute browser extension, a real wallet that can use LocalNet; its account is funded from the LocalNet dispenser. The wallet signs every sender and recipient transaction; its keys never reach the page or the server.
4. **Lock a capsule.**
   - **In the page.** The page reads the bucket key the committee attested straight from algod and seals the message under it, to your own wallet or to an address you give.
   - **From your wallet.** It registers u, a proof bound to the policy and the payload hash.
   - **The server's part.** It receives only the ciphertext, and stores it only if it matches the hash on chain.

   There is no dealer and no per-capsule committee.
5. **Be the recipient.**
   - Request access: the page makes a fresh X25519 key, keeps it in this browser (IndexedDB), and binds its public half from your wallet.
   - At the next handover every holder seals a partial to that key. The page reads the partials from the chain, checks them against the attested commitments and decrypts. The plaintext exists only in the page.
   - You can also try requesting early, from another wallet, again with a new key, or after expiry.
6. **Attacks.** The server's outsider account plays them:
   - **Wrong wallet.** It tries to request your capsule, and is refused.
   - **Replay.** It copies a capsule's u under its own policy. Every holder refuses that, because the proof is bound to the original policy.
7. **Members.** Each card shows the member's bond and how many seats it nominated for the next committee: seats follow bonds. The demo uses about one ticket per expected seat, each almost sure to win, so committee sizes stay near the target. Take members offline (an outage: they keep their memory and catch up when back). A committee hands over as long as t of its seats post.
8. **Operator view.** This toggle shows which seats each member holds and its private worker log, both taken from the workers rather than the chain.
9. **Committee security.** For the committee in office, it shows the per-epoch chance that a corrupt fraction f exposes the key or stalls a handover, using the exact-tail model from Phase 0.

`npm run browser-check` drives it in headless Chrome with the KMD wallet: the full capsule flow, the attacks, the operator view, a member outage, phone width and dark mode. It finds no page errors, and no request from the page to the server contains the plaintext (2026-10-12). The clock and the advance button share one queue, so a worker never runs two steps at once. The server binds to 127.0.0.1 only.

## Protocol

`EpochCommittee` implements the paper's evolving committees (eprint 2020/464 §3), and capsules are released from its handover messages (Phase 4). Epoch e spans rounds `[e·E, (e+1)·E)`. Committee c is nominated in epoch c − 1 from the block seed of that epoch's first round, and hands over in epoch c.

**Membership and sortition (Phase 5).** Anyone may join; there is no admin. A member enrolls with a payment that covers its own boxes, and the rest of the payment is its bond.
- **Weight.** A member's sortition weight is its bond, capped by its online stake (`voter_params_get`, which reads balances 320 rounds back). A bond change counts from the next epoch's nominations, after a seed nobody knew when making it. The bond is escrowed because online stake alone can be counted twice: moving coins between accounts during a nomination window counts them once per account. A withdrawal stops counting from the next epoch, so no coin counts twice in one sortition. It is paid only after four epochs (`claimWithdrawal`), so it stays slashable for longer than any seat its member holds.
- **Tickets.** The total bond is cut into `totalTickets` tickets, so a member holds ⌈w · totalTickets / total⌉ of them, the last one partial. Ticket j wins when the rank of `VRF(sha256("ecpss/nominate/v2" ‖ appId ‖ committee ‖ j ‖ seed))` is below `ticketThreshold`, scaled down for a partial ticket. This is Algorand's binomial sortition with tickets as sub-users. Each winning ticket is one seat, so a committee has about `totalTickets · ticketThreshold / 2^64` seats. Splitting stake across accounts does not change a member's expected seats.
- **Nominees.** A nominator seals each seat to a member drawn at random by bond, so accounts without a bond attract no seats.
- **Deposits.** Everyone pays for the boxes they need: a member for its registry entry and three key slots (145,700 µAlgo), a nominator for each seat (150,500 µAlgo, refunded when it deletes the seat), and a sender for each capsule. The creator funds only the app account's 0.1 Algo minimum. The app holds box deposits, bonds, withdrawals still unbonding and slashed funds, nothing else.
- **Penalties.** A holder answers with its bond for every leaf under the root it signs. Anyone who proves a bad subshare on chain (`reportBadDealing`) gets half the holder's bond, including any withdrawal still unbonding. The other half stays in the app (`slashedTotal`).

**Packed epochs.** Handovers alternate between packing and unpacking (`handoverPlan` in the crypto package's `ecpss.ts`), so each holder posts one dealing for all live buckets instead of one per bucket.
- **Pack.** A committee holding its buckets unpacked has each holder deal one polynomial in evaluation form. That polynomial carries its share of every live bucket and a contribution to every new one, at fixed points. The next committee then holds a single packed share.
- **Unpack.** A packed committee has each holder re-share its one packed share. The next committee interpolates each live bucket's own share from those dealings, and new buckets come from separate contributions.
- **When it applies.** A committee packs only when it carries at least two buckets and the next committee has the t + ℓ − 1 seats its own handover will need.
- **Cost.** Unpacking ℓ buckets needs t + ℓ − 1 valid dealings instead of t, and a capsule released by a packed committee needs t + ℓ − 1 partials. Secrecy still needs fewer than t corrupt seats.

| Rounds of epoch e | Call | Who | Checks |
| --- | --- | --- | --- |
| Any | `enroll(vrfKey, pay)` once; `addBond(pay)`; `withdrawBond(amount)`, then `claimWithdrawal()` four epochs later; `postNominationKey(epoch, key)` for the current or next epoch, never replaced | Anyone; member | `Txn.sender`; the enrollment payment covers the deposits |
| 1…`nominationRounds` (under 320) | `nominate(index, ticket, proof, epk, sigKey, sealedSeed, pay)`, once per winning ticket, for committee e + 1 | Member with weight | Exact seat deposit. The first nomination copies the seed with `block BlkSeed`, so nominations use a validity window ending within about 1,000 rounds of the seed round. The ticket exists for the member's weight, `vrf_verify` with the enrolled key, the rank wins, and the member enrolled before the seed round |
| Next `handoverRounds` | `claim(e, nominator, ticket, holder, stateDigest, dealingsRoot, sig)`, then `postChunk(e, nominator, ticket, a, b, c, d)` with the note, then `finalize`, as one atomic group per seat | Committee e's holders | The seat's one-time Ed25519 key signs the claim, including the Merkle root of the message's (dealing, recipient) leaves. After that, `Txn.sender` must be the claimed holder. Each chunk is folded into the seat's on-chain running digest |
| Until epoch e + 2 ends | `reportBadDealing(e, nominator, ticket, index, path, id, kind, k, epk, expected, r1, r2, b)` | Anyone | The leaf hashes to the seat's signed root along the path. The subshare then fails e(r1, g2) = e(g1, r2) or e(g1, b) = e(E, g2)·e(r1, epk), where E is the commitment the leaf says recipient k's subshare opens to. Two `ec_pairing_check`s; the holder's bond is slashed, half to the reporter. 0.09 Algo in fees, mostly for opcode budget, at any t |
| After epoch e + 2 | `deleteSeats(e, tickets[])` (batches of 7) | The nominator (workers do it three committees back) | Refunds the seat deposits to the nominator |
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
- **Handover.** As a holder, it builds its single handover message and its secrets are erased. Then it posts each seat from its own account as one atomic group: claim, message chunks and finalize. That is one round per seat for messages up to 14 chunks (about 280 KB). Seats go four at a time. There is no relayer.
- **Reports.** When a message matches its signed root but deals some recipient a bad subshare, the member proves it on chain (`fraud.ts` in the crypto package builds the proof). Members race to report, and the losers find nothing left to slash. A member never reports its own seats. Verifiers never check roots: a message is judged on its dealings alone.
- **Retries.** A stage counts as done only once it succeeds. A node error, such as a public node's rate limit, means it is retried at the next step, never skipped. The reader fetches at most eight boxes at a time.
- **Processing.** It processes every closed handover in order and catches up after an outage. Messages are verified on a shared thread pool (`VerifyPool` from the crypto package), and it combines shares for its seats in the next committee.
- **Cleanup.** It deletes the seats it nominated three committees back and recovers their deposits.
- **Liveness.** Each `received` event reports the handover's mode (plain, pack or unpack) and its margin: by how many valid dealings the worst kept bucket exceeds what it needs, t or t + ℓ − 1.

**Secrets (Phase 6).** Secrets live in one short-lived vault process per committee (`SeatVault` from the crypto package).
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

The cryptography lives in [`crypto/src/ecpss.ts`](../crypto/src/ecpss.ts) and is unreviewed.

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
- liveness: members go silent through one handover so that as few seats as possible speak, but at least what that handover needs (t, or t + ℓ − 1 if it unpacks). Every worker reports the resulting margin, the sender refuses to lock below its minimum, and the margin recovers after the next full handover.

`test/epoch-join.test.ts` (1 test, Phase 6, about 25 seconds): six members run. After two handovers one crashes, losing its process, vaults and history, and a new member enrolls and starts at once. The crashed member restarts an epoch later with nothing in memory. The test shows that:
- both join from the attested state and agree with everyone on every later handover, and no bucket is lost;
- every seat either holds after joining speaks, and the new member nominates once its stake counts;
- every old seat, including those the crashed run nominated, is deleted with its deposit returned.

`test/epoch-slash.test.ts` (1 test, about 20 seconds): eight members, one of which deals recipient 1 a bad subshare in every seat's first dealing under the root it signs (a test-only vault mode). The test shows that:
- honest members report it and the cheater loses its bond while the others keep theirs;
- no bucket is lost and all members agree;
- once slashed, the cheater wins no tickets and holds no new seats;
- the app holds exactly its deposits, bonds, withdrawals in progress and slashed funds.

`test/epoch-stake.test.ts` (1 test, Phase 5, about 90 seconds): ten member workers, eight with bonds of 1–6 Algo, run ten committees.
- **Seats track bonds:** each member's seat count lies within 4 standard deviations of the expectation from its tickets, and the fit's slope is between 0.8 and 1.2.
- **No weight, no seats:** an online member with no bond and a bonded member with no online stake hold no ticket. Their nominations are rejected, and they never nominate.
- **Bond timing:** a new bond counts from the next epoch's nominations. A withdrawal stops counting at the next epoch and is paid only after four, and claiming it early is refused.
- **Several seats per member:** holders with several seats speak once per seat, and no bucket is lost.
- **Deposits:** the app holds bonds beyond its boxes' deposits and nothing else.

`test/epochs.test.ts` (3 tests, Phases 1–2; equal bonds, one ticket each):
- **Sortition:** the captured seed equals the block's seed. Exactly the VRF-eligible members nominate, once each. Ineligible, late-enrolled, copied-proof, duplicate, nonexistent-ticket, underpaid and out-of-window nominations are rejected. Seats are numbered in signing-key order and each opens only for its nominee.
- **Handover on chain:** two real committees. A liar deals a bad subshare under the root it signs: a report convicts it (half its bond to the reporter), while a report against an honest leaf, under another seat's root or with a forged index fails, and a second report finds nothing to slash. The first holds an honest dealer's bucket. Each holder claims its seat with its one-time key and posts one encoded handover message: a single dealing that packs the bucket with a new committee-generated one. One holder posts 50 KB of garbage instead. Readers rebuild every message from blocks, the next committee drops the cheater and reconstructs the original secret, and after the epoch each nominator deletes its seat and gets the deposit back. Early, forged, repeated or outsider claims and posts are rejected.
- **Creation and immutability:** epoch-length and nomination-window checks; no update, delete or opt-in.

## What is and isn't protected

**Hidden:** which member holds which seat, until the seat speaks. A seat's holder posts from its own account only after its vault has erased the seat's secrets, as in the paper.

**Not hidden or not guaranteed:**
- **The cryptography is unreviewed.** The pairing-based re-sharing, the capsule KEM and their proofs (`crypto/src/pvss.ts`, `ecpss.ts`) have had no cryptographer's review. Plain ElGamal is not known to meet the paper's selective-opening requirement (RIND-SO), and HPKE's anonymity rests on the paper's unproven Conjecture 1. Packed epochs are newer still. On a packed committee, one capsule's partials also give its recipient e(u, S) for the pack's other buckets, which opens no other capsule: u is bound to its own capsule's label.
- **Committees here are small.** Security needs fewer than t corrupt seats per epoch, and liveness needs t honest seats speaking (t + ℓ − 1 when unpacking ℓ buckets, every other epoch). The plan's sizes (C ≈ 130–210) come from exact tails at f = 5%. Demo and test committees of 5–20 seats tolerate little corruption.
- **A seat is corrupt if its nominator or its holder is,** about 2f. Nominators are public and know a seat's keys until they erase them.
- **Weight is bonded stake.** f is the adversary's share of the bonds, not of Algorand's online stake. The online-stake cap can be worked around by moving online coins between bonded accounts.
- **Penalties deter nobody yet.** Only a subshare that fails its pairing checks under the root its holder signed is provable and slashed. A rational cheater signs a root that leaves its bad subshare out, or names a commitment its subshare matches, and its message is then just dropped, the same as silence. Silence, a garbled message, a wrong re-shared value and a bad contribution proof are not punished at all; penalizing non-delivery needs something like eprint 2026/919's time-lock puzzles. A cheater can also report itself and recover half its bond. A report costs 0.09 Algo, so it does not pay against bonds under about 0.2 Algo.
- **Forward secrecy rests on erasure.** Sealed seeds and handover messages stay on-chain forever. Each committee's secrets live in a vault process that exits before its seats speak, but JavaScript cannot wipe bigints or pin memory, so erasure is not provable. Until a vault exits, stealing a member's live state exposes what that vault holds.
- **One failed handover loses every live bucket.** That happens when fewer than t honest seats speak, or fewer than t + ℓ − 1 when a committee unpacks. Senders can check the liveness margin before locking, but nothing can rescue a bucket once a handover fails.
- **Network traffic can identify holders.** Members should each use their own node; a shared node sees which account reads what. Each worker trusts its own algod node, since this is not a light client.
- **Expiry is coarse,** with the granularity of the bucket width plus an epoch, and one more epoch when a bucket expires at an unpacking handover: the packed shares being re-shared still carry it, so it is gone only once the next committee erases. Expiry does not revoke releases already delivered.
- **Releases wait for the next handover,** up to an epoch.
- **Status: LocalNet tests and a small TestNet trial only.** Unaudited; use synthetic secrets only.
