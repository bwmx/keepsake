# Capsule policy app: hidden, variable-size holder committees (milestones 2–4)

This package contains the Algorand side of [the implementation plan](../IMPLEMENTATION_PLAN.md). It implements steps 1–5 of the plan's "Hidden committee design":

- **Private sortition seeded by our beacon.** Members select themselves privately with their own VRF keys, seeded by our instance of [bwmx/randomness-beacon](https://github.com/bwmx/randomness-beacon) at commit `0e164c3`.
- **Anonymous one-time holder keys.** Selected members nominate holders without revealing who they are.
- **Chain-only custody.** Holders interact only through those keys, and only via the chain.
- **Variable-size committees with a majority threshold.**

| Part | Contents |
| --- | --- |
| `smart_contracts/` | `CapsulePolicy`: Algorand TypeScript compiled with Puya TS through AlgoKit |
| `src/chain.ts` | Chain reader that fails closed; manifest rebuilt from chain data; shared message formats |
| `src/worker.ts` | Member worker (nominator + holder). Talks only to algod; no network API; also runs as a CLI |
| `src/sim.ts` | LocalNet environment: beacon + daemon, app, enrolled members, in-process workers, sender/recipient flows |
| `demo/` | **Capsule Lab**: a local web UI for the epoch-committee design (Phases 4–5) |
| `smart_contracts/epoch_committee/`, `src/epochs.ts`, `src/epoch-worker.ts`, `src/epoch-capsules.ts`, `src/epoch-sim.ts` | `EpochCommittee`, its member worker, the capsule sender and recipient, and the LocalNet environment: Phases 1–5 of `../PAPER_ALIGNMENT_PLAN.md`, the paper's epoch committees, drawn by stake-weighted sortition, holding bucket keys and releasing capsules (see below) |
| `smart_contracts/broadcast_probe/`, `bench/broadcast-probe.ts` | Phase 0 probe for `../PAPER_ALIGNMENT_PLAN.md`: argument and note limits and fees, an epoch of handover data posted and rebuilt from blocks, block-seed lookback, stake opcodes (`npm run probe`) |

It runs on **LocalNet only** and is not deployed elsewhere. All cryptography stays in the [crypto spike](../crypto-spike/README.md).

## Run

Requires Node.js 24+, AlgoKit CLI 2.10+, Docker, Git and npm. `randomness-beacon/` is a Git submodule pinned to an upstream commit and remains maintained in its upstream repository. The VRF library (`@bwmx/algorand-vrf-utils-ts`) is installed directly from its pinned upstream Git commit. Its upstream prepare step uses pnpm 12.6.0, supplied by the install command below.

```sh
git submodule update --init randomness-beacon
(cd randomness-beacon \
  && npx -y pnpm@12.6.0 install --frozen-lockfile && npx -y pnpm@12.6.0 run build:all)
(cd crypto-spike && npm ci --ignore-scripts)
cd policy-app && npm exec --yes --package=pnpm@12.6.0 -- npm ci
algokit localnet start
npm test        # 13 LocalNet tests, about 6 minutes
npm run demo    # Capsule Lab at http://127.0.0.1:8787
```

LocalNet must be in its default dev mode, where a block is sealed per transaction. All accounts, VRF keys and nomination keys are generated LocalNet throwaways and are never printed.

## Capsule Lab (demo UI)

`npm run demo` serves a single page at `127.0.0.1:8787` for the paper-aligned design: `EpochCommittee` with its member workers, with capsules on bucket keys. One local server plays every party, and the workers step in lockstep with the round clock. In a real deployment each member, sender and recipient would run its own client and node. What you can do:

1. **Start an environment.** Choose the number of members, the expected committee size (up to 12) and the threshold t. Each member's account goes online for consensus with throwaway participation keys. After Algorand's 320-round stake lookback, the app is deployed and members enroll with bonds of 1, 2, 3 and 5 Algo in turn. Their workers then start. The genesis committee creates the first buckets, and their keys are attested about two epochs later.
2. **Watch the epochs.** The epoch panel shows the nomination window and the handover window, the committee in office, the messages posted, and recent handovers: messages checked, buckets held with their public keys, and whether all members agree.
3. **Lock a capsule.** The sender encrypts under the key of the bucket its expiry falls in, taken from the state the committee attested. It registers u, a proof bound to the policy, and the payload hash. There is no dealer and no per-capsule committee.
4. **Play the recipient.**
   - Request access with a fresh key.
   - At the next handover every holder seals a partial to that key. The recipient checks the partials against the attested commitments and decrypts.
   - You can also try requesting early, from another wallet, again with a new key, or after expiry.
5. **Replay attack.** Copy a capsule's u under another policy. Every holder refuses it, because its proof is bound to the original policy.
6. **Members.** Each card shows the member's bond and how many seats it nominated for the next committee: seats follow bonds. The demo uses about one ticket per expected seat, each almost sure to win, so committee sizes stay near the target. Take members offline (an outage: they keep their memory and catch up when back). A committee hands over as long as t of its seats post.
7. **Operator view.** This toggle shows which seats each member holds and its private worker log, both taken from the workers rather than the chain.
8. **Committee security.** For the committee in office, it shows the per-epoch chance that a corrupt fraction f exposes the key or stalls a handover, using the exact-tail model from Phase 0.

The clock and the advance button share one queue, so a worker never runs two steps at once. The server binds to 127.0.0.1 only. The recipient's decryption happens inside the server process, standing in for the recipient's own client, and there is no wallet integration. The earlier per-capsule design (`CapsulePolicy`, `src/sim.ts`, `src/worker.ts`) is still in the package and tested, but the demo no longer uses it.

## Protocol

| Stage | Step | Who | Authenticated by |
| --- | --- | --- | --- |
| — | `admitCustodian(account)`; `enroll(vrfKey)` once | Admin; member | `Txn.sender` |
| — | `postNominationKey(epoch, key)`: a fresh X25519 key for the current or next epoch (`round / epochRounds`), once per epoch, never replaced. Stored in a ring of 3 per member | Member | `Txn.sender` is enrolled |
| `AWAITING_SEED` | `register(recipient, openRound, expiresRound, slotCount ≤ 64, minHolders ≥ 3, pay)`. Commits the terms, the registry snapshot and the registration epoch, and requests the beacon seed for `now + 8`. Returns the capsule ID, which is the beacon request ID | Sender | `Txn.sender`; exact payment |
| `NOMINATING` | Beacon `fulfillRandomness`; then `nominate(capsule, slot, index, proof, holderEncKey, holderSigKey, sealedSeed)` until `seedRound + nominationRounds`. The lowest VRF rank per slot wins | Beacon; eligible member | Caller app is the pinned beacon; `vrf_verify` with the enrolled key; rank below `nominatorThreshold`; `Txn.sender` is the member |
| `SELECTED` | `closeNominations`. The committee is the filled slots, n ≥ `minHolders`; threshold `⌊n/2⌋ + 1`; empty slots get no fallback | Anyone | — |
| `DEPOSITING` → `ANCHORED` | `anchorManifest(hash, payloadHash)`, then `postDeposits(slots[], commitments[], deposits[])` in batches of up to 7 until every filled slot has one | Sender | `Txn.sender` |
| `ACTIVE` | `acknowledgeCustody(capsule, slot, sig)`. Active once acknowledgments reach the threshold; later ones still count | Relayer | `ed25519verify_bare` with the slot's one-time key |
| | `requestAccess(capsule, hash, requestId, recipientKey)` once, in `[openRound, expiresRound)` | Recipient | `Txn.sender` |
| | `postRelease(capsule, slot, enc, ct, sig, chainSig)`, once per acknowledged slot, before `expiresRound` | Relayer | One-time key over request ID, recipient key and the release |
| deleted | After expiry: `deleteSlots(slots[])` in batches of up to 7, then `cleanup`, which refunds the sender. Or `cancelUnseeded` after the beacon's timeout, which refunds everything | Anyone | — |

Nominators seal each holder seed to the chosen member's key for the capsule's registration epoch. Once nominations close, holders find their slots by trying to decrypt each nomination with that epoch's key. Each member erases an epoch's private key as soon as every capsule of that epoch has closed nominations; `createApplication` requires `8 + nominationRounds < epochRounds`, so a ring entry is overwritten only after its epoch's nominations are over. Holders rebuild the manifest from chain data alone and accept their deposit only if it hashes to the anchored value. The recipient does the same and decrypts once a threshold of releases is on-chain. Only the payload ciphertext travels off-chain, and its hash is anchored. The application has no update, delete or opt-in path.

Batching keeps every call within Algorand's limit of 8 resource references per transaction. Each slot is its own box, and counters in the capsule record replace loops over slots.

**Costs on LocalNet (1,000 µAlgo minimum fee):**

- **Registration:** a payment of `137,700 + 176,900 × slots` µAlgo of box deposit, plus 98,200 for the beacon (14,000 fees and 84,200 deposit). For example, 2,358,700 for 12 slots. Cleanup refunds everything except the 14,000 beacon fees.
- **Each nomination:** 10,000, paid by the nominator (nine budget top-ups for `vrf_verify`).
- **Nomination keys:** 1,000 per member per epoch, paid by the member. The app account holds 126,500 of box deposit per member (registry, admission and 3 key boxes), pre-funded by the admin.
- **Each acknowledgment or release:** 4,000, paid by the relayer.
- **Each deposit batch:** about 3,000.
- **Leftover:** the beacon's unspent proof-fee share stays in the app.

## Chain behaviour vs the mock ledger

The spike's `MockConfirmedLedger` is still its own test double. Here, every authorization decision comes from chain state:

- **`ChainReader`** pins the genesis hash and app ID. It fails closed on a wrong network, a node that is catching up, a node idle longer than `MAX_ROUND_AGE_MS`, or a missing capsule.
- **`chainAuthorization`** re-reads the capsule before and after HPKE encryption for each release.
- **Workers refuse to start** if the app's beacon or their enrolled VRF key differ from their configuration.

Worker config is read from the environment:
- `ALGOD_SERVER`, `ALGOD_PORT`, `ALGOD_TOKEN`
- `GENESIS_HASH`, `APP_ID`, `BEACON_APP_ID`
- `MEMBER_MNEMONIC`, `VRF_SECRET_KEY`, `RELAYER_MNEMONIC` (nomination keys are generated in memory, never configured)
- `MAX_ROUND_AGE_MS`, `POLL_MS`

Each worker writes JSON event lines to stdout: `ready`, `nominated`, `custody`, `released`, `disposed`, `erased` (an epoch's nomination key). These name the member's own slots and stay private to its operator.

## Epoch committees (paper alignment, Phases 1–5)

`EpochCommittee` is a separate app for the paper's evolving committees (eprint 2020/464 §3). Its workers run it on LocalNet, and capsules are released from its handover messages (Phase 4). Epoch e spans rounds `[e·E, (e+1)·E)`. Committee c is nominated in epoch c − 1 from the block seed of that epoch's first round, and hands over in epoch c.

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
- **Handover.** As a holder, it builds its single handover message, erases its shares, claims the seat and posts the message from its own account. There is no relayer.
- **Processing.** It processes every closed handover in order and catches up after an outage. Messages are verified on a shared thread pool (`VerifyPool` from the crypto spike), and it combines shares for its seats in the next committee.
- **Cleanup.** It deletes the seats it nominated three committees back and recovers their deposits.

Secrets live only in memory. A restarted member would need to replay every handover since genesis from an archival node, which is not implemented.

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

`test/contract.test.ts` (5 tests):
- **Enrollment and registration:** enrollment rules; nomination keys only for the current or next epoch, never replaced, ring reuse two epochs later, and the epoch-length check; the capsule's registration epoch; committee-size bounds, registry size, payment, and the callback check.
- **Sortition:** a copied proof, another member's proof and another slot's proof are rejected. The on-chain rank equals the off-chain rank. Lower rank replaces higher without growing the committee. The snapshot, eligibility threshold and deadline are enforced, and too few holders means no fallback.
- **Variable committee:** 6 of 8 slots give threshold 4. Deposits go in batches, with unfilled, duplicate and oversized batches rejected. Activation happens at the threshold, and late acknowledgments still count. One-time-key signatures are enforced, releases require an acknowledgment, the window and replay rules hold, and batched cleanup refunds exactly.
- A withheld beacon proof leads to stale cancellation and a full refund.
- Update, delete and opt-in are rejected.

`test/workers.test.ts` (3 tests):
- **Step 5 end to end:** 24 members, 16 slots, and an eligibility rate that can leave slots empty. Every slot goes to its lowest-ranked eligible member, and a slot is empty exactly when nobody was eligible. Activation works. Holders are taken offline down to the threshold and recovery still works from chain releases. The indexer shows members sent only `enroll`, `postNominationKey` and `nominate`, and every custody call came from the relayer. A restarted member cannot reopen its slots. Online holders erase the capsule's epoch key while still holding custody. Workers dispose at expiry.
- **Tampered anchor:** holders refuse custody and the capsule never activates.
- **Fail-closed reader and CLI:** the chain reader fails closed, and the worker CLI starts only with matching enrolled keys.

`test/epoch-workers.test.ts` (1 test, Phase 3, about 3 minutes): ten member workers, driven in lockstep, run 22 handovers with four outages.
- **Agreement:** every member, including the ones that were offline, processes every handover, and all agree on each bucket's public key.
- **No losses:** no bucket is lost, and a bucket's key and reconstructed secret never change.
- **Schedule:** buckets appear and disappear exactly as scheduled.
- **Indexer:** each seat's claim and finalize happen once, from its own holder (a member, never a relayer), after that member posted its key for the next epoch. Nobody speaks while offline.
- **Cleanup:** nominators delete their old seats, and the app holds only bonds beyond its boxes' deposits. Workers report no errors.

`test/epoch-capsules.test.ts` (1 test, Phase 4, about 80 seconds): with eight member workers running, it shows:
- a capsule locked under an attested bucket key is privately released at the next handover and decrypts;
- requests are refused from another wallet, before opening, for a second key and after expiry;
- a capsule reusing another's u under its own policy is refused by every holder, without errors;
- the deposit is refunded;
- after its last handover the expired capsule's bucket is held by nobody and re-dealt by nobody.

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

**Hidden:** which member holds which slot. Holder accounts never sign or pay for anything on-chain.

**Not hidden or not guaranteed:**

- **Forward secrecy rests on erasure.** Deposits and sealed holder seeds stay on-chain forever. They stay closed only because each epoch's nomination key exists solely in its worker's memory and is erased once that epoch's nominations close (the paper's per-epoch keys, §2.1 and §3.1.3). Erasure is best effort: the key is a WebCrypto object whose reference is dropped, not provably wiped. Until erasure, and until expiry for the one-time keys and shares, stealing a member's live state exposes what it holds.
- **Erasure comes after acknowledgment.** The paper erases before a holder posts, because posting reveals the holder. Here the relayer posts, so posting does not name the holder, and the key is erased at the end of its epoch instead.
- **Restart loses custody.** A restarted member has fresh keys and cannot reopen its seeds; its slots count as offline. Keys it posted before restarting stay on-chain, so seats nominated to it under those keys are lost too.
- **Nominators are public, and a corrupt nominator owns its slot.** It knows the one-time keys until it erases them. A slot is corrupt with probability about `1 − (1 − f)²` ≈ 2f.
- **Larger committees are what make hidden selection pay off.** Holders are drawn with replacement, so one member can hold several slots. With n slots and a majority threshold, the chance that colluders control a threshold falls rapidly as n grows, provided 2f stays well below ½ (see Collusion risk in Capsule Lab). Small committees remain weak.
- **The encryption's anonymity is unreviewed.** HPKE base mode over X25519 is used for nominations without a review of key privacy or selective-opening security against the paper's requirements.
- **Network-level traffic can still identify holders.** The relayer hides who pays, not which IP queried algod or contacted the relayer.
- **The beacon seed is public once proven.** Its single operator (us) can learn it early or withhold it.
- **The admin is the Sybil gate.** Stake weighting (`voter_params_get`) and multi-epoch re-sharing (step 6) are not implemented.
- **Expiry does not revoke delivered responses,** and memory erasure is best effort.
- **Status: LocalNet only and unaudited.** Use synthetic secrets only.
