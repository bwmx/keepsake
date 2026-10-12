# Keepsake chain

The Algorand side of Keepsake: the `EpochCommittee` contract, the member worker that runs a member, the capsule client, Capsule Lab, and the LocalNet tests and TestNet trial. How the protocol works is in [docs/design.md](../docs/design.md); this page is about the code. The cryptography it uses is in the [crypto package](../crypto/README.md).

| Path | Contents |
| --- | --- |
| `smart_contracts/epoch_committee/` | `EpochCommittee`, in Algorand TypeScript compiled with Puya TS through AlgoKit |
| `src/epochs.ts` | Round windows, the bucket schedule, sortition tickets, message chunking, and a reader that rebuilds messages from blocks and checks them against the on-chain digests |
| `src/epoch-worker.ts` | The member worker: keys, nominations, seats, one handover message per seat, verification, fraud reports and cleanup, with secrets in per-committee vault processes. It talks only to algod, and also runs as a CLI |
| `src/epoch-capsules.ts` | Capsule sender and recipient, the attested public state, and the liveness margin |
| `src/epoch-sim.ts` | The LocalNet environment for tests and the demo: members online with throwaway participation keys, bonded and enrolled, with in-process workers |
| `src/chain.ts` | A chain reader that fails closed on the wrong network or a stale node, and shared helpers |
| `demo/` | **Capsule Lab**, the local web demo. `demo/client.ts` is bundled for the browser by esbuild |
| `test/` | LocalNet tests (below) |
| `bench/browser-check.ts` | Drives Capsule Lab in headless Chrome |
| `bench/testnet-trial.ts` | The TestNet trial |
| `smart_contracts/broadcast_probe/`, `bench/broadcast-probe.ts` | The feasibility probe: app-call limits and fees, an epoch of handover data posted and read back, block-seed lookback, and the stake opcodes |

## Run

Needs Node.js 24+, AlgoKit CLI 2.10+, Docker and Git. The VRF library (`@bwmx/algorand-vrf-utils-ts`) is installed from a pinned Git commit, and its prepare step needs pnpm 12.6.0, which the install command below fetches.

```sh
(cd ../crypto && npm ci --ignore-scripts)
npm exec --yes --package=pnpm@12.6.0 -- npm ci
algokit localnet start

npm test                # LocalNet tests, about 9 minutes
npm run demo            # Capsule Lab at http://127.0.0.1:8787
npm run browser-check   # Capsule Lab in headless Chrome (needs Chrome; CHROME_PATH overrides)
npm run probe           # Chain limits and fees
```

Every script builds first: the crypto package, the contract and its typed client, then this package. LocalNet must be in its default dev mode, which seals a block per transaction. All accounts and keys are generated LocalNet throwaways and are never printed.

## Capsule Lab

`npm run demo` serves one page on `127.0.0.1` only. The server runs the committee's members, stepped in lockstep with the round clock; in a real deployment each member runs its own worker and node. You play the sender and the recipient, and the page does their cryptography itself, so the server never sees a plaintext or a request key.

1. **Start an environment.** Choose the number of members, the expected committee size (up to 12) and the threshold t. Members go online with throwaway participation keys, wait out Algorand's 320-round stake lookback, then enroll with bonds of 1, 2, 3 and 5 Algo in turn. The first bucket keys are attested about two epochs later.
2. **Watch the epochs.** The epoch panel shows the nomination and handover windows, the committee in office, and recent handovers: messages checked, the liveness margin, the buckets held and whether all members agree.
3. **Connect a wallet.** "Connect wallet (KMD)" uses LocalNet's own wallet. "Lute" uses the Lute browser extension, funded from the LocalNet dispenser. The wallet signs every sender and recipient transaction.
4. **Lock a capsule.** The page reads the attested bucket key from algod and seals your message under it, to your own wallet or another address. Your wallet registers the capsule. The server receives only the ciphertext, and stores it only if it matches the hash on chain. Locking is refused while the liveness margin is 0.
5. **Be the recipient.** Request access: the page makes a fresh X25519 key, keeps it in this browser (IndexedDB), and your wallet binds its public half on chain. At the next handover the page reads the partials from the chain, checks them and decrypts. You can also try requesting early, from another wallet, a second time, or after expiry.
6. **Attacks.** The server's outsider account tries to request your capsule (refused: wrong wallet) and copies a capsule's u under its own policy (refused by every holder: replay).
7. **Members.** Each card shows the member's bond and how many seats it nominated; seats follow bonds. Take members offline and back. A committee hands over as long as enough of its seats post.
8. **Operator view.** Shows which seats each member holds and its private worker log, taken from the workers rather than the chain.
9. **Committee security.** The per-epoch chance that a corrupt fraction f exposes the keys or stalls a handover, for the committee in office.

`npm run browser-check` drives all of this in headless Chrome with the KMD wallet, at desktop and phone widths and in dark mode. It fails on any page error, or if anything the page sends the server contains the plaintext. Screenshots go to the git-ignored `browser-shots/`.

## The contract

Epoch e spans rounds `[e·E, (e+1)·E)`. Committee c is nominated in epoch c − 1 and hands over in epoch c.

| When (rounds of epoch e) | Call | Who | Checks |
| --- | --- | --- | --- |
| Any | `enroll(vrfKey, pay)` once; `addBond(pay)`; `withdrawBond(amount)`, then `claimWithdrawal()` four epochs later; `postNominationKey(epoch, key)` for the current or next epoch, never replaced | Anyone; members | `Txn.sender`. The enrollment payment covers the member's deposits, and the rest is its bond |
| 1…`nominationRounds` (under 320) | `nominate(index, ticket, proof, epk, sigKey, sealedSeed, pay)`, once per winning ticket, for committee e + 1 | Members with weight | Exact seat deposit. The ticket exists for the member's weight, `vrf_verify` passes with the enrolled key, the rank wins, and the member enrolled before the seed round. The first nomination copies the seed with `block BlkSeed` |
| The next `handoverRounds` | `claim(e, nominator, ticket, holder, stateDigest, dealingsRoot, sig)`, then `postChunk(e, nominator, ticket, a, b, c, d)` with the note, then `finalize`, as one atomic group per seat | Committee e's holders | The seat's one-time Ed25519 key signs the claim. After that, `Txn.sender` must be the claimed holder. Each chunk is folded into the seat's running digest |
| Until epoch e + 2 ends | `reportBadDealing(e, nominator, ticket, index, path, id, kind, k, epk, expected, r1, r2, b)` | Anyone | The leaf hashes to the seat's signed root, and the subshare fails a pairing check. The holder's bond is slashed, half to the reporter |
| After epoch e + 2 | `deleteSeats(e, tickets[])`, up to 7 per call | The nominator | Refunds the seat deposits |
| Any, after the genesis committee | `registerCapsule(recipient, openRound, expiresRound, u, proof, payloadHash, pay)` | Sender | The bucket `expiresRound / bucketRounds` exists by schedule, the window spans at least two epochs, and the deposit (118,500 µAlgo) is exact |
| `[openRound, expiresRound)` | `requestAccess(capsule, requestId, recipientKey)`, once | Recipient | `Txn.sender` is the recipient |
| After `expiresRound` | `deleteCapsule(capsule)` | Anyone | Refunds the sender's deposit |

`createApplication` fixes what every member must agree on: the epoch and window lengths, the ticket count and threshold, the sharing threshold t, the bucket schedule (`bucketRounds`, `bucketLead`) and the genesis committee. The app cannot be updated or deleted, and has no opt-in. Its creator funds only the app account's 0.1 Algo minimum; members, nominators and senders pay for the boxes they need.

## Running a member

`node dist/src/epoch-worker.js` runs one member against its own algod node, configured by environment variables:

| Variable | Meaning |
| --- | --- |
| `ALGOD_SERVER`, `ALGOD_PORT`, `ALGOD_TOKEN` | The member's own algod node |
| `GENESIS_HASH`, `APP_ID`, `MAX_ROUND_AGE_MS` | Pins for the network and app, and how stale the node may be |
| `MEMBER_MNEMONIC` | An enrolled, bonded account |
| `VRF_SECRET_KEY` | Base64, 64 bytes: seed ‖ public key |
| `POLL_MS` | Polling interval |

It checks the host by starting a vault before anything else: vaults refuse to start with core dumps on, or with swap unencrypted (macOS) or on at all (Linux; `ECPSS_ALLOW_SWAP=1` overrides). It writes JSON event lines that name the member's own seats, so keep them private. Each `received` event reports the handover's mode (plain, pack or unpack) and its liveness margin.

A worker that starts after genesis, or restarts with nothing in memory, joins from the latest state that at least t seats attested.

## TestNet trial

`npm run trial` runs the design on TestNet through a public node. It funds throwaway members from `TESTNET_MNEMONIC` in `../.env` (git-ignored), runs handovers and a capsule round trip, reports timings, data and fees, then returns what it can to the funder. Results so far are in [docs/results.md](../docs/results.md#testnet-trials).

| Variable | Meaning |
| --- | --- |
| `TRIAL_MEMBERS` | Number of members |
| `TRIAL_TICKETS` | Seats per committee |
| `TRIAL_T` | Threshold t |
| `TRIAL_EPOCH`, `TRIAL_NOMINATION`, `TRIAL_HANDOVER` | Epoch length and its windows, in rounds |
| `TRIAL_LEAD_EPOCHS` | How far ahead buckets are created |
| `TRIAL_BOND`, `TRIAL_FUND` | Each member's bond and funding |

The keys of an interrupted run are kept in the git-ignored `.testnet-trial.json`, and `npm run trial -- cleanup` recovers the funds. Cleanup closes an account only once none of its seats remain.

## Tests

`npm test` runs these on LocalNet, one at a time:

| Test | Time | What it shows |
| --- | --- | --- |
| `epochs.test.ts` (3 tests) | — | **Sortition:** exactly the VRF-eligible members nominate, once each, and ineligible, late, copied, duplicate, underpaid and out-of-window nominations are rejected. **Handover on chain:** two real committees; one holder posts garbage and the next committee still reconstructs the secret; a liar's bad subshare is reported and slashed, and bogus reports fail. **Immutability:** no update, delete or opt-in |
| `epoch-workers.test.ts` | about 3 min | Ten workers run 22 handovers with four outages. Every member processes every handover and agrees on every bucket key; no bucket is lost or changes; buckets appear and expire on schedule; each seat speaks once, from its own holder, after it posted its next key |
| `epoch-capsules.test.ts` | 1–2 min | A capsule is released privately and decrypts. Requests are refused early, late, from another wallet and for a second key. A replayed u is refused by every holder. The expired bucket is held by nobody. Liveness: with as few seats speaking as a handover can survive, the sender refuses to lock and the margin recovers afterwards |
| `epoch-stake.test.ts` | about 90 s | Ten workers with bonds of 1–6 Algo. Seats track bonds; members with no bond or no online stake win nothing; bond changes and withdrawals take effect on schedule; members with several seats speak once per seat |
| `epoch-join.test.ts` | about 25 s | A member crashes and restarts an epoch later with nothing in memory, and a new member enrolls mid-run. Both join from the attested state and agree with everyone; all old seats are deleted with their deposits returned |
| `epoch-slash.test.ts` | about 20 s | A cheating member among seven honest ones is reported and loses its bond; no bucket is lost; afterwards it wins no seats |

The worker, stake and slash tests also check that the app holds nothing beyond box deposits, bonds, pending withdrawals and slashed funds.
