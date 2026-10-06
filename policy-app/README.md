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
| `demo/` | **Capsule Lab**: a local web UI that drives all of the above |

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
npm test        # 8 LocalNet tests, about 60 s
npm run demo    # Capsule Lab at http://127.0.0.1:8787
```

LocalNet must be in its default dev mode, where a block is sealed per transaction. All accounts, VRF keys and nomination keys are generated LocalNet throwaways and are never printed.

## Capsule Lab (demo UI)

`npm run demo` serves a single page at `127.0.0.1:8787`. One local server plays every party; in a real deployment each would run its own client and each member its own node. What you can do:

1. **Start an environment.** Choose the number of members, the nomination window and the expected eligible members per slot. This deploys a fresh beacon with its own VRF key and daemon, plus the policy app, then enrolls the members and starts their workers.
2. **Lock a capsule.** Pick the slot count and minimum committee. Then watch each stage:
   - the beacon seed;
   - private sortition: slots fill with VRF ranks and public nominators, and some may stay empty;
   - the committee and threshold;
   - deposits;
   - holders' acknowledgments, which arrive through the relayer.
3. **Operator view.** This toggle reveals who actually holds each slot, taken from the workers' private logs, which are not on-chain. Turn it off to see only what the chain shows.
4. **Play the recipient.** The clock pauses automatically when the access window opens. Request access, then collect releases and decrypt; this works with members offline as long as a threshold remains. You can also try:
   - requesting early;
   - requesting from another wallet;
   - requesting again with a new key;
   - requesting after expiry.
5. **Members.** Click one to take it offline or bring it back. A returning member regains its slots from chain data, which demonstrates the forward-secrecy gap below.
6. **Tamper scenario.** The sender anchors a hash that doesn't match the chain data. Holders refuse custody and the capsule never activates.
7. **Collusion risk.** For the committee shown, compare the probability that colluders control a threshold of slots under hidden selection versus the earlier public draw.

The server binds to 127.0.0.1 only. The recipient's decryption happens inside the server process, standing in for the recipient's own client, and there is no wallet integration.

## Protocol

| Stage | Step | Who | Authenticated by |
| --- | --- | --- | --- |
| — | `admitCustodian(account)`; `enroll(vrfKey, nominationKey)` once | Admin; member | `Txn.sender` |
| `AWAITING_SEED` | `register(recipient, openRound, expiresRound, slotCount ≤ 64, minHolders ≥ 3, pay)`. Commits the terms and the registry snapshot and requests the beacon seed for `now + 8`. Returns the capsule ID, which is the beacon request ID | Sender | `Txn.sender`; exact payment |
| `NOMINATING` | Beacon `fulfillRandomness`; then `nominate(capsule, slot, index, proof, holderEncKey, holderSigKey, sealedSeed)` until `seedRound + nominationRounds`. The lowest VRF rank per slot wins | Beacon; eligible member | Caller app is the pinned beacon; `vrf_verify` with the enrolled key; rank below `nominatorThreshold`; `Txn.sender` is the member |
| `SELECTED` | `closeNominations`. The committee is the filled slots, n ≥ `minHolders`; threshold `⌊n/2⌋ + 1`; empty slots get no fallback | Anyone | — |
| `DEPOSITING` → `ANCHORED` | `anchorManifest(hash, payloadHash)`, then `postDeposits(slots[], commitments[], deposits[])` in batches of up to 7 until every filled slot has one | Sender | `Txn.sender` |
| `ACTIVE` | `acknowledgeCustody(capsule, slot, sig)`. Active once acknowledgments reach the threshold; later ones still count | Relayer | `ed25519verify_bare` with the slot's one-time key |
| | `requestAccess(capsule, hash, requestId, recipientKey)` once, in `[openRound, expiresRound)` | Recipient | `Txn.sender` |
| | `postRelease(capsule, slot, enc, ct, sig, chainSig)`, once per acknowledged slot, before `expiresRound` | Relayer | One-time key over request ID, recipient key and the release |
| deleted | After expiry: `deleteSlots(slots[])` in batches of up to 7, then `cleanup`, which refunds the sender. Or `cancelUnseeded` after the beacon's timeout, which refunds everything | Anyone | — |

Holders find their slots by trying to decrypt each nomination. They rebuild the manifest from chain data alone and accept their deposit only if it hashes to the anchored value. The recipient does the same and decrypts once a threshold of releases is on-chain. Only the payload ciphertext travels off-chain, and its hash is anchored. The application has no update, delete or opt-in path.

Batching keeps every call within Algorand's limit of 8 resource references per transaction. Each slot is its own box, and counters in the capsule record replace loops over slots.

**Costs on LocalNet (1,000 µAlgo minimum fee):**

- **Registration:** a payment of `134,500 + 176,900 × slots` µAlgo of box deposit, plus 98,200 for the beacon (14,000 fees and 84,200 deposit). For example, 2,355,500 for 12 slots. Cleanup refunds everything except the 14,000 beacon fees.
- **Each nomination:** 10,000, paid by the nominator (nine budget top-ups for `vrf_verify`).
- **Each acknowledgment or release:** 4,000, paid by the relayer.
- **Each deposit batch:** about 3,000.
- **Leftover:** the beacon's unspent proof-fee share stays in the app.

## Chain behaviour vs the mock ledger

The spike's `MockConfirmedLedger` is still its own test double. Here, every authorization decision comes from chain state:

- **`ChainReader`** pins the genesis hash and app ID. It fails closed on a wrong network, a node that is catching up, a node idle longer than `MAX_ROUND_AGE_MS`, or a missing capsule.
- **`chainAuthorization`** re-reads the capsule before and after HPKE encryption for each release.
- **Workers refuse to start** if the app's beacon or their enrolled keys differ from their configuration.

Worker config is read from the environment:
- `ALGOD_SERVER`, `ALGOD_PORT`, `ALGOD_TOKEN`
- `GENESIS_HASH`, `APP_ID`, `BEACON_APP_ID`
- `MEMBER_MNEMONIC`, `VRF_SECRET_KEY`, `NOMINATION_SEED`, `RELAYER_MNEMONIC`
- `MAX_ROUND_AGE_MS`, `POLL_MS`

Each worker writes JSON event lines to stdout: `ready`, `nominated`, `custody`, `released`, `disposed`. These name the member's own slots and stay private to its operator.

## Tests

`test/contract.test.ts` (5 tests):
- **Enrollment and registration:** enrollment rules, committee-size bounds, registry size, payment, and the callback check.
- **Sortition:** a copied proof, another member's proof and another slot's proof are rejected. The on-chain rank equals the off-chain rank. Lower rank replaces higher without growing the committee. The snapshot, eligibility threshold and deadline are enforced, and too few holders means no fallback.
- **Variable committee:** 6 of 8 slots give threshold 4. Deposits go in batches, with unfilled, duplicate and oversized batches rejected. Activation happens at the threshold, and late acknowledgments still count. One-time-key signatures are enforced, releases require an acknowledgment, the window and replay rules hold, and batched cleanup refunds exactly.
- A withheld beacon proof leads to stale cancellation and a full refund.
- Update, delete and opt-in are rejected.

`test/workers.test.ts` (3 tests):
- **Step 5 end to end:** 24 members, 16 slots, and an eligibility rate that can leave slots empty. Every slot goes to its lowest-ranked eligible member, and a slot is empty exactly when nobody was eligible. Activation works. Holders are taken offline down to the threshold and recovery still works from chain releases. The indexer shows members sent only `enroll` and `nominate`, and every custody call came from the relayer. A restarted member regains its slots from chain data. Workers dispose at expiry.
- **Tampered anchor:** holders refuse custody and the capsule never activates.
- **Fail-closed reader and CLI:** the chain reader fails closed, and the worker CLI starts only with matching enrolled keys.

## What is and isn't protected

**Hidden:** which member holds which slot. Holder accounts never sign or pay for anything on-chain.

**Not hidden or not guaranteed:**

- **No forward secrecy for nominations.** Deposits and sealed holder seeds stay on-chain forever. A member's long-term nomination key can decrypt every seed ever nominated to it, so compromising that key later exposes those shares even after expiry. Compromise a threshold of such keys and the secret is exposed, long after workers "disposed" their copies. The fix is rotating nomination keys with erasure, for example per epoch, with each capsule bound to the keys current at nomination. It is not implemented. Until then, the "ephemeral" guarantee is weaker than the earlier off-chain HTTP design.
- **Restart regains custody.** For the same reason, a member that restarts regains its slots from chain data. That's better for availability; it's the same forward-secrecy gap from the other side.
- **Nominators are public, and a corrupt nominator owns its slot.** It knows the one-time keys until it erases them. A slot is corrupt with probability about `1 − (1 − f)²` ≈ 2f.
- **Larger committees are what make hidden selection pay off.** Holders are drawn with replacement, so one member can hold several slots. With n slots and a majority threshold, the chance that colluders control a threshold falls rapidly as n grows, provided 2f stays well below ½ (see Collusion risk in Capsule Lab). Small committees remain weak.
- **The encryption's anonymity is unreviewed.** HPKE base mode over X25519 is used for nominations without a review of key privacy or selective-opening security against the paper's requirements.
- **Network-level traffic can still identify holders.** The relayer hides who pays, not which IP queried algod or contacted the relayer.
- **The beacon seed is public once proven.** Its single operator (us) can learn it early or withhold it.
- **The admin is the Sybil gate.** Stake weighting (`voter_params_get`) and multi-epoch re-sharing (step 6) are not implemented.
- **Expiry does not revoke delivered responses,** and memory erasure is best effort.
- **Status: LocalNet only and unaudited.** Use synthetic secrets only.
