# How Keepsake works

This is the design as built. It follows the evolving-committee scheme of Benhamouda et al., "Can a Public Blockchain Keep a Secret?" ([eprint 2020/464](https://eprint.iacr.org/2020/464)). Section numbers (§) refer to that paper. Measurements are in [results.md](results.md), and the limits of all this are in [security.md](security.md).

## The idea in five steps

1. **A committee holds the keys.** At any moment, an anonymous committee of members holds a set of keys, one per *bucket* (a span of rounds that capsules can expire in). Each holder has one share of each key, and any t of them are needed to use it.
2. **The committee changes every epoch.** Each epoch, a new committee is drawn at random. Every holder of the current committee posts one *handover* message that re-shares its key shares to the new committee, then it is done. Holders are anonymous until they post, and they erase their secrets before posting, so by the time anyone learns who they are, they hold nothing worth stealing.
3. **Senders need no committee.** A sender encrypts a message to the public key of the bucket that its expiry falls in, and registers the resulting *capsule* on chain. The ciphertext stays off chain.
4. **Release rides on the handover.** When the recipient requests a capsule during its window, every holder adds a decryption share for it to its next handover message, sealed to the recipient. The recipient combines t of them and decrypts. Nobody else learns anything.
5. **Expiry is forgetting.** Once a bucket's span has passed, the committee stops re-sharing its key. After that handover nobody holds the key, so its capsules can never be opened again.

```text
            epoch e                     epoch e+1                   epoch e+2
   ┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
   │ committee e holds   │     │ committee e+1 holds │     │ committee e+2 holds │
   │ shares of every     │────▶│ shares of every     │────▶│ shares of every     │──▶ …
   │ live bucket key     │     │ live bucket key     │     │ live bucket key     │
   └─────────────────────┘     └─────────────────────┘     └─────────────────────┘
        handover: each holder posts once ─ re-shares, new bucket keys,
        sealed release shares for requested capsules ─ then it is gone
```

## Who is involved

| Role | What it does |
| --- | --- |
| **Member** | An Algorand account that enrolled in the app with a bond. It runs the member worker ([`chain/src/epoch-worker.ts`](../chain/src/epoch-worker.ts)), which talks only to its own algod node |
| **Nominator** | A member whose sortition ticket won. It creates one seat in the next committee and secretly hands it to another member |
| **Holder** | The member a seat was handed to. Nobody but the holder (and, briefly, the nominator) knows who holds a seat until it posts |
| **Sender** | A wallet that locks a capsule for a recipient and a window of rounds |
| **Recipient** | The wallet a capsule is for. It requests the capsule during the window and decrypts it locally |
| **`EpochCommittee` app** | The smart contract. It is a bulletin board that checks rules: who may join, who won sortition, who may post for a seat, and who may request a capsule. It holds bonds and deposits, but never any secret |

## Time: epochs and buckets

An **epoch** is a fixed number of rounds, E. Epoch e spans rounds `[e·E, (e+1)·E)` and has two windows:

```text
round  e·E ─┬─ nominationRounds ──┬─ handoverRounds ──────────┬─ (idle) ─┤ (e+1)·E
            │ nominate seats for  │ committee e hands over to │          │
            │ committee e+1       │ committee e+1             │          │
```

Committee c is nominated in epoch c − 1, receives the keys at that epoch's handover, holds them, and hands over in epoch c.

A **bucket** covers rounds `[b·bucketRounds, (b+1)·bucketRounds)`. The committee creates each bucket's key `bucketLead` rounds before the bucket starts, and stops re-sharing it once the bucket ends. A capsule belongs to bucket `expiresRound / bucketRounds`. Bucketing keeps the cost of a handover proportional to the number of live buckets, not the number of capsules.

## 1. Joining

Anyone can join; there is no admin.
- **Enroll.** A member calls `enroll` once, with its VRF public key and a payment. The payment covers the member's own storage deposits, and the rest becomes its **bond**.
- **Weight.** A member's sortition weight is its bond, capped by its online consensus stake. The contract reads online stake with `voter_params_get`, which looks 320 rounds back. A bond change counts from the next epoch's nominations, after a seed nobody knew when making it.
- **Exit.** A withdrawal stops counting at the next epoch and is paid out four epochs later (`claimWithdrawal`), so it stays slashable for longer than any seat its member holds.
- **Nomination keys.** Each epoch, a member posts a fresh X25519 *nomination key* for the next epoch (§2.1, §3.1.3). Seats are handed to members through these keys, and each is erased after use.

The bond, not online stake alone, is the weight, because online stake can be moved between accounts during a nomination window and counted once per account.

## 2. Drawing the next committee (§3.1.2)

**Seed.** Sortition for committee c uses Algorand's block seed from the first round of epoch c − 1. The first nomination copies it into app state with `block BlkSeed`.

**Tickets.** The total bond is cut into `totalTickets` tickets. A member holds ⌈w · totalTickets / total⌉ of them, the last one partial. Ticket j wins when the rank of

```text
VRF_member( sha256("ecpss/nominate/v2" ‖ appId ‖ committee ‖ j ‖ seed) )
```

is below `ticketThreshold`, scaled down for a partial ticket. This is Algorand's own binomial sortition with tickets as sub-users. Expected seats are proportional to bond, and splitting stake across accounts does not change them.

**Nomination.** For each winning ticket, the member calls `nominate` with its VRF proof, which the contract checks with `vrf_verify`. The nomination creates one **seat**:
1. The nominator makes a fresh 32-byte seed. The seat's one-time keys derive from it: a BLS12-381 ElGamal key (epk in G2) and an Ed25519 signing key.
2. It picks a nominee among the members, at random and weighted by bond.
3. It posts both public keys and the seed, HPKE-sealed to the nominee's nomination key for that epoch. Then it erases the seed and its choice.

**Opening seats.** When nominations close, every member tries to decrypt every seat's sealed seed with its nomination key. The seats it can open are its own. Then it erases that nomination key. Seats are numbered in the order of their one-time signing keys, and any seat whose keys repeat another's is dropped, so a nominator cannot front-run an honest seat by copying its keys.

## 3. Handover: speak once (§3.1.3)

During the handover window, each holder posts one message per seat, and that is the seat's only act.

**What the message carries:**
- **Re-sharing.** For every live bucket, a fresh sharing of the holder's own share, encrypted to the next committee's seat keys, with public commitments anyone can check.
- **New bucket keys.** For each bucket being created, a random contribution with a proof of knowledge. The bucket's key is the sum of the first t valid contributions, so at least one is honest and no dealer is trusted after genesis. This is a distributed key generation (DKG).
- **Releases.** For each requested capsule under a bucket it holds, a decryption share sealed to the recipient (see Capsules below).
- **State.** The holder's view of the committee's public commitments.

**Posting.** The holder's secrets are erased before it posts (see Vaults below). Then it posts from its own account, as one atomic group per seat:
1. `claim`: the seat's one-time key signs the holder's account, the digest of its state view, and a Merkle root over the message's dealings. From now on only that account may post for the seat.
2. `postChunk`, repeated: message data in app-call arguments and the note, about 20 KB per call. The contract folds each chunk into a running digest. Data lives in blocks, not in boxes, which is the paper's broadcast channel (§2.1).
3. `finalize`: closes the seat's message.

One group holds up to 14 chunks, about 280 KB.

**Receiving.** Members read every message back from blocks and check it against the on-chain digest. They verify each dealing with pairing checks, on a thread pool. For each bucket they take the first t valid dealings in seat order and combine their own subshares with Lagrange coefficients. Every member sees the same chain data and checks validity against public data, so all honest members choose the same dealings. A message that fails is treated as silence.

### Packed epochs

With ℓ live buckets, a plain handover costs each holder ℓ dealings. Keepsake instead alternates two kinds of handover, so each holder posts one dealing for all buckets (`handoverPlan` in [`crypto/src/ecpss.ts`](../crypto/src/ecpss.ts)):
- **Pack.** From unpacked shares, each holder deals one polynomial of t + ℓ − 1 values, in evaluation form at the points −1…−m. Its shares of the live buckets come first, then a contribution to each new bucket, then t − 1 random values that mask the rest. The next committee holds one packed share, which contains every bucket at its own point.
- **Unpack.** From a packed share, each holder re-shares it as one ordinary dealing. The next committee interpolates each bucket's own share from the first t + ℓ − 1 valid dealings. New buckets come from separate contributions.

A committee packs only when it carries at least two buckets and the next committee has the t + ℓ − 1 seats its own handover will need.
- **Secrecy is unchanged:** any t − 1 packed shares reveal nothing.
- **Liveness costs a little:** unpacking, and opening a capsule from a packed committee, need t + ℓ − 1 valid dealings or partials instead of t.

The saving is about 70% of message bytes and verification time over two epochs; see [results.md](results.md#packed-epochs).

## 4. Capsules (§3.1.4)

**Locking.** The sender:
1. reads the bucket's public key P from the attested state (section 5);
2. computes the capsule's **label**, sha256("ecpss/capsule/v1" ‖ appId ‖ sender ‖ recipient ‖ openRound ‖ expiresRound);
3. picks a random r, sets u = r·g1 and K = e(P, g2)^r, and derives the payload key as HKDF(K, u, label);
4. encrypts the message with AES-256-GCM under that key, with the label as associated data;
5. calls `registerCapsule` with u, a Schnorr proof of r bound to the label, the payload hash and a refundable deposit.

The ciphertext stays off chain, and only its hash is anchored. The proof stops replay: copying someone's u into a new capsule with your own policy gives a proof that does not match the new label, and every holder refuses it.

**Requesting.** During `[openRound, expiresRound)`, the recipient makes a fresh X25519 key pair and calls `requestAccess` from its wallet with the public half. The contract checks `Txn.sender` and the window, and allows one request per capsule.

**Releasing.** At its next handover, each holder computes the partial D_k = e(u, S_k) from its share S_k. It adds a proof that the same S_k lies behind its public commitment, and seals both to the recipient's key with HPKE.

**Opening.** The recipient reads the partials from the chain and checks each against the attested commitments. It combines the first t valid ones (t + ℓ − 1 from a packed committee) into K, derives the payload key, and decrypts. Release takes up to one epoch, because it waits for the next handover.

**Expiring.** A bucket that has ended is not re-shared. After that handover nobody holds its key, under the assumptions in [security.md](security.md). A sender's deposit is refunded with `deleteCapsule` after expiry. Releases already delivered can still be decrypted.

## 5. Attested public state, and joining late

Senders, recipients and new members all need the committee's public commitments, without replaying history from genesis. When a holder claims its seat, it signs a digest of the public state it received, and its message carries that state. A state attested by at least t seats includes the view of an honest seat, since fewer than t are corrupt.
- **Senders** take bucket public keys from it.
- **Recipients** check partials against it.
- **Late members.** A newly enrolled member, or one restarted with nothing in memory, joins from the latest attested state and follows the handovers from there. Seats nominated to keys from before a restart stay closed to it.

## 6. Short-lived secrets: vaults

Forward secrecy rests on erasure, so each committee's secrets live in their own short-lived child process, a **vault** (`SeatVault`, [`crypto/src/vault.ts`](../crypto/src/vault.ts)).
- **Lifetime.** A member starts a vault when it posts the nomination key for an epoch. The vault holds that key (as wipeable bytes), the seats' one-time keys, and their shares.
- **Work.** It opens the seats, combines shares from the dealings the member chose, and builds the seats' messages, releases and claim signatures.
- **Exit.** It exits before any of its seats claims or posts, so the paper's "erase before you speak" holds at the process level. A vault with no seats exits as soon as seats are opened, and a member has at most three alive at once.
- **What the worker sees.** Only public data, its own seat numbers, and what it posts.
- **Host checks.** Vaults refuse to start with core dumps enabled, or where swap is unencrypted (macOS) or on at all (Linux).

JavaScript cannot wipe bigints or pin memory, so erasure is not provable: the process exit is what ends a secret.

## 7. Liveness

A handover succeeds only if at least t honest seats post (t + ℓ − 1 when unpacking). If one fails, every live bucket is lost. So:
- each worker reports every handover's **margin**: by how many valid dealings the worst bucket exceeded what it needed;
- `assertLive` ([`chain/src/epoch-capsules.ts`](../chain/src/epoch-capsules.ts)) lets a sender refuse to lock a capsule when the margin is thin. It checks the latest handover's attestations, the committee in office and the next committee.

The margin warns new senders. It cannot rescue buckets already at risk.

## 8. Accountability: bonds and fraud proofs

Holders answer with their bond for provably bad dealings, after the route in [eprint 2026/919](https://eprint.iacr.org/2026/919).
- **What a report proves.** The Merkle root in a holder's claim covers one leaf per (dealing, recipient). A leaf holds the recipient seat, its key, the commitment E its subshare should open to, and the subshare itself. Anyone can call `reportBadDealing` with a leaf and its path. The contract checks the path against the signed root, then two pairing equations with Algorand's BLS12-381 opcodes:
  - e(r1, g2) = e(g1, r2)
  - e(g1, b) = e(E, g2) · e(r1, epk)

  A report costs about 0.09 Algo at any t.
- **Penalty.** If the leaf fails, the holder loses its whole bond, including withdrawals still unbonding. Half goes to the reporter.
- **Why honest holders are safe.** An honest holder signs only leaves that pass.

This does not deter a careful cheater yet: it can sign a root that leaves its bad subshare out, and its message is then just dropped like silence. See [security.md](security.md#penalties-do-not-deter-yet).

## The cryptography

Everything is on BLS12-381, with generators g1 ∈ G1 and g2 ∈ G2 and pairing e. This is an **unreviewed** construction ([`crypto/src/pvss.ts`](../crypto/src/pvss.ts), [`crypto/src/ecpss.ts`](../crypto/src/ecpss.ts)).

- **Keys.** A bucket's secret is the group element S = s·g2, and its public key is P = s·g1.
- **Seat k.** It holds the share S_k = σ_k·g2, with public commitment V_k = σ_k·g1. Its one-time ElGamal key is x_k, with epk_k = x_k·g2.
- **Re-share by holder j.**
  - Pick a_1…a_(t−1). The commitments are A_0 = V_j (already public) and A_l = a_l·g1.
  - For seat k, let M = S_j + (Σ_l a_l·k^l)·g2. Send R1 = r·g1, R2 = r·g2 and B = M + r·epk_k.
  - Anyone can check e(R1, g2) = e(g1, R2) and e(g1, B) = e(Σ_l k^l·A_l, g2) · e(R1, epk_k). These checks batch across subshares.
- **Combine.** Seat k of the next committee computes S'_k = Σ_j λ_j·(B_j − x_k·R2_j) over the first t valid dealers j. Its new commitment Σ_j λ_j·Σ_l k^l·A_(j,l) is public.
- **New keys (DKG).** The same dealing, with A_0 = z·g1 for a fresh z and a Schnorr proof of knowledge of z, against rogue-key attacks.
- **Capsule KEM.** u = r·g1 and K = e(P, g2)^r, with a Schnorr proof of r bound to the capsule's label.
- **Partials.** D_k = e(u, S_k), with a sigma-protocol proof that the S_k behind e(g1, S_k) = e(V_k, g2) also produced D_k. The recipient computes K = Π D_k^(λ_k).
- **Packed dealings.** The same, with commitments in evaluation form at fixed points instead of coefficient form.

Precedents: pairing-based PVSS in SCRAPE (Cascudo and David, 2017), and group-element secret keys in aggregatable DKG (Gurkan et al., 2021). The questions this raises for a reviewer are listed in [security.md](security.md#open-questions-for-review).

## How it maps to the paper

| Paper | Keepsake |
| --- | --- |
| Evolving committees, one per epoch (Fig. 1) | One committee per epoch for the whole app |
| PKI with per-epoch keys (§2.1) | Per-epoch nomination keys, posted on chain and erased after use |
| Broadcast channel (§2.1) | App-call arguments and notes in blocks, with an on-chain digest per seat |
| Cryptographic sortition (§2.3) | Stake-weighted VRF tickets on the block seed, verified with `vrf_verify` |
| Nominating committee and anonymous holders (§3.1.2) | Each winning ticket nominates one seat, sealed to a member drawn by bond |
| Seats ordered by ephemeral key (§3.1.2 step 5) | Seats ordered by one-time signing key |
| Speak once, then erase (§3.1.3) | One atomic group per seat, posted from the holder's account after its vault exits |
| Verifiable re-sharing (§2.5, §2.6) | Pairing-checked ElGamal dealings on BLS12-381 (unreviewed; RIND-SO open) |
| Secret held by the committee | Bucket keys, created by the committee with a DKG, so there is no dealer after genesis |
| Threshold decryption (§3.1.4) | Capsule KEM with proven partials, released inside handover messages |
| Committee size from the corruption bound (§3.2) | Exact Poisson tails ([results.md](results.md#committee-size)) |

Where Keepsake departs from the paper:
- **Seats are keyed by (committee, nominator, ticket) on chain,** and ordered off chain.
- **A seat claims once.** Its one-time key signs the holder's account, instead of signing every message.
- **Weight is a bond capped by online stake,** not online stake alone.
- **Nominees are drawn by bond,** not uniformly.
- **Packed epochs and the attested state** are additions.
- **Not attempted:** the paper's Appendix A variant and its MPC and obfuscation applications.
