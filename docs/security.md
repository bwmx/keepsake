# Security: what Keepsake does and does not protect

**Keepsake is unreviewed research code.** No cryptographer has reviewed its construction, and nobody has audited the implementation. It has run on LocalNet and in small TestNet trials. Use synthetic secrets only.

## What it aims to provide

A capsule is released privately to one recipient, during a window of rounds, and never after its bucket expires. That holds under these assumptions:

| Assumption | What breaks without it |
| --- | --- |
| Fewer than t seats of any one committee are corrupt | Secrecy. Any t corrupt seats of one committee expose every live bucket, and so every capsule under them |
| At least t honest seats post at every handover (t + ℓ − 1 when a committee unpacks ℓ packed buckets) | Liveness. One failed handover loses every live bucket for good |
| Holders really erase their secrets before posting | Forward secrecy. Sealed seeds and handover messages stay on chain forever |
| Each member reads the chain through its own trusted node | Anonymity, and the correctness of what the member sees |

**Hidden:** which member holds which seat, until the seat posts. A holder posts from its own account only after its vault has exited.

## What it does not protect

**The sender and recipient know the plaintext.** Expiry ends future releases, but it does not revoke a release already delivered. A recipient can keep what it decrypted.

**Committees in the tests and demo are small.** The sizes that tolerate a 5% corrupt bond share are C ≈ 130–210 seats ([results.md](results.md#committee-size)), and they assume a bonded population in the thousands for anonymity. Test and demo committees of 5–20 seats tolerate little corruption, and the 60-seat TestNet trial had only five members.

**A seat is corrupt if its nominator or its holder is,** so roughly 2f for a corrupt fraction f. Nominators are public once they post, and they know their seat's keys until they erase them. The paper has the same "double dip" (§1.2).

**Weight is bonded stake.** f is the adversary's share of the bonds, not of Algorand's online stake. The online-stake cap is weak: within a window, an adversary can move online coins between its bonded accounts.

**Erasure is not provable.** Each committee's secrets live in a vault process that exits before its seats speak. But JavaScript can neither wipe bigints nor pin memory, the operating system keeps freed pages until it reuses them, and a hibernation image or a compromised host sees everything. Until a vault exits, stealing a member's live state exposes what that vault holds.

### Penalties do not deter yet

Only a subshare that fails its pairing checks, under a root its holder signed, can be proven and slashed.
- **The evasion.** A rational cheater signs a root that leaves its bad subshare out, or names a commitment its bad subshare does match. Its message is then dropped, the same as silence, and nothing is slashed.
- **Not punished at all:** silence, garbled messages, a wrong re-shared value, and a bad contribution proof. Punishing non-delivery needs something like the time-lock puzzles of [eprint 2026/919](https://eprint.iacr.org/2026/919).
- **Self-reporting.** A cheater can report itself from another account and recover half its bond.
- **Small bonds.** A report costs about 0.09 Algo, so it does not pay against bonds under about 0.2 Algo.

**Network traffic can identify holders.** A shared node sees which account reads what. Members should each use their own node. Workers trust that node; this is not a light client.

**Expiry is coarse.** Its granularity is the bucket width plus an epoch. It can lag one more epoch when a bucket expires at an unpacking handover: the packed shares being re-shared still carry it, so it is gone only once the next committee erases.

**Release is slow.** Partials wait for the next handover, up to one epoch.

**Packed partials reach further.** On a packed committee, one capsule's partials also give its recipient e(u, S) for the pack's other buckets. That opens no other capsule, because u is bound to its own capsule's label, and only that capsule's sender could build another capsule with the same u.

**Non-archival nodes forget.** They keep only the last 1,000 or so blocks. A member must read each handover before it ages out, or read from an archival node. Old seat records are also deleted after about two epochs, so a member offline for longer cannot rebuild the handovers it missed. Restarted, it rejoins from the attested state.

## Open questions for review

- **The construction's assumptions.** Does S = s·g2 stay hidden given P = s·g1 and all the commitments? Which assumption does the KEM need? How much bias can selective aborts introduce into the DKG?
- **Selective opening (RIND-SO).** The paper requires encryption that stays secure when some receivers' keys are later opened (§2.6). Plain ElGamal has no such proof. The paper suggests CHK05's DDH-based receiver non-committing encryption instead.
- **Anonymity of HPKE (E1).** Sealing seats to nomination keys with HPKE over X25519 relies on the paper's unproven Conjecture 1.
- **Packed epochs.** Is the alternation sound as a whole? In particular: weighting new-key contributions inside a pack by Lagrange coefficients instead of summing them; publishing evaluation-form commitments at fixed points; and a packed committee's partials giving e(u, S) for the pack's other buckets.
- **Seed redraws.** How many sortition redraws do block proposers really get by withholding blocks? The sizing assumes 2^8. Ferreira et al. ([arXiv:2406.15282](https://arxiv.org/abs/2406.15282)) suggest that is conservative, and dropping the margin entirely only moves C from 210 to 198 at f = 5%.
- **Seats per member.** The sizing models seats as Poisson. Per-member seats are sums of independent ticket trials, which we expect stays conservative; that is not proven.

## Smaller committees: the route not yet taken

[eprint 2026/919](https://eprint.iacr.org/2026/919) ("Towards Practical Committee Sizes in YOSO MPC") reaches committees of about 100 at any constant corruption fraction below 1. It relies on accountability: identifiable aborts through time-lock puzzles, penalties backed by fraud proofs, fixed-size sortition and a tighter analysis. Keepsake has the fraud proofs and bonds. It does not have time-lock puzzles, which are what would make the penalties bite, or fixed-size sortition.
