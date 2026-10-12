# Keepsake

**Can a public blockchain keep a secret?** Keepsake is a proof of concept of [Benhamouda et al., eprint 2020/464](https://eprint.iacr.org/2020/464) on Algorand. A secret is held by an anonymous committee that changes every epoch, and is released to one recipient within a time window. It expires for good after that window.

How it works:
- **Committees.** Each epoch, members win anonymous seats by stake-weighted VRF sortition. Seats are nominated through sealed one-time keys, so nobody knows who holds a seat until it speaks.
- **Handover.** Each holder speaks once: it re-shares its share of every live key to the next committee, then erases its secrets. Handovers alternate between packing every key into one dealing per holder and unpacking them again, so an epoch costs about one dealing per holder, not one per key. Secrets live in short-lived vault processes that exit before anything is posted.
- **Capsules.** A secret is sealed to the key of the time bucket its expiry falls in. When the recipient asks, holders release partial decryptions sealed to the recipient's key, and the recipient decrypts. After the bucket's last handover nobody holds its key.
- **Accountability.** Holders answer with an escrowed bond. A provably bad dealing, checked on chain with Algorand's BLS12-381 opcodes, costs the holder its bond. A careful cheater can avoid being provable, though, so this does not deter yet (see the [plan](PAPER_ALIGNMENT_PLAN.md)).

**Status: unreviewed research code.** It runs on LocalNet and has run small TestNet trials, with committees of up to 60 seats. No cryptographer has reviewed it. Use synthetic secrets only.

| Folder | Contents |
| --- | --- |
| [`crypto/`](crypto/README.md) | Off-chain cryptography (TypeScript, Node and browsers): pairing-based re-sharing on BLS12-381, the capsule KEM, fraud proofs, the verification thread pool, vault processes |
| [`chain/`](chain/README.md) | The `EpochCommittee` app (Algorand TypeScript, Puya TS via AlgoKit) and its member worker, capsule client, LocalNet tests and TestNet trial. Also **Capsule Lab**, a local web demo where you connect a wallet and seal, request and decrypt capsules in the page |

```sh
(cd crypto && npm ci --ignore-scripts && npm test)
algokit localnet start
cd chain && npm exec --yes --package=pnpm@12.6.0 -- npm ci
npm test         # LocalNet tests
npm run demo     # Capsule Lab at http://127.0.0.1:8787
```

Further reading:
- [PAPER_ALIGNMENT_PLAN.md](PAPER_ALIGNMENT_PLAN.md): the route from the first design to the paper's, with each phase's results and the open questions for review.
- [START_HERE.md](START_HERE.md): status and handoff notes.
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md): the original plan.
