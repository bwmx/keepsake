# Keepsake

**Can a public blockchain keep a secret?** Keepsake is a proof of concept on Algorand of the scheme from Benhamouda et al., "Can a Public Blockchain Keep a Secret?" ([eprint 2020/464](https://eprint.iacr.org/2020/464)).

You lock a message for one recipient and a window of rounds. During the window the recipient can ask for it and decrypt it, and nobody else can. Soon after the window closes, the key that could open it no longer exists anywhere.

For the story and the results, read the **[write-up](docs/writeup.md)**.

> **Status: unreviewed research code.** It runs on LocalNet and has run on TestNet at production size (216-seat committees), with every member on one machine. No cryptographer has reviewed it. Use synthetic secrets only. See [docs/security.md](docs/security.md).

## How it works

No single party ever holds the key. An anonymous **committee** of bonded members holds it in shares, and any t shares are needed to use it. The committee changes every epoch:

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

1. **Committees are drawn in secret.** Each epoch, members win seats in the next committee by stake-weighted VRF sortition on Algorand's block seed. Each seat is handed to a random member through a sealed one-time key, so nobody knows who holds a seat until it speaks.
2. **Holders speak once.** At the handover, each holder posts one message that re-shares its key shares to the next committee, then it is done. It erases its secrets *before* posting, so by the time it is known, it holds nothing.
3. **Senders encrypt to a bucket key.** Keys are kept per time bucket. A sender encrypts to the public key of the bucket its capsule's expiry falls in, and registers the capsule on chain. No committee is involved.
4. **Release rides on the handover.** When the recipient requests a capsule, every holder adds a decryption share to its next handover message, sealed to the recipient. The recipient combines t of them locally.
5. **Expiry is forgetting.** When a bucket's time is up, the committee stops passing its key on. After that handover, nobody holds it.

The full walkthrough is in [docs/design.md](docs/design.md).

## What is built

- **`EpochCommittee`, the smart contract.** Written in Algorand TypeScript (Puya TS via AlgoKit). It handles membership and bonds, verifies sortition on chain with `vrf_verify`, and logs the handover messages. It also keeps the capsule registry and access requests, and slashes bonds for provably bad dealings using Algorand's BLS12-381 opcodes. It holds no secrets.
- **The member worker.** It runs one member against its own algod node: nominating, opening seats, verifying and combining handovers on every core, and posting its messages. Its secrets live in short-lived vault processes that exit before anything is posted.
- **The crypto library.** Pairing-based verifiable re-sharing on BLS12-381, committee-generated bucket keys, the capsule encryption, packed handovers, and fraud proofs. It runs in Node and in browsers.
- **Capsule Lab.** A local web demo. You connect a wallet (LocalNet KMD or Lute), then lock, request and decrypt capsules in the page while watching the committees hand over. You can take members offline and try replay and wrong-wallet attacks.

What has been shown:
- **LocalNet tests** (see [chain/README.md](chain/README.md#tests)): every bucket survives many handovers with members going offline, crashing and rejoining, and with a cheater among them. Seats track bonds, capsules open only for the right wallet inside their window, and expired buckets are held by nobody.
- **TestNet at production size.** Committees of 216 seats with t = 80 ran four handovers with every seat posting, and a capsule opened 12 minutes after its request, for about 0.022 Algo of fees per seat per epoch ([docs/results.md](docs/results.md#testnet-trials)).
- **Capsule Lab in headless Chrome** (`npm run browser-check`): the whole flow, with a check that the plaintext never reaches the server.

What has not been shown:
- a large, independent bonded population: every trial ran five members, all on one machine;
- members on their own nodes and hosts;
- penalties that actually deter (a careful cheater evades the fraud proofs);
- a cryptographer's review.

## Quick start

Needs Node.js 24+, Docker, AlgoKit CLI 2.10+ and Git.

```sh
(cd crypto && npm ci --ignore-scripts && npm test)   # crypto library, about 30 seconds

algokit localnet start
cd chain
npm exec --yes --package=pnpm@12.6.0 -- npm ci       # pnpm is only for the VRF library's install step
npm test                                             # LocalNet tests, about 9 minutes
npm run demo                                         # Capsule Lab at http://127.0.0.1:8787
```

Tests and the demo create throwaway LocalNet accounts, so you need no wallet or funds. Only the TestNet trial needs a funded account (see [chain/README.md](chain/README.md#testnet-trial)).

## Repository

| Path | Contents |
| --- | --- |
| [`chain/`](chain/README.md) | The `EpochCommittee` contract, member worker, capsule client, LocalNet tests, Capsule Lab and the TestNet trial |
| [`crypto/`](crypto/README.md) | Off-chain cryptography: re-sharing, bucket keys, the capsule encryption, fraud proofs, the verification thread pool and vault processes |
| [`docs/writeup.md`](docs/writeup.md) | The write-up: what was built, what was learned, results and limits |
| [`docs/design.md`](docs/design.md) | How it works, step by step, and how it maps to the paper |
| [`docs/security.md`](docs/security.md) | What is and is not protected, and open questions for review |
| [`docs/results.md`](docs/results.md) | Committee sizes, costs, benchmarks and TestNet trials |
| [`docs/history.md`](docs/history.md) | How the design got here: decisions, lessons, and the earlier design that was removed |

## Conventions

- **Contracts** are Algorand TypeScript compiled with Puya TS through AlgoKit, not Algorand Python, PyTeal or TEALScript. Everything off chain is ordinary TypeScript.
- **Cryptography** lives in `crypto/`, which `chain/` imports. The shared modules must keep running in browsers, since Capsule Lab bundles them.
- **Nothing here goes near MainNet,** and real secrets never go near any of it.
