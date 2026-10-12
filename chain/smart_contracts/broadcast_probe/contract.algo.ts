import { Account, BoxMap, Bytes, Contract, Txn, op, readonly, type bytes, type uint64 } from '@algorandfoundation/algorand-typescript'

/**
 * FEASIBILITY PROBE, LocalNet only (docs/results.md). Handover data travels in app-call arguments and the note
 * (the paper's broadcast channel) and is folded into an on-chain running digest per seat, so readers can rebuild a
 * message from blocks and check it. Each part is hashed first because an AVM byte value holds at most 4096 bytes.
 */
export class BroadcastProbe extends Contract {
  digests = BoxMap<uint64, bytes<32>>({ keyPrefix: 'd' })

  post(seat: uint64, a: bytes, b: bytes, c: bytes, d: bytes): void {
    const box = this.digests(seat)
    const prev = box.exists ? box.value : Bytes<32>({ length: 32 })
    box.value = op.sha256(prev.concat(op.sha256(a)).concat(op.sha256(b)).concat(op.sha256(c)).concat(op.sha256(d))
      .concat(op.sha256(Txn.note)))
  }

  // The sortition seed candidate (docs/history.md, D5).
  @readonly
  seed(round: uint64): bytes<32> {
    return op.Block.blkSeed(round)
  }

  // Stake weighting inputs (docs/history.md, D6): total online stake, and the account's voting balance and status.
  @readonly
  stake(account: Account): [uint64, uint64, boolean] {
    const [balance, online] = op.VoterParams.voterBalance(account)
    return [op.onlineStake(), balance, online]
  }
}
