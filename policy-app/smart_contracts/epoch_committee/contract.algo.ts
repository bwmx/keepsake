import {
  Account, BoxMap, Bytes, Contract, Global, GlobalState, OpUpFeeSource, Txn, VrfVerify, abimethod, arc4, assert, clone,
  ensureBudget, gtxn, itxn, op, readonly, type bytes, type uint64,
} from '@algorandfoundation/algorand-typescript'

const VRF_BUDGET: uint64 = 6_300 // vrf_verify costs 5,700.
const SIG_BUDGET: uint64 = 2_500 // ed25519verify_bare costs 1,900.
// `block` reads only rounds in (LastValid − 1002, FirstValid), so the seed is copied early (PAPER_ALIGNMENT_PLAN.md
// Phase 0). Nominations, which copy it if nobody has, must therefore end within this many rounds of the seed round.
const SEED_LOOKBACK: uint64 = 990
const BATCH: uint64 = 7

// Admitted by the admin (Sybil gate; stake weighting is Phase 5) and enrolled by the member itself.
export type Member = { account: Account; vrfKey: bytes<32>; enrolledRound: uint64 }
// The paper's per-epoch "long-term" key (§2.1): receives the seeds of seats nominated to this member in that epoch.
export type EpochKey = { epoch: uint64; key: bytes<32> }
// Committee c is nominated in epoch c − 1 from the block seed of that epoch's first round, and hands over in epoch c.
export type Committee = { seed: bytes<32>; seats: uint64; finalized: uint64 }
// One seat, created by its nominator. The holder is unknown until it claims the seat to post its single message.
export type Seat = {
  epk: bytes<96> // One-time BLS12-381 G2 key that receives encrypted subshares.
  sigKey: bytes<32> // One-time Ed25519 key; seats are ordered by it off-chain (§3.1.2 step 5).
  sealedSeed: bytes<80> // HPKE(enc 32 || ct 48) of the seed behind both keys, to the nominee's epoch key.
  holder: Account // Zero until claimed: the account that posts this seat's handover message.
  digest: bytes<32> // Running SHA-256 over the message chunks, rebuilt by readers from block data.
  stateDigest: bytes<32> // Signed at the claim: the committee's public state as this holder received it.
  chunks: uint64
  finalized: boolean
}

// A capsule under bucket expiresRound / bucketRounds (Phase 4). Its key is the bucket key, used through a KEM: the
// committee in office releases decryption partials, sealed to the recipient's request key, in its handover messages.
export type CapsuleRecord = {
  sender: Account
  recipient: Account
  openRound: uint64
  expiresRound: uint64
  bucket: uint64
  u: bytes<48> // The KEM's r·g1.
  proof: bytes<64> // Proof of r bound to the capsule's label; holders refuse a u copied under another policy.
  payloadHash: bytes<32> // The payload ciphertext stays off-chain.
  requested: boolean
  requestId: bytes<16>
  recipientKey: bytes<32> // The recipient's fresh X25519 request key.
}

/**
 * Epoch committees for evolving-committee proactive secret sharing (eprint 2020/464 §3; PAPER_ALIGNMENT_PLAN.md
 * Phase 1). In each epoch, VRF-eligible members nominate the next committee's anonymous seats, then the current
 * committee's holders each claim their seat and post one handover message as app-call arguments. The contract orders
 * nothing and checks no cryptography beyond sortition and seat ownership; members verify messages off-chain.
 * No update/delete/opt-in handlers exist, so the AVM rejects those calls.
 */
export class EpochCommittee extends Contract {
  admin = GlobalState<Account>({ key: 'admin' })
  epochRounds = GlobalState<uint64>({ key: 'epochRounds' })
  nominationRounds = GlobalState<uint64>({ key: 'nominationRounds' }) // Rounds 1..this of each epoch.
  handoverRounds = GlobalState<uint64>({ key: 'handoverRounds' }) // The rounds right after nominations.
  nominatorThreshold = GlobalState<uint64>({ key: 'nominatorThreshold' }) // Eligible iff VRF rank < this.
  // Agreed by every member, used off-chain: the sharing threshold t, the bucket schedule (bucket b covers rounds
  // [b·bucketRounds, (b+1)·bucketRounds) and is created bucketLead rounds early), and the first committee, which holds
  // nothing and creates the first buckets.
  shareThreshold = GlobalState<uint64>({ key: 'shareThreshold' })
  bucketRounds = GlobalState<uint64>({ key: 'bucketRounds' })
  bucketLead = GlobalState<uint64>({ key: 'bucketLead' })
  genesisCommittee = GlobalState<uint64>({ key: 'genesisCommittee' })
  registrySize = GlobalState<uint64>({ key: 'registrySize', initialValue: 0 })
  registry = BoxMap<uint64, Member>({ keyPrefix: 'm' })
  admitted = BoxMap<Account, uint64>({ keyPrefix: 'a' }) // 0 = admitted, n = enrolled at index n − 1.
  nominationKeys = BoxMap<bytes, EpochKey>({ keyPrefix: 'k' }) // Key: itob(index) || itob(epoch % 3).
  committees = BoxMap<uint64, Committee>({ keyPrefix: 'c' })
  seats = BoxMap<bytes, Seat>({ keyPrefix: 'n' }) // Key: itob(committee) || itob(nominator index).
  capsuleCount = GlobalState<uint64>({ key: 'capsuleCount', initialValue: 0 })
  capsules = BoxMap<uint64, CapsuleRecord>({ keyPrefix: 'x' })

  @abimethod({ onCreate: 'require' })
  createApplication(
    epochRounds: uint64, nominationRounds: uint64, handoverRounds: uint64, nominatorThreshold: uint64, shareThreshold: uint64,
    bucketRounds: uint64, bucketLead: uint64, genesisCommittee: uint64,
  ): void {
    assert(nominationRounds > 0 && handoverRounds > 0 && nominatorThreshold > 0 && shareThreshold > 0, 'Invalid parameters')
    assert(bucketRounds >= epochRounds && genesisCommittee > Global.round / epochRounds + 1, 'Invalid schedule')
    assert(nominationRounds <= SEED_LOOKBACK, 'Nomination window too long')
    // Both windows fit in one epoch, so a ring entry is overwritten only after its epoch's nominations end.
    assert(nominationRounds + handoverRounds < epochRounds, 'Epoch too short')
    this.admin.value = Txn.sender
    this.epochRounds.value = epochRounds
    this.nominationRounds.value = nominationRounds
    this.handoverRounds.value = handoverRounds
    this.nominatorThreshold.value = nominatorThreshold
    this.shareThreshold.value = shareThreshold
    this.bucketRounds.value = bucketRounds
    this.bucketLead.value = bucketLead
    this.genesisCommittee.value = genesisCommittee
  }

  // The admin funds registry, key, committee and seat boxes by pre-funding the app account.
  admitMember(account: Account): void {
    assert(Txn.sender === this.admin.value, 'Not admin')
    assert(!this.admitted(account).exists, 'Already admitted')
    this.admitted(account).value = 0
  }

  enroll(vrfKey: bytes<32>): void {
    const entry = this.admitted(Txn.sender)
    assert(entry.exists, 'Not admitted')
    assert(entry.value === 0, 'Already enrolled')
    const index = this.registrySize.value
    this.registry(index).value = { account: Txn.sender, vrfKey, enrolledRound: Global.round }
    entry.value = index + 1
    this.registrySize.value = index + 1
  }

  /** A fresh nomination key for the current or next epoch, once, never replaced (ring of 3 per member). */
  postNominationKey(epoch: uint64, key: bytes<32>): void {
    const entry = this.admitted(Txn.sender)
    assert(entry.exists && entry.value > 0, 'Not enrolled')
    const current: uint64 = Global.round / this.epochRounds.value
    assert(epoch === current || epoch === current + 1, 'Wrong epoch')
    const box = this.nominationKeys(op.itob(entry.value - 1).concat(op.itob(epoch % 3)))
    assert(!box.exists || box.value.epoch !== epoch, 'Already posted')
    box.value = { epoch, key }
  }

  /** Copies committee c's seed (the block seed of epoch c − 1's first round) into state. Anyone; needs a short validity window. */
  captureSeed(committee: uint64): void {
    this.seedOf(committee)
  }

  /**
   * One nomination per member per epoch, in the epoch's nomination window, for the next committee (§3.1.2). The member
   * proves VRF(sha256("ecpss/nominate/v1" || appId || committee || seed)) with its enrolled key, ranks below the
   * threshold, and posts one seat: one-time keys plus their seed sealed to a uniformly chosen member's epoch key.
   */
  nominate(nominator: uint64, proof: bytes<80>, epk: bytes<96>, sigKey: bytes<32>, sealedSeed: bytes<80>): void {
    const start: uint64 = (Global.round / this.epochRounds.value) * this.epochRounds.value
    assert(Global.round > start && Global.round <= start + this.nominationRounds.value, 'Not nominating')
    const committee: uint64 = Global.round / this.epochRounds.value + 1
    assert(nominator < this.registrySize.value, 'Unknown member')
    const member = clone(this.registry(nominator).value)
    assert(Txn.sender === member.account, 'Not the nominator') // A copied proof is useless to anyone else.
    assert(member.enrolledRound < start, 'Enrolled after the seed round')
    const seat = this.seats(op.itob(committee).concat(op.itob(nominator)))
    assert(!seat.exists, 'Already nominated')
    const seed = this.seedOf(committee)
    ensureBudget(VRF_BUDGET, OpUpFeeSource.GroupCredit)
    const alpha = op.sha256(Bytes('ecpss/nominate/v1').concat(op.itob(Global.currentApplicationId.id))
      .concat(op.itob(committee)).concat(seed))
    const [output, verified] = op.vrfVerify(VrfVerify.VrfAlgorand, alpha, proof, member.vrfKey)
    assert(verified, 'Invalid VRF proof')
    assert(op.btoi(op.extract(output, 0, 8)) < this.nominatorThreshold.value, 'Not eligible')
    seat.value = {
      epk, sigKey, sealedSeed, holder: Global.zeroAddress, digest: Bytes<32>({ length: 32 }),
      stateDigest: Bytes<32>({ length: 32 }), chunks: 0, finalized: false,
    }
    const record = this.committees(committee)
    record.value.seats += 1
  }

  /**
   * A holder takes its seat for the handover window of epoch `committee`: the seat's one-time key signs
   * "ecpss/claim/v1" || appId || committee || nominator || holder || stateDigest. Only that account may then post the
   * message. Readers trust a public state that t seats attest: fewer than t are corrupt.
   */
  claim(committee: uint64, nominator: uint64, holder: Account, stateDigest: bytes<32>, signature: bytes<64>): void {
    const seat = this.openSeat(committee, nominator)
    assert(seat.value.holder === Global.zeroAddress, 'Already claimed')
    ensureBudget(SIG_BUDGET, OpUpFeeSource.GroupCredit)
    const message = Bytes('ecpss/claim/v1').concat(op.itob(Global.currentApplicationId.id)).concat(op.itob(committee))
      .concat(op.itob(nominator)).concat(holder.bytes).concat(stateDigest)
    assert(op.ed25519verifyBare(message, signature, seat.value.sigKey), 'Invalid seat signature')
    seat.value.holder = holder
    seat.value.stateDigest = stateDigest
  }

  /** Appends one chunk (four argument parts plus the note) to the seat's running digest. */
  postChunk(committee: uint64, nominator: uint64, a: bytes, b: bytes, c: bytes, d: bytes): void {
    const seat = this.openSeat(committee, nominator)
    assert(Txn.sender === seat.value.holder, 'Not the holder')
    assert(!seat.value.finalized, 'Finalized')
    // Parts are hashed first: an AVM byte value holds at most 4,096 bytes.
    seat.value.digest = op.sha256(seat.value.digest.concat(op.sha256(a)).concat(op.sha256(b)).concat(op.sha256(c))
      .concat(op.sha256(d)).concat(op.sha256(Txn.note)))
    seat.value.chunks += 1
  }

  finalize(committee: uint64, nominator: uint64): void {
    const seat = this.openSeat(committee, nominator)
    assert(Txn.sender === seat.value.holder, 'Not the holder')
    assert(!seat.value.finalized, 'Finalized')
    seat.value.finalized = true
    this.committees(committee).value.finalized += 1
  }

  /** Anyone, once committee c's epoch is over: up to 7 seats per call, then `deleteCommittee`. */
  deleteSeats(committee: uint64, nominators: uint64[]): void {
    assert(Global.round >= (committee + 1) * this.epochRounds.value, 'Committee still active')
    assert(nominators.length <= BATCH, 'Invalid batch')
    const record = this.committees(committee)
    for (const n of nominators) {
      if (this.seats(op.itob(committee).concat(op.itob(n))).delete()) record.value.seats -= 1
    }
  }

  deleteCommittee(committee: uint64): void {
    assert(Global.round >= (committee + 1) * this.epochRounds.value, 'Committee still active')
    assert(this.committees(committee).value.seats === 0, 'Seats remain')
    this.committees(committee).delete()
  }

  /**
   * Registers a capsule under bucket expiresRound / bucketRounds, which must exist by schedule. The window spans at
   * least two epochs, so a handover falls inside it after any request. The sender pays the box deposit exactly.
   */
  registerCapsule(recipient: Account, openRound: uint64, expiresRound: uint64, u: bytes<48>, proof: bytes<64>,
    payloadHash: bytes<32>, payment: gtxn.PaymentTxn): uint64 {
    const E = this.epochRounds.value
    const epoch: uint64 = Global.round / E
    assert(epoch > this.genesisCommittee.value, 'No buckets yet')
    assert(Global.round <= openRound && openRound < expiresRound && expiresRound - openRound >= 2 * E, 'Invalid window')
    const bucket: uint64 = expiresRound / this.bucketRounds.value
    assert(bucket * this.bucketRounds.value < (epoch + 1) * E + this.bucketLead.value, 'Bucket not created yet')
    assert(payment.receiver === Global.currentApplicationAddress && payment.amount === this.capsuleMbr(), 'Exact payment required')
    const id = this.capsuleCount.value
    this.capsules(id).value = {
      sender: Txn.sender, recipient, openRound, expiresRound, bucket, u, proof, payloadHash, requested: false,
      requestId: Bytes<16>({ length: 16 }), recipientKey: Bytes<32>({ length: 32 }),
    }
    this.capsuleCount.value = id + 1
    return id
  }

  /** The recipient binds one fresh request key inside [openRound, expiresRound). */
  requestAccess(capsuleId: uint64, requestId: bytes<16>, recipientKey: bytes<32>): void {
    const capsule = this.capsules(capsuleId)
    assert(Txn.sender === capsule.value.recipient, 'Not recipient')
    assert(Global.round >= capsule.value.openRound, 'Not open')
    assert(Global.round < capsule.value.expiresRound, 'Expired')
    assert(!capsule.value.requested, 'Already requested')
    capsule.value.requested = true
    capsule.value.requestId = requestId
    capsule.value.recipientKey = recipientKey
  }

  /** Anyone, after expiry: deletes the record and refunds the sender's deposit. */
  deleteCapsule(capsuleId: uint64): void {
    const record = clone(this.capsules(capsuleId).value)
    assert(Global.round >= record.expiresRound, 'Not expired')
    this.capsules(capsuleId).delete()
    itxn.payment({ receiver: record.sender, amount: this.capsuleMbr(), fee: 0 }).submit()
  }

  private capsuleMbr(): uint64 {
    return 2_500 + 400 * (this.capsules.keyPrefix.length + 8 + arc4.sizeOf<CapsuleRecord>())
  }

  private seedOf(committee: uint64): bytes<32> {
    assert(committee > 0, 'No committee 0')
    const record = this.committees(committee)
    if (!record.exists) record.value = { seed: op.Block.blkSeed((committee - 1) * this.epochRounds.value), seats: 0, finalized: 0 }
    return record.value.seed
  }

  // The seat of committee c during the handover window of epoch c.
  private openSeat(committee: uint64, nominator: uint64) {
    const start: uint64 = committee * this.epochRounds.value + this.nominationRounds.value
    assert(Global.round > start && Global.round <= start + this.handoverRounds.value, 'Not handing over')
    const seat = this.seats(op.itob(committee).concat(op.itob(nominator)))
    assert(seat.exists, 'No such seat')
    return seat
  }

  @readonly
  getMember(index: uint64): Member {
    return this.registry(index).value
  }

  @readonly
  getCommittee(committee: uint64): Committee {
    return this.committees(committee).value
  }

  @readonly
  getCapsule(capsuleId: uint64): CapsuleRecord {
    return this.capsules(capsuleId).value
  }

  @readonly
  getSeat(committee: uint64, nominator: uint64): Seat {
    return this.seats(op.itob(committee).concat(op.itob(nominator))).value
  }
}
