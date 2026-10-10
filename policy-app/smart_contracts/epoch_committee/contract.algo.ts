import {
  Account, BigUint, BoxMap, Bytes, Contract, Global, GlobalState, OpUpFeeSource, Txn, VrfVerify, abimethod, arc4, assert, clone,
  ensureBudget, gtxn, itxn, op, readonly, type biguint, type bytes, type uint64,
} from '@algorandfoundation/algorand-typescript'

const VRF_BUDGET: uint64 = 6_300 // vrf_verify costs 5,700.
const SIG_BUDGET: uint64 = 2_500 // ed25519verify_bare costs 1,900.
// `voter_params_get` reads stake as of 320 rounds back (measured on LocalNet). Nominations end within that many rounds
// of the seed round, so the online stake they see was fixed before the seed was known. `block` reaches about 990
// rounds back, so the seed is still readable then (PAPER_ALIGNMENT_PLAN.md Phase 0).
const BALANCE_LOOKBACK: uint64 = 320
const BATCH: uint64 = 7

// Anyone may enroll (PAPER_ALIGNMENT_PLAN.md Phase 5). A member's sortition weight is its bond, capped by its online
// stake. Bond changes count from the next epoch's nominations, after a seed nobody knew when making them.
export type Member = {
  account: Account
  vrfKey: bytes<32>
  enrolledRound: uint64
  bond: uint64 // Counted in nominations up to epoch bondEpoch.
  nextBond: uint64 // Counted from epoch bondEpoch + 1.
  bondEpoch: uint64
}
// The paper's per-epoch "long-term" key (§2.1): receives the seeds of seats nominated to this member in that epoch.
export type EpochKey = { epoch: uint64; key: bytes<32> }
// One seat per winning ticket, created and paid for by its nominator. The holder is unknown until it claims the seat
// to post its single message.
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
 * Phases 1 and 5). In each epoch, members win seats of the next committee by stake-weighted VRF sortition and nominate
 * them anonymously, then the current committee's holders each claim their seat and post one handover message as
 * app-call arguments. The contract orders nothing and checks no cryptography beyond sortition and seat ownership;
 * members verify messages off-chain. Every box is paid for by whoever needs it. No update/delete/opt-in handlers
 * exist, so the AVM rejects those calls.
 */
export class EpochCommittee extends Contract {
  epochRounds = GlobalState<uint64>({ key: 'epochRounds' })
  nominationRounds = GlobalState<uint64>({ key: 'nominationRounds' }) // Rounds 1..this of each epoch.
  handoverRounds = GlobalState<uint64>({ key: 'handoverRounds' }) // The rounds right after nominations.
  // Sortition: the bonded stake is cut into totalTickets tickets, each winning when its VRF rank is below
  // ticketThreshold, so a committee has about totalTickets · ticketThreshold / 2^64 seats.
  totalTickets = GlobalState<uint64>({ key: 'totalTickets' })
  ticketThreshold = GlobalState<uint64>({ key: 'ticketThreshold' })
  // Agreed by every member, used off-chain: the sharing threshold t, the bucket schedule (bucket b covers rounds
  // [b·bucketRounds, (b+1)·bucketRounds) and is created bucketLead rounds early), and the first committee, which holds
  // nothing and creates the first buckets.
  shareThreshold = GlobalState<uint64>({ key: 'shareThreshold' })
  bucketRounds = GlobalState<uint64>({ key: 'bucketRounds' })
  bucketLead = GlobalState<uint64>({ key: 'bucketLead' })
  genesisCommittee = GlobalState<uint64>({ key: 'genesisCommittee' })
  // Total bond, kept like a member's: bondTotal counts up to epoch bondTotalEpoch, nextBondTotal after it.
  bondTotal = GlobalState<uint64>({ key: 'bondTotal', initialValue: 0 })
  nextBondTotal = GlobalState<uint64>({ key: 'nextBondTotal', initialValue: 0 })
  bondTotalEpoch = GlobalState<uint64>({ key: 'bondTotalEpoch', initialValue: 0 })
  // The seed of the committee being nominated (the block seed of its nomination epoch's first round).
  seedCommittee = GlobalState<uint64>({ key: 'seedCommittee', initialValue: 0 })
  seed = GlobalState<bytes<32>>({ key: 'seed' })
  registrySize = GlobalState<uint64>({ key: 'registrySize', initialValue: 0 })
  registry = BoxMap<uint64, Member>({ keyPrefix: 'm' })
  members = BoxMap<Account, uint64>({ keyPrefix: 'a' }) // Index + 1.
  nominationKeys = BoxMap<bytes, EpochKey>({ keyPrefix: 'k' }) // Key: itob(index) || itob(epoch % 3).
  seats = BoxMap<bytes, Seat>({ keyPrefix: 'n' }) // Key: itob(committee) || itob(nominator index) || itob(ticket).
  capsuleCount = GlobalState<uint64>({ key: 'capsuleCount', initialValue: 0 })
  capsules = BoxMap<uint64, CapsuleRecord>({ keyPrefix: 'x' })

  @abimethod({ onCreate: 'require' })
  createApplication(
    epochRounds: uint64, nominationRounds: uint64, handoverRounds: uint64, totalTickets: uint64, ticketThreshold: uint64,
    shareThreshold: uint64, bucketRounds: uint64, bucketLead: uint64, genesisCommittee: uint64,
  ): void {
    assert(nominationRounds > 0 && handoverRounds > 0 && totalTickets > 0 && ticketThreshold > 0 && shareThreshold > 0, 'Invalid parameters')
    assert(bucketRounds >= epochRounds && genesisCommittee > Global.round / epochRounds + 1, 'Invalid schedule')
    assert(nominationRounds < BALANCE_LOOKBACK, 'Nomination window too long')
    // Both windows fit in one epoch, so a ring entry is overwritten only after its epoch's nominations end.
    assert(nominationRounds + handoverRounds < epochRounds, 'Epoch too short')
    this.epochRounds.value = epochRounds
    this.nominationRounds.value = nominationRounds
    this.handoverRounds.value = handoverRounds
    this.totalTickets.value = totalTickets
    this.ticketThreshold.value = ticketThreshold
    this.shareThreshold.value = shareThreshold
    this.bucketRounds.value = bucketRounds
    this.bucketLead.value = bucketLead
    this.genesisCommittee.value = genesisCommittee
  }

  /**
   * Anyone joins by paying for its own boxes (registry entry, index, three nomination-key slots); the rest of the
   * payment is its bond. The VRF key is fixed before any seed its bond will count under.
   */
  enroll(vrfKey: bytes<32>, payment: gtxn.PaymentTxn): void {
    const entry = this.members(Txn.sender)
    assert(!entry.exists, 'Already enrolled')
    assert(payment.receiver === Global.currentApplicationAddress && payment.amount >= this.enrollMbr(), 'Payment too small')
    const index = this.registrySize.value
    this.registry(index).value = { account: Txn.sender, vrfKey, enrolledRound: Global.round, bond: 0, nextBond: 0, bondEpoch: this.epoch() }
    entry.value = index + 1
    this.registrySize.value = index + 1
    this.setBond(index, payment.amount - this.enrollMbr())
  }

  /** Adds to the sender's bond, counted from the next epoch's nominations. */
  addBond(payment: gtxn.PaymentTxn): void {
    assert(payment.receiver === Global.currentApplicationAddress, 'Pay the app')
    const index = this.indexOf(Txn.sender)
    this.setBond(index, this.registry(index).value.nextBond + payment.amount)
  }

  /**
   * Returns bond at once. It still counts in this epoch's nominations, fixed before the seed; bonded again anywhere,
   * the coins count only from the next epoch, so no coin counts twice in one epoch's sortition.
   */
  withdrawBond(amount: uint64): void {
    const index = this.indexOf(Txn.sender)
    const next = this.registry(index).value.nextBond
    assert(amount <= next, 'Bond too small')
    this.setBond(index, next - amount)
    itxn.payment({ receiver: Txn.sender, amount, fee: 0 }).submit()
  }

  /** A fresh nomination key for the current or next epoch, once, never replaced (ring of 3 per member, prepaid). */
  postNominationKey(epoch: uint64, key: bytes<32>): void {
    const index = this.indexOf(Txn.sender)
    const current = this.epoch()
    assert(epoch === current || epoch === current + 1, 'Wrong epoch')
    const box = this.nominationKeys(op.itob(index).concat(op.itob(epoch % 3)))
    assert(!box.exists || box.value.epoch !== epoch, 'Already posted')
    box.value = { epoch, key }
  }

  /**
   * One seat per winning ticket, in the epoch's nomination window, for the next committee (§3.1.2). A member with
   * weight w holds ⌈w · totalTickets / total bond⌉ tickets, the last one partial. Ticket j wins iff the rank of
   * VRF(sha256("ecpss/nominate/v2" || appId || committee || j || seed)) is below ticketThreshold, scaled down for a
   * partial ticket: Algorand-style sortition with tickets as sub-users. The seat's one-time keys and their seed are
   * sealed to a stake-weighted random member's epoch key. The nominator pays the seat's box, refunded at deletion.
   */
  nominate(
    nominator: uint64, ticket: uint64, proof: bytes<80>, epk: bytes<96>, sigKey: bytes<32>, sealedSeed: bytes<80>, payment: gtxn.PaymentTxn,
  ): void {
    const epoch = this.epoch()
    const start: uint64 = epoch * this.epochRounds.value
    assert(Global.round > start && Global.round <= start + this.nominationRounds.value, 'Not nominating')
    const committee: uint64 = epoch + 1
    assert(nominator < this.registrySize.value, 'Unknown member')
    const member = clone(this.registry(nominator).value)
    assert(Txn.sender === member.account, 'Not the nominator') // A copied proof is useless to anyone else.
    assert(member.enrolledRound < start, 'Enrolled after the seed round')
    const seat = this.seats(this.seatKey(committee, nominator, ticket))
    assert(!seat.exists, 'Already nominated')
    assert(payment.receiver === Global.currentApplicationAddress && payment.amount === this.seatMbr(), 'Exact payment required')
    // In weight × totalTickets units, ticket j covers what is left after j tickets of `total` each, at most one ticket.
    const total = this.totalAt(epoch)
    const units: biguint = BigUint(this.weightOf(member, epoch)) * BigUint(this.totalTickets.value)
    const used: biguint = BigUint(ticket) * BigUint(total)
    assert(used < units, 'No such ticket')
    const share: biguint = units - used < BigUint(total) ? units - used : BigUint(total)
    const seed = this.seedOf(committee)
    ensureBudget(VRF_BUDGET, OpUpFeeSource.GroupCredit)
    const alpha = op.sha256(Bytes('ecpss/nominate/v2').concat(op.itob(Global.currentApplicationId.id))
      .concat(op.itob(committee)).concat(op.itob(ticket)).concat(seed))
    const [output, verified] = op.vrfVerify(VrfVerify.VrfAlgorand, alpha, proof, member.vrfKey)
    assert(verified, 'Invalid VRF proof')
    assert(BigUint(op.extract(output, 0, 8)) * BigUint(total) < BigUint(this.ticketThreshold.value) * share, 'Not eligible')
    seat.value = {
      epk, sigKey, sealedSeed, holder: Global.zeroAddress, digest: Bytes<32>({ length: 32 }),
      stateDigest: Bytes<32>({ length: 32 }), chunks: 0, finalized: false,
    }
  }

  /**
   * A holder takes its seat for the handover window of epoch `committee`: the seat's one-time key signs
   * "ecpss/claim/v2" || appId || committee || nominator || ticket || holder || stateDigest. Only that account may then
   * post the message. Readers trust a public state that t seats attest: fewer than t are corrupt.
   */
  claim(committee: uint64, nominator: uint64, ticket: uint64, holder: Account, stateDigest: bytes<32>, signature: bytes<64>): void {
    const seat = this.openSeat(committee, nominator, ticket)
    assert(seat.value.holder === Global.zeroAddress, 'Already claimed')
    ensureBudget(SIG_BUDGET, OpUpFeeSource.GroupCredit)
    const message = Bytes('ecpss/claim/v2').concat(op.itob(Global.currentApplicationId.id)).concat(op.itob(committee))
      .concat(op.itob(nominator)).concat(op.itob(ticket)).concat(holder.bytes).concat(stateDigest)
    assert(op.ed25519verifyBare(message, signature, seat.value.sigKey), 'Invalid seat signature')
    seat.value.holder = holder
    seat.value.stateDigest = stateDigest
  }

  /** Appends one chunk (four argument parts plus the note) to the seat's running digest. */
  postChunk(committee: uint64, nominator: uint64, ticket: uint64, a: bytes, b: bytes, c: bytes, d: bytes): void {
    const seat = this.openSeat(committee, nominator, ticket)
    assert(Txn.sender === seat.value.holder, 'Not the holder')
    assert(!seat.value.finalized, 'Finalized')
    // Parts are hashed first: an AVM byte value holds at most 4,096 bytes.
    seat.value.digest = op.sha256(seat.value.digest.concat(op.sha256(a)).concat(op.sha256(b)).concat(op.sha256(c))
      .concat(op.sha256(d)).concat(op.sha256(Txn.note)))
    seat.value.chunks += 1
  }

  finalize(committee: uint64, nominator: uint64, ticket: uint64): void {
    const seat = this.openSeat(committee, nominator, ticket)
    assert(Txn.sender === seat.value.holder, 'Not the holder')
    assert(!seat.value.finalized, 'Finalized')
    seat.value.finalized = true
  }

  /**
   * A nominator deletes its own seats once committee c's epoch is over, up to 7 per call (with its member entry, the
   * 8 references a call allows), and gets their deposits back in one payment. Abandoned seats lock only their
   * nominator's deposits.
   */
  deleteSeats(committee: uint64, tickets: uint64[]): void {
    assert(Global.round >= (committee + 1) * this.epochRounds.value, 'Committee still active')
    assert(tickets.length <= BATCH, 'Invalid batch')
    const nominator = this.indexOf(Txn.sender)
    let refund: uint64 = 0
    for (const ticket of tickets) {
      if (this.seats(this.seatKey(committee, nominator, ticket)).delete()) refund += this.seatMbr()
    }
    if (refund > 0) itxn.payment({ receiver: Txn.sender, amount: refund, fee: 0 }).submit()
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

  private seatMbr(): uint64 {
    return 2_500 + 400 * (this.seats.keyPrefix.length + 24 + arc4.sizeOf<Seat>())
  }

  // Registry entry, index, and three nomination-key slots.
  private enrollMbr(): uint64 {
    return 2_500 + 400 * (this.registry.keyPrefix.length + 8 + arc4.sizeOf<Member>())
      + 2_500 + 400 * (this.members.keyPrefix.length + 32 + 8)
      + 3 * (2_500 + 400 * (this.nominationKeys.keyPrefix.length + 16 + arc4.sizeOf<EpochKey>()))
  }

  private epoch(): uint64 {
    return Global.round / this.epochRounds.value
  }

  private indexOf(account: Account): uint64 {
    const entry = this.members(account)
    assert(entry.exists, 'Not enrolled')
    return entry.value - 1
  }

  private setBond(index: uint64, value: uint64): void {
    const epoch = this.epoch()
    const m = clone(this.registry(index).value)
    if (m.bondEpoch < epoch) {
      m.bond = m.nextBond
      m.bondEpoch = epoch
    }
    if (this.bondTotalEpoch.value < epoch) {
      this.bondTotal.value = this.nextBondTotal.value
      this.bondTotalEpoch.value = epoch
    }
    this.nextBondTotal.value = this.nextBondTotal.value - m.nextBond + value
    m.nextBond = value
    this.registry(index).value = clone(m)
  }

  // A member's weight in epoch e's nominations: its bond fixed before e, capped by its online stake.
  private weightOf(m: Member, epoch: uint64): uint64 {
    const bond: uint64 = m.bondEpoch < epoch ? m.nextBond : m.bond
    const [online] = op.VoterParams.voterBalance(m.account)
    return bond < online ? bond : online
  }

  private totalAt(epoch: uint64): uint64 {
    return this.bondTotalEpoch.value < epoch ? this.nextBondTotal.value : this.bondTotal.value
  }

  // Nominations only ever run for the next committee, so one slot holds the seed. Readers take it from the block header.
  private seedOf(committee: uint64): bytes<32> {
    if (this.seedCommittee.value !== committee) {
      this.seed.value = op.Block.blkSeed((committee - 1) * this.epochRounds.value)
      this.seedCommittee.value = committee
    }
    return this.seed.value
  }

  private seatKey(committee: uint64, nominator: uint64, ticket: uint64): bytes {
    return op.itob(committee).concat(op.itob(nominator)).concat(op.itob(ticket))
  }

  // The seat of committee c during the handover window of epoch c.
  private openSeat(committee: uint64, nominator: uint64, ticket: uint64) {
    const start: uint64 = committee * this.epochRounds.value + this.nominationRounds.value
    assert(Global.round > start && Global.round <= start + this.handoverRounds.value, 'Not handing over')
    const seat = this.seats(this.seatKey(committee, nominator, ticket))
    assert(seat.exists, 'No such seat')
    return seat
  }

  @readonly
  getMember(index: uint64): Member {
    return this.registry(index).value
  }

  /** The member's sortition weight and the total bond for the current epoch's nominations. */
  @readonly
  weight(nominator: uint64): [uint64, uint64] {
    return [this.weightOf(this.registry(nominator).value, this.epoch()), this.totalAt(this.epoch())]
  }

  /** Box deposits: enrollment (before any bond) and one seat. */
  @readonly
  deposits(): [uint64, uint64] {
    return [this.enrollMbr(), this.seatMbr()]
  }

  @readonly
  getCapsule(capsuleId: uint64): CapsuleRecord {
    return this.capsules(capsuleId).value
  }

  @readonly
  getSeat(committee: uint64, nominator: uint64, ticket: uint64): Seat {
    return this.seats(this.seatKey(committee, nominator, ticket)).value
  }
}
