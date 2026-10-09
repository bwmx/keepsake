import {
  Account, Application, BoxMap, Bytes, Contract, FixedArray, Global, GlobalState, OpUpFeeSource, Txn, VrfVerify,
  abimethod, arc4, assert, clone, ensureBudget, err, gtxn, itxn, op, readonly,
  type bytes, type uint64,
} from '@algorandfoundation/algorand-typescript'

// Step 5: the sender picks the slot count; the committee is whichever slots get nominated (at least minHolders),
// with a majority threshold. Batched methods touch at most 7 slot boxes, keeping each call within 8 references.
const MIN_HOLDERS: uint64 = 3
const MAX_SLOTS: uint64 = 64
const BATCH: uint64 = 7
// Beacon target round = registration round + SELECTION_DELAY, so the seed is unknown when terms are committed.
const SELECTION_DELAY: uint64 = 8
const VRF_BUDGET: uint64 = 6_300 // vrf_verify costs 5,700.
const SIG_BUDGET: uint64 = 2_500 // ed25519verify_bare costs 1,900.

// Capsule stages, strictly increasing.
const AWAITING_SEED: uint64 = 0 // Beacon request pending.
const NOMINATING: uint64 = 1 // Beacon seed received; VRF-eligible members nominate one-time holder keys.
const SELECTED: uint64 = 2 // Nominations closed with at least minHolders filled slots; threshold fixed.
const DEPOSITING: uint64 = 3 // Manifest hash anchored; sender posting commitments and deposits in batches.
const ANCHORED: uint64 = 4 // Every filled slot has its deposit.
const ACTIVE: uint64 = 5 // At least `threshold` one-time holder keys acknowledged.

// Admitted by the admin (Sybil gate), enrolled by the member itself. The VRF key is immutable; nomination keys
// rotate every epoch (postNominationKey).
export type Member = { account: Account; vrfKey: bytes<32> }

// The paper's per-epoch "long-term" key (§2.1, §3.1.3): a fresh X25519 key that receives holder-seed nominations.
export type EpochKey = { epoch: uint64; key: bytes<32> }

// Public policy record. Holds no plaintext, shares, or private keys; boxes are publicly readable.
export type CapsuleRecord = {
  sender: Account
  recipient: Account
  openRound: uint64
  expiresRound: uint64
  seedRound: uint64
  nominationDeadline: uint64
  registrySize: uint64 // Members enrolled before registration; only they can nominate or be nominated.
  epoch: uint64 // Registration epoch: holder seeds are sealed to members' nomination keys for this epoch.
  beaconDeposit: uint64 // Beacon box deposit, refunded to the sender on cleanup.
  stage: uint64
  slotCount: uint64
  minHolders: uint64
  filled: uint64 // Committee size n once nominations close.
  threshold: uint64 // floor(n / 2) + 1, set at close.
  deposits: uint64
  acks: uint64
  slotBoxes: uint64 // Existing slot boxes; all must be deleted before the capsule box.
  randomness: bytes<32>
  manifestHash: bytes<32>
  payloadHash: bytes<32>
  requested: boolean
  requestId: bytes<16>
  recipientKey: bytes<32>
}

// One holder slot. The holder is known only through one-time keys; nothing here names its account.
export type Slot = {
  filled: boolean
  deposited: boolean
  acknowledged: boolean
  released: boolean
  rank: uint64 // First 8 bytes of the winning nominator's VRF output; lowest wins.
  nominator: uint64 // Registry index. Nominators are public once they post.
  holderEncKey: bytes<32> // One-time X25519 key that receives the deposit.
  holderSigKey: bytes<32> // One-time Ed25519 key that authenticates acknowledgment and release.
  sealedSeed: bytes<80> // HPKE(enc 32 || ct 48) of the holder-key seed, to the holder's nomination key.
  commitment: bytes<32>
  deposit: bytes<81> // HPKE(enc 32 || ct 49) of the Shamir share, to holderEncKey.
  releaseEnc: bytes<32>
  releaseCiphertext: bytes<49>
  releaseSignature: bytes<64> // The spike's release signature, checked by the recipient.
}

export type BeaconCosts = { fees: uint64; boxMbr: uint64 }

/** ABI of the randomness beacon methods this app calls (github.com/bwmx/randomness-beacon @ 0e164c3). */
abstract class RandomnessBeaconStub extends Contract {
  createRequest(_requesterAddress: arc4.Address, _round: uint64, _costsPayment: gtxn.PaymentTxn): uint64 { err() }
  cancelRequest(_requestId: uint64): uint64 { err() }
  @readonly
  getCosts(): BeaconCosts { err() }
}

/**
 * Capsule policy with hidden holder committees (paper-aligned VRF use). The beacon supplies only the common seed;
 * members self-select privately with their own VRF keys to nominate anonymous one-time holder keys.
 * No update/delete/opt-in handlers exist, so the AVM rejects those calls. The admin can only admit members.
 */
export class CapsulePolicy extends Contract {
  admin = GlobalState<Account>({ key: 'admin' })
  beacon = GlobalState<Application>({ key: 'beacon' })
  nominationRounds = GlobalState<uint64>({ key: 'nominationRounds' })
  nominatorThreshold = GlobalState<uint64>({ key: 'nominatorThreshold' }) // Eligible iff VRF rank < this.
  epochRounds = GlobalState<uint64>({ key: 'epochRounds' }) // Epoch = round / epochRounds.
  registrySize = GlobalState<uint64>({ key: 'registrySize', initialValue: 0 })
  registry = BoxMap<uint64, Member>({ keyPrefix: 'm' })
  admitted = BoxMap<Account, uint64>({ keyPrefix: 'a' }) // 0 = admitted, n = enrolled at index n - 1.
  nominationKeys = BoxMap<bytes, EpochKey>({ keyPrefix: 'k' }) // Key: itob(index) || itob(epoch % 3).
  capsules = BoxMap<uint64, CapsuleRecord>({ keyPrefix: 'c' })
  slots = BoxMap<bytes, Slot>({ keyPrefix: 's' }) // Key: itob(capsuleId) || itob(slot).

  @abimethod({ onCreate: 'require' })
  createApplication(beacon: Application, nominationRounds: uint64, nominatorThreshold: uint64, epochRounds: uint64): void {
    assert(nominationRounds > 0 && nominatorThreshold > 0, 'Invalid parameters')
    // Every capsule closes nominations before the epoch after its registration ends (see postNominationKey).
    assert(SELECTION_DELAY + nominationRounds < epochRounds, 'Epoch too short')
    this.admin.value = Txn.sender
    this.beacon.value = beacon
    this.nominationRounds.value = nominationRounds
    this.nominatorThreshold.value = nominatorThreshold
    this.epochRounds.value = epochRounds
  }

  // The admin funds registry and nomination-key boxes by pre-funding the app account.
  admitCustodian(account: Account): void {
    assert(Txn.sender === this.admin.value, 'Not admin')
    assert(!this.admitted(account).exists, 'Already admitted')
    this.admitted(account).value = 0
  }

  // Step 1: the member registers its own VRF key, once, before any capsule that may use it.
  enroll(vrfKey: bytes<32>): void {
    const entry = this.admitted(Txn.sender)
    assert(entry.exists, 'Not admitted')
    assert(entry.value === 0, 'Already enrolled')
    const index = this.registrySize.value
    this.registry(index).value = { account: Txn.sender, vrfKey }
    entry.value = index + 1
    this.registrySize.value = index + 1
  }

  /**
   * The member posts a fresh nomination key for the current or next epoch, once; it cannot be replaced, so a sealed
   * seed always targets the key its holder posted. The member erases the private key after that epoch's capsules
   * close nominations, so later compromise cannot open their seeds. Each member has a ring of 3 entries: epoch e is
   * overwritten by e + 3, posted no earlier than epoch e + 2, after every epoch-e capsule closed nominations.
   */
  postNominationKey(epoch: uint64, key: bytes<32>): void {
    const entry = this.admitted(Txn.sender)
    assert(entry.exists && entry.value > 0, 'Not enrolled')
    const current: uint64 = Global.round / this.epochRounds.value
    assert(epoch === current || epoch === current + 1, 'Wrong epoch')
    const box = this.nominationKeys(op.itob(entry.value - 1).concat(op.itob(epoch % 3)))
    assert(!box.exists || box.value.epoch !== epoch, 'Already posted')
    box.value = { epoch, key }
  }

  /**
   * Commits the capsule terms and the registry snapshot, and requests beacon randomness for a future round, in one
   * transaction. Payment = capsule and slot box MBR + beacon fees + beacon box deposit, exactly. Returns the capsule
   * ID, which is the beacon request ID.
   */
  register(
    recipient: Account, openRound: uint64, expiresRound: uint64, slotCount: uint64, minHolders: uint64,
    payment: gtxn.PaymentTxn,
  ): uint64 {
    assert(MIN_HOLDERS <= minHolders && minHolders <= slotCount && slotCount <= MAX_SLOTS, 'Invalid committee size')
    const registrySize = this.registrySize.value
    assert(registrySize >= minHolders, 'Registry too small')
    assert(!this.admitted(recipient).exists, 'Recipient is a registry member')
    const seedRound: uint64 = Global.round + SELECTION_DELAY
    const nominationDeadline: uint64 = seedRound + this.nominationRounds.value
    assert(nominationDeadline < openRound && openRound < expiresRound, 'Invalid window')

    const beacon = this.beacon.value
    const costs = arc4.abiCall<typeof RandomnessBeaconStub.prototype.getCosts>({ appId: beacon, fee: 0 }).returnValue
    assert(payment.receiver === Global.currentApplicationAddress &&
      payment.amount === this.boxMbr(slotCount) + costs.fees + costs.boxMbr, 'Exact payment required')

    const capsuleId = arc4.abiCall<typeof RandomnessBeaconStub.prototype.createRequest>({
      appId: beacon,
      args: [new arc4.Address(Txn.sender), seedRound,
        itxn.payment({ receiver: beacon.address, amount: costs.fees + costs.boxMbr, fee: 0 })],
      fee: 0,
    }).returnValue
    this.capsules(capsuleId).value = {
      sender: Txn.sender, recipient, openRound, expiresRound, seedRound, nominationDeadline, registrySize,
      epoch: Global.round / this.epochRounds.value, beaconDeposit: costs.boxMbr, stage: AWAITING_SEED, slotCount, minHolders, filled: 0, threshold: 0,
      deposits: 0, acks: 0, slotBoxes: 0, randomness: Bytes<32>({ length: 32 }),
      manifestHash: Bytes<32>({ length: 32 }), payloadHash: Bytes<32>({ length: 32 }), requested: false, requestId: Bytes<16>({ length: 16 }), recipientKey: Bytes<32>({ length: 32 }),
    }
    return capsuleId
  }

  // Beacon callback. A proven beacon request can only be fulfilled, so this never rejects a genuine callback.
  fulfillRandomness(requestId: uint64, requesterAddress: arc4.Address, output: bytes<32>): void {
    assert(Global.callerApplicationId === this.beacon.value.id, 'Unauthorized callback')
    const box = this.capsules(requestId)
    if (!box.exists) return
    const record = clone(box.value)
    if (record.stage !== AWAITING_SEED) return
    record.randomness = output
    record.stage = NOMINATING
    box.value = clone(record)
  }

  /**
   * Step 2: private sortition. Member `nominator` proves VRF(alpha) with its enrolled key, where
   * alpha = sha256("capsule/nominate/v1" || itob(appId) || itob(capsuleId) || itob(slot) || beaconRandomness).
   * Eligible iff rank (first 8 output bytes) < nominatorThreshold; the lowest rank per slot wins.
   * Step 3: the post carries one-time holder public keys and their seed sealed to the chosen holder. The contract
   * cannot see who that holder is.
   */
  nominate(
    capsuleId: uint64, slot: uint64, nominator: uint64, proof: bytes<80>,
    holderEncKey: bytes<32>, holderSigKey: bytes<32>, sealedSeed: bytes<80>,
  ): void {
    const capsule = this.capsules(capsuleId)
    const record = clone(capsule.value)
    assert(record.stage === NOMINATING, 'Not nominating')
    assert(Global.round < record.nominationDeadline, 'Nominations closed')
    assert(slot < record.slotCount, 'Invalid slot')
    assert(nominator < record.registrySize, 'Not in snapshot')
    const member = clone(this.registry(nominator).value)
    // A copied proof is useless to anyone but its owner.
    assert(Txn.sender === member.account, 'Not the nominator')
    ensureBudget(VRF_BUDGET, OpUpFeeSource.GroupCredit)
    const alpha = op.sha256(Bytes('capsule/nominate/v1').concat(op.itob(Global.currentApplicationId.id))
      .concat(op.itob(capsuleId)).concat(op.itob(slot)).concat(record.randomness))
    const [output, verified] = op.vrfVerify(VrfVerify.VrfAlgorand, alpha, proof, member.vrfKey)
    assert(verified, 'Invalid VRF proof')
    const rank = op.btoi(op.extract(output, 0, 8))
    assert(rank < this.nominatorThreshold.value, 'Not eligible')
    // Slot boxes are created on first nomination (prepaid at registration), keeping register within 8 references.
    const box = this.slots(this.slotKey(capsuleId, slot))
    if (box.create()) record.slotBoxes += 1
    const current = clone(box.value)
    assert(!current.filled || rank < current.rank, 'Not better')
    if (!current.filled) record.filled += 1
    current.filled = true
    current.rank = rank
    current.nominator = nominator
    current.holderEncKey = holderEncKey
    current.holderSigKey = holderSigKey
    current.sealedSeed = sealedSeed
    box.value = clone(current)
    capsule.value = clone(record)
  }

  // Anyone, after the deadline. Empty slots are simply not in the committee; fewer than minHolders filled slots
  // means the capsule can never proceed. There is no fallback selection.
  closeNominations(capsuleId: uint64): void {
    const box = this.capsules(capsuleId)
    const record = clone(box.value)
    assert(record.stage === NOMINATING, 'Not nominating')
    assert(Global.round >= record.nominationDeadline, 'Nominations open')
    assert(record.filled >= record.minHolders, 'Too few holders')
    record.threshold = record.filled / 2 + 1
    record.stage = SELECTED
    box.value = clone(record)
  }

  // Step 4: the sender anchors the manifest hash, then posts every filled slot's commitment and deposit, so anyone
  // can rebuild the manifest from chain data and check its hash.
  anchorManifest(capsuleId: uint64, manifestHash: bytes<32>, payloadHash: bytes<32>): void {
    const box = this.capsules(capsuleId)
    const record = clone(box.value)
    assert(Txn.sender === record.sender, 'Not sender')
    assert(record.stage === SELECTED, 'Not selected')
    assert(Global.round < record.expiresRound, 'Expired')
    record.manifestHash = manifestHash
    record.payloadHash = payloadHash
    record.stage = DEPOSITING
    box.value = clone(record)
  }

  postDeposits(capsuleId: uint64, slotIndexes: uint64[], commitments: bytes<32>[], deposits: bytes<81>[]): void {
    const box = this.capsules(capsuleId)
    const record = clone(box.value)
    assert(Txn.sender === record.sender, 'Not sender')
    assert(record.stage === DEPOSITING, 'Not depositing')
    assert(Global.round < record.expiresRound, 'Expired')
    assert(slotIndexes.length === commitments.length && slotIndexes.length === deposits.length &&
      slotIndexes.length <= BATCH, 'Invalid batch')
    ensureBudget(1_400, OpUpFeeSource.GroupCredit)
    for (let i: uint64 = 0; i < slotIndexes.length; i++) {
      const slot = this.slots(this.slotKey(capsuleId, slotIndexes[i]))
      assert(slot.exists, 'Slot unfilled')
      const s = clone(slot.value)
      assert(s.filled && !s.deposited, 'Slot unfilled or already deposited')
      s.commitment = commitments[i]
      s.deposit = deposits[i]
      s.deposited = true
      slot.value = clone(s)
      record.deposits += 1
    }
    if (record.deposits === record.filled) record.stage = ANCHORED
    box.value = clone(record)
  }

  // Anyone may relay: the one-time holder key's signature, not Txn.sender, authenticates the holder.
  acknowledgeCustody(capsuleId: uint64, slot: uint64, signature: bytes<64>): void {
    const box = this.capsules(capsuleId)
    const record = clone(box.value)
    assert(record.stage === ANCHORED || record.stage === ACTIVE, 'Not anchored')
    assert(Global.round < record.expiresRound, 'Expired')
    const slotBox = this.slots(this.slotKey(capsuleId, slot))
    assert(slotBox.exists, 'Invalid slot')
    const s = clone(slotBox.value)
    assert(s.deposited, 'Invalid slot')
    assert(!s.acknowledged, 'Already acknowledged')
    ensureBudget(SIG_BUDGET, OpUpFeeSource.GroupCredit)
    const message = Bytes('capsule/chain-ack/v1').concat(this.slotHeader(capsuleId, slot)).concat(record.manifestHash)
    assert(op.ed25519verifyBare(message, signature, s.holderSigKey), 'Invalid holder signature')
    s.acknowledged = true
    slotBox.value = clone(s)
    record.acks += 1
    // A threshold of acknowledged holders makes recovery possible; the rest may still acknowledge later.
    if (record.stage === ANCHORED && record.acks >= record.threshold) record.stage = ACTIVE
    box.value = clone(record)
  }

  // Binds the spike's AccessRequest {manifestHash, requestId, recipientPublicKey} exactly once.
  requestAccess(capsuleId: uint64, manifestHash: bytes<32>, requestId: bytes<16>, recipientKey: bytes<32>): void {
    const box = this.capsules(capsuleId)
    const record = clone(box.value)
    assert(Txn.sender === record.recipient, 'Not recipient')
    assert(record.stage === ACTIVE, 'Not active')
    assert(record.manifestHash === manifestHash, 'Manifest mismatch')
    assert(Global.round >= record.openRound, 'Not open')
    assert(Global.round < record.expiresRound, 'Expired')
    assert(!record.requested, 'Already requested')
    record.requested = true
    record.requestId = requestId
    record.recipientKey = recipientKey
    box.value = clone(record)
  }

  // Anyone may relay a holder's release, once per slot, inside the window and after the recipient's request.
  postRelease(
    capsuleId: uint64, slot: uint64, enc: bytes<32>, ciphertext: bytes<49>, signature: bytes<64>,
    chainSignature: bytes<64>,
  ): void {
    const record = clone(this.capsules(capsuleId).value)
    assert(record.stage === ACTIVE && record.requested, 'No request')
    assert(Global.round < record.expiresRound, 'Expired')
    const slotBox = this.slots(this.slotKey(capsuleId, slot))
    assert(slotBox.exists, 'Invalid slot')
    const s = clone(slotBox.value)
    assert(s.acknowledged, 'Not acknowledged')
    assert(!s.released, 'Already released')
    ensureBudget(SIG_BUDGET, OpUpFeeSource.GroupCredit)
    const message = Bytes('capsule/chain-release/v1').concat(this.slotHeader(capsuleId, slot))
      .concat(record.requestId).concat(record.recipientKey).concat(enc).concat(ciphertext).concat(signature)
    assert(op.ed25519verifyBare(message, chainSignature, s.holderSigKey), 'Invalid holder signature')
    s.released = true
    s.releaseEnc = enc
    s.releaseCiphertext = ciphertext
    s.releaseSignature = signature
    slotBox.value = clone(s)
  }

  // Anyone may clean up after expiry once the beacon has delivered (which returned its deposit to this app).
  // All box MBR and the beacon deposit go to the sender. Deleting boxes does not erase chain history.
  cleanup(capsuleId: uint64): void {
    const record = clone(this.capsules(capsuleId).value)
    assert(Global.round >= record.expiresRound, 'Not expired')
    assert(record.stage !== AWAITING_SEED, 'Beacon request pending')
    assert(record.slotBoxes === 0, 'Slot boxes remain')
    this.deleteAndRefund(capsuleId, record, record.beaconDeposit)
  }

  // Anyone, after expiry, up to BATCH slots per call; then `cleanup`.
  deleteSlots(capsuleId: uint64, slotIndexes: uint64[]): void {
    const box = this.capsules(capsuleId)
    const record = clone(box.value)
    assert(Global.round >= record.expiresRound, 'Not expired')
    assert(slotIndexes.length <= BATCH, 'Invalid batch')
    for (const k of slotIndexes) {
      if (this.slots(this.slotKey(capsuleId, k)).delete()) record.slotBoxes -= 1
    }
    box.value = clone(record)
  }

  // Anyone may abandon a capsule whose beacon proof was withheld; the beacon enforces its stale timeout and
  // rejects proven rounds. There is no fallback seed.
  cancelUnseeded(capsuleId: uint64): void {
    const record = clone(this.capsules(capsuleId).value)
    assert(record.stage === AWAITING_SEED, 'Already seeded')
    const refund = arc4.abiCall<typeof RandomnessBeaconStub.prototype.cancelRequest>({
      appId: this.beacon.value, args: [capsuleId], fee: 0,
    }).returnValue
    this.deleteAndRefund(capsuleId, record, refund)
  }

  private slotKey(capsuleId: uint64, slot: uint64): bytes {
    return op.itob(capsuleId).concat(op.itob(slot))
  }

  // Domain fields shared by chain-signed messages; the text prefix differs per message type.
  private slotHeader(capsuleId: uint64, slot: uint64): bytes {
    return op.itob(Global.currentApplicationId.id).concat(op.itob(capsuleId)).concat(op.itob(slot))
  }

  // Capsule box + every slot box, prepaid in full at registration whether or not every slot gets nominated.
  private boxMbr(slotCount: uint64): uint64 {
    return 2_500 + 400 * (this.capsules.keyPrefix.length + 8 + arc4.sizeOf<CapsuleRecord>()) +
      slotCount * (2_500 + 400 * (this.slots.keyPrefix.length + 16 + arc4.sizeOf<Slot>()))
  }

  // Slot boxes are deleted first (deleteSlots); an unseeded capsule never has any.
  private deleteAndRefund(capsuleId: uint64, record: CapsuleRecord, extra: uint64): void {
    this.capsules(capsuleId).delete()
    itxn.payment({ receiver: record.sender, amount: this.boxMbr(record.slotCount) + extra, fee: 0 }).submit()
  }

  @readonly
  getCapsule(capsuleId: uint64): CapsuleRecord {
    return this.capsules(capsuleId).value
  }

  @readonly
  getSlot(capsuleId: uint64, slot: uint64): Slot {
    return this.slots(this.slotKey(capsuleId, slot)).value
  }

  @readonly
  getMember(index: uint64): Member {
    return this.registry(index).value
  }
}
