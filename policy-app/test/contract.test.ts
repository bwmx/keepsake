import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { microAlgo } from '@algorandfoundation/algokit-utils';
import { Custodian } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/protocol.js';
import { releaseBody } from '../src/chain.js';
import { ANY_RANK, SELECTION_DELAY, boxMbr } from '../src/sim.js';
import {
  STAGE, ack, closeAt, nextRoundIs, nominate, postDeposits, record, rejects, seed, slot, sortition, winners, withSim,
} from './localnet.js';

test('step 1: admin admits, members enroll VRF keys once and post one nomination key per epoch; registration checks bounds and payment', () => withSim({ epochRounds: 40n }, async sim => {
  const m0 = sim.members[0]!;
  assert.deepEqual(Buffer.from((await sim.app.getMember({ args: { index: 0n } })).vrfKey), Buffer.from(m0.vrfSecretKey.subarray(32)));
  const fresh = await sim.fund();
  await rejects(sim.app.send.admitCustodian({ args: { account: fresh.toString() }, sender: sim.outsider }), 'Not admin');
  await rejects(sim.app.send.enroll({ sender: fresh, args: { vrfKey: randomBytes(32) } }), 'Not admitted');
  await rejects(sim.app.send.admitCustodian({ args: { account: m0.account.toString() } }), 'Already admitted');
  await rejects(sim.app.send.enroll({ sender: m0.account, args: { vrfKey: randomBytes(32) } }), 'Already enrolled');

  // Nomination keys (the paper's per-epoch keys): current or next epoch only, once each, in a ring of 3 per member.
  await rejects(sim.deployPolicy(30n, ANY_RANK, 38n), 'Epoch too short'); // 8 + 30 rounds must fit in an epoch.
  const post = (epoch: bigint, key = randomBytes(32), sender = m0.account) =>
    sim.app.send.postNominationKey({ sender, args: { epoch, key } }).then(() => key);
  const e = (await sim.lastRound()) / 40n + 1n;
  await nextRoundIs(sim, e * 40n);
  await rejects(post(e, undefined, fresh), 'Not enrolled');
  await rejects(post(e - 1n), 'Wrong epoch');
  await rejects(post(e + 2n), 'Wrong epoch');
  const key = await post(e);
  await rejects(post(e), 'Already posted'); // A sealed seed always targets the key its holder posted.
  await post(e + 1n);
  assert.deepEqual(Buffer.from((await sim.reader.nominationKey(e, 0n))!), key);
  assert.equal(await sim.reader.nominationKey(e + 2n, 0n), undefined);
  await nextRoundIs(sim, (e + 2n) * 40n); // Epoch e + 3 reuses e's ring entry, posted two epochs later.
  await post(e + 3n);
  assert.equal(await sim.reader.nominationKey(e, 0n), undefined);

  for (const [slots, minHolders] of [[65, 3], [5, 2], [5, 6]]) {
    await rejects(sim.register({ slots: slots!, minHolders: minHolders! }), 'Invalid committee size');
  }
  const small = await sim.deployPolicy(30n, ANY_RANK);
  for (const m of sim.members.slice(0, 2)) await sim.enroll(m, small);
  await rejects(sim.register({ target: small }), 'Registry too small');
  await rejects(sim.register({ recipient: m0.account.toString() }), 'Recipient is a registry member');
  const next = (await sim.lastRound()) + 1n;
  await rejects(sim.register({ openRound: next + SELECTION_DELAY + 30n, expiresRound: next + 100n }), 'Invalid window');
  await rejects(sim.register({ amount: sim.payment(5) - 1 }), 'Exact payment required');
  await rejects(sim.register({ amount: sim.payment(5) + 1 }), 'Exact payment required');
  await rejects(sim.register({ receiver: sim.outsider.toString() }), 'Exact payment required');
  const c = await sim.register();
  assert.equal((await record(sim, c.capsuleId)).epoch, (c.seedRound - SELECTION_DELAY) / 40n); // Registration epoch.
  await rejects(sim.app.send.fulfillRandomness({ sender: sim.outsider, args: {
    requestId: c.capsuleId, requesterAddress: sim.sender.toString(), output: randomBytes(32) } }), 'Unauthorized callback');
  await seed(sim, c);
}));

test('step 2: beacon-seeded private sortition, verified on-chain with vrf_verify; lowest rank per slot wins', () => withSim({}, async sim => {
  const c = await sim.register({ slots: 5, minHolders: 5 });
  const [a, b] = [sim.members[0]!, sim.members[1]!];
  await rejects(nominate(sim, a, c.capsuleId, 0n, { proof: new Uint8Array(80) }), 'Not nominating');
  const late = await sim.addMember(); // Enrolled after registration: outside this capsule's snapshot.
  await seed(sim, c);
  await rejects(nominate(sim, late, c.capsuleId, 0n), 'Not in snapshot');
  await rejects(nominate(sim, a, c.capsuleId, 5n), 'Invalid slot');

  const ra = await sortition(sim, a, c.capsuleId, 0n);
  const rb = await sortition(sim, b, c.capsuleId, 0n);
  await rejects(nominate(sim, a, c.capsuleId, 0n, { sender: b.account }), 'Not the nominator'); // Copied proof.
  await rejects(nominate(sim, b, c.capsuleId, 0n, { proof: ra.proof }), 'Invalid VRF proof'); // Another member's proof.
  await rejects(nominate(sim, a, c.capsuleId, 1n, { proof: ra.proof }), 'Invalid VRF proof'); // Another slot's proof.
  const [better, worse] = ra.rank < rb.rank ? [a, b] : [b, a];
  await nominate(sim, worse, c.capsuleId, 0n);
  await nominate(sim, better, c.capsuleId, 0n);
  await rejects(nominate(sim, worse, c.capsuleId, 0n), 'Not better');
  const s0 = await slot(sim, c.capsuleId, 0n);
  assert.equal(s0.nominator, BigInt(better.index));
  assert.equal(s0.rank, ra.rank < rb.rank ? ra.rank : rb.rank); // On-chain rank equals the off-chain VRF output.
  assert.equal((await record(sim, c.capsuleId)).filled, 1n); // Replacing a nomination does not grow the committee.

  for (const k of [1n, 2n, 3n]) await nominate(sim, a, c.capsuleId, k);
  await rejects(sim.close(c.capsuleId), 'Nominations open');
  await sim.advancePast(c.deadline - 1n);
  await rejects(nominate(sim, a, c.capsuleId, 4n), 'Nominations closed');
  await rejects(sim.close(c.capsuleId), 'Too few holders'); // 4 of minimum 5; no fallback.

  // A threshold below 2^64 makes eligibility private and probabilistic (half the members per slot here).
  const half = await sim.deployPolicy(30n, 2n ** 63n);
  for (const m of sim.members.slice(0, 8)) await sim.enroll(m, half);
  const h = await sim.register({ target: half });
  await seed(sim, h, half);
  const results = await Promise.all(sim.members.slice(0, 8).map(async m => ({ m, rank: (await sortition(sim, m, h.capsuleId, 0n, half)).rank })));
  const ineligible = results.find(r => r.rank >= 2n ** 63n)!;
  const eligible = results.find(r => r.rank < 2n ** 63n)!;
  await rejects(nominate(sim, ineligible.m, h.capsuleId, 0n, { target: half }), 'Not eligible');
  await nominate(sim, eligible.m, h.capsuleId, 0n, { target: half });
}));

test('steps 3–5: variable committee, batched deposits, threshold activation, one-time-key acks and releases via relayer', () => withSim({}, async sim => {
  const c = await sim.register({ slots: 8, minHolders: 4, openIn: 25n, length: 6n });
  await seed(sim, c);
  const best = await winners(sim, c.capsuleId, 8, ANY_RANK);
  const filled = [0n, 1n, 2n, 4n, 5n, 7n]; // Slots 3 and 6 stay empty: the committee is the 6 filled slots.
  const seeds = new Map<bigint, Uint8Array>();
  for (const k of filled) seeds.set(k, await nominate(sim, sim.members[best[Number(k)]!]!, c.capsuleId, k));
  await closeAt(sim, c);
  const closed = await record(sim, c.capsuleId);
  assert.deepEqual([closed.filled, closed.threshold], [6n, 4n]); // Majority of the actual committee.

  const hash = randomBytes(32);
  await rejects(sim.app.send.anchorManifest({ sender: sim.outsider, args: { capsuleId: c.capsuleId, manifestHash: hash, payloadHash: hash } }), 'Not sender');
  await sim.app.send.anchorManifest({ sender: sim.sender, args: { capsuleId: c.capsuleId, manifestHash: hash, payloadHash: randomBytes(32) } });
  await rejects(sim.app.send.anchorManifest({ sender: sim.sender, args: { capsuleId: c.capsuleId, manifestHash: hash, payloadHash: hash } }), 'Not selected');
  await rejects(postDeposits(sim, c.capsuleId, [0n], sim.outsider), 'Not sender');
  await rejects(postDeposits(sim, c.capsuleId, [3n]), 'Slot unfilled');
  await rejects(postDeposits(sim, c.capsuleId, [0n, 1n, 2n, 4n, 5n, 7n, 0n, 1n]), 'Invalid batch');
  await postDeposits(sim, c.capsuleId, [0n, 1n, 2n]);
  await rejects(postDeposits(sim, c.capsuleId, [2n]), 'already deposited');
  await rejects(ack(sim, c.capsuleId, 0n, seeds.get(0n)!), 'Not anchored'); // Deposits incomplete.
  await postDeposits(sim, c.capsuleId, [4n, 5n, 7n]);
  assert.equal((await record(sim, c.capsuleId)).stage, STAGE.ANCHORED);

  await rejects(ack(sim, c.capsuleId, 0n, randomBytes(32)), 'Invalid holder signature'); // Not the slot's one-time key.
  await rejects(ack(sim, c.capsuleId, 1n, seeds.get(0n)!, 0n), 'Invalid holder signature'); // Slot 0's signature on slot 1.
  await rejects(ack(sim, c.capsuleId, 3n, randomBytes(32)), 'Invalid slot'); // Empty slot.
  for (const k of [0n, 1n, 2n]) await ack(sim, c.capsuleId, k, seeds.get(k)!);
  await rejects(ack(sim, c.capsuleId, 0n, seeds.get(0n)!), 'Already acknowledged');
  await rejects(sim.request(c.capsuleId, hash.toString('hex')), 'Not active');
  await ack(sim, c.capsuleId, 4n, seeds.get(4n)!); // 4 = threshold: active.
  assert.equal((await record(sim, c.capsuleId)).stage, STAGE.ACTIVE);
  await ack(sim, c.capsuleId, 5n, seeds.get(5n)!); // Late acknowledgments still count.
  assert.equal((await record(sim, c.capsuleId)).acks, 5n);

  const holder = await Custodian.fromSeed('slot-0', seeds.get(0n)!);
  const [enc, ct, sig] = [randomBytes(32), randomBytes(49), randomBytes(64)];
  const post = async (o: { signer?: Custodian; slot?: bigint } = {}) => {
    const k = o.slot ?? 0n;
    const chainSignature = (o.signer ?? holder).signChainMessage('release', releaseBody(sim.app.appId, c.capsuleId, k, await record(sim, c.capsuleId), enc, ct, sig));
    return sim.app.send.postRelease({ coverAppCallInnerTransactionFees: true, maxFee: microAlgo(20_000), sender: sim.relayer, args: {
      capsuleId: c.capsuleId, slot: k, enc, ciphertext: ct, signature: sig, chainSignature } });
  };
  await rejects(post(), 'No request');
  await rejects(sim.request(c.capsuleId, hash.toString('hex')), 'Not open');
  await nextRoundIs(sim, c.openRound);
  await rejects(sim.request(c.capsuleId, hash.toString('hex'), { as: sim.outsider }), 'Not recipient');
  await rejects(sim.request(c.capsuleId, randomBytes(32).toString('hex')), 'Manifest mismatch');
  await sim.request(c.capsuleId, hash.toString('hex'));
  await rejects(sim.request(c.capsuleId, hash.toString('hex')), 'Already requested'); // No key substitution.
  await rejects(post({ signer: await Custodian.fromSeed('slot-1', seeds.get(1n)!) }), 'Invalid holder signature');
  await rejects(post({ slot: 7n, signer: await Custodian.fromSeed('slot-7', seeds.get(7n)!) }), 'Not acknowledged');
  await post();
  await rejects(post(), 'Already released');
  const s0 = await slot(sim, c.capsuleId, 0n);
  assert.deepEqual([Buffer.from(s0.releaseEnc), Buffer.from(s0.releaseCiphertext), Buffer.from(s0.releaseSignature)], [enc, ct, sig]);

  await nextRoundIs(sim, c.expiresRound);
  await rejects(post({ slot: 1n, signer: await Custodian.fromSeed('slot-1', seeds.get(1n)!) }), 'Expired');
  await rejects(sim.app.send.cleanup({ args: { capsuleId: c.capsuleId }, sender: sim.outsider, extraFee: microAlgo(1000) }), 'Slot boxes remain');
  const balance = async () => (await sim.algorand.account.getInformation(sim.sender)).balance.microAlgo;
  const before = await balance();
  await sim.cleanup(c.capsuleId); // deleteSlots in batches of 7, then cleanup.
  assert.equal((await balance()) - before, BigInt(boxMbr(8)) + sim.costs.boxMbr); // All 9 boxes prepaid + beacon deposit.
  await rejects(record(sim, c.capsuleId), 'Box must have value');
}));

test('withheld beacon proof: no fallback seed; after the beacon timeout anyone cancels and the sender is refunded', () =>
  withSim({ beaconDaemon: false, staleRequestTimeout: 3n, nominationRounds: 2n, members: 5 }, async sim => {
    const balance = async () => (await sim.algorand.account.getInformation(sim.sender)).balance.microAlgo;
    const c = await sim.register({ openIn: 1n, length: 1n });
    await rejects(nominate(sim, sim.members[0]!, c.capsuleId, 0n, { proof: new Uint8Array(80) }), 'Not nominating');
    const cancel = () => sim.app.send.cancelUnseeded({ coverAppCallInnerTransactionFees: true, maxFee: microAlgo(20_000),
      args: { capsuleId: c.capsuleId }, sender: sim.outsider });
    await sim.advancePast(c.seedRound + 2n); // Executes at seedRound + 3: not yet past the beacon's 3-round timeout.
    await rejects(cancel(), 'NotStale');
    await sim.advancePast(c.expiresRound);
    await rejects(sim.app.send.cleanup({ args: { capsuleId: c.capsuleId }, extraFee: microAlgo(1000) }), 'Beacon request pending');
    const before = await balance();
    await cancel();
    assert.equal((await balance()) - before, BigInt(sim.payment(5))); // All box MBR + beacon fees + beacon deposit.
    await rejects(record(sim, c.capsuleId), 'Box must have value');
  }));

test('the application cannot be updated, deleted or opted into', () => withSim({ members: 5 }, async sim => {
  const appId = sim.app.appId;
  const program = '#pragma version 11\npushint 1\nreturn';
  const refused = 'logic eval error|rejected by ApprovalProgram';
  await rejects(sim.algorand.send.appUpdate({ sender: sim.admin, appId, approvalProgram: program, clearStateProgram: program }), refused);
  await rejects(sim.algorand.send.appDelete({ sender: sim.admin, appId }), refused);
  await rejects(sim.algorand.send.appCall({ sender: sim.admin, appId, onComplete: 1 /* OptIn */ }), refused);
}));
