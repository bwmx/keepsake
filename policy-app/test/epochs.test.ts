import assert from 'node:assert/strict';
import { randomBytes, randomInt } from 'node:crypto';
import { test } from 'node:test';
import { algo, microAlgo } from '@algorandfoundation/algokit-utils';
import vrf from '@bwmx/algorand-vrf-utils-ts';
import { generateEphemeralKey, open, seal } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/crypto.js';
import {
  dealerGenesis, decodeMessage, encodeMessage, encodeState, handover, receive, reconstruct, seatKeys, stateDigest, type Message,
} from 'algorand-ephemeral-capsule-crypto-spike/dist/src/ecpss.js';
import { decodeG2 } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/pvss.js';
import { EpochCommitteeFactory } from '../smart_contracts/artifacts/epoch_committee/EpochCommitteeClient.js';
import { b64url, vrfRank } from '../src/chain.js';
import { claimMessage, nominationAlpha, postMessage, seatSeedContext, windows, type OrderedSeat } from '../src/epochs.js';
import { algod, algorand, cover, deploy, lastRound, rejects, shortWindow, type Env, type Member } from './epoch-env.js';

/** Each member posts a fresh nomination key for `epoch` and keeps the private half (the worker's job in Phase 3). */
async function postKeys(env: Env, epoch: bigint) {
  for (const m of env.members) {
    const pair = await generateEphemeralKey();
    await env.app.send.postNominationKey({ sender: m.account, args: { epoch, key: Buffer.from(pair.publicKey, 'base64url') } });
    m.keys.set(epoch, pair);
  }
}

// Equal bonds and one ticket per member: these tests cover the seat mechanics; stake weighting is epoch-stake.test.ts.
const sortition = (env: Env, m: Member, committee: bigint, seed: Uint8Array, ticket = 0n) => {
  const { proof, output } = vrf.prove(m.vrfSecretKey, nominationAlpha(env.app.appId, committee, ticket, seed));
  return { proof, rank: vrfRank(output) };
};

/** The test plays nominator: one seat for a uniformly chosen nominee, sealed to its key for the nomination epoch. */
async function nominate(env: Env, m: Member, committee: bigint, seed: Uint8Array,
  o: { sender?: Member['account']; proof?: Uint8Array; ticket?: bigint; deposit?: bigint } = {}) {
  const nominee = env.members[randomInt(env.members.length)]!, ticket = o.ticket ?? 0n, sender = o.sender ?? m.account;
  const seatSeed = randomBytes(32), keys = seatKeys(seatSeed);
  const sealed = await seal(nominee.keys.get(committee - 1n)!.publicKey, seatSeed, seatSeedContext(env.pins, committee, m.index, ticket));
  await env.app.send.nominate({ ...cover, ...(await shortWindow()), sender, args: {
    nominator: m.index, ticket, proof: o.proof ?? sortition(env, m, committee, seed, ticket).proof, epk: keys.epk.toBytes(), sigKey: keys.sigKey,
    sealedSeed: Buffer.concat([Buffer.from(sealed.enc, 'base64url'), Buffer.from(sealed.ciphertext, 'base64url')]),
    payment: algorand.createTransaction.payment({ sender, receiver: env.app.appAddress, amount: microAlgo(o.deposit ?? env.seatDeposit) }) } });
  return { nominee, sigKey: b64url(keys.sigKey) };
}

/** Trial decryption with each member's key for the nomination epoch: who holds each seat, and its one-time keys. */
async function openSeats(env: Env, committee: bigint, seats: OrderedSeat[]) {
  return Promise.all(seats.map(async s => {
    for (const m of env.members) {
      const seed = await open(m.keys.get(committee - 1n)!.privateKey,
        { enc: b64url(s.value.sealedSeed.subarray(0, 32)), ciphertext: b64url(s.value.sealedSeed.subarray(32)) },
        seatSeedContext(env.pins, committee, s.nominator, s.ticket)).catch(() => undefined);
      if (!seed) continue;
      const keys = seatKeys(seed);
      assert.ok(keys.epk.equals(decodeG2(s.value.epk)) && Buffer.from(keys.sigKey).equals(Buffer.from(s.value.sigKey)));
      return { ...s, holder: m, keys };
    }
    throw new Error(`Nobody opens seat ${s.seat}`);
  }));
}

test('sortition: every VRF-eligible member nominates once; seats are ordered by one-time key and open only for their nominee', async () => {
  const env = await deploy({ members: 20, epochRounds: 80n, nominationRounds: 25n, handoverRounds: 40n, threshold: 2n ** 63n });
  const epoch = await env.nextEpoch(), committee = epoch + 1n;
  await postKeys(env, epoch);
  await env.nextRoundIs(epoch * 80n); // The seed round: enrolling now is too late for this epoch.
  const late = await env.addMember(20);
  const seed = await env.reader.seed(committee);

  const ranked = env.members.map(m => ({ m, rank: sortition(env, m, committee, seed).rank }));
  const eligible = ranked.filter(r => r.rank < 2n ** 63n).map(r => r.m), ineligible = ranked.filter(r => r.rank >= 2n ** 63n).map(r => r.m);
  assert.ok(eligible.length >= 2 && ineligible.length > 0, 'binomial(20, ½) outliers');
  await rejects(nominate(env, ineligible[0]!, committee, seed), 'Not eligible');
  await rejects(nominate(env, late, committee, seed), 'Enrolled after the seed round');
  await rejects(nominate(env, eligible[0]!, committee, seed, { sender: eligible[1]!.account }), 'Not the nominator'); // Copied proof.
  await rejects(nominate(env, eligible[0]!, committee, seed, { ticket: 1n }), 'No such ticket'); // One ticket per equal bond.
  await rejects(nominate(env, eligible[0]!, committee, seed, { deposit: env.seatDeposit - 1n }), 'Exact payment required');
  const nominees = new Map<string, Member>();
  for (const m of eligible) { const n = await nominate(env, m, committee, seed); nominees.set(n.sigKey, n.nominee); }
  // The contract captured the seed from the block it names, as readers do.
  assert.deepEqual(Buffer.from((await env.app.state.global.seed())!.asByteArray()!), Buffer.from((await algod.block(epoch * 80n).do()).block.header.seed));
  await rejects(nominate(env, eligible[0]!, committee, seed), 'Already nominated');
  await env.nextRoundIs(windows(env.params, epoch).nominate[1] + 1n);
  await rejects(nominate(env, eligible[1]!, committee, seed), 'Not nominating');

  // The committee is exactly the eligible members' seats (binomial around C = N·p), numbered in signing-key order.
  const seats = await env.reader.seats(committee);
  assert.equal(seats.length, eligible.length);
  assert.equal((await env.reader.seatIds(committee)).length, eligible.length);
  seats.slice(1).forEach((s, i) => assert.ok(Buffer.compare(Buffer.from(seats[i]!.value.sigKey), Buffer.from(s.value.sigKey)) < 0));
  for (const s of await openSeats(env, committee, seats)) assert.equal(s.holder, nominees.get(b64url(s.value.sigKey)));
});

test('handover on chain: holders claim seats and post one message each; readers rebuild them from blocks; the next committee reconstructs the secret', async () => {
  const t = 3, E = 100n;
  const env = await deploy({ members: 6, epochRounds: E, nominationRounds: 25n, handoverRounds: 50n, threshold: 2n ** 64n - 1n });
  const epoch = await env.nextEpoch(), c1 = epoch + 1n, c2 = c1 + 1n;
  await postKeys(env, epoch);

  // Epoch e: everyone is eligible, so committee c1 has six seats. Its genesis bucket comes from an honest dealer.
  await env.nextRoundIs(epoch * E + 1n);
  for (const m of env.members) await nominate(env, m, c1, await env.reader.seed(c1));
  await postKeys(env, c1);
  await env.nextRoundIs(windows(env.params, epoch).nominate[1] + 1n);
  const seats1 = await openSeats(env, c1, await env.reader.seats(c1));
  const keys1 = seats1.map(s => s.keys.epk);
  const genesis = dealerGenesis(1n, keys1, t);
  let state = receive(genesis.messages, new Map(), 0n, { live: [], create: [1n] }, keys1, t, seats1.map(s => ({ seat: s.seat, x: s.keys.x })));

  // Epoch c1: nominate committee c2, then committee c1 hands over to it.
  await env.nextRoundIs(c1 * E + 1n);
  for (const m of env.members) await nominate(env, m, c2, await env.reader.seed(c2));
  const [first, cheater] = [seats1[0]!, seats1[seats1.length - 1]!];
  const digest = stateDigest(encodeState(state.pub)); // Holders attest the public state they received.
  const claim = (s: (typeof seats1)[number], signer = s.keys) => env.app.send.claim({ ...cover, sender: s.holder.account, args: {
    committee: c1, nominator: s.nominator, ticket: s.ticket, holder: s.holder.account.toString(), stateDigest: digest,
    signature: signer.sign(claimMessage(env.app.appId, c1, s.nominator, s.ticket, s.holder.account.publicKey, digest)) } });
  await rejects(claim(first), 'Not handing over'); // Still the nomination window.
  await env.nextRoundIs(windows(env.params, c1).nominate[1] + 1n);
  const seats2 = await openSeats(env, c2, await env.reader.seats(c2));
  const keys2 = seats2.map(s => s.keys.epk);
  const buckets = { live: [1n], create: [2n] };

  assert.equal((await lastRound()) + 1n, windows(env.params, c1).handover[0]);
  await rejects(claim(first, seats1[1]!.keys), 'Invalid seat signature');
  const posted = new Map<number, Buffer>();
  for (const s of seats1) {
    await claim(s);
    const holder = state.holders.find(h => h.seat === s.seat)!;
    // One holder misbehaves: 50 KB of garbage in three chunks instead of a handover message.
    const message = s === cheater ? randomBytes(50_000) : encodeMessage({ ...handover(holder, state.pub, c1, buckets, keys2, t), state: encodeState(state.pub) });
    await postMessage(env.app, s.holder.account.toString(), { committee: c1, nominator: s.nominator, ticket: s.ticket }, message);
    posted.set(s.seat, message);
  }
  await rejects(claim(first), 'Already claimed');
  const outsider = env.members.find(m => m !== first.holder)!;
  const chunk = { committee: c1, nominator: first.nominator, ticket: first.ticket, a: Buffer.alloc(1), b: Buffer.alloc(1), c: Buffer.alloc(1), d: Buffer.alloc(1) };
  await rejects(env.app.send.postChunk({ sender: outsider.account, args: chunk }), 'Not the holder');
  await rejects(env.app.send.postChunk({ sender: first.holder.account, args: chunk }), 'Finalized');
  assert.equal((await env.reader.seats(c1)).filter(s => s.value.finalized).length, seats1.length);

  // Committee c2 rebuilds every message from blocks (checked against the on-chain digests), drops what fails to
  // decode or verify, and combines the first t valid dealings per bucket.
  const messages = new Map<number, Message>();
  const read = await env.reader.messages(c1, await env.reader.seats(c1));
  assert.equal(read.size, seats1.length);
  for (const s of await env.reader.seats(c1)) {
    const bytes = read.get(s.seat)!;
    assert.deepEqual(bytes, posted.get(s.seat));
    try { messages.set(s.seat, decodeMessage(bytes, s.seat, seats2.length, t)); } catch { assert.equal(s.seat, cheater.seat); }
  }
  const next = receive(messages, state.pub, c1, buckets, keys2, t, seats2.map(s => ({ seat: s.seat, x: s.keys.x })));
  assert.deepEqual(next.lost, []);
  assert.ok(!next.used.get(1n)!.includes(cheater.seat));
  const shares = (b: bigint) => next.holders.map(h => ({ seat: h.seat, share: h.shares.get(b)! }));
  assert.ok(reconstruct(next.pub.get(1n)!, shares(1n), t).equals(genesis.secret));
  reconstruct(next.pub.get(2n)!, shares(2n), t); // The committee-generated bucket is consistent with its commitments.

  // Old seats go once the epoch is over: each nominator deletes its own and gets the deposit back.
  const remove = (m: Member) => env.app.send.deleteSeats({ ...cover, sender: m.account, args: { committee: c1, tickets: [0n] } });
  await rejects(remove(env.members[0]!), 'Committee still active');
  await env.nextRoundIs((c1 + 1n) * E);
  const balance = async (a: string) => (await algod.accountInformation(a).do()).amount;
  for (const m of env.members) {
    const before = await balance(m.account.toString()), { transaction } = await remove(m);
    assert.equal((await balance(m.account.toString())) - before, env.seatDeposit - transaction.fee); // One seat each.
  }
  assert.deepEqual(await env.reader.seatIds(c1), []);
});

test('parameters are checked at creation, and the app cannot be updated, deleted or opted into', async () => {
  const admin = algorand.account.random();
  await algorand.account.ensureFunded(admin, await algorand.account.localNetDispenser(), algo(10));
  const factory = algorand.client.getTypedAppFactory(EpochCommitteeFactory, { defaultSender: admin.addr });
  const genesis = (await lastRound()) / 60n + 3n;
  const create = (epochRounds: bigint, nominationRounds: bigint, handoverRounds: bigint, o: { bucketRounds?: bigint; genesisCommittee?: bigint } = {}) =>
    factory.send.create.createApplication({ args: { epochRounds, nominationRounds, handoverRounds, totalTickets: 10n, ticketThreshold: 1n, shareThreshold: 3n,
      bucketRounds: o.bucketRounds ?? 120n, bucketLead: 60n, genesisCommittee: o.genesisCommittee ?? genesis } });
  await rejects(create(60n, 30n, 30n), 'Epoch too short');
  await rejects(create(5000n, 320n, 30n, { bucketRounds: 5000n, genesisCommittee: (await lastRound()) / 5000n + 3n }), 'Nomination window too long');
  await rejects(create(60n, 20n, 20n, { bucketRounds: 59n }), 'Invalid schedule'); // A bucket spans at least an epoch.
  await rejects(create(60n, 20n, 20n, { genesisCommittee: genesis - 2n }), 'Invalid schedule'); // Its nominations already began.
  const { appClient } = await create(60n, 20n, 20n);
  const program = '#pragma version 11\npushint 1\nreturn';
  const refused = 'logic eval error|rejected by ApprovalProgram';
  await rejects(algorand.send.appUpdate({ sender: admin, appId: appClient.appId, approvalProgram: program, clearStateProgram: program }), refused);
  await rejects(algorand.send.appDelete({ sender: admin, appId: appClient.appId }), refused);
  await rejects(algorand.send.appCall({ sender: admin, appId: appClient.appId, onComplete: 1 }), refused);
});
