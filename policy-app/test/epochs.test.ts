import assert from 'node:assert/strict';
import { randomBytes, randomInt } from 'node:crypto';
import { test } from 'node:test';
import { AlgorandClient, Config, algo, microAlgo } from '@algorandfoundation/algokit-utils';
import { nullLogger } from '@algorandfoundation/algokit-utils/types/logging';
import vrf from '@bwmx/algorand-vrf-utils-ts';
import { generateEphemeralKey, open, seal, type EphemeralKeyPair } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/crypto.js';
import {
  dealerGenesis, decodeMessage, encodeMessage, handover, receive, reconstruct, seatKeys, type Message,
} from 'algorand-ephemeral-capsule-crypto-spike/dist/src/ecpss.js';
import { decodeG2 } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/pvss.js';
import { EpochCommitteeFactory } from '../smart_contracts/artifacts/epoch_committee/EpochCommitteeClient.js';
import { b64url, vrfRank } from '../src/chain.js';
import { EpochReader, claimMessage, nominationAlpha, postMessage, seatSeedContext, windows, type OrderedSeat } from '../src/epochs.js';

Config.configure({ logger: nullLogger });
const algorand = AlgorandClient.defaultLocalNet();
const algod = algorand.client.algod;
const rejects = (p: Promise<unknown>, message: string) => assert.rejects(p, new RegExp(message));
const lastRound = async () => (await algod.status().do()).lastRound;
const cover = { coverAppCallInnerTransactionFees: true, maxFee: microAlgo(20_000) } as const;
/** A 10-round validity window from the next round, so `block` can still read the seed (cached params may be stale). */
const shortWindow = async () => ({ firstValidRound: (await lastRound()) + 1n, validityWindow: 10 });

type Env = Awaited<ReturnType<typeof deploy>>;
type Member = Env['members'][number];

async function deploy(o: { members: number; epochRounds: bigint; nominationRounds: bigint; handoverRounds: bigint; threshold: bigint }) {
  await vrf.init();
  const dispenser = await algorand.account.localNetDispenser();
  const fund = async (amount = 20) => { const a = algorand.account.random(); await algorand.account.ensureFunded(a, dispenser, algo(amount)); return a; };
  const [admin, ticker] = [await fund(50), await fund()];
  const { appClient: app } = await algorand.client.getTypedAppFactory(EpochCommitteeFactory, { defaultSender: admin.addr }).send.create
    .createApplication({ args: { epochRounds: o.epochRounds, nominationRounds: o.nominationRounds, handoverRounds: o.handoverRounds, nominatorThreshold: o.threshold } });
  await algorand.send.payment({ sender: admin, receiver: app.appAddress, amount: algo(20) });
  const { genesisHash } = await algorand.client.network();
  const pins = { genesisHash, appId: app.appId, beaconAppId: 0n, maxRoundAgeMs: 0 };
  const params = { epochRounds: o.epochRounds, nominationRounds: o.nominationRounds, handoverRounds: o.handoverRounds };
  const reader = new EpochReader(algod, pins, params, app.appClient.getABIMethod('postChunk').getSelector());
  const addMember = async (index: number) => {
    const account = await fund(), vrfSecretKey = vrf.generateKeyPair().secretKey;
    await app.send.admitMember({ args: { account: account.toString() } });
    await app.send.enroll({ sender: account, args: { vrfKey: vrfSecretKey.subarray(32) } });
    return { index: BigInt(index), account, vrfSecretKey, keys: new Map<bigint, EphemeralKeyPair>() };
  };
  const members = [];
  for (let i = 0; i < o.members; i++) members.push(await addMember(i));
  /** Advances so that the next transaction executes in `round`. */
  const nextRoundIs = async (round: bigint) => {
    while ((await lastRound()) + 1n < round) await algorand.send.payment({ sender: ticker, receiver: ticker, amount: microAlgo(0), note: randomBytes(8) });
    assert.equal((await lastRound()) + 1n, round, 'Target round already passed');
  };
  /** Moves to the start of a fresh epoch and returns the next one, whose keys members can now post in good time. */
  const nextEpoch = async () => {
    const current = (await lastRound()) / o.epochRounds + 1n;
    await nextRoundIs(current * o.epochRounds + 1n);
    return current + 1n;
  };
  return { app, admin, members, pins, params, reader, addMember, nextRoundIs, nextEpoch };
}

/** Each member posts a fresh nomination key for `epoch` and keeps the private half (the worker's job in Phase 3). */
async function postKeys(env: Env, epoch: bigint) {
  for (const m of env.members) {
    const pair = await generateEphemeralKey();
    await env.app.send.postNominationKey({ sender: m.account, args: { epoch, key: Buffer.from(pair.publicKey, 'base64url') } });
    m.keys.set(epoch, pair);
  }
}

const sortition = (env: Env, m: Member, committee: bigint, seed: Uint8Array) => {
  const { proof, output } = vrf.prove(m.vrfSecretKey, nominationAlpha(env.app.appId, committee, seed));
  return { proof, rank: vrfRank(output) };
};

/** The test plays nominator: one seat for a uniformly chosen nominee, sealed to its key for the nomination epoch. */
async function nominate(env: Env, m: Member, committee: bigint, seed: Uint8Array, o: { sender?: Member['account']; proof?: Uint8Array } = {}) {
  const nominee = env.members[randomInt(env.members.length)]!;
  const seatSeed = randomBytes(32), keys = seatKeys(seatSeed);
  const sealed = await seal(nominee.keys.get(committee - 1n)!.publicKey, seatSeed, seatSeedContext(env.pins, committee, m.index));
  await env.app.send.nominate({ ...cover, ...(await shortWindow()), sender: o.sender ?? m.account, args: {
    nominator: m.index, proof: o.proof ?? sortition(env, m, committee, seed).proof, epk: keys.epk.toBytes(), sigKey: keys.sigKey,
    sealedSeed: Buffer.concat([Buffer.from(sealed.enc, 'base64url'), Buffer.from(sealed.ciphertext, 'base64url')]) } });
  return { nominee, sigKey: b64url(keys.sigKey) };
}

/** Trial decryption with each member's key for the nomination epoch: who holds each seat, and its one-time keys. */
async function openSeats(env: Env, committee: bigint, seats: OrderedSeat[]) {
  return Promise.all(seats.map(async s => {
    for (const m of env.members) {
      const seed = await open(m.keys.get(committee - 1n)!.privateKey,
        { enc: b64url(s.value.sealedSeed.subarray(0, 32)), ciphertext: b64url(s.value.sealedSeed.subarray(32)) },
        seatSeedContext(env.pins, committee, s.nominator)).catch(() => undefined);
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
  await env.app.send.captureSeed({ args: { committee }, ...(await shortWindow()) });
  const { seed } = await env.app.getCommittee({ args: { committee } });
  assert.deepEqual(Buffer.from(seed), Buffer.from((await algod.block(epoch * 80n).do()).block.header.seed));

  const ranked = env.members.map(m => ({ m, rank: sortition(env, m, committee, seed).rank }));
  const eligible = ranked.filter(r => r.rank < 2n ** 63n).map(r => r.m), ineligible = ranked.filter(r => r.rank >= 2n ** 63n).map(r => r.m);
  assert.ok(eligible.length >= 2 && ineligible.length > 0, 'binomial(20, ½) outliers');
  await rejects(nominate(env, ineligible[0]!, committee, seed), 'Not eligible');
  await rejects(nominate(env, late, committee, seed), 'Enrolled after the seed round');
  await rejects(nominate(env, eligible[0]!, committee, seed, { sender: eligible[1]!.account }), 'Not the nominator'); // Copied proof.
  const nominees = new Map<string, Member>();
  for (const m of eligible) { const n = await nominate(env, m, committee, seed); nominees.set(n.sigKey, n.nominee); }
  await rejects(nominate(env, eligible[0]!, committee, seed), 'Already nominated');
  await env.nextRoundIs(windows(env.params, epoch).nominate[1] + 1n);
  await rejects(nominate(env, eligible[1]!, committee, seed), 'Not nominating');

  // The committee is exactly the eligible members' seats (binomial around C = N·p), numbered in signing-key order.
  const seats = await env.reader.seats(committee);
  assert.equal(seats.length, eligible.length);
  assert.equal((await env.reader.committee(committee))!.seats, BigInt(eligible.length));
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
  for (const m of env.members) await nominate(env, m, c1, await captured(env, c1));
  await postKeys(env, c1);
  await env.nextRoundIs(windows(env.params, epoch).nominate[1] + 1n);
  const seats1 = await openSeats(env, c1, await env.reader.seats(c1));
  const keys1 = seats1.map(s => s.keys.epk);
  const genesis = dealerGenesis(1n, keys1, t);
  let state = receive(genesis.messages, new Map(), 0n, { live: [], create: [1n] }, keys1, t, seats1.map(s => ({ seat: s.seat, x: s.keys.x })));

  // Epoch c1: nominate committee c2, then committee c1 hands over to it.
  await env.nextRoundIs(c1 * E + 1n);
  for (const m of env.members) await nominate(env, m, c2, await captured(env, c2));
  const [first, cheater] = [seats1[0]!, seats1[seats1.length - 1]!];
  const claim = (s: (typeof seats1)[number], signer = s.keys) => env.app.send.claim({ ...cover, sender: s.holder.account, args: {
    committee: c1, nominator: s.nominator, holder: s.holder.account.toString(),
    signature: signer.sign(claimMessage(env.app.appId, c1, s.nominator, s.holder.account.publicKey)) } });
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
    const message = s === cheater ? randomBytes(50_000) : encodeMessage(handover(holder, state.pub, c1, buckets, keys2, t));
    await postMessage(env.app, s.holder.account.toString(), c1, s.nominator, message);
    posted.set(s.seat, message);
  }
  await rejects(claim(first), 'Already claimed');
  const outsider = env.members.find(m => m !== first.holder)!;
  await rejects(env.app.send.postChunk({ sender: outsider.account, args: { committee: c1, nominator: first.nominator, a: Buffer.alloc(1), b: Buffer.alloc(1), c: Buffer.alloc(1), d: Buffer.alloc(1) } }), 'Not the holder');
  await rejects(env.app.send.postChunk({ sender: first.holder.account, args: { committee: c1, nominator: first.nominator, a: Buffer.alloc(1), b: Buffer.alloc(1), c: Buffer.alloc(1), d: Buffer.alloc(1) } }), 'Finalized');
  assert.equal((await env.reader.committee(c1))!.finalized, BigInt(seats1.length));

  // Committee c2 rebuilds every message from blocks (checked against the on-chain digests), drops what fails to
  // decode or verify, and combines the first t valid dealings per bucket.
  const messages = new Map<number, Message>();
  for (const s of await env.reader.seats(c1)) {
    const bytes = await env.reader.message(c1, s.nominator, s.value);
    assert.deepEqual(bytes, posted.get(s.seat));
    try { messages.set(s.seat, decodeMessage(bytes, s.seat, seats2.length, t)); } catch { assert.equal(s.seat, cheater.seat); }
  }
  const next = receive(messages, state.pub, c1, buckets, keys2, t, seats2.map(s => ({ seat: s.seat, x: s.keys.x })));
  assert.deepEqual(next.lost, []);
  assert.ok(!next.used.get(1n)!.includes(cheater.seat));
  const shares = (b: bigint) => next.holders.map(h => ({ seat: h.seat, share: h.shares.get(b)! }));
  assert.ok(reconstruct(next.pub.get(1n)!, shares(1n), t).equals(genesis.secret));
  reconstruct(next.pub.get(2n)!, shares(2n), t); // The committee-generated bucket is consistent with its commitments.

  // Old records go once the epoch is over.
  await rejects(env.app.send.deleteSeats({ args: { committee: c1, nominators: seats1.map(s => s.nominator) } }), 'Committee still active');
  await env.nextRoundIs((c1 + 1n) * E);
  await env.app.send.deleteSeats({ args: { committee: c1, nominators: seats1.map(s => s.nominator) } });
  await env.app.send.deleteCommittee({ args: { committee: c1 } });
  assert.equal(await env.reader.committee(c1), undefined);
  assert.deepEqual(await env.reader.seats(c1), []);
});

/** The seed for committee c, copying it into state first if nobody has (a short validity window lets `block` reach it). */
async function captured(env: Env, committee: bigint) {
  const existing = await env.reader.committee(committee);
  if (existing) return existing.seed;
  await env.app.send.captureSeed({ args: { committee }, ...(await shortWindow()) });
  return (await env.reader.committee(committee))!.seed;
}

test('parameters are checked at creation, and the app cannot be updated, deleted or opted into', async () => {
  const admin = algorand.account.random();
  await algorand.account.ensureFunded(admin, await algorand.account.localNetDispenser(), algo(10));
  const factory = algorand.client.getTypedAppFactory(EpochCommitteeFactory, { defaultSender: admin.addr });
  const create = (epochRounds: bigint, nominationRounds: bigint, handoverRounds: bigint) =>
    factory.send.create.createApplication({ args: { epochRounds, nominationRounds, handoverRounds, nominatorThreshold: 1n } });
  await rejects(create(60n, 30n, 30n), 'Epoch too short');
  await rejects(create(5000n, 991n, 30n), 'Nomination window too long');
  const { appClient } = await create(60n, 20n, 20n);
  const program = '#pragma version 11\npushint 1\nreturn';
  const refused = 'logic eval error|rejected by ApprovalProgram';
  await rejects(algorand.send.appUpdate({ sender: admin, appId: appClient.appId, approvalProgram: program, clearStateProgram: program }), refused);
  await rejects(algorand.send.appDelete({ sender: admin, appId: appClient.appId }), refused);
  await rejects(algorand.send.appCall({ sender: admin, appId: appClient.appId, onComplete: 1 }), refused);
});
