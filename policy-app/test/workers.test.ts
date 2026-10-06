import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { setTimeout as sleep } from 'node:timers/promises';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { Algodv2, secretKeyToMnemonic } from 'algosdk';
import { ChainReader, slotRange, type ChainPins } from '../src/chain.js';
import { ANY_RANK } from '../src/sim.js';
import {
  STAGE, closeAt, record, seed, waitFor, waitStage, winners, withSim, type CapsuleTerms, type LocalNetSim,
} from './localnet.js';

const plaintext = new TextEncoder().encode('Synthetic LocalNet secret');
const RATE = 2n ** 61n; // About 1/8 of members eligible per slot: with 24 members ~3 per slot, so a slot may stay empty.

/** All eligible members have had several polls to nominate and nothing has changed for 3 s. */
async function nominationsSettled(sim: LocalNetSim, c: CapsuleTerms) {
  let last = '';
  let since = Date.now();
  await waitFor('settled nominations', async () => {
    const slots = await sim.reader.slots(c.capsuleId, slotRange({ slotCount: BigInt(c.slots) }));
    const state = JSON.stringify(slots.map(s => s.filled && [s.nominator.toString(), s.rank.toString()]));
    if (state !== last) [last, since] = [state, Date.now()];
    return slots.some(s => s.filled) && Date.now() - since > 3000;
  });
}

test('step 5 end to end: 24 members, 16 slots, variable committee, majority threshold, hidden holders, restart', () =>
  withSim({ members: 24, nominationRounds: 60n, nominatorThreshold: RATE }, async sim => {
    await sim.startMembers();
    const c = await sim.register({ slots: 16, minHolders: 9, openIn: 40n, length: 30n });
    const id = c.capsuleId;
    await seed(sim, c);
    await nominationsSettled(sim, c);
    // Each slot went to its lowest-ranked eligible member; a slot is empty exactly when nobody was eligible.
    const best = await winners(sim, id, 16, RATE);
    (await sim.reader.slots(id, slotRange({ slotCount: 16n }))).forEach((s, k) =>
      assert.equal(s.filled ? Number(s.nominator) : undefined, best[k], `slot ${k}`));
    await closeAt(sim, c);
    const { filled, threshold } = await record(sim, id);
    assert.equal(threshold, filled / 2n + 1n);
    const { capsule, anchor } = await sim.anchor(id, plaintext);
    await waitStage(sim, id, STAGE.ACTIVE);
    await waitFor('every holder acknowledged', async () => (await record(sim, id)).acks === filled);

    // Operator-local logs (not chain data): every filled slot is held by exactly one member.
    const holdings = sim.holdings(id);
    assert.equal([...holdings.values()].flat().length, Number(filled));

    // Take holders offline while at least `threshold` slots stay held (a member may hold several).
    let lost = 0;
    const offline = [...holdings].sort((a, b) => a[1].length - b[1].length)
      .filter(([, held]) => lost + held.length <= Number(filled - threshold) && (lost += held.length) > 0)
      .map(([index]) => sim.members[index]!);
    assert.ok(offline.length >= 2);
    for (const m of offline) await sim.stopMember(m);

    await sim.advancePast(c.openRound - 1n);
    const { request, keys } = await sim.request(id, anchor);
    const released = async () => (await sim.reader.slots(id, slotRange({ slotCount: 16n }))).filter(s => s.released).length;
    await waitFor('releases from online holders', async () => (await released()) === Number(filled) - lost);
    const result = await sim.recover(id, anchor, capsule.payload, request, keys.privateKey);
    assert.deepEqual(result.plaintext, plaintext);

    // On-chain, members only enrolled and nominated; every acknowledgment and release came from the relayer.
    const target = await sim.lastRound();
    await waitFor('indexer', async () => (await sim.algorand.client.indexer.makeHealthCheck().do()).round >= target);
    const { transactions } = await sim.algorand.client.indexer.searchForTransactions().applicationID(sim.app.appId).limit(1000).do();
    const selector = (name: string) => Buffer.from(sim.app.appClient.getABIMethod(name).getSelector()).toString('hex');
    const custodyCalls = [selector('acknowledgeCustody'), selector('postRelease')];
    const memberCalls = [selector('enroll'), selector('nominate')];
    const memberAddresses = sim.members.map(m => m.account.toString());
    let custodyCount = 0;
    for (const txn of transactions) {
      const method = Buffer.from(txn.applicationTransaction?.applicationArgs?.[0] ?? []).toString('hex');
      if (custodyCalls.includes(method)) {
        custodyCount++;
        assert.equal(txn.sender, sim.relayer.toString());
      }
      if (memberAddresses.includes(txn.sender)) assert.ok(memberCalls.includes(method), `member sent ${method}`);
    }
    assert.equal(custodyCount, Number(filled) * 2 - lost);

    // Deposits live on-chain, so a member that comes back regains its slots from chain data and its long-term
    // nomination key (the forward-secrecy caveat), then releases them too.
    const back = offline[0]!;
    await sim.startMember(back);
    await waitFor('custody regained', async () => (await released()) === Number(filled) - lost + holdings.get(back.index)!.length);

    // Workers dispose at expiresRound by watching rounds; the delivered responses still decrypt.
    await sim.advancePast(c.expiresRound);
    const online = [...holdings].filter(([index]) => sim.members[index]!.worker);
    await waitFor('disposal', async () => online.every(([index, held]) =>
      sim.events.filter(e => e.member === index && e.disposed === id.toString()).length >= held.length));
    assert.deepEqual((await sim.recover(id, anchor, capsule.payload, request, keys.privateKey)).plaintext, plaintext);
  }));

test('holders refuse custody when the anchored hash does not match the chain data, so the capsule never activates', () =>
  withSim({ members: 8, nominationRounds: 40n }, async sim => {
    await sim.startMembers();
    const c = await sim.register({ slots: 5 });
    await seed(sim, c);
    await nominationsSettled(sim, c);
    await closeAt(sim, c);
    await sim.anchor(c.capsuleId, plaintext, { tamper: true });
    await sleep(3000);
    const r = await record(sim, c.capsuleId);
    assert.deepEqual([r.stage, r.acks], [STAGE.ANCHORED, 0n]);
    assert.ok(!sim.events.some(e => e.custody));
  }));

test('the chain reader fails closed; the worker CLI starts only with matching enrolled keys', () => withSim({ members: 3 }, async sim => {
  const algod = sim.algorand.client.algod;
  const reader = (pins: Partial<ChainPins>, client = algod) => new ChainReader(client, { ...sim.pins, ...pins });
  assert.ok((await reader({}).lastRound()) > 0n);
  await assert.rejects(reader({ genesisHash: Buffer.alloc(32).toString('base64') }).lastRound(), /Wrong network/);
  await assert.rejects(reader({}, new Algodv2('a'.repeat(64), 'http://127.0.0.1', 1)).lastRound());
  await sleep(1100); // Dev-mode LocalNet is idle, so its last round ages.
  await assert.rejects(reader({ maxRoundAgeMs: 1000 }).lastRound(), /stale/);
  await assert.rejects(reader({}).capsule(999_999_999n));

  const m = sim.members[0]!;
  const cli = (nominationSeed: Uint8Array) => {
    const child = spawn(process.execPath, [path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/worker.js')], {
      stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: process.env.PATH ?? '', ALGOD_SERVER: 'http://localhost', ALGOD_PORT: '4001',
        ALGOD_TOKEN: 'a'.repeat(64), GENESIS_HASH: sim.pins.genesisHash, APP_ID: sim.pins.appId.toString(),
        BEACON_APP_ID: sim.pins.beaconAppId.toString(), MAX_ROUND_AGE_MS: '0', MEMBER_MNEMONIC: secretKeyToMnemonic(m.account.account.sk),
        VRF_SECRET_KEY: Buffer.from(m.vrfSecretKey).toString('base64'), NOMINATION_SEED: Buffer.from(nominationSeed).toString('base64'),
        RELAYER_MNEMONIC: secretKeyToMnemonic(sim.relayer.account.sk) } });
    return { child, first: createInterface({ input: child.stdout! })[Symbol.asyncIterator]().next() };
  };
  const good = cli(m.nominationSeed);
  assert.deepEqual(JSON.parse((await good.first).value as string), { ready: m.account.toString() });
  good.child.kill('SIGTERM');
  const bad = cli(new Uint8Array(32).fill(9));
  const stderr: string[] = [];
  bad.child.stderr!.on('data', d => stderr.push(String(d)));
  assert.equal(await new Promise(resolve => bad.child.on('exit', resolve)), 1);
  assert.match(stderr.join(''), /Enrolled keys differ/);
}));
