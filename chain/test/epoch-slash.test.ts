import assert from 'node:assert/strict';
import { test } from 'node:test';
import { secretKeyToMnemonic } from 'algosdk';
import { VerifyPool } from 'keepsake-crypto/dist/src/parallel.js';
import { startEpochWorker } from '../src/epoch-worker.js';
import { algod, deploy, lastRound, type Member, type WorkerEvent } from './epoch-env.js';

const ALGOD = { server: 'http://localhost', port: 4001, token: 'a'.repeat(64) };

test('a provably bad dealing is reported by the other members and costs its holder the bond; nothing is lost and the cheater drops out', async () => {
  const E = 120n, t = 3;
  // Eight seats per committee: a single cheater would need six of them to leave fewer than t valid dealings (about
  // 1 in 10,000 per committee). With six seats it needs four, about 1 in 100, and the test then loses a bucket.
  const env = await deploy({ members: 8, epochRounds: E, nominationRounds: 40n, handoverRounds: 60n, threshold: 2n ** 64n - 1n, shareThreshold: BigInt(t) });
  const G = env.params.genesisCommittee, pool = new VerifyPool(4), events: WorkerEvent[] = [], cheater = env.members[7]!, bad = 7;
  // The cheater's vaults deal recipient 1 a bad subshare in each seat's first dealing, under the root they sign.
  const workers = await Promise.all(env.members.map(m => startEpochWorker({ pins: env.pins, algod: ALGOD, pool, pollMs: 0,
    memberMnemonic: secretKeyToMnemonic(m.account.account.sk), vrfSecretKey: m.vrfSecretKey, cheat: m === cheater,
    event: e => void lastRound().then(round => events.push({ member: Number(m.index), round, ...e })) })));
  const bond = async (m: Member) => (await env.app.getMember({ args: { index: m.index } })).nextBond;
  const step = async () => { await Promise.all(workers.map(w => w.step())); await env.tick(); };
  let slashedAt = 0n;
  try {
    while ((await bond(cheater)) > 0n) {
      assert.ok((await lastRound()) / E < G + 8n, 'the cheater was never slashed');
      await step();
    }
    slashedAt = await lastRound();
    // Two more epochs: its zero bond means no tickets and no seats as a nominee.
    while ((await lastRound()) < slashedAt + 2n * E + 80n) await step();
  } finally {
    await Promise.all(workers.map(w => w.stop()));
    await pool.close();
  }

  console.log(events.filter(e => e.reported || e.error || e.received || (e.member === bad && (e.posted || e.seat))).map(e =>
    `${e.round} #${e.member} ${e.reported ? `reported ${e.reported}/${e.dealer}` : e.error ? `ERROR ${e.message}` : e.received ? `received ${e.received} ${e.messages} m${e.margin}` : e.posted ? `posted ${e.posted}` : `seat ${e.seat}`}`).join('\n'));
  const reports = events.filter(e => e.reported);
  assert.ok(reports.length >= 1 && reports.every(e => e.member !== bad), 'honest members reported');
  for (const m of env.members.slice(0, bad)) assert.equal(await bond(m), 1_000_000n, `member ${m.index} kept its bond`);
  assert.deepEqual(events.filter(e => e.error), [], 'workers reported errors');
  // The cheater's dealings were dropped; every handover kept every bucket and all members agree.
  const received = events.filter(e => e.received);
  for (const c of new Set(received.map(e => e.received))) {
    const views = received.filter(e => e.received === c);
    assert.ok(views.every(e => e.lost === '') && new Set(views.map(e => e.keys)).size === 1, `handover ${c}`);
  }
  // Slashed, it wins no tickets and holds no new seats: nominations for committees after the slash exclude it.
  const after = slashedAt / E + 2n; // Committee nominated in the epoch after next.
  assert.ok(!events.some(e => e.member === bad && e.nominated && BigInt(String(e.nominated)) >= after), 'the cheater still nominated');
  assert.ok(!events.some(e => e.member === bad && e.seat && BigInt(String(e.seat)) >= after), 'the cheater still held seats');
  // The app holds bonds, unbonding withdrawals and slashed funds beyond its boxes' deposits, nothing else.
  const g = env.app.state.global, account = await algod.accountInformation(env.app.appAddress).do();
  assert.equal(account.amount - account.minBalance, (await g.nextBondTotal())! + (await g.unbondingTotal())! + (await g.slashedTotal())!);
  assert.equal((await g.slashedTotal())!, 500_000n); // The other half went to the reporter.
});
