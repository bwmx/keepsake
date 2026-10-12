import assert from 'node:assert/strict';
import { test } from 'node:test';
import { secretKeyToMnemonic } from 'algosdk';
import { VerifyPool } from 'keepsake-crypto/dist/src/parallel.js';
import { startEpochWorker } from '../src/epoch-worker.js';
import { windows } from '../src/epochs.js';
import { deploy, lastRound, type Member, type WorkerEvent } from './epoch-env.js';

const ALGOD = { server: 'http://localhost', port: 4001, token: 'a'.repeat(64) };

test('joining after genesis: a restarted member and a newly enrolled one take the attested state, agree on every later handover, and speak for the seats they hold', async () => {
  const E = 120n, t = 3;
  const env = await deploy({ members: 6, epochRounds: E, nominationRounds: 40n, handoverRounds: 60n, threshold: 2n ** 64n - 1n, shareThreshold: BigInt(t) });
  const G = env.params.genesisCommittee, pool = new VerifyPool(4), events: WorkerEvent[] = [];
  const start = (m: Member) => startEpochWorker({ pins: env.pins, algod: ALGOD, memberMnemonic: secretKeyToMnemonic(m.account.account.sk),
    vrfSecretKey: m.vrfSecretKey, pool, pollMs: 0, event: e => void lastRound().then(round => events.push({ member: Number(m.index), round, ...e })) });
  const workers = new Map<number, Awaited<ReturnType<typeof start>>>();
  for (const m of env.members) workers.set(Number(m.index), await start(m));
  const received = (c: bigint) => new Set(events.filter(e => e.received === c.toString()).map(e => e.member));
  const until = async (done: () => boolean | Promise<boolean>) => {
    while (!(await done())) { await Promise.all([...workers.values()].map(w => w.step())); await env.tick(); }
  };
  const epoch = async () => (await lastRound()) / E;
  let restart = 0n;

  try {
    await until(() => received(G + 1n).size === 6);
    // Member 5 crashes: its process, its vaults and its history are gone. A new member enrolls and starts at once.
    await workers.get(5)!.stop();
    workers.delete(5);
    const late = await env.addMember(6);
    env.members.push(late);
    workers.set(6, await start(late));
    // An epoch later member 5 restarts with nothing in memory.
    restart = (await epoch()) + 1n;
    await until(async () => (await epoch()) >= restart);
    workers.set(5, await start(env.members[5]!));
    await until(() => received(restart + 5n).size === 7);
  } finally {
    await Promise.all([...workers.values()].map(w => w.stop()));
    await pool.close();
  }

  assert.deepEqual(events.filter(e => e.error), [], 'workers reported errors');
  const last = restart + 5n;
  for (const m of [5, 6]) {
    const joined = BigInt(String(events.find(e => e.member === m && e.joined)?.joined));
    assert.ok(joined >= G + 1n && joined <= restart, `member ${m} joined at ${joined}`);
    // From the committee it joined at on, it agrees with everyone on every handover, and nothing is lost.
    for (let c = joined; c <= last; c++) {
      const views = events.filter(e => e.received === c.toString());
      assert.ok(views.some(e => e.member === m), `member ${m} skipped handover ${c}`);
      assert.equal(new Set(views.map(e => e.keys)).size, 1, `members disagree at ${c}`);
      assert.ok(views.every(e => e.lost === ''), `lost a bucket at ${c}`);
    }
  }
  console.log(`genesis ${G}, restart epoch ${restart}, last ${last}; joined: ${events.filter(e => e.joined).map(e => `#${e.member}@${e.joined}`).join(' ')}; ` +
    `joiners' seats: ${events.filter(e => (e.member === 5 || e.member === 6) && e.seat).map(e => `#${e.member}:${e.seat}`).join(' ')}; ` +
    `#6 nominated ${events.filter(e => e.member === 6 && e.nominated).map(e => e.nominated).join(',')}; handovers seen: ${new Set(events.filter(e => e.received).map(e => e.received)).size}`);
  // Every seat either member opened after joining spoke in its handover.
  const joinedAt = (m: number) => events.findIndex(e => e.member === m && e.joined); // Earlier seat events: the crashed run.
  const opened = events.filter((e, i) => (e.member === 5 || e.member === 6) && e.seat && i > joinedAt(e.member) && BigInt(String(e.seat)) <= last);
  assert.ok(opened.length > 0, 'neither joiner held a seat');
  for (const s of opened) assert.ok(events.some(e => e.member === s.member && e.posted === s.seat && e.number === s.number), `seat ${s.seat}:${s.number} stayed silent`);
  // The new member nominates once its online stake has passed the lookback and its bond counts.
  assert.ok(events.some(e => e.member === 6 && e.nominated), 'the new member never nominated');
  // Old seats are all gone, including those member 5 nominated before it crashed: their deposits came back.
  const w = windows(env.params, last);
  assert.ok((await lastRound()) > w.handover[1]);
  assert.deepEqual((await env.reader.seatIds()).filter(s => s.committee <= last - 3n), []);
});
