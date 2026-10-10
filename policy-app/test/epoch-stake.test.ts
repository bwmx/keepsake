import assert from 'node:assert/strict';
import { test } from 'node:test';
import { algo, microAlgo } from '@algorandfoundation/algokit-utils';
import { VerifyPool } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/parallel.js';
import { ticketCount, windows } from '../src/epochs.js';
import { algod, algorand, cover, deploy, lastRound, rejects, runUntil, startWorkers, type Member, type WorkerEvent } from './epoch-env.js';

test('stake-weighted sortition: seats track bonds over many epochs; no bond or no online stake, no seats; bond changes wait an epoch; members pay for every box', async () => {
  const E = 160n, t = 3, K = 10n, tickets = 32n;
  const stakes = [1, 1, 1, 2, 2, 3, 4, 6]; // Algos bonded; each member keeps 20 more online, so its weight is its bond.
  const env = await deploy({ members: stakes.length, stakes, tickets, threshold: 2n ** 63n, epochRounds: E, nominationRounds: 40n,
    // Dev-mode LocalNet takes a round per transaction: about three per seat (claim, chunks, finalize) plus key posts.
    handoverRounds: 100n, shareThreshold: BigInt(t) });
  // Two more members run workers but hold no weight: one online with no bond, one bonded with no online stake.
  const unbonded = await env.addMember(stakes.length, 0), offline = await env.addMember(stakes.length + 1, 5, false);
  env.members.push(unbonded, offline);
  const G = env.params.genesisCommittee, W = algo(stakes.reduce((a, b) => a + b, 0) + 5).microAlgo;
  const pool = new VerifyPool(4), events: WorkerEvent[] = [];
  const workers = await startWorkers(env, pool, events);
  const weight = (m: Member) => env.app.weight({ args: { nominator: m.index } });
  const attempt = (m: Member) => env.app.send.nominate({ ...cover, sender: m.account, args: { nominator: m.index, ticket: 0n,
    proof: new Uint8Array(80), epk: new Uint8Array(96), sigKey: new Uint8Array(32), sealedSeed: new Uint8Array(80),
    payment: algorand.createTransaction.payment({ sender: m.account, receiver: env.app.appAddress, amount: microAlgo(env.seatDeposit) }) } });

  // Seats per nominator in committees G .. G + K − 1, read once each committee's nominations close.
  const seats = new Map<bigint, number[]>();
  const tally = async () => {
    const round = await lastRound();
    for (let c = G; c < G + K; c++) {
      if (seats.has(c) || round <= windows(env.params, c - 1n).nominate[1]) continue;
      const counts = env.members.map(() => 0);
      for (const s of await env.reader.seatIds(c)) counts[Number(s.nominator)]!++;
      seats.set(c, counts);
    }
    return seats.size === Number(K);
  };

  try {
    // Inside a nomination window, the two weightless members hold no ticket.
    await runUntil(env, workers, async () => {
      const w = windows(env.params, (await lastRound()) / E), next = (await lastRound()) + 1n;
      return (await lastRound()) / E >= G - 1n && next >= w.nominate[0] && next < w.nominate[1];
    });
    assert.deepEqual(await weight(unbonded), [0n, W]);
    assert.deepEqual(await weight(offline), [0n, W]);
    await rejects(attempt(unbonded), 'No such ticket');
    await rejects(attempt(offline), 'No such ticket');
    await runUntil(env, workers, tally);

    // Bond changes count from the next epoch: a new bond starts there, and a withdrawal is paid out at once.
    const e = (await lastRound()) / E, two = algo(2).microAlgo, five = algo(5).microAlgo;
    await env.app.send.addBond({ sender: unbonded.account, args: {
      payment: algorand.createTransaction.payment({ sender: unbonded.account, receiver: env.app.appAddress, amount: microAlgo(two) }) } });
    const balance = async (m: Member) => (await algod.accountInformation(m.account).do()).amount, before = await balance(offline);
    const { transaction } = await env.app.send.withdrawBond({ ...cover, sender: offline.account, args: { amount: five } });
    assert.equal((await balance(offline)) - before, five - transaction.fee);
    await rejects(env.app.send.withdrawBond({ ...cover, sender: offline.account, args: { amount: 1n } }), 'Bond too small');
    assert.deepEqual(await weight(unbonded), [0n, W]);
    await runUntil(env, workers, async () => (await lastRound()) / E > e);
    const [w, total] = await weight(unbonded);
    assert.deepEqual([w, total], [two, W - five + two]);
    assert.ok(ticketCount(w, total, tickets) > 0n);
  } finally {
    await Promise.all(workers.map(w => w.stop()));
    await pool.close();
  }

  // Seats track bonds: each member's count within 4 standard deviations of its expectation, and the fit's slope near 1.
  // A member with weight w holds ⌈w · tickets / W⌉ tickets, each winning with probability ½ (the last one in proportion).
  const units = (s: number) => algo(s).microAlgo * tickets; // weight × tickets; one ticket is W of these
  const chances = (s: number) => {
    const out: number[] = [];
    for (let left = units(s); left > 0n; left -= W) out.push(0.5 * Number(left < W ? left : W) / Number(W));
    return out;
  };
  const observed = stakes.map((_, i) => [...seats.values()].reduce((n, counts) => n + counts[i]!, 0));
  const expected = stakes.map(s => Number(K) * chances(s).reduce((a, p) => a + p, 0));
  const sd = stakes.map(s => Math.sqrt(Number(K) * chances(s).reduce((a, p) => a + p * (1 - p), 0)));
  console.log(stakes.map((s, i) => `stake ${s}: ${observed[i]} seats (expected ${expected[i]!.toFixed(1)} ± ${sd[i]!.toFixed(1)})`).join('\n'));
  stakes.forEach((s, i) => assert.ok(Math.abs(observed[i]! - expected[i]!) <= 4 * sd[i]!, `stake ${s}: ${observed[i]} seats, expected ${expected[i]}`));
  const slope = observed.reduce((a, o, i) => a + o * expected[i]!, 0) / expected.reduce((a, x) => a + x * x, 0);
  assert.ok(slope > 0.8 && slope < 1.2, `slope ${slope}`);
  assert.ok([...seats.values()].every(counts => counts[stakes.length] === 0 && counts[stakes.length + 1] === 0), 'weightless members nominated');

  // Holders with several seats spoke once per seat, and no bucket was lost.
  assert.deepEqual(events.filter(e => e.error), [], 'workers reported errors');
  const received = events.filter(e => e.received);
  assert.ok(received.length > 0 && received.every(e => e.lost === ''));
  const held = new Map<string, number>();
  for (const e of events.filter(e => e.seat)) held.set(`${e.member}:${e.seat}`, (held.get(`${e.member}:${e.seat}`) ?? 0) + 1);
  assert.ok([...held.values()].some(n => n >= 2), 'some member held several seats');
  // The app holds bonds beyond its boxes' deposits and nothing else: members paid for every box.
  const account = await algod.accountInformation(env.app.appAddress).do();
  assert.equal(account.amount - account.minBalance, (await env.app.state.global.nextBondTotal())!);
});
