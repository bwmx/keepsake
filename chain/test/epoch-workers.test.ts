import assert from 'node:assert/strict';
import { test } from 'node:test';
import { secretKeyToMnemonic } from 'algosdk';
import { reconstruct } from 'keepsake-crypto/dist/src/ecpss.js';
import { VerifyPool } from 'keepsake-crypto/dist/src/parallel.js';
import type { G2Point } from 'keepsake-crypto/dist/src/pvss.js';
import { startEpochWorker } from '../src/epoch-worker.js';
import { bucketsNeeded, windows } from '../src/epochs.js';
import { algod, algorand, deploy, lastRound } from './epoch-env.js';

const ALGOD = { server: 'http://localhost', port: 4001, token: 'a'.repeat(64) };
type Event = { member: number; round: bigint } & Record<string, string | number | bigint>;

test('workers run 22 handovers on LocalNet: every bucket survives changing committees and outages; one message per seat, no relayer', async () => {
  const E = 120n, t = 3;
  const env = await deploy({ members: 10, epochRounds: E, nominationRounds: 40n, handoverRounds: 60n, threshold: 2n ** 64n - 1n, shareThreshold: BigInt(t) });
  const G = env.params.genesisCommittee, last = G + 21n;
  const pool = new VerifyPool(4);
  const events: Event[] = [];
  let round = 0n;
  const workers = await Promise.all(env.members.map(m => startEpochWorker({
    pins: env.pins, algod: ALGOD, memberMnemonic: secretKeyToMnemonic(m.account.account.sk), vrfSecretKey: m.vrfSecretKey, pool, pollMs: 0, audit: true,
    event: e => events.push({ member: Number(m.index), round, ...e }),
  })));
  // Outages within the liveness margin: everyone is nominated each epoch (10 seats, t = 3), at most two members off.
  const outages: [number, bigint, bigint][] = [[2, G + 3n, G + 5n], [5, G + 8n, G + 9n], [7, G + 8n, G + 10n], [1, G + 14n, G + 16n]];
  const offline = (i: number, epoch: bigint) => outages.some(([m, from, to]) => m === i && epoch >= from && epoch < to);

  // Each bucket's secret, reconstructed from the shares of every committee that holds it.
  const secrets = new Map<bigint, Map<bigint, G2Point>>();
  const capture = (c: bigint) => {
    const views = workers.map(w => w.view(c)).filter(v => v !== undefined);
    if (!views.length || secrets.has(c)) return;
    const shares = views.flatMap(v => v.holders ?? []); // Audit mode: the vaults report their shares.
    secrets.set(c, new Map([...views[0]!.pub].map(([b, sharing]) =>
      [b, reconstruct(sharing, shares.filter(h => h.shares.has(b)).map(h => ({ seat: h.seat, share: h.shares.get(b)! })))])));
  };

  try {
    // Lockstep: every online worker steps at each round, then the chain advances by at least one round.
    while ((round = await lastRound()) <= windows(env.params, last).handover[1] + 1n) {
      const epoch = round / E;
      await Promise.all(workers.filter((_, i) => !offline(i, epoch)).map(w => w.step()));
      for (let c = G + 1n; c <= last + 1n; c++) capture(c);
      await env.tick();
    }
    await Promise.all(workers.map(w => w.step())); // Everyone back online catches up.
    capture(last + 1n);
  } finally {
    await Promise.all(workers.map(w => w.stop()));
    await pool.close();
  }

  assert.deepEqual(events.filter(e => e.error), [], 'workers reported errors');
  // Nominators deleted their old seats, recovering the deposits; recent ones remain for catch-up. The app holds bonds
  // beyond its boxes' deposits and nothing else: members paid for every box.
  assert.deepEqual(await env.reader.seatIds(G), []);
  assert.ok((await env.reader.seatIds(last)).length > 0);
  const g = env.app.state.global, account = await algod.accountInformation(env.app.appAddress).do();
  assert.equal(account.amount - account.minBalance, (await g.nextBondTotal())! + (await g.unbondingTotal())! + (await g.slashedTotal())!);
  // Every member, including the ones that were offline, processed every handover, lost nothing and agrees on the keys.
  for (let c = G; c <= last; c++) {
    const received = events.filter(e => e.received === c.toString());
    assert.equal(new Set(received.map(e => e.member)).size, workers.length, `handover ${c}`);
    assert.ok(received.every(e => e.lost === ''), `lost a bucket at ${c}`);
    assert.equal(new Set(received.map(e => e.keys)).size, 1, `members disagree at ${c}`);
    // The next committee holds exactly the scheduled buckets: new ones appear, ended ones are gone.
    const keys = new Map(String(received[0]!.keys).split(',').map(kv => kv.split(':') as [string, string]));
    assert.deepEqual([...keys.keys()].map(BigInt), bucketsNeeded(env.params, c + 1n), `buckets after ${c}`);
  }
  // A bucket's public key and secret never change while it lives.
  const publicKeys = new Map<string, string>();
  for (const e of events.filter(e => e.received)) {
    for (const [b, key] of String(e.keys).split(',').filter(Boolean).map(kv => kv.split(':') as [string, string])) {
      assert.equal(publicKeys.get(b) ?? key, key, `bucket ${b} changed key`);
      publicKeys.set(b, key);
    }
  }
  const firstSeen = new Map<bigint, G2Point>();
  for (const [c, byBucket] of secrets) {
    for (const [b, secret] of byBucket) {
      assert.ok((firstSeen.get(b) ?? secret).equals(secret), `bucket ${b} secret changed by committee ${c}`);
      firstSeen.set(b, secret);
    }
  }
  assert.ok(secrets.size >= 20 && [...secrets.values()].some(m => m.size >= 2));

  // From the indexer: each seat's claim and finalize came once, from its own holder (a member, no relayer), after
  // that member posted its key for the next epoch (§3.1.3 step 4); nobody spoke while offline.
  const indexer = algorand.client.indexer;
  await new Promise(r => setTimeout(r, 1500));
  const txns = [];
  let next: string | undefined;
  do {
    const page = await (next ? indexer.searchForTransactions().applicationID(env.app.appId).limit(1000).nextToken(next) : indexer.searchForTransactions().applicationID(env.app.appId).limit(1000)).do();
    txns.push(...page.transactions);
    next = page.nextToken;
  } while (next);
  const selector = (name: string) => Buffer.from(env.app.appClient.getABIMethod(name).getSelector()).toString('hex');
  const members = new Map(env.members.map(m => [m.account.toString(), Number(m.index)]));
  const keyPosts = new Map<string, bigint>(); // "member:epoch" → round
  const claims = new Map<string, { holder: string; round: bigint }>(), finals = new Map<string, number>();
  for (const txn of txns.sort((a, b) => Number(a.confirmedRound! - b.confirmedRound!))) {
    const args = (txn.applicationTransaction?.applicationArgs ?? []).map(a => Buffer.from(a));
    const method = args[0]?.toString('hex');
    if (method === selector('postNominationKey')) keyPosts.set(`${txn.sender}:${args[1]!.readBigUInt64BE(0)}`, txn.confirmedRound!);
    if (![selector('claim'), selector('postChunk'), selector('finalize')].includes(method!)) continue;
    assert.ok(members.has(txn.sender), 'only members speak');
    const seat = `${args[1]!.readBigUInt64BE(0)}:${args[2]!.readBigUInt64BE(0)}:${args[3]!.readBigUInt64BE(0)}`, committee = args[1]!.readBigUInt64BE(0);
    if (method === selector('claim')) {
      assert.ok(!claims.has(seat), `seat ${seat} claimed twice`);
      claims.set(seat, { holder: txn.sender, round: txn.confirmedRound! });
      assert.ok((keyPosts.get(`${txn.sender}:${committee + 1n}`) ?? txn.confirmedRound!) < txn.confirmedRound!, 'key rotation precedes the claim');
      assert.ok(!offline(members.get(txn.sender)!, committee), 'an offline member spoke');
    } else {
      assert.equal(txn.sender, claims.get(seat)?.holder, 'only the seat holder posts');
      if (method === selector('finalize')) finals.set(seat, (finals.get(seat) ?? 0) + 1);
    }
  }
  assert.ok([...finals.values()].every(n => n === 1));
  assert.equal(finals.size, claims.size);
  assert.ok(claims.size >= 20 * (workers.length - 2), 'most seats spoke');
});
