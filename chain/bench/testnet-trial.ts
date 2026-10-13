import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { AlgorandClient, Config, algo, microAlgo } from '@algorandfoundation/algokit-utils';
import { nullLogger } from '@algorandfoundation/algokit-utils/types/logging';
import vrf from '@bwmx/algorand-vrf-utils-ts';
import { secretKeyToMnemonic } from 'algosdk';
import { generateEphemeralKey } from 'keepsake-crypto/dist/src/crypto.js';
import { VerifyPool } from 'keepsake-crypto/dist/src/parallel.js';
import { EpochCommitteeClient, EpochCommitteeFactory } from '../smart_contracts/artifacts/epoch_committee/EpochCommitteeClient.js';
import { CAPSULE_DEPOSIT, assertLive, bucketKey, capsuleLabel, openCapsule, sealCapsule } from '../src/epoch-capsules.js';
import { startEpochWorker } from '../src/epoch-worker.js';
import { EpochReader, windows, type EpochParams } from '../src/epochs.js';

/**
 * TESTNET TRIAL (docs/results.md). Runs the epoch design on TestNet through a shared public algod node:
 * funds throwaway member accounts from TESTNET_MNEMONIC, brings them online with dummy participation keys, deploys
 * EpochCommittee, enrolls them with small bonds, runs their workers in this process, locks and opens a capsule, and
 * reports round times, handover timings and fees. Then it returns what it can to the funder. Enrollment deposits stay
 * in the app for good (no exit), as do the app's own minimum balance and the creator's global-state deposit.
 *
 * Throwaway keys go to .testnet-trial.json (git-ignored, or TRIAL_STATE) so `npm run trial -- cleanup` can recover an
 * interrupted run.
 * The funder's mnemonic is read from the environment and never printed. Refuses any network but TestNet.
 */
Config.configure({ logger: nullLogger });
const ALGOD = { server: process.env.ALGOD_SERVER ?? 'https://testnet-api.algonode.cloud', token: process.env.ALGOD_TOKEN ?? '' };
const INDEXER = { server: process.env.INDEXER_SERVER ?? 'https://testnet-idx.algonode.cloud', token: '' };
const STATE = process.env.TRIAL_STATE ?? new URL('../../.testnet-trial.json', import.meta.url); // TRIAL_STATE: another run's file.
// Sizes (environment overrides): members, tickets (each wins, so seats per committee), threshold, epoch and window rounds,
// bucket lead in epochs, and Algos bonded and funded per member.
const num = (name: string, fallback: number) => Number(process.env[name] ?? fallback);
const MEMBERS = num('TRIAL_MEMBERS', 5), TICKETS = num('TRIAL_TICKETS', MEMBERS), t = num('TRIAL_T', 2), E = BigInt(num('TRIAL_EPOCH', 60));
const NW = BigInt(num('TRIAL_NOMINATION', 12)), HW = BigInt(num('TRIAL_HANDOVER', 30)), LEAD = BigInt(num('TRIAL_LEAD_EPOCHS', 6));
const BOND = num('TRIAL_BOND', 0.5), FUND = num('TRIAL_FUND', 3), PERSON = 1;
const algorand = AlgorandClient.fromConfig({ algodConfig: ALGOD, indexerConfig: INDEXER });
const algod = algorand.client.algod;
const log = (s: string) => console.log(`[${new Date().toISOString().slice(11, 19)}] ${s}`);
const lastRound = async () => (await algod.status().do()).lastRound;
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
// Waits can last hours; a failed status read (a network blip) just means another poll.
async function untilRound(round: bigint) { while ((await lastRound().catch(() => 0n)) < round) await sleep(2_000); }

interface State {
  appId?: string;
  members: { mnemonic: string; vrf: string }[];
  people: { sender: string; recipient: string };
  capsule?: { id: string; expires: string };
}
type Account = ReturnType<typeof algorand.account.fromMnemonic>;
const save = (s: State) => writeFileSync(STATE, JSON.stringify(s, null, 2), { mode: 0o600 });

const { genesisId, genesisHash } = await algorand.client.network();
if (genesisId !== 'testnet-v1.0') throw new Error(`Refusing to run on ${genesisId}: TestNet only`);
if (!process.env.TESTNET_MNEMONIC) throw new Error('TESTNET_MNEMONIC is required (see ../.env)');
const funder = algorand.account.fromMnemonic(process.env.TESTNET_MNEMONIC);
const balance = async (a: { toString(): string }) => (await algod.accountInformation(a.toString()).do()).amount;

/**
 * Deletes every seat the members nominated, withdraws their bonds, and closes every account to the funder. A member's
 * account is closed only once none of its seats remain (only its key can reclaim their deposits), and the state file is
 * removed only when nothing is left to recover. The epoch length comes from the app, not from this run's settings.
 */
async function cleanup(state: State) {
  const members = state.members.map(m => algorand.account.fromMnemonic(m.mnemonic));
  const people = [state.people.sender, state.people.recipient].map(m => algorand.account.fromMnemonic(m));
  const seatsOf = async (appId: bigint) => (await algod.getApplicationBoxes(appId).do()).boxes.map(b => Buffer.from(b.name))
    .filter(n => n.length === 25 && n[0] === 0x6e /* n */)
    .map(n => ({ committee: n.readBigUInt64BE(1), nominator: n.readBigUInt64BE(9), ticket: n.readBigUInt64BE(17) }));
  const keep = new Set<number>(); // Members whose seats could not all be deleted.
  if (state.appId) {
    const appId = BigInt(state.appId), app = new EpochCommitteeClient({ algorand, appId, defaultSender: funder.addr });
    const epochRounds = (await app.state.global.epochRounds())!;
    if (state.capsule) {
      await untilRound(BigInt(state.capsule.expires));
      await app.send.deleteCapsule({ sender: funder, args: { capsuleId: BigInt(state.capsule.id) }, extraFee: microAlgo(1_000) })
        .then(() => log(`Capsule ${state.capsule!.id} deleted; the sender's deposit is refunded.`), e => log(`Capsule cleanup: ${String(e).slice(0, 120)}`));
    }
    const seats = await seatsOf(appId);
    // Seats stay until their reporting window closes (the contract's REPORT_EPOCHS, 2); bonds stay slashable while
    // they unbond (UNBONDING_EPOCHS, 4).
    const last = seats.reduce((m, s) => (s.committee > m ? s.committee : m), 0n), deletable = (last + 3n) * epochRounds;
    if (last && (await lastRound()) < deletable) {
      log(`Waiting for committee ${last}'s reporting window to close (round ${deletable}) to delete its seats…`);
      await untilRound(deletable);
    }
    for (const [i, member] of members.entries()) {
      const mine = seats.filter(s => s.nominator === BigInt(i));
      for (const c of new Set(mine.map(s => s.committee))) {
        const tickets = mine.filter(s => s.committee === c).map(s => s.ticket);
        for (let j = 0; j < tickets.length; j += 7) {
          await app.send.deleteSeats({ sender: member, coverAppCallInnerTransactionFees: true, maxFee: microAlgo(10_000),
            args: { committee: c, tickets: tickets.slice(j, j + 7) } }).catch(e => log(`Seat cleanup: ${String(e).slice(0, 120)}`));
        }
      }
      const bond = (await app.getMember({ args: { index: BigInt(i) } }).catch(() => undefined))?.nextBond ?? 0n;
      if (bond) await app.send.withdrawBond({ sender: member, args: { amount: bond } }).catch(e => { keep.add(i); log(`Bond withdrawal: ${String(e).slice(0, 120)}`); });
    }
    const unbonding = await Promise.all(members.map(async (_, i) => (await app.getMember({ args: { index: BigInt(i) } }).catch(() => undefined))));
    const ready = unbonding.reduce((r, m) => (m && m.unbonding > 0n && (m.unbondEpoch + 4n) * epochRounds > r ? (m.unbondEpoch + 4n) * epochRounds : r), 0n);
    if (ready > (await lastRound())) { log(`Waiting for the bonds to finish unbonding (round ${ready})…`); await untilRound(ready); }
    for (const [i, member] of members.entries()) {
      if (!unbonding[i]?.unbonding) continue;
      await app.send.claimWithdrawal({ sender: member, coverAppCallInnerTransactionFees: true, maxFee: microAlgo(10_000), args: [] })
        .catch(e => { keep.add(i); log(`Bond claim: ${String(e).slice(0, 120)}`); });
    }
    for (const s of await seatsOf(appId)) if (s.nominator < BigInt(members.length)) keep.add(Number(s.nominator));
  }
  for (const [i, a] of [...members, ...people].entries()) {
    if (keep.has(i)) continue;
    const info = await algod.accountInformation(a.addr).do();
    if (info.amount === 0n) continue;
    if (info.status === 'Online') await algorand.send.offlineKeyRegistration({ sender: a });
    await algorand.send.payment({ sender: a, receiver: funder.addr, amount: microAlgo(0), closeRemainderTo: funder.addr });
  }
  if (keep.size) {
    log(`Members ${[...keep].join(', ')} still hold seats or bonds: their accounts stay open and the state file is kept. Run \`npm run trial -- cleanup\` again later.`);
    return false;
  }
  rmSync(STATE);
  log('Throwaway accounts closed to the funder; trial state removed.');
  return true;
}

if (process.argv.includes('cleanup')) {
  if (!existsSync(STATE)) throw new Error('No trial state to clean up');
  process.exit((await cleanup(JSON.parse(readFileSync(STATE, 'utf8')) as State)) ? 0 : 1);
}
if (existsSync(STATE)) throw new Error('A trial state file exists: run `npm run trial -- cleanup` first, or remove it');

// --- Setup: throwaway accounts (saved before any funding), funded in one group, online with dummy keys.
await vrf.init();
const funderBefore = await balance(funder.addr), started = Date.now(), startRound = await lastRound();
const fresh = () => algorand.account.random();
const memberAccounts = Array.from({ length: MEMBERS }, fresh), vrfKeys = memberAccounts.map(() => vrf.generateKeyPair().secretKey);
const [sender, recipient] = [fresh(), fresh()];
const state: State = {
  members: memberAccounts.map((a, i) => ({ mnemonic: secretKeyToMnemonic(a.account.sk), vrf: Buffer.from(vrfKeys[i]!).toString('base64') })),
  people: { sender: secretKeyToMnemonic(sender.account.sk), recipient: secretKeyToMnemonic(recipient.account.sk) },
};
save(state);
const funding = algorand.newGroup();
for (const a of memberAccounts) funding.addPayment({ sender: funder.addr, receiver: a.addr, amount: algo(FUND) });
for (const a of [sender, recipient]) funding.addPayment({ sender: funder.addr, receiver: a.addr, amount: algo(PERSON) });
await funding.send();
const keyRound = await lastRound();
await Promise.all(memberAccounts.map(a => algorand.send.onlineKeyRegistration({ sender: a, voteKey: randomBytes(32), selectionKey: randomBytes(32),
  stateProofKey: randomBytes(64), voteFirst: keyRound, voteLast: keyRound + 1_000_000n, voteKeyDilution: 10_000n })));
log(`Funded ${MEMBERS} members (${FUND} Algo each) and two capsule parties; members are online with throwaway participation keys.`);

// --- Deploy and enroll. The genesis committee is nominated once the members' online stake has passed the lookback.
const online = (await lastRound()) + 320n;
const params: EpochParams = { epochRounds: E, nominationRounds: NW, handoverRounds: HW, shareThreshold: BigInt(t), bucketRounds: 2n * E,
  bucketLead: LEAD * E, genesisCommittee: (online + 10n) / E + 2n };
const { appClient: app } = await algorand.client.getTypedAppFactory(EpochCommitteeFactory, { defaultSender: funder.addr }).send.create
  .createApplication({ args: { ...params, totalTickets: BigInt(TICKETS), ticketThreshold: 2n ** 64n - 1n } });
state.appId = app.appId.toString();
save(state);
await algorand.send.payment({ sender: funder, receiver: app.appAddress, amount: microAlgo(100_000) });
const [enrollDeposit] = await app.deposits();
for (const [i, a] of memberAccounts.entries()) {
  await app.send.enroll({ sender: a, args: { vrfKey: vrfKeys[i]!.subarray(32),
    payment: algorand.createTransaction.payment({ sender: a.addr, receiver: app.appAddress, amount: microAlgo(enrollDeposit + algo(BOND).microAlgo) }) } });
}
const G = params.genesisCommittee, pins = { genesisHash, appId: app.appId, maxRoundAgeMs: 30_000 };
log(`App ${app.appId}: epochs of ${E} rounds (nominations ${NW}, handover ${HW}), t = ${t}, ${TICKETS} seats per committee, bonds of ${BOND} Algo. ` +
  `Genesis committee ${G} is nominated from round ${(G - 1n) * E}.`);

// --- Workers: one per member, in this process, all on the shared node.
const reader = new EpochReader(algod, pins, params, app.appClient.getABIMethod('postChunk').getSelector());
const pool = new VerifyPool();
const events: ({ member: number; round: bigint; at: number } & Record<string, string | number | bigint>)[] = [];
const workers = await Promise.all(memberAccounts.map((a, i) => startEpochWorker({
  pins, algod: ALGOD, memberMnemonic: state.members[i]!.mnemonic, vrfSecretKey: vrfKeys[i]!, pool, pollMs: 3_000,
  event: e => void lastRound().then(round => {
    events.push({ member: i, round, at: Date.now(), ...e });
    if (e.received) log(`Committee ${e.received} handed over (seen by member ${i}): ${e.messages} messages, margin ${e.margin}${e.lost ? `, LOST ${e.lost}` : ''}`);
    if (e.error) log(`Member ${i}: ${e.error} failed: ${e.message}`);
  }),
})));

let failure: unknown;
try {
  // --- A capsule round trip once a bucket key is attested (giving up six epochs after genesis).
  await untilRound((G + 1n) * E);
  const epoch = async () => (await lastRound()) / E;
  const deadline = (G + 6n) * E;
  let locked: { id: bigint; open: bigint; expires: bigint; payload: ReturnType<typeof sealCapsule>['payload'] } | undefined;
  while (!locked) {
    const round = await lastRound(), bucket = (round + 15n + 2n * E) / params.bucketRounds;
    const key = await bucketKey(reader, bucket, t, (await epoch()) - 1n);
    if (!key && round > deadline) throw new Error(`No bucket key attested by round ${deadline}`);
    if (!key) { await sleep(30_000); continue; }
    await assertLive(reader, round, t, 1);
    // Reading the attested state takes many rounds at full size, so the window starts from the round after it.
    const open = (await lastRound()) + 15n, expires = open + 2n * E;
    if (expires / params.bucketRounds !== bucket) continue; // Crossed into the next bucket meanwhile: look up its key.
    const label = capsuleLabel(app.appId, { sender: sender.addr.toString(), recipient: recipient.addr.toString(), openRound: open, expiresRound: expires });
    const sealed = sealCapsule(key, label, Buffer.from('a synthetic TestNet capsule'));
    const id = (await app.send.registerCapsule({ sender, args: { recipient: recipient.addr.toString(), openRound: open, expiresRound: expires,
      u: sealed.u, proof: sealed.proof, payloadHash: sealed.payloadHash,
      payment: algorand.createTransaction.payment({ sender: sender.addr, receiver: app.appAddress, amount: microAlgo(CAPSULE_DEPOSIT) }) } })).return!;
    locked = { id, open, expires, payload: sealed.payload };
    state.capsule = { id: id.toString(), expires: expires.toString() };
    save(state);
    log(`Capsule ${id} locked under bucket ${bucket}: open [${open}, ${expires}).`);
  }
  await untilRound(locked.open);
  const keys = await generateEphemeralKey(), requestId = randomBytes(16), requested = await epoch(), requestedAt = Date.now();
  await app.send.requestAccess({ sender: recipient, args: { capsuleId: locked.id, requestId, recipientKey: Buffer.from(keys.publicKey, 'base64url') } });
  log(`Capsule ${locked.id}: access requested in epoch ${requested}.`);
  let opened: Uint8Array | undefined;
  while (!opened) {
    await sleep(10_000);
    const round = await lastRound(), now = round / E, latest = round > windows(params, now).handover[1] ? now : now - 1n;
    if (latest >= requested) opened = await openCapsule(reader, pins, locked.id, { requestId, privateKey: keys.privateKey }, locked.payload, t, requested, latest);
  }
  log(`Capsule ${locked.id} opened by its recipient ${((Date.now() - requestedAt) / 1000).toFixed(0)} s after the request: "${Buffer.from(opened).toString()}"`);

  // --- One more handover, then report.
  const finalCommittee = (await epoch()) + 1n;
  while (!events.some(e => e.received === finalCommittee.toString())) await sleep(5_000);
} catch (e) {
  failure = e; // Still report what happened and recover the funds.
  log(`Trial failed: ${e instanceof Error ? e.message : String(e)}`);
} finally {
  await Promise.all(workers.map(w => w.stop()));
  await pool.close();
}

const endRound = await lastRound(), seconds = (Date.now() - started) / 1000;
console.log(`\n## Trial report (app ${app.appId})\n`);
console.log(`- Rounds ${startRound}–${endRound}: ${(seconds / Number(endRound - startRound)).toFixed(2)} s per round over ${(seconds / 60).toFixed(1)} minutes.`);
for (const c of [...new Set(events.filter(e => e.received).map(e => String(e.received)))]) {
  const w = windows(params, BigInt(c)), posts = events.filter(e => e.posted === c), received = events.filter(e => e.received === c);
  const last = posts.reduce((m, e) => (e.round > m ? e.round : m), 0n), first = received.reduce((m, e) => (e.round < m ? e.round : m), received[0]!.round);
  const bytes = posts.reduce((n, e) => n + Number(e.bytes ?? 0), 0);
  console.log(`- Handover ${c}: ${received[0]!.messages} messages (${(bytes / 2 ** 20).toFixed(2)} MiB), margin ${received[0]!.margin}${received[0]!.lost ? `, lost ${received[0]!.lost}` : ''}; ` +
    `last post ${last ? `${last - w.handover[0]} rounds into the ${params.handoverRounds}-round window` : 'none'}; ` +
    `first member done ${first - w.handover[1]} rounds after the window, last ${received.reduce((m, e) => (e.round > m ? e.round : m), 0n) - w.handover[1]}.`);
}
console.log(`- Worker errors: ${events.filter(e => e.error).length}; refused releases: ${events.filter(e => e.refused).length}.`);
await sleep(5_000); // Let the indexer catch up.
const methods = new Map(app.appClient.appSpec.methods.map(m => [Buffer.from(app.appClient.getABIMethod(m.name).getSelector()).toString('base64'), m.name]));
const fees = new Map<string, { n: number; fee: bigint }>();
for (const a of [...memberAccounts, sender, recipient]) {
  let next: string | undefined;
  do {
    const page = await (next ? algorand.client.indexer.searchForTransactions().address(a.addr).addressRole('sender').nextToken(next)
      : algorand.client.indexer.searchForTransactions().address(a.addr).addressRole('sender')).do();
    for (const tx of page.transactions) {
      const arg = tx.applicationTransaction?.applicationArgs?.[0];
      const kind = arg ? methods.get(Buffer.from(arg).toString('base64')) ?? 'app call' : tx.txType ?? 'unknown';
      const f = fees.get(kind) ?? { n: 0, fee: 0n };
      fees.set(kind, { n: f.n + 1, fee: f.fee + tx.fee });
    }
    next = page.nextToken;
  } while (next);
}
for (const [kind, f] of [...fees].sort((a, b) => Number(b[1].fee - a[1].fee))) console.log(`- Fees for ${kind}: ${f.n} transactions, ${(Number(f.fee) / 1e6).toFixed(4)} Algo`);
console.log(`- Total fees: ${(Number([...fees.values()].reduce((s, f) => s + f.fee, 0n)) / 1e6).toFixed(4)} Algo over ${(endRound - (G - 1n) * E) / E} epochs since the genesis nominations.`);

if (!(await cleanup(state))) process.exitCode = 1;
const spent = funderBefore - (await balance(funder.addr));
console.log(`- Net cost to the funder: ${(Number(spent) / 1e6).toFixed(4)} Algo (fees, enrollment deposits and app deposits that stay locked).`);
if (failure) process.exitCode = 1;
