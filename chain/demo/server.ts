import { randomBytes } from 'node:crypto';
import { createServer, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { algo, microAlgo } from '@algorandfoundation/algokit-utils';
import { generateEphemeralKey, type EncryptedPayload } from 'keepsake-crypto/dist/src/crypto.js';
import { VerifyPool } from 'keepsake-crypto/dist/src/parallel.js';
import { CAPSULE_DEPOSIT, payloadHash } from '../src/epoch-capsules.js';
import { bondAt, windows } from '../src/epochs.js';
import { algorand, deploy, lastRound, startWorkers, stepAll, type Env, type WorkerEvent, type Workers } from '../src/epoch-sim.js';

/**
 * LOCALNET DEMO SERVER for Keepsake: evolving epoch committees, drawn by stake-weighted sortition, hold bucket keys and
 * release capsules from their handover messages. This process runs the committee's members (throwaway accounts) and
 * serves the page on 127.0.0.1. Senders and recipients act from the page with their own wallet (demo/client.ts): the
 * plaintext and request keys never reach this server, which stores only ciphertext checked against the hash anchored on
 * chain. An outsider account here plays the attacks (another wallet's request, a copied capsule).
 */
const PORT = Number(process.env.PORT ?? 8787);
const PUBLIC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../demo/public');
const E = 80n;
const STAKES = [1, 2, 3, 5]; // Algos bonded by members in turn.

type Account = Awaited<ReturnType<Env['fund']>>;
const LOCALNET = { algod: { server: 'http://localhost', port: 4001, token: 'a'.repeat(64) }, kmd: { server: 'http://localhost', port: 4002, token: 'a'.repeat(64) } };

let env: Env | undefined, workers: Workers | undefined, pool: VerifyPool | undefined;
let outsider: Account | undefined;
let starting = false, startError: string | undefined;
let settings = { members: 0, committee: 0, t: 0 };
const payloads = new Map<string, EncryptedPayload>(); // Capsule ID → its ciphertext, as uploaded by the sender's page.
const copies = new Map<string, string>(); // Capsule ID → the capsule whose u it copies (the replay attack).
const known = new Set<string>(); // Every capsule seen on chain, so deleted ones still show as cleaned up.
const offline = new Set<number>();
let events: WorkerEvent[] = [];
let seenEvents = 0;
const said = new Set<string>();
const narration: { at: number; text: string; private?: boolean; tone?: 'ok' | 'warn' | 'bad' }[] = [];
const clock = { running: true, rate: 4 };

const say = (text: string, o: { private?: boolean; tone?: 'ok' | 'warn' | 'bad' } = {}) => {
  narration.push({ at: Date.now(), text, ...o });
  if (narration.length > 400) narration.splice(0, narration.length - 400);
};
const once = (key: string, f: () => void) => { if (!said.has(key)) { said.add(key); f(); } };

/** The assert message (e.g. "Not open") from an algokit/algod error, without TEAL dumps. */
function reason(e: unknown): string {
  const line = (e instanceof Error ? e.message : String(e)).split('\n')[0] ?? '';
  return (/in transaction \S+: (.+)$/.exec(line)?.[1] ?? /logic eval error: (.+?)(\. Details|$)/.exec(line)?.[1] ?? line).slice(0, 160);
}

async function start(o: { members: number; committee: number; t: number }) {
  starting = true;
  startError = undefined;
  try {
    await Promise.all(workers?.map(w => w.stop()) ?? []);
    await pool?.close();
    [env, workers, pool] = [undefined, undefined, undefined];
    payloads.clear(); copies.clear(); known.clear(); offline.clear(); narration.length = 0; said.clear();
    events = []; seenEvents = 0;
    settings = o;
    say(`Bringing ${o.members} accounts online for consensus, waiting out the 320-round stake lookback, then deploying the EpochCommittee ` +
      `app; each member enrolls with a bond of ${STAKES.join(', ')} Algos in turn (expected committee ${o.committee}, threshold ${o.t})…`);
    // About one ticket per expected seat, each almost sure to win: committee sizes stay near the target on a demo-sized
    // registry, and a member's seats follow its bond (partial tickets win in proportion).
    const e = await deploy({ members: o.members, stakes: Array.from({ length: o.members }, (_, i) => STAKES[i % STAKES.length]!),
      tickets: BigInt(o.committee), threshold: 2n ** 64n - 1n, epochRounds: E, nominationRounds: 20n, handoverRounds: 55n,
      shareThreshold: BigInt(o.t), bucketRounds: 2n * E, bucketLead: 6n * E });
    outsider = await e.fund();
    pool = new VerifyPool();
    workers = await startWorkers(e, pool, events);
    env = e;
    say(`Ready: app ${e.app.appId}. Committee ${e.params.genesisCommittee} is the genesis committee: it holds nothing and creates the first buckets. ` +
      'Bucket keys are attested about two epochs later; until then capsules cannot be locked. Connect a wallet to send and receive.', { tone: 'ok' });
  } catch (err) {
    startError = reason(err);
    say(`Setup failed: ${startError}`, { tone: 'bad' });
  } finally {
    starting = false;
  }
}

// Workers step in lockstep with the clock (an offline member is skipped and keeps its memory, like a network outage).
// The clock and the advance button share one queue: a worker must never run two steps at once.
let stepping = Promise.resolve();
function advance(rounds = 1) {
  const run = stepping.then(async () => {
    for (let i = 0; i < rounds && env && workers; i++) await stepAll(env, workers, m => !offline.has(m));
    narrate();
  });
  stepping = run.catch(() => {});
  return run;
}

function narrate() {
  for (const e of events.slice(seenEvents)) {
    const who = `Member #${e.member}`;
    if (e.received) {
      const how = e.mode === 'pack' ? ' Each seat packed every bucket into one dealing.' : e.mode === 'unpack' ? ' Each seat re-shared its one packed share, and the next committee unpacked it per bucket.' : '';
      once(`r${e.received}`, () => say(`Committee ${e.received} handed over to committee ${BigInt(String(e.received)) + 1n}: ${e.messages} messages checked by every member.${how} ` +
        `Buckets now held: ${String(e.keys).split(',').filter(Boolean).map(kv => kv.split(':')[0]).join(', ') || 'none'}.${e.lost ? ` LOST: ${e.lost}.` : ''}` +
        (Number(e.margin) <= 0 && !e.lost ? ' Margin 0: one more silent seat would have lost buckets, so new capsules are refused until it recovers.' : ''),
      { tone: e.lost ? 'bad' : Number(e.margin) <= 0 ? 'warn' : 'ok' }));
    }
    if (e.seat) say(`${who} found it holds seat ${e.number} of committee ${e.seat} (trial decryption; nobody else knows).`, { private: true });
    if (e.posted) say(`${who} spoke once for committee ${e.posted} seat ${e.number}: re-sharings${e.releases ? `, partials for capsule ${e.releases}` : ''}. Its shares are erased.`, { private: true });
    if (e.erased) once(`e${e.erased}`, () => say(`Members are erasing their epoch-${e.erased} nomination keys.`, { private: true }));
    if (e.refused) once(`x${e.refused}`, () => say(`Holders refuse capsule ${e.refused}: its proof is bound to another policy (a copied u).`, { tone: 'warn' }));
    if (e.deleted) say(`${who} deleted its ${e.seats} old seat${e.seats === '1' ? '' : 's'} in committee ${e.deleted} and got the deposits back.`, { private: true });
    if (e.error) say(`${who}: ${e.error} failed: ${e.message}`, { tone: 'bad' });
  }
  seenEvents = events.length;
}

async function tickLoop() {
  for (;;) {
    if (env && !starting && clock.running) await advance().catch(e => say(`Clock: ${reason(e)}`, { tone: 'bad' }));
    await sleep(1000 / clock.rate);
  }
}

async function state() {
  if (!env || !workers || starting) return { ready: false, starting, error: startError, narration: narration.slice(-200), clock };
  const round = await lastRound(), epoch = round / E, w = windows(env.params, epoch);
  const received = events.filter(e => e.received);
  const history = [...new Set(received.map(e => String(e.received)))].slice(-6).reverse().map(c => {
    const views = received.filter(e => e.received === c);
    return { committee: c, messages: Number(views[0]!.messages), margin: Number(views[0]!.margin), lost: String(views[0]!.lost), agree: new Set(views.map(v => v.keys)).size === 1,
      buckets: String(views[0]!.keys).split(',').filter(Boolean).map(kv => ({ bucket: kv.split(':')[0], key: kv.split(':')[1]!.slice(0, 10) })) };
  });
  // Capsules come from the chain: the page registers them from the user's wallet.
  const records = await env.reader.capsuleRecords();
  for (const { id } of records) known.add(id.toString());
  const list = [...known].sort((a, b) => Number(b) - Number(a)).map(id => {
    const record = records.find(r => r.id.toString() === id)?.record;
    const releasedBy = events.filter(e => String(e.releases ?? '').split(',').includes(id)).length;
    return { id, copyOf: copies.get(id), gone: !record, releasedBy, refused: events.some(e => e.refused === id), stored: payloads.has(id),
      ...(record ? { sender: record.sender, recipient: record.recipient, open: Number(record.openRound), expires: Number(record.expiresRound),
        bucket: Number(record.bucket), requested: record.requested } : {}) };
  });
  const seats = async (k: bigint) => env!.reader.seats(k).catch(() => []);
  const office = await seats(epoch), next = await seats(epoch + 1n);
  return {
    ready: true, clock, round: Number(round),
    env: { appId: env.app.appId.toString(), epochRounds: Number(E), t: Number(env.params.shareThreshold), genesis: Number(env.params.genesisCommittee),
      bucketRounds: Number(env.params.bucketRounds), members: settings.members, committee: settings.committee },
    epoch: { epoch: Number(epoch), start: Number(epoch * E), nominate: w.nominate.map(Number), handover: w.handover.map(Number), end: Number((epoch + 1n) * E - 1n),
      inOffice: office.length, posted: office.filter(s => s.value.finalized).length, nominated: next.length },
    history,
    members: (await env.reader.members()).map((m, i) => ({ index: i, address: m.account.toString(), online: !offline.has(i),
      bond: Number(bondAt(m, epoch)) / 1e6, seats: workers![i]!.view(epoch)?.seats.length ?? 0,
      nominated: next.filter(s => s.nominator === BigInt(i)).length })),
    capsules: list,
    narration: narration.slice(-200),
  };
}

const record = async (id: string) => {
  const r = await env!.reader.capsuleRecord(BigInt(id)).catch(() => undefined);
  if (!r) throw new Error('No such capsule on chain');
  return r;
};

const actions: Record<string, (body: Record<string, unknown>, id?: string) => Promise<unknown>> = {
  async start(b) {
    if (starting) throw new Error('Already starting');
    const members = Math.min(Math.max(Number(b.members ?? 10), 4), 16);
    // Dev-mode LocalNet takes a round per transaction: about three per seat plus each member's key post fill the handover window.
    void start({ members, committee: Math.min(Math.max(Number(b.committee ?? members), 3), 12), t: Math.max(Number(b.t ?? 3), 1) });
    return {};
  },
  async clock(b) {
    if (typeof b.running === 'boolean') clock.running = b.running;
    if (typeof b.rate === 'number' && b.rate > 0 && b.rate <= 10) clock.rate = b.rate;
    return clock;
  },
  async advance(b) {
    await advance(Math.min(Number(b.rounds ?? 10), 120));
    return {};
  },
  /** Stores a capsule's ciphertext, only if it matches the payload hash its sender anchored on chain. */
  async payload(b, id) {
    const p = { nonce: String(b.nonce), ciphertext: String(b.ciphertext), tag: String(b.tag) };
    if (!payloadHash(p).equals(Buffer.from((await record(id!)).payloadHash))) throw new Error('Ciphertext does not match the hash anchored on chain');
    payloads.set(id!, p);
    return {};
  },
  /** LocalNet only: tops up a wallet account (for example a Lute account) so it can pay deposits and fees. */
  async fund(b) {
    const address = String(b.address ?? '');
    await algorand.account.ensureFunded(address, await algorand.account.localNetDispenser(), algo(10), { minFundingIncrement: algo(10) });
    return {};
  },
  /** A line for the activity log from the page (never the plaintext). */
  async note(b) {
    say(String(b.text ?? '').slice(0, 300), { tone: b.tone === 'warn' ? 'warn' : 'ok' });
    return {};
  },
  async copy(_b, id) {
    const original = await record(id!), round = await lastRound();
    const capsule = (await env!.app.send.registerCapsule({ sender: outsider!, args: {
      recipient: outsider!.toString(), openRound: round + 5n, expiresRound: round + 5n + 2n * E, u: original.u, proof: original.proof,
      payloadHash: Buffer.alloc(32), payment: algorand.createTransaction.payment({ sender: outsider!, receiver: env!.app.appAddress, amount: microAlgo(CAPSULE_DEPOSIT) }),
    } })).return!.toString();
    copies.set(capsule, id!);
    say(`An outsider registered capsule ${capsule} reusing capsule ${id}'s u and proof under its own policy, hoping the committee decrypts it.`, { tone: 'warn' });
    return { id: capsule };
  },
  /** The outsider requests access: to someone else's capsule (refused), or to its own copy (accepted, then never released). */
  async request(_b, id) {
    const keys = await generateEphemeralKey(), requestId = randomBytes(16);
    try {
      await env!.app.send.requestAccess({ sender: outsider!, args: { capsuleId: BigInt(id!), requestId, recipientKey: Buffer.from(keys.publicKey, 'base64url') } });
    } catch (e) {
      say(`Capsule ${id}: a different wallet tried to request access → rejected: ${reason(e)}`, { tone: 'warn' });
      throw e;
    }
    say(`Capsule ${id}: the outsider bound a request key to its copy. Holders will refuse it: the proof belongs to another policy.`, { tone: 'warn' });
    return {};
  },
  async cleanup(_b, id) {
    await env!.app.send.deleteCapsule({ args: { capsuleId: BigInt(id!) }, sender: outsider!, extraFee: microAlgo(1_000) });
    payloads.delete(id!);
    say(`Capsule ${id}: record deleted and the deposit refunded. Its bucket is dropped at the first handover after its window ends.`);
    return {};
  },
  async member(b, id) {
    const i = Number(id);
    if (!env?.members[i]) throw new Error('Unknown member');
    if (b.online) { offline.delete(i); say(`Member #${i} is back: it catches up on the handovers it missed, in order.`, { tone: 'ok' }); }
    else { offline.add(i); say(`Member #${i} went offline (it keeps its memory; its seats stay silent).`, { tone: 'warn' }); }
    return {};
  },
};

const send = (res: ServerResponse, status: number, body: unknown, type = 'application/json') => {
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' });
  res.end(type === 'application/json' ? JSON.stringify(body, (_, v) => (typeof v === 'bigint' ? v.toString() : v)) : (body as Buffer));
};

createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const m = /^\/api\/(\w+)(?:\/(\w+))?$/.exec(url.pathname);
    if (req.method === 'GET' && url.pathname === '/api/state') return send(res, 200, await state());
    if (req.method === 'GET' && url.pathname === '/api/config') {
      if (!env || starting) throw new Error('Environment not ready');
      return send(res, 200, { ...LOCALNET, appId: env.app.appId.toString(), genesisHash: env.pins.genesisHash, t: settings.t,
        params: Object.fromEntries(Object.entries(env.params).map(([k, v]) => [k, v.toString()])) });
    }
    if (req.method === 'GET' && m?.[1] === 'payload') {
      const p = payloads.get(m[2] ?? '');
      return p ? send(res, 200, p) : send(res, 404, { error: 'No ciphertext stored for this capsule' });
    }
    if (req.method === 'POST' && m && actions[m[1]!]) {
      if (m[1] !== 'start' && (!env || starting)) throw new Error('Environment not ready');
      let raw = '';
      for await (const chunk of req) {
        raw += chunk;
        if (raw.length > 16_384) throw new Error('Body too large');
      }
      return send(res, 200, await actions[m[1]!]!(raw ? JSON.parse(raw) : {}, m[2]));
    }
    if (req.method === 'GET') {
      const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
      if (!/^[\w.-]+$/.test(file)) return send(res, 404, { error: 'Not found' });
      const types: Record<string, string> = { html: 'text/html; charset=utf-8', js: 'text/javascript', css: 'text/css' };
      return send(res, 200, await readFile(path.join(PUBLIC, file)), types[file.split('.').pop()!] ?? 'application/octet-stream');
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) {
    send(res, 400, { error: reason(e) });
  }
}).listen(PORT, '127.0.0.1', () => console.log(`Capsule lab: http://127.0.0.1:${PORT}  (LocalNet only)`));

void tickLoop();
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => void Promise.all(workers?.map(w => w.stop()) ?? []).then(() => pool?.close()).finally(() => process.exit(0)));
}
