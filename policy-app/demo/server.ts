import { createServer, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AccessRequest, Capsule } from 'algorand-ephemeral-capsule-crypto-spike/dist/src/protocol.js';
import { STAGE, slotRange } from '../src/chain.js';
import { ANY_RANK, LocalNetSim } from '../src/sim.js';

/**
 * LOCALNET DEMO SERVER. Plays every party with throwaway accounts and serves the control-room UI on 127.0.0.1.
 * In a real deployment the sender, recipient and each member run their own clients; here one process hosts them.
 */
const PORT = Number(process.env.PORT ?? 8787);
const PUBLIC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../demo/public');

interface DemoCapsule {
  id: bigint;
  message: string;
  tamper: boolean;
  slots: number;
  capsule?: Capsule;
  anchor?: string;
  request?: AccessRequest;
  keys?: { privateKey: CryptoKey };
  recovered?: string;
  failed?: string;
  gone?: boolean;
  busy?: boolean;
  pausedAtOpen?: boolean;
}

let sim: LocalNetSim | undefined;
let starting = false;
let startError: string | undefined;
let settings = { members: 0, nominationRounds: 0n, perSlot: 0 };
const capsules = new Map<string, DemoCapsule>();
const narration: { at: number; text: string; private?: boolean; tone?: 'ok' | 'warn' | 'bad' }[] = [];
const clock = { running: true, rate: 1 };
let seenEvents = 0;

const say = (text: string, o: { private?: boolean; tone?: 'ok' | 'warn' | 'bad' } = {}) => {
  narration.push({ at: Date.now(), text, ...o });
  if (narration.length > 400) narration.splice(0, narration.length - 400);
};

/** The assert message (e.g. "Not open") from an algokit/algod error, without TEAL dumps. */
function reason(e: unknown): string {
  const line = (e instanceof Error ? e.message : String(e)).split('\n')[0] ?? '';
  return (/in transaction \S+: (.+)$/.exec(line)?.[1] ?? /logic eval error: (.+?)(\. Details|$)/.exec(line)?.[1] ?? line).slice(0, 160);
}

async function start(o: { members: number; nominationRounds: number; perSlot: number }) {
  starting = true;
  startError = undefined;
  try {
    await sim?.stop();
    capsules.clear();
    narration.length = 0;
    seenEvents = 0;
    const threshold = o.perSlot >= o.members ? ANY_RANK : (2n ** 64n * BigInt(Math.round(o.perSlot * 1000))) / BigInt(o.members * 1000);
    settings = { members: o.members, nominationRounds: BigInt(o.nominationRounds), perSlot: o.perSlot };
    say(`Deploying a fresh randomness beacon (own VRF key + daemon), the policy app, and enrolling ${o.members} members…`);
    sim = await LocalNetSim.create({ members: o.members, nominationRounds: BigInt(o.nominationRounds), nominatorThreshold: threshold });
    await sim.startMembers();
    say(`Environment ready: beacon app ${sim.beacon.appId}, policy app ${sim.app.appId}, ${o.members} member workers online.`, { tone: 'ok' });
  } catch (e) {
    startError = reason(e);
    say(`Setup failed: ${startError}`, { tone: 'bad' });
  } finally {
    starting = false;
  }
}

// The sender's client: closes nominations after the deadline and anchors the capsule once the committee is fixed.
async function drive() {
  if (!sim || starting) return;
  const round = await sim.lastRound();
  for (const c of capsules.values()) {
    if (c.busy || c.gone || c.failed) continue;
    c.busy = true;
    try {
      const record = await sim.app.getCapsule({ args: { capsuleId: c.id } }).catch(() => undefined);
      if (!record) {
        c.gone = true;
        continue;
      }
      // Pause the round clock once when the access window opens, so a presenter can act before it expires.
      if (!c.pausedAtOpen && record.stage === STAGE.ACTIVE && round >= record.openRound && clock.running) {
        c.pausedAtOpen = true;
        clock.running = false;
        say(`Capsule ${c.id} is open for access until round ${record.expiresRound}. Round clock paused; press Run clock to continue.`, { tone: 'ok' });
      }
      if (record.stage === STAGE.NOMINATING && round + 1n >= record.nominationDeadline) {
        await sim.close(c.id);
        const r = await sim.app.getCapsule({ args: { capsuleId: c.id } });
        say(`Capsule ${c.id}: nominations closed. Committee n = ${r.filled} of ${r.slotCount} slots, threshold ${r.threshold}.`, { tone: 'ok' });
      } else if (record.stage === STAGE.SELECTED) {
        const { capsule, anchor } = await sim.anchor(c.id, new TextEncoder().encode(c.message), { tamper: c.tamper });
        Object.assign(c, { capsule, anchor });
        say(c.tamper
          ? `Capsule ${c.id}: sender anchored a hash that does NOT match the chain data. Holders should refuse.`
          : `Capsule ${c.id}: sender encrypted the message, split the key and posted manifest hash, commitments and ${record.filled} deposits.`,
        { tone: c.tamper ? 'warn' : 'ok' });
      }
    } catch (e) {
      c.failed = reason(e);
      say(`Capsule ${c.id}: ${c.failed}`, { tone: 'bad' });
    } finally {
      c.busy = false;
    }
  }
  for (const e of sim.events.slice(seenEvents)) {
    const who = `Member #${e.member}`;
    if (e.nominated) say(`${who} won VRF sortition and nominated one-time holder keys for capsule ${e.nominated} slot ${e.slot} (public).`);
    if (e.custody) say(`${who} found it holds capsule ${e.custody} slot ${e.slot} and acknowledged via the relayer.`, { private: true });
    if (e.released) say(`${who} released capsule ${e.released} slot ${e.slot} to the bound recipient key via the relayer.`, { private: true });
    if (e.disposed) say(`${who} disposed its share for capsule ${e.disposed} slot ${e.slot} at expiry.`, { private: true });
    if (e.offline) say(`${who} went offline.`, { tone: 'warn' });
  }
  seenEvents = sim.events.length;
}

async function tickLoop() {
  for (;;) {
    if (sim && !starting && clock.running) await sim.tick().catch(() => {});
    await new Promise(r => setTimeout(r, 1000 / clock.rate));
  }
}

async function state() {
  if (!sim || starting) return { ready: false, starting, error: startError, narration: narration.slice(-200), clock };
  const s = sim;
  const round = await s.lastRound();
  const { genesisId } = await s.algorand.client.network();
  const list = [];
  for (const c of [...capsules.values()].reverse()) {
    const record = c.gone ? undefined : await s.app.getCapsule({ args: { capsuleId: c.id } }).catch(() => undefined);
    const holdings = s.holdings(c.id);
    const holderOf = new Map<string, number>();
    for (const [member, held] of holdings) for (const k of held) holderOf.set(k, member);
    const slots = record && record.stage >= STAGE.NOMINATING
      ? (await s.reader.slots(c.id, slotRange(record))).map((x, k) => ({
          k, filled: x.filled, nominator: Number(x.nominator), rank: Number(x.rank) / 2 ** 64,
          deposited: x.deposited, acknowledged: x.acknowledged, released: x.released, holder: holderOf.get(String(k)),
        }))
      : [];
    list.push({
      id: c.id.toString(), message: c.message, tamper: c.tamper, slotCount: c.slots, failed: c.failed, gone: !record,
      recovered: c.recovered, requested: !!c.request, slots,
      record: record && {
        stage: Number(record.stage), seedRound: Number(record.seedRound), deadline: Number(record.nominationDeadline),
        openRound: Number(record.openRound), expiresRound: Number(record.expiresRound), filled: Number(record.filled),
        threshold: Number(record.threshold), minHolders: Number(record.minHolders), acks: Number(record.acks),
        deposits: Number(record.deposits), requested: record.requested, registrySize: Number(record.registrySize),
        randomness: Buffer.from(record.randomness).toString('hex'), manifestHash: Buffer.from(record.manifestHash).toString('hex'),
      },
    });
  }
  return {
    ready: true, clock, round: Number(round), genesisId,
    env: {
      appId: s.app.appId.toString(), beaconAppId: s.beacon.appId.toString(), sender: s.sender.toString(),
      recipient: s.recipient.toString(), relayer: s.relayer.toString(), nominationRounds: Number(settings.nominationRounds),
      perSlot: settings.perSlot,
    },
    members: s.members.map(m => ({ index: m.index, address: m.account.toString(), online: !!m.worker })),
    capsules: list,
    narration: narration.slice(-200),
  };
}

const find = (id: string) => {
  const c = capsules.get(id);
  if (!c) throw new Error('Unknown capsule');
  return c;
};

const actions: Record<string, (body: Record<string, unknown>, id?: string) => Promise<unknown>> = {
  async start(b) {
    if (starting) throw new Error('Already starting');
    void start({ members: Number(b.members ?? 16), nominationRounds: Number(b.nominationRounds ?? 40), perSlot: Number(b.perSlot ?? 3) });
    return {};
  },
  async clock(b) {
    if (typeof b.running === 'boolean') clock.running = b.running;
    if (typeof b.rate === 'number' && b.rate > 0 && b.rate <= 10) clock.rate = b.rate;
    return clock;
  },
  async advance(b) {
    for (let i = 0; i < Math.min(Number(b.rounds ?? 1), 100); i++) await sim!.tick();
    return {};
  },
  async capsule(b) {
    const message = String(b.message ?? '').slice(0, 2000);
    if (!message) throw new Error('Message required');
    const slots = Number(b.slots ?? 9);
    const terms = await sim!.register({ slots, minHolders: Number(b.minHolders ?? 5), openIn: BigInt(Number(b.openIn ?? 20)),
      length: BigInt(Number(b.length ?? 60)) });
    capsules.set(terms.capsuleId.toString(), { id: terms.capsuleId, message, tamper: !!b.tamper, slots });
    say(`Capsule ${terms.capsuleId} registered: ${slots} slots, beacon seed at round ${terms.seedRound}, nominations until ${terms.deadline}, open [${terms.openRound}, ${terms.expiresRound}).`, { tone: 'ok' });
    return { id: terms.capsuleId.toString() };
  },
  async request(b, id) {
    const c = find(id!);
    if (!c.anchor) throw new Error('Not anchored yet');
    const as = b.as === 'outsider' ? sim!.outsider : sim!.recipient;
    const label = b.as === 'outsider' ? 'A different wallet' : c.request ? 'The recipient (again, with a fresh key)' : 'The recipient';
    try {
      const { request, keys } = await sim!.request(c.id, c.anchor, { as });
      Object.assign(c, { request, keys });
      say(`Capsule ${c.id}: recipient bound a fresh X25519 request key on-chain. Holders will encrypt shares only to that key.`, { tone: 'ok' });
    } catch (e) {
      say(`Capsule ${c.id}: ${label} tried to request access → rejected: ${reason(e)}`, { tone: 'warn' });
      throw e;
    }
    return {};
  },
  async recover(_b, id) {
    const c = find(id!);
    if (!c.request || !c.keys || !c.capsule || !c.anchor) throw new Error('Request access first');
    try {
      const { plaintext, releases } = await sim!.recover(c.id, c.anchor, c.capsule.payload, c.request, c.keys.privateKey);
      c.recovered = new TextDecoder().decode(plaintext);
      say(`Capsule ${c.id}: recipient rebuilt the manifest from chain data, verified ${releases} releases and decrypted locally.`, { tone: 'ok' });
    } catch (e) {
      say(`Capsule ${c.id}: recovery failed: ${reason(e)}`, { tone: 'bad' });
      throw e;
    }
    return { plaintext: c.recovered };
  },
  async cleanup(_b, id) {
    await sim!.cleanup(find(id!).id);
    say(`Capsule ${id}: boxes deleted; deposits refunded to the sender. (Chain history still shows everything posted.)`);
    return {};
  },
  async member(b, id) {
    const m = sim!.members[Number(id)];
    if (!m) throw new Error('Unknown member');
    if (b.online) {
      await sim!.startMember(m);
      say(`Member #${m.index} came back online and rescans the chain for its slots.`, { tone: 'ok' });
    } else {
      await sim!.stopMember(m);
    }
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
    if (req.method === 'GET' && url.pathname === '/api/state') return send(res, 200, await state());
    const m = /^\/api\/(\w+)(?:\/(\w+))?$/.exec(url.pathname);
    if (req.method === 'POST' && m && actions[m[1]!]) {
      if (m[1] !== 'start' && (!sim || starting)) throw new Error('Environment not ready');
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

setInterval(() => void drive().catch(() => {}), 500);
void tickLoop();
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => void (sim?.stop() ?? Promise.resolve()).finally(() => process.exit(0)));
}
