import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { b64, deriveEphemeralKey, open, seal, unb64 } from './crypto.js';
import { adopt, capsulePartial, decodeMessage, encodeMessage, encodeState, handover, seatKeys, type Holder } from './ecpss.js';
import { decodeG1, decodeG2, decodeProof, encodePartial, seatCommitment } from './pvss.js';
import type { Request, SeatInput, SpeakInput } from './vault.js';

/**
 * A seat vault's process (see vault.ts). It holds one committee's secrets for one member: the nomination key that
 * opens its seats, the seats' one-time keys, and their shares. It exits after building the seats' handover messages,
 * so the operating system reclaims everything before any of them is posted.
 */

/** Where secrets could reach disk: a core dump, or swap that is not encrypted. */
function hostProblems(): string[] {
  const problems: string[] = [];
  if (execFileSync('/bin/sh', ['-c', 'ulimit -c'], { encoding: 'utf8' }).trim() !== '0') problems.push('core dumps are enabled');
  if (process.env.ECPSS_ALLOW_SWAP !== '1') {
    if (process.platform === 'linux' && readFileSync('/proc/swaps', 'utf8').trim().split('\n').length > 1) problems.push('swap is on');
    else if (process.platform === 'darwin' && !execFileSync('sysctl', ['-n', 'vm.swapusage'], { encoding: 'utf8' }).includes('encrypted')) {
      problems.push('swap is not encrypted');
    } else if (process.platform !== 'linux' && process.platform !== 'darwin') problems.push(`no swap check for ${process.platform}`);
  }
  return problems;
}

const audit = process.argv.includes('--audit');
let ikm: Buffer | undefined; // The nomination key's seed: bytes we can wipe, not a WebCrypto key.
const mine: { seat: number; x: bigint; sign: (message: Uint8Array) => Buffer }[] = [];
let holders: Holder[] = [];

/** Trial decryption of every seat's sealed seed; the nomination key is wiped afterwards, whatever happens. */
async function openSeats(seats: SeatInput[]) {
  if (!ikm) throw new Error('Nomination key already erased');
  try {
    const { privateKey } = await deriveEphemeralKey(ikm);
    for (const s of seats) {
      const seed = await open(privateKey, { enc: b64(s.enc), ciphertext: b64(s.ct) }, Buffer.from(s.context)).catch(() => undefined);
      if (!seed) continue;
      const k = seatKeys(seed);
      seed.fill(0);
      if (!k.epk.equals(decodeG2(s.epk)) || !Buffer.from(k.sigKey).equals(Buffer.from(s.sigKey))) continue; // A lying nominator.
      mine.push({ seat: s.seat, x: k.x, sign: k.sign });
    }
  } finally {
    ikm.fill(0);
    ikm = undefined;
  }
  return mine.map(m => m.seat);
}

/** Each held seat's single message, its claim signature, and the capsule partials it releases. */
async function speak(o: SpeakInput) {
  const pub = new Map([...o.pub].map(([b, poly]) => [b, poly.map(decodeG1)])), next = o.next.map(decodeG2), state = encodeState(pub);
  const posts = [];
  for (const h of holders) {
    const releases = new Map<bigint, Uint8Array>(), refused: [bigint, string][] = [];
    for (const c of o.capsules) {
      try {
        const p = capsulePartial(h.shares.get(c.bucket)!, seatCommitment(pub.get(c.bucket)!, h.seat), decodeG1(c.u), decodeProof(c.proof), c.label);
        const sealed = await seal(c.recipientKey, encodePartial(p), Buffer.from(c.contexts.get(h.seat)!));
        releases.set(c.id, Buffer.concat([unb64(sealed.enc), unb64(sealed.ciphertext)]));
      } catch (e) {
        refused.push([c.id, e instanceof Error ? e.message : String(e)]); // E.g. a u copied under another policy.
      }
    }
    const message = encodeMessage({ ...handover(h, pub, o.committee, { live: o.buckets.live.filter(b => pub.has(b)), create: o.buckets.create },
      next, o.t), releases, state });
    posts.push({ seat: h.seat, message, signature: mine.find(m => m.seat === h.seat)!.sign(o.claims.get(h.seat)!), releases: [...releases.keys()], refused });
  }
  return posts;
}

async function handle(r: Request): Promise<unknown> {
  switch (r.op) {
    case 'open': return openSeats(r.seats);
    case 'genesis':
      holders = mine.map(m => ({ seat: m.seat, x: m.x, shares: new Map() }));
      return undefined;
    case 'adopt': {
      const keep = mine.map(m => m.seat);
      const messages = new Map([...r.messages].map(([s, bytes]) => [s, decodeMessage(bytes, s, r.n, r.t, keep)]));
      holders = adopt(messages, r.used, r.buckets, r.t, mine.map(m => ({ seat: m.seat, x: m.x }))).holders;
      // Audit mode (tests): the operator sees its shares. Never in a deployment.
      return audit ? holders.map(h => ({ seat: h.seat, shares: new Map([...h.shares].map(([b, s]) => [b, s.toBytes()])) })) : undefined;
    }
    case 'speak': return speak(r);
  }
}

const problems = hostProblems();
if (problems.length) {
  process.send!({ error: `Refusing to hold secrets: ${problems.join('; ')}` }, () => process.exit(1));
} else {
  ikm = randomBytes(32);
  const { publicKey } = await deriveEphemeralKey(ikm);
  process.send!({ publicKey });
  process.on('disconnect', () => process.exit(0)); // The member is gone: so are its secrets.
  process.on('message', (r: Request & { id: number }) => {
    void handle(r).then(result => ({ id: r.id, result }), (e: unknown) => ({ id: r.id, error: e instanceof Error ? e.message : String(e) }))
      .then(reply => process.send!(reply, () => { if (r.op === 'speak') process.exit(0); })); // Speaking ends the vault.
  });
}
