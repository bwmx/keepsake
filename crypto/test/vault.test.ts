import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createPublicKey, randomBytes, verify } from 'node:crypto';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { generateEphemeralKey, open, seal, unb64 } from '../src/crypto.js';
import { messageEntries, openCapsuleKey, reconstruct, sealCapsuleKey, seatKeys } from '../src/ecpss.js';
import { VerifyPool, receiveParallel } from '../src/parallel.js';
import { decodePartial, encodeProof } from '../src/pvss.js';
import { SeatVault, type Post } from '../src/vault.js';

const t = 2;
const ed25519 = (raw: Uint8Array) => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), format: 'der', type: 'spki' });

/** A nominator's seat for `key`: fresh one-time keys whose seed is sealed to it. */
async function nominate(key: string, seat: number, committee: bigint) {
  const seed = randomBytes(32), k = seatKeys(seed), context = Buffer.from(`seat ${committee}:${seat}`);
  const sealed = await seal(key, seed, context);
  return { seat, epk: k.epk, sigKey: k.sigKey,
    input: { seat, enc: unb64(sealed.enc), ct: unb64(sealed.ciphertext), context, epk: k.epk.toBytes(), sigKey: k.sigKey } };
}
type Seat = Awaited<ReturnType<typeof nominate>>;
const claims = (seats: number[], committee: bigint) => new Map(seats.map(s => [s, Buffer.from(`claim ${committee}:${s}`)]));
const chosen = (raw: Map<number, Uint8Array>, used: Map<bigint, number[]>) => new Map([...new Set([...used.values()].flat())].map(s => [s, raw.get(s)!]));

test('seat vaults: each opens only its seats and wipes its key, combines shares, speaks once and exits; the secret survives vault to vault', async () => {
  const start = () => SeatVault.start({ audit: true });
  const [A, B, C, D, E] = await Promise.all([start(), start(), start(), start(), start()]);
  const pool = new VerifyPool(2);
  try {
    // Committee 1: seats 1–2 for A, 3–4 for B, and one for an outsider's key. Committee 2: C holds 1–2, D holds 3.
    // Committee 3: E holds all three.
    const outsider = await generateEphemeralKey();
    const c1 = [await nominate(A.publicKey, 1, 1n), await nominate(A.publicKey, 2, 1n), await nominate(B.publicKey, 3, 1n),
      await nominate(B.publicKey, 4, 1n), await nominate(outsider.publicKey, 5, 1n)];
    const c2 = [await nominate(C.publicKey, 1, 2n), await nominate(C.publicKey, 2, 2n), await nominate(D.publicKey, 3, 2n)];
    const c3 = await Promise.all([1, 2, 3].map(s => nominate(E.publicKey, s, 3n)));
    // A lying nominator: a seat sealed to C whose posted keys are not the sealed seed's.
    const liar = { ...c2[0]!.input, seat: 4, epk: c3[0]!.input.epk };
    assert.deepEqual(await A.open(c1.map(s => s.input)), [1, 2]);
    assert.deepEqual(await B.open(c1.map(s => s.input)), [3, 4]);
    assert.deepEqual(await C.open([...c2.map(s => s.input), liar]), [1, 2]);
    assert.deepEqual(await D.open(c2.map(s => s.input)), [3]);
    assert.deepEqual(await E.open(c3.map(s => s.input)), [1, 2, 3]);
    await assert.rejects(A.open(c1.map(s => s.input)), /already erased/);

    const keys = (seats: Seat[]) => seats.map(s => s.epk);
    const checkClaims = (posts: Post[], seats: Seat[], committee: bigint) => posts.forEach(p =>
      assert.ok(verify(null, Buffer.concat([claims([p.seat], committee).get(p.seat)!, p.root]), ed25519(seats.find(s => s.seat === p.seat)!.sigKey), p.signature)));

    // Committee 1 (genesis) creates bucket 7. Each vault exits once it has spoken.
    await A.genesis(); await B.genesis();
    const create = { committee: 1n, pub: new Map(), buckets: { live: [], create: [7n] }, next: keys(c2).map(p => p.toBytes()), t, capsules: [] };
    const posts1 = [...await A.speak({ ...create, claims: claims([1, 2], 1n) }), ...await B.speak({ ...create, claims: claims([3, 4], 1n) })];
    checkClaims(posts1, c1, 1n);
    await Promise.all([A.exited, B.exited]);
    await assert.rejects(A.genesis(), /Vault exited/);

    // Everyone verifies publicly; the next committee's vaults combine their shares from the chosen dealings.
    const raw1 = new Map(posts1.map(p => [p.seat, p.message]));
    const r1 = await receiveParallel(pool, raw1, new Map(), 1n, { live: [], create: [7n] }, keys(c2), t);
    assert.deepEqual(r1.valid.get(7n), [1, 2, 3, 4]);
    const shares2 = [...(await C.adopt(chosen(raw1, r1.used), r1.used, { live: [], create: [7n] }, 3, t))!,
      ...(await D.adopt(chosen(raw1, r1.used), r1.used, { live: [], create: [7n] }, 3, t))!];
    const poly = r1.pub.get(7n)!, secret = reconstruct(poly, shares2.map(h => ({ seat: h.seat, share: h.shares.get(7n)! })), t);

    // Committee 2 re-shares bucket 7 and releases a capsule to its recipient, refusing a copy under another policy.
    const recipient = await generateEphemeralKey(), label = Buffer.from('capsule 9 policy');
    const capsule = sealCapsuleKey(poly[0]!, label);
    const input = (id: bigint, l: Uint8Array) => ({ id, bucket: 7n, u: capsule.u.toBytes(), proof: encodeProof(capsule.proof), label: l,
      recipientKey: recipient.publicKey, contexts: new Map([1, 2, 3].map(s => [s, Buffer.from(`release ${id}:${s}`)])) });
    const reshare = { committee: 2n, pub: r1.pub, buckets: { live: [7n], create: [] }, next: keys(c3).map(p => p.toBytes()), t,
      capsules: [input(9n, label), input(10n, Buffer.from('copied under another policy'))] };
    const posts2 = [...await C.speak({ ...reshare, pub: new Map([[7n, poly.map(p => p.toBytes())]]), claims: claims([1, 2], 2n) }),
      ...await D.speak({ ...reshare, pub: new Map([[7n, poly.map(p => p.toBytes())]]), claims: claims([3], 2n) })];
    checkClaims(posts2, c2, 2n);
    assert.ok(posts2.every(p => p.releases.join() === '9' && p.refused.length === 1 && p.refused[0]![0] === 10n));
    const parts = await Promise.all(posts2.map(async p => {
      const body = messageEntries(p.message, 3, t).find(e => e.kind === 2 && e.id === 9n)!.body;
      const plain = await open(recipient.privateKey, { enc: body.subarray(0, 32).toString('base64url'), ciphertext: body.subarray(32).toString('base64url') },
        Buffer.from(`release 9:${p.seat}`));
      return { seat: p.seat, p: decodePartial(plain) };
    }));
    assert.deepEqual(openCapsuleKey(poly, capsule.u, label, parts, t), capsule.key);

    const raw2 = new Map(posts2.map(p => [p.seat, p.message]));
    const r2 = await receiveParallel(pool, raw2, r1.pub, 2n, { live: [7n], create: [] }, keys(c3), t);
    const shares3 = (await E.adopt(chosen(raw2, r2.used), r2.used, { live: [7n], create: [] }, 3, t))!;
    assert.ok(reconstruct(r2.pub.get(7n)!, shares3.map(h => ({ seat: h.seat, share: h.shares.get(7n)! })), t).equals(secret));
    assert.ok(r2.pub.get(7n)![0]!.equals(poly[0]!), 'the bucket key never changes');
  } finally {
    for (const v of [A, B, C, D, E]) v.close();
    await pool.close();
  }
});

test('a vault refuses to hold secrets while core dumps are enabled', async t => {
  const script = fileURLToPath(new URL('../src/vault-process.js', import.meta.url));
  const child = spawn('/bin/sh', ['-c', 'ulimit -c unlimited 2>/dev/null || exit 3; exec "$0" "$@"', process.execPath, script],
    { stdio: ['ignore', 'inherit', 'inherit', 'ipc'], serialization: 'advanced' });
  const first = await new Promise<{ error?: string; publicKey?: string } | number>(resolve => {
    child.once('message', m => resolve(m as { error?: string }));
    child.once('exit', code => resolve(code ?? -1));
  });
  if (first === 3) return t.skip('cannot raise the core-dump limit here');
  assert.match((first as { error?: string }).error ?? '', /core dumps are enabled/);
});
