import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { microAlgo } from '@algorandfoundation/algokit-utils';
import { generateEphemeralKey } from 'keepsake-crypto/dist/src/crypto.js';
import { messageEntries } from 'keepsake-crypto/dist/src/ecpss.js';
import { VerifyPool } from 'keepsake-crypto/dist/src/parallel.js';
import { CAPSULE_DEPOSIT, assertLive, attestedState, bucketKey, capsuleLabel, handoverNeeds, livenessMargin, openCapsule, sealCapsule } from '../src/epoch-capsules.js';
import { windows } from '../src/epochs.js';
import { algorand, deploy, lastRound, rejects, runUntil, startWorkers, stepAll, type WorkerEvent } from './epoch-env.js';

test('capsules on bucket keys: private release from handover messages; refusals; a bucket is gone after its last handover; senders refuse a thin liveness margin', async () => {
  const E = 120n, t = 3;
  const env = await deploy({ members: 8, epochRounds: E, nominationRounds: 40n, handoverRounds: 60n, threshold: 2n ** 64n - 1n,
    // A long lead: a bucket is created early enough to be attested (one epoch later) before capsules need its key.
    shareThreshold: BigInt(t), bucketRounds: 2n * E, bucketLead: 6n * E });
  const G = env.params.genesisCommittee, plaintext = Buffer.from('a synthetic capsule secret');
  const [sender, recipient, outsider, copier] = await Promise.all([env.fund(), env.fund(), env.fund(), env.fund()]);
  const pool = new VerifyPool(4), events: WorkerEvent[] = [];
  const workers = await startWorkers(env, pool, events);
  const epoch = async () => (await lastRound()) / E;
  /** Registers a capsule opening `openIn` rounds from now, once the latest attested state holds its bucket's key. */
  const register = async (o: { from?: typeof sender; openIn: bigint; length: bigint; to?: typeof recipient; copy?: { u: Uint8Array; proof: Uint8Array };
    minMargin?: number }) => {
    const from = o.from ?? sender, to = o.to ?? recipient;
    let open: bigint, expires: bigint, bucket: bigint, key: Awaited<ReturnType<typeof bucketKey>>;
    for (;;) { // Waiting may move the window into the next bucket: recompute until the key is at hand.
      open = (await lastRound()) + o.openIn;
      expires = open + o.length;
      bucket = expires / env.params.bucketRounds;
      if ((key = await bucketKey(env.reader, bucket, t, (await epoch()) - 1n))) break;
      await runUntil(env, workers, async () => !!(await bucketKey(env.reader, bucket, t, (await epoch()) - 1n)));
    }
    await assertLive(env.reader, await lastRound(), t, o.minMargin ?? 1); // By default, refuse when one more silent seat would lose buckets.
    const label = capsuleLabel(env.app.appId, { sender: from.toString(), recipient: to.toString(), openRound: open, expiresRound: expires });
    const sealed = sealCapsule(key, label, plaintext);
    const id = (await env.app.send.registerCapsule({ sender: from, args: {
      recipient: to.toString(), openRound: open, expiresRound: expires, u: o.copy?.u ?? sealed.u, proof: o.copy?.proof ?? sealed.proof,
      payloadHash: sealed.payloadHash, payment: algorand.createTransaction.payment({ sender: from, receiver: env.app.appAddress, amount: microAlgo(CAPSULE_DEPOSIT) }),
    } })).return!;
    return { id, bucket, open, expires, ...sealed };
  };
  const request = async (id: bigint, as = recipient) => {
    const keys = await generateEphemeralKey(), requestId = randomBytes(16);
    await env.app.send.requestAccess({ sender: as, args: { capsuleId: id, requestId, recipientKey: Buffer.from(keys.publicKey, 'base64url') } });
    return { requestId, privateKey: keys.privateKey };
  };

  try {
    await runUntil(env, workers, async () => (await epoch()) > G); // Buckets exist from committee G + 1.
    await rejects(env.app.send.registerCapsule({ sender, args: { recipient: recipient.toString(), openRound: 1n, expiresRound: 2n, u: Buffer.alloc(48),
      proof: Buffer.alloc(64), payloadHash: Buffer.alloc(32), payment: algorand.createTransaction.payment({ sender, receiver: env.app.appAddress, amount: microAlgo(CAPSULE_DEPOSIT) }) } }), 'Invalid window');

    // Capsule A opens now and lasts three epochs; capsule B opens later.
    const a = await register({ openIn: 30n, length: 3n * E });
    const b = await register({ openIn: 2n * E, length: 3n * E });
    await rejects(request(a.id, outsider), 'Not recipient');
    await rejects(request(b.id), 'Not open');
    await runUntil(env, workers, async () => (await lastRound()) >= a.open);
    const req = await request(a.id);
    await rejects(request(a.id), 'Already requested'); // No key substitution.

    // Capsule C copies A's u and proof under another sender's policy: every holder refuses it.
    const c = await register({ from: copier, to: copier, openIn: 5n, length: 3n * E, copy: { u: a.u, proof: a.proof } });
    await runUntil(env, workers, async () => (await lastRound()) >= c.open);
    const reqC = await request(c.id, copier);

    // The next handover releases A to its request key, and only A.
    const from = await epoch();
    await runUntil(env, workers, async () => (await lastRound()) > windows(env.params, from).handover[1]);
    const opened = await openCapsule(env.reader, env.pins, a.id, req, a.payload, t, from, from);
    assert.deepEqual(Buffer.from(opened!), plaintext);
    assert.equal(await openCapsule(env.reader, env.pins, c.id, reqC, c.payload, t, from, from), undefined);
    assert.ok(events.some(e => e.refused === c.id.toString()) && !events.some(e => e.error), 'holders refused the copy, without errors');

    // After A expires its bucket ends, and once no committee needs the bucket it is dropped at a handover: never re-dealt.
    await runUntil(env, workers, async () => (await lastRound()) >= a.expires);
    await rejects(request(a.id), 'Already requested|Expired');
    await env.app.send.deleteCapsule({ args: { capsuleId: a.id }, sender: outsider, extraFee: microAlgo(1_000) });
    const held = (e: WorkerEvent) => String(e.keys).split(',').some(kv => kv.startsWith(`${a.bucket}:`));
    const received = () => events.filter(e => e.received);
    await runUntil(env, workers, () => received().some(held) && !held(received().at(-1)!));
    const after = BigInt(String(received().at(-1)!.received)) + 1n; // The first committee without the bucket.
    await runUntil(env, workers, async () => (await lastRound()) > windows(env.params, after).handover[1] + 1n);
    assert.ok(workers.every(w => ![...(w.view(after + 1n)?.pub.keys() ?? [])].includes(a.bucket)));
    assert.ok(!(await attestedState(env.reader, after, t))?.has(a.bucket));
    const n = (await env.reader.seats(after + 1n)).length;
    for (const bytes of (await env.reader.messages(after, await env.reader.seats(after))).values()) {
      assert.ok(!messageEntries(bytes, n, t).some(e => e.kind <= 1 && e.id === a.bucket), 'nobody re-deals the dropped bucket');
    }

    // Liveness: members go silent through one handover window, leaving as few seats speaking as possible, but at least
    // what the handover needs: t, or t + ℓ − 1 if it unpacks (exactly that when some set of members holds that many
    // seats). Workers report the margin, and senders refuse to lock while it is below their minimum, until a full
    // handover restores it.
    const quiet = (await epoch()) + 1n, w = windows(env.params, quiet);
    await runUntil(env, workers, async () => (await lastRound()) + 1n >= w.handover[0]);
    const pub = workers.map(x => x.view(quiet)).find(v => v)!.pub;
    const need = handoverNeeds(env.params, pub, quiet, t, [(await env.reader.seats(quiet + 1n)).length])[0]!;
    const seatsHeld = workers.map(x => x.view(quiet)?.seats.length ?? 0), total = (set: number[]) => set.reduce((a, i) => a + seatsHeld[i]!, 0);
    let speakers = [...seatsHeld.keys()];
    for (let mask = 1; mask < 1 << seatsHeld.length; mask++) {
      const set = [...seatsHeld.keys()].filter(i => mask & (1 << i));
      if (total(set) >= need && total(set) < total(speakers)) speakers = set;
    }
    const margin = total(speakers) - need;
    while ((await lastRound()) < w.handover[1]) await stepAll(env, workers, i => speakers.includes(i));
    await runUntil(env, workers, () => events.some(e => e.received === quiet.toString()));
    assert.ok(events.filter(e => e.received === quiet.toString()).every(e => e.margin === margin.toString() && e.lost === ''));
    assert.equal(await livenessMargin(env.reader, await lastRound(), t), margin);
    await rejects(register({ openIn: 5n, length: 3n * E, minMargin: margin + 1 }), 'Liveness margin too thin');
    await runUntil(env, workers, () => events.some(e => e.received === (quiet + 1n).toString()));
    assert.ok((await livenessMargin(env.reader, await lastRound(), t))! > margin);
  } finally {
    await Promise.all(workers.map(w => w.stop()));
    await pool.close();
  }
});
