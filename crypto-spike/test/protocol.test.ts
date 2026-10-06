import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { test } from 'node:test';
import { b64, encode, generateEphemeralKey, newId, open, seal, SUITE, unb64 } from '../src/crypto.js';
import {
  Custodian, FixedCommitteeSelector, createAccessRequest, createCapsule, manifestHash, recover, requestFields,
  type AuthorizationSource,
} from '../src/protocol.js';
import { MockConfirmedLedger } from '../src/mock-ledger.js';
import { fixture } from './fixture.js';

const altered = (value: string): string => {
  const bytes = unb64(value);
  bytes[0] = bytes[0]! ^ 1;
  return b64(bytes);
};

test('all ten three-of-five subsets recover the exact message', async () => {
  const f = await fixture();
  const responses = await f.releases();
  let combinations = 0;
  for (let a = 0; a < 3; a++) for (let b = a + 1; b < 4; b++) for (let c = b + 1; c < 5; c++) {
    const recovered = await recover(f.capsule, f.anchor, f.request, f.keys.privateKey,
      [responses[a]!, responses[b]!, responses[c]!]);
    assert.deepEqual(recovered, f.plaintext);
    recovered.fill(0);
    combinations++;
  }
  assert.equal(combinations, 10);
});

test('four and five valid responses recover; shuffled order does not matter', async () => {
  const f = await fixture();
  const responses = (await f.releases()).reverse();
  for (const count of [4, 5]) {
    assert.deepEqual(await recover(f.capsule, f.anchor, f.request, f.keys.privateKey, responses.slice(0, count)), f.plaintext);
  }
});

test('zero, one, or two responses are refused', async () => {
  const f = await fixture();
  const responses = await f.releases();
  for (const count of [0, 1, 2]) {
    await assert.rejects(recover(f.capsule, f.anchor, f.request, f.keys.privateKey, responses.slice(0, count)), /at least a threshold/);
  }
});

test('two unavailable custodians preserve recovery; three unavailable prevent it', async () => {
  const f = await fixture();
  f.custodians[0]!.dispose();
  f.custodians[1]!.dispose();
  const responses = await Promise.all(f.custodians.slice(2).map(c => c.release(f.request, f.ledger)));
  assert.deepEqual(await recover(f.capsule, f.anchor, f.request, f.keys.privateKey, responses), f.plaintext);
  f.custodians[2]!.dispose();
  await assert.rejects(f.custodians[2]!.release(f.request, f.ledger), /disposed/);
});

test('duplicate identities cannot satisfy the threshold', async () => {
  const f = await fixture();
  const responses = await f.releases();
  await assert.rejects(recover(f.capsule, f.anchor, f.request, f.keys.privateKey,
    [responses[0]!, responses[0]!, responses[1]!]), /Duplicate custodian/);
});

test('modified ciphertext and signature fail authentication', async () => {
  const f = await fixture();
  for (const field of ['ciphertext', 'signature'] as const) {
    const responses = structuredClone(await f.releases()).slice(0, 3);
    responses[0]![field] = altered(responses[0]![field]);
    await assert.rejects(recover(f.capsule, f.anchor, f.request, f.keys.privateKey, responses), /signature/);
  }
});

test('wrong recipient private key cannot decrypt responses', async () => {
  const f = await fixture();
  const stranger = await generateEphemeralKey();
  await assert.rejects(recover(f.capsule, f.anchor, f.request, stranger.privateKey, (await f.releases()).slice(0, 3)));
});

test('unknown custodian and response/request substitution are rejected', async () => {
  const f = await fixture();
  for (const field of ['custodianId', 'requestId', 'recipientPublicKey'] as const) {
    const responses = structuredClone(await f.releases()).slice(0, 3);
    responses[0]![field] = field === 'recipientPublicKey' ? (await generateEphemeralKey()).publicKey : 'substituted';
    await assert.rejects(recover(f.capsule, f.anchor, f.request, f.keys.privateKey, responses), /Unknown custodian|request mismatch/);
  }
});

test('payload tampering and policy/network/application substitution invalidate the trusted anchor', async () => {
  const f = await fixture();
  const responses = (await f.releases()).slice(0, 3);
  const corruptPayload = structuredClone(f.capsule);
  corruptPayload.payload.ciphertext = altered(corruptPayload.payload.ciphertext);
  await assert.rejects(recover(corruptPayload, f.anchor, f.request, f.keys.privateKey, responses), /Ciphertext hash/);
  for (const field of ['network', 'applicationId', 'capsuleId', 'recipient', 'expiresRound'] as const) {
    const substituted = structuredClone(f.capsule);
    substituted.manifest.policy[field] = field === 'applicationId' ? '1' : field === 'expiresRound' ? '201' : 'changed';
    await assert.rejects(recover(substituted, f.anchor, f.request, f.keys.privateKey, responses), /trusted anchor/);
  }
});

test('cross-capsule responses cannot be combined', async () => {
  const a = await fixture();
  const b = await fixture();
  await assert.rejects(recover(a.capsule, a.anchor, a.request, a.keys.privateKey,
    (await b.releases()).slice(0, 3)), /request mismatch/);
});

test('unauthorized caller, premature access, and exact expiry are rejected; opening round is inclusive', async () => {
  const f = await fixture();
  const ledger = new MockConfirmedLedger(99n);
  ledger.register(f.capsule.manifest);
  assert.throws(() => ledger.authorize(f.request, 'attacker'), /Unauthorized/);
  assert.throws(() => ledger.authorize(f.request, f.capsule.manifest.policy.recipient), /not open/);
  ledger.advanceTo(100n);
  ledger.authorize(f.request, f.capsule.manifest.policy.recipient);
  await f.custodians[0]!.release(f.request, ledger);
  ledger.advanceTo(199n);
  await f.custodians[1]!.release(f.request, ledger);
  ledger.advanceTo(200n);
  assert.throws(() => ledger.authorize(f.request, f.capsule.manifest.policy.recipient), /expired/);
  await assert.rejects(f.custodians[2]!.release(f.request, ledger), /expired/);
  assert.equal(f.custodians[2]!.disposed, true);
});

test('unconfirmed requests, replacement recipient keys, and second requests are refused', async () => {
  const f = await fixture();
  const fresh = await createAccessRequest(f.anchor);
  await assert.rejects(f.custodians[0]!.release(fresh.request, f.ledger), /not authorized/);
  assert.throws(() => f.ledger.authorize(fresh.request, f.capsule.manifest.policy.recipient), /already authorized/);
  const replaced = { ...f.request, recipientPublicKey: fresh.keys.publicKey };
  await assert.rejects(f.custodians[0]!.release(replaced, f.ledger), /not authorized/);
});

test('same-request retries are safe but never count as another share', async () => {
  const f = await fixture();
  f.ledger.authorize(f.request, f.capsule.manifest.policy.recipient);
  const first = await f.custodians[0]!.release(f.request, f.ledger);
  const retry = await f.custodians[0]!.release(f.request, f.ledger);
  assert.notEqual(first.enc, retry.enc);
  await assert.rejects(recover(f.capsule, f.anchor, f.request, f.keys.privateKey,
    [first, retry, await f.custodians[1]!.release(f.request, f.ledger)]), /Duplicate/);
});

test('round is rechecked after HPKE work; a response crossing expiry is not released', async () => {
  const f = await fixture();
  let reads = 0;
  const source: AuthorizationSource = { assertAuthorized(anchor, request) {
    if (++reads === 2) f.ledger.advanceTo(200n);
    return f.ledger.assertAuthorized(anchor, request);
  } };
  await assert.rejects(f.custodians[0]!.release(f.request, source), /expired/);
  assert.equal(reads, 2);
  assert.equal(f.custodians[0]!.disposed, true);
});

test('disposal during asynchronous release prevents returning the prepared response', async () => {
  const f = await fixture();
  const custodian = f.custodians[0]!;
  const source: AuthorizationSource = { assertAuthorized(anchor, request) {
    queueMicrotask(() => custodian.dispose());
    return f.ledger.assertAuthorized(anchor, request);
  } };
  await assert.rejects(custodian.release(f.request, source), /disposed/);
});

test('request mutation during an await cannot substitute recipient encryption keys', async () => {
  const f = await fixture();
  const mutable = structuredClone(f.request);
  const pending = f.custodians[0]!.release(mutable, f.ledger);
  mutable.recipientPublicKey = 'invalid';
  const first = await pending;
  const responses = [first, ...await Promise.all(f.custodians.slice(1, 3).map(c => c.release(f.request, f.ledger)))];
  assert.deepEqual(await recover(f.capsule, f.anchor, f.request, f.keys.privateKey, responses), f.plaintext);
});

test('authorization-source failure fails closed', async () => {
  const f = await fixture();
  await assert.rejects(f.custodians[0]!.release(f.request, {
    assertAuthorized() { throw new Error('Chain unavailable'); },
  }), /Chain unavailable/);
});

test('expired/disposed custody cannot release, but already delivered responses remain decryptable', async () => {
  const f = await fixture();
  const responses = (await f.releases()).slice(0, 3);
  f.ledger.advanceTo(200n);
  for (const custodian of f.custodians) custodian.expire(f.ledger.currentRound);
  for (const custodian of f.custodians) {
    assert.equal(custodian.disposed, true);
    await assert.rejects(custodian.release(f.request, f.ledger), /disposed/);
  }
  assert.deepEqual(await recover(f.capsule, f.anchor, f.request, f.keys.privateKey, responses), f.plaintext);
});

test('duplicate committee identities and keys are rejected', async () => {
  const f = await fixture();
  const members = f.custodians.map(c => c.descriptor);
  for (const field of ['id', 'encryptionPublicKey', 'signingPublicKey'] as const) {
    const copied = structuredClone(members);
    copied[1]![field] = copied[0]![field];
    await assert.rejects(createCapsule(f.plaintext, f.capsule.manifest.policy, new FixedCommitteeSelector(copied)), /Duplicate/);
  }
});

test('invalid round ranges and noncanonical uint64 strings are rejected', async () => {
  const f = await fixture();
  for (const bad of ['-1', '01', '18446744073709551616', '1.5']) {
    const manifest = structuredClone(f.capsule.manifest);
    manifest.policy.expiresRound = bad;
    assert.throws(() => manifestHash(manifest), /uint64/);
  }
  const manifest = structuredClone(f.capsule.manifest);
  manifest.policy.expiresRound = '100';
  assert.throws(() => manifestHash(manifest), /access window/);
  assert.throws(() => f.ledger.advanceTo(99n), /Round must increase/);
});

test('fresh capsules have independent keys and encryption even for identical plaintext', async () => {
  const a = await fixture();
  const b = await fixture();
  assert.notEqual(a.anchor, b.anchor);
  assert.notEqual(a.capsule.payload.ciphertext, b.capsule.payload.ciphertext);
  assert.notEqual(a.capsule.payload.nonce, b.capsule.payload.nonce);
  assert.notEqual(a.custodians[0]!.descriptor.encryptionPublicKey, b.custodians[0]!.descriptor.encryptionPublicKey);
});

test('modified deposits fail, and custody cannot be reinitialized', async () => {
  const custodians = await Promise.all(Array.from({ length: 5 }, (_, i) => Custodian.create(`node-${i}`)));
  const result = await createCapsule(new Uint8Array([1, 2]), {
    network: 'test', applicationId: '0', capsuleId: newId(), recipient: 'recipient', openRound: '1', expiresRound: '2',
  }, new FixedCommitteeSelector(custodians.map(c => c.descriptor)));
  const wrong = { ...result.deposits[0]!, ciphertext: altered(result.deposits[0]!.ciphertext) };
  await assert.rejects(custodians[0]!.accept(result.capsule.manifest, wrong, result.anchor));
  await assert.rejects(custodians[0]!.accept(result.capsule.manifest, result.deposits[1]!, result.anchor), /Wrong deposit/);
  await custodians[0]!.accept(result.capsule.manifest, result.deposits[0]!, result.anchor);
  await assert.rejects(custodians[0]!.accept(result.capsule.manifest, result.deposits[0]!, result.anchor), /already initialized/);
});

test('a valid custodian signature cannot legitimize a corrupted share; other custodians still recover', async () => {
  const honest = await Promise.all(Array.from({ length: 4 }, (_, i) => Custodian.create(`honest-${i}`)));
  const evilKeys = await generateEphemeralKey();
  const evilSigning = generateKeyPairSync('ed25519');
  const evil = { id: 'malicious', encryptionPublicKey: evilKeys.publicKey,
    signingPublicKey: b64(evilSigning.publicKey.export({ format: 'der', type: 'spki' })) };
  const { capsule, anchor, deposits } = await createCapsule(encode('synthetic secret'), {
    network: 'test', applicationId: '0', capsuleId: newId(), recipient: 'recipient', openRound: '1', expiresRound: '10',
  }, new FixedCommitteeSelector([...honest.map(c => c.descriptor), evil]));
  await Promise.all(honest.map((c, i) => c.accept(capsule.manifest, deposits[i]!, anchor)));
  const ledger = new MockConfirmedLedger(1n);
  ledger.register(capsule.manifest);
  const { request, keys } = await createAccessRequest(anchor);
  ledger.authorize(request, 'recipient');
  const share = await open(evilKeys.privateKey, deposits[4]!, encode(['capsule/deposit/v1', SUITE, anchor, evil.id]));
  share[0] = share[0]! ^ 1;
  const context = encode(['capsule/release/v1', SUITE, ...requestFields(request), evil.id]);
  const envelope = await seal(keys.publicKey, share, context);
  share.fill(0);
  const unsigned = { ...request, custodianId: evil.id, ...envelope };
  const forged = { ...unsigned, signature: b64(sign(null,
    encode(['capsule/response-signature/v1', b64(context), unsigned.enc, unsigned.ciphertext]), evilSigning.privateKey)) };
  const valid = await Promise.all(honest.map(c => c.release(request, ledger)));
  await assert.rejects(recover(capsule, anchor, request, keys.privateKey, [forged, valid[0]!, valid[1]!]), /commitment/);
  assert.deepEqual(await recover(capsule, anchor, request, keys.privateKey, valid.slice(0, 3)), new Uint8Array(encode('synthetic secret')));
});

test('HPKE binds context, rejects modified envelopes, and cannot be opened with another key', async () => {
  const recipient = await generateEphemeralKey();
  const context = encode(['hpke-test', 'capsule-A']);
  const message = encode('random-share-placeholder');
  const envelope = await seal(recipient.publicKey, message, context);
  assert.deepEqual(await open(recipient.privateKey, envelope, context), new Uint8Array(message));
  await assert.rejects(open(recipient.privateKey, envelope, encode(['hpke-test', 'capsule-B'])));
  await assert.rejects(open(recipient.privateKey, { ...envelope, enc: altered(envelope.enc) }, context));
  await assert.rejects(open((await generateEphemeralKey()).privateKey, envelope, context));
});

test('seeded one-time holder keys are deterministic, and chain signatures are domain-separated', async () => {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const holder = await Custodian.fromSeed('slot-0', seed);
  assert.deepEqual((await Custodian.fromSeed('slot-0', seed)).descriptor, holder.descriptor);
  assert.notDeepEqual((await Custodian.fromSeed('slot-0', new Uint8Array(32).fill(1))).descriptor, holder.descriptor);
  const body = new Uint8Array([1, 2, 3]);
  const signature = holder.signChainMessage('ack', body);
  const key = createPublicKey({ key: unb64(holder.descriptor.signingPublicKey), format: 'der', type: 'spki' });
  assert.ok(verify(null, Buffer.concat([Buffer.from('capsule/chain-ack/v1'), body]), key, signature));
  assert.ok(!verify(null, Buffer.concat([Buffer.from('capsule/chain-release/v1'), body]), key, signature));
  holder.dispose();
  assert.throws(() => holder.signChainMessage('ack', body), /unavailable/);
});

test('larger committees use a majority threshold: 9 of 16 recover, 8 do not; sizes outside 3–64 are rejected', async () => {
  const custodians = await Promise.all(Array.from({ length: 16 }, (_, i) => Custodian.create(`custodian-${i}`)));
  const policy = { network: 'crypto-spike:no-chain', applicationId: '0', capsuleId: newId(), recipient: 'mock-authorized-wallet',
    openRound: '100', expiresRound: '200' };
  const plaintext = new TextEncoder().encode('sixteen custodians');
  const { capsule, deposits, anchor } = await createCapsule(plaintext, policy, new FixedCommitteeSelector(custodians.map(c => c.descriptor)));
  assert.equal(capsule.manifest.threshold, 9);
  await Promise.all(custodians.map((c, i) => c.accept(capsule.manifest, deposits[i]!, anchor)));
  const ledger = new MockConfirmedLedger(100n);
  ledger.register(capsule.manifest);
  const { request, keys } = await createAccessRequest(anchor);
  ledger.authorize(request, policy.recipient);
  const responses = await Promise.all(custodians.slice(3, 12).map(c => c.release(request, ledger)));
  assert.deepEqual(await recover(capsule, anchor, request, keys.privateKey, responses), plaintext);
  await assert.rejects(recover(capsule, anchor, request, keys.privateKey, responses.slice(1)), /at least a threshold/);
  for (const size of [2, 65]) {
    const members = await Promise.all(Array.from({ length: size }, (_, i) => Custodian.create(`m-${i}`)));
    await assert.rejects(createCapsule(plaintext, policy, new FixedCommitteeSelector(members.map(c => c.descriptor))), /out of range/);
  }
});
