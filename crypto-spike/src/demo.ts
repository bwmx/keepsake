import assert from 'node:assert/strict';
import { newId } from './crypto.js';
import { Custodian, FixedCommitteeSelector, createAccessRequest, createCapsule, recover } from './protocol.js';
import { MockConfirmedLedger } from './mock-ledger.js';

const custodians = await Promise.all(Array.from({ length: 5 }, (_, i) => Custodian.create(`custodian-${i + 1}`)));
const plaintext = new TextEncoder().encode('A synthetic ephemeral secret for this demonstration.');
let recovered: Uint8Array | undefined;
try {
  const { capsule, deposits, anchor } = await createCapsule(plaintext, {
    network: 'crypto-spike:no-chain', applicationId: '0', capsuleId: newId(),
    recipient: 'mock-authorized-wallet', openRound: '100', expiresRound: '200',
  }, new FixedCommitteeSelector(custodians.map(c => c.descriptor)));
  await Promise.all(custodians.map((c, i) => c.accept(capsule.manifest, deposits[i]!, anchor)));
  const ledger = new MockConfirmedLedger(99n);
  ledger.register(capsule.manifest);
  const { request, keys } = await createAccessRequest(anchor);
  assert.throws(() => ledger.authorize(request, capsule.manifest.policy.recipient), /not open/);
  ledger.advanceTo(100n);
  assert.throws(() => ledger.authorize(request, 'wrong-wallet'), /Unauthorized/);
  ledger.authorize(request, capsule.manifest.policy.recipient);
  const responses = await Promise.all(custodians.slice(0, 3).map(c => c.release(request, ledger)));
  await assert.rejects(recover(capsule, anchor, request, keys.privateKey, responses.slice(0, 2)), /at least a threshold/);
  recovered = await recover(capsule, anchor, request, keys.privateKey, responses);
  assert.deepEqual(recovered, plaintext);
  recovered.fill(0);
  ledger.advanceTo(200n);
  for (const custodian of custodians) custodian.expire(ledger.currentRound);
  await assert.rejects(custodians[0]!.release(request, ledger), /disposed/);
  recovered = await recover(capsule, anchor, request, keys.privateKey, responses);
  assert.deepEqual(recovered, plaintext);
  console.log(JSON.stringify({
    mode: 'OFF-CHAIN CRYPTO SPIKE — trusted mock ledger; no Algorand deployment or VRF proof',
    manifestHash: anchor,
    committee: '3 of 5, fixed-demo',
    checks: {
      prematureAccessRejected: true, wrongRecipientRejected: true,
      twoResponsesRejected: true, threeResponsesRecoveredExactMessage: true,
      expiredCustodyRefusesRelease: true, alreadyDeliveredResponsesStillDecrypt: true,
    },
    erasure: 'Best-effort buffer wiping/reference disposal only; not provable secure erasure.',
    loggedSecrets: false,
  }, null, 2));
} finally {
  plaintext.fill(0);
  recovered?.fill(0);
  for (const custodian of custodians) custodian.dispose();
}
