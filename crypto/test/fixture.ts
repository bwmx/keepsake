import { newId } from '../src/crypto.js';
import { Custodian, FixedCommitteeSelector, createAccessRequest, createCapsule } from '../src/protocol.js';
import { MockConfirmedLedger } from '../src/mock-ledger.js';

export async function fixture() {
  const custodians = await Promise.all(Array.from({ length: 5 }, (_, i) => Custodian.create(`custodian-${i + 1}`)));
  const plaintext = new TextEncoder().encode('Synthetic demo secret: café 🔐');
  const { capsule, deposits, anchor } = await createCapsule(plaintext, {
    network: 'crypto:no-chain', applicationId: '0', capsuleId: newId(),
    recipient: 'mock-authorized-wallet', openRound: '100', expiresRound: '200',
  }, new FixedCommitteeSelector(custodians.map(c => c.descriptor)));
  await Promise.all(custodians.map((c, i) => c.accept(capsule.manifest, deposits[i]!, anchor)));
  const ledger = new MockConfirmedLedger(100n);
  ledger.register(capsule.manifest);
  const { request, keys } = await createAccessRequest(anchor);
  ledger.authorize(request, capsule.manifest.policy.recipient);
  const releases = () => Promise.all(custodians.map(c => c.release(request, ledger)));
  return { capsule, anchor, custodians, ledger, request, keys, plaintext, deposits, releases };
}
