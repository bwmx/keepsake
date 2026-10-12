import { AlgorandClient, microAlgo } from '@algorandfoundation/algokit-utils';
import { WalletManager } from '@txnlab/use-wallet';
import { kmd } from '@txnlab/use-wallet-kmd';
import { lute } from '@txnlab/use-wallet-lute';
import { generateEphemeralKey, type EncryptedPayload } from 'keepsake-crypto/dist/src/crypto.js';
import { EpochCommitteeClient } from '../smart_contracts/artifacts/epoch_committee/EpochCommitteeClient.js';
import { CAPSULE_DEPOSIT, assertLive, bucketKey, capsuleLabel, openCapsule, payloadHash, sealCapsule } from '../src/epoch-capsules.js';
import { EpochReader, windows, type EpochParams } from '../src/epochs.js';
import type { G1Point } from 'keepsake-crypto/dist/src/pvss.js';

/**
 * Capsule Lab's browser side (milestone 4). The connected wallet seals capsules, requests access and decrypts, all in
 * this page: the plaintext, the payload key and the recipient's request key never leave it. The page reads the chain
 * straight from algod. The server stores only ciphertext, and only ciphertext matching the hash anchored on chain.
 * Bundled by esbuild into public/client.js; the page script uses it through `window.keepsake`.
 */
interface Config {
  appId: string; genesisHash: string; t: number; params: Record<keyof EpochParams, string>;
  algod: { server: string; port: number; token: string }; kmd: { server: string; port: number; token: string };
}

const api = async <T>(path: string, body?: unknown): Promise<T> => {
  const res = await fetch(`/api/${path}`, body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || res.statusText);
  return json as T;
};

// Request keys stay in this browser's IndexedDB (non-extractable CryptoKeys), so a reload can still decrypt.
const db = () => new Promise<IDBDatabase>((resolve, reject) => {
  const open = indexedDB.open('keepsake', 1);
  open.onupgradeneeded = () => open.result.createObjectStore('requests');
  open.onsuccess = () => resolve(open.result);
  open.onerror = () => reject(open.error);
});
type StoredRequest = { requestId: Uint8Array; privateKey: CryptoKey; epoch: bigint };
const store = async (mode: IDBTransactionMode, f: (s: IDBObjectStore) => IDBRequest) => new Promise<unknown>(async (resolve, reject) => {
  const tx = (await db()).transaction('requests', mode), req = f(tx.objectStore('requests'));
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
});

let config: Config, algorand: AlgorandClient, app: EpochCommitteeClient, reader: EpochReader, manager: WalletManager, params: EpochParams;
const keys = new Map<bigint, G1Point>(); // Bucket → its attested public key: it never changes while the bucket lives.

async function init() {
  config = await api<Config>('config');
  params = Object.fromEntries(Object.entries(config.params).map(([k, v]) => [k, BigInt(v)])) as unknown as EpochParams;
  const algodConfig = { server: config.algod.server, port: config.algod.port, token: config.algod.token };
  algorand = AlgorandClient.fromConfig({ algodConfig });
  app = new EpochCommitteeClient({ algorand, appId: BigInt(config.appId) });
  reader = new EpochReader(algorand.client.algod, pins(), params, app.appClient.getABIMethod('postChunk').getSelector());
  manager = new WalletManager({
    wallets: [
      kmd({ wallet: 'unencrypted-default-wallet', token: config.kmd.token, baseServer: config.kmd.server, port: config.kmd.port, promptForPassword: async () => '' }),
      lute({ siteName: 'Keepsake Capsule Lab' }),
    ],
    networks: { localnet: { algod: { token: config.algod.token, baseServer: config.algod.server, port: config.algod.port } } },
    defaultNetwork: 'localnet',
  });
  await manager.resumeSessions();
  bindSigner();
}

const pins = () => ({ genesisHash: config.genesisHash, appId: BigInt(config.appId), maxRoundAgeMs: 0 });
const me = () => { const a = manager?.activeAddress; if (!a) throw new Error('Connect a wallet first'); return a; };
function bindSigner() { if (manager.activeAddress) algorand.setSigner(manager.activeAddress, manager.transactionSigner); }

/** Connects a wallet ('kmd' for LocalNet's own wallet, 'lute' for the browser extension) and returns its address. */
async function connect(walletId: 'kmd' | 'lute') {
  await manager.getWallet(walletId)!.connect();
  bindSigner();
  return me();
}

async function account() {
  const address = manager?.activeAddress;
  if (!address) return undefined;
  const info = await algorand.client.algod.accountInformation(address).do();
  return { address, wallet: manager.activeWallet?.id, algo: Number(info.amount) / 1e6 };
}

/**
 * Seals `message` in this page under the key of the bucket its expiry falls in (as the committee attested it) and
 * registers the capsule from the wallet. Only the ciphertext goes to the server.
 */
async function lock(o: { message: string; openIn: number; length: number; recipient?: string }) {
  const sender = me(), recipient = o.recipient || sender, E = params.epochRounds;
  // The window starts when the capsule is registered: reading a bucket key takes a while, and the chain moves on.
  const window = async () => {
    const round = await reader.lastRound(), open = round + BigInt(o.openIn), expires = open + BigInt(o.length);
    return { round, open, expires, bucket: expires / params.bucketRounds };
  };
  let w = await window();
  for (;;) {
    if (!keys.has(w.bucket)) {
      const key = await bucketKey(reader, w.bucket, config.t, w.round / E - 1n);
      if (!key) throw new Error(`Bucket ${w.bucket}'s key is not attested yet: let the clock run (keys appear about two epochs after a bucket is created).`);
      keys.set(w.bucket, key);
    }
    await assertLive(reader, w.round, config.t, 1);
    const next = await window();
    if (next.bucket === w.bucket) { w = next; break; }
    w = next;
  }
  const { open, expires, bucket } = w, key = keys.get(bucket)!;
  const label = capsuleLabel(app.appId, { sender, recipient, openRound: open, expiresRound: expires });
  const sealed = sealCapsule(key, label, new TextEncoder().encode(o.message));
  const id = (await app.send.registerCapsule({ sender, args: {
    recipient, openRound: open, expiresRound: expires, u: sealed.u, proof: sealed.proof, payloadHash: sealed.payloadHash,
    payment: algorand.createTransaction.payment({ sender, receiver: app.appAddress, amount: microAlgo(CAPSULE_DEPOSIT) }),
  } })).return!;
  await api(`payload/${id}`, sealed.payload);
  return { id: id.toString(), bucket: bucket.toString() };
}

/** Binds a fresh X25519 request key, made in this page, from the recipient's wallet. */
async function request(id: string) {
  const keys = await generateEphemeralKey(), requestId = crypto.getRandomValues(new Uint8Array(16));
  await app.send.requestAccess({ sender: me(), args: { capsuleId: BigInt(id), requestId, recipientKey: Buffer.from(keys.publicKey, 'base64url') } });
  const stored: StoredRequest = { requestId, privateKey: keys.privateKey, epoch: (await reader.lastRound()) / params.epochRounds };
  await store('readwrite', s => s.put(stored, `${config.appId}:${id}`));
}

/** Collects the partials released to this page's request key, checks them and decrypts here. Undefined until released. */
async function decrypt(id: string): Promise<string | undefined> {
  const stored = await store('readonly', s => s.get(`${config.appId}:${id}`)) as StoredRequest | undefined;
  if (!stored) throw new Error('No request key in this browser for this capsule: request access from here first');
  const payload = await api<EncryptedPayload>(`payload/${id}`), record = await reader.capsuleRecord(BigInt(id));
  if (!payloadHash(payload).equals(Buffer.from(record.payloadHash))) throw new Error('The stored ciphertext does not match the hash anchored on chain');
  const round = await reader.lastRound(), epoch = round / params.epochRounds;
  const latest = round > windows(params, epoch).handover[1] ? epoch : epoch - 1n; // The latest completed handover.
  const plain = await openCapsule(reader, pins(), BigInt(id), stored, payload, config.t, stored.epoch, latest);
  return plain && new TextDecoder().decode(plain);
}

// Initialized on first use, once the server's environment exists; retried if it does not yet.
let ready: Promise<void> | undefined;
const after = <A extends unknown[], R>(f: (...a: A) => Promise<R>) => async (...a: A) => {
  ready ??= init().catch(e => { ready = undefined; throw e; });
  await ready;
  return f(...a);
};
(window as unknown as { keepsake: unknown }).keepsake = {
  connect: after(connect), disconnect: after(async () => manager.disconnect()), account: after(account),
  lock: after(lock), request: after(request), decrypt: after(decrypt),
  hasRequest: after(async (id: string) => !!(await store('readonly', s => s.get(`${config.appId}:${id}`)))),
};
