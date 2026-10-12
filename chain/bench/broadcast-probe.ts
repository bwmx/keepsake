import { createHash, randomBytes } from 'node:crypto';
import { AlgorandClient, Config, algo, microAlgo } from '@algorandfoundation/algokit-utils';
import { nullLogger } from '@algorandfoundation/algokit-utils/types/logging';
import { encodeUint64 } from 'algosdk';
import { BroadcastProbeFactory } from '../smart_contracts/artifacts/broadcast_probe/BroadcastProbeClient.js';

/**
 * FEASIBILITY PROBE, LocalNet only (docs/results.md): app-call argument and note limits and their fees, posting one
 * epoch's handover data, rebuilding it from blocks through algod, the block-seed lookback, and the stake opcodes.
 */
Config.configure({ logger: nullLogger, populateAppCallResources: false });
const algorand = AlgorandClient.defaultLocalNet();
const algod = algorand.client.algod;
const sha = (...parts: Uint8Array[]) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
const firstLine = (e: unknown) => (e instanceof Error ? e.message : String(e)).split('\n')[0]!.replace(/^.*?(TransactionPool\.Remember: |logic eval error: )/, '').slice(0, 140);

const poster = algorand.account.random();
await algorand.account.ensureFunded(poster, await algorand.account.localNetDispenser(), algo(2_000));
const { appClient: app } = await algorand.client.getTypedAppFactory(BroadcastProbeFactory, { defaultSender: poster.addr }).send.create.bare();
await algorand.send.payment({ sender: poster, receiver: app.appAddress, amount: algo(10) }); // Digest boxes: 18,900 µAlgo each.
const params = await algod.getTransactionParams().do();
console.log(`Consensus ${params.consensusVersion}; suggested fee ${params.fee} µAlgo/byte, min fee ${params.minFee} µAlgo.`);

// Arguments are selector (4) + seat (8) + four byte[] parts (2-byte length prefix each) = 20 bytes of overhead.
const OVERHEAD = 20;
const boxName = (seat: bigint) => Buffer.concat([Buffer.from('d'), Buffer.from(encodeUint64(seat))]);
const split = (data: Uint8Array) => { const q = Math.ceil(data.length / 4); return [0, 1, 2, 3].map(i => data.subarray(i * q, (i + 1) * q)); };
const postCall = (seat: bigint, data: Uint8Array, note: Uint8Array, fee: number) => {
  const [a, b, c, d] = split(data);
  return { args: { seat, a: a!, b: b!, c: c!, d: d! }, note, staticFee: microAlgo(fee), boxReferences: [boxName(seat)] };
};
const send = (seat: bigint, data: number, note: number, fee: number) => app.send.post(postCall(seat, randomBytes(data), randomBytes(note), fee));

/** Smallest accepted fee, or the rejection when even 1 Algo is refused. */
async function minFee(dataBytes: number, noteBytes: number): Promise<number | string> {
  let lo = 0, hi = 1000, last = '';
  for (;;) {
    try { await send(999n, dataBytes, noteBytes, hi); break; } catch (e) { last = firstLine(e); }
    if (hi >= 1_000_000) return last;
    [lo, hi] = [hi, hi * 2];
  }
  while (hi - lo > 1) {
    const mid = Math.floor((lo + hi) / 2);
    try { await send(999n, dataBytes, noteBytes, mid); hi = mid; } catch { lo = mid; }
  }
  return hi;
}

console.log('\n## Limits and fees (one app call)');
const cases: [string, number, number][] = [
  ['args 2,048 total, no note', 2048 - OVERHEAD, 0], ['args 2,049', 2049 - OVERHEAD, 0], ['args 4,096', 4096 - OVERHEAD, 0],
  ['args 8,192', 8192 - OVERHEAD, 0], ['args 16,384', 16384 - OVERHEAD, 0], ['args 16,385', 16385 - OVERHEAD, 0],
  ['note 1,024', 0, 1024], ['note 1,025', 0, 1025], ['note 4,096', 0, 4096], ['note 4,097', 0, 4097],
  ['args 16,384 + note 4,096', 16384 - OVERHEAD, 4096],
];
const fees = new Map<string, number | string>();
for (const [name, data, note] of cases) {
  const fee = await minFee(data, note);
  fees.set(name, fee);
  console.log(`- ${name}: ${typeof fee === 'number' ? `minimum fee ${fee} µAlgo` : `rejected (${fee})`}`);
}

// One epoch of handover data: C dealings of t·48 + C·240 bytes (the pairing prototype's sizes).
console.log('\n## Posting one epoch of handover data');
async function postEpoch(base: number, C: number, t: number, data: number, note: number, fee: number) {
  const dealing = t * 48 + C * 240, perTxn = data + note;
  const calls = Array.from({ length: C }, (_, j) => {
    const message = randomBytes(dealing);
    return Array.from({ length: Math.ceil(dealing / perTxn) }, (_, i) => {
      const chunk = message.subarray(i * perTxn, (i + 1) * perTxn);
      return postCall(BigInt(base + j), chunk.subarray(0, data), chunk.subarray(data), fee);
    });
  }).flat();
  const start = (await algod.status().do()).lastRound;
  const began = performance.now();
  for (let i = 0; i < calls.length; i += 16) {
    const group = app.newGroup(); // Typed composer methods add to the group in place.
    for (const call of calls.slice(i, i + 16)) group.post(call);
    await group.send();
  }
  const end = (await algod.status().do()).lastRound;
  const seconds = (performance.now() - began) / 1000;
  console.log(`- C = ${C}, t = ${t}, ${(C * dealing / 2 ** 20).toFixed(2)} MiB at ${perTxn} bytes per call: ${calls.length} calls in ` +
    `${Math.ceil(calls.length / 16)} groups, rounds ${start + 1n}–${end}, ${(calls.length * fee / 1e6).toFixed(3)} Algo in fees, ${seconds.toFixed(1)} s to submit on LocalNet`);
  return { base, C, start, end };
}

// The cheapest packing at the measured fees: extended limits, or the base 2,048-byte args + 1,024-byte note.
const extended = fees.get('args 16,384 + note 4,096'), base = fees.get('args 2,048 total, no note');
const packings: [string, number, number, number][] = [];
if (typeof base === 'number') packings.push(['base', 2048 - OVERHEAD, 1024, base]);
if (typeof extended === 'number') packings.push(['extended', 16384 - OVERHEAD, 4096, extended]);
for (const [name, data, note, fee] of packings) {
  console.log(`- ${name} packing: ${((fee / (data + note)) * 1024).toFixed(1)} µAlgo per KiB`);
}
const [, data, note, fee] = packings.reduce((a, b) => (a[3] / (a[1] + a[2]) <= b[3] / (b[1] + b[2]) ? a : b));
const epochs = [await postEpoch(1000, 120, 44, data, note, fee), await postEpoch(2000, 200, 72, data, note, fee)]; // Distinct seats per epoch.

// A reader rebuilds every seat's running digest from block data alone and compares it with the on-chain box.
console.log('\n## Rebuilding messages from blocks through algod');
for (const { base, C, start, end } of epochs) {
  const began = performance.now();
  const digests = new Map<bigint, Buffer>();
  let bytes = 0;
  for (let r = start + 1n; r <= end; r++) {
    for (const s of (await algod.block(r).do()).block.payset) {
      const txn = s.signedTxn.signedTxn.txn, call = txn.applicationCall;
      if (call?.appIndex !== app.appId || call.appArgs.length !== 6) continue;
      const args = call.appArgs;
      const seat = Buffer.from(args[1]!).readBigUInt64BE(0);
      if (seat < base || seat >= base + C) continue;
      const parts = args.slice(2).map(a => a.subarray(2));
      bytes += parts.reduce((n, p) => n + p.length, 0) + txn.note.length;
      digests.set(seat, sha(digests.get(seat) ?? Buffer.alloc(32), ...parts.map(p => sha(p)), sha(txn.note)));
    }
  }
  const seconds = (performance.now() - began) / 1000;
  let matches = 0;
  for (const [seat, digest] of digests) {
    if (Buffer.from((await algod.getApplicationBoxByName(app.appId, boxName(seat)).do()).value).equals(digest)) matches++;
  }
  console.log(`- C = ${C}: ${end - start} blocks, ${(bytes / 2 ** 20).toFixed(2)} MiB read in ${seconds.toFixed(1)} s; ${matches}/${C} seat digests match the chain`);
}
const archival = await algod.block(1).do().then(() => true, () => false);
console.log(`- Block 1 is ${archival ? 'available: this LocalNet node is archival' : 'gone: this node prunes old blocks'}.`);

// `block` only reads rounds in (LastValid − 1002, FirstValid), so a seed read needs a short validity window.
console.log('\n## Block seed lookback (simulated reads, validity window 10 rounds)');
const last = (await algod.status().do()).lastRound;
for (const back of [0n, 1n, 500n, 990n, 991n, 1000n]) {
  const seed = await app.seed({ args: { round: last - back }, firstValidRound: last + 1n, validityWindow: 10 }).then((s: Uint8Array) => Buffer.from(s).toString('hex').slice(0, 16), firstLine);
  console.log(`- lastRound − ${back}: ${seed}`);
}

console.log('\n## Stake opcodes');
const kmd = algorand.client.kmd;
const wallet = (await kmd.listWallets()).wallets.find((w: { name: string }) => w.name === 'unencrypted-default-wallet')!;
const handle = (await kmd.initWalletHandle(wallet.id, '')).wallet_handle_token;
for (const address of [...(await kmd.listKeys(handle)).addresses, poster.addr.toString()]) {
  const [total, balance, online] = (await app.stake({ args: { account: address } }));
  const status = (await algod.accountInformation(address).do()).status;
  console.log(`- ${address.slice(0, 8)}… (${status}): online_stake ${total}, voter balance ${balance}, voter params present ${online}`);
}
