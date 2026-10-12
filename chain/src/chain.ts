import { type Algodv2, encodeUint64 } from 'algosdk';
import { check } from 'keepsake-crypto/dist/src/crypto.js';

const u64 = (n: bigint) => Buffer.from(encodeUint64(n));
export const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
export const b64url = (b: Uint8Array) => Buffer.from(b).toString('base64url');

/** VRF output → rank compared with the contract's ticketThreshold; lower wins. */
export const vrfRank = (output: Uint8Array) => Buffer.from(output).readBigUInt64BE(0);

/** Values a member or client pins out of band; never taken from the data it is checking. */
export interface ChainPins {
  genesisHash: string; // base64, as algod reports it
  appId: bigint;
  maxRoundAgeMs: number; // 0 disables the staleness check (dev-mode LocalNet only produces blocks on demand)
}

/**
 * Reads confirmed app state from ONE algod node the operator trusts. Fails closed on a wrong network, a node that is
 * catching up or stale, or a missing box. Not a light client: a lying node can still lie.
 */
export class ChainReader {
  constructor(readonly algod: Algodv2, readonly pins: ChainPins) {}

  async lastRound(): Promise<bigint> {
    const [version, status] = await Promise.all([this.algod.versionsCheck().do(), this.algod.status().do()]);
    check(Buffer.from(version.genesisHashB64).toString('base64') === this.pins.genesisHash, 'Wrong network');
    check(status.catchupTime === 0n && !status.stoppedAtUnsupportedRound, 'Node not synced');
    check(this.pins.maxRoundAgeMs === 0 || Number(status.timeSinceLastRound / 1_000_000n) <= this.pins.maxRoundAgeMs,
      'Node state is stale');
    return status.lastRound;
  }

  protected box(...parts: Uint8Array[]) {
    return this.algod.getApplicationBoxByName(this.pins.appId, Buffer.concat(parts)).do();
  }

  /** Member `index`'s nomination key for `epoch`, or undefined if it never posted one (or it was rotated out). */
  async nominationKey(epoch: bigint, index: bigint): Promise<Uint8Array | undefined> {
    const value = await this.box(Buffer.from('k'), u64(index), u64(epoch % 3n)).then(b => Buffer.from(b.value),
      (e: { response?: { status?: number } }) => { if (e.response?.status !== 404) throw e; });
    return value && value.readBigUInt64BE(0) === epoch ? value.subarray(8, 40) : undefined; // EpochKey: uint64 || byte[32]
  }
}
