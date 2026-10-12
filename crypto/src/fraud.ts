import { sha256 } from '@noble/hashes/sha2.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { check } from './crypto.js';
import type { Message } from './ecpss.js';
import { ORDER, type Dealing, type G1Point, type G2Point, type Subshare } from './pvss.js';

/**
 * UNREVIEWED. Fraud proofs for bad dealings (PAPER_ALIGNMENT_PLAN.md, the accountability spike after eprint 2026/919).
 * A holder commits, when it claims its seat, to a Merkle root over one leaf per dealing and recipient: the recipient's
 * key, the dealing's commitments and the encrypted subshare. A subshare that fails its pairing checks is then provable
 * on-chain with one leaf and its path; the contract slashes the holder's bond. Leaves use the point encodings Algorand's
 * ec_* opcodes take, so the contract hashes exactly what it pairs. Honest holders cannot be framed: every leaf of an
 * honest dealing passes. A root that does not match the posted message makes verifiers drop the message (as silence).
 */
const { G1, G2 } = bls;
const be48 = (x: bigint) => Buffer.from(x.toString(16).padStart(96, '0'), 'hex');
/** A G1 point as ec_* opcodes take it: X || Y, big-endian (96 bytes). */
export const avmG1 = (p: G1Point) => { const { x, y } = p.toAffine(); return Buffer.concat([be48(x), be48(y)]); };
/** A G2 point as ec_* opcodes take it: X0 || X1 || Y0 || Y1, big-endian, Fp2 as c0 then c1 (192 bytes). */
export const avmG2 = (p: G2Point) => { const { x, y } = p.toAffine(); return Buffer.concat([be48(x.c0), be48(x.c1), be48(y.c0), be48(y.c1)]); };
export const fromAvmG1 = (b: Uint8Array) => G1.Point.fromAffine({ x: big(b.subarray(0, 48)), y: big(b.subarray(48, 96)) });
export const fromAvmG2 = (b: Uint8Array) => G2.Point.fromAffine({
  x: { c0: big(b.subarray(0, 48)), c1: big(b.subarray(48, 96)) }, y: { c0: big(b.subarray(96, 144)), c1: big(b.subarray(144, 192)) },
});
const big = (b: Uint8Array) => BigInt(`0x${Buffer.from(b).toString('hex')}`);
const sha = (...parts: Uint8Array[]) => { const h = sha256.create(); for (const p of parts) h.update(p); return Buffer.from(h.digest()); };
const u64 = (n: bigint | number) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };

/** Kinds as in the message wire format: 0 a re-sharing, 1 a new-key contribution. */
export type Kind = 0 | 1;
/**
 * One leaf: sha256 over the domain, bucket, kind, recipient seat k, its key (encoded), the hash of the dealing's
 * encoded commitments, and the subshare.
 */
export const dealingLeaf = (bucket: bigint, kind: Kind, k: number, epk: Uint8Array, commitmentsHash: Uint8Array, s: Subshare) => sha(
  Buffer.from('ecpss/leaf/v1'), u64(bucket), Buffer.from([kind]), u64(k), epk, commitmentsHash, avmG1(s.r1), avmG2(s.r2), avmG2(s.b));

/** A message's dealings in leaf order: re-sharings then contributions, each by bucket. */
export const leafDealings = (m: Pick<Message, 'reshares' | 'contributions'>) => (['reshares', 'contributions'] as const).flatMap((kind, i) =>
  [...m[kind]].sort(([a], [b]) => (a < b ? -1 : 1)).map(([bucket, d]) => ({ bucket, kind: i as Kind, dealing: d })));

/** Every leaf of a message: for each dealing in leaf order, recipients 1..n. `next`: the recipients' keys, encoded. */
export const messageLeaves = (m: Pick<Message, 'reshares' | 'contributions'>, next: Uint8Array[]) =>
  leafDealings(m).flatMap(({ bucket, kind, dealing }) => {
    const commitmentsHash = sha(...dealing.commitments.map(avmG1));
    return dealing.subshares.map((s, i) => dealingLeaf(bucket, kind, i + 1, next[i]!, commitmentsHash, s));
  });

/** A message's dealings root, as its holder commits to it when claiming the seat. */
export const dealingsRoot = (m: Pick<Message, 'reshares' | 'contributions'>, next: Uint8Array[]) => merkleRoot(messageLeaves(m, next));

// A binary Merkle tree padded with zero leaves to a power of two; a node is sha256(left || right).
function levels(leaves: Buffer[]) {
  let level = [...leaves];
  while (level.length & (level.length - 1) || level.length === 0) level.push(Buffer.alloc(32));
  const out = [level];
  while (level.length > 1) {
    const prev = level;
    level = Array.from({ length: prev.length / 2 }, (_, i) => sha(prev[2 * i]!, prev[2 * i + 1]!));
    out.push(level);
  }
  return out;
}
export const merkleRoot = (leaves: Buffer[]) => levels(leaves).at(-1)![0]!;
/** Siblings from the leaf up; the contract walks them with the leaf's index bits (0: the node is on the left). */
export const merklePath = (leaves: Buffer[], index: number) => levels(leaves).slice(0, -1).map((level, d) => level[(index >> d) ^ 1]!);

/** Whether one subshare passes both pairing checks against its dealing's commitments and the recipient's key. */
export function subshareValid(d: Dealing, k: number, epk: G2Point, t: number) {
  const s = d.subshares[k - 1]!;
  let c = G1.Point.ZERO, power = 1n;
  for (let l = 0; l < t; l++) { c = c.add(d.commitments[l]!.multiply(power)); power = (power * BigInt(k)) % ORDER; }
  const one = (pairs: { g1: G1Point; g2: G2Point }[]) => bls.fields.Fp12.eql(bls.pairingBatch(pairs), bls.fields.Fp12.ONE);
  const neg = G1.Point.BASE.negate();
  try {
    return one([{ g1: s.r1, g2: G2.Point.BASE }, { g1: neg, g2: s.r2 }]) && one([{ g1: neg, g2: s.b }, { g1: c, g2: G2.Point.BASE }, { g1: s.r1, g2: epk }]);
  } catch {
    return false; // An identity point cannot be paired.
  }
}

/** What `reportBadDealing` takes: the leaf's fields in opcode encodings, and its path to the holder's root. */
export interface FraudProof {
  index: number; path: Buffer; bucket: bigint; kind: Kind; k: number;
  epk: Buffer; commitments: Buffer; r1: Buffer; r2: Buffer; b: Buffer;
}

/** The first subshare of a message that fails its checks, as a fraud proof against its root; undefined if none does. */
export function findBadDealing(m: Pick<Message, 'reshares' | 'contributions'>, next: G2Point[], t: number): FraudProof | undefined {
  const encoded = next.map(avmG2), leaves = messageLeaves(m, encoded);
  let index = 0;
  for (const { bucket, kind, dealing } of leafDealings(m)) {
    check(dealing.subshares.length === next.length && dealing.commitments.length === t, 'Malformed dealing');
    for (let k = 1; k <= next.length; k++, index++) {
      if (subshareValid(dealing, k, next[k - 1]!, t)) continue;
      const s = dealing.subshares[k - 1]!;
      return { index, path: Buffer.concat(merklePath(leaves, index)), bucket, kind, k, epk: encoded[k - 1]!,
        commitments: Buffer.concat(dealing.commitments.map(avmG1)), r1: avmG1(s.r1), r2: avmG2(s.r2), b: avmG2(s.b) };
    }
  }
  return undefined;
}
