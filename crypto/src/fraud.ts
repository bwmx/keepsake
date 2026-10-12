import { sha256 } from '@noble/hashes/sha2.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { check } from './crypto.js';
import type { Message } from './ecpss.js';
import { batchOk, seatCommitment, type Dealing, type Form, type G1Point, type G2Point, type Subshare } from './pvss.js';

/**
 * UNREVIEWED. Fraud proofs for bad dealings (docs/design.md, Accountability; after eprint 2026/919).
 * A holder commits, when it claims its seat, to a Merkle root over one leaf per dealing and recipient: the recipient's
 * key, the commitment its subshare should open to (E = Σ_i w_i(k)·C_i, from the dealing's commitments) and the
 * encrypted subshare. A leaf whose subshare fails its two pairing checks against E is provable on chain with the leaf
 * and its path, at a cost independent of t; the contract slashes the holder's bond. Leaves use the point encodings
 * Algorand's ec_* opcodes take, so the contract hashes exactly what it pairs. Honest holders cannot be framed: every
 * leaf an honest holder signs passes.
 *
 * Not a deterrent on its own: a cheater can sign a root that does not cover its bad subshare (or names a matching E),
 * and its message is then merely dropped, as if it were silent. Verifiers never check roots for that reason (and it
 * would cost them a multi-scalar multiplication per leaf). Penalizing non-delivery needs more (eprint 2026/919's
 * time-lock puzzles).
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

/** Kinds as in the message wire format: 0 a re-sharing, 1 a contribution, 4 a pack, 5 an unpack. */
export type Kind = 0 | 1 | 4 | 5;
/** One leaf: sha256 over the domain, id (bucket, or 0), kind, recipient seat k, its key, E and the subshare (encoded). */
export const dealingLeaf = (id: bigint, kind: Kind, k: number, epk: Uint8Array, expected: G1Point, s: Subshare) => sha(
  Buffer.from('ecpss/leaf/v2'), u64(id), Buffer.from([kind]), u64(k), epk, avmG1(expected), avmG1(s.r1), avmG2(s.r2), avmG2(s.b));

type Dealings = Pick<Message, 'reshares' | 'contributions' | 'pack' | 'unpack'>;
/** A message's dealings in leaf order, each with its commitments' form: re-sharings then contributions by bucket, then a pack or an unpack. */
export const leafDealings = (m: Dealings) => [
  ...(['reshares', 'contributions'] as const).flatMap((field, i) => [...m[field]].sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([id, dealing]) => ({ id, kind: i as Kind, dealing, form: 'coefficients' as Form }))),
  ...(m.pack ? [{ id: 0n, kind: 4 as Kind, dealing: m.pack, form: 'evaluations' as Form }] : []),
  ...(m.unpack ? [{ id: 0n, kind: 5 as Kind, dealing: m.unpack, form: 'coefficients' as Form }] : []),
];

/** Recipient k's commitment E: the dealer's own record when it has one, else computed from the commitments. */
const expectedFor = (d: Dealing, k: number, form: Form) => d.expected?.[k - 1] ?? seatCommitment(d.commitments, k, form);

/** Every leaf of a message: for each dealing in leaf order, recipients 1..n. `next`: the recipients' keys, encoded. */
export const messageLeaves = (m: Dealings, next: Uint8Array[]) => leafDealings(m).flatMap(({ id, kind, dealing, form }) =>
  dealing.subshares.map((s, i) => dealingLeaf(id, kind, i + 1, next[i]!, expectedFor(dealing, i + 1, form), s)));

/** A message's dealings root, as its holder commits to it when claiming the seat. */
export const dealingsRoot = (m: Dealings, next: Uint8Array[]) => merkleRoot(messageLeaves(m, next));

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

/** Whether a subshare passes both pairing checks against commitment E and the recipient's key: what the contract checks. */
export function subshareValid(s: Subshare, expected: G1Point, epk: G2Point) {
  const one = (pairs: { g1: G1Point; g2: G2Point }[]) => bls.fields.Fp12.eql(bls.pairingBatch(pairs), bls.fields.Fp12.ONE);
  const neg = G1.Point.BASE.negate();
  try {
    return one([{ g1: s.r1, g2: G2.Point.BASE }, { g1: neg, g2: s.r2 }]) && one([{ g1: neg, g2: s.b }, { g1: expected, g2: G2.Point.BASE }, { g1: s.r1, g2: epk }]);
  } catch {
    return false; // An identity point cannot be paired.
  }
}

/** What `reportBadDealing` takes: the leaf's fields in opcode encodings, and its path to the holder's root. */
export interface FraudProof {
  index: number; path: Buffer; id: bigint; kind: Kind; k: number;
  epk: Buffer; expected: Buffer; r1: Buffer; r2: Buffer; b: Buffer;
}

/**
 * The first subshare of a message that fails its checks, as a fraud proof against `root` (the holder's signed root);
 * undefined if every subshare passes or the message's leaves do not hash to `root`. Dealings that pass one batch check
 * are skipped, so a single bad dealing costs a pairing check per recipient, and leaves are built only once one is found.
 */
export function findBadDealing(m: Dealings, next: G2Point[], root: Uint8Array): FraudProof | undefined {
  let index = 0;
  for (const { id, kind, dealing, form } of leafDealings(m)) {
    check(dealing.subshares.length === next.length, 'Malformed dealing');
    if (batchOk([dealing], next, dealing.commitments.length, form)) { index += next.length; continue; }
    for (let k = 1; k <= next.length; k++, index++) {
      const s = dealing.subshares[k - 1]!, expected = expectedFor(dealing, k, form);
      if (subshareValid(s, expected, next[k - 1]!)) continue;
      const encoded = next.map(avmG2), leaves = messageLeaves(m, encoded);
      if (!merkleRoot(leaves).equals(Buffer.from(root))) return undefined; // Not what the holder signed: nothing to prove.
      return { index, path: Buffer.concat(merklePath(leaves, index)), id, kind, k, epk: encoded[k - 1]!,
        expected: avmG1(expected), r1: avmG1(s.r1), r2: avmG2(s.r2), b: avmG2(s.b) };
    }
  }
  return undefined;
}
