import { createHash, randomBytes } from 'node:crypto';
import { pippenger } from '@noble/curves/abstract/curve.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';

/**
 * UNREVIEWED: the pairing-based re-sharing sketched in PAPER_ALIGNMENT_PLAN.md (decision D2). Not for real secrets.
 *
 * A secret is a G2 element S = s·g2 with public key P = s·g1. A holder's share is σ·g2 with public commitment σ·g1.
 * A dealer sends each next-committee seat its subshare ElGamal-encrypted in G2 to that seat's ephemeral key, plus
 * r·g1, so anyone can check every subshare with pairings against the dealer's G1 polynomial commitments.
 */
const { G1, G2 } = bls;
const { Fr, Fp12 } = bls.fields;
export type G1Point = typeof G1.Point.BASE;
export type G2Point = typeof G2.Point.BASE;
export type GT = ReturnType<typeof bls.pairing>;

export interface Subshare { r1: G1Point; r2: G2Point; b: G2Point } // r·g1, r·g2, M + r·epk
export interface Proof { c: bigint; z: bigint }
export interface Dealing {
  dealer: number; // The dealer's seat (evaluation point) in the current committee.
  commitments: G1Point[]; // A_0..A_(t-1): A_0 is the dealer's share commitment, or z·g1 for a new-key contribution.
  subshares: Subshare[]; // One per next-committee seat 1..n, in seat order.
  pok?: Proof; // New-key contributions only: knowledge of A_0's discrete log, against rogue-key choices.
}

export const ORDER = Fr.ORDER;
const mod = (x: bigint) => ((x % ORDER) + ORDER) % ORDER;
export const randomScalar = (bits = 384): bigint => {
  for (;;) {
    const x = mod(BigInt(`0x${randomBytes(bits / 8).toString('hex')}`));
    if (x !== 0n) return x;
  }
};
const g1 = (x: bigint) => (mod(x) === 0n ? G1.Point.ZERO : G1.Point.BASE.multiply(mod(x)));
const g2 = (x: bigint) => (mod(x) === 0n ? G2.Point.ZERO : G2.Point.BASE.multiply(mod(x)));
export const hashScalar = (domain: string, ...parts: Uint8Array[]) => {
  const h = createHash('sha512').update(domain);
  for (const p of parts) h.update(p);
  return mod(BigInt(`0x${h.digest('hex')}`));
};
const u32 = (n: number) => Buffer.from(n.toString(16).padStart(8, '0'), 'hex');

/** Σ_l coefficients[l]·k^l (Horner). */
export function evaluate(coefficients: bigint[], k: bigint): bigint {
  let acc = 0n;
  for (let l = coefficients.length - 1; l >= 0; l--) acc = mod(acc * k + coefficients[l]!);
  return acc;
}

/** Lagrange coefficients at 0 for the given seats. */
export function lagrange(seats: number[]): bigint[] {
  return seats.map(j => {
    let num = 1n, den = 1n;
    for (const m of seats) if (m !== j) [num, den] = [mod(num * BigInt(m)), mod(den * BigInt(m - j))];
    return mod(num * Fr.inv(den));
  });
}

/** Schnorr proof of knowledge of x with X = x·g1, bound to a label. */
export function proveG1(x: bigint, X: G1Point, label: Uint8Array): Proof {
  const w = randomScalar();
  const c = hashScalar('pvss/pok/v1', label, X.toBytes(), g1(w).toBytes());
  return { c, z: mod(w + c * x) };
}
export function verifyG1(X: G1Point, proof: Proof, label: Uint8Array): boolean {
  if (X.is0() || proof.c >= ORDER || proof.z >= ORDER) return false;
  const a = g1(proof.z).subtract(X.multiplyUnsafe(proof.c)); // z·g1 − c·X
  return proof.c === hashScalar('pvss/pok/v1', label, X.toBytes(), a.toBytes());
}
const pokLabel = (context: Uint8Array, dealer: number) => Buffer.concat([context, u32(dealer)]);

/**
 * Deal `share` (with public commitment `commitment`) to the next committee's ephemeral keys, threshold t.
 * For a new-key contribution pass share z·g2, commitment z·g1 and z itself, which adds a proof of knowledge bound to
 * `context` (for example the committee and bucket) and the dealer's seat.
 */
export function deal(dealer: number, share: G2Point, commitment: G1Point, epks: G2Point[], t: number, z?: bigint,
  context: Uint8Array = new Uint8Array()): Dealing {
  const a = [0n, ...Array.from({ length: t - 1 }, () => randomScalar())];
  return {
    dealer,
    commitments: [commitment, ...a.slice(1).map(g1)],
    subshares: epks.map((epk, i) => {
      const r = randomScalar();
      return { r1: g1(r), r2: g2(r), b: share.add(g2(evaluate(a, BigInt(i + 1)))).add(epk.multiply(r)) };
    }),
    ...(z === undefined ? {} : { pok: proveG1(z, commitment, pokLabel(context, dealer)) }),
  };
}

/**
 * The dealings that pass, keeping their order. Re-sharing passes `prior` (each dealer's current share commitment, which
 * A_0 must equal); new-key contributions instead need a valid proof of knowledge for `context`. All subshares are checked
 * in one random-linear-combination batch, bisected when it fails:
 *   e(Σρ·r1, g2) = e(g1, Σρ·r2)  and  e(g1, Σρ·b) = e(Σ_jl c_jl·A_jl, g2) · Π_k e(W_k, epk_k),
 * with ρ_jk = α_j·β_k (sound with probability about 2^-127), c_jl = α_j·Σ_k β_k·k^l and W_k = Σ_j ρ_jk·r1_jk.
 */
export function validDealings(dealings: Dealing[], epks: G2Point[], t: number,
  o: { prior?: Map<number, G1Point>; context?: Uint8Array } = {}): Dealing[] {
  const seen = new Set<number>();
  const shaped = dealings.filter(d => {
    const ok = !seen.has(d.dealer) && d.commitments.length === t && d.subshares.length === epks.length &&
      (o.prior ? !!o.prior.get(d.dealer)?.equals(d.commitments[0]!)
        : !!d.pok && verifyG1(d.commitments[0]!, d.pok, pokLabel(o.context ?? new Uint8Array(), d.dealer)));
    seen.add(d.dealer);
    return ok;
  });
  return bisect(shaped, epks, t);
}

function bisect(dealings: Dealing[], epks: G2Point[], t: number): Dealing[] {
  if (!dealings.length || batchOk(dealings, epks, t)) return dealings;
  if (dealings.length === 1) return [];
  const mid = dealings.length >> 1;
  return [...bisect(dealings.slice(0, mid), epks, t), ...bisect(dealings.slice(mid), epks, t)];
}

function batchOk(dealings: Dealing[], epks: G2Point[], t: number): boolean {
  try {
    const alpha = dealings.map(() => randomScalar(128)), beta = epks.map(() => randomScalar(128));
    const gamma = Array.from({ length: t }, (_, l) => beta.reduce((s, b, k) => mod(s + b * mod(BigInt(k + 1) ** BigInt(l))), 0n));
    const rho = dealings.flatMap((_, j) => beta.map(b => mod(alpha[j]! * b)));
    const all = dealings.flatMap(d => d.subshares);
    const W = epks.map((_, k) => pippenger(G1.Point, dealings.map(d => d.subshares[k]!.r1), dealings.map((_, j) => mod(alpha[j]! * beta[k]!))));
    const cv = pippenger(G1.Point, dealings.flatMap(d => d.commitments), dealings.flatMap((_, j) => gamma.map(g => mod(alpha[j]! * g))));
    const negG1 = G1.Point.BASE.negate();
    const isOne = (x: GT) => Fp12.eql(x, Fp12.ONE);
    return isOne(bls.pairingBatch([{ g1: W.reduce((x, y) => x.add(y)), g2: G2.Point.BASE }, { g1: negG1, g2: pippenger(G2.Point, all.map(s => s.r2), rho) }])) &&
      isOne(bls.pairingBatch([{ g1: negG1, g2: pippenger(G2.Point, all.map(s => s.b), rho) }, { g1: cv, g2: G2.Point.BASE },
        ...W.map((w, k) => ({ g1: w, g2: epks[k]! }))]));
  } catch {
    return false; // An identity point cannot be paired.
  }
}

/** The next committee's polynomial commitments from the chosen dealings: A'_l = Σ_j weight_j·A_jl. */
export const aggregate = (dealings: Dealing[], weights: bigint[]): G1Point[] =>
  dealings[0]!.commitments.map((_, l) => pippenger(G1.Point, dealings.map(d => d.commitments[l]!), weights));

/** Seat k's public share commitment from polynomial commitments: Σ_l k^l·A_l. */
export const seatCommitment = (poly: G1Point[], k: number): G1Point =>
  pippenger(G1.Point, poly, poly.map((_, l) => mod(BigInt(k) ** BigInt(l))));

/**
 * Seat k's new share from the chosen dealings: weights are Lagrange coefficients over the dealers' seats when
 * re-sharing, or all 1 when summing new-key contributions.
 */
export function combine(k: number, x: bigint, dealings: Dealing[], weights: bigint[]): G2Point {
  return pippenger(G2.Point, dealings.map(d => d.subshares[k - 1]!).map(s => s.b.subtract(s.r2.multiply(x))), weights);
}

/** Capsule KEM: key = e(P, g2)^r with u = r·g1, plus a proof of r bound to the capsule's policy label. */
export function encapsulate(publicKey: G1Point, label: Uint8Array) {
  const r = randomScalar(), u = g1(r);
  return { u, proof: proveG1(r, u, label), key: bls.pairing(publicKey.multiply(r), G2.Point.BASE) };
}

/** Holder's decryption partial e(u, S_k) with a proof that the S_k behind its commitment was used. */
export interface Partial { d: GT; proof: { c: bigint; z: G2Point } }
export function partial(share: G2Point, commitment: G1Point, u: G1Point): Partial {
  const d = bls.pairing(u, share), w = randomScalar();
  const W = g2(w);
  const c = partialChallenge(commitment, u, d, bls.pairing(G1.Point.BASE, W), bls.pairing(u, W));
  return { d, proof: { c, z: W.add(share.multiply(c)) } };
}
export function verifyPartial(commitment: G1Point, u: G1Point, p: Partial): boolean {
  try {
    const { c, z } = p.proof;
    const a1 = bls.pairingBatch([{ g1: G1.Point.BASE, g2: z }, { g1: commitment.multiply(c).negate(), g2: G2.Point.BASE }]);
    const a2 = Fp12.mul(bls.pairing(u, z), Fp12.pow(p.d, ORDER - c));
    return c === partialChallenge(commitment, u, p.d, a1, a2);
  } catch {
    return false;
  }
}
const partialChallenge = (commitment: G1Point, u: G1Point, d: GT, a1: GT, a2: GT) =>
  hashScalar('pvss/partial/v1', commitment.toBytes(), u.toBytes(), Fp12.toBytes(d), Fp12.toBytes(a1), Fp12.toBytes(a2));

/** The KEM key from t verified partials of distinct seats. */
export function combinePartials(parts: { seat: number; d: GT }[]): GT {
  const weights = lagrange(parts.map(p => p.seat));
  return parts.reduce((acc, p, i) => Fp12.mul(acc, Fp12.pow(p.d, weights[i]!)), Fp12.ONE);
}

// --- Encoding: compressed points (48-byte G1, 96-byte G2), 32-byte big-endian scalars ---

const SCALAR = 32;
const scalarBytes = (x: bigint) => Buffer.from(x.toString(16).padStart(SCALAR * 2, '0'), 'hex');
export const dealingSize = (n: number, t: number, contribution: boolean) => t * 48 + n * 240 + (contribution ? 2 * SCALAR : 0);

export function encodeDealing(d: Dealing): Buffer {
  return Buffer.concat([...d.commitments.map(p => p.toBytes()), ...d.subshares.flatMap(s => [s.r1.toBytes(), s.r2.toBytes(), s.b.toBytes()]),
    ...(d.pok ? [scalarBytes(d.pok.c), scalarBytes(d.pok.z)] : [])]);
}

/** Strict decoding of untrusted bytes: exact length, canonical scalars, curve and subgroup checks, no identity points. */
export function decodeDealing(bytes: Uint8Array, dealer: number, n: number, t: number, contribution: boolean): Dealing {
  if (bytes.length !== dealingSize(n, t, contribution)) throw new Error('Bad dealing length');
  let at = 0;
  const take = (len: number) => bytes.subarray(at, (at += len));
  const p1 = () => decodeG1(take(48)), p2 = () => decodeG2(take(96));
  const scalar = () => { const x = BigInt(`0x${Buffer.from(take(SCALAR)).toString('hex')}`); if (x >= ORDER) throw new Error('Non-canonical scalar'); return x; };
  const commitments = Array.from({ length: t }, p1);
  const subshares = Array.from({ length: n }, () => ({ r1: p1(), r2: p2(), b: p2() }));
  return { dealer, commitments, subshares, ...(contribution ? { pok: { c: scalar(), z: scalar() } } : {}) };
}

const nonZero = <P extends { is0(): boolean }>(p: P) => { if (p.is0()) throw new Error('Identity point'); return p; };
/** Untrusted compressed points: curve and subgroup checked (by noble), identity rejected. */
export const decodeG1 = (bytes: Uint8Array): G1Point => nonZero(G1.Point.fromBytes(bytes));
export const decodeG2 = (bytes: Uint8Array): G2Point => nonZero(G2.Point.fromBytes(bytes));

export const point = { g1, g2 };
