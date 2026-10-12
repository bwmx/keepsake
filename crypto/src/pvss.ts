import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { pippenger } from '@noble/curves/abstract/curve.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';

/**
 * UNREVIEWED: the pairing-based re-sharing described in docs/design.md (The cryptography). Not for real secrets.
 *
 * A secret is a G2 element S = s·g2 with public key P = s·g1. A holder's share is σ·g2 with public commitment σ·g1.
 * A dealer sends each next-committee seat its subshare ElGamal-encrypted in G2 to that seat's ephemeral key, plus
 * r·g1, so anyone can check every subshare with pairings against the dealer's G1 polynomial commitments.
 */
const { G1, G2 } = bls;
const { Fr, Fp12 } = bls.fields;
const check = (ok: boolean, message: string) => { if (!ok) throw new Error(message); };
export type G1Point = typeof G1.Point.BASE;
export type G2Point = typeof G2.Point.BASE;
export type GT = ReturnType<typeof bls.pairing>;

export interface Subshare { r1: G1Point; r2: G2Point; b: G2Point } // r·g1, r·g2, M + r·epk
export interface Proof { c: bigint; z: bigint }
/**
 * A dealing's polynomial has m values v_0..v_(m-1) and seat k's share is Σ_i w_i(k)·v_i, where the weights w(k) come
 * from its form: powers of k (coefficient form, v_0 the constant term) or Lagrange coefficients at k over the points
 * −1..−m (evaluation form, v_i the value at −(i+1)), which packs several secrets into one polynomial.
 */
export type Form = 'coefficients' | 'evaluations';
export interface Dealing {
  dealer: number; // The dealer's seat (evaluation point) in the current committee.
  // C_i = v_i·g1. The first values (the heads) are dealt shares, whose commitments are public, or new-key contributions
  // z·g1; the rest are random.
  commitments: G1Point[];
  subshares: Subshare[]; // One per next-committee seat 1..n, in seat order.
  proofs: Proof[]; // One per new-key contribution head (the last heads): knowledge of z, against rogue-key choices.
  expected?: G1Point[]; // Dealer side only, never on the wire: each recipient's commitment Σ_i w_i(k)·C_i (fraud.ts).
}

export const ORDER = Fr.ORDER;
const mod = (x: bigint) => ((x % ORDER) + ORDER) % ORDER;
export const randomScalar = (bits = 384): bigint => {
  for (;;) {
    const x = mod(BigInt(`0x${bytesToHex(randomBytes(bits / 8))}`));
    if (x !== 0n) return x;
  }
};
const g1 = (x: bigint) => (mod(x) === 0n ? G1.Point.ZERO : G1.Point.BASE.multiply(mod(x)));
const g2 = (x: bigint) => (mod(x) === 0n ? G2.Point.ZERO : G2.Point.BASE.multiply(mod(x)));
export const hashScalar = (domain: string, ...parts: Uint8Array[]) => {
  const h = sha512.create().update(utf8ToBytes(domain));
  for (const p of parts) h.update(p);
  return mod(BigInt(`0x${bytesToHex(h.digest())}`));
};
const u32 = (n: number) => Buffer.from(n.toString(16).padStart(8, '0'), 'hex');

/** Σ_l coefficients[l]·k^l (Horner). */
export function evaluate(coefficients: bigint[], k: bigint): bigint {
  let acc = 0n;
  for (let l = coefficients.length - 1; l >= 0; l--) acc = mod(acc * k + coefficients[l]!);
  return acc;
}

/** Lagrange coefficients at `at` (by default 0, where a bucket's own polynomial keeps its secret) for the given seats. */
export function lagrange(seats: number[], at = 0n): bigint[] {
  return seats.map(j => {
    let num = 1n, den = 1n;
    for (const m of seats) if (m !== j) [num, den] = [mod(num * (at - BigInt(m))), mod(den * BigInt(j - m))];
    return mod(num * Fr.inv(den));
  });
}

const bases = new Map<string, bigint[]>();
/** The weights w(k) of a form with m values (see Form). Cached: every dealing of a handover uses the same ones. */
export function basis(form: Form, m: number, k: bigint): bigint[] {
  const key = `${form}:${m}:${k}`;
  let w = bases.get(key);
  if (w) return w;
  if (form === 'coefficients') {
    w = [1n];
    while (w.length < m) w.push(mod(w.at(-1)! * k));
  } else {
    // L_i(k) = Π_(j≠i) (k + j)/(j − i) over i, j in 1..m: Z(k) / ((k + i)·D_i), with D_i = (−1)^(i−1)·(i−1)!·(m−i)!.
    const at = Array.from({ length: m }, (_, i) => mod(k + BigInt(i + 1)));
    const hit = at.indexOf(0n);
    if (hit >= 0) w = at.map((_, i) => (i === hit ? 1n : 0n));
    else {
      const fact = [1n];
      for (let i = 1; i < m; i++) fact.push(mod(fact[i - 1]! * BigInt(i)));
      const z = at.reduce((a, b) => mod(a * b), 1n);
      const inv = Fr.invertBatch(at.map((x, i) => mod(x * (i % 2 ? -1n : 1n) * fact[i]! * fact[m - 1 - i]!)));
      w = inv.map(x => mod(z * x));
    }
  }
  if (bases.size > 50_000) bases.clear();
  bases.set(key, w);
  return w;
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

/** A value the dealer deals as given: a share it holds (commitment public), or a new-key contribution z·g2 (with z). */
export interface Head { share: G2Point; commitment: G1Point; z?: bigint; context?: Uint8Array }

/**
 * Deals a polynomial of m values in `form` to the next committee's ephemeral keys: the heads first, then random values.
 * Heads with z (new-key contributions, after any dealt shares) get a proof of knowledge bound to their `context` (for
 * example the committee and bucket) and the dealer's seat. A plain re-sharing is one head in coefficient form, m = t.
 */
export function deal(dealer: number, heads: Head[], epks: G2Point[], m: number, form: Form = 'coefficients'): Dealing {
  const proved = heads.findIndex(h => h.z !== undefined);
  check(heads.length <= m && (proved < 0 || heads.slice(proved).every(h => h.z !== undefined)), 'Contributions must be the last heads');
  const a = Array.from({ length: m - heads.length }, () => randomScalar());
  const expected: G1Point[] = [];
  const subshares = epks.map((epk, i) => {
    const w = basis(form, m, BigInt(i + 1)), r = randomScalar();
    const tail = a.reduce((s, x, l) => mod(s + x * w[heads.length + l]!), 0n);
    let value = g2(tail), commitment = g1(tail);
    heads.forEach((h, j) => {
      value = value.add(w[j] === 1n ? h.share : h.share.multiply(w[j]!)); // Weights at seats are never 0.
      commitment = commitment.add(h.commitment.multiplyUnsafe(w[j]!));
    });
    expected.push(commitment);
    return { r1: g1(r), r2: g2(r), b: value.add(epk.multiply(r)) };
  });
  return {
    dealer,
    commitments: [...heads.map(h => h.commitment), ...a.map(g1)],
    subshares,
    proofs: heads.filter(h => h.z !== undefined).map(h => proveG1(h.z!, h.commitment, pokLabel(h.context ?? new Uint8Array(), dealer))),
    expected,
  };
}

/**
 * The dealings that pass, keeping their order. Each has m commitments in `form`; its first heads must equal `prior`
 * (the dealer's share commitments, when re-sharing) and the next ones carry valid proofs of knowledge for `contexts`
 * (new-key contributions). All subshares are checked in one random-linear-combination batch, bisected when it fails:
 *   e(Σρ·r1, g2) = e(g1, Σρ·r2)  and  e(g1, Σρ·b) = e(Σ_ji c_ji·C_ji, g2) · Π_k e(W_k, epk_k),
 * with ρ_jk = α_j·β_k (sound with probability about 2^-127), c_ji = α_j·Σ_k β_k·w_i(k) and W_k = Σ_j ρ_jk·r1_jk.
 */
export function validDealings(dealings: Dealing[], epks: G2Point[], m: number,
  o: { form?: Form; prior?: Map<number, G1Point[]>; contexts?: Uint8Array[] } = {}): Dealing[] {
  const seen = new Set<number>(), contexts = o.contexts ?? [];
  const shaped = dealings.filter(d => {
    const prior = o.prior ? o.prior.get(d.dealer) : [];
    const ok = !seen.has(d.dealer) && !!prior && d.commitments.length === m && d.subshares.length === epks.length &&
      prior.length + contexts.length <= m && d.proofs.length === contexts.length && prior.every((c, i) => c.equals(d.commitments[i]!)) &&
      contexts.every((c, i) => verifyG1(d.commitments[prior.length + i]!, d.proofs[i]!, pokLabel(c, d.dealer)));
    seen.add(d.dealer);
    return ok;
  });
  return bisect(shaped, epks, m, o.form ?? 'coefficients');
}

function bisect(dealings: Dealing[], epks: G2Point[], m: number, form: Form): Dealing[] {
  if (!dealings.length || batchOk(dealings, epks, m, form)) return dealings;
  if (dealings.length === 1) return [];
  const mid = dealings.length >> 1;
  return [...bisect(dealings.slice(0, mid), epks, m, form), ...bisect(dealings.slice(mid), epks, m, form)];
}

/** Whether every subshare of these well-shaped dealings matches its commitments (one batch; see validDealings). */
export function batchOk(dealings: Dealing[], epks: G2Point[], m: number, form: Form = 'coefficients'): boolean {
  try {
    const alpha = dealings.map(() => randomScalar(128)), beta = epks.map(() => randomScalar(128));
    const gamma = Array<bigint>(m).fill(0n);
    beta.forEach((b, k) => basis(form, m, BigInt(k + 1)).forEach((w, i) => (gamma[i] = mod(gamma[i]! + b * w))));
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

/** Seat k's public share commitment from a polynomial's commitments: Σ_i w_i(k)·C_i. */
export const seatCommitment = (poly: G1Point[], k: number, form: Form = 'coefficients'): G1Point =>
  pippenger(G1.Point, poly, basis(form, poly.length, BigInt(k)));

/** Seat k's subshares from these dealings, decrypted with its ephemeral key x. */
export const openSubshares = (k: number, x: bigint, dealings: Dealing[]) =>
  dealings.map(d => d.subshares[k - 1]!).map(s => s.b.subtract(s.r2.multiply(x)));
/** Σ weights_j·points_j in G2. */
export const weightedG2 = (points: G2Point[], weights: bigint[]): G2Point => pippenger(G2.Point, points, weights);

/**
 * Seat k's new share from the chosen dealings: weights are Lagrange coefficients over the dealers' seats when
 * re-sharing, or all 1 when summing new-key contributions.
 */
export function combine(k: number, x: bigint, dealings: Dealing[], weights: bigint[]): G2Point {
  return weightedG2(openSubshares(k, x, dealings), weights);
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

/** A partial on the wire: d in GT (576 bytes), c (32), z in G2 (96). */
export const PARTIAL_SIZE = 576 + 32 + 96;
export const encodePartial = (p: Partial) => Buffer.concat([Fp12.toBytes(p.d), scalarBytes(p.proof.c), p.proof.z.toBytes()]);
/** Strict decoding: d must lie in GT (order r), c be canonical and z a valid G2 point. */
export function decodePartial(bytes: Uint8Array): Partial {
  if (bytes.length !== PARTIAL_SIZE) throw new Error('Bad partial length');
  const d = Fp12.fromBytes(bytes.subarray(0, 576));
  if (!Fp12.eql(Fp12.pow(d, ORDER), Fp12.ONE)) throw new Error('Partial not in GT');
  const c = BigInt(`0x${Buffer.from(bytes.subarray(576, 608)).toString('hex')}`);
  if (c >= ORDER) throw new Error('Non-canonical scalar');
  return { d, proof: { c, z: decodeG2(bytes.subarray(608)) } };
}

/** The KEM key from enough verified partials of distinct seats, interpolated to the secret's point `at`. */
export function combinePartials(parts: { seat: number; d: GT }[], at = 0n): GT {
  const weights = lagrange(parts.map(p => p.seat), at);
  return parts.reduce((acc, p, i) => Fp12.mul(acc, Fp12.pow(p.d, weights[i]!)), Fp12.ONE);
}

// --- Encoding: compressed points (48-byte G1, 96-byte G2), 32-byte big-endian scalars ---

const SCALAR = 32;
const scalarBytes = (x: bigint) => Buffer.from(x.toString(16).padStart(SCALAR * 2, '0'), 'hex');
/** A Schnorr proof (c, z) on the wire: two 32-byte scalars. */
export const encodeProof = (p: Proof) => Buffer.concat([scalarBytes(p.c), scalarBytes(p.z)]);
export function decodeProof(bytes: Uint8Array): Proof {
  if (bytes.length !== 2 * SCALAR) throw new Error('Bad proof length');
  const big = (b: Uint8Array) => BigInt(`0x${Buffer.from(b).toString('hex')}`);
  return { c: big(bytes.subarray(0, SCALAR)), z: big(bytes.subarray(SCALAR)) };
}
/** A dealing on the wire: m commitments, n subshares, then its proofs. */
export const dealingSize = (n: number, m: number, proofs: number) => m * 48 + n * 240 + proofs * 2 * SCALAR;

export function encodeDealing(d: Dealing): Buffer {
  return Buffer.concat([...d.commitments.map(p => p.toBytes()), ...d.subshares.flatMap(s => [s.r1.toBytes(), s.r2.toBytes(), s.b.toBytes()]),
    ...d.proofs.flatMap(p => [scalarBytes(p.c), scalarBytes(p.z)])]);
}

/**
 * Strict decoding of untrusted bytes: exact length, canonical scalars, curve and subgroup checks, no identity points.
 * With `keep` (seats), only those subshares are decoded and the rest are left out of the sparse array: such a partial
 * dealing serves `aggregate` and `combine` for already-verified dealings, never `validDealings`.
 */
export function decodeDealing(bytes: Uint8Array, dealer: number, n: number, m: number, proofs: number, keep?: number[]): Dealing {
  if (bytes.length !== dealingSize(n, m, proofs)) throw new Error('Bad dealing length');
  let at = 0;
  const take = (len: number) => bytes.subarray(at, (at += len));
  const p1 = () => decodeG1(take(48)), p2 = () => decodeG2(take(96));
  const scalar = () => { const x = BigInt(`0x${Buffer.from(take(SCALAR)).toString('hex')}`); if (x >= ORDER) throw new Error('Non-canonical scalar'); return x; };
  const commitments = Array.from({ length: m }, p1);
  const wanted = keep && new Set(keep);
  const subshares: Subshare[] = [];
  for (let k = 1; k <= n; k++) {
    if (!wanted || wanted.has(k)) subshares[k - 1] = { r1: p1(), r2: p2(), b: p2() };
    else at += 240; // Skipped: no subgroup checks for points this caller never uses.
  }
  return { dealer, commitments, subshares, proofs: Array.from({ length: proofs }, () => ({ c: scalar(), z: scalar() })) };
}

const nonZero = <P extends { is0(): boolean }>(p: P) => { if (p.is0()) throw new Error('Identity point'); return p; };
/** Untrusted compressed points: curve and subgroup checked (by noble), identity rejected. */
export const decodeG1 = (bytes: Uint8Array): G1Point => nonZero(G1.Point.fromBytes(bytes));
export const decodeG2 = (bytes: Uint8Array): G2Point => nonZero(G2.Point.fromBytes(bytes));

export const point = { g1, g2 };
