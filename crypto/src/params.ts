/**
 * Committee size C and threshold t for the paper's committee selection (eprint 2020/464 §3.2). f is the corrupt
 * fraction; the adversary may redraw the sortition 2^k1 times; secrecy and liveness each fail with probability at most
 * 2^-k2 and 2^-k3 per epoch. Assumes N ≫ C, as the paper's analysis does.
 */
export interface Bound { C: number; t: number }

const LN2 = Math.LN2;
const logAdd = (a: number, b: number) =>
  a === -Infinity ? b : b === -Infinity ? a : Math.max(a, b) + Math.log1p(Math.exp(-Math.abs(a - b)));

/** The paper's Chernoff bounds, equations (2)–(6), minimised over ε1 and ε2 on a log grid. */
export function paperBound(f: number, k1: number, k2: number, k3: number): Bound | undefined {
  let best: { C: number; t: number } | undefined;
  for (let i = 0; i < 300; i++) {
    for (let j = 0; j < 300; j++) {
      const e1 = 0.03 * 1.02 ** i, e2 = 0.03 * 1.02 ** j;
      let C = Math.max((k1 + k2 + 1) * (2 + e1) * LN2 / (f * e1 * e1), (k2 + 1) * (2 + e2) * LN2 / (f * (1 - f) * e2 * e2));
      let settled = false;
      for (let n = 0; n < 50 && !settled; n++) { // ε3 from (6) depends weakly on C, so iterate (4) to a fixed point.
        const e3 = (1 - (4 + e1 + e2) * f + (2 + e2) * f * f - 1 / C) / (1 - f) ** 2;
        if (e3 <= 0) break;
        const C4 = 2 * k3 * LN2 / (e3 * (1 - f)) ** 2;
        if (C4 <= C) settled = true;
        else C = C4;
      }
      if (settled && C < (best?.C ?? Infinity)) best = { C, t: C * ((2 + e1 + e2) * f - (1 + e2) * f * f) + 1 };
    }
  }
  return best && { C: Math.ceil(best.C), t: Math.ceil(best.t) };
}

/**
 * Exact Poisson tails of the same process: corrupt seats ~ Pois(C·f·(2 − f)) (corrupt nominators, plus honest ones
 * that pick corrupt nominees), honest seats ~ Pois(C·(1 − f)²). Smallest C with a threshold t such that
 * 2^k1·P(corrupt ≥ t) ≤ 2^-k2 (secrecy) and P(honest < t + extra) ≤ 2^-k3 (liveness). With packed epochs
 * (ecpss handoverPlan) a committee unpacking ℓ buckets needs t + ℓ − 1 valid dealings: pass extra = ℓ − 1.
 */
export function exactBound(f: number, k1: number, k2: number, k3: number, extra = 0): Bound {
  let lo = 4, hi = 64;
  while (threshold(hi, f, k1, k2, k3, extra) === undefined) hi *= 2;
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (threshold(mid, f, k1, k2, k3, extra) === undefined) lo = mid + 1;
    else hi = mid;
  }
  return { C: lo, t: threshold(lo, f, k1, k2, k3, extra)! };
}

function threshold(C: number, f: number, k1: number, k2: number, k3: number, extra: number): number | undefined {
  const corrupt = C * f * (2 - f), honest = C * (1 - f) ** 2;
  const K = Math.ceil(honest + 30 * Math.sqrt(honest) + 300);
  const logPmf = (lambda: number) => { // log P(Pois(λ) = k) for k = 0..K, from P(0) = e^-λ upwards.
    const out = [-lambda];
    for (let k = 1; k <= K; k++) out.push(out[k - 1]! + Math.log(lambda) - Math.log(k));
    return out;
  };
  const pc = logPmf(corrupt);
  const tail = new Array<number>(K + 2).fill(-Infinity); // tail[t] = log P(corrupt ≥ t)
  for (let k = K; k >= 0; k--) tail[k] = logAdd(tail[k + 1]!, pc[k]!);
  const t = tail.findIndex(x => k1 * LN2 + x <= -k2 * LN2);
  const ph = logPmf(honest);
  let below = -Infinity; // log P(honest < t + extra)
  for (let k = 0; k < t + extra; k++) below = logAdd(below, ph[k]!);
  return below <= -k3 * LN2 ? t : undefined;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const fs = [0.01, 0.05, 0.10, 0.20];
  const show = (b: Bound | undefined) => (b ? `C ${b.C}, t ${b.t}` : 'impossible').padEnd(16);
  console.log(`${'redraws, failure per epoch'.padEnd(30)}${fs.map(f => `f = ${f * 100}%`.padEnd(16)).join('')}`);
  for (const [k1, k2] of [[64, 128], [64, 64], [8, 64], [0, 64], [0, 40]] as const) {
    console.log(`${`2^${k1}, 2^-${k2} exact`.padEnd(30)}${fs.map(f => show(exactBound(f, k1, k2, k2))).join('')}`);
  }
  console.log(`${'2^64, 2^-128 paper bounds'.padEnd(30)}${fs.map(f => show(paperBound(f, 64, 128, 128))).join('')}`);
  for (const l of [4, 8]) console.log(`${`2^0, 2^-40 exact, ${l} packed`.padEnd(30)}${fs.map(f => show(exactBound(f, 0, 40, 40, l - 1))).join('')}`);
}
