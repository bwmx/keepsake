import { availableParallelism } from 'node:os';
import { Worker } from 'node:worker_threads';
import { adopt, decodeMessage, type Buckets, type Public } from './ecpss.js';
import type { G2Point } from './pvss.js';

/**
 * Receiving a handover on every core. The costly part, a subgroup check per received point plus the batched pairing
 * checks, runs in threads over disjoint groups of dealers. The caller's thread then decodes only what it uses (the
 * chosen dealings' commitments and its own subshares) and combines (see PAPER_ALIGNMENT_PLAN.md, Phase 3).
 */
export interface Task {
  n: number; t: number; committee: string; epks: Uint8Array[];
  live: [string, Uint8Array[]][]; create: string[]; messages: [number, Uint8Array][];
}
export type TaskResult = [string, number[]][];

/** A fixed pool of verification threads, shared by every member in a process. Idle threads take the next queued task. */
export class VerifyPool {
  readonly size: number;
  #idle: Worker[] = [];
  #queue: { task: Task; settle: (r: TaskResult | Error) => void }[] = [];
  #current = new Map<Worker, (r: TaskResult | Error) => void>();

  constructor(size = availableParallelism()) {
    this.size = size;
    for (let i = 0; i < size; i++) {
      const w = new Worker(new URL('./parallel-worker.js', import.meta.url));
      w.on('message', ({ result, error }: { result?: TaskResult; error?: string }) => {
        this.#finish(w, error ? new Error(error) : result!);
        w.unref(); // Only threads with work keep the process alive.
        this.#idle.push(w);
        this.#dispatch();
      });
      w.on('error', e => this.#finish(w, e)); // A crashed thread leaves the pool.
      w.unref();
      this.#idle.push(w);
    }
  }

  run(task: Task): Promise<TaskResult> {
    return new Promise((resolve, reject) => {
      this.#queue.push({ task, settle: r => (r instanceof Error ? reject(r) : resolve(r)) });
      this.#dispatch();
    });
  }

  close() { return Promise.all([...this.#idle, ...this.#current.keys()].map(w => w.terminate())); }

  #dispatch() {
    while (this.#idle.length && this.#queue.length) {
      const w = this.#idle.pop()!, { task, settle } = this.#queue.shift()!;
      this.#current.set(w, settle);
      w.ref();
      w.postMessage(task);
    }
  }

  #finish(w: Worker, r: TaskResult | Error) {
    this.#current.get(w)?.(r);
    this.#current.delete(w);
  }
}

/** `receive` from raw message bytes, verified on the pool. Undecodable or invalid messages count as absent. */
export async function receiveParallel(pool: VerifyPool, raw: Map<number, Uint8Array>, pub: Public, committee: bigint, buckets: Buckets,
  next: G2Point[], t: number, mine: { seat: number; x: bigint }[] = []) {
  const seats = [...raw.keys()].sort((a, b) => a - b);
  // One task per thread: every batch repeats about C pairings, so fewer, larger batches are cheaper (measured).
  const per = Math.max(1, Math.ceil(seats.length / pool.size)), k = Math.ceil(seats.length / per);
  const common = { n: next.length, t, committee: committee.toString(), epks: next.map(p => p.toBytes()),
    live: buckets.live.filter(b => pub.has(b)).map(b => [b.toString(), pub.get(b)!.map(p => p.toBytes())] as [string, Uint8Array[]]),
    create: buckets.create.map(String) };
  const results = await Promise.all(Array.from({ length: k }, (_, i) =>
    pool.run({ ...common, messages: seats.slice(i * per, (i + 1) * per).map(s => [s, raw.get(s)!]) })));
  const valid = new Map<bigint, number[]>();
  for (const [b, list] of results.flat()) valid.set(BigInt(b), [...(valid.get(BigInt(b)) ?? []), ...list].sort((x, y) => x - y));
  const chosen = new Set([...valid.values()].flatMap(list => list.slice(0, t)));
  const messages = new Map([...chosen].map(s => [s, decodeMessage(raw.get(s)!, s, next.length, t, mine.map(m => m.seat))]));
  return adopt(messages, valid, buckets, t, mine);
}
