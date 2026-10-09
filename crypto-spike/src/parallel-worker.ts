import { createHash } from 'node:crypto';
import { parentPort } from 'node:worker_threads';
import { decodeMessage, validSeats, type Message } from './ecpss.js';
import { decodeG1, decodeG2, type G2Point } from './pvss.js';
import type { Task } from './parallel.js';

// Verification thread for VerifyPool: strict decoding and batched checks for one group of dealers.
const committees = new Map<string, G2Point[]>(); // A committee's keys arrive with every task; decode them once.
parentPort!.on('message', (task: Task) => {
  try {
    const id = createHash('sha256').update(Buffer.concat(task.epks)).digest('hex');
    if (!committees.has(id)) { if (committees.size > 8) committees.clear(); committees.set(id, task.epks.map(decodeG2)); }
    const next = committees.get(id)!;
    const pub = new Map(task.live.map(([b, poly]) => [BigInt(b), poly.map(decodeG1)]));
    const messages = new Map<number, Message>();
    for (const [seat, bytes] of task.messages) {
      try { messages.set(seat, decodeMessage(bytes, seat, task.n, task.t)); } catch { /* Undecodable: absent. */ }
    }
    const valid = validSeats(messages, pub, BigInt(task.committee), { live: [...pub.keys()], create: task.create.map(BigInt) }, next, task.t);
    parentPort!.postMessage({ result: [...valid].map(([b, seats]) => [b.toString(), seats]) });
  } catch (e) {
    parentPort!.postMessage({ error: e instanceof Error ? e.message : String(e) });
  }
});
