import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import type { Buckets, Recipe } from './ecpss.js';
import { decodeG2, type G2Point } from './pvss.js';

/**
 * One short-lived process per committee's secrets (PAPER_ALIGNMENT_PLAN.md Phase 6). A member starts a vault when it
 * posts its nomination key for an epoch. The vault opens the seats nominated to that key, receives their shares at the
 * handover into the committee, builds their single handover messages, and exits. The member's long-running process
 * sees only public data, its own seat numbers, and the messages and claim signatures it posts.
 *
 * The vault runs with core dumps off (checked from inside) and refuses to start where swap could write its memory to
 * disk in the clear. JavaScript cannot wipe bigints or pin memory, so erasure is still not provable: the process exit
 * is what ends the secrets.
 */
export interface SeatInput { seat: number; enc: Uint8Array; ct: Uint8Array; context: Uint8Array; epk: Uint8Array; sigKey: Uint8Array }
export interface CapsuleInput {
  id: bigint; bucket: bigint; u: Uint8Array; proof: Uint8Array; label: Uint8Array;
  recipientKey: string; contexts: Map<number, Uint8Array>; // HPKE context per seat
}
export interface SpeakInput {
  committee: bigint; state: Uint8Array; buckets: Buckets; next: Uint8Array[]; t: number; // state: the committee's (encodeState)
  claims: Map<number, Uint8Array>; // per seat, the claim message its one-time key signs, less its last field: the dealings root
  capsules: CapsuleInput[];
}
export interface Post {
  seat: number; message: Uint8Array; root: Uint8Array; signature: Uint8Array; // root: the message's dealings root (fraud.ts), signed into the claim
  releases: bigint[]; refused: [bigint, string][];
}
export type Request =
  | { op: 'open'; seats: SeatInput[] }
  | { op: 'genesis' }
  | { op: 'adopt'; messages: Map<number, Uint8Array>; used: Map<bigint, Recipe>; n: number; t: number }
  | ({ op: 'speak' } & SpeakInput);

export class SeatVault {
  #child: ChildProcess;
  #pending = new Map<number, (reply: { result?: unknown; error?: string }) => void>();
  #next = 0;
  /** Settles when the vault process is gone (after speaking, on close, or on a crash). */
  readonly exited: Promise<void>;

  private constructor(child: ChildProcess, readonly publicKey: string) {
    this.#child = child;
    this.exited = new Promise(resolve => (child.exitCode !== null || child.signalCode !== null ? resolve() : child.once('exit', () => resolve())));
    child.on('message', (reply: { id: number; result?: unknown; error?: string }) => {
      this.#pending.get(reply.id)?.(reply);
      this.#pending.delete(reply.id);
    });
    child.on('exit', () => {
      for (const settle of this.#pending.values()) settle({ error: 'Vault exited' });
      this.#pending.clear();
    });
  }

  /**
   * Starts a vault with a fresh nomination key (an X25519 public key, base64url). Tests only: `audit` reveals shares,
   * and `cheat` makes every seat deal recipient 1 a bad subshare in its first dealing, under a root that convicts it.
   */
  static start(o: { audit?: boolean; cheat?: boolean } = {}): Promise<SeatVault> {
    const script = fileURLToPath(new URL('./vault-process.js', import.meta.url));
    const child = spawn('/bin/sh', ['-c', 'ulimit -c 0 && exec "$0" "$@"', process.execPath, script, ...(o.audit ? ['--audit'] : []),
      ...(o.cheat ? ['--cheat'] : [])],
      { stdio: ['ignore', 'inherit', 'inherit', 'ipc'], serialization: 'advanced' });
    return new Promise((resolve, reject) => {
      child.once('message', (m: { publicKey?: string; error?: string }) => (m.publicKey ? resolve(new SeatVault(child, m.publicKey)) : reject(new Error(m.error))));
      child.once('exit', code => reject(new Error(`Vault exited (${code})`)));
      child.once('error', reject);
    });
  }

  /** Opens the seats sealed to this vault's nomination key, then wipes that key. Returns the seat numbers it holds. */
  open(seats: SeatInput[]) { return this.#call<number[]>({ op: 'open', seats }); }
  /** The genesis committee holds no buckets. */
  genesis() { return this.#call<void>({ op: 'genesis' }); }
  /**
   * Shares for this vault's seats from the dealings the member chose (`used`: per bucket, its recipe from ecpss
   * `choose`), given those dealers' raw messages. In audit mode, returns the shares.
   */
  async adopt(messages: Map<number, Uint8Array>, used: Map<bigint, Recipe>, n: number, t: number) {
    const shares = await this.#call<{ seat: number; shares: Map<bigint, Uint8Array> }[] | undefined>({ op: 'adopt', messages, used, n, t });
    return shares?.map(h => ({ seat: h.seat, shares: new Map<bigint, G2Point>([...h.shares].map(([b, s]) => [b, decodeG2(s)])) }));
  }
  /** Every held seat's handover message and claim signature. The vault exits before the caller posts any of them. */
  speak(input: SpeakInput) { return this.#call<Post[]>({ op: 'speak', ...input }); }
  close() { this.#child.kill(); }

  #call<T>(request: Request): Promise<T> {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      if (!this.#child.connected) return reject(new Error('Vault exited'));
      this.#pending.set(id, r => (r.error ? reject(new Error(r.error)) : resolve(r.result as T)));
      this.#child.send({ id, ...request }, e => { if (e) { this.#pending.delete(id); reject(new Error('Vault exited')); } });
    });
  }
}
