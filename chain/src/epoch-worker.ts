import { randomBytes } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { AlgorandClient, Config, microAlgo } from '@algorandfoundation/algokit-utils';
import { nullLogger } from '@algorandfoundation/algokit-utils/types/logging';
import vrf from '@bwmx/algorand-vrf-utils-ts';
import { check, seal } from 'keepsake-crypto/dist/src/crypto.js';
import { decodeMessage, encodeState, handoverPlan, publicKey, seatKeys, stateDigest, type Public } from 'keepsake-crypto/dist/src/ecpss.js';
import { findBadDealing } from 'keepsake-crypto/dist/src/fraud.js';
import { VerifyPool, receiveParallel } from 'keepsake-crypto/dist/src/parallel.js';
import { decodeG2, type G2Point } from 'keepsake-crypto/dist/src/pvss.js';
import { SeatVault, type Post } from 'keepsake-crypto/dist/src/vault.js';
import { EpochCommitteeClient } from '../smart_contracts/artifacts/epoch_committee/EpochCommitteeClient.js';
import { b64url, vrfRank, type ChainPins } from './chain.js';
import { attestedState, capsuleLabel, releaseContext } from './epoch-capsules.js';
import {
  EpochReader, bondAt, claimMessage, handoverBuckets, nominationAlpha, postMessage, seatSeedContext, ticketCount, ticketWins, windows,
  type EpochParams, type OrderedSeat, type SeatId,
} from './epochs.js';

export interface EpochWorkerConfig {
  pins: ChainPins;
  algod: { server: string; port?: number; token: string };
  memberMnemonic: string; // Enrolled and bonded; posts keys and nominations, and as a holder one message per seat (speak once).
  vrfSecretKey: Uint8Array; // 64-byte VRF key (seed || public key) enrolled for this member.
  pool: VerifyPool; // Verification threads; members in one process share them.
  pollMs: number; // 0: no loop, the caller drives `step()` (lockstep tests).
  event?: (e: Record<string, string>) => void; // Operator-local log: names this member's seats, never secrets.
  audit?: boolean; // Tests only: vaults report their shares to the operator.
  cheat?: boolean; // Tests only: this member's seats each deal one bad subshare, provably.
}

interface MySeat extends SeatId { seat: number }

/**
 * A member of the EpochCommittee app (PAPER_ALIGNMENT_PLAN.md Phases 3 and 5). Each step, it:
 * - posts its nomination keys for the current and next epoch;
 * - nominates one seat per winning sortition ticket (§3.1.2), each sealed to a member chosen at random by bond;
 * - opens its seats once nominations close, then erases that epoch's key;
 * - as a holder, builds its single handover message (§3.1.3): re-sharings, new-bucket contributions, a sealed
 *   decryption partial for each authorized capsule, and the public state it attests. Its secrets are then erased, and it
 *   claims the seat and posts from its own account. No relayer: posting reveals the holder only after it has erased.
 * - processes every handover whose window has closed, in order (catching up after an outage while the blocks and
 *   seat records last), verifying on the thread pool, and combines shares for its seats in the next committee;
 * - deletes the seats it nominated once they are old, recovering their deposits.
 * Secrets live in one short-lived vault process per committee (PAPER_ALIGNMENT_PLAN.md Phase 6): the nomination key
 * for the epoch that nominates it, its seats' one-time keys and its shares. The vault exits once its seats have their
 * messages, before any is posted; this process holds only public data.
 * A member that starts after genesis, newly enrolled or restarted with nothing in memory, joins from the latest public
 * state that t seats attested (see below). Seats nominated to an earlier run's keys stay closed to it.
 */
export async function startEpochWorker(cfg: EpochWorkerConfig) {
  Config.configure({ logger: nullLogger });
  await vrf.init();
  const algorand = AlgorandClient.fromConfig({ algodConfig: cfg.algod });
  const member = algorand.account.fromMnemonic(cfg.memberMnemonic);
  const app = new EpochCommitteeClient({ algorand, appId: cfg.pins.appId, defaultSender: member.addr });
  const g = app.state.global;
  const params: EpochParams = {
    epochRounds: (await g.epochRounds())!, nominationRounds: (await g.nominationRounds())!, handoverRounds: (await g.handoverRounds())!,
    shareThreshold: (await g.shareThreshold())!, bucketRounds: (await g.bucketRounds())!, bucketLead: (await g.bucketLead())!,
    genesisCommittee: (await g.genesisCommittee())!,
  };
  const totalTickets = (await g.totalTickets())!, ticketThreshold = (await g.ticketThreshold())!, t = Number(params.shareThreshold), E = params.epochRounds;
  const [, seatDeposit] = await app.deposits();
  const reader = new EpochReader(algorand.client.algod, cfg.pins, params, app.appClient.getABIMethod('postChunk').getSelector());
  const event = cfg.event ?? (() => {});
  await reader.lastRound();
  let me: { index: bigint; enrolledRound: bigint } | undefined;
  for (let i = 0n; i < (await g.registrySize())!; i++) {
    const m = await app.getMember({ args: { index: i } });
    if (m.account !== member.addr.toString()) continue;
    check(b64url(m.vrfKey) === b64url(cfg.vrfSecretKey.subarray(32)), 'Enrolled keys differ from configured keys');
    me = { index: i, enrolledRound: m.enrolledRound };
  }
  check(me !== undefined, 'Not enrolled');
  const { index: myIndex, enrolledRound } = me;

  const cover = { coverAppCallInnerTransactionFees: true, maxFee: microAlgo(20_000) } as const;
  const posted = new Set<bigint>(); // Epochs whose nomination key is on chain (possibly from an earlier run, then unusable).
  const vaults = new Map<bigint, SeatVault>(); // Committee → the vault holding this member's secrets for it.
  const winning = new Map<bigint, { ticket: bigint; proof: Uint8Array }[]>(); // Committee → winning tickets not yet nominated.
  const ordered = new Map<bigint, OrderedSeat[]>(); // Committee → its seats in key order (public).
  const seats = new Map<bigint, MySeat[]>(); // Committee → the seats this member holds in it (operator-local).
  // Committee → messages built for its handover but not yet on chain (public once posted; no secrets).
  const unposted = new Map<bigint, { posts: (Post & MySeat & { tried: boolean })[]; digest: Uint8Array }>();
  type Audit = { seat: number; shares: Map<bigint, G2Point> }[];
  const views = new Map<bigint, { pub: Public; holders?: Audit }>(); // Committee → public state after the handover into it.
  let opened = params.genesisCommittee - 2n; // Last epoch whose nominations were opened (committee = epoch + 1).
  let processed = params.genesisCommittee - 1n; // Last committee whose handover was processed.

  // The next epoch's key waits until nominations close, so key posts never crowd the nomination window; a holder still
  // has it before it speaks.
  async function postKeys(epoch: bigint, next: boolean) {
    for (const e of next ? [epoch, epoch + 1n] : [epoch]) {
      if (posted.has(e) || e < params.genesisCommittee - 1n) continue; // Earlier keys would never be opened or erased.
      if (await reader.nominationKey(e, myIndex)) { posted.add(e); continue; }
      const vault = await SeatVault.start({ audit: cfg.audit, cheat: cfg.cheat }); // The key for epoch e opens seats of committee e + 1.
      await app.send.postNominationKey({ args: { epoch: e, key: Buffer.from(vault.publicKey, 'base64url') } }).catch(err => { vault.close(); throw err; });
      vaults.set(e + 1n, vault);
      posted.add(e);
    }
  }

  // Tickets are drawn once per committee with the contract's own reading of the weight; failed nominations are retried
  // while the window lasts.
  async function nominate(epoch: bigint) {
    const committee = epoch + 1n;
    if (committee < params.genesisCommittee || enrolledRound >= epoch * E) return;
    if (!winning.has(committee)) {
      const [w, total] = await app.weight({ args: { nominator: myIndex } }), seed = await reader.seed(committee), wins = [];
      for (let j = 0n; j < ticketCount(w, total, totalTickets); j++) {
        const { proof, output } = vrf.prove(cfg.vrfSecretKey, nominationAlpha(cfg.pins.appId, committee, j, seed));
        if (ticketWins(vrfRank(output), j, w, total, totalTickets, ticketThreshold)) wins.push({ ticket: j, proof });
      }
      for (const c of winning.keys()) if (c < committee) winning.delete(c);
      winning.set(committee, wins);
    }
    const wins = winning.get(committee)!;
    if (!wins.length) return;
    // Nominees are drawn by bond among members with a key for this epoch: a member with no bond attracts no seats.
    const members = await reader.members(), bonds = members.map(m => bondAt(m, epoch)), sum = bonds.reduce((a, b) => a + b, 0n);
    const draw = () => {
      let r = BigInt(`0x${randomBytes(16).toString('hex')}`) % sum, i = 0;
      while (r >= bonds[i]!) r -= bonds[i++]!;
      return BigInt(i);
    };
    const done = new Set<bigint>();
    try {
      await inBatches([...wins], async win => {
        let nomineeKey: Uint8Array | undefined;
        for (let tries = 0; !nomineeKey && tries < 64; tries++) nomineeKey = await reader.nominationKey(epoch, draw());
        if (!nomineeKey) return;
        await nominateTicket(committee, win, nomineeKey);
        done.add(win.ticket);
      });
    } finally {
      winning.set(committee, wins.filter(w => !done.has(w.ticket))); // The rest are retried while the window lasts.
    }
  }

  /** Runs `f` over `items`, PARALLEL at a time: a member with many seats posts them together without flooding its node. */
  async function inBatches<T>(items: T[], f: (item: T) => Promise<void>) {
    const failures: unknown[] = [];
    for (let i = 0; i < items.length; i += PARALLEL) {
      for (const r of await Promise.allSettled(items.slice(i, i + PARALLEL).map(f))) if (r.status === 'rejected') failures.push(r.reason);
    }
    if (failures.length) throw failures[0];
  }

  async function nominateTicket(committee: bigint, win: { ticket: bigint; proof: Uint8Array }, nomineeKey: Uint8Array) {
    const seatSeed = randomBytes(32);
    try {
      const k = seatKeys(seatSeed), sealed = await seal(b64url(nomineeKey), seatSeed, seatSeedContext(cfg.pins, committee, myIndex, win.ticket));
      // `block` reads the seed only while LastValid < seed round + 1002; nominations end within 320 rounds of it.
      const last = await reader.lastRound();
      await app.send.nominate({ ...cover, firstValidRound: last + 1n, validityWindow: 100, args: {
        nominator: myIndex, ticket: win.ticket, proof: win.proof, epk: k.epk.toBytes(), sigKey: k.sigKey,
        sealedSeed: Buffer.concat([Buffer.from(sealed.enc, 'base64url'), Buffer.from(sealed.ciphertext, 'base64url')]),
        payment: algorand.createTransaction.payment({ sender: member.addr, receiver: app.appAddress, amount: microAlgo(seatDeposit) }) } });
      event({ nominated: committee.toString(), ticket: win.ticket.toString() });
    } finally {
      seatSeed.fill(0); // The nominator forgets the seat it created and whom it chose.
    }
  }

  // Seats of committee `epoch + 1` are final once nominations close: the vault opens ours, then erases the epoch's key.
  // A vault that holds no seat has nothing left to keep and exits.
  async function openSeats(epoch: bigint) {
    const committee = epoch + 1n, list = await reader.seats(committee), vault = vaults.get(committee);
    let mine: MySeat[] = [];
    if (vault) {
      const numbers = await vault.open(list.map(s => ({ seat: s.seat, enc: s.value.sealedSeed.subarray(0, 32), ct: s.value.sealedSeed.subarray(32),
        context: seatSeedContext(cfg.pins, committee, s.nominator, s.ticket), epk: s.value.epk, sigKey: s.value.sigKey }))).catch((e): number[] => { report('open')(e); return []; });
      event({ erased: epoch.toString() });
      mine = list.filter(s => numbers.includes(s.seat)).map(({ seat, nominator, ticket }) => ({ seat, nominator, ticket }));
      for (const m of mine) event({ seat: committee.toString(), number: m.seat.toString() });
      if (!mine.length) closeVault(committee);
      else if (committee === params.genesisCommittee) await vault.genesis();
    }
    ordered.set(committee, list);
    seats.set(committee, mine);
    if (committee === params.genesisCommittee) views.set(committee, { pub: new Map() });
  }

  function closeVault(committee: bigint) {
    vaults.get(committee)?.close();
    vaults.delete(committee);
  }

  // Committee `epoch` hands over: one message per seat held, after rotating keys and erasing (§3.1.3 steps 4–5).
  async function handOver(epoch: bigint) {
    if (unposted.has(epoch)) return postPending(epoch);
    const view = views.get(epoch), mine = seats.get(epoch), next = ordered.get(epoch + 1n), vault = vaults.get(epoch);
    // The rotation precedes speaking: wait for the next epoch's key.
    if (!view || !mine?.length || !next || !vault || !posted.has(epoch + 1n)) return;
    seats.delete(epoch);
    vaults.delete(epoch);
    const state = encodeState(view.pub), digest = stateDigest(state);
    // Capsules this committee releases: requested, still open, under a bucket it holds. The vault refuses a u whose
    // proof belongs to another policy.
    const round = await reader.lastRound();
    const capsules = (await reader.capsuleRecords()).filter(({ record }) => record.requested && round + 1n < record.expiresRound && view.pub.has(record.bucket));
    const posts = await vault.speak({
      committee: epoch, state, buckets: handoverBuckets(params, epoch),
      next: next.map(s => s.value.epk), t,
      claims: new Map(mine.map(m => [m.seat, claimMessage(cfg.pins.appId, epoch, m.nominator, m.ticket, member.addr.publicKey, digest)])),
      capsules: capsules.map(({ id, record }) => ({ id, bucket: record.bucket, u: record.u, proof: record.proof, label: capsuleLabel(cfg.pins.appId, record),
        recipientKey: b64url(record.recipientKey), contexts: new Map(mine.map(m => [m.seat, releaseContext(cfg.pins, id, record.requestId, epoch, m.seat)])) })),
    }).finally(() => vault.close());
    await vault.exited; // Erase before speaking: the vault and every secret in it are gone.
    for (const p of posts) for (const [id, reason] of p.refused) event({ refused: id.toString(), reason });
    unposted.set(epoch, { posts: posts.map(p => ({ ...p, ...mine.find(x => x.seat === p.seat)!, tried: false })), digest });
    await postPending(epoch);
  }

  // Posts the built messages not yet on chain, four seats at a time; each step retries the rest while the window lasts.
  // A seat's claim, chunks and finalize form one atomic group, so a seat this member has claimed is fully posted.
  async function postPending(epoch: bigint) {
    const entry = unposted.get(epoch)!;
    try {
      await inBatches([...entry.posts], async p => {
        // A retry first checks whether the earlier attempt landed with its reply lost.
        const landed = p.tried && (await reader.seat(epoch, p)).holder === member.addr.toString();
        p.tried = true;
        if (!landed) {
          await postMessage(app, member.addr.toString(), { committee: epoch, nominator: p.nominator, ticket: p.ticket }, p.message,
            { holder: member.addr.toString(), stateDigest: entry.digest, dealingsRoot: p.root, signature: p.signature });
        }
        event({ posted: epoch.toString(), number: p.seat.toString(), bytes: p.message.length.toString(), releases: p.releases.join(',') });
        entry.posts = entry.posts.filter(x => x !== p);
      });
    } finally {
      if (!entry.posts.length) unposted.delete(epoch);
    }
  }

  // Everyone processes committee c's handover once its window is over, to follow the public commitments.
  // It reads and verifies before changing any state, so a failed read (a node error) is simply retried next step.
  async function receiveHandover(c: bigint) {
    const view = views.get(c), next = ordered.get(c + 1n);
    if (view && next) {
      // Fresh seat records: the digests and finalized flags were written after the seats were opened.
      const posted = await reader.seats(c), raw: Map<number, Uint8Array> = await reader.messages(c, posted); // Missing or mismatched: absent.
      const buckets = handoverBuckets(params, c), nextKeys = next.map(s => decodeG2(s.value.epk));
      const result = await receiveParallel(cfg.pool, raw, view.pub, c, buckets, nextKeys, t);
      await reportBadDealings(c, posted, raw, result.valid, nextKeys).catch(report('report'));
      // The vault for committee c + 1 combines its seats' shares from the dealings everyone chose.
      const vault = vaults.get(c + 1n), chosen = new Map([...new Set([...result.used.values()].flatMap(r => r.seats))].map(s => [s, raw.get(s)!]));
      const holders = await vault?.adopt(chosen, result.used, next.length, t).catch(e => { report('adopt')(e); closeVault(c + 1n); return undefined; });
      views.set(c + 1n, { pub: result.pub, ...(holders ? { holders } : {}) });
      // Liveness: how far the valid dealings for the tightest kept bucket exceed its need (t, or t + ℓ − 1 to unpack).
      // At zero, one more silent seat loses buckets.
      const margin = result.margin ?? raw.size - t;
      event({ received: c.toString(), messages: raw.size.toString(), lost: result.lost.join(','), margin: margin.toString(),
        mode: handoverPlan(view.pub, buckets, t, next.length).mode, // plain, pack or unpack (ecpss handoverPlan)
        // Public: each bucket's key, so operators can see that all members agree and that keys never change.
        keys: [...result.pub].map(([b, s]) => `${b}:${b64url(publicKey(s).toBytes())}`).join(',') });
    }
    views.delete(c);
    ordered.delete(c);
    unposted.delete(c); // The window is over: whatever did not get on chain stays silent.
    seats.delete(c); // Seats this member missed posting for (offline in their window): their vault goes too.
    closeVault(c);
    // Each member deletes the seats it nominated KEEP committees back, recovering their deposits. Until then a member
    // that was offline can still catch up from the on-chain digests.
    const old = c - KEEP;
    if (old >= params.genesisCommittee) await deleteSeats(old).catch(report('cleanup'));
  }

  const KEEP = 3n, PARALLEL = 4;

  // A message that matches its signed dealings root but deals some recipient a subshare that fails its checks is proven
  // on chain, and its holder loses its bond. Other faults (undecodable, wrong root, a wrong re-shared value or a bad
  // contribution proof) only get the message dropped. Members race to report; the losers find nothing left to slash.
  async function reportBadDealings(c: bigint, posted: OrderedSeat[], raw: Map<number, Uint8Array>, valid: Map<bigint, number[]>, next: G2Point[]) {
    for (const s of posted) {
      const bytes = raw.get(s.seat);
      if (!bytes || s.value.holder === member.addr.toString() || [...valid.values()].every(list => list.includes(s.seat))) continue;
      let proof;
      try {
        proof = findBadDealing(decodeMessage(bytes, s.seat, next.length, t), next, s.value.dealingsRoot);
      } catch {
        continue;
      }
      if (!proof) continue;
      await app.send.reportBadDealing({ coverAppCallInnerTransactionFees: true, maxFee: microAlgo(250_000), args: {
        committee: c, nominator: s.nominator, ticket: s.ticket, index: BigInt(proof.index), path: proof.path, id: proof.id,
        kind: BigInt(proof.kind), k: BigInt(proof.k), epk: proof.epk, expected: proof.expected, r1: proof.r1, r2: proof.r2, b: proof.b,
      } }).then(() => event({ reported: c.toString(), dealer: s.seat.toString() }), e => { if (!/Nothing to slash/.test(String(e))) throw e; });
    }
  }
  const report = (at: string) => (e: unknown) => event({ error: at, message: (e instanceof Error ? e.message : String(e)).split('\n')[0]!.slice(0, 200) });

  async function deleteSeats(c: bigint) {
    const mine = (await reader.seatIds(c)).filter(s => s.nominator === myIndex);
    for (let i = 0; i < mine.length; i += 7) {
      const batch = mine.slice(i, i + 7);
      await app.send.deleteSeats({ ...cover, args: { committee: c, tickets: batch.map(s => s.ticket) } });
    }
    if (mine.length) event({ deleted: c.toString(), seats: mine.length.toString() });
  }

  // Joining after genesis: replaying from genesis is impossible once old seat records are deleted. The member takes
  // committee c's public state as at least t of c's seats attested it when claiming (fewer than t are corrupt, so an
  // honest seat agrees) and follows the handovers from c on. It also deletes old seats it nominated in an earlier run.
  const startRound = await reader.lastRound(), startEpoch = startRound / E;
  if (startEpoch > params.genesisCommittee) {
    const latest = startRound > windows(params, startEpoch).handover[1] ? startEpoch : startEpoch - 1n;
    let joined: bigint | undefined;
    for (let c = latest; c > latest - KEEP && c >= params.genesisCommittee && joined === undefined; c--) {
      const pub = await attestedState(reader, c, t);
      if (!pub) continue;
      views.set(c, { pub });
      [joined, opened, processed] = [c, c - 1n, c - 1n]; // Open the seats of c + 1 next, then process c's handover.
    }
    check(joined !== undefined, 'No attested public state to join from: wait for a handover in which t seats agree');
    event({ joined: joined.toString() });
    const stale = (await reader.seatIds()).filter(s => s.nominator === myIndex && s.committee < joined - KEEP);
    for (const c of new Set(stale.map(s => s.committee))) await deleteSeats(c).catch(report('cleanup'));
  }

  async function step() {
    const round = await reader.lastRound(), epoch = round / E, w = windows(params, epoch);
    await postKeys(epoch, round >= w.nominate[1]).catch(report('keys')); // Raced with an epoch boundary: retried next step.
    if (round + 1n >= w.nominate[0] && round + 1n <= w.nominate[1]) await nominate(epoch).catch(report('nominate'));
    // Catch up in order: seats are opened before the handover into them is processed. A stage counts as done only once
    // it succeeds; one that fails (a node error) is retried at the next step, never skipped.
    await (async () => {
      while (opened + 1n < epoch || (opened + 1n === epoch && round >= w.nominate[1])) { await openSeats(opened + 1n); opened += 1n; }
    })().catch(report('open'));
    if (round + 1n >= w.handover[0] && round + 1n <= w.handover[1]) await handOver(epoch).catch(report('handover'));
    await (async () => {
      while (windows(params, processed + 1n).handover[1] <= round && processed + 1n <= opened) { await receiveHandover(processed + 1n); processed += 1n; }
    })().catch(report('receive'));
  }

  let running = cfg.pollMs > 0;
  const loop = (async () => {
    while (running) {
      await step().catch(report('step')); // E.g. the node unreachable or rate-limiting: tried again after pollMs.
      await sleep(cfg.pollMs);
    }
  })();

  return {
    address: member.addr.toString(),
    index: myIndex,
    step,
    /**
     * Operator-local view after the handover into committee c: its public commitments, the seats this member holds in
     * it, and in audit mode (tests) their shares.
     */
    view: (c: bigint) => { const v = views.get(c); return v && { ...v, seats: (seats.get(c) ?? []).map(s => s.seat) }; },
    async stop() {
      running = false;
      await loop;
      for (const c of [...vaults.keys()]) closeVault(c);
      views.clear(); seats.clear();
    },
  };
}

const required = (name: string) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
};

// One member per process, against its own algod node: `node dist/src/epoch-worker.js` with the variables below. Events
// go to stdout as JSON lines and name the member's own seats: keep them private to its operator.
if (import.meta.url === `file://${process.argv[1]}`) {
  (await SeatVault.start()).close(); // Fails fast where secrets could reach disk (core dumps on, swap unencrypted).
  const pool = new VerifyPool();
  const worker = await startEpochWorker({
    pins: { genesisHash: required('GENESIS_HASH'), appId: BigInt(required('APP_ID')), maxRoundAgeMs: Number(process.env.MAX_ROUND_AGE_MS ?? 30_000) },
    algod: { server: required('ALGOD_SERVER'), token: process.env.ALGOD_TOKEN ?? '',
      ...(process.env.ALGOD_PORT ? { port: Number(process.env.ALGOD_PORT) } : {}) },
    memberMnemonic: required('MEMBER_MNEMONIC'),
    vrfSecretKey: Buffer.from(required('VRF_SECRET_KEY'), 'base64'),
    pool,
    pollMs: Number(process.env.POLL_MS ?? 1_000),
    event: e => console.log(JSON.stringify(e)),
  });
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.on(signal, () => void worker.stop().then(() => pool.close()).finally(() => process.exit(0)));
  }
  console.log(JSON.stringify({ ready: worker.address, member: worker.index.toString() }));
}
