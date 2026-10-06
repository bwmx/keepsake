const $ = id => document.getElementById(id);
// Only touch the DOM when markup changes, so 1 s polling never swaps an element out from under a click.
const view = el => ({ set html(markup) { if (el.dataset.html !== markup) { el.innerHTML = markup; el.dataset.html = markup; } } });
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const store = { get: k => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode */ } } };

let state = null;
let selected = store.get('capsule');
let god = store.get('god') === '1';
$('god').checked = god;

const STAGES = ['Seed', 'Nominating', 'Selected', 'Deposits', 'Anchored', 'Active', 'Requested', 'Expired'];
const EXPLAIN = [
  r => `Terms, the registry snapshot (${r.registrySize} members) and a beacon request are committed together. The seed for round ${r.seedRound} doesn't exist until that block is made. Then our beacon operator proves it with its VRF key and the AVM verifies the proof.`,
  r => `Each member privately runs its <b>own VRF</b> on the beacon seed for every slot. Eligible members post a proof; the contract verifies it and keeps the lowest rank. The winner picks a holder at random and posts <b>one-time keys</b> sealed to that holder, then erases its choice. Nominators are public. Holders are not. Open until round ${r.deadline}.`,
  r => `Nominations closed. The <b>${r.filled}</b> filled slots are the committee; any <b>${r.threshold}</b> of them can recover (a majority). Empty slots had no eligible nominator.`,
  r => `The sender encrypted the message, split the key ${r.threshold}-of-${r.filled}, anchored the manifest hash, and is posting commitments and encrypted shares on-chain in batches of 7.`,
  r => `Holders find their slots by trying to decrypt each nomination. They rebuild the manifest from chain data, check its hash and their share, and acknowledge through the shared relayer. ${r.acks}/${r.threshold} acknowledgments so far.`,
  r => `Active: ${r.acks} holders acknowledged (threshold ${r.threshold}). From round ${r.openRound} the recipient can bind a one-time key; holders then post shares encrypted to it.`,
  r => `The recipient bound a fresh key. Holders post releases through the relayer; ${r.threshold} are enough to decrypt locally.`,
  () => `Expired. Holders disposed their shares and the contract rejects new releases. Responses already delivered still decrypt; expiry can't recall them.`,
];

function toast(text) {
  const t = $('toast');
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 4000);
}

async function post(path, body = {}) {
  const res = await fetch(`/api/${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || res.statusText);
  return json;
}

async function act(button, fn) {
  if (button) button.disabled = true;
  try { await fn(); await refresh(); } catch (e) { toast(e.message); } finally { if (button) button.disabled = false; }
}

const short = a => `${a.slice(0, 4)}…${a.slice(-4)}`;
const binomTail = (n, q, t) => {
  let p = 0;
  for (let k = t; k <= n; k++) {
    let c = 1;
    for (let i = 0; i < k; i++) c = (c * (n - i)) / (i + 1);
    p += c * q ** k * (1 - q) ** (n - k);
  }
  return Math.min(1, p);
};
const pct = p => (p < 0.0001 ? '<0.01%' : `${(p * 100).toFixed(p < 0.1 ? 2 : 1)}%`);

function stageIndex(c) {
  const r = c.record;
  if (!r) return 7;
  if (state.round >= r.expiresRound) return 7;
  if (r.requested) return 6;
  return r.stage;
}

function renderSetup() {
  $('setup').hidden = state.ready;
  $('lab').hidden = !state.ready;
  $('clockControls').hidden = !state.ready;
  $('start').disabled = state.starting;
  $('startStatus').textContent = state.starting ? 'Starting… funding accounts, deploying, enrolling (≈20–40 s)' : state.error ? `Failed: ${state.error}` : '';
}

function renderHeader() {
  $('net').textContent = state.ready
    ? `round ${state.round} · ${state.genesisId} · policy app ${state.env.appId} · beacon ${state.env.beaconAppId}`
    : state.starting ? 'starting environment…' : 'no environment';
  $('play').textContent = state.clock.running ? 'Pause' : 'Run clock';
  $('play').setAttribute('aria-label', state.clock.running ? 'Pause the round clock' : 'Run the round clock');
  if (document.activeElement !== $('rate')) $('rate').value = String(state.clock.rate);
}

function renderCapsuleList() {
  const list = $('capsules');
  $('noCapsules').hidden = state.capsules.length > 0;
  if (!selected || !state.capsules.some(c => c.id === selected)) selected = state.capsules[0]?.id ?? null;
  view(list).html = state.capsules.map(c => {
    const i = stageIndex(c);
    const tone = c.failed ? 'bad' : c.recovered ? 'ok' : i === 7 ? '' : 'acc';
    const label = c.failed ? 'failed' : c.recovered ? 'opened' : c.gone ? 'cleaned up' : STAGES[i];
    return `<li><button data-capsule="${c.id}" aria-current="${c.id === selected}"><span>Capsule ${c.id}${c.tamper ? ' · tampered' : ''}</span><span class="pill ${tone}">${esc(label)}</span></button></li>`;
  }).join('');
}

function renderCapsule() {
  if (!state?.ready) return;
  const c = state.capsules.find(x => x.id === selected);
  $('pickCapsule').hidden = !!c;
  $('capsuleBody').hidden = !c;
  if (!c) return;
  const r = c.record;
  const i = stageIndex(c);
  $('cTitle').textContent = `Capsule ${c.id}`;
  const status = $('cStatus');
  status.className = `pill ${c.failed ? 'bad' : c.recovered ? 'ok' : 'acc'}`;
  status.textContent = c.failed ? `failed: ${c.failed}` : c.recovered ? 'opened by recipient' : c.gone ? 'cleaned up' : STAGES[i];
  view($('stepper')).html = STAGES.map((s, k) => `<li class="${k < i ? 'done' : k === i ? 'now' : ''}">${s}</li>`).join('');
  view($('explain')).html = r ? EXPLAIN[i](r) : 'Boxes deleted after expiry. The chain history still contains everything that was posted.';

  if (r) {
    const start = r.seedRound - 8;
    const end = Math.max(r.expiresRound + 5, state.round + 1);
    const at = x => `${Math.max(0, Math.min(100, ((x - start) / (end - start)) * 100))}%`;
    const label = x => `${Math.max(7, Math.min(93, ((x - start) / (end - start)) * 100))}%`; // Keep text inside the card.
    const width = (a, b) => `${Math.max(0, ((Math.min(b, end) - a) / (end - start)) * 100)}%`;
    view($('timeline')).html = `<div class="track"></div>
      <div class="noms" style="left:${at(r.seedRound)};width:${width(r.seedRound, r.deadline)}" title="Nomination window"></div>
      <div class="window" style="left:${at(r.openRound)};width:${width(r.openRound, r.expiresRound)}" title="Access window"></div>
      <span class="mark" style="left:${label(r.seedRound)}">seed ${r.seedRound}</span>
      <span class="mark" style="left:${label(r.deadline)}">close ${r.deadline}</span>
      <span class="mark" style="left:${label(r.openRound)};top:22px">open ${r.openRound}</span>
      <span class="mark" style="left:${label(r.expiresRound)};top:22px">expires ${r.expiresRound}</span>
      <div class="now-mark" style="left:${at(state.round)}" title="Current round ${state.round}"></div>`;
    const released = c.slots.filter(s => s.released).length;
    view($('facts')).html = [
      [r.stage >= 2 ? r.filled : c.slots.filter(s => s.filled).length, `committee (of ${c.slotCount} slots)`],
      [r.stage >= 2 ? r.threshold : '–', 'threshold'], [r.acks, 'acknowledged'], [released, 'released'],
      [state.round, 'current round'],
    ].map(([v, l]) => `<div class="fact"><b>${v}</b><span>${l}</span></div>`).join('');
  } else {
    view($('timeline')).html = '';
    view($('facts')).html = '';
  }

  view($('slotGrid')).html = (c.slots.length ? c.slots : Array.from({ length: c.slotCount }, (_, k) => ({ k, filled: false, pending: true })))
    .map(s => s.filled ? `<div class="slot">
        <div class="top"><span>Slot ${s.k}</span><span class="chips">
          <span class="chip d ${s.deposited ? 'on' : ''}" title="deposit">D</span><span class="chip a ${s.acknowledged ? 'on' : ''}" title="acknowledged">A</span><span class="chip r ${s.released ? 'on' : ''}" title="released">R</span></span></div>
        <div class="rank" title="VRF rank ${s.rank.toFixed(4)}"><div style="width:${Math.max(3, s.rank * 100)}%"></div></div>
        <div>nominated by #${s.nominator}</div>
        ${god ? `<div class="holder">${s.holder === undefined ? 'holder unknown' : `held by #${s.holder}`}</div>` : ''}
      </div>`
      : `<div class="slot empty"><div class="top"><span>Slot ${s.k}</span></div><div style="margin-top:8px">${r && r.stage >= 1 ? (r.stage >= 2 ? 'no eligible nominator' : 'waiting for nominations') : 'waiting for seed'}</div></div>`)
    .join('');
  $('godLegend').hidden = !god;

  // The next transaction executes in round + 1.
  const when = !r ? '' : state.round + 1 < r.openRound ? ' (too early: should fail)' : state.round + 1 >= r.expiresRound ? ' (expired: should fail)' : '';
  $('request').disabled = !r || r.stage < 5;
  $('request').textContent = c.requested ? 'Request again with a new key (should fail)' : `Request access with a fresh key${when}`;
  $('recover').disabled = !c.requested;
  $('wrongWallet').disabled = !r || r.stage < 5;
  $('cleanup').disabled = !r || state.round < r.expiresRound;
  view($('recResult')).html = c.recovered
    ? `<div class="result ok">Decrypted locally from on-chain releases:<pre>${esc(c.recovered)}</pre></div>`
    : c.failed ? `<div class="result bad">${esc(c.failed)}</div>` : '';
}

function renderMembers() {
  const held = new Map();
  const nominated = new Map();
  for (const c of state.capsules) for (const s of c.slots) {
    if (s.holder !== undefined) held.set(s.holder, (held.get(s.holder) ?? 0) + 1);
    if (s.filled && c.id === selected) nominated.set(s.nominator, (nominated.get(s.nominator) ?? 0) + 1);
  }
  view($('members')).html = state.members.map(m => `<button class="member ${m.online ? '' : 'off'}" data-member="${m.index}" data-online="${m.online}"
      title="${m.address} · click to take ${m.online ? 'offline' : 'online'}"><b>#${m.index}</b>${m.online ? 'online' : 'offline'}
      ${nominated.get(m.index) ? `<div>nominated ${nominated.get(m.index)}</div>` : ''}
      ${god && held.get(m.index) ? `<div class="held">holds ${held.get(m.index)}</div>` : ''}</button>`).join('');
}

function renderRisk() {
  if (!state?.ready) return;
  const f = Number($('corrupt').value) / 100;
  $('fOut').textContent = `${Math.round(f * 100)}%`;
  const c = state.capsules.find(x => x.id === selected);
  const n = c?.record?.stage >= 2 ? c.record.filled : Number($('slots').value);
  const t = Math.floor(n / 2) + 1;
  const rows = [
    ['Hidden (now)', binomTail(n, 1 - (1 - f) ** 2, t), 'var(--priv)'],
    ['Public draw', binomTail(n, f, t), 'var(--accent)'],
  ];
  view($('riskBars')).html = rows.map(([label, p, color]) => `<div class="bar"><span>${label}</span>
    <div class="fill"><div style="width:${Math.max(1, p * 100)}%;background:${color}"></div></div><b>${pct(p)}</b></div>`).join('');
  $('riskNote').textContent = `P(colluders control ≥ ${t} of ${n} slots), holders drawn independently from a large registry. Hidden mode: a slot is lost if its public nominator or its secret holder is corrupt, about 2f. Larger committees push both toward zero, which is why step 5 matters.`;
}

function renderLog() {
  const items = state.narration.filter(n => god || !n.private).slice(-120).reverse();
  view($('log')).html = items.map(n => `<li class="${n.private ? 'priv' : n.tone ?? ''}"><time>${new Date(n.at).toLocaleTimeString([], { hour12: false })}</time><span>${n.private ? '[operator log] ' : ''}${esc(n.text)}</span></li>`).join('');
}

async function refresh() {
  try {
    state = await (await fetch('/api/state')).json();
  } catch {
    $('net').textContent = 'server unreachable';
    return;
  }
  renderSetup();
  renderHeader();
  renderLog();
  if (!state.ready) return;
  renderCapsuleList();
  renderCapsule();
  renderMembers();
  renderRisk();
}

$('start').onclick = e => act(e.target, () => post('start', {
  members: Number($('sMembers').value), nominationRounds: Number($('sRounds').value), perSlot: Number($('sPerSlot').value) }));
$('play').onclick = e => act(e.target, () => post('clock', { running: !state.clock.running }));
$('rate').onchange = e => act(null, () => post('clock', { rate: Number(e.target.value) }));
document.querySelector('[data-advance]').onclick = e => act(e.target, () => post('advance', { rounds: 10 }));
$('god').onchange = e => { god = e.target.checked; store.set('god', god ? '1' : '0'); if (state?.ready) { renderCapsule(); renderMembers(); } if (state) renderLog(); };
$('lock').onclick = e => act(e.target, async () => {
  const { id } = await post('capsule', { message: $('message').value, slots: Number($('slots').value), minHolders: Number($('minHolders').value),
    openIn: Number($('openIn').value), length: Number($('length').value), tamper: $('tamper').checked });
  selected = id;
  store.set('capsule', id);
});
$('capsules').onclick = e => {
  const b = e.target.closest('[data-capsule]');
  if (!b) return;
  selected = b.dataset.capsule;
  store.set('capsule', selected);
  renderCapsuleList(); renderCapsule(); renderMembers(); renderRisk();
};
$('members').onclick = e => {
  const b = e.target.closest('[data-member]');
  if (b) act(b, () => post(`member/${b.dataset.member}`, { online: b.dataset.online !== 'true' }));
};
$('request').onclick = e => act(e.target, () => post(`request/${selected}`, { as: 'recipient' }));
$('wrongWallet').onclick = e => act(e.target, () => post(`request/${selected}`, { as: 'outsider' }));
$('recover').onclick = e => act(e.target, () => post(`recover/${selected}`));
$('cleanup').onclick = e => act(e.target, () => post(`cleanup/${selected}`));
$('corrupt').oninput = renderRisk;
$('slots').oninput = renderRisk;

refresh();
setInterval(refresh, 1000);
