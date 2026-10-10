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

const STAGES = ['Locked', 'Open', 'Requested', 'Opened', 'Expired'];

function toast(text) {
  const t = $('toast');
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 5000);
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

// Exact Poisson tails of the paper's §3.2 process for a committee of about C seats (illustrative: assumes N ≫ C).
const below = (lambda, t) => { let p = Math.exp(-lambda), sum = 0; for (let k = 0; k < t; k++) { sum += p; p *= lambda / (k + 1); } return Math.min(1, sum); };
const pct = p => (p < 0.0001 ? '<0.01%' : `${(p * 100).toFixed(p < 0.1 ? 2 : 1)}%`);

function stageIndex(c) {
  if (c.gone || state.round >= c.expires) return 4;
  if (c.opened) return 3;
  if (c.requested) return 2;
  return state.round >= c.open ? 1 : 0;
}

function renderSetup() {
  $('setup').hidden = state.ready;
  $('lab').hidden = !state.ready;
  $('clockControls').hidden = !state.ready;
  $('start').disabled = state.starting;
  $('startStatus').textContent = state.starting ? 'Starting… funding accounts, deploying, enrolling (≈20–40 s)' : state.error ? `Failed: ${state.error}` : '';
}

function renderHeader() {
  $('net').textContent = state.ready ? `round ${state.round} · app ${state.env.appId} · epoch ${state.epoch.epoch} · threshold t = ${state.env.t}`
    : state.starting ? 'starting environment…' : 'no environment';
  $('play').textContent = state.clock.running ? 'Pause' : 'Run clock';
  if (document.activeElement !== $('rate')) $('rate').value = String(state.clock.rate);
}

function renderEpoch() {
  const e = state.epoch, r = state.round;
  $('eTitle').textContent = `Epoch ${e.epoch} · committee ${e.epoch} in office`;
  const phase = r < e.nominate[0] ? 'starting' : r <= e.nominate[1] ? 'nominations' : r <= e.handover[1] ? 'handover' : 'verification';
  $('ePhase').textContent = phase;
  const span = e.end + 1 - e.start, at = x => `${((x - e.start) / span) * 100}%`, width = (a, b) => `${((b - a + 1) / span) * 100}%`;
  view($('eTimeline')).html = `<div class="track"></div>
    <div class="noms" style="left:${at(e.nominate[0])};width:${width(e.nominate[0], e.nominate[1])}" title="Nominations for the next committee"></div>
    <div class="hand" style="left:${at(e.handover[0])};width:${width(e.handover[0], e.handover[1])}" title="Handover"></div>
    <span class="mark" style="left:12%">nominate ${e.epoch + 1}</span><span class="mark" style="left:62%">hand over</span>
    <div class="now-mark" style="left:${at(r)}" title="Round ${r}"></div>`;
  const genesis = state.env.genesis;
  view($('eExplain')).html = e.epoch < genesis
    ? `Warming up: committee ${genesis} is the genesis committee. It holds nothing and creates the first buckets at its handover.`
    : phase === 'nominations' ? `Each member privately runs its VRF on this epoch's block seed, once per ticket: its bond buys tickets, so seats follow stake. For each winning ticket it seals a fresh seat's one-time keys to a member chosen at random by bond, then erases its choice. <b>${e.nominated}</b> seats for committee ${e.epoch + 1} so far.`
    : phase === 'handover' ? `Committee ${e.epoch}'s holders speak once, from their own accounts, after erasing: re-sharings of every bucket key, contributions to new buckets, capsule partials, and the public state they attest. <b>${e.posted}/${e.inOffice}</b> seats posted.`
    : `Every member checks the posted messages on its thread pool. The next committee's seats combine the first t valid dealings per bucket. The old committee's shares are gone.`;
  view($('eFacts')).html = [[e.inOffice, `seats in committee ${e.epoch}`], [e.posted, 'messages posted'], [e.nominated, `seats nominated for ${e.epoch + 1}`], [state.env.t, 'threshold t']]
    .map(([v, l]) => `<div class="fact"><b>${v}</b><span>${l}</span></div>`).join('');
  view($('history')).html = state.history.length
    ? `<table class="hist"><tr><th>Handover</th><th>Messages</th><th title="Valid dealings beyond t, for the worst bucket: at 0, one more silent seat loses buckets">Margin</th><th>Buckets held after</th><th>Agree</th></tr>${state.history.map(h =>
      `<tr><td>${h.committee} → ${Number(h.committee) + 1}</td><td>${h.messages}</td><td>${h.margin <= 0 ? `<span class="pill bad">${h.margin}</span>` : h.margin}</td><td>${h.buckets.map(b => `<span class="mono" title="public key ${esc(b.key)}…">b${b.bucket}</span>`).join(' ') || '–'}${h.lost ? ` <span class="pill bad">lost ${esc(h.lost)}</span>` : ''}</td><td>${h.agree ? '✓' : '✗'}</td></tr>`).join('')}</table>`
    : '<p class="note">No handover processed yet.</p>';
}

function renderCapsuleList() {
  $('noCapsules').hidden = state.capsules.length > 0;
  if (!selected || !state.capsules.some(c => c.id === selected)) selected = state.capsules[0]?.id ?? null;
  view($('capsules')).html = state.capsules.map(c => {
    const i = stageIndex(c), tone = c.opened ? 'ok' : c.refused ? 'warn' : i === 4 ? '' : 'acc';
    return `<li><button data-capsule="${c.id}" aria-current="${c.id === selected}"><span>Capsule ${c.id}${c.copyOf ? ` · copy of ${c.copyOf}` : ''}</span><span class="pill ${tone}">${c.gone ? 'cleaned up' : STAGES[i]}</span></button></li>`;
  }).join('');
  $('copy').disabled = !state.capsules.some(c => c.id === selected && !c.copyOf);
}

function renderCapsule() {
  const c = state.capsules.find(x => x.id === selected);
  $('pickCapsule').hidden = !!c;
  $('capsuleBody').hidden = !c;
  if (!c) return;
  const i = stageIndex(c);
  $('cTitle').textContent = `Capsule ${c.id}${c.copyOf ? ` (copied u of ${c.copyOf})` : ''}`;
  $('cStatus').className = `pill ${c.opened ? 'ok' : c.refused ? 'warn' : 'acc'}`;
  $('cStatus').textContent = c.gone ? 'cleaned up' : c.refused ? 'refused by holders' : STAGES[i];
  view($('stepper')).html = STAGES.map((s, k) => `<li class="${k < i ? 'done' : k === i ? 'now' : ''}">${s}</li>`).join('');
  const start = Math.min(c.open, state.round) - 10, end = Math.max(c.expires + 10, state.round + 1);
  const at = x => `${Math.max(0, Math.min(100, ((x - start) / (end - start)) * 100))}%`, label = x => `${Math.max(7, Math.min(93, ((x - start) / (end - start)) * 100))}%`;
  view($('timeline')).html = `<div class="track"></div>
    <div class="window" style="left:${at(c.open)};width:${((c.expires - c.open) / (end - start)) * 100}%" title="Access window"></div>
    <span class="mark" style="left:${label(c.open)}">open ${c.open}</span><span class="mark" style="left:${label(c.expires)};top:22px">expires ${c.expires}</span>
    <div class="now-mark" style="left:${at(state.round)}"></div>`;
  view($('explain')).html = [
    `Locked under bucket ${c.bucket}'s key, as attested by at least t holders. Opens at round ${c.open}.`,
    `Open until round ${c.expires}. Request access to bind a fresh key. The committee in office then releases at its next handover.`,
    c.refused ? 'Every holder refused: this u carries a proof bound to another policy, so copying a capsule gets nothing decrypted.'
      : `Requested. Each holder of the committee in office puts a partial, sealed to the recipient's key, into its single handover message (rounds ${state.epoch.handover.join('–')}).`,
    'Opened locally from t verified partials.',
    `Expired: no new releases. Bucket ${c.bucket} is dropped at the first handover after its window ends. After that no committee holds it, and the erased shares are gone.`,
  ][i];
  view($('facts')).html = [[`b${c.bucket}`, 'bucket'], [c.requested ? 'yes' : 'no', 'requested'],
    ...(god ? [[c.releasedBy, 'seats released (operator)']] : []), [state.round, 'current round']]
    .map(([v, l]) => `<div class="fact"><b>${v}</b><span>${l}</span></div>`).join('');
  $('request').disabled = c.gone || i === 4;
  $('request').textContent = c.requested ? 'Request again with a new key (should fail)' : `Request access with a fresh key${state.round + 1 < c.open ? ' (too early: should fail)' : ''}`;
  $('open').disabled = !c.requested || !!c.opened;
  $('wrongWallet').disabled = c.gone || !!c.copyOf;
  $('cleanup').disabled = c.gone || state.round < c.expires;
  view($('recResult')).html = c.opened ? `<div class="result ok">Decrypted locally from t verified partials:<pre>${esc(c.opened)}</pre></div>` : '';
}

function renderMembers() {
  view($('members')).html = state.members.map(m => `<button class="member ${m.online ? '' : 'off'}" data-member="${m.index}" data-online="${m.online}"
      title="${m.address} · bond ${m.bond} Algo · ${m.nominated} seat(s) nominated for the next committee · click to take ${m.online ? 'offline' : 'online'}"><b>#${m.index}</b>${m.online ? 'online' : 'offline'}
      <div class="held">bond ${m.bond} · nominated ${m.nominated}</div>
      ${god && m.seats ? `<div class="held">${m.seats} seat${m.seats > 1 ? 's' : ''} now</div>` : ''}</button>`).join('');
}

function renderRisk() {
  if (!state?.ready) return;
  const f = Number($('corrupt').value) / 100, C = state.epoch.inOffice || state.env.committee, t = state.env.t;
  $('fOut').textContent = `${Math.round(f * 100)}%`;
  const exposed = 1 - below(C * f * (2 - f), t), stuck = below(C * (1 - f) ** 2, t);
  view($('riskBars')).html = [['Key exposed', exposed, 'var(--bad)'], ['Handover fails', stuck, 'var(--warn)']].map(([label, p, color]) =>
    `<div class="bar"><span>${label}</span><div class="fill"><div style="width:${Math.max(1, p * 100)}%;background:${color}"></div></div><b>${pct(p)}</b></div>`).join('');
  $('riskNote').textContent = `Per epoch, for a committee of about ${C} seats and threshold ${t}. A seat is corrupt if its nominator or its holder is (about 2f). ` +
    `Exposure needs t corrupt seats; a handover fails without t honest ones. Demo-sized committees are weak: the plan's parameters are C ≈ 130–210.`;
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
  renderEpoch();
  renderCapsuleList();
  renderCapsule();
  renderMembers();
  renderRisk();
}

$('start').onclick = e => act(e.target, () => post('start', { members: Number($('sMembers').value), committee: Number($('sCommittee').value), t: Number($('sT').value) }));
$('play').onclick = e => act(e.target, () => post('clock', { running: !state.clock.running }));
$('rate').onchange = e => act(null, () => post('clock', { rate: Number(e.target.value) }));
for (const b of document.querySelectorAll('[data-advance]')) b.onclick = e => act(e.target, () => post('advance', { rounds: Number(b.dataset.advance) }));
$('god').onchange = e => { god = e.target.checked; store.set('god', god ? '1' : '0'); if (state?.ready) { renderCapsule(); renderMembers(); } if (state) renderLog(); };
$('lock').onclick = e => act(e.target, async () => {
  const { id } = await post('capsule', { message: $('message').value, openIn: Number($('openIn').value), length: Number($('length').value) });
  selected = id;
  store.set('capsule', id);
});
$('copy').onclick = e => act(e.target, async () => { const { id } = await post(`copy/${selected}`); selected = id; store.set('capsule', id); });
$('capsules').onclick = e => {
  const b = e.target.closest('[data-capsule]');
  if (!b) return;
  selected = b.dataset.capsule;
  store.set('capsule', selected);
  renderCapsuleList(); renderCapsule();
};
$('members').onclick = e => {
  const b = e.target.closest('[data-member]');
  if (b) act(b, () => post(`member/${b.dataset.member}`, { online: b.dataset.online !== 'true' }));
};
$('request').onclick = e => act(e.target, () => post(`request/${selected}`, { as: 'recipient' }));
$('wrongWallet').onclick = e => act(e.target, () => post(`request/${selected}`, { as: 'outsider' }));
$('open').onclick = e => act(e.target, () => post(`open/${selected}`));
$('cleanup').onclick = e => act(e.target, () => post(`cleanup/${selected}`));
$('corrupt').oninput = renderRisk;

refresh();
setInterval(refresh, 1000);
