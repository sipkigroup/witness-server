import { get, post, put, del } from './api.js';
import { uxText } from './uxguard.js';
import { h, $, clear, notice, mountNav, fmtTime, fmtMoney, copyButton, mcpConfig, until, safeId, failText } from './ui.js';
import { coverageView } from './coverage.js';
import { anchorText } from './anchors.js';
import { revokeMandate } from './revoke.js';
import { explainError } from './webauthn.js';
import { mountChannels, frozenText } from './channels.js';
import { askOf } from './ask.js';
import { inspectFields } from './honest.js';

const msg = $('#msg');
const state = { agents: [], before: null, feedAgent: '', me: null, mandates: [] };
const name = (id) => (state.agents.find((a) => a.id === id) || {}).name || id;
const fail = (e) => notice(msg, 'err', e.detail ? e.code + ': ' + e.detail : e.message);

async function coverageOf(a) {
  try { return (await get('/api/catalog/' + encodeURIComponent(a.id))) || null; } catch (e) { return null; }
}

async function revoke(a, btn) {
  const row = state.mandates.find((x) => x.id === a.active_mandate_id);
  if (!row) { notice(msg, 'err', 'The active mandate was not found; reload the page.'); return; }
  if (!confirm('Revoke the mandate of "' + a.name + '"? Every action of the agent is refused until a new mandate is signed. Your passkey signs the revocation; one signature of any signer is enough.')) return;
  btn.disabled = true;
  try { await revokeMandate(row, state.me); notice(msg, 'ok', 'Mandate revoked. The agent is refused until a new mandate is signed.'); await refreshAll(); }
  catch (e) { notice(msg, 'err', e.code ? failText(e) : explainError(e)); btn.disabled = false; }
}

// 0.2.17 (R9-04): the Claude Code hook's judge rounds that ended without an action (the witness asked for file facts, or refused the call)
function hookRounds(r) {
  if (!r || !(r.need || r.refuse)) return '';
  const text = 'Claude Code hook, last 24 h: ' + r.need + ' file-fact rounds and ' + r.refuse + ' refused calls (they count toward the quota).';
  return h('p', { class: r.suspicious ? 'notice warn' : 'hint', text: r.suspicious ? text + ' Unusually many: someone may be probing the witness with this agent key.' : text });
}

// 0.2.25: freeze / unfreeze on the agent card (the server asks for a fresh passkey touch; api.js requests it and retries)
function frozenNote(a) { const t = frozenText(a); return t ? h('p', { class: 'notice warn', text: t }) : ''; }

async function freeze(a, btn) {
  if (!confirm('Freeze "' + a.name + '"? Everything it waits for is refused and its new calls are refused until you unfreeze it. Your passkey confirms it.')) return;
  btn.disabled = true;
  try { const x = await post('/api/agents/' + encodeURIComponent(a.id) + '/freeze'); notice(msg, 'warn', 'Agent frozen. Requests cancelled: ' + x.cancelled + '.'); await refreshAll(); }
  catch (e) { notice(msg, 'err', e.code ? failText(e) : explainError(e)); btn.disabled = false; }
}

async function unfreeze(a, btn) {
  if (!confirm('Unfreeze "' + a.name + '"? Its calls are judged by the mandate again. Only the owner can do this; your passkey confirms it.')) return;
  btn.disabled = true;
  try { await post('/api/agents/' + encodeURIComponent(a.id) + '/unfreeze'); notice(msg, 'ok', 'Agent unfrozen. Its calls are judged by the mandate again.'); await refreshAll(); }
  catch (e) { notice(msg, 'err', e.code ? failText(e) : explainError(e)); btn.disabled = false; }
}

async function loadAgents() {
  state.agents = await get('/api/agents');
  try { state.mandates = await get('/api/mandates'); } catch (e) { state.mandates = []; }
  const cats = await Promise.all(state.agents.map(coverageOf));
  const box = clear($('#agents'));
  if (!state.agents.length) box.append(h('p', { class: 'hint', text: 'No agents yet. Create one below; its API key is shown once.' }));
  state.agents.forEach((a, i) => {
    const m = a.active_mandate_id;
    const cat = cats[i];
    box.append(h('div', { class: 'card' },
      h('div', { class: 'row' }, h('strong', { text: a.name }), h('span', { class: 'mono hint', text: a.id + ' / ' + a.key_prefix + '...' }),
        h('span', { class: 'pill ' + (m ? 'allow' : 'defer'), text: m ? 'mandate active' : 'no mandate' }),
        a.frozen_at ? h('span', { class: 'pill deny', text: 'frozen' }) : ''),
      frozenNote(a),
      m ? h('p', { class: 'hint' }, 'Mandate ', h('span', { class: 'mono', text: m })) : h('p', { class: 'hint', text: 'Without a signed mandate every action is denied (NO_MANDATE).' }),
      cat ? h('div', {}, ...coverageView(cat.coverage)) : '',
      cat && cat.drift ? h('p', { class: 'notice warn', text: 'The MCP tools of this agent changed; new arguments are refused until you review the catalog.' }) : '',
      hookRounds(a.hook_rounds_24h),
      h('div', { class: 'row' },
        h('a', { class: 'btn', href: 'mandate.html?agent=' + encodeURIComponent(a.id) }, m ? 'New mandate' : 'Create mandate'),
        m ? h('button', { class: 'btn danger', type: 'button', onclick: (ev) => revoke(a, ev.target) }, 'Revoke mandate') : '',
        cat && cat.catalog_sha256 && safeId(a.id) ? h('a', { class: 'btn ghost', href: 'catalog.html?agent=' + encodeURIComponent(a.id) }, 'Tool catalog') : '',
        a.frozen_at
          ? h('button', { class: 'btn', type: 'button', onclick: (ev) => unfreeze(a, ev.target) }, 'Unfreeze')
          : h('button', { class: 'btn ghost', type: 'button', onclick: (ev) => freeze(a, ev.target) }, 'Freeze'),
        h('button', { class: 'btn danger ghost', type: 'button', onclick: async () => {
          if (!confirm('Disable agent "' + a.name + '"? Its API key stops working.')) return;
          try { await del('/api/agents/' + a.id); await refreshAll(); } catch (e) { fail(e); }
        } }, 'Disable'))));
  });
  const sel = $('#ff'), cur = sel.value;
  clear(sel).append(h('option', { value: '' }, 'all agents'), ...state.agents.map((a) => h('option', { value: a.id }, a.name)));
  sel.value = cur;
  const ta = $('#tmagent'), cta = ta.value;
  clear(ta).append(...state.agents.map((a) => h('option', { value: a.id }, a.name)));
  if (cta) ta.value = cta;
  showToolmap();
}

function showToolmap() {
  const a = state.agents.find((x) => x.id === $('#tmagent').value);
  $('#tm').value = a ? JSON.stringify(a.toolmap, null, 2) : '';
  notice($('#tmmsg'), 'ok', '');
}

async function loadBudget() {
  const rows = await get('/api/budget');
  const box = clear($('#budget'));
  if (!rows.length) { box.append(h('p', { class: 'hint', text: 'No purchase budget yet. It appears once a mandate with purchases is signed.' })); return; }
  for (const r of rows) {
    const pct = r.budget ? Math.min(100, Math.round((r.committed / r.budget) * 100)) : 0;
    box.append(h('div', {},
      h('div', { class: 'row' }, h('strong', { text: name(r.agent_id) }), h('span', { class: 'hint', text: fmtMoney(r.committed, r.currency) + ' of ' + fmtMoney(r.budget, r.currency) + ' committed, window ' + Math.round(r.window_s / 3600) + ' h, max per action ' + fmtMoney(r.max_per_action, r.currency) })),
      bar(pct)));
  }
}

function bar(pct) {
  const i = h('i'); i.style.width = pct + '%'; // CSSOM, allowed under a strict style CSP
  return h('div', { class: 'bar' + (pct >= 90 ? ' hot' : ''), role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(pct) }, i);
}

function feedRow(x) {
  const target = [x.recipient, x.amount != null ? fmtMoney(x.amount, x.currency) : ''].filter(Boolean).join(' / ');
  return h('tr', {},
    h('td', { 'data-l': 'Time', text: fmtTime(x.t) }), h('td', { 'data-l': 'Agent', text: name(x.agent_id) }),
    h('td', { 'data-l': 'Tool', title: x.args_preview || '', text: x.tool }), h('td', { 'data-l': 'Target', text: target }),
    h('td', { 'data-l': 'Verdict' }, h('span', { class: 'pill ' + x.verdict, text: x.verdict }), ' ', x.status && x.status !== x.verdict ? h('span', { class: 'hint', text: statusText(x) }) : null),
    h('td', { 'data-l': 'Reason', text: x.reason || '' }));
}

// 0.2.43b (C): the hook said its wait ended (timeout): the agent was refused and did not run the call; it stays approvable until it expires
export function statusText(x) {
  if (x && x.gave_up_at && x.status === 'pending_approval') return 'not run: timeout (the agent stopped waiting; you may still approve it for a repeat of the same call)';
  if (x && x.gave_up_at && x.status === 'expired') return 'not run: timeout';
  return x ? x.status : '';
}

async function loadFeed(more) {
  const q = new URLSearchParams({ limit: '25' });
  if (state.feedAgent) q.set('agent_id', state.feedAgent);
  if (more && state.before) q.set('before', state.before);
  const r = await get('/api/feed?' + q);
  const body = $('#feed');
  if (!more) clear(body);
  for (const x of r.items) body.append(feedRow(x));
  if (!body.children.length) body.append(h('tr', {}, h('td', { colspan: '6', class: 'hint', text: 'No actions yet. Send one with curl or through the MCP proxy.' })));
  state.before = r.next_before;
  $('#more').hidden = !r.next_before;
}

let lastPending = -1;
// the hook's wait ended: approving now runs nothing at once; it only records the decision for a repeat of the same call
// 06.11 (owner at the phone: too many words): one short line
export const GONE_TEXT = 'the agent stopped waiting: if you approve, it runs when the agent tries again';
// 0.2.76: the waiting call in words ("wants to run python3 hello.py"), through the honest filter, cut to one short line
function askLine(x) {
  const a = askOf(x);
  const w = inspectFields([['What', String(a.what || '')]], []).rows[0][1];
  return a.verb.replace(/^Your agent /, '') + (w ? ' ' + (w.length > 90 ? w.slice(0, 90) + '…' : w) : '');
}
async function loadPending() {
  // 28.10 (browser check): a held call (a secret seen, a written file run ...) waits for the person too but was missing here
  const [pend, held] = await Promise.all([get('/api/approvals?status=pending'), get('/api/approvals?status=held').catch(() => [])]);
  const items = [...pend, ...held.map((x) => ({ ...x, held: true }))];
  document.title = (items.length ? '(' + items.length + ') ' : '') + 'Dashboard - Deus Witness';
  $('#pcount').replaceChildren(items.length ? h('span', { class: 'pending-dot', text: items.length + ' waiting' }) : '');
  $('#pending-card').hidden = !items.length;
  const box = clear($('#pending'));
  for (const x of items) {
    const gone = !!x.gave_up_at && !x.held;            // 04.11 (L3): the agent stopped waiting: Review is not the main action, and the text says what a decision does
    box.append(h('div', { class: 'row' },
      h('span', { class: 'pendtext' }, h('strong', { text: name(x.agent_id) }), ' ' + askLine(x), h('span', { class: 'hint', text: ' (' + (x.held ? 'held, you decide; ' : '') + (gone ? GONE_TEXT + '; ' : '') + until(x.expires) + ')' })),
      h('a', { class: gone ? 'btn ghost' : 'btn big', href: 'approve.html?rid=' + encodeURIComponent(x.rid) }, 'Review')));
  }
  if (items.length > 1) box.append(h('p', {}, h('a', { href: 'approve.html' }, 'All waiting items and batches')));
  if (items.length !== lastPending) { lastPending = items.length; if (items.length) loadFeed(false).catch(fail); }
}

// 0.2.41: text next to the Create agent button; the beta allows 25 agents per account
export function newAgentError(e) {
  const t = e && e.detail ? e.code + ': ' + e.detail : (e && e.message) || 'Could not create the agent.';
  return e && e.code === 'QUOTA' ? t + ' Disable an agent you no longer use (disabled agents don\'t count).' : t;
}

async function refreshAll() {
  await loadAgents(); await Promise.all([loadBudget(), loadFeed(false), loadPending()]);
}

async function loadPatterns() {
  const r = await get('/api/data-patterns');
  const box = clear($('#dp'));
  for (const [cls, vals] of Object.entries(r.patterns || {})) box.append(patternRow(cls, vals));
  if (!box.children.length) box.append(h('p', { class: 'hint', text: 'No classes yet.' }));
}
function patternRow(cls, vals) {
  return h('div', { class: 'dprow' }, h('label', { text: cls }), h('input', { 'data-cls': cls, value: (vals || []).join(', '), placeholder: 'comma-separated phrases' }));
}

// 0.2.96 ("approved without reading", server app/uxstat.py): the three numbers side by side and the warning when the alarm is on
async function loadUx() {
  let v;
  try { v = await get('/api/ux-guard'); } catch (e) { return; }
  const t = uxText(v);
  if (!t) return;
  $('#ux-card').hidden = false;
  $('#uxline').textContent = t;
  $('#uxwarn').hidden = !v.alarm;
  $('#uxwarn').textContent = v.alarm ? (v.warning || '') : '';
}

async function main() {
  const me = await mountNav(true);
  if (!me) return;
  state.me = me;
  loadUx();
  try { const org = await get('/api/org'); const t = anchorText((org.settings || {}).profile || 'smb'); $('#anchor').textContent = t.lead; clear($('#anchormore')).append(...t.more.map((x) => h('p', { class: 'hint', text: x }))); $('#anchorsum').textContent = t.moreTitle; } catch (e) { $('#anchorbox').hidden = true; }
  // 0.2.41: the key box is filled FIRST and never cleared by a list refresh; the button is locked during the request (a double submit made a second
  // agent / a 429 and the box was lost); an error is shown next to the button (#newerr), not at the top of the page
  $('#newagent').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const btn = $('#newbtn'); if (btn.disabled) return;
    btn.disabled = true; notice($('#newerr'), 'err', '');
    let r;
    try {
      r = await post('/api/agents', { name: $('#an').value.trim(), preset: $('#ap').value });
    } catch (e) {
      notice($('#newerr'), 'err', newAgentError(e)); $('#newerr').scrollIntoView({ block: 'nearest' }); btn.disabled = false; return;
    }
    try {
      const preset = $('#ap').value;
      const box = $('#newkey'); clear(box); box.hidden = false; box.className = 'notice warn';
      let copied = false;
      const close = h('button', { class: 'btn ghost', type: 'button', onclick: () => { if (copied || confirm('Close without copying the API key? It cannot be shown again.')) { clear(box); box.hidden = true; } } }, 'I have copied the key, close');
      box.append(h('strong', { text: 'API key (shown once, copy it now):' }), h('pre', { text: r.api_key }), copyButton(() => { copied = true; return r.api_key; }, 'Copy key'), close);
      box.scrollIntoView({ block: 'nearest' });
      const cfg = mcpConfig(r.api_key);
      box.append(
        h('p', { text: 'Install the client once: pip install deus-witness (or pipx install deus-witness). Then the MCP client config (Claude Desktop, Claude Code, any stdio client). It is the quickstart example: the bundled demo tools, nothing real happens. For your own tools replace what follows "--" with that server\'s command:' }),
        h('pre', { text: cfg }), copyButton(() => { copied = true; return cfg; }, 'Copy config'));
      // 0.2.28: create agent + sign its mandate in one go: the mandate page opens prefilled with the quickstart example (step 3); nothing is signed until you press Sign
      if (preset === 'demo' && r.agent && safeId(r.agent.id)) {
        const next = h('a', { class: 'btn', href: 'mandate.html?agent=' + encodeURIComponent(r.agent.id) + '&sample=1', text: 'Next: sign the example mandate' });
        next.addEventListener('click', (e) => { if (!copied && !confirm('Did you copy the API key? It is shown only once.')) e.preventDefault(); });
        box.append(h('p', { text: 'Then sign the example mandate of the quickstart (purchases up to $100 each, $200 a day; mail only to acme.example; publishing waits for you). You review it before your passkey signs it.' }), next);
      }
      $('#an').value = '';
    } catch (e) { fail(e); }
    btn.disabled = false;
    try { await refreshAll(); } catch (e) { fail(e); }   // the list refresh must not touch the key box
  });
  $('#ff').addEventListener('change', (ev) => { state.feedAgent = ev.target.value; loadFeed(false).catch(fail); });
  $('#more').addEventListener('click', () => loadFeed(true).catch(fail));
  $('#tmagent').addEventListener('change', showToolmap);
  $('#tmsave').addEventListener('click', async () => {
    const id = $('#tmagent').value; if (!id) return;
    let tm;
    try { tm = JSON.parse($('#tm').value); } catch (e) { notice($('#tmmsg'), 'err', 'Not valid JSON: ' + e.message); return; }
    try { const r = await put('/api/agents/' + id + '/toolmap', { toolmap: tm }); const a = state.agents.find((x) => x.id === id); if (a) a.toolmap = r.agent.toolmap; notice($('#tmmsg'), 'ok', 'Saved. Until you sign a new mandate for this agent (Mandate page), every call of this agent is refused with TOOLMAP_CHANGED: the passkey-signed mandate is tied to the tool map it was signed with.'); }
    catch (e) { notice($('#tmmsg'), 'err', e.code + (e.detail ? ': ' + e.detail : '')); }
  });
  $('#dpadd').addEventListener('click', () => {
    const n = $('#dpname').value.trim(); if (!/^[a-z0-9_]{1,40}$/.test(n)) { notice($('#dpmsg'), 'err', 'Class name: lowercase letters, digits, underscore.'); return; }
    if ($('#dp .hint')) clear($('#dp')); $('#dp').append(patternRow(n, [])); $('#dpname').value = ''; notice($('#dpmsg'), 'ok', '');
  });
  $('#dpsave').addEventListener('click', async () => {
    const patterns = {};
    document.querySelectorAll('#dp input[data-cls]').forEach((i) => { patterns[i.dataset.cls] = i.value.split(',').map((s) => s.trim()).filter(Boolean); });
    try { await put('/api/data-patterns', { patterns }); notice($('#dpmsg'), 'ok', 'Saved.'); } catch (e) { notice($('#dpmsg'), 'err', e.code + ': ' + e.detail); }
  });
  try { await refreshAll(); await loadPatterns(); } catch (e) { fail(e); }
  mountChannels().catch(() => { $('#chan-card').hidden = true; });
  setInterval(() => { loadPending().catch(() => {}); }, 5000);
}
main();
