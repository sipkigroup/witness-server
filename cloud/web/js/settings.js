// 0.2.47: Settings page. Card "Export tokens": issue (agent, 1-168 h; passkey step-up via api.js), show the token ONCE with Copy, list the
// live ones, revoke. Server data goes in through textContent only (ui.h). Texts and checks: export_tokens.js.
import { get, post, del } from './api.js';
import { explainError } from './webauthn.js';
import { h, $, clear, notice, mountNav, fmtTime, failText, copyButton, safeId } from './ui.js';
import { TTL_DEFAULT, TTL_MAX, TTL_MIN, issueBody, liveTokens, leftText, usesText, useExample, ONCE_TEXT, SCOPE_TEXT, xtError } from './export_tokens.js';

const msg = $('#xtmsg');
const S = { agents: [], tokens: [] };
const errText = (e) => xtError(e) || (e && e.code ? failText(e) : explainError(e));
const agentName = (id) => { const a = S.agents.find((x) => x.id === id); return a ? a.name : id; };

function render() {
  const body = clear($('#xtlist'));
  const live = liveTokens(S.tokens);
  $('#xtnone').hidden = live.length > 0;
  $('#xttable').hidden = live.length === 0;
  for (const t of live) {
    body.append(h('tr', {},
      h('td', { 'data-l': 'Agent', text: agentName(t.agent_id) }),
      h('td', { 'data-l': 'Label', text: t.label || '-' }),
      h('td', { 'data-l': 'Issued', text: fmtTime(t.created_at) }),
      h('td', { 'data-l': 'Expires', text: fmtTime(t.expires_at) + ' (' + leftText(t.expires_at) + ')' }),
      h('td', { 'data-l': 'Used', text: usesText(t) + (t.last_used_at ? ', last ' + fmtTime(t.last_used_at) : '') }),
      h('td', {}, safeId(t.id) ? h('button', { class: 'btn danger', type: 'button', 'data-xt': t.id, onclick: () => revoke(t) }, 'Revoke') : '')));
  }
}

async function load() {
  S.tokens = await get('/api/export-tokens');
  render();
}

function fillAgents() {
  const sel = clear($('#xtagent'));
  for (const a of S.agents) sel.append(h('option', { value: a.id, text: a.name + (a.frozen_at ? ' (frozen)' : '') }));
  const none = S.agents.length === 0;
  $('#xtnoagent').hidden = !none;
  $('#xtnew').disabled = none;
}

async function issue() {
  notice(msg, 'ok', '');
  const b = issueBody($('#xtagent').value, $('#xtttl').value, $('#xtlabel').value);
  if (!b) { notice(msg, 'err', $('#xtagent').value ? 'Valid for: a whole number of hours from ' + TTL_MIN + ' to ' + TTL_MAX + '.' : 'Choose an agent.'); return; }
  const btn = $('#xtnew'); btn.disabled = true;
  try {
    const r = await post('/api/export-tokens', b);
    showOnce(r.export_token, r.token);
    $('#xtlabel').value = '';
    await load();
  } catch (e) { notice(msg, 'err', errText(e)); }
  btn.disabled = S.agents.length === 0;
}

function showOnce(tok, row) {
  const box = clear($('#xtshown'));
  let copied = false;
  const done = h('button', { class: 'btn ghost', type: 'button', id: 'xtdone' }, 'Done, I saved it');
  done.addEventListener('click', () => {
    if (!copied && !confirm('Did you copy the export token? It is shown only once.')) return;
    clear(box); box.hidden = true;
  });
  const cp = copyButton(() => { copied = true; return tok; }, 'Copy token');
  cp.id = 'xtcopy';
  box.append(h('strong', { text: 'Export token for ' + agentName(row && row.agent_id) + ' (valid until ' + fmtTime(row && row.expires_at) + '):' }),
    h('pre', { id: 'xttok', text: tok }), h('p', { class: 'row' }, cp, done),
    h('p', { class: 'hint', text: ONCE_TEXT }),
    h('p', { class: 'hint', text: 'A CI job downloads the evidence pack with it and the agent\'s API key:' }),
    h('pre', { text: useExample(tok, location.origin) }));
  box.hidden = false;
  box.scrollIntoView({ block: 'nearest' });
}

async function revoke(t) {
  if (!confirm('Revoke the export token for "' + agentName(t.agent_id) + '"' + (t.label ? ' (' + t.label + ')' : '') + '? A CI job that uses it stops getting the evidence pack at once.')) return;
  notice(msg, 'ok', '');
  try {
    await del('/api/export-tokens/' + t.id);
    notice(msg, 'ok', 'Export token revoked.');
    await load();
  } catch (e) { notice(msg, 'err', errText(e)); }
}

async function main() {
  const me = await mountNav(true);
  if (!me) return;
  $('#xtscope').replaceChildren(...SCOPE_TEXT.map((t) => h('li', { text: t })));
  const ttl = $('#xtttl'); ttl.min = String(TTL_MIN); ttl.max = String(TTL_MAX); ttl.value = String(TTL_DEFAULT);
  try { S.agents = await get('/api/agents'); } catch (e) { S.agents = []; }
  fillAgents();
  try { await load(); } catch (e) {
    if (e && (e.code === 'FORBIDDEN' || e.code === 'NOT_MEMBER')) { $('#xtform').hidden = true; $('#xttable').hidden = true; $('#xtnone').hidden = true; notice(msg, 'warn', xtError(e)); return; }
    throw e;
  }
  $('#xtnew').addEventListener('click', issue);
}
main().catch((e) => notice(msg, 'err', failText(e)));
