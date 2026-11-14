import { get } from './api.js';
import { h, $, clear, notice, mountNav, fmtMoney, safeId, failText } from './ui.js';
import { digestFigures } from './digest_calc.js';

const msg = $('#msg');
const names = new Map();
const nm = (id) => names.get(id) || id;

function pairs(dl, obj, label = (k) => k) {
  const e = Object.entries(obj || {}).sort((a, b) => b[1] - a[1]);
  clear(dl).append(...(e.length ? e.flatMap(([k, v]) => [h('dt', { text: label(k) }), h('dd', { text: String(v) })]) : [h('dt', { text: 'none' }), h('dd', { text: '' })]));
}

function suggestion(s) {
  const what = s.kind === 'budget'
    ? 'Budget ' + fmtMoney(s.proposed_budget, 'USD') + ' for ' + s.class + (s.key ? ' (' + s.key + ')' : '')
    : 'Add ' + s.class + ' ' + (s.class === 'publish' ? 'channel' : 'recipient') + ' "' + s.key + '"';
  const q = new URLSearchParams({ agent: s.agent_id, suggest: s.id });
  return h('div', { class: 'row' },
    h('span', {}, h('strong', { text: nm(s.agent_id) }), ': ' + what + ' - approved ' + s.approved + ' times in ' + (s.window_days || 14) + ' days, refused ' + s.rejected),
    safeId(s.agent_id) && safeId(s.id) ? h('a', { class: 'btn', href: 'mandate.html?' + q }, 'Compose new mandate') : '');
}

async function load() {
  const since = Math.floor(Date.now() / 1000) - Number($('#period').value);
  const d = await get('/api/digest?since=' + since);
  const f = digestFigures(d);
  clear($('#stats')).append(...[['W', f.W], ['H', f.H], ['F', f.F], ['A100', f.A100], ['F100', f.F100]].map(([k, v]) => h('div', { class: 'stat' }, h('b', { text: String(v) }), k)));
  const pr = d.pending_by_role || {};
  clear($('#pending')).append(h('dt', { text: 'money approvers' }), h('dd', { text: String(pr.budget || 0) }), h('dt', { text: 'access approvers' }), h('dd', { text: String(pr.access || 0) }),
    ...(pr.escalated != null ? [h('dt', { text: 'escalated to owners' }), h('dd', { text: String(pr.escalated) })] : []));
  const sg = d.suggestions || [];
  clear($('#sugg')).append(...(sg.length ? sg.map(suggestion) : [h('p', { class: 'hint', text: 'No suggestions in this period.' })]));
  $('#rate').textContent = (d.approval_rate_denials || 0) + ' requests refused with APPROVAL_RATE (an agent had too many waiting, or asked too often in an hour). They are not in the ledger.';
  const dr = d.catalog_drift || [];
  clear($('#drift')).append(...(dr.length ? dr.map((a) => h('p', {}, 'The MCP tools of ', h('strong', { text: nm(a) }), ' changed. New arguments are refused until you decide. ', safeId(a) ? h('a', { href: 'catalog.html?agent=' + encodeURIComponent(a) }, 'Review catalog') : '')) : [h('p', { class: 'hint', text: 'No changes.' })]));
  pairs($('#byv'), d.by_verdict); pairs($('#bya'), d.by_agent, nm); pairs($('#byr'), d.by_reason);
}

async function main() {
  if (!(await mountNav(true))) return;
  try { for (const a of await get('/api/agents')) names.set(a.id, a.name); } catch (e) { /* names are cosmetic */ }
  $('#period').addEventListener('change', () => load().catch((e) => notice(msg, 'err', failText(e))));
  await load();
}
main().catch((e) => notice(msg, 'err', failText(e)));
