import { get, post, put } from './api.js';
import { applyDecisions, classProblems, amountProblems, DECISIONS, CLASSES, dkey } from './catalog_calc.js';
import { coverageView } from './coverage.js';
import { h, $, clear, notice, mountNav, safeId, failText } from './ui.js';

const msg = $('#msg');
const agentId = new URLSearchParams(location.search).get('agent');
const C = { draft: null, unknown: [], decisions: new Map(), classes: {}, tools: [] };

function recompute() {
  const r = applyDecisions(C.draft, C.unknown, C.decisions, C.classes);
  const cp = classProblems(r.toolmap), ap = amountProblems(r.toolmap);
  const n = r.unresolved.length;
  $('#apply').disabled = n > 0 || cp.length > 0 || ap.length > 0;
  $('#left').textContent = n ? n + ' UNKNOWN argument(s) still need a decision; "Apply" stays off until none is left.'
    : cp.length ? 'Pick a class for: ' + cp.join(', ') + ' (it has a recipient but is marked pass).'
      : ap.length ? 'A money tool needs an amount argument: ' + ap.join(', ') + '.' : 'Every argument is decided.';
  $('#tmjson').textContent = JSON.stringify(r.toolmap, null, 2);
  return r;
}

function render() {
  const box = clear($('#tools'));
  const tools = Object.keys(C.draft.tools).sort();
  for (const name of tools) {
    const t = C.draft.tools[name];
    const desc = (C.tools.find((x) => x.name === name) || {}).description || '';
    const cls = h('select', { class: 'inline', 'aria-label': 'Class of ' + name }, ...CLASSES.map((c) => h('option', { value: c, selected: c === t.class }, c)));
    cls.addEventListener('change', () => { C.classes[name] = cls.value; recompute(); });
    const mapped = [t.recipient != null ? 'recipient: ' + [].concat(t.recipient).join(', ') : '', t.text ? 'text: ' + t.text.join(', ') : '', t.amount ? 'amount: ' + t.amount : ''].filter(Boolean).join('; ');
    const card = h('div', { class: 'choice' }, h('div', { class: 'row' }, h('strong', { class: 'mono', text: name }), cls), desc ? h('p', { class: 'hint', text: desc.slice(0, 300) }) : '', h('p', { class: 'hint', text: mapped ? 'Mapped: ' + mapped : 'Nothing mapped automatically.' }));
    for (const u of C.unknown.filter((x) => x.tool === name)) {
      const sel = h('select', { class: 'inline', 'aria-label': 'Decision for ' + name + '.' + u.arg }, h('option', { value: '' }, 'UNKNOWN - decide'), ...Object.entries(DECISIONS).map(([k, v]) => h('option', { value: k }, v)));
      sel.addEventListener('change', () => { if (sel.value) C.decisions.set(dkey(u.tool, u.arg), sel.value); else C.decisions.delete(dkey(u.tool, u.arg)); recompute(); });
      card.append(h('div', { class: 'row' }, h('span', { class: 'pill defer', text: 'UNKNOWN' }), h('span', { class: 'mono', text: u.arg }), sel));
    }
    box.append(card);
  }
  if (!tools.length) box.append(h('p', { class: 'hint', text: 'The catalog is empty.' }));
  recompute();
}

async function main() {
  if (!(await mountNav(true))) return;
  if (!safeId(agentId)) { notice(msg, 'err', 'Unknown agent. Go back to the dashboard and choose one.'); return; }
  const agents = await get('/api/agents');
  const a = agents.find((x) => x.id === agentId);
  $('#agentname').textContent = a ? a.name : agentId;
  const v = await get('/api/catalog/' + encodeURIComponent(agentId));
  clear($('#cov')).append(h('h2', { text: 'Coverage' }), ...coverageView(v.coverage));
  C.tools = v.tools || [];
  if (!v.catalog_sha256) { notice(msg, 'warn', 'No catalog yet: the proxy sends it when it starts (deus-witness-mcp 0.2).'); return; }
  $('#drift').hidden = !v.drift;
  $('#drift').textContent = 'The tools changed since the previous catalog. New arguments are refused until you decide them here.';
  const d = await post('/api/catalog/' + encodeURIComponent(agentId) + '/draft', {});
  C.draft = d.toolmap_draft; C.unknown = d.unknown || [];
  render();
  $('#apply').addEventListener('click', async () => {
    const r = recompute();
    if (r.unresolved.length) return;
    $('#apply').disabled = true;
    try {
      await put('/api/agents/' + encodeURIComponent(agentId) + '/toolmap', { toolmap: r.toolmap });
      notice($('#applymsg'), 'warn', 'Tool map saved. Calls of this agent are now refused (TOOLMAP_CHANGED) until a new mandate is signed.');
      $('#newm').href = 'mandate.html?agent=' + encodeURIComponent(agentId); $('#newm').hidden = false;
    } catch (e) { notice($('#applymsg'), 'err', failText(e)); $('#apply').disabled = false; }
  });
}
main().catch((e) => notice(msg, 'err', failText(e)));
