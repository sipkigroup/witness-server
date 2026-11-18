// 0.2.10 (PROPOSAL-07): the owner's project permissions (allowances): list and one-click revoke.
import { get, post } from './api.js';
import { STATUS_TEXT, TRUST_TEXT, untilText } from './allowance.js';
import { $, h, clear, notice, mountNav, fmtTime, failText } from './ui.js';
import { inspectFields } from './honest.js';
import { STATUS_TEXT as REPEAT_STATUS, untilTime } from './repeat.js';

const msg = $('#msg');

export function rowCells(x) {
  const shown = inspectFields([['Commands', x.commands.join(', ')], ['Project', x.project + (x.branch ? ' (branch ' + x.branch + ')' : '')], ['Agent', x.agent || x.agent_id]], []).rows.map((r) => r[1]);
  return [shown[0], shown[1], shown[2], untilText(x.exp), x.uses ? x.uses + ' times, last ' + fmtTime(x.last_used) : 'not yet', STATUS_TEXT[x.status] || x.status];
}

// r0327: the text of trust of the version this rule signed (the list shows THAT text, not today's); an older rule signed the page only
export const OLD_TEXT_NOTE = 'Signed before the text of trust became part of the signature: the page was signed, the text shown next to the button was not.';
export function trustNote(x) {
  if (x && typeof x.text === 'string' && x.text && typeof x.text_v === 'string') return { signed: true, summary: 'Text you signed with this rule (version ' + x.text_v + ')', text: x.text };
  return { signed: false, summary: 'Text you signed with this rule: none', text: OLD_TEXT_NOTE };
}

async function load() {
  const r = await get('/api/allowances');
  const tb = clear($('#rows'));
  $('#empty').hidden = r.items.length > 0;
  for (const x of r.items) {
    const tr = h('tr', {}, ...rowCells(x).map((c, i) => h('td', { 'data-label': ['Commands', 'Project', 'Agent', 'Until', 'Used', 'Status'][i], text: c })));
    const td = h('td', {});
    if (x.status === 'active') {
      const b = h('button', { class: 'btn danger', type: 'button' }, 'Revoke');
      b.addEventListener('click', async () => {
        b.disabled = true;
        try { await post('/api/allowances/' + encodeURIComponent(x.id) + '/revoke'); notice(msg, 'ok', 'Revoked: ' + x.commands.join(', ') + ' is asked again in ' + x.project + '.'); await load(); }
        catch (e) { notice(msg, 'err', failText(e)); b.disabled = false; }
      });
      td.append(b);
    }
    tr.append(td);
    tb.append(tr);
    const tn = trustNote(x);
    tb.append(h('tr', { class: 'trustrow' }, h('td', { colspan: '7' }, h('details', {}, h('summary', { text: tn.summary }), h('p', { class: tn.signed ? 'hint' : 'hint warn', text: tn.text })))));
  }
}

// 0.2.29: approvals for later runs (server/app/repeat.py)
export function laterCells(x) {
  const call = x.tool + (x.recipient ? ' -> ' + x.recipient : '') + (x.args_preview ? ' (' + x.args_preview + ')' : '');
  const shown = inspectFields([['Call', call], ['Agent', x.agent || x.agent_id]], []).rows.map((r) => r[1]);
  return [shown[0], shown[1], untilTime(x.exp), x.used + ' of ' + x.uses + (x.last_used ? ', last ' + fmtTime(x.last_used) : ''), (REPEAT_STATUS[x.status] || x.status) + (x.ended_files && x.ended_files.length ? ' (' + x.ended_files.join(', ') + ')' : '')];
}

async function loadLater() {
  const r = await get('/api/repeat-approvals');
  const tb = clear($('#lrows'));
  $('#lempty').hidden = r.items.length > 0;
  for (const x of r.items) {
    const tr = h('tr', {}, ...laterCells(x).map((c, i) => h('td', { 'data-label': ['Call', 'Agent', 'Until', 'Used', 'Status'][i], text: c })));
    const td = h('td', {});
    if (x.status === 'active') {
      const b = h('button', { class: 'btn danger', type: 'button' }, 'Revoke');
      b.addEventListener('click', async () => {
        b.disabled = true;
        try { await post('/api/repeat-approvals/' + encodeURIComponent(x.id) + '/revoke'); notice(msg, 'ok', 'Revoked: the next such call of ' + (x.agent || x.agent_id) + ' is asked again.'); await loadLater(); }
        catch (e) { notice(msg, 'err', failText(e)); b.disabled = false; }
      });
      td.append(b);
    }
    tr.append(td);
    tb.append(tr);
  }
}

async function main() {
  const me = await mountNav(true);
  if (!me) return;
  $('#trust').textContent = TRUST_TEXT;
  await load();
  await loadLater();
}
if (typeof document !== 'undefined' && document.querySelector('#rows')) main().catch((e) => notice(msg, 'err', failText(e)));
