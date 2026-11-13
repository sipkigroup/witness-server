// 0.2.27: public page of node 2 (independent co-signer). Data: GET /v1/node2, /v1/node2/keys, /v1/node2/alarms (404 = node 2 is off here).
import { get } from './api.js';
import { h, $, clear, mountNav, failText } from './ui.js';
import { OFF_TEXT, latestRows, keyView, alarmRows, stageHidden } from './node2_view.js';

function kvList(dl, rows) {
  clear(dl).append(...rows.flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { class: /^[0-9a-f]{32,}$/.test(String(v)) ? 'mono' : '', text: String(v == null ? '-' : v) })]));
  return dl;
}

async function main() {
  await mountNav(false);
  let st;
  try { st = await get('/v1/node2'); } catch (e) {
    clear($('#latest')).append(h('dt', { text: 'status' }), h('dd', { text: e && e.status === 404 ? OFF_TEXT : failText(e) }));
    clear($('#keys')).append(h('p', { class: 'hint', text: '-' }));
    clear($('#alarms')).append(h('p', { class: 'hint', text: '-' }));
    return;
  }
  kvList($('#latest'), latestRows(st));
  const keys = await get('/v1/node2/keys');
  const box = clear($('#keys'));
  if (!keys.length) box.append(h('p', { class: 'hint', text: 'No key registered yet.' }));
  for (const k of keys.slice().reverse()) {
    const v = keyView(k);
    box.append(h('h3', { text: v.title }), h('p', { class: v.bad ? 'notice warn' : 'notice ok', text: v.verdict }), kvList(h('dl', { class: 'kv' }), v.rows),
      h('details', {}, h('summary', { text: 'Container policy text (its SHA-256 is host_data)' }), h('pre', { class: 'mono', text: v.policy })));
  }
  $('#stage').hidden = stageHidden(keys);
  const al = await get('/v1/node2/alarms');
  const ab = clear($('#alarms'));
  ab.append(al.length ? kvList(h('dl', { class: 'kv' }), alarmRows(al)) : h('p', { text: 'No alarm published.' }));
}
main().catch((e) => { const m = $('#msg'); m.hidden = false; m.textContent = failText(e); });
