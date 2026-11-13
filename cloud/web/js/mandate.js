import { get, post } from './api.js';
import { encode, bytesToHex } from './cde.js';
import { challenge, sha256, TYP_MANDATE } from './profile.js';
import { signPayload } from './sign.js';
import { explainError, supported, isClone, cloneNote } from './webauthn.js';
import { describeMandate } from './describe.js';
import { inspectFields } from './honest.js';
import { formWarnings, L2_CLASSES, inputsFromMandate, applySuggestion, commandForm, recommendedCommand, READONLY_COMMANDS, sampleFor, httpForm, recommendedHttp } from './mandate_form.js';
import { importForm, pendingImport } from './mandate_import.js';
import { revokeMandate } from './revoke.js';
import { needsText } from './policy.js';
import { h, $, clear, notice, mountNav, dollarsToCents, csv, lines, kv, safeId, failText } from './ui.js';

const msg = $('#msg');
const qs = new URLSearchParams(location.search);
let agentId = qs.get('agent');
const suggestId = qs.get('suggest');
let me = null, mandate = null, payload = null, ack = false, reqId = null, needs = null;
const L2_DEFAULT = ['card_number', 'iban', 'ssn', 'phone'];
const raw = () => ({ pu_on: $('#pu_on').checked, pu_budget: $('#pu_budget').value, pu_max: $('#pu_max').value, pu_min: $('#pu_min').value, pu_payees: $('#pu_payees').value, ms_on: $('#ms_on').checked, ms_dom: $('#ms_dom').value, ms_to: $('#ms_to').value });

function formFromInputs() {
  const form = { currency: 'USD', valid_days: Number($('#days').value) };
  if (!Number.isInteger(form.valid_days) || form.valid_days < 1 || form.valid_days > 365) throw new Error('Valid days must be a whole number from 1 to 365.');
  if ($('#pu_on').checked && !$('#pu_budget').value.trim() && !$('#pu_max').value.trim()) form.purchase = { enabled: false };
  else if ($('#pu_on').checked) {
    const b = dollarsToCents($('#pu_budget').value), m = dollarsToCents($('#pu_max').value);
    if (b === null || m === null) throw new Error('Purchase amounts: dollars with up to 2 decimals, e.g. 200 or 12.50.');
    if (m > b) throw new Error('Max per purchase cannot exceed the budget.');
    form.purchase = { enabled: true, budget: b, max_per_action: m };
    if ($('#pu_min').value.trim()) {                     // 0.2.83: lower bound of one purchase, the only payees
      const mn = dollarsToCents($('#pu_min').value);
      if (mn === null) throw new Error('Min per purchase: dollars with up to 2 decimals, e.g. 5 or 0.50.');
      if (mn > m) throw new Error('Min per purchase cannot exceed the max per purchase.');
      if (mn > 0) form.purchase.min_per_action = mn;
    }
    const pay = lines($('#pu_payees').value);        // 0.2.84 (R5-P3): one payee id per line (an id may hold a comma)
    if (pay.length) form.purchase.payees = pay;
  } else form.purchase = { enabled: false };
  const on = $('#ms_on').checked;
  form.message = { domains: on ? csv($('#ms_dom').value).map((s) => s.toLowerCase()) : [], to: on ? csv($('#ms_to').value).map((s) => s.toLowerCase()) : [] };
  form.forbidden_data = [...new Set([...[...document.querySelectorAll('#l2 input:checked')].map((i) => i.value), ...csv($('#fd').value)])];
  form.delete = $('#del_mode').value === 'targets' ? { targets: csv($('#del_t').value), allow_irreversible: $('#del_irr').checked } : null;
  form.publish = $('#pub_mode').value === 'channels' ? { channels: csv($('#pub_c').value) } : null;
  form.command = commandForm($('#cmd_mode').value, $('#cmd_allow').value, $('#cmd_unlisted').value, $('#cmd_sandboxed').value);
  form.http = httpForm($('#http_mode').value, $('#http_allow').value, $('#http_unlisted').value);   // PROPOSAL-08-http
  return form;
}

async function main() {
  me = await mountNav(true);
  if (!me) return;
  if (!supported()) notice(msg, 'err', 'This browser does not support passkeys (WebAuthn).');
  const agents = await get('/api/agents');
  // 04.11 (L3): no ?agent= : one agent opens at once, several are offered as a list
  if (!agentId && agents.length === 1 && safeId(agents[0].id)) { agentId = agents[0].id; try { history.replaceState(null, '', 'mandate.html?agent=' + encodeURIComponent(agentId) + location.search.replace(/^\?/, '&')); } catch (e) { /* ignore */ } }
  const a = agents.find((x) => x.id === agentId);
  if (!agentId && agents.length > 1) {
    $('#form').hidden = true; $('#imp').hidden = true; $('#pick').hidden = false;
    clear($('#picklist')).append(...agents.filter((x) => safeId(x.id)).map((x) => h('p', {}, h('a', { class: 'btn', href: 'mandate.html?agent=' + encodeURIComponent(x.id) }, x.name), ' ', h('span', { class: 'hint mono', text: x.id }))));
    return;
  }
  if (!a) { notice(msg, 'err', 'Unknown agent. Go back to the dashboard and choose one.'); $('#form').hidden = true; return; }
  $('#agentname').textContent = a.name;
  $('#l2').append(...L2_CLASSES.map(([k, t]) => h('label', {}, h('input', { type: 'checkbox', value: k, checked: L2_DEFAULT.includes(k) }), k + ' - ' + t)));
  await prefill(a);

  $('#del_mode').addEventListener('change', () => { $('#del_box').hidden = $('#del_mode').value !== 'targets'; });
  $('#pub_mode').addEventListener('change', () => { $('#pub_box').hidden = $('#pub_mode').value !== 'channels'; });
  $('#cmd_mode').addEventListener('change', () => { $('#cmd_box').hidden = $('#cmd_mode').value !== 'list'; });
  $('#http_mode').addEventListener('change', () => { $('#http_box').hidden = $('#http_mode').value !== 'list'; });

  // 0.2.7: Import from JSON (what `deus-witness-hook --print-form` prints)
  let imported = null, appliedText = null, impTimer = null;
  // 04.11 (L3): the pasted JSON is checked and applied at once (a pause after typing); an error stays on screen and the form is not signed over it
  const checkImport = (apply) => {
    const r = importForm($('#imp_text').value, a.id, Math.floor(Date.now() / 1000));
    imported = r.values; $('#imp_apply').disabled = !r.values; $('#imp_hint').hidden = true;
    $('#imp_err').hidden = !r.errors.length; $('#imp_prev').hidden = !r.values;
    clear($('#imp_errl')).append(...r.errors.map((t) => h('li', { text: t })));
    clear($('#imp_rows')).append(kv(inspectFields(r.rows).rows));
    if (apply && r.values) applyImport();
  };
  const applyImport = () => {
    if (!imported) return;
    setInputs(imported); appliedText = $('#imp_text').value; $('#impwarn').hidden = true; ack = false; $('#warnbox').hidden = true;
    notice($('#suggnote'), 'ok', 'Imported from JSON. Check every section below, then press "Review and sign": nothing is signed yet.');
  };
  $('#imp_text').addEventListener('input', () => {
    imported = null; $('#imp_apply').disabled = true; $('#imp_prev').hidden = true; $('#imp_err').hidden = true;
    clearTimeout(impTimer);
    if (!$('#imp_text').value.trim()) { $('#imp_hint').hidden = true; return; }
    impTimer = setTimeout(() => checkImport(true), 400);
  });
  $('#imp_check').addEventListener('click', () => { clearTimeout(impTimer); checkImport(false); });
  $('#imp_apply').addEventListener('click', () => {
    applyImport(); if (!appliedText) return;
    $('#impd').open = false; $('#form').scrollIntoView();
  });

  const fieldsChanged = () => { ack = false; $('#warnbox').hidden = true; };
  for (const id of ['pu_on', 'pu_budget', 'pu_max', 'pu_min', 'pu_payees', 'ms_on', 'ms_dom', 'ms_to']) $('#' + id).addEventListener('input', fieldsChanged);
  $('#warnfix').addEventListener('click', () => { const w = formWarnings(raw())[0]; $('#warnbox').hidden = true; if (w) $('#' + w.field).focus(); });
  $('#warngo').addEventListener('click', () => { ack = true; $('#form').requestSubmit(); });

  let impAck = false;
  $('#impwarn_back').addEventListener('click', () => { $('#impwarn').hidden = true; $('#impd').open = true; $('#imp_text').focus(); $('#impd').scrollIntoView(); });
  $('#impwarn_go').addEventListener('click', () => { impAck = true; $('#impwarn').hidden = true; $('#form').requestSubmit(); });
  $('#form').addEventListener('submit', async (ev) => {
    ev.preventDefault(); notice(msg, 'ok', '');
    // 0.2.41: JSON typed in Import but not applied: the form shows the preset defaults; do not sign them silently
    if (pendingImport($('#imp_text').value, appliedText) && !impAck) {
      clearTimeout(impTimer); checkImport(true);
      if (!pendingImport($('#imp_text').value, appliedText)) { notice($('#suggnote'), 'ok', 'The JSON you pasted was applied just now. Check the form, then press "Review and sign" again: nothing is signed yet.'); $('#form').scrollIntoView(); return; }
      $('#impwarn').hidden = false; $('#impwarn').scrollIntoView(); return;
    }
    impAck = false;
    const W = formWarnings(raw());
    if (W.length && !ack) {
      clear($('#warnlist')).append(...W.map((w) => h('li', { text: w.text })));
      $('#warnbox').hidden = false; $('#warnbox').scrollIntoView(); return;
    }
    $('#warnbox').hidden = true;
    try {
      const r = await post('/api/mandates/draft', { agent_id: agentId, form: formFromInputs() });
      if (r.typ !== TYP_MANDATE) throw new Error('Unexpected object type from server: ' + r.typ);
      mandate = r.mandate; // what is shown is what is encoded
      // 0.2.4 (draft-deus-aar-05 8.6): the signing page computes the tool map hash from the document it shows; a different value from the server is refused
      if (!r.gateway) throw new Error('The server did not send the tool map document: update the server or sign nothing.');
      const gw = bytesToHex(await sha256(encode(r.gateway)));
      if (mandate.toolmap_sha256 !== gw) throw new Error('The tool map hash in the mandate is not the hash of the tool map shown. Nothing was signed.');
      payload = encode(mandate);
      reqId = r.quorum && safeId(r.req_id) ? r.req_id : null;
      needs = r.needs || null;
      $('#signbtn').textContent = reqId ? 'Continue to team signing (' + needsText((needs || []).map((n) => [n.role, n.k])) + ')' : 'Sign with passkey';
      const dl = h('dl', { class: 'kv' });
      // R5-01/02: every value passes through inspectFields (hidden / bidi characters become <U+XXXX>, look-alike text is flagged)
      const mrows = describeMandate(mandate), ins = inspectFields(mrows);
      mrows.forEach(([k], i) => dl.append(h('dt', { text: k }), h('dd', { text: ins.rows[i][1] })));
      clear($('#human')).append(dl);
      if (ins.warnings.length) $('#human').prepend(h('div', { class: 'notice warn', role: 'alert' }, h('strong', { text: 'CHECK before you sign: this mandate contains text that can be disguised.' }), h('ul', {}, ...ins.warnings.slice(0, 12).map((w) => h('li', { text: w })))));
      const gwd = h('details', {}, h('summary', { text: 'Tool map, protected data and advisor mode covered by the signature' }), h('pre', { text: JSON.stringify(r.gateway, null, 1) }));
      $('#human').append(gwd);
      $('#hexp').textContent = bytesToHex(payload);
      $('#hexc').textContent = bytesToHex(await challenge(TYP_MANDATE, payload));
      $('#form').hidden = true; $('#sign').hidden = false; $('#sign').scrollIntoView();
    } catch (e) { notice(msg, 'err', e.detail ? e.code + ': ' + e.detail : e.message); }
  });
  $('#back').addEventListener('click', () => { $('#sign').hidden = true; $('#form').hidden = false; });
  $('#signbtn').addEventListener('click', async () => {
    const btn = $('#signbtn'); btn.disabled = true; notice(msg, 'ok', '');
    try {
      if (reqId) { location.href = 'sign.html?req=' + encodeURIComponent(reqId); return; } // team: collected as a quorum
      const envelope_b64 = await signPayload(TYP_MANDATE, payload, me);
      const r = await post('/api/mandates', { mandate, envelope_b64 });
      notice($('#suggnote'), 'ok', '');   // 0.2.41: "Imported from JSON... nothing is signed yet" is no longer true after the signature
      $('#sign').hidden = true; $('#done').hidden = false;
      await showActive().catch(() => { $('#active').hidden = true; });   // 04.11 (L3): the "Active mandate" card showed the old one until a reload
      $('#donehead').textContent = 'Mandate active';
      $('#doneinfo').textContent = 'Mandate ' + r.mandate_id + ' is ' + r.status + ' (ledger entry ' + r.ledger_seq + '). A previous mandate of this agent, if any, is superseded.';
    } catch (e) { notice(msg, 'err', isClone(e) ? explainError(e) : e.code && e.code.startsWith('WA_') || e.code === 'KEY_MISMATCH' || e.code === 'MANDATE_SIG' ? 'The server rejected the signature (' + e.code + '). Nothing was changed.' : explainError(e)); cloneNote(msg, e); btn.disabled = false; }
  });
}
// form inputs <- raw values (same names as inputsFromMandate)
function setInputs(v) {
  $('#days').value = v.days; $('#pu_on').checked = v.pu_on; $('#pu_budget').value = v.pu_budget; $('#pu_max').value = v.pu_max;
  $('#pu_min').value = v.pu_min || ''; $('#pu_payees').value = v.pu_payees || '';
  $('#ms_on').checked = v.ms_on; $('#ms_dom').value = v.ms_dom; $('#ms_to').value = v.ms_to; $('#fd').value = v.fd;
  document.querySelectorAll('#l2 input').forEach((i) => { i.checked = v.l2.includes(i.value); });
  $('#del_mode').value = v.del_mode; $('#del_t').value = v.del_t; $('#del_irr').checked = v.del_irr; $('#del_box').hidden = v.del_mode !== 'targets';
  $('#pub_mode').value = v.pub_mode; $('#pub_c').value = v.pub_c; $('#pub_box').hidden = v.pub_mode !== 'channels';
  $('#cmd_mode').value = v.cmd_mode || 'none'; $('#cmd_allow').value = v.cmd_allow || READONLY_COMMANDS.join(', '); $('#cmd_unlisted').value = v.cmd_unlisted || 'ask'; $('#cmd_sandboxed').value = v.cmd_sandboxed === 'allow' ? 'allow' : 'ask'; $('#cmd_box').hidden = $('#cmd_mode').value !== 'list';
  $('#http_mode').value = v.http_mode || 'none'; $('#http_allow').value = v.http_allow || ''; $('#http_unlisted').value = v.http_unlisted || 'ask'; $('#http_box').hidden = $('#http_mode').value !== 'list';
}

function showActiveRow(act) {
  clear($('#activekv')).append(...kv(describeMandate(act.mandate)).childNodes);
  $('#active').hidden = false; $('#revoke').disabled = false;
  $('#revoke').onclick = async () => {
    if (!confirm('Revoke this mandate? The agent is refused until a new mandate is signed.')) return;
    $('#revoke').disabled = true;
    try { await revokeMandate(act, me); $('#active').hidden = true; notice(msg, 'ok', 'Mandate revoked. Sign a new one below when you are ready.'); }
    catch (e) { notice(msg, 'err', e.code ? failText(e) : explainError(e)); $('#revoke').disabled = false; }
  };
}
// the card of the active mandate, read again from the server (after a signature)
async function showActive() {
  const a = (await get('/api/agents')).find((x) => x.id === agentId);
  const rows = await get('/api/mandates');
  const act = a && rows.find((x) => x.id === a.active_mandate_id && x.status === 'active');
  if (act) showActiveRow(act); else $('#active').hidden = true;
}
// the active mandate prefills the form (a new mandate replaces it); a suggestion of the digest is applied on top
async function prefill(a) {
  let rows = [];
  try { rows = await get('/api/mandates'); } catch (e) { rows = []; }
  const act = rows.find((x) => x.id === a.active_mandate_id && x.status === 'active');
  if (act) showActiveRow(act);
  let v = act ? inputsFromMandate(act.mandate) : null;
  if (suggestId && safeId(suggestId)) {
    try {
      const s = ((await get('/api/suggestions')).suggestions || []).find((x) => x.id === suggestId && x.agent_id === a.id);
      if (s) { const r = applySuggestion(v || inputsFromMandate(null), s); v = r.values; notice($('#suggnote'), 'ok', 'Prefilled from the digest suggestion: ' + r.note + ' Check every section, then sign: nothing is applied until the signers sign.'); }
      else notice($('#suggnote'), 'warn', 'That suggestion is no longer offered.');
    } catch (e) { notice($('#suggnote'), 'warn', 'Suggestions are not available: ' + failText(e)); }
  }
  if (!v && !act && qs.get('sample') === '1') {         // 0.2.28: right after "Create agent": the quickstart example, to review and sign
    v = sampleFor(a.toolmap);
    if (v) notice($('#suggnote'), 'ok', 'Prefilled with the example mandate of the quickstart. Check every section, then press "Review and sign": nothing is signed yet.');
  }
  if (v) { if (!act) v.l2 = v.l2.length ? v.l2 : L2_DEFAULT; setInputs(v); }
  const rc = (act || suggestId) ? null : recommendedCommand(a.toolmap);    // 0.2.9: a Claude Code agent's first mandate: the read-only list, other commands asked
  if (rc) { $('#cmd_mode').value = rc.cmd_mode; $('#cmd_allow').value = rc.cmd_allow; $('#cmd_unlisted').value = rc.cmd_unlisted; $('#cmd_sandboxed').value = rc.cmd_sandboxed; $('#cmd_box').hidden = false; }
  const rh = (act || suggestId) ? null : recommendedHttp(a.toolmap);     // 0.2.43: an OpenShell agent's first mandate: the HTTP list open, empty (everything asked)
  if (rh) { $('#http_mode').value = rh.http_mode; $('#http_allow').value = rh.http_allow; $('#http_unlisted').value = rh.http_unlisted; $('#http_box').hidden = false; }
}
main().catch((e) => notice(msg, 'err', e.message));
