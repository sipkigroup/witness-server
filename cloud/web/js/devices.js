// 0.2.2 Devices: the person's passkeys (add = signed by a current one, remove = signed, never the last), and the mandates a removed
// passkey signed (valid; revocable in one ceremony per 20).
import { get, post, put } from './api.js';
import { createCredential, explainError, b64uDec } from './webauthn.js';
import { signPayload, signBatch } from './sign.js';
import { TYP_REVOCATION } from './wb.js';
import { keyStatus, revocationBatches, cloneView, TYP_KEY_EVENT } from './recovery.js';
import { h, $, clear, notice, mountNav, fmtTime, failText } from './ui.js';
import { deviceLabel, deviceActions, levelError } from './levels.js';
import { KEPT_TEXT, nameMatches, deleteError } from './account_delete.js';

const msg = $('#msg');
const S = { me: null, keys: [] };
const spaced = (hex) => hex.slice(0, 16).replace(/(.{4})/g, '$1 ').trim();
const errText = (e) => (e && e.code ? failText(e) : explainError(e));
// a key event is signed by the person's own ACTIVE passkeys (not the team key list): any of them, never the new one
const ownSigners = (exceptKid) => S.keys.filter((k) => k.active && k.kid_hex !== exceptKid).map((k) => ({ kid_hex: k.kid_hex, credential_id_b64: k.credential_id_b64 }));

function render() {
  const body = clear($('#keys'));
  const active = S.keys.filter((k) => k.active).length;
  for (const k of S.keys) {
    const team = (k.team_key_in || []).length ? ' Team key in: ' + k.team_key_in.map((o) => o.name || o.account_id.slice(0, 8)).join(', ') + '.' : '';
    body.append(h('tr', {},
      h('td', { 'data-l': 'Name', text: k.label }),
      h('td', { 'data-l': 'Key', class: 'mono', text: spaced(k.kid_hex) }),
      h('td', { 'data-l': 'Device' }, h('span', { text: deviceLabel(k) }), ...deviceActions(k).map((a) => h('button', { class: a.cancel ? 'btn danger' : 'btn ghost', type: 'button', onclick: () => (a.cancel ? cancelPhone(k) : setDevice(k, a.device)) }, a.label))),
      h('td', { 'data-l': 'Status' }, h('span', { class: 'pill ' + (k.active ? 'allow' : 'deny'), text: k.active ? 'active' : 'removed' }), ' ', h('span', { class: 'hint', text: keyStatus(k) + team }), ...cloneCell(k, active)),
      h('td', { 'data-l': 'Last used', text: fmtTime(k.last_used_at) || '-' }),
      h('td', {}, k.active ? h('button', { class: 'btn ghost', type: 'button', disabled: active <= 1, title: active <= 1 ? 'Your only passkey: add another one first' : '',
        onclick: () => remove(k) }, active <= 1 ? 'Only passkey' : 'Remove') : '')));
  }
}

// 0.2.21: a passkey whose signature counter went back (possible clone): a red mark, what happened (numbers only, textContent), and the
// way out: remove it with ANOTHER passkey (the existing signed removal), or "This was me" (fresh confirmation with another passkey).
// No automatic freeze on the server: a clone must not be able to lock the owner out.
function cloneCell(k, active) {
  const v = cloneView(k, active);
  if (!v) return [];
  const out = [h('div', { class: 'notice err', role: 'alert' }, h('strong', { text: v.head }), h('br', {}), h('span', { text: v.text }))];
  if (v.remove) out.push(h('button', { class: 'btn danger', type: 'button', onclick: () => remove(k, true) }, 'Remove (sign with another passkey)'));
  out.push(h('button', { class: 'btn ghost', type: 'button', onclick: () => dismissClone(k) }, 'This was me'));
  return out;
}

async function dismissClone(k) {
  if (!confirm('Clear the warning on "' + k.label + '"? Only if YOU caused it (for example an old signature was sent again). You confirm with another passkey.')) return;
  notice(msg, 'ok', '');
  try {
    await post('/api/auth/keys/' + k.kid_hex + '/clone-dismiss', {});
    notice(msg, 'ok', 'Warning cleared on "' + k.label + '". If it happens again, it is shown again.');
    await load();
  } catch (e) { notice(msg, 'err', errText(e)); }
}

// 0.2.13: phone or this computer. Marking a key "phone" needs a fresh confirmation with ANOTHER phone passkey (the server asks for it).
async function setDevice(k, device) {
  notice(msg, 'ok', '');
  try {
    await post('/api/auth/keys/' + k.kid_hex + '/device', { device });
    notice(msg, 'ok', '"' + k.label + '" is now marked as ' + (device === 'phone' ? 'your phone.' : 'this computer.'));
    await load();
  } catch (e) { notice(msg, 'err', (levelError(e) && e.code === 'DEVICE_LEVEL' ? 'Confirm with your phone\'s passkey (not this one) to mark a key as your phone. ' : '') + errText(e)); }
}

// 0.2.15: someone used a recovery code and declared a new phone; it waits before it counts. Cancel with your phone (or, with no phone,
// any other passkey that is not waiting itself): the claim is gone for good, its sessions end, every unused recovery code stops.
// 0.2.17 (R9-03): the passkey itself and every passkey it confirmed stop working too.
async function cancelPhone(k) {
  notice(msg, 'ok', '');
  try {
    const r = await post('/api/auth/keys/' + k.kid_hex + '/cancel-phone', {});
    const n = (r.keys_removed || []).length;   // 0.2.17: the cancelled passkey and the ones it confirmed are stopped
    notice(msg, 'ok', '"' + k.label + '" no longer works' + (n ? ', nor the ' + n + ' passkey(s) it confirmed' : '') + '. ' + r.recovery_codes_stopped + ' unused recovery code(s) stopped working: make new ones.');
    await load();
  } catch (e) { notice(msg, 'err', (e && e.code === 'DEVICE_LEVEL' ? 'Cancel with your phone\'s passkey (or, without a phone, another passkey of yours that is not waiting). ' : '') + errText(e)); }
}

async function load() {
  const r = await get('/api/auth/keys');
  S.keys = r.keys;
  const c = r.recovery_codes;
  $('#codestate').textContent = c.total ? c.remaining + ' of ' + c.total + ' recovery codes unused (made ' + fmtTime(c.created_at) + ').' : 'No recovery codes yet. Make them now: they are your way back if you lose every passkey.';
  render();
  await renderRevocable();
}

async function renderRevocable() {
  const box = clear($('#revlist'));
  let any = false;
  for (const k of S.keys.filter((x) => !x.active)) {
    let r;
    try { r = await get('/api/mandates/by-key/' + k.kid_hex); } catch (e) { continue; }
    if (!r.mandates.length) continue;
    any = true;
    const btn = h('button', { class: 'btn danger', type: 'button' }, 'Revoke all ' + r.mandates.length + ' (' + Math.ceil(r.mandates.length / r.max_per_batch) + ' signature' + (r.mandates.length > r.max_per_batch ? 's' : '') + ')');
    btn.addEventListener('click', () => revokeAll(r.mandates, btn));
    box.append(h('div', { class: 'row' }, h('span', { text: k.label + ' (' + spaced(k.kid_hex) + '): ' + r.mandates.map((m) => 'agent ' + m.agent_id).join(', ') }), btn));
  }
  $('#revcard').hidden = !any;
}

async function revokeAll(mandates, btn) {
  if (!confirm('Revoke ' + mandates.length + ' mandate(s)? Their agents are refused at once, until you sign new mandates.')) return;
  btn.disabled = true; notice(msg, 'ok', '');
  try {
    let n = 0;
    for (const b of await revocationBatches(mandates)) {
      const envelope_b64 = await signBatch(b.items, S.me, TYP_REVOCATION);
      n += (await post('/api/mandates/revoke-batch', { mandate_ids: b.ids, envelope_b64 })).revoked.length;
    }
    notice(msg, 'ok', n + ' mandate(s) revoked.');
    await load();
  } catch (e) { notice(msg, 'err', errText(e)); btn.disabled = false; }
}

async function remove(k, notItself = false) {
  if (!confirm('Remove "' + k.label + '"? It stops signing in and signing at once; sessions it opened end. What it signed before stays valid.')) return;
  notice(msg, 'ok', '');
  try {
    const b = await post('/api/auth/keys/' + k.kid_hex + '/remove/begin', {});
    if (b.typ !== TYP_KEY_EVENT) throw new Error('unexpected request type');
    const envelope_b64 = await signPayload(TYP_KEY_EVENT, b64uDec(b.payload_b64), S.me, ownSigners(notItself ? k.kid_hex : null));   // 0.2.21: a suspected key is removed by another one
    const r = await post('/api/auth/keys/' + k.kid_hex + '/remove', { flow_id: b.flow_id, envelope_b64 });
    notice(msg, 'ok', 'Removed.' + (r.mandates_signed_by_it ? ' ' + r.mandates_signed_by_it + ' active mandate(s) it signed stay valid; you can revoke them below.' : ''));
    if (k.this_session) { location.href = 'login.html'; return; }
    await load();
  } catch (e) { notice(msg, 'err', errText(e)); }
}

// Two separate prompts on purpose: (1) the NEW device creates its passkey, (2) a device you already use confirms it. The new key is
// not active until (2); if (2) never happens, nothing was added.
async function add() {
  const btn = $('#add'); btn.disabled = true; notice(msg, 'ok', '');
  const step = $('#addstep');
  try {
    const b = await post('/api/auth/keys/add/begin', { label: $('#label').value, device: $('#device').value });
    step.hidden = false; step.textContent = 'Step 1 of 2: create the new passkey on the device that should hold it.';
    const credential = await createCredential(b.options);
    const f = await post('/api/auth/keys/add/finish', { flow_id: b.flow_id, credential });
    if (f.typ !== TYP_KEY_EVENT) throw new Error('unexpected request type');
    S.pending = f;
    step.textContent = 'Step 2 of 2: the new passkey ' + f.short + ' is not active yet. Confirm it with a passkey you already use (not the new one): '
      + 'that passkey signs exactly this new key. Within 5 minutes.';
    $('#confirm').hidden = false;
  } catch (e) { step.hidden = true; notice(msg, 'err', errText(e)); btn.disabled = false; }
}

async function confirmAdd() {
  const f = S.pending;
  if (!f) return;
  const btn = $('#confirm'); btn.disabled = true; notice(msg, 'ok', '');
  try {
    const envelope_b64 = await signPayload(TYP_KEY_EVENT, b64uDec(f.payload_b64), S.me, ownSigners(f.kid_hex));
    await post('/api/auth/keys/add/confirm', { confirm_id: f.confirm_id, envelope_b64 });
    S.pending = null;
    $('#addstep').hidden = true; btn.hidden = true; $('#add').disabled = false;
    notice(msg, 'ok', 'Passkey ' + f.short + ' added. Your other devices were notified.');
    $('#label').value = '';
    await load();
  } catch (e) {
    notice(msg, 'err', errText(e) + (e && e.code === 'FLOW_UNKNOWN' ? ' Start again with "Add passkey".' : ''));
    if (e && e.code) { S.pending = null; btn.hidden = true; $('#addstep').hidden = true; $('#add').disabled = false; }
  }
  btn.disabled = false;
}

function wireDelete() {
  const name = (S.me.user && S.me.user.display_name) || '';
  $('#delwho').textContent = name ? '"' + name + '"' : '';
  $('#delkept').replaceChildren(...KEPT_TEXT.map((t) => h('li', { text: t })));
  const upd = () => { $('#delgo').disabled = !nameMatches($('#delname').value, name); };
  $('#delname').addEventListener('input', upd); upd();
  $('#delgo').addEventListener('click', async () => {
    $('#delgo').disabled = true;
    try { await post('/api/account/delete', { confirm_name: $('#delname').value }); location.href = 'index.html'; }
    catch (e) { notice($('#delmsg'), 'err', deleteError(e) || errText(e)); upd(); }
  });
}

async function main() {
  S.me = await mountNav(true);
  if (!S.me) return;
  wireDelete();
  $('#add').addEventListener('click', add);
  try { $('#phoneall').checked = (await get('/api/confirm-rules')).phone_for === 'all'; } catch (e) { $('#rulecard').hidden = true; }
  $('#phoneall').addEventListener('change', async () => {
    const want = $('#phoneall').checked ? 'all' : 'risky';
    try { await put('/api/confirm-rules', { phone_for: want }); notice(msg, 'ok', want === 'all' ? 'Every approval now needs your phone.' : 'A passkey of this computer may again confirm ordinary project commands.'); }
    catch (e) { $('#phoneall').checked = !$('#phoneall').checked; notice(msg, 'err', levelError(e) || errText(e)); }
  });
  $('#confirm').addEventListener('click', confirmAdd);
  await load();
}
main().catch((e) => notice(msg, 'err', failText(e)));
