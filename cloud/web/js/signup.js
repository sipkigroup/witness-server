import { post } from './api.js';
import { createCredential, explainError, supported } from './webauthn.js';
import { mountNav, notice, copyButton, failText, $ } from './ui.js';
import { codesFile } from './recovery.js';

const msg = $('#msg');
let who = 'user', shown = null;
mountNav(false);
if (!supported()) notice(msg, 'err', 'This browser does not support passkeys (WebAuthn).');

$('#f').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const btn = $('#go'); btn.disabled = true; notice(msg, 'ok', '');
  try {
    const name = $('#name').value.trim() || 'user';
    const b = await post('/api/auth/register/begin', { display_name: name });
    const credential = await createCredential(b.options);
    const r = await post('/api/auth/register/finish', { flow_id: b.flow_id, credential });
    $('#short').textContent = r.keycard.short;
    $('#kid').textContent = r.keycard.kid_hex;
    const next = new URLSearchParams(location.search).get('next');
    if (next && /^[a-z]+\.html(\?[\w=&%.-]*)?$/.test(next)) { $('#cont').href = next; $('#cont').textContent = 'Continue'; }
    $('#f').hidden = true; $('#card').hidden = false; $('#codesbox').hidden = false;
    who = name;
  } catch (e) { notice(msg, 'err', explainError(e)); btn.disabled = false; msg.scrollIntoView({ block: 'nearest' }); }   // 0.2.22: the message sits below the button, which no longer moves
});

// 0.2.109: recovery codes right after the account exists (the codes page of devices.html stays); "Later" leaves a reminder on the dashboard.
$('#copy').append(copyButton(() => shown || ''));
$('#savecodes').addEventListener('click', async () => {
  const btn = $('#savecodes'); btn.disabled = true; notice($('#codesmsg'), 'ok', '');
  try {
    const r = await post('/api/auth/recovery-codes', {});
    shown = codesFile(r.codes, who, new Date(r.created_at * 1000).toISOString().slice(0, 10));
    $('#codes').textContent = r.codes.join('\n');
    $('#codesshown').hidden = false; btn.hidden = true; $('#later').hidden = true;
    try { localStorage.removeItem('dw_codes_later'); } catch (e) { /* no storage: nothing to forget */ }
  } catch (e) { notice($('#codesmsg'), 'err', e && e.code ? failText(e) : explainError(e)); btn.disabled = false; }
});
$('#later').addEventListener('click', () => {
  try { localStorage.setItem('dw_codes_later', '1'); } catch (e) { /* the reminder is a convenience */ }
  $('#codesbox').hidden = true;
});
$('#dl').addEventListener('click', () => {
  if (!shown) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([shown], { type: 'text/plain' }));
  a.download = 'deus-witness-recovery-codes.txt';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});
