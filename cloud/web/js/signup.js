import { post } from './api.js';
import { createCredential, explainError, supported } from './webauthn.js';
import { mountNav, notice, $ } from './ui.js';

const msg = $('#msg');
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
    $('#f').hidden = true; $('#card').hidden = false;
  } catch (e) { notice(msg, 'err', explainError(e)); btn.disabled = false; msg.scrollIntoView({ block: 'nearest' }); }   // 0.2.22: the message sits below the button, which no longer moves
});
