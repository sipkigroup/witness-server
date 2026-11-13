// 0.2.2 Recovery codes: state (never the codes), make 10 new ones (step-up by api.js), show once, copy / download.
import { get, post } from './api.js';
import { explainError } from './webauthn.js';
import { codesFile } from './recovery.js';
import { $, notice, mountNav, fmtTime, failText, copyButton } from './ui.js';

const msg = $('#msg');
let shown = null;

async function state() {
  const c = await get('/api/auth/recovery-codes');
  $('#state').textContent = c.total ? c.remaining + ' of ' + c.total + ' codes unused, made ' + fmtTime(c.created_at) + '.' : 'You have no recovery codes yet.';
  $('#make').textContent = c.total ? 'Replace with 10 new codes' : 'Make 10 codes';
}

async function main() {
  const me = await mountNav(true);
  if (!me) return;
  await state();
  $('#copy').append(copyButton(() => shown || ''));
  $('#make').addEventListener('click', async () => {
    const btn = $('#make'); btn.disabled = true; notice(msg, 'ok', '');
    try {
      const r = await post('/api/auth/recovery-codes', {});
      shown = codesFile(r.codes, me.user.display_name || me.account.display_name, new Date(r.created_at * 1000).toISOString().slice(0, 10));
      $('#codes').textContent = r.codes.join('\n');
      $('#shown').hidden = false;
      await state();
    } catch (e) { notice(msg, 'err', e && e.code ? failText(e) : explainError(e)); }
    btn.disabled = false;
  });
  $('#dl').addEventListener('click', () => {
    if (!shown) return;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([shown], { type: 'text/plain' }));
    a.download = 'deus-witness-recovery-codes.txt';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  window.addEventListener('beforeunload', (e) => { if (shown) { e.preventDefault(); e.returnValue = ''; } });
}
main().catch((e) => notice(msg, 'err', failText(e)));
