// 0.2.2 Recover access: recovery code -> a session that can ONLY add a new passkey -> new passkey -> sign in again.
import { get, post } from './api.js';
import { createCredential, explainError, supported } from './webauthn.js';
import { normCode, groupCode } from './recovery.js';
import { $, notice, mountNav, skipMe, until, failText } from './ui.js';

const msg = $('#msg');
const errText = (e) => (e && e.code === 'RECOVERY_INVALID' ? 'This code is unknown or was already used. Check it, or try another one.'
  : e && e.code === 'RATE_LIMIT' ? 'Too many attempts. Wait an hour and try again.' : e && e.code ? failText(e) : explainError(e));

async function step2() {
  const st = await get('/api/auth/recovery/state');
  recNote(st.expires_at);
  $('#step1').hidden = true; $('#step2').hidden = false;
  $('#who').textContent = 'Account: ' + (st.display_name || '?') + '. ' + st.codes_left + ' recovery code(s) left. This recovery session: ' + until(st.expires_at) + '.';
}

// 0.2.22 (N2): the recovery session lives in an HttpOnly cookie the page cannot see, so remember (locally, no secret) until when it lasts;
// without that note the page does not ask /api/auth/recovery/state (it would only answer 401 and put a red line in the console).
const REC_KEY = 'dw_rec_until';
const recUntil = () => { try { return Number(localStorage.getItem(REC_KEY)) || 0; } catch (e) { return 0; } };
const recNote = (exp) => { try { if (exp) localStorage.setItem(REC_KEY, String(exp)); else localStorage.removeItem(REC_KEY); } catch (e) { /* ignore */ } };
const recActive = () => recUntil() > Math.floor(Date.now() / 1000);

async function main() {
  skipMe(recActive()); await mountNav(false);
  if (!supported()) notice(msg, 'err', 'This browser does not support passkeys (WebAuthn): use another browser or device.');
  if (recActive()) { try { await step2(); } catch (e) { recNote(0); /* the note was stale: step 1 */ } }
  $('#use').addEventListener('click', async () => {
    const c = normCode($('#code').value);
    if (!c) { notice(msg, 'err', 'A recovery code has 20 letters and digits (dashes optional), e.g. ABCD-EFGH-JKLM-NPQR-STUV.'); return; }
    const btn = $('#use'); btn.disabled = true; notice(msg, 'ok', '');
    try {
      await post('/api/auth/recovery/login', { code: groupCode(c) });
      notice(msg, 'warn', 'Code accepted. Every session of your account has ended and your devices were notified.');
      skipMe(true); await mountNav(false);          // 0.2.19: every session ended -> the header shows the state NOW (signed out); 0.2.22: without asking /api/me (recovery-only session: 403)
      await step2();
    } catch (e) { notice(msg, 'err', errText(e)); }
    btn.disabled = false;
  });
  $('#create').addEventListener('click', async () => {
    const btn = $('#create'); btn.disabled = true;
    try {
      const b = await post('/api/auth/recovery/passkey/begin', { label: $('#label').value, device: $('#rdevice').value });
      const credential = await createCredential(b.options);
      const r = await post('/api/auth/recovery/passkey/finish', { flow_id: b.flow_id, credential });
      $('#step2').hidden = true; $('#done').hidden = false;
      notice(msg, 'ok', '');
      recNote(0);
      skipMe(true); await mountNav(false);           // 0.2.19 (0.2.22: the recovery session ended with the new passkey; no /api/me)
      $('#donetext').textContent = 'Passkey ' + r.short + ' is active. It is recorded as "added with a recovery code". ' + r.codes_left + ' code(s) left.'
        + (r.phone_not_before ? ' It counts as your phone from ' + new Date(r.phone_not_before * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC ('
          + r.delay_h + ' h): until then it confirms only what a computer\'s passkey may. Your other devices were told and can cancel it.' : '');   // 0.2.15
    } catch (e) { notice(msg, 'err', errText(e)); btn.disabled = false; }
  });
}
main().catch((e) => notice(msg, 'err', failText(e)));
