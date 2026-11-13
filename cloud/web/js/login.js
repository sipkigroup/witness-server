import { post } from './api.js';
import { getCredential, explainError, supported } from './webauthn.js';
import { mountNav, notice, $ } from './ui.js';

const msg = $('#msg');
mountNav(false).then((me) => { if (me) location.href = 'app.html'; });
if (!supported()) notice(msg, 'err', 'This browser does not support passkeys (WebAuthn).');

const next = new URLSearchParams(location.search).get('next');
// 0.2.75 (N23): opened from a call's link (approve.html?rid=... or trial.html?rid=...): the witness names the trial account that call waits
// for and the device offers only its passkeys. With two trial accounts in one browser a sign-in without this picked the first passkey.
export function ridOf(n) {
  const m = /[?&]rid=([rR]_[A-Za-z2-7]{1,40})(?:&|$)/.exec(String(n || ''));
  return m ? 'r_' + m[1].slice(2).toUpperCase() : null;
}
const rid = ridOf(next);
let early = null;                                       // a begun sign-in (with the hint), used by the first press while fresh
const FRESH_MS = 4 * 60 * 1000;
async function begin() { const b = await post('/api/auth/login/begin', rid ? { rid } : {}); return { b, at: Date.now() }; }
function showHint(b) {
  const el = $('#hint');
  if (!el || !b || !b.hint || !b.hint.name) return;
  el.hidden = false;
  el.textContent = 'The call you opened waits for the account whose passkey is named "' + b.hint.name + '". Choose that passkey: your device offers only it.';
}
if (rid) {                                              // 04.11 (L3): say why this page came first and what follows (the call waits; one more passkey touch approves it)
  const why = $('#why'); if (why) { why.hidden = false; why.textContent = 'You were sent here to answer a request of your agent. Your session on this browser has ended or this browser has none. Sign in with your passkey (touch 1 of 2); the request opens at once and the second touch approves or refuses it.'; }
}
if (rid) begin().then((x) => { early = x; showHint(x.b); }).catch(() => { /* the button asks again */ });

$('#go').addEventListener('click', async () => {
  const btn = $('#go'); btn.disabled = true; notice(msg, 'ok', '');
  try {
    const x = early && Date.now() - early.at < FRESH_MS ? early : await begin();
    early = null;
    showHint(x.b);
    const credential = await getCredential(x.b.options);
    await post('/api/auth/login/finish', { flow_id: x.b.flow_id, credential });
    location.href = next && /^[a-z]+\.html(\?[\w=&%.-]*)?$/.test(next) ? next : 'app.html';
  } catch (e) {
    notice(msg, 'err', e && e.name === 'NotAllowedError' ? 'The passkey prompt was cancelled or timed out: you are not signed in. Press "Sign in with passkey" again.' : explainError(e));
    btn.disabled = false;
  }
});
