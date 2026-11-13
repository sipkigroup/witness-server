import { post } from './api.js';
import { $, notice, mountNav, failText } from './ui.js';

const msg = $('#msg');
const token = new URLSearchParams(location.search).get('token') || '';

async function main() {
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(token)) { await mountNav(false); notice(msg, 'err', 'This invite link is incomplete.'); return; }
  const me = await mountNav(false);
  const back = 'join.html?token=' + encodeURIComponent(token);
  if (!me) {
    $('#su').href = 'signup.html?next=' + encodeURIComponent(back);
    $('#li').href = 'login.html?next=' + encodeURIComponent(back);
    $('#out').hidden = false; return;
  }
  $('#who').textContent = me.account.display_name + ' (' + me.keycard.short + ')';
  $('#in').hidden = false;
  $('#join').addEventListener('click', async () => {
    $('#join').disabled = true;
    try {
      const r = await post('/api/org/join', { token });
      $('#in').hidden = true; $('#done').hidden = false;
      $('#donetext').textContent = r.status === 'active' ? 'You are an observer: you can read the team and download the evidence pack.' : 'You are pending as ' + r.roles.join(', ') + '. You can sign once the owner adds you to a new policy version and it is signed.';
    } catch (e) { notice(msg, 'err', e.code === 'INVITE_INVALID' ? 'This invite was already used or has expired. Ask the owner for a new link.' : failText(e)); $('#join').disabled = false; }
  });
}
main().catch((e) => notice(msg, 'err', failText(e)));
