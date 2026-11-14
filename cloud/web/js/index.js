import { get, post } from './api.js';
import { h, $, clear, mountNav, notice } from './ui.js';

mountNav(false);
if ($('#hashes')) get('/api/witness').then((w) => {
  const box = clear($('#hashes'));
  const files = Object.entries(w.web_js_sha256 || {});
  if (!files.length) { box.append(h('p', { class: 'hint', text: 'The server has not published hashes yet.' })); return; }
  const t = h('table', {}, h('tbody', {}, files.sort().map(([f, x]) => h('tr', {}, h('td', { class: 'mono', text: f }), h('td', { class: 'mono', text: x })))));
  box.append(h('div', { class: 'tablewrap', tabindex: '0', role: 'region', 'aria-label': 'Page script hashes (scrolls sideways)' }, t));
}).catch(() => { clear($('#hashes')).append(h('p', { class: 'hint', text: 'Hashes are unavailable right now.' })); });

// 0.2.28: the Team access form (POST /api/team-request: the e-mail and the text only; the server keeps them up to 180 days)
const tf = $('#teamreq');
if (tf) tf.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const msg = $('#tr_msg'), btn = tf.querySelector('button');
  btn.disabled = true; notice(msg, 'ok', '');
  try {
    await post('/api/team-request', { email: $('#tr_email').value.trim(), text: $('#tr_text').value.trim(), website: $('#tr_site').value });
    notice(msg, 'ok', 'Thank you: your request is in. We answer by e-mail.'); tf.reset();
  } catch (e) {
    notice(msg, 'err', e.code === 'TEAM_EMAIL' ? 'Please check the e-mail address.' : e.code === 'TEAM_TEXT' ? 'Please write a few words (up to 2000 characters).'
      : e.code === 'RATE_LIMIT' ? 'Too many requests right now. Please write to support@sipkigroup.com.' : 'Not sent (' + (e.code || 'error') + '). Please write to support@sipkigroup.com.');
  } finally { btn.disabled = false; }
});
