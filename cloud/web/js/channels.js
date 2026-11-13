// 0.2.25: notification channels besides Web Push: Telegram (your own bot), Slack (incoming webhook), e-mail. A message says only that an
// agent waits and links to the request; approving is still done on approve.html with your passkey. The server keeps the token / webhook /
// address encrypted and never shows it again (the list shows a masked label). iPhone / iPad: Web Push only from the Home Screen app.
// The DOM part mounts on #chan-card (app.html); the rest is plain functions (test/v0225.test.mjs runs them in node).
import { get, post, del } from './api.js';
import { h, $, clear, notice, fmtTime, failText } from './ui.js';

export const IOS_NOTE = 'iPhone / iPad: Web Push reaches you only if Witness was added to the Home Screen (Share, then "Add to Home Screen", iOS 16.4 or later) and notifications were enabled from that Home Screen app. Safari tabs get no pushes. If you do not want that, use Telegram, Slack or e-mail below.';
export const KIND_HELP = {
  telegram: 'Create a bot with @BotFather in Telegram and copy its token. Send your bot any message, then press "Find my chat" (or type the chat id). Only you should know the token.',
  slack: 'In Slack: Apps, "Incoming Webhooks", add one for a channel only you read, copy its URL (https://hooks.slack.com/services/...).',
  email: 'We send a 6-digit code to this address; type it below to turn the channel on.',
};

export function frozenText(a) {
  if (!a || !a.frozen_at) return '';
  const when = fmtTime(a.frozen_at);
  return a.frozen_kind === 'auto'
    ? 'Frozen automatically ' + when + ': it sent a flood of approval requests the witness had to refuse (APPROVAL_RATE). Its waiting requests were cancelled; every new call is refused (AGENT_FROZEN) until you unfreeze it.'
    : 'Frozen ' + when + ': every new call is refused (AGENT_FROZEN) until the owner unfreezes it.';
}

// what the form sends for each kind (the server checks it again; this only catches typos early)
export function channelBody(kind, f) {
  const t = (x) => String(x || '').trim();
  if (kind === 'telegram') {
    if (!/^[0-9]{5,12}:[A-Za-z0-9_-]{30,64}$/.test(t(f.token))) return { error: 'The bot token looks like 123456789:AA... (from @BotFather).' };
    if (!/^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$/.test(t(f.chat_id))) return { error: 'The chat id is a number (press "Find my chat").' };
    return { body: { kind, token: t(f.token), chat_id: t(f.chat_id) } };
  }
  if (kind === 'slack') {
    if (!/^https:\/\/hooks\.slack\.com\/(services|workflows|triggers)\/[A-Za-z0-9_/-]{10,200}$/.test(t(f.url))) return { error: 'A Slack incoming webhook URL starts with https://hooks.slack.com/services/' };
    return { body: { kind, url: t(f.url) } };
  }
  if (kind === 'email') {
    if (!/^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$/.test(t(f.address)) || t(f.address).length > 254) return { error: 'Type an e-mail address.' };
    return { body: { kind, address: t(f.address) } };
  }
  return { error: 'Choose Telegram, Slack or e-mail.' };
}

export function channelState(c) {
  if (!c.verified) return c.kind === 'email' ? 'waiting for the code' : 'not working yet (send a test)';
  return c.fail_count ? 'last delivery failed (' + (c.last_error || 'error') + ')' : 'on';
}

function fieldsOf(kind) {
  if (kind === 'telegram') return [['token', 'Bot token', 'password'], ['chat_id', 'Chat id', 'text']];
  if (kind === 'slack') return [['url', 'Incoming webhook URL', 'password']];
  return [['address', 'E-mail address', 'email']];
}

export async function mountChannels() {
  const card = $('#chan-card'); if (!card) return;
  const msg = $('#chanmsg');
  $('#chan-ios').textContent = IOS_NOTE;
  const r = await get('/api/notify/channels');
  const kindSel = $('#chankind');
  [...kindSel.options].forEach((o) => { if (o.value === 'email' && !r.email_enabled) { o.disabled = true; o.textContent = 'E-mail (not configured on this server)'; } });
  const list = clear($('#chanlist'));
  if (!r.channels.length) list.append(h('p', { class: 'hint', text: 'No channel yet.' }));
  for (const c of r.channels) {
    const row = h('div', { class: 'row' }, h('strong', { text: c.label }), h('span', { class: 'hint', text: channelState(c) + (c.last_ok_at ? ', last delivered ' + fmtTime(c.last_ok_at) : '') }));
    if (c.kind === 'email' && !c.verified) {
      const inp = h('input', { class: 'num', inputmode: 'numeric', maxlength: '6', placeholder: '6-digit code', 'aria-label': 'Code from the e-mail' });
      row.append(inp, h('button', { class: 'btn', type: 'button', onclick: async () => {
        try { await post('/api/notify/channels/' + encodeURIComponent(c.id) + '/verify', { code: inp.value }); notice(msg, 'ok', 'E-mail channel is on.'); await mountChannels(); } catch (e) { notice(msg, 'err', failText(e)); }
      } }, 'Confirm'));
    }
    row.append(h('button', { class: 'btn ghost', type: 'button', onclick: async () => {
      try { const x = await post('/api/notify/channels/' + encodeURIComponent(c.id) + '/test'); notice(msg, x.sent ? 'ok' : 'err', x.sent ? 'Test message sent.' : 'The test message was not delivered: check the token / webhook / address.'); await mountChannels(); } catch (e) { notice(msg, 'err', failText(e)); }
    } }, 'Send a test'), h('button', { class: 'btn danger ghost', type: 'button', onclick: async () => {
      if (!confirm('Remove this channel? Your passkey confirms it.')) return;
      try { await del('/api/notify/channels/' + encodeURIComponent(c.id)); await mountChannels(); } catch (e) { notice(msg, 'err', failText(e)); }
    } }, 'Remove'));
    list.append(row);
  }
  const draw = () => {
    const k = kindSel.value, box = clear($('#chanfields'));
    $('#chanhelp').textContent = KIND_HELP[k] || '';
    for (const [n, label, type] of fieldsOf(k)) box.append(h('div', {}, h('label', { for: 'chan-' + n, text: label }), h('input', { id: 'chan-' + n, type, autocomplete: 'off', spellcheck: 'false' })));
    $('#chanfind').hidden = k !== 'telegram';
  };
  if (!card.dataset.wired) {
    card.dataset.wired = '1';
    kindSel.addEventListener('change', draw);
    $('#chanfind').addEventListener('click', async () => {
      try {
        const x = await post('/api/notify/telegram/chats', { token: ($('#chan-token') || {}).value || '' });
        if (!x.chats.length) { notice(msg, 'warn', 'No chat found: send your bot a message in Telegram first, then try again.'); return; }
        $('#chan-chat_id').value = x.chats[0].chat_id;
        notice(msg, 'ok', 'Chat found: ' + (x.chats[0].name || x.chats[0].chat_id) + (x.chats.length > 1 ? ' (' + x.chats.length + ' chats wrote to the bot; the first is used)' : ''));
      } catch (e) { notice(msg, 'err', failText(e)); }
    });
    $('#chanadd').addEventListener('click', async () => {
      const k = kindSel.value, f = {};
      for (const [n] of fieldsOf(k)) f[n] = ($('#chan-' + n) || {}).value;
      const b = channelBody(k, f);
      if (b.error) { notice(msg, 'err', b.error); return; }
      try {
        const x = await post('/api/notify/channels', b.body);
        notice(msg, x.sent ? 'ok' : 'err', x.needs_code ? (x.sent ? 'Code sent. Type it next to the new channel.' : 'The e-mail was not delivered; check the address.') : (x.sent ? 'Channel added: a test message was sent.' : 'Saved, but the test message was not delivered: check the token / chat id / webhook.'));
        draw(); await mountChannels();
      } catch (e) { notice(msg, 'err', failText(e)); }
    });
  }
  draw();
}
