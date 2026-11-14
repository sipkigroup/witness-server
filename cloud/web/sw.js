// Deus Witness service worker (08; P0-4). Shows a fixed-text notification for each push and opens the request's page when tapped.
// It never approves anything: an approval is signed with the owner's passkey (Face ID, fingerprint or security key) on approve.html.
// Classic script, no imports: it is evaluated as is by the browser and by test/push.test.mjs (node:vm).
'use strict';

const PAGE_RE = /^(approve\.html\?rid=[rR]_[A-Za-z2-7]{1,40}|sign\.html\?req=sr_[0-9a-f]{1,40}|approve\.html|app\.html|devices\.html)$/;

// Only these pages of this site may be opened from a push; anything else falls back to the dashboard.
function safeUrl(url, scope) {
  return scope + (typeof url === 'string' && PAGE_RE.test(url) ? url : 'app.html');
}

// P0-4: a push is a SIGNAL. The payload (server app/push.py) carries only opaque ids {v: 2, k, id, g}; the text shown here is FIXED
// and never comes from the server, so nothing about the request (agent, tool, recipient, amount) reaches the lock screen or the
// push service. The page loads the request after login. k: a = approval, s = signature, q = summary, t = test;
// 0.2.2 security signals (never merged away): r = a recovery code was used, k = a passkey was added or removed;
// 0.2.14: d = a passkey's device class (phone / this computer) changed; 0.2.15: p = a new phone was declared with a recovery code;
// 0.2.21: c = a passkey signed with a counter that went back (a copy of it, or an old signature sent again; at most one per key per 10 min).
// r0288: i = the account has not been used for a long time and will be erased; a sign-in (or a call of the hook) keeps it.
// RT-SUP 29.10: v = a team signature request was replaced because what it shows changed; earlier signatures do not count, sign again.
const TEXT = {
  a: ['Deus Witness', 'An agent is waiting for your decision. Open to see what it wants.'],
  s: ['Deus Witness', 'Your signature is requested. Open to review it.'],
  v: ['Deus Witness', 'The view changed, sign again: a request you were asked to sign now shows something else. Open to review it.'],
  q: ['Deus Witness', 'Requests are waiting for your decision.'],
  t: ['Deus Witness', 'Test notification: approval requests will arrive like this.'],
  r: ['Deus Witness - security', 'A recovery code was just used on your account and every session was ended. If this was not you, sign in and check Devices now.'],
  k: ['Deus Witness - security', 'A passkey was added to or removed from your account. If this was not you, sign in and check Devices now.'],
  d: ['Deus Witness - security', 'A passkey was re-marked as your phone or as this computer. If this was not you, sign in and check Devices now.'],
  p: ['Deus Witness - security', 'A recovery code was used to declare a NEW PHONE on your account. It counts as your phone only after a waiting time. Not you? Open Devices and press "This was not me - cancel".'],
  i: ['Deus Witness', 'Your account has not been used for a long time and will be erased. To keep it, sign in once (or use Claude Code with the hook); the dashboard shows the date.'],
  c: ['Deus Witness - security', 'One of your passkeys may have been copied: it signed with a counter that went back, and it was refused. Open Devices: the key is marked there. If this was not you, remove it with another passkey.'],
};

function urlFor(d) {
  if (d.k === 'a' && typeof d.id === 'string' && /^[rR]_[A-Za-z2-7]{1,40}$/.test(d.id)) return 'approve.html?rid=' + d.id;
  if ((d.k === 's' || d.k === 'v') && typeof d.id === 'string' && /^sr_[0-9a-f]{1,40}$/.test(d.id)) return 'sign.html?req=' + d.id;
  if (d.k === 'q') return 'approve.html';
  if (d.k === 'i') return 'app.html';
  if (d.k === 'r' || d.k === 'k' || d.k === 'd' || d.k === 'p' || d.k === 'c') return 'devices.html';
  return 'app.html';
}

function noteFrom(d, scope) {
  d = d && typeof d === 'object' ? d : {};
  const k = Object.prototype.hasOwnProperty.call(TEXT, d.k) ? d.k : 'a';   // unknown / old / broken payload: the neutral approval text
  let [title, body] = TEXT[k];
  // 05.11 (owner rule): a question's push says in two short lines what the agent wants and what it can harm (the server's general sentence)
  if (k === 'a' && Array.isArray(d.t) && d.t.length === 2 && d.t.every((x) => typeof x === 'string' && x.length > 0 && x.length < 200)) body = d.t[0] + '. ' + d.t[1];
  const g = typeof d.g === 'string' && /^[0-9a-f]{1,32}$/.test(d.g) ? d.g : '';
  // one agent = one tag: a newer request replaces its older notification on the device (renotify: it still buzzes)
  const tag = k === 'i' ? 'dw-idle' : k === 'q' ? 'dw-summary' : k === 't' ? 'dw-test' : k === 'r' || k === 'k' || k === 'p' || k === 'c' ? 'dw-security-' + k : g ? 'dw-' + k + '-' + g : 'dw';
  const data = { url: safeUrl(urlFor(d), scope) };
  const b = ackBody(d, 'opened');
  if (b) { data.id = b.id; data.n = b.n; }
  return { title, options: { body, tag, renotify: true, requireInteraction: k === 'a' || k === 's' || k === 'v' || k === 'i' || k === 'r' || k === 'k' || k === 'p' || k === 'c',
    icon: scope + 'icons/icon-192.png', data } };
}

// r0276 (SVODKA-1311 p.5): HTTP 201 from the push service is not "delivered". For a question's push (k a) this worker tells the server how
// far it got: received (the push reached this device), shown (the notification is up), opened (the person tapped it). The proof is `n`,
// which only the encrypted push carried; nothing about the device is sent. An ack that fails is simply lost (the server then retries the
// push once and tells the agent's terminal "did not reach your phone: open the link").
function ackBody(d, s) {
  if (!d || d.k !== 'a' || typeof d.id !== 'string' || !/^[rR]_[A-Za-z2-7]{1,40}$/.test(d.id)) return null;
  if (typeof d.n !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(d.n)) return null;
  return { id: d.id, n: d.n, s };
}

async function ack(fetchFn, scope, d, s) {
  const b = ackBody(d, s);
  if (!b || typeof fetchFn !== 'function') return false;
  try {
    const r = await fetchFn(scope + 'api/push/ack', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b),
      credentials: 'omit', keepalive: true });
    return !!(r && r.ok);
  } catch (err) { return false; }
}

async function openOrFocus(clients, url, scope) {
  const list = await clients.matchAll({ type: 'window', includeUncontrolled: true });
  for (const c of list) if (c.url === url && 'focus' in c) return c.focus();
  for (const c of list) {
    if (c.url.startsWith(scope) && 'navigate' in c) { const n = await c.navigate(url); return (n || c).focus(); }
  }
  return clients.openWindow(url);
}

if (typeof self !== 'undefined' && self.addEventListener) {
  const scope = () => (self.registration && self.registration.scope) || '/';
  self.addEventListener('install', () => self.skipWaiting());
  self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
  self.addEventListener('push', (e) => {
    let d = {};
    try { d = e.data ? e.data.json() : {}; } catch (err) { d = {}; }
    const n = noteFrom(d, scope());
    const f = typeof fetch === 'function' ? fetch : null;
    // iOS/Chrome: every push MUST show a notification (userVisibleOnly), or the subscription is revoked. The acks never hold it back.
    e.waitUntil(Promise.all([ack(f, scope(), d, 'received'),
      self.registration.showNotification(n.title, n.options).then(() => ack(f, scope(), d, 'shown'))]));
  });
  self.addEventListener('notificationclick', (e) => {
    e.notification.close();
    const nd = e.notification.data || {};
    const url = safeUrl((nd.url || '').slice(scope().length), scope());
    const f = typeof fetch === 'function' ? fetch : null;
    e.waitUntil(Promise.all([openOrFocus(self.clients, url, scope()), ack(f, scope(), { k: 'a', id: nd.id, n: nd.n }, 'opened')]));
  });
}

if (typeof module !== 'undefined') module.exports = { safeUrl, noteFrom, openOrFocus, urlFor, PAGE_RE, TEXT, ackBody, ack };
