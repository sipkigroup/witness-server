// 08: push notifications of approval requests on this device (Web Push, VAPID). The notification only opens approve.html;
// approving is still a passkey (Face ID, fingerprint or security key) signature there. iOS: push works only from the app added to the Home Screen, iOS 16.4+.
// The DOM part mounts itself on a page with #push-card (app.html); the rest is plain functions (test/push.test.mjs runs them in node).
import { get, post } from './api.js';

export class PushError extends Error {
  constructor(code, text) { super(text); this.code = code; }
}

export function b64uToBytes(s) {
  const b = atob(String(s).replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

export function iosInfo(ua, platform, maxTouchPoints) {
  const ios = /iPhone|iPad|iPod/.test(ua) || (platform === 'MacIntel' && maxTouchPoints > 1); // iPadOS asks for the desktop site
  const m = /OS (\d+)[_.](\d+)/.exec(ua);
  return { ios, version: ios && m && /iPhone|iPad|iPod/.test(ua) ? [Number(m[1]), Number(m[2])] : null };
}

// env: {ua, platform, maxTouchPoints, standalone, hasSW, hasPush, hasNotification, permission}
export function supportState(env) {
  const { ios, version } = iosInfo(env.ua || '', env.platform || '', env.maxTouchPoints || 0);
  if (ios && version && (version[0] < 16 || (version[0] === 16 && version[1] < 4))) return { state: 'ios-old', version: version.join('.') };
  if (ios && !env.standalone) return { state: 'ios-install' };
  if (!env.hasSW || !env.hasPush || !env.hasNotification) return { state: ios ? 'ios-install' : 'unsupported' };
  if (env.permission === 'denied') return { state: 'denied' };
  return { state: 'ok' };
}

export function envOf(win) {
  const nav = win.navigator || {};
  const standalone = nav.standalone === true || !!(win.matchMedia && win.matchMedia('(display-mode: standalone)').matches);
  return { ua: nav.userAgent || '', platform: nav.platform || '', maxTouchPoints: nav.maxTouchPoints || 0, standalone,
    hasSW: !!nav.serviceWorker, hasPush: 'PushManager' in win, hasNotification: 'Notification' in win,
    permission: win.Notification ? win.Notification.permission : 'default' };
}

export const HINTS = {
  'ios-install': 'Add Deus Witness to the Home Screen to get approval requests on this device. On iPhone and iPad, notifications work only from the installed app (iOS 16.4 or later): tap Share, then "Add to Home Screen", open Deus Witness from the Home Screen and enable notifications there.',
  'ios-old': 'Web notifications need iOS 16.4 or later (this device: iOS %v). Update iOS, then add this site to the Home Screen.',
  unsupported: 'This browser cannot receive web push notifications. Keep the dashboard open, or use a phone (Android Chrome, or iPhone with the site added to the Home Screen).',
  denied: 'Notifications are blocked for this site. Allow them in the browser or system settings, then reload this page.',
};

// P0-4: iOS delivers web push only to the site opened from the Home Screen (standalone). The onboarding says how, and checks it.
export const IOS_STEPS = [
  'In Safari, tap the Share button (the square with an arrow).',
  'Choose "Add to Home Screen", then "Add".',
  'Close Safari and open Deus Witness from its icon on the Home Screen.',
  'Sign in there and tap "Enable notifications" on this page.',
];

export function iosOnboarding(env) {
  const { ios, version } = iosInfo(env.ua || '', env.platform || '', env.maxTouchPoints || 0);
  if (!ios) return { needed: false };
  const old = !!(version && (version[0] < 16 || (version[0] === 16 && version[1] < 4)));
  const standalone = !!env.standalone;
  return { needed: !standalone || old, standalone, old, steps: IOS_STEPS,
    state: old ? HINTS['ios-old'].replace('%v', version.join('.'))
      : standalone ? 'Opened from the Home Screen: yes. Notifications can be enabled.'
        : 'Opened from the Home Screen: no. Add Deus Witness to the Home Screen to get approval requests: in a browser tab iOS never delivers notifications.' };
}

export function deviceLabel(ua) {
  const os = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'device';
  const br = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : '';
  return (os + (br ? ' ' + br : '')).slice(0, 80);
}

// The same id the server stores (sha256(endpoint), 32 hex characters).
export async function subId(endpoint) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint));
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

export async function registerSW(nav) {
  if (!nav.serviceWorker) return null;
  return nav.serviceWorker.register('/sw.js', { scope: '/' });
}

// serviceWorker.ready never settles when the registration failed: give up after a while instead of hanging the card.
export function ready(nav, ms = 8000) {
  return Promise.race([nav.serviceWorker.ready, new Promise((_, rej) => setTimeout(() => rej(new PushError('NO_SW', 'The service worker did not start; reload the page.')), ms))]);
}

function sameKey(a, b) {
  if (!a) return false;
  const x = new Uint8Array(a);
  return x.length === b.length && x.every((v, i) => v === b[i]);
}

// keyInfo = GET /api/push/key, fetched BEFORE the tap: iOS grants the permission prompt only inside the user gesture.
export async function enablePush({ nav, Notif, api = { get, post }, keyInfo, device }) {
  if (!keyInfo || !keyInfo.enabled) throw new PushError('PUSH_DISABLED', 'Push is not configured on this server.');
  const perm = await Notif.requestPermission();
  if (perm !== 'granted') throw new PushError('PERMISSION', perm === 'denied' ? HINTS.denied : 'Notifications were not allowed.');
  const reg = await ready(nav);
  const key = b64uToBytes(keyInfo.public_key);
  let sub = await reg.pushManager.getSubscription();
  if (sub && !sameKey(sub.options && sub.options.applicationServerKey, key)) { await sub.unsubscribe(); sub = null; } // server key rotated
  if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
  await api.post('/api/push/subscribe', { subscription: sub.toJSON(), device }); // session + Origin + passkey step-up (api.js asks for it)
  return sub;
}

export async function disablePush({ nav, api = { get, post } }) {
  const reg = await ready(nav);
  const sub = await reg.pushManager.getSubscription();
  if (!sub) return false;
  await api.post('/api/push/unsubscribe', { endpoint: sub.endpoint });
  await sub.unsubscribe();
  return true;
}

// 'on' = this browser has a subscription the server knows; 'off' otherwise.
export async function deviceState({ nav, api = { get, post } }) {
  const reg = await ready(nav);
  const sub = await reg.pushManager.getSubscription();
  if (!sub) return { on: false, devices: (await api.get('/api/push/subscriptions')).subscriptions.length };
  const [id, list] = await Promise.all([subId(sub.endpoint), api.get('/api/push/subscriptions')]);
  return { on: list.subscriptions.some((s) => s.id === id), devices: list.subscriptions.length };
}

// ---------------- DOM (app.html) ----------------
async function mount(win, doc) {
  const el = (id) => doc.getElementById(id);
  const msg = el('pushmsg'), state = el('pushstate'), on = el('pushon'), off = el('pushoff'), test = el('pushtest');
  const say = (kind, text) => { msg.hidden = !text; msg.className = 'notice ' + kind; msg.textContent = text || ''; };
  const nav = win.navigator;
  if (nav.serviceWorker) registerSW(nav).catch(() => {}); // also what makes the site installable
  const ob = iosOnboarding(envOf(win));
  if (ob.needed && el('push-ios')) {
    el('push-ios').hidden = false;
    el('push-ios-steps').replaceChildren(...ob.steps.map((t) => { const li = doc.createElement('li'); li.textContent = t; return li; }));
    const check = () => {
      const o = iosOnboarding(envOf(win));
      el('push-ios-state').textContent = o.state;
      el('push-ios-state').className = 'notice ' + (o.needed ? 'warn' : 'ok');
      if (!o.needed) win.location.reload();
    };
    el('push-ios-check').addEventListener('click', check);
    el('push-ios-state').textContent = ob.state;
    state.textContent = '';
    return;
  }
  const s = supportState(envOf(win));
  if (s.state !== 'ok') { say('warn', HINTS[s.state].replace('%v', s.version || '')); state.textContent = ''; return; }
  let keyInfo;
  try { keyInfo = await get('/api/push/key'); } catch (e) { return; } // not logged in: app.js redirects
  if (!keyInfo.enabled) { state.textContent = 'Push notifications are not configured on this server.'; return; }
  const show = async () => {
    try {
      const st = await deviceState({ nav });
      state.textContent = st.on ? 'Notifications are on for this device.' + (st.devices > 1 ? ' Devices with notifications: ' + st.devices + '.' : '')
        : 'Notifications are off for this device.' + (st.devices ? ' Other devices with notifications: ' + st.devices + '.' : '');
      on.hidden = st.on; off.hidden = !st.on; test.hidden = !st.on;
    } catch (e) { state.textContent = ''; on.hidden = false; }
  };
  const run = (fn) => async () => {
    on.disabled = off.disabled = test.disabled = true; say('ok', '');
    try { await fn(); } catch (e) { say('err', e.detail ? e.code + ': ' + e.detail : e.message); }
    on.disabled = off.disabled = test.disabled = false;
    await show();
  };
  on.addEventListener('click', run(async () => {
    await enablePush({ nav, Notif: win.Notification, keyInfo, device: deviceLabel(nav.userAgent || '') });
    say('ok', 'Done. When an agent waits for you, this device gets a notification; tap it, check the action and confirm with Face ID, a fingerprint or a security key.');
  }));
  off.addEventListener('click', run(async () => { await disablePush({ nav }); say('ok', 'Notifications are off for this device.'); }));
  test.addEventListener('click', run(async () => { await post('/api/push/test'); say('ok', 'Test notification sent.'); }));
  await show();
}

if (typeof document !== 'undefined' && document.getElementById('push-card')) mount(window, document);
