// 0.2.96 (plan 13.11 p.1): "Get questions on your phone" right where a trial person has just touched the passkey (trial.html "Done",
// approve.html after a decision). The same Web Push as the dashboard card (push.js: VAPID, the server's per-minute limit and retries);
// the page that is open keeps watching the server by itself, a push is only a wake-up. Honest line: on iPhone a web push reaches
// only the site added to the Home Screen.
import { get } from './api.js';
import { supportState, envOf, enablePush, deviceState, registerSW, deviceLabel, HINTS, iosInfo } from './push.js';
import { h, clear } from './ui.js';

export const BUTTON = 'Get questions on your phone';
// r0276 (SVODKA-1311 p.5): the short how-to, only on iPhone / iPad in a browser tab (outside the Home Screen app); in the Home Screen app
// the button alone (it already works there)
export const IPHONE_LINE = 'iPhone: tap Share → Add to Home Screen, then open Witness from the Home Screen and turn on notifications there, not from a Safari tab.';
export const ON_TEXT = 'Done: this device gets a notification when your agent waits for you. Delivery is not guaranteed: this page keeps checking too.';

// -> what to show for this browser: {button: bool, line: string}
export function offerState(env) {
  const s = supportState(env).state;
  // r0271 (ISPYTANIE-0266 Н6): the iPhone line only on iOS (it was shown on a Mac and on Android too)
  // r0276: on iOS the line is the how-to, and only outside the Home Screen app (standalone: the button, nothing to add)
  if (s === 'ok') return { button: true, line: iosInfo(env.ua || '', env.platform || '', env.maxTouchPoints || 0).ios && !env.standalone ? IPHONE_LINE : '' };
  if (s === 'ios-install') return { button: false, line: IPHONE_LINE };
  return { button: false, line: (HINTS[s] || HINTS.unsupported).replace('%v', '') };
}

export async function mountOffer(win, box) {
  if (!box || !win || !win.navigator) return null;
  // r0278 (find 2): the permission changes outside the page (iPhone Settings, the question answered late): look again when the page is seen again
  if (!box.__dwSeen && win.document && win.document.addEventListener) {
    box.__dwSeen = true;
    win.document.addEventListener('visibilitychange', () => { if (win.document.visibilityState === 'visible' && box.__dwState !== 'on' && box.__dwState !== 'busy') mountOffer(win, box).catch(() => {}); });
  }
  const r = await mountOffer1(win, box);
  if (box.__dwState !== 'busy') box.__dwState = r;
  return r;
}

async function mountOffer1(win, box) {
  let keyInfo;
  try { keyInfo = await get('/api/push/key'); } catch (e) { return null; }      // not signed in yet
  if (!keyInfo || !keyInfo.enabled) return null;
  const nav = win.navigator;
  if (nav.serviceWorker) registerSW(nav).catch(() => {});
  const st = offerState(envOf(win));
  try { if (st.button && (await deviceState({ nav })).on) { clear(box).append(h('p', { class: 'hint', text: 'Notifications are on for this device.' })); return 'on'; } }
  catch (e) { /* no service worker yet: offer the button */ }
  const say = h('p', { class: 'hint' });
  const parts = st.line ? [h('p', { class: 'hint', text: st.line })] : [];
  if (st.button) {
    const b = h('button', { class: 'btn', type: 'button' }, BUTTON);
    b.addEventListener('click', async () => {
      b.disabled = true; say.textContent = ''; box.__dwState = 'busy';
      try {
        await enablePush({ nav, Notif: win.Notification, keyInfo, device: deviceLabel(nav.userAgent || '') });
        clear(box).append(h('p', { class: 'notice ok', text: ON_TEXT })); box.__dwState = 'on';
      } catch (e) { say.textContent = (e && e.detail) ? e.code + ': ' + e.detail : String((e && e.message) || e); b.disabled = false; box.__dwState = 'offer'; }
    });
    parts.unshift(h('p', {}, b));
  }
  clear(box).append(...parts, say);
  return st.button ? 'offer' : 'line';
}
