// Small DOM helpers. All server data goes in through textContent only (no HTML parsing of server data).
import { get, post } from './api.js';

export function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
export const $ = (s, r = document) => r.querySelector(s);
export function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); return e; }

export function notice(el, kind, text) {
  clear(el); el.className = 'notice ' + kind; el.setAttribute('role', kind === 'err' ? 'alert' : 'status');
  el.hidden = !text; if (text) el.textContent = text;
}

export function fmtTime(t) { return t ? new Date(t * 1000).toLocaleString() : ''; }
export function fmtMoney(cents, cur) {
  if (cents == null) return '';
  const neg = cents < 0, a = Math.abs(cents);
  return (neg ? '-' : '') + (a / 100).toFixed(2) + ' ' + (cur || 'USD');
}
// "12.34" -> 1234 (integer cents, no floating point)
export function dollarsToCents(s) {
  const m = /^\s*(\d{1,9})(?:\.(\d{1,2}))?\s*$/.exec(String(s));
  if (!m) return null;
  return Number(m[1]) * 100 + Number((m[2] || '').padEnd(2, '0') || 0);
}
export function csv(s) { return String(s || '').split(',').map((x) => x.trim()).filter(Boolean); }
// 0.2.84 (R5-P3): a list whose items may hold a comma (payee ids) lives in a textarea, one item per line; each line is trimmed (what you see)
export function lines(s) { return String(s || '').split(/\r\n|\r|\n/).map((x) => x.trim()).filter(Boolean); }
export const utf8Len = (s) => new TextEncoder().encode(String(s)).length;
export function until(exp) {
  const left = exp - Math.floor(Date.now() / 1000);
  if (left <= 0) return 'expired';
  const m = Math.floor(left / 60);
  return m + ' min ' + (left % 60) + ' s left';
}

// 0.2.19: "a session may exist" marker (cookie dw_in, set by the server at sign-in, cleared at sign-out; no secret, never an authority).
// A public page without it does not ask /api/me at all (no 401 line in the console); a page that needs the login always asks.
const hasMarker = () => /(?:^|;\s*)dw_in=1(?:;|$)/.test(document.cookie || '');
const setMarker = (on) => { try { document.cookie = 'dw_in=' + (on ? '1; path=/; SameSite=Strict' : '; path=/; max-age=0; SameSite=Strict'); } catch (e) { /* ignore */ } };

// 0.2.19: below 600 px the header is ONE row: brand + a "Menu" button; the links drop down under it (css/app.css .navmenu).
function fillNav(nav, kids) {
  clear(nav);
  // 0.2.76 (owner's iPhone 30.10: "DashboardApprovals…" glued): a space between the items, so they never glue even when a style is missing
  const links = h('div', { class: 'navlinks', id: 'navlinks' }, ...kids.flatMap((k, i) => (i ? [' ', k] : [k])));
  const tog = h('button', { class: 'btn ghost navtoggle', type: 'button', 'aria-expanded': 'false', 'aria-controls': 'navlinks' }, 'Menu');
  tog.addEventListener('click', () => { const o = nav.classList.toggle('open'); tog.setAttribute('aria-expanded', o ? 'true' : 'false'); });
  nav.classList.add('navmenu'); nav.classList.remove('open');
  nav.append(tog, links);
}

// 0.2.22: skipMe(true) = draw the signed-out header without asking /api/me (recover.html: that session is recovery-only, /api/me could only answer 401/403)
let noMe = false;
export const skipMe = (on) => { noMe = !!on; };
export async function mountNav(requireLogin, opts) {      // 0.2.78: opts.noSignup -- no "Create account" in the header (the trial page: a second account has no key of the agent)
  const nav = $('#nav');
  let me = null;
  if (!noMe && (requireLogin || hasMarker())) {
    try { me = await get('/api/me'); setMarker(true); } catch (e) {
      me = null;
      if (e && e.status === 401) setMarker(false);
      // 0.2.2: signed in with a recovery code -- the only page that session may use is recover.html
      if (e && e.code === 'RECOVERY_ONLY' && !location.pathname.endsWith('recover.html')) { location.href = 'recover.html'; return null; }
    }
  }
  if (nav) {
    if (me) {
      fillNav(nav, [h('a', { href: 'app.html' }, 'Dashboard'), h('a', { href: 'approve.html' }, 'Approvals'), h('a', { href: 'allowances.html' }, 'Permissions'), h('a', { href: 'team.html' }, 'Team'), h('a', { href: 'digest.html' }, 'Digest'), h('a', { href: 'devices.html' }, 'Devices'), h('a', { href: 'settings.html' }, 'Settings'), h('span', { class: 'who', text: me.account.display_name }),
        h('button', { class: 'btn ghost', type: 'button', onclick: async () => { try { await post('/api/auth/logout'); } catch (e) { /* ignore */ } setMarker(false); location.href = 'index.html'; } }, 'Sign out'),
        h('button', { class: 'btn ghost', type: 'button', title: 'End every session of this account on all devices', onclick: async () => { if (!confirm('Sign out on all devices? Every session of this account ends. Agent API keys keep working: if you fear a stolen session, also delete and recreate the agents\' keys.')) return; try { await post('/api/auth/logout-all'); } catch (e) { /* ignore */ } setMarker(false); location.href = 'index.html'; } }, 'Sign out everywhere')]);
    } else {
      fillNav(nav, opts && opts.noSignup ? [h('a', { href: 'login.html' }, 'Sign in')] : [h('a', { href: 'login.html' }, 'Sign in'), h('a', { class: 'btn', href: 'signup.html' }, 'Create account')]);
    }
  }
  if (requireLogin && !me) { location.href = 'login.html?next=' + encodeURIComponent(location.pathname.split('/').pop() + location.search); return null; }
  return me;
}

export function copyButton(getText, label = 'Copy') {
  const b = h('button', { class: 'btn ghost', type: 'button' }, label);
  b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(getText()); b.textContent = 'Copied'; } catch (e) { b.textContent = 'Select and copy manually'; }
    setTimeout(() => { b.textContent = label; }, 2000);
  });
  return b;
}
// 0.2.23: the SAME example as docs/quickstart.md step 5 (demo tools; nothing real happens); for a real server replace what follows "--".
export function mcpConfig(key) {
  return JSON.stringify({ mcpServers: { witnessed: { command: 'deus-witness-mcp',
    args: ['--', 'deus-witness-demo-tools'],
    env: { DEUS_WITNESS_KEY: key, DEUS_WITNESS_URL: location.origin, DEUS_DEMO_OUT: '/Users/you/dw-demo' } } } }, null, 2);
}

// Server-supplied ids go into URLs only through this check.
export const safeId = (s) => typeof s === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(s);
export const short = (hex) => String(hex || '').slice(0, 8);
export function kv(rows) { return h('dl', { class: 'kv' }, ...rows.flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { text: v })])); }
export const failText = (e) => (e && e.code ? e.code + (e.detail ? ': ' + e.detail : '') : (e && e.message) || String(e));
