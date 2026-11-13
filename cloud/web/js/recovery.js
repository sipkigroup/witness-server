// 0.2.2: pure helpers of the recovery pages (no DOM; tested in node by test/recovery.test.mjs).
import { encode } from './cde.js';
import { sha256 } from './profile.js';
import { revocationPayload } from './policy.js';
import { MAX_ITEMS } from './wb.js';

export const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const TYP_KEY_EVENT = 'application/dw-key-event+cbor';

// What the person typed -> the 20 code symbols, or null. Spaces, dashes and lower case are fine; I/O/0/1 never occur in a code.
export function normCode(s) {
  if (typeof s !== 'string' || s.length > 64) return null;
  const c = s.toUpperCase().replace(/[\s-]/g, '');
  if (c.length !== 20 || [...c].some((ch) => !CODE_ALPHABET.includes(ch))) return null;
  return c;
}
export const groupCode = (c) => c.match(/.{1,4}/g).join('-');

// The text file the person saves (or prints). Says plainly what a code can and cannot do.
export function codesFile(codes, who, when) {
  return ['Deus Witness - recovery codes for ' + who, 'Made ' + when + '. Each code works ONCE.', '',
    ...codes.map((c, i) => String(i + 1).padStart(2, ' ') + '. ' + c), '',
    'A code only lets you add a NEW passkey after you lost yours. Using one signs out every device and sends a',
    'notification to your other devices. It does not let anyone sign mandates or approvals by itself.',
    'In a team, the other members still have to replace your key in the team policy.',
    'Keep this offline (paper, password manager). Anyone holding a code and your account can add a passkey.', ''].join('\n');
}

// One line of the device list.
export function keyStatus(k) {
  if (!k.active) return 'removed ' + new Date(k.removed_at * 1000).toISOString().slice(0, 10) + ': cannot sign in or sign anything';
  const by = { registration: 'your first passkey', passkey: 'added, confirmed by another of your passkeys',
    'recovery-code': 'added with a recovery code' }[k.added_by] || k.added_by;
  return (k.this_session ? 'this session - ' : '') + by;
}

// Mandates signed by a lost key -> batches of at most 20 (one passkey ceremony each): {ids, payloads, items}.
export async function revocationBatches(mandates) {
  const out = [];
  for (let i = 0; i < mandates.length; i += MAX_ITEMS) {
    const part = mandates.slice(i, i + MAX_ITEMS);
    const payloads = [], items = [];
    for (const m of part) { const p = await revocationPayload(m.mandate); payloads.push(p); items.push(await sha256(p)); }
    out.push({ ids: part.map((m) => m.id), payloads, items });
  }
  return out;
}

// Decode the server's key-event payload just enough to show WHAT the passkey is about to sign (op and the new key's kid prefix).
export function describeKeyEvent(decoded) {
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  if (!decoded || decoded.v !== 'dw-key-event-0.1' || !['add', 'remove'].includes(decoded.op)) throw new Error('not a key event');
  return (decoded.op === 'add' ? 'Add passkey ' : 'Remove passkey ') + hex(decoded.kid).slice(0, 16).replace(/(.{4})/g, '$1 ').trim()
    + ' to/from ' + decoded.principal;
}
export const cde = encode;

// 0.2.21: "possible clone" mark of a passkey (server app/keyalert.py, keys[].clone_alert). Only numbers and a route from a FIXED list
// are shown (an unknown route reads "a signature"); the page puts it in with textContent. No automatic freeze: the owner removes the key
// with ANOTHER passkey (the signed removal), or with a single passkey uses a recovery code first. -> null or {head, text, remove, single}.
export const CLONE_ROUTES = { login: 'a sign-in', approve: 'an approval', refuse: 'a refusal', mandate: 'a mandate', revoke: 'a mandate revocation',
  release: 'a release', allowance: 'an allowance', key_event: 'a passkey change', revoke_batch: 'a batch revocation', batch: 'a batch approval',
  'sigreq:policy': 'a team policy signature', 'sigreq:mandate': 'a team mandate signature', 'sigreq:approval': 'a team approval signature',
  'sigreq:release': 'a team release signature', 'sigreq:phone_lift': 'a team signature', 'sigreq:key_replace': 'a team signature' };
export function cloneView(k, activeCount) {
  const a = k && k.active ? k.clone_alert : null;
  if (!a || typeof a !== 'object') return null;
  const num = (x) => (Number.isSafeInteger(x) && x >= 0 ? x : 0);
  const at = (t) => new Date(num(t) * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  const where = Object.prototype.hasOwnProperty.call(CLONE_ROUTES, a.route) ? CLONE_ROUTES[a.route] : 'a signature';
  const single = num(activeCount) <= 1;
  const n = num(a.count);
  const head = 'possible clone detected at ' + at(a.last_at);
  const text = 'On ' + where + ' this passkey presented signature counter ' + num(a.got) + ' after ' + num(a.stored) + ' (it must grow): '
    + 'a copy of the passkey, or an old signature sent again. It was refused' + (n > 1 ? ' (' + n + ' times since ' + at(a.first_at) + ')' : '') + '. '
    + (single
      ? 'This is your only passkey. If you can still sign with it, add a second passkey now and then remove this one with it. If it is refused, '
        + 'use a recovery code (sign-in page: "Use a recovery code", recover.html) to add a new passkey, then remove this one with the new one.'
      : 'If this was not you, remove it now, signing with ANOTHER of your passkeys. If it was you (for example an old signature was sent again), '
        + 'press "This was me" and confirm with another passkey.');
  return { head, text, remove: !single, single };
}
