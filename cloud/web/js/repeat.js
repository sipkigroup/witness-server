// 0.2.29: "Also approve this exact call for this agent's later runs" (server/app/repeat.py). The owner's device makes up the receipt ids of
// the later uses (the time limit is written into each id) and signs ONE batch envelope over the approval payloads of this request and of
// those ids. What the summary says (how many more times, until when) is read back from the very ids that are signed. Pure functions here;
// the DOM part is in approve.js / allowances.js.
import { sha256, approvalPayload } from './profile.js';

export const USES = [1, 3, 10];
export const HOURS = [1, 24, 72];
export const MAX_USES = 10;
export const MAX_HOURS = 72;
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const RID_RE = /^r_[A-Z2-7]{32}$/;

function b32(bytes) {
  let bits = 0, v = 0, out = '';
  for (const x of bytes) { v = ((v << 8) | x) & 0x1fff; bits += 8; while (bits >= 5) { out += B32[(v >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(v << (5 - bits)) & 31];
  return out;
}

// "r_" + 7 base32 characters of the expiry (35 bits, big-endian, seconds) + 25 random base32 characters (an ordinary rid has 26 after "r_")
export function reservedRid(exp, rand = (n) => crypto.getRandomValues(new Uint8Array(n))) {
  const e = Math.floor(exp);
  if (!(e > 0 && e < 2 ** 35)) throw new Error('bad time limit');
  let s = '';
  for (let i = 6; i >= 0; i--) s += B32[Math.floor(e / 2 ** (5 * i)) % 32];
  return 'r_' + s + b32(rand(16)).slice(0, 25);
}

export function ridExp(rid) {
  if (typeof rid !== 'string' || !RID_RE.test(rid)) return null;
  let v = 0;
  for (const c of rid.slice(2, 9)) v = v * 32 + B32.indexOf(c);
  return v;
}

// uses: 1 | 3 | 10, hours: 1 | 24 | 72, nowS: the witness time (offer.t plus the seconds since the page got it) -> {exp, rids}
export function planRids(uses, hours, nowS, rand) {
  const n = USES.includes(Number(uses)) ? Number(uses) : 1;
  const h = HOURS.includes(Number(hours)) ? Number(hours) : 24;
  const exp = Math.floor(nowS) + h * 3600;
  const rids = [];
  while (rids.length < n) { const r = reservedRid(exp, rand); if (!rids.includes(r)) rids.push(r); }
  return { exp, rids };
}

// What the passkey signs: SHA-256 of the approval payload of this request, then of each reserved id (same mandate, same action, approved)
// late = the request expired unanswered: only the reserved ids are signed (the expired request itself can no longer be approved)
// pv2: view = the presentation hash of this page (signview.js) or null; it is in EVERY payload (the later runs are approved on what was shown)
export async function repeatItems(rid, mandate, action, rids, late = false, view = null) {
  const out = [];
  for (const r of late ? rids : [rid, ...rids]) out.push(await sha256(await approvalPayload(r, mandate, action, true, view)));
  return out;
}

// The summary is built from the ids themselves: the number of ids and the time inside them. null when they are not one consistent plan.
export function readPlan(rids, nowS) {
  if (!Array.isArray(rids) || !rids.length || rids.length > MAX_USES || new Set(rids).size !== rids.length) return null;
  const exps = new Set(rids.map(ridExp));
  if (exps.size !== 1 || exps.has(null)) return null;
  const exp = [...exps][0];
  if (nowS !== undefined && !(exp > nowS && exp <= nowS + MAX_HOURS * 3600 + 600)) return null;
  return { uses: rids.length, exp };
}

export function untilTime(expS) {
  return new Date(expS * 1000).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export function summaryText(plan, tool, late = false) {
  const times = late ? (plan.uses === 1 ? '1 time' : plan.uses + ' times') + ' in the next runs' : (plan.uses === 1 ? '1 more time' : plan.uses + ' more times');
  return 'Your passkey signs ' + (late ? '' : 'this request and ') + 'the same call ' + times + ' (this agent, ' + (tool || 'this tool') + ', exactly these arguments, '
    + 'under this mandate), usable until ' + untilTime(plan.exp) + '. When that time passes or those uses are spent, and for any call with '
    + 'other arguments, the agent asks you again.';
}

// the checkbox: {show, enabled, note}
export function offerView(offer) {
  if (!offer) return { show: false };
  if (!offer.eligible) return { show: !!offer.why_not, enabled: false, note: 'Not possible here: ' + (offer.why_not || '') + '.' };
  return { show: true, enabled: true, note: '' };
}

export const STATUS_TEXT = { active: 'active', revoked: 'revoked', expired: 'expired', used_up: 'used up', mandate_ended: 'ended: the mandate was replaced or revoked',
  file_changed: 'ended: the agent changed a file this command runs' };
