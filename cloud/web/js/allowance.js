// 0.2.10 (PROPOSAL-07): "Allow this command in this project" on the approval page, and the Project permissions page.
// The owner's device builds the allowance map itself (the mandate hash is computed here, as for an approval) and signs it with the passkey
// (typ application/aar-allowance+cbor); the server records it in the ledger. Pure functions here; the DOM part is in approve.js / allowances.js.
import { encode } from './cde.js';
import { sha256 } from './profile.js';
import { jcs } from './signview.js';

export const TYP_ALLOWANCE = 'application/aar-allowance+cbor';
export const DEFAULT_DAYS = 1;          // 0.2.51: one day by default (was 30): one question, then 24 h of quiet in this project
export const MAX_DAYS = 30;          // r0271: the server's cap (allowances.MAX_DAYS); was a dead 90
// shown next to the checkbox; the same sentence as server/app/allowances.py TRUST_TEXT (a test keeps them equal)
export const TRUST_TEXT = "Allowing a command for this project means trusting the project's code: pytest, npm test, make, cargo test and go test run "
  + "the project's tests, conftest.py, plugins, scripts and build files, npm install and pip install -e . install the dependencies "
  + 'the project declares, and the agent can change those files. In practice the agent can then run code it wrote in this project '
  + 'without asking you when Witness could read what it wrote and that text does not reach the network, your keys or files outside this '
  + 'project. Dangerous commands the agent types (recursive delete, force-push, reading secrets, a download piped into a shell) are still '
  + "asked every time, and so is anything outside this project. Inside the project's code Witness looks for them too, but it cannot "
  + 'promise to find every one: allow only a project whose code you trust.';

// r0327 (law "Signed = shown"): the rule's `view` is the hash of the approval page's view AND of the text of trust shown next to the
// button, whole (server app/allowances.allow_view: {v, page, text_v, text}). The text is the server's offer.text (the page shows exactly it).
export const ALLOW_VIEW_V = 'dw-allow-view-1';
export function trustTextOf(offer) {
  return offer && typeof offer.text === 'string' && offer.text ? offer.text : TRUST_TEXT;
}
export function allowView(pageView, offer) {
  if (!pageView || typeof pageView !== 'object') throw new Error('no page view');
  if (!offer || typeof offer.text !== 'string' || !offer.text || typeof offer.text_v !== 'string' || !offer.text_v) throw new Error('the offer names no text of trust');
  return { v: ALLOW_VIEW_V, page: pageView, text_v: offer.text_v, text: offer.text };
}
export async function allowViewHash(pageView, offer) {
  return sha256(new TextEncoder().encode(jcs(allowView(pageView, offer))));
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function newAllowanceId(rand = (n) => crypto.getRandomValues(new Uint8Array(n))) {
  const b = rand(16);
  let bits = 0, v = 0, out = '';
  for (const x of b) { v = ((v << 8) | x) & 0x1fff; bits += 8; while (bits >= 5) { out += B32[(v >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(v << (5 - bits)) & 31];
  return 'al_' + out.slice(0, 26);
}

// days: 1 | 7 | 30 | 90; nowS: the witness time (offer.t plus the seconds since the page got it)
// pv2: view = the presentation hash of the approval page (signview.js) or null (then the permission is marked "view not signed")
export async function allowancePayload(offer, mandate, days, nowS, id, view = null) {
  const d = Math.max(1, Math.min(MAX_DAYS, Math.floor(Number(days) || DEFAULT_DAYS)));
  const nbf = Math.floor(nowS);
  const a = {
    v: 'deus-aar-0.1', t: 'allowance', id, mandate: await sha256(encode(mandate)), class: 'command',
    commands: offer.commands.slice(), project: offer.project, nbf, exp: nbf + d * 86400,
  };
  if (view != null) {
    if (!(view instanceof Uint8Array) || view.length !== 32) throw new Error('view must be 32 bytes');
    a.view = view;
  }
  return encode(a);
}

// what the checkbox says: {show, enabled, label, note}
export function offerView(offer) {
  if (!offer) return { show: false };
  if (!offer.eligible) return { show: !!offer.why_not, enabled: false, label: 'Allow this command in this project', note: 'Not possible here: ' + (offer.why_not || '') + '.' };
  const cmds = offer.commands.map((c) => '"' + c + '"').join(', ');
  return { show: true, enabled: true, label: 'Allow ' + cmds + ' in this project (' + offer.project + ') without asking', note: '' };
}

export function untilText(expS) {
  return new Date(expS * 1000).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export const STATUS_TEXT = { active: 'active', revoked: 'revoked', expired: 'expired', mandate_ended: 'ended: the mandate was replaced or revoked',
  branch_changed: 'ended: the project switched to another git branch' };
