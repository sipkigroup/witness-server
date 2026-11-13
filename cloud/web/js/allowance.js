// 0.2.10 (PROPOSAL-07): "Allow this command in this project" on the approval page, and the Project permissions page.
// The owner's device builds the allowance map itself (the mandate hash is computed here, as for an approval) and signs it with the passkey
// (typ application/aar-allowance+cbor); the server records it in the ledger. Pure functions here; the DOM part is in approve.js / allowances.js.
import { encode } from './cde.js';
import { sha256 } from './profile.js';

export const TYP_ALLOWANCE = 'application/aar-allowance+cbor';
export const DEFAULT_DAYS = 1;          // 0.2.51: one day by default (was 30): one question, then 24 h of quiet in this project
export const MAX_DAYS = 90;
// shown next to the checkbox; the same sentence as server/app/allowances.py TRUST_TEXT (a test keeps them equal)
export const TRUST_TEXT = "Allowing a command for this project means trusting the project's code: pytest, npm test, make, cargo test and go test run "
  + "the project's tests, conftest.py, plugins, scripts and build files, npm install and pip install -e . install the dependencies "
  + 'the project declares, and the agent can change those files. In practice the agent can then run code it wrote in this project '
  + 'without asking you. Dangerous commands (recursive delete, force-push, reading secrets, a download piped into a shell) are still '
  + 'asked every time, and so is anything outside this project.';

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

export const STATUS_TEXT = { active: 'active', revoked: 'revoked', expired: 'expired', mandate_ended: 'ended: the mandate was replaced or revoked' };
