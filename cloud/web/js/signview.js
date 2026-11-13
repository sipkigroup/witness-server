// pv2810: the signing view (presentation hash). The approval page hashes what it shows -- the members of the server's answer it renders
// (action, recipient, danger mark, previews of the arguments, the text, the code and the changed files, the reason it waits) -- and the
// passkey signs that hash inside the approval / release payload. Same object and same hashing as server/app/signview.py:
// SHA-256 over the RFC 8785 (JCS) form of {v: "dw-view-1", <members below that the answer has>}.
import { sha256 } from './profile.js';
import { bytesToHex } from './cde.js';

export const VIEW_V = 'dw-view-1';
export const VIEW_KEYS = ['rid', 'status', 'tool', 'action', 'args_preview', 'text_preview', 'reason', 'adv', 'line_commands', 'net_code',
  'exec_changed', 'written_run', 'masked_dep', 'unseen_write', 'line_full', 'text_cut', 'what', 'harm', 'risk', 'details', 'omitted'];   // r0277 (P2): what the first screen does not show whole, built by the server   // 05.11: the question's plain words (qwords.py)   // 04.11 (Hypothesis I2): every command of a shell line, whole   // N4 29.10: unseen_write only when the answer has it   // 29.10 MDEP: masked_dep only when the answer has it (the view of an older row is as before)

// RFC 8785: members sorted by UTF-16 code units (JS string order), no white space, ECMAScript numbers and strings (JSON.stringify)
export function jcs(v) {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('JCS: not a finite number');
    if (Number.isInteger(v) && !Number.isSafeInteger(v)) throw new Error('JCS: integer outside the exact range');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  if (typeof v === 'object') {
    const ks = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    return '{' + ks.map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
  }
  throw new Error('JCS: ' + typeof v + ' is not JSON');
}

export function viewOf(r) {
  const v = { v: VIEW_V };
  for (const k of VIEW_KEYS) if (r && r[k] !== undefined && r[k] !== null) v[k] = r[k];
  return v;
}

export async function viewHash(r) {
  return sha256(new TextEncoder().encode(jcs(viewOf(r))));
}

// -> {view: Uint8Array(32) | null, hex, same}: the hash this page signs (only when the server binds the view: r.view_sha256 present)
export async function signedView(r) {
  if (!r || typeof r.view_sha256 !== 'string') return { view: null, hex: null, same: null };
  const view = await viewHash(r);
  const hex = bytesToHex(view);
  return { view, hex, same: hex === r.view_sha256 };
}
