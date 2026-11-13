// Profile draft-deus-aar-profile-webauthn-00: challenge (3.3), DER -> r||s low-S, envelope wa-sig (3.2).
import { encode, concat } from './cde.js';

const TE = new TextEncoder();
export const VERSION = 'deus-aar-wa-0.1';
export const TYP_MANDATE = 'application/aar-mandate+cbor';
export const TYP_APPROVAL = 'application/aar-approval+cbor';
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

// challenge = SHA-256("deus-aar-wa-0.1" || 0x00 || typ || 0x00 || payload)
export function challenge(typ, payload) {
  return sha256(concat([TE.encode(VERSION), Uint8Array.of(0), TE.encode(typ), Uint8Array.of(0), payload]));
}

function bigFromBytes(b) {
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  return x;
}
function bigToBytes32(x) {
  const o = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { o[i] = Number(x & 255n); x >>= 8n; }
  return o;
}

// DER ECDSA signature -> 64 bytes r||s, s replaced by n - s when s > n/2.
export function derToLowS(der) {
  let i = 0;
  const need = (c) => { if (!c) throw new Error('bad DER signature'); };
  need(der[i++] === 0x30);
  let len = der[i++];
  if (len & 0x80) { need((len & 0x7f) === 1); len = der[i++]; }
  need(len === der.length - i);
  const readInt = () => {
    need(der[i++] === 0x02);
    const l = der[i++];
    need(l > 0 && l < 128 && i + l <= der.length);
    const v = der.subarray(i, i + l);
    i += l;
    return bigFromBytes(v);
  };
  const r = readInt();
  let s = readInt();
  need(i === der.length);
  need(r > 0n && r < N && s > 0n && s < N);
  if (s > N >> 1n) s = N - s;
  return concat([bigToBytes32(r), bigToBytes32(s)]);
}

// payload of approval, -04 6.6: {v,t:"approval",receipt,mandate:SHA-256(CDE(mandate)),action:SHA-256(CDE(action)),approved}
// pv2810: view = SHA-256 of the JCS signing view the page showed (32 bytes, signview.js); a member only when given (else the 0.1 bytes)
export async function approvalPayload(rid, mandate, action, approved, view = null) {
  const p = {
    v: 'deus-aar-0.1', t: 'approval', receipt: rid,
    mandate: await sha256(encode(mandate)), action: await sha256(encode(action)), approved: !!approved,
  };
  if (view != null) {
    if (!(view instanceof Uint8Array) || view.length !== 32) throw new Error('view must be 32 bytes');
    p.view = view;
  }
  return encode(p);
}

// wa-sig envelope, exactly 7 members, CDE order is produced by the encoder.
export function buildEnvelope({ typ, kid, payload, authData, clientDataJSON, sig }) {
  if (kid.length !== 32 || sig.length !== 64) throw new Error('kid must be 32 bytes, sig 64 bytes');
  return encode({ v: VERSION, typ, kid, payload, authData, clientDataJSON, sig });
}
