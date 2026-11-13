// Sign a -04 payload with the pinned passkey: browser computes challenge itself (profile 3.3).
import { challenge, derToLowS, buildEnvelope } from './profile.js';
import { assertOver, b64uEnc } from './webauthn.js';
import { hexToBytes } from './cde.js';
import { wbChallenge, buildWb } from './wb.js';

// 0.2.2: the passkeys that may sign here (me.signing_keys: [{kid_hex, credential_id_b64}]); an older server: the keycard only.
export function signingKeys(me) {
  const ks = (me.signing_keys && me.signing_keys.length) ? me.signing_keys : [me.keycard];
  return ks.map((k) => ({ kid_hex: k.kid_hex, credential_id_b64: k.credential_id_b64 }));
}
// the kid of the passkey the browser actually used (rawId)
export function kidOfAssertion(keys, rawId) {
  const k = keys.find((x) => x.credential_id_b64 === rawId) || (keys.length === 1 ? keys[0] : null);
  if (!k) throw new Error('The passkey you used is not one that may sign here. Use the one listed in Devices.');
  return hexToBytes(k.kid_hex);
}

// me = GET /api/me ({keycard:{kid_hex, credential_id_b64, rp_id}, signing_keys})
export async function signPayload(typ, payload, me, keys) {
  const ks = keys || signingKeys(me);
  const ch = await challenge(typ, payload);
  const a = await assertOver(ch, me.keycard.rp_id, ks.map((k) => k.credential_id_b64));
  const sig = derToLowS(a.signature);
  const env = buildEnvelope({ typ, kid: kidOfAssertion(ks, a.rawId), payload, authData: a.authData, clientDataJSON: a.clientDataJSON, sig });
  return b64uEnc(env);
}

// One passkey ceremony over a batch (ARHITEKTURA-0.2 3.3): items = SHA-256 of each approval (or 0.2.2: revocation) payload.
export async function signBatch(items, me, typ) {
  const ks = signingKeys(me);
  const a = await assertOver(await wbChallenge(items, typ), me.keycard.rp_id, ks.map((k) => k.credential_id_b64));
  const env = buildWb({ items, kid: kidOfAssertion(ks, a.rawId), authData: a.authData, clientDataJSON: a.clientDataJSON, sig: derToLowS(a.signature), typ });
  return b64uEnc(env);
}
