// "Revoke mandate": one signature of any signer stops it (ARHITEKTURA-0.2 0.3, rule revocation {any, 1}).
import { post } from './api.js';
import { revocationPayload, TYP_REVOCATION } from './policy.js';
import { signPayload } from './sign.js';

// row = an item of GET /api/mandates ({id, mandate, status})
export async function revokeMandate(row, me) {
  const payload = await revocationPayload(row.mandate);
  const envelope_b64 = await signPayload(TYP_REVOCATION, payload, me);
  return post('/api/mandates/' + encodeURIComponent(row.id) + '/revoke', { envelope_b64 });
}
