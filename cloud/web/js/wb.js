// Batch approval envelope wb (ARHITEKTURA-0.2 3.3). The browser computes items from its OWN CDE of each approval payload
// and the challenge from those items; the server only sends fields (rid, mandate, action).
import { encode, concat } from './cde.js';
import { sha256, approvalPayload, TYP_APPROVAL } from './profile.js';

const TE = new TextEncoder();
export const V_WB = 'deus-aar-wb-0.1';
export const MAX_ITEMS = 20;

export const TYP_REVOCATION = 'application/aar-revocation+cbor';

// challenge = SHA-256("deus-aar-wb-0.1" || 0x00 || typ || 0x00 || CDE(items)); typ = approval, or (0.2.2) revocation
export function wbChallenge(items, typ = TYP_APPROVAL) {
  if (typ !== TYP_APPROVAL && typ !== TYP_REVOCATION) throw new Error('a batch is an approval or a revocation');
  return sha256(concat([TE.encode(V_WB), Uint8Array.of(0), TE.encode(typ), Uint8Array.of(0), encode(items)]));
}

// rows: [{rid, mandate, action}] -> {payloads, items}; refuses > 20, duplicates (ZAMECHANIYA 00 #10) and an empty list.
export async function batchItems(rows, approved = true) {
  if (!rows.length || rows.length > MAX_ITEMS) throw new Error('A batch holds 1 to ' + MAX_ITEMS + ' items.');
  const payloads = [], items = [], seen = new Set();
  for (const r of rows) {
    const p = await approvalPayload(r.rid, r.mandate, r.action, approved, r.view || null);     // pv2: each item's own view, when the page has it
    const it = await sha256(p);
    const key = Array.from(it).join(',');
    if (seen.has(key)) throw new Error('The same item twice in one batch: ' + r.rid);
    seen.add(key); payloads.push(p); items.push(it);
  }
  return { payloads, items };
}

// wb envelope, exactly 7 members; key order is produced by the CDE encoder.
export function buildWb({ items, kid, authData, clientDataJSON, sig, typ = TYP_APPROVAL }) {
  if (kid.length !== 32 || sig.length !== 64) throw new Error('kid must be 32 bytes, sig 64 bytes');
  if (!items.length || items.length > MAX_ITEMS || items.some((x) => x.length !== 32)) throw new Error('items: 1..20 hashes of 32 bytes');
  if (typ !== TYP_APPROVAL && typ !== TYP_REVOCATION) throw new Error('a batch is an approval or a revocation');
  return encode({ v: V_WB, typ, items, kid, authData, clientDataJSON, sig });
}

// A batch group must be homogeneous (3.3): one agent, one class, one recipient/channel. Returns null or the reason.
export function mixedReason(rows) {
  const f = rows[0];
  if (!f) return 'empty';
  for (const r of rows) {
    if (r.agent_id !== f.agent_id) return 'different agents';
    if (r.action.class !== f.action.class) return 'different action classes';
    if (String(r.action.recipient) !== String(f.action.recipient)) return 'different recipients or channels';
  }
  return null;
}
