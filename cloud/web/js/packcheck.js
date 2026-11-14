// P0-2: evidence-pack checker that runs in the browser (and in node for the tests). It shares no code with the server:
// its own CBOR decoder (with the canonical-form check), COSE_Sign1 Ed25519 through WebCrypto, the SHA-256 hash chain of the
// ledger, RFC 6962-style Merkle roots of checkpoints, receipt inclusion and the checkpoint's inclusion in an anchor batch.
// What it does NOT check (the Python checker verify_pack.py does): the owner's passkey signatures (WebAuthn) on mandates and
// approvals, re-evaluating each decision against the mandate, the Bitcoin (OpenTimestamps) and RFC 3161 stamps, team policies.
// API: checkPack(read) where read(path) -> Promise<Uint8Array> of a file of the unpacked pack. -> {ok, lines, ledger}
import { encode as cde, bytesToHex, hexToBytes, concat } from './cde.js';

export const TYP_ENTRY = 'application/aar-ledger-entry+cbor';
export const TYP_AAR = 'application/aar-receipt+cbor';
export const TYP_CHECKPOINT = 'application/aar-checkpoint+cbor';
export const TYP_MANIFEST = 'application/deus-witness-pack-manifest+cbor';
const ENTRY_TYPES = ['MANDATE', 'CEILING', 'REVOCATION', 'RECEIPT', 'APPROVAL', 'CONSUME', 'RELEASE', 'REFUND', 'CHECKPOINT'];
const TE = new TextEncoder();
const subtle = globalThis.crypto.subtle;

export class CborError extends Error {}

// ---------------- CBOR (RFC 8949): definite lengths, no floats; canonical = shortest heads + map keys sorted by encoded bytes
// (shorter first, then bytewise: the order of cbor2 canonical=True / js/cde.js); a duplicate key is an error.
function cmpKey(a, b) {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

export function decode(b, { canonical = true } = {}) {
  let i = 0;
  const need = (n) => { if (i + n > b.length) throw new CborError('truncated'); };
  const arg = (ai) => {
    if (ai < 24) return BigInt(ai);
    const n = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : ai === 27 ? 8 : -1;
    if (n < 0) throw new CborError('indefinite or reserved length');
    need(n);
    let x = 0n;
    for (let k = 0; k < n; k++) x = (x << 8n) | BigInt(b[i++]);
    if (canonical && x < (n === 1 ? 24n : n === 2 ? 256n : n === 4 ? 65536n : 4294967296n)) throw new CborError('not shortest form');
    return x;
  };
  const num = (x) => (x <= BigInt(Number.MAX_SAFE_INTEGER) && x >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(x) : x);
  let depth = 0;
  const item = () => {
    if (++depth > 64) throw new CborError('too deep');
    need(1);
    const ib = b[i++], mt = ib >> 5, ai = ib & 31;
    let v;
    if (mt === 7) {
      if (ai === 20) v = false; else if (ai === 21) v = true; else if (ai === 22) v = null; else throw new CborError('simple/float');
    } else {
      const n = arg(ai);
      if (mt === 0) v = num(n);
      else if (mt === 1) v = num(-1n - n);
      else if (mt === 2) { need(Number(n)); v = b.slice(i, i + Number(n)); i += Number(n); }
      else if (mt === 3) { need(Number(n)); v = new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(i, i + Number(n))); i += Number(n); }
      else if (mt === 4) { v = []; for (let k = 0n; k < n; k++) v.push(item()); }
      else if (mt === 5) {
        v = new Map();
        let prev = null;
        for (let k = 0n; k < n; k++) {
          const s = i, key = item(), kb = b.subarray(s, i);
          if (typeof key !== 'string' && typeof key !== 'number') throw new CborError('map key type');
          if (v.has(key)) throw new CborError('duplicate key');
          if (canonical && prev && cmpKey(prev, kb) >= 0) throw new CborError('map keys not in canonical order');
          prev = kb;
          v.set(key, item());
        }
      } else if (mt === 6) v = { tag: num(n), value: item() };
      else throw new CborError('major type');
    }
    depth--;
    return v;
  };
  const v = item();
  if (i !== b.length) throw new CborError('trailing bytes');
  return v;
}

// Map -> plain object (text keys) for the JSON-shaped bodies; byte strings stay Uint8Array.
export function plain(x) {
  if (x instanceof Map) { const o = {}; for (const [k, v] of x) o[k] = plain(v); return o; }
  if (Array.isArray(x)) return x.map(plain);
  return x;
}

// ---------------- crypto
export async function sha256(b) { return new Uint8Array(await subtle.digest('SHA-256', b)); }
export const eq = (a, b) => a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((x, k) => x === b[k]);

// RFC 9679 thumbprint of an Ed25519 COSE_Key {1: 1, -1: 6, -2: x}: canonical order 1, -1, -2
export async function kidOf(pub) {
  if (!(pub instanceof Uint8Array) || pub.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
  return sha256(concat([Uint8Array.of(0xa3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20), pub]));
}

export async function witnessKey(pubHex) {
  const pub = hexToBytes(pubHex);
  let key;
  try { key = await subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']); }
  catch (e) { throw new Error('this browser has no Ed25519 in WebCrypto (Chrome 137+, Firefox 129+, Safari 17+); use the command below'); }
  return { pub, key, kid: await kidOf(pub) };
}

// r0286 (crypto agility, POSTKVANT-1311): the witness key algorithms this page verifies -- manifest name -> COSE alg id. Another name
// (e.g. a future ML-DSA-65, COSE -49) is "CANNOT CHECK" + RESULT: NOT PROVEN: never VALID, never a crash.
export const WITNESS_ALGS = new Map([['EdDSA', -8]]);

// COSE_Sign1 (RFC 9052), witness key only: tag 18, protected = canonical map with alg -8 and kid, typ as asked, payload canonical.
export async function verify1(data, wk, typ) {
  const t = decode(data, { canonical: false });
  if (!t || t.tag !== 18 || !Array.isArray(t.value) || t.value.length !== 4) throw new Error('MALFORMED');
  const [pb, un, payload, sig] = t.value;
  if (!(pb instanceof Uint8Array) || !(un instanceof Map) || !(payload instanceof Uint8Array) || !(sig instanceof Uint8Array)) throw new Error('MALFORMED');
  let prot;
  try { prot = decode(pb); } catch (e) { throw new Error('MALFORMED'); }
  if (!(prot instanceof Map) || !prot.has(1) || !prot.has(4)) throw new Error('MALFORMED');
  if (typ && prot.get(16) !== typ) throw new Error('TYP_MISMATCH');
  if (!eq(prot.get(4), wk.kid)) throw new Error('KID_UNKNOWN');
  if (prot.get(1) !== WITNESS_ALGS.get('EdDSA')) throw new Error('ALG_MISMATCH');
  const tbs = cde(['Signature1', pb, new Uint8Array(0), payload]);
  if (!(await subtle.verify({ name: 'Ed25519' }, wk.key, sig, tbs))) throw new Error('SIGNATURE_INVALID');
  let body;
  try { body = decode(payload); } catch (e) { throw new Error('MALFORMED'); }
  return { body, prot };
}

// ---------------- Merkle (svidetel_v4/checkpoint.py): leaf = H(0x00 || x), node = H(0x01 || l || r), split at the largest power of 2 < n
const leafH = (x) => sha256(concat([Uint8Array.of(0), x]));
const nodeH = (l, r) => sha256(concat([Uint8Array.of(1), l, r]));
function split(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }

export async function merkleRoot(leaves) {
  if (!leaves.length) return sha256(new Uint8Array(0));
  const rec = async (ls) => (ls.length === 1 ? leafH(ls[0]) : nodeH(await rec(ls.slice(0, split(ls.length))), await rec(ls.slice(split(ls.length)))));
  return rec(leaves);
}

export function pathSides(index, size) {
  if (size === 1) return [];
  const k = split(size);
  return index < k ? [...pathSides(index, k), 'R'] : [...pathSides(index - k, size - k), 'L'];
}

export async function verifyInclusion(leaf, path, root, index, size) {
  if (JSON.stringify(path.map((x) => x[0])) !== JSON.stringify(pathSides(index, size))) return false;
  let h = await leafH(leaf);
  for (const [side, sib] of path) h = side === 'R' ? await nodeH(h, sib) : await nodeH(sib, h);
  return eq(h, root);
}

// ---------------- the pack
const SAFE = /^(?!\/)(?!.*(^|\/)\.\.?(\/|$))[A-Za-z0-9._\/-]{1,200}$/;
const json = (b) => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(b));
const stable = (x) => (Array.isArray(x) ? '[' + x.map(stable).join(',') + ']' : x && typeof x === 'object'
  ? '{' + Object.keys(x).sort().map((k) => JSON.stringify(k) + ':' + stable(x[k])).join(',') + '}' : JSON.stringify(x));

export async function checkPack(read) {
  const lines = [];
  let ok = true;
  const say = (s, good = true) => { lines.push(s); if (!good) ok = false; };
  const fail = (why) => { say('pack: ' + why, false); lines.push('RESULT: INVALID'); return { ok: false, lines }; };
  let man;
  try { man = json(await read('manifest.json')); } catch (e) { return fail('no readable manifest.json'); }
  if (!man || typeof man.files !== 'object' || !man.witness) return fail('manifest malformed');
  // 0. every file of the manifest
  let bad = 0;
  const files = {};
  for (const [p, h] of Object.entries(man.files)) {
    if (!SAFE.test(p)) { say('manifest: PATH OUTSIDE PACK ' + JSON.stringify(p), false); bad++; continue; }
    let b;
    try { b = await read(p); } catch (e) { say('manifest: MISSING ' + p, false); bad++; continue; }
    files[p] = b;                            // a mismatching file is still checked below: the reader sees WHAT is wrong in it
    if (bytesToHex(await sha256(b)) !== h) { say('manifest: MISMATCH ' + p, false); bad++; }
  }
  say('manifest: ' + (bad ? bad + ' problems' : 'ok') + ' (' + Object.keys(man.files).length + ' files)', !bad);
  const walg = man.witness.alg === undefined ? 'EdDSA' : man.witness.alg;      // absent in old packs = EdDSA
  if (!WITNESS_ALGS.has(walg)) {
    say('witness: CANNOT CHECK (key algorithm ' + JSON.stringify(walg) + ' is not one this page verifies: ' + [...WITNESS_ALGS.keys()].join(', ') + ')', false);
    lines.push(bad ? 'RESULT: INVALID' : 'RESULT: NOT PROVEN');
    return { ok: false, lines };
  }
  let wk;
  try { wk = await witnessKey(man.witness.pub_hex); } catch (e) { return fail(e.message); }
  if (bytesToHex(wk.kid) !== man.witness.kid_hex) say('witness: kid does not match pub', false);
  // the signed manifest: file hashes + the checkpoint the ledger must end with
  let signed = null;
  try {
    signed = plain((await verify1(await read('manifest.cose'), wk, TYP_MANIFEST)).body);
    const a = Object.entries(signed.files || {}).sort(), b = Object.entries(man.files).sort();
    if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error('files differ');
    say('manifest: signed by the witness key');
  } catch (e) { signed = null; say('manifest: SIGNATURE INVALID (' + e.message + ')', false); }
  // registry log: hash chain
  let reg;
  try { reg = json(files['registry.json'] || await read('registry.json')); } catch (e) { return fail('no registry.json'); }
  let prev = '', chainOk = Array.isArray(reg.log) && reg.log.length > 0;
  for (const r of reg.log || []) {
    if (r.prev !== prev) chainOk = false;
    if ('entry_json' in r && bytesToHex(await sha256(concat([hexToBytes(r.prev), TE.encode(r.entry_json)]))) !== r.hash) chainOk = false;
    prev = r.hash;
  }
  const own = (reg.log || []).filter((r) => 'entry_json' in r);
  if (!own.length || stable(JSON.parse(own.at(-1).entry_json)) !== stable(reg.entry)) chainOk = false;
  say('registry: ' + (chainOk ? 'chain ok' : 'CHAIN BROKEN') + ' (' + (reg.log || []).length + ' rows)', chainOk);
  // 1. the ledger: witness signature on every entry, seq, prev = hash of the previous entry, ledger id, time order
  const raw = files['ledger/ledger.cose'];
  if (!raw) return fail('no ledger');
  const lid = await sha256(concat([TE.encode('deus-aar/ledger/' + reg.principal), wk.kid]));
  const entries = [];
  let why = null;
  const rows = new TextDecoder().decode(raw).split('\n').filter((x) => x.length);
  for (let k = 0; k < rows.length && !why; k++) {
    let cose;
    try { cose = hexToBytes(rows[k]); } catch (e) { why = 'MALFORMED@' + k; break; }
    let e;
    try { e = (await verify1(cose, wk, TYP_ENTRY)).body; } catch (x) { why = x.message + '@' + k; break; }
    const hash = await sha256(cose);
    if (e.get('seq') !== k || !eq(e.get('ledger'), lid) || (k === 0 ? e.get('prev') !== null : !eq(e.get('prev'), entries[k - 1].hash))) why = 'CHAIN_BREAK@' + k;
    else if (!ENTRY_TYPES.includes(e.get('type')) || typeof e.get('t') !== 'number' || (k && e.get('t') < entries[k - 1].t)) why = 'MALFORMED@' + k;
    entries.push({ seq: k, type: e.get('type'), t: e.get('t'), body: e.get('body'), hash });
  }
  const hashes = entries.map((x) => x.hash);
  for (const x of entries) {                 // a CHECKPOINT entry names the head and the Merkle root of the entries before it
    if (why || x.type !== 'CHECKPOINT') continue;
    const s = x.body.get('seq');
    if (!(s < x.seq) || !eq(x.body.get('head'), hashes[s]) || !eq(x.body.get('root'), await merkleRoot(hashes.slice(0, s + 1)))) why = 'CHECKPOINT@' + x.seq;
  }
  say(why ? 'ledger: invalid ' + why : 'ledger: valid (' + entries.length + ' entries, every one signed by the witness, hash chain unbroken)', !why);
  if (signed) {
    const last = entries.at(-1);
    const fine = signed.cp_seq == null ? !entries.length
      : !!last && last.type === 'CHECKPOINT' && last.body.get('seq') === signed.cp_seq && eq(last.body.get('head'), signed.cp_head);
    say(fine ? 'complete as of ' + new Date(signed.created_t * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC (seq ' + signed.cp_seq + ')'
      : 'pack: INCOMPLETE (the ledger does not end with the checkpoint the signed manifest names)', fine);
  }
  // 2. checkpoint files: signature, head and Merkle root over the entries
  const cps = Object.keys(files).filter((p) => /^checkpoints\/\d+\.cose$/.test(p));
  const cpLeaves = new Set();
  for (const p of cps) {
    let fine = false;
    try {
      const c = (await verify1(files[p], wk, TYP_CHECKPOINT)).body;
      const s = c.get('seq');
      fine = s < entries.length && eq(c.get('head'), hashes[s]) && eq(c.get('root'), await merkleRoot(hashes.slice(0, s + 1)));
      cpLeaves.add(bytesToHex(await sha256(files[p])));
    } catch (e) { fine = false; }
    if (!fine) say('checkpoint ' + p + ': INVALID', false);
  }
  say('checkpoints: ' + cps.length);
  // 3. receipts: witness-signed AAR, subject = file name, equal to the RECEIPT entry it names
  const rcs = Object.keys(files).filter((p) => /^receipts\/r_[A-Z2-7]+\.aar\.cose$/.test(p));
  let inc = 0;
  for (const p of rcs) {
    const rid = p.slice('receipts/'.length, -'.aar.cose'.length);
    try {
      const { body, prot } = await verify1(files[p], wk, TYP_AAR);
      const ch = body.get('chain'), e = entries[ch.get('seq')];
      const cwt = prot.get(15);
      if (cwt instanceof Map && cwt.get(2) === rid && e && e.type === 'RECEIPT' && e.body.get('id') === rid && eq(e.hash, ch.get('entry'))) { inc++; continue; }
    } catch (e) { /* not included */ }
    say('receipt ' + rid + ': NOT INCLUDED', false);
  }
  say('receipts: ' + inc + '/' + rcs.length + ' included', inc === rcs.length);
  // 4. anchors: the checkpoint is a leaf of the hourly batch root (the root's Bitcoin / RFC 3161 stamps are not checked here)
  for (const p of Object.keys(files).filter((x) => /^anchors\/[^/]+\.json$/.test(x))) {
    let good = false, a = {};
    try {
      a = json(files[p]);
      good = cpLeaves.has(a.leaf) && await verifyInclusion(hexToBytes(a.leaf), a.path.map(([s, h]) => [s, hexToBytes(h)]), hexToBytes(a.root), a.leaf_index, a.size);
    } catch (e) { good = false; }
    say('anchor ' + (a.batch || p) + ': ' + (good ? 'checkpoint included in the batch root (' + (a.status === 'off' ? 'root not sent to Bitcoin in this demo' : 'stamp: ' + a.status + ', not checked here') + ')'
      : 'MISMATCH (checkpoint is not under the batch root)'), good);
  }
  lines.push(ok ? 'RESULT: VALID' : 'RESULT: INVALID');
  return { ok, lines, entries, wk };
}

// The decision feed (feed.json, NOT signed) against the checked ledger: what the witness recorded for each rid.
export function crossCheck(items, entries) {
  const byRid = new Map(), consumed = new Set(), approved = new Set();
  for (const e of entries || []) {
    if (e.type === 'RECEIPT') byRid.set(e.body.get('id'), e);
    if (e.type === 'CONSUME') consumed.add(e.body.get('receipt'));
    if (e.type === 'APPROVAL' && e.body.get('approved') === true) approved.add(e.body.get('receipt'));
  }
  return items.map((it) => {
    const e = byRid.get(it.rid);
    if (it.actor === 'owner') return { ...it, inLedger: approved.has(it.rid), ledgerVerdict: approved.has(it.rid) ? 'approve' : null };
    if (!e) return { ...it, inLedger: false, ledgerVerdict: null };
    // after an approval the RECEIPT keeps the recorded defer; the approved receipt is the one that was consumed
    const lv = e.body.get('verdict'), lr = e.body.get('reason');
    const fine = (lv === it.verdict && lr === it.reason) || (it.reason === 'OK_APPROVED' && approved.has(it.rid) && consumed.has(it.rid));
    return { ...it, inLedger: fine, ledgerVerdict: lv, ledgerReason: lr, ledgerTool: e.body.get('action') && e.body.get('action').get('class'),
      consumed: consumed.has(it.rid) };
  });
}
