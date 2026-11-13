// Core Deterministic Encoding (RFC 8949 4.2.1) for the profile subset:
// uint, negative int, text, bytes, array, map with text keys, true/false/null.
// Float (non-integer Number), undefined, other types -> throws.
// Map keys are sorted by their encoded bytes (shorter first, then bytewise), as the reference does.
const TE = new TextEncoder();

function head(major, n) {
  // n: BigInt >= 0
  const m = major << 5;
  if (n < 24n) return Uint8Array.of(m | Number(n));
  if (n < 256n) return Uint8Array.of(m | 24, Number(n));
  if (n < 65536n) return Uint8Array.of(m | 25, Number(n >> 8n), Number(n & 255n));
  if (n < 4294967296n) {
    const o = new Uint8Array(5); o[0] = m | 26;
    for (let i = 0; i < 4; i++) o[1 + i] = Number((n >> BigInt(8 * (3 - i))) & 255n);
    return o;
  }
  if (n < 18446744073709551616n) {
    const o = new Uint8Array(9); o[0] = m | 27;
    for (let i = 0; i < 8; i++) o[1 + i] = Number((n >> BigInt(8 * (7 - i))) & 255n);
    return o;
  }
  throw new RangeError('CDE: integer out of range');
}

function concat(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const o = new Uint8Array(len);
  let k = 0;
  for (const p of parts) { o.set(p, k); k += p.length; }
  return o;
}

function cmp(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

export function encode(v, top = true) {
  if (v === null) return Uint8Array.of(0xf6);
  if (v === true) return Uint8Array.of(0xf5);
  if (v === false) return Uint8Array.of(0xf4);
  if (typeof v === 'bigint') return v >= 0n ? head(0, v) : head(1, -1n - v);
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new TypeError('CDE: floats and unsafe integers are not allowed');
    return v >= 0 ? head(0, BigInt(v)) : head(1, BigInt(-1 - v));
  }
  if (typeof v === 'string') {
    const b = TE.encode(v); // UTF-8, no normalisation
    return concat([head(3, BigInt(b.length)), b]);
  }
  if (v instanceof Uint8Array) return concat([head(2, BigInt(v.length)), v]);
  if (Array.isArray(v)) return concat([head(4, BigInt(v.length)), ...v.map((x) => encode(x, false))]);
  if (v && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype) {
    // 0.2.4 (draft-deus-aar-05 8.6): the JSON wire form of the bstr member `toolmap_sha256` is 64 lower-case hex; in the signed bytes it is `bstr .size 32`.
    // 0.2.5 (R4-03): converted ONLY as a member of the top-level map (the mandate / the action), never deeper: the server does the same (app/wire.py), so a nested member of that name hashes alike on both sides.
    const items = Object.keys(v).map((k) => [encode(k, false), encode(top && k === 'toolmap_sha256' && typeof v[k] === 'string' && /^[0-9a-f]{64}$/.test(v[k]) ? hexToBytes(v[k]) : v[k], false)]);
    items.sort((a, b) => cmp(a[0], b[0]));
    return concat([head(5, BigInt(items.length)), ...items.flat()]);
  }
  throw new TypeError('CDE: unsupported type ' + typeof v);
}

// JSON value from vectors/cde: {"$bytes": "<hex>"} -> Uint8Array
export function fromVectorJson(x) {
  if (Array.isArray(x)) return x.map(fromVectorJson);
  if (x && typeof x === 'object') {
    const ks = Object.keys(x);
    if (ks.length === 1 && ks[0] === '$bytes') return hexToBytes(x.$bytes);
    const o = {};
    for (const k of ks) o[k] = fromVectorJson(x[k]);
    return o;
  }
  return x;
}

export function hexToBytes(h) {
  if (h.length % 2) throw new Error('odd hex');
  const o = new Uint8Array(h.length / 2);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(2 * i, 2), 16);
  return o;
}
export function bytesToHex(b) {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}
export { concat };
