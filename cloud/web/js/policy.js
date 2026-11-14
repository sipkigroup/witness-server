// Organisation policy 0.2 (ARHITEKTURA-0.2 2.2): map from server fields, CDE, hash, checks, requirements, words.
// Port of contract/v02/wq_profile.py (validate_policy, requirements); the browser computes every hash itself (3.7).
import { encode, hexToBytes, bytesToHex, concat } from './cde.js';
import { sha256 } from './profile.js';
import { fmtMoney } from './ui.js';

export const V_POLICY = 'dw-org-policy-0.1';
export const TYP_POLICY = 'application/dw-org-policy+cbor';
export const TYP_REVOCATION = 'application/aar-revocation+cbor';
export const TYP_RELEASE = 'application/dw-release+cbor';
export const TYP_PHONE_LIFT = 'application/dw-phone-lift+cbor';   // 0.2.15: the team ends the wait of a recovery-declared phone
export const V_PHONE_LIFT = 'dw-phone-lift-0.1';
const DELEGATION_KEYS = ['agent', 'operator', 'approvers', 'until'], MAX_DELEGATIONS = 64, MAX_AGENT_ID = 64;
export const ROLES = ['owner', 'budget', 'access'];
export const MONEY = ['purchase', 'sale', 'refund'];
export const NONMONEY = ['message', 'file', 'disclosure', 'delete', 'publish', 'meeting', 'command', 'http'];   // command: PROPOSAL-06; http: PROPOSAL-08-http
const MAX_MEMBERS = 16, MAX_LABEL = 32;
const POLICY_KEYS = ['v', 'principal', 'ver', 'prev', 'members', 'rules'];
const MEMBER_KEYS = ['kid', 'pub', 'cred', 'roles', 'label'];
const RULE_KEYS = ['policy', 'mandate', 'approval', 'revocation', 'ceiling'];
const RULE_OF_TYP = { 'application/aar-mandate+cbor': 'mandate', 'application/aar-approval+cbor': 'approval', [TYP_REVOCATION]: 'revocation', 'application/aar-ceiling+cbor': 'ceiling', [TYP_POLICY]: 'policy' };

const isB = (x, n) => x instanceof Uint8Array && (n === undefined || x.length === n);
const uint = (x) => Number.isSafeInteger(x) && x >= 0;
const sameKeys = (o, ks) => o && typeof o === 'object' && !Array.isArray(o) && !(o instanceof Uint8Array) && Object.keys(o).length === ks.length && ks.every((k) => k in o);
function cmpB(a, b) { const n = Math.min(a.length, b.length); for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; }

// Server JSON (bytes as hex, openapi-0.2 PolicyJson) -> policy map with Uint8Array members.
export function policyFromJson(j) {
  return {
    v: j.v, principal: j.principal, ver: j.ver, prev: j.prev == null ? null : hexToBytes(j.prev),
    members: (j.members || []).map((m) => ({ kid: hexToBytes(m.kid), pub: hexToBytes(m.pub), cred: hexToBytes(m.cred), roles: [...m.roles], label: m.label })),
    rules: j.rules,
  };
}

// Build a policy map from fields; members are sorted by kid (2.2), roles keep the given order.
export function buildPolicy({ principal, ver, prev, members, rules }) {
  const ms = members.map((m) => ({ kid: m.kid, pub: m.pub, cred: m.cred, roles: [...m.roles], label: m.label }));
  ms.sort((a, b) => cmpB(a.kid, b.kid));
  return { v: V_POLICY, principal, ver, prev: prev == null ? null : prev, members: ms, rules };
}
export const encodePolicy = (p) => encode(p);
export async function policyHash(p) { return sha256(encode(p)); }

// RFC 9679 thumbprint of the EC2 P-256 COSE_Key {1:2, -1:1, -2:x, -3:y} in CDE (integer keys: 01, 20, 21, 22).
export async function thumbprint(pub) {
  if (!isB(pub, 65) || pub[0] !== 4) throw new Error('MALFORMED');
  return sha256(concat([Uint8Array.of(0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20), pub.subarray(1, 33), Uint8Array.of(0x22, 0x58, 0x20), pub.subarray(33)]));
}

function reqOk(r, allowed) { return sameKeys(r, ['role', 'k']) && allowed.includes(r.role) && uint(r.k) && r.k >= 1 && r.k <= MAX_MEMBERS; }
function tierOk(t) {
  if (!t || typeof t !== 'object' || !['money', 'money_over', 'access'].includes(t.if)) return false;
  const ks = ['if', 'role', 'k'].concat(t.if === 'money_over' ? ['amount'] : []);
  return sameKeys(t, ks) && ROLES.includes(t.role) && uint(t.k) && t.k >= 1 && t.k <= MAX_MEMBERS && (t.if !== 'money_over' || uint(t.amount));
}

// null when well formed, else 'POLICY_MALFORMED' (same rules as the reference, incl. unsatisfiable k).
export async function validatePolicy(p) {
  try {
    if (!sameKeys(p, POLICY_KEYS) || p.v !== V_POLICY) return 'POLICY_MALFORMED';
    if (typeof p.principal !== 'string' || !p.principal.startsWith('dw:') || p.principal.length < 4) return 'POLICY_MALFORMED';
    if (!uint(p.ver) || p.ver < 1) return 'POLICY_MALFORMED';
    if ((p.prev === null) !== (p.ver === 1) || (p.prev !== null && !isB(p.prev, 32))) return 'POLICY_MALFORMED';
    const ms = p.members;
    if (!Array.isArray(ms) || ms.length < 1 || ms.length > MAX_MEMBERS) return 'POLICY_MALFORMED';
    let last = null;
    for (const m of ms) {
      if (!sameKeys(m, MEMBER_KEYS)) return 'POLICY_MALFORMED';
      if (!isB(m.kid, 32) || !isB(m.pub, 65) || m.pub[0] !== 4 || !isB(m.cred)) return 'POLICY_MALFORMED';
      if (cmpB(await thumbprint(m.pub), m.kid) !== 0) return 'POLICY_MALFORMED';
      if (last && cmpB(m.kid, last) <= 0) return 'POLICY_MALFORMED';
      last = m.kid;
      const r = m.roles;
      if (!Array.isArray(r) || !r.length || new Set(r).size !== r.length || r.some((x) => !ROLES.includes(x))) return 'POLICY_MALFORMED';
      const lab = m.label;
      if (typeof lab !== 'string' || [...lab].length > MAX_LABEL || lab.includes('@') || [...lab].some((c) => c.codePointAt(0) < 32)) return 'POLICY_MALFORMED';
    }
    const rl = p.rules;
    const extra = Object.keys(rl || {}).filter((k) => !RULE_KEYS.includes(k));
    if (!rl || !RULE_KEYS.every((k) => k in rl) || extra.some((k) => k !== 'recovery' && k !== 'delegation')) return 'POLICY_MALFORMED';
    for (const k of ['policy', 'revocation', 'ceiling']) if (!reqOk(rl[k], ROLES.concat('any'))) return 'POLICY_MALFORMED';
    if (rl.revocation.role !== 'any' || rl.revocation.k !== 1) return 'POLICY_MALFORMED';   // law Z3: any ONE signer may stop
    for (const k of ['mandate', 'approval']) if (!Array.isArray(rl[k]) || !rl[k].every(tierOk)) return 'POLICY_MALFORMED';
    const holders = { any: ms.length };
    for (const r of ROLES) holders[r] = ms.filter((m) => m.roles.includes(r)).length;
    const reqs = [rl.policy, rl.revocation, rl.ceiling, ...rl.mandate, ...rl.approval];
    if (reqs.some((q) => q.k > holders[q.role])) return 'POLICY_MALFORMED';
    if ('recovery' in rl) {   // 0.2.2: k >= 2 OTHER members, reachable whichever one member is lost
      const rc = rl.recovery;
      if (!reqOk(rc, ROLES.concat('any')) || rc.k < 2) return 'POLICY_MALFORMED';
      for (const m of ms) if (ms.filter((o) => o !== m && (rc.role === 'any' || o.roles.includes(rc.role))).length < rc.k) return 'POLICY_MALFORMED';
    }
    if ('delegation' in rl && !delegationOk(rl.delegation, ms)) return 'POLICY_MALFORMED';
    return null;
  } catch (e) { return 'POLICY_MALFORMED'; }
}

// 0.2.15: rules.delegation (same rules as wq_profile._delegation_ok): sorted by agent, one entry per agent, kids as lowercase hex text,
// approvers null or sorted distinct member kids without the operator, until null or unix seconds.
const hexKid = (x) => typeof x === 'string' && /^[0-9a-f]{64}$/.test(x);
function delegationOk(dl, ms) {
  if (!Array.isArray(dl) || dl.length < 1 || dl.length > MAX_DELEGATIONS) return false;
  const kids = new Set(ms.map((m) => bytesToHex(m.kid)));
  let last = null;
  for (const d of dl) {
    if (!sameKeys(d, DELEGATION_KEYS)) return false;
    const a = d.agent;
    if (typeof a !== 'string' || a.length < 1 || a.length > MAX_AGENT_ID || [...a].some((c) => c.charCodeAt(0) < 33 || c.charCodeAt(0) > 126)) return false;
    if (last !== null && !(a > last)) return false;
    last = a;
    if (!hexKid(d.operator)) return false;
    const ap = d.approvers;
    if (ap !== null) {
      if (!Array.isArray(ap) || ap.length < 1 || ap.length > MAX_MEMBERS || !ap.every(hexKid)) return false;
      const srt = [...new Set(ap)].sort();
      if (srt.length !== ap.length || srt.some((k, i) => k !== ap[i]) || ap.includes(d.operator) || ap.some((k) => !kids.has(k))) return false;
    }
    if (d.until !== null && !uint(d.until)) return false;
  }
  return true;
}

// 0.2.15: the bytes the team signs to end the wait of a phone declared with a recovery code (wq_profile.phone_lift_payload)
export function phoneLiftPayload(b) {
  const kid = hexToBytes(b.kid), nonce = hexToBytes(b.nonce);
  if (b.v !== V_PHONE_LIFT || typeof b.principal !== 'string' || !isB(kid, 32) || !uint(b.not_before) || !isB(nonce, 16)) throw new Error('phone lift: bad fields');
  return encode({ v: V_PHONE_LIFT, principal: b.principal, kid, not_before: b.not_before, nonce });
}

const grant = (v) => v !== undefined && v !== null && v !== false;
function moneyLevel(perm) {
  if (perm === true) return Infinity;
  if (!perm || typeof perm !== 'object') return 0;
  return Math.max(0, ...['budget', 'max_per_action', 'min_price'].map((k) => perm[k]).filter(uint));
}

// [[role, k]] sorted by role, one entry per role (max k of the fired rules); same as wq_profile.requirements.
export function requirements(policy, typ, payload, action) {
  const rule = RULE_OF_TYP[typ], rules = policy.rules, out = {};
  const add = (role, k) => { out[role] = Math.max(out[role] || 0, k); };
  if (['revocation', 'ceiling', 'policy'].includes(rule)) add(rules[rule].role, rules[rule].k);
  else if (rule === 'mandate') {
    const perms = (payload && payload.permissions) || {};
    const money = MONEY.filter((c) => grant(perms[c]));
    const level = Math.max(0, ...money.map((c) => moneyLevel(perms[c])));
    const access = NONMONEY.some((c) => grant(perms[c]));
    for (const t of rules.mandate) {
      if ((t.if === 'money' && money.length) || (t.if === 'access' && access) || (t.if === 'money_over' && money.length && level > t.amount)) add(t.role, t.k);
    }
  } else if (rule === 'approval' && action) {
    const isMoney = MONEY.includes(action.class);
    const amount = uint(action.amount) ? action.amount : 0;
    for (const t of rules.approval) {
      if ((t.if === 'money' && isMoney) || (t.if === 'access' && !isMoney) || (t.if === 'money_over' && isMoney && amount > t.amount)) add(t.role, t.k);
    }
  }
  return Object.keys(out).sort().map((r) => [r, out[r]]);
}

// Who of the member list can meet [role,k]: same count rule as verify_wq (distinct kid with that role).
export function holders(policy, role) {
  return policy.members.filter((m) => role === 'any' || m.roles.includes(role));
}

const ROLE_WORD = { owner: 'owner', budget: 'budget signer', access: 'access signer', any: 'signer' };
const names = (ms) => ms.map((m) => m.label || bytesToHex(m.kid).slice(0, 8)).sort((a, b) => a.localeCompare(b)).join(', '); // stable for people, not kid order
function need(policy, role, k) {
  const hs = holders(policy, role);
  return k + ' of ' + hs.length + ' ' + ROLE_WORD[role] + (hs.length === 1 ? '' : 's') + ': ' + names(hs);
}
function tierText(policy, t, what, cur) {
  const head = t.if === 'money' ? what.money : t.if === 'money_over' ? what.over + ' ' + fmtMoney(t.amount, cur) : what.access;
  return head + ' - ' + (t.k === 1 ? 'signature' : 'signatures') + ' ' + need(policy, t.role, t.k);
}

// The current policy in words: [[label, text]] (e.g. "Purchases over 500.00 USD - signatures 2 of 3 budget signers: Anna, Boris, Vera").
export function describePolicy(policy, cur = 'USD') {
  const r = policy.rules, L = [];
  L.push(['Version', String(policy.ver) + (policy.prev ? ' (follows version ' + (policy.ver - 1) + ')' : ' (first)')]);
  L.push(['Members', policy.members.map((m) => (m.label || '?') + ' (' + m.roles.join(', ') + ')').join('; ')]);
  const M = { money: 'Mandates with purchases', over: 'Mandates with purchases over', access: 'Mandates with messages, files, deletes or publishing' };
  const A = { money: 'Approving a held purchase', over: 'Approving a held purchase over', access: 'Approving any other held action' };
  if (!r.mandate.length) L.push(['Mandates', 'no extra rule: one signature of any member']);
  for (const t of r.mandate) L.push(['Mandates', tierText(policy, t, M, cur)]);
  for (const t of r.approval) L.push(['Approvals', tierText(policy, t, A, cur)]);
  if (!r.approval.length) L.push(['Approvals', 'no extra rule: one signature of any member']);
  L.push(['Changing this policy', (r.policy.k === 1 ? 'signature ' : 'signatures ') + need(policy, r.policy.role, r.policy.k)]);
  L.push(['Revoking a mandate', (r.revocation.k === 1 ? 'signature ' : 'signatures ') + need(policy, r.revocation.role, r.revocation.k)]);
  L.push(['Ceiling', (r.ceiling.k === 1 ? 'signature ' : 'signatures ') + need(policy, r.ceiling.role, r.ceiling.k)]);
  for (const d of r.delegation || []) {     // 0.2.15: who runs which agent, who confirms for it
    const lab = (kh) => { const m = policy.members.find((x) => bytesToHex(x.kid) === kh); return m ? m.label : kh.slice(0, 8); };
    L.push(['Delegated agent ' + d.agent, 'run by ' + lab(d.operator) + ', who never confirms its actions; confirmed by '
      + (d.approvers ? d.approvers.map(lab).join(', ') : 'anyone the approval rule allows') + (d.until ? ' until ' + new Date(d.until * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : '')]);
  }
  L.push(['Replacing a lost key', r.recovery
    ? 'signatures ' + need(policy, r.recovery.role, r.recovery.k) + ' - never the lost key itself; only that key changes'
    : 'no recovery rule: only as a policy change (' + need(policy, r.policy.role, r.policy.k) + ')']);
  return L;
}

// [[role,k]] -> "2 budget signers + 1 access signer"
export function needsText(needs) {
  if (!needs.length) return 'one signature';
  return needs.map(([r, k]) => k + ' ' + ROLE_WORD[r] + (k === 1 ? '' : 's')).join(' + ');
}

// Revocation payload (-04 6.7): {v:"deus-aar-0.1", t:"revocation", mandate: SHA-256(CDE(mandate))}.
export async function revocationPayload(mandate) {
  return encode({ v: 'deus-aar-0.1', t: 'revocation', mandate: await sha256(encode(mandate)) });
}
// Release payload of an advisory hold (4.2): {rid, args_sha256 (32 bytes), release}.
// pv2810: view (32 bytes or 64 hex) = the presentation hash of the page; a member only when given
export function releasePayload(rid, argsSha256, release, view = null) {
  const a = typeof argsSha256 === 'string' ? hexToBytes(argsSha256) : argsSha256;
  const w = typeof view === 'string' ? hexToBytes(view) : view;
  if (!isB(a, 32) || typeof rid !== 'string' || typeof release !== 'boolean' || (w != null && !isB(w, 32))) throw new Error('release payload: bad fields');
  return encode(w != null ? { rid, args_sha256: a, release, view: w } : { rid, args_sha256: a, release });
}

// Editor of team.html -> rules map (2.2). overCents: threshold for money_over; overK: budget signatures above it;
// accK: access signatures for non-money mandates; polK: owner signatures to change the policy.
// recK (0.2.2): signatures of OTHER members that replace one member's lost key (rule recovery {any, recK}); 0 = no such rule.
export function rulesFromForm({ overCents, overK, accK, polK, recK = 0 }) {
  const money = [{ if: 'money', role: 'budget', k: 1 }];
  if (overK > 1) money.push({ if: 'money_over', amount: overCents, role: 'budget', k: overK });
  const r = {
    policy: { role: 'owner', k: polK }, revocation: { role: 'any', k: 1 }, ceiling: { role: 'owner', k: 1 },
    mandate: [...money, { if: 'access', role: 'access', k: accK }],
    approval: [...money.map((t) => ({ ...t })), { if: 'access', role: 'access', k: 1 }],
  };
  if (recK) r.recovery = { role: 'any', k: recK };
  return r;
}
// Inverse for prefilling the editor from the current policy (values the editor does not express fall back to defaults).
export function formFromRules(r) {
  const over = (r.mandate || []).find((t) => t.if === 'money_over');
  const acc = (r.mandate || []).find((t) => t.if === 'access');
  return { overCents: over ? over.amount : 50000, overK: over ? over.k : 1, accK: acc ? acc.k : 1, polK: r.policy ? r.policy.k : 1,
    ...(r.recovery ? { recK: r.recovery.k } : {}) };      // 0.2.2: recK only when the policy has the rule
}
// Problems of a draft before it is sent: [{field, text}] (empty = fine). Same limits as validate_policy, on fields only.
export function checkDraft(members, rules) {
  const P = [];
  if (!members.length) P.push({ field: 'members', text: 'The policy needs at least one member.' });
  if (members.length > MAX_MEMBERS) P.push({ field: 'members', text: 'At most ' + MAX_MEMBERS + ' members.' });
  for (const m of members) {
    if (!m.roles.length) P.push({ field: 'members', text: (m.label || 'A member') + ' has no role; untick "in policy" instead.' });
    if (typeof m.label !== 'string' || !m.label.length || [...m.label].length > MAX_LABEL) P.push({ field: 'members', text: 'Label: 1 to ' + MAX_LABEL + ' characters.' });
    else if (m.label.includes('@')) P.push({ field: 'members', text: 'Label "' + m.label + '" looks like an e-mail address; labels go into the evidence pack, use a name.' });
  }
  if (!members.some((m) => m.roles.includes('owner'))) P.push({ field: 'members', text: 'Keep at least one owner.' });
  const cnt = (role) => (role === 'any' ? members.length : members.filter((m) => m.roles.includes(role)).length);
  const reqs = [rules.policy, rules.revocation, rules.ceiling, ...rules.mandate, ...rules.approval];
  for (const q of reqs) {
    if (!Number.isInteger(q.k) || q.k < 1) P.push({ field: 'rules', text: 'Every number of signatures must be 1 or more.' });
    else if (q.k > cnt(q.role)) P.push({ field: 'rules', text: q.k + ' ' + ROLE_WORD[q.role] + ' signatures needed, but only ' + cnt(q.role) + ' member(s) hold that role: the team would lock itself out.' });
  }
  if (rules.recovery) {
    const k = rules.recovery.k;
    if (!Number.isInteger(k) || k < 2) P.push({ field: 'rules', text: 'Replacing a lost key takes at least 2 other members (one person alone must never take over a key).' });
    else if (members.length - 1 < k) P.push({ field: 'rules', text: 'Replacing a lost key needs ' + k + ' other members, but a team of ' + members.length + ' has only ' + (members.length - 1) + ' left when one is lost.' });
  }
  return P.filter((p, i) => P.findIndex((x) => x.text === p.text) === i);
}
