// Pure helpers of the approval queue (no DOM): roles, escalation, batch groups, differences between items.
import { MONEY, requirements } from './policy.js';
import { TYP_APPROVAL } from './profile.js';
import { MAX_ITEMS } from './wb.js';

export const roleOf = (action) => (MONEY.includes(action.class) ? 'budget' : 'access');

// 3.5: not decided within escalate_after_s -> escalated (the server flag wins when present)
export function isEscalated(x, settings, now) {
  if (typeof x.escalated === 'boolean') return x.escalated;
  const after = (settings && settings.escalate_after_s) || 600;
  return typeof x.t === 'number' && now - x.t >= after;
}

// Which items does this person see under "For my roles": the role of the action, or escalated items for owners.
export function forMe(x, myRoles, settings, now) {
  if (myRoles.includes(roleOf(x.action))) return true;
  return myRoles.includes('owner') && isEscalated(x, settings, now);
}

// k of an approval item by the policy; solo accounts (no policy) are always k = 1.
export function quorumOf(policy, action) {
  if (!policy) return 1;
  return Math.max(1, ...requirements(policy, TYP_APPROVAL, null, action).map(([, k]) => k));
}

const keyOf = (x) => JSON.stringify([x.agent_id, x.action.class, x.action.recipient == null ? null : String(x.action.recipient)]);

// Fallback when the server has no /api/approvals/groups: homogeneous groups (agent, class, recipient) of >= 2 items
// with k = 1, cut into chunks of <= 20, oldest first. Items needing k >= 2 never enter a batch (3.3).
export function groupItems(items, policy) {
  const by = new Map();
  for (const x of [...items].sort((a, b) => (a.t || 0) - (b.t || 0))) {
    if (quorumOf(policy, x.action) > 1 || x.agent_waiting === true) continue;     // N19 0.2.74: a call the agent waits on now is decided alone
    const k = keyOf(x);
    if (!by.has(k)) by.set(k, []);
    by.get(k).push(x);
  }
  const out = [];
  for (const xs of by.values()) {
    for (let i = 0; i < xs.length; i += MAX_ITEMS) {
      const part = xs.slice(i, i + MAX_ITEMS);
      if (part.length >= 2) out.push({ agent_id: part[0].agent_id, class: part[0].action.class, recipient: part[0].action.recipient, rids: part.map((x) => x.rid) });
    }
  }
  return out;
}

// Server groups are re-checked here: the UI never assembles a mixed or oversized group.
// 27.10 (polygon O2): a server group of ONE item (an outlier, or the 21st of 21) is not offered as "Review batch of 1": the batch screen has no
// Refuse, Freeze, "This looks suspicious" or "Allow for 24 h". That item is listed with the others and opens its own page.
export function acceptGroup(g, byRid, policy) {
  // N19 0.2.74 (series 10): a call the agent waits on NOW (the same call sent again keeps its rid) is never inside a batch: it has its own
  // row and Review, and approving it does not take the agent's older calls of the same kind along
  const xs = (g.rids || []).map((r) => byRid.get(r)).filter((x) => !(x && x.agent_waiting === true));
  if (xs.length < 2 || xs.length > MAX_ITEMS || xs.some((x) => !x)) return null;
  if (new Set(xs.map(keyOf)).size !== 1) return null;
  if (xs.some((x) => quorumOf(policy, x.action) > 1)) return null;
  return { ...g, rids: xs.map((x) => x.rid) };
}

// At most 4 KB of UTF-8 (R-05): cut on a character boundary.
export function clip4k(s) {
  const TE = new TextEncoder();
  const str = String(s == null ? '' : s);
  if (TE.encode(str).length <= 4096) return str;
  let out = '', n = 0;
  for (const ch of str) { const l = TE.encode(ch).length; if (n + l > 4096 - 3) break; out += ch; n += l; }
  return out + '...';
}

// Highlight what differs: a token is "common" if it appears in every text; each text -> [[token, differs]].
export function diffTokens(texts) {
  const split = (t) => String(t || '').split(/(\s+)/).filter((x) => x.length);
  const toks = texts.map(split);
  const sets = toks.map((ts) => new Set(ts.filter((x) => !/^\s+$/.test(x))));
  const common = sets.length ? [...sets[0]].filter((w) => sets.every((s) => s.has(w))) : [];
  const C = new Set(common);
  return toks.map((ts) => ts.map((w) => [w, !/^\s+$/.test(w) && texts.length > 1 && !C.has(w)]));
}

// Action fields whose values differ between items (to highlight in every item).
export function differingFields(actions) {
  const keys = new Set(actions.flatMap((a) => Object.keys(a)));
  return [...keys].filter((k) => new Set(actions.map((a) => JSON.stringify(a[k]))).size > 1);
}

// 27.10 (polygon O3): the server marks a call `agent_waiting` (true: its hook is polling for the answer now; false: nobody polled for it lately,
// the agent stopped waiting; absent: an older server). Live calls first, then unknown, then abandoned; the newest first within each.
const liveRank = (x) => (x.agent_waiting === true ? 0 : x.agent_waiting === false ? 2 : 1);
export function waitingFirst(items) {
  return [...(items || [])].sort((a, b) => liveRank(a) - liveRank(b) || (b.t || 0) - (a.t || 0));
}

// 27.10 (polygon O1): after a decision on `decided`, the next call of the same agent to open by itself, or null. Never the decided call, never
// a call already opened from this tab (sessionStorage), never a call the agent stopped waiting for, never another agent's call: no loop
// of page changes (Back from the next call shows the decided one as "already approved" and does not move again).
// `decided`: one rid, or the rids of a batch decided with one signature.
export function nextPending(items, decided, agentId, opened) {
  const seen = new Set([...(opened || []), ...(Array.isArray(decided) ? decided : [decided])]);
  const xs = (items || []).filter((x) => x && x.agent_id === agentId && !seen.has(x.rid) && x.agent_waiting !== false
    && (!x.status || x.status === 'pending_approval'));
  const w = waitingFirst(xs);
  return w.length ? w[0].rid : null;
}

// 27.10 (polygon series 2, N2): on the page of an undecided call `rid`, a NEWER call of the same agent that is still (or maybe) waiting, or null.
// Newer = asked after `rid` (by `t`; when `rid` is no longer in the list, any). Live calls first, the newest first.
export function newerPending(items, rid, agentId) {
  const L = (items || []).filter((x) => x && typeof x === 'object');
  const me = L.find((x) => x.rid === rid);
  const t0 = me && typeof me.t === 'number' ? me.t : null;
  const xs = L.filter((x) => x.agent_id === agentId && x.rid !== rid && x.agent_waiting !== false
    && (!x.status || x.status === 'pending_approval') && (t0 === null || (typeof x.t === 'number' && x.t > t0)));
  const w = waitingFirst(xs);
  return w.length ? w[0] : null;
}
