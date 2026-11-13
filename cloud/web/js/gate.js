// 12.11 (r0263): the pure rules of the question page (approve.js), testable without a DOM (test/v1112.test.mjs).
export const REFUSED_MS = 600000;
export function gateNeeded(q) {
  q = q && typeof q === 'object' ? q : {};
  const lv = q.risk && typeof q.risk === 'object' ? q.risk.level : q.risk;
  if (lv !== 'low' && lv !== 'medium') return true;              // high, critical, unknown: fail closed
  // the server's level already counts the danger mark (server qwords.DANGER_WORDS: a wipe, a push, a secret, a download run at once are
  // high; installing packages, a part Witness cannot read, a write outside the project are medium): a bare mark adds nothing here
  return !!(q.netCode || q.written || q.unseen || q.exec || q.honest || q.masked || q.parts || q.held);
}
export function actKey(r) {
  const a = r && r.action && typeof r.action === 'object' ? r.action : {};
  return String((r && r.tool) || '').split('.')[0] + '|' + String(a.class || '') + '|' + String(a.recipient || '');
}
export function refusedRecently(agent, o, t = Date.now(), key = null) {
  const e = agent && o && typeof o === 'object' ? o[agent] : null;
  if (!e || typeof e !== 'object' || typeof e.t !== 'number' || t - e.t >= REFUSED_MS) return false;
  return key === null || (typeof e.k === 'string' && e.k !== '' && e.k === key);
}
