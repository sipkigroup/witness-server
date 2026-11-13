// Tool-map draft from an MCP catalog (ARHITEKTURA-0.2 6): every UNKNOWN argument gets an owner decision before "apply".
export const DECISIONS = { recipient: 'recipient (checked against the mandate)', text: 'text (scanned for closed data)', extra: 'safe extra key (not judged)', forbid: 'forbid the whole tool' };
const CLASSES = ['message', 'file', 'disclosure', 'purchase', 'sale', 'meeting', 'refund', 'delete', 'publish', 'pass'];
export const dkey = (tool, arg) => tool + '\u0000' + arg;

// draft: suggested toolmap; unknown: [{tool, arg}]; decisions: Map dkey -> one of DECISIONS; classes: {tool: class} overrides.
// -> {toolmap, unresolved: [{tool,arg}], forbidden: [tool]}
export function applyDecisions(draft, unknown, decisions, classes = {}) {
  const tm = JSON.parse(JSON.stringify(draft || { version: 1, default: 'deny', tools: {} }));
  tm.default = 'deny';
  const forbidden = new Set(unknown.filter((u) => decisions.get(dkey(u.tool, u.arg)) === 'forbid').map((u) => u.tool));
  const unresolved = [];
  for (const u of unknown) {
    if (forbidden.has(u.tool)) continue;
    const d = decisions.get(dkey(u.tool, u.arg));
    const t = tm.tools[u.tool];
    if (!t || !d || !(d in DECISIONS)) { unresolved.push(u); continue; }
    const path = '$.' + u.arg;
    if (d === 'recipient') {
      const rc = t.recipient == null ? [] : Array.isArray(t.recipient) ? t.recipient : [t.recipient];
      if (!rc.includes(path)) rc.push(path);
      t.recipient = rc.length === 1 ? rc[0] : rc;
    } else if (d === 'text') {
      t.text = [...new Set([...(t.text || []), path])];
    } else if (d === 'extra') {
      t.extra_keys = [...new Set([...(t.extra_keys || []), u.arg])];
    }
  }
  for (const [tool, c] of Object.entries(classes)) if (tm.tools[tool] && CLASSES.includes(c)) tm.tools[tool].class = c;
  for (const tool of forbidden) delete tm.tools[tool];
  for (const t of Object.values(tm.tools)) t.strict = true;
  return { toolmap: tm, unresolved, forbidden: [...forbidden] };
}
// A tool with a recipient path judged as "pass" would not be judged at all: the owner must pick a class.
export function classProblems(tm) {
  return Object.entries(tm.tools).filter(([, t]) => t.class === 'pass' && t.recipient != null).map(([n]) => n);
}
// money classes need an amount path (server check_toolmap)
export function amountProblems(tm) {
  return Object.entries(tm.tools).filter(([, t]) => ['purchase', 'sale', 'refund'].includes(t.class) && t.amount == null).map(([n]) => n);
}
export { CLASSES };
