// 05.11 (owner rule, docs/PRAVILO-VOPROSA.md): the question in plain words. what / harm / details are built by the SERVER from its reason
// dictionary (server/app/qwords.py) and are members of the signed view (signview.js VIEW_KEYS): this page only draws them, it never
// composes them from the agent's text. A server that sends none (an older one) gets the honest general text, never an empty box.
export const UNKNOWN_WHAT = 'Your agent wants to run a command Witness could not classify';
export const UNKNOWN_HARM = 'Unknown effect';
export const LATER_DAYS = 30;              // "Allow this from now on": 30 days, this project, this agent, exactly these commands

const str = (v) => (typeof v === 'string' && v.trim() ? v : '');

// answer (or the view of a line part) -> {what, harm, details}
export function qwView(r) {
  r = r && typeof r === 'object' ? r : {};
  return { what: str(r.what) || UNKNOWN_WHAT, harm: str(r.harm) || UNKNOWN_HARM, details: str(r.details) || 'Witness has no more facts about this call. Decide only if you expected it.' };
}

// the parts of a line question, each with its own what / harm (the "from now on" is decided for each part on its own)
export function qwParts(r) {
  const g = r && Array.isArray(r.line_group) ? r.line_group : [];
  return g.map((p) => qwView(p && p.view));
}

// "Allow this from now on" for the lead and for EVERY part of a line: possible only when the server offers it for all of them (each part is
// signed on its own: its commands, this project, 30 days). -> {ok, why, items: [{rid, offer, mandate, view (hex of the signed view) , partView}]}
export function laterPlan(r) {
  const items = [{ rid: r && r.rid, offer: r && r.allowance_offer, mandate: r && r.mandate, hex: null, part: null }];
  for (const g of (r && Array.isArray(r.line_group) ? r.line_group : [])) items.push({ rid: g && g.rid, offer: g && g.allowance_offer, mandate: g && g.mandate, hex: g && g.view_sha256, part: g });
  for (const it of items) {
    const o = it.offer;
    if (!o || o.eligible !== true) return { ok: false, why: (o && o.why_not) || 'the server does not offer it for this kind of question', items };
  }
  return { ok: true, why: '', items };
}

// 05.11 (prompt bombing, Gemini/ChatGPT opinions): "Allow this from now on" does not sign at once. It shows the exact bounds that WILL be signed (the same
// allowance_offer of the server that allowancePayload() signs): which commands, which project, which agent, until when, and where to revoke.
// -> {ok, why, agent, until (YYYY-MM-DD, UTC), rows: [{commands, project}], revoke, text}
export function laterConfirm(r, nowS, agentName) {
  const lp = laterPlan(r);
  if (!lp.ok) return { ok: false, why: lp.why, rows: [] };
  const agent = str(agentName) || str(r && r.agent_name) || str(r && r.agent_id) || str(r && r.action && r.action.agent) || 'this agent';
  const until = new Date((Math.floor(Number(nowS) || 0) + LATER_DAYS * 86400) * 1000).toISOString().slice(0, 10);
  const rows = lp.items.map((it) => ({ commands: it.offer.commands.slice(), project: it.offer.project }));
  const revoke = 'You can revoke it in Settings → Allowances.';
  const text = rows.map((x) => x.commands.join(', ') + ' in ' + x.project).join('; ') + ' — agent ' + agent + ', until ' + until + '. ' + revoke;
  return { ok: true, why: '', agent, until, rows, revoke, text };
}

// 05.11 (owner at the phone): the ONE line with the command on the first screen. -> {text, cut}. `cut`: what is shown is not the whole call
// (several commands named by their programs, a long or multi-line text cut with "…"): Allow then waits until Details was opened.
// heads: the programs of a line of several commands (already cleaned of invisible characters), or null; text: the one-command text.
export const CMD_MAX = 60;
// 12.11 (r0264, L3 "Третий прогон" q-Z62DVF): a LOW question of a few short commands (`sed; echo; git log; git config get`) showed only their
// names ("4 commands: sed, echo, ...") and Allow once waited for Details: a gate by the NUMBER of commands, not by the risk. whole: the full
// text of every command (cleaned of invisible characters), passed only for a low question: when there are at most CMD_LINES of them, each
// short and on one line, the first screen holds every one in full (one per line) and nothing is cut. Anything else is named, as before.
export const CMD_LINES = 4;
export function cmdLine(heads, text, whole) {
  const hs = Array.isArray(heads) ? heads.map(String).filter(Boolean) : [];
  if (hs.length > 1) {
    const w = Array.isArray(whole) ? whole.map((c) => String(c == null ? '' : c).trim()) : null;
    if (w && w.length === hs.length && w.length <= CMD_LINES && w.every((c) => c && c.length <= CMD_MAX && !/[\r\n]/.test(c)))
      return { text: w.join('\n'), cut: false, lines: w.length };
    return { text: hs.length + ' commands: ' + hs.join(', '), cut: true };
  }
  const t = String(text == null ? '' : text).replace(/\s+$/, '');
  if (!t) return { text: '', cut: false };
  const nl = t.indexOf('\n');
  const first = nl >= 0 ? t.slice(0, nl) : t;
  if (nl < 0 && first.length <= CMD_MAX) return { text: first, cut: false };
  return { text: first.slice(0, CMD_MAX - 1) + '\u2026', cut: true };
}

// the short note by the buttons when "Allow this from now on" is not offered (the full reason, from the server, is under Details)
export function laterShort(r) {
  const a = (r && r.action && typeof r.action === 'object') ? r.action : {};
  const tool = String((r && r.tool) || '');
  if (tool === 'Bash.net' || /^(WebFetch|WebSearch)/.test(tool) || ['disclosure', 'message', 'publish', 'purchase'].includes(a.class)) return 'Only once for internet requests';
  if (a.class === 'delete') return 'Only once for deleting files';
  if (a.class === 'file' || /^(Write|Edit|MultiEdit|NotebookEdit)/.test(tool)) return 'Only once for file changes';
  if (r && r.danger) return 'Only once for dangerous commands';
  return 'Only once for this kind of request';
}

// 05.11 (owner, the risk scale): the level is the SERVER's (qwords.py, from the reason code), a member of the signed view. A call of several parts: the
// highest over the lead and every part (each part's own view carries its own). -> {level, n (1..4), label ("High risk")} or null (an older server
// that sends none: no bar, never an invented level). A part without a level counts as high.
export const RISKS = ['low', 'medium', 'high', 'critical'];
export const RISK_LABELS = { low: 'Low risk', medium: 'Medium risk', high: 'High risk', critical: 'Critical risk' };
export function riskOf(r) {
  const lead = r && r.risk;
  const parts = (r && Array.isArray(r.line_group) ? r.line_group : []).map((g) => (g && g.view && g.view.risk) || 'high');
  if (!lead && !parts.length) return null;
  const all = [lead || 'high', ...parts].map((x) => (RISKS.includes(x) ? x : 'high'));
  const level = RISKS[Math.max(...all.map((x) => RISKS.indexOf(x)))];
  return { level, n: RISKS.indexOf(level) + 1, label: RISK_LABELS[level] };
}

// Details, first level: "who -> what -> where -> can it be undone" in a few plain lines, from fields of the signed view (action, tool).
// -> {who, where, undo}; `what` is the call's own text (drawn by the page through the honest checks).
export function simpleRows(r, agentName, text) {
  const a = (r && r.action && typeof r.action === 'object') ? r.action : {};
  const tool = String((r && r.tool) || '');
  const rc = a.recipient != null ? String(a.recipient) : '';
  const net = rc.startsWith('(network) ') || tool === 'Bash.net' || /^(WebFetch|WebSearch)/.test(tool) || ['disclosure', 'message', 'publish', 'purchase'].includes(a.class);
  const file = a.class === 'file' || a.class === 'delete' || /^(Write|Edit|MultiEdit|NotebookEdit|Read|NotebookRead)/.test(tool);
  const who = 'Agent ' + (str(agentName) || str(r && r.agent_name) || str(r && r.agent_id) || str(a.agent) || '(unnamed)');
  const where = net ? (rc.replace(/^\(network\) /, '').split('@').pop() || 'a site on the internet')
    : file ? (rc || 'a file') : 'This computer, in your project folder';
  const undo = net || a.class === 'delete' ? 'No' : /^(Read|NotebookRead)/.test(tool) ? 'Nothing changes' : 'Not always';
  // 05.11 (outside UX review): the kind of action in plain words, with the program (the first word of the call's text)
  const prog = String(text || (r && r.ask && r.ask.what) || '').trim().split(/\s+/)[0] || '';
  const kind = net ? 'Network request' : a.class === 'delete' ? 'Deletes files' : /^(Read|NotebookRead)/.test(tool) ? 'Reads a file' : file ? 'Changes a file' : 'Runs a command';
  const act = prog && !file ? kind + ' (' + prog.slice(0, 40) + ')' : kind;
  return { who: who.replace(/^Agent /, ''), where, undo, act };
}
