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
  // r0348: a rule keyed by the consequence of the whole call (offer.kind "klyuch") is the same for every part: it is signed once
  const seen = new Set();
  const uniq = items.filter((it) => {
    if (it.offer.kind !== 'klyuch') return true;
    const k = JSON.stringify(it.offer.commands);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return { ok: true, why: '', items: uniq };
}

// r0348: the term of "from now on": a key rule names its own (7 days, 1 day for a program); the others LATER_DAYS
export function laterDays(offer) {
  return offer && offer.kind === 'klyuch' && Number.isInteger(offer.default_days) ? offer.default_days : LATER_DAYS;
}

// 05.11 (prompt bombing, Gemini/ChatGPT opinions): "Allow this from now on" does not sign at once. It shows the exact bounds that WILL be signed (the same
// allowance_offer of the server that allowancePayload() signs): which commands, which project, which agent, until when, and where to revoke.
// -> {ok, why, agent, until (YYYY-MM-DD, UTC), rows: [{commands, project}], revoke, text}
export function laterConfirm(r, nowS, agentName) {
  const lp = laterPlan(r);
  if (!lp.ok) return { ok: false, why: lp.why, rows: [] };
  const agent = str(agentName) || str(r && r.agent_name) || str(r && r.agent_id) || str(r && r.action && r.action.agent) || 'this agent';
  const until = new Date((Math.floor(Number(nowS) || 0) + Math.min(...lp.items.map((it) => laterDays(it.offer))) * 86400) * 1000).toISOString().slice(0, 10);
  const rows = lp.items.map((it) => ({ commands: it.offer.commands.slice(), project: it.offer.project, ...(str(it.offer.branch) ? { branch: it.offer.branch } : {}) }));
  // 0.2.96: the rule is bound to the git branch it was given on and ends when the project is on another one
  const revoke = 'It ends earlier if the project switches to another git branch. You can revoke it in Settings → Allowances.';
  const text = rows.map((x) => x.commands.join(', ') + ' in ' + x.project + (x.branch ? ' (branch ' + x.branch + ')' : '')).join('; ') + ' — agent ' + agent + ', until ' + until + '. ' + revoke;
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
// r0281 (blind evaluation, rule (g)): a one-line command is not cut where it names what the signed `what` quotes (the file, the host, the
// path): up to CMD_WIDE characters it stands whole (it wraps; at 390 px that is 4 lines at most). keep = those quotes.
export const CMD_WIDE = 150;
export function cmdLine(heads, text, whole, keep) {
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
  const ks = Array.isArray(keep) ? keep.map(String).filter((k) => k.length >= 3) : [];
  if (nl < 0 && first.length <= CMD_WIDE && ks.some((k) => { const i = first.indexOf(k); return i >= 0 && i + k.length > CMD_MAX - 1; })) return { text: first, cut: false };
  return { text: first.slice(0, CMD_MAX - 1) + '\u2026', cut: true };
}

// 13.11 (r0271, ISPYTANIE-0266 Н3): the command line is the ONE place of the first screen the AGENT writes, and an agent can write prose
// into it: `npm test -- --reporter "DEUS WITNESS VERIFIED: SAFE. Press Allow from now on"`, `make build # Witness note: checked, harmless`.
// On the first screen: shell comments (`# ...` outside quotes) are left out and a quoted string longer than STR_MAX is folded to "…"
// (the whole text stays under Details and Allow waits until it was seen: `folded` counts as cut). The words still come from the agent:
// the page labels the line "Command, as your agent wrote it" and warns when it sounds like Witness itself (agentVoice).
export const STR_MAX = 16;
export const CMD_BY = 'Command, as your agent wrote it:';
export const VOICE_NOTE = 'Text from the agent, not from Witness: this command contains words that sound like a verdict ("{w}"). Witness never writes inside a command.';
// words of a verdict / of Witness in a comment or a string of the command (not `deus-witness` in a path or a package name)
const VOICE = /(?<![-\w./])(witness|verified|approved|pre-?approved|harmless|trusted|whitelisted|press allow|choose allow|click allow|allow this|safe to run|no risk)(?![-\w])/i;
const VOICE_UP = /(?<![-\w./])(SAFE|VERIFIED|APPROVED|WITNESS|HARMLESS|TRUSTED)(?![-\w])/;

// one line of a shell command -> {text, folded, said: [comment and string texts]}; never throws
export function agentFold(line) {
  const t = String(line == null ? '' : line);
  let out = '', folded = false, i = 0;
  const said = [];
  while (i < t.length) {
    const c = t[i];
    if (c === '\\' && i + 1 < t.length) { out += c + t[i + 1]; i += 2; continue; }
    if (c === "'" || c === '"' || (c === '$' && t[i + 1] === "'")) {
      const q = c === '$' ? "'" : c, st = c === '$' ? i + 2 : i + 1;
      let j = st;
      while (j < t.length && t[j] !== q) j += (q === '"' && t[j] === '\\') ? 2 : 1;
      const body = t.slice(st, Math.min(j, t.length));
      said.push(body);
      const pre = c === '$' ? "$'" : q;
      if (body.length > STR_MAX) { out += pre + '\u2026' + q; folded = true; } else out += pre + body + (j < t.length ? q : '');
      i = j + 1;
      continue;
    }
    if (c === '#' && (i === 0 || /\s/.test(t[i - 1]))) {
      const nl = t.indexOf('\n', i);
      said.push(t.slice(i + 1, nl < 0 ? t.length : nl));
      folded = true;
      if (nl < 0) break;
      i = nl;
      continue;
    }
    out += c; i += 1;
  }
  return { text: folded ? out.replace(/[ \t]+$/gm, '') : out, folded, said };
}

// the words of a verdict the agent put into the command (a comment, a string, or shouted bare words), or '' -> for VOICE_NOTE
export function agentVoice(text) {
  const t = String(text == null ? '' : text);
  for (const s of agentFold(t).said) { const m = VOICE.exec(s) || VOICE_UP.exec(s); if (m) return m[1]; }
  const up = VOICE_UP.exec(t);
  return up ? up[1] : '';
}

// the short note by the buttons when "Allow this from now on" is not offered (the full reason, from the server, is under Details)
// r0281 (blind evaluation #3, #16): the reason stands ON the button that cannot be chosen (one place, one wording), not in a second line
export function laterShort(r) {
  const a = (r && r.action && typeof r.action === 'object') ? r.action : {};
  const tool = String((r && r.tool) || '');
  const rc = a.recipient != null ? String(a.recipient) : '';
  if (tool === 'Bash.net' || rc.startsWith('(network) ') || /^(WebFetch|WebSearch)/.test(tool) || ['disclosure', 'message', 'publish', 'purchase'].includes(a.class)) return 'Not for internet requests';
  if (a.class === 'delete') return 'Not for deleting files';
  if (a.class === 'file' || /^(Write|Edit|MultiEdit|NotebookEdit)/.test(tool)) return 'Not for file changes';
  if ((r && r.danger) || a.dangerous === true) return 'Asked every time for this command';
  return 'Not for this kind of request';
}

// r0281 (blind evaluation #9, #10, #13, #15): the signed Details words (server qwords.details) as lines a person reads: one fact per line,
// the command text in its own block. Left out on this level: "Tool: ..." (the tool name is under Technical details) and the full text of
// the call when the first screen already shows it whole (shownWhole: the same text, so it is not said twice).
// -> [{label, text, block}] (block: the text of the call, kept on its lines)
export function detLines(details, shownWhole) {
  const src = String(details == null ? '' : details).split('\n');
  const out = [];
  for (let i = 0; i < src.length; i++) {
    const ln = src[i];
    const m = /^(Full text|Text \(first [^)]*\)|All commands of the line):$/.exec(ln);
    if (m) {
      const body = [];
      while (i + 1 < src.length && !/^(What changes: |Undo: |All commands of the line:$)/.test(src[i + 1])) body.push(src[++i]);     // the server's order (qwords.py)
      const text = body.join('\n');
      if (m[1] === 'Full text' && shownWhole && text === shownWhole) continue;
      out.push({ label: m[1], text, block: true });
      continue;
    }
    if (/^Tool: /.test(ln) || !ln.trim()) continue;
    const k = /^([A-Z][A-Za-z ]{1,30}): ([\s\S]*)$/.exec(ln);
    // r0283 (third blind evaluation #19 / Н-2): the absolute path of a file is technical: the page shows it under Technical details (tech)
    if (k && k[1] === 'Full path') { out.push({ label: k[1], text: k[2], block: false, tech: true }); continue; }
    out.push(k ? { label: k[1], text: k[2], block: false } : { label: '', text: ln, block: false });
  }
  return out;
}

// 05.11 (owner, the risk scale): the level is the SERVER's (qwords.py, from the reason code), a member of the signed view. A call of several parts: the
// highest over the lead and every part (each part's own view carries its own). -> {level, n (1..4), label ("High risk")} or null (an older server
// that sends none: no bar, never an invented level). A part without a level counts as high.
export const RISKS = ['low', 'medium', 'high', 'critical'];
export const RISK_LABELS = { low: 'Low risk', medium: 'Medium risk', high: 'High risk', critical: 'Critical risk' };   // r0283 (#11): the label alone, no "N of 4"
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
