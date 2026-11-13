// 04.11 (L3; red team 04.11 p.1, p.2: "signed != shown"). One tool call = one question: the witness judges the parts of a line one by one
// (`curl ...; make deploy-prod`: a network part and a command part, each with its own receipt) and asks ONCE, on the page of the lead.
// One passkey prompt then signs a batch (wb) over the lead and every part asked with it, each part with its OWN signing view. So the lead's
// page must SHOW each part's view -- everything that view holds that the owner must read (every command of the line, the danger mark, the
// code, the changed / written files, masked values, the text) -- and sign exactly the view it showed. Pure functions: approve.js renders the
// result through textContent; the server sends each part's view in GET /api/approvals/{lead} (line_group[i].view, .view_sha256).
import { viewHash } from './signview.js';
import { bytesToHex } from './cde.js';
import { inspectFields } from './honest.js';
import { askOf, dangerText, reasonWords } from './ask.js';
import { dangerShown, execView } from './levels.js';
import { clip4k } from './queue.js';

// 04.11 (Hypothesis I2, "signed != shown"): every command of a shell line, whole (line_full: [{cmd, fold?}], part of the signed view). The
// text preview stops at 4 KB, so `echo "<4 KB>" ; cat ~/.ssh/id_rsa` showed only the echo. -> {all: [text], shown: [text], folded: [text],
// cut, items: [{text, fold}]} or null. `folded`: long echoes of plain words (the server says which); every other command is shown in full, never cut.
export function fullCommands(lf, cut) {
  if (!Array.isArray(lf) || !lf.length) return null;
  const all = [], shown = [], folded = [], items = [];
  for (const c of lf) {
    const t = String(c && typeof c === 'object' ? c.cmd : c);
    const fold = !!(c && c.fold === true);
    all.push(t); items.push({ text: t, fold });
    (fold ? folded : shown).push(t);
  }
  return { all, shown, folded, items, cut: cut === true };
}

// the full commands of the WHOLE line for the top of the lead's page: the lead's own, else the first part's (as lineCommands)
export function lineFull(r) {
  if (r && Array.isArray(r.line_full) && r.line_full.length) return fullCommands(r.line_full, r.text_cut);
  for (const g of (r && Array.isArray(r.line_group) ? r.line_group : [])) {
    const v = g && g.view;
    if (v && Array.isArray(v.line_full) && v.line_full.length) return fullCommands(v.line_full, v.text_cut);
  }
  return null;
}

// view of a part -> {head, items: [{kind: 'warn'|'hint'|'pre', text}], warnings}: what the lead's page shows of it, above the gate's end
// top: the full commands already listed at the top of the page (lineFull): a part with the same list says so instead of repeating it
export function partLines(g, i, n, top) {
  const v = (g && g.view && typeof g.view === 'object') ? g.view : {};
  const ask = askOf(v);
  const items = [];
  const fields = [], texts = [];
  const add = (kind, label, text, isText = false) => { items.push({ kind, label }); (isText ? texts : fields).push([label, String(text)]); };
  add('head', 'Part', ask.verb + (ask.what ? ': ' + clip4k(ask.what) : ''));
  items[0].prefix = 'Part ' + (i + 1) + ' of ' + n + ' of this call. ';
  add('hint', 'Why', 'Asked because: ' + reasonWords(g && g.reason) + '.');
  const dt = dangerText(dangerShown(v.action, v), v);
  if (dt) add('warn', 'Danger', dt);
  if (Array.isArray(v.line_commands) && v.line_commands.length) add('warn', 'Commands', 'Commands in this line (' + v.line_commands.length + '): ' + v.line_commands.map(String).join(', '));
  const fc = fullCommands(v.line_full, v.text_cut);
  if (fc && top && JSON.stringify(top.all) === JSON.stringify(fc.all)) add('hint', 'Full commands', 'Its commands: every command of this line, listed in full above (' + fc.all.length + ').');
  else if (fc) { add('warn', 'Full commands', 'Every command of this line, in full (' + fc.all.length + '):'); fc.all.forEach((t, k) => add('pre', 'Command ' + (k + 1), t, true)); }
  if (Array.isArray(v.masked_dep) && v.masked_dep.length) add('warn', 'Masked', 'This decision depends on ' + (v.masked_dep.length > 1 ? 'masked values: ' : 'a masked value: ') + v.masked_dep.map(String).join(', '));
  if (v.unseen_write && Array.isArray(v.unseen_write.paths) && v.unseen_write.paths.length) {
    add('warn', 'Unseen write', 'It writes files whose text the witness cannot see (an archive, a patch or git objects): ' + v.unseen_write.paths.map(String).join(', ')
      + (v.unseen_write.secret === true ? '. This agent read a secret in the last minutes: what it writes may carry it.' : '.'));
  }
  if (typeof v.net_code === 'string' && v.net_code) { add('hint', 'Code label', 'Code it runs (talks to the network; the witness cannot tell where):'); add('pre', 'Code', clip4k(v.net_code), true); }
  const ev = execView(v.exec_changed);
  if (ev.show) {
    add('warn', 'Changed files', ev.head + ' ' + ev.files.join(', ') + (ev.note ? '. ' + ev.note : ''));
    if (ev.risk.note || ev.risk.lines.length) add('warn', 'Change risk', (ev.risk.dangerous ? 'Dangerous: ' : '') + ev.risk.note + (ev.risk.lines.length ? ' ' + ev.risk.lines.join('; ') : ''));
    for (const pv of ev.risk.previews) { add('hint', 'Content label', 'Content of ' + pv.file + (pv.cut ? ' (first 4 KB; the file is longer)' : '') + ' as sent by the agent\'s machine:'); add('pre', 'Content', pv.text, true); }
  }
  if (v.written_run && Array.isArray(v.written_run.files) && v.written_run.files.length) {
    add('warn', 'Written run', 'It runs files this agent wrote: ' + v.written_run.files.map(String).join(', '));
    for (const w of (Array.isArray(v.written_run.writes) ? v.written_run.writes : [])) {
      if (w && typeof w.text === 'string' && w.text) { add('hint', 'Written label', 'Written by the agent (' + (w.by || 'a write') + ') into ' + (w.file || 'the file') + ':'); add('pre', 'Written', w.text, true); }
      else if (w) add('warn', 'Written blind', 'The witness has no text of what was written into ' + (w.file || 'the file') + ': open the file and read it before approving.');
      for (const x of (Array.isArray(w && w.git_texts) ? w.git_texts : [])) if (x && typeof x.text === 'string' && x.text) { add('hint', 'Git label', 'Last written by the agent into ' + (x.file || 'the file') + ' before that git line:'); add('pre', 'Git text', x.text, true); }
    }
  }
  if (typeof v.adv === 'string' && v.adv) add('warn', 'Advisor', 'Flagged by the data advisor (' + v.adv + ').');
  if (typeof v.text_preview === 'string' && v.text_preview && v.text_preview !== ask.what) { add('hint', 'Text label', 'What it sends:'); add('pre', 'Text', clip4k(v.text_preview), true); }
  if (typeof v.args_preview === 'string' && v.args_preview) add('hint', 'Arguments', 'Tool: ' + (v.tool || '') + '. Arguments (first 300 characters): ' + v.args_preview);
  const ins = inspectFields(fields, texts);              // hidden / bidi characters become <U+XXXX>, look-alikes are flagged
  let fi = 0, ti = fields.length;                         // rows: the fields first, then the texts (honest.js)
  const out = items.map((it) => ({ kind: it.kind, text: (it.prefix || '') + ins.rows[it.kind === 'pre' ? ti++ : fi++][1] }));
  return { items: out, warnings: ins.warnings };
}

// the commands of the WHOLE line, for the top of the lead's page: the lead's own list, else the first part that has one (a network lead has
// none: `curl ...; make deploy-prod` -- the command part holds every command of the line)
export function lineCommands(r) {
  if (r && Array.isArray(r.line_commands) && r.line_commands.length > 1) return r.line_commands.map(String);
  for (const g of (r && Array.isArray(r.line_group) ? r.line_group : [])) {
    const v = g && g.view;
    if (v && Array.isArray(v.line_commands) && v.line_commands.length) return v.line_commands.map(String);
  }
  return null;
}

// -> the rows the lead's page signs: [{rid, mandate, action, view, hex}], the lead first, each part with the view the page SHOWED (line_group[i].view).
// Throws (code LINE_VIEW) when a view is missing or is not the hash the witness named: the page then signs nothing for the line (red team p.2:
// it used to drop every view and sign the batch "view not signed").
export async function lineRows(r, sv) {
  if (!sv || !sv.view) throw Object.assign(new Error('The witness could not build what this page shows of this call.'), { code: 'LINE_VIEW' });
  const rows = [{ rid: r.rid, mandate: r.mandate, action: r.action, view: sv.view, hex: sv.hex }];
  for (const g of r.line_group) {
    if (!g || !g.view || typeof g.view_sha256 !== 'string' || !g.mandate) throw Object.assign(new Error('The witness could not build what this page shows of a part of this call.'), { code: 'LINE_VIEW' });
    const view = await viewHash(g.view);
    const hex = bytesToHex(view);
    if (hex !== g.view_sha256) throw Object.assign(new Error('This page and the witness disagree on what a part of this call shows.'), { code: 'VIEW_CHANGED' });
    rows.push({ rid: g.rid, mandate: g.mandate, action: g.view.action, view, hex });
  }
  return rows;
}

// the result of the batch, part by part, in words (red team p.3: never "one answer covers all" when a part did not pass)
export function lineResult(res, rids, approved) {
  const by = new Map((res && Array.isArray(res.results) ? res.results : []).map((x) => [x && x.rid, x]));
  const want = approved ? 'allow' : 'refused';
  const bad = rids.map((rid, i) => [i, by.get(rid)]).filter(([, x]) => !x || x.verdict !== want);
  if (!bad.length) return { ok: true, text: approved ? 'One answer covers all ' + rids.length + ' parts of this call.' : 'All ' + rids.length + ' parts of this call were refused. Nothing was executed.' };
  const parts = bad.map(([i, x]) => 'part ' + (i + 1) + (x && x.verdict === 'error' ? ' was not ' + (approved ? 'approved' : 'refused') + ' (' + (x.error === 'NOT_WRITTEN' ? 'not written: an earlier part failed' : 'the witness refused it') + ')' : ' was not decided'));
  return { ok: false, text: (approved ? 'Not every part of this call was approved: ' : 'Not every part was refused: ') + parts.join('; ') + '. The call does not run until every part is approved; reload the page.' };
}
