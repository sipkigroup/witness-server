// 0.2.38: the trial page (server app/trial.py). The claim comes in the URL fragment from `deus-witness try` (the part after # is not sent to
// any server), is kept in this browser's storage until the first touch and is removed then. Server data goes in through textContent only.
// 0.2.39 (E2E 24.10): this browser may hold the claims of several trial accounts (`try` run again, an older tab, a page opened by the hook
// as trial.html?rid=...): the page uses the claim of the account that call belongs to, never a stale one; a claim used or replaced in
// another tab switches this page to that state instead of a red error; one card per call (the parts of one Bash line are one call).
import { get, post, ApiError, BUILD } from './api.js';
import { encode, bytesToHex } from './cde.js';
import { sha256, TYP_MANDATE } from './profile.js';
import { signPayload } from './sign.js';
import { createCredential, explainError, supported, NO_PASSKEY_TEXT } from './webauthn.js';
import { describeMandate, isTempPath } from './describe.js';
import { autoProfileForm, isAutoProfile, AUTO_PROFILE, AUTO_OUTSIDE } from './mandate_form.js';
import { mountHomePlate } from './homeplate.js';
import { inspectFields } from './honest.js';
import { h, $, clear, notice, mountNav, fmtTime, kv, safeId, termsShown } from './ui.js';
import { mountOffer } from './pushoffer.js';

const KEY = 'dw_trial_claim';             // 0.2.38: one claim
const KEYS = 'dw_trial_claims';           // 0.2.39: the claims this browser holds, newest first (at most MAX_CLAIMS)
const MAX_CLAIMS = 5;
const msg = $('#msg');
// 0.2.43b: r_ + base32 in any case -> canonical upper case (the signed payload and the server use the upper case); anything else stays as it is
function canonRid(v) { return typeof v === 'string' && /^[rR]_[A-Za-z2-7]+$/.test(v) ? 'r_' + v.slice(2).toUpperCase() : v; }
const rid = canonRid(new URLSearchParams(location.search).get('rid'));    // 0.2.43b: OpenShell lowercases the id in the reason code; fold the case only
let claim = null, view = null, polling = null, gone = false;

// 0.2.75 (N21): what went wrong in a passkey step is said NEXT TO the button that starts it again, in words (never a bare server code);
// page-level news (the link was used elsewhere, no passkeys here) stays under the title.
export function passkeyStepText(e, label) {
  const again = 'Press "' + label + '" again: it starts over.';
  if (e && e.code === 'FLOW_UNKNOWN') return 'The passkey step took too long and expired, so this attempt does not count. ' + again
    + ' (If your device saved a passkey just now, that one is not used: you can delete it later in your passwords list.)';
  if (e && e.name === 'NotAllowedError') return 'The passkey prompt was cancelled or timed out: nothing was saved. ' + again
    + ' If the system window said it could not create or use a passkey, check that a screen lock is set on this device and that you are signed in to the account that stores passkeys (Apple ID on iPhone, Google account on Android).';
  return explainError(e);
}
function sayNear(btn, kind, text) {
  const at = (btn && btn.closest('p')) || btn;
  if (at && at.nextElementSibling !== msg) at.after(msg);
  notice(msg, kind, text);
}
function sayTop(kind, text) {
  const t = $('#title');
  if (t && t.nextElementSibling !== msg) t.after(msg);
  notice(msg, kind, text);
}

const CLAIM_RE = /^dwc_[A-Za-z0-9_-]{20,90}$/;
function claims() {
  let L = [];
  try { L = JSON.parse(localStorage.getItem(KEYS) || '[]'); } catch (e) { L = []; }
  if (!Array.isArray(L)) L = [];
  try { const one = localStorage.getItem(KEY); if (one && !L.includes(one)) L.push(one); } catch (e) { /* private mode */ }
  return L.filter((c) => typeof c === 'string' && CLAIM_RE.test(c)).slice(0, MAX_CLAIMS);
}
function save(L) {
  try { localStorage.setItem(KEYS, JSON.stringify(L.slice(0, MAX_CLAIMS))); localStorage.removeItem(KEY); } catch (e) { /* private mode: kept in memory only */ }
}
export function withClaim(L, c) { return [c, ...L.filter((x) => x !== c)].slice(0, MAX_CLAIMS); }
export function withoutClaim(L, c) { return L.filter((x) => x !== c); }
// store(v): v = the claim in use (newest first); store(null): the claim in use is dead (used, replaced or expired) and leaves the browser
function store(v) { save(v ? withClaim(claims(), v) : withoutClaim(claims(), claim)); }
function forget(c) { save(withoutClaim(claims(), c)); }

export function claimFromHash(hash) {
  const m = /^#c=(dwc_[A-Za-z0-9_-]{20,90})$/.exec(hash || '');
  return m ? m[1] : null;
}

// the rules of the drafted form, in words (before the passkey exists the mandate itself is not built yet)
export function describeForm(f) {
  const L = [];
  const d = f.delete || {}, c = f.command || {}, m = f.message || {};
  // r0283 (third blind evaluation Н-3 Н-4, decision 7): only what Witness checks -- "asked first or refused", never "no purchases" / "only inside"
  L.push(['Writes and deletes', 'without asking only inside: ' + ((d.targets || []).join(', ') || 'nowhere') + '; anywhere else asked first or refused']);
  // r0339 (Р-1711-baza п.2): a form with `unlisted: allow` is named honestly, never "asks you first"
  L.push(['Shell commands', 'run without asking: ' + ((c.allow || []).join(', ') || 'none') + (c.unlisted === 'allow'
    ? '; any other command runs without asking you too. Like an antivirus: Witness stops only the dangerous ones it recognises; what it does not know passes'
    : '; any other command asks you first or is refused')]);
  L.push(['Web', 'reads without asking only from: ' + ((m.domains || []).join(', ') || 'nowhere') + '; other sites asked first or refused']);
  L.push(['Money', 'purchases and payments are asked first']);
  if (isAutoProfile(c)) L.push(['Auto mode profile', 'ask only what cannot be undone: a change of a file outside the project in your home folder runs without asking after Witness keeps a copy (undo); deleting outside the project, network and git push, money, secrets, the agent\'s settings and anything that starts by itself are still asked']);
  L.push(['Valid', (f.valid_days || 7) + ' days; then your agent is refused until you sign new rules']);
  return L;
}

// r0296: the profile "auto mode + Witness" -- one line above the button. Ticked, the form the passkey signs gets the profile's two
// entries (mandate_form.autoProfileForm = server hookjudge/mapping.auto_profile_form); the full list and the signed view show them.
const AUTO_KEY = 'dw_trial_auto';
export function profiled(form, on) {
  if (on) return autoProfileForm(form);
  const f = JSON.parse(JSON.stringify(form || {}));
  if (f.command && Array.isArray(f.command.allow)) f.command.allow = f.command.allow.filter((x) => x !== AUTO_PROFILE && x !== AUTO_OUTSIDE);
  return f;
}
// the choice made on this page (null: never shown here -- then the form as `deus-witness try` sent it decides)
function autoChoice() { try { const v = localStorage.getItem(AUTO_KEY); return v === '1' ? true : v === '0' ? false : null; } catch (e) { return null; } }
function setAutoChoice(v) { try { localStorage.setItem(AUTO_KEY, v ? '1' : '0'); } catch (e) { /* per-browser convenience only */ } }

// the folders the rules let the agent change without asking, as a person names them ("your project folder “proekt”")
export function outsideWords(targets) {
  const names = [...new Set((targets || []).map(String).filter((t) => !isTempPath(t)).map((t) => t.replace(/\\/g, '/').replace(/\/\*+$/, '').replace(/\/+$/, '').split('/').pop() || t))];
  if (names.length === 1) return 'outside your project folder \u201c' + names[0] + '\u201d';
  if (names.length > 1) return 'outside your folders ' + names.map((x) => '\u201c' + x + '\u201d').join(', ');
  return 'anywhere on this computer';
}
// 0.2.76 (owner 31.10: "very technical"): the rules in short lines above the button; the full list is folded under it
// r0283 (third blind evaluation #4 #5 #6 Н-3 Н-4, decision 7): each line promises only what Witness checks: what is ASKED, not "no purchases"
// or "files change only inside" (a program a command starts is not seen inside); "dangerous ones always" said plainly; what day 8 brings
export function ruleSummary(f) {
  const d = f.delete || {}, c = f.command || {}, m = f.message || {};
  const n = (c.allow || []).filter((x) => x !== AUTO_PROFILE && x !== AUTO_OUTSIDE).length, dom = (m.domains || []).length;   // r0296: the profile's entries are no commands
  // r0283 (PES UIT2 on prod 0.2.108: the summary is at most 3 lines): what runs by itself / what is asked / how long
  return [
    'Everyday commands (' + n + ' listed)' + (dom ? ' and reading ' + dom + ' listed site' + (dom > 1 ? 's' : '') : '') + ' run without asking.',
    isAutoProfile(c)
      ? 'Only what cannot be undone asks you first or is refused: deleting ' + outsideWords(d.targets) + ', sending or publishing, purchases and payments; other changes keep a copy.'
      : 'Anything else asks you first or is refused: changes ' + outsideWords(d.targets) + ', purchases and payments too.',
    'These rules last ' + (f.valid_days || 7) + ' days; then your agent is refused until you sign new rules.',        // r0281 (#30), r0283 (#6)
  ];
}
// r0283 (third blind evaluation #2 #3, decision 8): the button names what THIS device does (Face ID on an iPhone); "passkey" is explained under it
export function confirmMethod(nav) {
  const ua = String((nav && nav.userAgent) || ''), pf = String((nav && nav.platform) || ''), tp = Number((nav && nav.maxTouchPoints) || 0);
  if (/iPhone|iPod/.test(ua) || pf === 'iPhone') return 'Face ID';
  if (/iPad/.test(ua) || (pf === 'MacIntel' && tp > 1)) return 'Touch ID';
  if (/Macintosh|Mac OS X/.test(ua) || /^Mac/.test(pf)) return 'Touch ID';
  if (/Windows/.test(ua) || /^Win/.test(pf)) return 'Windows Hello';
  return 'your device';
}
const METHOD = typeof navigator !== 'undefined' ? confirmMethod(navigator) : 'your device';
export const GO_TEXT = 'Confirm with ' + METHOD;

async function trialState(c) {
  const r = await fetch('/api/trial/state', { headers: { 'x-dw-claim': c, 'x-dw-build': BUILD }, credentials: 'omit' });
  let j = null; try { j = await r.json(); } catch (e) { /* not JSON */ }
  if (!r.ok) throw new ApiError(r.status, (j && j.error) || 'HTTP_' + r.status, (j && j.detail) || '');
  return j;
}

// One card per call: the parts of one Bash line (Bash.write, Bash.danger, ...) are rows of the same call, made by the same judge request.
export function groupCalls(items) {
  const out = [];
  for (const w of items || []) {
    const base = String(w.tool || '').split('.')[0];
    const head = callText(w).text;
    const g = out.find((x) => x.base === base && x.head === head && Math.abs(x.t - w.t) <= 5);
    if (g) { g.parts.push(w); continue; }
    out.push({ base, head, t: w.t, from_hook: !!w.from_hook, parts: [w] });
  }
  return out;
}
// what the call does, in words, from the masked preview (JSON, possibly cut); the raw preview goes under Details
export function callText(w) {
  const tool = String(w.tool || '').split('.')[0];
  const raw = String(w.args_preview || '');
  let a = null;
  try { a = JSON.parse(raw); } catch (e) { a = null; }
  const pick = (k) => {
    if (a && typeof a[k] === 'string') return a[k];
    const m = new RegExp('"' + k + '":\\s*"((?:[^"\\\\]|\\\\.)*)').exec(raw);
    if (!m) return null;
    try { return JSON.parse('"' + m[1].replace(/\\$/, '') + '"'); } catch (e) { return m[1]; }
  };
  const cut = (x, n) => (x.length > n ? x.slice(0, n) + '…' : x);
  let verb = 'use ' + tool, what = '';
  if (tool === 'Bash') { verb = 'run'; what = pick('command') || ''; }
  else if (/^(Write|Edit|MultiEdit|NotebookEdit)$/.test(tool)) { verb = 'write the file'; what = pick('file_path') || pick('notebook_path') || ''; }
  else if (/^(Read|NotebookRead)$/.test(tool)) { verb = 'read the file'; what = pick('file_path') || pick('notebook_path') || ''; }
  else if (tool === 'WebFetch') { verb = 'fetch'; what = pick('url') || ''; }
  else if (tool === 'WebSearch') { verb = 'search the web for'; what = pick('query') || ''; }
  else if (/^(Grep|Glob|LS)$/.test(tool)) { verb = 'search files'; what = pick('pattern') || pick('path') || ''; }
  return { verb, text: cut(what, 400), raw };
}
const PART_WORDS = { write: 'writes a file', danger: 'a risky command', net: 'goes to the network', delete: 'deletes', read: 'reads', exec: 'runs a project file' };

function showWaiting(items) {
  const box = clear($('#waiting'));
  const calls = groupCalls(items);
  // r0281b (second blind evaluation #1): signing the rules does not allow the waiting call: the agent repeats it and the rules decide (a listed
  // command runs, anything else is asked on the next screen). The line says that, not "you decide this call"
  $('#waithead').textContent = calls.length ? (calls.length === 1 ? 'Waiting for your rules (nothing is allowed yet): after you confirm, your agent repeats this call and the rules decide it; if they need you, you decide on the next screen:' : 'Waiting for your rules (nothing is allowed yet): after you confirm, your agent repeats these ' + calls.length + ' calls and the rules decide them; if they need you, you decide on the next screen:')
    : 'Waiting for the first call of your agent that needs you… Use Claude Code as usual: the call shows up here. You do not have to wait: the button above works before any call arrives.';
  const shown = calls.slice(0, 5);
  const ins = inspectFields(shown.map((c) => { const t = callText(c.parts[0]); return [t.verb, t.text]; }));
  shown.forEach((c, i) => {
    const why = c.parts.map((p) => PART_WORDS[String(p.tool || '').split('.')[1]]).filter(Boolean);
    const det = h('details', {}, h('summary', { text: 'Details' }),
      ...c.parts.map((p) => h('div', {}, h('span', { class: 'hint', text: p.tool + ' (receipt ' + p.rid + ')' }), h('pre', { text: p.args_preview || '' }))));
    box.append(h('div', { class: 'notice' },
      h('strong', { text: c.base + ': ' + ins.rows[i][0] }), h('pre', { text: ins.rows[i][1] || '(see Details)' }),
      h('span', { class: 'hint', text: fmtTime(c.t) + (c.from_hook ? ' - from Claude Code' : '') + (why.length ? ' - ' + [...new Set(why)].join(', ') : '') }), det));
  });
  if (ins.warnings.length) box.prepend(h('div', { class: 'notice warn', role: 'alert', text: 'Check: this text contains characters that can be disguised. ' + ins.warnings.slice(0, 3).join(' ') }));
}

// The claim this page uses is dead: used in another tab (then this browser has the session: show that), replaced by a newer
// `deus-witness try` (its account is erased), or expired. Never a red error: the person did nothing wrong here.
async function claimGone() {
  if (gone) return; gone = true;
  if (polling) { clearInterval(polling); polling = null; }
  if (claim) forget(claim);
  claim = null;
  $('#claim').hidden = true;
  try { await claimed(); sayTop('ok', ''); return; } catch (e) { /* no session here */ }
  const next = claims()[0];
  if (next) { location.reload(); return; }                  // another trial link is in this browser: use it
  $('#none').hidden = false;
  sayTop('ok', 'This trial link was used in another tab or replaced by a newer `deus-witness try`. Use the page that `deus-witness try` opened last (you can close this one).');
}

function showRules() {
  const ins = inspectFields(describeForm(view.form || {}));
  clear($('#rules')).append(...ins.rows.flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { text: v })]));
  const sum = inspectFields(ruleSummary(view.form || {}).map((t, i) => ['Rule ' + (i + 1), t]));
  clear($('#rulesum')).append(...sum.rows.map(([, v]) => h('li', { text: v })));
  // r0281 (blind evaluation #29): the full list opens right under the summary, BEFORE the button that signs it
  const nCmd = ((view.form || {}).command || {}).allow; if (Array.isArray(nCmd)) $('#rulesfullsum').textContent = 'See every rule you sign (the ' + nCmd.length + ' commands, the full paths)';
}

async function unclaimed() {
  $('#claim').hidden = false;
  const box = $('#autoprof');
  if (box) {
    box.checked = isAutoProfile((view.form || {}).command);      // as `deus-witness try` sent it (try --profile auto); off by default
    setAutoChoice(box.checked);
    box.onchange = () => { setAutoChoice(box.checked); view.form = profiled(view.form, box.checked); showRules(); };
  }
  showRules();
  clear($('#sent')).append(...(view.sent || []).map((s) => h('li', { text: s })));
  showWaiting(view.waiting || []);
  polling = setInterval(async () => {
    try { showWaiting((await trialState(claim)).waiting || []); }
    catch (e) { if (e && e.code === 'TRIAL_UNKNOWN') claimGone(); }
  }, 2000);
}

// Which of this browser's claims to use: the one whose account holds the call in ?rid= (the hook opens that), else the newest valid one.
// Dead claims leave the browser on the way.
async function pickClaim(fromHash) {
  let L = claims();
  if (fromHash) L = withClaim(L, fromHash);
  const ok = [];
  for (const c of L) {
    try { ok.push([c, await trialState(c)]); }
    catch (e) { if (e && e.code === 'TRIAL_UNKNOWN') { L = withoutClaim(L, c); continue; } throw e; }
    if (!rid || (ok[ok.length - 1][1].waiting || []).some((w) => w.rid === rid)) break;      // found; the rest is not asked
  }
  const hit = rid ? ok.find(([, v]) => (v.waiting || []).some((w) => w.rid === rid)) : null;
  const best = hit || (fromHash ? ok.find(([c]) => c === fromHash) : null) || ok[0] || null;
  save(best ? withClaim(L, best[0]) : L);
  return best;
}

async function signRules(agentId, form) {
  { const ch = autoChoice(); form = profiled(form, ch === null ? isAutoProfile((form || {}).command) : ch); }   // r0296: the line as ticked
  const me = await get('/api/me');
  const r = await post('/api/mandates/draft', { agent_id: agentId, form });
  if (r.typ !== TYP_MANDATE) throw new Error('Unexpected object type from server: ' + r.typ);
  if (!r.gateway) throw new Error('The server did not send the tool map document: nothing was signed.');
  if (r.mandate.toolmap_sha256 !== bytesToHex(await sha256(encode(r.gateway)))) throw new Error('The tool map hash in the mandate is not the hash of the tool map shown. Nothing was signed.');
  const rows = inspectFields(describeMandate(r.mandate));
  clear($('#human')).append(...rows.rows.flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { text: v })]));
  const envelope_b64 = await signPayload(TYP_MANDATE, encode(r.mandate), me);
  return post('/api/mandates', { mandate: r.mandate, envelope_b64 });
}

async function afterSigned(agentId, startedAt) {
  $('#claim').hidden = true; $('#signrules').hidden = true; $('#done').hidden = false;
  $('#doneinfo').textContent = 'Your passkey is the only key of this account and the rules are signed. The calls that waited are judged again under them now.';
  const t = await get('/api/trial').catch(() => null);
  if (t) $('#expiry').textContent = 'This account is yours and stays: free for one person, no expiry.';
  clear($('#next')).append(h('p', { class: 'hint', text: 'Looking for a call that still needs you…' }));
  mountOffer(window, $('#pushoffer')).catch(() => {});     // 0.2.96: "Get questions on your phone" right after the passkey touch
  watchCalls(agentId, startedAt);
}

// 27.10 (L3 with the owner): the page used to look for 40 x 1.5 s, say "Nothing is waiting" and stop looking, so a call made later
// (python3 --version, the hook waiting up to 600 s) showed up only after a manual reload. Now the page keeps watching while it is open:
// every POLL_VISIBLE ms while the tab is seen, every POLL_HIDDEN ms in the background, at once when the tab is seen again. A new waiting
// call opens its approval page (approve.html?rid=...&from=trial, which comes back here after the decision); a call already opened from
// this tab and left undecided (Back) is listed here with a link instead of opening again.
export const POLL_VISIBLE = 2500, POLL_HIDDEN = 15000, SETTLE_TICKS = 8;
export function pollDelay(hidden) { return hidden ? POLL_HIDDEN : POLL_VISIBLE; }
const SEEN = 'dw_trial_seen';
function seen() { try { const L = JSON.parse(sessionStorage.getItem(SEEN) || '[]'); return Array.isArray(L) ? L : []; } catch (e) { return []; } }
function markSeen(r) { try { sessionStorage.setItem(SEEN, JSON.stringify([r, ...seen().filter((x) => x !== r)].slice(0, 50))); } catch (e) { /* private mode */ } }
// the calls of this trial agent that wait for a human now, oldest first, and the one to open (the newest not opened from this tab yet)
export function pendingFor(items, agentId, startedAt, opened) {
  const mine = (items || []).filter((x) => x && x.agent_id === agentId && safeId(x.rid) && x.t >= startedAt - 900);
  const fresh = mine.filter((x) => !(opened || []).includes(x.rid) && x.agent_waiting !== false);   // 27.10 O3: never open a call the agent gave up on
  return { mine, open: fresh.length ? fresh[fresh.length - 1].rid : null };
}
export function approveHref(r) { return 'approve.html?rid=' + encodeURIComponent(r) + '&from=trial'; }
let watch = null, watching = false;
function watchCalls(agentId, startedAt) {
  if (watching) return; watching = true;
  let ticks = 0;
  const next = $('#next');
  const tick = async () => {
    watch = null; ticks++;
    let items = null;
    try { items = await get('/api/approvals'); }
    catch (e) {
      if (e && (e.status === 401 || e.status === 403)) {    // signed out (or the session ended): nothing to watch with
        clear(next).append(h('p', { text: 'This browser is no longer signed in to the account, so this page cannot show new calls. ' }, h('a', { href: 'login.html?next=trial.html', text: 'Sign in' })));
        watching = false; return;
      }
      /* network hiccup: try again on the next tick */
    }
    if (items) {
      const p = pendingFor(items, agentId, startedAt, seen());
      if (p.open) { markSeen(p.open); location.href = approveHref(p.open); return; }
      if (p.mine.length) {
        clear(next).append(h('p', { text: p.mine.length === 1 ? 'Your agent is waiting for you to decide on this call:' : 'Your agent is waiting for you (' + p.mine.length + ' calls):' }),
          ...p.mine.slice(-5).map((x) => { const t = callText({ tool: x.tool, args_preview: JSON.stringify((x.action && x.action.args) || x.action || {}) });
            return h('div', { class: 'notice' }, h('strong', { text: String(x.tool || '') + ': ' + t.verb }), h('pre', { text: t.text || '(see the approval page)' }),
              h('a', { class: 'btn', href: approveHref(x.rid), text: 'Open to approve or refuse' })); }));
      } else if (ticks >= SETTLE_TICKS || !next.querySelector('.hint')) {
        clear(next).append(h('p', { text: 'Nothing is waiting for you right now: the calls that waited were judged under your rules (allowed, or refused if the rules forbid them; your agent got the answer). This page keeps watching: when your agent next needs you, the call opens here by itself (or open ' }, h('a', { href: 'approve.html', text: 'Approvals' }), ').'));
      }
    }
    watch = setTimeout(tick, pollDelay(document.hidden));
  };
  document.addEventListener('visibilitychange', () => { if (!document.hidden && watch) { clearTimeout(watch); tick(); } });
  tick();
}

async function claimed() {
  view = await get('/api/trial');
  if (!view.mandate_id) {
    $('#signrules').hidden = false;
    $('#sign').onclick = () => doSign(view.agent_id, view.form);
    return;
  }
  await afterSigned(view.agent_id, Math.floor(Date.now() / 1000));
}

async function doSign(agentId, form) {
  const btn = $('#sign'); btn.disabled = true; sayNear(btn, 'ok', '');
  const t0 = Math.floor(Date.now() / 1000);
  try { await signRules(agentId, form); await afterSigned(agentId, t0); }
  catch (e) { sayNear(btn, 'err', passkeyStepText(e, 'Confirm the rules with ' + METHOD)); btn.disabled = false; }
}

$('#go').addEventListener('click', async () => {
  const btn = $('#go'); btn.disabled = true; sayNear(btn, 'ok', '');
  const t0 = Math.floor(Date.now() / 1000);
  let r;
  try {
    const b = await post('/api/trial/claim/begin', { claim });
    const credential = await createCredential(b.options);
    r = await post('/api/trial/claim/finish', { flow_id: b.flow_id, credential, claim, terms: termsShown(document) });
  } catch (e) {
    if (e && (e.code === 'TRIAL_UNKNOWN' || e.code === 'TRIAL_CLAIMED')) { btn.disabled = false; claimGone(); return; }
    btn.disabled = false; sayNear(btn, 'err', passkeyStepText(e, GO_TEXT)); return;
  }
  store(null); claim = null; gone = true;
  if (polling) clearInterval(polling);
  try { await signRules(r.agent_id, r.form); await afterSigned(r.agent_id, t0); }
  catch (e) {                                          // e.g. Safari wants a click for the second passkey prompt
    $('#claim').hidden = true; $('#signrules').hidden = false;
    $('#sign').onclick = () => doSign(r.agent_id, r.form);
    sayNear($('#sign'), (e && e.name === 'NotAllowedError') ? 'ok' : 'err', (e && e.name === 'NotAllowedError') ? 'Passkey made. Press the button above to confirm the rules.' : passkeyStepText(e, 'Confirm the rules with ' + METHOD));
  }
});

$('#keep').addEventListener('click', async () => {
  const btn = $('#keep'); btn.disabled = true;
  try { await post('/api/trial/keep', {}); $('#expiry').textContent = 'This is an ordinary Free account, with no expiry.'; btn.hidden = true; }
  catch (e) { sayNear(btn, 'err', explainError(e)); btn.disabled = false; }
});

window.addEventListener('hashchange', () => { if (claimFromHash(location.hash)) location.reload(); });   // a new trial link in this same tab
window.addEventListener('storage', (ev) => {        // the claim was used (or replaced) in another tab of this browser
  if (claim && !gone && (ev.key === KEYS || ev.key === null) && !claims().includes(claim)) claimGone();
});

(async () => {
  mountNav(false, { noSignup: true });
  $('#go').textContent = GO_TEXT; $('#sign').textContent = 'Confirm the rules with ' + METHOD;        // r0283 (decision 8)
  mountHomePlate(window, $('#homeplate'));                                                           // r0283 (#26, decision 4)
  // 0.2.48: no passkeys in this browser -> hide the buttons that cannot work and say where to go
  if (!supported()) { $('#go').hidden = true; $('#sign').hidden = true; sayTop('err', NO_PASSKEY_TEXT); }
  const fromHash = claimFromHash(location.hash);
  if (fromHash) history.replaceState(null, '', location.pathname + location.search);   // the link leaves the address bar and the history
  try {
    const best = await pickClaim(fromHash);
    if (best) { claim = best[0]; view = best[1]; await unclaimed(); return; }
  } catch (e) { sayTop('err', explainError(e)); return; }
  try { await claimed(); return; } catch (e) { /* no session or not a trial account */ }
  $('#none').hidden = false;
  if (rid) sayTop('ok', 'A call of your agent (receipt ' + rid + ') waits for your first touch, but this browser does not have the trial link.');
})();
