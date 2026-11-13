import { mountOffer } from './pushoffer.js';
import { uxReport } from './uxguard.js';
import { get, post } from './api.js';
import { bytesToHex } from './cde.js';
import { challenge, approvalPayload, TYP_APPROVAL } from './profile.js';
import { signPayload } from './sign.js';
import { explainError, isClone, cloneNote } from './webauthn.js';
import { describeMandate, describeAction } from './describe.js';
import { main as queueMain, advisoryText, decideHeld } from './batch.js';
import { clip4k, nextPending, newerPending } from './queue.js';
import { inspectFields } from './honest.js';
import { $, notice, mountNav, until, safeId, failText } from './ui.js';
import { TYP_ALLOWANCE, TRUST_TEXT, allowancePayload, newAllowanceId, offerView, untilText } from './allowance.js';
import { levelView, execView, levelError, keySummary, dangerShown, secretLead } from './levels.js';
import { signBatch } from './sign.js';
import { wbChallenge, batchItems } from './wb.js';
import { planRids, readPlan, repeatItems, summaryText, offerView as repeatView, untilTime } from './repeat.js';
import { signedView, viewHash } from './signview.js';
import { askOf, dangerText, protectedTarget, reasonWords, dangerCovered } from './ask.js';
import { qwView, qwParts, laterPlan, laterConfirm, laterShort, cmdLine, riskOf, simpleRows, LATER_DAYS, agentFold, agentVoice, CMD_BY, VOICE_NOTE } from './qwords.js';
import { partLines, lineCommands, lineFull, lineRows, lineResult, partRedundant } from './line.js';
import { gateNeeded, actKey, refusedRecently, REFUSED_MS } from './gate.js';

// 0.2.76 (owner 31.10: "very technical; hide the extra, every needed button visible at once, no scrolling up and down"):
// the page opens on WHAT the agent asks (title + the command), the marks the person must see, and the decision bar (sticky at the bottom of
// the screen, so Approve / Refuse are on the first screen whatever the length of the page). The hashes, the table, the mandate, the exact
// bytes, "suspicious / freeze" are under Details. What the person MUST see before deciding (the text of a file the agent wrote and runs,
// a secret, the danger mark, a masked value the decision depends on, a changed file, disguised text) stays in #must, above #mustend:
// while #mustend has not been on screen above the bar, Approve / Release / Allow are disabled (the gate). Refuse is never gated.
let gateOpen = true;
let gateSeen = false;       // 0.2.90: the person clicked a gated button once: the text was read; a later error notice never locks the page again
const GATED = ['#yes', '#allow24', '#rel'];
function barTop() {
  const b = ['#decide', '#release'].map((s) => $(s)).find((x) => x && !x.hidden);
  return b ? b.getBoundingClientRect().top : innerHeight;
}
export function mustSeen(endTop, bar, vh) { return endTop <= Math.min(vh, bar) + 2; }
// 05.11 (owner at the phone: "keep only the main thing"): everything that must be read is under Details (#qw_more), closed at first. While it is
// closed and there IS something to read there (the command on the first screen is cut or has several parts, or #must holds a mark, a text,
// a file, code ...), the end of the text is "not seen": Allow stays off until Details is opened (and then, as before, until its end was on
// screen above the bar). A short command shown whole and nothing else to read: no gate.
let cmdCut = false;
let cmdWhole = false;
let firstWhole = '';      // r0278: the one command the first screen shows whole ('' otherwise)     // 12.11 (r0264): every command of the line stands in full on the first screen (a low question): Details does not repeat them
// 12.11 (r0263, L3 ISPYTANIE-L3-0260 З1): "Allow once" stayed grey until Details was opened and scrolled to the end even for `pytest | tail`;
// the person on L3 did not understand it and the call timed out. The gate is kept for what is really dangerous: a high or critical risk
// (the server's level counts the danger mark), code / a written file / a changed file / hidden characters / a masked value to read. A low or medium question whose every
// command the first screen names (no mark, nothing else to read) has no gate: Allow works at once.
let noGate = false;
let detHasText = false;
function mustHasContent() {
  const m = $('#must'); if (!m) return false;
  return [...m.children].some((c) => !c.hidden);
}
function detailsClosed() { const d = $('#qw_more'); return !!d && d.hidden; }      // the first level
function techClosed() { const d = $('#qw_more'), t = $('#qw_tech'); return !!d && (d.hidden || t.hidden); }      // the second level ("More technical"), where #must is
function cmdOverflow() { const c = $('#cmdline'); return !!c && !c.hidden && (c.scrollWidth > c.clientWidth + 1 || c.scrollHeight > c.clientHeight + 1); }   // r0278: the line wraps (a few lines at most)
// the end of the ONE full copy of the call under Details: the Details card (#what_dd), or the full list in #must (a line cut at 4 KB), or the
// signed words (#qw_det, "Full text:") when the card is hidden so as not to repeat it
function cmdEnd() {
  const dd = $('#what_dd');
  if (dd && !dd.hidden) return dd.getBoundingClientRect().bottom;
  if ($('#linefull')) return $('#mustend').getBoundingClientRect().top;
  const p = $('#qw_det'), t = p.firstChild, s = p.textContent, i = s.indexOf('Full text:\n');
  if (i < 0 || !t || t.nodeType !== 3) return p.getBoundingClientRect().bottom;
  const m = /\n(What changes|Undo):/.exec(s.slice(i)), r = document.createRange();     // only the text of the call, not the lines after it
  r.setStart(t, i); r.setEnd(t, m ? i + m.index : s.length);
  return r.getBoundingClientRect().bottom;
}
function mustTop() {
  // 12.11 (r0263): nothing dangerous to read first. But a command the first screen does not show whole (cut with "..." or only the names of
  // several commands) is still not allowed blind: Details opens by itself with all of it (gateApply), and Allow is on once the end of that
  // text was on screen above the buttons (cmdEnd; before, an open Details counted as read while the text was still below the bar at 390x844).
  if (noGate) return (cmdCut || cmdOverflow()) ? (detailsClosed() ? Infinity : cmdEnd()) : 0;
  // marks, texts, files, code, the parts of a line (#must) are on the second level: both must be open, and the end of #must on screen
  if (mustHasContent()) return techClosed() ? Infinity : $('#mustend').getBoundingClientRect().top;
  // only a cut command (the first screen shows "..." or the names of several commands): the first level holds its whole text
  if (cmdCut || cmdOverflow()) return detailsClosed() ? Infinity : cmdEnd();
  return 0;
}
let manyCmds = false;     // 06.11: the call has several commands the person can see (not the inner parts of one command)
let autoOpened = false;   // 05.11: Details opened once by itself because Allow waits for it
let laterOff = false;     // 05.11: "Allow this from now on" is not offered for this question (the note says why)
function fixLater() { if (laterOff && $('#allow24')) $('#allow24').disabled = true; }
function gateApply() {
  for (const s of GATED) if (!gateOpen && $(s)) $(s).disabled = true;
  $('#gate').hidden = gateOpen;
  // 05.11 (outside UX review): the page does not tell the person where to tap; one button opens what must be read and goes to it
  // 05.11 (outside UX review, owner: "do it"): no "tap here, then there"; Details opens by itself, the note says why Allow waits
  if (!gateOpen && !autoOpened && $('#qw_more') && $('#qw_more').hidden && (mustHasContent() || cmdCut || cmdOverflow()) && !$('#qw').hidden) { autoOpened = true; $('#qw_btn').click(); return; }
  // r0278 (find 3): one short neutral line (it was the fourth "dangerous" of the screen, a yellow block over the buttons)
  $('#gate').textContent = mustHasContent() ? (manyCmds ? 'This call does several things: Allow unlocks once each of them below was on screen.' : 'Allow unlocks once you have read to the end of the text below.') : (manyCmds ? 'This call runs several commands: Allow unlocks once each of them below was on screen.' : 'Allow unlocks once the whole command below was on screen.');
  fixLater();
}
// a decision in flight (Refuse / Reject disabled by decide / go): opening the gate then does not enable Approve again (unlock() does after an error)
const inFlight = () => !!(($('#no') && $('#no').disabled) || ($('#rej') && $('#rej').disabled));
function gateCheck() {
  if (gateOpen) return;
  if (mustSeen(mustTop(), barTop(), innerHeight)) { gateOpen = true; if (!inFlight()) for (const s of GATED) if ($(s)) $(s).disabled = false; gateApply(); }
}
function gateClose() {
  gateOpen = false; gateApply();
  // 0.2.90 (sandbox matrix, WebKit, the hold page of a written file): the person (or the harness) scrolled to the end while the page was
  // still being built; once the gate closes no scroll event comes any more, and Release stayed disabled for good. The gate is checked at
  // once, on resize, and every 500 ms until it opens (a check is a layout read, nothing else).
  let t = null;
  const on = () => { gateCheck(); if (gateOpen) { removeEventListener('scroll', on); removeEventListener('resize', on); if (t) clearInterval(t); t = null; } };
  addEventListener('scroll', on, { passive: true }); addEventListener('resize', on);
  t = setInterval(on, 500);
  on();
}
// 0.2.79 (red team R3-1, R3-2, R3-4): the layout changes without a resize too (a line or a note shown after the gate was judged, "why?"
// opened, an error above the box). Where #mustend lies in the PAGE (not on the screen: scrolling moves nothing) and the height of the bar are
// kept; when #mustend moved down or the bar grew, and #mustend is no longer above the bar, what must be seen was pushed off the screen:
// the gate closes again (it opens on scrolling, as on a first load). When the gate is closed, a layout that now shows #mustend opens it.
let gateGeo = null;
function gateGeom() {
  const b = ['#decide', '#release'].map((s) => $(s)).find((x) => x && !x.hidden);
  return { y: techClosed() ? 0 : $('#mustend').getBoundingClientRect().top + scrollY, bh: b ? b.offsetHeight : 0 };
}
let gateRaf = 0;
function gateLayout() {
  gateRaf = 0;
  if (!$('#done').hidden || $('#box').hidden) return;
  const g = gateGeom(), prev = gateGeo; gateGeo = g;
  if (!gateOpen) { gateCheck(); return; }
  // 0.2.90 (sandbox matrix, cancel cells): a taller bar alone (an error notice after a cancelled passkey prompt) does not close the gate again --
  // the person has seen the text; only new content above #mustend (it moved down) does
  if (prev && !gateSeen && g.y > prev.y + 1 && !mustSeen(mustTop(), barTop(), innerHeight)) gateClose();
}
let gateVp = null;
function gateStart() {
  gateOpen = mustSeen(mustTop(), barTop(), innerHeight);
  gateApply();
  gateGeo = gateGeom();
  if (!gateVp) {
    const later = () => { if (!gateRaf) gateRaf = requestAnimationFrame(gateLayout); };
    if (typeof ResizeObserver === 'function') { const ro = new ResizeObserver(later); for (const s of ['#main', '#box', '#must', '#decide', '#release']) if ($(s)) ro.observe($(s)); }
    if (typeof MutationObserver === 'function') new MutationObserver(later).observe($('#main'), { childList: true, subtree: true, attributes: true, attributeFilter: ['hidden', 'open', 'class'] });
    // 0.2.77: the layout changed (a phone turned, a window made smaller) while the page is still at its top: what is now below the bar
    // was never on screen in THIS layout, so the gate is judged again (it closes, and opens again on scrolling, as on a first load)
    gateVp = innerWidth + 'x' + innerHeight;
    addEventListener('resize', () => {
      const vp = innerWidth + 'x' + innerHeight;
      if (vp === gateVp) return;
      gateVp = vp;
      if (!$('#done').hidden || scrollY > 4 || $('#box').hidden) return;
      const was = gateOpen;
      gateOpen = mustSeen(mustTop(), barTop(), innerHeight);
      gateGeo = gateGeom();
      if (was && !gateOpen) gateClose();
      // 0.2.79: and the other way round (the closed gate opens for the new layout): the buttons must come back too, or Approve stayed disabled
      // for good (gateCheck returns early once gateOpen is true; sandbox C04 UI3: 390x664 -> 844 -> 1280 -> 664 -> 844)
      else if (!was && gateOpen) { for (const s of GATED) if ($(s)) $(s).disabled = false; gateApply(); }
    });
  }
  if (gateOpen) return;
  const on = () => { gateCheck(); if (gateOpen) { removeEventListener('scroll', on); removeEventListener('resize', on); } };
  addEventListener('scroll', on, { passive: true }); addEventListener('resize', on);
}
// re-enable the buttons after an error: Refuse always, the approving ones only once the gate is open
function unlock() { $('#no').disabled = $('#rej').disabled = false; for (const s of GATED) if ($(s)) $(s).disabled = !(gateOpen || gateSeen); fixLater(); }

const msg = $('#msg');
// 0.2.75 (sandbox «живой человек»): 409 APPROVAL_SIG = the signed bytes are not this request's approval. Seen when the browser ran part of
// this page from an OLDER copy (a profile.js without the view). The witness does not accept the old format; the person is told what to do.
export const STALE_SIG_TEXT = 'Nothing was approved: your browser ran an outdated copy of part of this page, so the signature did not match this request. '
  + 'Reload the page and decide again (on a phone: close the tab and open the link again).';
function reloadButton(el) {
  const b = document.createElement('button'); b.type = 'button'; b.className = 'btn'; b.textContent = 'Reload this page';
  b.addEventListener('click', async () => {
    try { await fetch('/api/build?clear=1', { cache: 'no-store', credentials: 'same-origin' }); } catch (e) { /* offline */ }
    try { await fetch(location.href, { cache: 'reload', credentials: 'same-origin' }); } catch (e) { /* offline */ }
    location.reload();
  });
  el.append(' ', b);
}
// r0278 (L3 13.11 with the owner, find 4): the hook waited 15 s and told the agent "refused", while the page still said "14 min 46 s left to
// decide". The page follows what the server knows (agent_waiting: the hook's polls; gave_up_at: the hook's last poll said it gave up) and
// says it in one line instead of the countdown: the answer is kept, it applies when the agent makes the same call again.
export function stoppedText(t) {
  const at = typeof t === 'number' && t > 0 ? ' at ' + new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
  return 'The agent stopped waiting' + at + '; your answer applies if it asks again (same command).';
}
let stoppedAt = null;
function showStopped(t) {
  if (typeof t !== 'number' || !(t > 0)) t = stoppedAt || Math.floor(Date.now() / 1000);    // an older server / no gave_up_at: when this page saw it
  stoppedAt = t;
  $('#stale').textContent = stoppedText(t); $('#stale').hidden = false; $('#left').hidden = true;
}
function showWaiting() { $('#stale').hidden = true; $('#left').hidden = false; }
// N2 29.10 (series 8b, R1a2): the agent may send the same call again after this page was opened (its hook then waits for it): the page
// re-reads the item and takes the "stopped waiting" line away, instead of saying it while the agent waits. r0278: and the other way round
// (the hook gives up while the page is open): every 3 s while the page is seen, every 15 s in the background, while undecided.
function followWait(n = 0) {
  if (n > 2000) return;
  setTimeout(async () => {
    if (!$('#done').hidden || $('#box').hidden) return;
    try {
      const x = await get('/api/approvals/' + encodeURIComponent(rid));
      if (!['pending_approval', 'held'].includes(x.status)) return;
      if (x.agent_waiting === false && !x.covered_by) showStopped(x.gave_up_at); else if (!$('#stale').hidden) { stoppedAt = null; showWaiting(); }
    } catch { /* network: try again */ }
    followWait(n + 1);
  }, document.hidden ? 15000 : 3000);
}
// N3 29.10: the owner let go a page whose file was rewritten since (the server says file_changed): the agent's run is refused, nothing ran
function changedText(r) {
  const f = r && typeof r.file_changed === 'string' ? r.file_changed : '';
  if (r && r.file_changed_by === 'late_write') return lateWriteText(f);      // 0.2.77b (R2-7): not a file the page showed
  return 'The file changed after you saw it; nothing ran' + (f ? ' (' + f + ')' : '') + '. If the agent runs it again, you will be asked again with the new text.';
}
// 0.2.77b (red team R2-7): the agent was no longer waiting when you approved; before it repeated the call it wrote a file (any file the command
// might run or read: the witness cannot tell which ones it does), so that approval was not used and the repeat is asked again
export function lateWriteText(f) {
  return 'After your approval the agent wrote a file' + (f ? ' (' + f + ')' : '') + ' before it repeated this command, so your approval was not used and nothing ran on it. '
    + 'The command may run or read that file: confirm the command once more.';
}
// N18 0.2.74 (series 10): "repeat" only when the agent no longer waits for this answer (the server says so in agent_waiting, read before the
// decision); a hook that still waits gets the answer and the call runs at once, with no repeat
export function approvedText(res) {
  if (res && res.agent_waiting === true) return 'The agent is waiting for this answer: the call runs now (once).';
  if (res && res.agent_waiting === false) return 'The agent stopped waiting for this call: it runs once when the agent makes the same call again.';
  return 'If the agent is still waiting, the call runs now; otherwise it runs once when the agent makes the same call again.';
}
// 0.2.43b: r_ + base32 in any case -> canonical upper case (the signed payload and the server use the upper case); anything else stays as it is
function canonRid(v) { return typeof v === 'string' && /^[rR]_[A-Za-z2-7]+$/.test(v) ? 'r_' + v.slice(2).toUpperCase() : v; }
const rid = canonRid(new URLSearchParams(location.search).get('rid'));    // 0.2.43b: OpenShell lowercases the id in the reason code; fold the case only

export function mutedText(untilS) {
  const t = new Date(untilS * 1000);
  const hm = String(t.getHours()).padStart(2, '0') + ':' + String(t.getMinutes()).padStart(2, '0');
  return 'Recorded. Notifications from this agent are muted until ' + hm + '. This request still waits: refuse it if you did not expect it.';
}

// Every value shown to the owner passes through inspectFields: hidden / bidi characters become <U+XXXX>, look-alike text is flagged.
export function renderHonest(box, warnings) {
  box.replaceChildren();
  if (!warnings.length) { box.hidden = true; return; }
  const p = document.createElement('strong'); p.textContent = 'Check before you approve: this request contains text that can be disguised.'; box.append(p);
  const ul = document.createElement('ul'); for (const w of warnings.slice(0, 12)) { const li = document.createElement('li'); li.textContent = w; ul.append(li); }
  box.append(ul); box.hidden = false;
}
const HUMAN_FIELDS = ['Class', 'Recipient', 'Amount', 'Data classes touched', 'Reversible', 'Dangerous command'];
function fill(dl, rows) { dl.replaceChildren(...rows.flatMap(([k, v]) => { const dt = document.createElement('dt'); dt.textContent = k; const dd = document.createElement('dd'); dd.textContent = v; return [dt, dd]; })); }
// 27.10: opened by the trial page (from=trial): after the decision go back there, it keeps watching for the agent's next call
const fromTrial = new URLSearchParams(location.search).get('from') === 'trial';
export const BACK_TO_TRIAL_MS = 2500;
// 27.10 (polygon O1): after a decision the page used to stay on "Approved / Back to approvals" while the agent's next call waited unseen
// (30-45 s of a person's time per call, 6 of 6 runs). Now, whatever opened this page, it keeps looking for the next call of the SAME agent
// that its hook is still waiting for, and opens it (nextPending: never this call again, never one already opened from this tab, never
// another agent's call, never one the agent stopped waiting for). The trial page does the same for its own agent (from=trial below).
export const HOOK_WAIT_S = 45;    // 06.11: plugin 0.2.58 waits 45 s (was 600). 0.2.78: DEUS_WITNESS_HOOK_WAIT of the plugin hook (scripts/deus-witness-hook.sh) and of the unattended templates
export const NEXT_POLL_MS = 2500, NEXT_POLL_HIDDEN_MS = 15000, NEXT_WATCH_MS = 600000, NEXT_FIRST_MS = 2500;   // the first look after the person read the result
const OPENED = 'dw_approve_opened';
function opened() { try { const L = JSON.parse(sessionStorage.getItem(OPENED) || '[]'); return Array.isArray(L) ? L : []; } catch (e) { return []; } }
function markOpened(r) { try { sessionStorage.setItem(OPENED, JSON.stringify([r, ...opened().filter((x) => x !== r)].slice(0, 100))); } catch (e) { /* private mode */ } }
let agentOfThis = null;
let keyOfThis = '';         // 12.11 (r0263): the act of this page (actKey), remembered with a refusal
let agentNameOfThis = null;     // 05.11: the confirm step of "from now on" names the agent, not its id (shown only; the signed offer is unchanged)
// decided: the rid of this page, or (27.10) the rids of a batch just approved from the queue (batch.js calls back here, see main)
function watchNext(decided = rid, agent = agentOfThis) {
  const ds = (Array.isArray(decided) ? decided : [decided]).filter((r) => /^r_[A-Z2-7]+$/.test(r || ''));
  if (!agent || !ds.length) return;
  ds.forEach(markOpened);
  const p = document.createElement('p'); p.id = 'nextnote'; p.className = 'hint';
  p.textContent = 'Watching for this agent\'s next call: when it asks for you again, it opens here by itself.';
  $('#done').insertBefore(p, $('#donetext').nextSibling);
  const stop = Date.now() + NEXT_WATCH_MS;
  let timer = null;
  const tick = async () => {
    timer = null;
    try {
      const items = await get('/api/approvals?status=pending');
      const next = nextPending(items, ds, agent, opened());
      if (next) { markOpened(next); p.textContent = 'Your agent asks again: opening its next call…'; location.href = 'approve.html?rid=' + encodeURIComponent(next); return; }
    } catch (e) {
      if (e && (e.status === 401 || e.status === 403)) { p.textContent = 'Signed out: open Approvals after you sign in again.'; return; }
    }
    if (Date.now() < stop) timer = setTimeout(tick, document.hidden ? NEXT_POLL_HIDDEN_MS : NEXT_POLL_MS);
    else p.textContent = 'Stopped watching after 10 minutes. New calls are under Approvals.';
  };
  document.addEventListener('visibilitychange', () => { if (!document.hidden && timer) { clearTimeout(timer); tick(); } });
  timer = setTimeout(tick, NEXT_FIRST_MS);
}
// 27.10 (polygon series 2, N2): the trial page opened a call X while its hook waited; the hook was then killed (Claude Code's timeout) and the
// agent asked Y. The page of X never showed Y. Now, while this call is undecided, the page looks for a NEWER call of the same agent and says
// so with a link. It does not change the page by itself: a switch while the person presses Approve would sign a call the person did not read.
function watchNewer() {
  if (!agentOfThis) return;
  const note = document.createElement('p'); note.id = 'newer'; note.className = 'notice warn'; note.hidden = true; note.setAttribute('role', 'status');
  $('#decide').before(note);          // 0.2.79 (red team R3-4): above the decision bar, below what must be seen (was: the top of the box)
  const stop = Date.now() + NEXT_WATCH_MS;
  let timer = null;
  const tick = async () => {
    timer = null;
    if (!$('#done').hidden) return;                    // decided here: watchNext() looks for the next call from now on
    try {
      const items = await get('/api/approvals?status=pending');
      const y = newerPending(items, rid, agentOfThis);
      const me = (items || []).find((x) => x && x.rid === rid);
      if (y) {
        const what = inspectFields([['Call', (y.tool || 'call') + (y.action && y.action.recipient != null ? ': ' + String(y.action.recipient) : '')]], []).rows[0][1];
        const a = document.createElement('a'); a.href = 'approve.html?rid=' + encodeURIComponent(y.rid) + (fromTrial ? '&from=trial' : ''); a.textContent = 'Open it';
        a.addEventListener('click', () => markOpened(y.rid));
        note.replaceChildren((me && me.agent_waiting === false ? 'Your agent stopped waiting for this call and now asks something else: ' : 'The same agent now asks a newer call: ')
          + what + '. ', a, ' (this call stays here: you can still decide it).');
        note.hidden = false;
      } else note.hidden = true;
    } catch (e) {
      if (e && (e.status === 401 || e.status === 403)) return;
    }
    if (Date.now() < stop) timer = setTimeout(tick, document.hidden ? NEXT_POLL_HIDDEN_MS : NEXT_POLL_MS);
  };
  document.addEventListener('visibilitychange', () => { if (!document.hidden && timer) { clearTimeout(timer); tick(); } });
  timer = setTimeout(tick, NEXT_FIRST_MS);
}
// 0.2.77 (red team 31.10, remark 1): after Refuse the agent may ask again at once, and the next page opens by itself (watchNext). Freeze is
// then on the first screen: on the "Refused" result, and on the next calls of that agent opened from this tab within REFUSED_MS.
const REFUSED = 'dw_refused_agents';
function refusedAgents() { try { const o = JSON.parse(sessionStorage.getItem(REFUSED) || '{}'); return o && typeof o === 'object' ? o : {}; } catch (e) { return {}; } }
// 12.11 (r0263, L3 З4): the banner "You refused a call of this agent a moment ago, and it asks again" hung on EVERY next question (ls, pytest)
// after one refusal. It is said only when the agent asks again for the SAME act (the tool, the class and the target the witness refuses
// "like" for an hour: actions.refused_like): sameAct(). An entry of an older page (a bare time) matches nothing.
function markRefused(agent, key) { if (!agent) return; try { const o = refusedAgents(); o[agent] = { t: Date.now(), k: String(key || '') }; sessionStorage.setItem(REFUSED, JSON.stringify(o)); } catch (e) { /* private mode */ } }
function freezeRow(agent, id, lead) {
  const d = document.createElement('div'); d.id = id; d.className = 'notice warn freezenow';
  const p = document.createElement('p'); p.textContent = lead;
  const b = document.createElement('button'); b.type = 'button'; b.className = 'btn danger'; b.id = id + '_btn'; b.textContent = 'Freeze this agent';
  b.addEventListener('click', async () => {
    if (!confirm('Freeze this agent? Everything it is waiting for is refused and its new calls are refused until you unfreeze it (Agents page).')) return;
    b.disabled = true;
    try {
      const x = await post('/api/agents/' + encodeURIComponent(agent) + '/freeze');
      p.textContent = 'Agent frozen. Requests cancelled: ' + x.cancelled + '. Its new calls are refused until you unfreeze it on the Agents page.'; b.hidden = true;
    } catch (e) { p.textContent = failText(e); b.disabled = false; }
  });
  d.append(p, b);
  return d;
}
function done(head, text, refused = false) {
  $('#box').hidden = true; $('#done').hidden = false; $('#donehead').textContent = head; $('#donetext').textContent = text;
  if (refused && agentOfThis) {
    markRefused(agentOfThis, keyOfThis);
    $('#donetext').after(freezeRow(agentOfThis, 'donefreeze', 'Did not expect this call? Freeze stops this agent now: nothing it asks runs until you unfreeze it.'));
  }
  if (!refused) mountOffer(window, $('#pushoffer')).catch(() => {});     // 0.2.96: "Get questions on your phone" after the passkey touch
  if (!fromTrial) { watchNext(); return; }
  const a = document.createElement('a'); a.href = 'trial.html'; a.textContent = 'Back to your trial page';
  $('#donetext').append(' Going back to your trial page, which shows your agent\'s next call by itself… ', a);
  setTimeout(() => { location.href = 'trial.html'; }, BACK_TO_TRIAL_MS);
}

// 0.2.96 ("approved without reading", server app/uxstat.py): when the question was on screen, when the person first pressed a decision
// button (before the passkey prompt) and whether THEY opened Details (a click by the page itself does not count). Sent with the decision.
export const UX = { t0: 0, at: 0, details: false };
export const DECIDE_BTNS = ['yes', 'no', 'allow24', 'rel', 'rej', 'lc_ok', 'bgo'];
export function withUx(body) { return Object.assign({}, body, { ux: uxNow() }); }
const uxNow = () => uxReport(UX, (typeof performance !== 'undefined' ? performance.now() : Date.now()));
const pnow = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());
if (typeof document !== 'undefined') {
  document.addEventListener('click', (ev) => {
    if (!ev.isTrusted || !ev.target || !ev.target.closest) return;
    const sm = ev.target.closest('summary');
    if (sm && sm.parentElement && !sm.parentElement.open && sm.parentElement.id !== 'more_opts') UX.details = true;   // a fold of the details opened by the person
    const b = ev.target.closest('button');
    if (!b) return;
    if (DECIDE_BTNS.includes(b.id) && !UX.at) UX.at = pnow();
    if ((b.id === 'qw_btn' || b.id === 'tech_btn') && b.getAttribute('aria-expanded') === 'true') UX.details = true;
  }, true);
}

async function single(me) {
  if (!/^r_[A-Z2-7]+$/.test(rid)) { notice(msg, 'err', 'No approval request in this link.'); return; }
  markOpened(rid);
  const r = await get('/api/approvals/' + encodeURIComponent(rid));
  UX.t0 = pnow();
  agentOfThis = r.agent_id || (r.action && r.action.agent) || null;
  keyOfThis = actKey(r);
  get('/api/agents').then((l) => { const a = (Array.isArray(l) ? l : []).find((z) => z && z.id === agentOfThis); if (a && typeof a.name === 'string' && a.name) agentNameOfThis = a.name; }).catch(() => {});
  const held = r.status === 'held';
  const late = r.status === 'expired' && !!(r.repeat_offer && r.repeat_offer.eligible);     // 0.2.29: only for the agent's next runs
  if (r.status !== 'pending_approval' && !held && !late) {
    if (r.status === 'approved' && r.file_changed_by === 'late_write') { notice(msg, 'warn', lateWriteText(r.file_changed)); return; }   // 0.2.77b (R2-7)
    const t = { approved: 'This request was already approved.', refused: 'This request was already refused.', expired: 'This request has expired. The agent can ask again.', consumed: 'This approval was already used.' }[r.status];
    notice(msg, 'warn', t || 'This request is no longer waiting (status: ' + r.status + ').'); return;
  }
  // 27.10 (polygon O3): the hook that asked stopped waiting (Claude Code's timeout, Ctrl-C, a closed session). The request is still valid: the
  // owner may approve it and ask the agent to repeat the call (the quickstart path relies on that), so it is said, not cancelled.
  if (r.agent_waiting === false && !r.covered_by) showStopped(r.gave_up_at);    // 05.11: one short line by the buttons, no yellow plate (r0278: in place of the countdown)
  if (r.covered_by) notice(msg, 'ok', 'Already allowed for this project (' + r.covered_by + '): the agent repeats the call and it runs. Nothing else to decide here.');
  const aRows = describeAction(r.action), mRows = describeMandate(r.mandate);
  document.getElementById('main').classList.add('single');
  $('#more_opts').hidden = true;
  const ask = askOf(r);
  const askIns = inspectFields([], [['What', clip4k(ask.what || '')]]);
  // 05.11 (owner rule + owner at the phone, "too complex"): the first screen holds ONE sentence (what, the title), ONE short line of harm, ONE line
  // with the command, the three answers and a small timer. The reasons, the parts, the full text, the host / path, what changes, the undo, the
  // tool and every mark are under Details (#qw_more). The words come from the server's dictionary and are signed with the view.
  {
    const q = qwView(r);
    $('#title').textContent = q.what;
    $('#what').textContent = askIns.rows[0][1] || '(nothing to show)';      // Details, first level: the whole text of the call
    $('#qw_harm').textContent = q.harm; $('#qw_det').textContent = q.details; $('#qw').hidden = false;
    detHasText = /(^|\n)Full text:\n/.test(q.details);     // 12.11 (r0263): the signed words hold the whole text: the card does not repeat it
    const pbox = $('#qw_parts'); pbox.textContent = '';
    qwParts(r).forEach((p, i) => {
      const d = document.createElement('div'); d.className = 'qpart';
      const a = document.createElement('strong'); a.textContent = 'Part ' + (i + 2) + ': ' + p.what;
      const b = document.createElement('p'); b.textContent = p.harm;
      const pre = document.createElement('pre'); pre.className = 'qpartdet'; pre.textContent = p.details;
      d.append(a, b, pre); pbox.append(d);
    });
    const relayer = () => { gateGeo = null; gateApply(); gateCheck(); requestAnimationFrame(() => { gateGeo = gateGeom(); gateCheck(); }); };
    $('#qw_btn').addEventListener('click', () => {
      const open = $('#qw_more').hidden;
      $('#qw_more').hidden = !open; $('#qw_tech').hidden = !open; $('#qw_btn').setAttribute('aria-expanded', String(open)); $('#tech_btn').setAttribute('aria-expanded', String(open));      // 05.11: one level
      $('#qw_btn').innerHTML = open ? 'Details &#9662;' : 'Details &#9656;';
      relayer();
    });
    $('#tech_btn').addEventListener('click', () => {
      const open = $('#qw_tech').hidden;
      $('#qw_tech').hidden = !open; $('#tech_btn').setAttribute('aria-expanded', String(open));
      $('#tech_btn').innerHTML = open ? 'More technical &#9662;' : 'More technical &#9656;';
      relayer();
    });
    const rk = riskOf(r);                                   // the server's level (signed); the word is next to the colour
    $('#riskbar').hidden = !rk;
    if (rk) {
      $('#riskbar').dataset.level = rk.level; $('#riskbar').setAttribute('aria-label', rk.label); $('#risk_word').textContent = rk.label;
      [...$('#riskbar').querySelectorAll('i')].forEach((el, i) => { el.className = i < rk.n ? 'on' : ''; });
    }
    const sr = simpleRows(r, agentNameOfThis, askIns.rows[0][1]);               // Details, first level: who -> what -> where -> can it be undone
    const sri = inspectFields([['Where', sr.where], ['Who', sr.who]], []);
    $('#sx_where').textContent = sri.rows[0][1]; $('#sx_who').textContent = sri.rows[1][1]; $('#sx_undo').textContent = sr.undo; $('#sx_act').textContent = sr.act;
    get('/api/agents').then((l) => { const a = (Array.isArray(l) ? l : []).find((z) => z && z.id === agentOfThis); if (a && typeof a.name === 'string' && a.name) $('#sx_who').textContent = inspectFields([['Who', a.name]], []).rows[0][1]; }).catch(() => {});
  }
  const ins = inspectFields([...aRows.map(([k, v]) => ['Action / ' + k, v]), ...mRows.map(([k, v]) => ['Mandate / ' + k, v]), ['Tool', r.tool || ''], ['Arguments', r.args_preview || '']],
    [['Text', r.text_preview ? clip4k(r.text_preview) : '']]);
  renderHonest($('#honest'), [...ins.warnings, ...askIns.warnings]);
  // 0.2.39: the person reads what the call does; the hashes and the witness' checks (args_sha256, dlp_rs, toolmap_sha256 ...) are under Details
  const human = aRows.map(([k], i) => [k, ins.rows[i][1]]).filter(([k]) => HUMAN_FIELDS.includes(k)), tech = aRows.map(([k], i) => [k, ins.rows[i][1]]).filter(([k]) => !HUMAN_FIELDS.includes(k));
  // s7 (O1, O2): "Dangerous command" says what the server found (a changed file that runs, code that hides its host), not only the signed flag
  const ds = dangerShown(r.action, r);
  const hasDanger = human.some(([k]) => k === 'Dangerous command');
  fill($('#act'), ds === null ? human : hasDanger ? human.map(([k, v]) => (k === 'Dangerous command' ? [k, ds] : [k, v])) : [...human, ['Dangerous command', ds]]);
  // 12.11 (L3 repeat on 0.2.61): "Medium risk", then "Dangerous: this command can delete, overwrite or send out data", then (Details) "Nothing
  // on this command sends it anywhere" on one page. The server's own words of THIS act (harm, risk; signed) say the danger; the generic line
  // (a bare dangerous flag, nothing more specific) is not drawn next to a low or medium question. High / critical keep it (and its gate).
  const dtx = dangerText(ds, r), rk = riskOf(r);
  // r0278 (L3 13.11 with the owner, find 3: "dangerous" four times on one screen): a generic line (a command that can delete / send, a request to
  // the internet) is not drawn next to the server's harm line at ANY level: the harm line and the level are on the first screen already
  // r0280 (R-06): and a secret read whose signed words already name the keys / passwords (the line was "danger" no. 2 and held Allow
  // behind a Details that opened by itself)
  const dGeneric = dangerCovered(dtx, r) && !!rk;
  $('#dangerline').textContent = dGeneric ? '' : dtx; $('#dangerline').hidden = dGeneric || !dtx;      // 0.2.76: the mark in words, at the top
  if (typeof r.net_code === 'string' && r.net_code) {                  // s7 (O1): the code itself, as the witness got it (masked, <= 4 KB)
    const nc = inspectFields([], [['Code', clip4k(r.net_code)]]);          // 28.10: code keeps its lines
    const h = document.createElement('p'); h.className = 'hint'; h.textContent = 'Code it runs (talks to the network; the witness cannot tell where):';
    const pre = document.createElement('pre'); pre.className = 'netcode'; pre.textContent = nc.rows[0][1];
    $('#must').append(h, pre);                                          // 0.2.76: must be seen, never under Details
    if (nc.warnings.length) renderHonest($('#honest'), [...ins.warnings, ...nc.warnings]);
  }
  // RT-0.2.55c: a long line can hide a second command after the 4 KB the text preview shows: list every command of the line
  // 04.11 (red team p.1): a network lead has no list of its own: the list of the WHOLE line comes from the part asked with it
  const lcs = lineCommands(r);
  // 12.11 (r0263, "ВОПРОС -- ПРОСТО": no repeat): the first screen already names every command (cmdLine below); this list was the 2nd copy
  if (lcs && false) {
    const lc = inspectFields(lcs.map((c, i) => ['Command ' + (i + 1), String(c)]), []);
    const p = document.createElement('p'); p.id = 'linecmds'; p.className = 'notice warn';
    p.textContent = 'Commands in this line (' + lc.rows.length + '): ' + lc.rows.map(([, v]) => v).join(', ');
    $('#dangerline').after(p);                                          // 0.2.76: must be seen (a second command hides in a long line)
    if (lc.warnings.length) renderHonest($('#honest'), [...ins.warnings, ...lc.warnings]);
  }
  // 04.11 (Hypothesis I2, "signed != shown"): every command of the line IN FULL (the text preview stops at 4 KB; the list above names only
  // the programs): what must be seen is above the gate's end; only long echoes of plain words fold, with their number
  {
    // 05.11: the ONE line of the first screen. Several commands: "2 commands: curl, make deploy" (every command is named; the full text is under
    // Details and Allow waits for it). One command: the whole text when it is short and on one line, else cut with "…" (and Allow waits too).
    const hv = lcs && lcs.length > 1 ? inspectFields(lcs.map((c, i) => ['Command ' + (i + 1), String(c)]), []).rows.map(([, v]) => v) : null;
    // 12.11 (r0264): a LOW question: the full text of each command (never a cut 4 KB text, never folded echoes) may stand on the first screen
    const lf0 = hv && rk && rk.level === 'low' ? lineFull(r) : null;
    const whole = lf0 && !lf0.cut && !lf0.items.some((c) => c.fold) ? inspectFields([], lf0.all.map((c, i) => ['Command ' + (i + 1), c])).rows.map(([, v]) => v) : null;
    const cmd = cmdLine(hv, askIns.rows[0][1], whole);
    // 13.11 (r0271, ISPYTANIE-0266 Н3): the agent's prose stays off the first screen: comments and long strings fold (the whole text is
    // under Details, Allow waits for it), the line is labelled as the agent's, and words of a verdict get a warning. The signed view is
    // the server's members (text_preview, line_full ...), unchanged: Details shows them whole.
    const fl = (!hv || cmd.lines) ? cmd.text.split('\n').map(agentFold) : [];
    const folded = fl.some((f) => f.folded);
    const shown = folded ? fl.map((f) => f.text).join('\n') : cmd.text;
    $('#cmdline').textContent = shown; $('#cmdline').hidden = !shown;
    $('#cmdline').classList.toggle('lines', !!cmd.lines);
    const isCmd = /^Bash/.test(String(r.tool || ''));
    $('#cmd_by').textContent = CMD_BY; $('#cmd_by').hidden = !shown || !isCmd;
    const vw = isCmd ? agentVoice([askIns.rows[0][1] || '', ...(whole || [])].join('\n')) : '';
    $('#cmd_voice').textContent = vw ? VOICE_NOTE.replace('{w}', vw) : ''; $('#cmd_voice').hidden = !vw;
    cmdCut = cmd.cut || folded; autoOpened = false; manyCmds = !!hv && !cmd.lines;
    cmdWhole = !!cmd.lines;
    // 05.11 (outside UX review): the whole command is already on the first screen: Details does not repeat it
    const dup = !cmd.cut && !folded && !hv && cmd.text === (askIns.rows[0][1] || '');
    firstWhole = dup ? cmd.text : '';
    $('#what_dt').hidden = dup; $('#what_dd').hidden = dup;
    $('#what_parts').hidden = true; $('#what').hidden = false; $('#what_dt').textContent = 'Command';
  }
  const lf = lineFull(r);
  if (lf) {
    const box = document.createElement('div'); box.id = 'linefull'; box.className = 'notice warn';
    const fi = inspectFields([], lf.all.map((c, i) => ['Command ' + (i + 1), c]));
    const at = new Map(lf.all.map((c, i) => [i, fi.rows[i][1]]));
    const hd = document.createElement('p');
    hd.textContent = 'Every command of this line, in full (' + lf.all.length + ')' + (lf.cut ? '. The text of the call is longer than 4 KB and is cut below; this list is not cut:' : ':');
    box.append(hd);
    const ol = document.createElement('ol'); ol.className = 'linefull';
    const fold = [];
    lf.items.forEach((c, k) => {
      const li = document.createElement('li'); const pre = document.createElement('pre'); pre.className = 'netcode'; pre.textContent = at.get(k); li.append(pre);
      if (c.fold) fold.push(li); else ol.append(li);
    });
    box.append(ol);
    // 12.11 (r0263): the full list is drawn ONCE: in the Details card (below) unless the text is cut at 4 KB or long echoes fold
    const fullHere = lf.cut || lf.items.some((c) => c.fold);
    // 05.11 (outside UX review): several commands: each in its own frame right in the Details card, not one run-on text
    if (lf.all.length > 1 && !fullHere && !cmdWhole) {
      const wp = $('#what_parts'); wp.textContent = '';
      lf.all.forEach((c, i) => { const pre = document.createElement('pre'); pre.className = 'what cmdpart'; pre.textContent = (i + 1) + '. ' + at.get(i); wp.append(pre); });
      wp.hidden = false; $('#what').hidden = true; $('#what_dt').textContent = 'Commands';
    }
    if (fold.length) {
      const d = document.createElement('details'); d.id = 'linefold';
      const s = document.createElement('summary'); s.textContent = fold.length + (fold.length > 1 ? ' long echo commands' : ' long echo command') + ' of plain text (they only print it), folded: show';
      const ol2 = document.createElement('ol'); ol2.append(...fold); d.append(s, ol2); box.append(d);
    }
    if (fullHere) { ($('#linecmds') || $('#dangerline')).after(box); $('#what_dt').hidden = $('#what_dd').hidden = true; }
    if (fi.warnings.length) renderHonest($('#honest'), [...ins.warnings, ...fi.warnings]);
  }
  if (detHasText && !$('#qw_parts').childElementCount) {
    $('#what_dt').hidden = $('#what_dd').hidden = true;             // 12.11 (r0263): one full copy of the call in Details (the signed words)
  }
  // 04.11 (L3): one tool call = one question: every reason the witness asked about, in this one place (the answer decides all parts)
  // red team p.4: in words, never the codes (ESCALATE_COMMAND ...)
  if (Array.isArray(r.line_reasons) && r.line_reasons.length > 1) {
    const p = document.createElement('p'); p.id = 'linereasons'; p.className = 'notice warn';
    p.textContent = 'This one call is asked about for ' + r.line_reasons.length + ' reasons: ' + [...new Set(r.line_reasons.map(reasonWords))].join('; ') + '. Your answer decides all of them.';
    $('#qw_det').before(p);             // 05.11: the reasons are under Details (the first screen says it once, in `harm`)
  }
  // red team p.1 ("signed != shown"): one answer signs every part asked with this one, each with its own view: each part is SHOWN here, in
  // full (what must be seen of it: commands, danger, code, files, masked values, the text), above the gate's end
  if (Array.isArray(r.line_group) && r.line_group.length) {
    const box = document.createElement('div'); box.id = 'lineparts';
    const n = r.line_group.length + 1;
    const ws = [];
    r.line_group.forEach((g, i) => {
      const pl = partLines(g, i + 1, n, lf);
      const d = document.createElement('div'); d.className = 'notice warn linepart'; d.dataset.rid = String(g.rid || '');
      for (const it of pl.items) {
        const e = document.createElement(it.kind === 'pre' ? 'pre' : it.kind === 'head' ? 'strong' : 'p');
        if (it.kind === 'pre') e.className = 'netcode'; else if (it.kind === 'hint') e.className = 'hint';
        e.textContent = it.text; d.append(e);
      }
      ws.push(...pl.warnings); box.append(d);
    });
    // r0278 (find 3): parts that repeat the first screen (the same command, generic danger, nothing else) are shown under Details, after
    // what must be read; they do not hold Allow back. Any other part stays in #must (read before Allow), as before.
    const same = !ws.length && r.line_group.every((g) => partRedundant(g, firstWhole, lf));
    if (same) { box.className = 'hint lineparts-same'; for (const d of box.children) d.className = 'linepart'; $('#mustend').after(box); }
    else $('#must').append(box);
    if (ws.length) renderHonest($('#honest'), [...ins.warnings, ...ws]);
  }
  // 29.10 MDEP: the witness asks because it could not resolve a value, and that value is masked by its name (part of the signed view)
  if (Array.isArray(r.masked_dep) && r.masked_dep.length) {
    const md = document.createElement('p'); md.id = 'maskdep'; md.className = 'hint';
    md.textContent = 'This decision depends on ' + (r.masked_dep.length > 1 ? 'masked values: ' : 'a masked value: ') + r.masked_dep.map(String).join(', ');
    md.className = 'notice warn'; $('#dangerline').after(md);            // 0.2.76: must be seen, at the top
  }
  fill($('#acttech'), tech);
  fill($('#man'), mRows.map(([k], i) => [k, ins.rows[aRows.length + i][1]]));
  const tShown = ins.rows[aRows.length + mRows.length][1], aShown = ins.rows[aRows.length + mRows.length + 1][1], xShown = ins.rows[aRows.length + mRows.length + 2][1];
  const adv = r.reason === 'ESCALATE_SECRET_SEEN'
    ? 'Held: this agent read a secret in the last minutes (a credential file or a token in its own call). The mandate allows this call, but it can carry data out or run code the agent wrote, so you decide.'
    : r.reason === 'ESCALATE_USER_CONTENT_HOST'
    ? 'Held: this request carries data (a query string or an upload) to a site where anyone can publish or read what is sent (GitHub, gists, pastebins, webhooks), or goes to a request catcher or tunnel. The mandate allows the domain, but this is a way to send data out, so you decide.'
    : r.reason === 'ESCALATE_WRITTEN_RUN'
    ? 'Held (ESCALATE_WRITTEN_RUN): this command runs code, and this agent wrote earlier a file that this code can run or load (an import, a source, a call)' + (r.written_run && r.written_run.files && r.written_run.files.length ? ' (' + r.written_run.files.join(', ') + ')' : '') + '. The witness could not read what the agent put into it (a shell write, a copy, a download), or what it read talks to the network or builds the code it runs. Look at the file before you release it.'
    : r.reason === 'ESCALATE_NET_UNSEEN'
    ? 'Held: this command runs a network program, but the destination is not in the line (it comes from a file or a variable). The witness cannot tell where the data goes, so you decide.'
    : r.reason === 'ESCALATE_SECRET_COPY'
    ? 'Held: this file is a copy this agent made earlier of a secret (a credential file). The mandate allows reading the file, but reading the copy reads the secret, so you decide.'
    : advisoryText(r) || (held ? 'Held by the data advisor (' + (r.reason || 'ADVISORY_HOLD') + '): the mandate allows this action, but the advisor flagged its text. A hint, not a decision.' : '');
  // r25 (s8 P2, P3): a question of the mandate or a secret hold that ALSO runs a file the agent wrote: both reasons are said
  const wrunFiles = r.written_run && Array.isArray(r.written_run.files) ? r.written_run.files : [];
  const adv1 = wrunFiles.length && r.reason !== 'ESCALATE_WRITTEN_RUN'
    ? (adv ? adv + ' ' : '') + 'It also runs a file this agent wrote earlier (' + wrunFiles.join(', ') + '): read what was written, shown below, before you decide.'
    : adv;
  // N4 29.10: an archive / a patch / git objects written into the project: the text is not in the line, the witness cannot show it
  const uw = r.unseen_write && Array.isArray(r.unseen_write.paths) ? r.unseen_write.paths : [];
  const adv2 = uw.length
    ? (adv1 ? adv1 + ' ' : '') + 'It writes files whose text the witness cannot see (an archive, a patch or git objects): ' + uw.join(', ') + '. Whatever it puts there is unseen; a later run of it is asked again.'
      + (r.unseen_write.secret === true && r.reason !== 'ESCALATE_SECRET_SEEN' ? ' This agent read a secret in the last minutes: what it writes may carry it.' : '')
    : adv1;
  $('#advmark').hidden = !adv2; $('#advmark').textContent = adv2;
  const sl = held ? '' : secretLead(r);                                // N20 0.2.74: the page opens on what is asked: a secret read
  if (sl) {
    $('#boxlead').textContent = sl;
    // r0280 (R-06, rule "signed = shown"): the title stays the server's signed `what` (qwords names a secret read: "keys or passwords");
    // the page no longer writes its own title over it (05.11 "Your agent wants to read a secret" was the page's words, not signed ones)
  }
  if (r.written_run && Array.isArray(r.written_run.writes)) {          // 28.10: what the agent wrote into the file this command runs (masked, <= 4 KB)
    let at = $('#advmark');                                            // r25 (s8 P5): in the server's order (the file the line runs first)
    for (const w of r.written_run.writes) {
      const h = document.createElement('p'); h.className = 'hint';
      // N14 0.2.73: a git line (stash pop / restore) brought back what the agent had put into git; the witness saw that text written
      const gx = Array.isArray(w.git_texts) ? w.git_texts.filter((g) => g && typeof g.text === 'string' && g.text) : [];
      h.textContent = (w.by === 'shell' ? 'The agent\'s shell command that wrote ' + (w.file || 'the file')
          + (gx.length ? ' (a git line: it brings back what the agent had put into git; the text the agent last wrote there is shown below)' : ' (if it copies or downloads, the content itself is not shown and approving runs it blind)')
        : 'Written by the agent (' + (w.by || 'a write') + ') into ' + (w.file || 'the file')) + ':';
      at.after(h); at = h;
      if (typeof w.text === 'string' && w.text) {
        const wi = inspectFields([], [['Written', w.text]]);
        const pre = document.createElement('pre'); pre.className = 'netcode'; pre.textContent = wi.rows[0][1]; h.after(pre); at = pre;
        if (wi.warnings.length) renderHonest($('#honest'), [...ins.warnings, ...wi.warnings]);
      } else {
        // r25 (s8 P4): only a write the witness did not read is "blind"; a Write whose text was shown on a request you already let go is
        // not kept after that decision (privacy) -- the page says so instead of "could not read"
        const n = document.createElement('p'); n.className = 'notice warn';
        n.textContent = w.cut === true
          ? 'Its text was shown on an earlier request about this file that you let run; it is not kept after that decision. Open the file to read it again before approving.'
          : !['Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'Write.danger'].includes(w.by)
          ? 'The witness could not read what was written (a copy, a download or a file it did not see). Approving runs it blind.'
          : 'The witness read this write when it was made but did not keep its text for this page. Open the file to read it before approving.';
        h.after(n); at = n;
      }
      for (const g of gx) {
        const gh = document.createElement('p'); gh.className = 'hint';
        gh.textContent = 'Last written by the agent into ' + (g.file || 'the file') + ' before that git line (as the witness saw it; git may bring back this text or an older one):';
        at.after(gh); at = gh;
        const gi = inspectFields([], [['Written', g.text]]);
        const pre = document.createElement('pre'); pre.className = 'netcode'; pre.textContent = gi.rows[0][1]; gh.after(pre); at = pre;
        if (gi.warnings.length) renderHonest($('#honest'), [...ins.warnings, ...gi.warnings]);
      }
    }
  }
  // 28.10 the bar was unstuck on a dangerous / held / changed-file call so the person scrolled past the warning to reach it. 0.2.76 (owner
  // 31.10: buttons on the first screen): the bar stays at the bottom of the screen, and the gate (gateStart) keeps Approve / Release disabled
  // until everything in #must has been on screen above it. Refuse / Reject work at once.
  if (held) {                                                          // 28.10 (browser check): say what Release does BEFORE the click
    const rh = document.createElement('p'); rh.className = 'hint';
    rh.textContent = 'Release: the witness judges this call as usual and the agent may run it. Reject: it is refused and nothing runs. Both are signed with your passkey.';
    $('#more').prepend(rh);                                             // 0.2.76: under Details, the buttons say it
    $('#release').prepend($('#stale'), $('#left'), $('#gate'));
  }
  // 0.2.13: where it may be confirmed (laptop / phone, delegation) and which executed files changed (the server's view; shown, not signed)
  let ks = null;
  try { ks = keySummary((await get('/api/auth/keys')).keys); } catch (e) { ks = null; }   // 0.2.23: only the words depend on it; no answer -> the general text
  const lv = levelView(r.confirm, ks, r);
  $('#level').hidden = !lv.show; $('#level').textContent = lv.text; $('#level').className = 'notice ' + lv.cls;
  // 0.2.76: where to confirm is under Details, unless the person has to act first (no passkey counts as phone): then it is on top
  if (lv.show && r.confirm && r.confirm.level === 'phone' && ks && ks.phone === 0) $('#must').prepend($('#level'));
  const ev = execView(r.exec_changed);
  $('#execbox').hidden = !ev.show;
  if (ev.show) {
    const fi = inspectFields(ev.files.map((f, i) => ['File ' + (i + 1), f]), []);
    $('#exechead').textContent = ev.head; $('#execnote').textContent = ev.note;
    $('#execfiles').replaceChildren(...fi.rows.map(([, v]) => { const li = document.createElement('li'); li.textContent = v; return li; }));
    if (fi.warnings.length) renderHonest($('#honest'), [...ins.warnings, ...fi.warnings]);
    // s7 (O2): network lines the witness found in the change, or that the content was never sent (the approval is blind)
    const old = document.getElementById('execrisk'); if (old) old.remove();
    if (ev.risk.note || ev.risk.lines.length) {
      const box = document.createElement('div'); box.id = 'execrisk';
      const p = document.createElement('p'); p.textContent = (ev.risk.dangerous ? 'Dangerous: ' : '') + ev.risk.note; box.append(p);
      if (ev.risk.lines.length) {
        const ri = inspectFields(ev.risk.lines.map((l, i) => ['Line ' + (i + 1), l]), []);
        const ul = document.createElement('ul');
        ul.append(...ri.rows.map(([, v]) => { const li = document.createElement('li'); const c = document.createElement('code'); c.textContent = v; li.append(c); return li; }));
        box.append(ul);
        if (ri.warnings.length) renderHonest($('#honest'), [...ins.warnings, ...ri.warnings]);
      }
      for (const pv of ev.risk.previews) {          // 0.2.43b: the changed file's text as the hook read it (masked, <= 4 KB)
        const pi = inspectFields([], [['Content', pv.text]]);      // 28.10: a file keeps its lines (as a text, not a one-line field)
        const h = document.createElement('p'); h.textContent = 'Content of ' + pv.file + (pv.cut ? ' (first 4 KB; the file is longer)' : '') + ' as sent by the agent\'s machine:';
        const pre = document.createElement('pre'); pre.className = 'netcode'; pre.textContent = pi.rows[0][1];
        box.append(h, pre);
        if (pi.warnings.length) renderHonest($('#honest'), [...ins.warnings, ...pi.warnings]);
      }
      $('#execbox').append(box);
    }
  }
  // pv2810: the passkey signs the hash of what this page shows (signview.js); the server rebuilds it and refuses another one
  const sv = await signedView(r);
  $('#pvnote').textContent = (sv.view ? 'Signed with your decision: the hash of everything this page shows (the action, the danger mark, these previews, the files and the code above; view ' + sv.hex.slice(0, 16) + '…).'
    : (r.preview_note || 'Shown by this page, not signed.')) + ' Secrets and your closed-data literals are replaced by [masked]; long text is cut.';
  if (sv.same === false) notice(msg, 'warn', 'This page and the witness disagree on what is shown (view hash). Reload the page before you decide: the witness refuses a signature over another view.');
  $('#pvargs').textContent = 'Tool: ' + tShown + '\nArguments (first 300 characters): ' + aShown;
  $('#pvtext').textContent = r.text_preview ? xShown : '';
  // 0.2.76: the text the call sends stays on screen, unless it is exactly the command already shown as the title
  $('#pvblock').hidden = !r.text_preview || xShown === $('#what').textContent;
  if (protectedTarget(r)) $('#pvlabel').textContent = 'What it writes into this file:';      // 0.2.77 (H1)
  const tick = () => { const u = until(r.expires); $('#left').textContent = u === 'expired' ? 'Time is up' : u.replace(/ left$/, ' left to decide'); };
  if (late) {
    $('#title').textContent = 'This request expired';
    notice(msg, 'warn', 'Nobody answered in time, so this call was not run, and this request can no longer be approved. You can still approve the same call for this agent\'s next runs.');
    $('#left').textContent = 'Expired: ' + new Date(r.expires * 1000).toLocaleString() + '.';
  } else { tick(); setInterval(tick, 1000); if (!r.covered_by) followWait(); }
  if (!late && r.agent_waiting !== false) {      // 0.2.78: how long the agent still waits, and what comes after (the call's start: the pending list, `t`)
    const p = document.createElement('div'); p.id = 'agentwait'; p.className = 'hint agentwait'; p.hidden = true;
    const sh = document.createElement('span'); sh.id = 'agentwait-short';        // 0.2.79 (edit 2): one short line first, the full promise under "why?"
    const dt = document.createElement('details'); dt.id = 'agentwait-why';
    const sm = document.createElement('summary'); sm.textContent = 'why?';
    const fl = document.createElement('p'); fl.id = 'agentwait-full';
    dt.append(sm, fl); p.append(sh, dt);
    let created = null;
    const upd = () => {
      if (typeof created !== 'number') return;
      p.hidden = false;
      const m = stoppedAt ? 0 : Math.ceil(created + HOOK_WAIT_S - Date.now() / 1000);      // seconds (r0278: 0 once the server says the hook gave up)
      sh.textContent = m > 0
        ? 'Your agent is waiting (about ' + m + ' s). Approving later still counts.'
        : 'Your agent stopped waiting. Approving still counts.';
      fl.textContent = m > 0
        ? 'Your agent waits for this answer about ' + m + ' s more (its hook waits ' + HOOK_WAIT_S + ' s from the call). Approve in that time and the call runs at once. Later, but before the time above runs out, your approval still counts: the agent repeats the same call and it runs once.'
        : 'Your agent has stopped waiting. Your approval still counts until the time above runs out: when the agent repeats the same call, it runs once.';
    };
    $('#qw_more').append(p);            // 05.11: under Details (the first screen has the timer and, if the agent stopped, one line)
    (async () => { try { const it = (await get('/api/approvals?status=pending')).find((z) => z.rid === rid); if (it && typeof it.t === 'number') { created = it.t; upd(); setInterval(upd, 5000); } } catch (e) { /* no line, the page works without it */ } })();
  }
  if (!late && r.asked_again && typeof r.asked_again.file === 'string') {      // 0.2.77b (R2-7): why the same command is asked again
    const p = document.createElement('p'); p.id = 'askedagain'; p.className = 'notice warn';
    p.textContent = 'You approved this command before. ' + lateWriteText(r.asked_again.file);
    ($('#cmdline').hidden ? $('#qw_harmline') : $('#cmdline')).after(p);       // 05.11: stays on the first screen (a repeated ask is a warning)
  }
  if (!late && refusedRecently(agentOfThis, refusedAgents(), Date.now(), actKey(r))) {    // 0.2.77; 12.11 (r0263): only for the same act
    ($('#cmdline').hidden ? $('#qw_harmline') : $('#cmdline')).after(freezeRow(agentOfThis, 'freezetop', 'You refused this a moment ago, and your agent asks for it again.'));   // 05.11: the first screen
  }
  $('#box').hidden = false;
  if (!late) watchNewer();                             // N2 (27.10)
  let unav = '';                                       // 0.2.76: an option that cannot be chosen is not drawn as a choice
  // 0.2.24 (critique T2): stop this agent: everything it waits for is cancelled, every new call is refused until the owner unfreezes it
  $('#freeze').addEventListener('click', async () => {
    const aid = r.action && r.action.agent;
    if (!aid || !confirm('Freeze this agent? Everything it is waiting for is refused and its new calls are refused until the owner unfreezes it (Agents page).')) return;
    $('#freeze').disabled = true;
    try {
      const x = await post('/api/agents/' + encodeURIComponent(aid) + '/freeze');
      notice(msg, 'warn', 'Agent frozen. Requests cancelled: ' + x.cancelled + '. Its new calls are refused until the owner unfreezes it.');
    } catch (e) { notice(msg, 'err', failText(e)); $('#freeze').disabled = false; }
  });
  $('#sus').addEventListener('click', async () => {
    $('#sus').disabled = true;
    try {
      const x = await post('/api/push/suspicious', { rid });
      notice(msg, 'warn', mutedText(x.muted_until));
    } catch (e) { notice(msg, 'err', failText(e)); $('#sus').disabled = false; }
  });

  if (held) {
    // N5 29.10: a hold means the mandate ALLOWS the call (the witness or the advisor holds it), not "does not clearly allow"
    $('#boxlead').textContent = ['ESCALATE_SECRET_SEEN', 'ESCALATE_USER_CONTENT_HOST', 'ESCALATE_NET_UNSEEN', 'ESCALATE_WRITTEN_RUN', 'ESCALATE_SECRET_COPY'].includes(r.reason)
      ? 'Your mandate allows this call, but the witness holds it for you to decide.' : 'Your mandate allows this call, but the data advisor flagged it.';
    $('#decide').hidden = true; $('#release').hidden = false;
    gateStart();
    const go = async (release) => {
      if (release) gateSeen = true;
      $('#rel').disabled = $('#rej').disabled = true;
      try { const x = await decideHeld({ rid, action: r.action }, release, me, sv.view); if (release && x && x.file_changed) { done('Not run', changedText(x)); return; } done(release ? 'Released' : 'Rejected', release ? 'The witness now judges the action as usual (' + x.verdict + ', ' + x.reason + '). Your release is recorded in the receipt.' : 'The action was refused (' + x.reason + '). Nothing was executed.', !release); }
      catch (e) { notice(msg, 'err', e.code ? failText(e) : explainError(e)); unlock(); }
    };
    $('#rel').addEventListener('click', () => go(true));
    $('#rej').addEventListener('click', () => go(false));
    return;
  }

  const prepared = {};
  for (const approved of [true, false]) prepared[approved] = await approvalPayload(rid, r.mandate, r.action, approved, sv.view);
  const show = async (approved) => {
    $('#hexp').textContent = bytesToHex(prepared[approved]);
    $('#hexc').textContent = bytesToHex(await challenge(TYP_APPROVAL, prepared[approved]));
  };
  await show(true);

  // 0.2.10: "Allow this command in this project" (an unlisted, not dangerous shell command only; the server says whether it is possible)
  const got = Date.now();
  // 04.11 (owner): a call of several parts is approved once: no "24 h / in this project" and no "later runs" (the parts linked to it would
  // come back later as questions of their own)
  const multi = Array.isArray(r.line_group) && r.line_group.length > 0;
  const ov = multi ? { show: false, enabled: false } : offerView(r.allowance_offer);
  $('#allow').hidden = !ov.enabled;
  if (ov.show && !ov.enabled) unav += ov.label + ': ' + ov.note + ' ';
  if (ov.show) {
    $('#allow_label').textContent = ov.label;
    $('#allow_note').textContent = ov.note;
    $('#allow_cb').disabled = !ov.enabled;
    $('#allow_trust').textContent = TRUST_TEXT;
    $('#allow_trust').hidden = !ov.enabled;            // 0.2.51: the honest text is on screen whenever a permission can be signed
    $('#allow_cb').addEventListener('change', () => { $('#allow_more').hidden = !$('#allow_cb').checked; });
  }
  // 0.2.51: "Allow for 24 h in this project" is the first button when the command can be allowed: one question, then a day without asking
  // 05.11 (owner rule): the three answers are always on screen: "Allow once" / "Allow this from now on" / "Deny". "From now on" is the
  // project allowance (exact commands, this project, this agent, 30 days; listed on Project permissions, revoked in one tap); for a line,
  // one on each part. Where the server does not offer it (a dangerous command, a secret to the network, a file ...) the button is off and says why.
  const lp = laterPlan(r);
  $('#allow24').hidden = !!late;
  laterOff = !lp.ok; fixLater();
  if (!lp.ok && !late) {          // 05.11: one short line by the buttons; the full reason is under Details
    $('#later_note').textContent = laterShort(r); $('#later_note').hidden = false;
    $('#later_why').textContent = 'Only "Allow once" is available here: ' + lp.why + '.'; $('#later_why').hidden = false;
  }
  // 0.2.55: one main choice. With the 24 h button on screen, the checkboxes (longer time, later runs) fold under "More options" and the plain button says "Approve once"
  const day24 = !!ov.enabled && !late;   // (kept: the layout of "More options")
  $('#more_opts').open = false;
  const once = 'Allow once';
  const allowForProject = async (days) => {
    const o = r.allowance_offer;
    const id = newAllowanceId();
    const payload = await allowancePayload(o, r.mandate, days || $('#allow_days').value, o.t + (Date.now() - got) / 1000, id, sv.view);   // pv2
    $('#hexp').textContent = bytesToHex(payload);
    $('#hexc').textContent = bytesToHex(await challenge(TYP_ALLOWANCE, payload));
    const envelope_b64 = await signPayload(TYP_ALLOWANCE, payload, me);
    const res = await post('/api/allowances', withUx(sv.view ? { rid, envelope_b64, view_sha256: sv.hex } : { rid, envelope_b64 }));
    done('Allowed in this project', res.commands.join(', ') + ' now runs without a question in ' + res.project + ' until ' + untilText(res.exp)
      + '. The agent repeats the call. Every receipt it lets through names this permission; revoke it on Project permissions.');
  };

  // 05.11: "Allow this from now on" for a line: each part (and the lead) gets its own allowance, signed over its own view; all or nothing is
  // shown to the person: a part that fails is named, the call does not run until every part is covered
  const allowFromNow = async () => {
    if (!lp.ok) throw Object.assign(new Error('Only "Allow once" is available here: ' + lp.why + '.'), { shown: true });
    if (lp.items.length === 1) { await allowForProject(String(LATER_DAYS)); return; }
    if (!sv.view) throw Object.assign(new Error('The witness could not build what this page shows of this call.'), { code: 'LINE_VIEW' });
    const rows = [...lp.items.slice(1), lp.items[0]];                 // the parts first, the lead last
    let n = 0;
    for (const it of rows) {
      const lead = it === lp.items[0];
      const view = lead ? sv.view : await viewHash(it.part.view);
      const hex = lead ? sv.hex : bytesToHex(view);
      if (!lead && hex !== it.hex) throw Object.assign(new Error('This page and the witness disagree on what a part of this call shows.'), { code: 'VIEW_CHANGED' });
      const payload = await allowancePayload(it.offer, it.mandate, LATER_DAYS, it.offer.t + (Date.now() - got) / 1000, newAllowanceId(), view);
      const envelope_b64 = await signPayload(TYP_ALLOWANCE, payload, me);
      try { await post('/api/allowances', withUx({ rid: it.rid, envelope_b64, view_sha256: hex })); } catch (e) {
        throw Object.assign(new Error((n ? n + ' of ' + rows.length + ' parts were allowed from now on; the call does not run until every part is covered. ' : '') + 'A part could not be allowed from now on (' + failText(e) + '). You can still allow it once.'), { shown: true });
      }
      n++;
    }
    done('Allowed from now on', 'Each of the ' + rows.length + ' parts of this call is allowed on its own in this project for ' + LATER_DAYS + ' days. The agent repeats the call. Revoke any of them on Project permissions.');
  };

  // 0.2.29: "Also approve this exact call for this agent's later runs" (one batch signature over this request and the ids of the later uses)
  const rv = multi ? { show: false, enabled: false } : repeatView(r.repeat_offer);
  $('#repeat').hidden = !rv.enabled;
  if (rv.show && !rv.enabled) unav += 'Also approve this exact call for later runs: ' + (rv.note || 'not possible here.') + ' ';
  $('#rep_cmd').hidden = !(r.repeat_offer && r.repeat_offer.command);   // 0.2.30 (B1): the line is approved, not the content of the script it runs
  const label = () => { $('#yes').textContent = $('#allow_cb').checked ? 'Allow in this project' : $('#rep_cb').checked ? 'Approve now and for later runs' : once; };
  label();
  let plan = null;
  const replan = () => {
    const o = r.repeat_offer;
    plan = planRids($('#rep_uses').value, $('#rep_hours').value, o.t + (Date.now() - got) / 1000);
    const p = readPlan(plan.rids);                      // the summary is read back from the ids that will be signed
    $('#rep_sum').textContent = p ? summaryText(p, r.tool, late) : 'This plan cannot be signed.';
  };
  if (rv.show) {
    if (!rv.enabled) { $('#rep_note').textContent = rv.note; $('#rep_cb').disabled = true; }
    $('#rep_cb').addEventListener('change', () => {
      $('#rep_more').hidden = !$('#rep_cb').checked;
      if ($('#rep_cb').checked) { replan(); if (ov.show) { $('#allow_cb').checked = false; $('#allow_more').hidden = true; } }
      label();
    });
    $('#rep_uses').addEventListener('change', replan);
    $('#rep_hours').addEventListener('change', replan);
  }
  if (late) {
    $('#rep_cb').checked = true; $('#rep_cb').disabled = true; $('#rep_more').hidden = false; $('#allow').hidden = true; $('#allow_trust').hidden = true; $('#no').hidden = true;
    replan(); $('#yes').textContent = 'Approve for the next runs';
    $('#repeat').hidden = false;
  }
  // 0.2.76: "More options" only when it holds a choice; folded, except for an expired request (its plan is what is signed: on screen, above the gate)
  $('#more_opts').hidden = !(ov.enabled || rv.enabled || late);
  $('#more_sum').hidden = !!late; $('#more_opts').open = !!late;
  if (late) { $('#qw_more').hidden = false; $('#qw_tech').hidden = false; $('#qw_btn').setAttribute('aria-expanded', 'true'); $('#qw_btn').innerHTML = 'Details &#9662;'; $('#tech_btn').setAttribute('aria-expanded', 'true'); $('#tech_btn').innerHTML = 'More technical &#9662;'; }   // 05.11: an expired request shows its plan at once
  $('#more_sum').textContent = ov.enabled ? 'More options: a longer time, or this agent\'s later runs' : 'More options: also approve this call for this agent\'s later runs';
  if (late) $('#rep_sum').after($('#mustend'));
  $('#unavail').textContent = unav.trim() ? 'Not available for this call: ' + unav.trim() : ''; $('#unavail').hidden = !unav.trim();
  if (ov.show) $('#allow_cb').addEventListener('change', () => { if ($('#allow_cb').checked && rv.show) { $('#rep_cb').checked = false; $('#rep_more').hidden = true; } label(); });
  const approveForLater = async () => {
    replan();                                            // fresh ids and a fresh time limit at the moment of signing
    const p = readPlan(plan.rids, r.repeat_offer.t + (Date.now() - got) / 1000);
    if (!p) throw new Error('This plan cannot be signed.');
    $('#rep_sum').textContent = summaryText(p, r.tool, late);
    const items = await repeatItems(rid, r.mandate, r.action, plan.rids, late, sv.view);     // pv2: the view is in every item
    $('#hexp').textContent = items.map(bytesToHex).join('\n');
    $('#hexc').textContent = bytesToHex(await wbChallenge(items));
    const envelope_b64 = await signBatch(items, me);
    const res = await post('/api/approvals/' + encodeURIComponent(rid), withUx(sv.view ? { approved: true, envelope_b64, repeat: { rids: plan.rids }, view_sha256: sv.hex } : { approved: true, envelope_b64, repeat: { rids: plan.rids } }));
    if (late) {
      done('Approved for the next runs', 'The same call of this agent with exactly these arguments runs ' + (res.repeat.uses === 1 ? '1 time' : res.repeat.uses + ' times')
        + ' in its next runs until ' + untilTime(res.repeat.exp) + ' without asking you. Every receipt it lets through names your signature; revoke it on Permissions.');
      return;
    }
    done('Approved, also for later runs', 'The agent can repeat this call now. The same call of this agent with exactly these arguments also runs '
      + (res.repeat.uses === 1 ? '1 more time' : res.repeat.uses + ' more times') + ' until ' + untilTime(res.repeat.exp)
      + ' without asking you. Every receipt it lets through names your signature; revoke it on Permissions.');
  };

  // 04.11 (L3): one tool call = one question. The witness judged the parts of this line separately (each has its own receipt) but asked once:
  // this page is the lead; one passkey prompt signs ONE batch (wb) over the lead and the parts asked with it, each with its own view.
  // red team p.1, p.2: each part is signed with the view THIS page rendered (r.line_group[i].view, its hash checked against the witness'); a
  // part whose view is missing is never signed "view not signed": an approval stops with an error, a refusal refuses the lead alone (the
  // witness then withdraws the parts asked with it). p.3: the result is said part by part.
  const refuseLead = async () => {
    await show(false);
    const envelope_b64 = await signPayload(TYP_APPROVAL, prepared[false], me);
    const res = await post('/api/approvals/' + encodeURIComponent(rid), withUx(sv.view ? { approved: false, envelope_b64, view_sha256: sv.hex } : { approved: false, envelope_b64 }));
    done('Refused', 'The agent was refused' + (res.verdict === 'refused' ? '' : ' (' + res.verdict + ')') + '. Nothing was executed.', true);
  };
  const decideLine = async (approved) => {
    let rows;
    try { rows = await lineRows(r, sv); } catch (e) {
      if (!approved && e.code === 'LINE_VIEW') { await refuseLead(); return; }
      throw e;
    }
    const { items } = await batchItems(rows, approved);
    $('#hexp').textContent = items.map(bytesToHex).join('\n');
    $('#hexc').textContent = bytesToHex(await wbChallenge(items));
    const envelope_b64 = await signBatch(items, me);
    const body = { rids: rows.map((x) => x.rid), approved, envelope_b64, views: rows.map((x) => x.hex) };
    let res;
    try { res = await post('/api/approvals/batch', withUx(body)); } catch (e) {
      if (!approved && e.code !== 'NOT_DEFERRED' && !isClone(e)) { await refuseLead(); return; }    // a refusal always goes through
      throw e;
    }
    const first = (res.results || []).find((x) => x.rid === rid) || {};
    const lr = lineResult(res, rows.map((x) => x.rid), approved);
    if (!lr.ok) throw Object.assign(new Error(lr.text), { code: first.error || 'LINE_PART', shown: true });
    const lt = manyCmds ? ' ' + lr.text : '';      // 06.11: one command split inside into parts is still one command for the person
    done(approved ? 'Approved' : 'Refused', approved ? approvedText(first) + lt : 'The agent was refused.' + lt, !approved);
  };

  const decide = async (approved, day) => {
    if (approved) gateSeen = true;
    $('#yes').disabled = $('#no').disabled = $('#allow24').disabled = true; notice(msg, 'ok', '');
    try {
      if (approved && day) { await allowFromNow(); return; }                         // 05.11: "Allow this from now on"
      if (approved && ov.enabled && $('#allow_cb').checked) { await allowForProject(); return; }
      if (approved && rv.enabled && ($('#rep_cb').checked || late)) { await approveForLater(); return; }
      if (Array.isArray(r.line_group) && r.line_group.length) { await decideLine(approved); return; }
      await show(approved);
      const envelope_b64 = await signPayload(TYP_APPROVAL, prepared[approved], me);
      const res = await post('/api/approvals/' + encodeURIComponent(rid), withUx(sv.view ? { approved, envelope_b64, view_sha256: sv.hex } : { approved, envelope_b64 }));
      if (res.status === 'collecting') {
        // team policy needs more than one signature: the server keeps ours in a signature request
        done('Signature 1 collected', 'This action needs ' + (res.need || 2) + ' signatures (' + (res.have || 1) + ' so far). The other signers see it on their Approvals and Team pages.');
        if (safeId(res.req_id)) { $('#donetext').append(' '); const a = document.createElement('a'); a.href = 'sign.html?req=' + encodeURIComponent(res.req_id); a.textContent = 'Follow the signatures'; $('#donetext').append(a); }
        return;
      }
      if (res.verdict === 'allow' && res.file_changed) { done('Not run', changedText(res)); return; }
      done(res.verdict === 'allow' ? 'Approved' : 'Refused', res.verdict === 'allow' ? approvedText(res) : 'The agent was refused. Nothing was executed.', res.verdict !== 'allow' && !approved);
    } catch (e) {
      if (isClone(e)) { notice(msg, 'err', explainError(e)); cloneNote(msg, e); unlock(); return; }   // 0.2.22 (N3)
      if (e.shown) { notice(msg, 'err', e.message); unlock(); return; }                                // 04.11: the line's result, part by part
      if (e.code === 'LINE_VIEW') { notice(msg, 'err', 'This page cannot show (and so cannot sign) what every part of this call does. Nothing was approved. Reload the page; you can still refuse.'); unlock(); return; }
      notice(msg, 'err', levelError(e) ? levelError(e) : e.code === 'ALLOWANCE_NOT_ELIGIBLE' || e.code === 'ALLOWANCE_MISMATCH' ? 'This command cannot be allowed for the project (' + failText(e) + '). You can still approve it once.' : e.code === 'NOT_DEFERRED' ? 'This request is no longer waiting (already decided or expired).' : e.code === 'VIEW_CHANGED' ? 'What this page shows changed at the witness since you opened it. Reload the page, read it again and decide.' : (e.code || '').startsWith('REPEAT_') ? 'This call cannot be approved for later runs (' + failText(e) + '). You can still approve it once.' : e.code === 'APPROVAL_SIG' ? STALE_SIG_TEXT : (e.code || '').startsWith('WA_') || (e.code || '').startsWith('WQ_') ? 'The server rejected the signature (' + failText(e) + ').' : explainError(e));
      if (e.code === 'APPROVAL_SIG') reloadButton(msg);
      const sreq = e.code === 'VIEW_CHANGED' && /an older page/.test(e.detail || '') && (/sign\.html\?req=([A-Za-z0-9_-]+)/.exec(e.detail || '') || [])[1];   // pvh: the team's open request names no view (an older page)
      if (safeId(sreq)) {
        notice(msg, 'err', 'Another signer approved this on an older page, so its request names no view hash. Sign that request instead:');
        msg.append(' '); const a = document.createElement('a'); a.href = 'sign.html?req=' + encodeURIComponent(sreq); a.textContent = 'Open the signature request'; msg.append(a);
      }
      unlock();
    }
  };
  noGate = !gateNeeded({ risk: riskOf(r), danger: dangerShown(r.action, r), netCode: typeof r.net_code === 'string' && !!r.net_code,
    written: !!(r.written_run && Array.isArray(r.written_run.files) && r.written_run.files.length), unseen: !!r.unseen_write,
    exec: execView(r.exec_changed).show, honest: !$('#honest').hidden, masked: Array.isArray(r.masked_dep) && r.masked_dep.length > 0,
    parts: Array.isArray(r.line_group) && r.line_group.length > 0, held: false });
  gateStart();
  // 05.11: "from now on" first shows the exact bounds (from the server's allowance_offer, the same that is signed); only "Confirm with passkey" signs
  $('#allow24').addEventListener('click', () => {
    const c = laterConfirm(r, r.allowance_offer && typeof r.allowance_offer.t === 'number' ? r.allowance_offer.t + (Date.now() - got) / 1000 : Date.now() / 1000, agentNameOfThis || agentOfThis);
    if (!c.ok) { notice(msg, 'err', 'Only "Allow once" is available here: ' + c.why + '.'); return; }
    const ul = $('#lc_rows'); ul.textContent = '';
    for (const x of c.rows) { const li = document.createElement('li'); li.textContent = x.commands.join(', ') + ' in ' + x.project; ul.append(li); }
    $('#lc_agent').textContent = c.agent; $('#lc_until').textContent = c.until; $('#lc_revoke').textContent = c.revoke;
    $('#later_confirm').hidden = false; $('#decide').hidden = true; $('#lc_ok').focus();
  });
  $('#lc_back').addEventListener('click', () => { $('#later_confirm').hidden = true; $('#decide').hidden = false; });
  $('#lc_ok').addEventListener('click', async () => { $('#lc_ok').disabled = true; $('#later_confirm').hidden = true; $('#decide').hidden = false; await decide(true, true); $('#lc_ok').disabled = false; });
  $('#yes').addEventListener('click', () => decide(true));
  $('#no').addEventListener('click', () => decide(false));
}

async function main() {
  const me = await mountNav(true);
  if (!me) return;
  if (rid) await single(me); else await queueMain(me, { afterBatch: (rids, agent) => watchNext(rids, agent) });
}
main().catch((e) => notice(msg, 'err', failText(e)));
