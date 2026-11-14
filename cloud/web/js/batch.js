// Approval queue by roles, batches (one passkey prompt for up to 20 homogeneous items), advisory holds.
import { get, post } from './api.js';
import { bytesToHex } from './cde.js';
import { signBatch, signPayload } from './sign.js';
import { batchItems, wbChallenge, mixedReason } from './wb.js';
import { policyFromJson, releasePayload, TYP_RELEASE, roleWords } from './policy.js';
import { roleOf, isEscalated, forMe, quorumOf, groupItems, acceptGroup, clip4k, diffTokens, differingFields, waitingFirst } from './queue.js';
import { describeAction } from './describe.js';
import { reveal, inspectFields } from './honest.js';
import { explainError } from './webauthn.js';
import { h, $, clear, notice, until, safeId, failText } from './ui.js';
import { signedView } from './signview.js';

const msg = $('#msg');
// hidden / bidi characters are shown as <U+XXXX>; look-alike text gets a marker (details on the single-item screen)
const vis = (v) => { const r = reveal(v, true).text; return r; };
const rcp = (v) => { const i = inspectFields([['recipient', v]]); return i.rows[0][1] + (i.warnings.length ? ' [CHECK: hidden or look-alike characters]' : ''); };
const Q = { me: null, org: null, policy: null, roles: [], items: [], held: [], groups: [], all: false, names: new Map() };
const agentName = (id) => Q.names.get(id) || id;
const now = () => Math.floor(Date.now() / 1000);

// Advisory mark of an item (4.2): "heuristic-1:postal_address" style string or {label} object; never a decision.
export function advisoryText(x) {
  const a = x.adv || x.advisory;
  if (!a) return '';
  if (typeof a === 'string') return a.startsWith('heuristic') || a.startsWith('ner') ? 'Data advisor flag: ' + a.split(':').slice(1, 2).join('') + ' (' + a.split(':')[0] + '). A hint, not a decision.' : 'Data advisor: ' + a;
  return 'Data advisor flag: ' + (a.label || a.class || JSON.stringify(a)) + '. A hint, not a decision.';
}

// Release / reject an advisory hold: wa-sig of typ application/dw-release+cbor over {rid, args_sha256, release}.
// pv2810: view = the presentation hash the approval page computed (signview.js) or null (the queue row: the view is not signed)
export async function decideHeld(x, release, me, view = null) {
  const payload = releasePayload(x.rid, x.action.args_sha256, release, view);
  const envelope_b64 = await signPayload(TYP_RELEASE, payload, me);
  return post('/api/approvals/' + encodeURIComponent(x.rid) + '/release', view ? { release, envelope_b64, view_sha256: bytesToHex(view) } : { release, envelope_b64 });
}

function itemRow(x) {
  const esc = isEscalated(x, Q.org.settings, now());
  const k = quorumOf(Q.policy, x.action);
  return h('div', { class: 'row' },
    h('span', {}, h('strong', { text: agentName(x.agent_id) }), ' wants ', h('strong', { text: x.action.class }), x.action.recipient != null ? ' to ' + rcp(x.action.recipient) : '', ' ',
      h('span', { class: 'pill', text: roleOf(x.action) }), ' ', esc ? h('span', { class: 'pill esc', text: 'escalation' }) : '', ' ', k > 1 ? h('span', { class: 'pill defer', text: k + ' signatures' }) : '',
      advisoryText(x) ? h('span', { class: 'pill held', text: 'advisor flag' }) : '',
      x.agent_waiting === true ? h('span', { class: 'pill', text: 'agent is waiting' }) : x.agent_waiting === false ? h('span', { class: 'pill', text: 'agent stopped waiting' }) : '',   // 27.10 O3
      h('span', { class: 'hint', text: ' (' + until(x.expires) + ')' })),
    safeId(x.rid) ? h('a', { class: 'btn', href: 'approve.html?rid=' + encodeURIComponent(x.rid) }, 'Review') : '');
}

function renderQueue() {
  const vis = Q.all ? Q.items : Q.items.filter((x) => forMe(x, Q.roles, Q.org.settings, now()));
  $('#t_mine').className = 'btn' + (Q.all ? ' ghost' : ''); $('#t_all').className = 'btn' + (Q.all ? '' : ' ghost');
  $('#qhint').textContent = Q.all ? 'Everything waiting in this organisation.' : 'Money actions go to money approvers, other actions to access approvers; owners also see what was not decided in time (escalation). Your role: ' + (Q.roles.length ? roleWords(Q.roles) : 'none') + '.';
  const byRid = new Map(vis.map((x) => [x.rid, x]));
  const groups = Q.groups.map((g) => acceptGroup(g, byRid, Q.policy)).filter(Boolean);
  const inGroup = new Set(groups.flatMap((g) => g.rids));
  $('#groups-card').hidden = !groups.length;
  clear($('#groups')).append(...groups.map((g) => h('div', { class: 'row' },
    h('span', {}, h('strong', { text: agentName(g.agent_id) }), ' - ' + g.class + (g.recipient != null ? ' to ' + rcp(g.recipient) : '') + ': ', h('strong', { text: g.rids.length + ' items' }),
      g.rids.some((r) => byRid.get(r).agent_waiting === false) ? h('span', { class: 'hint', text: ' (' + g.rids.filter((r) => byRid.get(r).agent_waiting === false).length + ' no longer awaited by the agent)' }) : ''),
    h('button', { class: 'btn', type: 'button', onclick: () => openBatch(g).catch((e) => notice(msg, 'err', failText(e))) }, 'Review batch of ' + g.rids.length))));
  const singles = waitingFirst(vis.filter((x) => !inGroup.has(x.rid)));      // 27.10 O3: the call an agent waits on now is on top
  const box = clear($('#singles'));
  if (!singles.length) box.append(h('p', { class: 'hint', text: groups.length ? 'Everything else is in a batch above.' : 'Nothing is waiting.' }));
  for (const x of singles) box.append(itemRow(x));
  $('#held-card').hidden = !Q.held.length;
  // N5 29.10: the witness' own holds (a file the agent wrote, a secret it read, data going out) are not the data advisor's
  const byWitness = Q.held.filter((x) => WITNESS_HOLDS.includes(x.reason)).length;
  if ($('#heldhead')) $('#heldhead').textContent = !byWitness ? 'Held by the data advisor' : byWitness === Q.held.length ? 'Held: you decide' : 'Held for you';
  if ($('#heldhint')) $('#heldhint').textContent = !byWitness
    ? 'The mandate allows these actions, but the advisor flagged their text. The advisor never decides: you release (the witness then judges the action as usual) or reject.'
    : 'The mandate allows these actions, but ' + (byWitness === Q.held.length ? 'the witness holds them' : 'the witness or the data advisor holds them') + ' for you: open one to read what it runs or sends. You release (the witness then judges the action as usual) or reject.';
  clear($('#held')).append(...Q.held.map(heldRow));
  document.title = (vis.length ? '(' + vis.length + ') ' : '') + 'Approvals - Deus Witness';
}

const WITNESS_HOLDS = ['ESCALATE_SECRET_SEEN', 'ESCALATE_USER_CONTENT_HOST', 'ESCALATE_NET_UNSEEN', 'ESCALATE_WRITTEN_RUN', 'ESCALATE_SECRET_COPY'];
const HELD_WHY = {   // N5 29.10: the witness' holds in the list say what they are (the full page says more)
  ESCALATE_WRITTEN_RUN: 'Held: this command runs a file this agent wrote. Open it to read the file before you release it.',
  ESCALATE_SECRET_SEEN: 'Held: this agent read a secret in the last minutes, and this call can carry data out or run code it wrote.',
  ESCALATE_USER_CONTENT_HOST: 'Held: this request carries data to a site where anyone can publish or read it.',
  ESCALATE_NET_UNSEEN: 'Held: this command runs a network program whose destination is not in the line.',
  ESCALATE_SECRET_COPY: 'Held: this reads a copy this agent made of a secret.',
};
function heldRow(x) {
  const out = h('div', { class: 'batchitem' });
  out.append(h('p', {}, h('strong', { text: agentName(x.agent_id) }), ' - ' + x.action.class + (x.action.recipient != null ? ' to ' + rcp(x.action.recipient) : '')),
    h('p', { class: 'notice warn', text: HELD_WHY[x.reason] || advisoryText(x) || 'Held by the data advisor.' }),
    x.text_preview ? h('pre', { text: clip4k(x.text_preview) }) : '',
    h('div', { class: 'row' },
      // pvh 28.10: a release signs the hash of what the approval page shows (more than this row: tool, arguments, commands, files,
      // look-alike checks), so it is given there; a reject (the safe way) stays here, marked "view not signed"
      safeId(x.rid) ? h('a', { class: 'btn', href: 'approve.html?rid=' + encodeURIComponent(x.rid) }, 'Review and release') : '',
      h('button', { class: 'btn danger', type: 'button', onclick: (ev) => held(x, false, ev.target) }, 'Reject')));
  return out;
}
async function held(x, release, btn) {
  btn.disabled = true;
  try {
    const r = await decideHeld(x, release, Q.me);
    notice(msg, release && r.file_changed ? 'warn' : 'ok', release && r.file_changed ? 'The file changed after you saw it; nothing ran (' + r.file_changed + ').' : (release ? 'Released: ' : 'Rejected: ') + r.verdict + ' (' + r.reason + ').');
    await load();
  } catch (e) { notice(msg, 'err', e.code ? failText(e) : explainError(e)); btn.disabled = false; }
}

// ---- batch view ----
// pv2: what the single-item page shows besides the action and the preview is shown here too (it is inside the item's signed view)
function extraOf(x) {
  const out = [];
  if (Array.isArray(x.masked_dep) && x.masked_dep.length) out.push(h('p', { class: 'hint', text: 'This decision depends on ' + (x.masked_dep.length > 1 ? 'masked values: ' : 'a masked value: ') + x.masked_dep.map(String).join(', ') }));   // 29.10 MDEP
  if (Array.isArray(x.line_commands) && x.line_commands.length > 1) out.push(h('p', { class: 'hint', text: 'Commands in this line: ' + x.line_commands.map((c) => vis(String(c))).join(', ') }));
  if (Array.isArray(x.line_full) && x.line_full.length) {          // 04.11 (Hypothesis I2): every command of the line, whole (in the signed view)
    out.push(h('p', { class: 'notice warn', text: 'Every command of this line, in full (' + x.line_full.length + ')' + (x.text_cut === true ? '; the text above is cut at 4 KB, this list is not:' : ':') }));
    for (const c of x.line_full) out.push(h('pre', { text: vis(String(c && typeof c === 'object' ? c.cmd : c)) }));
  }
  if (typeof x.net_code === 'string' && x.net_code) out.push(h('p', { class: 'notice warn', text: 'This command talks to a host it does not show. Its code:' }), h('pre', { text: vis(clip4k(x.net_code)) }));
  if (x.exec_changed && Array.isArray(x.exec_changed.files)) {
    const rk = x.exec_changed.risk;
    out.push(h('p', { class: 'notice warn', text: 'Executed files changed: ' + x.exec_changed.files.map((f) => vis(String(f))).join(', ') + (rk && rk.dangerous ? '. ' + rk.note : '') }));
  }
  if (x.written_run && Array.isArray(x.written_run.files)) out.push(h('p', { class: 'notice warn', text: 'Runs files the agent wrote: ' + x.written_run.files.map((f) => vis(String(f))).join(', ') }));
  return out;
}
function textWithMarks(tokens) {
  const pre = h('pre');
  for (const [w, d] of tokens) pre.append(d ? h('mark', { text: vis(w) }) : document.createTextNode(vis(w)));
  return pre;
}

// N18 0.2.74 (series 10): "repeat" only for calls the agent no longer waits on; a call whose hook still waits runs now, without a repeat
export function batchDoneText(res) {
  const rs = res && Array.isArray(res.results) ? res.results.filter((x) => x && x.verdict === 'allow') : [];
  const live = rs.filter((x) => x.agent_waiting === true).length, gone = rs.filter((x) => x.agent_waiting === false).length;
  if (rs.length && live === rs.length) return rs.length === 1 ? 'The agent is waiting for this answer: the call runs now.' : 'The agent is waiting for these answers: the calls run now.';
  if (rs.length && gone === rs.length) return 'The agent stopped waiting for these calls: each runs once when the agent makes the same call again.';
  if (live || gone) return (live ? live + (live === 1 ? ' call the agent waits on runs now' : ' calls the agent waits on run now') : '')
    + (live && gone ? '; ' : '') + (gone ? gone + (gone === 1 ? ' call runs' : ' calls run') + ' once when the agent makes the same call again' : '') + '.';
  return 'If the agent is still waiting, each call runs now; otherwise it runs once when the agent makes the same call again.';
}

async function openBatch(g) {
  notice(msg, 'ok', '');
  const rows = [];
  for (const rid of g.rids) {
    const r = await get('/api/approvals/' + encodeURIComponent(rid));
    if (r.status !== 'pending_approval') throw new Error('Item ' + rid + ' is no longer waiting (' + r.status + '). Reload.');
    // N19 0.2.74: the agent sent this call again and waits on it now: it is decided on its own page, not inside a batch of older calls
    if (r.agent_waiting === true) throw new Error('Item ' + (rows.length + 1) + ' is a call your agent is waiting on now: it is decided on its own page. Back to the list (it is under One by one).');
    // pv2: each item's own signing view (the hash of what this list shows of it), signed inside that item's approval payload
    const sv = await signedView(r);
    if (sv.same === false) throw new Error('Item ' + (rows.length + 1) + ': this page and the witness disagree on what it shows (view hash). Reload the page.');
    rows.push({ rid, agent_id: g.agent_id, mandate: r.mandate, action: r.action, text: r.text_preview || '', args: r.args_preview || '', tool: r.tool || '', expires: r.expires,
      view: sv.view, hex: sv.hex, line_commands: r.line_commands, line_full: r.line_full, text_cut: r.text_cut, net_code: r.net_code, exec_changed: r.exec_changed, written_run: r.written_run, masked_dep: r.masked_dep });
  }
  if (!rows.every((x) => x.view)) for (const x of rows) { x.view = null; x.hex = null; }     // all items name their view, or none does (older server)
  const bw = inspectFields(rows.flatMap((x, i) => [['item ' + (i + 1) + ' recipient', x.action.recipient == null ? '' : x.action.recipient], ['item ' + (i + 1) + ' arguments', x.args]]), rows.map((x, i) => ['item ' + (i + 1) + ' text', clip4k(x.text)])).warnings;
  if (bw.length) notice(msg, 'warn', 'Check before you approve this batch: ' + bw.slice(0, 4).join(' | ') + (bw.length > 4 ? ' | (+' + (bw.length - 4) + ' more; open items one by one)' : ''));
  const mixed = mixedReason(rows);
  if (mixed) throw new Error('Not a uniform batch (' + mixed + '); decide these one by one.');
  if (rows.some((x) => quorumOf(Q.policy, x.action) > 1)) throw new Error('An item needs more than one signature; it cannot be in a batch.');
  const { items } = await batchItems(rows, true);
  const marks = diffTokens(rows.map((x) => clip4k(x.text || x.args))); // no text preview -> compare the arguments
  const diffKeys = new Set(differingFields(rows.map((x) => x.action)));
  const list = clear($('#blist'));
  rows.forEach((x, i) => {
    const dl = h('dl', { class: 'kv' });
    for (const [k, v] of describeAction(x.action)) {
      const key = { Class: 'class', Recipient: 'recipient', Amount: 'amount', 'Data classes touched': 'data', Reversible: 'reversible' }[k] || k;
      dl.append(h('dt', { text: k }), h('dd', {}, diffKeys.has(key) ? h('mark', { text: vis(v) }) : vis(v)));
    }
    list.append(h('div', { class: 'batchitem' }, h('h3', { text: (i + 1) + ' of ' + rows.length + ' - ' + x.tool }), dl,
      x.text ? '' : h('p', { class: 'hint', text: 'Arguments (first 300 characters):' }), textWithMarks(marks[i]), ...extraOf(x)));
  });
  const end = h('p', { class: 'hint', id: 'bend', text: 'End of the list: ' + rows.length + ' items.' });
  list.append(end);
  $('#bhead').textContent = 'Batch: ' + agentName(g.agent_id) + ' - ' + g.class + (g.recipient != null ? ' to ' + rcp(g.recipient) : '');
  $('#bintro').textContent = 'Read each item. Highlighted words and fields differ between items. One passkey prompt approves exactly these ' + rows.length + ' items, nothing else.'
    + (rows[0].view ? ' Signed with your decision: the hash of what this list shows of each item (its view).' : '');
  $('#bitems').textContent = items.map(bytesToHex).join('\n');
  $('#bch').textContent = bytesToHex(await wbChallenge(items));
  const go = $('#bgo'); go.disabled = true; go.textContent = 'Approve ' + rows.length; $('#bgate').hidden = false;
  const open = () => { go.disabled = false; $('#bgate').hidden = true; };
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting)) { open(); io.disconnect(); } }, { root: list, threshold: 1.0 });
    io.observe(end);
  } else list.addEventListener('scroll', () => { if (list.scrollTop + list.clientHeight >= list.scrollHeight - 2) open(); });
  go.onclick = async () => {
    go.disabled = true;
    try {
      const envelope_b64 = await signBatch(items, Q.me);
      const body = { rids: rows.map((x) => x.rid), approved: true, envelope_b64 };
      if (rows[0].view) body.views = rows.map((x) => x.hex);                       // pv2: one view per item, in the order of rids
      const res = await post('/api/approvals/batch', body);
      $('#batch').hidden = true; $('#done').hidden = false;
      $('#donehead').textContent = 'Approved ' + (res.n != null ? res.n : rows.length) + ' with one signature';
      $('#donetext').textContent = batchDoneText(res) + ' Each ledger entry carries the same batch envelope.';
      if (Q.afterBatch) Q.afterBatch(rows.map((x) => x.rid), g.agent_id);   // 27.10: the agent's next waiting call opens by itself, as after one call
    } catch (e) {
      const t = { VIEW_CHANGED: 'What an item shows changed at the witness since this list was opened. Reload and read it again.', BATCH_NOT_HOMOGENEOUS: 'The server says the items are not uniform.', BATCH_MIXED: 'The server says the items are not uniform.', BATCH_QUORUM: 'An item needs more than one signature.', WQ_QUORUM: 'Your role cannot approve one of these items alone.', NOT_DEFERRED: 'An item is no longer waiting (decided or expired). Reload.' }[e.code];
      notice(msg, 'err', t ? t + ' (' + failText(e) + ')' : e.code ? 'The server refused the batch (' + failText(e) + ').' : explainError(e));
      go.disabled = false;
    }
  };
  $('#queue').hidden = true; $('#batch').hidden = false; $('#title').textContent = 'Approve a batch';
  $('#batch').scrollIntoView();
}

async function load() {
  const [pend, held, groups] = await Promise.all([
    get('/api/approvals?status=pending'),
    get('/api/approvals?status=held').catch(() => []),
    get('/api/approvals/groups').catch(() => null)]);
  Q.items = pend.filter((x) => !x.status || x.status === 'pending_approval');
  Q.held = (held || []).filter((x) => x.status === 'held');
  const srv = Array.isArray(groups) ? groups : groups && Array.isArray(groups.groups) ? groups.groups : null;
  Q.groups = srv || groupItems(Q.items, Q.policy);
  if (Q.held.length) {
    for (const x of Q.held) {
      if (x.text_preview != null) continue;
      try { const d = await get('/api/approvals/' + encodeURIComponent(x.rid)); x.text_preview = d.text_preview; x.action = d.action || x.action; } catch (e) { /* keep the list item */ }
    }
  }
  renderQueue();
}

export async function main(me, hooks = {}) {
  Q.me = me; Q.afterBatch = typeof hooks.afterBatch === 'function' ? hooks.afterBatch : null;
  $('#title').textContent = 'Approvals';
  const [org, orgs, agents] = await Promise.all([get('/api/org').catch(() => ({ members: [], settings: {} })), get('/api/orgs').catch(() => []), get('/api/agents').catch(() => [])]);
  Q.org = org; Q.policy = org.policy ? policyFromJson(org.policy) : null;
  const cur = orgs.find((o) => o.current);
  Q.roles = cur ? cur.roles : ['owner', 'budget', 'access'];
  for (const a of agents) Q.names.set(a.id, a.name);
  $('#queue').hidden = false;
  $('#t_mine').addEventListener('click', () => { Q.all = false; renderQueue(); });
  $('#t_all').addEventListener('click', () => { Q.all = true; renderQueue(); });
  $('#bback').addEventListener('click', () => { $('#batch').hidden = true; $('#queue').hidden = false; $('#title').textContent = 'Approvals'; });
  await load();
  setInterval(() => { if ($('#batch').hidden && $('#done').hidden) load().catch(() => {}); }, 5000);
}
