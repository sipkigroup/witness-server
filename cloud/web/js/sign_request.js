// sign.html?req=<id>: one screen for every object that waits for team signatures (policy, mandate, approval, revocation).
// The server sends FIELDS; this page encodes CDE itself, compares with the bytes the server holds and signs an ordinary wa-sig.
import { get, post } from './api.js';
import { encode, bytesToHex, hexToBytes } from './cde.js';
import { signedView } from './signview.js';
import { challenge, approvalPayload, TYP_MANDATE, TYP_APPROVAL } from './profile.js';
import { signPayload } from './sign.js';
import { gatewayCheck } from './gateway_check.js';
import { b64uDec, explainError, isClone, cloneNote } from './webauthn.js';
import { describeMandate, describeAction } from './describe.js';
import { inspectFields } from './honest.js';
import { policyFromJson, buildPolicy, policyHash, validatePolicy, describePolicy, requirements, needsText, revocationPayload, phoneLiftPayload, TYP_POLICY, TYP_REVOCATION, TYP_PHONE_LIFT } from './policy.js';
import { h, $, clear, notice, mountNav, kv, short, safeId, failText, fmtTime } from './ui.js';

const msg = $('#msg');
const rid = new URLSearchParams(location.search).get('req');
const TYP_OF = { policy: TYP_POLICY, mandate: TYP_MANDATE, approval: TYP_APPROVAL, revocation: TYP_REVOCATION, phone_lift: TYP_PHONE_LIFT };
const KIND_WORD = { policy: 'team policy', mandate: 'mandate', approval: 'approval', revocation: 'revocation of a mandate', phone_lift: "end of a new phone's waiting time" };
const hex = (b) => bytesToHex(b);
const eqB = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
let S = { me: null, sr: null, cur: null, own: null };

// own bytes from the fields of the request
async function ownBytes(sr) {
  const b = sr.body || {};
  if (sr.kind === 'policy') { const p = buildPolicy(policyFromJson(b)); return { bytes: encode(p), obj: p }; }
  if (sr.kind === 'mandate') return { bytes: encode(b), obj: b };
  if (sr.kind === 'approval') return { bytes: await approvalPayload(b.rid, b.mandate, b.action, b.approved !== false, typeof b.view === 'string' ? hexToBytes(b.view) : null), obj: b };   // pv2: the view the request names
  if (sr.kind === 'revocation') return { bytes: await revocationPayload(b.mandate), obj: b };
  if (sr.kind === 'phone_lift') return { bytes: phoneLiftPayload(b), obj: b };
  throw new Error('Unknown kind of request: ' + sr.kind);
}

function labelOf(kidHex, pol) {
  const m = pol && pol.members.find((x) => hex(x.kid) === kidHex);
  return m ? m.label : short(kidHex);
}

// "budget signers: 1 of 2 - Anna signed" per required role, counted by distinct kid as verify_wq does
function progressRows(sr, judge) {
  const signed = sr.signed_by || [];
  const needs = (sr.needs || []).map((n) => [n.role, n.k]);
  if (!judge) return [['Signed', signed.length + ' of ' + (sr.need || 1)]];
  return needs.map(([role, k]) => {
    const who = signed.filter((kid) => { const m = judge.members.find((x) => hex(x.kid) === kid); return m && (role === 'any' || m.roles.includes(role)); });
    return [role === 'any' ? 'Any signer' : role + ' signers', who.length + ' of ' + k + ' needed' + (who.length ? ' - signed: ' + who.map((kid) => labelOf(kid, judge)).join(', ') : '')];
  });
}

function policyDiff(oldP, newP) {
  const L = [];
  const om = new Map(oldP.members.map((m) => [hex(m.kid), m])), nm = new Map(newP.members.map((m) => [hex(m.kid), m]));
  for (const [k, m] of nm) {
    const o = om.get(k);
    if (!o) L.push(['Added', m.label + ' (' + m.roles.join(', ') + ')']);
    else if (o.roles.join() !== m.roles.join() || o.label !== m.label) L.push(['Changed', o.label + ' (' + o.roles.join(', ') + ') -> ' + m.label + ' (' + m.roles.join(', ') + ')']);
  }
  for (const [k, o] of om) if (!nm.has(k)) L.push(['Removed', o.label + ' (' + o.roles.join(', ') + ')']);
  const ow = new Set(describePolicy(oldP).filter(([a]) => !['Version', 'Members'].includes(a)).map(([a, b]) => a + ': ' + b));
  for (const [a, b] of describePolicy(newP)) if (!['Version', 'Members'].includes(a) && !ow.has(a + ': ' + b)) L.push(['New rule', a + ': ' + b]);
  return L;
}

// R5-01/02: a mandate shown to a signer passes through inspectFields (hidden / bidi characters -> <U+XXXX>, look-alike text flagged), like approve.js
function kvInspected(rows, diff) {
  const ins = inspectFields(rows);
  if (ins.warnings.length) diff.append(h('div', { class: 'notice warn', role: 'alert' }, h('strong', { text: 'CHECK before you sign: this text can be disguised.' }), h('ul', {}, ...ins.warnings.slice(0, 12).map((w) => h('li', { text: w })))));
  return kv(ins.rows);
}

async function render() {
  const sr = S.sr;
  $('#head').textContent = 'Signature needed: ' + (KIND_WORD[sr.kind] || sr.kind);
  if (TYP_OF[sr.kind] !== sr.typ) throw new Error('The request type does not match its kind (' + sr.typ + '); not signing.');
  const own = await ownBytes(sr);
  if (sr.kind === 'mandate') {
    S.gw = await gatewayCheck(sr);
    if (!S.gw.ok) { notice(msg, 'err', S.gw.why + ' Nothing was signed; do not sign, report this to the owner.'); return false; }
  }
  const server = b64uDec(sr.payload_b64 || '');
  if (!eqB(own.bytes, server)) {
    notice(msg, 'err', 'The bytes held by the server differ from what this page encodes from the fields shown. Do not sign; report this to the owner.');
    return false;
  }
  S.own = own;
  const judge = sr.kind === 'policy' && !S.cur ? own.obj : S.cur; // genesis is judged by itself (one owner)
  // what is signed, in words
  const what = clear($('#what')), diff = clear($('#diff'));
  if (sr.kind === 'policy') {
    const bad = await validatePolicy(own.obj);
    if (bad) { notice(msg, 'err', 'This policy draft is malformed (' + bad + '); not signing.'); return false; }
    if (S.cur) {
      if (own.obj.ver !== S.cur.ver + 1 || !own.obj.prev || !eqB(own.obj.prev, await policyHash(S.cur))) { notice(msg, 'err', 'This draft does not follow the current policy version ' + S.cur.ver + ' (it was overtaken). Ask the owner for a new draft.'); return false; }
      diff.append(h('h3', { text: 'Changes from version ' + S.cur.ver }), kv(policyDiff(S.cur, own.obj)));
      const rec = sr.meta && sr.meta.recovery;
      if (rec) {   // 0.2.2: a key replacement after a lost passkey
        const who = S.cur.members.find((x) => hex(x.kid) === rec.old_kid);
        diff.append(h('p', { class: 'notice warn', text: 'Key replacement: ' + ((who && who.label) || 'a member') + ' lost the passkey '
          + rec.old_kid.slice(0, 8) + '; it is replaced by ' + rec.new_kid.slice(0, 8) + ', nothing else changes. Sign only if you have '
          + 'confirmed with that person yourself (call, in person) that they lost it and that the new key is theirs. The lost key cannot sign this.' }));
      }
    }
    what.append(kv(describePolicy(own.obj)));
  } else if (sr.kind === 'mandate') {
    what.append(kvInspected(describeMandate(own.obj), diff));
    if (S.gw && S.gw.rows.length) {
      what.append(h('h3', { text: 'Tool map, protected data and advisor mode covered by this signature' }), kv(S.gw.rows.map(([k, v]) => [k, v])));
      const ch = S.gw.rows.filter((r) => r[2]);
      if (ch.length) diff.append(h('p', { class: 'notice warn', text: 'Compared with the mandate in force, this changes: ' + ch.map((r) => r[0].replace('CHANGED ', '') + ' = ' + r[1]).join('; ') + '. Sign only if you know why.' }));
    }
    if (S.cur) {
      const mine = needsText(requirements(S.cur, sr.typ, own.obj));
      const theirs = needsText((sr.needs || []).map((n) => [n.role, n.k]));
      if (mine !== theirs) diff.append(h('p', { class: 'notice warn', text: 'This page computes the requirement as "' + mine + '", the server says "' + theirs + '". The ledger will hold the stricter one; tell the owner.' }));
    }
  } else if (sr.kind === 'approval') {
    what.append(h('p', { text: own.obj.approved === false ? 'You refuse this action:' : 'You approve this action:' }), kv(describeAction(own.obj.action)), h('h3', { text: 'Under mandate' }), kvInspected(describeMandate(own.obj.mandate), diff));
    if (typeof own.obj.view === 'string') {        // pv2: the stored bytes name the approval page's view: this page shows the same view and checks its hash
      const r = await get('/api/approvals/' + encodeURIComponent(own.obj.rid));
      const sv = await signedView(r);
      if (sv.hex !== own.obj.view) {         // pvh: the approval page replaces this request with one over what it shows now
        notice(msg, 'err', 'What the approval page shows now is not the view this request names (view hash). Do not sign here: read the approval page and decide there; it opens a new request (earlier signatures do not carry over).');
        if (safeId(own.obj.rid)) { msg.append(' '); msg.append(h('a', { href: 'approve.html?rid=' + encodeURIComponent(own.obj.rid), text: 'Open the approval page' })); }
        return false;
      }
      const rows = [['Tool', r.tool || ''], ['Arguments (first 300 characters)', r.args_preview || '']];
      if (r.text_preview) rows.push(['Text (up to 4 KB)', r.text_preview]);
      if (Array.isArray(r.line_commands) && r.line_commands.length > 1) rows.push(['Commands in the line', r.line_commands.join(', ')]);
      if (Array.isArray(r.line_full) && r.line_full.length) rows.push(['Every command of the line, in full' + (r.text_cut === true ? ' (the text above is cut at 4 KB)' : ''), r.line_full.map((c, i) => (i + 1) + '. ' + String(c && typeof c === 'object' ? c.cmd : c)).join('\n')]);   // 04.11 (I2)
      if (r.net_code) rows.push(['Code that talks to a host it does not show', r.net_code]);
      if (r.exec_changed && Array.isArray(r.exec_changed.files)) rows.push(['Executed files changed', r.exec_changed.files.join(', ') + (r.exec_changed.risk && r.exec_changed.risk.dangerous ? '. ' + r.exec_changed.risk.note : '')]);
      if (r.written_run && Array.isArray(r.written_run.files)) rows.push(['Runs files the agent wrote', r.written_run.files.join(', ')]);
      if (Array.isArray(r.masked_dep) && r.masked_dep.length) rows.push(['Masked value', 'This decision depends on ' + (r.masked_dep.length > 1 ? 'masked values: ' : 'a masked value: ') + r.masked_dep.map(String).join(', ')]);   // 29.10 MDEP (in the view)
      if (r.reason) rows.push(['Reason', r.reason]);
      what.append(h('h3', { text: 'What the approval page shows (signed with your decision: view ' + sv.hex.slice(0, 16) + '…)' }), kvInspected(rows, diff));
    }
  } else if (sr.kind === 'phone_lift') {   // 0.2.15
    what.append(h('p', { class: 'notice warn', text: 'A team member used a recovery code and declared a new phone (passkey ' + String(own.obj.kid).slice(0, 8)
      + '). It counts as their phone from ' + fmtTime(own.obj.not_before) + '. Your signature lets it count as a phone NOW. Sign only if you have '
      + 'confirmed with that person yourself (call, in person) that the new phone is theirs: a stolen recovery code looks exactly like this.' }));
  } else {
    what.append(h('p', { text: 'After this signature the mandate stops at once; the agent is refused until a new mandate is signed.' }), own.obj.mandate ? kvInspected(describeMandate(own.obj.mandate), diff) : '');
  }
  $('#intro').textContent = 'This ' + (KIND_WORD[sr.kind] || sr.kind) + ' takes effect when ' + needsText((sr.needs || []).map((n) => [n.role, n.k])) + ' have signed it. Each signer signs the same bytes on their own device.' + (sr.expires ? ' Open until ' + fmtTime(sr.expires) + '.' : '');
  $('#hexp').textContent = hex(own.bytes);
  $('#hexc').textContent = hex(await challenge(sr.typ, own.bytes));
  updateProgress(judge);
  $('#box').hidden = false;
  return true;
}

function updateProgress(judge) {
  const sr = S.sr;
  $('#prog').textContent = sr.status === 'done' ? 'done' : 'collecting ' + sr.have + '/' + sr.need;
  clear($('#needs')).append(...progressRows(sr, judge).flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { text: v })]));
  const mine = S.me.keycard.kid_hex;
  const btn = $('#signbtn');
  const signed = (sr.signed_by || []).includes(mine);
  const member = judge && judge.members.find((m) => hex(m.kid) === mine);
  const useful = member && (sr.needs || []).some((n) => n.role === 'any' || member.roles.includes(n.role));
  if (sr.status === 'done') { btn.disabled = true; btn.textContent = 'Already done'; }
  else if (signed) { btn.disabled = true; btn.textContent = 'You signed - waiting for the others'; }
  else if (judge && !member) { btn.disabled = true; btn.textContent = 'You are not a signer in the policy'; }
  else if (judge && !useful) { btn.disabled = true; btn.textContent = 'Your role is not needed here'; }
  else { btn.disabled = false; btn.textContent = 'Sign with passkey'; }
}

function finished(res) {
  $('#box').hidden = true; $('#done').hidden = false;
  $('#donehead').textContent = 'Done: ' + res.have + '/' + res.need;
  const t = { policy: 'Policy version ' + (res.policy_ver || '') + ' is now in force.', mandate: 'Mandate ' + (res.mandate_id || '') + ' is ' + (res.mandate_status || 'active') + '.', approval: 'The action is approved; the agent can repeat the call.', revocation: 'The mandate is revoked.' };
  $('#donetext').textContent = t[S.sr.kind] || 'Applied.';
  if (S.sr.kind === 'mandate' || S.sr.kind === 'revocation') $('#donelink').href = 'app.html';
}

// RT-SUP 29.10: a team approval request replaced because what it shows changed (meta.superseded_by): one line, the earlier signatures do not count
export function replacedText(sr) {
  const to = sr && sr.status === 'superseded' && sr.meta && sr.meta.superseded_by;
  return typeof to === 'string' && safeId(to) ? 'The view changed, sign again: this request was replaced by ' + to + ' (sign.html?req=' + to + '); signatures given here do not count.' : '';
}

async function refresh() {
  const sr = await get('/api/sig-requests/' + encodeURIComponent(rid));
  if (replacedText(sr)) { S.sr = { ...S.sr, status: sr.status }; $('#box').hidden = true; notice(msg, 'err', replacedText(sr)); return; }
  S.sr = { ...S.sr, have: sr.have, need: sr.need, status: sr.status, signed_by: sr.signed_by };
  if (sr.status === 'done') finished(sr); else updateProgress(S.sr.kind === 'policy' && !S.cur ? S.own.obj : S.cur);
}

async function main() {
  S.me = await mountNav(true);
  if (!S.me) return;
  if (!safeId(rid)) { notice(msg, 'err', 'No signature request in this link.'); return; }
  const [sr, org] = await Promise.all([get('/api/sig-requests/' + encodeURIComponent(rid)), get('/api/org')]);
  S.sr = sr; S.cur = org.policy ? policyFromJson(org.policy) : null;
  if (sr.status === 'done') { notice(msg, 'ok', 'This request is already complete (' + sr.have + '/' + sr.need + ').'); return; }
  if (replacedText(sr)) { notice(msg, 'err', replacedText(sr)); return; }
  if (!(await render())) return;
  $('#signbtn').addEventListener('click', async () => {
    const btn = $('#signbtn'); btn.disabled = true; notice(msg, 'ok', '');
    try {
      const envelope_b64 = await signPayload(S.sr.typ, S.own.bytes, S.me);
      const res = await post('/api/sig-requests/' + encodeURIComponent(rid), { envelope_b64 });
      S.sr = { ...S.sr, have: res.have, need: res.need, status: res.status, signed_by: [...(S.sr.signed_by || []), S.me.keycard.kid_hex] };
      if (res.status === 'done') finished(res);
      else { notice(msg, 'ok', 'Signed. ' + res.have + ' of ' + res.need + ' collected; the others see this request on their Team page.'); updateProgress(S.sr.kind === 'policy' && !S.cur ? S.own.obj : S.cur); }
    } catch (e) {
      notice(msg, 'err', isClone(e) ? explainError(e) : e.code ? 'The server refused the signature (' + failText(e) + ').' : explainError(e)); cloneNote(msg, e);   // 0.2.22 (N3)
      updateProgress(S.sr.kind === 'policy' && !S.cur ? S.own.obj : S.cur);
    }
  });
  setInterval(() => { if (S.sr.status !== 'done') refresh().catch(() => {}); }, 5000);
}
main().catch((e) => notice(msg, 'err', failText(e)));
