import { get, post, put, del } from './api.js';
import { levelError } from './levels.js';
import { policyFromJson, describePolicy, rulesFromForm, formFromRules, checkDraft, needsText } from './policy.js';
import { anchorText } from './anchors.js';
import { h, $, clear, notice, mountNav, dollarsToCents, kv, short, safeId, failText, copyButton } from './ui.js';

const msg = $('#msg');
const S = { me: null, org: null, orgs: [], myRoles: [], policy: null };
const isOwner = () => S.myRoles.includes('owner');
const ROLE_SET = ['owner', 'budget', 'access'];

function renderAnchors(profile) {
  const t = anchorText(profile);
  clear($('#anchors')).append(h('p', { text: t.lead }), h('details', {}, h('summary', { text: t.moreTitle }), ...t.more.map((x) => h('p', { class: 'hint', text: x }))));
}

function renderPolicy() {
  const box = clear($('#policy'));
  if (!S.policy) {
    box.append(h('p', { text: 'No team policy yet: this account works alone, as in version 0.1. Every mandate and approval is signed by your passkey only.' }));
    return;
  }
  box.append(kv(describePolicy(S.policy)));
}

function renderMembers() {
  const body = clear($('#members'));
  for (const m of S.org.members) {
    body.append(h('tr', {},
      h('td', { 'data-l': 'Label', text: m.label || m.user_id }),
      h('td', { 'data-l': 'Roles', text: m.roles.join(', ') }),
      h('td', { 'data-l': 'Status' }, h('span', { class: 'pill ' + (m.status === 'active' ? 'allow' : m.status === 'pending' ? 'defer' : 'deny'), text: m.status })),
      h('td', { 'data-l': 'Key', class: 'mono', text: short(m.kid) }),
      h('td', {}, canReplace(m) ? h('button', { class: 'btn ghost', type: 'button', onclick: () => replaceKey(m) }, 'Lost passkey: replace key') : '')));
  }
}

// 0.2.2: a member lost the passkey the policy names. Opens the policy request that swaps ONLY that key for the person's new one;
// the other members sign it (rule "recovery"). The person must have added a new passkey first (recovery code or another device).
const canReplace = (m) => S.policy && m.status === 'active' && !(m.roles.length === 1 && m.roles[0] === 'observer') && S.myRoles.some((r) => ROLE_SET.includes(r));
async function replaceKey(m) {
  if (!confirm('Replace the key of ' + (m.label || 'this member') + '? Do this only after you have spoken to them (call, in person): '
    + 'whoever holds a new passkey on their account will sign for them in this team.')) return;
  try {
    const r = await post('/api/org/key-replace', { user_id: m.user_id });
    if (safeId(r.req_id)) location.href = 'sign.html?req=' + encodeURIComponent(r.req_id);
  } catch (e) { notice(msg, 'err', failText(e)); }
}

async function renderSigRequests() {
  let list = [];
  try { list = await get('/api/sig-requests'); } catch (e) { list = []; }
  $('#sr-card').hidden = !list.length;
  const box = clear($('#srs'));
  const what = { policy: 'Policy version', mandate: 'Mandate', approval: 'Approval', revocation: 'Revocation' };
  for (const r of list) {
    if (!safeId(r.id)) continue;
    box.append(h('div', { class: 'row' },
      h('span', {}, h('strong', { text: (what[r.kind] || r.kind) + ' ' + (r.ref || '') }), ' - needs ' + needsText((r.needs || []).map((n) => [n.role, n.k])) + ', ',
        h('span', { class: 'progress', text: r.have + '/' + r.need })),
      h('a', { class: 'btn', href: 'sign.html?req=' + encodeURIComponent(r.id) }, 'Review and sign')));
  }
}

// ---- policy editor ----
function editorMembers() {
  // who can be in the policy: members with a key that are not observers or removed
  const byKid = new Map((S.policy ? S.policy.members : []).map((m) => [Array.from(m.kid).map((x) => x.toString(16).padStart(2, '0')).join(''), m]));
  return S.org.members.filter((m) => m.status !== 'removed' && !(m.roles.length === 1 && m.roles[0] === 'observer')).map((m) => {
    const inPol = byKid.get(m.kid);
    return { user_id: m.user_id, kid: m.kid, label: (inPol && inPol.label) || m.label || '', roles: inPol ? [...inPol.roles] : m.roles.filter((r) => ROLE_SET.includes(r)), inPolicy: !!inPol || m.status === 'pending', status: m.status };
  });
}

function renderEditor() {
  $('#edit-card').hidden = !isOwner();
  if (!isOwner()) return;
  const box = clear($('#pmembers'));
  if (!S.policy) {
    $('#edit-head').textContent = 'Start team mode';
    $('#edit-hint').textContent = 'The first policy lists only you, with all roles, every rule one signature. You sign it with your passkey. Then invite members and sign version 2 with their roles and the rules you want.';
    for (const id of ['r_over', 'r_overk', 'r_acck', 'r_polk', 'r_reck']) $('#' + id).closest('div').hidden = true;
    $('#draft').textContent = 'Create first policy and sign';
    return;
  }
  for (const m of editorMembers()) {
    const row = h('div', { class: 'member', 'data-uid': m.user_id },
      h('div', {}, h('label', {}, h('input', { type: 'checkbox', class: 'inpol', checked: m.inPolicy }), 'in policy'),
        h('input', { class: 'lab', value: m.label, maxlength: '32', 'aria-label': 'Label' }), h('span', { class: 'hint mono', text: short(m.kid) + (m.status === 'pending' ? ' (pending)' : '') })),
      h('div', { class: 'roles' }, ...ROLE_SET.map((r) => h('label', {}, h('input', { type: 'checkbox', class: 'role', value: r, checked: m.roles.includes(r) }), r))));
    box.append(row);
  }
  const f = formFromRules(S.policy.rules);
  $('#r_over').value = (f.overCents / 100).toFixed(2); $('#r_overk').value = String(Math.max(f.overK, 1)); $('#r_acck').value = String(f.accK); $('#r_polk').value = String(f.polK); $('#r_reck').value = String(f.recK || 0);
  $('#edit-card').addEventListener('input', preview);
  $('#edit-card').addEventListener('change', preview);
  preview();
}

function readDraft() {
  if (!S.policy) {
    const mine = S.org.members.find((m) => m.user_id === myUid());
    return { members: [{ user_id: myUid(), roles: [...ROLE_SET], label: ((mine && mine.label) || 'owner').slice(0, 32) }],
      rules: { policy: { role: 'owner', k: 1 }, revocation: { role: 'any', k: 1 }, ceiling: { role: 'owner', k: 1 }, mandate: [], approval: [] } };
  }
  const members = [];
  for (const row of document.querySelectorAll('#pmembers .member')) {
    if (!row.querySelector('.inpol').checked) continue;
    members.push({ user_id: row.dataset.uid, label: row.querySelector('.lab').value.trim(), roles: [...row.querySelectorAll('.role:checked')].map((i) => i.value) });
  }
  const overCents = dollarsToCents($('#r_over').value);
  const rules = rulesFromForm({ overCents: overCents === null ? -1 : overCents, overK: Number($('#r_overk').value), accK: Number($('#r_acck').value), polK: Number($('#r_polk').value), recK: Number($('#r_reck').value) });
  return { members, rules, badAmount: overCents === null };
}

function preview() {
  const d = readDraft();
  const P = checkDraft(d.members, d.rules);
  if (d.badAmount) P.unshift({ field: 'rules', text: 'Amount: dollars with up to 2 decimals, e.g. 500.' });
  const box = clear($('#pwords'));
  if (P.length) { notice($('#editmsg'), 'err', P.map((p) => p.text).join(' ')); $('#draft').disabled = true; return; }
  notice($('#editmsg'), 'ok', ''); $('#draft').disabled = false;
  const pseudo = { ver: S.policy ? S.policy.ver + 1 : 1, prev: S.policy ? new Uint8Array(32) : null, members: d.members, rules: d.rules };
  box.append(h('h3', { text: 'The draft in words' }), kv(describePolicy(pseudo)));
}

const myUid = () => (S.me.user && S.me.user.id) || S.me.account.id;

async function sendDraft() {
  const d = readDraft();
  const btn = $('#draft'); btn.disabled = true;
  try {
    const r = await post('/api/org/policy/draft', { members: d.members, rules: d.rules });
    if (!safeId(r.req_id)) throw new Error('Unexpected request id from server');
    location.href = 'sign.html?req=' + encodeURIComponent(r.req_id);
  } catch (e) { notice($('#editmsg'), 'err', failText(e)); btn.disabled = false; }
}

// ---- invites ----
async function invite() {
  const roles = [...document.querySelectorAll('#invroles input:checked')].map((i) => i.value);
  const out = $('#invout');
  if (!roles.length) { notice(out, 'err', 'Choose at least one role.'); return; }
  if (roles.includes('observer') && roles.length > 1) { notice(out, 'err', 'An observer has no other role: it signs nothing.'); return; }
  try {
    const r = await post('/api/org/invites', { roles });
    clear(out); out.hidden = false; out.className = 'notice warn';
    out.append(h('strong', { text: 'Invite link (shown once, works once for 24 hours):' }), h('pre', { text: r.url }), copyButton(() => r.url, 'Copy link'),
      h('p', { text: 'Send it to the person yourself. They create their own passkey; then add them to a new policy version below.' }));
  } catch (e) { notice(out, 'err', failText(e)); }
}

// ---- settings ----
function renderSettings() {
  const s = S.org.settings || {};
  $('#settings-card').hidden = !isOwner();
  renderAnchors(s.profile || 'smb');
  if (!isOwner()) return;
  $('#s_profile').value = s.profile || 'smb';
  $('#s_ttl').value = String(Math.round((s.defer_ttl_s || 3600) / 60));
  $('#s_esc').value = String(Math.round((s.escalate_after_s || 600) / 60));
  $('#s_pend').value = String(s.max_pending || 5);
  $('#s_hour').value = String(s.max_defers_hour || 20);
  $('#s_adv').value = s.advisor || 'off';
}
async function saveSettings() {
  const ttl = Number($('#s_ttl').value) * 60, esc = Number($('#s_esc').value) * 60;
  if (!(ttl >= 900 && ttl <= 3600)) { notice($('#setmsg'), 'err', 'An approval waits 15 to 60 minutes.'); return; }
  const body = { profile: $('#s_profile').value, defer_ttl_s: ttl, escalate_after_s: esc, max_pending: Number($('#s_pend').value), max_defers_hour: Number($('#s_hour').value), advisor: $('#s_adv').value };
  try { const r = await put('/api/org/settings', body); S.org.settings = r; renderAnchors(r.profile); notice($('#setmsg'), 'ok', 'Saved.'); } catch (e) { notice($('#setmsg'), 'err', failText(e)); }
}

// ---- 0.2.13: delegation (junior -> senior) ----
async function renderDelegation() {
  $('#deleg-card').hidden = !(isOwner() && S.policy);
  if ($('#deleg-card').hidden) return;
  let agents = [];
  try { agents = await get('/api/agents'); } catch (e) { agents = []; }
  const signing = S.org.members.filter((m) => m.status === 'active' && m.roles.some((r) => ROLE_SET.includes(r)));
  clear($('#d_agent')).append(...agents.map((a) => h('option', { value: a.id }, a.name + ' (' + a.id + ')')));
  clear($('#d_op')).append(...S.org.members.filter((m) => m.status === 'active').map((m) => h('option', { value: m.user_id }, m.label)));
  clear($('#d_appr')).append(...signing.map((m) => h('label', { class: 'check' }, h('input', { type: 'checkbox', value: m.user_id }), ' ' + m.label)));
  const show = async () => {
    const id = $('#d_agent').value;
    if (!safeId(id)) { $('#d_cur').textContent = ''; return; }
    try {
      const v = await get('/api/agents/' + encodeURIComponent(id) + '/delegation');
      const c = v.current, name = (u) => (S.org.members.find((m) => m.user_id === u) || {}).label || String(u).slice(0, 8);
      $('#d_cur').textContent = c ? 'Now: run by ' + name(c.operator_user_id) + '; confirmed by ' + (c.approvers ? c.approvers.map(name).join(', ') : 'anyone the policy allows except them')
        + (c.until ? ' until ' + new Date(c.until * 1000).toLocaleDateString() : '') + '. '
        + (c.policy_ver ? 'In the signed policy (version ' + c.policy_ver + ').' : 'Applied by the server only: not yet signed into the policy.')   // 0.2.15
        + ' Changes recorded: ' + v.history.length + '.' : 'Not assigned: anyone the policy allows confirms.';
    } catch (e) { $('#d_cur').textContent = failText(e); }
  };
  $('#d_agent').addEventListener('change', show);
  await show();
}
async function saveDelegation() {
  const ap = [...document.querySelectorAll('#d_appr input:checked')].map((x) => x.value);
  const body = { operator_user_id: $('#d_op').value, approvers: ap.length ? ap : null };
  if ($('#d_days').value) body.days = Number($('#d_days').value);
  try { const r = await put('/api/agents/' + encodeURIComponent($('#d_agent').value) + '/delegation', body); delegSigned(r, 'Saved'); await renderDelegation(); await renderSigRequests(); }
  catch (e) { notice($('#delegmsg'), 'err', levelError(e) || failText(e)); }
}
// 0.2.15: a delegation change is a policy version: point to the signature request it opened
function delegSigned(r, done) {
  const rq = r && r.policy_request;
  const box = $('#delegmsg');
  if (!rq) { notice(box, 'ok', done + '.'); return; }
  notice(box, 'ok', (r.waits_for_signatures ? 'Drafted: in force once policy version ' + rq.policy_ver + ' is signed (' + needsWords(rq.needs) + ').'
    : done + ' (the server applies it now). To prove it in the evidence pack, sign policy version ' + rq.policy_ver + ' (' + needsWords(rq.needs) + ').') + ' ');
  if (safeId(rq.req_id)) box.append(h('a', { href: 'sign.html?req=' + encodeURIComponent(rq.req_id), text: 'Open the signature request' }));
}
const needsWords = (needs) => (needs || []).map((n) => n.k + ' ' + n.role).join(' + ');
async function endDelegation() {
  try { const r = await del('/api/agents/' + encodeURIComponent($('#d_agent').value) + '/delegation'); delegSigned(r, 'Ended (the record stays)'); await renderDelegation(); await renderSigRequests(); }
  catch (e) { notice($('#delegmsg'), 'err', failText(e)); }
}

async function renderOrgs() {
  try { S.orgs = await get('/api/orgs'); } catch (e) { S.orgs = []; }
  const cur = S.orgs.find((o) => o.current);
  S.myRoles = cur ? cur.roles : [];
  $('#orgs-card').hidden = S.orgs.length < 2;
  clear($('#orgsel')).append(...S.orgs.map((o) => h('option', { value: o.account_id, selected: o.current }, (o.name || o.account_id) + ' (' + o.roles.join(', ') + ')')));
}

async function main() {
  S.me = await mountNav(true);
  if (!S.me) return;
  await renderOrgs();
  S.org = await get('/api/org');
  S.policy = S.org.policy ? policyFromJson(S.org.policy) : null;
  if (!S.myRoles.length) { const m = S.org.members.find((x) => x.user_id === myUid()); S.myRoles = m ? m.roles : []; }
  $('#orgname').textContent = S.org.principal || '';
  $('#invite-card').hidden = !isOwner();
  renderPolicy(); renderMembers(); renderEditor(); renderSettings();
  await renderSigRequests();
  await renderDelegation();
  $('#d_save').addEventListener('click', saveDelegation);
  $('#d_end').addEventListener('click', endDelegation);
  $('#invite').addEventListener('click', invite);
  $('#draft').addEventListener('click', sendDraft);
  $('#setsave').addEventListener('click', saveSettings);
  $('#orgswitch').addEventListener('click', async () => { try { await post('/api/orgs/switch', { account_id: $('#orgsel').value }); location.reload(); } catch (e) { notice(msg, 'err', failText(e)); } });
  setInterval(() => { renderSigRequests().catch(() => {}); }, 5000);
}
main().catch((e) => notice(msg, 'err', failText(e)));
