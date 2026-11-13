// Human-readable text derived from the SAME map that is encoded and signed.
import { fmtMoney, fmtTime } from './ui.js';
const SANDBOXED_CODE = '(code in the strict sandbox)';   // 0.2.82: the reserved command-list entry (mandate_form.js, server mapping.py)

export function describeMandate(m) {
  const L = [];
  const cur = m.currency;
  L.push(['Valid', fmtTime(m.nbf) + ' to ' + fmtTime(m.exp)]);
  L.push(['Agent', m.agent]);
  const P = m.permissions || {};
  const pu = P.purchase;
  if (pu === undefined) L.push(['Purchases', 'not specified (denied)']);
  else if (pu === false) L.push(['Purchases', 'forbidden']);
  else {
    L.push(['Purchases', (Number.isInteger(pu.min_per_action) ? 'from ' + fmtMoney(pu.min_per_action, cur) + ' ' : '') + 'up to ' + fmtMoney(pu.max_per_action, cur) + ' each, ' + fmtMoney(pu.budget, cur) + ' per ' + Math.round(m.budget_window_s / 3600) + ' h']);
    // 0.2.84 (R5-P3): every id quoted (JSON), so the list shown is exactly the list signed: 'Acme, Inc.' is one payee, never two
    if (Array.isArray(pu.allowed_payees)) L.push(['Payees', 'only ' + pu.allowed_payees.length + ': ' + pu.allowed_payees.map((x) => JSON.stringify(x)).join(', ') + ' (any other payee is denied)']);   // 0.2.83
  }
  const ms = P.message;
  if (ms === undefined) L.push(['Messages', 'not specified (denied)']);
  else if (ms === false) L.push(['Messages', 'forbidden']);
  else L.push(['Messages', 'domains: ' + (ms.domains.join(', ') || 'none') + '; addresses: ' + (ms.to.join(', ') || 'none')]);
  const d = P.delete;
  if (d === undefined) L.push(['Deleting', 'not specified: irreversible deletes denied, reversible ones need your approval']);
  else if (d === false) L.push(['Deleting', 'forbidden']);
  else L.push(['Deleting', 'targets: ' + (d.targets.join(', ') || 'none') + (d.allow_irreversible ? '; irreversible allowed' : '; irreversible not allowed')]);
  const pb = P.publish;
  if (pb === undefined) L.push(['Publishing', 'not specified: every publish needs your approval']);
  else if (pb === false) L.push(['Publishing', 'forbidden']);
  else L.push(['Publishing', 'channels: ' + (pb.channels.join(', ') || 'none')]);
  const cm = P.command;   // PROPOSAL-06
  const OTHER = { ask: 'need your approval', allow: 'run without asking', deny: 'are refused' };
  if (cm === undefined || cm === null) L.push(['Shell commands', 'not specified: every command needs your approval; dangerous ones (rm -rf, dd, mkfs, force-push, curl | sh ...) always do']);
  else if (cm === false) L.push(['Shell commands', 'forbidden']);
  else L.push(['Shell commands', 'run without asking: ' + ((cm.allow || []).filter((x) => x !== SANDBOXED_CODE).join(', ') || 'none') + '; other commands ' + (OTHER[cm.unlisted || 'ask'] || 'need your approval') + '; dangerous ones ' + (cm.unlisted === 'deny' ? 'are refused' : 'always need your approval')
    + (cm.sandboxed === 'allow' ? '; test runners (pytest, npm test, make ...) run without asking only inside a strict Claude Code sandbox (no network, secrets unreadable), asked otherwise' : '')
    + (cm.sandboxed === 'allow' && (cm.allow || []).includes(SANDBOXED_CODE) ? "; code in Claude Code's strict sandbox (scripts, interpreters, files the agent wrote) runs without asking; network, writes outside the project, .git, the agent's settings, secrets, remote git and deleting outside the project are still asked" : '')]);
  const hp = P.http;   // PROPOSAL-08-http
  if (hp === undefined || hp === null) L.push(['HTTP requests', 'not specified: every request needs your approval']);
  else if (hp === false) L.push(['HTTP requests', 'forbidden']);
  else L.push(['HTTP requests', 'run without asking: ' + ((hp.allow || []).join(', ') || 'none') + '; other requests ' + (hp.unlisted === 'deny' ? 'are refused' : 'need your approval') + ' (a rule allows its endpoint with any query and body; requests with personal data or secrets are refused anyway)']);
  L.push(['Closed data', (m.forbidden_data || []).join(', ') || 'none chosen here (secrets, card numbers and other protected data stay refused by the core anyway)']);
  if (m.toolmap_sha256) L.push(['Tool map (signed)', 'hash ' + m.toolmap_sha256.slice(0, 16) + '... of the tool map, protected data and advisor mode shown below; changing any of them needs a new signature']);
  L.push(['Signing key', 'passkey, ' + m.principal]);
  return L;
}

export function describeAction(a) {
  const L = [['Class', a.class]];
  if (a.recipient != null) L.push(['Recipient', String(a.recipient)]);
  if (a.amount != null) L.push(['Amount', fmtMoney(a.amount, a.currency || 'USD')]);
  if (a.data && a.data.length) L.push(['Data classes touched', a.data.join(', ')]);
  if (a.reversible != null) L.push(['Reversible', String(a.reversible)]);
  if (a.dangerous != null) L.push(['Dangerous command', String(a.dangerous)]);
  for (const [k, v] of Object.entries(a)) if (!['class', 'recipient', 'amount', 'currency', 'data', 'reversible', 'dangerous', 'agent'].includes(k)) L.push([k, typeof v === 'string' ? v : JSON.stringify(v)]);
  return L;
}
