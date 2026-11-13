// 0.2.32: /demo/live.html (no login). Renders the public feed of the ONE demo account (GET /v1/demo/live, app/demo_live.py):
// a scripted agent in a container asks the witness before each step. Everything from the server is rendered as text (textContent),
// never as HTML: the recipient is the only string the agent chooses, and a leaked agent key must not be able to put markup on our site.
const $ = (s) => document.querySelector(s);

const TOOL = { send_email: 'E-mail', purchase: 'Purchase', publish: 'Public post', delete_resource: 'Delete', read_file: 'Read a file' };
const REASON = {
  OK: 'inside the mandate',
  OK_APPROVED: 'the owner approved it with the passkey',
  RECIPIENT: 'recipient is not in the mandate',
  DATA_FORBIDDEN: 'the text carries data the mandate forbids (a phone number)',
  PER_ACTION_LIMIT: 'amount above the per-call limit',
  BUDGET: 'the daily budget is spent',
  ESCALATE_PUBLISH: 'publishing is not in the mandate: the owner has to approve',
  AGENT_FROZEN: 'the agent is frozen',
  APPROVAL_RATE: 'too many open questions to the owner',
};
const STATUS = {
  executed: 'ran (stub tool)', consumed: 'ran (stub tool)', allowed: 'allowed', denied: 'not run', expired: 'nobody answered: not run',
  pending_approval: 'waiting for the owner', not_executed: 'not run', approved: 'approved', rejected: 'owner said no: not run',
};
const PILL = { allow: 'allow', deny: 'deny', defer: 'defer' };
const WORD = { allow: 'allowed', deny: 'refused', defer: 'held for the owner' };

export function decisionOf(it) {
  // a held call shows where it ended: approved later (allow), or still held / expired
  if (it.verdict === 'defer' && (it.status === 'executed' || it.status === 'consumed' || it.status === 'approved')) return 'allow';
  return it.verdict;
}

export function describe(it) {
  const amt = typeof it.amount === 'number' ? ' ' + (it.amount / 100).toFixed(2) + ' ' + (it.currency || '') : '';
  return {
    tool: TOOL[it.tool] || String(it.tool || ''),
    target: String(it.recipient || '').slice(0, 80) + amt,
    decision: WORD[decisionOf(it)] || String(it.verdict || ''),
    pill: PILL[decisionOf(it)] || 'esc',
    why: REASON[it.reason] || String(it.reason || ''),
    status: STATUS[it.status] || String(it.status || ''),
    time: new Date((it.t || 0) * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC',
  };
}

export function mandateLines(m) {
  if (!m || !m.permissions) return ['No active mandate.'];
  const p = m.permissions, out = [];
  if (p.message && p.message.to) out.push('E-mail only to: ' + p.message.to.join(', '));
  if (p.purchase) out.push('Purchases: at most ' + (p.purchase.max_per_action / 100).toFixed(2) + ' ' + m.currency + ' per call, '
    + (p.purchase.budget / 100).toFixed(2) + ' ' + m.currency + ' per ' + Math.round((m.budget_window_s || 86400) / 3600) + ' h');
  if (!p.publish) out.push('Public posts: not allowed by the mandate, each one asks the owner');
  if (m.forbidden_data && m.forbidden_data.length) out.push('Never in any text: ' + m.forbidden_data.join(', ').replaceAll('_', ' '));
  if (m.exp) out.push('Valid until ' + new Date(m.exp * 1000).toISOString().slice(0, 10));
  return out;
}

function td(label, text, cls) {
  const e = document.createElement('td');
  e.setAttribute('data-l', label);
  if (cls) { const s = document.createElement('span'); s.className = cls; s.textContent = text; e.append(s); } else e.textContent = text;
  return e;
}

export function render(feed) {
  const body = $('#rows');
  body.replaceChildren();
  for (const it of feed.items || []) {
    const d = describe(it), tr = document.createElement('tr');
    tr.append(td('Time', d.time), td('Step', d.tool), td('To / amount', d.target), td('Witness', d.decision, 'pill ' + d.pill),
      td('Why', d.why), td('Outcome', d.status));
    body.append(tr);
  }
  const t = feed.totals || {};
  $('#totals').textContent = (t.allow || 0) + ' allowed, ' + (t.defer || 0) + ' held for the owner, ' + (t.deny || 0) + ' refused, since the start.';
  const ul = $('#mandate');
  ul.replaceChildren(...mandateLines(feed.mandate).map((x) => { const li = document.createElement('li'); li.textContent = x; return li; }));
  $('#feednote').textContent = (feed.items || []).length ? 'Newest first. Updated ' + describe({ t: feed.generated_at }).time + '.'
    : 'No calls yet: the agent runs once an hour.';
}

async function load() {
  try {
    const r = await fetch('/v1/demo/live', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    render(await r.json());
  } catch (e) {
    $('#feednote').textContent = 'The live feed is not available right now (' + e.message + ').';
  }
  try {
    const w = await (await fetch('/v1/witness')).json();
    $('#kid').textContent = w.kid_hex;
  } catch (e) { /* the command below still works: it fetches the key itself */ }
}

if (typeof document !== 'undefined' && document.querySelector('#rows')) {
  load();
  setInterval(load, 60000);
}
