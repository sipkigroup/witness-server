// Pure helpers of the mandate form (no DOM): testable with node.
import { encode, bytesToHex } from './cde.js';
// A switched-on permission with nothing to enforce is silently FORBIDDEN by the server, so warn before signing.
export function formWarnings(v) {
  const W = [];
  if (v.pu_on && !String(v.pu_budget || '').trim() && !String(v.pu_max || '').trim()) {
    W.push({ field: 'pu_budget', text: 'Purchases are switched on but the budget is empty: purchases will be FORBIDDEN. Set a budget?' });
  }
  if (v.ms_on && !String(v.ms_dom || '').trim() && !String(v.ms_to || '').trim()) {
    W.push({ field: 'ms_dom', text: 'Messages are switched on but no domain or address is listed: messages will be FORBIDDEN. Add a domain or address?' });
  }
  return W;
}

// L2 data classes (ARHITEKTURA-0.2 4.1): found by format with checksums, no list of phrases needed.
export const L2_CLASSES = [
  ['card_number', 'card numbers (13-19 digits, Luhn check)'],
  ['iban', 'IBAN (length of the country + mod 97)'],
  ['phone', 'phone numbers (E.164 and US/RU/EU national, 10+ digits)'],
  ['email_address', 'e-mail addresses in the text'],
  ['ssn', 'US social security numbers'],
  ['crypto_address', 'crypto addresses (BTC with checksum, ETH)'],
  ['postal_address', 'postal addresses (US and RU patterns)'],
];
const L2 = new Set(L2_CLASSES.map(([k]) => k));
const cents = (c) => (c == null ? '' : (c / 100).toFixed(2));

// Signed mandate map -> raw form values (to prefill "new mandate" from the active one).
export function inputsFromMandate(m) {
  const P = (m && m.permissions) || {};
  const v = { days: '30', pu_on: false, pu_budget: '', pu_max: '', pu_min: '', pu_payees: '', ms_on: false, ms_dom: '', ms_to: '', l2: [], fd: '', del_mode: 'none', del_t: '', del_irr: false, pub_mode: 'none', pub_c: '', cmd_mode: 'none', cmd_allow: '', cmd_unlisted: 'ask', cmd_sandboxed: 'ask', http_mode: 'none', http_allow: '', http_unlisted: 'ask' };
  if (m && m.exp && m.nbf) v.days = String(Math.max(1, Math.min(365, Math.round((m.exp - m.nbf) / 86400))));
  if (P.purchase && typeof P.purchase === 'object') {
    v.pu_on = true; v.pu_budget = cents(P.purchase.budget); v.pu_max = cents(P.purchase.max_per_action);
    if (Number.isInteger(P.purchase.min_per_action)) v.pu_min = cents(P.purchase.min_per_action);   // 0.2.83
    if (Array.isArray(P.purchase.allowed_payees)) v.pu_payees = P.purchase.allowed_payees.join('\n');     // 0.2.84 (R5-P3): one id per line, never re-split on ','
  }
  if (P.message && typeof P.message === 'object') { v.ms_on = true; v.ms_dom = (P.message.domains || []).join(', '); v.ms_to = (P.message.to || []).join(', '); }
  if (P.delete && typeof P.delete === 'object') { v.del_mode = 'targets'; v.del_t = (P.delete.targets || []).join(', '); v.del_irr = !!P.delete.allow_irreversible; }
  if (P.publish && typeof P.publish === 'object') { v.pub_mode = 'channels'; v.pub_c = (P.publish.channels || []).join(', '); }
  if (P.command && typeof P.command === 'object') { v.cmd_mode = 'list'; v.cmd_allow = (P.command.allow || []).join(', '); v.cmd_unlisted = P.command.unlisted || 'ask'; v.cmd_sandboxed = P.command.sandboxed === 'allow' ? 'allow' : 'ask'; }
  if (P.http && typeof P.http === 'object') { v.http_mode = 'list'; v.http_allow = (P.http.allow || []).join(', '); v.http_unlisted = P.http.unlisted || 'ask'; }
  else if (P.http === false) v.http_mode = 'forbid';
  const fd = (m && m.forbidden_data) || [];
  v.l2 = fd.filter((x) => L2.has(x));
  v.fd = fd.filter((x) => !L2.has(x)).join(', ');
  return v;
}

const addCsv = (s, x) => { const a = String(s || '').split(',').map((t) => t.trim()).filter(Boolean); if (!a.includes(x)) a.push(x); return a.join(', '); };

// Apply one suggestion of GET /api/suggestions (3.2) to raw form values; nothing else changes.
// -> {values, note} ; a server-provided ready `form` (task 02) is preferred over the kind/class/key fallback.
export function applySuggestion(v0, s) {
  const v = { ...v0 };
  if (s.form && typeof s.form === 'object') {
    const f = s.form;
    if (f.purchase && f.purchase.enabled) { v.pu_on = true; v.pu_budget = cents(f.purchase.budget); v.pu_max = cents(f.purchase.max_per_action); }
    if (f.message) { v.ms_on = !!((f.message.domains || []).length || (f.message.to || []).length); v.ms_dom = (f.message.domains || []).join(', '); v.ms_to = (f.message.to || []).join(', '); }
    if (f.publish) { v.pub_mode = 'channels'; v.pub_c = (f.publish.channels || []).join(', '); }
    if (f.delete) { v.del_mode = 'targets'; v.del_t = (f.delete.targets || []).join(', '); v.del_irr = !!f.delete.allow_irreversible; }
    if (f.command && typeof f.command === 'object') { v.cmd_mode = 'list'; v.cmd_allow = (f.command.allow || []).join(', '); v.cmd_unlisted = f.command.unlisted || 'ask'; v.cmd_sandboxed = f.command.sandboxed === 'allow' ? 'allow' : 'ask'; }
    if (f.http && typeof f.http === 'object') { v.http_mode = 'list'; v.http_allow = (f.http.allow || []).join(', '); v.http_unlisted = f.http.unlisted || 'ask'; }
    else if (f.http === false) v.http_mode = 'forbid';
    return { values: v, note: s.proposal || 'Suggested form applied.' };
  }
  if (s.kind === 'budget') {
    v.pu_on = true; v.pu_budget = cents(s.proposed_budget);
    if (!v.pu_max || Number(v.pu_max) > Number(v.pu_budget)) v.pu_max = v.pu_budget;
    return { values: v, note: 'Budget set to ' + v.pu_budget + ' (p95 of approved amounts x 1.2).' };
  }
  if (s.class === 'publish') { v.pub_mode = 'channels'; v.pub_c = addCsv(v.pub_c, s.key); return { values: v, note: 'Channel "' + s.key + '" added.' }; }
  if (s.class === 'message') { v.ms_on = true; v.ms_to = addCsv(v.ms_to, s.key); return { values: v, note: 'Address "' + s.key + '" added.' }; }
  if (s.class === 'delete') { v.del_mode = 'targets'; v.del_t = addCsv(v.del_t, s.key); return { values: v, note: 'Delete target "' + s.key + '" added.' }; }
  return { values: v, note: 'This suggestion (' + s.class + ') has no field in this form; nothing was changed.' };
}

// 0.2.28: the example mandate of docs/quickstart.md step 3, offered after "Create agent" with the demo preset (mandate.html?sample=1).
// Only for an agent whose tool map has the demo tools; null otherwise. Publishing and deleting stay "not specified": they wait for the owner.
export function sampleFor(toolmap) {
  const t = (toolmap && toolmap.tools) || {};
  if (!t.send_email || !t.purchase || !t.publish) return null;
  return { days: '30', pu_on: true, pu_budget: '200', pu_max: '100', ms_on: true, ms_dom: 'acme.example', ms_to: '', l2: ['card_number', 'iban', 'ssn', 'phone'],
    fd: 'home_address', del_mode: 'none', del_t: '', del_irr: false, pub_mode: 'none', pub_c: '', cmd_mode: 'none', cmd_allow: '', cmd_unlisted: 'ask', cmd_sandboxed: 'ask', http_mode: 'none', http_allow: '', http_unlisted: 'ask' };
}

// 0.2.9: read-only shell commands of the recommended Claude Code mandate (command.allow, other commands asked), modelled on Claude Code's own
// read-only set. Same list as server/app/toolmap.py CC_READONLY_COMMANDS and the hook's DEFAULT_SAFE_COMMANDS (tests keep them equal).
// Not listed on purpose: find, xargs, sed, awk, env, printenv, make, interpreters, package managers, curl, wget: each runs other programs or code, writes files or sends data.
// 0.2.53: then 15 local writes (mkdir ... git rm): the server allows only the form whose every path is inside the project; any other is asked.
// 0.2.54: + find, sed, awk, jq (the "not listed" note above is superseded): only the form that reads and prints; -exec, -delete, sed -i, e, w,
// awk system(), pipes, print > file, jq env ... are asked.
// 0.2.89: + 19 read-only diagnostics after jq; the server allows only their read-only form (git remote add, git tag v1, git stash pop,
// git config k v, pip list --outdated, ps eww ... are asked); '--version' = `python3 --version`, `node --version` ...
export const READONLY_COMMANDS = ['ls', 'pwd', 'cd', 'cat', 'head', 'tail', 'wc', 'echo', 'grep', 'rg', 'which', 'file', 'stat', 'du', 'df',
  'date', 'uname', 'git status', 'git log', 'git diff', 'git show', 'git branch', 'diff', 'tree', 'sort',
  'uniq', 'cut', 'tr', 'nl', 'column', 'basename', 'dirname', 'realpath', 'sha1sum', 'sha256sum', 'sha512sum',
  'shasum', 'cmp', 'comm', 'test', 'sleep', 'git blame', 'git ls-files', 'git rev-parse', 'git describe',
  'git shortlog', 'git grep', 'git reflog',
  'mkdir', 'touch', 'cp', 'mv', 'ln', 'chmod', 'rm', 'rmdir', 'git add', 'git commit', 'git checkout',
  'git switch', 'git restore', 'git mv', 'git rm',
  'find', 'sed', 'awk', 'jq',
  'ps', 'lsof', 'whoami', 'id', 'git remote', 'git tag list', 'git stash list', 'git stash show', 'git config get', 'npm ls', 'npm list',
  'pip list', 'pip3 list', 'pip freeze', 'pip3 freeze', 'pip show', 'pip3 show', 'uv pip', 'git check-ignore', 'git ls-tree', 'git rev-list', 'git merge-base', 'git show-ref',
  'od', 'hexdump', 'strings', 'xxd', '--version'];

// 0.2.56 (V3): command.sandboxed of the recommended form: "allow" = test runners (pytest, npm test, make ...) run without a question ONLY while
// the hook reports a strict Claude Code sandbox for that call (no network, secrets unreadable, no retry outside it); otherwise asked as before.
// Same value as the hook's and the server's DEFAULT_SANDBOXED (a test keeps them equal). A signed mandate without the key is never widened:
// prefilling from it (inputsFromMandate) keeps 'ask'.
export const RECOMMENDED_SANDBOXED = 'allow';
// 0.2.90 (standing mandate): the recommended form lets every command run with a receipt; the witness's own four gates ask (same value as
// the client's form.py DEFAULT_UNLISTED and the server's mapping.py; a test keeps them equal)
export const RECOMMENDED_UNLISTED = 'ask';   // 0.2.90 (QA 03.11): silence only under the strict sandbox (the code option), not by the list
// 0.2.82 (irreversibility gate): the option "Code in Claude Code's strict sandbox: run without asking" is this reserved entry of the signed
// command list (the core has no member for it); same string as the server's hookjudge/mapping.py SANDBOXED_CODE. It needs the runner option
// above (command.sandboxed = "allow"). On by default in the recommended section; delete the entry from the list to switch it off.
export const SANDBOXED_CODE = '(code in the strict sandbox)';
// r0296: the profile "auto mode + Witness" (ask only what cannot be undone) = these two reserved entries of the signed command list; same
// strings as the server's hookjudge/mapping.py AUTO_PROFILE / AUTO_OUTSIDE and the client's form.py (a test keeps them equal). The second
// lets a write in the home folder outside the project run with a receipt, only when the hook copied the file first (undo).
export const AUTO_PROFILE = '(auto mode: ask only what cannot be undone)';
export const AUTO_OUTSIDE = '(write outside the project) /*';
export function autoProfileForm(form) {
  const f = JSON.parse(JSON.stringify(form || {}));
  const c = f.command;
  if (!c || typeof c !== 'object' || !Array.isArray(c.allow)) return f;
  c.allow = c.allow.filter((x) => x !== AUTO_PROFILE && x !== AUTO_OUTSIDE).concat([AUTO_PROFILE, AUTO_OUTSIDE]);
  return f;
}
export function isAutoProfile(cm) {
  return !!cm && Array.isArray(cm.allow) && cm.allow.includes(AUTO_PROFILE) && cm.allow.includes(AUTO_OUTSIDE);
}

// 0.2.9: the recommended "Shell commands" section for an agent whose tool map judges shell commands as class `command` (preset claude-code);
// null for any other agent (nothing preset). Used only when the agent has no active mandate yet.
export function recommendedCommand(toolmap) {
  const b = toolmap && toolmap.tools && toolmap.tools.Bash;
  if (!b || b.class !== 'command') return null;
  return { cmd_mode: 'list', cmd_allow: READONLY_COMMANDS.concat([SANDBOXED_CODE]).join(', '), cmd_unlisted: RECOMMENDED_UNLISTED, cmd_sandboxed: RECOMMENDED_SANDBOXED };
}

// PROPOSAL-06: shell commands section of the form -> form.command (null = not specified: every command needs the owner's approval)
export function commandForm(mode, allowCsv, unlisted, sandboxed) {
  if (mode !== 'list') return null;
  const allow = String(allowCsv || '').split(',').map((t) => t.trim()).filter(Boolean);
  const c = { allow };
  if (unlisted && unlisted !== 'ask') c.unlisted = unlisted;
  if (sandboxed === 'allow') c.sandboxed = 'allow';     // 0.2.56: only "allow" is sent ("ask" = absent = the default)
  return c;
}

// PROPOSAL-08-http: HTTP requests section of the form -> form.http (null = not specified: every request needs the owner's approval; false = forbidden).
// Rules are comma-separated ("GET api.github.com/repos/acme/app/**, PUT api.github.com/repos/acme/app/pulls/*/merge"); the server canonicalises them.
export function httpForm(mode, allowCsv, unlisted) {
  if (mode === 'forbid') return false;
  if (mode !== 'list') return null;
  const allow = String(allowCsv || '').split(',').map((t) => t.trim()).filter(Boolean);
  const h = { allow };
  if (unlisted === 'deny') h.unlisted = 'deny';
  return h;
}

// 0.2.43: an agent whose tool map judges HTTP requests as class `http` (preset openshell): the section is opened as a list (empty: every request is
// asked until the owner names endpoints); null for any other agent.
export function recommendedHttp(toolmap) {
  const t = (toolmap && toolmap.tools) || {};
  if (!Object.values(t).some((e) => e && e.class === 'http')) return null;
  return { http_mode: 'list', http_allow: '', http_unlisted: 'ask' };
}

// one limit for a money amount (cents) of the form: the page field takes 9 digits of dollars + 2 decimals (ui.js dollarsToCents); the server (app/mandates.py MAX_CENTS) and the importer use the same number
export const MAX_CENTS = 99999999999;

export function renewCheck(old, neu) {
  if (!old || !neu || typeof old !== 'object' || typeof neu !== 'object') return 'no mandate';
  const ko = Object.keys(old).sort(), kn = Object.keys(neu).sort();
  if (ko.join() !== kn.join()) return 'the members differ';
  for (const k of ko) {
    if (['id', 'nbf', 'exp', 'toolmap_sha256'].includes(k)) continue;
    if (bytesToHex(encode(old[k])) !== bytesToHex(encode(neu[k]))) return 'member ' + k + ' differs';
  }
  if (neu.id === old.id) return 'the same id';
  if (!(Number.isInteger(neu.nbf) && Number.isInteger(neu.exp)) || neu.nbf < old.nbf || neu.exp > old.exp) return 'the time is wider';
  return null;
}
