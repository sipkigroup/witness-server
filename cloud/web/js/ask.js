// 0.2.76 (owner 31.10 after the live check: "the interface is very technical"): what the agent asks, in one line, for the top of the
// approval page ("Your agent wants to run" + the command). Pure functions: approve.js renders the result through honest.js (inspectFields);
// the signed view (signview.js) is the server's answer and does not depend on these words.
import { secretOf } from './levels.js';
import { fmtMoney } from './ui.js';

function argsOf(r) { try { const a = JSON.parse(String(r.args_preview || '')); return a && typeof a === 'object' ? a : null; } catch (e) { return null; } }

// -> {verb, what}: verb is the title ("Your agent wants to run"), what is the thing itself (a command, a file, a recipient), possibly ''
export function askOf(r) {
  const a = (r && r.action && typeof r.action === 'object') ? r.action : {};
  const tool = String((r && r.tool) || ''), base = tool.split('.')[0];
  const args = argsOf(r || {});
  const pick = (k) => (args && typeof args[k] === 'string' ? args[k] : null);
  const rc = a.recipient != null ? String(a.recipient) : '';
  const text = r && typeof r.text_preview === 'string' ? r.text_preview : '';
  const cmd = text || pick('command') || '';
  if (secretOf(r) !== null) return { verb: 'Your agent wants to read a secret', what: (base === 'Bash' ? cmd : pick('file_path')) || secretOf(r) };
  // 0.2.77 (red team 31.10, H1): a file tool judged dangerous (Write.danger: the agent's own settings, an MCP config, a git hook or git's
  // configuration) has class "command" but runs nothing: it WRITES a file. The title names the REAL file (the server's recipient, after
  // links), and the name the agent used when it differs (a link: notes.md -> .claude/settings.json). The new text is shown below (#pvblock).
  const prot = protectedWrite(r);
  if (prot) return prot;
  if (base === 'Bash' || a.class === 'command') return { verb: 'Your agent wants to run', what: cmd || rc };
  if (/^(Write|Edit|MultiEdit|NotebookEdit)$/.test(base)) return { verb: 'Your agent wants to write the file', what: pick('file_path') || pick('notebook_path') || rc };
  if (/^(Read|NotebookRead)$/.test(base)) return { verb: 'Your agent wants to read the file', what: pick('file_path') || pick('notebook_path') || rc };
  if (base === 'WebFetch') return { verb: 'Your agent wants to open', what: pick('url') || rc };
  if (base === 'WebSearch') return { verb: 'Your agent wants to search the web for', what: pick('query') || rc };
  const money = a.amount != null ? fmtMoney(a.amount, a.currency || 'USD') : '';
  switch (a.class) {
    case 'message': return { verb: 'Your agent wants to send a message to', what: rc };
    case 'purchase': return { verb: 'Your agent wants to pay' + (money ? ' ' + money : '') + (rc ? ' to' : ''), what: rc };
    case 'publish': return { verb: 'Your agent wants to publish to', what: rc };
    case 'delete': return { verb: 'Your agent wants to delete', what: rc };
    default: return { verb: 'Your agent wants to use ' + (tool || a.class || 'a tool') + (money ? ' (' + money + ')' : ''), what: rc };
  }
}

const FILE_TOOL = /^(Write|Edit|MultiEdit|NotebookEdit)$/;
// -> {kind: 'agent-config' | 'git-config', real, named} of a dangerous file write, or null
export function protectedTarget(r) {
  const a = (r && r.action && typeof r.action === 'object') ? r.action : {};
  const base = String((r && r.tool) || '').split('.')[0];
  if (!FILE_TOOL.test(base)) return null;
  const m = /^(agent-config|git-config):(.+)$/s.exec(a.recipient != null ? String(a.recipient) : '');
  if (!m) return null;
  const args = argsOf(r || {});
  const named = args && typeof args.file_path === 'string' ? args.file_path : args && typeof args.notebook_path === 'string' ? args.notebook_path : '';
  return { kind: m[1], real: m[2], named };
}
// 0.2.77b (red team R2-2): a hook of .git/hooks, or of core.hooksPath (husky, .githooks): a hook's name or a hooks folder
const HOOK_NAMES = /^(applypatch-msg|pre-applypatch|post-applypatch|pre-commit|pre-merge-commit|prepare-commit-msg|commit-msg|post-commit|pre-rebase|post-checkout|post-merge|pre-push|pre-receive|update|proc-receive|post-receive|post-update|reference-transaction|push-to-checkout|pre-auto-gc|post-rewrite|sendemail-validate|fsmonitor-watchman|p4-[a-z-]+|post-index-change)$/i;
export function isGitHook(p) {
  const s = String(p || '');
  return /\/hooks(\/|$)/i.test(s) || /\/(\.husky|\.githooks|githooks|\.git-hooks|git-hooks)\//i.test(s) || HOOK_NAMES.test(s.split('/').pop() || '');
}
function protectedWrite(r) {
  const t = protectedTarget(r);
  if (!t) return null;
  const verb = t.kind === 'agent-config' ? 'Your agent wants to change its own settings, the file'
    : isGitHook(t.real) ? 'Your agent wants to change a git hook, the file' : 'Your agent wants to change git\'s configuration, the file';
  const via = t.named && t.named !== t.real && !t.real.endsWith('/' + t.named.replace(/^\.\//, '')) ? '\n(it writes through ' + t.named + ', a link to this file)' : '';
  return { verb, what: t.real + via };
}

// the danger mark in words (dangerShown() of levels.js gives "true", "true (why)", "false" or null) -> a sentence, or '' when not dangerous
export function dangerText(ds, r) {
  const s = ds == null ? '' : String(ds);
  const t = protectedTarget(r);     // 0.2.77 (H1): what this file is, in words (before 0.2.77: the generic line of a command)
  if (t && t.kind === 'agent-config') return 'Dangerous: these are your agent\'s own settings (hooks, MCP servers, permissions). A change here can switch the witness off for its next session. Approve only if you asked for exactly this change.';
  if (t) return isGitHook(t.real) ? 'Dangerous: git runs this hook by itself (on commit, checkout, push): what is written here runs later without asking you.'
    : 'Dangerous: git\'s configuration can name programs git runs by itself, and where your code is sent. Approve only if you asked for exactly this change.';
  if (!/^true/.test(s)) return '';
  if (s === 'true' && r && secretOf(r) !== null) return 'Dangerous: this reads a secret.';
  const m = /^true \((.*)\)$/.exec(s);
  if (m) return 'Dangerous: ' + m[1].replace(/shown above/g, 'shown below').replace(/see below/g, 'shown below') + '.';
  // 06.11 (owner's check: "curl -sI" was called a command that can delete files): a network call says what it does
  if (r && (String(r.tool || '') === 'Bash.net' || String((r.action && r.action.recipient) || '').startsWith('(network) '))) return 'Dangerous: this sends a request to the internet. Data from your computer can go out with it. Read it before you decide.';
  return GENERIC_DANGER;
}
export const GENERIC_DANGER = 'Dangerous: this command can delete, overwrite or send out data. Read it before you decide.';

// 04.11 (L3, red team p.4): why the witness asks, in words for the owner (the page never shows a reason code such as ESCALATE_COMMAND)
export const REASON_WORDS = {
  ESCALATE_COMMAND: 'a command that is not on your list of commands that run without a question',
  ESCALATE_COMMAND_DANGER: 'a dangerous command (it can delete, overwrite or send out data, or run a download)',
  ESCALATE_PUBLISH: 'it sends data out of this machine, or is hard to undo, and your mandate names no channel for it',
  ESCALATE_DELETE: 'a deletion your mandate does not cover',
  ESCALATE_MONEY: 'a payment your mandate does not settle by itself',
  ESCALATE_DATA: 'it may carry data your mandate protects',
  ESCALATE_FILE: 'a file action your mandate does not cover',
  ESCALATE_COUNT: 'too many actions of this kind in a short time',
  ESCALATE_EXEC_CHANGED: 'it runs files that changed since you last confirmed them',
  ESCALATE_HTTP: 'a web request that is not on your list of requests that run without a question',
  ESCALATE_WRITTEN_RUN: 'it runs a file this agent wrote',
  ESCALATE_SECRET_SEEN: 'this agent read a secret a few minutes ago',
  ESCALATE_NET_UNSEEN: 'a network program whose destination is not in the line',
  ESCALATE_TRIAL_CLAIM: 'the first touch of a trial account',
  ESCALATE_EGRESS_UNSPECIFIED: 'it reaches a host outside this machine and your mandate names no destinations',
  ESCALATE_USER_CONTENT_HOST: 'it sends data to a site where anyone can publish or read it',
  ADVISORY_HOLD: 'the data advisor flagged its text',
};
export function reasonWords(code) { return REASON_WORDS[String(code || '')] || 'another check of the witness'; }
