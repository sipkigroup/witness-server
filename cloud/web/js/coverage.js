// Coverage badge (ARHITEKTURA-0.2 5.2-5.3): a claim of the operator's proxy, not a proof. -> DOM nodes
import { h } from './ui.js';

const LEVEL = { C0: 'no proxy', C1: 'proxy with bypasses', C2: 'all MCP behind the proxy, built-in tools off', C3: 'C2 in a sandbox' };
export function coverageBypasses(cov) {
  if (!cov) return [];
  return [...(cov.unwitnessed || []).map(String), ...(cov.pass_net_tools || []).map((t) => String(t) + ' (pass tool with network access)')];
}
export function coverageLabel(cov) {
  if (!cov || !LEVEL[cov.level]) return 'coverage unknown';
  return cov.level + ' (declared by operator)';
}
export function coverageView(cov) {
  if (!cov) return [h('p', { class: 'hint', text: 'Coverage unknown: the proxy has not reported (it does at start, deus-witness-mcp 0.2).' })];
  const by = coverageBypasses(cov);
  return [h('p', {}, h('span', { class: 'pill cov', text: coverageLabel(cov) }), ' ', LEVEL[cov.level] || ''),
    by.length ? h('div', {}, h('p', { class: 'hint', text: 'Actions through these channels are not witnessed:' }), h('ul', {}, ...by.map((b) => h('li', { class: 'mono', text: b })))) : '',
    h('p', { class: 'hint', text: 'Declared by the operator\'s proxy (deus-witness doctor), not verified by the witness. The evidence pack marks it operator-declared.' })];
}

// r0278 (L3 13.11 with the owner, find 5): an agent behind the Claude Code hook (its tool map maps Bash) has no MCP proxy to report
// coverage: "Coverage unknown: the proxy has not reported (deus-witness-mcp 0.2)" said nothing to that person. No line for it.
export function isHookAgent(a) {
  const t = a && a.toolmap && typeof a.toolmap === 'object' ? a.toolmap.tools : null;
  return !!(t && typeof t === 'object' && Object.prototype.hasOwnProperty.call(t, 'Bash'));
}
// one agent, behind the hook: the dashboard shows the simple first screen and folds the rest under "Advanced"
export function simpleAccount(agents) { return Array.isArray(agents) && agents.length === 1 && isHookAgent(agents[0]); }
