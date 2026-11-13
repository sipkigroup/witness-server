// "Import from JSON" of the mandate page (0.2.7): the JSON that `deus-witness-hook --print-form <dir>` prints (a form object; an object {"form": {...}}
// is accepted too) -> checked like the server checks a form -> raw values of the page form + a text of what will be signed. No DOM here: testable with node.
// Nothing is sent or signed by this module; the page puts the values into its form and the usual "Review and sign" step follows.
import { describeMandate } from './describe.js';
import { inputsFromMandate, MAX_CENTS } from './mandate_form.js';
import { utf8Len } from './ui.js';

export const MAX_IMPORT = 64 * 1024;
const TOP = ['currency', 'valid_days', 'purchase', 'message', 'forbidden_data', 'publish', 'delete', 'command', 'http'];
const UNLISTED = ['ask', 'allow', 'deny'];
// shape of an http rule (the server checks the rest and canonicalises): METHOD or *, one space, an ASCII host (or *.domain) with an optional port, a path
export const HTTP_RULE_RE = /^(\*|[A-Za-z]{1,16}) (\*\.)?[A-Za-z0-9_.-]+(:[0-9]{1,5})?\/[\x21-\x7e]*$/;
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const isInt = (x) => typeof x === 'number' && Number.isInteger(x);

// a list of items the page can hold in a comma-separated field: non-empty strings, no comma, no control character
// R5-01: invisible, direction-control and other Cc/Cf/Zl/Zp characters (and non-ASCII spaces) change what a person sees, not what the core compares: refused
const HIDDEN_RE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]/u;
const hexcp = (ch) => 'U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
// R5-02: a domain is ASCII (an international one is written in punycode, xn--...)
const domainOf = (s, kind) => (kind === 'domain' ? s : kind === 'addr' && s.includes('@') ? s.slice(s.lastIndexOf('@') + 1) : '');
function strs(x, name, E, kind) {
  if (x === undefined || x === null) return [];
  if (!Array.isArray(x) || x.length > 200) { E.push(name + ' must be a list of at most 200 strings.'); return []; }
  const out = [];
  for (const s of x) {
    if (typeof s !== 'string' || !s.trim() || s.length > 256) { E.push(name + ': every item must be a non-empty text of at most 256 characters.'); return []; }
    if (/[,\u0000-\u001f\u007f]/.test(s)) { E.push(name + ': "' + s.replace(/[\u0000-\u001f\u007f]/g, '?') + '" contains a comma or a control character, which this page cannot carry; remove it from the JSON.'); return []; }
    const hid = s.match(HIDDEN_RE);
    if (hid) { E.push(name + ': "' + s.replace(new RegExp(HIDDEN_RE.source, 'gu'), '?') + '" contains an invisible or direction-control character (' + hexcp(hid[0]) + '): what you would read is not what is signed. Remove it from the JSON.'); return []; }
    if (/[^\x00-\x7f]/.test(domainOf(s, kind))) { E.push(name + ': "' + s.replace(/[^\x00-\x7f]/g, '?') + '" is not ASCII. Write an international domain in punycode (xn--...).'); return []; }
    out.push(s.trim());
  }
  return out;
}
function only(o, keys, name, E) { for (const k of Object.keys(o)) if (!keys.includes(k)) E.push(name + ': unknown field "' + k.slice(0, 40) + '" (the server would ignore it, so it is refused here).'); }

// -> { errors: [text], form } ; `form` is what the page will send to /api/mandates/draft after the import (normalised: lower-case domains, an unspecified purchase = forbidden)
export function parseImport(text) {
  const E = [];
  if (typeof text !== 'string' || !text.trim()) return { errors: ['Paste the JSON printed by deus-witness-hook --print-form.'], form: null };
  if (text.length > MAX_IMPORT) return { errors: ['The text is too long for a mandate form (limit 64 KB).'], form: null };
  let j;
  try { j = JSON.parse(text); } catch (e) { return { errors: ['This is not valid JSON: ' + String(e.message).slice(0, 120)], form: null }; }
  if (isObj(j) && isObj(j.form) && !TOP.some((k) => k in j)) {
    const extra = Object.keys(j).filter((k) => k !== 'form');
    if (extra.length) return { errors: ['The {"form": ...} wrapper may hold only "form"; unknown field "' + extra[0].slice(0, 40) + '" (unknown fields are refused).'], form: null };
    j = j.form;
  }
  if (!isObj(j)) return { errors: ['The JSON must be an object (the form).'], form: null };
  only(j, TOP, 'form', E);
  const f = {};
  const cur = j.currency === undefined ? 'USD' : j.currency;
  if (cur !== 'USD') E.push('currency: only USD is supported on this page.');
  f.currency = 'USD';
  const days = j.valid_days === undefined ? 30 : j.valid_days;
  if (!isInt(days) || days < 1 || days > 365) E.push('valid_days must be a whole number from 1 to 365.');
  f.valid_days = days;
  const pu = j.purchase;
  if (pu === undefined || pu === null) f.purchase = { enabled: false };
  else if (!isObj(pu)) E.push('purchase must be an object or null.');
  else {
    only(pu, ['enabled', 'budget', 'max_per_action', 'min_per_action', 'payees'], 'purchase', E);
    if (pu.enabled !== undefined && typeof pu.enabled !== 'boolean') E.push('purchase.enabled must be true or false (a real JSON boolean, not a text).');
    else if (!pu.enabled) f.purchase = { enabled: false };
    else if (!isInt(pu.budget) || !isInt(pu.max_per_action) || pu.budget < 0 || pu.max_per_action < 0 || pu.budget > MAX_CENTS || pu.max_per_action > MAX_CENTS) E.push('purchase: budget and max_per_action are whole numbers of cents, at most ' + MAX_CENTS + '.');
    else if (pu.max_per_action > pu.budget) E.push('purchase: max_per_action cannot exceed the budget.');
    else if (pu.min_per_action !== undefined && pu.min_per_action !== null && (!isInt(pu.min_per_action) || pu.min_per_action < 0 || pu.min_per_action > pu.max_per_action)) E.push('purchase: min_per_action is a whole number of cents, at most max_per_action.');
    else if (pu.payees !== undefined && pu.payees !== null && (!Array.isArray(pu.payees) || pu.payees.some((x) => typeof x !== 'string' || !x || utf8Len(x) > 256) || pu.payees.length > 200 || new Set(pu.payees).size !== pu.payees.length)) E.push('purchase: payees is a list of distinct non-empty payee ids of at most 256 bytes (UTF-8) each, at most 200.');
    // 0.2.84 (R5-P5): the same refusals as the server form: no space at either end (it would be compared byte for byte), no invisible character
    else if (pu.payees && pu.payees.some((x) => x !== x.trim())) E.push('purchase: payee "' + pu.payees.find((x) => x !== x.trim()).trim().slice(0, 60) + '" has a space at the start or end; payee ids are compared byte for byte, remove the space.');
    else if (pu.payees && pu.payees.some((x) => HIDDEN_RE.test(x))) E.push('purchase: a payee id contains an invisible, line-break or direction-control character (' + hexcp(pu.payees.find((x) => HIDDEN_RE.test(x)).match(HIDDEN_RE)[0]) + '): what you would read is not what is signed.');
    else {
      f.purchase = { enabled: true, budget: pu.budget, max_per_action: pu.max_per_action };     // 0.2.83: min_per_action, payees (optional)
      if (pu.min_per_action) f.purchase.min_per_action = pu.min_per_action;
      if (pu.payees && pu.payees.length) f.purchase.payees = pu.payees;
    }
  }
  const ms = j.message;
  if (ms === undefined || ms === null) f.message = { domains: [], to: [] };
  else if (!isObj(ms)) E.push('message must be an object or null.');
  else { only(ms, ['domains', 'to'], 'message', E); f.message = { domains: strs(ms.domains, 'message.domains', E, 'domain').map((s) => s.toLowerCase()), to: strs(ms.to, 'message.to', E, 'addr').map((s) => s.toLowerCase()) }; }
  f.forbidden_data = [...new Set(strs(j.forbidden_data, 'forbidden_data', E))];
  const d = j.delete;
  if (d === undefined || d === null) f.delete = null;
  else if (!isObj(d)) E.push('delete must be an object or null.');
  else { only(d, ['targets', 'allow_irreversible'], 'delete', E); f.delete = { targets: strs(d.targets, 'delete.targets', E), allow_irreversible: d.allow_irreversible === true }; if (d.allow_irreversible !== undefined && typeof d.allow_irreversible !== 'boolean') E.push('delete.allow_irreversible must be true or false.'); }
  const p = j.publish;
  if (p === undefined || p === null) f.publish = null;
  else if (!isObj(p)) E.push('publish must be an object or null.');
  else { only(p, ['channels'], 'publish', E); f.publish = { channels: strs(p.channels, 'publish.channels', E) }; }
  // PROPOSAL-06: shell commands. absent/null = every command needs the owner; {allow, unlisted}
  const c = j.command;
  if (c === undefined || c === null) f.command = null;
  else if (!isObj(c)) E.push('command must be an object or null.');
  else {
    only(c, ['allow', 'unlisted', 'sandboxed'], 'command', E);
    f.command = { allow: strs(c.allow, 'command.allow', E) };
    if (c.unlisted !== undefined && c.unlisted !== null) {
      if (!UNLISTED.includes(c.unlisted)) E.push('command.unlisted must be "ask", "allow" or "deny".');
      else f.command.unlisted = c.unlisted;
    }
    if (c.sandboxed !== undefined && c.sandboxed !== null) {        // 0.2.56 (V3)
      if (!['ask', 'allow'].includes(c.sandboxed)) E.push('command.sandboxed must be "ask" or "allow".');
      else if (c.sandboxed === 'allow') f.command.sandboxed = 'allow';
    }
  }
  // PROPOSAL-08-http: HTTP requests of a sandbox. absent/null = every request needs the owner; {allow: [rules], unlisted: ask|deny}; the server
  // canonicalises each rule (lower-case host, upper-case method, no :443) and refuses what is not a rule; the signing page shows the canonical text
  const hp = j.http;
  if (hp === undefined || hp === null) f.http = null;
  else if (hp === false) f.http = false;
  else if (!isObj(hp)) E.push('http must be an object, false or null.');
  else {
    only(hp, ['allow', 'unlisted'], 'http', E);
    f.http = { allow: strs(hp.allow, 'http.allow', E) };
    for (const r of f.http.allow) if (!HTTP_RULE_RE.test(r)) { E.push('http.allow: "' + r.slice(0, 80) + '" is not a rule: METHOD host[:port]/path, e.g. GET api.github.com/repos/acme/app/**'); break; }
    if (hp.unlisted !== undefined && hp.unlisted !== null) {
      if (!['ask', 'deny'].includes(hp.unlisted)) E.push('http.unlisted must be "ask" or "deny".');
      else f.http.unlisted = hp.unlisted;
    }
  }
  return E.length ? { errors: E, form: null } : { errors: [], form: f };
}

// the mandate the server would build from `form` (same members as app/mandates.py), for describeMandate; only for display, never signed
export function previewMandate(form, agent, now) {
  const P = {};
  const pu = form.purchase;
  P.purchase = pu && pu.enabled ? { max_per_action: pu.max_per_action, budget: pu.budget } : false;
  if (P.purchase && pu.min_per_action) P.purchase.min_per_action = pu.min_per_action;     // 0.2.83 (as app/mandates.py)
  if (P.purchase && pu.payees && pu.payees.length) P.purchase.allowed_payees = pu.payees;
  const ms = form.message;
  P.message = ms && (ms.domains.length || ms.to.length) ? { domains: ms.domains, to: ms.to } : false;
  if (form.delete) P.delete = { targets: form.delete.targets, allow_irreversible: !!form.delete.allow_irreversible };
  if (form.publish) P.publish = { channels: form.publish.channels };
  if (form.command) {
    P.command = form.command.unlisted ? { allow: form.command.allow, unlisted: form.command.unlisted } : { allow: form.command.allow };
    if (form.command.sandboxed === 'allow') P.command.sandboxed = 'allow';
  }
  if (form.http === false) P.http = false;
  else if (form.http) P.http = form.http.unlisted === 'deny' ? { allow: form.http.allow, unlisted: 'deny' } : { allow: form.http.allow };
  return { v: 'deus-aar-0.1', agent, principal: 'your passkey', nbf: now, exp: now + form.valid_days * 86400, currency: form.currency, budget_window_s: 86400, permissions: P, forbidden_data: form.forbidden_data };
}

// -> { errors, form, values, rows } ; values = raw input values of the page form (setInputs), rows = [[label, text]] of what will be signed
export function importForm(text, agent, now) {
  const r = parseImport(text);
  if (!r.form) return { ...r, values: null, rows: [] };
  const m = previewMandate(r.form, agent, now);
  return { ...r, values: inputsFromMandate(m), rows: describeMandate(m).filter(([k]) => k !== 'Signing key') };
}

// 0.2.41: is there JSON in the Import field that the form does not hold? (typed/pasted and not applied, or changed after the last Apply). Pure, for the page and node tests.
export function pendingImport(text, appliedText) {
  const t = String(text == null ? '' : text).trim();
  return t !== '' && t !== (appliedText == null ? null : String(appliedText).trim());
}
