// Honest approval screen helpers (pure, no DOM): make invisible / bidi characters visible and flag look-alike text.
// This is a heuristic aid, not a guarantee: a clean result does NOT prove an address or domain is genuine.

const HIDDEN = [
  [0x00AD, 0x00AD, 'SOFT HYPHEN'], [0x034F, 0x034F, 'COMBINING GRAPHEME JOINER'], [0x061C, 0x061C, 'ARABIC LETTER MARK'],
  [0x115F, 0x1160, 'HANGUL FILLER'], [0x17B4, 0x17B5, 'KHMER INHERENT VOWEL'], [0x180B, 0x180E, 'MONGOLIAN FREE VARIATION/VOWEL SEPARATOR'],
  [0x200B, 0x200B, 'ZERO WIDTH SPACE'], [0x200C, 0x200C, 'ZERO WIDTH NON-JOINER'], [0x200D, 0x200D, 'ZERO WIDTH JOINER'],
  [0x200E, 0x200F, 'DIRECTIONAL MARK'], [0x202A, 0x202E, 'BIDI EMBEDDING/OVERRIDE'], [0x2060, 0x2064, 'WORD JOINER / INVISIBLE OPERATOR'],
  [0x2066, 0x2069, 'BIDI ISOLATE'], [0x206A, 0x206F, 'DEPRECATED FORMAT'], [0x3164, 0x3164, 'HANGUL FILLER'], [0xFEFF, 0xFEFF, 'ZERO WIDTH NO-BREAK SPACE'],
  [0xFFA0, 0xFFA0, 'HALFWIDTH HANGUL FILLER'], [0xFFF9, 0xFFFB, 'INTERLINEAR ANNOTATION'], [0xE0000, 0xE007F, 'TAG CHARACTER'], [0xE0100, 0xE01EF, 'VARIATION SELECTOR SUPPLEMENT'],
  [0x00A0, 0x00A0, 'NO-BREAK SPACE'], [0x1680, 0x1680, 'OGHAM SPACE MARK'], [0x2000, 0x200A, 'SPACE VARIANT'], [0x2028, 0x2029, 'LINE/PARAGRAPH SEPARATOR'],
  [0x202F, 0x202F, 'NARROW NO-BREAK SPACE'], [0x205F, 0x205F, 'MEDIUM MATHEMATICAL SPACE'], [0x3000, 0x3000, 'IDEOGRAPHIC SPACE'],
];
export const BIDI = new Set([0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C]);

export function hiddenName(cp, keepNewlines) {
  if (keepNewlines && (cp === 0x0A || cp === 0x09 || cp === 0x0D)) return null;
  if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) return 'CONTROL CHARACTER';
  for (const [a, b, n] of HIDDEN) if (cp >= a && cp <= b) return n;
  return null;
}
const u = (cp) => '<U+' + cp.toString(16).toUpperCase().padStart(4, '0') + '>';

// Replace every hidden / control / bidi / odd-space character by <U+XXXX>. Returns {text, found:[{cp,tag,name,bidi}]}.
export function reveal(s, keepNewlines = false) {
  const found = []; let out = '';
  for (const ch of String(s == null ? '' : s)) {
    const cp = ch.codePointAt(0), n = hiddenName(cp, keepNewlines);
    if (n) { out += u(cp); found.push({ cp, tag: u(cp), name: n, bidi: BIDI.has(cp) }); } else out += ch;
  }
  return { text: out, found };
}

const SCRIPTS = ['Latin', 'Cyrillic', 'Greek', 'Armenian', 'Hebrew', 'Arabic', 'Devanagari', 'Thai', 'Han', 'Hiragana', 'Katakana', 'Hangul', 'Georgian', 'Cherokee'];
const SRE = SCRIPTS.map((n) => [n, new RegExp('^\\p{Script=' + n + '}$', 'u')]);
export function scriptOf(ch) { for (const [n, re] of SRE) if (re.test(ch)) return n; return /^\p{L}$/u.test(ch) ? 'Other' : null; }

// frequent look-alikes of ASCII letters (not exhaustive): non-Latin char -> the ASCII letter it imitates
const CONF = {};
const add = (from, to) => { for (let i = 0; i < from.length; i++) CONF[from[i]] = to[i]; };
add('аеорсухіјѕԁһԛԝѵ', 'aeopcyxijsdhqwv');           // Cyrillic small
add('АВЕКМНОРСТХУЅІЈ', 'ABEKMHOPCTXYSIJ');          // Cyrillic capital
add('αεορυνικτχωβ', 'aeopuvikt' + 'xwb');           // Greek small (alpha, epsilon, omicron, rho, upsilon, nu, iota, kappa, tau, chi, omega, beta)
add('ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ', 'ABEZHIKMNOPTYX');           // Greek capital
add('օսցԱ', 'ousA');                                // Armenian
add('ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ', 'abcdefghijklmnopqrstuvwxyz'); // fullwidth
add('ⅰⅼ', 'il');
export function lookalike(ch) { return CONF[ch] || null; }

const lbl = (cp) => 'U+' + cp.toString(16).toUpperCase().padStart(4, '0');
// Split into word tokens at anything that is not a letter, mark or digit (so "a.b@c-d" gives a, b, c, d).
function tokens(s) { return String(s).split(/[^\p{L}\p{M}\p{N}]+/u).filter(Boolean); }

// Analyse one visible string (an address, a domain, a URL, a field value).
// Returns {warnings:[string], mixed:[{token,scripts}], confusables:[{ch,cp,like,script}], punycode:bool, nonAscii:bool}
export function analyze(s) {
  const str = String(s == null ? '' : s), warnings = [], mixed = [], confusables = [];
  let nonAscii = false;
  for (const tk of tokens(str)) {
    const sc = new Set();
    for (const ch of tk) { const x = scriptOf(ch); if (x) sc.add(x); }
    // digits and marks are script-neutral; ASCII letters count as Latin
    if (sc.size > 1) mixed.push({ token: tk, scripts: [...sc] });
  }
  for (const ch of str) {
    const cp = ch.codePointAt(0);
    if (cp > 0x7F) nonAscii = true;
    const like = lookalike(ch);
    if (like) confusables.push({ ch, cp: lbl(cp), like, script: scriptOf(ch) });
  }
  const punycode = /(^|[.@/])xn--/i.test(str);
  for (const m of mixed) warnings.push('"' + m.token + '" mixes ' + m.scripts.join(' + ') + ' letters: a classic look-alike trick.');
  if (confusables.length) {
    const seen = new Set(), list = [];
    for (const c of confusables) { const k = c.cp; if (!seen.has(k)) { seen.add(k); list.push(c.script + ' "' + c.ch + '" (' + c.cp + ') looks like Latin "' + c.like + '"'); } }
    warnings.push('Letters that imitate Latin ones: ' + list.slice(0, 6).join('; ') + (list.length > 6 ? '; ...' : '') + '.');
  }
  if (punycode) warnings.push('Punycode label (xn--): the browser would show it as other-script letters. Compare it with the real address.');
  return { warnings, mixed, confusables, punycode, nonAscii };
}

// Pull address/domain-like words out of free text (agent-written messages): user@host, host.tld, URLs.
export function addressLike(text) {
  const out = []; const re = /[^\s<>"'()\[\]{},;]*[@.][^\s<>"'()\[\]{},;]*/gu;
  for (const m of String(text).matchAll(re)) { const t = m[0].replace(/[.:!?]+$/, ''); if (/[\p{L}]/u.test(t) && t.length > 3) out.push(t); }
  return out;
}

// Full report for the approval screen. fields: [[label, value]] checked as whole values; texts: [[label, text]] checked for hidden
// characters and for address-like words only. Returns {rows:[[label, shownText]], warnings:[string], hidden:int, bidi:bool}
export function inspectFields(fields, texts = []) {
  const rows = [], warnings = []; let hidden = 0, bidi = false;
  const note = (label, found) => {
    if (!found.length) return;
    hidden += found.length; if (found.some((f) => f.bidi)) bidi = true;
    const names = [...new Set(found.map((f) => f.tag + ' ' + f.name))].slice(0, 5).join(', ');
    warnings.push((found.some((f) => f.bidi) ? 'Text direction can be disguised in "' + label + '". ' : '') + 'Hidden characters in "' + label + '" (' + found.length + '), shown as <U+XXXX>: ' + names + '.');
  };
  for (const [label, v] of fields) {
    const r = reveal(v); rows.push([label, r.text]); note(label, r.found);
    for (const w of analyze(r.text.replace(/<U\+[0-9A-F]+>/g, ' ')).warnings) warnings.push(label + ': ' + w);
  }
  for (const [label, t] of texts) {
    const r = reveal(t, true); rows.push([label, r.text]); note(label, r.found);
    const seen = new Set();
    for (const a of addressLike(r.text.replace(/<U\+[0-9A-F]+>/g, ' '))) for (const w of analyze(a).warnings) { const k = a + w; if (!seen.has(k) && seen.size < 6) { seen.add(k); warnings.push(label + ': in "' + a + '": ' + w); } }
  }
  return { rows, warnings, hidden, bidi };
}
