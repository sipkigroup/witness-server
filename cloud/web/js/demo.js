// P0-2: the /demo page (no login). Renders the decision feed of the scripted attacks, runs the in-browser pack checker on the
// DEMO pack, and a tamper button that flips one byte of the ledger in memory to show the checker saying INVALID.
import { checkPack, crossCheck } from './packcheck.js';

const $ = (s) => document.querySelector(s);
const BASE = '/demo/';
const PACK = BASE + 'pack/';
const HARM = {
  C1: 'Without Deus Witness: the home address and phone go to a stranger (2 emails).',
  C2: 'Without Deus Witness: the production database is gone.',
  C3: 'Without Deus Witness: 300 USD spent against a 200 USD budget.',
  C4: 'Without Deus Witness: works. With it: works too (no false alarm).',
  C5: 'Without Deus Witness: published without the owner.',
};
const PILL = { allow: 'allow', deny: 'deny', defer: 'defer', approve: 'allow' };

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) if (k === 'class') e.className = v; else e.setAttribute(k, v);
  for (const k of kids) e.append(k);
  return e;
}

function argsText(a) {
  if (!a) return '';
  return Object.entries(a).map(([k, v]) => k + ': ' + (typeof v === 'string' ? v : JSON.stringify(v))).join('\n');
}

export function renderFeed(items, box) {
  box.replaceChildren();
  let cur = null, list = null;
  items.forEach((it, i) => {
    if (it.scenario !== cur) {
      cur = it.scenario;
      list = el('ol', { class: 'steps' });
      box.append(el('h3', {}, it.scenario + '. ' + it.title), el('p', { class: 'hint' }, HARM[cur] || ''), list);
    }
    const head = el('p', {}, el('span', { class: 'pill ' + (PILL[it.verdict] || 'esc') }, it.verdict), ' ',
      el('strong', {}, it.actor === 'owner' ? 'Owner' : (it.tool || '')), ' ', it.reason ? el('code', {}, it.reason) : '');
    const li = el('li', { 'data-i': String(i) }, head, el('p', { class: 'hint' }, it.what || ''));
    if (it.args) li.append(el('pre', {}, argsText(it.args)));
    li.append(el('p', { class: 'hint ledger' }, 'receipt ' + (it.rid || '-') + ' · not checked yet'));
    list.append(li);
  });
}

function markFeed(checked) {
  checked.forEach((it, i) => {
    const p = document.querySelector('li[data-i="' + i + '"] .ledger');
    if (!p) return;
    const what = it.actor === 'owner' ? 'APPROVAL entry (approved: true)'
      : 'RECEIPT ' + it.ledgerVerdict + ' ' + it.ledgerReason + (it.consumed ? '; CONSUME (the tool ran once)' : '');
    p.textContent = 'receipt ' + it.rid + ' · ' + (it.inLedger ? 'matches the signed ledger: ' + what : 'NOT matched by the signed ledger');
    p.className = 'hint ledger ' + (it.inLedger ? 'ok' : 'bad');
  });
}

async function getBytes(path) {
  const r = await fetch(path, { cache: 'no-store' });
  if (!r.ok) throw new Error(path + ': HTTP ' + r.status);
  return new Uint8Array(await r.arrayBuffer());
}

async function run(feed, tamper) {
  $('#run').disabled = $('#tamper').disabled = true;
  const out = $('#out');
  out.hidden = false;
  out.textContent = 'checking...';
  const read = async (p) => {
    const b = await getBytes(PACK + p);
    if (tamper && p === 'ledger/ledger.cose') {            // one hex digit of the 4th entry's signature changes
      const rows = new TextDecoder().decode(b).split('\n');
      const r = rows[3];
      rows[3] = r.slice(0, -2) + (r.at(-2) === '0' ? '1' : '0') + r.at(-1);
      return new TextEncoder().encode(rows.join('\n'));
    }
    return b;
  };
  try {
    const r = await checkPack(read);
    out.textContent = (tamper ? '(ledger/ledger.cose changed in memory: one hex digit of entry 3)\n' : '') + r.lines.join('\n');
    const v = $('#verdict');
    v.hidden = false;
    v.className = 'notice ' + (r.ok ? 'ok' : 'err');
    v.textContent = r.ok ? 'VALID: the pack is intact and every entry is signed by the (DEMO) witness key.' : 'INVALID: the checker found what changed. A real pack with one changed byte is rejected the same way.';
    if (r.ok && feed) markFeed(crossCheck(feed.items, r.entries));
  } catch (e) {
    out.textContent = 'The check could not run: ' + e.message;
  }
  $('#run').disabled = $('#tamper').disabled = false;
}

async function main() {
  const origin = location.origin;
  $('#cmd').textContent = $('#cmd').textContent.replace('https://witness.sipkigroup.com', origin);
  let feed = null;
  try {
    feed = JSON.parse(new TextDecoder().decode(await getBytes(BASE + 'feed.json')));
    renderFeed(feed.items, $('#feed'));
    $('#feednote').textContent = feed.items.length + ' calls of a scripted (compromised) agent and one owner approval, through the real witness server. '
      + 'This list is not signed; run the check below to match every line against the signed ledger.';
  } catch (e) { $('#feednote').textContent = 'The decision feed could not be loaded (' + e.message + ').'; }
  try {
    const meta = JSON.parse(new TextDecoder().decode(await getBytes(BASE + 'demo.json')));
    $('#zipsha').textContent = meta.zip_sha256;
    $('#nfiles').textContent = String(meta.files - 2) + ' files';
  } catch (e) { /* the page still works */ }
  $('#run').addEventListener('click', () => run(feed, false));
  $('#tamper').addEventListener('click', () => run(null, true));
}

if (typeof document !== 'undefined' && document.getElementById('feed')) main();
