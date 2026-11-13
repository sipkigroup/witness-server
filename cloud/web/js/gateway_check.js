import { encode, bytesToHex } from './cde.js';
import { sha256 } from './profile.js';

// 0.2.5 (R4-05): the tool map document the mandate's `toolmap_sha256` binds. The hash must be the hash of the document shown; classes that differ from the
// document of the mandate in force are listed first (a map edited by one owner must not reach the quorum unseen).
export async function gatewayCheck(sr) {
  const b = sr.body || {};
  const claimed = b.toolmap_sha256;
  if (claimed === undefined) return { ok: true, rows: [] };           // a request of the 0.2.0-0.2.3 form: nothing bound
  const doc = sr.meta && sr.meta.gateway;
  if (!doc || typeof doc !== 'object') return { ok: false, why: 'The request carries no tool map document for the hash it signs.' };
  if (bytesToHex(await sha256(encode(doc))) !== claimed) return { ok: false, why: 'The tool map hash in the mandate is not the hash of the tool map shown.' };
  const prev = sr.meta && sr.meta.gateway_prev;
  const rows = [];
  const tools = (doc.tools && doc.tools.tools) || {};
  const ptools = prev && prev.tools && prev.tools.tools;
  for (const name of Object.keys(tools).sort()) {
    const now = tools[name] && tools[name].class;
    const was = ptools && ptools[name] && ptools[name].class;
    const changed = prev ? was !== now : false;
    rows.push([(changed ? 'CHANGED ' : '') + 'tool ' + name, now + (changed ? ' (was ' + (was || 'not mapped') + ')' : '') + (JSON.stringify(tools[name]) === JSON.stringify(ptools && ptools[name]) ? '' : ' ' + JSON.stringify(tools[name])), changed]);
  }
  if (ptools) for (const name of Object.keys(ptools).sort()) if (!(name in tools)) rows.push(['CHANGED tool ' + name, 'removed (was ' + ptools[name].class + ')', true]);
  rows.push(['Default for unmapped tools', String(doc.tools && doc.tools.default) + (prev && prev.tools && prev.tools.default !== doc.tools.default ? ' (was ' + prev.tools.default + ')' : ''), !!(prev && prev.tools && prev.tools.default !== doc.tools.default)]);
  rows.push(['Protected literals', (doc.patterns || []).length + ' (values are not shown)' + (prev && (prev.patterns || []).length !== (doc.patterns || []).length ? ' (was ' + (prev.patterns || []).length + ')' : ''), !!(prev && (prev.patterns || []).length !== (doc.patterns || []).length)]);
  rows.push(['Advisor mode', String(doc.advisor) + (prev && prev.advisor !== doc.advisor ? ' (was ' + prev.advisor + ')' : ''), !!(prev && prev.advisor !== doc.advisor)]);
  return { ok: true, rows, hasPrev: !!prev };
}
