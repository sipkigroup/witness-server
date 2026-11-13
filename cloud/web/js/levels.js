// 0.2.13: confirmation levels (laptop / phone), files a command executes that changed (PROPOSAL-08), Team delegation -- texts of the pages.
// Pure functions: approve.js, devices.js and team.js render them; test/levels.test.mjs checks them against the server's codes.

export const DEVICES = ['phone', 'laptop'];

// 0.2.23: what the page knows about the person's passkeys (GET /api/auth/keys, optional): is there a key that counts as "phone"?
// A key with no mark counts as phone (levels.py); a key waiting after a recovery code counts as this computer until then.
export function keySummary(keys) {
  if (!Array.isArray(keys)) return null;
  const act = keys.filter((k) => k && k.active !== false);
  if (!act.length) return null;
  const phone = act.filter((k) => !k.phone_not_before && (k.device === 'phone' || !k.device));
  return { n: act.length, phone: phone.length, onlyOne: act.length === 1 };
}

// N20 0.2.74 (series 10): a question about a secret (`cat .env`, `cat hl.txt` a hard link of .env, `ln .env x`, Read of a key) says so
// first, in one sentence, instead of the page opening on money, messages and deletions. -> the detail after "secrets:", or null
export function secretOf(r) {
  const a = r && r.action && typeof r.action === 'object' ? r.action : {};
  const rc = typeof a.recipient === 'string' ? a.recipient : '';
  if (rc.startsWith('secrets:')) return rc.slice('secrets:'.length) || 'a credential';
  if (r && typeof r.tool === 'string' && /\.secret$/.test(r.tool)) return rc || 'a credential file';
  return null;
}
export function secretLead(r) {
  const d = secretOf(r);
  if (d === null) return '';
  return 'An agent wants to read a secret: ' + d + '. What it reads, the agent sees, and a later call could carry it out.';
}

// what the approval page says about where this request may be confirmed
// (keys: optional, from keySummary; the logic of the levels is the server's, only the words depend on it)
export function levelView(confirm, keys, r) {
  if (!confirm || !confirm.level) return { show: false, text: '', cls: '' };
  const phone = confirm.level === 'phone';
  // r25 (s8 P2): a question that runs a file the agent wrote is not "an ordinary command": the page says what it runs
  const wrun = !!(r && r.written_run && Array.isArray(r.written_run.files) && r.written_run.files.length);
  let text, cls = phone ? 'warn' : 'ok';
  if (!phone) {
    text = 'May be confirmed with this computer\'s passkey (Touch ID / Windows Hello) or on your phone: '
      + (wrun ? 'it runs a file the agent wrote (read what was written, shown above).' : 'an ordinary command of the project.');
    if (wrun) cls = 'warn';
  } else if (keys && keys.onlyOne && keys.phone === 1) {
    cls = 'ok';
    // N20 0.2.74: a secret read is named as such (the page opened on "Money, messages and deletions" for `cat .env`)
    text = (secretOf(r) !== null ? 'Reading a secret is' : 'Money, messages and deletions are') + ' confirmed with your "phone" key. You have one passkey and it counts as that key, so there is nothing else to set up: press Approve and confirm with it.';
  } else if (keys && keys.phone >= 1) {
    cls = 'ok';
    text = 'This kind of request is confirmed with a passkey marked as your phone (the keys with no mark count as one). Use that passkey: the key of the computer the agent runs on is not accepted here, because the agent could be tricking that computer.';
  } else if (keys && keys.phone === 0) {
    text = 'This request needs a passkey marked as your phone, and every passkey you have is marked "this computer". Open Devices, add your phone\'s passkey (or mark one as phone), then come back. You can refuse it from any key.';
  } else {
    text = 'This kind of request is confirmed with your "phone" key. If you have one passkey it already counts as that key: just press Approve. A key marked "this computer" on Devices is not accepted here, because the agent could be tricking that computer.';
  }
  if (confirm.phone_for === 'all') text += ' Your rule: every approval on the phone.';
  const d = confirm.delegated;
  if (d) {
    text += d.you_run_this_agent
      ? ' You run this agent: another member of the team confirms its actions (you may refuse).'
      : ' This agent is run by another member; you confirm on their behalf.';
  }
  return { show: true, text, cls };
}

// the files that made a command a question
export function execView(ex) {
  if (!ex || !Array.isArray(ex.files) || !ex.files.length) return { show: false, head: '', files: [], note: '' };
  const root = typeof ex.root === 'string' ? ex.root.replace(/\/$/, '') + '/' : '';
  // 0.2.24 (critique V): the digest (first 12 hex of SHA-256) and size the hook reported, and the judged write that changed the file
  const det = {};
  if (Array.isArray(ex.details)) for (const d of ex.details) if (d && typeof d.file === 'string') det[d.file] = d;
  // r25 (s8 P6): a file the agent wrote through a judged call and that changed AGAIN after it (on disk, a shell write)
  const after = new Set(ex.risk && Array.isArray(ex.risk.files) ? ex.risk.files.filter((f) => f && f.after === true).map((f) => f.file) : []);
  const files = ex.files.slice(0, 64).map((f) => {
    const name = root && f.startsWith(root) ? f.slice(root.length) : f;
    const d = det[f];
    if (!d) return name;
    const bits = [];
    if (typeof d.sha256_12 === 'string' && /^[0-9a-f]{12}$/.test(d.sha256_12)) bits.push('sha256 ' + d.sha256_12);
    if (Number.isInteger(d.size)) bits.push(d.size + ' bytes');
    if (typeof d.written_by === 'string' && /^r_[A-Z0-9]{1,40}$/.test(d.written_by)) {
      bits.push((after.has(f) ? 'written by the agent (' + d.written_by + '), then changed outside a judged call' : 'written by the agent (' + d.written_by + ')'));
    }
    return bits.length ? name + ' (' + bits.join(', ') + ')' : name;
  });
  // s7 (polygon series 7, O2): what the witness saw of the change -- network lines it found, or "not sent: blind" (the server's view)
  const rk = ex.risk && typeof ex.risk === 'object' ? ex.risk : null;
  const risk = { dangerous: !!(rk && rk.dangerous === true), note: rk && typeof rk.note === 'string' ? rk.note : '', lines: [], previews: [] };
  if (rk && Array.isArray(rk.files)) for (const f of rk.files.slice(0, 64)) {
    if (!f || typeof f.file !== 'string') continue;
    const name = root && f.file.startsWith(root) ? f.file.slice(root.length) : f.file;
    // 0.2.43b: a hook that can sends the changed file's text (masked, <= 4 KB): shown instead of "blind"; still dangerous (not judged)
    if (f.blind === true && typeof f.preview === 'string') {
      risk.previews.push({ file: name, text: f.preview.slice(0, 4096), cut: f.preview_cut === true });
      risk.lines.push(name + (f.after === true ? ': changed after the agent\'s judged write, outside a judged call (on disk or by a shell write); its content now is shown below'
        : ': not written through a judged call; its content is shown below') + (f.preview_cut === true ? ' (first 4 KB)' : ''));
    } else if (f.blind === true) risk.lines.push(name + ': content not sent to the witness, you approve it blind');
    for (const l of (Array.isArray(f.lines) ? f.lines : []).slice(0, 5)) if (typeof l === 'string') risk.lines.push(name + ': ' + l);
  }
  return { show: true, head: 'Changed since you last confirmed (' + files.length + ' file' + (files.length > 1 ? 's' : '') + ' this command executes):', files, note: ex.note || '', risk };
}

// s7 (O1, O2): the "Dangerous command" row the person reads: the signed action's own value, or "true" with the reason the server found
export function dangerShown(action, r) {
  const a = action && typeof action === 'object' ? action : {};
  const ev = execView(r && r.exec_changed);
  if (a.dangerous !== true && ev.show && ev.risk.dangerous) return 'true (a file this command runs changed: ' + (ev.risk.lines.length ? 'network or unseen content, see below' : 'see below') + ')';
  if (r && r.written_run && Array.isArray(r.written_run.files) && r.written_run.files.length) return 'true (it runs a file the agent wrote: read what was written, shown above)';   // 28.10
  if (r && r.unseen_write && Array.isArray(r.unseen_write.paths) && r.unseen_write.paths.length) return 'true (it writes files whose text the witness cannot see' + (r.unseen_write.secret === true ? ', after the agent read a secret' : '') + ')';   // N4 29.10
  if (a.dangerous === true && r && typeof r.net_code === 'string') return 'true (code that talks to the network without showing where: read it below)';
  return a.dangerous == null ? null : String(a.dangerous);
}

// server error codes of 0.2.13 -> a sentence for the person
export const LEVEL_ERRORS = {
  DEVICE_LEVEL: 'This request needs the passkey you marked as your phone, and the one just used is marked "this computer". Confirm with your phone (open this page there), or see Devices: with a single passkey you can mark it as your phone.',
  SELF_APPROVAL: 'You run this agent, so you cannot confirm its actions: another member of the team confirms them. You can still refuse.',
  NOT_DELEGATE: 'Only the approvers the owner named for this agent can confirm it.',
  APPROVER_NONE: 'Nobody who may confirm this agent\'s actions is available: the action was blocked.',
  NOT_A_TEAM: 'Delegation needs an organisation with a signed team policy.',
  PHONE_PENDING: 'This passkey was declared your new phone with a recovery code and is still waiting (24 h): until then it cannot make new recovery codes, add or remove passkeys (nor can a passkey it confirmed).',   // 0.2.16, 0.2.17
};
export function levelError(e) {
  return e && e.code && LEVEL_ERRORS[e.code] ? LEVEL_ERRORS[e.code] : null;
}

// the devices page
export function deviceLabel(k) {
  if (!k) return '';
  if (k.phone_not_before) return 'New phone from a recovery code: counts as this computer until ' + new Date(k.phone_not_before * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';   // 0.2.15
  if (k.device === 'phone') return 'Phone';
  if (k.device === 'laptop') return 'This computer';
  return 'Not marked (counts as phone)';
}
export function deviceActions(k) {
  if (!k || !k.active) return [];
  const out = [];
  if (k.phone_not_before) return [{ cancel: true, label: 'This was not me - cancel' }];   // 0.2.15: the claim of a recovery code, cancelled by your phone
  if (k.device !== 'laptop') out.push({ device: 'laptop', label: 'Mark as computer' });
  if (k.device !== 'phone') out.push({ device: 'phone', label: 'Mark as phone' });
  return out;
}
