// 0.2.96 ("approved without reading", server app/uxstat.py): the pure parts, shared by approve.js (what the page reports with a
// decision) and app.js (the dashboard card); node tests run them (test/v1113.test.mjs).

// u = {t0: when the question was on screen, at: the first press of a decision button (0 = none yet), details: the person opened Details}
// -> {read_ms (null when the question time is unknown), details}
export function uxReport(u, nowMs) {
  const end = u.at || nowMs;
  return { read_ms: u.t0 ? Math.max(0, Math.min(3600000, Math.round(end - u.t0))) : null, details: !!u.details };
}

// the dashboard line: the three numbers side by side (a number alone would be a target; together they are a picture)
export const UX_TIME_N = 5;      // r0283: below it a median time is one or two cases, not "typical"
export const UX_MIN_N = 10;      // = server uxstat.MIN_N: below it a share is noise (r0281, blind evaluation B9: "50%" of 2 decisions)
export function uxText(v) {
  if (!v || !v.decisions) return '';
  if (v.decisions < UX_MIN_N) {
    // r0283 (third blind evaluation #32 Н-8): a "typical" time of one decision is not typical: shown from UX_TIME_N decisions on; no note
    // about shares that are not there
    const head = v.decisions + (v.decisions === 1 ? ' decision' : ' decisions') + ': ' + v.approvals + ' approved, ' + v.denials + ' refused';
    if (v.decisions < UX_TIME_N || typeof v.median_read_ms !== 'number') return head + '.';
    return head + '; typical time from the question to the button ' + (v.median_read_ms / 1000).toFixed(1) + ' s.';
  }
  const pct = (x) => (typeof x === 'number' ? Math.round(x * 100) + '%' : 'n/a');
  const sec = typeof v.median_read_ms === 'number' ? (v.median_read_ms / 1000).toFixed(1) + ' s' : 'n/a';
  return v.decisions + ' decisions: ' + v.approvals + ' approved, ' + v.denials + ' refused. Typical time from the question to the button: ' + sec
    + '; under 2 s: ' + pct(v.fast_share) + '. Opened Details: ' + pct(v.details_share) + '. "From now on": ' + pct(v.forward_share) + ' of approvals.';
}
