// 0.2.96 ("approved without reading", server app/uxstat.py): the pure parts, shared by approve.js (what the page reports with a
// decision) and app.js (the dashboard card); node tests run them (test/v1113.test.mjs).

// u = {t0: when the question was on screen, at: the first press of a decision button (0 = none yet), details: the person opened Details}
// -> {read_ms (null when the question time is unknown), details}
export function uxReport(u, nowMs) {
  const end = u.at || nowMs;
  return { read_ms: u.t0 ? Math.max(0, Math.min(3600000, Math.round(end - u.t0))) : null, details: !!u.details };
}

// the dashboard line: the three numbers side by side (a number alone would be a target; together they are a picture)
export function uxText(v) {
  if (!v || !v.decisions) return '';
  const pct = (x) => (typeof x === 'number' ? Math.round(x * 100) + '%' : 'n/a');
  const sec = typeof v.median_read_ms === 'number' ? (v.median_read_ms / 1000).toFixed(1) + ' s' : 'n/a';
  return v.decisions + ' decisions: ' + v.approvals + ' approved, ' + v.denials + ' refused. Typical time from the question to the button: ' + sec
    + '; under 2 s: ' + pct(v.fast_share) + '. Opened Details: ' + pct(v.details_share) + '. "From now on": ' + pct(v.forward_share) + ' of approvals.';
}
