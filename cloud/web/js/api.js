// fetch wrapper: JSON in, JSON out, errors as ApiError(code, detail, status).
export class ApiError extends Error {
  constructor(status, code, detail) {
    super(code + (detail ? ': ' + detail : ''));
    this.status = status; this.code = code; this.detail = detail || '';
  }
}

// R-17: sensitive changes need a passkey signature newer than 5 minutes; on STEPUP_REQUIRED ask for it once and retry.
async function stepUp() {
  const { getCredential } = await import('./webauthn.js');
  const b = await api('POST', '/api/auth/stepup/begin', {});
  const credential = await getCredential(b.options);
  await api('POST', '/api/auth/stepup/finish', { flow_id: b.flow_id, credential });
}

// 0.2.75: the build of this code (the server writes it in place of the placeholder). The server tells a page that does NOT send it (an older
// copy kept by the browser) to drop its cache (server main._stale_page).
export const BUILD = '__DW_BUILD__';
// r0288: the witness' status page (js/boot.js keeps what GET /api/build said; none = no link). Only a plain https URL is ever shown.
export function statusHint() {
  let u = null;
  try { u = localStorage.getItem('dw_status_url'); } catch (e) { u = null; }
  return u && /^https:\/\/[A-Za-z0-9.-]+(:[0-9]{1,5})?(\/[A-Za-z0-9._~\/-]*)?$/.test(u) ? '. Status of the witness: ' + u : '';
}
export async function api(method, path, body, retried) {
  const opt = { method, credentials: 'same-origin', headers: { 'x-dw-build': BUILD } };
  if (body !== undefined) { opt.headers['content-type'] = 'application/json'; opt.body = JSON.stringify(body); }
  let r;
  try { r = await fetch(path, opt); } catch (e) { throw new ApiError(0, 'NETWORK', 'Cannot reach the server' + statusHint()); }
  if (r.status === 204) return null;
  let j = null;
  try { j = await r.json(); } catch (e) { /* not JSON */ }
  if (r.status === 403 && j && j.error === 'STEPUP_REQUIRED' && !retried) { await stepUp(); return api(method, path, body, true); }
  if (!r.ok) throw new ApiError(r.status, (j && j.error) || 'HTTP_' + r.status, ((j && j.detail) || '') + (!j && r.status >= 502 && r.status <= 504 ? statusHint() : ''));
  return j;
}
export const get = (p) => api('GET', p);
export const post = (p, b) => api('POST', p, b === undefined ? {} : b);
export const put = (p, b) => api('PUT', p, b);
export const del = (p) => api('DELETE', p);
