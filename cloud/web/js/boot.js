// 0.2.75 (sandbox «живой человек», APPROVAL_SIG and N24): is the code this page runs ONE build, the server's?
// The server serves every page and module with ?v=<build> in its address (server app/webbuild.py) and writes the build into this file in
// place of __DW_BUILD__. This module is its own module graph (a separate <script> on every page, no imports), so it runs even when the
// page's main module fails to link (an old module without an export the new one imports: "Importing binding name ... is not found").
// The page is reloaded ONCE (per server build, per tab) when:
//   - this module was loaded without the build in its address (the page itself is an old copy from the browser's cache),
//   - the server's build is another one (an update since this page was loaded), or
//   - a module of this page failed to link or load.
// Before that reload the browser is told to drop its HTTP cache of this site (GET /api/build?clear=1 -> Clear-Site-Data) and the page's
// own address is fetched again, so the reload loads fresh files. A second mismatch in the same tab does not reload again: it says what to do.
const MINE = '__DW_BUILD__';
const KEY = 'dw_build_reload';
const STALE_TEXT = 'This page could not load its current version: your browser keeps an outdated copy of it. Close this tab and open the link again '
  + '(on a computer you can also hold Shift and press Reload). Nothing was approved or changed by this page.';

export function decide(mine, inUrl, server, reloadedFor, linkError) {
  // -> 'ok' | 'reload' | 'tell'
  if (!mine || mine.startsWith('__')) return 'ok';                // not served by the witness server (a test, a file): nothing to compare
  const stale = !!linkError || inUrl !== mine || !!(server && server !== mine);
  if (!stale) return 'ok';
  return reloadedFor === (server || mine) ? 'tell' : 'reload';
}

function tell() {
  if (document.getElementById('dw-stale')) return;
  const d = document.createElement('div');
  d.id = 'dw-stale'; d.className = 'notice err'; d.setAttribute('role', 'alert'); d.textContent = STALE_TEXT;
  const at = document.querySelector('main') || document.body;
  at.prepend(d);
}

let busy = false;
async function check(server, linkError) {
  if (busy) return; busy = true;
  let inUrl = null;
  try { inUrl = new URL(import.meta.url).searchParams.get('v'); } catch (e) { inUrl = null; }
  let done = null;
  try { done = sessionStorage.getItem(KEY); } catch (e) { done = 'no-storage'; }      // cannot remember -> never reload (no loop)
  const what = decide(MINE, inUrl, server, done, linkError);
  if (what === 'ok') { busy = false; return; }
  if (what === 'tell' || done === 'no-storage') { tell(); return; }
  try { sessionStorage.setItem(KEY, server || MINE); } catch (e) { tell(); return; }
  try { await fetch('/api/build?clear=1', { cache: 'no-store', credentials: 'same-origin', headers: { 'x-dw-build': MINE } }); } catch (e) { /* offline */ }
  try { await fetch(location.href, { cache: 'reload', credentials: 'same-origin' }); } catch (e) { /* offline */ }
  location.reload();
}

async function serverBuild() {
  try {
    const r = await fetch('/api/build', { cache: 'no-store', credentials: 'same-origin', headers: { 'x-dw-build': MINE } });
    if (!r.ok) return null;
    const j = await r.json();
    // r0288: the status page of this witness (DW_STATUS_URL, kept off this server): remembered for the day this server does not answer
    try {
      if (typeof j.status_url === 'string' && /^https:\/\/[A-Za-z0-9.-]+(:[0-9]{1,5})?(\/[A-Za-z0-9._~\/-]*)?$/.test(j.status_url)) localStorage.setItem('dw_status_url', j.status_url);
      else localStorage.removeItem('dw_status_url');
    } catch (e) { /* no storage: no link */ }
    return j.build || null;
  } catch (e) { return null; }
}

if (typeof window !== 'undefined' && typeof document !== 'undefined' && !MINE.startsWith('__')) {
  // a module of this page that does not link (an export it imports is missing) or does not load: an old copy took part
  window.addEventListener('error', (ev) => {
    const m = String((ev && (ev.message || (ev.error && ev.error.message))) || '');
    const t = ev && ev.target;
    if (/binding name|does not provide an export named|Importing binding|import(ed)? .*not found/i.test(m)
      || (t && t.tagName === 'SCRIPT' && t.type === 'module')) serverBuild().then((s) => check(s, true));
  }, true);
  serverBuild().then((s) => check(s, false));
}
