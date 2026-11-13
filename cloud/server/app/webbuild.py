"""0.2.75 (sandbox «живой человек», APPROVAL_SIG and N24): the site's modules are served under addresses that carry the build.

Until 27.10 the server sent js/*.js without Cache-Control and with the image's fixed Last-Modified, so a browser kept them by heuristic
freshness (weeks) and never asked again. The 27.10 headers (no-cache, content ETag) cannot reach what is already cached under the same
address: a fresh approve.js then ran with an old profile.js (a signature without the view -> 409 APPROVAL_SIG) or an old levels.js (a
module link error -> an empty approval page). Now every address a page loads names the build:

  - the build = the first 16 hex of the sha256 over (name, sha256 of the bytes) of every js/*.js and css/app.css;
  - a served page (*.html) gets `?v=<build>` on its <script src="js/..."> and <link href="css/app.css">;
  - a served module (js/*.js) gets `?v=<build>` on every `import ... from './x.js'` / `import('./x.js')`, and the text __DW_BUILD__ in it
    becomes the build (js/boot.js compares it with GET /api/build; js/api.js sends it as X-DW-Build).

So a page of build B loads only modules of build B, under addresses no older cache holds. The files on disk are not changed (the tests and
the reader read them as they are); what /api/witness publishes as web_js_sha256 is the sha256 of the bytes as SERVED.
"""
import hashlib
import os
import re

PLACEHOLDER = b"__DW_BUILD__"
_IMPORT = re.compile(rb"""((?:\bfrom|\bimport)\s*\(?\s*)(['"])(\./[A-Za-z0-9_]+\.js)\2""")
_PAGE = re.compile(rb"""(<(?:script|link)\b[^>]*?\b(?:src|href)=")((?:/|\.\./)*(?:js/[A-Za-z0-9_]+\.js|css/app\.css))(")""")
_BUILD = {}
_SERVED = {}


def _key(p):
    st = os.stat(p)
    return (p, st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino)   # ctime: a rewrite that keeps the old mtime still changes it


def build(web_dir) -> str:
    """-> the build of the site in web_dir ('' when it has no js/)."""
    d = os.path.join(web_dir, "js")
    if not os.path.isdir(d):
        return ""
    paths = [os.path.join(d, n) for n in sorted(os.listdir(d)) if n.endswith(".js") and os.path.isfile(os.path.join(d, n))]
    css = os.path.join(web_dir, "css", "app.css")
    if os.path.isfile(css):
        paths.append(css)
    sig = tuple(_key(p) for p in paths)
    hit = _BUILD.get(web_dir)
    if hit and hit[0] == sig:
        return hit[1]
    h = hashlib.sha256()
    for p in paths:
        with open(p, "rb") as f:
            h.update(os.path.relpath(p, web_dir).encode() + b"\0" + hashlib.sha256(f.read()).digest())
    b = h.hexdigest()[:16]
    _BUILD[web_dir] = (sig, b)
    return b


def rewritten(rel) -> bool:
    """Is the file at this site path served rewritten (a page or a module of js/)?"""
    return rel.endswith(".html") or (rel.startswith("js/") and rel.endswith(".js") and "/" not in rel[3:])


def rewrite(rel, data: bytes, b: str) -> bytes:
    if not b:
        return data
    v = b.encode()
    if rel.endswith(".js"):
        return _IMPORT.sub(lambda m: m.group(1) + m.group(2) + m.group(3) + b"?v=" + v + m.group(2), data).replace(PLACEHOLDER, v)
    return _PAGE.sub(lambda m: m.group(1) + m.group(2) + b"?v=" + v + m.group(3), data)


def served(web_dir, p, rel):
    """-> the bytes served for the file p (site path rel), or None: served as the file is."""
    if not rewritten(rel):
        return None
    b = build(web_dir)
    k = _key(p) + (b,)
    out = _SERVED.get(k)
    if out is None:
        with open(p, "rb") as f:
            out = rewrite(rel, f.read(), b)
        if len(_SERVED) > 1024:
            _SERVED.clear()
        _SERVED[k] = out
    return out
