"""Deus Witness Cloud server. Run: python -m app.main --port 8810   (env: see app/config.py and RUN.md)"""
import hashlib
import json
import mimetypes
import os
import sys
import time

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, FileResponse
from svidetel_v4 import cose

from app import _paths
from app.config import Config, ConfigError
from app.context import Ctx, Err
from app.db import NeedsMigration
from app.hub import ACC_RE, DataDirBusy, KeyFileError
from app.log import log
from app import api_agent, api_web, erase, notify, push

MAX_BODY = 256 * 1024        # R-04


class BodyLimit:
    """Pure ASGI middleware: Content-Length above the limit -> 413 at once; a body that grows past it while streaming (chunked) -> 413."""

    def __init__(self, app, limit=MAX_BODY):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        cl = dict(scope["headers"]).get(b"content-length")
        too_big = Err(413, "BODY_TOO_LARGE", "request body limit is %d KB" % (self.limit // 1024))
        if cl is not None:
            try:
                if int(cl) > self.limit:
                    return await _send_err(send, too_big)
            except ValueError:
                return await _send_err(send, Err(400, "BAD_REQUEST", "bad Content-Length"))
        total = 0
        over = []

        async def limited():
            nonlocal total
            m = await receive()
            if m["type"] == "http.request":
                total += len(m.get("body", b""))
                if total > self.limit:
                    over.append(1)                # stop feeding the application; its answer is replaced by 413 below
                    return {"type": "http.request", "body": b"", "more_body": False}
            return m
        sent = []

        async def watch(m):
            if over:
                if not sent:
                    sent.append(1)
                    await _send_err(send, too_big)
                return
            await send(m)
        await self.app(scope, limited, watch)


MAX_INFLIGHT = 256            # 0.2.18 (DW_MAX_INFLIGHT): ~1 s of queue at the measured ceiling; 64 sheds honest calls at 300 bots (OTCHET-0.2.18.md)
THREADS = 8                   # 0.2.18 (DW_THREADS): worker threads of the handlers (anyio default 40); fewer = less GIL convoy (measured)


PER_KEY_INFLIGHT = 8          # 0.2.18: requests of one Bearer key in progress at once (a burst never fills the server)
# r0285 (NAGRUZKA-I-EKONOMIKA-1311 p.1): Claude Code runs up to 10 tool calls of one agent at once (CLAUDE_CODE_MAX_TOOL_USE_CONCURRENCY,
# default 10) and its subagents share the key: 10 hooks at once got 3 x 429 and the hook said "cannot be reached". A request of a key that
# has PER_KEY_INFLIGHT in progress now WAITS for a slot (on the event loop: no worker thread, not counted in the global limit), at most
# PER_KEY_QUEUE of one key and at most PER_KEY_WAIT_S; beyond -> 429 at once, as before. The work one key may hold stays PER_KEY_INFLIGHT.
PER_KEY_QUEUE = 40
PER_KEY_WAIT_S = 2.0


POLL_PER_KEY = 8              # 2710rt: long polls (GET /v1/actions/{rid}?wait=N, N>0) of one key open at once; beyond -> answered at once as wait=0


def wait_seconds(qs):
    """2710rt: the value of the query parameter `wait` (exact name; the last one wins like Starlette's QueryParams) as a positive int, else 0."""
    from urllib.parse import parse_qsl
    try:
        v = [x for k, x in parse_qsl(qs.decode("latin-1"), keep_blank_values=True) if k == "wait"]
        return max(0, int(v[-1])) if v else 0
    except (ValueError, UnicodeError):
        return 0


def is_long_poll(scope):
    p = scope.get("path", "")
    return scope.get("method") == "GET" and p.startswith("/v1/actions/") and p.count("/") == 3 and wait_seconds(scope.get("query_string", b"")) > 0


class DropWatch:
    """2710u (polygon series 2, proposal 3): pure ASGI middleware for the long poll GET /v1/actions/{rid}?wait=N only. It reads the (empty)
    request itself, then watches the connection while the endpoint waits: a client that goes away (http.disconnect before the answer)
    sets scope["dw_dropped"] (an anyio.Event) that the endpoint checks between its 0.25 s steps. Starlette's Request.is_disconnected()
    does not see it through the BaseHTTPMiddleware of headers_and_log (measured: real uvicorn socket, 27.10)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        p = scope.get("path", "") if scope["type"] == "http" else ""
        if scope["type"] != "http" or scope.get("method") != "GET" or not p.startswith("/v1/actions/") or p.count("/") != 3 \
                or wait_seconds(scope.get("query_string", b"")) <= 0:
            return await self.app(scope, receive, send)
        import anyio
        first = []
        while True:                                   # a GET: one empty http.request (a huge body is not a long poll: passed on as is)
            m = await receive()
            first.append(m)
            if m["type"] != "http.request" or not m.get("more_body") or len(first) > 4:
                break
        dropped = anyio.Event()
        scope["dw_dropped"] = dropped
        done = []

        async def replay():
            if first:
                return first.pop(0)
            await dropped.wait()
            return {"type": "http.disconnect"}

        async def sent(m):
            if m["type"] == "http.response.start":
                done.append(1)
            await send(m)

        async with anyio.create_task_group() as tg:
            async def watch():
                if first and first[-1]["type"] == "http.disconnect":
                    dropped.set()
                    return
                while True:
                    m = await receive()
                    if m["type"] == "http.disconnect":
                        if not done:
                            dropped.set()
                        return

            tg.start_soon(watch)
            try:
                await self.app(scope, replay, sent)
            finally:
                tg.cancel_scope.cancel()


class Shed:
    """0.2.18: overload protection BEFORE any work. More than `limit` requests in progress -> 503 OVERLOADED with Retry-After at once, instead
    of a queue of tens of seconds behind the worker threads (OTCHET-NAGRUZKA-2026-10-20: p95 8-25 s, then dropped connections). Not
    shed: /healthz and the steps of an action already decided (/v1/actions/{rid}: GET, present, report): shedding them would waste the
    judge's work and the hook answers deny on any error; they count toward the limit, so new work (judge, POST /v1/actions, the web API) is
    shed first. The long poll GET ...?wait=N is not counted at all (it sleeps on the event loop, holds no worker thread).
    One agent key may have at most `per_key` requests in progress (not counted in the global limit): a burst of one key cannot push the
    other tenants into 503. r0285: beyond it a request waits for a slot of its key (at most `per_key_queue` of one key, at most
    `per_key_wait` s, first come first served), then 429 RATE_LIMIT; the waiting ones hold no worker thread."""

    def __init__(self, app, limit=MAX_INFLIGHT, retry_after=1, per_key=PER_KEY_INFLIGHT, poll_per_key=POLL_PER_KEY,
                 per_key_queue=PER_KEY_QUEUE, per_key_wait=PER_KEY_WAIT_S):
        self.app, self.limit, self.retry_after, self.per_key = app, limit, retry_after, per_key
        self.poll_per_key = poll_per_key
        self.per_key_queue, self.per_key_wait = per_key_queue, per_key_wait
        self.polls = {}                 # 2710rt: key hash -> long polls open now
        self.n = 0
        self.shed = 0
        self.keys = {}
        self.waiters = {}               # r0285: key hash -> deque of futures waiting for a slot of that key
        self.key_refused = 0            # r0285: 429s of the per-key bound (a burst that did not fit the queue either)

    async def _key_slot(self, k) -> bool:
        """r0285: take a slot of key `k` (True), waiting for one when the key has `per_key` in progress; False = 429."""
        if self.keys.get(k, 0) < self.per_key and not self.waiters.get(k):
            self.keys[k] = self.keys.get(k, 0) + 1
            return True
        import asyncio
        from collections import deque
        q = self.waiters.setdefault(k, deque())
        if len(q) >= self.per_key_queue or self.per_key_wait <= 0:
            if not q:
                del self.waiters[k]
            return False
        fut = asyncio.get_running_loop().create_future()
        q.append(fut)
        try:
            await asyncio.wait_for(fut, self.per_key_wait)
            return True                 # the slot was handed over by _key_free (the count already includes it)
        except asyncio.TimeoutError:
            # the slot may have been handed over in the same turn of the loop as the timeout: it is ours then (else it would leak)
            return fut.done() and not fut.cancelled()
        except asyncio.CancelledError:
            if fut.done() and not fut.cancelled():
                self._key_free(k)       # handed over just as the client went away: pass it on
            raise
        finally:
            try:
                q.remove(fut)
            except ValueError:
                pass
            if not q and self.waiters.get(k) is q:
                del self.waiters[k]

    def _key_free(self, k) -> None:
        q = self.waiters.get(k)
        while q:
            f = q.popleft()
            if not f.done():
                f.set_result(True)      # the slot goes to the oldest waiter: the count of the key stays
                return
        if self.keys.get(k, 0) <= 1:
            self.keys.pop(k, None)
        else:
            self.keys[k] -= 1

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.limit or scope["path"] == "/healthz":
            return await self.app(scope, receive, send)
        if is_long_poll(scope):
            return await self._long_poll(scope, receive, send)
        k = None
        for h, v in scope.get("headers", ()):
            if h == b"authorization":
                k = hashlib.sha256(v).digest() if v.startswith(b"Bearer ") and len(v) <= 200 else None
                break
        if k is not None and not await self._key_slot(k):
            self.key_refused += 1
            return await self._refuse(send, 429, "RATE_LIMIT", "at most %d requests of one key at a time" % self.per_key)
        cont = scope["path"].startswith("/v1/actions/")          # present / report / GET of an action already decided: never shed
        if not cont and self.n >= self.limit:
            self.shed += 1
            if k is not None:
                self._key_free(k)
            return await self._refuse(send, 503, "OVERLOADED", "the server is busy; retry after %d s" % self.retry_after)
        self.n += 1                     # one event loop: no lock needed
        try:
            await self.app(scope, receive, send)
        finally:
            self.n -= 1
            if k is not None:
                self._key_free(k)

    async def _long_poll(self, scope, receive, send):
        """2710rt: a long poll is not counted in the global limit (it holds no worker thread) but at most `poll_per_key` of one key may be open:
        the rest are answered AT ONCE as wait=0 (the current status, 200), not 429: the hook and the SDKs treat that as 'still pending' and
        poll again (client.wait backs off when an answer comes in < 0.5 s), while a 429 on a legal poll could end in the hook's fail-closed deny."""
        k = None
        for h, v in scope.get("headers", ()):
            if h == b"authorization":
                k = hashlib.sha256(v).digest() if v.startswith(b"Bearer ") and len(v) <= 200 else None
                break
        if k is None or not self.poll_per_key:
            return await self.app(scope, receive, send)
        if self.polls.get(k, 0) >= self.poll_per_key:
            from urllib.parse import parse_qsl, urlencode
            q = [(a, b) for a, b in parse_qsl(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True) if a != "wait"] + [("wait", "0")]
            scope = dict(scope, query_string=urlencode(q).encode("latin-1"))
            return await self.app(scope, receive, send)
        self.polls[k] = self.polls.get(k, 0) + 1
        try:
            await self.app(scope, receive, send)
        finally:
            if self.polls[k] <= 1:
                del self.polls[k]
            else:
                self.polls[k] -= 1

    async def _refuse(self, send, status, code, detail):
        body = json.dumps({"error": code, "detail": detail}).encode()
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), (b"retry-after", str(self.retry_after).encode()),
            (b"x-content-type-options", b"nosniff"), (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": body})


async def _send_err(send, e):
    body = json.dumps({"error": e.code, "detail": e.detail}).encode()
    await send({"type": "http.response.start", "status": e.status, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                                                              (b"connection", b"close")]})
    await send({"type": "http.response.body", "body": body})


CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'"


def _js_hashes(web_dir, cache={}):
    """sha256 of the files that run in the owner's browser: js/*.js, css/app.css, *.html (top level), sw.js (08)."""
    cand = []
    for sub, ext in (("js", ".js"), ("", ".html")):
        d = os.path.join(web_dir, sub)
        if os.path.isdir(d):
            cand += [(sub + "/" + n if sub else n) for n in sorted(os.listdir(d)) if n.endswith(ext) and os.path.isfile(os.path.join(d, n))]
    if os.path.isfile(os.path.join(web_dir, "css", "app.css")):
        cand.append("css/app.css")
    if os.path.isfile(os.path.join(web_dir, "sw.js")):
        cand.append("sw.js")
    from app import webbuild
    b = webbuild.build(web_dir)          # 0.2.75: pages and modules are served with the build in their addresses: hashes of the SERVED bytes
    sig = [(n, os.path.getmtime(os.path.join(web_dir, n)), os.path.getsize(os.path.join(web_dir, n))) for n in cand] + [b]
    if cache.get(web_dir, (None,))[0] != sig:
        out = {}
        for n in cand:
            data = webbuild.served(web_dir, os.path.join(web_dir, n), n)
            if data is None:
                with open(os.path.join(web_dir, n), "rb") as f:
                    data = f.read()
            out[n] = hashlib.sha256(data).hexdigest()
        cache[web_dir] = (sig, out)
    return cache[web_dir][1]


_TAGS = {}


def _stale_page(req) -> bool:
    """0.2.75: a request of a page whose code is OLDER than the build-in-the-address change (it was kept by the browser's cache from before
    27.10, under an address without the build): it comes from this site's own page (Sec-Fetch-Site), is not a navigation, and has no
    X-DW-Build (js/api.js of 0.2.75+ sends it). Only on GET /api/me (every signed-in page asks it on load) and on POSTs (a person's action):
    the answer then carries Clear-Site-Data "cache", so the next load of any page of this site is fresh. Agents and scripts never send
    Sec-Fetch-Site, so they never get it."""
    p = req.url.path
    if not p.startswith("/api/") or req.headers.get("x-dw-build") or req.headers.get("sec-fetch-site") != "same-origin":
        return False
    if req.headers.get("sec-fetch-mode") == "navigate" or p == "/api/push/ack":     # r0276: the service worker's ack is no page of old code
        return False
    return req.method == "POST" or (req.method == "GET" and p == "/api/me")


def _content_tag(p, st):
    """N1 (27.10): 32 hex of the sha256 of the file's bytes, cached by (path, mtime, ctime, size, inode)."""
    k = (p, st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino)   # ctime: a rewrite with the old mtime still changes it
    t = _TAGS.get(k)
    if t is None:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
        t = h.hexdigest()[:32]
        if len(_TAGS) > 4096:
            _TAGS.clear()
        _TAGS[k] = t
    return t


PUBLIC_TOP = (".html",)
PUBLIC_FILES = ("sw.js", "manifest.webmanifest", "sitemap.xml", "robots.txt")   # 08: SW + PWA manifest; 24.10: sitemap, robots (поиск)
PUBLIC_DIRS = {"js": (".js",), "css": (".css",), "dl": None, "icons": (".png",), "demo": None, "pricing": (".html",), "constitution": (".html", ".json"), ".well-known": ("security.txt",)}      # None = any file (demo: P0-2, /demo)
mimetypes.add_type("application/manifest+json", ".webmanifest")


_re_docs_noext = __import__("re").compile(r"dl/docs/[a-z0-9-]+")
_re_const_v = __import__("re").compile(r"constitution/v[0-9]{1,4}")     # r0312: /constitution/v1 -> constitution/v1.html (pinned copy)


def _public(path):
    """R-08: only the site itself is served: top-level *.html, sw.js, manifest.webmanifest, js/*.js, css/*.css, icons/*.png, dl/** (the wheel
    and the docs) and demo/** (the no-signup demo with its DEMO pack). Notes and tests are not."""
    parts = [x for x in path.split("/") if x]
    if any(x in (".", "..") or "\\" in x or "\0" in x for x in parts):
        return False                                  # R3-10: `demo/../OTCHET-02.md` stays inside web/ but is not the site
    if not parts:
        return True
    if len(parts) == 1:
        return parts[0].endswith(PUBLIC_TOP) or parts[0] in PUBLIC_FILES or parts[0] in PUBLIC_DIRS
    exts = PUBLIC_DIRS.get(parts[0], ())
    return exts is None or (exts != () and parts[-1].endswith(exts))


class KeyMismatch(KeyFileError):
    """The witness key does not match the key that signed a journal on disk (wrong key restored, or a replaced one)."""


def _last_line(path):
    """Last COMPLETE line (ends with \\n) of a file, b"" if none. A tail without \\n was never acknowledged (Ledger._catch_up drops it)."""
    size = os.path.getsize(path)
    n = 65536
    with open(path, "rb") as f:
        while True:
            f.seek(max(0, size - n))
            buf = f.read()
            lines = buf[:buf.rfind(b"\n") + 1].split(b"\n")[:-1]
            if len(lines) >= 2 or n >= size:                   # >= 2: the last one has a newline BEFORE it, so it is whole
                return lines[-1] if lines else b""
            n *= 4


def check_witness_key(ctx, allow_mismatch=None):
    """Startup guard: the configured witness key must have signed the LAST entry of every journal (data/ledgers/*/ledger.cose).
    Healthz says "ok" with a foreign key and every action then fails with 500; this refuses to start instead (KeyMismatch -> exit 2).
    DW_ALLOW_KEY_MISMATCH=1 starts anyway (a deliberate key change only) and logs a WARN per journal. -> number of journals checked."""
    if allow_mismatch is None:
        allow_mismatch = os.environ.get("DW_ALLOW_KEY_MISMATCH") == "1"
    root = ctx.hub.root
    bad = []
    n = 0
    for acc in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        p = os.path.join(root, acc, "ledger.cose")
        if not ACC_RE.match(acc) or not os.path.isfile(p):
            continue
        n += 1
        line = _last_line(p)
        if not line:
            continue                                                  # empty journal: nothing signed yet
        try:
            cose.verify1(bytes.fromhex(line.decode()), [ctx.wk], cose.TYP_ENTRY)
        except (cose.CoseError, ValueError, UnicodeDecodeError) as e:
            bad.append((acc, str(e) or type(e).__name__))
    if not bad:
        return n
    for acc, why in bad:
        log("WARN" if allow_mismatch else "ERROR", "witness key did not sign the last entry of the journal", account=acc, kid=ctx.wk.kid.hex(), why=why)
    if allow_mismatch:
        log("WARN", "DW_ALLOW_KEY_MISMATCH=1: starting with a key that did not sign %d of %d journals; writes to them will fail" % (len(bad), n))
        return n
    raise KeyMismatch("the witness key (kid %s) did not sign the last entry of %d of %d journals (e.g. %s: %s). Wrong secrets/witness_ed25519 "
                      "restored? Put the original key back (restore.md step 1). Only for a deliberate key change: DW_ALLOW_KEY_MISMATCH=1"
                      % (ctx.wk.kid.hex()[:16], len(bad), n, bad[0][0], bad[0][1]))


def create_app(cfg=None):
    cfg = cfg or Config.from_env()
    from app import hub as _hub
    _hub.claim_data_dir(cfg.data_dir)                    # RT-SUP 29.10: hub.lock is per process -> one server process per data dir
    ctx = Ctx(cfg)
    erase.recover(ctx)                                   # 0.2.34: a crash in the middle of an account deletion is settled first
    check_witness_key(ctx)
    from app import actions as _actions
    try:
        _actions.reconcile_on_start(ctx)                 # rel 28.10: waiting rows whose id the ledger already judged follow the ledger
    except Exception as e:  # noqa: BLE001 -- never stops the start; per-row rules still refuse a second judgement (409)
        log("ERROR", "reconcile on start failed: " + type(e).__name__)
    web_dir = os.path.abspath(cfg.web_dir or _paths.WEB_DIR_DEFAULT)
    app = FastAPI(title="Deus Witness Cloud", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.ctx = ctx
    push.attach(ctx)                     # 08: raises ConfigError on an unusable VAPID key; no key = push off
    notify.attach(ctx)                   # 0.2.25: Telegram / Slack / e-mail channels (app/notify.py)
    from app import stats as _stats
    _stats.attach(ctx)                   # 0.2.28: funnel counters + Team form (app/stats.py); /internal/stats only with DW_STATS_TOKEN_FILE

    @app.exception_handler(Err)
    async def _err(req, e):
        x = getattr(e, "extra", None) if isinstance(getattr(e, "extra", None), dict) else {}
        hd = {"Retry-After": str(int(x["retry_after"]))} if isinstance(x.get("retry_after"), int) else None     # 0.2.39
        if e.code == "APPROVAL_SIG" and req.headers.get("sec-fetch-site") == "same-origin":
            hd = dict(hd or {}, **{"Clear-Site-Data": '"cache"'})    # 0.2.75: a browser page whose signature did not match: its next load is fresh
        return JSONResponse(dict(x, error=e.code, detail=e.detail), status_code=e.status, headers=hd)

    @app.exception_handler(Exception)
    async def _boom(req, e):
        log("ERROR", "unhandled " + type(e).__name__, route=_route(req), status=500, account=getattr(req.state, "account", None))
        return JSONResponse({"error": "INTERNAL", "detail": "internal error"}, status_code=500)

    def _route(req):
        r = req.scope.get("route")
        return getattr(r, "path", None) or ("static" if not req.url.path.startswith(("/api", "/v1")) else "unmatched")

    @app.middleware("http")
    async def headers_and_log(req: Request, call_next):
        t0 = time.time()
        try:
            resp = await call_next(req)
        except Exception as e:  # noqa
            log("ERROR", "unhandled " + type(e).__name__, route=_route(req), status=500)
            resp = JSONResponse({"error": "INTERNAL", "detail": "internal error"}, status_code=500)
        resp.headers["Content-Security-Policy"] = CSP
        if _stale_page(req):
            resp.headers["Clear-Site-Data"] = '"cache"'
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        if req.url.path != "/healthz":
            log("INFO", "request", route=_route(req), status=resp.status_code, ms=int((time.time() - t0) * 1000),
                account=getattr(req.state, "account", None))
        return resp

    app.add_middleware(DropWatch)                     # 2710u: inside BodyLimit and Shed; sees the raw connection of a long poll
    app.add_middleware(BodyLimit)

    @app.on_event("startup")
    async def _threads():
        import anyio.to_thread
        anyio.to_thread.current_default_thread_limiter().total_tokens = max(1, THREADS if cfg.threads is None else cfg.threads)
    app.add_middleware(Shed, limit=MAX_INFLIGHT if cfg.max_inflight is None else cfg.max_inflight,
                       poll_per_key=POLL_PER_KEY if cfg.poll_per_key is None else cfg.poll_per_key)     # outermost: sheds before anything else runs
    from app.actions import hooks
    if getattr(hooks, "router", None) is not None:      # task 02 (ARHITEKTURA-0.2 8): first, so /api/approvals/batch is not taken as {rid}
        app.include_router(hooks.router)
    app.include_router(api_web.make_router(ctx))
    app.include_router(api_agent.make_router(ctx))
    app.include_router(push.make_router(ctx))
    app.include_router(notify.make_router(ctx))

    if ctx.tee is not None:                                       # DW_TEE=on only (cloud/tee/DIZAIN-TDX.md)
        from app import tee
        app.include_router(tee.make_router(ctx))
    app.include_router(_stats.make_router(ctx))
    from app import node2feed
    if node2feed.attach(ctx):                                    # 0.2.27, DW_NODE2=on only: node 2 feed + public /v1/node2/*
        app.include_router(node2feed.make_router(ctx))
    from app import tlog as _tlog
    app.include_router(_tlog.make_router(ctx))                   # r0269: public log of anchor batches, C2SP checkpoint, daily stamp
    try:
        _tlog.record_constitution(ctx, web_dir)                  # r0312: every constitution version into the signed log, once
    except Exception as e:  # noqa: BLE001 -- never stops the start; constitution_check.py says INVALID to anyone instead
        log("ERROR", "constitution log failed: " + type(e).__name__)
    from app import demo_live
    if demo_live.enabled(ctx):                                   # 0.2.32, DW_DEMO_ACCOUNT set only: public feed + pack of the demo account
        app.include_router(demo_live.make_router(ctx))

    def witness_view():
        hs = dict(_js_hashes(web_dir))
        if not node2feed.enabled(ctx):
            hs.pop("node2.html", None)        # 0.2.40: with DW_NODE2 off the page answers 404 (see static()), so it is not in the list a reader checks
        v = {"iss": cfg.iss, "alg": "EdDSA", "kid_hex": ctx.wk.kid.hex(), "pub_hex": ctx.wk.pub.hex(), "web_js_sha256": hs}
        if ctx.tee is not None:
            v["attestation"] = ctx.tee.boot
        return v

    @app.get("/api/build")
    def web_build(clear: str = ""):
        """0.2.75: the build of the site's modules (js/boot.js compares its own with it). ?clear=1 also tells the browser to drop its HTTP
        cache of this site (Clear-Site-Data), so the page that asked loads fresh on its one reload."""
        from app import webbuild
        hd = {"Cache-Control": "no-store"}
        if clear == "1":
            hd["Clear-Site-Data"] = '"cache"'
        return JSONResponse({"build": webbuild.build(web_dir), "status_url": ctx.cfg.status_url or None}, headers=hd)     # r0288: kept by the page for the day this server is down

    @app.get("/api/witness")
    @app.get("/v1/witness")
    def witness():
        return witness_view()

    @app.api_route("/healthz", methods=["GET", "HEAD"])
    def healthz():
        last = ctx.db.one("SELECT MAX(t) AS t FROM anchor_batches")["t"]
        return {"ok": True, "ledgers": ctx.hub.count(), "last_anchor_t": last}

    @app.api_route("/{path:path}", methods=["GET", "HEAD"])      # 0.1.1: HEAD on static files answers 200 like GET
    def static(path: str, req: Request):
        if path.startswith(("api/", "v1/")):
            raise Err(404, "NOT_FOUND")
        if path in ("node2", "node2/"):                           # 0.2.27: the node 2 page answers at /node2 too
            path = "node2.html"
        if _re_docs_noext.fullmatch(path) and os.path.isfile(os.path.join(web_dir, "dl", "docs", path[len("dl/docs/"):] + ".html")):
            path += ".html"                                       # 0.2.55: /dl/docs/quickstart -> quickstart.html (only [a-z0-9-], only an existing file)
        if _re_const_v.fullmatch(path):
            path += ".html"                                       # r0312: a version of the constitution at a permanent address
        if path == "node2.html" and not node2feed.enabled(ctx):
            raise Err(404, "NOT_FOUND")                           # 0.2.30: DW_NODE2 off -> no node 2 page either (it describes a feature that is off)
        if not os.path.isdir(web_dir):
            raise Err(404, "NOT_FOUND", "no static site")
        if not _public(path):
            raise Err(404, "NOT_FOUND")
        p = os.path.realpath(os.path.join(web_dir, path))
        if p != web_dir and not p.startswith(web_dir + os.sep):
            raise Err(404, "NOT_FOUND")
        if os.path.isdir(p):
            p = os.path.join(p, "index.html")
        if not os.path.isfile(p):
            raise Err(404, "NOT_FOUND")
        if path in ("demo", "demo/", "demo/index.html") and req.method == "GET":
            _stats.visit(ctx, req.headers.get("user-agent") or "")     # 0.2.28: +1 for today, nothing about the visitor kept
        mt = mimetypes.guess_type(p)[0] or "application/octet-stream"
        # 27.10 (polygon series 2, N1): the release image touches every file to SOURCE_DATE_EPOCH, so Last-Modified (and Starlette's
        # mtime+size ETag) stay the same across releases and, with no Cache-Control, a browser kept the old approve.js by heuristic
        # freshness. Now: revalidate every time (no-cache), an ETag of the CONTENT, no Last-Modified, 304 only on that ETag.
        st = os.stat(p)
        from app import webbuild
        data = webbuild.served(web_dir, p, os.path.relpath(p, web_dir).replace(os.sep, "/"))   # 0.2.75: the build in every module address
        etag = '"%s"' % (_content_tag(p, st) if data is None else hashlib.sha256(data).hexdigest()[:32])
        hdr = {"etag": etag, "cache-control": "no-cache"}
        inm = req.headers.get("if-none-match")
        if inm and (inm.strip() == "*" or etag in [x.strip().removeprefix("W/") for x in inm.split(",")]):
            return Response(status_code=304, headers=hdr)
        if data is not None:
            return Response(content=b"" if req.method == "HEAD" else data, media_type=mt, headers=dict(hdr, **{"content-length": str(len(data))}))
        resp = FileResponse(p, media_type=mt, headers=hdr, stat_result=st)
        del resp.headers["last-modified"]
        return resp

    import asyncio as _aio
    from app import jobs as _jobs

    @app.on_event("startup")
    async def _start_prune():
        async def prune_loop():
            # 0.2.24 (critique B): previews kept only while an action waits; decided ones -> hash + excerpt, then hash only after DW_PREVIEW_KEEP_DAYS
            while True:
                await _aio.sleep(int(os.environ.get("DW_PRUNE_EVERY", "3600")))
                try:
                    await _aio.to_thread(_jobs.prune_previews, ctx)
                except Exception as e:  # noqa
                    log("ERROR", "preview prune failed: " + type(e).__name__)
                try:
                    from app import refusals as _refusals
                    await _aio.to_thread(_refusals.prune, ctx)             # 0.2.46: 429 counts older than 14 days
                except Exception as e:  # noqa
                    log("ERROR", "refusals prune failed: " + type(e).__name__)
                try:
                    from app import trial as _trial
                    await _aio.to_thread(_trial.expire_due, ctx)          # 0.2.38: unkept trial accounts past their time are erased
                except Exception as e:  # noqa
                    log("ERROR", "trial sweep failed: " + type(e).__name__)
        app.state.jobs_prune = _aio.create_task(prune_loop())

        async def policy_due_loop():
            # 0.2.37: delayed Team policy changes take effect when their wait is over (also lazily on every policy / request path)
            from app import org as _org
            while True:
                await _aio.sleep(int(os.environ.get("DW_POLICY_DUE_EVERY", "60")))
                try:
                    await _aio.to_thread(_org.apply_due, ctx)
                except Exception as e:  # noqa
                    log("ERROR", "policy due job failed: " + type(e).__name__)
        app.state.jobs_policy_due = _aio.create_task(policy_due_loop())

        async def refusals_loop():
            # 0.2.46: the 429 counts are kept in memory and written in one batch (app/refusals.py)
            from app import refusals as _rf
            while True:
                await _aio.sleep(_rf.FLUSH_EVERY_S)
                await _aio.to_thread(_rf.flush, ctx)
        app.state.jobs_refusals = _aio.create_task(refusals_loop())

    @app.on_event("shutdown")
    async def _stop_refusals():
        from app import refusals as _rf
        await _aio.to_thread(_rf.flush, ctx)

    if cfg.anchor == "on" or cfg.tsa_url:          # 0.2.9: DW_TSA_URL alone also runs the batch job (RFC 3161 only, no OTS, no promises)
        import asyncio
        from app import jobs

        @app.on_event("startup")
        async def _start_jobs():
            async def loop():
                n = 0
                while True:
                    # 19.10 Деус: якорь раз в 30 мин — запас к обещанию включения MMD 3600 с
                    await asyncio.sleep(int(os.environ.get("DW_ANCHOR_EVERY", "1800")) if n else 60)
                    n += 1
                    try:
                        await asyncio.to_thread(jobs.anchor_once, ctx)
                    except Exception as e:  # noqa
                        log("ERROR", "anchor job failed: " + type(e).__name__)
                    try:
                        await asyncio.to_thread(_tlog.stamp_due, ctx)          # r0269: daily stamp of the log checkpoint (+ retries of queued ones)
                    except Exception as e:  # noqa
                        log("ERROR", "tlog stamp job failed: " + type(e).__name__)

            async def upgrade_loop():
                # 0.2.5 (R4-01): the upgrade of pending stamps (calendars + two block explorers, 30 s timeout each) is its OWN task: it must not stretch the anchor period
                await asyncio.sleep(300)
                while True:
                    try:
                        await asyncio.to_thread(jobs.upgrade_once, ctx)
                    except Exception as e:  # noqa
                        log("ERROR", "upgrade job failed: " + type(e).__name__)
                    try:
                        await asyncio.to_thread(_tlog.upgrade_stamps, ctx)
                    except Exception as e:  # noqa
                        log("ERROR", "tlog upgrade job failed: " + type(e).__name__)
                    await asyncio.sleep(int(os.environ.get("DW_UPGRADE_EVERY", "1800")))
            if cfg.anchor == "on":
                app.state.jobs_upgrade = asyncio.create_task(upgrade_loop())
            app.state.jobs = asyncio.create_task(loop())
    return app


def main(argv=None):
    import argparse
    import uvicorn
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--host", default="127.0.0.1")
    o = ap.parse_args(argv)
    try:
        app = create_app()
    except (ConfigError, KeyFileError, NeedsMigration, DataDirBusy) as e:
        log("ERROR", "startup refused: %s" % e)
        sys.exit(2)
    uvicorn.run(app, host=o.host, port=o.port, log_level="warning")


if __name__ == "__main__":
    main()
