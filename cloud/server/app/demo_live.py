"""0.2.32: the public live feed of ONE demo account (cloud/demo-live). OFF unless DW_DEMO_ACCOUNT is set (32 hex = the id of the demo
account); off = no route below exists (404 like any unknown path).

  GET /v1/demo/live            the last 50 decisions of the demo account: rid, time, tool, class, recipient, amount, verdict, reason,
                               status, plus the active mandate's permissions. Nothing else and no other account.
  GET /v1/demo/live/pack.zip   the demo account's evidence pack (the same bytes /api/export gives its owner), signed by the service key.

What is NOT shown on purpose: the arguments (args_preview / text_preview): if the agent key leaked, whoever holds it could write any
text into them and it would appear on our site. Tool, recipient and verdict are bounded by the mandate and the tool map; the recipient
is cut to 80 characters and the page renders everything as text.

Abuse limits (nobody logs in here):
  - the feed is computed at most once per FEED_TTL_S for everybody (one cached answer), and each IP may ask FEED_PER_MIN per minute;
  - a pack is BUILT at most once per PACK_MIN_S and only when the account has new actions since the last build (each build appends a
    checkpoint to the demo journal, R-16); everybody gets the cached bytes; each IP may download PACK_PER_HOUR per hour.
"""
import ipaddress
import json
import re
import threading
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from app import _paths  # noqa: F401
from app import actions as act
from app.context import Err

FEED_TTL_S, FEED_PER_MIN, FEED_N = 15, 60, 50
PACK_MIN_S, PACK_PER_HOUR = 600, 20
ACCOUNT_RE = re.compile(r"[0-9a-f]{32}")


def enabled(ctx):
    return bool(getattr(ctx.cfg, "demo_account", ""))


def make_router(ctx, clock=time.time):
    r = APIRouter()
    db, aid = ctx.db, ctx.cfg.demo_account
    trusted = [x.strip() for x in (ctx.cfg.trusted_proxy or "").split(",") if x.strip()]

    def client_ip(req):
        """Same rule as api_web (R-11, N-06): X-Real-IP only from the trusted reverse proxy (default: loopback only)."""
        peer = req.client.host if req.client else "?"
        try:
            ip = ipaddress.ip_address(peer)
            ok = ip.is_loopback if not trusted else any(ip in ipaddress.ip_network(t, strict=False) for t in trusted)
        except ValueError:
            ok = False
        return (req.headers.get("x-real-ip") or peer) if ok else peer
    feed_cache = {"t": -1e18, "body": None}
    pack_cache = {"t": -1e18, "mark": None, "data": None, "name": None}
    lock = threading.Lock()

    def limit(req, kind, n, window):
        if not ctx.limiter.hit("demo-%s:%s" % (kind, client_ip(req)), n, window):
            raise Err(429, "RATE_LIMIT", "%d per %d s" % (n, window))

    def build_feed():
        rows = db.q("SELECT rid, created_at, tool, class, recipient, amount, currency, verdict, reason FROM actions WHERE account_id=? "
                    "ORDER BY created_at DESC, rowid DESC LIMIT ?", (aid, FEED_N))
        items = []
        for x in rows:
            st = act.refresh(ctx, x["rid"])["status"]
            rc = x["recipient"]
            items.append({"rid": x["rid"], "t": x["created_at"], "tool": x["tool"], "class": x["class"],
                          "recipient": (rc[:80] if isinstance(rc, str) else None), "amount": x["amount"], "currency": x["currency"],
                          "verdict": x["verdict"], "reason": x["reason"], "status": st})
        m = db.one("SELECT id, mandate_json, created_at FROM mandates WHERE account_id=? AND status='active' ORDER BY created_at DESC, rowid DESC LIMIT 1", (aid,))
        mandate = None
        if m:
            mm = json.loads(m["mandate_json"])
            mandate = {"id": m["id"], "nbf": mm.get("nbf"), "exp": mm.get("exp"), "currency": mm.get("currency"),
                       "budget_window_s": mm.get("budget_window_s"), "permissions": mm.get("permissions"), "forbidden_data": mm.get("forbidden_data")}
        tot = {x["verdict"]: x["n"] for x in db.q("SELECT verdict, COUNT(*) AS n FROM actions WHERE account_id=? GROUP BY verdict", (aid,))}
        return {"demo_account": aid, "generated_at": int(clock()), "items": items, "mandate": mandate, "totals": tot}

    @r.get("/v1/demo/live")
    async def live(req: Request):
        limit(req, "feed", FEED_PER_MIN, 60)
        with lock:
            fresh = clock() - feed_cache["t"] < FEED_TTL_S
        if not fresh:
            body = await run_in_threadpool(build_feed)
            with lock:
                feed_cache.update(t=clock(), body=body)
        return JSONResponse(feed_cache["body"], headers={"Cache-Control": "public, max-age=%d" % FEED_TTL_S})

    def pack():
        from app.export import build_pack
        with lock:                       # one build at a time; everybody else waits for it and gets the same bytes
            mark = db.one("SELECT COUNT(*) AS n, MAX(updated_at) AS u FROM actions WHERE account_id=?", (aid,))
            mark = (mark["n"], mark["u"])
            due = pack_cache["data"] is None or (mark != pack_cache["mark"] and clock() - pack_cache["t"] >= PACK_MIN_S)
            if due:
                data, name = build_pack(ctx, aid)
                pack_cache.update(t=clock(), mark=mark, data=data, name=name)
            return pack_cache["data"], pack_cache["name"], int(pack_cache["t"])

    @r.get("/v1/demo/live/pack.zip")
    async def live_pack(req: Request):
        limit(req, "pack", PACK_PER_HOUR, 3600)
        if not db.one("SELECT 1 AS k FROM accounts WHERE id=?", (aid,)):
            raise Err(404, "NOT_FOUND")
        data, name, t = await run_in_threadpool(pack)
        return Response(data, media_type="application/zip",
                        headers={"Content-Disposition": 'attachment; filename="%s"' % name, "X-Pack-Built": str(t),
                                 "Cache-Control": "public, max-age=60"})

    return r
