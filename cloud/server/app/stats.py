"""0.2.28: the funnel of the service, counted on the server, without personal data and without third-party analytics.

What is stored:
- funnel_daily(day, step, n_all, n_own): one number per UTC day and step. Steps: demo_visit (a GET of /demo/ that does not look like a
  robot; no cookie, no IP, no user agent kept: only +1), registration, agent, mandate, first_call, first_approval (each counted ONCE per
  account, the first time it happens). n_own = the part of n_all whose account looks like ours (display name of the account or of one of its
  people matches OWN_RE or DW_STATS_OWN_NAMES), so the owner sees outsiders as n_all - n_own without a second tool.
- funnel_seen(account_id, step): which account has already passed a step (so "first" stays first). Erased with the account
  (account_delete.TABLES_BY_ACCOUNT).
- team_requests(id, t, email, text, confirmed_at, flood): the Team access form (POST /api/team-request). Only what the person typed; no IP, no user agent,
  no cookie. Kept TEAM_KEEP_DAYS, then deleted. The owner's own Witness account (DW_OWNER_ACCOUNT) gets "a new Team request #N" in its
  existing notification channels; the e-mail and the text never go into a notification.

Read: GET /internal/stats?days=N with `Authorization: Bearer <token>`; the token sits in a secret file (DW_STATS_TOKEN_FILE, >= 32
characters, only its SHA-256 is kept in memory). No token file = the endpoint answers 404. Counting never breaks a request: errors are
logged and swallowed."""
import hashlib
import hmac
import os
import re
import threading
import time

from app.context import Err
from app.log import log

STEPS = ("demo_visit", "registration", "agent", "mandate", "first_call", "first_approval",
         "trial", "hook_touch", "hook_touch_day2")      # 0.2.38 (app/trial.py): a trial account; the first passkey touch on a call of the Claude
                                                         # Code hook; another such touch on a later UTC day (internal / demo / own accounts never count)
ACCOUNT_STEPS = STEPS[1:]
OWN_RE = re.compile(r"^(test|demo|smoke|e2e|probe|owner|deus|sipki|tmp)", re.I)     # same rule as deploy/voronka.py EXCL
BOT_RE = re.compile(r"bot|crawl|spider|slurp|preview|monitor|curl|wget|python|httpx|go-http|headless|scan", re.I)
TEAM_KEEP_DAYS = 180
TEAM_MAX_PER_DAY = 50            # all senders together: beyond this a request is still stored, marked flood=1 and not notified (0.2.30)
TEAM_HARD_PER_DAY = 2000         # storage bound only: a flood this large is refused (429 + the support address), the disk stays bounded
TEAM_EMAIL_MAX, TEAM_TEXT_MAX = 254, 2000
EMAIL_RE = re.compile(r"[^@\s<>\"',;]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}")
MAX_DAYS = 400


_seen = set()                    # (account, step) known to be counted: no write on every action of an active agent
_seen_lock = threading.Lock()


def day(t=None):
    return time.strftime("%Y-%m-%d", time.gmtime(time.time() if t is None else t))


def own_names():
    return {x.strip().lower() for x in (os.environ.get("DW_STATS_OWN_NAMES") or "").split(",") if x.strip()}


def _own_name(n, extra):
    n = (n or "").strip().lower()
    return bool(n) and (bool(OWN_RE.match(n)) or n in extra)


def is_own(ctx, account_id):
    extra = own_names()
    a = ctx.db.one("SELECT display_name, internal FROM accounts WHERE id=?", (account_id,))
    if a is not None and (_own_name(a["display_name"], extra) or a["internal"]):      # 0.2.38: accounts.internal (our networks / our scripts)
        return True
    for u in ctx.db.q("SELECT u.display_name AS n FROM members m JOIN users u ON u.id=m.user_id WHERE m.account_id=?", (account_id,)):
        if _own_name(u["n"], extra):
            return True
    u = ctx.db.one("SELECT display_name FROM users WHERE id=?", (account_id,))       # solo account: the person has the account's id
    return u is not None and _own_name(u["display_name"], extra)


def _add(ctx, step, own, t=None):
    d = day(t)
    ctx.db.x("INSERT INTO funnel_daily(day,step,n_all,n_own) VALUES(?,?,1,?) ON CONFLICT(day,step) DO UPDATE SET n_all=n_all+1, n_own=n_own+?",
             (d, step, 1 if own else 0, 1 if own else 0))


def visit(ctx, user_agent=""):
    """+1 demo_visit for today. Nothing about the visitor is kept; obvious robots are not counted."""
    try:
        if user_agent and BOT_RE.search(user_agent):
            return False
        if not user_agent:
            return False
        _add(ctx, "demo_visit", False)
        return True
    except Exception as e:  # noqa - counting never breaks the page
        log("ERROR", "stats visit failed: " + type(e).__name__)
        return False


def first(ctx, account_id, step, t=None):
    """+1 `step` for today if this account passes it for the first time. -> True when counted."""
    if step not in ACCOUNT_STEPS or not isinstance(account_id, str) or not account_id:
        return False
    k = (account_id, step)
    with _seen_lock:
        if k in _seen:
            return False
    try:
        new = ctx.db.n("INSERT OR IGNORE INTO funnel_seen(account_id, step, t) VALUES(?,?,?)", (account_id, step, int(time.time() if t is None else t)))
        with _seen_lock:
            _seen.add(k)
            if len(_seen) > 200000:
                _seen.clear()
        if new:
            _add(ctx, step, is_own(ctx, account_id), t)
        return bool(new)
    except Exception as e:  # noqa
        log("ERROR", "stats count failed: " + type(e).__name__, step=step)
        return False


def uncount(ctx, step, own, t=None):
    """0.2.39: take back one count of `step` on the day of t (a trial account replaced by the same person's next `deus-witness try`; an
    account marked internal afterwards, deploy/mark-internal). hook_touch* of an own account were never in n_all."""
    try:
        if step in ("hook_touch", "hook_touch_day2") and own:
            return False
        return bool(ctx.db.n("UPDATE funnel_daily SET n_all=MAX(0, n_all-1), n_own=MAX(0, n_own-?) WHERE day=? AND step=?",
                             (1 if own else 0, day(t), step)))
    except Exception as e:  # noqa
        log("ERROR", "stats uncount failed: " + type(e).__name__, step=step)
        return False


def forget(account_id):
    """The account was deleted (its funnel_seen rows go with TABLES_BY_ACCOUNT): drop it from the in-memory set too."""
    with _seen_lock:
        for s in ACCOUNT_STEPS:
            _seen.discard((account_id, s))


def report(ctx, days=30, t=None):
    days = max(1, min(MAX_DAYS, int(days)))
    t = time.time() if t is None else t
    since = day(t - (days - 1) * 86400)
    rows = {}
    for r in ctx.db.q("SELECT day, step, n_all, n_own FROM funnel_daily WHERE day>=? ORDER BY day", (since,)):
        rows.setdefault(r["day"], {})[r["step"]] = {"all": r["n_all"], "own": r["n_own"], "outside": r["n_all"] - r["n_own"]}
    tot = {s: {"all": 0, "own": 0, "outside": 0} for s in STEPS}
    for d in rows.values():
        for s, v in d.items():
            if s in tot:
                for k in ("all", "own", "outside"):
                    tot[s][k] += v[k]
    prune_team(ctx, t)
    team = [{"id": r["id"], "t": r["t"], "email": r["email"], "text": r["text"], "confirmed": r["confirmed_at"] is not None,
             "confirmed_at": r["confirmed_at"], "flood": bool(r["flood"])}
            for r in ctx.db.q("SELECT id, t, email, text, confirmed_at, flood FROM team_requests WHERE t>=? ORDER BY id", (int(t) - days * 86400,))]
    return {"since": since, "days": [{"day": d, "steps": rows[d]} for d in sorted(rows)], "total": tot, "steps": list(STEPS),
            "team_requests": team, "team_confirmed_n": sum(1 for x in team if x["confirmed"]),
            "note": "demo_visit = page loads of /demo/ (robots by user agent left out), not people; a Team request counts only once the "
                    "owner confirmed it (POST /internal/team-requests/{id}/confirm); hook_touch / hook_touch_day2 = a passkey decision on a "
                    "call of the Claude Code hook, first ever / again on a later day, internal, demo and own accounts left out (not in n_all)"}


def confirm_team(ctx, rid, real=True, t=None):
    """0.2.30 (review V1): the owner read request #rid and says it is a real person (real=True) or not (False). Only confirmed requests count
    for the 04.11 criterion (deploy/voronka.py): a robot or our own test fills the table, not the criterion."""
    t = int(time.time() if t is None else t)
    if not isinstance(rid, int) or isinstance(rid, bool) or ctx.db.one("SELECT 1 AS k FROM team_requests WHERE id=?", (rid,)) is None:
        raise Err(404, "NOT_FOUND")
    ctx.db.x("UPDATE team_requests SET confirmed_at=? WHERE id=?", (t if real else None, rid))
    r = ctx.db.one("SELECT id, confirmed_at FROM team_requests WHERE id=?", (rid,))
    return {"id": r["id"], "confirmed": r["confirmed_at"] is not None, "confirmed_at": r["confirmed_at"]}


# ---------- Team access form ----------
def net_key(ip):
    """0.2.30: the rate-limit key of a sender: an IPv4 address, or the /64 of an IPv6 one (one host is given a whole /64 to rotate through)."""
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return str(ip)
    if a.version == 6:
        if a.ipv4_mapped is not None:
            return str(a.ipv4_mapped)
        return str(ipaddress.ip_network(str(a) + "/64", strict=False))
    return str(a)


def prune_team(ctx, t=None):
    t = time.time() if t is None else t
    ctx.db.x("DELETE FROM team_requests WHERE t<?", (int(t) - TEAM_KEEP_DAYS * 86400,))


def team_request(ctx, b, t=None):
    """-> {"ok": True, "id": n}. A filled hidden field `website` (robots fill every field) is accepted silently and not stored."""
    t = int(time.time() if t is None else t)
    if isinstance(b.get("website"), str) and b["website"].strip():
        return {"ok": True, "id": 0}
    email = b.get("email")
    text = b.get("text")
    if not isinstance(email, str) or len(email.strip()) > TEAM_EMAIL_MAX or not EMAIL_RE.fullmatch(email.strip()):
        raise Err(422, "TEAM_EMAIL", "a work e-mail address")
    if not isinstance(text, str) or not text.strip() or len(text) > TEAM_TEXT_MAX:
        raise Err(422, "TEAM_TEXT", "a few words about your team (1..%d characters)" % TEAM_TEXT_MAX)
    # 0.2.30 (review V1): the daily limit no longer refuses everybody after 50 robot posts. Beyond TEAM_MAX_PER_DAY a request is still
    # stored (a real buyer is not turned away) but marked flood=1 and not notified; only TEAM_HARD_PER_DAY (a bound of the disk) refuses.
    # Why not an e-mail confirmation link: the server would send mail to any address a robot types (a relay against strangers, and the
    # project does not write to strangers unasked); a captcha is excluded. The criterion is protected by the owner's confirmation instead.
    n_day = ctx.db.one("SELECT COUNT(*) AS n, SUM(CASE WHEN flood=1 THEN 0 ELSE 1 END) AS ok FROM team_requests WHERE t>?", (t - 86400,))
    if n_day["n"] >= TEAM_HARD_PER_DAY:
        raise Err(429, "RATE_LIMIT", "too many requests today: write to support@sipkigroup.com")
    flood = 1 if (n_day["ok"] or 0) >= TEAM_MAX_PER_DAY else 0
    prune_team(ctx, t)
    rid = ctx.db.x("INSERT INTO team_requests(t, email, text, flood) VALUES(?,?,?,?)", (t, email.strip(), text.strip(), flood))
    owner = (os.environ.get("DW_OWNER_ACCOUNT") or "").strip()
    n = getattr(ctx, "notify", None)
    if owner and n is not None and not flood:
        try:
            n.digest(owner, "team")          # 0.2.30: at most one summary in 10 minutes ("N new Team access requests"), no e-mail, no text
        except Exception as e:  # noqa - the request is stored; a channel that fails does not lose it
            log("WARN", "team request notify failed: " + type(e).__name__)
    return {"ok": True, "id": rid}


# ---------- owner endpoint ----------
def token_sha256(env=None):
    e = os.environ if env is None else env
    tf = (e.get("DW_STATS_TOKEN_FILE") or "").strip()
    if not tf:
        return b""
    try:
        with open(tf) as f:
            tok = f.read().strip()
    except OSError:
        log("ERROR", "DW_STATS_TOKEN_FILE unreadable: /internal/stats is off")
        return b""
    if len(tok) < 32:
        log("ERROR", "DW_STATS_TOKEN_FILE: the token must be at least 32 characters; /internal/stats is off")
        return b""
    return hashlib.sha256(tok.encode()).digest()


def attach(ctx):
    ctx.stats_token = token_sha256()
    return ctx


def make_router(ctx):
    from fastapi import APIRouter, Request

    r = APIRouter()

    def _owner(req):
        """0.2.30 (review, small 1): the right token always passes; only WRONG tries are limited, and globally (key "statsauth"), not by
        the TCP peer address: behind the proxy that is the proxy's address, shared by everyone, so a stranger's ten wrong tries locked the owner
        out. Guessing is no way in anyway: the token has >= 32 characters (>= 160 bits from `openssl rand`) and is compared as a SHA-256 in
        constant time; the limit only keeps a flood of wrong tries cheap."""
        if not getattr(ctx, "stats_token", b""):
            raise Err(404, "NOT_FOUND")
        a = req.headers.get("authorization") or ""
        tok = a[7:].strip() if a.startswith("Bearer ") and len(a) <= 300 else ""
        if tok and hmac.compare_digest(hashlib.sha256(tok.encode()).digest(), ctx.stats_token):
            return
        if not ctx.limiter.hit("statsauth", 30, 60):
            raise Err(429, "RATE_LIMIT", "too many failed logins")
        raise Err(401, "STATS_AUTH", "owner token required")

    @r.post("/internal/team-requests/{rid}/confirm")
    async def _confirm(rid: int, req: Request):
        _owner(req)
        try:
            b = await req.json()
        except Exception:
            b = {}
        real = b.get("real", True) if isinstance(b, dict) else True
        if not isinstance(real, bool):
            raise Err(400, "BAD_REQUEST", "real: true | false")
        return confirm_team(ctx, rid, real)

    @r.get("/metrics")
    def _metrics(req: Request):
        """0.2.96: Prometheus text, counts only (app/uxstat.py); the same owner token as /internal/stats, 404 without one."""
        from fastapi.responses import PlainTextResponse
        from app import uxstat
        _owner(req)
        return PlainTextResponse(uxstat.metrics_text(ctx), media_type="text/plain; version=0.0.4")

    @r.get("/internal/stats")
    def _stats(req: Request):
        _owner(req)
        try:
            days = int(req.query_params.get("days") or 30)
        except ValueError:
            raise Err(400, "BAD_REQUEST", "days: a whole number")
        return report(ctx, days)

    return r
