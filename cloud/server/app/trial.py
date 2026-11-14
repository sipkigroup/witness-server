"""0.2.38: trial accounts -- "an account on the first touch" (PROEKT-REZHIM-BEZ-AKKAUNTA-2026-10-24.md, variant B).

  POST /v1/trial                 no account, no key: makes an anonymous account WITHOUT a passkey, one agent (preset claude-code) and its key,
                                 and keeps the mandate form the client sent (the recommended form of the project) as a DRAFT: nothing is signed.
                                 -> {api_key, agent_id, claim, claim_url, expires_at, quota_per_day, sent, privacy_url, coverage_url}
  GET  /api/trial/state          X-DW-Claim: <claim>  (before the first touch): the draft and the calls that wait for the first touch
  POST /api/trial/claim/begin    {claim}  -> passkey registration options (UV required)
  POST /api/trial/claim/finish   {flow_id, credential, claim, device?}  -> the passkey is the account's first key; a session starts
  GET  /api/trial                (session) the trial view of the signed-in account: draft, agent, expiry, whether a mandate is signed
  POST /api/trial/keep           (session, owner, fresh passkey touch) the account stays: no expiry, ordinary Free account from now on
  POST /v1/trial/retire          (0.2.39, agent key) `deus-witness try` again: the previous trial account, if it has no passkey yet, is erased

Who can approve (the 0.2.37 rule holds): only a human passkey signature. Before the first touch the account has NO key, NO mandate and NO
journal: a call that is not `pass` waits (verdict defer, reason ESCALATE_TRIAL_CLAIM, status pending_approval, no ledger entry) and can never
be approved as it is (approve/release refuse a row without a mandate). The first touch = the page registers a passkey (WebAuthn UV) with the
claim, then the person signs the drafted mandate with it (an ordinary wa-sig, verified like every mandate) and the waiting calls become
`covered`: the hook judges each again, now under the signed mandate (allow, or an ordinary question with a signed approval).

The claim is the only proof of "I am the person who ran `deus-witness try`": a random secret returned once to the client, never stored in
clear here (SHA-256), never given to the agent key (no /v1 path returns it), dead after the first touch. The client hands it to the browser in
the URL fragment (not sent to any server, not in our logs) and does not print it or store it. Honest limit (the report and /privacy.html say
it): before the first touch, a program that runs as the same user and reads the browser's storage could claim the account first; after it,
everything needs the passkey.

Abuse bounds: DW_TRIAL_PER_HOUR new trials per sender network (an IPv6 sender = its /64) and DW_TRIAL_PER_DAY for everybody (in memory, the
IP is not stored); DW_TRIAL_QUOTA actions a day per trial account (instead of the Free quota); at most PENDING_MAX calls waiting for the first
touch; the account and everything in it are erased DW_TRIAL_TTL_DAYS after it was made unless the person keeps it (expire_due, hourly; an
expired key is refused at once).

r0288 (13.11): an account that is USED is not erased by time. "Used" = its agents called the witness (any /v1 call
with the agent key: the hook, the MCP proxy) or a person signed in / signed with a passkey, within DW_IDLE_DAYS (90).
  - a quick start account without a passkey: each call moves its end to (the call + DW_IDLE_DAYS); one the hook never called still ends
    DW_TRIAL_TTL_DAYS after it was made (nobody can be warned: it has no passkey, no push, no page);
  - an account with a passkey (solo, not a team): DW_IDLE_WARN_DAYS before the end a push goes to its devices (sw.js text "i"); it is
    erased (account_delete.erase_unasked: the journal becomes the hash skeleton) only when the idle time is over AND that push is at
    least DW_IDLE_WARN_DAYS old AND nothing happened since; a team, a person who signs for another team and the demo account never.
  Days count from IDLE_FROM at the earliest (the rule's start), so no account made before the rule loses a day of notice.

Counting (the 04.11 criterion, app/stats.py): `trial` once per trial account; `hook_touch` = the first passkey decision of an account on a
call that came from the Claude Code hook (/v1/hook/judge: actions.via = 'hook'), `hook_touch_day2` = another such touch on a later UTC day.
Accounts marked internal (made from DW_STATS_INTERNAL_NETS, or by our own scripts), the demo account and accounts with our names never count."""
import hashlib
import ipaddress
import json
import os
import re
import secrets
import time

from app import _paths  # noqa: F401
from app.context import Err
from app import refusals
from app.log import log

TRIAL_NAME = "Trial"
IDLE_FROM = 1794528000             # r0288: 2026-11-13 00:00 UTC, the day the idle rule began (no account is idle from before it)
_SEEN = {}                         # r0288: account -> last use not yet written (flush_seen, hourly with the sweep)
PENDING_MAX = 20
REASON = "ESCALATE_TRIAL_CLAIM"
FORM_MAX = 16 * 1024
# r0288 (owner 13.11): the one wording of "free" (privacy.html, terms.html, trial.html, index.html, docs say the same; a test checks)
FREE_TEXT = "Free for one person. If this ever changes, existing accounts stay free and we announce it in advance."
KEEP_TEXT = ("A quick start account without a passkey is erased after %d days if your hook never calls; an account in use is kept: it is "
             "erased only after %d days with no call from your hook and no sign-in, and with a passkey you get a push 14 days before.")
SENT = ["the tool name and its full input of every call the hook sees (shell commands, file paths, URLs; the text written by Write/Edit is "
        "kept only as a short masked preview while a call waits)", "the working directory and the project directory",
        "answers to the witness' questions about paths of that call (does it exist, where does a link point) and SHA-256 fingerprints of the "
        "project files a command executes", "nothing else from this machine; no e-mail, no name"]


def now():
    return int(time.time())


def enabled(ctx):
    return getattr(ctx.cfg, "trial", "on") == "on"


def claim_hash(claim):
    return hashlib.sha256(("dw-trial-claim-1\0" + claim).encode()).digest() if isinstance(claim, str) and 20 <= len(claim) <= 100 else None


def info(ctx, account_id):
    """-> the trial columns of an account (cached until accounts is written), or None for an ordinary account."""
    r = ctx.db.cached(("acc_trial", account_id), ("accounts",),
                      lambda: ctx.db.one("SELECT trial_until, trial_claimed_at, internal FROM accounts WHERE id=?", (account_id,)))
    return r if r is not None and r["trial_until"] is not None else None


def expired(ctx, account_id, t=None):
    r = info(ctx, account_id)
    # 04.11 Open Core: an account with a passkey is the person's own and never expires; only a quick start account nobody claimed does
    if r is None or r["trial_claimed_at"] is not None or r["trial_until"] > (now() if t is None else t):
        return False
    return not (idle_days(ctx) and account_id in _SEEN)       # r0288: used within the last hour (not written yet): not expired


def idle_days(ctx):
    return int(getattr(ctx.cfg, "idle_days", 90) or 0)


def seen(ctx, account_id, t=None):
    """r0288: an agent key of this account called the witness (or its owner opened the dashboard). Kept IN MEMORY only (no write on the
    request path, which runs in the event loop); flush_seen() writes them, hourly (expire_due) and before every sweep. Never raises."""
    t = now() if t is None else t
    if _SEEN.get(account_id, 0) < t:
        if len(_SEEN) > 200000:
            _SEEN.clear()
        _SEEN[account_id] = t
    return True


def flush_seen(ctx):
    """Write the uses kept by seen(): last_hook_at, and the end of a quick start account without a passkey moves to (use + DW_IDLE_DAYS)."""
    if not _SEEN:
        return 0
    items = list(_SEEN.items())
    d = idle_days(ctx)
    try:
        with ctx.db.tx() as db:
            for aid, t in items:
                db.x("UPDATE accounts SET last_hook_at=MAX(COALESCE(last_hook_at,0),?), trial_until=CASE WHEN trial_until IS NOT NULL AND "
                     "trial_claimed_at IS NULL AND ?>0 AND trial_until<? THEN ? ELSE trial_until END WHERE id=? AND erased_at IS NULL",
                     (t, d, t + d * 86400, t + d * 86400, aid))
    except Exception as e:  # noqa - kept for the next flush
        log("ERROR", "uses not written: " + type(e).__name__)
        return 0
    for aid, t in items:
        if _SEEN.get(aid) == t:
            _SEEN.pop(aid, None)
    return len(items)


def last_use(ctx, account_id):
    """-> when the account was last used (r0288): its agents' last call, a passkey of its owner, its creation, the rule's start."""
    r = ctx.db.one("SELECT MAX(COALESCE(a.last_hook_at,0), a.created_at, ?, COALESCE((SELECT MAX(last_used_at) FROM credentials c "
                   "WHERE c.user_id=a.id), 0)) AS t FROM accounts a WHERE a.id=?", (IDLE_FROM, account_id))
    return r["t"] if r is not None else None


def idle_view(ctx, account_id, t=None):
    """r0288, for /api/me: None, or {erase_at, warned_at} of an account that was warned in its present idle time (a sign-in ends it)."""
    d = idle_days(ctx)
    if not d:
        return None
    r = ctx.db.one("SELECT idle_warned_at, trial_until FROM accounts WHERE id=?", (account_id,))
    if r is None or r["trial_until"] is not None or r["idle_warned_at"] is None:
        return None
    last = last_use(ctx, account_id) or 0
    return {"warned_at": r["idle_warned_at"], "last_use": last, "days": d, "erase_at": max(last + d * 86400,
            r["idle_warned_at"] + int(getattr(ctx.cfg, "idle_warn_days", 14)) * 86400), "kept": last > r["idle_warned_at"]}


def internal_ip(ctx, ip):
    nets = [x.strip() for x in (getattr(ctx.cfg, "internal_nets", "") or "").split(",") if x.strip()]
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(n, strict=False) for n in nets)


def excluded(ctx, account_id):
    """Not counted for the 04.11 criterion: internal, the demo account, our own names."""
    from app import stats
    if account_id == (getattr(ctx.cfg, "demo_account", "") or None):
        return True
    r = ctx.db.one("SELECT internal FROM accounts WHERE id=?", (account_id,))
    return r is None or bool(r["internal"]) or stats.is_own(ctx, account_id)


def _form(b, ttl_days):
    """The mandate form to keep as the draft: validated as the Mandate page would; no purchases, valid at most the trial's lifetime."""
    from app.mandates import mandate_from_form
    f = b.get("form")
    if not isinstance(f, dict):
        raise Err(422, "FORM_INVALID", "form: the recommended mandate form of the project (deus-witness-hook --print-form)")
    if len(json.dumps(f)) > FORM_MAX:
        raise Err(413, "FORM_TOO_LARGE")
    f = dict(f, purchase=None, valid_days=min(ttl_days, f.get("valid_days", ttl_days) if isinstance(f.get("valid_days"), int) and not isinstance(f.get("valid_days"), bool) else ttl_days))
    if f["valid_days"] < 1:
        f["valid_days"] = ttl_days
    mandate_from_form(f, "dw:" + "0" * 32, "ag_000000000000", "x")         # raises 422 FORM_INVALID like the draft would
    if _whole_home_target(f):
        # 29.10 (RT-BASHRC-2910): a client older than 0.2.46 run from ~ or / sends a form whose write targets are the whole home
        # directory or machine; the witness cannot see the client's HOME, so it refuses the usual home/root shapes.
        raise Err(422, "FORM_INVALID", "form: the project is / or a home directory (or a folder above one), not a project; run "
                  "`deus-witness try` inside the project's own folder")
    return f


_HOME_LIKE = re.compile(r"|/(?:Users|home)(?:/[^/]+)?|/root|/var/root|/private/var/root")


def _whole_home_target(f) -> bool:
    """True when a write target of the form (delete.targets) is "/*", "/Users/*", "/Users/<name>/*", "/home/<name>/*", "/root/*" ..."""
    d = f.get("delete") if isinstance(f, dict) else None
    ts = d.get("targets") if isinstance(d, dict) else None
    for t in ts if isinstance(ts, list) else []:
        if isinstance(t, str) and t.endswith("/*") and _HOME_LIKE.fullmatch(t[:-2].rstrip("/")):
            return True
    return False


def _limited(ctx, key, limit, window, what):
    """0.2.39: a refused trial says WHEN the next one is possible (retry_after seconds, reset_at UTC; the Retry-After header too)."""
    wait = ctx.limiter.reset_in(key, limit, window) or 1
    at = now() + wait
    return Err(429, "RATE_LIMIT", "%s: the next one is possible in %d min (at %s UTC). A page that already opened keeps working: press its "
               "button again. Or sign up at %s/signup.html" % (what, (wait + 59) // 60, time.strftime("%H:%M", time.gmtime(at)), ctx.cfg.origin),
               extra={"retry_after": wait, "reset_at": at})


def create(ctx, b, ip):
    import base64
    from app import stats
    from app import toolmap as tm
    cfg = ctx.cfg
    ttl = int(cfg.trial_ttl_days) * 86400
    form = _form(b, int(cfg.trial_ttl_days))
    net = "trial:" + stats.net_key(ip)
    if not ctx.limiter.allowed(net, cfg.trial_per_hour, 3600):
        refusals.note(ctx, "NET_HOUR")
        raise _limited(ctx, net, cfg.trial_per_hour, 3600, "%d trial accounts per hour from one network" % cfg.trial_per_hour)
    if not ctx.limiter.allowed("trialday", cfg.trial_per_day, 86400):
        refusals.note(ctx, "TRIAL_DAY")
        raise _limited(ctx, "trialday", cfg.trial_per_day, 86400, "The daily limit of trial accounts is used up (it is a shared limit for everybody); sign up instead, free during the beta")
    expire_due(ctx)                                   # lazily, besides the hourly job
    t = now()
    aid = os.urandom(16).hex()
    claim = "dwc_" + secrets.token_urlsafe(32)
    key = "dwk_" + base64.b32encode(os.urandom(32)).decode().rstrip("=")
    agid = "ag_" + os.urandom(6).hex()
    internal = 1 if (internal_ip(ctx, ip) or b.get("internal") is True) else 0     # our own scripts say so; a stranger saying so only hides from our count
    with ctx.db.tx() as db:
        db.x("INSERT INTO accounts(id,principal,display_name,created_at,trial_until,trial_claim,trial_form,internal) VALUES(?,?,?,?,?,?,?,?)",
             (aid, "dw:" + aid, TRIAL_NAME, t, t + ttl, claim_hash(claim), json.dumps(form, sort_keys=True), internal))
        db.x("INSERT INTO agents(id,account_id,name,key_prefix,key_hash,toolmap_json,created_at) VALUES(?,?,?,?,?,?,?)",
             (agid, aid, "claude-code", key[:12], ctx.key_hash(key), json.dumps(tm.preset("claude-code")), t))
    ctx.limiter.hit(net, cfg.trial_per_hour, 3600)
    ctx.limiter.hit("trialday", cfg.trial_per_day, 86400)
    stats.first(ctx, aid, "trial")
    log("INFO", "trial created", account=aid)
    return {"api_key": key, "agent_id": agid, "claim": claim, "claim_url": "%s/trial.html#c=%s" % (cfg.origin, claim), "expires_at": t + ttl,
            "quota_per_day": cfg.trial_quota, "sent": SENT, "privacy_url": cfg.origin + "/privacy.html",
            "coverage_url": cfg.origin + "/dl/docs/coverage.html", "form": form,
            "note": "Nothing is signed yet and nothing is allowed: the first call that needs you waits for your first touch on the page "
                    "(a passkey: Touch ID / Windows Hello / phone). " + FREE_TEXT + " " + KEEP_TEXT % (cfg.trial_ttl_days, idle_days(ctx) or 90)}


def _unclaimed(ctx, claim):
    h = claim_hash(claim)
    r = ctx.db.one("SELECT * FROM accounts WHERE trial_claim=? AND trial_claimed_at IS NULL AND erased_at IS NULL", (h,)) if h else None
    if r is None or r["trial_until"] is None or r["trial_until"] <= now():
        raise Err(404, "TRIAL_UNKNOWN", "this trial link is unknown, already used or expired: run `deus-witness try` again")
    return r


def _waiting(ctx, account_id, t=None):
    t = now() if t is None else t
    out = []
    for x in ctx.db.q("SELECT rid, tool, args_preview, created_at, expires, via FROM actions WHERE account_id=? AND reason=? AND status='pending_approval' "
                      "ORDER BY created_at DESC LIMIT ?", (account_id, REASON, PENDING_MAX)):
        if x["expires"] > t:
            out.append({"rid": x["rid"], "tool": x["tool"], "args_preview": x["args_preview"] or "", "t": x["created_at"], "expires": x["expires"],
                        "from_hook": x["via"] == "hook"})
    return out


def _agent(ctx, account_id):
    return ctx.db.one("SELECT id, name FROM agents WHERE account_id=? AND disabled_at IS NULL ORDER BY created_at LIMIT 1", (account_id,))


def state(ctx, claim):
    a = _unclaimed(ctx, claim)
    ag = _agent(ctx, a["id"])
    return {"claimed": False, "expires_at": a["trial_until"], "form": json.loads(a["trial_form"] or "{}"), "agent_id": ag["id"] if ag else None,
            "waiting": _waiting(ctx, a["id"]), "sent": SENT}


def passkey_name(account_id, t=None) -> str:
    """0.2.75 (N23): the name the passkey gets on the device. Two trial accounts made the same day used to be both "Trial 2026-10-30", and
    a sign-in without a hint picked the first one of the list. Now: the minute (UTC) and the first 6 characters of the account id, the same
    id the sign-in page names when a call of that account waits."""
    return "Trial %s UTC - %s" % (time.strftime("%Y-%m-%d %H:%M", time.gmtime(time.time() if t is None else t)), short_id(account_id))


def short_id(account_id) -> str:
    return str(account_id or "")[:6].upper()


def claim_begin(ctx, claim):
    from app import auth
    a = _unclaimed(ctx, claim)
    o = auth.register_begin(ctx, passkey_name(a["id"]))
    st = ctx.db.one("SELECT state_json FROM wa_flows WHERE id=?", (o["flow_id"],))
    s = json.loads(st["state_json"])
    s["trial"] = a["id"]
    ctx.db.x("UPDATE wa_flows SET purpose='trial-claim', state_json=? WHERE id=?", (json.dumps(s), o["flow_id"]))
    return o


def claim_finish(ctx, flow_id, credential, claim, device=None):
    """The first touch: the passkey becomes the account's first key. One conditional UPDATE decides who was first (a second claim, or a
    replay of this one, finds the claim gone: 409)."""
    from app import auth
    st = auth.take_flow(ctx, flow_id, "trial-claim")
    a = _unclaimed(ctx, claim)
    if st.get("trial") != a["id"]:
        raise Err(400, "FLOW_UNKNOWN", "flow expired or unknown")
    cid, pub, sign_count = auth.verify_registration(ctx, st, credential)
    t = now()
    with ctx.db.tx() as db:
        if not db.n("UPDATE accounts SET trial_claimed_at=?, trial_claim=NULL, display_name=? WHERE id=? AND trial_claim=? AND trial_claimed_at IS NULL",
                    (t, st["display_name"], a["id"], claim_hash(claim))):
            raise Err(409, "TRIAL_CLAIMED", "this trial account already has its passkey")
        principal, kid = auth.bind_identity(ctx, db, a["id"], st["display_name"], cid, pub, sign_count, device, t, new_account=False)
    from app import stats
    stats.first(ctx, a["id"], "registration")
    ag = _agent(ctx, a["id"])
    log("INFO", "trial claimed", account=a["id"])
    return ({"id": a["id"], "principal": principal, "display_name": st["display_name"]}, {"kid_hex": kid.hex(), "short": auth.short_kid(kid)},
            {"agent_id": ag["id"] if ag else None, "form": json.loads(a["trial_form"] or "{}"), "expires_at": a["trial_until"]})


def view(ctx, acc):
    """GET /api/trial (session)."""
    r = ctx.db.one("SELECT trial_until, trial_claimed_at, trial_form FROM accounts WHERE id=?", (acc["id"],))
    if r is None or r["trial_until"] is None:
        raise Err(404, "NOT_TRIAL", "this account is not a trial account")
    ag = _agent(ctx, acc["id"])
    m = ctx.db.one("SELECT id FROM mandates WHERE agent_id=? AND status='active'", (ag["id"],)) if ag else None
    return {"expires_at": r["trial_until"], "claimed_at": r["trial_claimed_at"], "form": json.loads(r["trial_form"] or "{}"),
            "agent_id": ag["id"] if ag else None, "mandate_id": m["id"] if m else None, "waiting": _waiting(ctx, acc["id"])}


def on_mandate(ctx, acc, agent_id, mandate_id):
    """A mandate was signed on a trial account: the calls that waited for the first touch are `covered` (the waiting hook sends the same call
    again and it is judged under the signed mandate). A covered row is never an approval: it holds no receipt and allows nothing."""
    if info(ctx, acc["id"]) is None:
        return 0
    t = now()
    rows = ctx.db.q("SELECT rid, via FROM actions WHERE agent_id=? AND reason=? AND status='pending_approval'", (agent_id, REASON))
    n = ctx.db.n("UPDATE actions SET status='covered', covered_by=?, updated_at=? WHERE agent_id=? AND reason=? AND status='pending_approval'",
                 (mandate_id, t, agent_id, REASON))
    if any(r["via"] == "hook" for r in rows):
        count_touch(ctx, acc["id"], t)             # the first touch was made for a real call of the hook
    return n


def count_touch(ctx, account_id, t=None):
    """A human passkey decision on a call of the Claude Code hook (the 04.11 signal). -> the step counted or None."""
    from app import stats
    try:
        if excluded(ctx, account_id):
            return None
        t = now() if t is None else t
        if stats.first(ctx, account_id, "hook_touch", t):
            return "hook_touch"
        r = ctx.db.one("SELECT t FROM funnel_seen WHERE account_id=? AND step='hook_touch'", (account_id,))
        if r is not None and r["t"] is not None and stats.day(r["t"]) != stats.day(t) and stats.first(ctx, account_id, "hook_touch_day2", t):
            return "hook_touch_day2"
    except Exception as e:  # noqa - counting never breaks a decision
        log("ERROR", "touch count failed: " + type(e).__name__)
    return None


def status(ctx, agent):
    """2710u, GET /v1/trial/status (the agent key): `deus-witness try` asks it BEFORE making a new trial, so the previous one is retired only
    after the new one exists (a refused new trial no longer costs the working one). claimed: it has a passkey (or was kept: trial false);
    nothing secret (no claim, no key)."""
    r = ctx.db.one("SELECT trial_until, trial_claimed_at FROM accounts WHERE id=?", (agent["account_id"],))
    if r is None:
        raise Err(401, "BAD_KEY")
    trial = r["trial_until"] is not None
    claimed = r["trial_claimed_at"] is not None or not trial
    return {"trial": trial, "claimed": claimed, "expires_at": r["trial_until"]}


def retire(ctx, agent):
    """0.2.39, POST /v1/trial/retire (the agent key of a trial account that has NO passkey yet): `deus-witness try` run again replaces its
    previous, unclaimed trial account, so an older page in the browser can no longer claim an account the hook does not use (the 0.2.38
    E2E: a second `try` + a touch on the first page = the hook waited for an account nobody would ever claim). Erased like an expired one:
    no passkey ever = no journal. Gives nothing back (no claim, no key); a claimed account is never touched (409)."""
    aid = agent["account_id"]
    r = ctx.db.one("SELECT trial_until, trial_claimed_at FROM accounts WHERE id=?", (aid,))
    if r is None or r["trial_until"] is None:
        raise Err(409, "NOT_TRIAL", "this key is not the key of a trial account")
    if r["trial_claimed_at"] is not None:
        raise Err(409, "TRIAL_CLAIMED", "this trial account already has its passkey: it is yours, keep using it")
    from app import stats
    try:
        own = stats.is_own(ctx, aid)
        seen = [(x["step"], x["t"]) for x in ctx.db.q("SELECT step, t FROM funnel_seen WHERE account_id=?", (aid,))]
    except Exception:  # noqa - counting never breaks the retire
        own, seen = False, []
    if not _purge_unclaimed(ctx, aid):
        raise Err(409, "TRIAL_CLAIMED", "this trial account already has its passkey: it is yours, keep using it")
    ctx.hub.forget(aid)
    stats.forget(aid)
    for step, t in seen:                              # the same person's second `try` is not a second trial in the funnel
        stats.uncount(ctx, step, own, t)
    log("INFO", "trial retired", account=aid)
    return {"ok": True, "retired": True}


def keep(ctx, acc):
    if ctx.db.one("SELECT trial_until FROM accounts WHERE id=?", (acc["id"],))["trial_until"] is None:
        return {"ok": True, "kept": True}
    if ctx.db.one("SELECT trial_claimed_at FROM accounts WHERE id=?", (acc["id"],))["trial_claimed_at"] is None:
        raise Err(409, "TRIAL_UNCLAIMED")
    ctx.db.x("UPDATE accounts SET trial_until=NULL WHERE id=?", (acc["id"],))
    log("INFO", "trial kept", account=acc["id"])
    return {"ok": True, "kept": True}


def _purge_unclaimed(ctx, aid):
    """No passkey ever: no journal, no registry entry. Every row of the account goes, the account row too."""
    from app.account_delete import TABLES_BY_ACCOUNT
    with ctx.hub.lock(aid):
        with ctx.db.tx() as db:
            if not db.one("SELECT 1 AS k FROM accounts WHERE id=? AND trial_claimed_at IS NULL AND trial_until IS NOT NULL", (aid,)):
                return False
            for a in db.q("SELECT id FROM agents WHERE account_id=?", (aid,)):
                db.x("DELETE FROM exec_files WHERE agent_id=?", (a["id"],))
                db.x("DELETE FROM exec_roots WHERE agent_id=?", (a["id"],))
            for tb in TABLES_BY_ACCOUNT:
                db.x("DELETE FROM %s WHERE account_id=?" % tb, (aid,))
            db.x("DELETE FROM accounts WHERE id=?", (aid,))
    return True


def expire_due(ctx, t=None):
    """Erase every quick start account past its time that nobody claimed (abuse/garbage bound, kept). -> number erased.
    04.11 Open Core (a single person is free for good): a CLAIMED account (it has a passkey) is never erased by time; it is kept automatically
    (trial_until=NULL, an ordinary Free account), the person no longer has to press "Keep"."""
    from app import account_delete, stats
    t = now() if t is None else t
    flush_seen(ctx)                                   # r0288: the uses of the last hour first: a used account is never swept
    n = 0
    for r in ctx.db.q("SELECT * FROM accounts WHERE trial_until IS NOT NULL AND trial_until<=? AND erased_at IS NULL LIMIT 500", (t,)):
        try:
            if r["trial_claimed_at"] is None:
                ok = _purge_unclaimed(ctx, r["id"])
            else:
                ctx.db.x("UPDATE accounts SET trial_until=NULL WHERE id=? AND trial_claimed_at IS NOT NULL", (r["id"],))
                log("INFO", "quick start account kept (has a passkey)", account=r["id"])
                continue
            if ok:
                n += 1
                ctx.hub.forget(r["id"])
                stats.forget(r["id"])
        except Err as e:
            log("WARN", "trial not erased: " + e.code, account=r["id"])
        except Exception as e:  # noqa - one account must not stop the sweep
            log("ERROR", "trial erase failed: " + type(e).__name__, account=r["id"])
    try:
        n += idle_due(ctx, t)
    except Exception as e:  # noqa - the idle sweep must not stop the trial sweep
        log("ERROR", "idle sweep failed: " + type(e).__name__)
    return n


def _team_bound(ctx, aid):
    """A team (other people attached) or a person who signs for another team is never erased for idleness."""
    if ctx.db.one("SELECT 1 AS k FROM members WHERE account_id=? AND user_id<>? AND status<>'removed' LIMIT 1", (aid, aid)):
        return True
    for m in ctx.db.q("SELECT roles, status FROM members WHERE user_id=? AND account_id<>? AND status<>'removed'", (aid, aid)):
        if m["status"] == "active" and json.loads(m["roles"] or "[]") != ["observer"]:
            return True
    return False


def idle_due(ctx, t=None):
    """r0288: accounts with a passkey unused for DW_IDLE_DAYS: first a push (idle_warned_at), then, not sooner than DW_IDLE_WARN_DAYS after
    it and only if nothing happened since, the erase. -> number erased."""
    from app import account_delete
    d = idle_days(ctx)
    if not d:
        return 0
    t = now() if t is None else t
    warn = int(getattr(ctx.cfg, "idle_warn_days", 14))
    demo = getattr(ctx.cfg, "demo_account", "") or ""
    n = 0
    rows = ctx.db.q("SELECT a.id, a.idle_warned_at, MAX(COALESCE(a.last_hook_at,0), a.created_at, ?, COALESCE((SELECT MAX(last_used_at) "
                    "FROM credentials c WHERE c.user_id=a.id), 0)) AS last FROM accounts a WHERE a.erased_at IS NULL AND a.trial_until IS NULL "
                    "AND a.id<>?", (IDLE_FROM, demo))
    for r in rows:
        last = r["last"]
        if last > t - (d - warn) * 86400:
            continue
        aid = r["id"]
        try:
            if _team_bound(ctx, aid):
                continue
            w = r["idle_warned_at"]
            if w is None or w < last:
                ctx.db.x("UPDATE accounts SET idle_warned_at=? WHERE id=?", (t, aid))
                push = getattr(ctx, "push", None)
                if push is not None and hasattr(push, "notify_idle"):
                    push.notify_idle(aid)
                log("INFO", "idle account warned", account=aid)
                continue
            if last > t - d * 86400 or w > t - warn * 86400:
                continue
            acc = ctx.db.one("SELECT * FROM accounts WHERE id=?", (aid,))
            account_delete.erase_unasked(ctx, aid, acc, "unused for %d days" % d)
            n += 1
            log("INFO", "idle account erased", account=aid)
        except Err as e:
            log("WARN", "idle account not erased: " + e.code, account=aid)
        except Exception as e:  # noqa - one account must not stop the sweep
            log("ERROR", "idle erase failed: " + type(e).__name__, account=aid)
    return n


def make_router(ctx, client_ip, session_account, require_stepup, body):
    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse
    from app import auth

    r = APIRouter()

    def on(req):
        if not enabled(ctx):
            raise Err(404, "NOT_FOUND")

    def origin_ok(req):
        if req.headers.get("origin") != ctx.cfg.origin:
            raise Err(403, "BAD_ORIGIN", "Origin not allowed")

    @r.post("/v1/trial")
    async def trial_new(req: Request):
        on(req)
        o = req.headers.get("origin")
        if o is not None and o != ctx.cfg.origin:
            raise Err(403, "BAD_ORIGIN", "a trial is made by the client (deus-witness try), not by another site")
        if req.headers.get("authorization"):
            raise Err(400, "BAD_REQUEST", "a trial is made without a key")
        b = await body(req)
        from starlette.concurrency import run_in_threadpool
        return await run_in_threadpool(create, ctx, b, client_ip(req))

    def claim_of(req, b=None):
        c = (b or {}).get("claim") if b is not None else req.headers.get("x-dw-claim")
        if not ctx.limiter.hit("trialclaim:" + client_ip(req), 120, 60):
            raise Err(429, "RATE_LIMIT", "too many requests")
        return c

    @r.get("/api/trial/state")
    def trial_state(req: Request):
        on(req)
        return state(ctx, claim_of(req))

    @r.post("/api/trial/claim/begin")
    async def trial_claim_begin(req: Request):
        on(req)
        origin_ok(req)
        b = await body(req)
        return claim_begin(ctx, claim_of(req, b))

    @r.post("/api/trial/claim/finish")
    async def trial_claim_finish(req: Request):
        on(req)
        origin_ok(req)
        b = await body(req)
        if not isinstance(b.get("credential"), dict):
            raise Err(400, "BAD_REQUEST")
        acc, keycard, extra = claim_finish(ctx, b.get("flow_id"), b["credential"], claim_of(req, b), b.get("device"))
        resp = JSONResponse(dict(extra, account=acc, keycard=keycard, user={"id": acc["id"], "display_name": acc["display_name"]}))
        cr = ctx.db.one("SELECT id FROM credentials WHERE kid=?", (bytes.fromhex(keycard["kid_hex"]),))
        auth.start_session(ctx, resp, acc["id"], acc["id"], cr["id"] if cr else None)
        req.state.account = acc["id"]
        return resp

    @r.get("/api/trial")
    def trial_view(req: Request):
        acc = session_account(ctx, req)
        return view(ctx, acc)

    @r.post("/api/trial/keep")
    async def trial_keep(req: Request):
        acc = session_account(ctx, req, True, "owner")
        require_stepup(ctx, req, acc)
        return keep(ctx, acc)

    return r
