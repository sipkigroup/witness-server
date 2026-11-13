"""0.2.46 (github-action/OTCHET.md, "what blocks publishing" 1): a CI job downloads the evidence pack without a passkey session.

Choice (threat model, OTCHET-0.2.46.md): the pack is ONE account's whole hash-chained ledger (every agent of the account, its mandates and
approvals); a subset "only this agent's entries" would not verify (the chain needs every entry) and would leak the rest's hashes anyway.
So the agent key alone gets NOTHING more than before: a stolen agent key (it sits in CI secrets) must not open the account's other data.
Instead the owner, with a fresh passkey signature (step-up), issues a short export token (POST /api/export-tokens from the signed-in session; 0.2.47: dashboard Settings → Export tokens, web/settings.html):
  - read-only: it opens GET /v1/export only (no actions, no approvals, no settings);
  - bound to one agent: the request must carry that agent's key too (Bearer dwk_ + X-DW-Export-Token: dwx_...), so a token leaked from a
    log is useless alone, and disabling the agent ends the token;
  - short: 1 to 168 hours (default 24), revocable at once (DELETE), at most MAX_ACTIVE live per account;
  - stored as a hash only; shown once; every use counted (uses, last_used_at) for the owner;
  - rate: EXPORTS_PER_HOUR per token (each export appends a checkpoint to the ledger, R-16), and the account's own 6/hour bucket is not spent.
The owner knows what it opens: the same pack /api/export gives the owner (the whole account's ledger)."""
import base64
import os
import time

from app.context import Err

PREFIX = "dwx_"
TTL_DEFAULT_H = 24
TTL_MAX_H = 168
MAX_ACTIVE = 10
EXPORTS_PER_HOUR = 6
INVALID_HINT = ("an export token for this agent: issue one in the dashboard, Settings \u2192 Export tokens (settings.html), "
                "or with POST /api/export-tokens from your signed-in session")      # 0.2.47: the button exists


def _now():
    return int(time.time())


def view(r):
    return {"id": r["id"], "agent_id": r["agent_id"], "label": r["label"], "created_at": r["created_at"], "expires_at": r["expires_at"],
            "revoked_at": r["revoked_at"], "last_used_at": r["last_used_at"], "uses": r["uses"], "token_prefix": PREFIX + "…",
            "live": r["revoked_at"] is None and r["expires_at"] > _now()}


def issue(ctx, account_id, user_id, b):
    """-> (row view, token). The caller checked the session (owner), the step-up and the account lock."""
    aid = b.get("agent_id")
    a = ctx.db.one("SELECT * FROM agents WHERE id=? AND account_id=? AND disabled_at IS NULL", (aid, account_id)) if isinstance(aid, str) else None
    if a is None:
        raise Err(404, "NOT_FOUND", "agent_id: an active agent of this account")
    ttl = b.get("ttl_hours", TTL_DEFAULT_H)
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= TTL_MAX_H:
        raise Err(422, "BAD_TTL", "ttl_hours: a whole number from 1 to %d" % TTL_MAX_H)
    label = b.get("label") if isinstance(b.get("label"), str) else None
    t = _now()
    n = ctx.db.one("SELECT COUNT(*) AS n FROM export_tokens WHERE account_id=? AND revoked_at IS NULL AND expires_at>?", (account_id, t))["n"]
    if n >= MAX_ACTIVE:
        raise Err(429, "QUOTA", "%d live export tokens per account: revoke one first" % MAX_ACTIVE)
    tok = PREFIX + base64.b32encode(os.urandom(32)).decode().rstrip("=")
    tid = "xt_" + os.urandom(6).hex()
    ctx.db.x("INSERT INTO export_tokens(id,account_id,agent_id,token_hash,label,created_at,expires_at,created_by) VALUES(?,?,?,?,?,?,?,?)",
             (tid, account_id, a["id"], ctx.key_hash(tok), (label or "")[:80] or None, t, t + ttl * 3600, user_id))
    return view(ctx.db.one("SELECT * FROM export_tokens WHERE id=?", (tid,))), tok


def listing(ctx, account_id):
    return [view(r) for r in ctx.db.q("SELECT * FROM export_tokens WHERE account_id=? ORDER BY created_at DESC, id LIMIT 100", (account_id,))]


def revoke(ctx, account_id, tid):
    r = ctx.db.one("SELECT * FROM export_tokens WHERE id=? AND account_id=?", (tid, account_id))
    if r is None:
        raise Err(404, "NOT_FOUND")
    if r["revoked_at"] is None:
        ctx.db.x("UPDATE export_tokens SET revoked_at=? WHERE id=?", (_now(), tid))


def _entitled(db, account_id, user_id):
    """The issuer still holds the right that issued the token: an active member with the role owner (org.RIGHTS["owner"])."""
    import json
    from app.org import RIGHTS
    roles, statuses = RIGHTS["owner"]
    m = db.one("SELECT roles, status FROM members WHERE account_id=? AND user_id=?", (account_id, user_id)) if user_id else None
    return m is not None and m["status"] in statuses and any(r in roles for r in json.loads(m["roles"] or "[]"))


def revoke_unentitled(db, account_id):
    """0.2.46: a member removed from the team or no longer an owner (a signed policy changed the members) loses the export tokens they
    issued, at once: their live tokens are revoked. Called by org.adopt_policy inside its transaction. -> number revoked."""
    t, n = _now(), 0
    for r in db.q("SELECT id, created_by FROM export_tokens WHERE account_id=? AND revoked_at IS NULL AND expires_at>?", (account_id, t)):
        if not _entitled(db, account_id, r["created_by"]):
            db.x("UPDATE export_tokens SET revoked_at=? WHERE id=?", (t, r["id"]))
            n += 1
    return n


def check(ctx, agent, header):
    """The agent (already authenticated by its key) + the X-DW-Export-Token header -> the token row, or 401 EXPORT_TOKEN_INVALID (one
    answer for absent, unknown, another agent's, expired, revoked: the caller learns nothing about other tokens). Counts nothing
    (0.2.85: the run context declaration, app/runctx.py, uses the same owner-issued CI token without spending an export)."""
    if not isinstance(header, str) or not header.startswith(PREFIX) or len(header) > 200:
        raise Err(401, "EXPORT_TOKEN_INVALID", INVALID_HINT)
    t = _now()
    r = ctx.db.one("SELECT * FROM export_tokens WHERE token_hash=?", (ctx.key_hash(header),))
    if (r is None or r["agent_id"] != agent["id"] or r["account_id"] != agent["account_id"] or r["revoked_at"] is not None or r["expires_at"] <= t
            or not _entitled(ctx.db, r["account_id"], r["created_by"])):      # defence in depth: the issuer is no longer an owner
        raise Err(401, "EXPORT_TOKEN_INVALID", INVALID_HINT)
    return r


def take(ctx, agent, header):
    """check() + counts the use as an export (EXPORTS_PER_HOUR per token)."""
    r = check(ctx, agent, header)
    t = _now()
    if not ctx.limiter.hit("export-token:" + r["id"], EXPORTS_PER_HOUR, 3600):
        raise Err(429, "RATE_LIMIT", "%d exports per hour per export token" % EXPORTS_PER_HOUR)
    ctx.db.x("UPDATE export_tokens SET uses=uses+1, last_used_at=? WHERE id=?", (t, r["id"]))
    return r
