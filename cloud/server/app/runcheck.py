"""0.2.63 (red team RT-0.2.41 F1): the witness' side of `deus-witness run` (client 0.2.41+).

A local mark file proves only that SOME process of the run wrote it: the run id and directory are in the environment of the whole process
tree, so any subprocess (a Bash call, an injected command) can forge it. The witness counts instead:

  POST /v1/hook/run                 (agent key) -> {"run": nonce, "exp": t}: a one-time nonce for ONE run of Claude Code, bound to this agent
  POST /v1/hook/run/start           (agent key, X-DW-Run: nonce, body {"session": id}) the hook's SessionStart: starts += 1, session id kept
  POST /v1/hook/judge               (agent key, X-DW-Run: nonce) every judged PreToolUse call (an answer, not a fact round; part = null): judged += 1
  GET  /v1/hook/run/{nonce}         (agent key) -> {"starts", "judged", "sessions"}

Only a hash of the nonce is stored. A nonce of another agent counts nothing and reads as 404. Rows live RUN_TTL_S, at most MAX_OPEN open per
agent. The table is added with CREATE IF NOT EXISTS (schema.sql): a server older than 0.2.63 ignores it, so a rollback is safe; client
0.2.41's `run` then gets 404 and falls back to the local mark (and says so).
What it proves: the witness judged N calls / saw N session starts carrying this run's nonce, with this agent's key. Not that the calls were
the run's tool calls: a subprocess that has the key and the nonce can still send them (they are then judged and journaled like any call)."""
import hashlib
import json
import re
import secrets
import time

from app.context import Err

RUN_TTL_S = 86400
MAX_OPEN = 200                         # open run nonces per agent
NEW_PER_MIN = 30                       # new run nonces a minute per agent
# RT №8 N3: the same limits per ACCOUNT (sum over its agents). 2x the per-agent value: one account normally runs a few agents
# (a CI matrix), so a single agent still reaches its own cap, but N agents no longer multiply it without bound.
ACCOUNT_MAX_OPEN = 400
ACCOUNT_NEW_PER_MIN = 60
MAX_STARTS = 1000                      # RT №8 N2: starts of one run stops growing here (sessions are capped at 16)
MAX_JUDGED = 1000000                   # RT №8 N2: judged stops here (a real run is far below)
MAX_SESSIONS = 16
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{43}")
SESSION_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}")


def _h(nonce: str) -> bytes:
    return hashlib.sha256(b"dw-run1\0" + nonce.encode("ascii")).digest()


def valid(nonce) -> bool:
    return isinstance(nonce, str) and NONCE_RE.fullmatch(nonce) is not None


def purge_expired(db, t=None) -> None:
    """Expired rows go: from create(), from a read, and from the server's periodic flusher (app/db.py)."""
    db.n("DELETE FROM run_checks WHERE exp<?", (int(time.time()) if t is None else t,))


def create(ctx, agent) -> dict:
    if not ctx.limiter.hit("run:" + agent["id"], NEW_PER_MIN, 60):
        raise Err(429, "RATE_LIMIT", "at most %d new runs a minute per key" % NEW_PER_MIN)
    if not ctx.limiter.hit("runacc:" + agent["account_id"], ACCOUNT_NEW_PER_MIN, 60):
        raise Err(429, "RATE_LIMIT", "at most %d new runs a minute per account" % ACCOUNT_NEW_PER_MIN)
    t = int(time.time())
    db = ctx.db
    purge_expired(db, t)
    n = db.one("SELECT COUNT(*) AS n FROM run_checks WHERE agent_id=?", (agent["id"],))["n"]
    if db.one("SELECT COUNT(*) AS n FROM run_checks WHERE account_id=?", (agent["account_id"],))["n"] >= ACCOUNT_MAX_OPEN:
        raise Err(429, "RATE_LIMIT", "at most %d open runs per account (they expire after %d h)" % (ACCOUNT_MAX_OPEN, RUN_TTL_S // 3600))
    if n >= MAX_OPEN:
        raise Err(429, "RATE_LIMIT", "at most %d open runs per key (they expire after %d h)" % (MAX_OPEN, RUN_TTL_S // 3600))
    nonce = secrets.token_urlsafe(32)
    db.x("INSERT INTO run_checks(nonce_hash, account_id, agent_id, created_at, exp, starts, judged, sessions) VALUES(?,?,?,?,?,0,0,'[]')",
         (_h(nonce), agent["account_id"], agent["id"], t, t + RUN_TTL_S))
    return {"run": nonce, "exp": t + RUN_TTL_S}


def _row(ctx, agent, nonce):
    if not valid(nonce):
        return None
    return ctx.db.one("SELECT * FROM run_checks WHERE nonce_hash=? AND agent_id=? AND exp>=?", (_h(nonce), agent["id"], int(time.time())))


def start(ctx, agent, nonce, session) -> dict:
    r = _row(ctx, agent, nonce)
    if r is None:
        raise Err(404, "NOT_FOUND")
    sessions = json.loads(r["sessions"] or "[]")
    if isinstance(session, str) and SESSION_RE.fullmatch(session) and session not in sessions and len(sessions) < MAX_SESSIONS:
        sessions.append(session)
    ctx.db.n("UPDATE run_checks SET starts=MIN(starts+1, ?), sessions=? WHERE nonce_hash=?", (MAX_STARTS, json.dumps(sessions), r["nonce_hash"]))
    return {"ok": True}


def judged(ctx, agent, nonce) -> None:
    """A judge answer (not a fact round) for a call that carried this run's nonce. Never raises: the judge's answer is what matters."""
    try:
        if valid(nonce):
            ctx.db.n("UPDATE run_checks SET judged=MIN(judged+1, ?) WHERE nonce_hash=? AND agent_id=? AND exp>=?", (MAX_JUDGED, _h(nonce), agent["id"], int(time.time())))
    except Exception:      # noqa: BLE001
        pass


def view(ctx, agent, nonce) -> dict:
    try:
        purge_expired(ctx.db)            # RT №8 N4: a read sweeps expired rows too
    except Exception:      # noqa: BLE001
        pass
    r = _row(ctx, agent, nonce)
    if r is None:
        raise Err(404, "NOT_FOUND")
    return {"starts": r["starts"], "judged": r["judged"], "sessions": json.loads(r["sessions"] or "[]"), "exp": r["exp"]}
