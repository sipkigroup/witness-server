"""0.2.46: counts of 429 refusals by reason, per UTC hour (table refusals_429). Why: on the day of a launch we must SEE where newcomers
hit the limits, and the server wrote nothing about its 429s. Stored: hour (UTC, truncated), reason, account_id / agent_id when known, a counter.
NEVER stored: an IP, a request body, a key. Counted in memory, flushed by one executemany UPSERT every 10 s (no database work per refusal, no reads).
A failed flush is logged and dropped: the refusal itself is always sent."""
import threading
import time

from app.log import log

KEEP_DAYS = 14
REASONS = ("TRIAL_QUOTA",      # the daily action limit of a trial account
           "TRIAL_DAY",        # the shared daily ceiling of new trial accounts
           "AGENT_QUOTA",      # actions per day of one agent
           "ACCOUNT_QUOTA",    # actions per day of one account
           "READS_CAP",        # the ceiling of reads (class pass), per agent or per account
           "RATE_MINUTE",      # requests per minute per key
           "NET_HOUR")         # registrations / trial accounts per hour from one network


MAX_KEYS = 10000          # more distinct keys in one flush period: the rest is added to ONE key per (hour, reason): account_id "", agent_id OVERFLOW
OVERFLOW = "overflow"
FLUSH_EVERY_S = 10
_lock = threading.Lock()
_UPSERT = ("INSERT INTO refusals_429(hour,reason,account_id,agent_id,n) VALUES(?,?,?,?,?) "
           "ON CONFLICT(hour,reason,account_id,agent_id) DO UPDATE SET n=n+excluded.n")


def _buf(ctx):
    b = getattr(ctx, "_refusal_buf", None)
    if b is None:
        with _lock:
            b = getattr(ctx, "_refusal_buf", None)
            if b is None:
                b = ctx._refusal_buf = {}
    return b


def note(ctx, reason, account_id=None, agent_id=None, t=None):
    """Memory only (a flood costs a dict increment, no database); flush() writes it. Never raises."""
    try:
        h = (int(time.time()) if t is None else int(t)) // 3600 * 3600
        k = (h, reason, account_id or "", agent_id or "")
        b = _buf(ctx)
        with _lock:
            if k not in b and len(b) >= MAX_KEYS:
                k = (h, reason, "", OVERFLOW)
            b[k] = b.get(k, 0) + 1
    except Exception:  # noqa - the refusal must still be sent
        pass


def flush(ctx):
    """One executemany UPSERT of everything counted since the last flush (every FLUSH_EVERY_S seconds and at shutdown). On an error the batch is
    dropped and logged: the buffer never grows without bound. -> rows written."""
    b = _buf(ctx)
    with _lock:
        items = list(b.items())
        b.clear()
    if not items:
        return 0
    try:
        with ctx.db.lock:
            ctx.db.c.executemany(_UPSERT, [(h, r, a, g, n) for (h, r, a, g), n in items])
        return len(items)
    except Exception as e:  # noqa
        try:
            log("ERROR", "refusal count flush failed: " + type(e).__name__)
        except Exception:  # noqa
            pass
        return 0


def prune(ctx, t=None):
    """Rows older than KEEP_DAYS days (hourly job of main.py)."""
    t = int(time.time()) if t is None else int(t)
    return ctx.db.n("DELETE FROM refusals_429 WHERE hour<?", (t - KEEP_DAYS * 86400,))
