"""APPROVAL_RATE (ARHITEKTURA-0.2 §3.4): a dry `defer` from an agent that already has >= max_pending waiting DECISIONS, or >= max_defers_hour
defers in the last hour, is refused by the gateway (deny APPROVAL_RATE, nothing written to the ledger). Only turns defer -> deny.

fatigue-fix (ZAMECHANIYA 02 p.6, ZAMER-F100: 33 of 500 benign calls refused, every one by max_pending with ALL the agent's pending items
in ONE group): `max_pending` counts what the human has to decide, not rows. Pending items of one (class, recipient) form one batch group
(batch.groups: one `wb` ceremony per <= MAX_ITEMS), so a group counts ceil(n / MAX_ITEMS); a defer that joins a group with room adds
nothing. Next to it a hard cap of PENDING_ITEMS_CAP = MAX_ITEMS pending items per agent (one full batch): an agent cannot queue more
items than one page shows, whatever their grouping. `max_defers_hour` counts the same units over the defers created in the last hour
(the reference load peaks at 22 defers of one agent in an hour but only 4 groups: the item count refused 3 honest publications),
next to a hard cap of HOUR_ITEMS_CAP = 3 x MAX_ITEMS items per hour. An owner who sets a limit above a cap raises that cap with it
(max_pending 25 = up to 25 pending items, as before). 0.2.50: defaults max_pending 10, max_defers_hour 120 (were 5/20: a newcomer's session asks ~1 new command a minute, so 20 an hour ended it at minute ~20; the limit guards against a flood of UNANSWERED questions, which max_pending does)."""
from app.flow import store

CODE = "APPROVAL_RATE"
HOUR = 3600
MAX_ITEMS = 20                     # = batch.MAX_ITEMS (not imported: batch imports the ledger stack)
PENDING_ITEMS_CAP = MAX_ITEMS
HOUR_ITEMS_CAP = 3 * MAX_ITEMS


def limits(ctx, account_id):
    s = store.settings(ctx, account_id)
    return int(s["max_pending"]), int(s["max_defers_hour"])


def pending_count(ctx, agent_id, t):
    return ctx.db.one("SELECT COUNT(*) AS n FROM actions WHERE agent_id=? AND status='pending_approval' AND expires>=?", (agent_id, t))["n"]


STALE_UNHEARD_S = 600        # 0.2.90 (L2 chel01 03.11, p.1): a question nobody was told about (no push device, no channel) stops taking a
                             # place in the queue after this long: before, 10 unanswered questions filled max_pending in 10 minutes, every
                             # further call was APPROVAL_RATE at once and 10 of those froze the agent for the rest of the session


def can_hear(ctx, agent) -> bool:
    """Is there anyone a question of this agent reaches (a push device or a verified channel)? Never raises; unknown -> True (as before)."""
    try:
        from app.hookjudge.judge import notify_view
        v = notify_view(ctx, agent)
        return bool(v.get("push")) or bool(v.get("channels"))
    except Exception:      # noqa: BLE001
        return True


def pending_groups(ctx, agent_id, t, since=None):
    """-> {(class, recipient): n} of the agent's pending items (since: only those created after it, 0.2.90)."""
    q = "SELECT class, COALESCE(recipient,'') AS rcpt, COUNT(*) AS n FROM actions WHERE agent_id=? AND status='pending_approval' AND expires>=? "
    a = (agent_id, t)
    if since is not None:
        q, a = q + "AND created_at>? ", a + (since,)
    return {(r["class"], r["rcpt"]): r["n"] for r in ctx.db.q(q + "GROUP BY class, COALESCE(recipient,'')", a)}


def units(groups):
    return sum(-(-n // MAX_ITEMS) for n in groups.values())


_HOUR_WHERE = ("agent_id=? AND created_at>? AND (reason LIKE 'ESCALATE_%' OR reason='OK_APPROVED' OR status IN ('refused','pending_approval','approved'))")


def defers_last_hour(ctx, agent_id, t):
    """Defers created in the window: still pending, decided (OK_APPROVED / refused) or expired; their first reason was ESCALATE_*."""
    return ctx.db.one("SELECT COUNT(*) AS n FROM actions WHERE " + _HOUR_WHERE, (agent_id, t - HOUR))["n"]


def hour_groups(ctx, agent_id, t):
    """-> {(class, recipient): n} of the defers counted by defers_last_hour."""
    return {(r["class"], r["rcpt"]): r["n"] for r in ctx.db.q(
        "SELECT class, COALESCE(recipient,'') AS rcpt, COUNT(*) AS n FROM actions WHERE " + _HOUR_WHERE + " GROUP BY class, COALESCE(recipient,'')",
        (agent_id, t - HOUR))}


def check(ctx, agent, dry_verdict, t=None, act=None):
    """-> None | ("deny", "APPROVAL_RATE"). Looks only at a dry defer. act = the action (its class and recipient pick the group; None = a new group)."""
    if dry_verdict != "defer":
        return None
    t = store.now() if t is None else t
    max_pending, max_hour = limits(ctx, agent["account_id"])
    k = (act.get("class", ""), (act.get("recipient") or "")[:300]) if act is not None else None      # as actions stores it
    heard = can_hear(ctx, agent)
    g, h = pending_groups(ctx, agent["id"], t, since=None if heard else t - STALE_UNHEARD_S), hour_groups(ctx, agent["id"], t)
    if not heard:
        h = {}                                            # 0.2.90: the hourly cap is for a flood the owner is drowning in; nobody hears these
    if sum(g.values()) >= max(PENDING_ITEMS_CAP, max_pending) or sum(h.values()) >= max(HOUR_ITEMS_CAP, max_hour):
        return ("deny", CODE)
    for cur, cap in ((g, max_pending), (h, max_hour)):
        after = dict(cur)
        after[k] = after.get(k, 0) + 1
        if units(after) > cap:
            return ("deny", CODE)
    return None


def backlog(ctx, agent_id, t):
    """0.2.26 (P3): what an APPROVAL_RATE refusal tells the agent and its operator -> (waiting, oldest_age_s, frees_in_s). waiting = the
    agent's requests that still wait for the owner (also from an earlier run: the witness has no notion of a run, a restart frees nothing);
    frees_in_s = when the first place frees by itself (the earliest expiry of a waiting request; with nothing waiting, the hour window)."""
    r = ctx.db.one("SELECT COUNT(*) AS n, MIN(created_at) AS c, MIN(expires) AS e FROM actions WHERE agent_id=? AND status='pending_approval' "
                   "AND expires>=?", (agent_id, t))
    if r["n"]:
        return r["n"], max(0, t - (r["c"] or t)), max(0, (r["e"] or t) - t)
    h = ctx.db.one("SELECT MIN(created_at) AS c FROM actions WHERE " + _HOUR_WHERE, (agent_id, t - HOUR))["c"]
    return 0, 0, max(0, (h + HOUR - t) if h else 0)


def backlog_text(ctx, agent_id, t):
    n, age, frees = backlog(ctx, agent_id, t)
    mins = lambda s: max(1, -(-s // 60))           # noqa: E731  rounded up, at least 1
    if n:
        return ("%d request(s) of this agent wait for the owner, the oldest for %d min; a place frees in about %d min or when the owner answers"
                % (n, age // 60, mins(frees)))
    return "this agent reached the limit of questions per hour; a place frees in about %d min" % mins(frees)


APPROVAL_RATE = {"code": CODE, "settings": ("max_pending", "max_defers_hour"), "defaults": (store.DEFAULTS["max_pending"], store.DEFAULTS["max_defers_hour"]),
                 "pending_items_cap": PENDING_ITEMS_CAP, "hour_items_cap": HOUR_ITEMS_CAP}
