"""0.2.96 (plan 13.11 p.3): the guard "approved without reading" -- measured on our own data, not taken from a blog.

Per account, over the last WINDOW_S (7 days), from the decisions people make on the approval page (table decision_ux):
  - read time: from the question shown to the button pressed. The page measures it (its own clock, from the moment the question is on
    screen to the click, before the passkey prompt); the server caps it by what it saw itself (the first load of the question,
    actions.shown_at, to the decision), so a page cannot claim more reading than happened. No page value: the server's own span.
  - whether "Details" was opened before the decision (the page says; unknown = not counted in that share);
  - the share of "from now on" among the approvals.
Alarm: at least MIN_N approvals in the window and more than FAST_SHARE (90 %) of them faster than FAST_MS (2 s). The account's panel
then shows a warning. A number without its guard is a Goodhart target: the alarm needs a sample, and the panel shows the three numbers
side by side (a person who reads in the notification and approves on the page in 1 s is told, not punished: nothing is refused for it).

GET /api/ux-guard (session) -> the account's view. GET /metrics (owner token, as /internal/stats) -> Prometheus text, counts only:
no account id, no rid, no text of any call."""
import time

WINDOW_S = 7 * 86400
FAST_MS = 2000
FAST_SHARE = 0.9
MIN_N = 10
MAX_MS = 3600 * 1000
KINDS = ("once", "forward", "deny")
BUCKETS_MS = (1000, 2000, 5000, 15000, 60000)


def now():
    return int(time.time())


def page_ux(b):
    """The page's report from a decision body: {"read_ms": int, "details": bool} -> (read_ms or None, details or None)."""
    u = b.get("ux") if isinstance(b, dict) else None
    if not isinstance(u, dict):
        return None, None
    ms = u.get("read_ms")
    ms = ms if isinstance(ms, int) and not isinstance(ms, bool) and 0 <= ms <= MAX_MS else None
    d = u.get("details")
    return ms, (d if isinstance(d, bool) else None)


def mark_shown(ctx, acc_id, rid, status):
    """The first time a person's page loads a question that waits for them."""
    if status in ("pending_approval", "held"):
        try:
            ctx.db.x("UPDATE actions SET shown_at=? WHERE rid=? AND account_id=? AND shown_at IS NULL", (now(), rid, acc_id))
            # r0276b: the question's page was opened by a signed-in person, by any path (the push, the terminal's link, the list): opened
            ctx.db.x("UPDATE actions SET push_state='opened', push_state_at=? WHERE rid=? AND account_id=? AND push_state IS NOT NULL "
                     "AND push_state<>'opened'", (now(), rid, acc_id))
        except Exception:  # noqa: BLE001  a count never breaks the page
            pass


def record(ctx, acc_id, rid, kind, b, t=None):
    """One decision of a person on rid (kind once | forward | deny). Never raises; the first decision of a rid counts."""
    if kind not in KINDS or not isinstance(rid, str):
        return None
    try:
        t = now() if t is None else t
        ms, det = page_ux(b)
        r = ctx.db.one("SELECT shown_at FROM actions WHERE rid=? AND account_id=?", (rid, acc_id))
        seen = r["shown_at"] if r is not None else None
        if seen is not None:
            span = max(0, t - seen) * 1000 + 999                    # whole seconds on the server: never below the page's honest value
            ms = span if ms is None else min(ms, span)
        ctx.db.x("INSERT OR IGNORE INTO decision_ux(account_id, rid, t, kind, read_ms, details) VALUES(?,?,?,?,?,?)",
                 (acc_id, rid, t, kind, ms, None if det is None else int(det)))
        return ms
    except Exception:  # noqa: BLE001
        return None


def account_view(ctx, acc_id, t=None):
    t = now() if t is None else t
    rows = ctx.db.q("SELECT kind, read_ms, details FROM decision_ux WHERE account_id=? AND t>?", (acc_id, t - WINDOW_S))
    appr = [r for r in rows if r["kind"] in ("once", "forward")]
    timed = sorted(r["read_ms"] for r in appr if r["read_ms"] is not None)
    fast = sum(1 for x in timed if x < FAST_MS)
    det = [r["details"] for r in rows if r["details"] is not None]
    out = {"window_days": WINDOW_S // 86400, "decisions": len(rows), "approvals": len(appr),
           "denials": sum(1 for r in rows if r["kind"] == "deny"),
           "fast_share": round(fast / len(timed), 3) if timed else None,
           "median_read_ms": timed[len(timed) // 2] if timed else None,
           "details_share": round(sum(det) / len(det), 3) if det else None,
           "forward_share": round(sum(1 for r in appr if r["kind"] == "forward") / len(appr), 3) if appr else None,
           "fast_ms": FAST_MS, "alarm_share": FAST_SHARE, "min_n": MIN_N}
    out["alarm"] = bool(len(timed) >= MIN_N and fast / len(timed) > FAST_SHARE)
    if out["alarm"]:
        out["warning"] = ("In the last 7 days %d%% of your approvals took under 2 seconds from the question to the button. A question you "
                          "approve without reading protects nothing: read the first line and the danger line before you touch Allow; if "
                          "the same safe command keeps asking, \"Allow this from now on\" (narrow, for this project) is the honest answer."
                          % round(100 * fast / len(timed)))
    return out


def metrics_text(ctx, t=None):
    """Prometheus text format, counts only (no account, no rid, no text)."""
    t = now() if t is None else t
    since = t - WINDOW_S
    L = ["# HELP dw_decisions_7d Decisions on approval pages in the last 7 days, by kind.", "# TYPE dw_decisions_7d gauge"]
    by = {r["kind"]: r["n"] for r in ctx.db.q("SELECT kind, COUNT(*) AS n FROM decision_ux WHERE t>? GROUP BY kind", (since,))}
    L += ['dw_decisions_7d{kind="%s"} %d' % (k, by.get(k, 0)) for k in KINDS]
    L += ["# HELP dw_approval_read_ms_7d Approvals by the time from the question shown to the button (ms), last 7 days.",
          "# TYPE dw_approval_read_ms_7d histogram"]
    ms = [r["read_ms"] for r in ctx.db.q("SELECT read_ms FROM decision_ux WHERE t>? AND kind IN ('once','forward') AND read_ms IS NOT NULL",
                                         (since,))]
    for b in BUCKETS_MS:
        L.append('dw_approval_read_ms_7d_bucket{le="%d"} %d' % (b, sum(1 for x in ms if x <= b)))
    L += ['dw_approval_read_ms_7d_bucket{le="+Inf"} %d' % len(ms), "dw_approval_read_ms_7d_count %d" % len(ms),
          "dw_approval_read_ms_7d_sum %d" % sum(ms)]
    d = ctx.db.one("SELECT COUNT(*) AS n, SUM(details) AS k FROM decision_ux WHERE t>? AND details IS NOT NULL", (since,))
    L += ["# HELP dw_decisions_details_opened_7d Decisions made after opening Details / with a known Details state, last 7 days.",
          "# TYPE dw_decisions_details_opened_7d gauge", "dw_decisions_details_opened_7d %d" % (d["k"] or 0),
          "dw_decisions_details_known_7d %d" % d["n"]]
    accs = [r["account_id"] for r in ctx.db.q("SELECT DISTINCT account_id FROM decision_ux WHERE t>?", (since,))]
    alarms = sum(1 for a in accs if account_view(ctx, a, t)["alarm"])
    L += ["# HELP dw_accounts_unread_alarm Accounts with more than 90% of at least 10 approvals under 2 s in the last 7 days.",
          "# TYPE dw_accounts_unread_alarm gauge", "dw_accounts_unread_alarm %d" % alarms,
          "dw_accounts_deciding_7d %d" % len(accs)]
    # r0276 (SVODKA-1311 p.5): how far the phone push of a question got (HTTP 201 from the push service is only "sent"), last 7 days
    from app import push
    lc = push.ladder_counts(ctx.db, since)
    tot = sum(lc.values())
    L += ["# HELP dw_push_ladder_7d Questions pushed to a phone in the last 7 days, by the last state reached (failed, sent, received, shown, opened).",
          "# TYPE dw_push_ladder_7d gauge"] + ['dw_push_ladder_7d{state="%s"} %d' % (k, lc[k]) for k in push.LADDER]
    L += ["# HELP dw_push_ladder_share_7d The same as a share of the questions pushed (0 when none).", "# TYPE dw_push_ladder_share_7d gauge"] + \
         ['dw_push_ladder_share_7d{state="%s"} %.4f' % (k, (lc[k] / tot) if tot else 0.0) for k in push.LADDER]
    # r0310 (app/renew.py): active mandates by the reason vocabulary they pinned; stale = their questions use older sentences
    from app import renew
    try:
        bv = renew.by_vocab(ctx)
        L += ["# HELP dw_mandates_active_by_vocab Active mandates by the reason vocabulary they pinned (none = pins none: current words).",
              "# TYPE dw_mandates_active_by_vocab gauge"] + ['dw_mandates_active_by_vocab{v="%s"} %d' % (k, n) for k, n in bv["by"].items()]
        L += ["# HELP dw_mandates_stale_vocab Active mandates whose questions use older sentences than the current vocabulary.",
              "# TYPE dw_mandates_stale_vocab gauge", "dw_mandates_stale_vocab %d" % bv["stale"]]
    except Exception:  # noqa: BLE001  the metrics page never breaks on one count
        pass
    return "\n".join(L) + "\n"
