"""0.2.39: mark accounts made by our own tests as internal AFTER the fact, and take their past counts out of the outside numbers.

    python -m app.mark_internal [--apply] [--db PATH] ID [ID ...]        ID = an agent id (ag_...) or an account id (32 hex)

Without --apply nothing is written: the plan is printed. With --apply, one transaction: for every account that is not internal yet,
its funnel steps already counted (funnel_seen) move from "outside" to "own" on their day (n_own + 1; hook_touch / hook_touch_day2 of an own
account are never counted at all, so they leave n_all), then accounts.internal = 1. Idempotent: an account already internal is skipped, so a
second run changes nothing. Touches only funnel_daily and accounts.internal; no journal, no key, no other row.

On the VPS (works with the running image, 0.2.38 too, no deploy needed): cloud/deploy/mark-internal.sh (pipes this file into the container).
The DB is the one of the running server (DW_DATA_DIR/db.sqlite); SQLite's own locking makes the write safe while it runs."""
import argparse
import os
import re
import sqlite3
import sys
import time

HOOK_STEPS = ("hook_touch", "hook_touch_day2")
AG = re.compile(r"^ag_[0-9a-f]{12}$")
ACC = re.compile(r"^[0-9a-f]{32}$")


class _DB:
    def __init__(self, con):
        self.c = con

    def one(self, sql, args=()):
        return self.c.execute(sql, args).fetchone()

    def q(self, sql, args=()):
        return self.c.execute(sql, args).fetchall()


class _Ctx:
    def __init__(self, con):
        self.db = _DB(con)


def _own(ctx, account_id):
    try:
        from app import stats
        return bool(stats.is_own(ctx, account_id))
    except ImportError:                    # outside the server tree: only the column
        r = ctx.db.one("SELECT internal FROM accounts WHERE id=?", (account_id,))
        return bool(r and r["internal"])


def _day(t):
    return time.strftime("%Y-%m-%d", time.gmtime(time.time() if t is None else t))


def resolve(con, ident):
    """-> (account_id, why) ; account_id None when unknown."""
    if AG.match(ident):
        r = con.execute("SELECT account_id FROM agents WHERE id=?", (ident,)).fetchone()
        return (r["account_id"], "agent " + ident) if r else (None, "agent %s: not found (erased already?)" % ident)
    if ACC.match(ident):
        r = con.execute("SELECT id FROM accounts WHERE id=?", (ident,)).fetchone()
        return (ident, "account") if r else (None, "account %s: not found" % ident)
    return None, "%s: not an agent id (ag_ + 12 hex) or an account id (32 hex)" % ident[:40]


def plan(con, ids):
    ctx = _Ctx(con)
    out, seen = [], set()
    for ident in ids:
        aid, why = resolve(con, ident)
        if aid is None:
            out.append({"id": ident, "skip": why})
            continue
        if aid in seen:
            out.append({"id": ident, "account": aid, "skip": "same account as above"})
            continue
        seen.add(aid)
        a = con.execute("SELECT display_name, internal FROM accounts WHERE id=?", (aid,)).fetchone()
        if a["internal"]:
            out.append({"id": ident, "account": aid, "skip": "already internal (nothing to do)"})
            continue
        own = _own(ctx, aid)
        moves = []
        if not own:                        # counted as outside so far: move each counted step
            for s in con.execute("SELECT step, t FROM funnel_seen WHERE account_id=?", (aid,)).fetchall():
                moves.append((_day(s["t"]), s["step"], "drop" if s["step"] in HOOK_STEPS else "own"))
        out.append({"id": ident, "account": aid, "name": a["display_name"], "was_own": own, "moves": moves})
    return out


def apply(con, p):
    con.execute("BEGIN IMMEDIATE")
    try:
        for x in p:
            if "skip" in x:
                continue
            if not con.execute("UPDATE accounts SET internal=1 WHERE id=? AND COALESCE(internal,0)=0", (x["account"],)).rowcount:
                continue                   # marked by someone else meanwhile: its counts are not ours to move
            for d, step, how in x["moves"]:
                if how == "drop":
                    con.execute("UPDATE funnel_daily SET n_all=MAX(0, n_all-1) WHERE day=? AND step=?", (d, step))
                else:
                    con.execute("UPDATE funnel_daily SET n_own=MIN(n_all, n_own+1) WHERE day=? AND step=?", (d, step))
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise


def main(argv=None, out=None):
    out = out or sys.stdout
    ap = argparse.ArgumentParser(prog="mark_internal", description=__doc__.split("\n\n")[0])
    ap.add_argument("ids", nargs="+")
    ap.add_argument("--apply", action="store_true", help="write (default: print the plan only)")
    ap.add_argument("--db", default=os.path.join(os.environ.get("DW_DATA_DIR") or "/data", "db.sqlite"))
    o = ap.parse_args(argv)
    if not os.path.exists(o.db):
        print("no database at %s" % o.db, file=out)
        return 2
    con = sqlite3.connect(o.db, timeout=30, isolation_level=None)
    con.row_factory = sqlite3.Row
    try:
        p = plan(con, o.ids)
        for x in p:
            if "skip" in x:
                print("SKIP %s: %s" % (x["id"], x["skip"]), file=out)
            else:
                print("MARK %s account=%s name=%r was_own=%s steps=%s" % (x["id"], x["account"], x["name"], x["was_own"],
                      ", ".join("%s %s->%s" % m for m in x["moves"]) or "none"), file=out)
        if o.apply:
            apply(con, p)
            print("applied", file=out)
        else:
            print("dry run: nothing written (add --apply)", file=out)
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
