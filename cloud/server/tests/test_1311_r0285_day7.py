"""r0285 (PARALLEL-I-KVOTA-1311 p.3): the funnel step day7 -- the account's Claude Code hook still asks the witness on the 7th UTC day after
the account was made. A number per day and per account row, nothing about the person; accounts named "proba-..." (the trial on
acquaintances) are a cohort apart (day7_proba). PRED: 0.2.108 has no such step (report() has no "day7"); here: counted once, not before
day 7, own / internal accounts never, proba apart, kept_day7_with_touch = day7 AND hook_touch."""
import os

from app import stats
from app.hookjudge import judge as hj
from tests.test_0218_concurrency import _write_full, hook_agent  # noqa: F401  (fixture)


def _n(ctx, step):
    return ctx.db.one("SELECT COALESCE(SUM(n_all),0) AS a FROM funnel_daily WHERE step=?", (step,))["a"]


def test_day7_counted_once_from_the_7th_day(client, hook_agent, tmp_path, monkeypatch):
    ctx = client.app.state.ctx
    agent, _ = hook_agent
    p = os.path.realpath(str(tmp_path))
    stats._day7_from.clear()
    made = ctx.db.one("SELECT created_at FROM accounts WHERE id=?", (agent["account_id"],))["created_at"]
    day1 = made // 86400 * 86400
    for d in (0, 3, 5):                            # days 1, 4, 6: not yet
        assert stats.day7(ctx, agent["account_id"], day1 + d * 86400 + 3600) is False
    assert _n(ctx, "day7") == 0
    assert stats.day7(ctx, agent["account_id"], day1 + 6 * 86400 + 60) is True     # day 7
    assert stats.day7(ctx, agent["account_id"], day1 + 8 * 86400) is False         # once
    assert _n(ctx, "day7") == 1 and _n(ctx, "day7_proba") == 0
    stats._day7_from.clear()                                     # a restart: the table still says "seen"
    assert stats.day7(ctx, agent["account_id"], day1 + 9 * 86400) is False and _n(ctx, "day7") == 1
    r = stats.report(ctx, days=30, t=day1 + 9 * 86400)
    assert "day7" in r["steps"] and r["kept_day7_with_touch"] == {"outside": 0, "proba": 0}
    ctx.db.x("INSERT INTO funnel_seen(account_id, step, t) VALUES(?,?,?)", (agent["account_id"], "hook_touch", made))
    assert stats.report(ctx, days=30)["kept_day7_with_touch"] == {"outside": 1, "proba": 0}


def test_the_judge_counts_it(client, hook_agent, tmp_path, monkeypatch):
    ctx = client.app.state.ctx
    agent, _ = hook_agent
    p = os.path.realpath(str(tmp_path))
    stats._day7_from.clear()
    hj.judge(ctx, agent, _write_full(p, 1))
    assert _n(ctx, "day7") == 0                                  # today: day 1
    ctx.db.x("UPDATE accounts SET created_at=created_at-7*86400 WHERE id=?", (agent["account_id"],))
    stats._day7_from.clear()
    hj.judge(ctx, agent, _write_full(p, 2))
    assert _n(ctx, "day7") == 1


def test_proba_apart_and_own_never(client, hook_agent, tmp_path):
    ctx = client.app.state.ctx
    agent, _ = hook_agent
    acc = agent["account_id"]
    made = ctx.db.one("SELECT created_at FROM accounts WHERE id=?", (acc,))["created_at"]
    for name, step in (("proba-ira", "day7_proba"), ("deus-test", None)):
        ctx.db.x("DELETE FROM funnel_seen WHERE account_id=? AND step IN ('day7','day7_proba')", (acc,))
        ctx.db.x("UPDATE accounts SET display_name=? WHERE id=?", (name, acc))
        ctx.db.x("UPDATE users SET display_name=? WHERE id=?", (name, acc))
        stats._day7_from.clear()
        stats._seen.clear()
        got = stats.day7(ctx, acc, made + 7 * 86400)
        assert got is (step is not None), name
    assert _n(ctx, "day7_proba") == 1 and _n(ctx, "day7") == 0
