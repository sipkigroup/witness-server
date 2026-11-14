"""0.2.18: the global database lock is gone (app/db.py: one writer, read connections beside it, table generations for the caches, the
round buffer). Where 0.2.17 got atomicity from that lock, these tests race real threads against the statement or transaction that keeps it now:
- one receipt presented by many threads at once: exactly one accept;
- the daily quota spent by many judges at once (rounds without an action and actions): never more than the quota, per account and per agent;
- a waiting phone (0.2.15) under concurrent cancels and level checks: one cancel wins, it never counts as a phone meanwhile;
- refresh (lazy expiry) never overwrites a status another thread set between its SELECT and its UPDATE;
- a cached key/mandate row is never served after a write to its table, even one committed while the row was being loaded."""
import os
import threading
import time

import pytest

from app import _paths  # noqa: F401
from app import actions as act
from app import keys, levels
from app.context import Err
from app.hookjudge import judge as hj
from tests_flow.helpers import set_settings

N = 16


def _race(n, fn):
    """Run fn(i) in n threads released together. -> list of (result | Exception)."""
    bar = threading.Barrier(n)
    out = [None] * n

    def run(i):
        bar.wait()
        try:
            out[i] = fn(i)
        except Exception as e:  # noqa: BLE001
            out[i] = e
    ts = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    [t.start() for t in ts]
    [t.join(60) for t in ts]
    assert not any(t.is_alive() for t in ts), "a racing thread hung"
    return out


@pytest.fixture()
def hook_agent(client, owner, tmp_path):
    from app.hookjudge.mapping import default_form
    set_settings(client.app.state.ctx, owner.account["id"], max_pending=1000, max_defers_hour=10000)
    ag, hdr = owner.new_agent("claude-code", "cc")
    owner.mandate(ag["id"], default_form(os.path.realpath(str(tmp_path))))
    return client.app.state.ctx.db.one("SELECT * FROM agents WHERE id=?", (ag["id"],)), hdr


def _write(p, i):
    f = {"home": "/home/u", "proc_cwd": p, "env": {"CLAUDE_PROJECT_DIR": p}, "fs": {"realpath": {p: p, "/home/u": "/home/u"}}, "exec": "off"}
    return {"v": 1, "event": {"tool_name": "Write", "tool_input": {"file_path": p + "/f%d.txt" % i, "content": "x"}, "cwd": p}, "facts": f, "part": None}


def _write_full(p, i):
    """r0285: a Write with every fact the classifier asks for already in it (classify_event is pure: no quota, no round)."""
    b = _write(p, i)
    while True:
        r = hj.classify_event(b)
        if r[0] != "need":
            return b
        b["facts"]["fs"]["realpath"].update({x: x for x in r[1].get("realpath", [])})


def _need(p, i):
    f = {"home": "/home/u", "proc_cwd": p, "env": {"CLAUDE_PROJECT_DIR": p}, "fs": {"realpath": {p: p, "/home/u": "/home/u"}}, "exec": "off"}
    return {"v": 1, "event": {"tool_name": "Bash", "tool_input": {"command": "cat a%d > /tmp/zz%d" % (i, i)}, "cwd": p}, "facts": f, "part": None}


def _allowed_rid(ctx, agent, p):
    b = _write(p, 0)
    while True:
        r = hj.judge(ctx, agent, b)
        if "need" not in r:
            break
        b["facts"]["fs"]["realpath"].update({x: x for x in r["need"].get("realpath", [])})
    part = r["parts"][0]["result"]
    assert part["verdict"] == "allow", part
    return part["rid"]


def test_parallel_present_of_one_receipt_accepts_exactly_once(client, hook_agent, tmp_path):
    ctx = client.app.state.ctx
    agent, _ = hook_agent
    rid = _allowed_rid(ctx, agent, os.path.realpath(str(tmp_path)))
    out = _race(N, lambda i: act.do_present(ctx, agent, rid))
    assert not [x for x in out if isinstance(x, Exception)], out
    assert sum(1 for x in out if x["result"] == "accept") == 1, out
    assert ctx.db.one("SELECT status FROM actions WHERE rid=?", (rid,))["status"] == "consumed"
    rep = _race(N, lambda i: act.do_report(ctx, agent, rid, True))           # and the report after it: one row state, no error
    assert not [x for x in rep if isinstance(x, Exception)], rep
    assert ctx.db.one("SELECT status FROM actions WHERE rid=?", (rid,))["status"] == "executed"


@pytest.mark.parametrize("which", ["account", "agent"])
def test_parallel_judges_never_spend_more_than_the_quota(client, hook_agent, tmp_path, monkeypatch, which):
    ctx = client.app.state.ctx
    agent, _ = hook_agent
    p = os.path.realpath(str(tmp_path))
    q = 9
    if which == "account":
        monkeypatch.setattr(ctx.cfg, "quota_per_day", q)
    else:
        monkeypatch.setattr(act, "QUOTA_PER_AGENT_DAY", q)
    bodies = [(_need if i % 2 else _write_full)(p, i) for i in range(3 * N)]       # r0285: even ones end in an action at once
    out = _race(3 * N, lambda i: hj.judge(ctx, agent, bodies[i]))       # rounds (`need`) and actions, mixed
    bad = [x for x in out if isinstance(x, Exception) and not (isinstance(x, Err) and x.code == "QUOTA")]
    assert not bad, bad
    ok = [x for x in out if not isinstance(x, Exception)]
    t0 = int(time.time())
    n_act = ctx.db.one("SELECT COUNT(*) AS n FROM actions WHERE agent_id=? AND created_at>?", (agent["id"], t0 - 86400))["n"]
    n_rnd = ctx.db.one("SELECT COUNT(*) AS n FROM hook_rounds WHERE agent_id=? AND t>?", (agent["id"], t0 - 86400))["n"]      # the buffer is written first
    # r0285: only actions spend the quota (rounds share the reads' ceiling): never more than q actions, every answer is an action or a round
    assert n_act == q, (n_act, n_rnd)
    assert n_act + n_rnd == len(ok)
    assert sum(1 for x in out if isinstance(x, Err)) == 3 * N - len(ok)


def test_parallel_rounds_never_pass_the_reads_ceiling(client, hook_agent, tmp_path, monkeypatch):
    """r0285: the hook's `need` rounds left the action quota; under their own ceiling (cfg.pass_per_agent_day) they stay atomic."""
    ctx = client.app.state.ctx
    agent, _ = hook_agent
    p = os.path.realpath(str(tmp_path))
    q = 9
    monkeypatch.setattr(ctx.cfg, "pass_per_agent_day", q)
    out = _race(3 * N, lambda i: hj.judge(ctx, agent, _need(p, i)))
    assert not [x for x in out if isinstance(x, Exception) and not (isinstance(x, Err) and x.code == "QUOTA")]
    n_rnd = ctx.db.one("SELECT COUNT(*) AS n FROM hook_rounds WHERE agent_id=?", (agent["id"],))["n"]
    assert n_rnd == q == sum(1 for x in out if not isinstance(x, Exception))


def test_waiting_phone_under_concurrent_cancels_and_level_checks(app):
    from tests.test_0217_recovery import _setup
    p, lost, lap, ph = _setup(app, "Ria")
    ctx = app.state.ctx
    uid = p.account["id"]
    signer = ctx.db.one("SELECT * FROM credentials WHERE kid=?", (lost.kid,))
    seen = []
    stop = threading.Event()

    def watch():
        while not stop.is_set():
            seen.append(levels.device_of_kid(ctx, ph.kid))
    w = [threading.Thread(target=watch) for _ in range(4)]
    [t.start() for t in w]
    try:
        out = _race(N, lambda i: keys.cancel_phone(ctx, uid, ph.kid, signer))
    finally:
        stop.set()
        [t.join(10) for t in w]
    won = [x for x in out if isinstance(x, dict)]
    lost_ = [x for x in out if isinstance(x, Err)]
    assert len(won) == 1 and won[0]["cancelled"] is True, out
    assert len(lost_) == N - 1 and all(e.status in (403, 404, 409) for e in lost_), [(e.status, e.code) for e in lost_]
    assert seen and set(seen) == {levels.LAPTOP}               # waiting, then cancelled: never a phone in between
    row = ctx.db.one("SELECT * FROM credentials WHERE kid=?", (ph.kid,))
    assert row["revoked_at"] is not None and row["phone_nb"] is None
    rows = ctx.db.q("SELECT entry_json FROM registry_log WHERE account_id=? AND kid=? AND entry_json LIKE '%\"cancelled\":true%'", ("keys:" + uid, ph.kid))
    assert len(rows) == 1                                      # one cancellation in the ownership chain, not one per thread


def test_refresh_never_overwrites_a_status_set_between_its_select_and_update(client, hook_agent, tmp_path, monkeypatch):
    ctx = client.app.state.ctx
    agent, _ = hook_agent
    rid = _allowed_rid(ctx, agent, os.path.realpath(str(tmp_path)))
    ctx.db.x("UPDATE actions SET status='pending_approval', expires=? WHERE rid=?", (int(time.time()) - 5, rid))
    real = ctx.db.one
    once = []

    def one(sql, args=(), **k):
        r = real(sql, args, **k)
        if sql.startswith("SELECT * FROM actions WHERE rid=?") and not once:
            once.append(1)                                     # another thread decides the action right after our SELECT
            ctx.db.x("UPDATE actions SET status='refused', updated_at=? WHERE rid=?", (int(time.time()), rid))
        return r
    monkeypatch.setattr(ctx.db, "one", one)
    x = act.refresh(ctx, rid)
    assert once and x["status"] == "refused"


def test_parallel_refresh_of_an_expired_row_expires_it_once(client, hook_agent, tmp_path):
    ctx = client.app.state.ctx
    agent, _ = hook_agent
    rid = _allowed_rid(ctx, agent, os.path.realpath(str(tmp_path)))
    ctx.db.x("UPDATE actions SET status='pending_approval', expires=? WHERE rid=?", (int(time.time()) - 5, rid))
    out = _race(N, lambda i: act.refresh(ctx, rid)["status"])
    assert set(out) == {"expired"}, out


def test_cached_rows_never_outlive_a_write_to_their_table(client, hook_agent):
    ctx = client.app.state.ctx
    db = ctx.db
    agent, hdr = hook_agent
    assert client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "ls"}}, headers=hdr).status_code == 200
    # a write committed WHILE the row is being loaded: the entry stored with the older generation is never served
    kh = db.one("SELECT key_hash FROM agents WHERE id=?", (agent["id"],))["key_hash"]
    key = ("agent_key", kh)
    db._cache.pop(key, None)

    def load():
        r = db.one("SELECT * FROM agents WHERE key_hash=? AND disabled_at IS NULL", (kh,))
        db.x("UPDATE agents SET disabled_at=? WHERE id=?", (int(time.time()), agent["id"]))      # the owner disables the key meanwhile
        return r
    assert db.cached(key, ("agents",), load) is not None
    assert client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "ls"}}, headers=hdr).status_code == 401
    # and under load: once the disabling write returns, no request of the key is accepted any more
    db.x("UPDATE agents SET disabled_at=NULL WHERE id=?", (agent["id"],))
    assert client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "ls"}}, headers=hdr).status_code == 200
    done = threading.Event()
    late = []

    def hammer(i):
        while True:
            after = done.is_set()
            a = db.cached(key, ("agents",), lambda: db.one("SELECT * FROM agents WHERE key_hash=? AND disabled_at IS NULL", (kh,)))
            if after and a is not None:
                late.append(1)
            if after:
                return
    ts = [threading.Thread(target=hammer, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    time.sleep(0.05)
    db.x("UPDATE agents SET disabled_at=? WHERE id=?", (int(time.time()), agent["id"]))
    done.set()
    [t.join(10) for t in ts]
    assert not late


def test_a_new_mandate_is_seen_at_once(client, owner, hook_agent, tmp_path):
    from app.hookjudge.mapping import default_form
    ctx = client.app.state.ctx
    agent, _ = hook_agent
    m1 = act.active_mandate(ctx, agent["id"])
    owner.mandate(agent["id"], default_form(os.path.realpath(str(tmp_path))))
    m2 = act.active_mandate(ctx, agent["id"])
    assert m2["id"] != m1["id"] and m2["status"] == "active"


def test_rounds_are_counted_before_they_are_written_and_kept_when_written(client, hook_agent, tmp_path):
    ctx = client.app.state.ctx
    agent, _ = hook_agent
    p = os.path.realpath(str(tmp_path))
    ctx.db.rounds.FLUSH_S = 3600                               # nothing is written by time during this test
    for i in range(5):
        assert "need" in hj.judge(ctx, agent, _need(p, i))
    assert len(ctx.db.rounds) == 5
    used, mine = act.rounds_used(ctx, agent, int(time.time()))      # r0285: rounds_used (they left quota_used)
    assert used == mine == 5                                   # counted from the buffer
    assert act.quota_used(ctx, agent, int(time.time())) == (0, 0)
    assert ctx.db.one("SELECT COUNT(*) AS n FROM hook_rounds WHERE agent_id=?", (agent["id"],))["n"] == 5     # a read of the table writes it first
    assert len(ctx.db.rounds) == 0
    assert act.rounds_used(ctx, agent, int(time.time())) == (5, 5)


def test_overload_is_shed_with_503_and_retry_after(cfg):
    import asyncio
    from app.main import Shed

    async def slow(scope, receive, send):
        await asyncio.sleep(0.2)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    s = Shed(slow, limit=2)
    got = []

    async def call(path="/v1/hook/judge", qs=b""):
        st = {}

        async def send(m):
            if m["type"] == "http.response.start":
                st.update(status=m["status"], headers=dict(m["headers"]))

        async def recv():
            return {"type": "http.request", "body": b"", "more_body": False}
        t = time.time()
        await s({"type": "http", "path": path, "method": "GET" if qs else "POST", "query_string": qs, "headers": []}, recv, send)
        got.append((st["status"], st["headers"].get(b"retry-after"), time.time() - t))

    async def main():
        await asyncio.gather(*[call() for _ in range(5)], call("/healthz"), call("/v1/actions/r_x", b"wait=5"), call("/v1/actions/r_y/present"))
    asyncio.run(main())
    codes = sorted(g[0] for g in got)
    assert codes.count(200) == 5 and codes.count(503) == 3     # 2 in progress + healthz + the long poll + a present (never shed); 3 shed
    assert all(g[1] == b"1" and g[2] < 0.1 for g in got if g[0] == 503)          # at once, with Retry-After
    assert s.n == 0


def test_one_key_cannot_fill_the_server(cfg):
    """A burst of one Bearer key gets 429 beyond its own share; another key is still served (no 503 for the other tenants)."""
    import asyncio
    from app.main import Shed

    async def slow(scope, receive, send):
        await asyncio.sleep(0.2)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    s = Shed(slow, limit=10, per_key=3, per_key_queue=0)      # r0285: without the per-key queue (as before it); the queue: test_1311_r0285
    got = []

    async def call(key):
        st = {}

        async def send(m):
            if m["type"] == "http.response.start":
                st["status"] = m["status"]

        async def recv():
            return {"type": "http.request", "body": b"", "more_body": False}
        await s({"type": "http", "path": "/v1/hook/judge", "method": "POST", "query_string": b"",
                 "headers": [(b"authorization", b"Bearer dwk_" + key)]}, recv, send)
        got.append((key, st["status"]))

    async def main():
        await asyncio.gather(*[call(b"burst") for _ in range(50)], *[call(b"other%d" % i) for i in range(3)])
    asyncio.run(main())
    burst = [c for k, c in got if k == b"burst"]
    assert burst.count(200) == 3 and burst.count(429) == 47
    assert [c for k, c in got if k != b"burst"] == [200, 200, 200]
    assert s.n == 0 and s.keys == {}


def test_a_judge_burst_of_one_account_is_refused_at_once_beyond_the_waiting_room(client, hook_agent, tmp_path, owner):
    """0.2.18: hj.MAX_CONCURRENT classify, hj.MAX_WAITING wait (up to hj.ENTER_WAIT_S), every other request of the account: 429 at once."""
    import asyncio
    from app import api_agent
    acc = owner.account["id"]
    for _ in range(hj.MAX_CONCURRENT):
        assert hj.enter(acc)
    try:
        async def main():
            t = time.time()
            r = await asyncio.gather(*[api_agent._enter_judge(acc) for _ in range(10)])
            return r, time.time() - t
        r, dt = asyncio.run(main())
        assert r == [False] * 10 and hj._WAITING.get(acc) is None
    finally:
        for _ in range(hj.MAX_CONCURRENT):
            hj.leave(acc)

    async def one_free():                       # a slot frees while a request waits: it gets it
        assert hj.enter(acc) and hj.enter(acc)
        w = asyncio.ensure_future(api_agent._enter_judge(acc))
        await asyncio.sleep(0.1)
        hj.leave(acc)
        ok = await w
        hj.leave(acc)
        if ok:
            hj.leave(acc)
        return ok
    assert asyncio.run(one_free()) is True and hj._RUNNING.get(acc) is None


def test_feed_before_outside_int64_is_400_not_500(client, owner):
    """found by cloud/fuzz while testing 0.2.18 (already in 0.2.17): an int64-overflowing `before` reached sqlite -> 500."""
    for b in (2 ** 63, -2 ** 63 - 1, 2 ** 70):
        r = owner.c.get("/api/feed", params={"before": b})
        assert r.status_code == 400 and r.json()["error"] == "BAD_REQUEST", r.text
    assert owner.c.get("/api/feed", params={"before": 2 ** 63 - 1}).status_code == 200
