"""r0285 (PARALLEL-I-KVOTA-1311 p.2): what the daily quota counts, what the person is told near it and at it.

Measured on the friction stand (dev corpus, 968 calls of real Claude Code subagents, 5.6 active hours) with server 0.2.108: 1118 action
rows + 1254 hook rounds (`need`) = 2372 quota units, 2.45 per call; the hook's Read / Grep / Glob (class pass, status consumed) spent the
quota although the pages say reads do not count. PRED (before the change): (1) a hook read and a `need` round spend nothing of the action
quota; (2) the judge's answer carries `quota` from 80 % of a limit on; (3) the refusal says when the next action is possible."""
import os
import re
import time

from app import actions as act
from app.context import Err
from app.hookjudge import judge as hj
from tests.test_0218_concurrency import _need, _write_full, hook_agent  # noqa: F401  (fixture)


def _read(p, i):
    f = {"home": "/home/u", "proc_cwd": p, "env": {"CLAUDE_PROJECT_DIR": p}, "fs": {"realpath": {p: p, "/home/u": "/home/u"}}, "exec": "off"}
    b = {"v": 1, "event": {"tool_name": "Read", "tool_input": {"file_path": p + "/r%d.py" % i}, "cwd": p}, "facts": f, "part": None}
    while True:
        r = hj.classify_event(b)
        if r[0] != "need":
            return b
        b["facts"]["fs"]["realpath"].update({x: x for x in r[1].get("realpath", [])})


def test_hook_reads_and_fact_rounds_do_not_spend_the_action_quota(client, hook_agent, tmp_path, monkeypatch):
    ctx = client.app.state.ctx
    agent, _ = hook_agent
    p = os.path.realpath(str(tmp_path))
    monkeypatch.setattr(act, "QUOTA_PER_AGENT_DAY", 5)
    for i in range(8):
        r = hj.judge(ctx, agent, _read(p, i))
        assert r["parts"][0]["result"]["verdict"] == "allow", r
    for i in range(8):
        assert "need" in hj.judge(ctx, agent, _need(p, i))
    # 0.2.108: 16 units used -> the next write 429 QUOTA. Now: 5 writes fit, the 6th is refused
    for i in range(5):
        r = hj.judge(ctx, agent, _write_full(p, 100 + i))
        assert r["parts"][0]["result"]["verdict"] == "allow", r
    try:
        hj.judge(ctx, agent, _write_full(p, 200))
        raise AssertionError("the 6th write passed the limit of 5")
    except Err as e:
        assert e.status == 429 and e.code == "QUOTA"
        assert "for one agent" in e.detail and re.search(r"possible at \d\d:\d\d UTC", e.detail), e.detail
        assert "reads such as Read, Grep and Glob do not count" in e.detail


def test_near_the_limit_the_answer_says_so(client, hook_agent, tmp_path, monkeypatch):
    ctx = client.app.state.ctx
    agent, _ = hook_agent
    p = os.path.realpath(str(tmp_path))
    monkeypatch.setattr(act, "QUOTA_PER_AGENT_DAY", 10)
    seen = []
    for i in range(10):
        r = hj.judge(ctx, agent, _write_full(p, i))
        seen.append(r.get("quota"))
    assert seen[:8] == [None] * 8                      # checked BEFORE the call: 0..7 used of 10
    assert seen[8] == {"used": 8, "limit": 10, "of": "agent"} and seen[9] == {"used": 9, "limit": 10, "of": "agent"}


def test_account_limit_text_and_time(client, hook_agent, tmp_path, monkeypatch):
    ctx = client.app.state.ctx
    agent, _ = hook_agent
    p = os.path.realpath(str(tmp_path))
    monkeypatch.setattr(ctx.cfg, "quota_per_day", 3)
    t0 = int(time.time())
    for i in range(3):
        hj.judge(ctx, agent, _write_full(p, i))
    first = ctx.db.one("SELECT MIN(created_at) AS t FROM actions WHERE agent_id=?", (agent["id"],))["t"]
    try:
        hj.judge(ctx, agent, _write_full(p, 9))
        raise AssertionError("passed the account limit")
    except Err as e:
        assert e.code == "QUOTA" and "of this account" in e.detail
        assert time.strftime("%H:%M UTC", time.gmtime(first + 86400)) in e.detail, e.detail
    assert first >= t0 - 1
