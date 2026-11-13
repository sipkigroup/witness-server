"""0.2.26 (OTCHET-UNATTENDED-ZHIVOY-2026-10-22, P3): an unanswered request of an earlier run of the agent and the next run.

The witness has no notion of a run (the hook sends tool_name, tool_input, cwd), so a restart frees no place in the owner's queue: the
number of questions the owner gets does not depend on restarts (test 3, the attacker's restart loop). What changes:
1. auto-freeze counts DIFFERENT refused requests: a run that retries the call refused behind requests left by an earlier run does not
   freeze the agent (it asks the owner nothing new); a flood of new questions still freezes it (test_0225 kept);
2. the refusal says why and when a place frees (the agent stops instead of trying other commands; the operator reads it in the result)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "mcp"))

from app import actions as A  # noqa: E402
from app.flow import rate
from app.hookjudge import judge as hj
from app.hookjudge.reasons import REASONS
from tests.test_0224_critique import Agent
from tests.test_0225 import defaults, flood
from tests.test_0217_judge import _body
from tests_flow.helpers import set_settings


def questions(client, agent_id):
    """Requests that reached the owner (a defer or a hold), whatever happened to them later."""
    return client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM actions WHERE agent_id=? AND (reason LIKE 'ESCALATE_%' OR hold_reason IS NOT NULL "
                                       "OR status IN ('pending_approval','held','approved','refused','expired'))", (agent_id,))["n"]


def frozen(client, agent_id):
    return bool(client.app.state.ctx.db.one("SELECT frozen_at FROM agents WHERE id=?", (agent_id,))["frozen_at"])


def test_0226_retry_behind_earlier_runs_requests_does_not_freeze(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    defaults(a)
    flood(a, 5)                                                       # run 1 leaves 5 unanswered questions (max_pending 5)
    for _run in range(3):                                             # runs 2..4 (cron every few minutes) retry their one call
        for _ in range(6):
            v, parts = a.line("make release")
            assert v == "DENY" and parts[-1][2] == "APPROVAL_RATE", parts
    assert not frozen(client, a.ag["id"])                             # 18 refusals of ONE request: not a flood (0.2.25 froze at 10)
    assert questions(client, a.ag["id"]) == 5                         # and the owner was asked nothing new


def test_0226_distinct_flood_still_freezes(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    defaults(a)
    flood(a, 5)
    for i in range(A.AUTOFREEZE_N - 2):
        a.line("make retry")                                         # repeats of one call count once
        a.line("make other%d" % i)
    assert not frozen(client, a.ag["id"])                             # 1 + 8 = 9 different requests: one short
    a.line("make other-last")
    assert frozen(client, a.ag["id"])                                 # the 10th DIFFERENT refused request freezes it
    # 0.2.89 (QA 03.11, D5): an automatic freeze refuses what would ask, not what the mandate allows by itself (was: "ls" DENY too)
    assert a.line("make after-freeze")[0] == "DENY" and a.line("ls")[0] == "ALLOW"


def test_0226_restart_loop_gives_no_more_questions(client, owner, tmp_path, monkeypatch):
    """The attacker restarts the agent (a new Claude Code session) after every few calls. Same number of questions to the owner as one long
    run, the owner's open queue never above max_pending, and it is frozen the same way."""
    asked = []                                                        # every question sent to the owner's channels
    monkeypatch.setattr(client.app.state.ctx.notify, "approval", lambda row: asked.append(row["agent_id"]))
    one = Agent(client, owner, tmp_path, name="one")
    loop = Agent(client, owner, tmp_path, name="loop")
    defaults(one)                                                     # after both: Agent() resets the account's limits
    for i in range(60):
        one.tool("Bash", {"command": "make q%d" % i})
    for run in range(12):                                             # 12 sessions x 5 calls = the same 60 different calls
        for j in range(5):
            m = run * 5 + j
            loop.tool("Bash", {"command": "make q%d" % m})
            ctx = client.app.state.ctx
            assert rate.pending_count(ctx, loop.ag["id"], A.now()) <= 5
    qa, qb = asked.count(one.ag["id"]), asked.count(loop.ag["id"])
    assert qa == qb == 5, (qa, qb)
    assert frozen(client, one.ag["id"]) and frozen(client, loop.ag["id"])


def test_0226_restart_loop_with_one_repeated_call_asks_nothing(client, owner, tmp_path):
    """Not freezing a repeater is not a way around the limit: the repeated call never becomes a question."""
    a = Agent(client, owner, tmp_path)
    defaults(a)
    flood(a, 5)
    for _run in range(20):
        a.line("make same")
    assert questions(client, a.ag["id"]) == 5 and not frozen(client, a.ag["id"])
    assert rate.pending_count(client.app.state.ctx, a.ag["id"], A.now()) == 5


def test_0226_refusal_says_why_and_when(client, owner, tmp_path):
    from app.hookjudge.mapping import default_form
    p = os.path.realpath(str(tmp_path))
    ctx = client.app.state.ctx
    ag, hdr = owner.new_agent("claude-code", "cc")
    owner.mandate(ag["id"], default_form(p))
    set_settings(ctx, owner.account["id"], max_pending=1, max_defers_hour=20)
    r1 = client.post("/v1/hook/judge", json=_body("make build", p), headers=hdr).json()
    assert r1["parts"][-1]["result"]["status"] == "pending_approval", r1     # the earlier run's question, nobody answers it
    ctx.db.x("UPDATE actions SET created_at=created_at-300 WHERE agent_id=?", (ag["id"],))     # 5 min ago
    r2 = client.post("/v1/hook/judge", json=_body("make test", p), headers=hdr).json()
    part = r2["parts"][-1]
    assert part["result"]["reason"] == "APPROVAL_RATE"
    assert REASONS["APPROVAL_RATE"][1] in part["why"] and "earlier run" in part["why"]
    assert "1 request(s) of this agent wait for the owner, the oldest for 5 min" in part["why"], part["why"]
    assert "Answer the waiting ones at " in part["why"] and part["why"].rstrip().endswith("/approve.html first"), part["why"]   # 0.2.50
    assert "a place frees in about 15 min" in part["why"], part["why"]       # TTL 900 s from its creation (created_at moved, expires not)
    assert r2["texts"]["APPROVAL_RATE"] == list(REASONS["APPROVAL_RATE"])
    assert rate.backlog(ctx, ag["id"], A.now())[0] == 1


def test_0226_backlog_hour_limit_text(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    set_settings(client.app.state.ctx, owner.account["id"], max_pending=5, max_defers_hour=2)
    a.line("make h1")
    a.line("make h2")
    ctx = client.app.state.ctx
    ctx.db.x("UPDATE actions SET status='expired' WHERE agent_id=?", (a.ag["id"],))     # nothing waits, the hour window is full
    v, parts = a.line("make h3")
    assert parts[-1][2] == "APPROVAL_RATE"
    assert rate.backlog(ctx, a.ag["id"], A.now())[0] == 0
    assert "limit of questions per hour" in rate.backlog_text(ctx, a.ag["id"], A.now())


def test_0226_hook_shows_the_witness_words(tmp_path):
    """The thin hook (client 0.2.23, unchanged) prints the part's `why`: the new words reach the agent without a client release."""
    from tests.test_hookjudge_hook import dec
    from deus_witness.hook.main import deny
    d, why = dec(deny("APPROVAL_RATE", "r_1", texts=hj.texts_for(["APPROVAL_RATE"])))
    assert d == "deny" and "APPROVAL_RATE" in why and REASONS["APPROVAL_RATE"][1] in why
