"""r0297 (client 0.2.76), L2: the thin hook in Claude Code's auto mode against the real server (TestClient through HTTP, ledger, receipts
verified by the client). A witnessed allow is answered with no decision; the check after the call tells the witness whether the call ran,
and the journal row follows: PostToolUse -> executed; PermissionDenied (auto mode refused it) -> not_executed (the page: "Not run");
nothing -> consumed, nothing claimed by the client. PRED is written before each check. Server code is not changed by r0297."""
import json
import os
import sys

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))
from deus_witness import client as dwc  # noqa: E402
from deus_witness.hook import main as thin  # noqa: E402
from tests.helpers import ORIGIN  # noqa: E402
from tests.test_0216_thin import Via, agent  # noqa: E402,F401  (fixture)


@pytest.fixture
def hook(client, agent, tmp_path, monkeypatch):  # noqa: F811
    p = str(tmp_path.resolve())
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", p)
    key = agent["Authorization"][7:]
    env = {"DEUS_WITNESS_KEY": key, "CLAUDE_PROJECT_DIR": p, "DEUS_WITNESS_HOME": str(tmp_path / "dw"), "HOME": str(tmp_path / "home")}
    w = dwc.Witness(ORIGIN, key, pin_path=str(tmp_path / "pins" / "witness.json"), transport=Via(client))
    s = thin.Settings(env)
    real = thin.Witness                                   # the hook's own reporter (_reporter), its HTTP into the in-process server
    monkeypatch.setattr(thin, "Witness", lambda url, k, **kw: real(ORIGIN, k, **dict(kw, transport=Via(client))))
    return {"p": p, "w": w, "s": s, "env": env}


def _ev(h, event="PreToolUse", tid="toolu_1", mode="auto", cmd="ls"):
    return {"hook_event_name": event, "session_id": "s", "tool_use_id": tid, "permission_mode": mode, "tool_name": "Bash",
            "tool_input": {"command": cmd}, "cwd": h["p"]}


def _status(client):
    return client.app.state.ctx.db.q("SELECT status FROM actions ORDER BY created_at")[-1]["status"]


def test_auto_mode_allow_is_neutral_then_denied_is_not_run(client, hook):
    out = thin.judge(_ev(hook), hook["s"], witness=hook["w"])
    PRED = ({}, "consumed")
    assert (out, _status(client)) == PRED                      # allowed by the witness, receipt used, no decision for Claude Code
    assert thin.run(json.dumps(dict(_ev(hook, "PermissionDenied"), reason="[x]")).encode(), hook["env"]) is None
    assert _status(client) == "not_executed"


def test_auto_mode_allow_is_neutral_then_ran_is_executed(client, hook):
    thin.judge(_ev(hook, tid="toolu_2"), hook["s"], witness=hook["w"])
    thin.run(json.dumps(dict(_ev(hook, "PostToolUse", tid="toolu_2"), tool_response={})).encode(), hook["env"])
    assert _status(client) == "executed"


def test_other_modes_stay_allow_and_consumed(client, hook):
    out = thin.judge(_ev(hook, tid="toolu_3", mode="default"), hook["s"], witness=hook["w"])
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
    thin.run(json.dumps(dict(_ev(hook, "PostToolUse", tid="toolu_3", mode="default"), tool_response={})).encode(), hook["env"])
    assert _status(client) == "consumed"                       # 0.2.68 behaviour: no report request per call


def test_question_stays_hard_in_auto_mode(client, hook):
    out = thin.judge(_ev(hook, tid="toolu_4", cmd="make build > out.txt"), hook["s"], witness=hook["w"])
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"     # held for the owner: deny (ON_DEFER default), never neutral
