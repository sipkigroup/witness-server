"""0.2.63 (RT-0.2.41 F1): the witness counts SessionStart calls and judged PreToolUse calls of one `deus-witness run` (app/runcheck.py)."""
import os
import time

import pytest

from app import _paths  # noqa: F401
from app import account_delete, runcheck
from tests_flow.helpers import set_settings


@pytest.fixture()
def two(client, owner, tmp_path):
    from app.hookjudge.mapping import default_form
    set_settings(client.app.state.ctx, owner.account["id"], max_pending=1000, max_defers_hour=10000)
    ag, hdr = owner.new_agent("claude-code", "cc")
    owner.mandate(ag["id"], default_form(os.path.realpath(str(tmp_path))))
    _, hdr2 = owner.new_agent("claude-code", "cc2")
    return hdr, hdr2


def _body(cmd, cwd, fs):
    f = {"home": "/home/u", "proc_cwd": cwd, "env": {"CLAUDE_PROJECT_DIR": cwd}, "fs": fs, "exec": "off"}
    return {"v": 1, "event": {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": cwd}, "facts": f,
            "client": {"name": "t", "version": "0"}, "part": None, "nonce": "n" * 32}


def _judge(client, hdr, p, nonce):
    rp = {p: p, "/home/u": "/home/u"}
    rounds = 0
    while True:
        r = client.post("/v1/hook/judge", json=_body("echo hi > out.txt", p, fs={"realpath": dict(rp)}), headers=dict(hdr, **{"X-DW-Run": nonce}))
        assert r.status_code == 200, r.text
        r = r.json()
        rounds += 1
        if "need" not in r:
            return rounds
        rp.update({x: x for x in r["need"].get("realpath", [])})


def test_counts_start_and_judged_calls_not_fact_rounds(client, two, tmp_path):
    hdr, _ = two
    n = client.post("/v1/hook/run", json={}, headers=hdr).json()
    assert runcheck.valid(n["run"])
    assert client.get("/v1/hook/run/" + n["run"], headers=hdr).json()["starts"] == 0
    assert client.post("/v1/hook/run/start", json={"session": "s-1"}, headers=dict(hdr, **{"X-DW-Run": n["run"]})).status_code == 200
    p = os.path.realpath(str(tmp_path))
    rounds = _judge(client, hdr, p, n["run"]) + _judge(client, hdr, p, n["run"])
    v = client.get("/v1/hook/run/" + n["run"], headers=hdr).json()
    assert v["starts"] == 1 and v["judged"] == 2 and v["sessions"] == ["s-1"] and rounds >= 2


def test_other_agent_and_bad_nonce_count_nothing(client, two, tmp_path):
    hdr, hdr2 = two
    n = client.post("/v1/hook/run", json={}, headers=hdr).json()["run"]
    assert client.post("/v1/hook/run/start", json={}, headers=dict(hdr2, **{"X-DW-Run": n})).status_code == 404
    assert client.get("/v1/hook/run/" + n, headers=hdr2).status_code == 404
    assert client.get("/v1/hook/run/" + "x" * 43, headers=hdr).status_code == 404
    assert client.post("/v1/hook/run/start", json={}, headers=dict(hdr, **{"X-DW-Run": "../../etc"})).status_code == 404
    assert client.post("/v1/hook/run", json={}).status_code == 401
    assert client.get("/v1/hook/run/" + n, headers=hdr).json()["starts"] == 0
    row = client.app.state.ctx.db.one("SELECT * FROM run_checks")
    assert n.encode() not in bytes(row["nonce_hash"]) and len(row["nonce_hash"]) == 32      # only the hash is stored


def test_rate_and_open_limits(client, two, monkeypatch):
    hdr, _ = two
    monkeypatch.setattr(runcheck, "MAX_OPEN", 3)
    codes = [client.post("/v1/hook/run", json={}, headers=hdr).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    monkeypatch.setattr(runcheck, "MAX_OPEN", 1000)
    codes = [client.post("/v1/hook/run", json={}, headers=hdr).status_code for _ in range(runcheck.NEW_PER_MIN)]
    assert 429 in codes


def test_rows_go_with_the_account_and_table_is_additive():
    assert "run_checks" in account_delete.TABLES_BY_ACCOUNT
    sql = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "schema.sql")).read()
    tail = sql[sql.index("0.2.63 (RT-0.2.41 F1)"):]
    assert "CREATE TABLE IF NOT EXISTS run_checks" in tail and "ALTER" not in tail and "DROP" not in tail


# ---------------------------------------------------------------- RT №8 regressions (N2, N3, N4)
def test_rt8_p2_counters_are_capped(client, two, tmp_path, monkeypatch):
    hdr, _ = two
    monkeypatch.setattr(runcheck, "MAX_STARTS", 5)
    monkeypatch.setattr(runcheck, "MAX_JUDGED", 3)
    n = client.post("/v1/hook/run", json={}, headers=hdr).json()["run"]
    for _ in range(50):
        client.post("/v1/hook/run/start", json={"session": "s"}, headers=dict(hdr, **{"X-DW-Run": n}))
    p = os.path.realpath(str(tmp_path))
    for _ in range(8):
        _judge(client, hdr, p, n)
    v = client.get("/v1/hook/run/" + n, headers=hdr).json()
    assert v["starts"] == 5 and v["judged"] == 3


def test_rt8_p3_open_limit_is_per_account_too(client, owner, monkeypatch):
    monkeypatch.setattr(runcheck, "MAX_OPEN", 5)
    monkeypatch.setattr(runcheck, "NEW_PER_MIN", 1000)
    monkeypatch.setattr(runcheck, "ACCOUNT_MAX_OPEN", 7)
    monkeypatch.setattr(runcheck, "ACCOUNT_NEW_PER_MIN", 1000)
    for i in range(3):
        _, hdr = owner.new_agent("claude-code", "a%d" % i)
        for _ in range(5):
            client.post("/v1/hook/run", json={}, headers=hdr)
    assert client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM run_checks")["n"] == 7


def test_rt8_p3_new_per_minute_is_per_account_too(client, owner, monkeypatch):
    monkeypatch.setattr(runcheck, "NEW_PER_MIN", 1000)
    monkeypatch.setattr(runcheck, "ACCOUNT_NEW_PER_MIN", 4)
    ok = 0
    for i in range(3):
        _, hdr = owner.new_agent("claude-code", "b%d" % i)
        ok += sum(1 for _ in range(3) if client.post("/v1/hook/run", json={}, headers=hdr).status_code == 200)
    assert ok == 4


def test_rt8_p3b_expired_rows_are_reaped_by_read_and_by_the_flusher(client, two):
    from app import db as dbmod
    hdr, _ = two
    ctx = client.app.state.ctx
    n = client.post("/v1/hook/run", json={}, headers=hdr).json()["run"]
    ctx.db.n("UPDATE run_checks SET exp=?", (int(time.time()) - 10,))
    assert client.get("/v1/hook/run/" + n, headers=hdr).status_code == 404
    assert ctx.db.one("SELECT COUNT(*) AS n FROM run_checks")["n"] == 0          # the read swept it
    client.post("/v1/hook/run", json={}, headers=hdr)
    ctx.db.n("UPDATE run_checks SET exp=?", (int(time.time()) - 10,))
    dbmod._purge_runs.__defaults__[0][0] = 0.0                                    # let the periodic sweep run now
    dbmod._purge_runs()
    assert ctx.db.one("SELECT COUNT(*) AS n FROM run_checks")["n"] == 0


# ---------------------------------------------------------------- end to end: client 0.2.41 `run` + hook against this server
def _client_mods():
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "mcp"))
    from deus_witness import run as R
    from deus_witness import client as dwc
    from deus_witness.hook import main as H
    return R, dwc, H


@pytest.mark.parametrize("case,rc_want,word", [("honest", 0, "tool calls judged 1"), ("forged", 3, "the witness saw no hook call"),
                                               ("session-only", 3, "NONE of the 1 tool call(s)")])
def test_run_end_to_end(client, two, tmp_path, monkeypatch, case, rc_want, word):
    import io
    import json
    import time
    R, dwc, H = _client_mods()
    hdr, _ = two
    key = hdr["Authorization"][7:]
    T = client._transport
    prj = tmp_path / "prj"
    prj.mkdir()
    p = os.path.realpath(str(prj))
    home = tmp_path / "home"
    info = client.get("/v1/witness").json()                 # this machine trusts this witness (a pin of its own, not a leftover)
    (tmp_path / "pins.json").write_text(json.dumps({"http://localhost:8810": {"kid_hex": info["kid_hex"], "pub_hex": info["pub_hex"]}}))
    os.chmod(str(tmp_path / "pins.json"), 0o600)
    monkeypatch.setattr(H, "Witness", lambda url, k, **kw: dwc.Witness(url, k, transport=T, pin_path=str(tmp_path / "pins.json"), **kw))

    class Claude:
        """Claude Code in-process: SessionStart hook, one Bash call through the PreToolUse hook (or a forged local mark), a transcript."""
        def __init__(self, argv, env):
            env = dict(env, DEUS_WITNESS_URL="http://localhost:8810", DEUS_WITNESS_KEY=key, HOME=str(home),
                       DEUS_WITNESS_HOME=str(tmp_path / "dw"), CLAUDE_PROJECT_DIR=p)
            if case == "forged":
                for m in ("client-session-start", "client-pretool"):
                    open(os.path.join(env["DEUS_WITNESS_RUN_DIR"], env["DEUS_WITNESS_RUN_ID"] + ".%s.1" % m), "w").close()
            else:
                assert H._run_report({"session_id": "s-e2e"}, env=env)
            if case == "honest":
                ev = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": p, "session_id": "s-e2e"}
                out = H.judge(ev, H.Settings(env))
                assert "hookSpecificOutput" in out
            d = home / ".claude" / "projects" / R._sanitize(p)
            d.mkdir(parents=True, exist_ok=True)
            ts = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() + 1))
            (d / "s-e2e.jsonl").write_text(json.dumps({"type": "assistant", "timestamp": ts, "message": {"content": [
                {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}}]}}) + "\n")

        def wait(self):
            return 0

    out = io.StringIO()
    rc = R.run(["--", "/bin/true", "-p", "hi"], env={"HOME": str(home), "PATH": "/usr/bin:/bin", "DEUS_WITNESS_HOME": str(tmp_path / "dw")},
               out=out, cwd=p, popen=Claude,
               witness=lambda e: (dwc.Witness("http://localhost:8810", key, verify=False, transport=T), None))
    assert rc == rc_want and word in out.getvalue(), out.getvalue()
