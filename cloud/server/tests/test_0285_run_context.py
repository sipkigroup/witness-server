"""0.2.85 (Ц3, AIUC-1 E015.2, SOC 2 CC8.1): the CI run context, signed by the witness, inside the evidence pack (app/runctx.py,
POST /v1/run-context, packtools/run_context.py). The CI job declares repository / commit / run / workflow / actor / start / sessions with
the agent key AND the owner's export token; the witness signs a RUN_CONTEXT record bound to the ledger position and to the decisions of
the run (by session id when the hook sent it, else by time window); the pack carries it as runs/<id>.cose.
Old client checker (0.2.54) must stay VALID on such a pack (it ignores runs/, the manifest still hashes it); an altered commit is INVALID."""
import io
import os
import shutil
import subprocess
import time
import zipfile

import cbor2
import pytest

from app import runctx
from tests.helpers import act
from tests.recovery_helpers import run_verify
from tests_flow.helpers import set_settings

MCP = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "mcp")
NONCE = "n" * 32
SHA = "0123456789abcdef0123456789abcdef01234567"


def _client_verify(folder, *flags):
    py = os.path.join(MCP, ".venv", "bin", "python")
    if not os.path.exists(py):
        pytest.skip("no mcp/.venv")
    q = subprocess.run([py, "-m", "deus_witness.verify_pack", folder, *flags], capture_output=True, text=True, timeout=120, cwd=MCP)
    return q.returncode, q.stdout + q.stderr


def _cc(client, owner, tmp_path, name="cc"):
    from app.hookjudge.mapping import default_form
    set_settings(client.app.state.ctx, owner.account["id"], max_pending=1000, max_defers_hour=10000)
    ag, hdr = owner.new_agent("claude-code", name)
    m, r = owner.mandate(ag["id"], default_form(os.path.realpath(str(tmp_path))))
    assert r.status_code == 200, r.text
    tok = owner.post("/api/export-tokens", agent_id=ag["id"], ttl_hours=1, label="ci").json()["export_token"]
    return ag, hdr, tok


def _judge(client, hdr, cwd, cmd, session=None, where="top"):
    rp = {cwd: cwd, "/home/u": "/home/u"}
    while True:
        b = {"v": 1, "event": {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": cwd},
             "facts": {"home": "/home/u", "proc_cwd": cwd, "env": {"CLAUDE_PROJECT_DIR": cwd}, "fs": {"realpath": dict(rp)}, "exec": "off"},
             "client": {"name": "t", "version": "0"}, "part": None, "nonce": NONCE}
        if session and where == "top":
            b["session_id"] = session
        elif session:
            b["event"]["session_id"] = session
        r = client.post("/v1/hook/judge", json=b, headers=hdr)
        assert r.status_code == 200, r.text
        r = r.json()
        if "need" not in r:
            return r
        rp.update({x: x for x in r["need"].get("realpath", [])})


def _declare(client, hdr, tok, **b):
    h = dict(hdr)
    if tok is not None:
        h["X-DW-Export-Token"] = tok
    return client.post("/v1/run-context", json=b, headers=h)


def _pack(client, hdr, tok, dest):
    r = client.get("/v1/export", headers=dict(hdr, **{"X-DW-Export-Token": tok}))
    assert r.status_code == 200, r.text
    zipfile.ZipFile(io.BytesIO(r.content)).extractall(dest)
    return str(dest)


def test_0285_session_link_signed_in_pack_both_checkers_valid(client, owner, tmp_path):
    p = os.path.realpath(str(tmp_path))
    ag, hdr, tok = _cc(client, owner, tmp_path)
    rids = []
    for cmd, sess, where in (("ls", "s-1", "top"), ("git status", "s-1", "event"), ("ls -la", "other", "top")):
        j = _judge(client, hdr, p, cmd, sess, where)
        rids += [x["result"]["rid"] for x in j["parts"]]
    assert len(rids) == 3
    r = _declare(client, hdr, tok, repository="acme/app", commit=SHA, run_id="123456", run_attempt="1", workflow="ci", actor="alice",
                 started_at="2026-11-02T10:00:00Z", session_ids=["s-1"])
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["link"] == "session" and j["receipts"] == 2 and j["note"] == runctx.NOTE and not j["truncated"]
    folder = _pack(client, hdr, tok, tmp_path / "pack")
    assert os.listdir(os.path.join(folder, "runs")) == [j["id"] + ".cose"]
    rc, out = run_verify(folder, "--offline")
    assert rc == 0 and out.strip().endswith("RESULT: VALID"), out
    assert "run context %s: signed by the witness at seq %d; DECLARED by the CI job: repository acme/app, commit %s, run 123456" % (j["id"], j["at_seq"], SHA) in out, out
    assert "2 decision(s) linked by session" in out and "trust: the CI run context" in out
    rc, out = _client_verify(folder, "--offline")             # client 0.2.54: knows nothing of runs/, must not fail
    assert rc == 0 and out.strip().endswith("RESULT: VALID"), out


def test_0285_altered_commit_is_invalid_for_both_checkers(client, owner, tmp_path):
    p = os.path.realpath(str(tmp_path))
    ag, hdr, tok = _cc(client, owner, tmp_path)
    _judge(client, hdr, p, "ls")
    j = _declare(client, hdr, tok, repository="acme/app", commit=SHA, started_at=int(time.time()) - 60).json()
    assert j["link"] == "window" and j["receipts"] == 1
    folder = _pack(client, hdr, tok, tmp_path / "pack")
    f = os.path.join(folder, "runs", j["id"] + ".cose")
    raw = open(f, "rb").read()
    bad = raw.replace(SHA.encode(), ("f" + SHA[1:]).encode())
    assert bad != raw
    open(f, "wb").write(bad)
    rc, out = run_verify(folder, "--offline")
    assert rc == 1 and "INVALID RUN_CONTEXT_SIG" in out and out.strip().endswith("RESULT: INVALID"), out
    rc, out = _client_verify(folder, "--offline")             # the old checker: the signed manifest hashes runs/ too
    assert rc == 1 and "MISMATCH runs/" in out and out.strip().endswith("RESULT: INVALID"), out


def _resign(folder, name, data, wk):
    """Replace one file and re-seal the manifest with the witness key (a lying or buggy server): only the run-context check can catch it."""
    import hashlib
    import json
    from svidetel_v4 import cose
    from app.export import TYP_MANIFEST
    open(os.path.join(folder, name), "wb").write(data)
    mp, sp = os.path.join(folder, "manifest.json"), os.path.join(folder, "manifest.cose")
    man = json.load(open(mp))
    man["files"][name] = hashlib.sha256(data).hexdigest()
    open(mp, "w").write(json.dumps(man, indent=1))
    signed = cose.loads(cose.verify1(open(sp, "rb").read(), [wk], TYP_MANIFEST)[0])
    signed["files"][name] = man["files"][name]
    open(sp, "wb").write(cose.sign1(wk, cbor2.dumps(signed, canonical=True), TYP_MANIFEST))


def test_0285_witness_signed_but_wrong_position_or_link_is_invalid(client, owner, tmp_path, app):
    """The checker does not trust the record's own claims about the ledger: a record re-signed by the witness key (a buggy or lying
    server) that names another position or a receipt that is not there is INVALID."""
    from svidetel_v4 import cose
    p = os.path.realpath(str(tmp_path))
    ag, hdr, tok = _cc(client, owner, tmp_path)
    _judge(client, hdr, p, "ls")
    j = _declare(client, hdr, tok, actor="bob", started_at=int(time.time()) - 60).json()
    src = _pack(client, hdr, tok, tmp_path / "pack")
    f = os.path.join(src, "runs", j["id"] + ".cose")
    payload = cose.loads(cose.verify1(open(f, "rb").read(), [app.state.ctx.wk], runctx.TYP_RUN)[0])
    wk = app.state.ctx.wk
    for i, (change, code) in enumerate(((dict(at_head=b"\0" * 32), "RUN_CONTEXT_CHAIN"), (dict(receipts=[["r_AAAAAAAAAAAAAAAA", 0]]), "RUN_CONTEXT_LINK"),
                         (dict(receipts=[[payload["receipts"][0][0], payload["at_seq"] + 1]]), "RUN_CONTEXT_LINK"),
                         (dict(extra=1), "RUN_CONTEXT_MALFORMED"))):
        d = str(tmp_path / ("t%d" % i))
        shutil.copytree(src, d)
        _resign(d, "runs/%s.cose" % j["id"], cose.sign1(wk, cbor2.dumps(dict(payload, **change), canonical=True), runctx.TYP_RUN), wk)
        rc, out = run_verify(d, "--offline")
        assert rc == 1 and code in out, (change, out)


def test_0285_auth_and_refusals(client, owner, tmp_path):
    p = os.path.realpath(str(tmp_path))
    ag, hdr, tok = _cc(client, owner, tmp_path)
    assert _declare(client, hdr, None, actor="x").json()["error"] == "EXPORT_TOKEN_INVALID"              # the agent key alone declares nothing
    assert _declare(client, {}, tok, actor="x").status_code == 401
    os.makedirs(tmp_path / "b")
    ag2, hdr2, tok2 = _cc(client, owner, tmp_path / "b", name="cc2")
    assert _declare(client, hdr2, tok, actor="x").json()["error"] == "EXPORT_TOKEN_INVALID"             # another agent's token
    _judge(client, hdr, p, "ls")
    for b, code in (({"token": "abc", "actor": "x"}, "BAD_RUN_CONTEXT"), ({}, "BAD_RUN_CONTEXT"), ({"commit": SHA.upper()}, "BAD_RUN_CONTEXT"),
                    ({"actor": "a\nb"}, "BAD_RUN_CONTEXT"), ({"actor": " a"}, "BAD_RUN_CONTEXT"), ({"started_at": "yesterday"}, "BAD_RUN_CONTEXT"),
                    ({"session_ids": ["a", "a"]}, "BAD_RUN_CONTEXT"), ({"session_ids": "s"}, "BAD_RUN_CONTEXT"),
                    ({"actor": "ghp_" + "A" * 36}, "SECRET_REFUSED"), ({"workflow": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvIn0.x"}, "SECRET_REFUSED"),
                    ({"repository": "x dwx_ABC"}, "SECRET_REFUSED"), ({"run_id": "1" * 65}, "BAD_RUN_CONTEXT")):
        r = _declare(client, hdr, tok, **b)
        assert r.status_code == 400 and r.json()["error"] == code, (b, r.text)
    stored = client.app.state.ctx.db.q("SELECT claimed_json FROM run_contexts")
    assert stored == [] or all("ghp_" not in x["claimed_json"] for x in stored)


def test_0285_empty_ledger_and_no_link(client, owner, tmp_path):
    ag, hdr = owner.new_agent()
    tok = owner.post("/api/export-tokens", agent_id=ag["id"], ttl_hours=1).json()["export_token"]
    assert _declare(client, hdr, tok, actor="x").json()["error"] == "EMPTY_LEDGER"
    owner.mandate(ag["id"])
    j = _declare(client, hdr, tok, actor="x").json()                       # no session, no start: recorded, links nothing
    assert j["link"] == "none" and j["receipts"] == 0
    act(client, hdr, "send_email", {"to": "a@example.com", "subject": "s", "body": "b"})
    j2 = _declare(client, hdr, tok, actor="x", started_at=int(time.time()) - 5).json()
    assert j2["link"] == "window" and j2["receipts"] == 1 and j2["at_seq"] > j["at_seq"]
    folder = _pack(client, hdr, tok, tmp_path / "pack")
    rc, out = run_verify(folder, "--offline")
    assert rc == 0 and "0 decision(s) linked by none" in out and "1 decision(s) linked by window" in out, out


def test_0285_tables_erased_with_the_account():
    from app.account_delete import TABLES_BY_ACCOUNT
    assert "run_contexts" in TABLES_BY_ACCOUNT and "action_sessions" in TABLES_BY_ACCOUNT
