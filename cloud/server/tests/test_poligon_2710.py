"""27.10 polygon "people", series 1 (poligon-lyudi/OTCHET-SERIYA-1-2026-10-27.md).

O3: a call the agent stopped waiting for is marked (agent_waiting false) so the approval pages put the live call first; it is not cancelled.
O4: which commands of a newcomer's path get "Allow for 24 h" -- by design, not a bug: only the explicit list of test runners / build tools /
    file commands (app/allowances.py PROJECT_*), and never a question about a changed executed file (ESCALATE_EXEC_CHANGED)."""
import json

from app import waiting
from tests.test_allowance_0210 import Dev


def _offer(d, cmd):
    [(_, r)] = d.send(cmd)
    assert r["verdict"] == "defer", r
    o = d.offer(r["rid"])
    return r, o["eligible"], o["why_not"] or ""


def test_o4_allow24_only_for_listed_runners(client, owner, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    d = Dev(client, owner, proj.resolve())
    _, ok, why = _offer(d, "uptime")
    assert not ok and "is not a test runner, build tool or file command" in why           # an unknown program: asked each time
    _, ok, why = _offer(d, "python3 f.py")   # r0343: python3 -V is a closed form since r0341 (silent)
    assert not ok and "interpreter" in why                                               # an interpreter runs any code it is given
    for cmd in ("npm test", "npm run test", "pytest", "make test"):
        _, ok, why = _offer(d, cmd)
        assert ok, (cmd, why)


def test_o4_new_package_json_asks_once_then_npm_test_gets_24h(client, owner, tmp_path):
    """The polygon's P1: package.json written AFTER the first call -> npm test is a question about a changed executed file (no 24 h on it);
    once approved and run, package.json is confirmed and the next npm test offers "Allow for 24 h"."""
    proj = tmp_path / "proj"
    proj.mkdir()
    d = Dev(client, owner, proj.resolve())
    d.send("ls")                                                                          # the first report of the project: no package.json
    (proj / "package.json").write_text(json.dumps({"name": "p1", "scripts": {"test": "echo tests-ok"}}))
    r, ok, why = _offer(d, "npm test")
    assert r["reason"] == "ESCALATE_EXEC_CHANGED" and not ok and "ESCALATE_EXEC_CHANGED" in why
    assert owner.approve(r["rid"]).status_code == 200
    [(_, r2)] = d.send("npm test")
    assert r2["verdict"] == "allow" and client.post("/v1/actions/%s/present" % r2["rid"], headers=d.hdr).json()["result"] == "accept"
    _, ok, why = _offer(d, "npm test")
    assert ok, why


def test_o3_agent_waiting_mark(client, owner, tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    d = Dev(client, owner, proj.resolve())
    [(_, a)] = d.send("uptime")                       # its hook gave up (never polls again)
    [(_, b)] = d.send("pmset -g")                      # r0343: hostname is a closed form since r0341; its hook is long-polling for the answer
    clock = [waiting.time.time() + 100.0]              # both calls are older than the grace, the process too
    monkeypatch.setattr(waiting, "_now", lambda: clock[0])
    monkeypatch.setattr(waiting, "_started", 0.0)
    assert client.get("/v1/actions/%s?wait=1" % b["rid"], headers=d.hdr).status_code == 200
    clock[0] += 1.0                                    # s7 (Z3): a short poll is the hook's last one after FINAL_S (2 s) without a new poll
    L = {x["rid"]: x.get("agent_waiting") for x in client.get("/api/approvals").json()}
    assert L[b["rid"]] is True and L[a["rid"]] is False, L
    assert client.get("/api/approvals/" + a["rid"]).json()["agent_waiting"] is False
    assert client.get("/api/approvals/" + b["rid"]).json()["agent_waiting"] is True
    clock[0] += waiting.GRACE_S + 1                    # b's hook stops polling too
    assert client.get("/api/approvals/" + b["rid"]).json()["agent_waiting"] is False
    assert client.get("/api/approvals/" + a["rid"]).json()["status"] == "pending_approval"      # marked, not cancelled
    assert owner.approve(a["rid"]).status_code == 200                                          # and still approvable


def test_o3_unknown_right_after_start():
    waiting._polls.pop("r_X", None)
    assert waiting.state("r_X", 1000.0, now=waiting._started + 1) is None
    assert waiting.state("r_X", 1000.0, now=waiting._started + 100) is False
    waiting.note("r_X", now=waiting._started + 90)
    assert waiting.state("r_X", 1000.0, now=waiting._started + 100) is True
    assert waiting.state("r_Y", waiting._started + 95, now=waiting._started + 100) is None    # a call younger than the grace
