"""0.2.10 (PROPOSAL-07): what the hook reports for "allow this command in this project": the project (from Claude Code, not from the model),
the commands that left it, the variants of test runners and build tools; and the re-send when the owner answered with an allowance."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "mcp"))
from tests.hookfake import FakeW  # noqa: E402

from deus_witness.client import ActionResult, args_sha256
from app.hookjudge.mapping import map_event
from app.hookjudge.bashparse import classify
from deus_witness.hook.main import Settings, judge
from app.hookjudge.mapping import project_of

P = "/w/proj"


def heads(cmd, cwd=P):
    c = classify(cmd, cwd, "/home/u", project=P)
    return c.heads, c.outside


@pytest.mark.parametrize("cmd,ids", [
    ("pytest", ["pytest"]), ("pytest -q -x tests/test_a.py", ["pytest"]), ("pytest -k 'a or b' -rP", ["pytest"]),
    ("pytest -p no:cacheprovider", ["pytest"]),
    ("pytest -p evil", ["pytest [-p]"]), ("pytest -pevil", ["pytest [-p]"]), ("pytest -vp evil", ["pytest [-p]"]),
    ("pytest -c other.ini", ["pytest [-c]"]), ("pytest --config-file=x.ini", ["pytest [--config-file]"]),
    ("pytest --rootdir=/x", ["pytest [--rootdir]"]), ("pytest -o addopts=-pevil", ["pytest [-o]"]),
    ("pytest --basetemp=src", ["pytest [--basetemp]"]), ("pytest --pyargs pkg", ["pytest [--pyargs]"]),
    ("PYTEST_ADDOPTS=-pevil pytest", ["pytest [env PYTEST_ADDOPTS]"]), ("PYTHONPATH=/tmp pytest", ["pytest [env PYTHONPATH]"]),
    ("python -m pytest", ["python -m pytest"]), ("python -m pytest -p x", ["python -m pytest [-p]"]), ("python3 x.py", ["python3"]), ("python3 -c 1", ["python3 [eval]"]), ("npx jest", ["npx jest [fetch]"]), ("./pytest", ["./pytest"]), (".venv/bin/pytest", [".venv/bin/pytest"]),
    ("npm test", ["npm test"]), ("npm test --script-shell=./x", ["npm test [--script-shell]"]), ("npm run build", ["npm run"]),
    ("make", ["make"]), ("make test", ["make test"]), ("make CC=./x", ["make [vars]"]), ("make -f other.mk", ["make [-f]"]),
    ("make --eval='x:=1'", ["make [--eval]"]),
    ("cargo test", ["cargo test"]), ("cargo test --config build.rustc-wrapper=./x", ["cargo test [--config]"]),
    ("cargo -Zunstable-options test", ["cargo test [-Z]"]),
    ("go test ./...", ["go test"]), ("go test -exec ./x ./...", ["go test [-exec]"]), ("go test -toolexec=./x ./...", ["go test [-toolexec]"]),
    ("npm install", ["npm install"]), ("npm ci", ["npm ci"]), ("npm i left-pad", ["npm i [packages]"]), ("npm install -D typescript", ["npm install [packages]"]),
    ("npm install --registry=https://evil.example", ["npm install [--registry]"]), ("yarn add x", ["yarn add [packages]"]),
    ("pip install -e .", ["pip install"]), ("pip install -r requirements.txt", ["pip install"]), ("pip install .", ["pip install"]),
    ("pip install requests", ["pip install [packages]"]), ("pip install -e git+https://x.example/y", ["pip install [packages]"]),
    ("pip install --index-url https://evil.example -r requirements.txt", ["pip install [--index-url, packages]"]),
    ("python3 -m pip install x", ["python3 -m pip [packages]"]), ("pip list", ["pip list"]),
    ("timeout 60 pytest", ["pytest"]), ("xargs pytest", ["pytest [via xargs]"]), ("sudo pytest", ["sudo pytest"]),
])
def test_runner_identifiers(cmd, ids):
    assert heads(cmd)[0] == ids


@pytest.mark.parametrize("cmd,out", [
    ("pytest", []), ("cd sub && pytest", []), ("pytest tests/ ../proj/tests", []),
    ("cd /tmp && pytest", ["cd", "pytest"]), ("pytest /tmp/t.py", ["pytest"]), ("pytest ../other", ["pytest"]),
    ("pytest --rootdir=/x", ["pytest [--rootdir]"]), ("make -C /elsewhere", ["make"]), ("npm --prefix ~/x test", ["npm test"]),
    ("pytest $HOME/t.py", ["pytest"]), ("ls /etc && pytest", ["ls"]), ("bash -c 'cd /tmp; pytest'", ["cd", "pytest"]),
])
def test_outside_the_project(cmd, out):
    assert heads(cmd)[1] == out


def test_outside_when_the_session_cwd_is_elsewhere():
    assert heads("pytest", cwd="/tmp")[1] == ["pytest"]


def test_project_of(tmp_path):
    proj = tmp_path / "proj"
    (proj / "sub").mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(proj)
    rp = str(proj.resolve())
    env = {"CLAUDE_PROJECT_DIR": str(proj), "HOME": "/nonexistent"}
    assert project_of(str(proj / "sub"), env) == rp                    # a sub-folder of the session's project
    assert project_of(str(link / "sub"), env) == rp                     # a symlinked path names its target
    assert project_of(str(tmp_path), env) is None                       # the session left the project
    assert project_of(rp, {"HOME": "/nonexistent"}) == rp               # no CLAUDE_PROJECT_DIR: the cwd
    assert project_of(rp, {"CLAUDE_PROJECT_DIR": "relative/x", "HOME": "/nonexistent"}) == rp
    assert project_of(rp, {"HOME": rp}) is None                         # the home directory is not a project
    assert project_of("/", {"HOME": "/nonexistent"}) is None            # nor is the whole machine


def test_map_event_reports_project_and_outside(tmp_path):
    proj = str(tmp_path.resolve())
    env = {"CLAUDE_PROJECT_DIR": proj, "HOME": "/nonexistent"}
    [m] = map_event({"tool_name": "Bash", "tool_input": {"command": "pytest && cd /tmp && make"}, "cwd": proj}, env=env)
    w = m.args["_witness"]
    assert w["project"] == proj and w["commands"] == ["pytest", "cd", "make"] and w["outside"] == ["cd", "make"]
    [m] = map_event({"tool_name": "Bash", "tool_input": {"command": "pytest"}, "cwd": "/"}, env=env)
    assert "project" not in m.args["_witness"] and "outside" not in m.args["_witness"]
    # the model cannot name the project: `_witness` in the tool input is refused, an env assignment in the line is not the hook's env
    [m] = map_event({"tool_name": "Bash", "tool_input": {"command": "CLAUDE_PROJECT_DIR=/ pytest"}, "cwd": proj}, env=env)
    assert m.args["_witness"]["project"] == proj and m.args["_witness"]["commands"] == ["pytest [env CLAUDE_PROJECT_DIR]"]


class W(FakeW):  # 0.2.16: answers /v1/hook/judge with the real classifier, act() per part
    """The owner answers the pending call with an allowance: GET shows covered_by; the re-sent call is allowed (OK_ALLOWANCE)."""
    verify = True

    def __init__(self, covered=True):
        self.calls, self.presented, self.covered = 0, [], covered

    def act(self, tool, args, client=None, verify=None):
        self.calls += 1
        a = {"args_sha256": args_sha256(tool, args)}
        if self.calls == 1:
            return ActionResult(rid="r_1", verdict="defer", reason="ESCALATE_COMMAND", status="pending_approval", action=a, approval_url="u")
        return ActionResult(rid="r_2", verdict="allow", reason="OK_ALLOWANCE", status="allowed", action=a, raw={"allowed_by": ["al_X"]})

    def get(self, rid, wait=0):
        if self.covered:
            return ActionResult(rid="r_1", verdict="defer", reason="ESCALATE_COMMAND", status="covered", action=None, raw={"covered_by": "al_X"})
        return ActionResult(rid="r_1", verdict="defer", reason="ESCALATE_COMMAND", status="pending_approval", action=None)

    def check(self, res, sent=None):
        pass

    def present(self, rid):
        self.presented.append(rid)
        return {"result": "accept"}

    def close(self):
        pass


def test_waiting_hook_resends_once_after_an_allowance(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    s = Settings({"DEUS_WITNESS_KEY": "k", "DEUS_WITNESS_HOOK_WAIT": "3"})
    w = W()
    out = judge({"tool_name": "Bash", "tool_input": {"command": "pytest"}, "cwd": str(tmp_path)}, s, w)
    h = out["hookSpecificOutput"]
    assert h["permissionDecision"] == "allow" and "OK_ALLOWANCE" in h["permissionDecisionReason"]
    assert w.calls == 2 and w.presented == ["r_2"]


def test_waiting_hook_without_allowance_keeps_waiting(tmp_path):
    s = Settings({"DEUS_WITNESS_KEY": "k", "DEUS_WITNESS_HOOK_WAIT": "1", "DEUS_WITNESS_HOOK_TIMEOUT": "7",
                  "DEUS_WITNESS_HOOK_ON_DEFER": "ask"})      # 0.2.22: default is deny; ask set explicitly
    w = W(covered=False)
    out = judge({"tool_name": "Bash", "tool_input": {"command": "pytest"}, "cwd": str(tmp_path)}, s, w)
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask" and w.calls == 1


def test_npx_installed_in_the_project(tmp_path):
    proj = tmp_path / "p"
    (proj / "node_modules" / ".bin").mkdir(parents=True)
    (proj / "node_modules" / ".bin" / "jest").write_text("")
    (proj / "src").mkdir()
    rp = str(proj.resolve())
    assert classify("npx jest", rp + "/src", "/home/u", project=rp).heads == ["npx jest"]       # found upwards, as npx does
    assert classify("npx tsc", rp, "/home/u", project=rp).heads == ["npx tsc [fetch]"]           # not installed: npx would download it


def test_older_hook_semantics_for_a_covered_request(tmp_path):
    """status `covered` is not refused/expired: without a wait the hook answers ask, as for any open question (no deny, no run)."""
    s = Settings({"DEUS_WITNESS_KEY": "k", "DEUS_WITNESS_HOOK_ON_DEFER": "ask"})

    class Once(W):
        def act(self, tool, args, client=None, verify=None):
            self.calls += 1
            return ActionResult(rid="r_1", verdict="defer", reason="ESCALATE_COMMAND", status="covered", action={"args_sha256": args_sha256(tool, args)},
                                approval_url="u", raw={"covered_by": "al_X"})
    out = judge({"tool_name": "Bash", "tool_input": {"command": "pytest"}, "cwd": str(tmp_path)}, s, Once())
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
