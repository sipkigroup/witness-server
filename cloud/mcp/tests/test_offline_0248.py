"""0.2.48: the hook while the witness cannot be reached (deus_witness/hook/offline.py, cloud/OTCHET-DEGRADACIYA-STASH-0272.md).

A read of a project file runs outside the witness (no decision, a journal line, one notice); everything else is refused as before.
Threat model: the agent must not be able to make the witness "unreachable" on purpose and so read a secret or run code. Tested here:
a secret / harness / outside path, git (config-run programs), a glob, ~, cd, grep -r, jq / rg, writes, runs, network, MCP; a URL that is
not pinned, a URL that differs from the key file, a refusal of the key (401), a rate limit (429), any 4xx, a broken answer; a connection
lost AFTER the witness answered (an owner's question pending); the home directory as the "project"; a journal that cannot be written; strict.
"""
import json
import os
import socket
import threading
import time

import httpx
import pytest

from deus_witness import client as dwc
from deus_witness.hook import main as thin
from deus_witness.hook import offline

URL = "http://w.test"


@pytest.fixture()
def proj(tmp_path, monkeypatch):
    p = tmp_path / "work" / "shop"
    (p / "src").mkdir(parents=True)
    (p / "src" / "app.py").write_text("print('app')\n")
    (p / "README.md").write_text("readme\n")
    (p / ".env").write_text("TOKEN=s3cr3t\n")
    (p / "config").mkdir()
    (p / "config" / "server.key").write_text("KEY\n")
    (p / "secrets.yaml").write_text("a: b\n")
    (p / ".git").mkdir()
    (p / ".git" / "config").write_text("[core]\n\tfsmonitor = ./evil.sh\n")
    (p / ".claude").mkdir()
    (p / ".claude" / "settings.local.json").write_text("{}")
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_rsa").write_text("PEM\n")
    (p / "link").symlink_to(home / ".ssh" / "id_rsa")
    (p / "outlink").symlink_to(tmp_path)
    dw = tmp_path / "dw"
    dw.mkdir(mode=0o700)
    monkeypatch.setenv("DEUS_WITNESS_HOME", str(dw))
    return str(p.resolve()), str(home.resolve()), str(dw)


def _pin(dw, url=URL):
    pf = os.path.join(dw, "witness.json")
    with open(pf, "w") as f:
        json.dump({url: {"kid_hex": "00", "pub_hex": "00"}}, f)
    os.chmod(pf, 0o600)
    return pf


def _w(dw, handler, url=URL):
    return dwc.Witness(url, "dwk_t", pin_path=os.path.join(dw, "witness.json"), transport=httpx.MockTransport(handler))


def _down(req):
    raise httpx.ConnectError("down", request=req)


def _status(code, err="X"):
    return lambda req: httpx.Response(code, json={"error": err})


def _env(p, home, dw, **kw):
    e = {"DEUS_WITNESS_KEY": "dwk_t", "CLAUDE_PROJECT_DIR": p, "HOME": home, "DEUS_WITNESS_HOME": dw}
    e.update(kw)
    return e


def _judge(p, home, dw, tool, inp, handler=_down, pin=True, env=None, cwd=None):
    if pin:
        _pin(dw)
    s = thin.Settings(env or _env(p, home, dw))
    return thin.judge({"tool_name": tool, "tool_input": inp, "cwd": cwd or p}, s, witness=_w(dw, handler))


def _dec(o):
    h = o.get("hookSpecificOutput") or {}
    return h.get("permissionDecision"), h.get("permissionDecisionReason", "")


def _journal(dw):
    try:
        return [json.loads(x) for x in open(os.path.join(dw, offline.JOURNAL))]
    except OSError:
        return []


# ---------------------------------------------------------------- reads of project files run (no decision), journal, one notice
@pytest.mark.parametrize("tool,inp", [
    ("Read", {"file_path": "README.md"}), ("Read", {"file_path": "src/app.py", "offset": 1, "limit": 5}),
    ("NotebookRead", {"notebook_path": "src/app.py"}), ("Grep", {"pattern": "app", "path": "src"}), ("Grep", {"pattern": "app"}),
    ("Glob", {"pattern": "**/*.py"}), ("LS", {"path": "src"}),
    ("Bash", {"command": "cat README.md"}), ("Bash", {"command": "head -n 5 src/app.py | wc -l"}),
    ("Bash", {"command": "ls -la src && grep -n app src/app.py"}), ("Bash", {"command": "grep -c app src/app.py 2>/dev/null"}),
    ("Bash", {"command": "find src -name app.py"}), ("Bash", {"command": "diff README.md src/app.py"}), ("Bash", {"command": "pwd"}),
])
def test_read_runs_without_the_witness(proj, tool, inp):
    p, home, dw = proj
    if "file_path" in inp:
        inp = dict(inp, file_path=os.path.join(p, inp["file_path"]))
    if "notebook_path" in inp:
        inp = dict(inp, notebook_path=os.path.join(p, inp["notebook_path"]))
    out = _judge(p, home, dw, tool, inp)
    assert _dec(out)[0] is None, out                                   # no decision: Claude Code's own rules apply, as for `pass`
    j = _journal(dw)
    assert j and j[-1]["decision"] == "witness unreachable, local read allowed" and j[-1]["tool"] == tool
    assert "NETWORK" in j[-1]["witness"] and "README" not in json.dumps(j)      # never the arguments


def test_notice_once_then_silent_and_5xx_too(proj):
    p, home, dw = proj
    a = _judge(p, home, dw, "Read", {"file_path": p + "/README.md"})
    assert "cannot be reached" in a.get("systemMessage", "") and offline.JOURNAL in a["systemMessage"]
    b = _judge(p, home, dw, "Read", {"file_path": p + "/README.md"}, handler=_status(503, "OVERLOAD"))
    assert b == {}                                                      # told once per 10 min
    assert [x["decision"] for x in _journal(dw)] == ["witness unreachable, local read allowed"] * 2
    assert "OVERLOAD" in _journal(dw)[-1]["witness"]


# ---------------------------------------------------------------- secrets, harness, outside: refused as before
@pytest.mark.parametrize("tool,inp", [
    ("Read", {"file_path": "{p}/.env"}), ("Read", {"file_path": "{p}/config/server.key"}), ("Read", {"file_path": "{p}/secrets.yaml"}),
    ("Read", {"file_path": "{home}/.ssh/id_rsa"}), ("Read", {"file_path": "{p}/link"}), ("Read", {"file_path": "{p}/outlink/home/.ssh/id_rsa"}),
    ("Read", {"file_path": "/etc/hosts"}), ("Read", {"file_path": "{p}/../../home/.ssh/id_rsa"}), ("Read", {"file_path": "{p}/.git/config"}),
    ("Read", {"file_path": "{p}/.claude/settings.local.json"}), ("Read", {"file_path": "{dw}/agent-key.json"}),
    ("Grep", {"pattern": ".", "path": "{p}/.env"}), ("Grep", {"pattern": ".", "glob": "**/.env*"}), ("Grep", {"pattern": ".", "glob": "*.key"}),
    ("Grep", {"pattern": ".", "path": "{home}"}), ("Grep", {"pattern": ".", "glob": "../**"}), ("Glob", {"pattern": "../../**"}),
    ("Glob", {"pattern": "/etc/*"}), ("LS", {"path": "{home}/.ssh"}),
])
def test_secret_harness_outside_refused(proj, tool, inp):
    p, home, dw = proj
    inp = {k: v.format(p=p, home=home, dw=dw) for k, v in inp.items()}
    d, why = _dec(_judge(p, home, dw, tool, inp))
    assert d == "deny" and "WITNESS_UNAVAILABLE" in why and "only reading files of the project runs" in why, (inp, why)
    assert _journal(dw)[-1]["decision"] == "witness unreachable, refused"


@pytest.mark.parametrize("cmd", [
    "cat .env", "cat ~/.ssh/id_rsa", "cat link", "cat config/*", "cat ./*", "cd .. && cat x", "cd src", "git status", "git log --oneline",
    "git diff --no-ext-diff --no-textconv", "jq -n env", "jq . README.md", "rg --hidden TOKEN", "rg app", "grep -r TOKEN .", "grep -rn x src",
    "grep -R x .", "grep --recursive x .", "grep -f .env README.md", "grep --file=.env README.md", "diff -r src src", "file -f README.md",
    "cat /etc/passwd", "cat ../../home/.ssh/id_rsa", "find . -name '*.env'", "find / -name id_rsa", "find . -exec cat {} ;",
    "cat .git/config", "cat .claude/settings.local.json", "cat secrets.yaml", "head -c 100 config/server.key",
    "python3 src/app.py", "bash -c 'cat README.md'", "curl https://example.com", "cat README.md > out.txt", "touch x", "rm README.md",
    "env", "printenv", "echo $TOKEN", "cat README.md | sh", "ls `pwd`", "sort README.md", "cat $HOME/.ssh/id_rsa", "wc --files0-from=list",
    "tail -n +1 ~/.zsh_history",
])
def test_bash_beyond_plain_reads_refused(proj, cmd):
    p, home, dw = proj
    d, why = _dec(_judge(p, home, dw, "Bash", {"command": cmd}))
    assert d == "deny" and "WITNESS_UNAVAILABLE" in why, (cmd, why)


@pytest.mark.parametrize("tool,inp", [
    ("Write", {"file_path": "{p}/x.py", "content": "x"}), ("Edit", {"file_path": "{p}/README.md", "old_string": "a", "new_string": "b"}),
    ("NotebookEdit", {"notebook_path": "{p}/n.ipynb", "new_source": "x"}), ("WebFetch", {"url": "https://example.com", "prompt": "x"}),
    ("WebSearch", {"query": "x"}), ("mcp__srv__read_file", {"path": "{p}/README.md"}), ("Task", {"prompt": "read README", "description": "x"}),
    ("PowerShell", {"command": "Get-Content README.md"}),
])
def test_non_reads_refused(proj, tool, inp):
    p, home, dw = proj
    inp = {k: v.format(p=p) for k, v in inp.items()}
    d, why = _dec(_judge(p, home, dw, tool, inp))
    assert d == "deny" and "WITNESS_UNAVAILABLE" in why


# ---------------------------------------------------------------- threat model: can the agent bring the mode about itself?
def test_strict_flag_refuses_everything(proj):
    p, home, dw = proj
    for v in ("strict", "deny", "", "READ", "off"):
        d, why = _dec(_judge(p, home, dw, "Read", {"file_path": p + "/README.md"}, env=_env(p, home, dw, DEUS_WITNESS_HOOK_OFFLINE=v)))
        assert d == "deny" and "WITNESS_UNAVAILABLE" in why, v
    assert _journal(dw) == []


def test_unpinned_url_is_never_offline(proj):
    """An unreachable witness this machine never talked to (a URL the agent might point the hook at) is not 'the witness is down'."""
    p, home, dw = proj
    d, why = _dec(_judge(p, home, dw, "Read", {"file_path": p + "/README.md"}, pin=False))
    assert d == "deny" and "WITNESS_UNAVAILABLE" in why


def test_own_witness_url_mismatch_and_unpinned_are_refusals(proj, monkeypatch):
    p, home, dw = proj
    _pin(dw)
    with open(os.path.join(dw, "agent-key.json"), "w") as f:
        json.dump({"key": "dwk_t", "url": URL}, f)
    os.chmod(os.path.join(dw, "agent-key.json"), 0o600)
    ev = {"tool_name": "Read", "tool_input": {"file_path": p + "/README.md"}, "cwd": p}
    # the environment names another witness than the key file: WITNESS_URL_MISMATCH, nothing is sent, never offline
    s = thin.Settings({"CLAUDE_PROJECT_DIR": p, "HOME": home, "DEUS_WITNESS_HOME": dw, "DEUS_WITNESS_URL": "http://127.0.0.1:9"})
    d, why = _dec(thin.judge(ev, s))
    assert d == "deny" and "WITNESS_URL_MISMATCH" in why
    # no key file, a dead URL from the environment that is not pinned: WITNESS_URL_UNPINNED, never offline
    os.remove(os.path.join(dw, "agent-key.json"))
    s = thin.Settings({"DEUS_WITNESS_KEY": "dwk_t", "CLAUDE_PROJECT_DIR": p, "HOME": home, "DEUS_WITNESS_HOME": dw,
                       "DEUS_WITNESS_URL": "http://127.0.0.1:9"})
    d, why = _dec(thin.judge(ev, s))
    assert d == "deny" and ("WITNESS_URL_UNPINNED" in why or "WITNESS_UNAVAILABLE" in why)
    assert "only reading files" not in why and _journal(dw) == []       # refused as before: not the offline mode


# r0285: (429, "RATE_LIMIT") left this list: a witness busy at this moment lets a read of the project run as while unreachable
# (PARALLEL-I-KVOTA-1311 p.1 (c), tests/test_1311_r0285.py); a 429 of another kind (TOO_MANY) is still a plain refusal
@pytest.mark.parametrize("code,err", [(401, "BAD_KEY"), (403, "FORBIDDEN"), (404, "NOT_FOUND"), (409, "X"), (429, "TOO_MANY"), (400, "BAD")])
def test_refusals_and_4xx_are_not_unreachable(proj, code, err):
    p, home, dw = proj
    d, why = _dec(_judge(p, home, dw, "Read", {"file_path": p + "/README.md"}, handler=_status(code, err)))
    assert d == "deny"
    assert _journal(dw) == []


def test_broken_answer_is_not_unreachable(proj):
    p, home, dw = proj
    for body in ({"v": 2}, {"v": 1, "parts": [{"tool": 1}]}, {"v": 1, "need": {"realpath": "x"}}):
        def h(req, body=body):
            return httpx.Response(200, json=body if req.url.path == "/v1/hook/judge" else {"kid_hex": "00", "pub_hex": "00"})
        _pin(dw)
        s = thin.Settings(_env(p, home, dw, DEUS_WITNESS_VERIFY="0"))
        w = _w(dw, h)
        w.verify = False
        d, why = _dec(thin.judge({"tool_name": "Read", "tool_input": {"file_path": p + "/README.md"}, "cwd": p}, s, witness=w))
        assert d == "deny" and "WITNESS_UNAVAILABLE" not in why, why
    assert _journal(dw) == []


def test_connection_lost_after_the_witness_answered_is_refused(proj):
    """The witness asked the owner about this read (defer) and the connection dropped while the hook waited: never let through."""
    p, home, dw = proj
    _pin(dw)
    st = {}
    calls = {"n": 0}

    class W:
        url = URL
        verify = False

        def _read_pins(self):
            return {URL: {}}

        def hook_judge(self, body):
            calls["n"] += 1
            st["answered_seen"] = True
            raise dwc.WitnessError(0, "NETWORK")
    state = {"answered": True}
    s = thin.Settings(_env(p, home, dw))
    out = thin.unreachable({"tool_name": "Read", "tool_input": {"file_path": p + "/README.md"}, "cwd": p}, s, dict(state, pinned=True),
                           "WITNESS_UNAVAILABLE NETWORK", thin.deny("WITNESS_UNAVAILABLE", detail="NETWORK"))
    assert _dec(out)[0] == "deny"
    # and through judge(): a defer answer, then the poll fails
    from deus_witness.client import args_sha256

    class W2(W):
        def hook_judge(self, body):
            inp = body["event"]["tool_input"]
            return {"v": 1, "parts": [{"i": 0, "tool": "Read", "args": dict(inp), "summary": "Read",
                                       "result": {"rid": "r_1", "verdict": "defer", "reason": "ESCALATE_X", "status": "pending_approval",
                                                  "action": {"args_sha256": args_sha256("Read", inp)}}}]}

        def get(self, rid, wait=0):
            raise dwc.WitnessError(0, "NETWORK")

        def scan_list(self, *a, **k):
            return None
    s = thin.Settings(_env(p, home, dw, DEUS_WITNESS_HOOK_WAIT="5", DEUS_WITNESS_HOOK_TIMEOUT="12"))
    st2 = {}
    d, why = _dec(thin.judge({"tool_name": "Read", "tool_input": {"file_path": p + "/README.md"}, "cwd": p}, s, witness=W2(), state=st2))
    assert d == "deny" and st2.get("answered") is True, why
    assert _journal(dw) == []


def test_home_or_root_is_no_project(proj, tmp_path):
    p, home, dw = proj
    (tmp_path / "home" / "notes.txt").write_text("x")
    for root in (home, "/"):
        env = _env(root, home, dw)
        d, why = _dec(_judge(p, home, dw, "Read", {"file_path": os.path.join(home, "notes.txt")}, env=env, cwd=home))
        assert d == "deny" and "no project directory" in why, root


def test_journal_unwritable_refuses(proj, monkeypatch):
    p, home, dw = proj
    monkeypatch.setattr(offline, "journal", lambda *a, **k: None)
    d, why = _dec(_judge(p, home, dw, "Read", {"file_path": p + "/README.md"}))
    assert d == "deny" and "WITNESS_UNAVAILABLE" in why


def test_secret_names_equal_the_servers():
    """The offline list is the server's (server/app/hookjudge/bashparse.py, mapping.py): a test keeps them equal."""
    import re
    root = os.path.join(os.path.dirname(__file__), "..", "..", "server", "app", "hookjudge")
    if not os.path.isdir(root):
        pytest.skip("no server tree")
    bp = open(os.path.join(root, "bashparse.py")).read()
    mp = open(os.path.join(root, "mapping.py")).read()
    for name, rx in (("SECRET_NAME", offline.SECRET_NAME), ("SECRET_DIR", offline.SECRET_DIR)):
        m = re.search(r"^%s = re\.compile\((.*?), re\.I\)" % name, bp, re.S | re.M)
        lit = re.sub(r"(?<=\")\s*#[^\n]*", "", m.group(1)) if m else ""      # a comment between the literals
        assert m and eval(lit.replace("\n", " ")) == rx.pattern, name      # noqa: S307  the literal of a regex
    m = re.search(r"^SECRET_SAMPLES = (\(.*?\))\n", mp, re.S | re.M)
    assert m and eval(m.group(1)) == offline.CREDENTIAL_NAMES                       # noqa: S307


# ---------------------------------------------------------------- real I/O: a hanging witness (timeout) and a dead one
@pytest.fixture()
def silent_server():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(16)
    conns, stop = [], threading.Event()

    def loop():
        s.settimeout(0.2)
        while not stop.is_set():
            try:
                conns.append(s.accept()[0])
            except OSError:
                pass
    threading.Thread(target=loop, daemon=True).start()
    yield "http://127.0.0.1:%d" % s.getsockname()[1]
    stop.set()
    for c in conns:
        c.close()
    s.close()


def test_hanging_pinned_witness_times_out_into_a_local_read(proj, silent_server):
    p, home, dw = proj
    _pin(dw, silent_server)
    env = _env(p, home, dw, DEUS_WITNESS_URL=silent_server, DEUS_WITNESS_HOOK_TIMEOUT="2")
    t = time.monotonic()
    out = thin.run(json.dumps({"tool_name": "Read", "tool_input": {"file_path": p + "/README.md"}, "cwd": p}).encode(), env)
    assert _dec(out)[0] is None and time.monotonic() - t < 4, out
    assert _journal(dw)[-1]["witness"] in ("WITNESS_TIMEOUT", "WITNESS_UNAVAILABLE NETWORK")     # httpx's read timeout, or the hook's own
    d, why = _dec(thin.run(json.dumps({"tool_name": "Read", "tool_input": {"file_path": p + "/.env"}, "cwd": p}).encode(), env))
    assert d == "deny" and ("WITNESS_TIMEOUT" in why or "WITNESS_UNAVAILABLE" in why)
    d, why = _dec(thin.run(json.dumps({"tool_name": "Bash", "tool_input": {"command": "python3 src/app.py"}, "cwd": p}).encode(), env))
    assert d == "deny" and ("WITNESS_TIMEOUT" in why or "WITNESS_UNAVAILABLE" in why)


def test_hook_own_timeout_into_a_local_read(proj, monkeypatch):
    """The hook's own deadline (run() gives up on the judging thread): a read runs, a secret / a run does not."""
    p, home, dw = proj
    _pin(dw)
    gate = threading.Event()

    def slow(ev, s, witness=None, deadline=None, state=None):
        state["pinned"] = True
        gate.wait(5)
        return thin.deny("NEVER")
    monkeypatch.setattr(thin, "judge", slow)
    env = _env(p, home, dw, DEUS_WITNESS_HOOK_TIMEOUT="1")
    out = thin.run(json.dumps({"tool_name": "Read", "tool_input": {"file_path": p + "/README.md"}, "cwd": p}).encode(), env)
    assert _dec(out)[0] is None and _journal(dw)[-1]["witness"] == "WITNESS_TIMEOUT", out
    d, why = _dec(thin.run(json.dumps({"tool_name": "Read", "tool_input": {"file_path": p + "/.env"}, "cwd": p}).encode(), env))
    assert d == "deny" and "WITNESS_TIMEOUT" in why
    gate.set()


def test_dead_pinned_witness_real_network(proj):
    p, home, dw = proj
    _pin(dw, "http://127.0.0.1:9")
    env = _env(p, home, dw, DEUS_WITNESS_URL="http://127.0.0.1:9")
    out = thin.run(json.dumps({"tool_name": "Bash", "tool_input": {"command": "cat README.md"}, "cwd": p}).encode(), env)
    assert _dec(out)[0] is None and "cannot be reached" in out.get("systemMessage", ""), out
    d, why = _dec(thin.run(json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm README.md"}, "cwd": p}).encode(), env))
    assert d == "deny" and "WITNESS_UNAVAILABLE" in why
