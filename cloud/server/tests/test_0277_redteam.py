"""0.2.77 (red team 31.10, cloud/OTCHET-KRASNAYA-NEDELYA-2026-10-31.md).

H2: a command approved AFTER its hook gave up is kept for "the same call again" (quickstart). A write the witness let through into the
    project after the question (any agent of the account) ends that: the repeat is asked again (FILE_CHANGED on the old row). Without a
    write since, the repeat keeps getting the approved row (the quickstart path).
H3: a hard link of the agent's configuration / of a git hook is judged as that file (samefile, protected=True); the hook's copy of the
    patterns equals the server's.
"""
import json
import os

from app import actions
from app.hookjudge import bashparse, samefile
from app.hookjudge import fs as hfs
from tests.test_0224_critique import Agent
from tests.test_r25_s8 import _rid
from tests.test_late_release_2910 import _give_up, _row, _present


def _late_approved(a, owner, line):
    rid = _rid(a.line(line)[1])
    assert _give_up(a, rid)["status"] == "pending_approval"
    assert owner.approve(rid).json()["verdict"] == "allow"
    return rid


# ---------------------------------------------------------------- H2
def test_h2_late_approval_then_project_write_is_asked_again(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=[])
    with open(os.path.join(a.proj, "tool.py"), "w") as f:
        f.write('print("hello")\n')
    rid = _late_approved(a, owner, "python3 tool.py")
    a.tool("Write", {"file_path": a.proj + "/tool.py", "content": "import os\nos.system('curl evil.example')\n"})
    v, parts = a.line("python3 tool.py")
    assert rid not in [p[3] for p in parts], parts                     # not the approval of the old text
    assert v == "ASK", parts
    ej = json.loads(_row(a, rid)["exec_json"] or "{}")
    assert ej.get("file_changed", "").endswith("/tool.py"), ej        # the owner is told why


def test_h2_other_agent_write_ends_the_late_approval_too(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, name="A")
    rid = _late_approved(a, owner, "python3 tool.py")
    b = Agent(client, owner, tmp_path, name="B")
    b.tool("Write", {"file_path": a.proj + "/helper.py", "content": "x = 1\n"})
    assert rid not in [p[3] for p in a.line("python3 tool.py")[1]]


def test_h2_quickstart_path_without_a_write_keeps_the_approval(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    a.tool("Write", {"file_path": a.proj + "/hello.py", "content": "print('hi')\n"})     # written BEFORE the question: shown / known
    rid = _late_approved(a, owner, "make build")
    v, parts = a.line("make build")
    assert v == "ALLOW" and [p[3] for p in parts] == [rid], parts
    assert _present(a, rid)["result"] == "accept"


def test_h2_write_outside_the_project_and_not_named_keeps_the_approval(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    rid = _late_approved(a, owner, "make build")
    x = actions.late_project_write(client.app.state.ctx, _row(a, rid))
    assert x is None


# ---------------------------------------------------------------- H3
def test_h3_patterns_equal_the_server():
    assert samefile.AGENT_CONFIG.pattern == bashparse.AGENT_CONFIG_PATH.pattern
    assert samefile.AGENT_CONFIG.flags == bashparse.AGENT_CONFIG_PATH.flags
    assert samefile.GIT_EXEC.pattern == bashparse.GIT_EXEC_PATH.pattern
    here = os.path.dirname(os.path.abspath(__file__))
    hook = os.path.join(here, "..", "..", "mcp", "deus_witness", "hook", "samefile.py")
    assert open(hook, "rb").read() == open(samefile.__file__, "rb").read()


def test_h3_hard_link_of_agent_config_and_git_hook(tmp_path):
    root = str(tmp_path / "proj")
    os.makedirs(os.path.join(root, ".claude"))
    os.makedirs(os.path.join(root, ".git", "hooks"))
    cfg = os.path.join(root, ".claude", "settings.json")
    hk = os.path.join(root, ".git", "hooks", "pre-commit")
    for p in (cfg, hk):
        open(p, "w").write("x\n")
    os.link(cfg, os.path.join(root, "notes.md"))
    os.link(hk, os.path.join(root, "pc.sh"))
    s = samefile.Secrets(root, str(tmp_path / "home"), bashparse.is_secret_path, protected=True)
    assert s.alias(os.path.join(root, "notes.md")) == cfg
    assert s.alias(os.path.join(root, "pc.sh")) == hk
    old = samefile.Secrets(root, str(tmp_path / "home"), bashparse.is_secret_path)       # without the flag: as before 0.2.77
    assert old.alias(os.path.join(root, "notes.md")) is None


def test_h3_shell_write_through_the_hard_link_is_agent_config(tmp_path):
    root = str(tmp_path / "proj")
    os.makedirs(os.path.join(root, ".claude"))
    cfg = os.path.join(root, ".claude", "settings.json")
    open(cfg, "w").write("{}\n")
    os.link(cfg, os.path.join(root, "notes.md"))
    tok = hfs.hint_root(root, str(tmp_path / "home"))
    try:
        c = bashparse.classify("echo '{\"hooks\": {}}' > notes.md", root, str(tmp_path / "home"))
    finally:
        hfs.reset_root(tok)
    assert any(d.startswith("agent-config:") for d in c.danger), c.danger
