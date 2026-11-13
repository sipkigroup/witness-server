"""0.2.91 (client 0.2.59; friction measurement 04.11, poligon-lyudi/pesochnica/trenie/rez-real-B.md): 47 hard refusals with no button
on calls of the owner's own sessions that were expected to be harmless. A hard deny is right only where the owner's approval would change
nothing; everywhere else the call is ASKED. One test per group of the 47:

  RESOURCE        a write outside the project with no shadow copy (a directory, git stash) and the agent's harness outside the project
                  (`sed -i ~/.claude/tools/x.sh`, Write ~/.claude/CLAUDE.md) were refused by the write part before the question;
  AGENT_CONFIG    the hook's lock K1 found the harness in a line the witness allowed: the hook's fact `harness` makes the witness ask;
  PERSIST_PLACE   a CLAUDE_* variable of one shell, a run of the witness's own client (`uvx --from deus-witness==X`, `python -m
                  deus_witness.verify_pack`), `claude plugin update` under another CLAUDE_CONFIG_DIR: the danger `witness` (asked);
                  what rewrites the witness's state (--trust, --undo, --setup-strict) and real persistence places stay `persist`;
  RECIPIENT       a host of a SHELL line outside the mandate's domains: a dangerous command "(network) HOST" (asked), unless the mandate
                  refuses dangerous commands (`unlisted: "deny"`); WebFetch unchanged;
  reads           `git remote -v` is no exit; `ls -la ~/.config/gh/` lists names, no secret."""
import os

import pytest

from app import allowances as al
from app.hookjudge import bashparse as bp
from app.hookjudge import fs as hfs
from app.hookjudge import judge as hj
from app.hookjudge import sandbox as hsb
from app.hookjudge.mapping import default_form, map_event
from tests.helpers import act
from tests.test_0290_standing import Dev, dev  # noqa: F401  (the fixture)
from tests_flow.helpers import set_settings

pytestmark = pytest.mark.standing
H = "/Users/u"


def cats(cmd, proj="/proj", home=H):
    c = bp.classify(cmd, proj, home, project=proj)
    return sorted({d.split(":", 1)[0] for d in c.danger}), c


def _no_deny(got):
    assert got and not any(r.get("verdict") == "deny" for _, r in got), [(t, r.get("verdict"), r.get("reason")) for t, r in got]
    assert any(r.get("verdict") == "defer" for _, r in got), [(t, r.get("verdict"), r.get("reason")) for t, r in got]


# ---- RESOURCE -----------------------------------------------------------------------------------------------------------------
def test_write_outside_with_no_copy_is_asked_never_resource(dev, monkeypatch):
    note = os.path.join(dev.home, "Vault", "note.md")
    monkeypatch.setattr(hfs.LocalFS, "shadow", lambda self, p: {"failed": "a directory"})
    got = dev.send("echo hi >> %s" % note)
    _no_deny(got)
    assert "Bash.write" not in [t for t, _ in got]


def test_harness_outside_the_project_is_asked_never_resource(dev):
    tools = os.path.join(dev.home, ".claude", "tools")
    os.makedirs(tools)
    open(os.path.join(tools, "x.sh"), "w").write("echo a\n")
    got = dev.send("sed -i '' 's/a/b/' %s/x.sh && bash -n %s/x.sh" % (tools, tools))
    _no_deny(got)
    assert any("agent-config:" in str(r.get("action", {}).get("recipient")) for _, r in got), got
    for path in (os.path.join(tools, "x.sh"), os.path.join(dev.home, ".claude", "CLAUDE.md"),
                 os.path.join(dev.home, ".claude", "projects", "p", "memory", "m.md")):
        got = dev.send(None, tool="Write", inp={"file_path": path, "content": "new\n"})
        _no_deny(got)


# ---- AGENT_CONFIG_UNAPPROVED: the hook's fact `harness` --------------------------------------------------------------------------
def test_harness_fact_is_kept_and_makes_the_line_asked(dev, monkeypatch):
    base = {"home": "/h", "proc_cwd": "/p", "env": {}, "fs": {}, "exec": None}
    assert hj._facts({"facts": dict(base, harness=".claude")}).get("harness") == ".claude"
    assert "harness" not in hj._facts({"facts": dict(base, harness=["x"])}) and "harness" not in hj._facts({"facts": base})
    got = dev.send("ls -l ~/.claude/settings.json | awk '{print $6}'")
    assert [r.get("verdict") for _, r in got] != [] and not any("agent-config" in str(r.get("action", {}).get("recipient")) for _, r in got)
    monkeypatch.setattr(hfs.LocalFS, "harness", lambda self: ".claude", raising=False)
    got = dev.send("ls -l ~/.claude/settings.json | awk '{print $6}' ")
    _no_deny(got)
    assert any("agent-config:(hook) .claude" in str(r.get("action", {}).get("recipient")) for _, r in got), got


# ---- PERSIST_PLACE -> witness (asked) where the owner's approval means something ---------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "CLAUDE_CONFIG_DIR=/tmp/x claude -p hi",
    "export CLAUDE_CONFIG_DIR=%s/dw-poligon-cfg; claude plugin update deus-witness@sipkigroup" % H,
    "env CLAUDE_CONFIG_DIR=/tmp/c claude plugin marketplace update x",
    "T=$(mktemp -d); UV_CACHE_DIR=$T uvx --no-config --from \"deus-witness==0.2.43\" python -c 'print(1)'",
    "deus-witness try",
    "deus-witness-hook --version",
    ".venv/bin/python -m deus_witness.verify_pack out/pack.zip --offline",
])                                            # r0263: `deus-witness-hook --setup-strict --dry-run` carries no danger (test_1211_r0263.py)
def test_one_shot_witness_runs_are_asked_not_refused(cmd):
    got, c = cats(cmd)
    assert "witness" in got and "persist" not in got, (cmd, c.danger)


@pytest.mark.parametrize("cmd", [
    "claude plugin disable deus-witness",
    "claude plugin update deus-witness@sipkigroup",
    "CLAUDE_CONFIG_DIR=%s/.claude claude plugin disable deus-witness" % H,
    "deus-witness-hook --trust https://evil.example",
    "deus-witness-hook --undo-strict",
    "deus-witness-hook --setup-strict",
    "deus-witness try --force",
    "echo 'x' >> ~/.zshrc",
])
def test_what_rewrites_the_witness_or_a_login_place_stays_persist(cmd):
    got, c = cats(cmd)
    assert "persist" in got, (cmd, c.danger)


def test_one_shot_witness_run_is_a_question_on_the_server(dev):
    got = dev.send("CLAUDE_CONFIG_DIR=/tmp/x claude -p hi")
    _no_deny(got)


# ---- RECIPIENT: a host of a shell line outside the domains is asked -------------------------------------------------------------
def test_shell_host_outside_the_domains_is_asked_as_a_dangerous_command(dev):
    got = dev.send("curl -s https://unlisted.example/healthz")
    net = [r for t, r in got if t == "Bash.net"]
    assert net and (net[0]["verdict"], net[0]["reason"]) == ("defer", "ESCALATE_COMMAND_DANGER"), got
    assert net[0]["action"]["class"] == "command" and net[0]["action"]["recipient"] == al.EXIT_PREFIX + "unlisted.example", net
    _no_deny(got)
    got = dev.send("python3 -c \"print('https://old.example/submit?x=1')\" > /dev/null")
    _no_deny(got)


def test_webfetch_and_a_mandate_that_refuses_dangerous_commands_keep_recipient(client, owner, tmp_path):
    (tmp_path / "p1").mkdir()
    dev = Dev(client, owner, (tmp_path / "p1").resolve(), home=str(tmp_path.resolve()))
    got = dev.send(None, tool="WebFetch", inp={"url": "https://unlisted.example/x", "prompt": "p"})
    assert (got[0][1]["verdict"], got[0][1]["reason"]) == ("deny", "RECIPIENT"), got
    proj = tmp_path / "p2"
    proj.mkdir()
    set_settings(client.app.state.ctx, owner.account["id"], max_pending=10000, max_defers_hour=100000)
    ag, hdr = owner.new_agent("claude-code", "cc2")
    f = default_form(str(proj.resolve()))
    f["command"]["unlisted"] = "deny"
    m, r = owner.mandate(ag["id"], f)
    assert r.status_code == 200, r.text
    env = {"CLAUDE_PROJECT_DIR": str(proj.resolve()), "HOME": str(tmp_path.resolve()), "DEUS_WITNESS_EXEC_SCAN": "0"}
    res = {}
    for mm in map_event({"tool_name": "Bash", "tool_input": {"command": "curl -s https://unlisted.example/x"}, "cwd": str(proj.resolve())},
                        home=str(tmp_path.resolve()), env=env):
        res[mm.tool] = act(client, hdr, mm.tool, mm.args).json()
    assert (res["Bash.net"]["verdict"], res["Bash.net"]["reason"]) == ("deny", "RECIPIENT"), res


# ---- reads -----------------------------------------------------------------------------------------------------------------------
def test_git_remote_listing_is_no_exit():
    for cmd in ("git remote -v", "git remote", "git remote get-url origin"):
        c = bp.classify(cmd, "/proj", H, project="/proj")
        assert not any(hsb.standing_exit(h) for h in c.heads), (cmd, c.heads)
    c = bp.classify("git remote show origin", "/proj", H, project="/proj")
    assert any(hsb.standing_exit(h) for h in c.heads), c.heads


def test_listing_a_credential_directory_is_no_secret_read():
    for cmd in ("ls -la ~/.config/gh/", "ls -la ~/.ssh", "ls ~/.aws"):
        assert "secrets" not in cats(cmd)[0], cmd
    for cmd in ("ls -R ~/.ssh", "ls ~/.ssh/id_rsa", "cat ~/.config/gh/hosts.yml", "ls ~/.config/deus-witness", "stat ~/.ssh/id_rsa"):
        assert "secrets" in cats(cmd)[0], cmd
