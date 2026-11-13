"""0.2.89 / client 0.2.57 (friction 03.11, OTCHET-TRENIE-0311.md): fewer questions on reads, no EXEC_CHANGED for a .venv a line does not
run, `rm -rf build` inside the project, who was told about a question (notify), SessionStart status. Every relaxation has its negative:
what stays DANGER / asked."""
import json
import os
import re
import sys

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))
sys.path.insert(0, CLOUD)

from app import execguard  # noqa: E402
from app.hookjudge import bashparse as bp  # noqa: E402
from app.hookjudge import judge as hj  # noqa: E402
from app.hookjudge.mapping import DEFAULT_SAFE_COMMANDS, default_form  # noqa: E402
from deus_witness import client as dwc  # noqa: E402
from deus_witness.hook import main as thin  # noqa: E402
from tests.helpers import ORIGIN  # noqa: E402
from tests.test_0216_thin import Via, _server  # noqa: E402
from tests_flow.helpers import set_settings  # noqa: E402

H, P = "/Users/u", "/Users/u/proj"


def cl(cmd, cwd=P):
    return bp.classify(cmd, cwd, H, project=P)


# ---------------------------------------------------------------- 3. recursive read outside the project
@pytest.mark.parametrize("cmd", ["grep -rl 9333 /Users/u/.claude/tools", "grep -rc x /Users/u/Vault", "grep -rq x ~/Vault/layer1",
                                 "rg -l x /Users/u/Vault", "rg --files /Users/u/Vault", "ls -R ~/Vault", "du ~/Vault", "tree ~/Vault/layer1",
                                 "grep -r -l x ~/code/other"])
def test_names_only_walk_outside_is_not_danger(cmd):
    c = cl(cmd)
    assert c.danger == [] and not any("[outside]" in h for h in c.heads), (cmd, c.heads, c.danger)


@pytest.mark.parametrize("cmd", ["grep -rn 9333 /Users/u/.claude/tools", "rg 9333 /Users/u/Vault", "grep -r TODO ~/code/other"])
def test_content_walk_outside_is_an_ordinary_question(cmd):
    c = cl(cmd)
    assert c.danger == [] and any(h.endswith(" [outside]") for h in c.heads), (cmd, c.heads)


@pytest.mark.parametrize("cmd", ["grep -r x ~/.ssh", "grep -rl x /Users/u/.ssh", "grep -r x ~", "grep -rl x ~", "grep -rl x /", "grep -rl x /etc",
                                 "grep -rl x /Users", "grep -rl x ~/.claude", "grep -rl x ~/.config/foo", "grep -rl x ~/.config",
                                 "grep -rl x ~/Library/Application\\ Support", "grep -rl x ~/.aws", "grep -rl x ~/.gnupg", "grep -rl x ~/.local/share",
                                 "grep -Rl x ~/Vault", "grep -rl -S x ~/Vault", "grep -l --dereference-recursive x ~/Vault", "rg -L -l x ~/Vault",
                                 "rg --follow x ~/Vault", "tree -l ~/Vault", "ls -RL ~/Vault", "du -L ~/Vault", "grep -rl x $DIR",
                                 "grep -rl x ~/.deus-witness", "grep -rl x ~/Library/Keychains", "grep -rl x /Users/other/code"])
def test_secret_roots_and_link_walks_stay_danger(cmd):
    c = cl(cmd)
    assert c.danger, (cmd, c.heads)


# ---------------------------------------------------------------- safe reads (0.2.89 list entries) and their other forms
@pytest.mark.parametrize("cmd,head", [("ps aux", "ps"), ("ps -ef", "ps"), ("lsof -i :3000", "lsof"), ("whoami", "whoami"), ("id", "id"),
                                      ("git remote -v", "git remote"), ("git remote get-url origin", "git remote"), ("git tag", "git tag list"),
                                      ("git tag -l 'v*'", "git tag list"), ("git stash list", "git stash list"), ("git stash show -p", "git stash show"),
                                      ("git config user.name", "git config get"), ("git config --get user.email", "git config get"),
                                      ("git config --list", "git config get"), ("git config get user.name", "git config get"), ("npm ls --depth=0", "npm ls"), ("pip list", "pip list"),
                                      ("pip3 freeze", "pip3 freeze"), ("uv pip list", "uv pip"), ("python3 --version", "--version"),
                                      ("node --version", "--version"), ("git --version", "--version")])
def test_read_only_forms_are_the_listed_ids(cmd, head):
    c = cl(cmd)
    assert c.heads == [head] and c.danger == [], (cmd, c.heads, c.danger)
    assert head in DEFAULT_SAFE_COMMANDS


@pytest.mark.parametrize("cmd", ["ps eww", "ps auxe", "ps -E", "git remote add o https://x", "git remote set-url origin x", "git remote show origin",
                                 "git tag v1", "git tag -d v1", "git tag -a v1 -m x", "git stash", "git stash pop", "git stash drop",
                                 "git config user.name bob", "git config --unset a.b", "git config -f ~/.gitconfig --list", "git config --add a b",
                                 "git config -e", "git config set a b", "git config --get diff.external", "git config core.pager",
                                 "git config --get-regexp filter", "pip list --outdated", "pip3 list -o", "uv pip install x", "uv pip sync r.txt",
                                 "uv pip list --outdated", "sudo python3 --version", "X=1 python3 --version", "./python3 --version",
                                 "pip --version", "pytest --version", "python3 --version x", "npm --version"])
def test_other_forms_are_not_the_listed_id(cmd):
    c = cl(cmd)
    lst = set(DEFAULT_SAFE_COMMANDS)
    assert c.danger or any(h not in lst for h in c.heads), (cmd, c.heads)


def test_a_program_named_like_the_version_entry_is_opaque():
    c = cl("-- x")
    assert c.danger or "--version" not in c.heads
    for cmd in ("'--version' x", "python3 --version; '--version'", "'a b' --version"):
        assert any(d.startswith("opaque:command name starting with '--'") for d in cl(cmd).danger), cmd


# ---------------------------------------------------------------- rm -rf inside the project
@pytest.mark.parametrize("cmd,writes", [("rm -rf build", [P + "/build"]), ("rm -rf node_modules/.cache", [P + "/node_modules/.cache"]),
                                        ("rm -r -f dist", [P + "/dist"]), ("rm -rf build/", [P + "/build"]), ("rm -rf pkg.egg-info", [P + "/pkg.egg-info"]),
                                        ("rm -rf web/.next", [P + "/web/.next"]), ("rm -rf build && rm -rf dist", [P + "/build", P + "/dist"])])
def test_rm_rf_of_a_project_subfolder_is_a_plain_delete(cmd, writes):
    c = cl(cmd)
    assert c.danger == [] and c.heads == ["rm"] and c.writes == writes, (cmd, c.heads, c.danger)


# 0.2.90 (standing mandate): any literal path strictly inside the project or a temp directory is a delete of the mandate's targets
# (`rm -rf src`, `rm -rf docs/old`, `rm -rf /tmp/x`, `bash -c 'rm -rf build'` left this list); the root, .git, globs, variables, outside stay DANGER
@pytest.mark.parametrize("cmd", ["rm -rf .", "rm -rf " + P, "rm -rf ..", "rm -rf .git", "rm -rf sub/.git", "rm -rf build/*", "rm -rf $X",
                                 "rm -rf ~/Documents", "rm -rf /", "rm -rf build ~/x", "echo 'rm -rf ~'; rm -rf build",
                                 "xargs rm -rf < l", "find . -delete", "rm -rf ~", "rm -rf -- build/../.."])
def test_rm_rf_elsewhere_stays_danger(cmd):
    assert any(d.startswith("rm-rf") or d.startswith("opaque") for d in cl(cmd).danger), cmd


# ---------------------------------------------------------------- 4. EXEC_CHANGED: only for a venv the line runs
def test_venv_root():
    assert execguard.venv_root("/p/.venv/bin/python3") == "/p/.venv"
    assert execguard.venv_root("/p/venv/bin/pip") == "/p/venv"
    assert execguard.venv_root("/p/.venv/lib/python3.12/site-packages/foo/core.py") == "/p/.venv"
    assert execguard.venv_root("/p/.venv/lib/python3.12/site-packages/a.pth") == "/p/.venv"
    assert execguard.venv_root("/p/conftest.py") is None and execguard.venv_root("/p/bin/run") is None


def _args(cmd, heads, which):
    w = {"commands": heads}
    if which is not None:
        w["which"] = which
    return {"command": cmd, "_witness": w}


@pytest.mark.parametrize("cmd,heads,which,idle", [
    ("python3 -c 1", ["python3 [eval]"], {"python3": ["/usr/bin/python3", "/usr/bin/python3"]}, True),
    ("pytest", ["pytest"], {"pytest": ["/opt/homebrew/bin/pytest", "/opt/homebrew/Cellar/x/pytest"]}, True),
    ("python3 -c 1", ["python3 [eval]"], None, False),                                                   # no fact: as before
    ("python3 -c 1", ["python3 [eval]"], {"python3": None}, False),
    ("python3 -c 1", ["python3 [eval]"], {"python3": ["/p/.venv/bin/python3", "/usr/bin/python3.12"]}, False),   # the venv is on PATH
    ("python3 -c 1", ["python3 [eval]"], {"python3": ["/Users/u/bin/python3", "/p/.venv/bin/python3"]}, False),  # a link into the venv
    ("python3 -c 1", ["python3 [eval]"], {"python3": ["/Users/u/.pyenv/shims/python3", "/Users/u/.pyenv/shims/python3"]}, False),
    (".venv/bin/python -c 1", [".venv/bin/python [eval]"], {}, False),
    ("source .venv/bin/activate && python3 x.py", ["source", "python3"], {"python3": ["/usr/bin/python3", "/usr/bin/python3"]}, False),
    ("PATH=/p/.venv/bin:$PATH python3 x.py", ["python3 [env PATH]"], {"python3": ["/usr/bin/python3", "/usr/bin/python3"]}, False),
    ("uv run pytest", ["uv run"], {}, False),
    ("poetry run pytest", ["poetry run"], {}, False),
])
def test_venv_idle(cmd, heads, which, idle):
    assert execguard._venv_idle("/p/.venv/lib/python3.12/site-packages/foo/core.py", _args(cmd, heads, which), "/p") is idle
    assert execguard._venv_idle("/p/conftest.py", _args(cmd, heads, which), "/p") is False       # not a venv file: never skipped


def _hook(tmp_path, safe=()):
    c, o = _server(tmp_path, "srv")
    set_settings(c.app.state.ctx, o.account["id"], max_pending=100000, max_defers_hour=1000000)
    proj = (tmp_path / "proj").resolve()
    for f, t in {"src/app.py": "print(1)\n", "conftest.py": "x = 1\n", ".venv/pyvenv.cfg": "home = /usr/bin\n",
                 ".venv/lib/python3.12/site-packages/foo/core.py": "x = 1\n", ".venv/lib/python3.12/site-packages/a.pth": "import foo\n",
                 ".venv/bin/python3": "#!/bin/sh\n"}.items():
        (proj / f).parent.mkdir(parents=True, exist_ok=True)
        (proj / f).write_text(t)
    os.chmod(proj / ".venv/bin/python3", 0o755)
    sysbin = (tmp_path / "sys" / "bin").resolve()
    sysbin.mkdir(parents=True)
    (sysbin / "python3").write_text("#!/bin/sh\n")
    os.chmod(sysbin / "python3", 0o755)
    ag, hdr = o.new_agent("claude-code", "cc")
    m, r = o.mandate(ag["id"], default_form(str(proj), safe_commands=list(DEFAULT_SAFE_COMMANDS) + list(safe)))
    assert r.status_code == 200, r.text
    key = hdr["Authorization"][7:]
    w = dwc.Witness(ORIGIN, key, pin_path=str(tmp_path / "pins.json"), transport=Via(c))

    def run(cmd, **env):
        e = {"DEUS_WITNESS_KEY": key, "CLAUDE_PROJECT_DIR": str(proj), "HOME": str(tmp_path / "home"), "DEUS_WITNESS_HOOK_ON_DEFER": "ask",
             "DEUS_WITNESS_HOME": str(tmp_path / "dw")}
        e.update(env)
        out = thin.judge({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(proj), "session_id": "s1"}, thin.Settings(e), witness=w)
        h = out.get("hookSpecificOutput") or {}
        return h.get("permissionDecision") or "none", h.get("permissionDecisionReason", ""), out
    return run, proj, sysbin, c, o, ag


def test_exec_changed_venv_end_to_end(tmp_path):
    run, proj, sysbin, c, o, ag = _hook(tmp_path, safe=["python3"])
    assert run("python3 src/app.py", DEUS_WITNESS_CALLER_PATH=str(sysbin))[0] == "allow"        # first report = the confirmed state
    (proj / ".venv/lib/python3.12/site-packages/a.pth").write_text("import foo, bar\n")                # `pip install` into the project venv
    (proj / ".venv/bin/python3").write_text("#!/bin/sh\n# new\n")
    d, why, _ = run("python3 src/app.py", DEUS_WITNESS_CALLER_PATH=str(sysbin))
    assert d == "allow", why                                                                           # system python3: the venv is not run
    d, why, _ = run("python3 src/app.py", CLAUDE_PLUGIN_ROOT="/x")                                     # an old plugin: no PATH fact
    assert d == "ask" and "ESCALATE_EXEC_CHANGED" in why
    d, why, _ = run("python3 src/app.py", DEUS_WITNESS_CALLER_PATH="%s:%s" % (proj / ".venv/bin", sysbin))
    assert d == "ask" and "ESCALATE_EXEC_CHANGED" in why                                               # the venv's python3 is first on PATH
    d, why, _ = run(".venv/bin/python3 src/app.py", DEUS_WITNESS_CALLER_PATH=str(sysbin))
    assert d == "ask" and ("ESCALATE_EXEC_CHANGED" in why or "ESCALATE_COMMAND" in why)                # the venv named by path: not allowed
    assert d != "allow"
    d, why, _ = run("python3 src/app.py", DEUS_WITNESS_CALLER_PATH="relative:%s" % sysbin)
    assert d == "ask" and "ESCALATE_EXEC_CHANGED" in why                                               # a relative PATH entry: no fact
    link = tmp_path / "lnk"
    link.mkdir()
    os.symlink(proj / ".venv/bin/python3", link / "python3")
    d, why, _ = run("python3 src/app.py", DEUS_WITNESS_CALLER_PATH=str(link))
    assert d == "ask" and "ESCALATE_EXEC_CHANGED" in why                                               # a link elsewhere into the venv
    (proj / "conftest.py").write_text("x = 2\n")                                                       # a project file python runs: asked
    d, why, _ = run("python3 -m pytest", DEUS_WITNESS_CALLER_PATH=str(sysbin))
    assert d == "ask" and "ESCALATE_EXEC_CHANGED" in why


# ---------------------------------------------------------------- 1. notify in the answer; 2. GET /v1/hook/status
def test_notify_and_texts_of_a_question(tmp_path):
    run, proj, sysbin, c, o, ag = _hook(tmp_path)
    d, why, out = run("make build")
    assert d == "ask" and "ESCALATE_COMMAND" in why
    assert "Notification: NOT sent" in why and "no phone push" in why
    sm = out.get("systemMessage") or ""
    assert sm.startswith("Deus Witness: ") and "/approve.html" in sm and "Notification: NOT sent" in sm
    d, why, out = run("make build", DEUS_WITNESS_HOOK_ON_DEFER="deny", DEUS_WITNESS_HOOK_WAIT="1", DEUS_WITNESS_HOOK_TIMEOUT="8")
    assert d == "deny" and "nobody approved it in Witness within" in why and "then rerun the SAME call" in why and "Notification:" in why
    assert "was not approved in time" in out["systemMessage"]
    d, why, out = run("ls")
    assert d == "allow" and "systemMessage" not in out                                                 # an allowed call: nothing for the person


def test_notify_view_counts(tmp_path):
    c, o = _server(tmp_path, "srv")
    ctx = c.app.state.ctx
    ag, hdr = o.new_agent("claude-code", "cc")
    a = ctx.db.one("SELECT * FROM agents WHERE id=?", (ag["id"],))
    assert hj.notify_view(ctx, a) == {"push": 0, "channels": [], "muted": False}
    ctx.db.x("INSERT INTO notify_channels(id, account_id, kind, label, verified, created_at, secret_enc) VALUES(?,?,?,?,?,?,?)",
             ("nc_1", o.account["id"], "telegram", "t", 1, 1, b"x"))
    ctx.db.x("INSERT INTO notify_channels(id, account_id, kind, label, verified, created_at, secret_enc) VALUES(?,?,?,?,?,?,?)",
             ("nc_2", o.account["id"], "slack", "s", 0, 1, b"x"))                                             # not verified: not counted
    assert hj.notify_view(ctx, a)["channels"] == ["telegram"]


def test_hook_status(tmp_path):
    c, o = _server(tmp_path, "srv")
    proj = str((tmp_path / "proj").resolve())
    ag, hdr = o.new_agent("claude-code", "cc")
    r = c.get("/v1/hook/status", params={"project": proj}, headers=hdr).json()
    assert r == {"v": 1, "trial": False, "mandate": {"active": False}, "notify": {"push": 0, "channels": [], "muted": False},
                 "latest": {"client": hj.LATEST_CLIENT}}
    assert hj.LATEST_CLIENT == thin.VERSION                                                            # bumped with every client
    o.mandate(ag["id"], default_form(proj))
    assert c.get("/v1/hook/status", params={"project": proj}, headers=hdr).json()["mandate"] == {"active": True, "covers": True}
    other = "/Users/nobody-dw/other"
    assert c.get("/v1/hook/status", params={"project": other}, headers=hdr).json()["mandate"] == {"active": True, "covers": False}
    assert c.get("/v1/hook/status", params={"project": proj + "/sub"}, headers=hdr).json()["mandate"]["covers"] is True
    assert c.get("/v1/hook/status").status_code == 401                                                 # the agent key is required


def test_session_warnings_client(tmp_path, monkeypatch):
    """client 0.2.57 SessionStart: the mandate of another folder and no channel are said, with the fix; a covered folder with a channel: silent"""
    c, o = _server(tmp_path, "srv")
    proj = str((tmp_path / "proj").resolve())
    other = "/Users/nobody-dw/other"
    ag, hdr = o.new_agent("claude-code", "cc")
    o.mandate(ag["id"], default_form(proj))
    key = hdr["Authorization"][7:]
    pins = tmp_path / "pins.json"
    w = dwc.Witness(ORIGIN, key, pin_path=str(pins), transport=Via(c), pin_new=True)
    w.witness_info()                                                                                   # the URL is pinned on this machine
    monkeypatch.setattr(dwc.Witness, "_read_pins", lambda self: {ORIGIN: {}})
    # client 0.2.61 (r0263, L3 З3): "no channel" is said only when a question reaches nobody: the browser page off (this env)
    env = {"DEUS_WITNESS_KEY": key, "DEUS_WITNESS_URL": ORIGIN, "DEUS_WITNESS_HOME": str(tmp_path / "dw"), "DEUS_WITNESS_HOOK_WAIT": "45",
           "DEUS_WITNESS_HOOK_TIMEOUT": "55", "DEUS_WITNESS_OPEN_BROWSER": "0"}
    t = thin.session_warnings(other, env, transport=Via(c))
    assert t and "do NOT cover this folder" in t and other in t and "deus-witness try" in t and "reach nobody" in t
    t = thin.session_warnings(proj, env, transport=Via(c))
    assert t and "do NOT cover" not in t and "reach nobody" in t
    assert thin.session_warnings(proj, dict(env, DEUS_WITNESS_OPEN_BROWSER="1"), transport=Via(c)) is None   # the page opens here
    ctx = c.app.state.ctx
    ctx.db.x("INSERT INTO notify_channels(id, account_id, kind, label, verified, created_at, secret_enc) VALUES(?,?,?,?,?,?,?)",
             ("nc_1", o.account["id"], "telegram", "t", 1, 1, b"x"))
    assert thin.session_warnings(proj, env, transport=Via(c)) is None


def test_which_fact_is_sent_and_parsed(tmp_path):
    f = {"home": "/h", "proc_cwd": "/", "which": {"python3": ["/usr/bin/python3", "/usr/bin/python3"], "pip": None}}
    assert hj._facts({"facts": f})["which"] == f["which"]
    for bad in ({"python3": "/usr/bin/python3"}, {"python3": ["rel"]}, {"x y": None}, {"python3": ["/a", "/b", "/c"]}):
        assert "which" not in hj._facts({"facts": dict(f, which=bad)})                                 # malformed: no fact (asked as before)
    e = {"DEUS_WITNESS_CALLER_PATH": "/usr/bin:/bin"}
    got = thin._which_fact("python3 -c 1 | grep x && pip list", e)
    assert set(got) == {"python3", "pip"}
    assert thin._which_fact("python3 -c 1", {"CLAUDE_PLUGIN_ROOT": "/x", "PATH": "/usr/bin"}) is None   # an old plugin filtered PATH
    assert thin._which_fact("python3 -c 1", {"PATH": ":/usr/bin"}) is None                                 # an empty entry = the cwd
    assert thin._which_fact("ls", {"PATH": "/usr/bin"}) == {}


# ---------------------------------------------------------------- QA 03.11 D5: an automatic freeze stops the questions, not the work
def test_auto_freeze_keeps_what_the_mandate_allows(tmp_path):
    from app import actions as act
    run, proj, sysbin, c, o, ag = _hook(tmp_path)
    ctx = c.app.state.ctx
    set_settings(ctx, o.account["id"], max_pending=2, max_defers_hour=100000)
    codes = []
    for i in range(16):                                    # a silent owner: distinct questions pile up, then APPROVAL_RATE, then the freeze
        d, why, _ = run("make t%d" % i, DEUS_WITNESS_HOOK_ON_DEFER="deny")
        codes.append(re.findall(r"\b(ESCALATE_[A-Z_]+|APPROVAL_RATE|AGENT_FROZEN)\b", why)[:1])
    assert ["APPROVAL_RATE"] in codes and act.frozen_kind(ctx, ag["id"]) == "auto", codes
    d, why, _ = run("ls")
    assert d == "allow", why                                                       # was: AGENT_FROZEN (B18: even ls / Read stopped)
    d, why, _ = run("cat README.md")
    assert d == "allow", why
    d, why, _ = run("make again", DEUS_WITNESS_HOOK_ON_DEFER="deny")
    assert d == "deny" and "AGENT_FROZEN" in why and "Agents page" in why        # a question: refused, and the text says how to unfreeze
    n = ctx.db.one("SELECT COUNT(*) AS n FROM actions WHERE agent_id=? AND status='pending_approval'", (ag["id"],))["n"]
    assert n == 0                                                                  # nothing new waits for the owner while frozen
    act.freeze(ctx, {"id": o.account["id"]}, None, ag["id"])                       # the owner's own Freeze: everything stops, as before
    d, why, _ = run("ls")
    assert d == "deny" and "AGENT_FROZEN" in why


def test_cli_hook_never_answers_ask(monkeypatch):
    """QA D16 (D34): DEUS_WITNESS_HOOK_ON_DEFER=ask from the environment (a project's settings can set env for hooks) is ignored by the hook
    Claude Code runs: a terminal "yes" would run the call without a receipt"""
    monkeypatch.setenv("DEUS_WITNESS_HOOK_ON_DEFER", "ask")
    assert thin.Settings().on_defer == "deny" and thin.Settings().ask_ignored
    assert thin.Settings({"DEUS_WITNESS_HOOK_ON_DEFER": "ask"}).on_defer == "ask"          # an embedding program's own settings dict


def test_project_env_overrides_and_versions(tmp_path):
    """QA D7 (the warning half) and D9"""
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"env": {"DEUS_WITNESS_KEY_FILE": "/x", "FOO": "1"}}))
    (tmp_path / ".claude" / "settings.local.json").write_text(json.dumps({"env": {"CLAUDE_PLUGIN_OPTION_STRICT": "false"}}))
    assert thin.project_env_overrides(str(tmp_path)) == ["CLAUDE_PLUGIN_OPTION_STRICT", "DEUS_WITNESS_KEY_FILE"]
    assert thin.project_env_overrides(str(tmp_path / "none")) == []
    (tmp_path / ".claude" / "settings.local.json").write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"command": "deus-witness-hook"}]}]},
                                                                           "env": {"DEUS_WITNESS_HOOK_TIMEOUT": "20"}}))
    assert thin.project_env_overrides(str(tmp_path), plugin=False) == ["DEUS_WITNESS_KEY_FILE"]           # its own settings.json install
    assert thin.project_env_overrides(str(tmp_path), plugin=True) == ["DEUS_WITNESS_HOOK_TIMEOUT", "DEUS_WITNESS_KEY_FILE"]
    w = thin.version_warnings({"CLAUDE_PLUGIN_ROOT": "/p"})
    assert w and "older than 0.2.5" in w[0]                                       # A13/A14: the 0.2.49 plugin exports no version
    assert thin.version_warnings({"CLAUDE_PLUGIN_ROOT": "/p", "DEUS_WITNESS_PLUGIN_VERSION": thin.VERSION}) == []
    assert "runs client" in thin.version_warnings({"DEUS_WITNESS_PLUGIN_VERSION": "0.2.49"})[0]
    assert "older than 9.9.9" in thin.version_warnings({}, "9.9.9")[0] and thin.version_warnings({}, thin.VERSION) == []
