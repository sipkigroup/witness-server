"""V3 (0.2.56): a test runner gets allow without a question ONLY when the hook's fact says the line runs in a strict Claude Code sandbox
AND the signed mandate says command.sandboxed = "allow". No fact, a non-strict fact, dangerouslyDisableSandbox, a variant, a non-runner,
a dangerous line or a mandate without the opt-in: asked as before."""
import copy
import os

import pytest

from app.hookjudge import fs as hfs
from app.hookjudge import judge as hj
from app.hookjudge import sandbox as hsb
from app.hookjudge.mapping import SANDBOXED_CODE, default_form, map_event
from tests.helpers import act
from tests_flow.helpers import set_settings

HOME = os.path.expanduser("~")
STRICT = {"v": 1, "platform": "darwin", "sources": {"user": "ok", "project": "absent", "local": "absent"},
          "enabled": True, "fail_if_unavailable": True, "allow_unsandboxed": False, "excluded": [], "ignore_violations": False,
          "fs_disabled": None, "deny_read": [HOME], "allow_read": [], "domains": [], "unix_sockets": [], "all_unix_sockets": None,
          "mach_lookup": [], "local_binding": None, "weaker": [], "env_scrub": True, "disable_flag": False, "env_files": [],
          "strict_allowlist": True, "managed_domains_only": False, "permission_mode": "default",
          "settings_digest": "ab" * 32, "since_start": [], "doubt": []}     # 0.2.57: network lock + mode
ASK = ("defer", "ESCALATE_COMMAND")
OK_SB = ("allow", "OK_SANDBOXED")


def fact(**over):
    f = copy.deepcopy(STRICT)
    f.update(over)
    return f


class Dev:
    def __init__(self, client, owner, proj, opt_in=True):
        self.c, self.proj = client, str(proj)
        set_settings(client.app.state.ctx, owner.account["id"], max_pending=10000, max_defers_hour=100000)
        self.ag, self.hdr = owner.new_agent("claude-code", "cc")
        form = default_form(self.proj)
        form["command"]["allow"].remove(SANDBOXED_CODE)              # 0.2.82: this file pins the 0.2.56 runners-only option (the code
                                                                     # option has its own tests: test_0282_irreversibility_gate.py)
        if opt_in:
            assert form["command"]["sandboxed"] == "allow"          # 0.2.56: the recommended form carries the opt-in
        else:
            form["command"].pop("sandboxed")                         # a mandate as signed before 0.2.56
        self.m, r = owner.mandate(self.ag["id"], form)
        assert r.status_code == 200, r.text

    def send(self, cmd):
        env = {"CLAUDE_PROJECT_DIR": self.proj, "HOME": "/nonexistent-home"}
        return [(m.tool, act(self.c, self.hdr, m.tool, m.args).json())
                for m in map_event({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": self.proj}, env=env)]

    def v(self, cmd):
        out = self.send(cmd)
        return [(r["verdict"], r["reason"]) for _, r in out]


@pytest.fixture
def sb(monkeypatch):
    def set_(f):
        monkeypatch.setattr(hfs, "LOCAL_SANDBOX", f)
    return set_


@pytest.fixture
def dev(client, owner, tmp_path):
    p = (tmp_path / "proj")
    p.mkdir()
    return Dev(client, owner, p.resolve())


@pytest.mark.parametrize("cmd", ["pytest -q", "python -m pytest -q", "python3 -m mypy src", "npm test", "npm run lint", "make", "make test",
                                 "go test ./...", "cargo test", "ruff check src", "yarn test"])
def test_strict_sandbox_runner_is_allowed(dev, sb, cmd):
    sb(fact())
    [(tool, r)] = dev.send(cmd)
    assert (r["verdict"], r["reason"]) == OK_SB, (cmd, r)
    assert r["action"]["sandboxed"] is True                      # the receipt records why no question was asked


def test_line_with_listed_and_runner(dev, sb):
    sb(fact())
    assert dev.v("ls && pytest -x -q tests/ 2>&1 | tail -20") == [OK_SB]


def test_no_fact_is_asked(dev, sb):
    sb(None)
    assert dev.v("pytest -q") == [ASK]


@pytest.mark.parametrize("over", [
    {"enabled": False}, {"enabled": None}, {"fail_if_unavailable": None}, {"platform": "linux"}, {"platform": "wsl"},
    {"platform": "win32"}, {"disable_flag": True}, {"domains": ["github.com"]}, {"unix_sockets": ["/var/run/docker.sock"]},
    {"all_unix_sockets": True}, {"local_binding": True}, {"mach_lookup": ["com.apple.SecurityServer"]}, {"env_scrub": False},
    {"deny_read": []}, {"deny_read": [HOME + "/.ssh"]}, {"allow_read": [HOME]}, {"allow_read": [HOME + "/.ssh"]},
    {"excluded": ["pytest *"]}, {"excluded": ["*"]}, {"excluded": ["docker compose *"]},
    {"allow_unsandboxed": None}, {"allow_unsandboxed": True}, {"fs_disabled": True}, {"ignore_violations": True},
    {"weaker": ["enableWeakerNestedSandbox"]}, {"sources": {"user": "ok", "project": "bad"}}, {"sources": {"managed-mdm": "unread"}},
])
def test_not_strict_is_asked(dev, sb, over):
    sb(fact(**over))
    assert dev.v("pytest -q") == [ASK], over


def test_env_file_must_be_denied(dev, sb):
    env = dev.proj + "/.env"
    sb(fact(allow_read=[dev.proj], env_files=[env]))             # denyRead ~/ + allowRead . re-opens the project's .env
    assert dev.v("pytest -q") == [ASK]
    sb(fact(allow_read=[dev.proj], env_files=[env], deny_read=[HOME, env]))
    assert dev.v("pytest -q") == [OK_SB]


def test_malformed_fact_is_no_fact(dev, sb):
    for bad in ({"v": 2}, {**STRICT, "enabled": "yes"}, {**STRICT, "deny_read": "~"}, "strict", {**STRICT, "disable_flag": None}):
        sb(bad)
        assert dev.v("pytest -q") == [ASK], bad


def test_mandate_without_opt_in_is_asked(client, owner, tmp_path, sb):
    p = tmp_path / "proj2"
    p.mkdir()
    d = Dev(client, owner, p.resolve(), opt_in=False)
    sb(fact())
    assert d.v("pytest -q") == [ASK]


@pytest.mark.parametrize("cmd,want", [
    ("pytest -p evil_plugin", [ASK]),                            # a variant: other code than the plain runner
    ("PYTHONPATH=/tmp/x pytest", [("defer", "ESCALATE_COMMAND_DANGER")]),   # 10.11 (r0260): a search path outside the project is
    #                                                                           code injected (bashparse._env_more): asked as dangerous
    ("python3 scripts/gen.py", [ASK]),                           # an interpreter: not a runner in this version
    ("npm install", [("defer", "ESCALATE_COMMAND_DANGER")]),   # 0.2.90: the gate G2 (net-out)                                      # installer: needs the network
    ("npm start", [ASK]),
    ("/usr/bin/pytest", [ASK]),
])
def test_strict_sandbox_does_not_cover(dev, sb, cmd, want):
    sb(fact())
    assert dev.v(cmd) == want, cmd


def test_dangerous_and_secrets_still_asked(dev, sb):
    sb(fact())
    got = dev.v("rm -rf ~/x && pytest")
    assert got and all(v[0] != "allow" for v in got[:1]), got
    got = dev.v("cat ~/.ssh/id_ed25519")
    assert all(v != OK_SB for v in got), got


def test_outside_project_is_asked(dev, sb, tmp_path):
    sb(fact())
    other = tmp_path / "other"
    other.mkdir()
    assert OK_SB not in dev.v("cd %s && pytest" % other)


def test_runner_list():
    for c in ("pytest", "python -m pytest", "python3.12 -m pytest", "npm run", "npx jest", "make build", "go test", "cargo test"):
        assert hsb.runner(c), c
    for c in ("pytest [-p]", "python3", "python -m http", "npm install", "npx jest [fetch]", "cargo run", "go run", "bash", "./pytest", "npm start"):
        assert not hsb.runner(c), c


def test_evaluate_explains():
    ok, why = hsb.evaluate(fact(), ["pytest"], HOME)
    assert ok and why == []
    ok, why = hsb.evaluate(fact(domains=["x.com"], env_scrub=False), ["pytest"], HOME)
    assert not ok and any("allowedDomains" in w for w in why) and any("SCRUB" in w for w in why)
    ok, why = hsb.evaluate(fact(excluded=["docker compose *"]), ["pytest"], HOME)
    assert not ok and any("excludedCommands is not empty" in w for w in why)    # 0.2.56: any exclusion -> not strict
    ok, why = hsb.evaluate(fact(excluded=["docker compose *"]), ["pytest", "docker compose"], HOME)
    assert not ok


def test_judge_facts_drops_malformed_sandbox():
    base = {"facts": {"home": HOME, "proc_cwd": "/tmp", "env": {}, "fs": {}, "exec": None}}
    assert "sandbox" not in hj._facts(base)
    b = copy.deepcopy(base)
    b["facts"]["sandbox"] = {"v": 1}
    assert hj._facts(b)["sandbox"] is None
    b["facts"]["sandbox"] = fact()
    assert hj._facts(b)["sandbox"] == fact()


def test_facts_fs_carries_the_fact():
    f = hfs.FactsFS({"home": HOME, "proc_cwd": "/tmp", "fs": {}, "sandbox": fact()})
    assert f.sandbox() == fact()
    assert hfs.FactsFS({"home": HOME, "proc_cwd": "/tmp", "fs": {}}).sandbox() is None


# ---- the hook's real reader (mcp/deus_witness/hook/sandbox_fact.py) on settings files in a test HOME -> the server's judgement ----
import json as _json  # noqa: E402
import sys as _sys  # noqa: E402

_sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "mcp"))
from deus_witness.hook import failsafe as _fsafe, sandbox_fact as _sf  # noqa: E402

# 0.2.56: no `allowRead: ["."]` at user level: there "." is ~/.claude (settings-reference, "Sandbox path prefixes"), which would re-open
# ~/.claude/.credentials.json. The documented place for `"allowRead": ["."]` is the project's .claude/settings.json (PROJECT_STRICT).
# 0.2.57: + network.strictAllowlist (counts from the user / managed layer only); the scrub counts only from the hook's own environment
# (SCRUB_ENV, the default env of _client_fact), not from a settings `env` block.
STRICT_SETTINGS = {"sandbox": {"enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False,
                               "filesystem": {"denyRead": ["~/"]}, "network": {"strictAllowlist": True}}}
USER_LOCK = {"sandbox": {"network": {"strictAllowlist": True}}}
SCRUB_ENV = {"CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1"}
PROJECT_STRICT = {"sandbox": {"enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False,
                              "filesystem": {"denyRead": ["~/", "./.env"], "allowRead": ["."]}}}


def _client_fact(tmp_path, monkeypatch, user=None, project=None, local=None, tool_input=None, proj=None, env=None, transcript=None,
                 mode="default"):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True, exist_ok=True)
    managed = tmp_path / "managed"
    managed.mkdir(exist_ok=True)
    monkeypatch.setattr(_fsafe, "MANAGED_DIR_OVERRIDE", str(managed))
    proj = proj or tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True, exist_ok=True)
    for path, d in ((home / ".claude" / "settings.json", user), (proj / ".claude" / "settings.json", project),
                    (proj / ".claude" / "settings.local.json", local)):
        if d is not None:
            path.write_text(d if isinstance(d, str) else _json.dumps(d))
    return (_sf.fact(tool_input or {"command": "pytest"}, str(proj), env=SCRUB_ENV if env is None else env, home=str(home), platform="darwin",
                     transcript=transcript, permission_mode=mode),
            str(home), str(proj))


def test_client_reader_strict_settings(tmp_path, monkeypatch):
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=STRICT_SETTINGS)
    assert hsb.well_formed(f)
    assert hsb.evaluate(f, ["pytest"], home, proj) == (True, [])


@pytest.mark.parametrize("project_layer,why", [
    ({"sandbox": {"enabled": False}}, "enabled"),                                     # a higher layer switches it off
    ({"sandbox": {"network": {"allowedDomains": ["github.com"]}}}, "allowedDomains"),  # lists merge: a project adds a host
    ({"permissions": {"allow": ["WebFetch(domain:evil.example)"]}}, "allowedDomains"),
    ({"sandbox": {"excludedCommands": ["pytest *"]}}, "excludedCommands"),
    ({"sandbox": {"filesystem": {"allowRead": ["~/.ssh"]}}}, "denyRead"),
    ({"sandbox": {"network": {"allowAllUnixSockets": True}}}, "Unix"),
    ("{not json", "settings not readable"),
])
def test_client_reader_project_layer_weakens(tmp_path, monkeypatch, project_layer, why):
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=STRICT_SETTINGS, project=project_layer)
    ok, whys = hsb.evaluate(f, ["pytest"], home, proj)
    assert not ok and any(why in w for w in whys), whys


def test_client_reader_disable_flag_and_env_file(tmp_path, monkeypatch):
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=STRICT_SETTINGS, tool_input={"command": "pytest", "dangerouslyDisableSandbox": True})
    assert not hsb.evaluate(f, ["pytest"], home, proj)[0]
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=STRICT_SETTINGS, tool_input={"command": "pytest", "dangerouslyDisableSandbox": "true"})
    assert f["disable_flag"] is True                                                  # any value but false: fail closed
    p2 = tmp_path / "p2"
    (p2 / ".claude").mkdir(parents=True)
    (p2 / ".env").write_text("K=1")
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=STRICT_SETTINGS, proj=p2)
    ok, whys = hsb.evaluate(f, ["pytest"], home, proj)
    assert not ok and any(".env" in w for w in whys)
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=STRICT_SETTINGS, proj=p2, local={"permissions": {"deny": ["Read(./.env)"]}})
    assert hsb.evaluate(f, ["pytest"], home, proj) == (True, [])


def test_client_fact_end_to_end(dev, sb, tmp_path, monkeypatch):
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=STRICT_SETTINGS)
    f["deny_read"] = [HOME if x == home else x for x in f["deny_read"]]               # the server judges against the real home here
    sb(f)
    assert dev.v("pytest -q") == [OK_SB]


# ---- 0.2.56 ----
@pytest.mark.parametrize("sbx,why", [
    ({"allowUnsandboxedCommands": True}, "allowUnsandboxedCommands"),
    ({"allowUnsandboxedCommands": None}, "allowUnsandboxedCommands"),     # unset = Claude Code's default true
    ({"excludedCommands": ["docker compose *"]}, "excludedCommands"),       # another program: still not strict
])
def test_0256_retry_and_exclusions(tmp_path, monkeypatch, sbx, why):
    user = copy.deepcopy(STRICT_SETTINGS)
    for k, v in sbx.items():
        if v is None:
            user["sandbox"].pop(k, None)
        else:
            user["sandbox"][k] = v
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=user)
    ok, whys = hsb.evaluate(f, ["pytest"], home, proj)
    assert not ok and any(why in w for w in whys), whys


def test_0256_documented_block_in_project_settings_is_strict(tmp_path, monkeypatch):
    p2 = tmp_path / "p2"
    (p2 / ".claude").mkdir(parents=True)
    (p2 / ".env").write_text("K=1")
    f, home, proj = _client_fact(tmp_path, monkeypatch, project=PROJECT_STRICT, proj=p2)
    assert not hsb.evaluate(f, ["pytest"], home, proj)[0]                      # 0.2.57: strictAllowlist is not in a user/managed layer
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=USER_LOCK, project=PROJECT_STRICT, proj=p2)
    assert hsb.evaluate(f, ["pytest"], home, proj) == (True, [])
    assert proj in f["allow_read"]                                              # "." of the project file = the project root


def test_0256_user_level_dot_is_claude_dir(tmp_path, monkeypatch):
    user = copy.deepcopy(STRICT_SETTINGS)
    user["sandbox"]["filesystem"]["allowRead"] = ["."]                          # = ~/.claude: re-opens ~/.claude/.credentials.json
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=user)
    assert os.path.join(home, ".claude") in f["allow_read"] and proj not in f["allow_read"]
    ok, whys = hsb.evaluate(f, ["pytest"], home, proj)
    assert not ok and any(".claude/.credentials.json" in w for w in whys), whys


def test_0256_relative_path_in_managed_is_unknown(tmp_path, monkeypatch):
    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / "managed-settings.json").write_text(_json.dumps({"sandbox": {"filesystem": {"allowRead": ["build"]}}}))
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=STRICT_SETTINGS)
    assert f["sources"].get("relative-managed") == "unread"
    assert not hsb.evaluate(f, ["pytest"], home, proj)[0]


def test_0256_config_dir_hidden_by_scrub(tmp_path, monkeypatch):
    """The scrub removes CLAUDE_CONFIG_DIR from the hook's environment; the transcript path shows Claude Code uses another directory."""
    other = tmp_path / "cfg"
    (other / "projects" / "-p").mkdir(parents=True)
    tr = str(other / "projects" / "-p" / "s.jsonl")
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=STRICT_SETTINGS, transcript=tr)
    assert f["sources"]["user"] == "unread" and not hsb.evaluate(f, ["pytest"], home, proj)[0]
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=STRICT_SETTINGS,
                                 transcript=os.path.join(home, ".claude", "projects", "-p", "s.jsonl"))
    assert f["sources"]["user"] == "ok" and hsb.evaluate(f, ["pytest"], home, proj)[0]
    (other / "settings.json").write_text(_json.dumps(STRICT_SETTINGS))         # CLAUDE_CONFIG_DIR visible and equal: read from there
    f, home, proj = _client_fact(tmp_path, monkeypatch, env=dict(SCRUB_ENV, CLAUDE_CONFIG_DIR=str(other)), transcript=tr)
    assert f["sources"]["user"] == "ok" and hsb.evaluate(f, ["pytest"], home, proj)[0]


def test_0256_signed_mandate_is_not_widened_by_the_new_default(client, owner, tmp_path, sb):
    """A mandate signed without command.sandboxed keeps asking; the server keeps only "allow" and refuses other values."""
    p = tmp_path / "proj3"
    p.mkdir()
    d = Dev(client, owner, p.resolve(), opt_in=False)
    sb(fact())
    assert d.v("pytest -q") == [ASK]
    assert "sandboxed" not in d.m["permissions"]["command"]
    from app.mandates import mandate_from_form
    from app.context import Err
    f = default_form(str(p))
    f["command"]["sandboxed"] = "ask"
    assert "sandboxed" not in mandate_from_form(f, "dw:" + "0" * 32, "ag_000000000000", "x")["permissions"]["command"]
    f["command"]["sandboxed"] = "yes"
    with pytest.raises(Err):
        mandate_from_form(f, "dw:" + "0" * 32, "ag_000000000000", "x")



@pytest.mark.parametrize("cmd", ["npm test --node-opt=--import=data:text/javascript,1", "npm test --node-o=--import=data:text/javascript,1",
                                 "make --ev='x:;id' x", "make -E 'x:;id' x", "make -sE 'x:;id' x", "pylint --init-h='import os' x.py",
                                 "npx jest --setup-files=/tmp/x.js"])
def test_0256_code_in_the_line_is_asked_even_in_strict_sandbox(dev, sb, cmd):
    """RT-0.2.55c x V3: options that run code given on the command line are a variant -> never OK_SANDBOXED."""
    sb(fact())
    assert all(v != OK_SB for v in dev.v(cmd)), cmd
