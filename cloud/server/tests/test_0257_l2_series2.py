"""0.2.57: findings of L2 series 2 (OTCHET-V3-L2, "Серия 2").
(1) the strict sandbox needs a network lock: sandbox.network.strictAllowlist true from the user or managed layer (or allowManagedDomainsOnly
    in managed), and the event's permission_mode must be one checked at L2 (default, acceptEdits, bypassPermissions); bypassPermissions
    without the lock let curl through (a1), with it the network was refused (a2).
(2) CLAUDE_CODE_SUBPROCESS_ENV_SCRUB counts only from the hook's own environment (b2: a project `env` block did not switch it on).
(4) a freshly opened ledger (first call after the server process starts) is caught up before the allowance / sandbox / recipient checks.
End to end: the client hook from the sources (deus_witness 0.2.39, thin.judge) -> the server (TestClient)."""
import copy
import json
import math
import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
from app.hookjudge import sandbox as hsb
from app.main import create_app
from tests.helpers import ORIGIN, act
from tests.test_v3_sandbox import ASK, OK_SB, STRICT_SETTINGS, PROJECT_STRICT, USER_LOCK, SCRUB_ENV, Dev, _client_fact, fact, HOME
from tests.test_allowance_0210 import Dev as Dev0210

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../mcp")))
from deus_witness import client as dwc  # noqa: E402
from deus_witness import __version__ as CLIENT_VERSION  # noqa: E402
from deus_witness.hook import failsafe as _fsafe, main as thin, sandbox_fact as _sf  # noqa: E402
from tests.test_0216_thin import Via  # noqa: E402


# ---------- (1) the network lock and the permission mode: the server's rule ----------
def test_bypass_without_lock_is_not_strict():
    ok, why = hsb.evaluate(fact(strict_allowlist=None, permission_mode="bypassPermissions"), ["pytest"], HOME)
    assert not ok and any("strictAllowlist" in w and "bypassPermissions" in w for w in why), why
    ok, why = hsb.evaluate(fact(strict_allowlist=False), ["pytest"], HOME)        # every mode: the lock is required
    assert not ok and any("strictAllowlist" in w for w in why), why


@pytest.mark.parametrize("mode", ["default", "acceptEdits", "bypassPermissions"])
def test_checked_modes_with_lock_are_strict(mode):
    assert hsb.evaluate(fact(permission_mode=mode), ["pytest"], HOME) == (True, [])


def test_managed_domains_only_is_a_lock():
    assert hsb.evaluate(fact(strict_allowlist=None, managed_domains_only=True, permission_mode="bypassPermissions"), ["pytest"], HOME) == (True, [])


@pytest.mark.parametrize("mode", ["plan", "dontAsk", "something-new", None])   # r0263: auto accepted (L2+ 12.11)
def test_unchecked_modes_fail_closed(mode):
    ok, why = hsb.evaluate(fact(permission_mode=mode), ["pytest"], HOME)
    assert not ok and any("permission mode" in w for w in why), why


@pytest.mark.parametrize("over", [{"strict_allowlist": "true"}, {"managed_domains_only": None}, {"permission_mode": 1},
                                  {"permission_mode": "x" * 33}])
def test_malformed_new_keys(over):
    assert not hsb.well_formed(fact(**over))


@pytest.mark.parametrize("drop", ["strict_allowlist", "permission_mode"])
def test_prototype_fact_without_new_keys_is_no_fact(drop):
    f = fact()
    f.pop(drop)
    assert not hsb.well_formed(f) and not hsb.evaluate(f, ["pytest"], HOME)[0]


# ---------- (1) the client reads the lock only from the user / managed layer ----------
def _no_lock():
    u = copy.deepcopy(STRICT_SETTINGS)
    u["sandbox"].pop("network")
    return u


@pytest.mark.parametrize("layer", ["project", "local"])
def test_lock_in_project_or_local_layer_is_ignored(tmp_path, monkeypatch, layer):
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=_no_lock(), **{layer: USER_LOCK})
    assert f["strict_allowlist"] is None
    ok, why = hsb.evaluate(f, ["pytest"], home, proj)
    assert not ok and any("strictAllowlist" in w for w in why), why


def test_lock_in_user_layer(tmp_path, monkeypatch):
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=STRICT_SETTINGS)
    assert f["strict_allowlist"] is True and f["permission_mode"] == "default"
    assert hsb.evaluate(f, ["pytest"], home, proj) == (True, [])


def test_lock_in_managed_layer_wins_and_managed_domains_only(tmp_path, monkeypatch):
    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / "managed-settings.json").write_text(json.dumps({"sandbox": {"network": {"strictAllowlist": True}}}))
    u = _no_lock()
    u["sandbox"]["network"] = {"strictAllowlist": False}
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=u)
    assert f["strict_allowlist"] is True and hsb.evaluate(f, ["pytest"], home, proj)[0]       # managed beats user
    (managed / "managed-settings.json").write_text(json.dumps({"sandbox": {"network": {"allowManagedDomainsOnly": True}}}))
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=_no_lock(), mode="bypassPermissions")
    assert f["managed_domains_only"] is True and hsb.evaluate(f, ["pytest"], home, proj)[0]


def test_managed_domains_only_from_user_layer_is_ignored(tmp_path, monkeypatch):
    u = _no_lock()
    u["sandbox"]["network"] = {"allowManagedDomainsOnly": True}
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=u)
    assert f["managed_domains_only"] is False and not hsb.evaluate(f, ["pytest"], home, proj)[0]


def test_bypass_reader_without_lock(tmp_path, monkeypatch):
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=_no_lock(), mode="bypassPermissions")
    ok, why = hsb.evaluate(f, ["pytest"], home, proj)
    assert not ok and any("bypassPermissions" in w for w in why), why


# ---------- (2) the scrub counts only from the hook's own environment ----------
@pytest.mark.parametrize("layer", ["user", "project", "local"])
def test_scrub_in_settings_env_does_not_count(tmp_path, monkeypatch, layer):
    s = {"env": {"CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1"}}
    kw = {"user": dict(STRICT_SETTINGS, **s)} if layer == "user" else {"user": STRICT_SETTINGS, layer: s}
    # r0263: the key in the environment and not in sandbox.credentials.envVars (STRICT_SETTINGS has none) -- then only the scrub of the
    # hook's own environment would hide it, and a settings `env` block does not switch it on
    f, home, proj = _client_fact(tmp_path, monkeypatch, env={"DEUS_WITNESS_KEY": "dwk_x"}, **kw)
    assert f["env_scrub"] is False and f["env_hidden"] is False
    ok, why = hsb.evaluate(f, ["pytest"], home, proj)
    assert not ok and any("agent key" in w for w in why), why


def test_scrub_in_process_env_counts(tmp_path, monkeypatch):
    f, home, proj = _client_fact(tmp_path, monkeypatch, user=STRICT_SETTINGS, env={"CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1"})
    assert f["env_scrub"] is True and hsb.evaluate(f, ["pytest"], home, proj)[0]


# ---------- end to end: the hook from the sources -> the server ----------
class Hook:
    """The real thin hook (deus_witness.hook.main.judge, client from the sources) against the in-process server; HOME is a temp home whose
    ~/.claude/settings.json is the user layer, the managed directory is an empty temp dir."""

    def __init__(self, client, owner, tmp_path, monkeypatch, user, project=None, scrub=True, plat=None):
        assert CLIENT_VERSION == "0.2.79"   # 16.11 (c078): client 0.2.78 (lock, foreign rewriters, check-after-call in lock, 106 everyday commands incl. r0335); 14.11 (r0303): client 0.2.77 (try prints the full short list of what the hook sends, docs/data.md); 14.11 (r0297 + r0302): client 0.2.76 (hook in auto mode: neutral allow, executed / not_executed report, PermissionDenied); 14.11 (r0293): client 0.2.75 (local rule knows browser password stores, cookies, password exports, Mail); 13.11 (r0291): client 0.2.74 (docs only); 13.11 (r0288 + r0289): client 0.2.73 (status page link in a refusal; consent line in try); 13.11 (r0285 + r0286): client 0.2.72 (parallel calls wait for a slot: WITNESS_BUSY / WITNESS_QUOTA; verifier --pq-cutoff, algorithm lists); 13.11 (r0279): client 0.2.71 (shared /tmp is never a mandate target; Linux quiet mode gets the session birth time); 13.11 (r0274): client 0.2.70 (links on the configured witness; home in a temp dir is asked); 13.11 (r0273): client 0.2.69 (trial read waits: TRIAL_NOT_CLAIMED; audit in the home folder; undo-strict words); 13.11 (r0272): client 0.2.68 (pin of the approved call, PostToolUse check); 13.11 (r0271): client 0.2.67 (README: containers not supported); 13.11 (r0270): client 0.2.66 (Linux quiet mode); 13.11 (r0267): client 0.2.65 (git_head fact, push words); 12.11 (r0265): client 0.2.63 (short connect/reply timeouts, read budget, down mark, git_self); 12.11 (r0264): client 0.2.62 (TMPDIR words, honest HOOK_ERROR, K1 git config reads, try mark of the hook); 12.11 (r0263): client 0.2.61 (try mark, session words, --settings read, TMPDIR); 12.11: client 0.2.60 (quiet mode, switch lock); 11.11: client 0.2.59 (closed list, held claim); 03.11: client 0.2.57 (friction: notify, which); 0.2.56 (fresh sandbox fact: session id, settings digest, doubt; was 0.2.55)
        home = tmp_path / "home"
        (home / ".claude").mkdir(parents=True)
        (home / ".claude" / "settings.json").write_text(json.dumps(user))
        managed = tmp_path / "managed"
        managed.mkdir()
        monkeypatch.setattr(_fsafe, "MANAGED_DIR_OVERRIDE", str(managed))
        monkeypatch.setenv("HOME", str(home))                     # the hook's home and the server's view of it agree
        self.proj = os.path.realpath(str(tmp_path / "proj"))
        os.makedirs(os.path.join(self.proj, ".claude"))
        if project is not None:
            with open(os.path.join(self.proj, ".claude", "settings.json"), "w") as fh:
                json.dump(project, fh)
        self.d = Dev(client, owner, self.proj)
        self.key = self.d.hdr["Authorization"][7:]
        self.env = {"DEUS_WITNESS_KEY": self.key, "CLAUDE_PROJECT_DIR": self.proj, "HOME": str(home), "DEUS_WITNESS_EXEC_SCAN": "0"}
        if scrub:
            self.env.update(SCRUB_ENV)
        self.c, self.pins = client, str(tmp_path / "pins" / "w.json")
        # 0.2.88 / client 0.2.56: a strict fact needs a session (id + transcript born after the settings) and a readable command line
        monkeypatch.setattr(_sf, "ANCESTRY_OVERRIDE", ["/bin/sh -c deus-witness-hook", "claude", "-zsh"])
        if plat is not None:
            _as_platform(monkeypatch, plat)
        self.coarse = _birth_clock(monkeypatch, tmp_path)
        self.restart()

    def restart(self):
        """A new Claude Code session (what changing the environment really takes)."""
        self.sid = "s0257-%s" % os.urandom(4).hex()
        self.transcript = os.path.join(self.env["HOME"], ".claude", "projects", "p", self.sid + ".jsonl")
        os.makedirs(os.path.dirname(self.transcript), exist_ok=True)
        _session_born_later(self.coarse)
        with open(self.transcript, "w") as fh:
            fh.write("{}\n")

    def run(self, cmd, mode):
        w = dwc.Witness("http://localhost:8810", self.key, pin_path=self.pins, transport=Via(self.c))
        ev = {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": self.proj, "permission_mode": mode,
              "session_id": self.sid, "transcript_path": self.transcript}
        o = thin.judge(ev, thin.Settings(self.env), witness=w)["hookSpecificOutput"]
        return o["permissionDecision"], o.get("permissionDecisionReason", "")


def _as_platform(monkeypatch, plat):
    """r0279 (Linux CI 13.11): the e2e tests below took the platform of the machine running them; on a Linux runner without bubblewrap
    the hook rightly reported no strict sandbox and `pytest -q` was asked. They now name the client's machine: macOS (Seatbelt), or Linux
    with Claude Code's sandbox installed (bubblewrap and socat on PATH, an architecture with Claude Code's seccomp filter)."""
    monkeypatch.setattr(_sf, "os_kind", lambda platform=None: platform or plat)
    if plat == "linux":
        monkeypatch.setattr(_sf, "_which", lambda name: "/usr/bin/" + name if name in ("bwrap", "socat") else None)
        import platform as _pl
        monkeypatch.setattr(_pl, "machine", lambda: "x86_64")


def _birth_clock(monkeypatch, tmp_path):
    """r0279 (Linux CI 13.11): the strict fact needs the session's start = the transcript's BIRTH time. Python has no st_birthtime on Linux
    and the client up to 0.2.70 read nothing else, so on Linux every session was "session start unknown" (not strict: fail closed). The
    client from r0279 reads it through statx (sandbox_fact._linux_birth). An installed client that still cannot read a birth time on this
    machine gets the transcript's mtime instead (the test writes the transcript once, so mtime = birth); a missing transcript stays None."""
    probe = tmp_path / "birth-probe"
    probe.write_text("x")
    b = _sf._session_start(str(probe))
    if b is not None:
        return float(b).is_integer()                              # r0282: whole seconds (statx %W, client 0.2.71 on Linux)

    def start(transcript):
        if not isinstance(transcript, str) or not os.path.isabs(transcript):
            return None
        try:
            return os.stat(transcript).st_mtime
        except OSError:
            return None
    monkeypatch.setattr(_sf, "_session_start", start)
    return False


def _session_born_later(coarse):
    """r0282 (Linux CI 13.11, client 0.2.71): a new session's transcript is born AFTER the settings files were written. With a birth clock in
    whole seconds (Linux: statx %W, rounded down = the safe side) "after" is only seen from the next second on: a settings file written in
    the same second as the session started counts as changed after it (not strict). A real Claude Code start is never in the same second as
    the settings it reads -- so the test waits for the next second instead of 10 ms. The rule itself is unchanged (test_r0282_*)."""
    if coarse:
        time.sleep(math.floor(time.time()) + 1.05 - time.time())
    else:
        time.sleep(0.01)


def _last(client):
    r = client.app.state.ctx.db.one("SELECT verdict, reason FROM actions ORDER BY created_at DESC, rowid DESC LIMIT 1")
    return r["verdict"], r["reason"]


def test_e2e_bypass_without_strict_allowlist_is_asked(client, owner, tmp_path, monkeypatch):
    h = Hook(client, owner, tmp_path, monkeypatch, user=_no_lock(), project=PROJECT_STRICT)
    d, why = h.run("pytest -q", "bypassPermissions")
    assert d != "allow" and _last(client) == ASK, (d, why)


@pytest.mark.parametrize("plat", ["darwin", "linux"])
def test_e2e_bypass_with_strict_allowlist_is_sandboxed(client, owner, tmp_path, monkeypatch, plat):
    h = Hook(client, owner, tmp_path, monkeypatch, user=STRICT_SETTINGS, project=PROJECT_STRICT, plat=plat)
    d, why = h.run("pytest -q", "bypassPermissions")
    assert d == "allow" and _last(client) == OK_SB, (d, why)
    d, why = h.run("pytest -q", "plan")                           # not checked at L2: asked (r0263: auto is checked)
    assert d != "allow" and _last(client) == ASK, (d, why)


@pytest.mark.parametrize("plat", ["darwin", "linux"])
def test_e2e_scrub_only_in_project_env_is_asked(client, owner, tmp_path, monkeypatch, plat):
    proj = dict(PROJECT_STRICT, env={"CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1"})
    h = Hook(client, owner, tmp_path, monkeypatch, user=USER_LOCK, project=proj, scrub=False, plat=plat)
    d, why = h.run("pytest -q", "default")
    assert d != "allow" and _last(client) == ASK, (d, why)
    h.env.update(SCRUB_ENV)                                       # the same settings, Claude Code started with the scrub
    h.restart()                                                   # 0.2.88: that is a new session (the environment is fixed per session)
    d, why = h.run("pytest -q", "default")
    assert d == "allow" and _last(client) == OK_SB, (d, why)


# ---------- (4) the first call after the server process starts ----------
def _fresh(app):
    """A second server process over the same data directory: a new hub, every ledger object opened cold."""
    return TestClient(create_app(app.state.ctx.cfg), base_url=ORIGIN)


def test_first_call_after_start_sees_the_project_allowance(client, owner, tmp_path, app):
    proj = tmp_path / "proj"
    proj.mkdir()
    d = Dev0210(client, owner, proj.resolve())
    [(_, r)] = d.send("pytest -q")
    assert (r["verdict"], r["reason"]) == ASK
    res, a = d.allowance(r["rid"])
    assert res.status_code == 200, res.text
    c2 = _fresh(app)
    d.c = c2
    [(_, r2)] = d.send("pytest -q")
    assert (r2["verdict"], r2["reason"]) == ("allow", "OK_ALLOWANCE"), r2


def test_first_call_after_start_sandbox_cover(client, owner, tmp_path, app, monkeypatch):
    from app.hookjudge import fs as hfs
    p = tmp_path / "proj"
    p.mkdir()
    d = Dev(client, owner, p.resolve())
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", fact())
    d.c = _fresh(app)
    assert d.v("pytest -q") == [OK_SB]


def test_first_call_after_start_every_recipient_is_judged(client, owner, app):
    """Before 0.2.57 a cold NO_MANDATE on the cc address replaced the action and the core judged only cc: `to` outside the list was allowed."""
    ag, hdr = owner.new_agent("demo", "bot")
    m, r = owner.mandate(ag["id"])
    assert r.status_code == 200, r.text
    c2 = _fresh(app)
    j = act(c2, hdr, "send_email", {"to": "x@evil.example", "cc": "bob@partner.example", "subject": "s", "body": "b"}).json()
    assert j["verdict"] != "allow", j
    j = act(c2, hdr, "send_email", {"to": "bob@partner.example", "cc": "bob@partner.example", "subject": "s", "body": "b"}).json()
    assert j["verdict"] == "allow", j
