"""0.2.88 (client 0.2.56): when in doubt -- ask (fail closed).
(1) The strict-sandbox fact must be FRESH: Claude Code reads its settings when the session starts; the hook reads them at every call. A session
    whose settings changed (a changed digest / fact between two calls, a file modified after the session started, a write of the agent into
    a settings file), or whose fact cannot be collected unambiguously (no session id, no transcript, Claude Code started with --settings /
    --setting-sources / --add-dir, ps unreadable, allowWrite / additionalDirectories), is NOT strict -- until a new session.
    Not a question on the ordinary path: "Yes, don't ask again" (a permission rule Claude Code writes into settings.local.json) changes nothing.
(2) Irreversible git commands outside the 0.2.82 git-destroy list are asked even in the strict sandbox; what the reflog recovers is not.
Red first: written before the code (run against HEAD 1cec75b: see OTCHET-0288.md)."""
import json
import os
import time

import pytest

from tests import r0261

from app.hookjudge import sandbox as hsb
from app.hookjudge.mapping import map_event
from tests.test_0282_irreversibility_gate import Dev as Dev82, asked, fact as fact82
from tests.test_0257_l2_series2 import Hook, _last, _session_born_later
from tests.test_v3_sandbox import ASK, OK_SB, STRICT_SETTINGS, PROJECT_STRICT, fact

from deus_witness.hook import sandbox_fact as _sf  # noqa: E402  (test_0257 put mcp/ on sys.path)


# ---------------------------------------------------------------- (2) git ------------------------------------------------------------
GIT_ASK = ["git restore -SW .", "git restore :/", "git reset --merge HEAD~1", "git clean -d", "git clean -fdx", "git clean -X", "git checkout --force main", "git checkout -f main", "git checkout -- .", "git restore .", "git switch --discard-changes main", "git switch -f main",
           "git stash drop", "git stash clear", "git branch -D feat", "git branch --delete --force feat", "git branch -d -f feat",
           "git branch -M new", "git branch -m -f old new", "git tag -d v1", "git tag --delete v1", "git tag -f v1 HEAD~1",
           "git reflog expire --expire=now --all", "git reflog delete HEAD@{1}", "git gc --prune=now", "git gc --prune=all", "git prune",
           "git repack -a -d", "git update-ref -d refs/heads/x", "git update-ref --stdin", "git symbolic-ref -d HEAD", "git filter-branch -f",
           "git filter-repo --path x", "git worktree remove --force ../wt", "git merge --abort", "git rm -f a.py", "git rm -rf src",
           "git mv -f a.py b.py", "git checkout-index -a -f", "git read-tree --reset -u HEAD", "git -C . reset --merge"]
GIT_KEEP = ["git reset --soft HEAD~1", "git reset HEAD~1", "git reset --keep HEAD~1", "git reset -- a.py", "git rebase main", "git rebase -i HEAD~3",
            "git rebase --abort", "git rebase --skip", "git commit --amend --no-edit", "git branch -d feat", "git branch -f feat HEAD~1",
            "git branch -m old new", "git switch -c feat", "git switch -C feat", "git checkout -b feat", "git restore --staged a.py",
            "git restore -S a.py", "git stash", "git stash pop", "git stash apply", "git rm --cached a.py", "git rm a.py", "git gc",
            "git gc --aggressive", "git update-ref refs/heads/x HEAD", "git worktree remove ../wt", "git clean -n", "git clean -fdn",
            "git tag v1", "git tag -a v1 -m msg", "git cherry-pick abc", "git revert abc", "git merge feat", "git status", "git log -5",
            "git diff", "git add -A", "git commit -m 'x -d'",
            # 0.2.53 light writes the owner's mandate lists, judged path by path like `rm <file>` (not a question for show):
            "git checkout -- src/a.py", "git checkout HEAD -- a.py", "git restore a.py", "git restore --worktree a.py",
            "git restore --source=HEAD~2 a.py"]


def dangers(proj, cmd):
    env = {"CLAUDE_PROJECT_DIR": proj, "HOME": "/nonexistent-home"}
    out = []
    for m in map_event({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": proj}, env=env):
        out += [d for d in (m.args.get("_witness") or {}).get("danger", []) if d not in out]
    return out


@pytest.fixture
def repo(tmp_path):
    p = (tmp_path / "proj").resolve()
    (p / ".git").mkdir(parents=True)
    (p / "src").mkdir()
    (p / "a.py").write_text("x")
    return str(p)


@pytest.mark.parametrize("cmd", GIT_ASK)
def test_irreversible_git_is_git_destroy(repo, cmd):
    assert any(d.startswith("git-destroy:") for d in dangers(repo, cmd)), (cmd, dangers(repo, cmd))


@pytest.mark.parametrize("cmd", GIT_KEEP)
def test_reflog_recoverable_git_is_not_git_destroy(repo, cmd):
    assert not any(d.startswith("git-destroy:") for d in dangers(repo, cmd)), (cmd, dangers(repo, cmd))


def test_push_prune_is_force_push(repo):
    assert any(d.startswith("git-force-push:") for d in dangers(repo, "git push --prune origin"))


def test_checkout_of_a_file_without_dashes_stays_the_listed_light_write(tmp_path):
    import subprocess
    p = str((tmp_path / "real").resolve())
    os.makedirs(p)
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_AUTHOR_NAME="d", GIT_AUTHOR_EMAIL="d@x.invalid",
               GIT_COMMITTER_NAME="d", GIT_COMMITTER_EMAIL="d@x.invalid")
    with open(os.path.join(p, "a.py"), "w") as fh:
        fh.write("x")
    for a in (["init", "-q", "-b", "main"], ["add", "a.py"], ["commit", "-q", "-m", "i"], ["branch", "feat"]):
        subprocess.run(["git", "-C", p] + a, check=True, capture_output=True, env=env)
    assert not any(x.startswith("git-destroy:") for x in dangers(p, "git checkout a.py"))      # a file: the 0.2.53 plain form (like rm a.py)
    assert not any(x.startswith("git-destroy:") for x in dangers(p, "git checkout feat"))      # a branch: git refuses to clobber changes
    assert any(x.startswith("git-destroy:") for x in dangers(p, "git checkout -- ."))


@pytest.fixture
def dev(client, owner, tmp_path):
    p = tmp_path / "p82"
    p.mkdir()
    (p / ".git").mkdir()
    (p / "a.py").write_text("x")
    return Dev82(client, owner, p.resolve())


IRREVERSIBLE_GIT = ["git reset --merge HEAD~1", "git checkout -- .", "git restore .", "git tag -d v1", "git stash clear",
                    "git gc --prune=now", "git reflog delete HEAD@{1}", "git update-ref -d refs/heads/x",
                    "git worktree remove --force ../wt", "git switch --discard-changes main", "python3 x.py && git clean -fd"]


@pytest.mark.parametrize("cmd", r0261.still(IRREVERSIBLE_GIT))
def test_irreversible_git_asked_in_strict_sandbox(dev, monkeypatch, cmd):
    from app.hookjudge import fs as hfs
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", fact82())
    got = dev.v(cmd)
    assert asked(got), (cmd, got)


# r0261 (Р-1111-закрытый-список): irreversible git INSIDE the project is not on the closed list of the strict sandbox -- silent now
# (tests/r0261.DESTROY: the weakest point of the list, reported to Deus). The old "asked" is kept above for what is still on the list.
@pytest.mark.parametrize("cmd", r0261.now(IRREVERSIBLE_GIT))
def test_irreversible_git_r0261_now_silent(dev, monkeypatch, cmd):
    from app.hookjudge import fs as hfs
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", fact82())
    got = dev.v(cmd)
    PRED = True
    assert r0261.quiet(got) is PRED, (cmd, got)


def test_recoverable_git_runs_in_strict_sandbox(dev, monkeypatch):
    from app.hookjudge import fs as hfs
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", fact82())
    for cmd in ("git reset --soft HEAD~1", "git commit --amend --no-edit"):
        assert not asked(dev.v(cmd)), cmd


# ---------------------------------------------------------------- (1) the fact's own rule ---------------------------------------------
def test_fact_without_freshness_keys_is_no_fact():
    for k in ("settings_digest", "since_start", "doubt"):
        f = fact()
        f.pop(k)
        assert not hsb.well_formed(f) and not hsb.evaluate(f, ["pytest"], hsb.posixpath.expanduser("~"))[0], k
    assert not hsb.well_formed(fact(settings_digest="x" * 64)) and not hsb.well_formed(fact(doubt="no"))


def test_doubt_is_not_strict():
    ok, why = hsb.evaluate(fact(doubt=["Claude Code was started with --settings: the hook cannot read what it sets"]), ["pytest"],
                           os.path.expanduser("~"))
    assert not ok and any("--settings" in w for w in why)


def test_fact_key_ignores_per_call_keys():
    a = fact()
    assert hsb.fact_key(a) == hsb.fact_key(fact(disable_flag=True, permission_mode="auto", env_files=["/p/.env"], since_start=["user"],
                                                doubt=["x"]))
    assert hsb.fact_key(a) != hsb.fact_key(fact(deny_read=["/x"])) and hsb.fact_key(a) != hsb.fact_key(fact(settings_digest="0" * 64))


# ---------------------------------------------------------------- (1) end to end: client from the sources -> server -----------------
class Sess(Hook):
    """test_0257's Hook with a session: every event carries session_id and transcript_path (created after the settings files, as when
    Claude Code starts after they were written)."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.n = 0
        self.home = self.env["HOME"]
        self.new_session()

    def new_session(self):
        self.n += 1
        self.sid = "sess-%d" % self.n
        t = os.path.join(self.home, ".claude", "projects", "p", "%s.jsonl" % self.sid)
        os.makedirs(os.path.dirname(t), exist_ok=True)
        _session_born_later(self.coarse)                          # r0282: a later second when the client's birth clock is whole seconds
        with open(t, "w") as fh:
            fh.write("{}\n")
        self.transcript = t

    def event(self, tool, inp, mode="default"):
        ev = {"tool_name": tool, "tool_input": inp, "cwd": self.proj, "permission_mode": mode}
        if self.sid is not None:
            ev["session_id"] = self.sid
        if self.transcript is not None:
            ev["transcript_path"] = self.transcript
        return ev

    def run(self, cmd, mode="default"):
        from deus_witness import client as dwc
        from deus_witness.hook import main as thin
        from tests.test_0216_thin import Via
        w = dwc.Witness("http://localhost:8810", self.key, pin_path=self.pins, transport=Via(self.c))
        o = thin.judge(self.event("Bash", {"command": cmd}, mode), thin.Settings(self.env), witness=w)["hookSpecificOutput"]
        return o["permissionDecision"], o.get("permissionDecisionReason", "")

    def tool(self, tool, inp):
        from deus_witness import client as dwc
        from deus_witness.hook import main as thin
        from tests.test_0216_thin import Via
        w = dwc.Witness("http://localhost:8810", self.key, pin_path=self.pins, transport=Via(self.c))
        o = thin.judge(self.event(tool, inp), thin.Settings(self.env), witness=w) or {}
        return (o.get("hookSpecificOutput") or {}).get("permissionDecision")

    def user_settings(self, d, later=True):
        p = os.path.join(self.home, ".claude", "settings.json")
        with open(p, "w") as fh:
            json.dump(d, fh)
        if later:                                                 # modified now: after this session's transcript, before the next one
            t = time.time()
            os.utime(p, (t, t))


@pytest.fixture
def clean_ps(monkeypatch):
    monkeypatch.setattr(_sf, "ANCESTRY_OVERRIDE", ["/bin/sh -c deus-witness-hook", "claude", "-zsh"])


def _sess(client, owner, tmp_path, monkeypatch, user=STRICT_SETTINGS):
    # r0279 (Linux CI): the client is a Mac (Seatbelt); on a runner without bubblewrap the machine's own platform was never strict.
    # Linux with Claude Code's sandbox installed: test_0257_l2_series2 (plat="linux").
    return Sess(client, owner, tmp_path, monkeypatch, user=user, project=PROJECT_STRICT, plat="darwin")


def test_e2e_fresh_session_is_strict(client, owner, tmp_path, monkeypatch, clean_ps):
    h = _sess(client, owner, tmp_path, monkeypatch)
    for _ in range(2):
        d, why = h.run("pytest -q")
        assert d == "allow" and _last(client) == OK_SB, (d, why)


def test_e2e_settings_changed_between_calls_is_not_strict_until_new_session(client, owner, tmp_path, monkeypatch, clean_ps):
    h = _sess(client, owner, tmp_path, monkeypatch)
    d, why = h.run("pytest -q")
    assert d == "allow", why
    u = json.loads(json.dumps(STRICT_SETTINGS))
    u["sandbox"]["filesystem"]["denyRead"].append("/opt/x")       # still strict-looking, but not what Claude Code started with
    h.user_settings(u)
    for _ in range(2):                                            # sticky
        d, why = h.run("pytest -q")
        assert d != "allow" and _last(client) == ASK, (d, why)
    h.new_session()                                               # a restart: the new settings are what Claude Code runs with
    assert h.run("pytest -q")[0] == "allow" and _last(client) == OK_SB


def test_e2e_loose_to_strict_looking_in_session_stays_asked(client, owner, tmp_path, monkeypatch, clean_ps):
    loose = json.loads(json.dumps(STRICT_SETTINGS))
    loose["sandbox"]["network"]["allowedDomains"] = ["evil.example"]
    h = _sess(client, owner, tmp_path, monkeypatch, user=loose)
    assert h.run("pytest -q")[0] != "allow"
    h.user_settings(STRICT_SETTINGS)                              # the agent removes the domain; Claude Code still lets it through
    d, why = h.run("pytest -q")
    assert d != "allow" and _last(client) == ASK, (d, why)


def test_e2e_dont_ask_again_rule_keeps_strict(client, owner, tmp_path, monkeypatch, clean_ps):
    h = _sess(client, owner, tmp_path, monkeypatch)
    assert h.run("pytest -q")[0] == "allow"
    u = dict(STRICT_SETTINGS, permissions={"allow": ["Bash(npm test:*)", "mcp__x__y"]})
    h.user_settings(u)                                            # what "Yes, don't ask again" writes: not sandbox-relevant
    d, why = h.run("pytest -q")
    assert d == "allow" and _last(client) == OK_SB, (d, why)


def test_e2e_first_view_after_a_non_bash_call_counts(client, owner, tmp_path, monkeypatch, clean_ps):
    h = _sess(client, owner, tmp_path, monkeypatch)
    h.tool("Read", {"file_path": os.path.join(h.proj, "README.md")})     # the session's first call: the witness keeps this view
    u = json.loads(json.dumps(STRICT_SETTINGS))
    u["sandbox"]["filesystem"]["denyRead"].append("/opt/y")
    h.user_settings(u)
    d, why = h.run("pytest -q")
    assert d != "allow" and _last(client) == ASK, (d, why)


def test_e2e_file_modified_after_session_start_is_not_strict(client, owner, tmp_path, monkeypatch, clean_ps):
    h = _sess(client, owner, tmp_path, monkeypatch)
    h.user_settings(STRICT_SETTINGS)                              # same content, but modified after the transcript was born
    d, why = h.run("pytest -q")
    assert d != "allow" and _last(client) == ASK, (d, why)
    h.new_session()
    assert h.run("pytest -q")[0] == "allow"


@pytest.mark.parametrize("target", ["{proj}/.claude/settings.local.json", "{proj}/.claude/settings.json", "{home}/.claude/settings.json"])
def test_e2e_agent_write_into_settings_ends_strict(client, owner, tmp_path, monkeypatch, clean_ps, target):
    h = _sess(client, owner, tmp_path, monkeypatch)
    assert h.run("pytest -q")[0] == "allow"
    h.tool("Write", {"file_path": target.format(proj=h.proj, home=h.home), "content": "{}"})     # asked or refused: the attempt counts
    d, why = h.run("pytest -q")
    assert d != "allow" and _last(client) == ASK, (d, why)


def test_e2e_bash_write_into_settings_ends_strict(client, owner, tmp_path, monkeypatch, clean_ps):
    h = _sess(client, owner, tmp_path, monkeypatch)
    assert h.run("pytest -q")[0] == "allow"
    h.run("echo '{}' > .claude/settings.local.json")
    d, why = h.run("pytest -q")
    assert d != "allow" and _last(client) == ASK, (d, why)


def test_e2e_no_session_id_is_not_strict(client, owner, tmp_path, monkeypatch, clean_ps):
    h = _sess(client, owner, tmp_path, monkeypatch)
    h.sid = None
    d, why = h.run("pytest -q")
    assert d != "allow" and _last(client) == ASK, (d, why)


def test_e2e_no_transcript_is_not_strict(client, owner, tmp_path, monkeypatch, clean_ps):
    h = _sess(client, owner, tmp_path, monkeypatch)
    h.transcript = None
    d, why = h.run("pytest -q")
    assert d != "allow" and _last(client) == ASK, (d, why)


@pytest.mark.parametrize("chain", [["sh -c hook", "claude --settings /tmp/s.json"], ["sh -c hook", "claude --setting-sources=project"],
                                   ["sh -c hook", "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js --add-dir /tmp"], "unreadable"])
def test_e2e_flags_the_hook_cannot_see_are_not_strict(client, owner, tmp_path, monkeypatch, chain):
    h = _sess(client, owner, tmp_path, monkeypatch)
    monkeypatch.setattr(_sf, "ANCESTRY_OVERRIDE", chain)
    d, why = h.run("pytest -q")
    assert d != "allow" and _last(client) == ASK, (d, why)


def test_e2e_flag_above_claude_does_not_count(client, owner, tmp_path, monkeypatch):
    h = _sess(client, owner, tmp_path, monkeypatch)
    monkeypatch.setattr(_sf, "ANCESTRY_OVERRIDE", ["sh -c hook", "claude -p x", "my-wrapper --settings y"])
    assert h.run("pytest -q")[0] == "allow"


@pytest.mark.parametrize("extra", [{"sandbox": {"filesystem": {"allowWrite": ["/opt/out"]}}}, {"permissions": {"additionalDirectories": ["/opt"]}}])
def test_e2e_writes_outside_project_allowed_is_not_strict(client, owner, tmp_path, monkeypatch, clean_ps, extra):
    proj = json.loads(json.dumps(PROJECT_STRICT))
    for k, v in extra.items():
        if k == "sandbox":
            proj["sandbox"]["filesystem"].update(v["filesystem"])
        else:
            proj[k] = v
    h = Sess(client, owner, tmp_path, monkeypatch, user=STRICT_SETTINGS, project=proj, plat="darwin")   # r0279: not asked merely for lacking bwrap
    d, why = h.run("pytest -q")
    assert d != "allow" and _last(client) == ASK, (d, why)


def test_server_session_store_unit(client, owner):
    """The store directly: first view, a change, sticky; another session is independent; no sid -> not fresh."""
    from app.hookjudge import freshness as fr
    ctx = client.app.state.ctx
    ag, _ = owner.new_agent("claude-code", "u")
    ag = ctx.db.one("SELECT * FROM agents WHERE id=?", (ag["id"],))
    b = {"facts": {"sandbox": fact()}}
    assert fr.note(ctx, ag, "s1", b, []) and fr.note(ctx, ag, "s1", b, [])
    assert not fr.note(ctx, ag, "s1", {"facts": {"sandbox": fact(settings_digest="1" * 64)}}, [])
    assert not fr.note(ctx, ag, "s1", b, [])                       # sticky
    assert fr.note(ctx, ag, "s2", b, [])
    assert not fr.note(ctx, ag, None, b, [])
    assert not fr.note(ctx, ag, "s3", {"facts": {"sandbox": fact(since_start=["local"])}}, [])
    assert fr.note(ctx, ag, "s4", {"facts": {"settings": {"settings_digest": fact()["settings_digest"], "since_start": []}}}, [])
    assert fr.note(ctx, ag, "s4", b, [])                           # the first Bash fact after a non-Bash view with the same digest
    assert not fr.note(ctx, ag, "s4", {"facts": {"sandbox": fact(deny_read=["/x", os.path.expanduser("~")])}}, [])   # fact key changed


# ---------------------------------------------------------------- r0282: the session start in whole seconds (Linux, client 0.2.71) ---
def test_r0282_whole_second_session_start_is_the_safe_side(tmp_path, monkeypatch):
    """Linux reads the transcript's birth through statx in whole seconds, rounded down. A settings file modified in that same second counts as
    modified after the session started (not strict); one modified in an earlier second counts as before it."""
    from pathlib import Path
    home, proj = tmp_path / "home", tmp_path / "proj"
    (home / ".claude").mkdir(parents=True)
    (proj / ".claude").mkdir(parents=True)
    managed = tmp_path / "managed"
    managed.mkdir()
    from deus_witness.hook import failsafe as _fs
    monkeypatch.setattr(_fs, "MANAGED_DIR_OVERRIDE", str(managed))
    user = home / ".claude" / "settings.json"
    user.write_text(json.dumps(STRICT_SETTINGS))
    tr = home / ".claude" / "projects" / "p" / "s.jsonl"
    tr.parent.mkdir(parents=True)
    tr.write_text("{}\n")
    S = 1_800_000_000
    monkeypatch.setattr(_sf, "_session_start", lambda t: S)
    for mt, changed in ((S + 0.5, True), (S + 0.0, False), (S - 0.5, False)):
        os.utime(user, (mt, mt))
        since = _sf.settings_view(str(proj), {}, Path(home), str(tr), cli={})[1]["since_start"]
        assert ("user" in since) is changed, (mt, since)


@pytest.mark.skipif(not os.uname().sysname == "Linux", reason="statx birth time: Linux only")
def test_r0282_linux_birth_is_whole_seconds_not_after_now(tmp_path):
    p = tmp_path / "t.jsonl"
    p.write_text("{}\n")
    b = _sf._linux_birth(str(p))
    if b is None:                                                 # a file system without birth times: fail closed (session start unknown)
        assert _sf._session_start(str(p)) is None
        return
    assert isinstance(b, int) and b <= time.time() and b >= os.stat(p).st_mtime - 2, b
