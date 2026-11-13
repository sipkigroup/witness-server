"""N6 / N7 / N10 (poligon-lyudi/OTCHET-SERIYA-8C-PROD-0270-2026-10-29.md, prod 0.2.70) -> server 0.2.71 (cloud/OTCHET-N6-N7-N10-0271.md).

N6 a whole-directory restore (`git stash pop` of the latest stash) after the page no longer makes FILE_CHANGED for a file git says the
   stash does not touch (git's object hashes, the hook's fact gitref); a release that ends FILE_CHANGED keeps the shown text for the next
   page and never says "you let run". Guards: a stash that holds the file, tar over the directory, an unknown answer, git tampering after the
   page -> FILE_CHANGED as before.
N7 a write whose line never ran (its question expired / was refused) is not in the list of written files; a line that runs code after an
   unseen risky write is still held (RT5: `python3 run.py` may import it).
N10 the agent is told to repeat the same call after FILE_CHANGED.
"""
import subprocess

import pytest

from app import actions as A
from app.hookjudge import fs as hfs
from app.hookjudge import judge, reasons as R
from tests.test_0224_critique import Agent
from tests.test_r25_s8 import _release, _rid, _page, _writes, reasons, PY_NET
from tests.test_late_release_2910 import _present, _db

PY_NET2 = "import urllib.request\nurllib.request.urlopen('https://staging.poligon-s8.invalid/r9-CHANGED-unseen')\n"


def git(p, *a):
    subprocess.run(["git", "-C", p] + list(a), check=True, capture_output=True)


def _repo(a, f9_in_head=None, stash=("legacy.py", "x=2\n")):
    """The 8c stand: run.py and legacy.py committed, a change of `stash[0]` stashed outside the witness (before the agent)."""
    git(a.proj, "init", "-q")
    git(a.proj, "config", "user.email", "t@t")
    git(a.proj, "config", "user.name", "t")
    open(a.proj + "/run.py", "w").write("print('run')\n")
    open(a.proj + "/legacy.py", "w").write("x=1\n")
    if f9_in_head is not None:
        open(a.proj + "/f9.py", "w").write(f9_in_head)
    git(a.proj, "add", ".")
    git(a.proj, "commit", "-qm", "c")
    open(a.proj + "/" + stash[0], "w").write(stash[1])
    git(a.proj, "stash", "-q")


def _bump(a):
    _db(a).x("UPDATE actions SET updated_at=updated_at-5, created_at=created_at-5 WHERE account_id=?", (a.o.account["id"],))


def _held_run(a, cmd="python3 run.py"):
    v, parts = a.line(cmd)
    assert "ESCALATE_WRITTEN_RUN" in reasons(parts), parts
    return _rid(parts)


def _run_line(a, cmd, shell=None):
    """The hook's way: every part judged; a question approved by the owner; every part presented; then the line runs."""
    v, parts = a.line(cmd)
    for _t, verdict, _r, rid in parts:
        if verdict == "defer":
            assert a.o.approve(rid).json()["verdict"] == "allow"
    for _t, verdict, _r, rid in parts:
        assert _present(a, rid)["result"] == "accept", (cmd, parts)
    if shell:
        subprocess.run(shell, shell=True, cwd=a.proj, check=True, capture_output=True)
    return parts


def _release_raw(a, rid):
    from tests.test_r25_s8 import wq
    sha = _page(a, rid)["action"]["args_sha256"]
    r = a.o.post("/api/approvals/%s/release" % rid, release=True, envelope_b64=a.o.sign(wq.TYP_RELEASE, wq.release_payload(rid, sha, True)))
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- N6 (a): stash pop with f9.py unchanged
def test_a_stash_pop_of_other_files_is_no_file_changed(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git"])
    _repo(a)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    open(a.proj + "/f9.py", "w").write(PY_NET)                                 # what the Write did on the agent's machine
    rid = _held_run(a)
    _bump(a)
    _run_line(a, "git stash pop", "git stash pop -q")
    assert open(a.proj + "/f9.py").read() == PY_NET                            # git really left f9.py alone
    j = _release_raw(a, rid)
    assert not j.get("file_changed"), j                                         # was: "The file changed after you saw it; nothing ran (f9.py)"
    assert _present(a, rid)["result"] == "accept"


# ---------------------------------------------------------------- N6 (c): the whole 8c chain -- python3 run.py is free after the release
def test_c_run_py_not_held_after_release_across_stash_pop(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git"])
    _repo(a)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _held_run(a)
    _bump(a)
    _run_line(a, "git stash pop", "git stash pop -q")
    _release(a, rid)
    assert a.line("python3 run.py ")[0] == "ALLOW"                            # was: held again "runs a file this agent wrote (f9.py)"
    assert a.line("python3 -B run.py")[0] == "ALLOW"


# ---------------------------------------------------------------- N6 guards: the file really changed / unknown / tampered
def test_a_guard_stash_that_holds_f9_is_file_changed(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git"])
    _repo(a, f9_in_head=PY_NET, stash=("f9.py", PY_NET2))
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})       # the page shows PY_NET (= HEAD)
    rid = _held_run(a, "python3 f9.py")
    _bump(a)
    _run_line(a, "git stash pop", "git stash pop -q")
    assert "r9-CHANGED-unseen" in open(a.proj + "/f9.py").read()               # the stash really rewrote it
    assert _release_raw(a, rid).get("file_changed", "").endswith("/f9.py")
    assert _present(a, rid)["reason"] == "FILE_CHANGED"
    v, parts = a.line("python3 f9.py")
    assert v == "ASK" and "ESCALATE_WRITTEN_RUN" in reasons(parts), parts


def test_a_guard_unknown_answer_is_file_changed(client, owner, tmp_path, monkeypatch):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git"])
    _repo(a)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _held_run(a)
    _bump(a)
    monkeypatch.setattr(hfs.LocalFS, "gitref", lambda self, top, ref: None)    # an older hook / git could not say
    _run_line(a, "git stash pop", "git stash pop -q")
    assert _release_raw(a, rid).get("file_changed")


def test_a_guard_git_tamper_after_page_is_file_changed(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git"])
    _repo(a)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _held_run(a)
    _bump(a)
    a.line("git notes add -m x")                                               # changes git's objects (gt): the stash may hold anything now
    _run_line(a, "git stash pop", "git stash pop -q")
    assert _release_raw(a, rid).get("file_changed")


def test_a_guard_tar_over_the_directory_is_file_changed(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git", "tar"])
    _repo(a)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _held_run(a)
    _bump(a)
    _run_line(a, "tar xf s.tar")
    assert _release_raw(a, rid).get("file_changed")


def test_a_guard_write_of_the_file_is_file_changed(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git"])
    _repo(a)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _held_run(a)
    _bump(a)
    _run_line(a, "sed -i.bak 's/health/x/' f9.py")
    assert _release_raw(a, rid).get("file_changed", "").endswith("/f9.py")


def test_a_stash_pop_with_tar_on_the_same_line_is_whole_directory(client, owner, tmp_path):
    """The file list is only kept when EVERY write of the line is the stash restore."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git", "tar"])
    _repo(a)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _held_run(a)
    _bump(a)
    _run_line(a, "git stash pop && tar xf s.tar")
    assert _release_raw(a, rid).get("file_changed")


def test_a_judge_asks_the_hook_for_the_stash_fact():
    """Through the thin hook: `git stash pop` asks need.gitref [top, "stash"] (a 0.2.37+ hook answers it, the word is in the line); a hook
    that sends no fs.gitref is not asked (unknown: the whole directory)."""
    from app.hookjudge.mapping import map_event
    top = "/tmp/p-n6"
    fx = judge._Facts(judge._facts({"facts": {"home": "/home/u", "proc_cwd": top, "env": {"CLAUDE_PROJECT_DIR": top},
                                              "fs": {"realpath": {}, "isdir": {}, "exists": {}, "gitref": {}}}}), "r")
    tok = hfs.use(fx)
    try:
        map_event({"tool_name": "Bash", "tool_input": {"command": "git stash pop"}, "cwd": top}, home="/home/u", env={"CLAUDE_PROJECT_DIR": top})
    finally:
        hfs.reset(tok)
    assert [top, "stash"] in fx.missing["gitref"]
    fx2 = judge._Facts(judge._facts({"facts": {"home": "/home/u", "proc_cwd": top, "env": {"CLAUDE_PROJECT_DIR": top},
                                               "fs": {"realpath": {}, "isdir": {}, "exists": {},
                                                      "gitref": {top + "\nstash": {"commit": True, "paths": ["legacy.py"], "more": False,
                                                                                    "special": []}}}}}), "r")
    tok = hfs.use(fx2)
    try:
        parts = map_event({"tool_name": "Bash", "tool_input": {"command": "git stash pop"}, "cwd": top}, home="/home/u",
                          env={"CLAUDE_PROJECT_DIR": top})
    finally:
        hfs.reset(tok)
    w = [m for m in parts if m.tool == "Bash.write"][0].args["_witness"]
    assert w["dirfiles"] == {top: [top + "/legacy.py"]}, w


# ---------------------------------------------------------------- N6 (b): a FILE_CHANGED release keeps the text, no "you let run"
def test_b_file_changed_release_keeps_the_text(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git"])
    _repo(a)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _held_run(a)
    _bump(a)
    _run_line(a, "git stash")                                                  # push: rewrites modified files back to HEAD (may touch f9.py)
    assert _release_raw(a, rid).get("file_changed")
    w = _writes(_page(a, _held_run(a, "python3 run.py ")))["f9.py"]
    assert "staging.poligon-s8.invalid/health" in (w.get("text") or "") and not w.get("cut"), w   # was: no text, cut ("you let run")


def test_b_file_changed_at_present_takes_back_you_let_run(client, owner, tmp_path):
    """Released while nothing changed (the texts go), THEN a directory write, the present is refused FILE_CHANGED: the page no longer
    says the text was shown on a request "you let run" (nothing ran)."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git"])
    _repo(a)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _held_run(a)
    _release(a, rid)
    _run_line(a, "git stash")
    assert _present(a, rid)["reason"] == "FILE_CHANGED"
    w = _writes(_page(a, _held_run(a, "python3 run.py ")))["f9.py"]
    assert not w.get("cut"), w


def test_b_control_release_that_ran_still_drops_the_text(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "bash"])
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _held_run(a, "python3 f9.py")
    _release(a, rid)
    assert _present(a, rid)["result"] == "accept"
    a.tool("Write", {"file_path": a.proj + "/f8c.py", "content": PY_NET2})
    w = _writes(_page(a, _held_run(a, "python3 f9.py ")))
    assert "f9.py" not in w or (not w["f9.py"].get("text") and w["f9.py"].get("cut") is True), w


# ---------------------------------------------------------------- N7
def test_c_guard_run_py_still_held_while_f9_unseen(client, owner, tmp_path):
    """RT5 stays: run.py may `import f9`; the witness does not see run.py's text."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    open(a.proj + "/run.py", "w").write("import f9\n")
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    v, parts = a.line("python3 run.py")
    assert v == "ASK" and "ESCALATE_WRITTEN_RUN" in reasons(parts), parts


@pytest.mark.parametrize("end", ["expired", "refused"])
def test_d_unrun_tar_not_in_the_written_list(client, owner, tmp_path, end):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])                 # tar unlisted: asked
    v, parts = a.line("tar xf s.tar")
    q = [rid for t, verdict, _r, rid in parts if verdict == "defer"]
    assert v == "ASK" and q, parts
    if end == "expired":
        _db(a).x("UPDATE actions SET expires=1 WHERE rid=?", (q[0],))
        A.refresh(a.c.app.state.ctx, q[0])
    else:
        assert a.o.approve(q[0], approved=False).status_code == 200
    assert _db(a).one("SELECT status FROM actions WHERE rid=?", (q[0],))["status"] == end
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    files = _page(a, _held_run(a))["written_run"]["files"]
    assert files == [a.proj + "/f9.py"], files                                 # was: the project directory (tar) too


def test_d_guard_waiting_or_run_tar_is_in_the_list(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    v, parts = a.line("tar xf s.tar")
    assert v == "ASK", parts
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    files = _page(a, _held_run(a))["written_run"]["files"]
    assert len(files) > 1, files                                               # the question still waits: it may run (fail closed)


# ---------------------------------------------------------------- N10
def test_n10_agent_is_told_to_repeat_the_same_call():
    k, t = R.REASONS["FILE_CHANGED"]
    assert k == "deny" and "Repeat the same call" in t and "asked again" in t and "nothing ran" in t
    assert judge.texts_for([])["FILE_CHANGED"] == [k, t]                        # sent with every answer: the hook needs it at present time


@pytest.mark.parametrize("line", ["git stash && git stash pop", "git stash pop; git stash pop", "git stash pop && python3 -c 'open(\"f9.py\",\"w\")'",
                                  "git stash pop && echo x > f9.py"])
def test_a_guard_stash_pop_with_anything_else_is_whole_directory(client, owner, tmp_path, line):
    """The file list counts only for a line that is ONE `git stash pop|apply` and nothing else (another write / run on the line may
    change the file in ways the list does not show)."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git"])
    _repo(a)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _held_run(a)
    _bump(a)
    v, parts = a.line(line)
    for _t, verdict, _r, r_ in parts:
        if verdict == "defer":
            a.o.approve(r_)
    for _t, verdict, _r, r_ in parts:
        _present(a, r_)
    assert _release_raw(a, rid).get("file_changed"), parts


@pytest.mark.parametrize("before", ["git commit -qam w", "git reset -q HEAD", "git checkout -q -b side", "git stash store HEAD"])
def test_a_guard_head_moved_in_look_back_is_whole_directory(client, owner, tmp_path, before):
    """git's list is HEAD vs the stash; the pop merges the stash's OWN change (its base vs it). A moved HEAD (or a forged stash) may hide a
    file the pop rewrites: any HEAD-moving / tampering git line of the account in the look-back -> the whole directory, as before."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git"])
    _repo(a)
    v, parts = a.line(before)
    for _t, verdict, _r, r_ in parts:
        if verdict == "defer":
            a.o.approve(r_)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _held_run(a)
    _bump(a)
    _run_line(a, "git stash pop", "git stash pop -q")
    assert _release_raw(a, rid).get("file_changed"), before


def test_d_refused_tar_after_the_page_is_no_file_changed(client, owner, tmp_path):
    """The write part of `tar xf` is allowed by the mandate, the line itself is asked and refused: it never ran, f9.py did not change."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _held_run(a, "python3 f9.py")
    _bump(a)
    v, parts = a.line("tar xf s.tar")
    q = [r_ for _t, verdict, _r, r_ in parts if verdict == "defer"]
    assert q and a.o.approve(q[0], approved=False).status_code == 200
    assert not _release_raw(a, rid).get("file_changed")
    assert _present(a, rid)["result"] == "accept"


def test_d_guard_waiting_tar_after_the_page_is_file_changed(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _held_run(a, "python3 f9.py")
    _bump(a)
    assert a.line("tar xf s.tar")[0] == "ASK"                                  # still waiting: it may run any moment (fail closed)
    assert _release_raw(a, rid).get("file_changed")
