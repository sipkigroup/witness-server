"""RT-0269 (cloud/RT-0269-PERED-VYKLADKOY.md): fixes before 0.2.69. Each test failed before its fix (OTCHET-RT0269-PRAVKA.md).

p.2 showing is not running: a file the page of a question showed, written after the question (any agent of the account), ends the
    approval: the approved repeat is judged anew, present is refused (FILE_CHANGED) -- also when the write came while the hook waited.
p.3 `cp other.py f.py` over a risky f.py: the destination is not the source; the page says the text is unknown, not the old text.
p.4 patch / tar x / unzip / git checkout|restore|switch|stash|apply|merge|am|pull|cherry-pick|rebase / perl -pi write files.
"""
import pytest

from app.hookjudge import bashparse as bp
from tests.test_0224_critique import Agent
from tests.test_r25_s8 import _release, _rid, _page, _writes, SH_NET, PY_NET
from tests.test_late_release_2910 import _present, _db, _give_up

SH2 = "#!/bin/sh\necho second-version\n"


def _bump(a):
    _db(a).x("UPDATE actions SET updated_at=updated_at-5, created_at=created_at-5 WHERE account_id=?", (a.o.account["id"],))


# ---------------------------------------------------------------- p.2
def test_r2d_approved_after_give_up_then_write_judged_anew(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])          # bash unlisted: the core asks, the page shows f8b.sh
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    rid = _rid(a.line("bash f8b.sh")[1])
    _give_up(a, rid)
    _bump(a)
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH2})
    assert a.o.approve(rid).json().get("verdict") == "allow"
    v, parts = a.line("bash f8b.sh")
    assert rid not in [p[3] for p in parts] and v == "ASK", parts


def test_r2a_write_while_question_waits_present_refused(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    rid = _rid(a.line("bash f8b.sh")[1])
    _bump(a)
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH2})
    assert a.o.approve(rid).json().get("verdict") == "allow"
    assert _present(a, rid) == {"result": "reject", "reason": "FILE_CHANGED"}


def test_r2b_write_while_held_release_present_refused(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "bash"])
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    rid = _rid(a.line("bash f8b.sh")[1])
    _bump(a)
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH2})
    _release(a, rid)
    assert _present(a, rid)["reason"] == "FILE_CHANGED"


def test_r2_other_agent_write_present_refused(client, owner, tmp_path):
    """Another agent of the same account rewrites the shown file while the question waits."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "bash"], name="A")
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    rid = _rid(a.line("bash f8b.sh")[1])
    _bump(a)
    b = Agent(client, owner, tmp_path, name="B")
    b.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH2})
    _release(a, rid)
    assert _present(a, rid)["reason"] == "FILE_CHANGED"


def test_r2_no_write_present_accepted(client, owner, tmp_path):
    """Control: nothing written after the question -> the released line runs (no extra touch)."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "bash"])
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    rid = _rid(a.line("bash f8b.sh")[1])
    _bump(a)
    a.tool("Write", {"file_path": a.proj + "/other.txt", "content": "x\n"})       # another file: not on the page
    _release(a, rid)
    assert _present(a, rid)["result"] == "accept"


# ---------------------------------------------------------------- p.3
def test_r4c_cp_over_risky_text_unknown(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f.py", "content": PY_NET})
    _bump(a)
    a.line("cp /tmp/rt0269-other.py f.py")
    v, parts = a.line("python3 f.py")
    w = _writes(_page(a, _rid(parts)))["f.py"]
    assert not w.get("text"), w                                           # not the old PY_NET text
    assert "urlopen" not in str(w)


def test_r4_cp_from_risky_keeps_its_text(client, owner, tmp_path):
    """Control: copying the risky file itself still carries its text to the destination."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f.py", "content": PY_NET})
    _bump(a)
    a.line("cp f.py g.py")
    v, parts = a.line("python3 g.py")
    assert "urlopen" in (_writes(_page(a, _rid(parts)))["g.py"].get("text") or "")


# ---------------------------------------------------------------- p.4
WRITERS = [
    ("patch s.py p.diff", ["/p/s.py"]), ("patch -p1 < x.diff", ["/p"]), ("patch -o out.py s.py p.diff", ["/p/out.py"]),
    ("tar xf a.tar", ["/p"]), ("tar -xzf a.tgz -C out", ["/p/out"]), ("tar --extract -f a.tar", ["/p"]),
    ("unzip -o a.zip", ["/p"]), ("unzip a.zip -d lib", ["/p/lib"]),
    ("git checkout -- s.py", ["/p/s.py"]), ("git checkout evil -- s.py", ["/p/s.py"]), ("git checkout evil", ["/p"]),
    ("git restore s.py", ["/p/s.py"]), ("git restore --source=evil s.py", ["/p/s.py"]), ("git switch evil", ["/p"]),
    ("git stash pop", ["/p"]), ("git stash apply", ["/p"]), ("git apply p.diff", ["/p"]), ("git merge evil", ["/p"]),
    ("git am p.mbox", ["/p"]), ("git pull", ["/p"]), ("git cherry-pick evil", ["/p"]), ("git rebase main", ["/p"]),
    ("perl -pi -e s/1/2/ s.py", ["/p/s.py"]),
]
NOT_WRITERS = ["tar czf a.tgz src", "tar tf a.tar", "tar -xOf a.tar x", "unzip -l a.zip", "git checkout -b fix", "git switch -c x",
               "git stash list", "git apply --check p.diff", "git status", "patch --dry-run s.py p.diff"]


@pytest.mark.parametrize("line,want", WRITERS)
def test_p4_content_writes(line, want, tmp_path):
    p = str(tmp_path.resolve())
    c = bp.classify(line, p, "/nonexistent-home", project=p)
    want = [w.replace("/p", p, 1) for w in want]
    assert c.writes == want and c.extract == want, (c.writes, c.extract)


@pytest.mark.parametrize("line", NOT_WRITERS)
def test_p4_no_content_writes(line, tmp_path):
    p = str(tmp_path.resolve())
    c = bp.classify(line, p, "/nonexistent-home", project=p)
    assert not c.extract, (line, c.writes, c.extract)


@pytest.mark.parametrize("line", ["tar xf a.tar", "unzip -o a.zip", "patch s.py p.diff", "git checkout evil -- s.py"])
def test_p4_extract_then_run_is_held(client, owner, tmp_path, line):
    """The risky-write mark is not lost: what an archive / patch / git puts in the project is unseen, the next run is held."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "tar", "unzip", "patch", "git"])
    v, parts = a.line(line)
    assert any(p[0] == "Bash.write" for p in parts), parts
    _bump(a)
    v, parts = a.line("python3 s.py")
    assert v == "ASK" and any(p[2] == "ESCALATE_WRITTEN_RUN" for p in parts), parts


def test_r2_own_line_write_does_not_end_its_approval(client, owner, tmp_path):
    """The question's own line writes the shown file (`git checkout -- f8b.sh && bash f8b.sh`): its re-send after the approval records that
    write again; it is the line the owner saw, so the approval holds (no endless re-asking)."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git"])
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    line = "git checkout -- f8b.sh && bash f8b.sh"
    rid = _rid(a.line(line)[1])
    _bump(a)
    assert a.o.approve(rid).json().get("verdict") == "allow"
    v, parts = a.line(line)
    assert v == "ALLOW" and rid in [p[3] for p in parts], parts
    assert _present(a, rid)["result"] == "accept"


def test_p4_tar_to_command_writes_nothing(tmp_path):
    p = str(tmp_path.resolve())
    assert not bp.classify("tar xf a.tar --to-command=true", p, "/nonexistent-home", project=p).extract
