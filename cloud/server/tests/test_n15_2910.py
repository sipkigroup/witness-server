"""N1-N5 (poligon-lyudi/OTCHET-SERIYA-8B-PROD-0269-2026-10-29.md, prod 0.2.69). Each test failed before its fix (cloud/OTCHET-N1-N5-2910.md).

N1 a decision that ended FILE_CHANGED (a second process rewrote the shown file between the page and the decision) is not a showing: the next
   run of the rewritten file is held / asked again with the NEW text (E2 -> E3 held, RT2 -> E1 question). "Seen" = the write the page showed.
N2 a held call the hook gave up on, sent again and waited for: the page no longer says "no longer waiting".
N3 the owner approves / releases a page whose file changed since: the answer says so (file_changed), not "allowed once".
N4 `tar xf s.tar` / `patch -p0 < s.diff` in the project: no false RESOURCE (the project itself is the extraction target); the question
   about an extraction says the text is unseen (unseen_write) and names a secret the agent saw.
"""
from tests.test_0224_critique import Agent
from tests.test_r25_s8 import _release, _rid, _page, _writes, reasons, SH_NET, PY_NET
from tests.test_late_release_2910 import _present, _db, _give_up, _row

PY_NET2 = "import urllib.request\nurllib.request.urlopen('https://staging.poligon-s8.invalid/r9-CHANGED-unseen')\n"
SH_NET2 = "#!/bin/sh\ncurl -s -m 5 https://staging.poligon-s8.invalid/rt2-changed\n"


def _bump(a):
    _db(a).x("UPDATE actions SET updated_at=updated_at-5, created_at=created_at-5 WHERE account_id=?", (a.o.account["id"],))


# ---------------------------------------------------------------- N1
def test_n1_held_rewritten_before_release_next_run_held_again(client, owner, tmp_path):
    """E2 -> E3: held `python3 f9.py`, the agent rewrites f9.py, Release -> FILE_CHANGED; the repeat must not run the unseen text."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    v, parts = a.line("python3 f9.py")
    assert "ESCALATE_WRITTEN_RUN" in reasons(parts), parts
    rid = _rid(parts)
    _bump(a)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET2})       # a second process of the agent, while the page waits
    _release(a, rid)
    assert _present(a, rid)["reason"] == "FILE_CHANGED"
    v, parts = a.line("python3 f9.py")
    assert v == "ASK" and "ESCALATE_WRITTEN_RUN" in reasons(parts), parts       # was ALLOW: the unseen text ran
    w = _writes(_page(a, _rid(parts)))["f9.py"]
    assert "r9-CHANGED-unseen" in (w.get("text") or ""), w                      # the page shows the NEW text


def test_n1_question_rewritten_before_approval_next_question_shows_it(client, owner, tmp_path):
    """RT2 -> E1: question `bash f8b.sh` (bash unlisted), rewritten, approved -> FILE_CHANGED; the next question names the file with its text."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    rid = _rid(a.line("bash f8b.sh")[1])
    _bump(a)
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET2})
    assert a.o.approve(rid).json().get("verdict") == "allow"
    assert _present(a, rid)["reason"] == "FILE_CHANGED"
    v, parts = a.line("bash f8b.sh")
    rid2 = _rid(parts)
    assert rid2 != rid and v == "ASK"
    g = _page(a, rid2)
    w = _writes(g).get("f8b.sh") if g.get("written_run") else None
    assert w is not None and "rt2-changed" in (w.get("text") or ""), g.get("written_run")   # was: "ordinary command", no text


def test_n1_written_while_waiting_unseen_even_without_present(client, owner, tmp_path):
    """The rewrite came between the page and the release, and the agent runs ANOTHER line (no present of the released row at all)."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _rid(a.line("python3 f9.py")[1])
    _bump(a)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET2})
    _release(a, rid)
    v, parts = a.line("python3 -u f9.py")
    assert v == "ASK" and "ESCALATE_WRITTEN_RUN" in reasons(parts), parts


def test_n1_secret_hold_rewritten_before_release_held_again(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f8a.py", "content": PY_NET})
    a.see_secret()
    v, parts = a.line("python3 f8a.py")
    assert "ESCALATE_SECRET_SEEN" in reasons(parts), parts
    rid = _rid(parts)
    _bump(a)
    a.tool("Write", {"file_path": a.proj + "/f8a.py", "content": PY_NET2})
    _release(a, rid)
    assert _present(a, rid)["reason"] == "FILE_CHANGED"
    v, parts = a.line("python3 f8a.py")
    assert v == "ASK", parts
    g = _page(a, _rid(parts))
    assert "r9-CHANGED-unseen" in (_writes(g)["f8a.py"].get("text") or ""), g.get("written_run")


def test_n1_control_release_without_rewrite_is_one_touch(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _rid(a.line("python3 f9.py")[1])
    _release(a, rid)
    assert _present(a, rid)["result"] == "accept"
    assert a.line("python3 f9.py")[0] == "ALLOW"


# ---------------------------------------------------------------- N2
def test_n2_repeat_of_given_up_held_call_is_awaited_again(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f1.py", "content": PY_NET})
    rid = _rid(a.line("python3 f1.py")[1])
    _give_up(a, rid)
    assert _row(a, rid)["gave_up_at"]
    assert _page(a, rid).get("agent_waiting") is False
    v, parts = a.line("python3 f1.py")                                           # R1a2: the same call again, the hook waits for it
    assert _rid(parts) == rid
    g = _page(a, rid)
    assert g.get("agent_waiting") is not False and not g.get("gave_up_at"), g
    assert not [x for x in a.c.get("/api/approvals?status=held").json() if x["rid"] == rid and x.get("agent_waiting") is False]


# ---------------------------------------------------------------- N3
def test_n3_approve_after_rewrite_says_file_changed(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    rid = _rid(a.line("bash f8b.sh")[1])
    _bump(a)
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET2})
    j = a.o.approve(rid).json()
    assert j.get("file_changed", "").endswith("f8b.sh"), j


def test_n3_release_after_rewrite_says_file_changed(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET})
    rid = _rid(a.line("python3 f9.py")[1])
    _bump(a)
    a.tool("Write", {"file_path": a.proj + "/f9.py", "content": PY_NET2})
    import wq_profile as wq
    sha = _page(a, rid)["action"]["args_sha256"]
    r = a.o.post("/api/approvals/%s/release" % rid, release=True, envelope_b64=a.o.sign(wq.TYP_RELEASE, wq.release_payload(rid, sha, True)))
    assert r.status_code == 200 and r.json().get("file_changed", "").endswith("f9.py"), r.text


def test_n3_control_no_rewrite_no_flag(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    rid = _rid(a.line("bash f8b.sh")[1])
    j = a.o.approve(rid).json()
    assert j.get("verdict") == "allow" and "file_changed" not in j, j


# ---------------------------------------------------------------- N4
def test_n4_extract_into_the_project_itself_not_refused(client, owner, tmp_path, monkeypatch):
    """The project outside the temp dir (as on the stand: the mandate covers only <project>/*, not the temp dir over it)."""
    import tempfile
    monkeypatch.setattr(tempfile, "gettempdir", lambda: "/nonexistent-tmp")
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "tar", "patch", "unzip"])
    for line in ("tar xf s.tar", "patch -p0 < s.diff", "unzip -o a.zip"):
        v, parts = a.line(line)
        assert not any(p[2] == "RESOURCE" for p in parts), (line, parts)          # was: deny RESOURCE "writes: only inside the project"
    v, parts = a.line("tar xf s.tar -C ..")
    # the folder above the project: still refused -- or, r0274, asked as a danger: here it is tmp_path, which also holds the fixture's
    # home folder (home-cc), so it is no longer "temp" (a path above the home is never temp) but an extraction over the home
    assert v in ("DENY", "ASK") and any(p[2] in ("RESOURCE", "ESCALATE_COMMAND_DANGER") for p in parts), parts


def test_n4_write_outside_still_refused(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["tar"])
    v, parts = a.line("tar xf s.tar -C /etc")
    assert v in ("DENY", "ASK") and any(p[2] in ("RESOURCE", "ESCALATE_COMMAND_DANGER") for p in parts), parts   # 0.2.90: outside the home: the danger write-outside (asked)


def test_n4_extract_question_says_unseen_and_secret(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])                 # tar / patch unlisted: asked
    a.see_secret()
    for line, want in (("tar xf s.tar -C sub", "/sub"), ("patch notes.txt s.diff", "/notes.txt")):
        v, parts = a.line(line)
        assert v == "ASK", parts
        g = _page(a, _rid(parts))
        uw = g.get("unseen_write")
        assert uw and any(p.endswith(want) for p in uw["paths"]) and uw.get("secret") is True, (line, g.get("unseen_write"), g.get("reason"))


def test_n4_extract_question_without_secret_unseen_only(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    g = _page(a, _rid(a.line("tar xf s.tar -C sub")[1]))
    assert g["unseen_write"]["paths"] and not g["unseen_write"].get("secret"), g.get("unseen_write")


# ---------------------------------------------------------------- noise lever (coordinator 29.10): git from the repo's own objects, plain copies
import pytest as _pytest


# RT-0270 29.10: pull / merge write the remote's text again (moved to the guards below; tests/test_rt0270.py)
@_pytest.mark.parametrize("line", ["git stash", "git stash pop", "git stash apply",
                                   "git switch main", "git checkout main", "git restore src/legacy.py", "git checkout -- src/legacy.py",
                                   "cp .env.example .env.local", "ln -s ../data data", "cp a.py b.py"])
def test_lever_repo_objects_and_plain_copies_not_risky(client, owner, tmp_path, line):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git", "cp", "ln"])
    v, parts = a.line(line)
    assert any(p[0] == "Bash.write" for p in parts), parts                       # still a write (FILE_CHANGED, the page)
    _bump(a)
    v, parts = a.line("python3 run.py")
    assert v == "ALLOW", (line, parts)                                           # was: held ESCALATE_WRITTEN_RUN


@_pytest.mark.parametrize("line", ["git apply p.diff", "git am p.mbox", "git checkout evil -- s.py", "git restore --source=evil s.py",
                                   "tar xf a.tar", "patch -p0 < p.diff", "git stash pop && tar xf a.tar",
                                   "git pull", "git pull --rebase", "git merge main"])
def test_lever_guards_foreign_text_still_held(client, owner, tmp_path, line):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git", "tar", "patch"])
    a.tool("Write", {"file_path": a.proj + "/p.diff", "content": "--- a/s.py\n+++ b/s.py\n@@ -0,0 +1 @@\n+import os\n"})
    a.line(line)
    _bump(a)
    v, parts = a.line("python3 s.py")
    assert v == "ASK" and "ESCALATE_WRITTEN_RUN" in reasons(parts), (line, parts)


def test_lever_cp_of_risky_file_carries_the_mark(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "cp"])
    a.tool("Write", {"file_path": a.proj + "/a.py", "content": PY_NET})
    _release(a, _rid(a.line("python3 a.py")[1]))
    a.line("cp a.py b.py")
    _bump(a)
    v, parts = a.line("python3 b.py")
    assert v == "ASK" and "ESCALATE_WRITTEN_RUN" in reasons(parts), parts


# ---------------------------------------------------------------- lever 2 (coordinator 29.10): after a secret, only writes with the agent's text hold
@_pytest.mark.parametrize("line", ["rm src/old.py", "chmod +x scripts/release.sh", "touch src/pkg/__init__.py", "mkdir -p src/pkg",
                                   "git restore src/legacy.py", "git stash pop"])   # RT-0270: `git pull --rebase` holds again
def test_lever2_no_content_writes_after_secret_do_not_hold(client, owner, tmp_path, line):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "git", "chmod", "touch", "mkdir", "rm"])
    a.see_secret()
    v, parts = a.line(line)
    assert any(p[0] == "Bash.write" for p in parts), parts
    _bump(a)
    v, parts = a.line("pytest -q")
    assert "ESCALATE_SECRET_SEEN" not in reasons(parts), (line, parts)


@_pytest.mark.parametrize("how", ["sed", "heredoc", "write", "cp_risky"])
def test_lever2_content_writes_after_secret_still_hold(client, owner, tmp_path, how):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "sed", "cp"])
    if how == "cp_risky":
        a.tool("Write", {"file_path": a.proj + "/a.py", "content": PY_NET})
    a.see_secret()
    if how == "sed":
        a.line("sed -i 's/pass/import os/' test_x.py")
    elif how == "heredoc":
        a.line("cat > test_x.py <<'EOF'\nimport os\nEOF")
    elif how == "write":
        a.tool("Write", {"file_path": a.proj + "/test_x.py", "content": "import os\n"})
    else:
        a.line("cp a.py test_x.py")
    _bump(a)
    v, parts = a.line("pytest -q")
    assert v == "ASK" and ("ESCALATE_SECRET_SEEN" in reasons(parts) or "ESCALATE_WRITTEN_RUN" in reasons(parts)), (how, parts)
