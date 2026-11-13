"""10.11 (r0260) -- the project's own folders in Claude Code's temp root (sandbox.cc_slug / in_temp), and their adversaries.

Read from the binary (Claude Code 2.1.322, 10.11): <tmp>/claude-<uid>/<slug>/<session id>/{scratchpad,tasks}, slug = the launch directory
with every character outside [A-Za-z0-9] replaced by "-" (cut at 200 + hash). One session owns more than one session id folder (scratchpad
under the id it started with, task output under the current id). Rule: under the strict fact every session folder of THIS project's slug
is the project's own scratch; another project's slug, the root, a folder of no session stay asked. PRED is written before the run.
"""
import os

import pytest

from tests import r0261

from app.hookjudge import fs as hfs
from app.hookjudge import sandbox as hsb
from tests.test_0611_popravki import _mk, _strict, _v

pytestmark = pytest.mark.standing
SID = "0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"                # the hook's session_id
SID2 = "9f8e7d6c-1111-4222-8333-444455556666"               # the same project's other session id (a resumed session's scratchpad)


@pytest.fixture(autouse=True)
def _session(monkeypatch):
    monkeypatch.setattr(hfs, "LOCAL_SESSION", SID)


def _ok(got):
    return bool(got) and {v for v, _ in _v(got)} == {"allow"}


def _tmp(slug, sid=SID2, rest="scratchpad"):
    return "/private/tmp/claude-%d/%s/%s/%s" % (os.getuid(), slug, sid, rest)


# ---------------------------------------------------------------------------------------------------------------- units
def test_slug_as_claude_code_builds_it():
    PRED = "-Users-dev-work-project"                # the folder seen on the owner's machine (/private/tmp/claude-501/)
    assert hsb.cc_slug("/Users/dev/work/project") == PRED
    assert hsb.cc_slug("/Users/dev/.claude/tools") == "-Users-dev--claude-tools"     # seen in ~/.claude/projects/
    for bad in (None, "", "/", "rel/x", "/Users/dev/Проект", "/Users/dev/my project", "/Users/dev/x$y", "/a" * 101):
        PRED = None                                         # non-ASCII-safe / too long / not absolute: no slug (only the own sid counts)
        assert hsb.cc_slug(bad) is PRED, bad


def test_in_temp_same_project_any_session_folder(tmp_path):
    home = str(tmp_path / "h")
    proj = str(tmp_path / "h" / "p")
    slug = hsb.cc_slug(proj)
    PRED = True
    for p in (_tmp(slug) + "/a.py", _tmp(slug, rest="tasks/b1.output"), _tmp(slug, SID) + "/x"):
        assert hsb.in_temp(p, proj, home, SID) is PRED, p
        assert hsb.in_temp(p, proj, home, None) is PRED, p          # by the project alone (the hook sent no session id)
    PRED = False
    for p in ("/private/tmp/claude-501/-Users-u-other/%s/scratchpad/a.py" % SID2,     # another project's session
              "/private/tmp/claude-%d/%s" % (os.getuid(), slug),                      # the project folder itself
              "/private/tmp/claude-%d/%s/x/y" % (os.getuid(), slug),                  # a folder of no session (too short a name)
              "/private/tmp/claude-%d/%s/%s" % (os.getuid(), slug, SID2),            # the session folder itself, not inside it
              _tmp(slug + "-x") + "/a.py",                                           # a longer slug (another project)
              _tmp(slug[:-1]) + "/a.py",                                             # a shorter one
              _tmp(slug) + "/.claude/settings.json", _tmp(slug) + "/r/.git/hooks/pre-commit",
              _tmp(slug) + "/../../../-Users-u-other/%s/scratchpad/a" % SID2,        # `..` back to another project
              _tmp(slug) + "/$X", _tmp(slug) + "/*"):
        assert hsb.in_temp(p, proj, home, SID) is PRED, p
    cyr = str(tmp_path / "h" / "Проект")                    # a Cyrillic project: no slug, its own session id only
    PRED = False
    assert hsb.in_temp(_tmp(hsb.cc_slug(proj) or "x") + "/a", cyr, home, SID) is PRED
    PRED = True
    assert hsb.in_temp("/private/tmp/claude-501/-anything/%s/scratchpad/a" % SID, cyr, home, SID) is PRED


def test_slug_collision_of_separators_is_the_accepted_residual():
    """Documented, not hidden: `a-b`, `a_b`, `a.b` and `a/b` share Claude Code's slug; the witness cannot tell them apart from the path."""
    PRED = True
    assert hsb.cc_slug("/Users/u/a-b") == hsb.cc_slug("/Users/u/a_b") == hsb.cc_slug("/Users/u/a/b") == hsb.cc_slug("/Users/u/a.b")
    assert (hsb.cc_slug("/Users/u/a-b") == "-Users-u-a-b") is PRED


# ---------------------------------------------------------------------------------------------------------------- end to end
def test_same_project_other_session_folder_is_own_scratch_in_the_sandbox(client, owner, tmp_path, monkeypatch):
    d = _mk(client, owner, tmp_path, "t1")
    slug = hsb.cc_slug(str(d.proj))
    S = _tmp(slug)
    cmds = ("mkdir -p {s}/w && cat > {s}/w/a.py <<'EOF'\nprint(1)\nEOF\npython3 {s}/w/a.py".format(s=S),
            "python3 src/x.py > %s/run.log 2>&1; tail -3 %s/run.log" % (S, S),
            "cp src/app.py %s/app.py.bak" % S,
            "rm -rf %s/w" % S)
    PRED = False                                            # no strict fact: as before (a write outside the project is a question)
    assert all(_ok(d.send(c)) for c in cmds) is PRED
    _strict(d, monkeypatch)
    PRED = True
    for c in cmds:
        got = d.send(c)
        assert _ok(got) is PRED, (c, _v(got))


OTHER_TEMP = [
    "/private/tmp/claude-501/-Users-u-other/9f8e7d6c-5b4a-4398-8a7b-6c5d4e3f2a1b/scratchpad/run.py",   # another project's session
    "/private/tmp/claude-501/-Users-u-other/9f8e7d6c-5b4a-4398-8a7b-6c5d4e3f2a1b/tasks/b1.output",
    "/tmp/claude-501/x/run.py",                                                                        # a folder of no session
    "/private/tmp/claude-501/run.py",                                                                  # the shared root
]


# r0261 (Р-1111-закрытый-список): a write into ANY folder of Claude Code's temp root is silent in the strict sandbox (the kernel allows
# it; the channel "plant a file another session runs outside the sandbox" is closed at the RUN: the written run is held there --
# tests/test_1111_zakrytyy_spisok.py::test_file_planted_in_temp_by_a_strict_line_is_held_when_run_outside). Was asked here.
@pytest.mark.parametrize("target", r0261.now(OTHER_TEMP))
def test_write_into_another_projects_temp_r0261_now_silent(client, owner, tmp_path, monkeypatch, target):
    d = _mk(client, owner, tmp_path, "t2s")
    _strict(d, monkeypatch)
    PRED = True
    for c in ("python3 gen.py > %s" % target, "cp src/app.py %s && python3 src/app.py" % target):
        got = d.send(c)
        assert _ok(got) is PRED, (c, _v(got))
    got = d.send("rm -rf %s" % os.path.dirname(target))
    PRED = False                                     # never a question (the whole temp root: refused by the mandate's targets, RESOURCE)
    assert any(v == "defer" for v, _ in _v(got)) is PRED, _v(got)


@pytest.mark.parametrize("target", r0261.still(OTHER_TEMP))
def test_write_into_another_projects_temp_is_asked(client, owner, tmp_path, monkeypatch, target):
    d = _mk(client, owner, tmp_path, "t2")
    _strict(d, monkeypatch)
    PRED = False
    for c in ("python3 gen.py > %s" % target, "cp src/app.py %s && python3 src/app.py" % target, "rm -rf %s" % os.path.dirname(target)):
        got = d.send(c)
        assert _ok(got) is PRED, (c, _v(got))


def test_rm_rf_home_hidden_in_a_variable_is_never_allowed(client, owner, tmp_path, monkeypatch):
    d = _mk(client, owner, tmp_path, "t3")
    _strict(d, monkeypatch)
    S = _tmp(hsb.cc_slug(str(d.proj)))
    # r0261 (Р-1111-закрытый-список): under the strict fact a whole top folder of the home is Н5 (refused at once, no question) -- the
    # kernel refuses it too; a deeper folder outside the project is silent (EPERM)
    for c in ("D=~/Documents; rm -rf $D", "rm -rf ~/Documents", "T=~; rm -rf $T/Documents"):
        got = d.send(c)
        assert "deny" in {v for v, _ in _v(got)}, (c, _v(got))
    PRED = True
    got = d.send("rm -rf ~/Documents/old-notes")
    assert _ok(got) is PRED, _v(got)
    e = _mk(client, owner, tmp_path, "t3b")
    PRED = False
    for c in ("D=~/Documents; rm -rf $D", "D=$HOME/Documents && rm -rf \"$D\"", "export D=~/Documents; rm -rf ${D}",
              "S=%s; D=~/Documents; rm -rf $S/w $D" % S, "T=~; rm -rf $T/Documents", "rm -rf ~/Documents",
              "S=%s/../../../../..; rm -rf $S/Users" % S):
        got = e.send(c)
        assert _ok(got) is PRED, (c, _v(got))
