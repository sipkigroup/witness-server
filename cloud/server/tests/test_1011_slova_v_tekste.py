"""10.11 (r0260) -- words in TEXT are not actions; actions are judged by their real targets. PRED is written before the run.

`grep -rn 'rm -rf' src` searches for the words: the text backstop (bashparse.RAW_RM) asked about it (16 questions in the developer corpus).
Now the search pattern of grep / egrep / fgrep / rg / git grep is data. Kept: rg --pre, git grep -O (they run a command), any grep via
xargs / find -exec, a pattern next to a real delete, interpreter code (python -c / perl -e / heredocs: code may run what it names).
`git archive HEAD x | tar -x -C dir` is local; `git archive --remote=...` is the network (it was not seen at all before).
"""
import pytest

from app.hookjudge import bashparse as bp
from app.hookjudge import fs as hfs
from app.hookjudge import sandbox as hsb
from tests.test_0611_popravki import _mk, _strict, _v

pytestmark = pytest.mark.standing
H, P = "/Users/u", "/Users/u/p"


def _rm(cmd):
    return [d for d in bp.classify(cmd, P, H, project=P).danger if d.startswith("rm-rf")]


@pytest.mark.parametrize("cmd", [
    "grep -rn 'rm -rf' src",
    "grep -rn \"rm -rf build\\|rm -rf dist\" tests | head",
    "grep -n 'def HOSTILE' -A60 x.py | grep -n 'rm -rf\\|git config' | head",
    "grep -lE 'rm -r?f?r? ?(build|dist)' tests/*.py 2>/dev/null",
    "egrep 'rm -rf' x", "fgrep -e 'rm -rf' x", "rg -n 'rm -rf' src", "git grep -n 'rm -rf' -- src",
    "grep -rn 'shutil.rmtree' src", "grep -c 'rimraf' package.json",
    "bash -c \"grep 'rm -rf' x\"",
])
def test_a_search_pattern_is_data(cmd):
    PRED = []
    assert _rm(cmd) == PRED, cmd


@pytest.mark.parametrize("cmd", [
    "rg --pre 'rm -rf' x",                       # runs the preprocessor command per file
    "rg --pre=sh -e 'rm -rf' x",
    "RIPGREP_CONFIG_PATH=c rg 'rm -rf' x",        # a config may carry --pre
    "git grep -O'rm -rf ~' x", "git grep -nO 'rm -rf' x", "git grep --open-files-in-pager='rm -rf ~' x",
    "xargs grep 'rm -rf' < f", "find . -exec grep 'rm -rf' {} +",
    "grep 'rm -rf' src; python3 -c \"import os; os.system('rm -rf '+p)\"",   # the second one is code: still marked
    "python3 -c \"for c in ['rm -rf build']: print(c)\"",                   # interpreter code: kept (see the module doc)
    "perl -pi -e 's/rm -rf build/rm -rf src/' t.py",
    "echo 'rm -rf build' | sh",
])
def test_text_that_may_run_keeps_its_mark(cmd):
    PRED = True
    assert bool(_rm(cmd)) is PRED, cmd


@pytest.mark.parametrize("cmd,pred", [
    ("grep -rn \"rm -rf $HOME\" src; rm -rf \"$HOME\"", "rm-rf:/Users/u"),     # r0350: "$HOME" = ~ (the home folder by its path)
    ("grep 'rm -rf' x && rm -rf ~/Documents", "rm-rf:/Users/u/Documents"),
    ("D=~/Documents; grep -q 'rm -rf' x || rm -rf $D", "rm-rf:/Users/u/Documents"),
])
def test_a_real_delete_next_to_a_pattern_is_judged_by_its_target(cmd, pred):
    PRED = pred
    assert PRED in _rm(cmd), (cmd, _rm(cmd))


def test_end_to_end_grep_passes_rm_home_is_refused(client, owner, tmp_path, monkeypatch):
    d = _mk(client, owner, tmp_path, "w1")
    _strict(d, monkeypatch)
    PRED = True
    got = d.send("grep -rn 'rm -rf' src | head")
    assert bool(got) and {v for v, _ in _v(got)} == {"allow"}, _v(got)
    PRED = "deny"                                              # Н5: the home folder, refused at once
    for c in ("rm -rf \"$HOME\"", "grep -q x src; rm -rf \"$HOME\""):
        got = d.send(c)
        assert PRED in {v for v, _ in _v(got)}, (c, _v(got))
    for c in ("rm -rf ~", "rm -rf %s" % d.home):
        got = d.send(c)                                        # measured: the test's home lives under the temp folder, so `~` is
        assert {v for v, _ in _v(got)} != {"allow"}, (c, _v(got))     # asked here, not refused; with a real home it is Н5 (below)
    for c in ("D=~/Documents; rm -rf $D", "rm -rf ~/Documents"):
        got = d.send(c)                                        # r0261: a whole top folder of the home -- Н5 under the strict fact
        assert "deny" in {v for v, _ in _v(got)}, (c, _v(got))


def test_rm_home_with_a_real_home_is_the_wipe_article():
    from app import constitution as k
    for cmd in ("rm -rf ~", "rm -rf \"$HOME\"", "grep -rn 'rm -rf' src; rm -rf ~"):
        c = bp.classify(cmd, P, H, project=P)
        PRED = "FORBIDDEN_WIPE"
        assert (k.check("Bash", {"command": cmd, "_witness": {"danger": c.danger, "project": P}}) or (None,))[0] == PRED, cmd


def test_git_archive_local_and_remote():
    PRED = []
    assert [d for d in bp.classify("git archive HEAD src | tar -x -C /tmp/x", P, H, project=P).danger if d.startswith("net-out")] == PRED
    assert hsb.code_exit("git archive") is False
    for cmd in ("git archive --remote=ssh://h/r HEAD | tar -x", "git archive --remote ssh://h/r HEAD", "git archive --exec=x --remote=h:r HEAD"):
        PRED = True
        assert any(d.startswith("net-out") for d in bp.classify(cmd, P, H, project=P).danger) is PRED, cmd
