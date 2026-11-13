"""0.2.55: recursive NAME readers (ls -R, du, tree) rooted outside the project -> asked, as RT-0.2.54 did for grep -r / rg.

pytest's tmp_path lives in the macOS temp directory (/var/folders/*/*/T), which the witness treats as a scratch area. To judge `..` (the
parent of the project) as "outside", these tests narrow bashparse.TEMP_IN to /tmp and /var/tmp only (the rule itself is unchanged)."""
import os
import re
import shutil
import subprocess
import sys

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))
from app.hookjudge import bashparse  # noqa: E402
from app.hookjudge.mapping import default_form, map_event  # noqa: E402
from tests.helpers import act  # noqa: E402
from tests.test_0254_find_sed_awk_jq import _env, _project  # noqa: E402


@pytest.fixture(autouse=True)
def _narrow_temp(monkeypatch):
    monkeypatch.setattr(bashparse, "TEMP_IN", re.compile(r"^(/private)?/(tmp|var/tmp)/."))


ASK = ["ls -R ~", "ls -laR /", "ls -lR /Users", "du -a ~", "du -ah ..", "tree ~", "tree -a /Users", "ls -R $HOME", "ls -R ${HOME}",
       "ls ~ -R", "ls -R -- ~", "ls --recursive ~", "ls --recur /etc", "ls -aR ..", "ls -R ../..", "ls -R src/../..", "ls -R .*",
       "du ~", "du -h ~", "du -d 2 ~", "du -d2 ~", "du --max-depth=3 ~", "du --max-depth 3 ~", "du -s -d 3 ~", "du -ah ~/..",
       "tree -L 3 ~", "tree -a ..", "ls -R ~root", "ls -R $X", "ls -R $(pwd)/..", "cd ~ && ls -R", "cd .. && du -a", "cd / && tree",
       "ls -R . ~", "du -a src ~", "grep -r KEY ..", "rg KEY .*", "cd ~ && rg KEY", "ls -aR ~"]
# content readers (Deus's addition): grep -d recurse / --directories=recurse, git grep run outside the project
ASK_CONTENT = ["grep -d recurse KEY ~", "grep --directories=recurse KEY ~", "grep --dir=recurse KEY ~", "grep --directories recurse KEY ~",
               "grep -drecurse KEY ~", "grep -nd recurse KEY ~", "grep -d rec KEY ~", "grep -id recurse KEY ..", "grep -d recurse KEY $HOME",
               "egrep -d recurse KEY ~", "git -C ~ grep --no-index KEY", "git -C .. grep --no-index KEY", "git -C .. grep KEY",
               "cd ~ && git grep --no-index KEY", "cd .. && git grep KEY", "git -C src -C ../.. grep --no-index KEY",
               "git -C $X grep KEY", "git grep --no-index KEY ..", "git -C ~ grep -n -e KEY"]
ASK_VARIANT = ["git --git-dir=../x/.git grep KEY", "git --work-tree .. grep KEY", "git -c core.worktree=/ grep KEY",
               "GIT_DIR=../r/.git git grep KEY", "GIT_WORK_TREE=.. git grep KEY"]       # already variants in 0.2.54 (never in the list)
ALLOW = ["ls", "ls -la", "ls -R", "ls -laR src", "ls -R src/.*", "ls ~", "ls -la ~", "ls /etc", "ls -la ..", "du -sh ~", "du -sh ..",
         "du -d 1 ~", "du -d0 ~", "du -hd1 ~", "du --summarize ~", "du -a", "du -ah src", "du -sh .", "du", "tree", "tree -L 2 src",
         "tree -a src", "ls -R /tmp/w55", "du -a /tmp/w55", "grep -r KEY .", "rg KEY", "ls -R ../proj/src",
         "grep -d skip KEY ~", "grep -d read KEY /etc/hosts", "grep -d recurse KEY src", "grep --directories=recurse KEY .",
         "git grep KEY", "git grep -n KEY HEAD -- src", "git -C src grep KEY", "git grep --no-index KEY", "git grep -e KEY src"]


def _send(client, hdr, cmd, proj, owner):
    out = []
    for m in map_event({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": proj}):
        r = act(client, hdr, m.tool, m.args).json()
        out.append(r["verdict"])
        if r["verdict"] == "defer":
            owner.approve(r["rid"])
    return out


def test_outside_names_asked_inside_allowed(client, owner, tmp_path):
    proj = _project(tmp_path)
    ag, hdr = owner.new_agent("claude-code", "cc")
    owner.mandate(ag["id"], default_form(proj))
    bad = []
    for cmd in ASK + ASK_CONTENT + ASK_VARIANT:
        v = _send(client, hdr, cmd, proj, owner)
        if not any(x in ("defer", "deny") for x in v):
            bad.append(("ASK", cmd, v))
    for cmd in ALLOW:
        v = _send(client, hdr, cmd, proj, owner)
        if not v or any(x != "allow" for x in v):
            bad.append(("ALLOW", cmd, v))
    assert not bad, bad


@pytest.mark.parametrize("cmd", ASK + ASK_CONTENT)
def test_classifier_opaque(tmp_path, cmd):
    proj = _project(tmp_path)
    c = bashparse.classify(cmd, proj, os.path.join(os.path.dirname(proj), "home"), project=proj)
    assert c.opaque and any("recursive" in d or "expansion" in d or "git grep" in d for d in c.danger), (cmd, c.danger)


@pytest.mark.parametrize("cmd", ALLOW)
def test_classifier_plain(tmp_path, cmd):
    proj = _project(tmp_path)
    c = bashparse.classify(cmd, proj, os.path.join(os.path.dirname(proj), "home"), project=proj)
    assert not c.opaque, (cmd, c.danger)


@pytest.mark.parametrize("cmd,walks", [("ls -R", True), ("ls -laR", True), ("ls --rec", True), ("ls --re", False), ("ls -la", False),
                                       ("du", True), ("du -a", True), ("du -s", False), ("du -sh", False), ("du -d 1", False),
                                       ("du -d1", False), ("du -hd0", False), ("du -d 2", True), ("du --max-depth=1", False),
                                       ("du --max-depth 0", False), ("du --summ", False), ("du -s -d 2", True), ("du -d x", True),
                                       ("du -B 1 -s", False), ("du -- -s", True), ("tree", True), ("tree -L 1", True),
                                       ("grep -r", True), ("grep --recursive", True), ("grep x", False), ("rg", True),
                                       ("grep -d recurse", True), ("grep -drecurse", True), ("grep --directories=recurse", True),
                                       ("grep --dir=rec", True), ("grep --directories recurse", True), ("grep -d skip", False),
                                       ("grep -d re", False), ("grep --dereference-recursive", True), ("grep -- -r", False)])
def test_walks(cmd, walks):
    name, *args = cmd.split()
    assert bashparse._walks(name, args) is walks


def _real(cmd, cwd, base):
    return subprocess.run(["/bin/bash", "-c", cmd], cwd=cwd, env=_env(base), capture_output=True, text=True, timeout=30)


def _snapshot(root):
    out = {}
    for d, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(d, f)
            st = os.lstat(p)
            out[p] = (st.st_size, st.st_mtime_ns)
    return out


def test_real_bsd_tools_show_secret_names_outside(tmp_path):
    """The danger is real: run from the project, these BSD ls / du forms print the key's name in the fake home next to it."""
    proj = _project(tmp_path)
    base = os.path.dirname(proj)
    for cmd in ("ls -aR ~", "ls -aR ..", "du -a ~", "du -ah ..", "ls -aR .*"):
        r = _real(cmd, proj, base)
        assert "id_rsa" in r.stdout, (cmd, r.stdout, r.stderr)
    for cmd in ("ls ~", "ls -la ..", "du -sh ~", "du -d 1 ~", "du -sh .."):           # one level: no key name
        r = _real(cmd, proj, base)
        assert "id_rsa" not in r.stdout, (cmd, r.stdout)


def test_real_bsd_tools_inside_change_nothing(tmp_path):
    proj = _project(tmp_path)
    base = os.path.dirname(proj)
    before = _snapshot(base)
    for cmd in ("ls -R", "ls -laR src", "du -a", "du -ah src", "du -sh .", "ls -R ../proj/src"):
        r = _real(cmd, proj, base)
        assert r.returncode == 0 and "id_rsa" not in r.stdout, (cmd, r.stdout, r.stderr)
    assert _snapshot(base) == before


@pytest.mark.skipif(shutil.which("tree") is None, reason="tree is not installed on this machine")
def test_real_tree(tmp_path):
    proj = _project(tmp_path)
    base = os.path.dirname(proj)
    assert "id_rsa" in _real("tree -a ..", proj, base).stdout
    assert "id_rsa" not in _real("tree -a src", proj, base).stdout


def test_real_grep_git_read_secret_outside(tmp_path):
    """grep -d recurse and git grep --no-index from a directory outside the project print the key's CONTENT (this machine's grep / git)."""
    proj = _project(tmp_path)
    base = os.path.dirname(proj)
    subprocess.run(["git", "init", "-q", "."], cwd=proj, check=True, capture_output=True)
    for cmd in ("grep -d recurse KEY ~", "grep -drecurse KEY ..", "git -C .. grep --no-index KEY", "cd .. && git grep --no-index KEY"):
        r = _real(cmd, proj, base)
        assert "id_rsa" in r.stdout, (cmd, r.stdout, r.stderr)
    for cmd in ("grep -d recurse KEY src", "git grep --no-index KEY"):
        assert "id_rsa" not in _real(cmd, proj, base).stdout
