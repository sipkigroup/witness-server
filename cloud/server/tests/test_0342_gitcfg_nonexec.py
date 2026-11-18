"""r0342 (17.11, S084 replay): a change of git's configuration that gives no code execution (url.insteadOf, user.name, a remote URL, a
branch) is not a changed executed file: `git status` / `git log` / `git remote -v` stay silent. A change that runs a program stays asked."""
import os
import sys

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))

from tests.test_0213 import CC, one, project  # noqa: E402

BASE = '[core]\n\tbare = false\n[remote "origin"]\n\turl = https://x/y.git\n'
CMD = "git status && git remote -v && git log"


def _start(client, owner, tmp_path):
    p = project(tmp_path)
    (p / ".git" / "config").write_text(BASE)
    d = CC(client, owner, p)
    assert one(d, CMD)["reason"] == "OK"
    return p, d


@pytest.mark.parametrize("add", [
    '[url "/tmp/bare-origin"]\n\tinsteadOf = https://x/y.git\n',
    '[user]\n\tname = A B\n\temail = a@b.c\n',
    '[remote "origin"]\n\turl = /tmp/other.git\n',
    '[branch "main"]\n\tremote = origin\n',
    '[alias]\n\tst = status\n',
])
def test_config_change_without_code_is_silent(client, owner, tmp_path, add):
    p, d = _start(client, owner, tmp_path)
    with open(p / ".git" / "config", "a") as f:
        f.write(add)
    r = one(d, CMD)
    assert r["reason"] == "OK", r


@pytest.mark.parametrize("add", [
    '[core]\n\tfsmonitor = /tmp/e\n',
    '[core]\n\tpager = /tmp/e\n',
    '[alias]\n\tst = "!/tmp/e"\n',
    '[core]\n\thooksPath = /tmp/h\n',
    '[include]\n\tpath = ../evil.cfg\n',
    '[diff "x"]\n\ttextconv = /tmp/e\n',
    '[merge "x"]\n\tdriver = /tmp/e\n',
    '[credential]\n\thelper = /tmp/e\n',
])
def test_config_change_with_code_stays_asked(client, owner, tmp_path, add):
    p, d = _start(client, owner, tmp_path)
    with open(p / ".git" / "config", "a") as f:
        f.write(add)
    r = one(d, CMD)
    assert r["reason"] == "ESCALATE_EXEC_CHANGED", r
