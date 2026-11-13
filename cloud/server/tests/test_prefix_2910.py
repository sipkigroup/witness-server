"""PREFIKSY-2910: long-option prefixes vs the real help of macOS tools (bsdtar, less 668), STRIPBIN, man pagers."""
import pytest

from tests.test_0224_critique import Agent
from tests.test_rt7_rules import WF, _run

LINES = [
    # 1. bsdtar: --use-compress-program from --us
    ("tar", "tar --us='python3 f.py' -xf a.tar"), ("tar", "tar --use='python3 f.py' -xf a.tar"),
    ("tar", "tar --us 'python3 f.py' -xf a.tar"), ("gtar", "gtar --us='python3 f.py' -xf a.tar"),
    # 3. BSD install -s: program from STRIPBIN
    ("install", "STRIPBIN=./f.py install -s a b"), ("install", "env STRIPBIN=./f.py install -s a b"),
    ("install", "STRIPBIN='python3 f.py' install -s a b"),
    # 4. man: -P, MANPAGER, PAGER
    ("man", "man -P 'python3 f.py' ls"), ("man", "man -Ppython3 ls"), ("man", "MANPAGER='python3 f.py' man ls"),
    ("man", "PAGER='python3 f.py' man ls"), ("man", "env MANPAGER=./f.py man ls"), ("man", "env PAGER=./f.py man ls"),
]


@pytest.mark.parametrize("allow,cmd", LINES, ids=[c for _, c in LINES])
def test_prefix_2910_asked(client, owner, tmp_path, allow, cmd):
    a = Agent(client, owner, tmp_path, extra_cmds=[allow], name="p29")
    assert a.line(cmd)[0] != "ALLOW", cmd


# 2. less: --lesskey-file / --lesskey-src / --lesskey-content load a key file (a reader option: asked only after a risky write)
LESS = [("less", "less --lesskey-src=k.src x.txt"), ("less", "less --lesskey-content=k x.txt"), ("less", "less --lesskey-file=k x.txt"),
        ("less", "less --lesskey-src k.src x.txt"), ("less", "less --lesskey=k x.txt")]
AFTER = LESS + [c for c in LINES if "STRIPBIN" not in c[1] and "PAGER" not in c[1]]


@pytest.mark.parametrize("allow,cmd", AFTER, ids=[c for _, c in AFTER])
def test_prefix_2910_after_risky_write(client, owner, tmp_path, allow, cmd):
    a = Agent(client, owner, tmp_path, extra_cmds=[allow, "python3"], name="p29r")
    _run(a, [WF])
    v, parts = a.line(cmd)
    assert v != "ALLOW", (cmd, parts)
