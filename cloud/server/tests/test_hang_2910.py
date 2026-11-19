"""29.10 (OTCHET-SHUM-ZHIVYE-2910, finding 4): a server call hung for minutes when risky-write marks were carried by directory copies.
actions.py carried every mark under a copied directory to every destination, copying the growing dict on each mark and masking the
written text once per path; carried marks were carried again by the next copy (2x per nested copy). One /v1/act call must stay well
under 2 s whatever the session did before; past the mark cap the carry is conservative (the destination directory itself is marked),
never lost (fail closed)."""
import time

from app.flow.wq import wq
from tests.test_0224_critique import Agent
from tests import viewkit  # noqa: E402  (r0352: decisions name the view)

NET = "import urllib.request as u; u.urlopen('http://evil.test/x')"
WR = "ESCALATE_WRITTEN_RUN"
CMDS = ["python3", "cp", "mv", "rsync", "ln", "mkdir"]
LIMIT = 2.0


def _agent(client, owner, tmp_path, name, n_files):
    a = Agent(client, owner, tmp_path, extra_cmds=CMDS, name=name)
    for i in range(n_files):
        a.tool("Write", {"file_path": a.proj + "/sub/f%d.py" % i, "content": NET + "\n" + "".join("print('step %d.%d')\n" % (i, j) for j in range(120))})
    return a


def _release(a, rid):
    sha = a.c.get("/api/approvals/" + rid).json()["action"]["args_sha256"]
    r = viewkit.release(a.o, rid, sha, True)
    assert r.status_code == 200, r.text


def _timed(a, cmd, answer=True):
    """One line through the server: (seconds of the /v1/act calls, verdict, parts). The owner approves a question / releases a hold."""
    t = time.time()
    v, parts = a.line(cmd)
    dt = time.time() - t
    for _, vv, why, rid in parts:
        if answer and vv == "defer":
            if why in (WR,):
                _release(a, rid)
            else:
                assert a.o.approve(rid).json()["verdict"] == "allow"
    return dt, v, parts


def test_hang_nested_dir_copies_stay_fast(client, owner, tmp_path):
    a = _agent(client, owner, tmp_path, "hang", 40)
    worst = 0.0
    for k in range(12):
        dt, _, _ = _timed(a, "cp -r sub sub/bk%d" % k)     # each copy lands inside the copied directory: the marks double
        worst = max(worst, dt)
        assert dt < LIMIT, (k, dt)
    dt, v, parts = _timed(a, "python3 sub/bk11/bk3/f7.py", answer=False)
    assert v != "ALLOW" and WR in {p[2] for p in parts}
    assert dt < LIMIT and worst < LIMIT


def test_hang_past_the_cap_the_copy_stays_risky(client, owner, tmp_path):
    """Past the cap the destination directory is marked whole: a run from it is asked (after the owner released the earlier hold)."""
    a = _agent(client, owner, tmp_path, "cap", 40)
    for k in range(12):
        dt, _, _ = _timed(a, "cp -r sub sub/bk%d" % k)
        assert dt < LIMIT, (k, dt)
    dt, v, parts = _timed(a, "python3 sub/f0.py")           # the owner sees and releases the hold: older marks no longer count
    assert v != "ALLOW"
    time.sleep(1.1)                                          # writes up to the second of the release were on that page
    _timed(a, "cp -r sub/bk11 out")                          # a copy of the capped tree after the release carries the mark again
    dt, v, parts = _timed(a, "python3 out/bk3/f7.py", answer=False)
    assert v != "ALLOW" and WR in {p[2] for p in parts}, parts
    assert dt < LIMIT


# ============================================================ noise (OTCHET-SHUM-ZHIVYE-2910 §5): fewer false ESCALATE_WRITTEN_RUN
KEYWORD_LINES = ["for i in 1 2 3; do echo $i; done", "while true; do sleep 1; break; done", "until false; do break; done",
                 "if [[ -f x.txt ]]; then echo y; elif [ -d d ]; then echo d; else echo n; fi", "{ echo a; echo b; }", "! grep -q x notes.txt",
                 "time ls", "seq 1 3", "kill 12345", "for f in *.txt; do wc -l $f; continue; done", "function show { echo x; }",
                 "for i in $(seq 3); do kill -0 $i; done"]
STILL_ASKED = ["eval echo hi", "source env.sh", ". env.sh", "exec ./run.sh", "while python3 poll.py; do sleep 1; done",
               "for i in 1 2; do python3 f.py; done", "if ./check.sh; then echo ok; fi", "time python3 f.py", "seq 3 | xargs -n1 python3 f.py"]
PROCSUB_TEXT = ["cat <<'EOF' > notes.md\nuse tee >(python3 x.py) to fork the stream\nEOF",
                "cat > notes.md <<EOF\nratio >(5 and <(10\nEOF",
                'echo "a >(5 b <(note: c" > notes.md']
PROCSUB_RUN = ["cat f.py | tee >(python3)", "diff <(sort a.txt) <(./gen.sh)", "tee >(sh) < notes.md"]


def _open_agent(client, owner, tmp_path, name):
    """The agent of the noise measure (setup D): unlisted commands allowed, so ESCALATE_WRITTEN_RUN is the only question left."""
    from app.hookjudge.mapping import DEFAULT_SAFE_COMMANDS, default_form
    a = Agent(client, owner, tmp_path, extra_cmds=CMDS, name=name)
    f = default_form(a.proj, safe_commands=list(DEFAULT_SAFE_COMMANDS) + ["pytest"] + CMDS)
    a.m, r = owner.mandate(a.ag["id"], dict(f, command=dict(f["command"], unlisted="allow")))
    assert r.status_code == 200, r.text
    a.tool("Write", {"file_path": a.proj + "/f.py", "content": NET + "\n"})
    return a


def _wr_reasons(a, cmd):
    return WR in {p[2] for p in a.line(cmd)[1]}


def _asked(a, cmd):
    return a.line(cmd)[0] != "ALLOW"


def test_shum_shell_keywords_are_not_runs(client, owner, tmp_path):
    bad = []
    for i, c in enumerate(KEYWORD_LINES):
        if _wr_reasons(_open_agent(client, owner, tmp_path, "kw%d" % i), c):
            bad.append(c)
    assert not bad, bad
    # guard (unchanged behaviour): eval / source / . / exec and a loop / if / time around a real run stay asked
    miss = []
    for i, c in enumerate(STILL_ASKED):
        b = _open_agent(client, owner, tmp_path, "sa%d" % i)
        if not _asked(b, c):
            miss.append(c)
    assert not miss, miss
    from app.hookjudge.runners import head_runs_code
    assert all(head_runs_code(h) for h in ("eval", "exec", "source", ".", "coproc", "trap", "python3", "./x.sh"))


def test_shum_procsub_only_outside_heredoc_text(client, owner, tmp_path):
    bad = []
    for i, c in enumerate(PROCSUB_TEXT):
        if _wr_reasons(_open_agent(client, owner, tmp_path, "ps%d" % i), c):
            bad.append(c)
    assert not bad, bad
    miss = []
    for i, c in enumerate(PROCSUB_RUN):
        b = _open_agent(client, owner, tmp_path, "pr%d" % i)
        if not _asked(b, c):
            miss.append(c)
    assert not miss, miss


# ============================================================ second hang (replay, session with `U=https://<long host>; ... $U$p`)
def test_hang_host_regex_is_linear():
    """bashparse.HOST_OK backtracked exponentially on a long host followed by a character a host may not have (`https://aaaa...a;`):
    2^n steps (n = 27: seconds; n = 60: years). A `curl` line with such a URL hung the server thread in execguard._risky_text."""
    from app.hookjudge import bashparse as bp
    for n in (27, 60, 4000):
        t = time.time()
        bp.code_net("curl -s https://" + "a" * n + "; echo")
        bp.code_net("U=https://" + "d7" * (n // 2) + "-8787.dstack.example.network;curl $U/x")
        assert time.time() - t < 0.5, n
    assert bp.HOST_OK.fullmatch("api.example.com") and bp.HOST_OK.fullmatch("a-b.c.") and bp.HOST_OK.fullmatch("[::1]")
    assert not bp.HOST_OK.fullmatch("a" * 30 + ";") and not bp.HOST_OK.fullmatch("-a.com") and not bp.HOST_OK.fullmatch("a-.com")


def test_hang_long_host_through_the_server(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=CMDS, name="host")
    t = time.time()
    a.line("U=https://" + "d7" * 20 + "-8787.dstack.example.network; for p in /a /b; do curl -s -o out.txt $U$p; done")
    assert time.time() - t < LIMIT
