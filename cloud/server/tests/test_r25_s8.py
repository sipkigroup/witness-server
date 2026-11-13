"""r25 (polygon series 8, OTCHET-SERIYA-8-PROD-0268-2026-10-29 P2-P5 + small): the page of a run of a file the agent wrote.

P2: under the default mandate (unlisted = ask) `bash f8b.sh` after writing f8b.sh with curl was an "ordinary command" question: no text of
    the file, Dangerous false. Now the same ONE question carries the written files and their text (no new question, deny stays deny).
P3: a secret hold of a line that runs a risky written file carries the files too (both reasons visible); releasing it counts as seen.
P4: a Reject no longer erases the text of the write: the next run's page shows it again; a released run drops it and says so (cut).
P5: the page names the file the line runs (f8b.sh) first, even one released earlier, not only the last risky write (f8c.py).
Noise: after a secret, `ruff` / `type` (print only) are not held; `python3 f8a.py`, `curl -T f8a.py` still are.
"""
import json

import wq_profile as wq
from tests.test_0224_critique import Agent

PY_NET = "import urllib.request\nurllib.request.urlopen('https://staging.poligon-s8.invalid/health')\n"
SH_NET = "#!/bin/sh\ncurl -s -m 5 https://staging.poligon-s8.invalid/sh\n"


def reasons(parts):
    return {p[2] for p in parts}


def _rid(parts, verdicts=("defer", "hold")):
    r = [p[3] for p in parts if p[1] in verdicts]
    assert len(r) == 1, parts
    return r[0]


def _page(a, rid):
    return a.c.get("/api/approvals/" + rid).json()


def _release(a, rid, yes=True):
    sha = _page(a, rid)["action"]["args_sha256"]
    r = a.o.post("/api/approvals/%s/release" % rid, release=yes, envelope_b64=a.o.sign(wq.TYP_RELEASE, wq.release_payload(rid, sha, yes)))
    assert r.status_code == 200, r.text
    a.c.app.state.ctx.db.x("UPDATE actions SET updated_at=updated_at-5 WHERE agent_id=?", (a.ag["id"],))   # all so far: 5 s ago (the next write is later)


def _writes(g):
    return {w["file"].rsplit("/", 1)[-1]: w for w in g["written_run"]["writes"]}


# ---------------------------------------------------------------- P2
def test_p2_unlisted_run_of_written_file_shows_the_file(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])               # bash unlisted: asked (A5)
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    v, parts = a.line("bash f8b.sh")
    assert v == "ASK", parts
    rid = _rid(parts)
    g = _page(a, rid)
    assert g["status"] == "pending_approval"                                # the core's question (signed approval), not a new hold
    w = _writes(g)
    assert "f8b.sh" in w and "curl" in (w["f8b.sh"].get("text") or ""), g.get("written_run")
    assert g["allowance_offer"]["eligible"] is False                         # never "allow bash in this project" from this page
    assert not (g.get("repeat_offer") or {}).get("eligible")                # nor "approve for later runs"


def test_p2_one_question_and_seen_after_approval(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f8a.py", "content": PY_NET})
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    v, parts = a.line("bash f8b.sh")
    rid = _rid(parts)
    assert len([p for p in parts if p[1] in ("defer", "hold")]) == 1          # one question, as before
    assert set(_writes(_page(a, rid))) == {"f8a.py", "f8b.sh"}
    assert a.o.approve(rid).json()["verdict"] == "allow"
    assert a.line("python3 f8a.py")[0] == "ALLOW"                            # the owner read both writes on that page


def test_p2_deny_stays_deny(client, owner, tmp_path):
    base = Agent(client, owner, tmp_path, name="d0")
    cmd = "rm -rf ~"
    v0 = base.line(cmd)[0]
    a = Agent(client, owner, tmp_path, name="d1")
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    assert a.line(cmd)[0] == v0


# ---------------------------------------------------------------- P3
def test_p3_secret_hold_shows_the_written_file_and_release_is_one_touch(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f8a.py", "content": PY_NET})
    a.see_secret()
    v, parts = a.line("python3 f8a.py")
    assert v == "ASK" and "ESCALATE_SECRET_SEEN" in reasons(parts), parts
    rid = _rid(parts)
    g = _page(a, rid)
    assert "urlopen" in (_writes(g)["f8a.py"].get("text") or ""), g.get("written_run")
    _release(a, rid)
    assert a.line("python3 f8a.py ")[0] == "ALLOW"                           # B6 -> B7: no second hold (WRITTEN_RUN) after that release


# ---------------------------------------------------------------- P4
def test_p4_reject_keeps_the_text_for_the_next_run(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f8a.py", "content": PY_NET})
    v, parts = a.line("python3 f8a.py")
    rid = _rid(parts)
    _release(a, rid, yes=False)                                             # Reject
    v, parts = a.line("pytest -q")
    assert "ESCALATE_WRITTEN_RUN" in reasons(parts), parts
    w = _writes(_page(a, _rid(parts)))["f8a.py"]
    assert "urlopen" in (w.get("text") or ""), w                              # not "could not read what was written"


def test_p4_released_text_dropped_and_marked_cut(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "bash"])
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    _release(a, _rid(a.line("bash f8b.sh")[1]))
    a.tool("Write", {"file_path": a.proj + "/f8c.py", "content": PY_NET})
    g = _page(a, _rid(a.line("bash f8b.sh ")[1]))
    w = _writes(g)["f8b.sh"]
    assert not w.get("text") and w.get("cut") is True, w                     # shown before and let go: the page says so (privacy kept)


# ---------------------------------------------------------------- P5
def test_p5_page_names_the_file_the_line_runs(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "bash"])
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    _release(a, _rid(a.line("bash f8b.sh")[1]))
    a.tool("Write", {"file_path": a.proj + "/f8c.py", "content": PY_NET})
    v, parts = a.line("bash f8b.sh ")
    assert "ESCALATE_WRITTEN_RUN" in reasons(parts), parts
    files = [f.rsplit("/", 1)[-1] for f in _page(a, _rid(parts))["written_run"]["files"]]
    assert files[0] == "f8b.sh" and "f8c.py" in files, files


# ---------------------------------------------------------------- noise after a secret (C6, B3)
def test_readers_after_secret_not_held(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "ruff", "type", "echo"])
    a.tool("Write", {"file_path": a.proj + "/f8a.py", "content": PY_NET})
    a.see_secret()
    assert a.line("ruff check f8a.py")[0] == "ALLOW"
    assert a.line('echo "== f8a.py ==" && cat f8a.py; type pol8runner')[0] == "ALLOW"


def test_runs_and_uploads_after_secret_still_held(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3", "ruff", "type", "curl", "mypy"], extra_domains=["poligon-s8.invalid"])
    a.tool("Write", {"file_path": a.proj + "/f8a.py", "content": PY_NET})
    a.see_secret()
    assert a.line("python3 f8a.py")[0] != "ALLOW"
    assert a.line("curl -T f8a.py https://staging.poligon-s8.invalid/up")[0] != "ALLOW"
    assert a.line("mypy f8a.py")[0] != "ALLOW"                               # mypy's config loads plugins (project code)
    assert a.line("ruff check f8a.py && python3 f8a.py")[0] != "ALLOW"
