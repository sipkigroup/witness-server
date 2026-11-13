"""late 29.10 (OTCHET-R1-HELD-WAIT-2910, remarks 1 and 2): the owner decides AFTER the hook gave up waiting.

1. A held call whose hook said "this is my last poll" (`?final=1`) is marked gave_up (journal: "not run: timeout"), as a pending one was.
2. Released after that: the agent repeats the same call and gets THAT released, not yet presented row (one touch), instead of a new
   decision that another rule (a secret seen) holds again. Only: same agent, same mandate, same request (byte for byte, the advisor's
   release label aside), released by the owner, not expired, not presented, once. An approved pending call was already returned by the
   repeat lookup (status approved is waiting): kept, tested here.
"""
import time

from tests.test_0224_critique import Agent
from tests.test_r25_s8 import _page, _release, _rid


def _db(a):
    return a.c.app.state.ctx.db


def _row(a, rid):
    return _db(a).one("SELECT * FROM actions WHERE rid=?", (rid,))


def _give_up(a, rid):
    r = a.c.get("/v1/actions/%s?wait=1&final=1" % rid, headers=a.hdr)
    assert r.status_code == 200, r.text
    return r.json()


URL = "https://docs.python.org/3/x"


def _fetch(a, url=URL):
    """After a secret, every fetch is held (ESCALATE_SECRET_SEEN), the released one too: the case of the second touch."""
    parts = a.tool("WebFetch", {"url": url, "prompt": "p"})
    return ("ALLOW" if all(p[1] == "allow" for p in parts) else "ASK"), parts


def _held_after_secret(a):
    a.see_secret()
    v, parts = _fetch(a)
    assert v == "ASK" and any(p[2] == "ESCALATE_SECRET_SEEN" for p in parts), parts
    return _rid(parts)


def _present(a, rid):
    return a.c.post("/v1/actions/%s/present" % rid, headers=a.hdr).json()


# ---------------------------------------------------------------- 1: held + final=1 -> gave_up
def test_held_last_poll_marks_gave_up(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    rid = _held_after_secret(a)
    j = _give_up(a, rid)
    assert j["status"] == "held"
    assert _row(a, rid)["gave_up_at"], "held + final=1 must say 'not run: timeout'"
    hist = client.get("/api/feed?agent_id=" + a.ag["id"]).json()["items"]
    assert any(it["rid"] == rid and it.get("gave_up_at") for it in hist), hist
    held = client.get("/api/approvals?status=held").json()
    assert any(it["rid"] == rid and it.get("gave_up_at") and it.get("agent_waiting") is False for it in held), held
    assert _page(a, rid).get("gave_up_at")


def test_held_poll_without_final_not_marked(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    rid = _held_after_secret(a)
    a.c.get("/v1/actions/%s?wait=1" % rid, headers=a.hdr)
    assert not _row(a, rid)["gave_up_at"]


# ---------------------------------------------------------------- 2: release after the hook gave up -> the repeat gets that row
def test_release_after_give_up_repeat_reuses_the_released_row(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    rid = _held_after_secret(a)
    _give_up(a, rid)
    _release(a, rid)
    assert _row(a, rid)["status"] == "allowed"
    n0 = _db(a).one("SELECT COUNT(*) AS n FROM actions WHERE agent_id=?", (a.ag["id"],))["n"]
    v, parts = _fetch(a)
    assert v == "ALLOW" and [p[3] for p in parts] == [rid], parts           # no second hold, no new row
    assert _db(a).one("SELECT COUNT(*) AS n FROM actions WHERE agent_id=?", (a.ag["id"],))["n"] == n0
    assert _present(a, rid)["result"] == "accept"
    v2, parts2 = _fetch(a)                                       # presented: never reused again
    assert rid not in [p[3] for p in parts2] and v2 == "ASK", parts2


def test_reuse_only_once(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    rid = _held_after_secret(a)
    _give_up(a, rid)
    _release(a, rid)
    assert [p[3] for p in _fetch(a)[1]] == [rid]
    parts = _fetch(a)[1]                                         # the reused answer was not presented: a NEW decision
    assert rid not in [p[3] for p in parts], parts


def test_release_while_waiting_not_reused(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    rid = _held_after_secret(a)
    _release(a, rid)                                                          # the hook was still waiting: it presents it itself
    assert rid not in [p[3] for p in _fetch(a)[1]]


def test_other_hash_gets_a_new_decision(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    rid = _held_after_secret(a)
    _give_up(a, rid)
    _release(a, rid)
    v, parts = _fetch(a, URL + "?v=1")
    assert rid not in [p[3] for p in parts] and v == "ASK", parts
    assert _row(a, rid)["gave_up_at"]                                         # still there for the exact repeat
    assert [p[3] for p in _fetch(a)[1]] == [rid]


def test_presented_row_not_reused(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    rid = _held_after_secret(a)
    _give_up(a, rid)
    _release(a, rid)
    assert _present(a, rid)["result"] == "accept"
    assert rid not in [p[3] for p in _fetch(a)[1]]


def test_expired_row_not_reused(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    rid = _held_after_secret(a)
    _give_up(a, rid)
    _release(a, rid)
    _db(a).x("UPDATE actions SET expires=? WHERE rid=?", (int(time.time()) - 1, rid))
    assert rid not in [p[3] for p in _fetch(a)[1]]


def test_rejected_row_not_reused(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    rid = _held_after_secret(a)
    _give_up(a, rid)
    _release(a, rid, yes=False)
    assert _row(a, rid)["status"] == "denied"
    assert rid not in [p[3] for p in _fetch(a)[1]]


def test_core_allowed_row_with_gave_up_not_reused(client, owner, tmp_path):
    """A row the CORE allowed (no owner decision) is never handed out again, even with a stray gave_up mark."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    v, parts = _fetch(a)                                                      # no secret seen: the core allows it
    assert v == "ALLOW", parts
    rid = parts[0][3]
    _db(a).x("UPDATE actions SET gave_up_at=? WHERE rid=?", (int(time.time()), rid))
    assert rid not in [p[3] for p in _fetch(a)[1]]


def test_command_released_after_give_up_not_reused(client, owner, tmp_path):
    """RT-0269 p.1 (deliberate change: was test_command_released_after_give_up_reused, asserting == [rid]). A command's hash does not cover
    the file it runs: another agent of the account (RT-0269 1a) or a write the witness does not see as one (`tar x`, `patch`: 1b) changes
    what runs after the owner let it go. The late release is never handed to a repeated command: it is judged anew (a second touch,
    as before late 29.10). Fetch / Write keep the reuse (their whole content is in the hash)."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.see_secret()
    a.tool("Write", {"file_path": a.proj + "/s.py", "content": "print(1)\n"})
    rid = _rid(a.line("python3 s.py")[1])
    _give_up(a, rid)
    _release(a, rid)
    assert rid not in [p[3] for p in a.line("python3 s.py")[1]]


def test_command_late_release_other_agent_write_not_reused(client, owner, tmp_path):
    """RT-0269 1a: agent B of the same account rewrites A's script; A's repeat must not get the released row."""
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"], name="A")
    a.tool("Write", {"file_path": a.proj + "/s.py", "content": "print(1)\n"})
    a.see_secret()
    rid = _rid(a.line("python3 s.py")[1])
    _give_up(a, rid)
    _release(a, rid)
    b = Agent(client, owner, tmp_path, extra_cmds=["python3"], name="B")
    b.tool("Write", {"file_path": a.proj + "/s.py", "content": "print(2)\n"})
    assert rid not in [p[3] for p in a.line("python3 s.py")[1]]


def test_write_after_release_not_reused(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.see_secret()
    a.tool("Write", {"file_path": a.proj + "/s.py", "content": "print(1)\n"})
    rid = _rid(a.line("python3 s.py")[1])
    _give_up(a, rid)
    _release(a, rid)
    a.tool("Write", {"file_path": a.proj + "/s.py", "content": "print(2)\n"})  # what the owner let run is not what would run now
    assert rid not in [p[3] for p in a.line("python3 s.py")[1]]


# ---------------------------------------------------------------- the same for an approved question (path already existed)
def test_approve_after_give_up_repeat_gets_the_approved_row(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    v, parts = a.line("make build")
    rid = _rid(parts)
    assert _give_up(a, rid)["status"] == "pending_approval"
    assert _row(a, rid)["gave_up_at"]
    assert owner.approve(rid).json()["verdict"] == "allow"
    v, parts = a.line("make build")
    assert v == "ALLOW" and [p[3] for p in parts] == [rid], parts
    assert _present(a, rid)["result"] == "accept"
    assert rid not in [p[3] for p in a.line("make build")[1]]
