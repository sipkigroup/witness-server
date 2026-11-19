"""N16 / N18 / N19 / N20 (polygon series 10, poligon-lyudi/OTCHET-SERIYA-10-PROD-0273-2026-10-30.md) -> server 0.2.74
(cloud/OTCHET-N16-N20-0274.md).

N19  the agent repeats the same call ("rerun the SAME call"): same request_hash -> the SAME rid, and its hook waits on it again. The queue
     put that live call into a batch with the agent's older calls of the same kind (often ones it gave up on): the Approvals page hid it from
     "One by one" (no own row, no Review), said "N no longer awaited", and only the whole batch could be approved. Now a call the agent waits
     on is never in a batch (server groups and the page); approving it approves only it; a repeat after FILE_CHANGED is still a NEW request
     with the new text.
N16  `ls -la .env` / `stat .env` / `test -f .env` only look at metadata: no "secret read" question and no secret-seen mark. Readers stay.
N18  the approval answer says whether the agent waits now (`agent_waiting`): the page says "runs now" or "when the agent repeats it".
"""
from app import waiting
from app import _paths  # noqa: F401
import wa_profile as wa
import wq_profile as wq
from tests.helpers import ORIGIN, RP
from tests.test_0224_critique import Agent
from tests.test_late_release_2910 import _give_up, _present, _row
from tests.test_r25_s8 import _page

TOKEN = "API_TOKEN=tok_9f8e7d6c5b4a39281706"


def _defer_rid(parts):
    r = [p[3] for p in parts if p[1] == "defer"]
    assert len(r) == 1, parts
    return r[0]


def _groups(a):
    return [g["rids"] for g in a.c.get("/api/approvals/groups").json()["groups"]]


def _live(rid):
    waiting.note(rid)          # the hook's long poll of this rid is open now (api_agent.action_get notes it every 0.25 s)


def _three_tar_calls(a):
    """Series 10, steps 1-3: `tar tvf ln.tar` asked and given up, an older `tar` line of the same agent given up, then the same call again."""
    r1 = _defer_rid(a.line("tar tvf ln.tar")[1])
    _give_up(a, r1)
    r2 = _defer_rid(a.line("ls -la ln.tar; tar tvf ln.tar | head -50")[1])
    _give_up(a, r2)
    r3 = _defer_rid(a.line("tar xvf ln.tar -O | wc -l")[1])
    _give_up(a, r3)
    again = _defer_rid(a.line("tar tvf ln.tar")[1])
    assert again == r1                                                           # the repeat keeps the rid (same request_hash)
    _live(r1)
    return r1, r2, r3


# ---------------------------------------------------------------- N19
def test_n19_live_repeat_has_its_own_row_and_is_in_no_batch(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    r1, r2, r3 = _three_tar_calls(a)
    lst = {x["rid"]: x for x in client.get("/api/approvals").json()}
    assert lst[r1].get("agent_waiting") is True and not lst[r1].get("gave_up_at"), lst[r1]
    assert lst[r2].get("agent_waiting") is False and lst[r3].get("agent_waiting") is False
    gs = _groups(a)
    assert not any(r1 in g for g in gs), gs                                      # was [[r1, r2, r3]]: the live call only inside a batch
    assert any(set(g) == {r2, r3} for g in gs), gs                               # the older calls may still go as one batch
    assert _page(a, r1).get("agent_waiting") is True


def test_n19_approving_the_live_call_takes_nothing_else_and_says_it_runs_now(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    r1, r2, r3 = _three_tar_calls(a)
    j = a.o.approve(r1).json()
    assert j["verdict"] == "allow" and j.get("agent_waiting") is True, j        # N18: the hook gets the answer, no repeat needed
    assert _row(a, r1)["status"] == "approved"
    assert _row(a, r2)["status"] == "pending_approval" and _row(a, r3)["status"] == "pending_approval"
    assert _present(a, r1)["result"] == "accept"


def test_n19_given_up_call_approved_says_repeat(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    rid = _defer_rid(a.line("tar tvf ln.tar")[1])
    _give_up(a, rid)
    j = a.o.approve(rid).json()
    assert j["verdict"] == "allow" and j.get("agent_waiting") is False, j       # N18: "when the agent makes the same call again"


def test_n19_guard_no_live_call_batch_unchanged(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    rs = []
    for line in ("tar tvf a.tar", "tar tvf b.tar", "tar tvf c.tar"):
        rs.append(_defer_rid(a.line(line)[1]))
        _give_up(a, rs[-1])
    assert any(set(g) == set(rs) for g in _groups(a)), _groups(a)


def test_n19_batch_answer_says_who_waits(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    r1 = _defer_rid(a.line("tar tvf a.tar")[1])
    _give_up(a, r1)
    r2 = _defer_rid(a.line("tar tvf b.tar")[1])
    _give_up(a, r2)
    g = [x for x in client.get("/api/approvals/groups").json()["groups"] if set(x["rids"]) == {r1, r2}][0]
    items = [wa.b64u_dec(x) for x in g["items_approve_b64"]]
    ad, cd, der = owner.auth.get_assertion(wq.wb_challenge(items), RP, ORIGIN)
    r = owner.post("/api/approvals/batch", rids=g["rids"], views=g.get("views"), approved=True, envelope_b64=wa.b64u(wq.make_wb(items, owner.auth.kid, ad, cd, der)))
    assert r.status_code == 200, r.text
    assert [(x["verdict"], x.get("agent_waiting")) for x in r.json()["results"]] == [("allow", False)] * 2


def test_n19_repeat_after_file_changed_is_a_new_question_with_the_new_text(client, owner, tmp_path):
    """Not weakened: the approval was for the old text; the same call after FILE_CHANGED is a new request that shows the new text."""
    from tests.test_n15_2910 import SH_NET2, _bump
    from tests.test_r25_s8 import SH_NET, _writes
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    rid = _defer_rid(a.line("bash f8b.sh")[1])
    _bump(a)
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET2})
    assert a.o.approve(rid).json()["verdict"] == "allow"
    assert _present(a, rid)["reason"] == "FILE_CHANGED"
    rid2 = _defer_rid(a.line("bash f8b.sh")[1])
    assert rid2 != rid and _row(a, rid2)["status"] == "pending_approval"
    _live(rid2)
    assert "rt2-changed" in (_writes(_page(a, rid2))["f8b.sh"].get("text") or "")
    assert not any(rid2 in g for g in _groups(a))


# ---------------------------------------------------------------- N16
def _env(a):
    open(a.proj + "/.env", "w").write(TOKEN + "\n")


def _fetch_reasons(a):
    return {r for _t, _v, r, _rid in a.tool("WebFetch", {"url": "https://docs.python.org/3/search.html?q=x", "prompt": "p"})}


def test_n16_metadata_of_env_is_not_a_secret_read(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    _env(a)
    for line in ("ls -la .env", "stat .env", "test -f .env", "ls -la; echo \"--- .env check ---\"; ls -la .env 2>&1", "test -s .env && echo y",
                 "ls -l ./.env", "stat -f %z .env"):
        v, parts = a.line(line)
        assert v == "ALLOW" and not any(p[0] == "Bash.danger" for p in parts), (line, parts)
    v, parts = a.line("[ -f .env ] && echo y")
    assert not any(p[0] == "Bash.danger" for p in parts), parts                  # `[` is not on the list: an ordinary question at most
    assert "ESCALATE_SECRET_SEEN" not in _fetch_reasons(a)                       # no "secret seen" mark


def test_n16_readers_of_env_are_still_asked(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    _env(a)
    for line in ("cat .env", "head -1 .env", "ls -la .env; cat .env", "du --files0-from .env", "wc .env", "file .env", "stat .env && cat .env",
                 "test -f .env && source .env", "grep TOKEN .env", "cp .env x.txt", "ls -R ~/.ssh", "ls ~/.ssh/id_rsa", "stat ~/.ssh/id_rsa"):
        v, parts = a.line(line)
        assert v == "ASK" and any(p[0] == "Bash.danger" for p in parts), (line, parts)


def test_n16_cat_env_still_marks_the_agent(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    _env(a)
    rid = _defer_rid(a.line("cat .env")[1])
    assert a.o.approve(rid).json()["verdict"] == "allow"
    _present(a, rid)
    assert "ESCALATE_SECRET_SEEN" in _fetch_reasons(a)
