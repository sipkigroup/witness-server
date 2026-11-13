"""04.11 (L3): one tool call = at most ONE question for the owner.
`curl -sI https://example.com; echo "rc=$?"` is judged in parts (Bash.net + Bash, each with its own receipt: the 0.2.56-0.2.58 hooks check
and consume them one by one) and used to make two questions, two pushes, two rows on the dashboard. Now (hookjudge/judge.py _one_question):
one lead question is listed and announced, the other parts are linked to it (actions.line_lead), the page signs ONE batch (wb) over them, a
refusal refuses all, a part that refuses the line withdraws the earlier questions of the call without a word to the owner."""
import hashlib
import os

import cbor2
import pytest

from app import _paths  # noqa: F401
import wa_profile as wa
from svidetel_v4.state import approval_payload
from app.flow.wq import wq
from tests.helpers import RP, ORIGIN
from tests.test_0217_judge import agent, _body, NONCE  # noqa: F401

LINE = 'curl -sI https://example.com; echo "rc=$?"'


class Spy:
    enabled = False

    def __init__(self):
        self.calls = []

    def notify_defer(self, row, name, lits):
        self.calls.append(row["rid"])

    def approval(self, row):
        self.calls.append(row["rid"])


@pytest.fixture()
def spies(client):
    ctx = client.app.state.ctx
    old = (getattr(ctx, "push", None), getattr(ctx, "notify", None))
    ctx.push, ctx.notify = Spy(), Spy()
    yield ctx.push, ctx.notify
    ctx.push, ctx.notify = old


def judge(client, agent, tmp_path, cmd):
    p = os.path.realpath(str(tmp_path))
    rp = {p: p, "/home/u": "/home/u"}
    while True:
        r = client.post("/v1/hook/judge", json=_body(cmd, p, fs={"realpath": dict(rp)}), headers=agent).json()
        if "need" not in r:
            return r
        rp.update({x: x for x in r["need"].get("realpath", [])})


def waiting(ctx):
    return [x["rid"] for x in ctx.db.q("SELECT rid FROM actions WHERE status='pending_approval' ORDER BY created_at, rowid")]


def wb_for(client, owner, rids, approved=True, views=None):
    items = []
    for i, rid in enumerate(rids):
        g = client.get("/api/approvals/" + rid).json()
        items.append(hashlib.sha256(approval_payload(g["mandate"], g["action"], rid, approved, bytes.fromhex(views[i]) if views else None)).digest())
    ad, cd, der = owner.auth.get_assertion(wq.wb_challenge(items), RP, ORIGIN)
    return wa.b64u(wq.make_wb(items, owner.auth.kid, ad, cd, der))


def test_1_two_parts_one_question_one_notification_both_reasons(client, owner, agent, tmp_path, spies):
    push, chan = spies
    ctx = client.app.state.ctx
    r = judge(client, agent, tmp_path, LINE)
    assert [p["tool"] for p in r["parts"]] == ["Bash.net", "Bash"]
    assert [p["result"]["status"] for p in r["parts"]] == ["pending_approval", "pending_approval"]     # each part keeps its own receipt
    lead, sib = r["parts"][0]["result"]["rid"], r["parts"][1]["result"]["rid"]
    assert lead != sib
    assert push.calls == [lead] and chan.calls == [lead]                                               # ONE notification, for the lead
    assert [x["rid"] for x in client.get("/api/approvals").json()] == [lead]                           # ONE row on the dashboard
    row = ctx.db.one("SELECT line_lead FROM actions WHERE rid=?", (sib,))
    assert row["line_lead"] == lead
    g = client.get("/api/approvals/" + lead).json()                                                    # the page names both reasons
    assert set(g["line_reasons"]) == {"ESCALATE_COMMAND_DANGER", "ESCALATE_COMMAND"}
    assert [x["rid"] for x in g["line_group"]] == [sib]
    # the same call sent again while it waits: the same questions, nothing new, no second notification
    r2 = judge(client, agent, tmp_path, LINE)
    assert [p["result"]["rid"] for p in r2["parts"]] == [lead, sib]
    assert push.calls == [lead] and waiting(ctx) == [lead, sib]


def test_2_one_signature_approves_the_whole_call_and_the_repeat_runs_once(client, owner, agent, tmp_path, spies):
    ctx = client.app.state.ctx
    r = judge(client, agent, tmp_path, LINE)
    lead, sib = r["parts"][0]["result"]["rid"], r["parts"][1]["result"]["rid"]
    res = owner.post("/api/approvals/batch", rids=[lead, sib], approved=True, envelope_b64=wb_for(client, owner, [lead, sib]))
    assert res.status_code == 409 and res.json()["error"] == "LINE_VIEW"         # red team 04.11: never "view not signed" for a call in parts
    hexes = [client.get("/api/approvals/" + x).json()["view_sha256"] for x in (lead, sib)]
    res = owner.post("/api/approvals/batch", rids=[lead, sib], approved=True, envelope_b64=wb_for(client, owner, [lead, sib], views=hexes), views=hexes)
    assert res.status_code == 200, res.text
    assert [x["verdict"] for x in res.json()["results"]] == ["allow", "allow"]
    r2 = judge(client, agent, tmp_path, LINE)                                                          # the repeat of the SAME call
    assert [(p["tool"], p["result"]["verdict"], p["result"]["status"], p["result"]["rid"]) for p in r2["parts"]] == [
        ("Bash.net", "allow", "approved", lead), ("Bash", "allow", "approved", sib)]                    # both parts OK, same receipts
    for rid in (lead, sib):                                                                            # the hook consumes each receipt once
        assert client.post("/v1/actions/%s/present" % rid, headers=agent).json()["result"] == "accept"
        assert client.post("/v1/actions/%s/present" % rid, headers=agent).json()["result"] != "accept"
    # the approval is for THIS exact text: another line is a new question
    r3 = judge(client, agent, tmp_path, 'curl -sI https://example.com; echo "rc=$?" ; sudo ls')
    assert all(p["result"]["status"] != "approved" for p in r3["parts"])
    assert ctx.db.one("SELECT COUNT(*) AS n FROM approvals")["n"] == 2


def test_2b_one_refusal_refuses_every_part(client, owner, agent, tmp_path, spies):
    ctx = client.app.state.ctx
    r = judge(client, agent, tmp_path, LINE)
    lead, sib = r["parts"][0]["result"]["rid"], r["parts"][1]["result"]["rid"]
    assert owner.approve(lead, approved=False).json()["verdict"] == "refused"
    assert ctx.db.one("SELECT status FROM actions WHERE rid=?", (sib,))["status"] == "denied"
    assert waiting(ctx) == []


def test_2c_a_part_cannot_be_approved_alone_by_the_single_page_and_shows_again_if_the_lead_is_gone(client, owner, agent, tmp_path, spies):
    ctx = client.app.state.ctx
    r = judge(client, agent, tmp_path, LINE)
    lead, sib = r["parts"][0]["result"]["rid"], r["parts"][1]["result"]["rid"]
    assert owner.approve(lead).json()["verdict"] == "allow"                  # an older page: the lead alone
    assert [x["rid"] for x in client.get("/api/approvals").json()] == [sib]   # the other part is not lost: it is listed now
    assert client.get("/api/approvals/" + sib).json()["status"] == "pending_approval"


def test_2d_batch_still_refuses_unrelated_parts(client, owner, agent, tmp_path, spies):
    a = judge(client, agent, tmp_path, LINE)["parts"]
    b = judge(client, agent, tmp_path, "make")["parts"]
    rids = [a[0]["result"]["rid"], b[0]["result"]["rid"]]
    res = owner.post("/api/approvals/batch", rids=rids, approved=True, envelope_b64=wb_for(client, owner, rids))
    assert res.status_code == 409 and res.json()["error"] == "BATCH_MIXED"


def test_3_a_part_that_refuses_the_line_withdraws_the_questions_before_it(client, owner, agent, tmp_path, spies):
    push, chan = spies
    ctx = client.app.state.ctx
    first = judge(client, agent, tmp_path, LINE)["parts"]
    lead, sib = first[0]["result"]["rid"], first[1]["result"]["rid"]
    assert owner.approve(sib, approved=False).json()["verdict"] == "refused"      # the owner refused the `Bash` part of this exact line
    ctx.db.x("UPDATE actions SET status='expired' WHERE rid=?", (lead,))         # ... and the question for its first part ran out
    push.calls.clear(); chan.calls.clear()
    r = judge(client, agent, tmp_path, LINE)
    assert [(p["tool"], p["result"]["verdict"]) for p in r["parts"]] == [("Bash.net", "deny"), ("Bash", "deny")]
    assert r["parts"][0]["result"]["rid"] not in (lead, sib) and r["parts"][0]["result"]["reason"] == "REFUSED"
    assert waiting(ctx) == []                                                     # the question stored for part 0 was withdrawn
    assert push.calls == [] and chan.calls == []                                  # and nobody was told
    assert ctx.db.one("SELECT status FROM actions WHERE rid=?", (r["parts"][0]["result"]["rid"],))["status"] == "denied"


def test_4_a_single_command_is_asked_as_before(client, owner, agent, tmp_path, spies):
    push, chan = spies
    ctx = client.app.state.ctx
    r = judge(client, agent, tmp_path, "make")
    assert len(r["parts"]) == 1 and r["parts"][0]["result"]["status"] == "pending_approval"
    rid = r["parts"][0]["result"]["rid"]
    assert push.calls == [rid] and chan.calls == [rid]
    assert ctx.db.one("SELECT line_lead FROM actions WHERE rid=?", (rid,))["line_lead"] is None
    assert [x["rid"] for x in client.get("/api/approvals").json()] == [rid]
    assert "line_group" not in client.get("/api/approvals/" + rid).json()
    assert owner.approve(rid).json()["verdict"] == "allow"
    ok = judge(client, agent, tmp_path, "ls")                                                          # an allowed line: no question at all
    assert ok["parts"][0]["result"]["verdict"] == "allow" and push.calls == [rid]


def test_5_a_team_policy_keeps_one_question_per_part(client, owner, agent, tmp_path, spies):
    from tests_flow.helpers import set_policy
    push, _ = spies
    ctx = client.app.state.ctx
    set_policy(ctx, owner.account["id"], {"policy": {"role": "owner", "k": 1}, "mandate": [], "approval": [], "revocation": {"role": "any", "k": 1},
                                          "ceiling": {"role": "owner", "k": 1}})
    r = judge(client, agent, tmp_path, LINE)
    assert len(r["parts"]) == 2 and sorted(push.calls) == sorted(p["result"]["rid"] for p in r["parts"])
    assert len(client.get("/api/approvals").json()) == 2
