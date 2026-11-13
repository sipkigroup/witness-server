"""04.11 (red team of 0e8d9e8): the lead's page signs every part of the call, so it must SHOW every part (signed = shown, p.1); a batch of one
call is all or nothing (p.3); with a team policy the parts are separate questions that can always be decided (p.5)."""
import hashlib

import pytest

from app import _paths  # noqa: F401
import wa_profile as wa
from svidetel_v4.state import approval_payload
from app import signview
from app.flow.wq import wq
from tests.helpers import RP, ORIGIN
from tests.test_0217_judge import agent, _body, NONCE  # noqa: F401
from tests.test_0411_one_approval_per_call import judge, waiting, spies, LINE  # noqa: F401

POC = 'curl -sI https://example.com; echo "%s"; make deploy-prod' % ("A" * 5000)


def wb_views(client, owner, rids, approved=True, views=None):
    """-> (envelope_b64, views hex): each item signed with its view; views = the hex the page claims (default: what GET of the lead shows)."""
    lead = client.get("/api/approvals/" + rids[0]).json()
    shown = {lead["rid"]: (lead["mandate"], lead["action"], lead["view_sha256"])}
    for g in lead.get("line_group") or []:
        shown[g["rid"]] = (g["mandate"], g["view"]["action"], g["view_sha256"])
    hexes = views or [shown[r][2] for r in rids]
    items = [hashlib.sha256(approval_payload(shown[r][0], shown[r][1], r, approved, bytes.fromhex(h))).digest() for r, h in zip(rids, hexes)]
    ad, cd, der = owner.auth.get_assertion(wq.wb_challenge(items), RP, ORIGIN)
    return wa.b64u(wq.make_wb(items, owner.auth.kid, ad, cd, der)), hexes


def test_p1_the_lead_shows_every_part_it_signs_poc_make_deploy_prod(client, owner, agent, tmp_path, spies):
    r = judge(client, agent, tmp_path, POC)
    pend = [p for p in r["parts"] if p["result"]["status"] == "pending_approval"]
    assert len(pend) >= 2
    lead = pend[0]["result"]["rid"]
    g = client.get("/api/approvals/" + lead).json()
    assert "make deploy-prod" not in (g.get("text_preview") or "")[-100:] and not g.get("line_commands")   # the lead alone hides it (the PoC)
    assert "make deploy-prod" in str(g["line_group"])                                     # now the lead's answer carries it
    for part in g["line_group"]:
        own = client.get("/api/approvals/" + part["rid"]).json()                           # the view shown on the lead = the part's own view
        assert part["view"] == signview.view_of(own) and part["view_sha256"] == own["view_sha256"]
        assert part["view"]["action"] == own["action"] and part["mandate"] == own["mandate"]
    assert any("make deploy-prod" in " ".join(p["view"].get("line_commands") or []) for p in g["line_group"])
    # one wb over the views the lead SHOWED: accepted, every part allowed, each APPROVAL names its view
    rids = [lead] + [p["rid"] for p in g["line_group"]]
    env, hexes = wb_views(client, owner, rids)
    res = owner.post("/api/approvals/batch", rids=rids, approved=True, envelope_b64=env, views=hexes)
    assert res.status_code == 200, res.text
    assert [x["verdict"] for x in res.json()["results"]] == ["allow"] * len(rids)
    ctx = client.app.state.ctx
    assert all(ctx.db.one("SELECT view_sha256 FROM approvals WHERE rid=?", (x,))["view_sha256"] == h for x, h in zip(rids, hexes))


def test_p1_a_part_view_other_than_the_shown_one_is_refused(client, owner, agent, tmp_path, spies):
    r = judge(client, agent, tmp_path, LINE)
    lead, sib = r["parts"][0]["result"]["rid"], r["parts"][1]["result"]["rid"]
    g = client.get("/api/approvals/" + lead).json()
    env, hexes = wb_views(client, owner, [lead, sib], views=[g["view_sha256"], "00" * 32])
    res = owner.post("/api/approvals/batch", rids=[lead, sib], approved=True, envelope_b64=env, views=hexes)
    assert res.status_code == 409 and res.json()["error"] == "VIEW_CHANGED"
    assert waiting(client.app.state.ctx) == [lead, sib]


def test_p3_a_part_that_fails_its_check_refuses_the_whole_call_before_any_entry(client, owner, agent, tmp_path, spies, monkeypatch):
    from app import actions as A
    from app.context import Err
    ctx = client.app.state.ctx
    r = judge(client, agent, tmp_path, LINE)
    lead, sib = r["parts"][0]["result"]["rid"], r["parts"][1]["result"]["rid"]
    real = A.levels.check_signers
    sib_reason = ctx.db.one("SELECT reason FROM actions WHERE rid=?", (sib,))["reason"]

    def only_sib(ctx_, acc_id, kids, action, reason, level_min):          # the part (not the lead) needs the phone
        if reason == sib_reason:
            raise Err(409, "DEVICE_LEVEL")
        return real(ctx_, acc_id, kids, action, reason, level_min)
    monkeypatch.setattr(A.levels, "check_signers", only_sib)
    env, hexes = wb_views(client, owner, [lead, sib])
    res = owner.post("/api/approvals/batch", rids=[lead, sib], approved=True, envelope_b64=env, views=hexes)
    assert res.status_code == 409 and res.json()["error"] == "DEVICE_LEVEL"
    assert ctx.db.one("SELECT COUNT(*) AS n FROM approvals")["n"] == 0                # nothing written: all or nothing
    assert waiting(ctx) == [lead, sib]


def test_p3_a_refusal_of_the_call_signs_a_refusal_for_every_part(client, owner, agent, tmp_path, spies):
    ctx = client.app.state.ctx
    r = judge(client, agent, tmp_path, LINE)
    lead, sib = r["parts"][0]["result"]["rid"], r["parts"][1]["result"]["rid"]
    env, hexes = wb_views(client, owner, [lead, sib], approved=False)
    res = owner.post("/api/approvals/batch", rids=[lead, sib], approved=False, envelope_b64=env, views=hexes)
    assert res.status_code == 200, res.text
    assert [(x["rid"], x["verdict"]) for x in res.json()["results"]] == [(lead, "refused"), (sib, "refused")]
    assert ctx.db.one("SELECT COUNT(*) AS n FROM approvals WHERE approved=0")["n"] == 2   # the part's own signed refusal (lead written last)
    assert waiting(ctx) == []


def test_p5_a_policy_that_came_in_while_the_call_waits_shows_every_part_and_no_line_batch(client, owner, agent, tmp_path, spies):
    from tests_flow.helpers import set_policy
    ctx = client.app.state.ctx
    r = judge(client, agent, tmp_path, LINE)
    lead, sib = r["parts"][0]["result"]["rid"], r["parts"][1]["result"]["rid"]
    assert [x["rid"] for x in client.get("/api/approvals").json()] == [lead]
    set_policy(ctx, owner.account["id"], {"policy": {"role": "owner", "k": 1}, "mandate": [], "approval": [], "revocation": {"role": "any", "k": 1},
                                          "ceiling": {"role": "owner", "k": 1}})
    assert sorted(x["rid"] for x in client.get("/api/approvals").json()) == sorted([lead, sib])   # nothing hidden: each part decidable
    g = client.get("/api/approvals/" + lead).json()
    assert "line_group" not in g and "line_reasons" not in g                          # the page decides the lead alone, not by batch
    env, hexes = wb_views(client, owner, [lead])
    res = owner.post("/api/approvals/batch", rids=[lead, sib], approved=False, envelope_b64=env, views=None)
    assert res.status_code == 409 and res.json()["error"] in ("BATCH_MIXED", "WB_ITEM")
