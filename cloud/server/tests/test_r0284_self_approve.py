"""r0284 item 5 (law Z2): in a team nobody approves the question of THEIR OWN agent by default, even with no delegation set.
"Their own" = the member who created the agent (agents.created_by). Only when another signing member exists; a solo account is untouched;
an agent with no known creator (made before r0284) keeps the old behaviour (limit: nothing is known about who runs it)."""
from tests.helpers import act
from tests.org_helpers import MSG_FORM, Person, ctx_of, team


def _agent(app, creator):
    ag, hdr = creator.new_agent("demo", "bot")
    from tests.test_quorum import mandate_draft
    dr = mandate_draft(creator, ag["id"], MSG_FORM)
    assert creator.sign_req(dr["req_id"]).json()["mandate_status"] == "active"
    return ag, hdr


def _defer(owner, hdr, v="news"):
    r = act(owner.c, hdr, "purchase", {"vendor": v + ".example", "amount_cents": 5000}).json()
    assert r["verdict"] == "defer", r
    return r


def test_creator_cannot_approve_own_agent_in_a_team_others_can(app):
    owner, bob, carol = team(app)
    ag, hdr = _agent(app, owner)
    r = _defer(owner, hdr)
    e = owner.approve(r["rid"])
    assert e.status_code == 409 and e.json()["error"] == "SELF_APPROVAL", e.text
    assert owner.approve(r["rid"], approved=False).json()["verdict"] == "refused"      # stopping is never harder
    r = _defer(owner, hdr, "news2")
    assert bob.approve(r["rid"]).json()["verdict"] == "allow"


def test_solo_account_is_untouched(client, owner):
    ag, hdr = owner.new_agent("demo", "bot")
    m, r = owner.mandate(ag["id"])
    assert r.status_code == 200, r.text
    r = act(client, hdr, "publish", {"channel": "blog", "text": "hi"}).json()
    assert r["verdict"] == "defer", r
    assert owner.approve(r["rid"]).json()["verdict"] == "allow"


def test_agent_of_unknown_creator_keeps_old_behaviour(app):
    owner, bob, carol = team(app)
    ag, hdr = _agent(app, owner)
    ctx_of(app).db.x("UPDATE agents SET created_by=NULL WHERE id=?", (ag["id"],))
    r = _defer(owner, hdr)
    assert owner.approve(r["rid"]).json()["verdict"] == "allow"
