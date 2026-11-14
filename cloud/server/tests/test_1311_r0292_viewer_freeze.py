"""r0292 (owner's decision 13.11, p.5): "anyone may stop". A Viewer (internal role "observer") may FREEZE an agent of the team:
only freeze -- not unfreeze, not revoke, not anything else; every freeze is in the journal with who did it; the rate is limited
(a broken viewer account cannot keep the team stopped faster than the owner unfreezes). Unfreezing stays the owner's."""
from app import _paths  # noqa: F401
from app import org, actions
from tests.helpers import H, act
from tests.org_helpers import Person, team


def _viewer(app, owner):
    obs = Person(app).register("Oscar", invite=owner.invite(["observer"]))
    assert obs.joined["roles"] == ["observer"] and obs.joined["status"] == "active"
    obs.stepup()
    return obs


def test_viewer_may_freeze_and_it_is_journaled(app):
    owner, bob, carol = team(app)
    ag, hdr = owner.new_agent("demo", "seen")
    obs = _viewer(app, owner)
    r = obs.post("/api/agents/%s/freeze" % ag["id"])
    assert r.status_code == 200, r.text
    assert r.json()["frozen_at"]
    j = owner.c.get("/api/agents/%s/freezes" % ag["id"]).json()
    assert j["frozen_at"] and j["journal"][0]["kind"] == "freeze" and j["journal"][0]["by_user"] == obs.uid
    # the agent is refused now
    assert "AGENT_FROZEN" in act(owner.c, hdr, "publish", {"channel": "news", "text": "t"}).text


def test_viewer_freeze_still_needs_a_fresh_passkey(app):
    owner, bob, carol = team(app)
    ag, _ = owner.new_agent("demo", "seen")
    obs = Person(app).register("Oscar", invite=owner.invite(["observer"]))
    app.state.ctx.db.x("UPDATE sessions SET stepup_at=0")
    assert obs.post("/api/agents/%s/freeze" % ag["id"]).status_code == 403
    assert app.state.ctx.db.one("SELECT frozen_at FROM agents WHERE id=?", (ag["id"],))["frozen_at"] is None


def test_viewer_cannot_unfreeze_or_revoke(app):
    owner, bob, carol = team(app)
    ag, _ = owner.new_agent("demo", "seen")
    obs = _viewer(app, owner)
    assert obs.post("/api/agents/%s/freeze" % ag["id"]).status_code == 200
    r = obs.post("/api/agents/%s/unfreeze" % ag["id"])
    assert r.status_code == 403 and r.json()["error"] == "FORBIDDEN", r.text
    assert app.state.ctx.db.one("SELECT frozen_at FROM agents WHERE id=?", (ag["id"],))["frozen_at"] is not None
    r = obs.c.post("/api/mandates/m_none/revoke", json={"envelope_b64": "AA"}, headers=H)
    assert r.status_code == 403, r.text
    # an approver (non-owner signer) may freeze but not unfreeze either: unfreezing is the owner's
    bob.stepup()
    assert bob.post("/api/agents/%s/unfreeze" % ag["id"]).status_code == 403
    owner.stepup()
    assert owner.post("/api/agents/%s/unfreeze" % ag["id"]).json()["changed"] is True


def test_viewer_freeze_rate_is_limited(app):
    owner, bob, carol = team(app)
    agents = [owner.new_agent("demo", "a%d" % i)[0] for i in range(actions.FREEZE_RATE_N + 1)]
    obs = _viewer(app, owner)
    codes = [obs.post("/api/agents/%s/freeze" % a["id"]).status_code for a in agents]
    assert codes[:actions.FREEZE_RATE_N] == [200] * actions.FREEZE_RATE_N, codes
    assert codes[-1] == 429, codes
    assert app.state.ctx.db.one("SELECT frozen_at FROM agents WHERE id=?", (agents[-1]["id"],))["frozen_at"] is None
    # the owner is not limited: the owner can always stop
    owner.stepup()
    assert owner.post("/api/agents/%s/freeze" % agents[-1]["id"]).status_code == 200


def test_rights_table_freeze_is_the_only_viewer_change():
    roles, statuses = org.RIGHTS["freeze"]
    assert "observer" in roles and set(org.SIGNERS) <= set(roles) and statuses == ("active",)
    assert all("observer" not in org.RIGHTS[a][0] for a in ("write", "mandate", "sign", "owner"))
