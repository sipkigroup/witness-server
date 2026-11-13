"""0.2.0 merge (08 x 01 x 02): pushes go to PEOPLE of the organisation, by role. A quorum request (mandate needing 2 budget signers)
wakes the budget members who have not signed; an access-only member is not woken; a new defer of the org wakes its signing members
(also a member who subscribed while in another organisation); an item held by the advisor wakes them like a defer."""
from tests.helpers import act
from tests.org_helpers import MONEY_FORM, MSG_FORM, Person, adopt, TEAM_RULES
from tests.test_push import Device, FakeSender, pcfg, papp  # noqa: F401  (fixtures)


def _team(app):
    owner = Person(app).register("Olga")
    tb, tc = owner.invite(["budget"]), owner.invite(["access"])
    bob = Person(app).register("Bob", invite=tb)
    carol = Person(app).register("Carol", invite=tc)
    adopt(owner)
    adopt(owner, [{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": bob.uid, "roles": ["budget"]},
                  {"user_id": carol.uid, "roles": ["access"]}], TEAM_RULES)
    return owner, bob, carol


def _sub(p, host):
    p.stepup()
    r = p.post("/api/push/subscribe", subscription=Device("https://%s/ep/%s" % (host, p.uid)).sub(), device=p.uid[:6])
    assert r.status_code == 200, r.text


def _sent(papp, since=0):
    papp.state.ctx.push.drain()
    return [c for c in papp.state.ctx.push.sender.calls[since:]]


def test_quorum_request_wakes_the_needed_signers_only(papp):
    owner, bob, carol = _team(papp)
    for p, h in ((owner, "push.test"), (bob, "push.test"), (carol, "push.test")):
        _sub(p, h)
    papp.state.ctx.push.sender = FakeSender()
    ag, hdr = owner.new_agent("demo", "buyer")
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=MONEY_FORM).json()
    calls = _sent(papp)
    eps = {c["endpoint"].rsplit("/", 1)[1] for c in calls}
    assert eps == {owner.uid, bob.uid}, eps                       # budget k=2: Olga and Bob; Carol (access) is not asked
    assert all(c["data"] == {"v": 2, "k": "s", "id": d["req_id"], "g": c["data"]["g"]} for c in calls)   # P0-4: only opaque ids


def test_defer_and_hold_wake_the_signing_members(papp):
    owner, bob, carol = _team(papp)
    _sub(bob, "push.test")
    papp.state.ctx.push.sender = FakeSender()
    ag, hdr = owner.new_agent("demo", "clerk")
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form={k: v for k, v in MSG_FORM.items() if k != "publish"}).json()
    assert owner.sign_req(d["req_id"]).json()["mandate_status"] == "active"
    n = len(_sent(papp))
    r = act(owner.c, hdr, "publish", {"channel": "news", "text": "hello"}).json()
    assert r["verdict"] == "defer"
    calls = _sent(papp, n)
    assert len(calls) == 1 and calls[0]["data"]["k"] == "a" and calls[0]["data"]["id"] == r["rid"]
    assert calls[0]["endpoint"].endswith(bob.uid)                  # Bob subscribed from his own session in Olga's org



def test_held_by_advisor_wakes_like_a_defer(papp):
    from app.flow import advisor
    owner, bob, carol = _team(papp)
    _sub(bob, "push.test")
    ag, hdr = owner.new_agent("demo", "clerk")
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=dict(MSG_FORM, forbidden_data=["postal_address"])).json()
    assert owner.sign_req(d["req_id"]).json()["mandate_status"] == "active"
    papp.state.ctx.db.x("INSERT OR REPLACE INTO org_settings(account_id, advisor) VALUES(?, 'heuristic')", (owner.uid,))
    papp.state.ctx.push.sender = FakeSender()
    advisor.warm()
    try:
        r = act(owner.c, hdr, "send_email", {"to": "ann@acme.example", "subject": "visit", "body": "I live at twelve Baker street"}).json()
    finally:
        advisor.reset()
    assert (r["status"], r["reason"]) == ("held", "ADVISORY_HOLD"), r
    calls = _sent(papp)
    assert [c["data"]["id"] for c in calls] == [r["rid"]] and calls[0]["endpoint"].endswith(bob.uid)
