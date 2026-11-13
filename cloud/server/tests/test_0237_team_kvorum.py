"""0.2.37 (owner decision 24.10): a Team policy changes only with the CURRENT quorum, never by the owner alone.
(a) the owner alone cannot lower the threshold / drop a member at once; (b) the quorum can; (c) a delayed change takes effect after the wait
and any current member cancels it; the lost-member recovery path (owner proposes, wait, members may cancel) works without them."""
import time

import pytest

from app import org
from tests.org_helpers import TEAM_RULES, adopt, ctx_of, team

ONE = [{"if": "money_over", "amount": 50000, "role": "budget", "k": 1}]
LOW = dict(TEAM_RULES, approval=ONE, mandate=ONE)


def members(owner, *others):
    return [{"user_id": owner.uid, "roles": ["owner", "budget"]}] + [{"user_id": p.uid, "roles": r} for p, r in others]


def ver(app, owner):
    return org.current_policy(ctx_of(app), owner.uid)[0]["ver"]


def draft(owner, delayed=False, drop_bob=True, bob=None, carol=None):
    ms = members(owner, (carol, ["access"])) if drop_bob else members(owner, (bob, ["budget"]), (carol, ["access"]))
    body = dict(members=ms, rules=LOW)
    if delayed:
        body["delayed"] = True
    r = owner.post("/api/org/policy/draft", **body)
    assert r.status_code == 200, r.text
    return r.json()


def test_a_owner_alone_cannot_lower_threshold_or_drop_member(app):
    owner, bob, carol = team(app)
    d = draft(owner, bob=bob, carol=carol)
    assert d["needs"] == [{"role": "owner", "k": 1}, {"role": "any", "k": 2}] and not d["delayed"]
    r = owner.sign_req(d["req_id"])
    assert r.status_code == 200 and r.json()["status"] == "collecting" and r.json()["have"] == 1, r.text
    assert ver(app, owner) == 2                                    # nothing changed
    assert org.member(ctx_of(app), owner.uid, bob.uid)["status"] == "active"
    # the same signature again is a duplicate, not a second signer
    assert owner.sign_req(d["req_id"]).status_code == 409
    # a hand-made apply path does not exist: the request stays collecting
    row = ctx_of(app).db.one("SELECT status FROM sig_requests WHERE id=?", (d["req_id"],))
    assert row["status"] == "collecting"


def test_a2_one_non_owner_member_cannot_do_it_either(app):
    owner, bob, carol = team(app)
    d = draft(owner, bob=bob, carol=carol)
    r = bob.sign_req(d["req_id"])                                  # Bob signs first: no owner signature -> not enough
    assert r.status_code == 200 and r.json()["status"] == "collecting", r.text
    assert ver(app, owner) == 2
    r = carol.sign_req(d["req_id"])                                # two members, still no owner (rule `policy`)
    assert r.status_code in (200, 409) and (r.status_code == 409 or r.json()["status"] == "collecting"), r.text
    assert ver(app, owner) == 2


def test_b_current_quorum_can_change_the_policy(app):
    owner, bob, carol = team(app)
    d = draft(owner, bob=bob, carol=carol)
    assert owner.sign_req(d["req_id"]).json()["status"] == "collecting"
    r = bob.sign_req(d["req_id"])
    assert r.status_code == 200 and r.json()["status"] == "done" and r.json()["policy_ver"] == 3, r.text
    assert org.member(ctx_of(app), owner.uid, bob.uid)["status"] == "removed"


def test_c_delayed_change_takes_effect_after_the_wait(app, monkeypatch):
    monkeypatch.setenv("DW_POLICY_DELAY_S", "3600")
    owner, bob, carol = team(app)
    d = draft(owner, delayed=True, bob=bob, carol=carol)
    assert d["delayed"] and d["delay_s"] == 3600 and d["needs"] == [{"role": "owner", "k": 1}]
    r = owner.sign_req(d["req_id"])
    assert r.status_code == 200 and r.json()["status"] == "scheduled", r.text
    eff = r.json()["effective_at"]
    assert eff >= int(time.time()) + 3590 and ver(app, owner) == 2
    assert org.apply_due(ctx_of(app), owner.uid) == 0 and ver(app, owner) == 2          # not yet
    info = owner.c.get("/api/org").json()
    assert [x["id"] for x in info["scheduled_policy"]] == [d["req_id"]]
    assert bob.c.get("/api/sig-requests/" + d["req_id"]).json()["effective_at"] == eff    # every member sees it
    ctx_of(app).db.x("UPDATE sig_requests SET meta=json_set(meta,'$.effective_at',?) WHERE id=?", (int(time.time()) - 1, d["req_id"]))
    assert org.apply_due(ctx_of(app), owner.uid) == 1
    assert ver(app, owner) == 3 and org.member(ctx_of(app), owner.uid, bob.uid)["status"] == "removed"
    assert ctx_of(app).db.one("SELECT status FROM sig_requests WHERE id=?", (d["req_id"],))["status"] == "done"


def test_c2_member_cancels_scheduled_change(app):
    owner, bob, carol = team(app)
    d = draft(owner, delayed=True, bob=bob, carol=carol)
    assert owner.sign_req(d["req_id"]).json()["status"] == "scheduled"
    r = bob.post("/api/sig-requests/%s/cancel" % d["req_id"])
    assert r.status_code == 200 and r.json()["status"] == "cancelled", r.text
    ctx_of(app).db.x("UPDATE sig_requests SET meta=json_set(meta,'$.effective_at',?) WHERE id=?", (int(time.time()) - 1, d["req_id"]))
    assert org.apply_due(ctx_of(app), owner.uid) == 0 and ver(app, owner) == 2
    assert bob.post("/api/sig-requests/%s/cancel" % d["req_id"]).status_code == 409          # already closed


def test_c3_outsider_and_stale_cannot_cancel_or_apply(app):
    from tests.org_helpers import Person
    owner, bob, carol = team(app)
    d = draft(owner, delayed=True, bob=bob, carol=carol)
    owner.sign_req(d["req_id"])
    stranger = Person(app).register("Eve")
    assert stranger.post("/api/sig-requests/%s/cancel" % d["req_id"]).status_code in (403, 404)
    # the chain moves on (quorum adopts another version) -> the scheduled one is void and never applies
    adopt(owner, members(owner, (bob, ["budget"]), (carol, ["access"])), dict(TEAM_RULES, ceiling={"role": "owner", "k": 1}))
    assert ctx_of(app).db.one("SELECT status FROM sig_requests WHERE id=?", (d["req_id"],))["status"] == "superseded"
    ctx_of(app).db.x("UPDATE sig_requests SET meta=json_set(meta,'$.effective_at',?) WHERE id=?", (int(time.time()) - 1, d["req_id"]))
    assert org.apply_due(ctx_of(app), owner.uid) == 0 and ver(app, owner) == 3


def test_d_solo_and_k1_organisations_unchanged(app):
    from tests.org_helpers import Person
    p = Person(app).register("Solo")
    assert adopt(p) == 1
    d = p.post("/api/org/policy/draft", members=[{"user_id": p.uid, "roles": ["owner", "budget", "access"]}],
               rules=org.GENESIS_RULES | {"revocation": org.REVOCATION_RULE}, delayed=True)
    assert d.status_code == 200 and d.json()["delayed"] is False        # no quorum anywhere: the owner's rule decides, now
    r = p.sign_req(d.json()["req_id"])
    assert r.json()["status"] == "done", r.text


def test_e_key_replace_path_is_not_slowed(app):
    from tests.test_recovery_org import team_with_recovery, lose_and_recover
    owner, bob, carol = team_with_recovery(app)
    lose_and_recover(app, bob, owner.uid)
    rq = owner.post("/api/org/key-replace", user_id=bob.uid).json()
    owner.sign_req(rq["req_id"])
    assert carol.sign_req(rq["req_id"]).json()["status"] == "done"
