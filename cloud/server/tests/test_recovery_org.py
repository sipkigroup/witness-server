"""0.2.2 for organisations (0.2 quorum): a member who lost the passkey the policy names gets it replaced by the OTHER members
(rule `recovery`, k of n, k >= 2). One test per rule:
 O1 the owner lost the phone: two other members replace the owner's key (wq), the registry log names the swap, the pack is VALID
 O2 the lost key never signs its own replacement; one other member is not enough
 O3 without a `recovery` rule the rule `policy` applies (no quiet takeover); a `recovery` rule with k = 1 is refused
 O4 nothing but the key changes through this door"""
import json

from app import _paths  # noqa: F401
import wa_profile as wa
from tests.org_helpers import MSG_FORM, TEAM_RULES, Person, adopt, ctx_of, team
from tests.recovery_helpers import export_to, new_codes, recover, remove_key, run_verify, switch_auth

RECOVERY_RULES = dict(TEAM_RULES, recovery={"role": "any", "k": 2})


def team_with_recovery(app):
    owner, bob, carol = team(app)
    v = adopt(owner, [{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": bob.uid, "roles": ["budget"]},
                      {"user_id": carol.uid, "roles": ["access"]}], RECOVERY_RULES)
    assert v == 3
    return owner, bob, carol


def lose_and_recover(app, person, org_id=None):
    """The person's phone is gone: a recovery code (made earlier) -> a new passkey on a new browser -> signed in with it."""
    codes = new_codes(person)
    lost = person.auth
    new, br, f = recover(app, person, codes[0])
    assert f.status_code == 200, f.text
    switch_auth(person, new)
    if org_id is not None and org_id != person.uid:                # a new sign-in starts in the person's own account
        assert person.post("/api/orgs/switch", account_id=org_id).status_code == 200
    return lost, new


def test_o1_owner_key_replaced_by_two_others_and_pack_valid(app, tmp_path):
    owner, bob, carol = team_with_recovery(app)
    ag, _ = owner.new_agent("demo", "bot")
    lost, new = lose_and_recover(app, owner)
    # the recovered owner is not a policy member with the NEW key yet: it cannot sign for the team
    me = owner.c.get("/api/me").json()
    assert [k["kid_hex"] for k in me["signing_keys"]] == [lost.kid.hex()]     # the policy still names the lost key (not on this device)
    r = bob.post("/api/org/key-replace", user_id=owner.uid)
    assert r.status_code == 200, r.text
    rq = r.json()
    assert rq["rule"] == "recovery" and rq["needs"] == [{"role": "any", "k": 2}] and rq["old_kid"] == lost.kid.hex() and rq["new_kid"] == new.kid.hex()
    g = bob.c.get("/api/sig-requests/" + rq["req_id"]).json()
    assert g["meta"]["recovery"]["old_kid"] == lost.kid.hex()
    assert rq["req_id"] in [x["id"] for x in carol.c.get("/api/sig-requests").json()]
    r = bob.sign_req(rq["req_id"])
    assert r.status_code == 200 and r.json()["status"] == "collecting" and r.json()["have"] == 1, r.text
    r = carol.sign_req(rq["req_id"])
    assert r.status_code == 200 and r.json()["status"] == "done" and r.json()["policy_ver"] == 4, r.text
    pol = owner.c.get("/api/org").json()
    kids = [m["kid"] for m in pol["policy"]["members"]]
    assert new.kid.hex() in kids and lost.kid.hex() not in kids
    assert [m for m in pol["members"] if m["user_id"] == owner.uid][0]["kid"] == new.kid.hex()
    assert pol["policy"]["rules"] == json.loads(json.dumps(RECOVERY_RULES))           # rules unchanged
    # the registry log row of v4 names the swap (a third party sees it in the pack)
    row = ctx_of(app).db.q("SELECT entry_json FROM registry_log WHERE account_id=? ORDER BY seq", ("org:" + owner.uid,))[-1]
    assert json.loads(row["entry_json"])["org_policy"]["key_swap"] == {"old_kid": lost.kid.hex(), "new_kid": new.kid.hex()}
    # the owner signs for the team again, with the new key
    assert owner.c.get("/api/me").json()["signing_keys"][0]["kid_hex"] == new.kid.hex()
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=MSG_FORM).json()
    r = owner.sign_req(d["req_id"])
    assert r.status_code == 200, r.text
    assert remove_key(owner, lost.kid.hex()).status_code == 200                       # the lost phone off the account
    d = export_to(owner.c, tmp_path / "pack")
    reg = json.load(open(d + "/registry.json"))
    swaps = [json.loads(x["row_json"])["org_policy"].get("key_swap") for x in reg["log"] if "row_json" in x and "org_policy" in x["row_json"]]
    assert {"old_kid": lost.kid.hex(), "new_kid": new.kid.hex()} in swaps
    rc, out = run_verify(d, "--offline")
    print(out)
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    assert "org policy: chain ok (v1..v4)" in out
    assert "org recovery: v4 replaced key %s -> %s (rule recovery any k=2, 2 signers, the replaced key not among them: yes)" % (
        lost.kid[:4].hex(), new.kid[:4].hex()) in out, out
    assert "keys: 2 keys (1 added: 0 by passkey, 1 by recovery code (witness-attested); 1 removed)" in out, out


def test_o2_lost_key_never_counts_one_is_not_enough(app):
    owner, bob, carol = team_with_recovery(app)
    lost, new = lose_and_recover(app, bob, owner.uid)
    rq = owner.post("/api/org/key-replace", user_id=bob.uid).json()
    # whoever holds bob's OLD key (a thief with the phone) cannot sign the replacement
    bob_old = Person(app)
    bob_old.c, bob_old.auth = bob.c, lost
    r = bob_old.sign_req(rq["req_id"])
    assert r.status_code == 409 and r.json()["error"] == "RECOVERY_SELF", r.text
    # bob's NEW key is not a member yet
    r = bob.sign_req(rq["req_id"])
    assert r.status_code == 409 and r.json()["error"] == "WQ_NOT_MEMBER", r.text
    r = owner.sign_req(rq["req_id"])
    assert r.json()["status"] == "collecting"                       # one other member is not enough (k = 2)
    assert owner.c.get("/api/org").json()["policy_ver"] == 3
    assert carol.sign_req(rq["req_id"]).json()["status"] == "done"
    assert owner.c.get("/api/org").json()["policy_ver"] == 4


def test_o3_no_recovery_rule_no_takeover_and_k1_refused(app):
    owner, bob, carol = team(app)                                   # TEAM_RULES: policy = owner k=1, no recovery rule
    lost, new = lose_and_recover(app, owner)
    rq = bob.post("/api/org/key-replace", user_id=owner.uid).json()
    assert rq["rule"] == "policy" and rq["needs"] == [{"role": "owner", "k": 1}]
    r = bob.sign_req(rq["req_id"])
    assert r.status_code == 403 and r.json()["error"] == "ROLE_NOT_NEEDED"     # bob and carol together cannot take the owner's key
    assert carol.sign_req(rq["req_id"]).status_code == 403
    # an owner may add a recovery rule, but never one that lets ONE person replace someone's key
    o2, b2, c2 = team(app)
    r = o2.post("/api/org/policy/draft", members=[{"user_id": o2.uid, "roles": ["owner", "budget"]}, {"user_id": b2.uid, "roles": ["budget"]},
                                                  {"user_id": c2.uid, "roles": ["access"]}], rules=dict(TEAM_RULES, recovery={"role": "any", "k": 1}))
    assert r.status_code == 422 and r.json()["error"] == "POLICY_MALFORMED", r.text


def test_o4_only_the_key_changes(app):
    owner, bob, carol = team_with_recovery(app)
    r = bob.post("/api/org/key-replace", user_id=carol.uid)
    assert r.status_code == 409 and r.json()["error"] == "NO_NEW_KEY"           # carol has no other passkey: nothing to swap to
    assert bob.post("/api/org/key-replace", user_id="nobody").status_code == 422
    lost, new = lose_and_recover(app, carol, owner.uid)
    rq = bob.post("/api/org/key-replace", user_id=carol.uid).json()
    g = bob.c.get("/api/sig-requests/" + rq["req_id"]).json()
    before = owner.c.get("/api/org").json()["policy"]
    after = g["body"]
    assert after["rules"] == before["rules"] and after["ver"] == before["ver"] + 1
    strip = lambda ms: sorted((m["label"], tuple(m["roles"])) for m in ms)
    assert strip(after["members"]) == strip(before["members"])
    assert {m["kid"] for m in after["members"]} ^ {m["kid"] for m in before["members"]} == {lost.kid.hex(), new.kid.hex()}
    # a member's wa-sig over a payload that changes MORE than the key is not this request's payload: refused by the signature check
    r = owner.post("/api/sig-requests/" + rq["req_id"], envelope_b64=owner.sign(g["typ"], wa.cde({"x": 1})))
    assert r.status_code == 409


def test_o5_revoked_key_never_counts_in_a_hand_built_wq_and_team_pack_with_wb(app, tmp_path):
    """Bob removed his lost key, the policy still names it (no replacement yet): a wq that an insider builds with that key's signature
    is refused. A member's batch approval (wb) in a team pack with key changes still verifies."""
    import hashlib
    import wq_profile as wq
    from svidetel_v4.state import approval_payload
    from tests.helpers import act
    from tests.org_helpers import policy_hash_now
    owner, bob, carol = team_with_recovery(app)
    ag, hdr = owner.new_agent("demo", "pub")
    form = {k: v for k, v in MSG_FORM.items() if k != "publish"}       # publishing unspecified -> deferred to a human
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=form).json()
    assert owner.sign_req(d["req_id"]).json()["status"] == "done"
    lost, new = lose_and_recover(app, bob, owner.uid)
    assert remove_key(bob, lost.kid.hex()).status_code == 200
    x = act(owner.c, hdr, "publish", {"channel": "blog", "text": "t"}).json()
    assert x["verdict"] == "defer", x
    g = owner.c.get("/api/approvals/" + x["rid"]).json()
    pay = approval_payload(g["mandate"], g["action"], x["rid"], True)
    env = wq.make_wq(wa.TYP_APPROVAL, pay, policy_hash_now(app, owner.uid),
                     [wq.wsig_of_wa(lost.sign_object(wa.TYP_APPROVAL, pay, "localhost", "http://localhost:8810"))])
    r = owner.post("/api/approvals/" + x["rid"], approved=True, envelope_b64=wa.b64u(env))
    assert r.status_code == 409 and r.json()["error"] == "KEY_REVOKED", r.text
    # carol approves it in a batch (wb, k = 1 for publish)
    items = [hashlib.sha256(pay).digest()]
    ad, cd, der = carol.auth.get_assertion(wq.wb_challenge(items), "localhost", "http://localhost:8810")
    r = carol.post("/api/approvals/" + x["rid"], approved=True, envelope_b64=wa.b64u(wq.make_wb(items, carol.auth.kid, ad, cd, der)))
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    lost_o, new_o = lose_and_recover(app, owner)                 # the owner's account (= the organisation) gets key changes too
    dd = export_to(owner.c, tmp_path / "pack")
    rc, out = run_verify(dd, "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    assert "batch approvals: 1 envelopes, 1 items" in out and "keys: 2 keys" in out, out
