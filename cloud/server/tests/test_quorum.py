"""Task 01 of 0.2: quorum of mandates, approvals, revocations and policy changes (ARHITEKTURA-0.2 2.2-2.4), flow hooks (8), held/release."""
import hashlib
import json

import pytest

from app import _paths  # noqa: F401
import wa_profile as wa
from app import wire
import wq_profile as wq
from svidetel_v4.state import approval_payload
from tests.helpers import RP, ORIGIN, act
from tests.org_helpers import MONEY_FORM, MSG_FORM, TEAM_RULES, adopt, ctx_of, ledger_entries, loads, policy_hash_now, team
from tests import viewkit  # noqa: E402  (r0352: decisions name the view)


def mandate_draft(p, agent_id, form):
    d = p.post("/api/mandates/draft", agent_id=agent_id, form=form)
    assert d.status_code == 200, d.text
    return d.json()


def money_mandate(owner, bob):
    ag, hdr = owner.new_agent("demo", "buyer")
    d = mandate_draft(owner, ag["id"], MONEY_FORM)
    assert d["quorum"] is True and d["needs"] == [{"role": "budget", "k": 2}]
    return ag, hdr, d


def msg_mandate(owner):
    """A mandate without money (no tier fires): one member's signature makes it active; purchases defer (ESCALATE_MONEY)."""
    ag, hdr = owner.new_agent("demo", "clerk")
    d = mandate_draft(owner, ag["id"], MSG_FORM)
    assert d["needs"] == []
    r = owner.sign_req(d["req_id"])
    assert r.json()["status"] == "done" and r.json()["mandate_status"] == "active", r.text
    return ag, hdr, d["mandate"]


# (1) budget k=2 above 50000: one signature -> collecting, two -> active, the ledger entry carries a wq
def test_1_mandate_quorum_collecting_then_active(app):
    owner, bob, carol = team(app)
    ag, hdr, d = money_mandate(owner, bob)
    r = owner.sign_req(d["req_id"])
    assert r.status_code == 200 and r.json()["status"] == "collecting" and (r.json()["have"], r.json()["need"]) == (1, 2), r.text
    assert owner.c.get("/api/agents").json()[0]["active_mandate_id"] is None
    assert [x["id"] for x in bob.c.get("/api/sig-requests").json()] == [d["req_id"]]          # Bob is asked, the owner is not again
    assert owner.c.get("/api/sig-requests").json() == []
    r = bob.sign_req(d["req_id"])
    assert r.status_code == 200 and r.json()["status"] == "done" and r.json()["mandate_status"] == "active", r.text
    assert [x["status"] for x in owner.c.get("/api/mandates").json()] == ["active"]
    ent = [e for e in ledger_entries(app, owner.uid) if e["type"] == "MANDATE"]
    assert len(ent) == 1
    env = ent[0]["body"]["cose"]
    assert wq.envelope_kind(env) == "wq"
    q = loads(env)
    assert q["policy"] == policy_hash_now(app, owner.uid) and len(q["sigs"]) == 2
    assert {w["kid"] for w in q["sigs"]} == {bytes.fromhex(owner.keycard["kid_hex"]), bytes.fromhex(bob.keycard["kid_hex"])}
    # the agent now works under the quorum mandate
    assert act(owner.c, hdr, "purchase", {"vendor": "v.example", "amount_cents": 5000}).json()["verdict"] == "allow"


# (2) the same mandate signed by owner + access -> 409 WQ_QUORUM (the budget rule needs two budget signers)
def test_2_owner_plus_access_is_not_a_budget_quorum(app):
    owner, bob, carol = team(app)
    ag, hdr, d = money_mandate(owner, bob)
    m = d["mandate"]
    pay = wa.cde(m)
    env = wq.make_wq(wa.TYP_MANDATE, pay, policy_hash_now(app, owner.uid), [owner.wsig(wa.TYP_MANDATE, pay), carol.wsig(wa.TYP_MANDATE, pay)])
    r = owner.post("/api/mandates", mandate=m, envelope_b64=wa.b64u(env))
    assert r.status_code == 409 and r.json()["error"] == "WQ_QUORUM", r.text
    # through the signature request: the access signer is not needed at all, the owner's one budget signature is not enough
    assert carol.sign_req(d["req_id"]).json()["error"] == "ROLE_NOT_NEEDED"
    assert owner.sign_req(d["req_id"]).json()["status"] == "collecting"
    # a single wa-sig of the owner on the 0.1 path is a wq of one: also WQ_QUORUM, nothing in the ledger
    r = owner.post("/api/mandates", mandate=m, envelope_b64=owner.sign(wa.TYP_MANDATE, pay))
    assert r.status_code == 409 and r.json()["error"] == "WQ_QUORUM"
    assert not [e for e in ledger_entries(app, owner.uid) if e["type"] == "MANDATE"]


def test_2b_core_registry_refuses_short_quorum_even_without_the_server(app):
    """The ledger's QuorumRegistry judges the mandate rule itself (stateless part, 2.4): the server's checks are not the only wall."""
    owner, bob, carol = team(app)
    ag, hdr, d = money_mandate(owner, bob)
    pay = wa.cde(d["mandate"])
    env = wq.make_wq(wa.TYP_MANDATE, pay, policy_hash_now(app, owner.uid), [owner.wsig(wa.TYP_MANDATE, pay)])
    L = ctx_of(app).hub.ledger(owner.uid)
    assert L.register_mandate(wire.cbor_form(d["mandate"]), cose_bytes=env) == {"result": "reject", "reason": "WQ_QUORUM"}
    one = owner.auth.sign_object(wa.TYP_MANDATE, pay, RP, ORIGIN)              # the owner's plain wa-sig: refused once a policy exists
    assert L.register_mandate(wire.cbor_form(d["mandate"]), cose_bytes=one) == {"result": "reject", "reason": "WQ_REQUIRED"}
    env2 = wq.make_wq(wa.TYP_MANDATE, pay, policy_hash_now(app, owner.uid), [owner.wsig(wa.TYP_MANDATE, pay), bob.wsig(wa.TYP_MANDATE, pay)])
    assert L.register_mandate(wire.cbor_form(d["mandate"]), cose_bytes=env2)["result"] == "accept"


def test_mixed_mandate_needs_both_roles(app):
    owner, bob, carol = team(app)
    rules = dict(TEAM_RULES, mandate=TEAM_RULES["mandate"] + [{"if": "access", "role": "access", "k": 1}])
    adopt(owner, [{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": bob.uid, "roles": ["budget"]},
                  {"user_id": carol.uid, "roles": ["access"]}], rules)
    ag, hdr = owner.new_agent("demo", "mixed")
    d = mandate_draft(owner, ag["id"], dict(MONEY_FORM, message={"domains": ["acme.example"], "to": []}))
    assert d["needs"] == [{"role": "access", "k": 1}, {"role": "budget", "k": 2}]
    assert owner.sign_req(d["req_id"]).json()["status"] == "collecting"
    assert bob.sign_req(d["req_id"]).json()["status"] == "collecting"          # budget met, access not yet
    assert carol.sign_req(d["req_id"]).json()["mandate_status"] == "active"


def deferred_purchase(owner, hdr, amount):
    r = act(owner.c, hdr, "purchase", {"vendor": "v.example", "amount_cents": amount}).json()
    assert (r["verdict"], r["reason"]) == ("defer", "ESCALATE_MONEY"), r
    return r


def approval_env(p, rid, approved=True):
    g = p.c.get("/api/approvals/" + rid).json()
    return p.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], rid, approved, viewkit.page_view(g)))


# (3) a money defer of 80000: one signature -> collecting, the second -> allow with an AAR
def test_3_money_approval_by_quorum(app):
    owner, bob, carol = team(app)
    ag, hdr, m = msg_mandate(owner)
    d = deferred_purchase(owner, hdr, 80000)
    r = owner.post("/api/approvals/" + d["rid"], **viewkit.claim(viewkit.answer(owner.c, d["rid"])), approved=True, envelope_b64=approval_env(owner, d["rid"]))
    assert r.status_code == 200 and r.json()["verdict"] == "collecting" and (r.json()["have"], r.json()["need"]) == (1, 2), r.text
    assert owner.c.get("/v1/actions/" + d["rid"], headers=hdr).json()["status"] == "pending_approval"
    assert carol.post("/api/approvals/" + d["rid"], **viewkit.claim(viewkit.answer(carol.c, d["rid"])), approved=True, envelope_b64=approval_env(carol, d["rid"])).json()["error"] == "ROLE_NOT_NEEDED"
    r = bob.post("/api/approvals/" + d["rid"], **viewkit.claim(viewkit.answer(bob.c, d["rid"])), approved=True, envelope_b64=approval_env(bob, d["rid"]))
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    res = owner.c.get("/v1/actions/" + d["rid"], headers=hdr).json()
    assert res["verdict"] == "allow" and res["reason"] == "OK_APPROVED" and res["aar_b64"] and res["proof"]["approval"]["envelope_b64"]
    apr = [e for e in ledger_entries(app, owner.uid) if e["type"] == "APPROVAL"]
    assert len(apr) == 1 and wq.envelope_kind(apr[0]["body"]["cose"]) == "wq" and len(loads(apr[0]["body"]["cose"])["sigs"]) == 2


def test_3b_small_money_and_refusal_take_one_signer(app):
    owner, bob, carol = team(app)
    ag, hdr, m = msg_mandate(owner)
    small = deferred_purchase(owner, hdr, 3000)
    r = bob.post("/api/approvals/" + small["rid"], **viewkit.claim(viewkit.answer(bob.c, small["rid"])), approved=True, envelope_b64=approval_env(bob, small["rid"]))
    assert r.json()["verdict"] == "allow", r.text
    big = deferred_purchase(owner, hdr, 90000)
    r = bob.post("/api/approvals/" + big["rid"], **viewkit.claim(viewkit.answer(bob.c, big["rid"])), approved=False, envelope_b64=approval_env(bob, big["rid"], False))
    assert r.json()["verdict"] == "refused", r.text            # stopping is easy: one budget signer refuses
    assert owner.c.get("/v1/actions/" + big["rid"], headers=hdr).json()["status"] == "refused"


def test_3c_approve_with_envelope_rejects_a_short_wq(app):
    """The common path (task 02 batch uses it) checks the approval rule of THIS action before Ledger.approve."""
    from app import actions
    owner, bob, carol = team(app)
    ag, hdr, m = msg_mandate(owner)
    d = deferred_purchase(owner, hdr, 70000)
    g = owner.c.get("/api/approvals/" + d["rid"]).json()
    pay = approval_payload(g["mandate"], g["action"], d["rid"], True)      # the core path itself (no page, no view)
    acc = ctx_of(app).db.one("SELECT * FROM accounts WHERE id=?", (owner.uid,))
    env = wq.make_wq(wa.TYP_APPROVAL, pay, policy_hash_now(app, owner.uid), [owner.wsig(wa.TYP_APPROVAL, pay)])
    with pytest.raises(Exception) as e:
        actions.approve_with_envelope(ctx_of(app), acc, d["rid"], True, env)
    assert e.value.code == "WQ_QUORUM"
    # a wb (batch of one) by a budget member is k=1 only -> WQ_QUORUM for 70000; fine for 4000
    items = [hashlib.sha256(pay).digest()]
    ad, cd, der = bob.auth.get_assertion(wq.wb_challenge(items), RP, ORIGIN)
    with pytest.raises(Exception) as e:
        actions.approve_with_envelope(ctx_of(app), acc, d["rid"], True, wq.make_wb(items, bob.auth.kid, ad, cd, der))
    assert e.value.code == "WQ_QUORUM"
    s = deferred_purchase(owner, hdr, 4000)
    g = owner.c.get("/api/approvals/" + s["rid"]).json()
    pay = approval_payload(g["mandate"], g["action"], s["rid"], True)
    items = [hashlib.sha256(pay).digest()]
    ad, cd, der = bob.auth.get_assertion(wq.wb_challenge(items), RP, ORIGIN)
    assert actions.approve_with_envelope(ctx_of(app), acc, s["rid"], True, wq.make_wb(items, bob.auth.kid, ad, cd, der)) == {"verdict": "allow"}
    assert owner.c.get("/v1/actions/" + s["rid"], headers=hdr).json()["aar_b64"]


# (4) revocation by ONE signature of the access signer -> revoked
def test_4_revocation_by_one_access_signer(app):
    owner, bob, carol = team(app)
    ag, hdr, m = msg_mandate(owner)
    g = carol.c.get("/api/mandates/%s/revoke" % m["id"]).json()
    r = carol.post("/api/mandates/%s/revoke" % m["id"], envelope_b64=carol.sign(g["typ"], wa.b64u_dec(g["payload_b64"])))
    assert r.status_code == 200 and r.json()["status"] == "revoked", r.text
    assert [x["status"] for x in owner.c.get("/api/mandates").json()] == ["revoked"]
    rv = [e for e in ledger_entries(app, owner.uid) if e["type"] == "REVOCATION"]
    assert len(rv) == 1 and wq.envelope_kind(rv[0]["body"]["cose"]) == "wq"
    assert act(owner.c, hdr, "send_email", {"to": "a@acme.example", "subject": "s", "body": "b"}).json()["verdict"] == "deny"


# (5) a member removed in v3 signs after v3 -> 409 WQ_NOT_MEMBER / WQ_POLICY_UNKNOWN
def test_5_removed_member_cannot_sign_after_v3(app):
    owner, bob, carol = team(app)
    ag, hdr, d = money_mandate(owner, bob)
    pay = wa.cde(d["mandate"])
    bob_v2 = bob.wsig(wa.TYP_MANDATE, pay)
    old_hash = policy_hash_now(app, owner.uid)
    assert bob.sign_req(d["req_id"]).json()["status"] == "collecting"      # Bob signed under v2 ...
    assert adopt(owner, [{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": carol.uid, "roles": ["access", "budget"]}],
                 TEAM_RULES) == 3                                          # ... v3 removes Bob
    assert [m["status"] for m in owner.c.get("/api/org").json()["members"] if m["user_id"] == bob.uid] == ["removed"]
    sr = owner.c.get("/api/sig-requests/" + d["req_id"]).json()
    assert sr["have"] == 0 and sr["policy_hash_b64"] == wa.b64u(policy_hash_now(app, owner.uid))   # re-based: Bob's signature dropped
    assert bob.c.get("/api/sig-requests/" + d["req_id"]).status_code == 403     # a removed member no longer reads the organisation
    r = bob.post("/api/sig-requests/" + d["req_id"], envelope_b64=bob.sign(wa.TYP_MANDATE, pay))   # ... but a signature is judged
    assert r.status_code == 409 and r.json()["error"] == "WQ_NOT_MEMBER", r.text
    # a wq built with Bob's v2 signature, naming v2, presented after v3
    env = wq.make_wq(wa.TYP_MANDATE, pay, old_hash, [owner.wsig(wa.TYP_MANDATE, pay), bob_v2])
    r = owner.post("/api/mandates", mandate=d["mandate"], envelope_b64=wa.b64u(env))
    assert r.status_code == 409 and r.json()["error"] == "WQ_POLICY_UNKNOWN", r.text
    env = wq.make_wq(wa.TYP_MANDATE, pay, policy_hash_now(app, owner.uid), [owner.wsig(wa.TYP_MANDATE, pay), bob_v2])
    r = owner.post("/api/mandates", mandate=d["mandate"], envelope_b64=wa.b64u(env))
    assert r.status_code == 409 and r.json()["error"] == "WQ_NOT_MEMBER", r.text
    # under v3 the owner + Carol (now budget) are the quorum
    assert owner.sign_req(d["req_id"]).json()["status"] == "collecting"
    assert carol.sign_req(d["req_id"]).json()["mandate_status"] == "active"


def test_policy_change_needs_rule_of_previous_version(app):
    """v3 makes policy changes need owner k=2 (two owners); v4 signed by one owner stays collecting, the second owner completes it."""
    owner, bob, carol = team(app)
    rules = dict(TEAM_RULES, policy={"role": "owner", "k": 2})
    adopt(owner, [{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": bob.uid, "roles": ["budget", "owner"]},
                  {"user_id": carol.uid, "roles": ["access"]}], rules)
    d = owner.post("/api/org/policy/draft", members=[{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": bob.uid, "roles": ["budget", "owner"]}],
                   rules=dict(rules, policy={"role": "owner", "k": 1})).json()
    assert owner.sign_req(d["req_id"]).json()["status"] == "collecting"
    assert owner.c.get("/api/org").json()["policy_ver"] == 3
    r = bob.sign_req(d["req_id"])
    assert r.json()["status"] == "done" and r.json()["policy_ver"] == 4, r.text
    assert [m["status"] for m in owner.c.get("/api/org").json()["members"] if m["user_id"] == carol.uid] == ["removed"]
    chain = ctx_of(app).hub.chain_of(owner.uid)
    assert wq.verify_policy_chain(chain, rp={"rp_id": RP, "origins": [ORIGIN]}) is None and len(chain) == 4
    assert [t for _, _, t in chain] == sorted(set(t for _, _, t in chain))         # strictly increasing effective times


def test_policy_draft_rules(app):
    owner, bob, carol = team(app)
    base = [{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": bob.uid, "roles": ["budget"]}]
    r = owner.post("/api/org/policy/draft", members=base, rules=dict(TEAM_RULES, revocation={"role": "owner", "k": 1}))
    assert r.status_code == 422                                                    # stopping must stay one signature
    r = owner.post("/api/org/policy/draft", members=[{"user_id": bob.uid, "roles": ["budget"]}, {"user_id": owner.uid, "roles": ["budget"]}], rules=TEAM_RULES)
    assert r.status_code == 422                                                    # nobody keeps the owner role
    r = owner.post("/api/org/policy/draft", members=base + [{"user_id": "f" * 32, "roles": ["access"]}], rules=TEAM_RULES)
    assert r.status_code == 422 and r.json()["error"] == "NOT_MEMBER"
    r = owner.post("/api/org/policy/draft", members=base, rules=dict(TEAM_RULES, mandate=[{"if": "money", "role": "access", "k": 1}]))
    assert r.status_code == 422 and r.json()["error"] == "POLICY_MALFORMED"        # no access holder: the rule could never be met
    r = bob.post("/api/org/policy/draft", members=base, rules=TEAM_RULES)
    assert r.status_code == 403


def test_defer_ttl_of_quorum_org(app):
    owner, bob, carol = team(app)
    ag, hdr, m = msg_mandate(owner)
    d = deferred_purchase(owner, hdr, 1000)
    assert 3590 <= d["expires"] - ctx_of(app).hub.ledger(owner.uid).now() <= 3600
    owner.stepup()
    assert owner.c.put("/api/org/settings", json={"defer_ttl_s": 900}, headers={"Origin": ORIGIN}).json()["defer_ttl_s"] == 900
    d = deferred_purchase(owner, hdr, 1001)
    assert 890 <= d["expires"] - ctx_of(app).hub.ledger(owner.uid).now() <= 900
    a = act(owner.c, hdr, "send_email", {"to": "x@acme.example", "subject": "s", "body": "b"}).json()
    assert a["verdict"] == "allow" and 890 <= a["expires"] - ctx_of(app).hub.ledger(owner.uid).now() <= 900     # an allow keeps 900 s
    assert owner.c.put("/api/org/settings", json={"defer_ttl_s": 100}, headers={"Origin": ORIGIN}).status_code == 422


def test_solo_account_unchanged_by_0_2(client, owner):
    """No policy: one wa-sig of the pinned key, the ledger keeps plain wa-sig envelopes (0.1)."""
    from tests.test_flow import setup_agent
    ag, hdr, m = setup_agent(owner)
    d = act(client, hdr, "publish", {"channel": "blog", "text": "x"}).json()
    assert owner.approve(d["rid"]).json() == {"verdict": "allow"}
    ents = ledger_entries(client.app, owner.account["id"])
    assert {wq.envelope_kind(e["body"]["cose"]) for e in ents if e["type"] in ("MANDATE", "APPROVAL")} == {"wa"}
    assert client.get("/api/org").json()["policy_ver"] == 0


# (11) pre_authorize -> deny: no ledger entry, a row in actions; hold -> held, release
@pytest.fixture()
def hooked(monkeypatch):
    from app import actions
    calls = {"pre": [], "decided": []}
    state = {"answer": None}

    def pre(ctx, agent, mandate_row, a, dv, dwhy):
        calls["pre"].append((a["class"], dv, dwhy))
        return state["answer"]

    def decided(ctx, agent, row):
        calls["decided"].append((row["rid"], row["status"]))
    monkeypatch.setattr(actions.hooks, "pre_authorize", pre)
    monkeypatch.setattr(actions.hooks, "on_decided", decided)
    return state, calls


def test_11_pre_authorize_deny_is_not_in_the_ledger(client, owner, hooked):
    from tests.test_flow import setup_agent
    state, calls = hooked
    ag, hdr, m = setup_agent(owner)
    L = ctx_of(client.app).hub.ledger(owner.account["id"])
    n0 = (L.sync_now(), L.S.nseq)[1]
    state["answer"] = ("deny", "APPROVAL_RATE")
    r = act(client, hdr, "publish", {"channel": "blog", "text": "x"}).json()
    assert (r["verdict"], r["reason"], r["status"]) == ("deny", "APPROVAL_RATE", "denied")
    L.sync_now()
    assert L.S.nseq == n0 and r["rid"] not in L.S.receipts
    row = ctx_of(client.app).db.one("SELECT * FROM actions WHERE rid=?", (r["rid"],))
    assert row["verdict"] == "deny" and row["reason"] == "APPROVAL_RATE" and row["mandate_id"] == m["id"]
    assert calls["pre"][-1] == ("publish", "defer", "ESCALATE_PUBLISH") and calls["decided"][-1] == (r["rid"], "denied")
    # a hook cannot loosen: whatever it returns for a core deny, the core's deny is recorded
    state["answer"] = ("hold", "ADVISORY_HOLD")
    r = act(client, hdr, "send_email", {"to": "x@evil.example", "subject": "s", "body": "b"}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "RECIPIENT")
    state["answer"] = ("allow", "X")
    r = act(client, hdr, "publish", {"channel": "news", "text": "y"}).json()
    assert r["verdict"] == "defer"


def test_11b_hold_and_release(client, owner, hooked):
    from tests.test_flow import setup_agent
    state, calls = hooked
    ag, hdr, m = setup_agent(owner)
    L = ctx_of(client.app).hub.ledger(owner.account["id"])
    state["answer"] = ("hold", "ADVISORY_HOLD")
    n0 = (L.sync_now(), L.S.nseq)[1]
    h = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s", "body": "street 5"}).json()
    assert (h["verdict"], h["reason"], h["status"]) == ("defer", "ADVISORY_HOLD", "held") and h["approval_url"]
    assert (L.sync_now(), L.S.nseq)[1] == n0                          # nothing in the ledger while held
    assert act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s", "body": "street 5"}).json()["rid"] == h["rid"]
    state["answer"] = None
    a = json.loads(ctx_of(client.app).db.one("SELECT action_json FROM actions WHERE rid=?", (h["rid"],))["action_json"])
    bad = owner.post("/api/approvals/%s/release" % h["rid"], release=True, **viewkit.claim(viewkit.answer(owner.c, h["rid"])),
                     envelope_b64=owner.sign(wq.TYP_RELEASE, wq.release_payload(h["rid"], a["args_sha256"], False, viewkit.page_view(viewkit.answer(owner.c, h["rid"])))))
    assert bad.status_code == 409 and bad.json()["error"] == "RELEASE_SIG"
    r = owner.post("/api/approvals/%s/release" % h["rid"], release=True, **viewkit.claim(viewkit.answer(owner.c, h["rid"])),
                   envelope_b64=owner.sign(wq.TYP_RELEASE, wq.release_payload(h["rid"], a["args_sha256"], True, viewkit.page_view(viewkit.answer(owner.c, h["rid"])))))
    assert r.status_code == 200 and (r.json()["verdict"], r.json()["status"]) == ("allow", "allowed"), r.text
    res = client.get("/v1/actions/" + h["rid"], headers=hdr).json()
    assert res["aar_b64"] and res["rid"] in L.S.receipts
    assert owner.post("/api/approvals/%s/release" % h["rid"], release=True, envelope_b64="AA").json()["error"] == "NOT_HELD"
    # reject
    state["answer"] = ("hold", "ADVISORY_HOLD")
    h2 = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s2", "body": "street 6"}).json()
    a2 = json.loads(ctx_of(client.app).db.one("SELECT action_json FROM actions WHERE rid=?", (h2["rid"],))["action_json"])
    r = owner.post("/api/approvals/%s/release" % h2["rid"], release=False, **viewkit.claim(viewkit.answer(owner.c, h2["rid"])),
                   envelope_b64=owner.sign(wq.TYP_RELEASE, wq.release_payload(h2["rid"], a2["args_sha256"], False, viewkit.page_view(viewkit.answer(owner.c, h2["rid"])))))
    assert (r.json()["verdict"], r.json()["reason"]) == ("deny", "ADVISORY_REJECTED")
    assert h2["rid"] not in (L.sync_now(), L.S.receipts)[1]
    assert (h2["rid"], "denied") in calls["decided"]


def test_release_by_access_member(app, hooked):
    """In an organisation any member of the policy in force may release (one signature, like stopping)."""
    state, calls = hooked
    owner, bob, carol = team(app)
    ag, hdr, m = msg_mandate(owner)
    state["answer"] = ("hold", "ADVISORY_HOLD")
    h = act(owner.c, hdr, "send_email", {"to": "x@acme.example", "subject": "s", "body": "b"}).json()
    assert h["status"] == "held"
    a = json.loads(ctx_of(app).db.one("SELECT action_json FROM actions WHERE rid=?", (h["rid"],))["action_json"])
    r = carol.post("/api/approvals/%s/release" % h["rid"], release=True, **viewkit.claim(viewkit.answer(carol.c, h["rid"])),
                   envelope_b64=carol.sign(wq.TYP_RELEASE, wq.release_payload(h["rid"], a["args_sha256"], True, viewkit.page_view(viewkit.answer(carol.c, h["rid"])))))
    assert r.json()["verdict"] == "allow"
