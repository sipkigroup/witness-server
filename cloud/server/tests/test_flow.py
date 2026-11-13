import json

from tests.helpers import FORM, H, Owner, act
from fastapi.testclient import TestClient
import wa_profile as wa


def setup_agent(owner, form=None, preset="demo"):
    ag, hdr = owner.new_agent(preset)
    m, r = owner.mandate(ag["id"], form)
    assert r.status_code == 200, r.text
    return ag, hdr, m


def test_stage1_deny_allow(client, owner):
    ag, hdr, m = setup_agent(owner)
    r = act(client, hdr, "send_email", {"to": "x@evil.example", "subject": "s", "body": "b"}).json()
    assert (r["verdict"], r["reason"], r["status"]) == ("deny", "RECIPIENT", "denied")
    r = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "hi", "body": "b"}).json()
    assert (r["verdict"], r["reason"]) == ("allow", "OK")
    assert r["aar_b64"] and r["proof"] is None                       # R-16: the proof comes with GET (batched)
    r = client.get("/v1/actions/" + r["rid"], headers=hdr).json()
    assert r["aar_b64"] and r["proof"]["entry_b64"] and r["proof"]["approval"] is None


def test_register_login_me_logout(client, owner):
    assert client.get("/api/me").json()["account"]["id"] == owner.account["id"]
    assert client.post("/api/auth/logout", headers=H).status_code == 204
    assert client.get("/api/me").status_code == 401
    assert owner.login().status_code == 200
    assert client.get("/api/me").json()["keycard"]["kid_hex"] == owner.keycard["kid_hex"]


def test_register_rejects_non_es256(client):
    o = Owner(client)
    j = o.post("/api/auth/register/begin", display_name="x").json()
    assert j["options"]["pubKeyCredParams"] == [{"type": "public-key", "alg": -7}]
    assert j["options"]["authenticatorSelection"]["residentKey"] == "required"
    assert j["options"]["authenticatorSelection"]["userVerification"] == "required"
    cred = o.auth.create_credential(wa.b64u_dec(j["options"]["challenge"])[::-1], "localhost", "http://localhost:8810")  # wrong challenge
    assert o.post("/api/auth/register/finish", flow_id=j["flow_id"], credential=cred).status_code == 400


def test_login_wrong_key_rejected(client, owner):
    other = wa.SoftAuthenticator(credential_id=owner.auth.credential_id)
    j = owner.post("/api/auth/login/begin").json()
    cred = other.login_credential(wa.b64u_dec(j["options"]["challenge"]), "localhost", "http://localhost:8810")
    assert owner.post("/api/auth/login/finish", flow_id=j["flow_id"], credential=cred).status_code == 401


def test_bad_origin_and_no_session(client, owner):
    r = client.post("/api/agents", json={"name": "x"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["error"] == "BAD_ORIGIN"
    assert TestClient(client.app, base_url="http://localhost:8810").get("/api/agents").status_code == 401


def test_cookie_flags(client):
    o = Owner(client)
    j = o.post("/api/auth/register/begin", display_name="x").json()
    cred = o.auth.create_credential(wa.b64u_dec(j["options"]["challenge"]), "localhost", "http://localhost:8810")
    r = o.post("/api/auth/register/finish", flow_id=j["flow_id"], credential=cred)
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "samesite=strict" in sc and "dw_session" in sc


def test_headers_csp(client):
    r = client.get("/healthz")
    assert r.headers["content-security-policy"] == "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.json()["ok"] is True


def test_agents_quota_and_disable(client, owner):
    keys = [owner.new_agent()[0] for _ in range(25)]
    assert owner.post("/api/agents", name="26th").status_code == 429
    assert client.delete("/api/agents/" + keys[0]["id"], headers=H).status_code == 204
    assert owner.post("/api/agents", name="26th").status_code == 200


def test_disabled_key_stops_working(client, owner):
    ag, hdr = owner.new_agent()
    assert act(client, hdr, "read_file", {"path": "/x"}).status_code == 200
    client.delete("/api/agents/" + ag["id"], headers=H)
    assert act(client, hdr, "read_file", {"path": "/x"}).status_code == 401


def test_bad_key(client):
    assert act(client, {"Authorization": "Bearer dwk_NOPE"}, "x", {}).status_code == 401
    assert client.post("/v1/actions", json={}).status_code == 401


def test_toolmap_put_and_invalid(client, owner):
    ag, hdr = owner.new_agent("empty")
    r = act(client, hdr, "anything", {}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "TOOL_UNMAPPED")
    tm = {"version": 1, "default": "deny", "tools": {"mail": {"class": "message", "recipient": "$.to"}}}
    assert client.put("/api/agents/%s/toolmap" % ag["id"], json={"toolmap": tm}, headers=H).status_code == 200
    bad = client.put("/api/agents/%s/toolmap" % ag["id"], json={"toolmap": {"version": 2}}, headers=H)
    assert bad.status_code == 422 and bad.json()["error"] == "TOOLMAP_INVALID"


def test_no_mandate(client, owner):
    ag, hdr = owner.new_agent()
    r = act(client, hdr, "send_email", {"to": "a@b.example"}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "NO_MANDATE")


def test_pass_with_a_receipt_under_a_signed_map(client, owner):
    """0.2.4 (draft-deus-aar-05 8.6): a mandate whose signature binds the map decides `pass` calls as class `pass`: allow OK_PASS, a RECEIPT entry, an AAR."""
    ag, hdr, _ = setup_agent(owner)
    r = act(client, hdr, "read_file", {"path": "/a"}).json()
    assert (r["verdict"], r["reason"], r["status"]) == ("allow", "OK_PASS", "allowed") and r["aar_b64"] is not None
    items = client.get("/api/feed").json()["items"]
    assert items[0]["status"] == "allowed" and items[0]["class"] == "pass"


def test_pass_not_in_ledger_for_a_legacy_mandate(client, owner, app):
    """A mandate RECORDED before 0.2.4 (no toolmap_sha256 inside the signature) keeps the old rule: `pass` is answered without a receipt. A NEW one without the member is refused (R4-04)."""
    ag, hdr = owner.new_agent()
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=FORM).json()
    m = {k: v for k, v in d["mandate"].items() if k != "toolmap_sha256"}
    r = owner.post("/api/mandates", mandate=m, envelope_b64=owner.sign(wa.TYP_MANDATE, wa.cde(m)), toolmap_sha256=d["toolmap_sha256"])
    assert r.status_code == 409 and r.json()["error"] == "MANDATE_OLD_FORM", r.text
    r = owner.post("/api/mandates", mandate=d["mandate"], envelope_b64=owner.sign(wa.TYP_MANDATE, wa.cde(d["mandate"])))
    assert r.status_code == 200, r.text
    db = app.state.ctx.db                       # make the recorded row a legacy one: the member is not in its mandate_json, no document
    db.x("UPDATE mandates SET mandate_json=?, gateway_doc=NULL WHERE id=?", (json.dumps(m), m["id"]))
    r = act(client, hdr, "read_file", {"path": "/a"}).json()
    assert r["verdict"] == "pass" and r["status"] == "pass" and r["aar_b64"] is None
    items = client.get("/api/feed").json()["items"]
    assert items[0]["status"] == "pass"


def test_dlp_and_secret_masking(client, owner):
    ag, hdr, _ = setup_agent(owner)
    assert client.put("/api/data-patterns", json={"patterns": {"home_address": ["14 Maple Court"]}}, headers=H).status_code == 200
    r = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "x", "body": "I live at 14 maple court"}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "DATA_FORBIDDEN")
    sec = "sk-" + "a" * 30
    r = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "k", "body": "key " + sec}).json()
    f = client.get("/api/feed").json()["items"]
    assert all(sec not in x["args_preview"] and "14 maple" not in x["args_preview"].lower() for x in f)
    assert all(len(x["args_preview"]) <= 300 for x in f)


def test_purchase_budget_and_feed_budget(client, owner):
    ag, hdr, _ = setup_agent(owner)
    for _ in range(2):
        r = act(client, hdr, "purchase", {"vendor": "v.example", "amount_cents": 10000}).json()
        assert r["reason"] == "OK", r
    r = act(client, hdr, "purchase", {"vendor": "v.example", "amount_cents": 1}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "BUDGET")
    b = client.get("/api/budget").json()
    assert b[0]["committed"] == 20000 and b[0]["budget"] == 20000
    r = act(client, hdr, "purchase", {"vendor": "v.example", "amount_cents": 1.5}).json()
    assert r["reason"] == "BAD_AMOUNT"
    feed = client.get("/api/feed?limit=2").json()
    assert len(feed["items"]) == 2 and feed["next_before"] is not None


def test_defer_approve_repeat_present_replay(client, owner):
    ag, hdr, _ = setup_agent(owner)
    args = {"channel": "blog", "text": "release notes"}
    r = act(client, hdr, "publish", args).json()
    assert (r["verdict"], r["reason"], r["status"]) == ("defer", "ESCALATE_PUBLISH", "pending_approval")
    rid = r["rid"]
    assert r["approval_url"].endswith("approve.html?rid=" + rid)
    again = act(client, hdr, "publish", args).json()
    assert again["rid"] == rid                                     # repeat while pending: same action
    assert [a["rid"] for a in client.get("/api/approvals").json()] == [rid]
    a = owner.approve(rid)
    assert a.status_code == 200 and a.json()["verdict"] == "allow"
    again = act(client, hdr, "publish", args).json()
    assert again["rid"] == rid and again["verdict"] == "allow" and again["reason"] == "OK_APPROVED"
    assert again["proof"]["approval"]["approved"] is True and again["proof"]["approval"]["entry_b64"] and again["aar_b64"]
    g = client.get("/v1/actions/%s?wait=0" % rid, headers=hdr).json()
    assert g["status"] == "approved"
    p = client.post("/v1/actions/%s/present" % rid, json={}, headers=hdr).json()
    assert p == {"result": "accept", "reason": "OK"}
    p = client.post("/v1/actions/%s/present" % rid, json={}, headers=hdr).json()
    assert p["result"] == "reject" and p["reason"] == "REPLAY"
    rp = client.post("/v1/actions/%s/report" % rid, json={"executed": True}, headers=hdr).json()
    assert rp["result"] == "ignored"
    assert client.get("/v1/actions/%s" % rid, headers=hdr).json()["status"] == "executed"
    # replay of the approval envelope
    assert owner.approve(rid).status_code == 409


def test_approval_binds_to_exact_request(client, owner):
    """Approve email A -> the same recipient with a different body must be a NEW deferral, not allow."""
    form = dict(FORM, message=None, delete=None)
    ag, hdr, _ = setup_agent(owner, form={"currency": "USD", "valid_days": 30, "message": {"to": ["bob@partner.example"], "domains": []}})
    # make `message` need approval: use publish (deferred) with two different texts to the same channel
    a = act(client, hdr, "publish", {"channel": "blog", "text": "A text"}).json()
    assert a["verdict"] == "defer"
    assert owner.approve(a["rid"]).status_code == 200
    b = act(client, hdr, "publish", {"channel": "blog", "text": "B text, different"}).json()
    assert b["verdict"] == "defer" and b["rid"] != a["rid"] and b["status"] == "pending_approval"
    assert a["action"]["args_sha256"] != b["action"]["args_sha256"]
    # and the present of B with A's rid is refused by the ledger binding
    pa = client.post("/v1/actions/%s/present" % a["rid"], json={}, headers=hdr).json()
    assert pa["result"] == "accept"


def test_refused_approval(client, owner):
    ag, hdr, _ = setup_agent(owner)
    r = act(client, hdr, "publish", {"channel": "b", "text": "t"}).json()
    a = owner.approve(r["rid"], approved=False)
    assert a.json()["verdict"] == "refused"
    g = client.get("/v1/actions/" + r["rid"], headers=hdr).json()
    assert g["status"] == "refused" and g["verdict"] == "deny"
    p = client.post("/v1/actions/%s/present" % r["rid"], json={}, headers=hdr).json()
    assert p["result"] == "reject"


def test_present_deferred_rejected(client, owner):
    ag, hdr, _ = setup_agent(owner)
    r = act(client, hdr, "publish", {"channel": "b", "text": "t"}).json()
    p = client.post("/v1/actions/%s/present" % r["rid"], json={}, headers=hdr).json()
    assert p["result"] == "reject" and p["reason"] == "NOT_ALLOWED"


def test_report_not_executed_releases(client, owner):
    ag, hdr, _ = setup_agent(owner)
    r = act(client, hdr, "purchase", {"vendor": "v.example", "amount_cents": 5000}).json()
    rp = client.post("/v1/actions/%s/report" % r["rid"], json={"executed": False}, headers=hdr).json()
    assert rp["result"] == "released"
    assert client.get("/api/budget").json()[0]["committed"] == 0


def test_long_poll_returns_after_approval(client, owner):
    import threading, time
    ag, hdr, _ = setup_agent(owner)
    r = act(client, hdr, "publish", {"channel": "b", "text": "t"}).json()
    t0 = time.time()
    g = client.get("/v1/actions/%s?wait=1" % r["rid"], headers=hdr).json()
    assert g["status"] == "pending_approval" and time.time() - t0 >= 0.9


def test_mandate_tampered_payload(client, owner):
    ag, hdr = owner.new_agent()
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=FORM).json()["mandate"]
    env = owner.sign(wa.TYP_MANDATE, wa.cde(d))
    d2 = dict(d, forbidden_data=[])
    r = owner.post("/api/mandates", mandate=d2, envelope_b64=env)
    assert r.status_code == 409 and r.json()["error"] in ("MANDATE_SIG", "KEY_MISMATCH")


def test_mandate_foreign_key(client, owner):
    ag, hdr = owner.new_agent()
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=FORM).json()["mandate"]
    other = wa.SoftAuthenticator()
    env = wa.b64u(other.sign_object(wa.TYP_MANDATE, wa.cde(d), "localhost", "http://localhost:8810"))
    r = owner.post("/api/mandates", mandate=d, envelope_b64=env)
    assert r.status_code == 409 and r.json()["error"] == "KEY_MISMATCH"
    r = owner.post("/api/mandates", mandate=d, envelope_b64="AAAA")
    assert r.json()["error"] == "WA_MALFORMED"


def test_mandate_exists_and_superseded(client, owner):
    ag, hdr = owner.new_agent()
    m, r = owner.mandate(ag["id"])
    assert r.json()["status"] == "active"
    env = owner.sign(wa.TYP_MANDATE, wa.cde(m))
    assert owner.post("/api/mandates", mandate=m, envelope_b64=env).json()["error"] == "MANDATE_EXISTS"
    m2, r2 = owner.mandate(ag["id"], dict(FORM, valid_days=10))
    st = {x["id"]: x["status"] for x in client.get("/api/mandates").json()}
    assert st[m["id"]] == "superseded" and st[m2["id"]] == "active"


def test_mandate_draft_matches_contract_forms(client, owner):
    import forms, time
    ag, _ = owner.new_agent()
    m = owner.post("/api/mandates/draft", agent_id=ag["id"], form=FORM).json()["mandate"]
    ref = forms.mandate_from_form(FORM, owner.account["principal"], ag["id"], m["pin_source"], now=m["nbf"], mid=m["id"])
    assert m.pop("toolmap_sha256") and wa.cde(m) == wa.cde(ref)       # 0.2.4: the draft adds the signed map hash to the contract form
    assert m["key_attestation"] == "passkey" and m["pin_source"].startswith("webauthn-registration:localhost:")


def test_form_invalid(client, owner):
    ag, _ = owner.new_agent()
    r = owner.post("/api/mandates/draft", agent_id=ag["id"], form={"purchase": {"enabled": True, "budget": -1, "max_per_action": 1}})
    assert r.status_code == 422 and r.json()["error"] == "FORM_INVALID"


def test_approval_wrong_signature_codes(client, owner):
    ag, hdr, _ = setup_agent(owner)
    r = act(client, hdr, "publish", {"channel": "b", "text": "t"}).json()
    g = client.get("/api/approvals/" + r["rid"]).json()
    from svidetel_v4.state import approval_payload
    pay = approval_payload(g["mandate"], g["action"], r["rid"], True)
    other = wa.SoftAuthenticator()
    env = wa.b64u(other.sign_object(wa.TYP_APPROVAL, pay, "localhost", "http://localhost:8810"))
    assert owner.post("/api/approvals/" + r["rid"], approved=True, envelope_b64=env).json()["error"] == "KEY_MISMATCH"
    wrong = owner.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], r["rid"], False))     # signed "refuse", sent as approve
    assert owner.post("/api/approvals/" + r["rid"], approved=True, envelope_b64=wrong).json()["error"] == "APPROVAL_SIG"
    assert owner.post("/api/approvals/" + r["rid"], approved=True, envelope_b64="AAAA").json()["error"] == "WA_MALFORMED"
    ok = owner.approve(r["rid"])
    assert ok.status_code == 200


def test_rate_limit(client, owner):
    from app.api_agent import RATE as R
    ag, hdr = owner.new_agent()
    codes = [act(client, hdr, "read_file", {"p": i}).status_code for i in range(R + 2)]
    assert codes.count(200) == R and codes[-1] == 429
    assert act(client, hdr, "read_file", {}).json()["error"] == "RATE_LIMIT"


def test_quota_actions(client, owner, monkeypatch):
    import app.actions as A
    monkeypatch.setattr(A, "QUOTA_PER_DAY", 3)
    ag, hdr = owner.new_agent()
    for _ in range(5):
        assert act(client, hdr, "read_file", {}).status_code == 200      # 0.2.45: reads do not spend the quota
    for _ in range(3):
        assert act(client, hdr, "publish", {}).status_code == 200
    r = act(client, hdr, "publish", {})
    assert r.status_code == 429 and r.json()["error"] == "QUOTA"


def test_witness_public(client, app):
    j = client.get("/v1/witness").json()
    assert j == client.get("/api/witness").json()
    assert j["alg"] == "EdDSA" and len(j["pub_hex"]) == 64 and j["iss"] == "https://witness.test"


def test_witness_js_hashes(cfg):
    import os, hashlib
    from app.main import create_app
    w = cfg.web_dir
    os.makedirs(w + "/js"); os.makedirs(w + "/css")
    open(w + "/js/a.js", "w").write("x"); open(w + "/css/app.css", "w").write("y"); open(w + "/index.html", "w").write("<p>")
    c = TestClient(create_app(cfg), base_url="http://localhost:8810")
    h = c.get("/v1/witness").json()["web_js_sha256"]
    assert set(h) == {"js/a.js", "css/app.css", "index.html"} and h["js/a.js"] == hashlib.sha256(b"x").hexdigest()
    assert c.get("/").text == "<p>" and c.get("/../../etc/passwd").status_code in (404,)


def test_startup_refuses_without_key(cfg):
    import os
    from app.hub import KeyFileError
    import pytest
    from app.main import create_app
    os.remove(cfg.witness_key_file)
    with pytest.raises(KeyFileError):
        create_app(cfg)
