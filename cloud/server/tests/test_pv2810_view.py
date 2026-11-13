"""pv2810: the passkey signature names what the approval page showed (presentation hash). Real server (TestClient), real ledger.
The page builds the signing view from GET /api/approvals/{rid} and signs SHA-256(JCS(view)) inside the approval / release payload;
the server rebuilds the view from its own rows and refuses another hash (VIEW_CHANGED); an older page (no view) is accepted as before
and its approval is marked "view not signed"; the evidence pack shows the hash per approval and per release."""
import json
import subprocess

import cbor2
import pytest

from app import signview
from svidetel_v4 import cose
from svidetel_v4.state import approval_payload
import wa_profile as wa
import wq_profile as wq
from tests.test_0224_critique import Agent, row


def _get(owner, rid):
    g = owner.c.get("/api/approvals/" + rid)
    assert g.status_code == 200, g.text
    return g.json()


def _approve(owner, rid, approved=True, sign_view="page", send_view="page", g=None):
    """sign_view / send_view: 'page' (the hash the page computes from the answer), None (an older page), or 32 bytes."""
    g = g or _get(owner, rid)
    page = signview.view_hash({k: v for k, v in g.items() if k not in ("view_sha256", "view_signed", "view_signed_sha256")})
    sv = page if sign_view == "page" else sign_view
    nv = page if send_view == "page" else send_view
    pay = approval_payload(g["mandate"], g["action"], rid, approved, sv)
    body = {"approved": approved, "envelope_b64": owner.sign(wa.TYP_APPROVAL, pay)}
    if nv is not None:
        body["view_sha256"] = nv.hex() if isinstance(nv, bytes) else nv
    return owner.post("/api/approvals/" + rid, **body), page


def _pending(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    [(t, v, reason, rid)] = a.tool("Read", {"file_path": a.proj + "/.env"})   # 06.11 (Н1): a private key is refused outright; the project .env stays a question
    assert v == "defer"
    return a, rid


def _approval_entries(app, account_id):
    L = app.state.ctx.hub.ledger(account_id)
    out = []
    for raw in L.raws:
        e = cose.loads(cose.verify1(raw, [L.wk], cose.TYP_ENTRY)[0])
        if e["type"] == "APPROVAL":
            out.append(e["body"])
    return out


def test_pv2810_server_offers_the_hash_the_page_computes(client, owner, tmp_path):
    a, rid = _pending(client, owner, tmp_path)
    g = _get(owner, rid)
    assert g["view_sha256"] == signview.view_hash({k: v for k, v in g.items() if k != "view_sha256"}).hex()
    v = signview.view_of(g)
    assert set(v) - {"v"} <= set(signview.KEYS) and "mandate" not in v and "expires" not in v and v["action"] == g["action"]
    assert ".env" in v["args_preview"]                                       # the preview the person reads is inside the hash
    assert _get(owner, rid)["view_sha256"] == g["view_sha256"]                 # stable while nothing changes


def test_pv2810_view_signed_and_recorded(client, owner, tmp_path):
    a, rid = _pending(client, owner, tmp_path)
    r, page = _approve(owner, rid)
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    g = _get(owner, rid)
    assert g["view_signed"] is True and g["view_signed_sha256"] == page.hex()
    body = [b for b in _approval_entries(client.app, owner.account["id"]) if b["receipt"] == rid][0]
    assert body["view"] == page                                               # the APPROVAL entry of the ledger carries the hash
    env = cbor2.loads(body["cose"])
    assert cbor2.loads(env["payload"])["view"] == page                        # ... and the passkey signed it
    assert client.post("/v1/actions/%s/present" % rid, json={}, headers=a.hdr).json()["result"] == "accept"


def test_pv2810_refusal_names_the_view_too(client, owner, tmp_path):
    a, rid = _pending(client, owner, tmp_path)
    r, page = _approve(owner, rid, approved=False)
    assert r.status_code == 200 and r.json()["verdict"] == "refused", r.text
    body = [b for b in _approval_entries(client.app, owner.account["id"]) if b["receipt"] == rid][0]
    assert body["approved"] is False and body["view"] == page


def test_pv2810_changed_view_is_refused(client, owner, tmp_path):
    a, rid = _pending(client, owner, tmp_path)
    g = _get(owner, rid)
    client.app.state.ctx.db.x("UPDATE actions SET args_preview=args_preview || ' (changed)' WHERE rid=?", (rid,))   # shown != held now
    r, _ = _approve(owner, rid, g=g)
    assert r.status_code == 409 and r.json()["error"] == "VIEW_CHANGED", r.text
    assert row(client, rid)["status"] == "pending_approval"                    # nothing decided
    assert _approval_entries(client.app, owner.account["id"]) == [b for b in _approval_entries(client.app, owner.account["id"]) if b["receipt"] != rid]
    r, _ = _approve(owner, rid)                                               # reloaded page: the new view is signed
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text


def test_pv2810_a_view_claimed_but_not_signed_is_refused(client, owner, tmp_path):
    a, rid = _pending(client, owner, tmp_path)
    r, _ = _approve(owner, rid, sign_view=None)                               # claims the view, the passkey signed the 0.1 payload
    assert r.status_code == 409 and r.json()["error"] == "APPROVAL_SIG", r.text
    r, _ = _approve(owner, rid, sign_view=b"\x01" * 32, send_view=b"\x01" * 32)    # signs and claims a view the server never showed
    assert r.status_code == 409 and r.json()["error"] == "VIEW_CHANGED", r.text
    r, _ = _approve(owner, rid, send_view=None)                               # signed a view but does not say so: no silent downgrade
    assert r.status_code == 409 and r.json()["error"] == "APPROVAL_SIG", r.text
    assert row(client, rid)["status"] == "pending_approval"


@pytest.mark.parametrize("bad", ["AB" * 32, "ab" * 31, 5, "zz" * 32])
def test_pv2810_malformed_view_is_a_bad_request(client, owner, tmp_path, bad):
    a, rid = _pending(client, owner, tmp_path)
    r, _ = _approve(owner, rid, sign_view=None, send_view=bad)
    assert r.status_code == 400, r.text


def test_pv2810_older_page_is_accepted_and_marked(client, owner, tmp_path):
    a, rid = _pending(client, owner, tmp_path)
    assert owner.approve(rid).json()["verdict"] == "allow"                     # the 0.1 page: no view in the payload or the request
    g = _get(owner, rid)
    assert g["view_signed"] is False and "view_signed_sha256" not in g
    body = [b for b in _approval_entries(client.app, owner.account["id"]) if b["receipt"] == rid][0]
    assert "view" not in body


def _held(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path)
    a.see_secret()
    a.tool("Write", {"file_path": a.proj + "/tests/test_new.py", "content": "def test_n():\n    pass\n"})
    v, parts = a.line("pytest -q ")
    rid = [p[3] for p in parts if p[2] == "ESCALATE_SECRET_SEEN"][0]
    assert row(client, rid)["status"] == "held"
    return a, rid


def _release(owner, rid, rel=True, view="page"):
    g = _get(owner, rid)
    assert g["status"] == "held" and isinstance(g.get("view_sha256"), str)
    page = signview.view_hash({k: v for k, v in g.items() if k != "view_sha256"})
    vh = page if view == "page" else view
    pay = wq.release_payload(rid, g["action"]["args_sha256"], rel, vh)
    body = {"release": rel, "envelope_b64": owner.sign(wq.TYP_RELEASE, pay)}
    if vh is not None:
        body["view_sha256"] = vh.hex()
    return owner.post("/api/approvals/%s/release" % rid, **body), page


def test_pv2810_release_names_the_view(client, owner, tmp_path):
    a, rid = _held(client, owner, tmp_path)
    r, page = _release(owner, rid)
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    m = client.app.state.ctx.db.one("SELECT meta, payload FROM sig_requests WHERE kind='release' AND ref=?", (rid,))
    assert json.loads(m["meta"])["view"] == page.hex() and cbor2.loads(bytes(m["payload"]))["view"] == page


def test_pv2810_release_with_a_changed_view_is_refused(client, owner, tmp_path):
    a, rid = _held(client, owner, tmp_path)
    g = _get(owner, rid)
    old = signview.view_hash({k: v for k, v in g.items() if k != "view_sha256"})
    client.app.state.ctx.db.x("UPDATE actions SET text_preview='other' WHERE rid=?", (rid,))
    pay = wq.release_payload(rid, g["action"]["args_sha256"], True, old)
    r = owner.post("/api/approvals/%s/release" % rid, release=True, envelope_b64=owner.sign(wq.TYP_RELEASE, pay), view_sha256=old.hex())
    assert r.status_code == 409 and r.json()["error"] == "VIEW_CHANGED", r.text
    assert row(client, rid)["status"] == "held"


def test_pv2810_release_from_an_older_page_still_works(client, owner, tmp_path):
    a, rid = _held(client, owner, tmp_path)
    r, _ = _release(owner, rid, view=None)
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text


def test_pv2810_pack_shows_view_hashes_offline(app, tmp_path):
    from tests.recovery_helpers import Person, export_to, run_verify
    p = Person(app).register("Pat")
    a = Agent(p.c, p, tmp_path)
    rid_old = a.see_secret()                                                   # 0.1 page: not signed
    [(t, v, reason, rid_new)] = a.tool("Read", {"file_path": a.proj + "/.env.local"})   # 06.11: another credential file than see_secret()
    r, page = _approve(p, rid_new)
    assert r.status_code == 200, r.text
    a.tool("Write", {"file_path": a.proj + "/tests/test_new.py", "content": "def test_n():\n    pass\n"})
    v, parts = a.line("pytest -q ")
    rid_h = [x[3] for x in parts if x[2] == "ESCALATE_SECRET_SEEN"][0]
    r, rpage = _release(p, rid_h)
    assert r.status_code == 200, r.text
    folder = export_to(p.c, tmp_path / "pack")
    rc, out = run_verify(folder, "--offline")
    assert rc == 0 and "RESULT: VALID" in out, out
    assert "approval %s (approved): view sha256 %s" % (rid_new, page.hex()) in out, out
    assert "approval %s (approved): view not signed" % rid_old in out, out
    assert "approval views: 1 signed, 1 not signed" in out, out
    assert "advisory %s: released, view sha256 %s" % (rid_h, rpage.hex()) in out, out
    # a release file that names another view than the one signed does not verify (besides the manifest mismatch)
    import os
    import shutil
    bad = str(tmp_path / "bad")
    shutil.copytree(folder, bad)
    fp = os.path.join(bad, "advisory", rid_h + ".json")
    j = json.load(open(fp))
    j["view_sha256"] = "00" * 32
    json.dump(j, open(fp, "w"))
    rc, outb = run_verify(bad, "--offline")
    assert rc != 0 and "advisory %s: MANDATE_SIG" % rid_h in outb and "RESULT: INVALID" in outb, outb
    # the client's checker (mcp/deus_witness/verify_pack) says the same
    mcp = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "mcp")
    py = os.path.join(mcp, ".venv", "bin", "python")
    if not os.path.exists(py):
        pytest.skip("no mcp/.venv: the client's checker is tested in mcp/tests")
    q = subprocess.run([py, "-m", "deus_witness.verify_pack", folder, "--offline"], capture_output=True, text=True, timeout=120, cwd=mcp)
    out2 = q.stdout + q.stderr
    assert q.returncode == 0 and "RESULT: VALID" in out2, out2
    assert "approval %s (approved): view sha256 %s" % (rid_new, page.hex()) in out2 and "approval views: 1 signed, 1 not signed" in out2, out2
    assert "advisory %s: released, view sha256 %s" % (rid_h, rpage.hex()) in out2, out2


def test_pv2810_pack_with_a_tampered_view_is_invalid(app, tmp_path):
    """The view hash is inside the passkey signature: a pack whose APPROVAL body names another view does not verify."""
    from tests.recovery_helpers import Person
    p = Person(app).register("Pat")
    a = Agent(p.c, p, tmp_path)
    [(t, v, reason, rid)] = a.tool("Read", {"file_path": a.proj + "/.env"})   # 06.11 (Н1): a private key is refused outright; the project .env stays a question
    r, page = _approve(p, rid)
    assert r.status_code == 200, r.text
    L = app.state.ctx.hub.ledger(p.account["id"])
    from svidetel_v4.state import approval_payload as ap
    body = [b for b in _approval_entries(app, p.account["id"]) if b["receipt"] == rid][0]
    rc_ = L.S.receipts[rid]
    good = ap(L.S.mandates[rc_["mandate"]], rc_["action"], rid, True, body["view"])
    bad = ap(L.S.mandates[rc_["mandate"]], rc_["action"], rid, True, b"\x00" * 32)
    env = cbor2.loads(body["cose"])
    assert env["payload"] == good and env["payload"] != bad
    entry = p.c.app.state.ctx.hub.active_keys(p.account["id"])[env["kid"]]
    assert wa.verify_envelope(body["cose"], wa.TYP_APPROVAL, good, entry) is None
    assert wa.verify_envelope(body["cose"], wa.TYP_APPROVAL, bad, entry) is not None


def test_pv2810_schema_refuses_a_malformed_view():
    from svidetel_v4.schema import validate_body
    assert validate_body("APPROVAL", {"receipt": "r", "approved": True}) is None
    assert validate_body("APPROVAL", {"receipt": "r", "approved": True, "view": b"\x00" * 32}) is None
    assert validate_body("APPROVAL", {"receipt": "r", "approved": True, "view": b"\x00" * 31}) == "view"
    assert validate_body("APPROVAL", {"receipt": "r", "approved": True, "view": "00" * 32}) == "view"
    with pytest.raises(TypeError):
        approval_payload({"id": "m"}, {"class": "x"}, "r", True, b"short")
    with pytest.raises(ValueError):
        wq.release_payload("r", b"\x00" * 32, True, b"short")


def test_pv2810_jcs_is_rfc8785_on_the_tricky_parts():
    assert signview.jcs({"￿": 2, "\U0001F600": 1, "a": [1, 1.5, -0.0, None, True]}) == \
        '{"a":[1,1.5,0,null,true],"\U0001F600":1,"￿":2}'.encode()      # UTF-16 order puts the surrogate pair first
    assert signview.jcs(" \x07\n\"\\") == b'"\xe2\x80\xa8\\u0007\\n\\"\\\\"'
    assert signview.jcs(1e21) == b"1e+21" and signview.jcs(1e-7) == b"1e-7" and signview.jcs(0.1) == b"0.1"
    with pytest.raises(ValueError):
        signview.jcs(float("nan"))
    with pytest.raises(ValueError):
        signview.jcs(2 ** 60)


def test_pv2810_vectors_of_the_page_are_current():
    """web/test/vectors_view_pv2810.json (read by web/test/signview.test.mjs) is what this server computes now."""
    import os
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "web", "test", "vectors_view_pv2810.json")
    V = json.load(open(p, encoding="utf-8"))
    assert signview.jcs(signview.view_of(V["answer"])).decode() == V["jcs"]
    h = signview.view_hash(V["answer"])
    assert h.hex() == V["view_sha256"]
    assert approval_payload(V["mandate"], V["action"], V["rid"], True, h).hex() == V["approval_payload_hex"]
    assert wq.release_payload(V["rid"], "ab" * 32, True, h).hex() == V["release_payload_hex"]
    # 29.10 MDEP: masked_dep is a member of the view when the answer has it; without it the view is the one before (an older row)
    M = V["mdep"]
    assert "masked_dep" not in V["answer"] and "masked_dep" in signview.KEYS
    assert signview.jcs(signview.view_of(M["answer"])).decode() == M["jcs"] and '"masked_dep":["AUTH_URL","passthrough_cmd"]' in M["jcs"]
    assert signview.view_hash(M["answer"]).hex() == M["view_sha256"] != M["view_sha256_without"]
    assert signview.view_hash({k: v for k, v in M["answer"].items() if k != "masked_dep"}).hex() == M["view_sha256_without"]
    assert signview.view_hash(dict(M["answer"], masked_dep=None)).hex() == M["view_sha256_without"]


# held 28.10: a held row whose id the ledger already judged (a crash between L.authorize and the row update of an earlier release; a row
# set to held by hand) -- the release was a 500 (DUPLICATE_RECEIPT_ID) after the release request had been stored as done
def _no_release_written(client, rid):
    return client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM sig_requests WHERE kind='release' AND ref=?", (rid,))["n"] == 0


def test_held_release_of_a_judged_id_is_409_and_writes_nothing(client, owner, tmp_path):
    a, rid = _pending(client, owner, tmp_path)               # judged by the core: DEFER receipt in the ledger
    client.app.state.ctx.db.x("UPDATE actions SET status='held', reason='ADVISORY_HOLD' WHERE rid=?", (rid,))
    r, _ = _release(owner, rid)
    assert r.status_code == 409 and r.json()["error"] == "HELD_ALREADY_JUDGED", r.text
    assert row(client, rid)["status"] == "held" and _no_release_written(client, rid)
    r2, _ = _release(owner, rid, rel=False)                 # the owner can still clear it: reject only denies the row
    assert r2.status_code == 200 and r2.json()["reason"] == "ADVISORY_REJECTED", r2.text
    assert row(client, rid)["status"] == "denied"


def test_held_release_after_a_crash_between_ledger_and_row_is_409(client, owner, tmp_path):
    a, rid = _held(client, owner, tmp_path)
    x = row(client, rid)
    L = client.app.state.ctx.hub.ledger(owner.account["id"])
    from app import wire
    L.authorize(rid, x["mandate_id"], wire.cbor_form(json.loads(x["action_json"])), ttl=300, audience="tool")   # the earlier release's entry; the row update never ran
    r, _ = _release(owner, rid)
    assert r.status_code == 409 and r.json()["error"] == "HELD_ALREADY_JUDGED", r.text
    assert row(client, rid)["status"] == "held" and _no_release_written(client, rid)
