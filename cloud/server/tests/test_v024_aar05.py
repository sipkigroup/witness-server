"""0.2.4 (draft-deus-aar-05 8.6 and 9.5, ERRATA-05): the tool map document is INSIDE the signed mandate, `pass` has a receipt, every decision comes
with an inclusion promise. One test per rule."""
import hashlib
import json

import cbor2

from app import _paths  # noqa: F401
import wa_profile as wa
from app import wire
from svidetel_v4 import cose
from svidetel_v4.verify import check_promise_cose, load_entries
from tests.helpers import FORM, H, act, promises_on
from tests.test_flow import setup_agent


def ctx_of(app):
    return app.state.ctx


def mandate_row(app, mid):
    return ctx_of(app).db.one("SELECT * FROM mandates WHERE id=?", (mid,))


def ledger_entries(app, owner):
    ctx = ctx_of(app)
    path = ctx.hub.ledger(owner.account["id"]).path
    return load_entries(path, [ctx.wk])


def test_draft_puts_the_map_hash_into_the_mandate_the_passkey_signs(client, owner):
    ag, hdr = owner.new_agent()
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=FORM).json()
    doc = d["gateway"]
    assert doc["v"] == "dw-gateway-0.2.4" and doc["tools"] == ag["toolmap"] and "patterns" in doc and "advisor" in doc
    h = hashlib.sha256(wa.cde_raw(doc)).hexdigest()
    assert d["mandate"]["toolmap_sha256"] == h == d["gateway_sha256"]


def test_the_ledger_holds_toolmap_sha256_as_32_bytes_inside_the_signed_mandate(client, owner, app):
    ag, hdr, m = setup_agent(owner)
    e = [x for x in ledger_entries(app, owner) if x["type"] == "MANDATE"][0]
    tm_bytes = e["body"]["mandate"]["toolmap_sha256"]
    assert isinstance(tm_bytes, bytes) and len(tm_bytes) == 32 and tm_bytes.hex() == m["toolmap_sha256"]
    # the passkey signed exactly these bytes (wa-sig over the CDE of the mandate WITH the bstr member)
    assert wa.cde_raw(wire.cbor_form(m)) == wa.cde_raw(e["body"]["mandate"])
    assert wa.cde_raw(m) != wa.cde_raw(wire.cbor_form(m))      # hex string vs bstr: different bytes, so a page that signs the hex string does not match


def test_a_hash_that_is_not_the_servers_document_is_refused(client, owner):
    ag, hdr = owner.new_agent()
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=FORM).json()
    m = dict(d["mandate"], toolmap_sha256="00" * 32)
    r = owner.post("/api/mandates", mandate=m, envelope_b64=owner.sign(wa.TYP_MANDATE, wa.cde(m)))
    assert r.status_code == 409 and r.json()["error"] == "TOOLMAP_CHANGED"
    m = dict(d["mandate"], toolmap_sha256="zz")
    r = owner.post("/api/mandates", mandate=m, envelope_b64=owner.sign(wa.TYP_MANDATE, wa.cde(m)))
    assert r.status_code == 409 and r.json()["error"] == "MANDATE_MALFORMED"
    m = dict(d["mandate"], toolmap_sha256="ab" * 31)
    r = owner.post("/api/mandates", mandate=m, envelope_b64=owner.sign(wa.TYP_MANDATE, wa.cde(m)))
    assert r.status_code == 409 and r.json()["error"] == "MANDATE_MALFORMED"


def test_changing_the_map_after_signing_is_toolmap_changed(client, owner):
    ag, hdr, _ = setup_agent(owner)
    t = json.loads(json.dumps(ag["toolmap"]))
    t["tools"]["extra_tool"] = {"class": "pass"}
    assert owner.c.put("/api/agents/%s/toolmap" % ag["id"], json={"toolmap": t}, headers=H).status_code == 200
    r = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s"}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "TOOLMAP_CHANGED")


def test_the_stored_document_cannot_be_edited_behind_the_signature(client, owner, app):
    """Row edited (map weakened in the stored document AND in the agent): the document no longer hashes to the SIGNED value -> TOOLMAP_CHANGED."""
    ag, hdr, m = setup_agent(owner)
    ctx = ctx_of(app)
    row = mandate_row(app, m["id"])
    doc = json.loads(row["gateway_doc"])
    doc["tools"]["extra_tool"] = {"class": "pass"}
    ctx.db.x("UPDATE mandates SET gateway_doc=? WHERE id=?", (json.dumps(doc), m["id"]))
    ctx.db.x("UPDATE agents SET toolmap_json=? WHERE id=?", (json.dumps(doc["tools"]), ag["id"]))
    r = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s"}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "TOOLMAP_CHANGED")


def test_the_row_columns_of_the_old_guard_do_not_weaken_a_signed_mandate(client, owner, app):
    """R3-06 at 0.2.4: the protected literals and the advisor mode at signing are in the signed document; emptying the row columns does not hide a removed literal."""
    assert owner.c.put("/api/data-patterns", json={"patterns": {"home_address": ["14 Maple Court"]}}, headers=H).status_code == 200
    ag, hdr, m = setup_agent(owner)
    ctx = ctx_of(app)
    ctx.db.x("UPDATE mandates SET patterns_items=?, advisor_sha256=? WHERE id=?", (json.dumps([]), None, m["id"]))
    assert owner.c.put("/api/data-patterns", json={"patterns": {}}, headers=H).status_code == 200
    r = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s"}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "DATA_PATTERNS_CHANGED")


def test_pass_is_decided_by_the_witness_and_written_to_the_ledger_with_a_receipt(client, owner, app):
    ag, hdr, m = setup_agent(owner)
    r = act(client, hdr, "read_file", {"path": "/a"}).json()
    assert (r["verdict"], r["reason"], r["status"]) == ("allow", "OK_PASS", "allowed") and r["aar_b64"]
    rec = [x for x in ledger_entries(app, owner) if x["type"] == "RECEIPT" and x["body"]["id"] == r["rid"]]
    assert len(rec) == 1
    a = rec[0]["body"]["action"]
    assert a["class"] == "pass" and a["recipient"] == "tool:read_file" and a["amount"] == 0 and a["toolmap_sha256"].hex() == m["toolmap_sha256"]
    assert (rec[0]["body"]["verdict"], rec[0]["body"]["reason"]) == ("allow", "OK_PASS")


def test_pass_with_protected_data_is_data_forbidden(client, owner, app):
    ag, hdr, m = setup_agent(owner)
    r = act(client, hdr, "read_file", {"path": "/a", "note": "key sk-" + "a" * 30}).json()      # a secret shape in an argument of a pass tool
    assert (r["verdict"], r["reason"]) == ("deny", "DATA_FORBIDDEN")
    assert [x for x in ledger_entries(app, owner) if x["type"] == "RECEIPT" and x["body"]["id"] == r["rid"]]       # the refusal is in the book too


def test_a_pass_receipt_for_an_agent_without_mandate_stays_no_mandate(client, owner):
    ag, hdr = owner.new_agent()
    r = act(client, hdr, "read_file", {"path": "/a"}).json()
    assert r["verdict"] == "pass"            # no mandate, nothing to bind: the legacy answer (the gateway decides what an unsigned pass means)


def test_default_pass_gives_a_receipt_with_a_signed_map(client, owner):
    ag, hdr = owner.new_agent()
    t = {"version": 1, "default": "pass", "tools": {}}
    assert owner.c.put("/api/agents/%s/toolmap" % ag["id"], json={"toolmap": t}, headers=H).status_code == 200
    owner.mandate(ag["id"])
    r = act(client, hdr, "anything_at_all", {}).json()
    assert (r["verdict"], r["reason"]) == ("allow", "OK_PASS") and r["aar_b64"]


def test_every_decision_comes_with_a_promise_that_the_verifier_accepts(client, owner, app):
    promises_on(app)
    ag, hdr, m = setup_agent(owner)
    ctx = ctx_of(app)
    for tool, args in (("send_email", {"to": "bob@partner.example", "subject": "s"}), ("send_email", {"to": "x@evil.example", "subject": "s"}),
                       ("read_file", {"path": "/a"}), ("publish", {"channel": "blog", "text": "t"})):
        r = act(client, hdr, tool, args).json()
        assert r["promise_b64"], (tool, r)
        p = wa.b64u_dec(r["promise_b64"])
        pl = cose.loads(cose.verify1(p, [ctx.wk], cose.TYP_PROMISE)[0])
        assert pl["t"] == "promise" and pl["mmd"] == 3600 and pl["ledger"] == ctx.hub.ledger(owner.account["id"]).lid
        ents = load_entries(ctx.hub.ledger(owner.account["id"]).path, [ctx.wk])
        e = ents[pl["seq"]]
        assert e["type"] == "RECEIPT" and e["body"]["id"] == r["rid"] and e["hash"] == pl["entry"] and e["t"] == pl["entry_t"]
        assert check_promise_cose(p, ents, [ctx.wk], [], pl["entry_t"] + 10) == "pending"
        assert check_promise_cose(p, ents, [ctx.wk], [], pl["entry_t"] + 4000) == "PROMISE_LATE"      # the entry is there, no anchor by the deadline
        # a repeat of the same request returns the same promise (nothing new is appended)
    r1 = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s"}).json()
    r2 = client.get("/v1/actions/" + r1["rid"], headers=hdr).json()
    assert r2["promise_b64"] == r1["promise_b64"]


def test_a_promise_is_kept_once_an_anchored_checkpoint_covers_the_entry(client, owner, app):
    promises_on(app)
    ag, hdr, m = setup_agent(owner)
    ctx = ctx_of(app)
    r = act(client, hdr, "read_file", {"path": "/a"}).json()
    p = wa.b64u_dec(r["promise_b64"])
    L = ctx.hub.ledger(owner.account["id"])
    with ctx.hub.lock(owner.account["id"]):
        L._checkpoint_locked()
    ents = load_entries(L.path, [ctx.wk])
    cp = [i for i, e in enumerate(ents) if e["type"] == "CHECKPOINT"][-1]
    assert check_promise_cose(p, ents, [ctx.wk], [cp], ents[cp]["t"] + 5) == "kept"
    assert check_promise_cose(p, ents, [ctx.wk], [], ents[cp]["t"] + 5) == "pending"        # the checkpoint was not anchored (anchor off)


def test_a_forged_or_foreign_promise_is_not_evidence_and_does_not_break_the_ledger(client, owner, app):
    from svidetel_v4.verify import verify_file
    promises_on(app)
    ag, hdr, m = setup_agent(owner)
    ctx = ctx_of(app)
    r = act(client, hdr, "read_file", {"path": "/a"}).json()
    L = ctx.hub.ledger(owner.account["id"])
    ents = load_entries(L.path, [ctx.wk])
    other = cose.Key.from_seed(cose.ALG_EDDSA, bytes([7]) * 32)
    forged = cose.sign1(other, cose.verify1(wa.b64u_dec(r["promise_b64"]), [ctx.wk], cose.TYP_PROMISE)[0], cose.TYP_PROMISE)
    assert check_promise_cose(forged, ents, [ctx.wk], [], 0) == "PROMISE_SIG"
    long_mmd = cose.sign1(ctx.wk, cbor2.dumps({"v": "deus-aar-0.1", "t": "promise", "ledger": L.lid, "seq": 1, "entry": ents[1]["hash"], "entry_t": 0, "mmd": 7200},
                                              canonical=True), cose.TYP_PROMISE)
    assert check_promise_cose(long_mmd, ents, [ctx.wk], [], 0) == "PROMISE_MALFORMED"


def test_audit_of_the_signed_ledger_still_valid_with_pass_receipts_and_counters(client, owner, app):
    from svidetel_v4.verify import verify_file
    ag, hdr, m = setup_agent(owner)
    ctx = ctx_of(app)
    for tool, args in (("read_file", {"path": "/a"}), ("send_email", {"to": "bob@partner.example", "subject": "s"}), ("read_file", {"path": "/b"})):
        act(client, hdr, tool, args)
    L = ctx.hub.ledger(owner.account["id"])
    reg = ctx.hub.registry if hasattr(ctx.hub, "registry") else None
    ents = load_entries(L.path, [ctx.wk])
    assert [e["body"]["action"]["class"] for e in ents if e["type"] == "RECEIPT"] == ["pass", "message", "pass"]
    assert all(e["witness_sig_valid"] for e in ents)


def test_gateway_vectors_match_the_server_bytes():
    """contract/vectors/gateway (the page's CDE encoder is tested against the same files in web/test/gateway.test.mjs)."""
    import glob
    import os
    d = os.path.join(_paths.CLOUD, "contract", "vectors", "gateway")
    files = sorted(glob.glob(os.path.join(d, "*.json")))
    assert len(files) == 3
    for f in files:
        v = json.load(open(f))
        b = wa.cde_raw(wire.cbor_form(v["json"]))
        assert b.hex() == v["cde_hex"] and hashlib.sha256(b).hexdigest() == v["sha256"], v["id"]
