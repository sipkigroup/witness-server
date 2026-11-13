"""L3 advisor holds only (§4.2). Required (8)."""
from app.flow import advisor
from tests_flow.helpers import FORM, act, ledger_entries, set_settings

ADDR = "Meet me, I live at twelve Baker street"


def _setup(client, owner, ctx, mode="heuristic"):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"], dict(FORM, publish={"channels": ["#team"]}))
    set_settings(ctx, owner.account["id"], advisor=mode)
    return ag, hdr


def test_8_hold_then_release_true(client, owner, ctx, warm_advisor):
    ag, hdr = _setup(client, owner, ctx)
    n = len(ledger_entries(ctx, owner.account["id"]))
    r = act(client, hdr, "publish", {"channel": "#team", "text": ADDR}).json()
    assert (r["status"], r["reason"]) == ("held", "ADVISORY_HOLD")
    assert len(ledger_entries(ctx, owner.account["id"])) == n                 # held: nothing in the ledger yet
    assert act(client, hdr, "publish", {"channel": "#team", "text": ADDR}).json()["rid"] == r["rid"]     # repeat -> same held rid
    x = owner.release(r["rid"], r["action"]["args_sha256"], True)
    assert x.status_code == 200, x.text
    assert (x.json()["verdict"], x.json()["reason"], x.json()["status"]) == ("allow", "OK", "allowed")    # contract 0.2: {status, verdict, reason}
    j = client.get("/v1/actions/" + r["rid"], headers=hdr).json()
    assert (j["verdict"], j["reason"]) == ("allow", "OK") and j["aar_b64"]
    assert j["action"]["adv"].startswith("heuristic-1:postal_address:released:") and len(j["action"]["adv"].split(":")[-1]) == 8
    rec = [e for e in ledger_entries(ctx, owner.account["id"]) if e["type"] == "RECEIPT" and e["body"]["id"] == r["rid"]]
    assert rec and "released" in rec[0]["body"]["action"]["adv"]


def test_8_release_false_rejected(client, owner, ctx, warm_advisor):
    ag, hdr = _setup(client, owner, ctx)
    r = act(client, hdr, "publish", {"channel": "#team", "text": ADDR}).json()
    j = owner.release(r["rid"], r["action"]["args_sha256"], False).json()
    assert (j["verdict"], j["reason"], j["status"]) == ("deny", "ADVISORY_REJECTED", "denied")
    assert owner.release(r["rid"], r["action"]["args_sha256"], True).json()["error"] == "NOT_HELD"


def test_8_release_signature_bound(client, owner, ctx, warm_advisor):
    ag, hdr = _setup(client, owner, ctx)
    r = act(client, hdr, "publish", {"channel": "#team", "text": ADDR}).json()
    from app.flow.wq import wq
    pay = wq.release_payload(r["rid"], r["action"]["args_sha256"], False)            # signed "reject", sent as "release"
    x = owner.post("/api/approvals/%s/release" % r["rid"], release=True, envelope_b64=owner.sign(wq.TYP_RELEASE, pay))
    assert x.status_code == 409
    assert ctx.db.one("SELECT status FROM actions WHERE rid=?", (r["rid"],))["status"] == "held"


def test_8_dry_deny_no_hold(client, owner, ctx, warm_advisor):
    ag, hdr = _setup(client, owner, ctx)
    r = act(client, hdr, "publish", {"channel": "#ops", "text": ADDR + " IBAN DE89370400440532013000"}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "DATA_FORBIDDEN") and r["status"] == "denied"


def test_advisor_dry_defer_no_hold(client, owner, ctx, warm_advisor):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])                                                   # no publish permission -> dry defer
    set_settings(ctx, owner.account["id"], advisor="heuristic")
    r = act(client, hdr, "publish", {"channel": "#ops", "text": ADDR}).json()
    assert (r["verdict"], r["reason"]) == ("defer", "ESCALATE_PUBLISH")


def test_advisor_off_and_timeout_no_mark(client, owner, ctx, warm_advisor):
    ag, hdr = _setup(client, owner, ctx, mode="off")
    assert act(client, hdr, "publish", {"channel": "#team", "text": ADDR}).json()["verdict"] == "allow"
    set_settings(ctx, owner.account["id"], advisor="heuristic")
    advisor.FN = "tests_flow.helpers:slow_advise"
    try:
        r = act(client, hdr, "publish", {"channel": "#team", "text": ADDR + " 2"}).json()
        assert r["verdict"] == "defer" and r["reason"] == "ADVISORY_HOLD"     # R3-08 (0.2.2): no answer in 300 ms = a human looks (was: fail open)
    finally:
        advisor.FN = None
        advisor.warm()


def test_advisor_label_outside_org_list(client, owner, ctx, warm_advisor):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"], dict(FORM, publish={"channels": ["#team"]}, forbidden_data=["iban"]))
    set_settings(ctx, owner.account["id"], advisor="heuristic")
    assert act(client, hdr, "publish", {"channel": "#team", "text": ADDR}).json()["verdict"] == "allow"
