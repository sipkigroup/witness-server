"""0.2.43b: a receipt id from a client is matched without regard to case (OpenShell lowercases the reason code `witness_approval_pending_retry_<rid>`
to a-z0-9_). Only the case is folded: the shape r_ + base32 is still required, garbage is not found."""
import wa_profile as wa
from app import _paths  # noqa: F401
from app.context import canon_rid
from svidetel_v4.state import approval_payload
from tests.test_0243_http import HFORM, call
from tests import viewkit  # noqa: E402  (r0352: decisions name the view)


def test_canon_rid_unit():
    assert canon_rid("r_abc234") == "r_ABC234" and canon_rid("R_Abc234") == "r_ABC234" and canon_rid("r_ABC234") == "r_ABC234"
    for bad in ("r_ab1", "r_ab-c", "x_abc", "r_", "", "r_" + "a" * 41, "r_abc/../x", "r_abc\n", None, 5, ["r_abc"]):
        assert canon_rid(bad) == bad, bad


def test_lowercase_rid_finds_the_request(client, owner):
    ag, hdr = owner.new_agent("openshell", "os")
    owner.mandate(ag["id"], HFORM)
    x = call(client, hdr, "DELETE api.github.com:443/repos/acme/app/git/refs/heads/main")
    rid = x["rid"]
    low = rid.lower()
    assert low != rid and x["status"] == "pending_approval"
    g = client.get("/api/approvals/" + low)                                   # the owner's page: approve.html?rid=<lower> asks this
    assert g.status_code == 200 and g.json()["rid"] == rid
    a = client.get("/v1/actions/" + low, headers=hdr)                         # the agent side (the tool took the id from the reason code)
    assert a.status_code == 200 and a.json()["rid"] == rid
    pay = approval_payload(g.json()["mandate"], g.json()["action"], g.json()["rid"], True, viewkit.page_view(g.json()))      # the page signs the canonical id it was given back
    assert owner.post("/api/approvals/" + low, **viewkit.claim(viewkit.answer(owner.c, low)), approved=True, envelope_b64=owner.sign(wa.TYP_APPROVAL, pay)).status_code == 200                              # decided through the lower-case id; stored under the canonical one
    y = call(client, hdr, "DELETE api.github.com:443/repos/acme/app/git/refs/heads/main")
    assert (y["rid"], y["verdict"], y["reason"]) == (rid, "allow", "OK_APPROVED")


def test_garbage_rid_is_not_found(client, owner):
    ag, hdr = owner.new_agent("openshell", "os")
    owner.mandate(ag["id"], HFORM)
    call(client, hdr, "DELETE api.github.com:443/repos/acme/app/git/refs/heads/main")
    for bad in ("r_zz1", "r_%2e%2e", "x_abc", "r_" + "a" * 60, "r_a-b"):
        assert client.get("/api/approvals/" + bad).status_code == 404, bad
        assert client.get("/v1/actions/" + bad, headers=hdr).status_code == 404, bad
