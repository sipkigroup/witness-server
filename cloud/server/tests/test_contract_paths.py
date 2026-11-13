"""Every path+method of cloud/contract/openapi.yaml is exercised and its 2xx answer validates against the schema of the contract."""
import os
import re

import jsonschema
import yaml
from fastapi.testclient import TestClient

from app import _paths
from tests.helpers import FORM, H, ORIGIN, RP, Owner, act
import wa_profile as wa
from svidetel_v4.state import approval_payload

SPEC = yaml.safe_load(open(os.path.join(_paths.CONTRACT_DIR, "openapi.yaml")))


class Rec(TestClient):
    seen = {}

    def request(self, method, url, **kw):
        r = super().request(method, url, **kw)
        path = url.split("?")[0]
        for tpl, ops in SPEC["paths"].items():
            if re.fullmatch(re.sub(r"\{[^}]+\}", "[^/]+", tpl), path) and method.lower() in ops:
                if 200 <= r.status_code < 300:
                    self.seen.setdefault((tpl, method.lower()), []).append(r)
                break
        return r


def schema_of(tpl, method):
    resp = SPEC["paths"][tpl][method]["responses"].get("200") or SPEC["paths"][tpl][method]["responses"].get("204")
    return (resp.get("content") or {}).get("application/json", {}).get("schema"), resp


def test_all_paths_answer_per_schema(app):
    c = Rec(app, base_url=ORIGIN)
    Rec.seen = {}
    o = Owner(c).register("Tester")
    o.login()
    c.get("/api/me")
    ag, hdr = o.new_agent()
    c.get("/api/agents")
    c.put("/api/agents/%s/toolmap" % ag["id"], json={"toolmap": ag["toolmap"]}, headers=H)
    c.get("/api/data-patterns")
    c.put("/api/data-patterns", json={"patterns": {"phone": ["555-0100"]}}, headers=H)
    m, r = o.mandate(ag["id"])
    c.get("/api/mandates")
    for tool, a in (("send_email", {"to": "x@evil.example"}), ("send_email", {"to": "bob@partner.example"}), ("read_file", {"path": "/a"}),
                    ("mystery", {})):
        act(c, hdr, tool, a)
    d = act(c, hdr, "publish", {"channel": "blog", "text": "t"}).json()
    c.get("/api/feed")
    c.get("/api/budget")
    c.get("/api/approvals?status=pending")
    c.get("/api/approvals/" + d["rid"])
    o.approve(d["rid"])
    c.get("/v1/actions/%s?wait=0" % d["rid"], headers=hdr)
    al = act(c, hdr, "send_email", {"to": "bob@partner.example", "subject": "s"}).json()
    c.post("/v1/actions/%s/present" % al["rid"], json={}, headers=hdr)
    c.post("/v1/actions/%s/report" % al["rid"], json={"executed": True}, headers=hdr)
    c.get("/api/export")
    c.get("/api/witness")
    c.get("/v1/witness")
    c.get("/healthz")
    c.post("/api/auth/logout", headers=H)
    ag2, _ = Owner(c).register("Second").new_agent() if False else (None, None)
    o.login()
    j = o.post("/api/auth/stepup/begin").json()
    o.post("/api/auth/stepup/finish", flow_id=j["flow_id"], credential=o.auth.login_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN))
    c.delete("/api/agents/" + ag["id"], headers=H)
    c.post("/api/auth/logout-all", headers=H)
    missing = [(t, mth) for t, ops in SPEC["paths"].items() for mth in ops if (t, mth) not in Rec.seen]
    assert not missing, missing
    n = 0
    for (tpl, mth), resps in Rec.seen.items():
        sch, resp = schema_of(tpl, mth)
        if not sch:
            continue
        for r in resps:
            jsonschema.Draft202012Validator({**sch, "components": SPEC["components"]}).validate(r.json())
            n += 1
    assert n >= 25
    # error shape
    e = c.get("/api/approvals/r_nope")
    assert set(e.json()) == {"error", "detail"}
    e = TestClient(app, base_url=ORIGIN).post("/v1/actions", json={})
    assert set(e.json()) == {"error", "detail"}
    jsonschema.Draft202012Validator({"$ref": "#/components/schemas/Error", "components": SPEC["components"]}).validate(e.json())


def test_fixtures_shapes_equal(app):
    """Key sets of the contract fixtures equal those of the real answers for the same calls."""
    import json, glob
    c = TestClient(app, base_url=ORIGIN)
    o = Owner(c).register("F")
    ag, hdr = o.new_agent()
    o.mandate(ag["id"])
    fx = lambda n: json.load(open(os.path.join(_paths.CONTRACT_DIR, "fixtures", n + ".json")))
    got = act(c, hdr, "send_email", {"to": "bob@partner.example", "subject": "s"}).json()
    assert got["proof"] is None                                   # R-16 (0.1.1): proof on demand
    got = c.get("/v1/actions/" + got["rid"], headers=hdr).json()
    # r0269: `anchor` (unsigned time status of the receipt, on allow only) is an addition of the server to the 0.1 fixtures; it is in openapi.yaml
    assert got["anchor"]["status"] in ("queued", "stamped")
    assert set(got) - {"anchor"} == set(fx("action-allow")) and set(got["proof"]) == set(fx("action-allow")["proof"])
    got = act(c, hdr, "send_email", {"to": "x@evil.example", "subject": "s"}).json()
    assert set(got) == set(fx("action-deny-recipient"))
    got = act(c, hdr, "publish", {"channel": "b", "text": "t"}).json()
    assert set(got) == set(fx("action-defer-publish"))
    assert set(c.get("/api/me").json()["keycard"]) == set(fx("me")["keycard"])
    # 0.2.13: `confirm` (where it may be confirmed: laptop / phone) is an addition of the server to a pending item, not in the 0.1 contract;
    # 0.2.29: so is `repeat_offer` ("approve this call for later runs"); pv2810: and `view_sha256` (the presentation hash the page signs); 05.11: and `what` / `harm` / `details` (the question in plain words, signed with the view)
    # r0277 (P2): and `omitted` (what the first screen does not show whole, signed with the view)
    assert set(c.get("/api/approvals/" + got["rid"]).json()) - {"confirm", "repeat_offer", "view_sha256", "what", "harm", "risk", "details", "omitted"} == set(fx("approval-get"))
    assert set(c.get("/api/feed").json()["items"][0]) == set(fx("feed")["items"][0])
