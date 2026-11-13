"""0.2.43 (spec/PROPOSAL-08-http.md): class `http` on the server -- preset `openshell`, the form (canonical rules, unlisted ask/deny),
decisions through /v1/actions (listed runs with a receipt, unlisted asked or refused, PH-6 attacks never run unasked), approval, carry-over
in suggestions, phone level, team access tier; old presets and mandates unchanged."""
import importlib.util
import os

from app import levels
from app.flow.suggest import form_of
from app.toolmap import check_toolmap, preset
from tests.helpers import FORM, act

import wq_profile as wq

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))    # repository root
MOD = os.path.join(ROOT, "openshell-modul", "witness_openshell", "policy.py")
TOOL = "openshell.http"
RULES = ["GET api.github.com/repos/acme/app/**", "PUT api.github.com/repos/acme/app/pulls/*/merge"]
HFORM = dict(FORM, http={"allow": ["get API.GitHub.com:443/repos/acme/app/**", "PUT api.github.com/repos/acme/app/pulls/*/merge"]})


def args(target, body="", query=""):
    import hashlib
    b = body.encode()
    return {"target": target, "query": query, "body": body, "body_sha256": hashlib.sha256(b).hexdigest(), "body_bytes": len(b), "sandbox_id": "sb-1"}


def call(client, hdr, target, **kw):
    r = act(client, hdr, TOOL, args(target, **kw))
    assert r.status_code == 200, r.text
    return r.json()


def test_preset_is_the_module_map():
    tm = preset("openshell")
    check_toolmap(tm)
    assert tm["tools"][TOOL]["class"] == "http"
    if os.path.exists(MOD):                                     # the middleware ships the same entry (kept equal here)
        spec = importlib.util.spec_from_file_location("osw_policy", MOD)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        assert m.TOOLMAP == tm


def test_form_canonicalises_and_refuses(client, owner):
    ag, _ = owner.new_agent("openshell", "os")
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=HFORM)
    assert d.status_code == 200, d.text
    assert d.json()["mandate"]["permissions"]["http"] == {"allow": RULES}
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=dict(FORM, http={"allow": RULES, "unlisted": "deny"}))
    assert d.json()["mandate"]["permissions"]["http"] == {"allow": RULES, "unlisted": "deny"}
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=dict(FORM, http=False))
    assert d.json()["mandate"]["permissions"]["http"] is False
    for bad in ({"allow": ["GET api.github.com/repos/../admin"]}, {"allow": ["GET api.github.com/a*"]}, {"allow": ["GET api.github.com"]},
                {"allow": ["GET аpi.github.com/x"]}, {"allow": ["^/repos/.*$"]}, {"allow": RULES, "unlisted": "allow"},
                {"allow": RULES, "dangerous": True}, ["GET h.example/x"], True):
        r = owner.post("/api/mandates/draft", agent_id=ag["id"], form=dict(FORM, http=bad))
        assert r.status_code == 422 and r.json()["error"] == "FORM_INVALID", (bad, r.text)


def test_listed_runs_unlisted_is_asked_then_approved(client, owner):
    ag, hdr = owner.new_agent("openshell", "os")
    m, r = owner.mandate(ag["id"], HFORM)
    assert r.status_code == 200, r.text
    x = call(client, hdr, "GET api.github.com:443/repos/acme/app/pulls")
    assert (x["verdict"], x["reason"]) == ("allow", "OK") and x["aar_b64"]
    x = call(client, hdr, "PUT api.github.com:443/repos/acme/app/pulls/7/merge", body='{"merge_method":"squash"}')
    assert (x["verdict"], x["reason"]) == ("allow", "OK")
    x = call(client, hdr, "DELETE api.github.com:443/repos/acme/app/git/refs/heads/main")
    assert (x["verdict"], x["reason"], x["status"]) == ("defer", "ESCALATE_HTTP", "pending_approval")
    g = client.get("/api/approvals/" + x["rid"]).json()
    assert g["action"]["class"] == "http" and g["action"]["recipient"] == "DELETE api.github.com:443/repos/acme/app/git/refs/heads/main"
    assert owner.approve(x["rid"]).status_code == 200
    y = call(client, hdr, "DELETE api.github.com:443/repos/acme/app/git/refs/heads/main")
    assert (y["rid"], y["verdict"], y["reason"]) == (x["rid"], "allow", "OK_APPROVED")
    for t in ("GET api.github.com:443/repos/acme/app/../../../admin", "GET api.github.com:443/repos/acme/app/..;/x", "GET api.github.com:443/repos/acme/app/x%2F..%2F..%2Fz",
              "GET api.github.com:80/repos/acme/app/x", "GET api.github.com:443/repos/acme/app/%252e%252e/x", "GET аpi.github.com:443/repos/acme/app/x",
              "GET api.github.com.evil.example:443/repos/acme/app/x"):
        z = call(client, hdr, t)
        assert z["verdict"] != "allow", t                                       # asked (ESCALATE_HTTP) or, past the pending-approval rate, refused
        assert z["reason"] in ("ESCALATE_HTTP", "APPROVAL_RATE"), (t, z["reason"])


def test_unlisted_deny_and_secret_in_body(client, owner):
    ag, hdr = owner.new_agent("openshell", "os")
    owner.mandate(ag["id"], dict(FORM, http={"allow": RULES, "unlisted": "deny"}))
    x = call(client, hdr, "POST api.github.com:443/repos/acme/app/issues")
    assert (x["verdict"], x["reason"]) == ("deny", "RESOURCE")
    x = call(client, hdr, "GET api.github.com:443/repos/acme/app/x", body='{"t":"ghp_' + "A" * 36 + '"}')
    assert (x["verdict"], x["reason"]) == ("deny", "DATA_FORBIDDEN")
    x = call(client, hdr, "GET api.github.com:443/repos/acme/app/x", query="token=ghp_" + "B" * 36)
    assert (x["verdict"], x["reason"]) == ("deny", "DATA_FORBIDDEN")


def test_mandate_silent_on_http_asks_everything_and_strict_args(client, owner):
    ag, hdr = owner.new_agent("openshell", "os")
    owner.mandate(ag["id"], FORM)
    x = call(client, hdr, "GET api.github.com:443/repos/acme/app/x")
    assert (x["verdict"], x["reason"]) == ("defer", "ESCALATE_HTTP")
    r = act(client, hdr, TOOL, dict(args("GET api.github.com:443/x"), headers="x"))
    assert r.json()["reason"] == "TOOL_ARGS_UNMAPPED"                     # strict class: an unknown argument is refused


def test_old_presets_unchanged(client, owner):
    ag, hdr = owner.new_agent("demo", "d")
    owner.mandate(ag["id"], FORM)
    x = act(client, hdr, "publish", {"channel": "blog", "text": "hi"}).json()
    assert (x["verdict"], x["reason"]) == ("defer", "ESCALATE_PUBLISH")


def test_suggest_carries_http_and_levels_and_team_tier():
    m = {"permissions": {"http": {"allow": RULES, "unlisted": "deny"}}, "nbf": 0, "exp": 86400 * 30}
    f, lossy = form_of(m)
    assert f["http"] == {"allow": RULES, "unlisted": "deny"} and lossy == []
    assert form_of({"permissions": {"http": False}})[0]["http"] is False
    assert levels.level_of({"class": "http"}, "ESCALATE_HTTP") == levels.PHONE
    assert "http" in wq.NONMONEY
