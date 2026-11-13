"""Catalog from the MCP JSON schema (§6), drift, pass_net_tools, coverage. Required (6)."""
import json

from app import toolmap as tm
from app.flow import catalog
from tests_flow.helpers import H

GMAIL = {"tools": [
    {"name": "send_email", "description": "Send an e-mail via Gmail",
     "inputSchema": {"type": "object", "properties": {"to": {"type": "array", "items": {"type": "string"}}, "cc": {"type": "array"},
                                                      "subject": {"type": "string"}, "body": {"type": "string"}, "reply_to": {"type": "string"}},
                     "required": ["to", "subject", "body"]}},
    {"name": "search_emails", "description": "Search the mailbox", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
    {"name": "fetch_url", "description": "Download a web page", "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}}]}


def _post(client, hdr, body):
    return client.post("/v1/catalog", json=body, headers=hdr)


def test_6_gmail_catalog_unknown_reply_to_not_applicable(client, owner):
    ag, hdr = owner.new_agent()
    r = _post(client, hdr, GMAIL)
    assert r.status_code == 200 and r.json()["drift"] is False and len(r.json()["catalog_sha256"]) == 64
    g = client.get("/api/catalog/" + ag["id"]).json()
    assert {"tool": "send_email", "arg": "reply_to"} in g["suggestion"]["unknown"]
    assert g["suggestion"]["args"]["send_email"]["reply_to"] == "UNKNOWN"
    assert g["suggestion"]["toolmap"]["tools"]["send_email"]["class"] == "message"
    # 0.2.0 merge: openapi-0.2 -- the draft without decisions is shown, not applicable while UNKNOWN remains
    r = client.post("/api/catalog/%s/draft" % ag["id"], json={}, headers=H)
    assert r.status_code == 200 and r.json()["applicable"] is False and {"tool": "send_email", "arg": "reply_to"} in r.json()["unknown"]
    # decisions that leave an UNKNOWN -> 422
    r = client.post("/api/catalog/%s/draft" % ag["id"], json={"decisions": {"send_email": {"args": {}}}}, headers=H)
    assert (r.status_code, r.json()["error"]) == (422, "CATALOG_UNRESOLVED")
    assert "reply_to" in r.json()["detail"]


def test_catalog_draft_resolved_is_valid_toolmap(client, owner):
    ag, hdr = owner.new_agent()
    _post(client, hdr, GMAIL)
    r = client.post("/api/catalog/%s/draft" % ag["id"], json={"decisions": {"send_email": {"args": {"reply_to": "recipient"}}}}, headers=H)
    assert r.status_code == 200, r.text
    t = r.json()["toolmap"]
    tm.check_toolmap(t)
    e = t["tools"]["send_email"]
    assert e["strict"] is True and e["recipient"] == ["$.to", "$.cc", "$.reply_to"] and e["text"] == ["$.body", "$.subject"]
    assert t["tools"]["search_emails"] == {"class": "pass"}
    # the draft is NOT applied: the agent still has its preset
    assert client.get("/api/agents").json()[0]["toolmap"] == tm.preset("demo")
    # applied by the owner (PUT, step-up): the unmapped reply_to of a strict tool is refused, mapped -> judged as a recipient
    owner.put_toolmap(ag["id"], t)


def test_catalog_deny_tool_decision(client, owner):
    ag, hdr = owner.new_agent()
    _post(client, hdr, GMAIL)
    r = client.post("/api/catalog/%s/draft" % ag["id"], json={"decisions": {"send_email": {"deny_tool": True}}}, headers=H)
    assert r.status_code == 200 and "send_email" not in r.json()["toolmap"]["tools"]


def test_catalog_drift(client, owner):
    ag, hdr = owner.new_agent()
    h1 = _post(client, hdr, GMAIL).json()
    assert _post(client, hdr, GMAIL).json() == h1                                   # same catalog -> same hash, no drift
    g2 = json.loads(json.dumps(GMAIL))
    g2["tools"][0]["inputSchema"]["properties"]["bcc"] = {"type": "string"}
    h2 = _post(client, hdr, g2).json()
    assert h2["drift"] is True and h2["catalog_sha256"] != h1["catalog_sha256"]
    d = client.get("/api/digest?since=0").json()
    assert [x["catalog_sha256"] for x in d["catalog_drift"]] == [h2["catalog_sha256"]]
    assert client.get("/api/catalog/" + ag["id"]).json()["drift"] is True


def test_pass_net_tools(client, owner):
    ag, hdr = owner.new_agent()
    t = tm.preset("demo")
    t["tools"]["fetch_url"] = {"class": "pass"}
    t["tools"]["search_emails"] = {"class": "pass"}
    owner.put_toolmap(ag["id"], t)
    assert _post(client, hdr, GMAIL).json()["pass_net_tools"] == ["fetch_url"]


def test_suggest_toolmap_unit():
    cat = catalog.check_catalog({"tools": [
        {"name": "buy_item", "inputSchema": {"properties": {"vendor": {"type": "string"}, "amount": {"type": "integer"}}}},
        {"name": "pay_invoice", "inputSchema": {"properties": {"total": {"type": "string"}}}},
        {"name": "frobnicate", "inputSchema": {"properties": {"x": {"type": "string"}}}}]})
    s = catalog.suggest_toolmap(cat)
    assert s["toolmap"]["tools"]["buy_item"]["amount"] == "$.amount"
    assert {"tool": "buy_item", "arg": "vendor"} in s["unknown"]
    assert {"tool": "pay_invoice", "arg": "total"} in s["unknown"]           # amount word but not integer -> UNKNOWN
    assert {"tool": "frobnicate", "arg": None} in s["unknown"]
    assert all(e.get("strict") is True for e in s["toolmap"]["tools"].values() if e["class"] != "pass")
    assert catalog.suggest_toolmap(cat) == s                                 # deterministic


def test_catalog_invalid_and_isolation(client, owner, owner2):
    ag, hdr = owner.new_agent()
    assert _post(client, hdr, {"tools": [{"name": "a"}, {"name": "a"}]}).status_code == 422
    assert _post(client, {"Authorization": "Bearer dwk_nope"}, GMAIL).status_code == 401
    _post(client, hdr, GMAIL)
    assert owner2.c.get("/api/catalog/" + ag["id"]).status_code == 404


def test_coverage_store(client, owner, ctx):
    ag, hdr = owner.new_agent()
    r = client.post("/v1/coverage", json={"level": "C1", "unwitnessed": ["Bash"], "tool": "doctor-0.2", "pass_net_tools": ["fetch_url"]}, headers=hdr)
    assert r.status_code == 200 and r.json() == {"stored": True, "level": "C1", "trust": "operator-declared"}
    assert client.post("/v1/coverage", json={"level": "C9"}, headers=hdr).status_code == 422
    cov = client.get("/api/digest").json()["coverage"]
    assert cov[0]["level"] == "C1" and cov[0]["trust"] == "operator-declared" and cov[0]["agent_id"] == ag["id"]
