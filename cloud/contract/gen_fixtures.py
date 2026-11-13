"""Generates fixtures/*.json by driving stub.py in-process (real shapes, test identities)."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.normpath(os.path.join(HERE, "../..")))
from fastapi.testclient import TestClient
import stub, wa_profile as wa
from svidetel_v4.state import approval_payload

O = "http://localhost:8899"
c = TestClient(stub.create_app("localhost", O, web_dir="/nonexistent"), base_url=O, headers={"Origin": O})
out = os.path.join(HERE, "fixtures"); os.makedirs(out, exist_ok=True)
def save(name, obj):
    with open(os.path.join(out, name + ".json"), "w") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)
auth = wa.SoftAuthenticator()
r = c.post("/api/auth/register/begin", json={"display_name": "Demo owner"}).json(); save("register-begin", r)
fin = c.post("/api/auth/register/finish", json={"flow_id": r["flow_id"], "credential": auth.create_credential(wa.b64u_dec(r["options"]["challenge"]), "localhost", O)}).json(); save("register-finish", fin)
l = c.post("/api/auth/login/begin", json={}).json(); save("login-begin", l)
save("login-finish", c.post("/api/auth/login/finish", json={"flow_id": l["flow_id"], "credential": auth.login_credential(wa.b64u_dec(l["options"]["challenge"]), "localhost", O)}).json())
save("me", c.get("/api/me").json())
ag = c.post("/api/agents", json={"name": "demo-bot", "preset": "demo"}).json(); save("agent-create", ag)
save("agents", c.get("/api/agents").json())
save("toolmap-put", c.put("/api/agents/%s/toolmap" % ag["agent"]["id"], json={"toolmap": ag["agent"]["toolmap"]}).json())
save("data-patterns", c.put("/api/data-patterns", json={"patterns": {"home_address": ["14 Maple Court"], "phone": ["555-0100"]}}).json())
form = {"currency": "USD", "valid_days": 30, "purchase": {"enabled": True, "budget": 20000, "max_per_action": 10000},
        "message": {"domains": ["acme.example"], "to": ["bob@partner.example"]}, "forbidden_data": ["home_address", "phone"],
        "delete": None, "publish": None}
save("mandate-form", form)
dr = c.post("/api/mandates/draft", json={"agent_id": ag["agent"]["id"], "form": form}).json(); save("mandate-draft", dr)
m = dr["mandate"]
save("mandate-post", c.post("/api/mandates", json={"mandate": m, "envelope_b64": wa.b64u(auth.sign_object(wa.TYP_MANDATE, wa.cde(m), "localhost", O))}).json())
save("mandates", c.get("/api/mandates").json())
H = {"Authorization": "Bearer " + ag["api_key"]}
def act(tool, args): return c.post("/v1/actions", json={"tool": tool, "args": args}, headers=H).json()
calls = {"allow": ("send_email", {"to": "bob@acme.example", "subject": "hello", "body": "meeting at 10"}),
         "deny-recipient": ("send_email", {"to": "eve@evil.example", "subject": "hi", "body": "x"}),
         "deny-budget": ("purchase", {"vendor": "shop.example", "amount_cents": 9000}),
         "deny-data": ("send_email", {"to": "bob@acme.example", "subject": "addr", "body": "I live at 14 Maple Court"}),
         "deny-irreversible-delete": ("delete_resource", {"resource": "prod-db"}),
         "pass": ("read_file", {"path": "/tmp/sandbox/a.txt"}),
         "deny-tool-unmapped": ("format_disk", {"disk": "c"}),
         "defer-publish": ("publish", {"channel": "blog", "text": "launch"})}
act("purchase", {"vendor": "shop.example", "amount_cents": 10000}); act("purchase", {"vendor": "shop.example", "amount_cents": 10000})
res = {}
for k, (t, a) in calls.items():
    res[k] = act(t, a); save("action-" + k, res[k])
rid = res["defer-publish"]["rid"]
save("action-wait", c.get("/v1/actions/%s?wait=0" % rid, headers=H).json())
save("approvals-pending", c.get("/api/approvals?status=pending").json())
det = c.get("/api/approvals/" + rid).json(); save("approval-get", det)
env = auth.sign_object(wa.TYP_APPROVAL, approval_payload(det["mandate"], det["action"], rid, True), "localhost", O)
save("approval-post", c.post("/api/approvals/" + rid, json={"approved": True, "envelope_b64": wa.b64u(env)}).json())
save("action-allow-after-approval", act("publish", {"channel": "blog", "text": "launch"}))
save("present", c.post("/v1/actions/%s/present" % rid, json={}, headers=H).json())
save("report", c.post("/v1/actions/%s/report" % rid, json={"executed": True}, headers=H).json())
act("publish", {"channel": "news", "text": "second draft"}); act("delete_resource", {"resource": "cache-tmp"})
feed = c.get("/api/feed?limit=8").json(); save("feed", feed)
save("budget", c.get("/api/budget").json())
save("witness", c.get("/v1/witness").json()); save("healthz", c.get("/healthz").json())
print(len(os.listdir(out)), "fixtures; feed items", len(feed["items"]), "verdicts", sorted({i["verdict"] for i in feed["items"]}))
for k in ("deny-data", "deny-budget", "deny-irreversible-delete"): print(k, res[k]["reason"])
