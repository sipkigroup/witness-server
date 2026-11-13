from tests.helpers import FORM, H, act
import wa_profile as wa
from svidetel_v4.state import approval_payload


def test_tenant_isolation(client, owner, owner2, app):
    from fastapi.testclient import TestClient
    cb = owner2.c
    ag, hdr = owner.new_agent()
    m, r = owner.mandate(ag["id"])
    d = act(client, hdr, "publish", {"channel": "b", "text": "t"}).json()
    rid = d["rid"]
    # web side
    assert cb.get("/api/approvals/" + rid).status_code == 404
    pay = approval_payload(m, d["action"], rid, True)
    env = owner2.sign(wa.TYP_APPROVAL, pay)
    assert owner2.post("/api/approvals/" + rid, approved=True, envelope_b64=env).status_code == 404
    assert cb.delete("/api/agents/" + ag["id"], headers=H).status_code == 404
    assert cb.put("/api/agents/%s/toolmap" % ag["id"], json={"toolmap": {"version": 1, "default": "pass", "tools": {}}}, headers=H).status_code == 404
    assert owner2.post("/api/mandates/draft", agent_id=ag["id"], form=FORM).status_code == 404
    env_m = owner2.sign(wa.TYP_MANDATE, wa.cde(m))
    assert owner2.post("/api/mandates", mandate=m, envelope_b64=env_m).status_code == 409           # principal of A
    assert cb.get("/api/mandates").json() == [] and cb.get("/api/feed").json()["items"] == []
    assert cb.get("/api/approvals").json() == [] and cb.get("/api/budget").json() == []
    # agent side: B's key cannot touch A's rid; A's key cannot use B's
    agb, hdrb = owner2.new_agent()
    for path, body in (("", None), ("/present", {}), ("/report", {"executed": True})):
        u = "/v1/actions/" + rid + path
        r = client.get(u, headers=hdrb) if body is None else client.post(u, json=body, headers=hdrb)
        assert r.status_code == 404, (u, r.status_code)
    # B's agent has no mandate: A's mandate does not apply to it
    assert act(client, hdrb, "publish", {"channel": "b", "text": "t"}).json()["reason"] == "NO_MANDATE"
    # A's key is rejected on nothing of B's: B's rid is invisible to A
    owner2.mandate(agb["id"])
    rb = act(client, hdrb, "publish", {"channel": "b", "text": "t"}).json()["rid"]
    assert client.get("/v1/actions/" + rb, headers=hdr).status_code == 404
    assert client.get("/api/approvals/" + rb).status_code == 404
    # ledgers are separate files
    import os
    assert len(os.listdir(os.path.join(app.state.ctx.cfg.data_dir, "ledgers"))) == 2


def test_agent_key_hash_with_pepper(app, client, owner):
    ag, hdr = owner.new_agent()
    key = hdr["Authorization"][7:]
    import hashlib
    ctx = app.state.ctx
    row = ctx.db.one("SELECT key_hash FROM agents WHERE id=?", (ag["id"],))
    assert bytes(row["key_hash"]) == hashlib.sha256(b"test-pepper" + key.encode()).digest()
    assert key not in str(ctx.db.q("SELECT * FROM agents"))
    import re
    assert re.fullmatch(r"dwk_[A-Z2-7]{52}", key)
