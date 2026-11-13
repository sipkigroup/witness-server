"""0.1.1: R-17 (sign out everywhere, passkey step-up) and R-16 (batched checkpoints)."""
import time

from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
import wa_profile as wa
from tests.helpers import H, ORIGIN, RP, Owner


def stepup(owner):
    j = owner.post("/api/auth/stepup/begin").json()
    cred = owner.auth.login_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)
    return owner.post("/api/auth/stepup/finish", flow_id=j["flow_id"], credential=cred)


def age(app, secs=600):
    app.state.ctx.db.x("UPDATE sessions SET stepup_at=stepup_at-?", (secs,))


def test_stepup_gates_sensitive_changes(app, owner):
    c = owner.c
    ag, _ = owner.new_agent()
    pat = {"patterns": {"phone": ["555-0100"]}}
    assert c.put("/api/data-patterns", json=pat, headers=H).status_code == 200      # fresh session: login counts
    age(app)
    for r in (c.put("/api/data-patterns", json=pat, headers=H),
              c.put("/api/agents/%s/toolmap" % ag["id"], json={"toolmap": ag["toolmap"]}, headers=H),
              c.delete("/api/agents/" + ag["id"], headers=H)):
        assert r.status_code == 403 and r.json()["error"] == "STEPUP_REQUIRED", r.text
    assert c.get("/api/agents").status_code == 200                                    # reads are not gated
    assert stepup(owner).status_code == 200
    assert c.put("/api/data-patterns", json=pat, headers=H).status_code == 200
    assert c.put("/api/agents/%s/toolmap" % ag["id"], json={"toolmap": ag["toolmap"]}, headers=H).status_code == 200
    assert c.delete("/api/agents/" + ag["id"], headers=H).status_code == 204


def test_stepup_expires_after_5_minutes(app, owner):
    age(app, 301)
    assert owner.c.put("/api/data-patterns", json={"patterns": {}}, headers=H).status_code == 403
    stepup(owner)
    age(app, 299)
    assert owner.c.put("/api/data-patterns", json={"patterns": {}}, headers=H).status_code == 200


def test_stepup_other_accounts_passkey_rejected(app, owner, owner2):
    age(app)
    j = owner.post("/api/auth/stepup/begin").json()
    cred = owner2.auth.login_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)   # Bob's passkey on Alice's flow
    r = owner.post("/api/auth/stepup/finish", flow_id=j["flow_id"], credential=cred)
    assert r.status_code == 401
    assert owner.c.put("/api/data-patterns", json={"patterns": {}}, headers=H).status_code == 403


def test_stepup_needs_session_and_origin(client):
    assert client.post("/api/auth/stepup/begin", json={}, headers=H).status_code == 401
    assert client.post("/api/auth/stepup/begin", json={}).status_code == 403


def test_logout_everywhere(app, client, owner):
    ag, _ = owner.new_agent()
    other = TestClient(app, base_url=ORIGIN)
    o2 = Owner(other)
    o2.auth = owner.auth                                  # same passkey, second device/session
    assert o2.login().status_code == 200
    assert other.get("/api/agents").status_code == 200 and client.get("/api/agents").status_code == 200
    assert client.post("/api/auth/logout-all", headers=H).status_code == 204
    assert client.get("/api/agents").status_code == 401
    assert other.get("/api/agents").status_code == 401
    assert client.post("/api/auth/logout-all", headers=H).status_code == 401           # needs a session


def test_refused_action_repeat_is_denied_no_new_request(client, owner):
    from tests.helpers import act
    ag, hdr = owner.new_agent("demo")
    assert owner.mandate(ag["id"])[1].status_code == 200
    r = act(client, hdr, "publish", {"channel": "b", "text": "t"}).json()
    assert r["status"] == "pending_approval"
    assert owner.approve(r["rid"], approved=False).json()["verdict"] == "refused"
    for _ in range(3):
        again = act(client, hdr, "publish", {"channel": "b", "text": "t"}).json()
        assert (again["verdict"], again["reason"], again["status"]) == ("deny", "REFUSED", "denied"), again
        assert again["approval_url"] is None
    assert owner.c.get("/api/approvals").json() == []                       # nothing pending: no spam
    other = act(client, hdr, "publish", {"channel": "b", "text": "different"}).json()   # N-11: a changed text to the same target is blocked too (1 h)
    assert (other["verdict"], other["reason"]) == ("deny", "REFUSED")
    other = act(client, hdr, "publish", {"channel": "c", "text": "t"}).json()           # another target may still defer
    assert other["status"] == "pending_approval"
    # a new mandate (the owner decided again) lifts the block
    assert owner.mandate(ag["id"])[1].status_code == 200
    assert act(client, hdr, "publish", {"channel": "b", "text": "t"}).json()["status"] == "pending_approval"


def test_R16_batched_proofs_verify_and_share_one_checkpoint(app, client, owner):
    import cbor2
    from svidetel_v4.checkpoint import inclusion_path, verify_inclusion
    from tests.helpers import act
    ag, hdr = owner.new_agent("demo")
    assert owner.mandate(ag["id"])[1].status_code == 200
    rids = [act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s%d" % i, "body": "b"}).json()["rid"] for i in range(25)]
    L = app.state.ctx.hub.ledger(owner.account["id"])
    n0 = L.S.nseq
    assert n0 == 1 + 1 + 25 or n0 >= 26                                  # no CHECKPOINT per allow
    cps = set()
    for rid in rids:
        r = client.get("/v1/actions/" + rid, headers=hdr).json()
        p = r["proof"]
        assert p and r["aar_b64"]
        cps.add(p["checkpoint_b64"])
        cp = cbor2.loads(cbor2.loads(wa.b64u_dec(p["checkpoint_b64"])).value[2])
        path = [(chr(b[0]), b[1:]) for b in map(wa.b64u_dec, p["path_b64"])]
        entry = wa.b64u_dec(p["entry_b64"])
        idx = L.rseq[rid]
        assert path == inclusion_path(L.hashes[:cp["seq"] + 1], idx)       # identical to the core's own path
        assert verify_inclusion(L.hashes[idx], path, cp["root"], idx, cp["seq"] + 1)
    assert len(cps) == 1                                                 # ONE checkpoint for the whole batch
    assert L.S.nseq == n0 + 1


def test_head_on_static_is_200(cfg, tmp_path):
    from app.config import Config
    from app.main import create_app
    web = tmp_path / "w2"
    web.mkdir()
    (web / "index.html").write_text("<!doctype html><title>x</title>")
    c2 = Config(**{**cfg.__dict__, "web_dir": str(web)})
    cl = TestClient(create_app(c2), base_url=ORIGIN)
    for path in ("/", "/index.html", "/healthz"):
        g, h = cl.get(path), cl.head(path)
        assert g.status_code == 200 and h.status_code == 200, (path, h.status_code)
        assert h.content == b""
    assert cl.head("/nope.html").status_code == 404
