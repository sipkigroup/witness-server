"""0.2.46: the evidence pack for CI by an owner-issued export token bound to one agent (app/export_tokens.py, GET /v1/export).
Threat model: a stolen agent key alone must not open the account's other data (the pack is the whole account's ledger)."""
import io
import time
import zipfile

from tests.helpers import H, act
from tests.recovery_helpers import run_verify


def issue(owner, agent_id, **kw):
    return owner.post("/api/export-tokens", agent_id=agent_id, **kw)


def get(client, hdr, tok=None):
    h = dict(hdr)
    if tok is not None:
        h["X-DW-Export-Token"] = tok
    return client.get("/v1/export", headers=h)


def test_agent_key_alone_opens_nothing_token_alone_neither(client, owner):
    ag, hdr = owner.new_agent()
    r = get(client, hdr)
    assert r.status_code == 401 and r.json()["error"] == "EXPORT_TOKEN_INVALID"            # the CI key of 0.2.45: still no pack
    tok = issue(owner, ag["id"]).json()["export_token"]
    assert get(client, {}, tok).status_code == 401                                        # the token without the agent key
    assert get(client, {"Authorization": "Bearer dwk_WRONG"}, tok).json()["error"] == "BAD_KEY"


def test_token_with_its_agent_downloads_a_valid_pack(client, owner, tmp_path):
    ag, hdr = owner.new_agent()
    m, r = owner.mandate(ag["id"])
    assert r.status_code == 200, r.text
    act(client, hdr, "send_email", {"to": "a@example.com", "subject": "s", "body": "b"})
    j = issue(owner, ag["id"], ttl_hours=2, label="ci").json()
    assert j["export_token"].startswith("dwx_") and j["token"]["live"] and j["token"]["expires_at"] - j["token"]["created_at"] == 7200
    r = get(client, hdr, j["export_token"])
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip" and r.headers["cache-control"] == "no-store"
    zipfile.ZipFile(io.BytesIO(r.content)).extractall(tmp_path / "pack")
    rc, out = run_verify(str(tmp_path / "pack"), "--offline")
    assert rc == 0 and "RESULT: VALID" in out, out
    lst = client.get("/api/export-tokens").json()
    assert lst[0]["uses"] == 1 and lst[0]["last_used_at"] and "dwx_" + "A" not in str(lst) and j["export_token"] not in str(lst)


def test_bound_to_one_agent_and_one_account(client, owner, owner2):
    a1, h1 = owner.new_agent(name="a1")
    a2, h2 = owner.new_agent(name="a2")
    b1, hb = owner2.new_agent(name="b1")
    tok = issue(owner, a1["id"]).json()["export_token"]
    assert get(client, h2, tok).json()["error"] == "EXPORT_TOKEN_INVALID"                   # another agent of the same account
    assert get(client, hb, tok).json()["error"] == "EXPORT_TOKEN_INVALID"                   # another account's agent
    assert issue(owner2, a1["id"]).status_code == 404                                        # no token for someone else's agent
    assert get(client, h1, tok).status_code == 200


def test_expired_revoked_disabled_frozen(client, owner, app):
    ag, hdr = owner.new_agent()
    j = issue(owner, ag["id"]).json()
    db = app.state.ctx.db
    db.x("UPDATE export_tokens SET expires_at=? WHERE id=?", (int(time.time()) - 1, j["token"]["id"]))
    assert get(client, hdr, j["export_token"]).json()["error"] == "EXPORT_TOKEN_INVALID"
    j = issue(owner, ag["id"]).json()
    assert client.delete("/api/export-tokens/" + j["token"]["id"]).status_code == 403          # no Origin: not the dashboard
    assert client.delete("/api/export-tokens/" + j["token"]["id"], headers=H).status_code == 204
    assert get(client, hdr, j["export_token"]).json()["error"] == "EXPORT_TOKEN_INVALID"
    j = issue(owner, ag["id"]).json()
    db.x("UPDATE agents SET frozen_at=? WHERE id=?", (int(time.time()), ag["id"]))
    assert get(client, hdr, j["export_token"]).json()["error"] == "AGENT_FROZEN"
    db.x("UPDATE agents SET frozen_at=NULL, disabled_at=? WHERE id=?", (int(time.time()), ag["id"]))
    assert get(client, hdr, j["export_token"]).json()["error"] == "BAD_KEY"


def test_issue_needs_a_fresh_passkey_and_bounds(client, owner, app):
    ag, hdr = owner.new_agent()
    for bad in (0, 169, "24", True, 1.5):
        assert issue(owner, ag["id"], ttl_hours=bad).status_code == 422, bad
    assert issue(owner, "ag_nope").status_code == 404
    for _ in range(10):
        assert issue(owner, ag["id"]).status_code == 200
    assert issue(owner, ag["id"]).json()["error"] == "QUOTA"
    app.state.ctx.db.x("UPDATE sessions SET stepup_at=0")
    assert issue(owner, ag["id"]).json()["error"] == "STEPUP_REQUIRED"                       # a stolen cookie cannot mint one


def test_rate_limit_per_token(client, owner):
    ag, hdr = owner.new_agent()
    tok = issue(owner, ag["id"]).json()["export_token"]
    codes = [get(client, hdr, tok).status_code for _ in range(7)]
    assert codes[:6] == [200] * 6 and codes[6] == 429
