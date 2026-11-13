"""0.2.35: DW_ARGS_SALT=off|transition|on with the real client (deus_witness >= 0.2.26) and with an old client (no X-DW-Args-Salt header).
Real server (TestClient); the client talks to it through a transport that forwards to the TestClient."""
import dataclasses
import hashlib
import hmac
import json
import os
import sys

import httpx
import pytest

from app import _paths  # noqa: F401
from app import jobs
from app.main import create_app
from tests.helpers import act
from tests.org_helpers import MSG_FORM, Person, ctx_of
from tests.test_flow import setup_agent

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../mcp")))
import deus_witness.client as dwc  # noqa: E402

RCPT = "secret-marker-7f3a@acme.example"


class Bridge(httpx.BaseTransport):
    """forwards the client's requests to a Starlette TestClient (same process, same app)"""

    def __init__(self, tc):
        self.tc, self.seen = tc, []

    def handle_request(self, req):
        self.seen.append((req.method, req.url.path, req.headers.get("x-dw-args-salt")))
        r = self.tc.request(req.method, req.url.raw_path.decode(), content=req.read(), headers={k: v for k, v in req.headers.items() if k.lower() != "host"})
        return httpx.Response(r.status_code, headers={"content-type": r.headers.get("content-type", "application/json")}, content=r.content)


def mode_app(cfg, tmp_path, mode):
    app = create_app(dataclasses.replace(cfg, data_dir=str(tmp_path / ("d-" + mode)), args_salt=mode))
    p = Person(app).register("P" + mode)
    ag, hdr, m = setup_agent(p, MSG_FORM)
    return app, p, hdr


def new_client(p, hdr, tmp_path):
    br = Bridge(p.c)
    w = dwc.Witness("http://testserver", hdr["Authorization"][7:], pin_path=str(tmp_path / "pins.json"), transport=br)
    return w, br


def raw(tool, args):
    return json.dumps([tool, args], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def args(i=0):
    return {"to": RCPT, "subject": "s%d" % i, "body": "b"}


def salt_of(app, p):
    return bytes(ctx_of(app).db.one("SELECT args_salt FROM accounts WHERE id=?", (p.uid,))["args_salt"])


def test_off_new_client_bare_and_no_salt(cfg, tmp_path):
    app, p, hdr = mode_app(cfg, tmp_path, "off")
    w, br = new_client(p, hdr, tmp_path)
    assert w.salt() is None
    r = w.act("send_email", args())                                  # verify=True: hash and receipt checked
    assert r.verdict == "allow" and r.action["args_sha256"] == hashlib.sha256(raw("send_email", args())).hexdigest()
    assert ctx_of(app).db.one("SELECT args_salt FROM accounts WHERE id=?", (p.uid,))["args_salt"] is None
    assert ("GET", "/v1/salt", "1") in br.seen


@pytest.mark.parametrize("mode", ["transition", "on"])
def test_salted_modes_new_client_checks_the_receipt(cfg, tmp_path, mode):
    app, p, hdr = mode_app(cfg, tmp_path, mode)
    w, _ = new_client(p, hdr, tmp_path)
    salt = w.salt()
    assert salt == salt_of(app, p) and len(salt) == 32
    r = w.act("send_email", args())
    want = hmac.new(salt, b"dw-args1\0" + raw("send_email", args()), hashlib.sha256).hexdigest()
    assert r.verdict == "allow" and r.action["args_sha256"] == want and want == w.args_hash("send_email", args())
    assert r.action["args_sha256"] != dwc.args_sha256("send_email", args())          # a dictionary guess without the salt does not match
    row = ctx_of(app).db.one("SELECT action_json FROM actions WHERE account_id=?", (p.uid,))
    assert json.loads(row["action_json"])["args_sha256"] == want                     # the journal action is the salted one


def test_transition_old_client_still_works_with_bare(cfg, tmp_path):
    app, p, hdr = mode_app(cfg, tmp_path, "transition")
    r = act(p.c, hdr, "send_email", args(1)).json()                  # no X-DW-Args-Salt: an old client
    assert r["verdict"] == "allow" and r["action"]["args_sha256"] == hashlib.sha256(raw("send_email", args(1))).hexdigest()
    assert dwc.args_sha256("send_email", args(1)) == r["action"]["args_sha256"]      # what an old client recomputes
    r2 = act(p.c, {**hdr, "X-DW-Args-Salt": "1"}, "send_email", args(2)).json()
    assert r2["action"]["args_sha256"] != hashlib.sha256(raw("send_email", args(2))).hexdigest()


def test_on_refuses_an_old_client_before_anything_is_written(cfg, tmp_path):
    app, p, hdr = mode_app(cfg, tmp_path, "on")
    r = act(p.c, hdr, "send_email", args())
    assert r.status_code == 426 and r.json()["error"] == "ARGS_SALT_REQUIRED"
    assert ctx_of(app).db.one("SELECT COUNT(*) AS n FROM actions WHERE account_id=?", (p.uid,))["n"] == 0
    j = p.c.post("/v1/hook/judge", json={"v": 1}, headers=hdr)                      # the judge path takes the same gate (or fails earlier on the body)
    assert j.status_code in (400, 426)


def test_new_client_against_an_old_server_uses_bare(tmp_path):
    def old(req):
        if req.url.path == "/v1/salt":
            return httpx.Response(404, json={"error": "NOT_FOUND"})
        raise AssertionError(req.url.path)
    w = dwc.Witness("http://old", "dwk_x", pin_path=str(tmp_path / "p.json"), transport=httpx.MockTransport(old))
    assert w.salt() is None and w.args_hash("t", {"a": 1}) == dwc.args_sha256("t", {"a": 1})


def test_client_recovers_when_server_mode_changes(cfg, tmp_path):
    app, p, hdr = mode_app(cfg, tmp_path, "off")
    w, _ = new_client(p, hdr, tmp_path)
    assert w.act("send_email", args(0)).verdict == "allow"           # salt cached as None
    ctx_of(app).cfg.args_salt = "on"                                  # operator switches the mode
    assert w.act("send_email", args(1)).verdict == "allow"           # one re-ask of the salt, no REQUEST_MISMATCH


def test_packs_with_bare_and_salted_entries_are_valid(cfg, tmp_path):
    import tests.recovery_helpers as rh
    app, p, hdr = mode_app(cfg, tmp_path, "transition")
    assert act(p.c, hdr, "send_email", args(0)).json()["verdict"] == "allow"                     # bare (old client)
    assert act(p.c, {**hdr, "X-DW-Args-Salt": "1"}, "send_email", args(1)).json()["verdict"] == "allow"      # salted
    jobs.anchor_once(ctx_of(app))
    pk = rh.export_to(p.c, tmp_path / "pk")
    rc, out = rh.run_verify(pk, "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
