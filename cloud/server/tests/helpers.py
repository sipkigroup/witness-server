import json

import cbor2

from app import _paths  # noqa: F401
import wa_profile as wa
from svidetel_v4.state import approval_payload

RP = "localhost"
ORIGIN = "http://localhost:8810"
H = {"Origin": ORIGIN}

FORM = {"currency": "USD", "valid_days": 30,
        "purchase": {"enabled": True, "budget": 20000, "max_per_action": 10000},
        "message": {"domains": ["acme.example"], "to": ["bob@partner.example"]},
        "forbidden_data": ["home_address", "phone"], "delete": None, "publish": None}


class Owner:
    def __init__(self, client):
        self.c = client
        self.auth = wa.SoftAuthenticator()

    def post(self, path, **j):
        return self.c.post(path, json=j, headers=H)

    def register(self, name="Alice"):
        r = self.post("/api/auth/register/begin", display_name=name)
        assert r.status_code == 200, r.text
        j = r.json()
        cred = self.auth.create_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)
        r = self.post("/api/auth/register/finish", flow_id=j["flow_id"], credential=cred)
        assert r.status_code == 200, r.text
        self.account = r.json()["account"]
        self.keycard = r.json()["keycard"]
        return self

    def login(self):
        j = self.post("/api/auth/login/begin").json()
        cred = self.auth.login_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)
        return self.post("/api/auth/login/finish", flow_id=j["flow_id"], credential=cred)

    def new_agent(self, preset="demo", name="bot"):
        r = self.post("/api/agents", name=name, preset=preset)
        assert r.status_code == 200, r.text
        j = r.json()
        return j["agent"], {"Authorization": "Bearer " + j["api_key"]}

    def sign(self, typ, payload):
        return wa.b64u(self.auth.sign_object(typ, payload, RP, ORIGIN))

    def mandate(self, agent_id, form=None):
        d = self.post("/api/mandates/draft", agent_id=agent_id, form=form or FORM)
        assert d.status_code == 200, d.text
        m = d.json()["mandate"]
        env = self.sign(wa.TYP_MANDATE, wa.cde(m))
        r = self.post("/api/mandates", mandate=m, envelope_b64=env)
        return m, r

    def approve(self, rid, approved=True):
        g = self.c.get("/api/approvals/" + rid).json()
        pay = approval_payload(g["mandate"], g["action"], rid, approved)
        return self.post("/api/approvals/" + rid, approved=approved, envelope_b64=self.sign(wa.TYP_APPROVAL, pay))


def act(client, hdr, tool, args):
    return client.post("/v1/actions", json={"tool": tool, "args": args}, headers=hdr)


def promises_on(app):
    """0.2.5 (R4-01): inclusion promises are given only with DW_ANCHOR=on and a fresh, successful anchor run; tests that look at promises switch that on (no stamping happens
    unless the test itself calls jobs.anchor_once while cfg.anchor is "on" -- see promises_off)."""
    import time
    ctx = app.state.ctx
    ctx.cfg.anchor = "on"
    ctx.anchor_state = {"t": time.time(), "ok": True}


def promises_off(app):
    app.state.ctx.cfg.anchor = "off"


CLIENT_UID = 501      # r0279: the uid of the one client the tests model (tests/conftest.py pins mapping.FORM_UID to it), on every OS


def time_scale() -> float:
    """r0279 (Linux CI 13.11: 0.80 s for a 0.5 s bound, 53 ms for a 50 ms one on a shared GitHub runner): a time bound of the tests is
    for THIS machine. 1 on a developer's machine; on a CI runner (CI set, as GitHub Actions does) 4, or DW_TIME_SCALE. The checks stay:
    what they guard is work that grows faster than the input (seconds to minutes at the size limits), not a constant factor."""
    import os
    v = os.environ.get("DW_TIME_SCALE")
    try:
        if v:
            return max(1.0, float(v))
    except ValueError:
        pass
    return 4.0 if os.environ.get("CI") else 1.0
