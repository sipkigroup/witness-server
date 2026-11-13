"""Helpers of tests_flow (02). Port 8811 (origin of the test client); own copy of the owner driver (tests/helpers.py is 01's)."""
import base64
import hashlib
import json
import time

import cbor2

from app import _paths  # noqa: F401
import wa_profile as wa
from svidetel_v4 import cose
from svidetel_v4.state import approval_payload
from app.flow.wq import wq

RP = "localhost"
ORIGIN = "http://localhost:8811"
H = {"Origin": ORIGIN}

FORM = {"currency": "USD", "valid_days": 30,
        "purchase": {"enabled": True, "budget": 20000, "max_per_action": 10000},
        "message": {"domains": ["acme.example"], "to": ["bob@partner.example"]},
        "forbidden_data": ["home_address", "phone", "iban", "postal_address"], "delete": None, "publish": None}

ORG_DDL = ["CREATE TABLE IF NOT EXISTS org_settings(account_id TEXT PRIMARY KEY, profile TEXT, defer_ttl_s INTEGER, max_pending INTEGER, "
           "max_defers_hour INTEGER, escalate_after_s INTEGER, advisor TEXT)",
           "CREATE TABLE IF NOT EXISTS org_policies(account_id TEXT, ver INTEGER, policy BLOB, envelope BLOB, hash BLOB, registry_seq INTEGER, t INTEGER, "
           "PRIMARY KEY(account_id,ver))"]


class Owner:
    def __init__(self, client):
        self.c = client
        self.auth = wa.SoftAuthenticator()

    def post(self, path, **j):
        return self.c.post(path, json=j, headers=H)

    def register(self, name="Alice"):
        j = self.post("/api/auth/register/begin", display_name=name).json()
        cred = self.auth.create_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)
        r = self.post("/api/auth/register/finish", flow_id=j["flow_id"], credential=cred)
        assert r.status_code == 200, r.text
        self.account = r.json()["account"]
        return self

    def new_agent(self, preset="demo", name="bot"):
        r = self.post("/api/agents", name=name, preset=preset)
        assert r.status_code == 200, r.text
        j = r.json()
        return j["agent"], {"Authorization": "Bearer " + j["api_key"]}

    def stepup(self):
        j = self.post("/api/auth/stepup/begin").json()
        cred = self.auth.login_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)
        r = self.post("/api/auth/stepup/finish", flow_id=j["flow_id"], credential=cred)
        assert r.status_code == 200, r.text

    def put_toolmap(self, aid, toolmap):
        self.stepup()
        r = self.c.put("/api/agents/%s/toolmap" % aid, json={"toolmap": toolmap}, headers=H)
        assert r.status_code == 200, r.text

    def sign(self, typ, payload):
        return wa.b64u(self.auth.sign_object(typ, payload, RP, ORIGIN))

    def mandate(self, agent_id, form=None):
        d = self.post("/api/mandates/draft", agent_id=agent_id, form=form or FORM)
        assert d.status_code == 200, d.text
        m = d.json()["mandate"]
        r = self.post("/api/mandates", mandate=m, envelope_b64=self.sign(wa.TYP_MANDATE, wa.cde(m)))
        assert r.status_code == 200, r.text
        return m

    def approve(self, rid, approved=True):
        g = self.c.get("/api/approvals/" + rid).json()
        pay = approval_payload(g["mandate"], g["action"], rid, approved)
        return self.post("/api/approvals/" + rid, approved=approved, envelope_b64=self.sign(wa.TYP_APPROVAL, pay))

    def wb(self, items, auth=None):
        a = auth or self.auth
        ad, cd, der = a.get_assertion(wq.wb_challenge(items), RP, ORIGIN)
        return wa.b64u(wq.make_wb(items, a.kid, ad, cd, der))

    def release(self, rid, args_sha256, release):
        pay = wq.release_payload(rid, args_sha256, release)
        return self.post("/api/approvals/%s/release" % rid, release=release, envelope_b64=self.sign(wq.TYP_RELEASE, pay))


def act(client, hdr, tool, args):
    return client.post("/v1/actions", json={"tool": tool, "args": args}, headers=hdr)


def b64d(s):
    return wa.b64u_dec(s)


def org_tables(ctx):
    for s in ORG_DDL:
        ctx.db.x(s)


def set_settings(ctx, account_id, **kw):
    org_tables(ctx)
    cols = ["max_pending", "max_defers_hour", "escalate_after_s", "advisor", "defer_ttl_s", "profile"]
    vals = {c: kw.get(c) for c in cols}
    ctx.db.x("INSERT OR REPLACE INTO org_settings(account_id,%s) VALUES(?,%s)" % (",".join(cols), ",".join("?" * len(cols))),
             (account_id,) + tuple(vals[c] for c in cols))


def set_policy(ctx, account_id, rules, members=None):
    """A policy row for the flow's reads (01 writes real ones). Only `rules` (and members for wb) matter to the flow."""
    org_tables(ctx)
    p = {"v": wq.V_POLICY, "principal": "dw:" + account_id, "ver": 2, "prev": b"\0" * 32, "members": members or [], "rules": rules}
    ctx.db.x("INSERT OR REPLACE INTO org_policies(account_id,ver,policy,envelope,hash,registry_seq,t) VALUES(?,?,?,?,?,?,?)",
             (account_id, 2, wa.cde(p), b"", wq.policy_hash(p), 0, int(time.time())))
    return p


def ledger_entries(ctx, account_id):
    L = ctx.hub.ledger(account_id)
    L.sync_now()
    return [cose.loads(cose.verify1(raw, [ctx.wk], cose.TYP_ENTRY)[0]) for raw in L.raws]


def slow_advise(text, mode):
    time.sleep(2)
    return [("postal_address", 0.9)]
