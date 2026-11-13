"""People of an organisation for the 0.2 tests: each Person has its own cookie jar (TestClient) and its own SoftAuthenticator."""
import hashlib
from urllib.parse import parse_qs, urlparse

import cbor2
from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
import wa_profile as wa
import wq_profile as wq
from tests.helpers import H, ORIGIN, RP, Owner

TEAM_RULES = {"policy": {"role": "owner", "k": 1},
              "mandate": [{"if": "money_over", "amount": 50000, "role": "budget", "k": 2}],
              "approval": [{"if": "money_over", "amount": 50000, "role": "budget", "k": 2}],
              "revocation": {"role": "any", "k": 1}, "ceiling": {"role": "owner", "k": 1}}
MONEY_FORM = {"currency": "USD", "valid_days": 30, "purchase": {"enabled": True, "budget": 200000, "max_per_action": 100000},
              "forbidden_data": []}
MSG_FORM = {"currency": "USD", "valid_days": 30, "message": {"domains": ["acme.example"], "to": []}, "forbidden_data": [],
            "publish": {"channels": ["blog"]}}


class Person(Owner):
    def __init__(self, app):
        super().__init__(TestClient(app, base_url=ORIGIN))
        self.app = app

    @property
    def uid(self):
        return self.account["id"]

    def register(self, name="Alice", invite=None):
        r = self.post("/api/auth/register/begin", display_name=name)
        assert r.status_code == 200, r.text
        j = r.json()
        cred = self.auth.create_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)
        body = {"flow_id": j["flow_id"], "credential": cred}
        if invite is not None:
            body["invite"] = invite
        r = self.c.post("/api/auth/register/finish", json=body, headers=H)
        assert r.status_code == 200, r.text
        self.account, self.keycard = r.json()["account"], r.json()["keycard"]
        self.joined = r.json().get("joined")
        return self

    def stepup(self):
        j = self.post("/api/auth/stepup/begin").json()
        cred = self.auth.login_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)
        r = self.post("/api/auth/stepup/finish", flow_id=j["flow_id"], credential=cred)
        assert r.status_code == 200, r.text

    def invite(self, roles):
        r = self.post("/api/org/invites", roles=roles)
        assert r.status_code == 200, r.text
        return parse_qs(urlparse(r.json()["url"]).query)["token"][0]

    def sign_req(self, sid):
        g = self.c.get("/api/sig-requests/" + sid)
        assert g.status_code == 200, g.text
        g = g.json()
        return self.post("/api/sig-requests/" + sid, envelope_b64=self.sign(g["typ"], wa.b64u_dec(g["payload_b64"])))

    def wsig(self, typ, payload):
        return wq.wsig_of_wa(self.auth.sign_object(typ, payload, RP, ORIGIN))


def adopt(owner, members=None, rules=None, others=None):
    """Owner drafts the next policy version and signs it. 0.2.37: on a Team policy (some k >= 2) the CURRENT quorum must sign too: `others`
    (default: the people team() made, in order) add signatures until the request is done. -> the version number."""
    body = {} if members is None else {"members": members, "rules": rules}
    d = owner.post("/api/org/policy/draft", **body)
    assert d.status_code == 200, d.text
    r = owner.sign_req(d.json()["req_id"])
    for p in (others if others is not None else getattr(owner, "team_mates", ())):
        if r.status_code == 200 and r.json()["status"] != "collecting":
            break
        r = p.sign_req(d.json()["req_id"])
    assert r.status_code == 200 and r.json()["status"] == "done", r.text
    return r.json()["policy_ver"]


def team(app):
    """Owner (owner+budget), Bob (budget), Carol (access); policy v1 = genesis, v2 = TEAM_RULES. -> (owner, bob, carol)."""
    owner = Person(app).register("Olga")
    tb, tc = owner.invite(["budget"]), owner.invite(["access"])
    bob = Person(app).register("Bob", invite=tb)
    carol = Person(app).register("Carol", invite=tc)
    assert bob.joined["status"] == "pending" and bob.joined["account_id"] == owner.uid
    assert adopt(owner) == 1
    v = adopt(owner, [{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": bob.uid, "roles": ["budget"]},
                      {"user_id": carol.uid, "roles": ["access"]}], TEAM_RULES)
    assert v == 2
    owner.team_mates = (bob, carol)
    return owner, bob, carol


def ctx_of(app):
    return app.state.ctx


def ledger_entries(app, account_id):
    from svidetel_v4 import cose
    L = ctx_of(app).hub.ledger(account_id)
    L.sync_now()
    return [cose.loads(cose.verify1(raw, [ctx_of(app).wk], cose.TYP_ENTRY)[0]) for raw in L.raws]


def policy_hash_now(app, account_id):
    from app import org
    return org.current_policy(ctx_of(app), account_id)[2]


def sha(b):
    return hashlib.sha256(b).digest()


def loads(b):
    return cbor2.loads(b)
