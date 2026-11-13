"""0.2.2: every path+method of contract/v02/openapi-0.2.2-recovery.yaml is served by the real server and its 2xx answers validate
against the contract's schema (a team scenario: devices, codes, recovery, key replacement, batch revocation)."""
import os
import re

import jsonschema
import yaml
from fastapi.testclient import TestClient

from app import _paths
from tests.helpers import H, ORIGIN
from tests.org_helpers import TEAM_RULES, adopt, team
from tests.recovery_helpers import add_key, new_codes, recover, remove_key, revoke_batch, switch_auth

SPEC = yaml.safe_load(open(os.path.join(_paths.CONTRACT02_DIR, "openapi-0.2.2-recovery.yaml")))
SEEN = {}


def record(r, method, url):
    path = url.split("?")[0]
    for tpl, ops in SPEC["paths"].items():
        if re.fullmatch(re.sub(r"\{[^}]+\}", "[^/]+", tpl), path) and method.lower() in ops and 200 <= r.status_code < 300:
            SEEN.setdefault((tpl, method.lower()), []).append(r)
    return r


class Rec(TestClient):
    def request(self, method, url, **kw):
        return record(super().request(method, url, **kw), method, url)


def test_recovery_paths_answer_per_contract(app):
    SEEN.clear()
    owner, bob, carol = team(app)
    for p in (owner, bob, carol):
        jar = p.c.cookies
        p.c = Rec(app, base_url=ORIGIN)
        p.c.cookies = jar
    adopt(owner, [{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": bob.uid, "roles": ["budget"]},
                  {"user_id": carol.uid, "roles": ["access"]}], dict(TEAM_RULES, recovery={"role": "any", "k": 2}))
    ag, _ = owner.new_agent("demo", "a1")
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form={"currency": "USD", "valid_days": 30, "message": {"domains": ["x.example"], "to": []},
                                                                   "forbidden_data": []}).json()
    assert owner.sign_req(d["req_id"]).json()["status"] == "done"
    owner.c.get("/api/auth/keys")
    owner.c.get("/api/auth/recovery-codes")
    lap, r = add_key(owner)
    assert r.status_code == 200
    codes = new_codes(owner)
    lost = owner.auth
    new, br, f = recover(app, owner, codes[0], client_cls=Rec)
    assert f.status_code == 200
    br2 = Rec(app, base_url=ORIGIN)
    assert br2.post("/api/auth/recovery/login", json={"code": codes[1]}, headers=H).status_code == 200
    br2.get("/api/auth/recovery/state")
    switch_auth(owner, new)
    owner.c.get("/api/mandates/by-key/" + lost.kid.hex())
    rq = bob.post("/api/org/key-replace", user_id=owner.uid).json()
    bob.sign_req(rq["req_id"])
    assert carol.sign_req(rq["req_id"]).json()["status"] == "done"
    assert remove_key(owner, lost.kid.hex()).status_code == 200
    mids = [x["id"] for x in owner.c.get("/api/mandates").json() if x["status"] == "active"]
    assert revoke_batch(owner, mids).status_code == 200
    missing = [(t, m) for t, ops in SPEC["paths"].items() for m in ops if (t, m) not in SEEN]
    assert not missing, missing
    n = 0
    for (tpl, mth), resps in SEEN.items():
        sch = SPEC["paths"][tpl][mth]["responses"]["200"]["content"]["application/json"]["schema"]
        for r in resps:
            jsonschema.Draft202012Validator({**sch, "components": SPEC["components"]}).validate(r.json())
            n += 1
    assert n >= 14
