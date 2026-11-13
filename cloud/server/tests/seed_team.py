"""Seed a data dir with a team of three test participants (software passkeys) for task 05 / manual runs on port 8810 (RUN-02.md).
    cd cloud/server && .venv/bin/python -m tests.seed_team --data /tmp/dw-team [--origin http://localhost:8810]
Creates (in-process, the same code as the server): Olga (owner+budget), Bob (budget), Carol (access), Oscar (observer); policy v1
(genesis) and v2 "budget k=2 above 50000"; one agent with a message/publish mandate; one pending purchase of 80000.
Writes <data>/team.json: per person the session cookie `dw_session`, user id, kid, the P-256 private key (int) and credential id
(to sign as that person from a test), plus the agent API key. TEST DATA ONLY: never point it at a real database."""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from app import _paths  # noqa: F401,E402
from app.config import Config  # noqa: E402
from app.main import create_app  # noqa: E402
import tests.helpers as hp  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--origin", default="http://localhost:8810")
    ap.add_argument("--rp-id", default="localhost")
    o = ap.parse_args(argv)
    if os.path.exists(os.path.join(o.data, "data", "db.sqlite")):
        print("seed_team: %s already has a database; use an empty directory" % o.data)
        return 2
    os.makedirs(o.data, exist_ok=True)
    kf = os.path.join(o.data, "witness_key")
    if not os.path.exists(kf):
        with open(kf, "w") as f:
            f.write(os.urandom(32).hex())
    hp.ORIGIN, hp.RP, hp.H = o.origin, o.rp_id, {"Origin": o.origin}
    import tests.org_helpers as oh
    oh.ORIGIN, oh.RP, oh.H = hp.ORIGIN, hp.RP, hp.H
    cfg = Config(data_dir=os.path.join(o.data, "data"), witness_key_file=kf, key_pepper=os.environ.get("DW_KEY_PEPPER", "dev-pepper"),
                 rp_id=o.rp_id, origin=o.origin, anchor="off")
    app = create_app(cfg)
    owner, bob, carol = oh.team(app)
    obs = oh.Person(app).register("Oscar", invite=owner.invite(["observer"]))
    ag, hdr = owner.new_agent("demo", "team-bot")
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=oh.MSG_FORM).json()
    owner.sign_req(d["req_id"])
    pend = hp.act(owner.c, hdr, "purchase", {"vendor": "v.example", "amount_cents": 80000}).json()
    out = {"origin": o.origin, "account_id": owner.uid, "agent_id": ag["id"], "api_key": hdr["Authorization"][7:],
           "pending_rid": pend["rid"], "people": {}}
    for name, p in (("olga", owner), ("bob", bob), ("carol", carol), ("oscar", obs)):
        out["people"][name] = {"user_id": p.uid, "kid_hex": p.keycard["kid_hex"], "dw_session": p.c.cookies.get("dw_session"),
                               "private_int": p.auth.key.private_numbers().private_value, "credential_id_hex": p.auth.credential_id.hex()}
    with open(os.path.join(o.data, "team.json"), "w") as f:
        json.dump(out, f, indent=1)
    print("seeded %s: account %s, people olga/bob/carol/oscar, policy v2, pending %s" % (o.data, owner.uid, pend["rid"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
