"""Builds tests/fixtures/prod011/ : a production-like data dir of Witness Cloud 0.1.1/0.1.3 (schema BEFORE migration 002_org)
and an evidence pack exported from it BEFORE the migration. Runs ONLY on the 0.1.x server code (it was run once on commit 6705877,
before task 01 of 0.2 touched app/); the output is committed and used by tests/test_migrate.py.
Usage (0.1.x tree): cd cloud/server && .venv/bin/python tests/fixtures/make_prod011.py"""
import io
import json
import os
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, SERVER)
from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
from app.config import Config
from app.main import create_app
import wa_profile as wa
from tests.helpers import FORM, ORIGIN, RP, Owner, act

OUT = os.path.join(HERE, "prod011")
KEY = "b2" * 32
PRIV = {"alice": 0x1A11CE0001, "bob": 0xB0B0000002}
CRED = {"alice": b"A" * 32, "bob": b"B" * 32}


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(OUT)
    with open(os.path.join(OUT, "witness_key"), "w") as f:
        f.write(KEY)
    cfg = Config(data_dir=os.path.join(OUT, "data"), witness_key_file=os.path.join(OUT, "witness_key"), key_pepper="test-pepper",
                 rp_id=RP, origin=ORIGIN, iss="https://witness.test", anchor="off", web_dir=os.path.join(OUT, "noweb"))
    app = create_app(cfg)
    info = {}
    for name in ("alice", "bob"):
        c = TestClient(app, base_url=ORIGIN)
        o = Owner(c)
        o.auth = wa.SoftAuthenticator(private_int=PRIV[name], credential_id=CRED[name])
        o.register(name.title())
        ag, hdr = o.new_agent("demo", name + "-bot")
        m, r = o.mandate(ag["id"], FORM)
        assert r.status_code == 200, r.text
        rs = []
        rs.append(act(c, hdr, "send_email", {"to": "bob@partner.example", "subject": "s", "body": "b"}).json())
        rs.append(act(c, hdr, "send_email", {"to": "x@evil.example", "subject": "s", "body": "b"}).json())
        rs.append(act(c, hdr, "purchase", {"vendor": "v.example", "amount_cents": 5000}).json())
        d = act(c, hdr, "publish", {"channel": "blog", "text": "hello " + name}).json()
        assert o.approve(d["rid"]).status_code == 200
        pend = act(c, hdr, "publish", {"channel": "news", "text": "pending " + name}).json()
        c.get("/v1/actions/" + rs[0]["rid"], headers=hdr)
        info[name] = {"account_id": o.account["id"], "agent_id": ag["id"], "api_key": hdr["Authorization"][7:], "mandate_id": m["id"],
                      "private_int": PRIV[name], "credential_id_hex": CRED[name].hex(), "pending_rid": pend["rid"],
                      "rids": [x["rid"] for x in rs] + [d["rid"]]}
        if name == "alice":
            p = c.get("/api/export")
            assert p.status_code == 200
            zipfile.ZipFile(io.BytesIO(p.content)).extractall(os.path.join(OUT, "pack_alice"))
    app.state.ctx.db.c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    with open(os.path.join(OUT, "info.json"), "w") as f:
        json.dump(info, f, indent=1)
    print("ok", OUT)


if __name__ == "__main__":
    main()
