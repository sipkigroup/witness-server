"""Task 01 of 0.2: migration 002_org on a COPY of a production-like 0.1.1 database (tests/fixtures/prod011, made by the 0.1.3 code
before this task touched app/, see make_prod011.py), the old accounts working as 0.1 afterwards, and a pack exported BEFORE the
migration still VALID after it (ARHITEKTURA-0.2 2.6, 11 risk 2)."""
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
import wa_profile as wa
from app import migrate
from app.config import Config
from app.db import DB, NeedsMigration
from app.main import create_app
from tests.helpers import FORM, ORIGIN, RP, Owner, act

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures", "prod011")
SERVER = os.path.dirname(HERE)
INFO = json.load(open(os.path.join(FIX, "info.json")))


def dump(path):
    c = sqlite3.connect(path)
    try:
        return "\n".join(c.iterdump())
    finally:
        c.close()


@pytest.fixture()
def prod(tmp_path):
    """A copy of the production-like data dir; the fixture itself is never written."""
    d = tmp_path / "prod"
    shutil.copytree(FIX, d)
    os.makedirs(d / "data" / "anchors", exist_ok=True)
    return d


def cfg_of(d):
    return Config(data_dir=str(d / "data"), witness_key_file=str(d / "witness_key"), key_pepper="test-pepper", rp_id=RP, origin=ORIGIN,
                  iss="https://witness.test", anchor="off", web_dir=str(d / "noweb"))


def run_migrate(*args):
    p = subprocess.run([sys.executable, "-m", "app.migrate", *args], cwd=SERVER, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def test_server_refuses_an_unmigrated_database(prod):
    with pytest.raises(NeedsMigration):
        DB(str(prod / "data" / "db.sqlite"))
    rc, out = run_migrate("--db", str(prod / "data" / "nothing.sqlite"), "--backup", str(prod / "b.sqlite"))
    assert rc == 2 and "FAILED" in out


# (9) migration of a copy of a production-like 0.1.1 database: old accounts work as 0.1, a second run changes nothing
def test_9_migrate_copy_then_old_accounts_work(prod):
    db = str(prod / "data" / "db.sqlite")
    before = dump(db)
    rc, out = run_migrate("--db", db, "--backup", str(prod / "backup" / "db-before-002.sqlite"))
    assert rc == 0 and out.strip() == "migrated 002_org: users=2 members=2", out
    assert dump(str(prod / "backup" / "db-before-002.sqlite")) == before          # the copy is the database BEFORE the change
    after = dump(db)
    rc, out2 = run_migrate("--db", db, "--backup", str(prod / "backup" / "db-before-002.sqlite"))
    assert rc == 0 and "already applied, no changes" in out2 and dump(db) == after, out2
    c = sqlite3.connect(db)
    assert [r[0] for r in c.execute("PRAGMA integrity_check")] == ["ok"]
    assert {r[1] for r in c.execute("PRAGMA table_info(credentials)")} >= {"user_id", "account_id", "credential_id"}
    assert not [r for r in c.execute("PRAGMA index_list(credentials)") if r[2] and "account_id" in str(list(c.execute("PRAGMA index_info(%s)" % r[1])))]
    assert c.execute("SELECT COUNT(*) FROM credentials WHERE user_id=account_id").fetchone()[0] == 2
    assert sorted(json.loads(r[0]) == ["owner", "budget", "access"] and r[1] == "active" for r in c.execute("SELECT roles, status FROM members")) == [True, True]
    c.close()
    # the server starts on it; old accounts log in with their old passkeys and work exactly as 0.1 (solo, wa-sig)
    app = create_app(cfg_of(prod))
    for name in ("alice", "bob"):
        i = INFO[name]
        o = Owner(TestClient(app, base_url=ORIGIN))
        o.auth = wa.SoftAuthenticator(private_int=i["private_int"], credential_id=bytes.fromhex(i["credential_id_hex"]))
        r = o.login()
        assert r.status_code == 200 and r.json()["account"]["id"] == i["account_id"] == r.json()["user"]["id"], r.text
        o.account = r.json()["account"]
        me = o.c.get("/api/me").json()
        assert me["roles"] == ["owner", "budget", "access"] and me["keycard"]["kid_hex"] == o.auth.kid.hex()
        ms = o.c.get("/api/mandates").json()
        assert [m["id"] for m in ms] == [i["mandate_id"]]
        feed = {x["rid"] for x in o.c.get("/api/feed").json()["items"]}
        assert set(i["rids"]) <= feed
        hdr = {"Authorization": "Bearer " + i["api_key"]}
        assert o.c.get("/v1/actions/" + i["rids"][0], headers=hdr).json()["verdict"] == "allow"
        m, r = o.mandate(i["agent_id"], FORM)                                   # a fresh mandate on the old ledger (old one may expire)
        assert r.status_code == 200, r.text
        assert act(o.c, hdr, "send_email", {"to": "bob@partner.example", "subject": "s", "body": "b"}).json()["verdict"] == "allow"
        assert act(o.c, hdr, "send_email", {"to": "x@evil.example", "subject": "s", "body": "b"}).json()["reason"] == "RECIPIENT"
        d = act(o.c, hdr, "publish", {"channel": "blog", "text": "after migration " + name}).json()
        assert d["verdict"] == "defer" and o.approve(d["rid"]).json() == {"verdict": "allow"}
        assert o.c.get("/api/org").json()["policy_ver"] == 0
    # a migrated account can grow into an organisation: the genesis policy is signed by its pinned 0.1 key
    g = o.post("/api/org/policy/draft").json()
    assert g["genesis"] is True and g["policy"]["members"][0]["kid"] == o.auth.kid.hex()
    env = o.sign(g["typ"], wa.b64u_dec(g["payload_b64"]))
    assert o.post("/api/sig-requests/" + g["req_id"], envelope_b64=env).json()["policy_ver"] == 1


def unpack(client, dest):
    r = client.get("/api/export")
    assert r.status_code == 200
    zipfile.ZipFile(io.BytesIO(r.content)).extractall(dest)
    return str(dest)


def verify(folder, *flags, checker=None):
    p = subprocess.run([sys.executable, "-I", checker or os.path.join(SERVER, "packtools", "verify_pack.py"), folder, *flags],
                       capture_output=True, text=True)
    return p.returncode, p.stdout


# (10) a pack exported BEFORE the migration verifies after it with packtools/verify_pack.py --offline -> RESULT: VALID
def test_10_pack_before_migration_valid_after(prod, tmp_path):
    db = str(prod / "data" / "db.sqlite")
    pack = str(prod / "pack_alice")
    rc, out = verify(pack, "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    rc, _ = run_migrate("--db", db, "--backup", str(tmp_path / "copy.sqlite"))
    assert rc == 0
    app = create_app(cfg_of(prod))                       # the server (registry_wa.QuorumRegistry, new tables) runs on the migrated data
    i = INFO["alice"]
    o = Owner(TestClient(app, base_url=ORIGIN))
    o.auth = wa.SoftAuthenticator(private_int=i["private_int"], credential_id=bytes.fromhex(i["credential_id_hex"]))
    assert o.login().status_code == 200
    hdr = {"Authorization": "Bearer " + i["api_key"]}
    act(o.c, hdr, "send_email", {"to": "bob@partner.example", "subject": "post", "body": "b"})
    rc, out = verify(pack, "--offline")                  # the OLD pack, checked by the NEW checker tree (source registry_wa.py)
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    rc, out = verify(pack, "--offline", "--use-pack-code")          # and by the code it carried
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    new = unpack(o.c, tmp_path / "after")                # a pack of the same ledger exported after the migration
    rc, out = verify(new, "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    old_ledger = open(os.path.join(pack, "ledger", "ledger.cose")).read()
    assert open(os.path.join(new, "ledger", "ledger.cose")).read().startswith(old_ledger)   # same book, only appended


def test_fresh_database_is_created_migrated(cfg):
    d = DB(os.path.join(cfg.data_dir, "db.sqlite"))
    assert migrate.applied(d.c)
    rc, out = run_migrate("--db", os.path.join(cfg.data_dir, "db.sqlite"), "--backup", os.path.join(cfg.data_dir, "b.sqlite"))
    assert rc == 0 and "already applied" in out and not os.path.exists(os.path.join(cfg.data_dir, "b.sqlite"))


def test_migrate_refuses_to_overwrite_a_backup(prod):
    db = str(prod / "data" / "db.sqlite")
    b = prod / "b.sqlite"
    b.write_bytes(b"earlier copy")
    rc, out = run_migrate("--db", db, "--backup", str(b))
    assert rc == 2 and "refusing to overwrite" in out and b.read_bytes() == b"earlier copy"
    with pytest.raises(NeedsMigration):
        DB(db)                                            # nothing was changed
