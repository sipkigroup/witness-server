"""0.2.12: regression tests of the fixes of review 7 beyond the reviewer's own proofs (cloud/review7/tests).
R7-03 the checker names and checks the keys it trusts; R7-04 the ownership chain of the registry; R7-05 recovery limits per account."""
import json
import os
import sqlite3

import cbor2
from fastapi.testclient import TestClient

from app import export
from app.config import Config
from app.main import create_app
from svidetel_v4 import cose
from tests.helpers import H, ORIGIN, RP
from tests.recovery_helpers import Person, add_key, export_to, new_codes, remove_key, run_verify, switch_auth
from tests.test_pack import scenario


def _files(d):
    out = {}
    for base, _, names in os.walk(d):
        for n in names:
            p = os.path.join(base, n)
            out[os.path.relpath(p, d).replace(os.sep, "/")] = open(p, "rb").read()
    return out


def _reseal(app, src, dst, edit):
    """The operator (it holds the witness key) edits the pack and signs the manifest again."""
    ctx = app.state.ctx
    files = _files(src)
    old = json.loads(files.pop("manifest.json"))
    signed = cbor2.loads(cose.verify1(files.pop("manifest.cose"), [ctx.wk], export.TYP_MANIFEST)[0])
    edit(files)
    export.seal(files, ctx.wk, old["account"], old["principal"], old["witness"]["iss"], signed["created_t"], signed["cp_seq"], signed["cp_head"])
    for k, v in files.items():
        p = os.path.join(dst, k)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "wb").write(v)
    return dst


# ---------------------------------------------------------------- R7-03
def test_checker_compares_the_keys_given_on_the_command_line(client, owner, app, tmp_path):
    scenario(client, owner)
    d = export_to(client, tmp_path / "pack")
    wk = app.state.ctx.wk.kid.hex()
    rc, out = run_verify(d, "--offline", "--witness-kid=" + wk, "--owner-kid=" + owner.keycard["kid_hex"][:16])
    assert rc == 0 and "matches --witness-kid" in out and "is among the active keys" in out, out
    assert "trust: the witness key" not in out and "trust: the owner key" not in out          # given, so not taken on trust
    rc, out = run_verify(d, "--offline", "--witness-kid=" + "00" * 32)
    assert rc == 1 and "DOES NOT MATCH" in out, out
    rc, out = run_verify(d, "--offline", "--owner-kid=" + "ab" * 8)
    assert rc == 1 and "is NOT among" in out, out


def test_no_anchors_is_said_and_can_be_required(client, owner, tmp_path):
    scenario(client, owner)
    d = export_to(client, tmp_path / "pack")
    rc, out = run_verify(d, "--offline")
    assert rc == 0 and "anchors: NONE" in out and "trust: the whole history" in out, out
    rc, out = run_verify(d, "--offline", "--require-anchors")
    assert rc == 1 and out.strip().splitlines()[-1] == "RESULT: INVALID", out


# ---------------------------------------------------------------- R7-04
def test_hidden_own_row_in_the_middle_is_found(app, tmp_path):
    p = Person(app).register("Alice")
    k2, r = add_key(p)
    assert r.status_code == 200, r.text
    old = p.keycard["kid_hex"]
    switch_auth(p, k2)
    assert remove_key(p, old).status_code == 200
    k3, r = add_key(p)                                        # a later own row: the removal is not the last one
    assert r.status_code == 200, r.text
    d = export_to(p.c, tmp_path / "pack")
    rc, out = run_verify(d, "--offline")
    assert rc == 0 and "owner tags ok" in out and "1 removed" in out, out

    def strip(files):
        reg = json.loads(files["registry.json"])
        for row in reg["log"]:
            if "row_json" in row and json.loads(row["row_json"])["key_event"]["op"] == "remove":
                row["body"] = __import__("hashlib").sha256(row.pop("row_json").encode()).hexdigest()   # exactly as a foreign row looks
        files["registry.json"] = json.dumps(reg, indent=1).encode()
    rc, out = run_verify(_reseal(app, d, str(tmp_path / "p2"), strip), "--offline")
    assert rc == 1 and "HIDDEN ROW" in out, out


def test_retagging_a_row_breaks_the_second_chain(app, tmp_path):
    p = Person(app).register("Alice")
    Person(app).register("Bob")
    k2, r = add_key(p)
    d = export_to(p.c, tmp_path / "pack")

    def retag(files):
        reg = json.loads(files["registry.json"])
        foreign = next(r for r in reg["log"] if "body" in r)
        for row in reg["log"]:
            if "row_json" in row:
                row["body"] = __import__("hashlib").sha256(row.pop("row_json").encode()).hexdigest()
                row["tag"] = foreign["tag"]                    # pretend it is Bob's
        files["registry.json"] = json.dumps(reg, indent=1).encode()
    rc, out = run_verify(_reseal(app, d, str(tmp_path / "p2"), retag), "--offline")
    assert rc == 1 and "owner tags BROKEN" in out, out


def test_rows_of_an_older_database_are_backfilled(tmp_path):
    kf = tmp_path / "witness_key"
    kf.write_text("a1" * 32)
    cfg = dict(data_dir=str(tmp_path / "data"), witness_key_file=str(kf), key_pepper="test-pepper", rp_id=RP, origin=ORIGIN,
               iss="https://witness.test", anchor="off", web_dir=str(tmp_path / "web"))
    app = create_app(Config(**cfg))
    p = Person(app).register("Alice")
    add_key(p)
    db = sqlite3.connect(os.path.join(cfg["data_dir"], "db.sqlite"))
    db.execute("UPDATE registry_log SET tag=NULL, hash2=NULL")              # as a 0.2.11 database
    db.commit()
    db.close()
    app2 = create_app(Config(**cfg))                                         # start of 0.2.12: backfill
    assert not app2.state.ctx.db.one("SELECT 1 FROM registry_log WHERE hash2 IS NULL")
    p.c = TestClient(app2, base_url=ORIGIN, cookies=p.c.cookies)
    d = export_to(p.c, tmp_path / "pack")
    rc, out = run_verify(d, "--offline")
    assert rc == 0 and "owner tags ok (2 rows" in out, out


def test_pack_without_tags_says_so(client, owner, app, tmp_path):
    scenario(client, owner)
    d = export_to(client, tmp_path / "pack")

    def old(files):
        reg = json.loads(files["registry.json"])
        for row in reg["log"]:
            for k in ("tag", "hash2", "body"):
                row.pop(k, None)
        files["registry.json"] = json.dumps(reg, indent=1).encode()
    rc, out = run_verify(_reseal(app, d, str(tmp_path / "p2"), old), "--offline")
    assert rc == 0 and "owner tags: not in this pack" in out and "trust: no own registry row" in out, out


# ---------------------------------------------------------------- R7-05
def _try(app, code, ip_reset=True):
    if ip_reset:
        app.state.ctx.limiter.w.pop("recovery:testclient", None)            # as if from another address
    return TestClient(app, base_url=ORIGIN).post("/api/auth/recovery/login", json={"code": code}, headers=H).status_code


def _wrong(code):
    """The same lookup group (it reaches the account), a wrong rest."""
    return code[:-1] + ("2" if code[-1] != "2" else "3")


def test_failed_attempts_are_limited_per_account(app):
    a, b = Person(app).register("Alice"), Person(app).register("Bob")
    ca, cb = new_codes(a), new_codes(b)
    for _ in range(10):
        assert _try(app, _wrong(ca[0])) == 401
    assert _try(app, ca[1]) == 429                           # Alice's account is closed for the hour (10 failures against it)
    assert _try(app, cb[0]) == 200                           # Bob's is not


def test_garbage_flood_is_capped_and_does_not_reach_real_codes(app):
    a = Person(app).register("Alice")
    ca = new_codes(a)
    for i in range(300):
        assert app.state.ctx.limiter.hit("recovery:*", 300, 3600)
    assert _try(app, "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ") == 429      # garbage pays the global ceiling
    assert _try(app, ca[0]) == 200                           # the owner's code does not


# ---------------------------------------------------------------- R7-03 / R7-04: what a stamped batch anchors
def _stamp_pending(ctx, bid):
    """Test-side: give the batch a well-formed OpenTimestamps file with a pending attestation (no calendar is contacted)."""
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.serialize import StreamSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    b = ctx.db.one("SELECT root FROM anchor_batches WHERE id=?", (bid,))
    ts = Timestamp(bytes(b["root"]))
    ts.attestations.add(PendingAttestation("https://calendar.test"))
    with open(os.path.join(ctx.anchor_dir, bid + ".ots"), "wb") as f:
        DetachedTimestampFile(OpSHA256(), ts).serialize(StreamSerializationContext(f))
    ctx.db.x("UPDATE anchor_batches SET status='pending' WHERE id=?", (bid,))


def test_stamped_batch_anchors_checkpoints_and_registry(client, owner, app, tmp_path):
    from app import jobs
    scenario(client, owner)
    bid = jobs.anchor_once(app.state.ctx)
    _stamp_pending(app.state.ctx, bid)
    d = export_to(client, tmp_path / "pack")
    rc, out = run_verify(d, "--offline", "--require-anchors")
    assert rc == 0 and "anchors: 1 of 2 checkpoints under a stamped batch" in out and "registry: anchored through row 1" in out, out

    def rebuild(files):                      # the operator rewrites the second chain (new tag of its own row) and re-signs: the anchor disagrees
        import hashlib
        reg = json.loads(files["registry.json"])
        prev2 = b""
        for row in reg["log"]:
            tg = b"\x01" * 16 if "entry_json" in row else bytes.fromhex(row["tag"])
            body = hashlib.sha256(row.get("entry_json", row.get("row_json", "")).encode()).digest() if "body" not in row else bytes.fromhex(row["body"])
            row["tag"] = tg.hex()
            prev2 = hashlib.sha256(b"dw-registry-v2\0" + prev2 + tg + body).digest()
            row["hash2"] = prev2.hex()
        files["registry.json"] = json.dumps(reg, indent=1).encode()
    rc, out = run_verify(_reseal(app, d, str(tmp_path / "p2"), rebuild), "--offline")
    assert rc == 1 and "registry: ANCHOR MISMATCH" in out, out
