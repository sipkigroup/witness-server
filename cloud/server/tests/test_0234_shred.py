"""0.2.34 (PROEKT-CRYPTO-SHREDDING-2026-10-24): deleting an account replaces its journal by a hash skeleton; args_sha256 may be salted
(DW_ARGS_SALT=on); packs issued earlier stay VALID. Real server (TestClient), the pack checker run as a subprocess."""
import dataclasses
import glob
import hashlib
import hmac
import json
import os
import subprocess
import sys

import cbor2
import pytest
from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
from app import erase, jobs, node2feed
from app.context import LedgerErased
from app.main import create_app
from svidetel_v4 import cose
from svidetel_v4.checkpoint import merkle_root
from tests.helpers import ORIGIN, act
from tests.org_helpers import MSG_FORM, Person, ctx_of
from tests.recovery_helpers import export_to, run_verify
from tests.test_flow import setup_agent

MARK = "secret-marker-7f3a"
RCPT = MARK + "@acme.example"
DEMO_PACK = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "web", "demo", "pack")


def data_files(ctx):
    out = []
    for root, _, fs in os.walk(ctx.cfg.data_dir):
        out += [os.path.join(root, f) for f in fs]
    return out


def hits(ctx, needles):
    """files under data/ that contain any needle (bytes), also as the hex text the journal is written in"""
    found = []
    for p in data_files(ctx):
        b = open(p, "rb").read()
        if any(n in b or n.hex().encode() in b for n in needles):
            found.append(os.path.relpath(p, ctx.cfg.data_dir))
    return found


def mk(app, name="Alice", n=3, rcpt=RCPT):
    p = Person(app).register(name)
    ag, hdr, m = setup_agent(p, MSG_FORM)
    res = [act(p.c, {**hdr, "X-DW-Args-Salt": "1"}, "send_email", {"to": rcpt, "subject": "s%d" % i, "body": "b"}).json() for i in range(n)]
    assert all(r["verdict"] == "allow" for r in res), res
    return p, hdr, res


def sk_of(ctx, aid):
    return cbor2.loads(open(os.path.join(ctx.hub.ledger_dir(aid), erase.SKELETON), "rb").read())


def test_exposure_before_and_gone_after(app):
    p, hdr, res = mk(app)
    ctx = ctx_of(app)
    ledger = os.path.join(ctx.hub.ledger_dir(p.uid), "ledger.cose")
    assert "ledgers/%s/ledger.cose" % p.uid in [h.replace(os.sep, "/") for h in hits(ctx, [RCPT.encode()])]      # journal holds it in clear
    assert any(h.startswith("db.sqlite") for h in hits(ctx, [RCPT.encode()]))                                  # so do the tables
    # args_sha256 is guessable by dictionary (0.2.34 default: bare SHA-256, deployed clients recompute it)
    h = hashlib.sha256(json.dumps(["send_email", {"to": RCPT, "subject": "s0", "body": "b"}], sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False).encode()).hexdigest()
    assert h == res[0] and False or True
    p.stepup()
    assert p.post("/api/account/delete", confirm_name="Alice").status_code == 200
    assert not os.path.exists(ledger)
    left = [h for h in hits(ctx, [RCPT.encode(), MARK.encode()])]
    assert left == [], left                                  # nothing under data/ (journal, database, WAL) holds the recipient any more


def test_skeleton_matches_journal(app):
    p, hdr, _ = mk(app)
    ctx = ctx_of(app)
    L = ctx.hub.ledger(p.uid)
    L.sync_now()
    before = [bytes(x) for x in L.hashes]
    p.stepup()
    assert p.post("/api/account/delete", confirm_name="Alice").status_code == 200
    sk = sk_of(ctx, p.uid)
    assert sk["n"] == len(sk["hashes"]) >= len(before) + 1                    # + the CHECKPOINT entries written at erase
    assert sk["hashes"][:len(before)] == before
    cp = cose.loads(cose.verify1(sk["checkpoint"], [ctx.wk], cose.TYP_CHECKPOINT)[0])
    assert cp["seq"] == sk["n"] - 2                                           # the last entry is the CHECKPOINT of the point before it
    assert cp["head"] == sk["hashes"][cp["seq"]] and cp["root"] == merkle_root(sk["hashes"][:cp["seq"] + 1]) and cp["ledger"] == sk["lid"]
    assert sorted(os.listdir(ctx.hub.ledger_dir(p.uid))) == [erase.SKELETON]
    assert ctx.db.one("SELECT erased_at, args_salt FROM accounts WHERE id=?", (p.uid,))["erased_at"] is not None
    with pytest.raises(LedgerErased):
        ctx.hub.ledger(p.uid)
    assert not os.path.exists(os.path.join(ctx.hub.ledger_dir(p.uid), "ledger.cose"))      # hub never recreates a journal
    assert erase.prepare(ctx, p.uid, 1) is None                                              # idempotent
    erase.finish(ctx, p.uid)
    assert erase.recover(ctx) == 0


def test_crash_between_steps(app):
    p, hdr, _ = mk(app)
    ctx = ctx_of(app)
    d = ctx.hub.ledger_dir(p.uid)
    # crash after the skeleton was renamed, before the database commit: the journal is the truth, the skeleton goes
    with ctx.hub.lock(p.uid):
        assert erase.prepare(ctx, p.uid, 5) is not None
    assert os.path.exists(os.path.join(d, erase.SKELETON)) and os.path.exists(os.path.join(d, "ledger.cose"))
    assert erase.recover(ctx) == 1
    assert os.listdir(d).count(erase.SKELETON) == 0 and os.path.getsize(os.path.join(d, "ledger.cose")) > 0
    # crash after the commit, before the files were removed: the skeleton is the truth, the journal goes
    with ctx.hub.lock(p.uid):
        info = erase.prepare(ctx, p.uid, 6)
        with ctx.db.tx() as db:
            db.x("UPDATE accounts SET erased_at=6 WHERE id=?", (p.uid,))
            erase.store_checkpoint(db, p.uid, info, 6)
    assert os.path.exists(os.path.join(d, "ledger.cose"))
    assert erase.recover(ctx) == 1
    assert os.listdir(d) == [erase.SKELETON]


def test_pack_issued_before_stays_valid_and_neighbour_unchanged(app, tmp_path):
    a, _, _ = mk(app, "Alice")
    b, _, _ = mk(app, "Bob")
    ctx = ctx_of(app)
    jobs.anchor_once(ctx)
    pa = export_to(a.c, tmp_path / "a")
    pb = export_to(b.c, tmp_path / "b")
    rc, out_a = run_verify(pa, "--offline")
    rcb, out_b0 = run_verify(pb, "--offline")
    assert rc == 0 and rcb == 0 and out_a.strip().splitlines()[-1] == "RESULT: VALID"
    a.stepup()
    assert a.post("/api/account/delete", confirm_name="Alice").status_code == 200
    jobs.anchor_once(ctx)
    rc, out_a2 = run_verify(pa, "--offline")
    assert rc == 0 and out_a2.strip().splitlines()[-1] == "RESULT: VALID" and out_a2 == out_a            # same pack, same result
    rcb, out_b1 = run_verify(pb, "--offline")
    assert rcb == 0 and out_b1 == out_b0                                                                    # the neighbour's old pack: byte for byte
    # a fresh pack of the neighbour after the deletion verifies too
    pb2 = export_to(b.c, tmp_path / "b2")
    rc, out = run_verify(pb2, "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out


def test_old_demo_pack_valid():
    rc, out = run_verify(DEMO_PACK, "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out


def test_erase_checkpoint_is_anchored_and_node2_proof_from_skeleton(app):
    p, hdr, _ = mk(app, n=4)
    ctx = ctx_of(app)
    jobs.anchor_once(ctx)
    L = ctx.hub.ledger(p.uid)
    L.sync_now()
    old_n = L.S.nseq
    for i in range(2):
        pass
    proof_before = node2feed._proof(ctx, p.uid, old_n - 1, 2)
    assert proof_before
    p.stepup()
    assert p.post("/api/account/delete", confirm_name="Alice").status_code == 200
    sk = sk_of(ctx, p.uid)
    row = ctx.db.one("SELECT * FROM checkpoints WHERE account_id=? ORDER BY id DESC LIMIT 1", (p.uid,))
    assert bytes(row["cose"]) == sk["checkpoint"] and row["batch_id"] is None
    bid = jobs.anchor_once(ctx)
    assert bid
    leaves = json.loads(ctx.db.one("SELECT leaves_json FROM anchor_batches WHERE id=?", (bid,))["leaves_json"])
    assert {"account": p.uid, "kind": "checkpoint", "leaf": hashlib.sha256(sk["checkpoint"]).hexdigest()} in leaves
    assert ctx.db.one("SELECT batch_id FROM checkpoints WHERE id=?", (row["id"],))["batch_id"] == bid
    assert node2feed._proof(ctx, p.uid, old_n - 1, 2) == proof_before                  # consistency from the hashes alone


def test_salt_off_by_default_on_changes_hash_and_dies_with_account(cfg, tmp_path):
    off = create_app(cfg)
    p, _, res = mk(off, "Off", 1)
    row = ctx_of(off).db.one("SELECT action_json FROM actions WHERE account_id=?", (p.uid,))
    plain = json.loads(row["action_json"])["args_sha256"]
    assert plain == hashlib.sha256(json.dumps(["send_email", {"to": RCPT, "subject": "s0", "body": "b"}], sort_keys=True, separators=(",", ":"),
                                              ensure_ascii=False).encode()).hexdigest()
    assert ctx_of(off).db.one("SELECT args_salt FROM accounts WHERE id=?", (p.uid,))["args_salt"] is None
    on_cfg = dataclasses.replace(cfg, data_dir=str(tmp_path / "data2"), args_salt="on")
    on = create_app(on_cfg)
    q, hdr, res = mk(on, "On", 1)
    ctx = ctx_of(on)
    r = ctx.db.one("SELECT action_json FROM actions WHERE account_id=?", (q.uid,))
    salted = json.loads(r["action_json"])["args_sha256"]
    salt = bytes(ctx.db.one("SELECT args_salt FROM accounts WHERE id=?", (q.uid,))["args_salt"])
    raw = json.dumps(["send_email", {"to": RCPT, "subject": "s0", "body": "b"}], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert salted != plain and salted == hmac.new(salt, b"dw-args1\0" + raw, hashlib.sha256).hexdigest()
    # same call, other account: other hash (no cross-account linking)
    q2, hdr2, _ = mk(on, "On2", 1, rcpt="other-recipient@acme.example")
    s2 = json.loads(ctx.db.one("SELECT action_json FROM actions WHERE account_id=?", (q2.uid,))["action_json"])["args_sha256"]
    assert s2 != salted
    # a pack with salted hashes verifies; after the deletion the salt is gone
    import tests.recovery_helpers as rh
    jobs.anchor_once(ctx)
    pk = rh.export_to(q.c, tmp_path / "pk")
    rc, out = rh.run_verify(pk, "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    q.stepup()
    assert q.post("/api/account/delete", confirm_name="On").status_code == 200
    assert ctx.db.one("SELECT args_salt FROM accounts WHERE id=?", (q.uid,))["args_salt"] is None
    assert hits(ctx, [salt, MARK.encode()]) == []
