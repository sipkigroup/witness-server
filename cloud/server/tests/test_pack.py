import io
import json
import os
import subprocess
import sys
import zipfile

from app import jobs
from svidetel_v4.checkpoint import verify_inclusion
from tests.helpers import H, act

SERVER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def scenario(client, owner):
    from tests.test_flow import setup_agent
    ag, hdr, _ = setup_agent(owner)
    r = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s", "body": "b"}).json()
    client.post("/v1/actions/%s/present" % r["rid"], json={}, headers=hdr)
    act(client, hdr, "purchase", {"vendor": "v.example", "amount_cents": 5000})
    act(client, hdr, "send_email", {"to": "x@evil.example", "subject": "s", "body": "b"})
    d = act(client, hdr, "publish", {"channel": "blog", "text": "hello"}).json()
    owner.approve(d["rid"])
    act(client, hdr, "publish", {"channel": "blog", "text": "hello"})
    return ag, hdr


def unpack(client, dest):
    r = client.get("/api/export")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    zipfile.ZipFile(io.BytesIO(r.content)).extractall(dest)
    return dest


def run_verify(folder, *flags):
    p = subprocess.run([sys.executable, "-I", os.path.join(folder, "verify", "verify_pack.py"), folder, *flags], capture_output=True, text=True)
    return p.returncode, p.stdout


def test_pack_valid_and_tamper(client, owner, app, tmp_path):
    scenario(client, owner)
    jobs.anchor_once(app.state.ctx)
    d = str(unpack(client, tmp_path / "pack"))
    for f in ("README.txt", "manifest.json", "registry.json", "ledger/ledger.cose", "verify/verify_pack.py", "verify/wa_profile.py",
              "verify/svidetel_v4/verify.py", "web_js_sha256.json"):
        assert os.path.exists(os.path.join(d, f)), f
    assert os.listdir(os.path.join(d, "receipts")) and os.listdir(os.path.join(d, "checkpoints")) and os.listdir(os.path.join(d, "anchors"))
    rc, out = run_verify(d, "--offline")
    assert "RESULT: VALID" in out and rc == 0, out
    assert out.strip().splitlines()[-1] == "RESULT: VALID"
    assert "ledger: valid (" in out and "receipts: 3/3 included" in out
    # tamper: remove a row of the ledger in a copy
    import shutil
    d2 = str(tmp_path / "pack2")
    shutil.copytree(d, d2)
    p = os.path.join(d2, "ledger", "ledger.cose")
    lines = open(p).read().split("\n")
    del lines[2]
    open(p, "w").write("\n".join(lines))
    rc, out = run_verify(d2, "--offline")
    assert rc == 1 and "RESULT: INVALID" in out and "CHAIN_BREAK" in out, out
    # tamper: a receipt byte
    d3 = str(tmp_path / "pack3")
    shutil.copytree(d, d3)
    rp = os.path.join(d3, "receipts", sorted(os.listdir(os.path.join(d3, "receipts")))[0])
    b = bytearray(open(rp, "rb").read())
    b[-3] ^= 1
    open(rp, "wb").write(bytes(b))
    rc, out = run_verify(d3, "--offline")
    assert rc == 1 and "RESULT: INVALID" in out


def test_pack_empty_account(client, owner, tmp_path):
    d = str(unpack(client, tmp_path / "p"))
    rc, out = run_verify(d, "--offline")
    assert rc == 0 and "RESULT: VALID" in out and "receipts: 0/0" in out


def test_pack_foreign_ledger_row_detected(client, owner, app, tmp_path):
    scenario(client, owner)
    d = str(unpack(client, tmp_path / "p"))
    man = json.load(open(os.path.join(d, "manifest.json")))
    man["witness"]["pub_hex"] = "00" * 32
    json.dump(man, open(os.path.join(d, "manifest.json"), "w"))
    rc, out = run_verify(d, "--offline")
    assert rc == 1


def test_anchor_off_batch_and_merkle_path(client, owner, owner2, app):
    scenario(client, owner)
    from tests.test_flow import setup_agent
    setup_agent(owner2)
    ctx = app.state.ctx
    bid = jobs.anchor_once(ctx)
    assert bid
    b = ctx.db.one("SELECT * FROM anchor_batches WHERE id=?", (bid,))
    leaves = json.loads(b["leaves_json"])
    assert [l["kind"] for l in leaves] == ["checkpoint", "checkpoint", "registry", "registry2"]       # 0.2.12 (R7-04): the ownership chain too
    from svidetel_v4.checkpoint import inclusion_path, merkle_root
    lv = [bytes.fromhex(l["leaf"]) for l in leaves]
    assert merkle_root(lv) == bytes(b["root"])
    for i in range(len(lv)):
        assert verify_inclusion(lv[i], inclusion_path(lv, i), bytes(b["root"]), i, len(lv))
    assert b["status"] == "off"
    cps = ctx.db.q("SELECT * FROM checkpoints WHERE batch_id=?", (bid,))
    assert len(cps) == 2 and all(bytes(c["digest"]).hex() in [l["leaf"] for l in leaves] for c in cps)
    assert os.path.exists(os.path.join(ctx.anchor_dir, bid + ".json"))
    # nothing new -> no second batch
    assert jobs.anchor_once(ctx) is None


def test_anchor_cli_off(cfg, tmp_path, client, owner):
    scenario(client, owner)
    env = dict(os.environ, DW_DATA_DIR=cfg.data_dir, DW_WITNESS_KEY_FILE=cfg.witness_key_file, DW_KEY_PEPPER="test-pepper",
               DW_RP_ID=cfg.rp_id, DW_ORIGIN=cfg.origin, DW_ANCHOR="off")
    p = subprocess.run([sys.executable, "-m", "app.jobs", "anchor-once"], cwd=SERVER, env=env, capture_output=True, text=True)
    assert p.returncode == 0 and "recorded" in p.stdout, p.stdout + p.stderr


def test_start_without_key_file_exits(cfg, tmp_path):
    env = dict(os.environ, DW_DATA_DIR=cfg.data_dir, DW_WITNESS_KEY_FILE=str(tmp_path / "missing"), DW_KEY_PEPPER="x", DW_RP_ID="localhost",
               DW_ORIGIN="http://localhost:8810")
    p = subprocess.run([sys.executable, "-m", "app.main", "--port", "8811"], cwd=SERVER, env=env, capture_output=True, text=True, timeout=30)
    assert p.returncode == 2 and "startup refused" in p.stdout
