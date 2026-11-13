"""r0271 (ISPYTANIE-0266-1311 Н2): the public log stays consistent when ANOTHER process writes it.

Before: the server's tree was read once per process; after `python -m app.jobs anchor-once` (deploy/restore-drill.sh) /checkpoint served a
stale size and refused the inclusion proof of the new leaf; after `python -m app.jobs tlog-stamp` (signs the bigger size) it answered
503 TLOG_INCONSISTENT until restarted. Now the leaves another process wrote are read before every checkpoint and proof.
The second process here is a real one (subprocess, the same database file), with the external anchor and the TSA off (no network)."""
import os
import subprocess
import sys

import tlogcheck as TC
from app import jobs
from tests.test_pack import scenario

SERVER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _other_process(cfg, cmd):
    env = dict(os.environ, DW_DATA_DIR=cfg.data_dir, DW_WITNESS_KEY_FILE=cfg.witness_key_file, DW_KEY_PEPPER="test-pepper",
               DW_RP_ID=cfg.rp_id, DW_ORIGIN=cfg.origin, DW_ISS=cfg.iss, DW_ANCHOR="off", DW_TLOG_TSA="off")
    env.pop("DW_TSA_URL", None)
    r = subprocess.run([sys.executable, "-m", "app.jobs", cmd], cwd=SERVER, env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, (cmd, r.stdout[-2000:], r.stderr[-2000:])


def _cp(client):
    r = client.get("/checkpoint")
    assert r.status_code == 200, r.text
    vk = client.get("/tlog/vkey").text.strip()
    return TC.open_checkpoint(r.text, [vk])


def _all_included(client, cp):
    for i in range(cp["size"]):
        lf = client.get("/tlog/leaf", params={"index": i}).json()
        pr = client.get("/tlog/proof/inclusion", params={"index": i, "size": cp["size"]})
        assert pr.status_code == 200, (i, pr.text)
        assert TC.verify_inclusion(TC.leaf_hash(TC.b64d(lf["leaf_b64"])), i, cp["size"], [TC.b64d(x) for x in pr.json()["path"]],
                                   cp["root"]), i


def test_two_processes_write_the_log(client, owner, app, cfg):
    ctx = app.state.ctx
    assert _cp(client)["size"] == 0                        # the server holds its tree in memory from here on
    scenario(client, owner)
    _other_process(cfg, "anchor-once")                     # restore-drill.sh does this: a batch and its leaf, written elsewhere
    cp1 = _cp(client)
    assert cp1["size"] == 1, cp1                           # was: size 0 (stale tree), inclusion for size 1 -> 400
    _all_included(client, cp1)
    scenario(client, owner)
    jobs.anchor_once(ctx)                                  # this process writes too
    scenario(client, owner)
    _other_process(cfg, "anchor-once")
    _other_process(cfg, "tlog-stamp")                      # the other process SIGNS the bigger size (was: 503 TLOG_INCONSISTENT here)
    cp3 = _cp(client)
    assert cp3["size"] == 3, cp3
    _all_included(client, cp3)
    cons = client.get("/tlog/proof/consistency", params={"old": 1, "new": 3}).json()
    assert TC.verify_consistency(1, 3, cp1["root"], cp3["root"], [TC.b64d(x) for x in cons["path"]])
    # the note the other process signed and the one the server serves are the same signed text (one root per size)
    stored = ctx.db.one("SELECT note FROM tlog_checkpoints WHERE size=3")["note"]
    assert client.get("/checkpoint").text == stored
    scenario(client, owner)
    jobs.anchor_once(ctx)
    cp4 = _cp(client)
    assert cp4["size"] == 4 and ctx.db.one("SELECT COUNT(*) AS n FROM tlog_leaves")["n"] == 4
    _all_included(client, cp4)
    idx = [r["idx"] for r in ctx.db.q("SELECT idx FROM tlog_leaves ORDER BY idx")]
    assert idx == [0, 1, 2, 3]
