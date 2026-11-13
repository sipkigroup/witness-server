"""0.2.4: the evidence pack carries the inclusion promises and the tool map documents; the checker judges them (draft-deus-aar-05 9.5, 8.6)."""
import glob
import hashlib
import io
import json
import os
import zipfile

import cbor2

from app import _paths  # noqa: F401
from app import jobs
from svidetel_v4 import cose
from tests.helpers import promises_on, promises_off
from tests.test_pack import scenario as _scenario
from kit import CHECKER, reseal, run_verify


def scenario(client, owner):
    promises_on(client.app)             # 0.2.5: no promise without DW_ANCHOR=on and a fresh anchor run
    out = _scenario(client, owner)
    promises_off(client.app)            # the tests below call jobs.anchor_once: no stamping, status "off"
    return out


def export(client, dest):
    r = client.get("/api/export")
    assert r.status_code == 200
    zipfile.ZipFile(io.BytesIO(r.content)).extractall(dest)
    return str(dest)


def test_pack_has_promises_and_toolmap_and_checker_reports_them(client, owner, app, tmp_path):
    scenario(client, owner)
    jobs.anchor_once(app.state.ctx, tsa=False)
    d = export(client, tmp_path / "p")
    ps = glob.glob(os.path.join(d, "promises", "*.promise.cose"))
    tms = glob.glob(os.path.join(d, "toolmaps", "*.cbor"))
    assert len(ps) >= 4 and len(tms) == 1
    assert os.path.basename(tms[0])[:-5] == hashlib.sha256(open(tms[0], "rb").read()).hexdigest()
    rc, out = run_verify(d, "--offline", checker=CHECKER)
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    assert "promises: %d pending" % len(ps) in out            # anchor is off in tests: nothing is anchored yet, nothing is late
    assert "toolmaps: 1 mandate(s) bind a tool map, 1 document(s) present" in out


def test_a_toolmap_file_that_does_not_hash_to_its_name_is_invalid(client, owner, app, tmp_path):
    scenario(client, owner)
    d = export(client, tmp_path / "p")
    f = glob.glob(os.path.join(d, "toolmaps", "*.cbor"))[0]
    doc = cbor2.loads(open(f, "rb").read())
    doc["tools"]["extra"] = {"class": "pass"}
    open(f, "wb").write(cbor2.dumps(doc, canonical=True))
    reseal(d, app.state.ctx.wk)
    rc, out = run_verify(d, "--offline", checker=CHECKER)
    assert rc == 1 and "toolmaps: MISMATCH" in out and "RESULT: INVALID" in out, out


def test_a_foreign_promise_is_ignored_a_broken_one_invalidates(client, owner, app, tmp_path):
    scenario(client, owner)
    ctx = app.state.ctx
    d = export(client, tmp_path / "p")
    f = sorted(glob.glob(os.path.join(d, "promises", "*.promise.cose")))[0]
    pl = cose.loads(cose.verify1(open(f, "rb").read(), [ctx.wk], cose.TYP_PROMISE)[0])
    other = cose.Key.from_seed(cose.ALG_EDDSA, bytes([9]) * 32)
    open(f, "wb").write(cose.sign1(other, cbor2.dumps(pl, canonical=True), cose.TYP_PROMISE))
    reseal(d, ctx.wk)
    rc, out = run_verify(d, "--offline", checker=CHECKER)
    assert rc == 0 and "RESULT: VALID" in out and "1 PROMISE_SIG" in out, out
    # the witness key signs a promise whose entry hash is not the ledger's: two statements about one position
    bad = dict(pl, entry=b"\x00" * 32)
    open(f, "wb").write(cose.sign1(ctx.wk, cbor2.dumps(bad, canonical=True), cose.TYP_PROMISE))
    reseal(d, ctx.wk)
    rc, out = run_verify(d, "--offline", checker=CHECKER)
    assert rc == 1 and "PROMISE_BROKEN" in out and "RESULT: INVALID" in out, out


def test_a_promise_is_kept_when_the_checkpoint_is_anchored(client, owner, app, tmp_path):
    """The checker function with an anchored set (a stamped batch is needed for the real thing; the anchor is off in tests)."""
    import verify_pack as vp
    from svidetel_v4.verify import load_entries
    scenario(client, owner)
    ctx = app.state.ctx
    jobs.anchor_once(ctx, tsa=False)
    d = export(client, tmp_path / "p")
    cps = {int(os.path.basename(p)[:-5]): open(p, "rb").read() for p in glob.glob(os.path.join(d, "checkpoints", "*.cose"))}
    ents = load_entries(os.path.join(d, "ledger", "ledger.cose"), [ctx.wk])
    anchored = {hashlib.sha256(cps[max(cps)]).hexdigest()}
    lines = vp._promises(d, ctx.wk, ents, cps, anchored, {"created_t": 2 ** 31})
    assert lines and not any(bad for _, bad in lines) and "kept" in lines[-1][0], lines
