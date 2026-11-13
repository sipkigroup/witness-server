"""(4) A single-owner pack (0.1.1 shape: no organisation policy) -> RESULT: VALID with no org/quorum/batch lines, through the real
server and export; with TSA tokens it also carries the tsa line. A pack made by the 0.1.x export (no verify/wq_profile.py,
no verify/tsa.py) still verifies with the new checker."""
import io
import os
import zipfile

from app import jobs
from tests.test_pack import scenario
from kit import CHECKER, run_verify

ORG_PREFIXES = ("org policy", "quorum", "batch approvals", "coverage", "advisory")


def export(client, dest):
    r = client.get("/api/export")
    assert r.status_code == 200
    zipfile.ZipFile(io.BytesIO(r.content)).extractall(dest)
    return str(dest)


def test_4_solo_pack_valid_without_org_lines(client, owner, app, tmp_path):
    scenario(client, owner)
    jobs.anchor_once(app.state.ctx, tsa=False)
    d = export(client, tmp_path / "solo")
    assert not os.path.exists(os.path.join(d, "org"))
    for chk in (None, CHECKER):
        rc, out = run_verify(d, "--offline", checker=chk)
        assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
        assert "receipts: 3/3 included" in out
        assert not [ln for ln in out.splitlines() if ln.startswith(ORG_PREFIXES + ("tsa",))], out


def test_4b_pack_of_the_01x_layout_still_valid(client, owner, app, tmp_path):
    """The 0.1.x export had no verify/wq_profile.py, verify/registry_wq.py, verify/tsa.py: the trusted checker does not need them
    for a single-owner pack (it imports its own modules; manifest lists only what the pack has)."""
    import json
    from kit import reseal
    scenario(client, owner)
    d = export(client, tmp_path / "old")
    for f in ("verify/wq_profile.py", "verify/registry_wq.py", "verify/tsa.py"):
        os.remove(os.path.join(d, f))
    man = json.load(open(os.path.join(d, "manifest.json")))
    assert "verify/tsa.py" in man["files"]
    reseal(d, app.state.ctx.wk)
    rc, out = run_verify(d, "--offline", checker=CHECKER)
    assert rc == 0 and "RESULT: VALID" in out and "org policy" not in out, out


def test_4c_solo_pack_with_tsa(client, owner, app, tmp_path, providers):
    scenario(client, owner)
    bid = jobs.anchor_once(app.state.ctx, tsa=True)
    d = export(client, tmp_path / "solo-tsa")
    rc, out = run_verify(d, "--offline")
    assert rc == 0 and "tsa %s: OK (tsa-a, tsa-b)" % bid in out and "org policy" not in out, out
