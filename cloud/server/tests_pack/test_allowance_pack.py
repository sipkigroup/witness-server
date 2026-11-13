import pytest
"""0.2.10 (PROPOSAL-07): an exported evidence pack with ALLOWANCE / ALLOWANCE_END entries verifies offline (the checker shipped in the pack and the
trusted one): the owner's wa-sig over the allowance, the mandate hash it names, and every OK_ALLOWANCE receipt replayed from them."""
import os
import sys

from app import jobs
from kit import CHECKER, run_verify
from test_solo_pack import export

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from tests.test_allowance_0210 import Dev  # noqa: E402
from tests.helpers import H  # noqa: E402


@pytest.mark.xfail(strict=False, reason="0.2.90 (OTCHET-0258.md): re-check under the standing mandate -- a literal variable is substituted, an exit / D12 refusal is not what 0.2.89 expected")
def test_pack_with_allowances_is_valid(client, owner, app, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    d = Dev(client, owner, proj.resolve())
    [(_, r)] = d.send("pytest")
    res, a = d.allowance(r["rid"])
    assert res.status_code == 200
    [(_, ok)] = d.send("pytest -q")
    assert ok["reason"] == "OK_ALLOWANCE"
    assert client.post("/v1/actions/%s/present" % ok["rid"], json={}, headers=d.hdr).json()["result"] == "accept"
    assert client.post("/api/allowances/%s/revoke" % a["id"], headers=H).status_code == 200
    assert d.verdicts("pytest") == [("Bash", "defer", "ESCALATE_COMMAND")]
    jobs.anchor_once(app.state.ctx, tsa=False)
    out_dir = export(client, tmp_path / "pack")
    for chk in (None, CHECKER):
        rc, out = run_verify(out_dir, "--offline", checker=chk)
        assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
