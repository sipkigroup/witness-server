"""0.2.83 (Mandate Receipt MR-24): the evidence pack carries the shown object of every signed page (views/<rid>.json,
views/release-<rid>.json), stored when the server accepted the claimed presentation hash. The server's checker (packtools) and the
client's checker (mcp, deus-witness 0.2.52) recompute SHA-256(JCS(object)) and compare it with the hash inside the passkey signature.
Honest pack -> VALID with --require-views; an edited object -> INVALID VIEW_MISMATCH; an older page (no view signed) -> INVALID with
--require-views and a warning without it."""
import json
import os
import shutil
import subprocess

import pytest

from app import signview
from tests.test_0224_critique import Agent
from tests.test_pv2810_view import _approve, _release

MCP = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "mcp")


def _client_verify(folder, *flags):
    py = os.path.join(MCP, ".venv", "bin", "python")
    if not os.path.exists(py):
        pytest.skip("no mcp/.venv: the client's checker is tested in mcp/tests")
    q = subprocess.run([py, "-m", "deus_witness.verify_pack", folder, *flags], capture_output=True, text=True, timeout=120, cwd=MCP)
    return q.returncode, q.stdout + q.stderr


def _signed_pack(app, tmp_path):
    from tests.recovery_helpers import Person, export_to
    p = Person(app).register("Pat")
    a = Agent(p.c, p, tmp_path)
    envf = a.proj + "/.env"                     # 06.11 (Н1): a private key is refused outright now; the project's .env stays a question
    open(envf, "w").write("GH_TOKEN=x\n")
    [(t, v, reason, rid)] = a.tool("Read", {"file_path": envf})
    r, page = _approve(p, rid)
    assert r.status_code == 200, r.text
    a.tool("Write", {"file_path": a.proj + "/tests/test_new.py", "content": "def test_n():\n    pass\n"})
    v, parts = a.line("pytest -q ")
    rid_h = [x[3] for x in parts if x[2] == "ESCALATE_SECRET_SEEN"][0]
    r, rpage = _release(p, rid_h)
    assert r.status_code == 200, r.text
    return p, a, rid, page, rid_h, rpage, export_to(p.c, tmp_path / "pack")


def test_0283_pack_carries_the_shown_objects_and_both_checkers_recompute_them(app, tmp_path):
    from tests.recovery_helpers import run_verify
    p, a, rid, page, rid_h, rpage, folder = _signed_pack(app, tmp_path)
    vo = json.load(open(os.path.join(folder, "views", rid + ".json"), encoding="utf-8"))
    ro = json.load(open(os.path.join(folder, "views", "release-%s.json" % rid_h), encoding="utf-8"))
    import hashlib
    assert hashlib.sha256(signview.jcs(vo)).digest() == page and vo["rid"] == rid and vo["v"] == "dw-view-1"
    assert hashlib.sha256(signview.jcs(ro)).digest() == rpage and ro["rid"] == rid_h
    man = json.load(open(os.path.join(folder, "manifest.json")))
    assert "views/%s.json" % rid in man["files"] and "views/release-%s.json" % rid_h in man["files"]
    assert "verify/mandate_check.py" in man["files"]
    rc, out = run_verify(folder, "--offline", "--require-views")
    assert rc == 0 and out.strip().endswith("RESULT: VALID"), out
    assert "views: 1 shown object(s) hash to the presentation hash the owner signed; 0 without a checkable object" in out, out
    assert "views: 1 release page object(s) hash to the presentation hash the person signed" in out, out
    rc, out2 = _client_verify(folder, "--offline", "--require-views")
    assert rc == 0 and out2.strip().endswith("RESULT: VALID"), out2
    assert "views: 1 shown object(s) hash" in out2 and "views: 1 release page object(s)" in out2, out2


@pytest.mark.parametrize("which", ["approval", "release"])
def test_0283_an_edited_shown_object_is_invalid(app, tmp_path, which):
    """The attacker is whoever hands the pack over (the witness included: it can re-sign the manifest). The object is tied to the
    PASSKEY signature, so a re-sealed manifest does not help: VIEW_MISMATCH."""
    from app.export import seal
    from tests.recovery_helpers import run_verify
    p, a, rid, page, rid_h, rpage, folder = _signed_pack(app, tmp_path)
    key = rid if which == "approval" else "release-" + rid_h
    fp = os.path.join(folder, "views", key + ".json")
    o = json.load(open(fp, encoding="utf-8"))
    o["args_preview"] = "Read: /tmp/harmless.txt"            # what a forger would like the person to have seen
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(o, f)
    # re-seal with the witness key (a dishonest witness can do that); the passkey signature still names the true view
    ctx = app.state.ctx
    files = {}
    for dp, _, fs in os.walk(folder):
        for n in fs:
            full = os.path.join(dp, n)
            rel = os.path.relpath(full, folder)
            if rel not in ("manifest.json", "manifest.cose"):
                files[rel] = open(full, "rb").read()
    import cbor2
    from svidetel_v4 import cose
    signed = cbor2.loads(cose.parse1(open(os.path.join(folder, "manifest.cose"), "rb").read())[2])
    m = json.load(open(os.path.join(folder, "manifest.json")))
    seal(files, ctx.wk, m["account"], m["principal"], m["witness"]["iss"], m["created_t"], signed["cp_seq"], signed["cp_head"])
    for n in ("manifest.json", "manifest.cose"):
        open(os.path.join(folder, n), "wb").write(files[n])
    rc, out = run_verify(folder, "--offline")
    assert rc != 0 and "VIEW_MISMATCH" in out and out.strip().endswith("RESULT: INVALID"), out
    rc, out2 = _client_verify(folder, "--offline")
    assert rc != 0 and "VIEW_MISMATCH" in out2 and "RESULT: INVALID" in out2, out2


def test_0283_an_older_page_has_no_object_and_require_views_says_so(app, tmp_path):
    from tests.recovery_helpers import Person, export_to, run_verify
    p = Person(app).register("Pat")
    a = Agent(p.c, p, tmp_path)
    a.see_secret()                                                             # approved by a page that signed no view
    folder = export_to(p.c, tmp_path / "pack")
    assert not os.path.isdir(os.path.join(folder, "views"))
    rc, out = run_verify(folder, "--offline")
    assert rc == 0 and "warning VIEW_NOT_SIGNED" in out and out.strip().endswith("RESULT: VALID"), out
    rc, out = run_verify(folder, "--offline", "--require-views")
    assert rc != 0 and "VIEW_NOT_SIGNED" in out and out.strip().endswith("RESULT: INVALID"), out


def test_0283_shown_objects_follow_the_preview_retention_and_account_deletion(app, tmp_path):
    from app import jobs
    from app.account_delete import TABLES_BY_ACCOUNT
    assert "shown_views" in TABLES_BY_ACCOUNT
    p, a, rid, page, rid_h, rpage, folder = _signed_pack(app, tmp_path)
    ctx = app.state.ctx
    acc = p.account["id"]
    assert ctx.db.one("SELECT COUNT(*) AS n FROM shown_views WHERE account_id=?", (acc,))["n"] == 2
    import time
    jobs.prune_previews(ctx, now=int(time.time()) + 86400 * (ctx.cfg.preview_keep_days + 1))
    assert ctx.db.one("SELECT COUNT(*) AS n FROM shown_views WHERE account_id=?", (acc,))["n"] == 0
    from tests.recovery_helpers import export_to, run_verify
    f2 = export_to(p.c, tmp_path / "pack2")
    assert not os.path.isdir(os.path.join(f2, "views"))
    rc, out = run_verify(f2, "--offline")
    assert rc == 0 and "warning VIEW_UNVERIFIABLE" in out and out.strip().endswith("RESULT: VALID"), out
    shutil.rmtree(f2)


# ---- purchase: allowed_payees and min_per_action (decision core shared with the client: aar_ref = svidetel_v4) --------------------------
def _pm(**pu):
    from app.mandates import mandate_from_form
    return mandate_from_form({"purchase": dict({"enabled": True, "max_per_action": 40000, "budget": 100000}, **pu)},
                             "p", "agent-1", "webauthn-registration", now=1000)


def test_0283_form_builds_min_and_payees_and_refuses_nonsense():
    from app.context import Err
    from svidetel_v4.schema import validate_mandate
    m = _pm(min_per_action=10000, payees=["merchant-1", "shop.example"])
    assert m["permissions"]["purchase"] == {"max_per_action": 40000, "budget": 100000, "min_per_action": 10000,
                                            "allowed_payees": ["merchant-1", "shop.example"]}
    assert validate_mandate(m) is None
    assert _pm()["permissions"]["purchase"] == {"max_per_action": 40000, "budget": 100000}       # absent = the mandate as before
    assert _pm(min_per_action=0, payees=[])["permissions"]["purchase"] == {"max_per_action": 40000, "budget": 100000}
    for bad in ({"min_per_action": 50000}, {"min_per_action": -1}, {"min_per_action": True}, {"payees": ["a", "a"]}, {"payees": [""]},
                {"payees": "merchant-1"}, {"payees": ["a‮b"]}):
        with pytest.raises(Err):
            _pm(**bad)


def test_0283_schema_refuses_a_malformed_purchase():
    from svidetel_v4.schema import validate_mandate
    m = _pm(min_per_action=10000, payees=["merchant-1"])
    for k, v in (("min_per_action", 50000), ("min_per_action", -5), ("allowed_payees", []), ("allowed_payees", ["a", "a"]),
                 ("allowed_payees", [1]), ("allowed_payees", "merchant-1"), ("allowed_payees", ["x"] * 201), ("payees", ["x"])):
        bad = json.loads(json.dumps(m))
        bad["permissions"]["purchase"][k] = v
        if k == "allowed_payees" and v == ["x"] * 201:
            bad["permissions"]["purchase"][k] = ["x%d" % i for i in range(201)]
        assert validate_mandate(bad) == ("permissions.purchase unknown member" if k == "payees" else "permissions.purchase"), (k, v)


@pytest.mark.parametrize("amount, payee, want", [
    (27999, "merchant-1", ("allow", "OK")),
    (27999, "merchant-999", ("deny", "RECIPIENT")),
    (27999, "Merchant-1", ("deny", "RECIPIENT")),            # byte-exact: no case folding, no canonical form
    (27999, "merchant-1 ", ("deny", "RECIPIENT")),
    (5000, "merchant-1", ("deny", "PER_ACTION_LIMIT")),       # below the signed lower bound
    (10000, "merchant-1", ("allow", "OK")),                   # the bound itself is inside
    (45000, "merchant-1", ("deny", "PER_ACTION_LIMIT")),
    (45000, "merchant-999", ("deny", "RECIPIENT")),           # the payee is checked first
])
def test_0283_decide_payees_and_min(amount, payee, want):
    from svidetel_v4.decide import decide
    m = _pm(min_per_action=10000, payees=["merchant-1"])
    a = {"class": "purchase", "agent": "agent-1", "amount": amount, "currency": "USD", "recipient": payee}
    assert decide(m, a, {}, now=m["nbf"] + 10) == want


def test_0283_old_purchase_mandates_decide_as_before():
    """Every decision vector of the drafts (spec/vectors D*.json) still comes out the same: absent members change nothing."""
    import glob
    from app import _paths
    from svidetel_v4.decide import decide
    n = 0
    for f in sorted(glob.glob(os.path.join(_paths.CORE_DIR, "spec", "vectors", "*.json"))):
        x = json.load(open(f))
        if not isinstance(x, dict) or x.get("kind") != "decision":
            continue
        M = x["input"]["mandate"]
        if M is not None:
            M = dict(M, _sig_valid=x["input"].get("mandate_signature_valid", True))
        assert decide(M, x["input"]["action"], x["input"].get("ledger_state", {}), x["input"].get("now"))[1] == x["expected"]["reason"], f
        n += 1
    assert n >= 100


def test_0283_client_core_is_byte_equal():
    import re
    from app import _paths
    for n in ("decide.py", "schema.py"):
        t = open(os.path.join(_paths.CORE_DIR, "svidetel_v4", n), encoding="utf-8").read().replace("svidetel_v4", "aar_ref")
        assert re.sub(r"PROPOSAL-0\d", "extension", t) == open(os.path.join(MCP, "deus_witness", "verify_pack", "aar_ref", n), encoding="utf-8").read(), n
    a = open(os.path.join(MCP, "deus_witness", "verify_pack", "mandate_check.py"), encoding="utf-8").read().replace("aar_ref", "svidetel_v4")
    b = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packtools", "mandate_check.py"), encoding="utf-8").read()
    assert a.split("\n", 1)[1] == b.split("\n", 1)[1]


def test_0283_allowance_and_later_runs_carry_their_shown_objects(client, owner, tmp_path):
    """The other signing paths (project permission, approval for later runs) store the object too, and the pack verifies with
    --require-views in both checkers."""
    from tests.recovery_helpers import export_to, run_verify
    from tests.test_pv2_view import _allow, _dev, _later, ARGS, act, _expire, _get as g2
    d, rid = _dev(client, owner, tmp_path)
    r, a, page = _allow(d, rid)
    assert r.status_code == 200, r.text
    ag, hdr = owner.new_agent("demo", "night")
    owner.mandate(ag["id"])
    rid2 = act(client, hdr, "publish", ARGS).json()["rid"]
    _expire(client, rid2)
    r2, rids, page2 = _later(owner, rid2, late=True, g=g2(owner, rid2))
    assert r2.status_code == 200, r2.text
    x = act(client, hdr, "publish", ARGS).json()                          # the later run: its APPROVAL entry names the view signed earlier
    assert x["rid"] == rids[0] and x["verdict"] == "allow", x
    folder = export_to(owner.c, tmp_path / "pack")
    assert os.path.isfile(os.path.join(folder, "views", "%s.json" % rids[0]))
    assert os.path.isfile(os.path.join(folder, "views", "allowance-%s.json" % a["id"]))
    rc, out = run_verify(folder, "--offline", "--require-views")
    assert rc == 0 and out.strip().endswith("RESULT: VALID"), out
    rc, out2 = _client_verify(folder, "--offline", "--require-views")
    assert rc == 0 and out2.strip().endswith("RESULT: VALID"), out2
    assert "views: 2 shown object(s) hash to the presentation hash the owner signed; 0 without a checkable object" in out2, out2
