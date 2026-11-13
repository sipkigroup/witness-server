"""Team evidence pack through the REAL export (app/export.py, GET /api/export) and the real anchor job with two local test TSAs.
export_org of task 01 does not exist yet -> a fixture module app.org (ARHITEKTURA-0.2 8: the only junction 01 <-> 06).
Mandatory acceptance items: (1) team ledger 3 members, 2 of 3 -> VALID with org/quorum/batch lines; (2) policy v2 replaced -> BROKEN;
(5) .tsr over another digest -> tsa MISMATCH; (6) --offline opens no socket."""
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import time
import types
import zipfile

import pytest

import app as app_pkg
from app import jobs
import wa_profile as wa
import wq_profile as q
from forms import mandate_from_form
from svidetel_v4.state import approval_payload, revocation_payload
from tests.helpers import ORIGIN, RP
import tsa as T
from kit import CHECKER, SOLO_RULES, Team, auth, cde, lines, member, members, pol, reseal, run_verify, team_ledger

ROLES3 = ["owner", "budget", "access"]


def build_team_pack(app, client, owner, dest, monkeypatch):
    """Owner registered on the server (pinned passkey) + two more members; policy v1 (genesis) -> v2 (3 members, money_over 50000:
    budget k=2); mandate 200000 signed by 2 of 3; one purchase allowed; three publishes approved by ONE batch envelope; one publish
    approved by a one-signer quorum; revocation by one member. Then anchor (TSA on), export, unzip."""
    ctx = app.state.ctx
    aid, principal = owner.account["id"], owner.account["principal"]
    entry = ctx.hub.entry_of(aid)
    team = Team({"own": owner.auth, "bea": auth("bea"), "cy": auth("cy")}, RP, ORIGIN)
    now = int(time.time())
    P1 = pol(principal, 1, None, [member(owner.auth, ROLES3, "Ann")], SOLO_RULES)
    P2 = pol(principal, 2, P1, members(member(owner.auth, ["owner", "budget"], "Ann"), member(team.A["bea"], ["budget"], "Bea"),
                                      member(team.A["cy"], ["budget", "access"], "Cy")))
    chain, pols = team.chain([(P1, ["own"], now - 200), (P2, ["own"], now - 100)])
    with ctx.hub.lock(aid):
        L = team_ledger(ctx.hub.ledger_dir(aid), ctx.wk, principal, entry, chain, team.rp, time.time)
        M = mandate_from_form({"currency": "USD", "valid_days": 30, "purchase": {"enabled": True, "budget": 200000, "max_per_action": 100000}},
                              principal, "ag_team", entry["pin_source"], now=now)
        r = L.register_mandate(M, cose_bytes=team.wq(["bea", "own"], wa.TYP_MANDATE, cde(M), P2))
        assert r["result"] == "accept", r
        assert L.authorize("r_buy1", M["id"], {"agent": "ag_team", "class": "purchase", "recipient": "vendor.example", "data": [],
                                               "amount": 60000, "currency": "USD"})["verdict"] == "allow"
        rids = ["r_pub%d" % i for i in range(4)]
        for rid in rids:
            v = L.authorize(rid, M["id"], {"agent": "ag_team", "class": "publish", "recipient": "blog", "data": []}, ttl=900)
            assert v["verdict"] == "defer", v
        pays = [approval_payload(M, L.S.receipts[rid]["action"], rid, True) for rid in rids]
        wb = team.wb("cy", pays[:3])
        for rid in rids[:3]:
            assert L.approve(rid, cose_bytes=wb)["result"] == "accept"
        assert L.approve(rids[3], cose_bytes=team.wq(["cy"], wa.TYP_APPROVAL, pays[3], P2))["result"] == "accept"
        assert L.revoke(M["id"], cose_bytes=team.wq(["bea"], wa.TYP_REVOCATION, revocation_payload(M), P2))["result"] == "accept"
    rel = q.release_payload("r_adv1", "ab" * 32, True)
    org = {"principal": principal, "policies": pols,
           "coverage": {"ag_team": {"level": "C2", "unwitnessed": [], "tool": "doctor-0.2"}},
           "advisory": [{"rid": "r_adv1", "args_sha256": "ab" * 32, "release": True, "envelope": team.wa("cy", q.TYP_RELEASE, rel)}]}
    mod = types.ModuleType("app.org")
    mod.export_org = lambda c, a: org if a == aid else None
    monkeypatch.setitem(sys.modules, "app.org", mod)
    monkeypatch.setattr(app_pkg, "org", mod, raising=False)
    bid = jobs.anchor_once(ctx, tsa=True)
    res = client.get("/api/export")
    assert res.status_code == 200, res.text
    zipfile.ZipFile(io.BytesIO(res.content)).extractall(dest)
    return {"dir": str(dest), "bid": bid, "team": team, "P1": P1, "P2": P2, "principal": principal, "ctx": ctx}


@pytest.fixture()
def team_pack(app, client, owner, tmp_path, monkeypatch, providers):
    return build_team_pack(app, client, owner, tmp_path / "pack", monkeypatch)


def copy(tp, tmp_path, name):
    d = str(tmp_path / name)
    shutil.copytree(tp["dir"], d)
    return d


def test_1_team_pack_valid(team_pack):
    d, bid = team_pack["dir"], team_pack["bid"]
    for f in ("org/policy-v1.cbor", "org/policy-v2.cbor", "org/policy-v2.env.cbor", "org/chain.json", "coverage/ag_team.json",
              "advisory/r_adv1.json", "verify/wq_profile.py", "verify/registry_wa.py", "verify/registry_wq.py", "verify/tsa.py",
              "anchors/%s.tsr.tsa-a" % bid, "anchors/%s.tsr.tsa-b" % bid, "anchors/tsa-ca/tsa-a.pem", "anchors/tsa-ca/tsa-b.pem"):
        assert os.path.isfile(os.path.join(d, f)), f
    rc, out = run_verify(d, "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    assert "org policy: chain ok (v1..v2)" in out
    assert "quorum: 6/6 entries meet policy-at-time" in out
    assert "batch approvals: 1 envelopes, 3 items" in out
    assert "tsa %s: OK (tsa-a, tsa-b)" % bid in out
    assert "coverage ag_team: C2 (operator-declared, not verified)" in out
    assert "advisory: 1/1 releases signed" in out
    # the same verdict from the checker of the source tree (not the pack's copy)
    rc2, out2 = run_verify(d, "--offline", checker=CHECKER)
    assert rc2 == 0 and "quorum: 6/6" in out2, out2


def test_1b_pack_copies_are_byte_exact(team_pack):
    d = team_pack["dir"]
    man = json.load(open(os.path.join(d, "manifest.json")))
    from app import _paths
    src = open(os.path.join(_paths.CONTRACT_DIR, "v02", "wq_profile.py"), "rb").read()
    assert man["files"]["verify/wq_profile.py"] == hashlib.sha256(src).hexdigest()
    reg = open(os.path.join(os.path.dirname(_paths.__file__), "registry_wa.py"), "rb").read()
    assert man["files"]["verify/registry_wa.py"] == hashlib.sha256(reg).hexdigest()
    readme = open(os.path.join(d, "README.txt")).read()
    assert "witness's clock" in readme and "operator's proxy DECLARED" in readme and "Swift checker" in readme


def test_2_policy_v2_substituted(team_pack, tmp_path):
    d = copy(team_pack, tmp_path, "p2")
    p = os.path.join(d, "org", "policy-v2.cbor")
    m = q.cbor2.loads(open(p, "rb").read())
    m["members"][0]["label"] = "Mallory"
    open(p, "wb").write(cde(m))
    rc, out = run_verify(d, "--offline")
    assert rc == 1 and lines(out, "org policy: BROKEN") and out.strip().splitlines()[-1] == "RESULT: INVALID", out
    reseal(d, team_pack["ctx"].wk)                    # even with a fresh manifest, the chain itself is broken
    rc, out = run_verify(d, "--offline")
    assert rc == 1 and "org policy: BROKEN POLICY_SIG@v2" in out and "RESULT: INVALID" in out, out


def test_2b_forged_but_well_signed_v2_does_not_cover_the_ledger(team_pack, tmp_path):
    """The owner alone may sign a new v2 under v1's rule; but the ledger's quorums name the REAL v2 -> the ledger fails."""
    tp = team_pack
    d = copy(tp, tmp_path, "p2b")
    P2f = dict(tp["P2"], members=[m for m in tp["P2"]["members"] if m["label"] == "Ann"],
               rules=SOLO_RULES)
    P2f["members"] = [dict(P2f["members"][0], roles=["owner", "budget", "access"])]
    pb = cde(P2f)
    open(os.path.join(d, "org", "policy-v2.cbor"), "wb").write(pb)
    open(os.path.join(d, "org", "policy-v2.env.cbor"), "wb").write(tp["team"].wq(["own"], q.TYP_POLICY, pb, tp["P1"]))
    cj = json.load(open(os.path.join(d, "org", "chain.json")))
    cj["versions"][1]["hash"] = hashlib.sha256(pb).hexdigest()
    json.dump(cj, open(os.path.join(d, "org", "chain.json"), "w"))
    reseal(d, tp["ctx"].wk)
    rc, out = run_verify(d, "--offline")
    assert "org policy: chain ok (v1..v2)" in out
    assert rc == 1 and "ledger: invalid" in out and "RESULT: INVALID" in out, out


def test_5_tsr_over_foreign_digest(team_pack, tmp_path, tsas):
    d = copy(team_pack, tmp_path, "p5")
    bid = team_pack["bid"]
    other = tsas["tsa-a"].respond(T.make_query(hashlib.sha256(b"another root").digest())[0])
    open(os.path.join(d, "anchors", "%s.tsr.tsa-a" % bid), "wb").write(other)
    reseal(d, team_pack["ctx"].wk)
    rc, out = run_verify(d, "--offline")
    assert rc == 1 and "tsa %s: MISMATCH (tsa-a: TSA_IMPRINT)" % bid in out and out.strip().splitlines()[-1] == "RESULT: INVALID", out


def test_5b_foreign_tsa_root_caught_with_trusted_roots(team_pack, tmp_path, tsas):
    """A pack author can bring his own 'TSA' and its root; --tsa-ca=<roots you trust> catches it."""
    import testtsa
    d = copy(team_pack, tmp_path, "p5b")
    bid = team_pack["bid"]
    root = bytes.fromhex(json.load(open(os.path.join(d, "anchors", bid + ".json")))["root"])
    fake = testtsa.TestTSA("Test TSA A", kind="ec")
    open(os.path.join(d, "anchors", "%s.tsr.tsa-a" % bid), "wb").write(fake.respond(T.make_query(root)[0]))
    open(os.path.join(d, "anchors", "tsa-ca", "tsa-a.pem"), "wb").write(fake.root_pem)
    reseal(d, team_pack["ctx"].wk)
    rc, out = run_verify(d, "--offline")
    assert rc == 0 and "tsa-ca tsa-a: sha256" in out, out          # self-consistent: only the root fingerprint line warns
    trusted = tmp_path / "roots"
    trusted.mkdir()
    for n, t in tsas.items():
        (trusted / (n + ".pem")).write_bytes(t.root_pem)
    rc, out = run_verify(d, "--offline", "--tsa-ca=%s" % trusted)
    assert rc == 1 and "tsa %s: MISMATCH (tsa-a: TSA_CHAIN)" % bid in out, out


HOOK = r"""
import os, runpy, sys
def hook(ev, args):
    if ev.startswith("socket."):
        sys.stderr.write("SOCKET-OPENED %s\n" % ev); sys.stderr.flush(); os._exit(3)
sys.addaudithook(hook)
if sys.argv[1] == "--probe":
    import socket; socket.socket()
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
"""


def test_6_offline_opens_no_socket(team_pack):
    d = team_pack["dir"]
    chk = os.path.join(d, "verify", "verify_pack.py")
    p = subprocess.run([sys.executable, "-I", "-c", HOOK, "--probe"], capture_output=True, text=True)
    assert p.returncode == 3 and "SOCKET-OPENED" in p.stderr            # the hook does catch a socket
    p = subprocess.run([sys.executable, "-I", "-c", HOOK, chk, d, "--offline"], capture_output=True, text=True, timeout=120)
    assert p.returncode == 0 and "SOCKET-OPENED" not in p.stderr and "RESULT: VALID" in p.stdout, p.stdout + p.stderr
    assert "tsa " in p.stdout and "quorum: 6/6" in p.stdout
