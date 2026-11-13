"""Interop pack set (19.10.2026, OTCHET-INTEROP-PACK, ambiguities 1-10): packs with a PREDICTED verdict, checked here with the Python checker and
(when DEUS_PACK_OUT is set) copied to <out>/<name>/ with <out>/<name>.expected ("VALID"/"INVALID" + the key line) for the Swift run:
`aarc-wa verify-pack <out>/<name>`. Cases: promise kept with a stand-in .ots (no network), a stamped status without .ots, a failed batch that does not
cover P.seq, E5-3 (money_over, class without limits), E5-5 (ver != position), E5-7 (wb with a wrong typ)."""
import glob
import io
import os
import shutil
import time
import zipfile

import cbor2
import pytest

from app import export as exp
from app import jobs
import wa_profile as wa
import wq_profile as q
from registry_wq import QuorumRegistry
from svidetel_v4.state import approval_payload
from tests.helpers import act, promises_on, promises_off
from tests.test_flow import setup_agent
from tests.test_pack import scenario
from kit import SOLO_RULES, auth, cde, lines, member, members, pol, reseal, run_verify
from test_second_pass import BIG, Book, PRINCIPAL, SMALL

OUT = os.environ.get("DEUS_PACK_OUT")


def emit(name, d, verdict, key=""):
    """Run the Python checker on d, assert the predicted verdict and key line, copy the pack to OUT for the Swift run."""
    rc, out = run_verify(d, "--offline")
    last = out.strip().splitlines()[-1]
    assert last == "RESULT: " + verdict, out
    assert key in out, out
    if OUT:
        dst = os.path.join(OUT, name)
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(d, dst)
        open(dst + ".expected", "w").write("%s %s\n" % (verdict, key))
    return out


def write_ots(path, root_hex, bitcoin_height=None):
    """A stand-in confirmation: a valid detached OpenTimestamps file over the batch root with a pending (or, offline, a Bitcoin) attestation."""
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.serialize import StreamSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(bytes.fromhex(root_hex))
    ts.attestations.add(BitcoinBlockHeaderAttestation(bitcoin_height) if bitcoin_height else PendingAttestation("https://calendar.invalid"))
    with open(path, "wb") as f:
        DetachedTimestampFile(OpSHA256(), ts).serialize(StreamSerializationContext(f))


def fake_stamper(height=None):
    class _S:
        @staticmethod
        def stamp(root, out):
            write_ots(out, root, height)
            return ["https://calendar.invalid"]
    return _S


def export_at(client, dest, monkeypatch, shift=0):
    real = time.time
    if shift:
        monkeypatch.setattr(exp.time, "time", lambda: real() + shift)
    r = client.get("/api/export")
    monkeypatch.setattr(exp.time, "time", real)
    zipfile.ZipFile(io.BytesIO(r.content)).extractall(dest)
    return str(dest)


# ---------------------------------------------------------------- promises with a .ots (ambiguity 8: "anchored")
@pytest.mark.parametrize("height,name", [(None, "kept-ots-pending"), (812345, "kept-ots-bitcoin")])
def test_promise_kept_with_substitute_ots(client, owner, app, tmp_path, monkeypatch, height, name):
    promises_on(app)
    scenario(client, owner)
    monkeypatch.setattr(jobs, "_anchor_mod", lambda: fake_stamper(height))
    jobs.anchor_once(app.state.ctx, tsa=False)                           # anchor "on": status pending + .ots
    d = export_at(client, tmp_path / "p", monkeypatch)
    assert glob.glob(os.path.join(d, "anchors", "*.ots"))
    out = emit(name, d, "VALID", " kept")
    assert "PROMISE_LATE" not in out and "pending" not in [ln for ln in out.splitlines() if ln.startswith("promises:")][0].split(", ")[0]


def test_stamped_status_without_ots_is_not_anchored(client, owner, app, tmp_path, monkeypatch):
    """verify.md 0.2.6: status `pending` in the record but no .ots in the pack = a claim, not a stamp -> the checkpoint is not anchored -> late."""
    promises_on(app)
    scenario(client, owner)
    monkeypatch.setattr(jobs, "_anchor_mod", lambda: fake_stamper())
    jobs.anchor_once(app.state.ctx, tsa=False)
    d = export_at(client, tmp_path / "p", monkeypatch, shift=2 * 3600)
    for f in glob.glob(os.path.join(d, "anchors", "*.ots")):
        os.remove(f)
    reseal(d, app.state.ctx.wk)
    emit("pending-status-no-ots", d, "INVALID", "PROMISE_LATE")


def test_ots_over_another_digest_python_only(client, owner, app, tmp_path, monkeypatch):
    """Not in the scope of C-WA (it does not read .ots): Python says MISMATCH; recorded to show the divergence honestly."""
    promises_on(app)
    scenario(client, owner)
    monkeypatch.setattr(jobs, "_anchor_mod", lambda: fake_stamper())
    jobs.anchor_once(app.state.ctx, tsa=False)
    d = export_at(client, tmp_path / "p", monkeypatch)
    for f in glob.glob(os.path.join(d, "anchors", "*.ots")):
        write_ots(f, "ab" * 32)
    reseal(d, app.state.ctx.wk)
    emit("ots-foreign-digest-python-only", d, "INVALID", "MISMATCH (.ots commits to another digest)")


# ---------------------------------------------------------------- ambiguity 9: a disclosure must cover P.seq
def test_failed_batch_covers_all_is_disclosed(client, owner, app, tmp_path, monkeypatch):
    promises_on(app)
    scenario(client, owner)

    class _Fail:
        @staticmethod
        def stamp(root, out):
            raise SystemExit("calendars unreachable")
    monkeypatch.setattr(jobs, "_anchor_mod", lambda: _Fail)
    jobs.anchor_once(app.state.ctx, tsa=False)
    d = export_at(client, tmp_path / "p", monkeypatch, shift=2 * 3600)
    emit("failed-batch-covers", d, "VALID", "PROMISE_UNMET_DISCLOSED")


def test_failed_batch_not_covering_later_promise_is_late(client, owner, app, tmp_path, monkeypatch):
    """Failed batch for an EARLY checkpoint; later decisions have promises beyond it (seq > covered) and nothing discloses them -> PROMISE_LATE."""
    promises_on(app)
    ctx = app.state.ctx
    ag, hdr, _ = setup_agent(owner)
    act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s", "body": "b"})

    class _Fail:
        @staticmethod
        def stamp(root, out):
            raise SystemExit("calendars unreachable")
    monkeypatch.setattr(jobs, "_anchor_mod", lambda: _Fail)
    jobs.anchor_once(ctx, tsa=False)                                      # failed batch over the checkpoint after the first decision
    promises_on(app)                                                      # a new promise needs a fresh good run (stand-in)
    for i in range(2):
        act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s%d" % i, "body": "b"})
    d = export_at(client, tmp_path / "p", monkeypatch, shift=2 * 3600)
    out = emit("failed-batch-not-covering", d, "INVALID", "PROMISE_LATE")
    assert "PROMISE_UNMET_DISCLOSED" in out                                # the early promise IS disclosed, the later ones are not


# ---------------------------------------------------------------- E5-3, E5-5, E5-7 through the core (Book of test_second_pass)
def _no_limits(M, cls="purchase"):
    M["permissions"][cls] = {}
    return M


def test_e5_3_money_over_class_without_limits(tmp_path):
    """purchase {} contributes level 0 (ERRATA-05 E5-3): `money` (k=1) fires, `money_over 50000` (k=2) does not -> ONE budget member is enough: VALID.
    (The control, a mandate above 50000 signed by one member, is refused by the core itself; the vectors errata05/E5-3 cover the function.)"""
    b = Book(tmp_path)
    L = b.open([(b.P1, ["own"], 1790000000), (b.P2, ["own"], 1790000100)])
    M = _no_limits(b.mandate(SMALL, 1790000200))
    r = L.register_mandate(M, cose_bytes=b.team.wq(["b1"], wa.TYP_MANDATE, cde(M), b.P2))
    assert r["result"] == "accept", r
    emit("e53-no-limits-one-budget", b.pack(), "VALID", "quorum: 1/1 entries meet policy-at-time")


def test_e5_3_class_true_is_unbounded_two_needed(tmp_path):
    """refund: true is unbounded (greater than every X): money_over fires, k=2. Two budget members: VALID; the same with the second pass reading `{}` as
    unbounded would also be VALID, so the discriminating pack is the one above; this one fixes that two signers always pass."""
    b = Book(tmp_path)
    L = b.open([(b.P1, ["own"], 1790000000), (b.P2, ["own"], 1790000100)])
    M = b.mandate(SMALL, 1790000200)
    M["permissions"] = {"refund": True}
    r = L.register_mandate(M, cose_bytes=b.team.wq(["b1", "b2"], wa.TYP_MANDATE, cde(M), b.P2))
    assert r["result"] == "accept", r
    emit("e53-true-two-budget", b.pack(), "VALID", "quorum: 1/1 entries meet policy-at-time")


def test_e5_5_version_not_equal_to_position(tmp_path):
    b = Book(tmp_path)
    P3skip = pol(PRINCIPAL, 3, b.P1, b.P2["members"])                     # v1 then "v3": position 2 carries ver 3 (gap)
    L = b.open([(b.P1, ["own"], 1790000000), (P3skip, ["own"], 1790000100)])
    M = b.mandate(SMALL, 1789990000)
    assert L.register_mandate(M, cose_bytes=b.team.wa("own", wa.TYP_MANDATE, cde(M)))["result"] == "accept"
    emit("e55-ver-not-position", b.pack(), "INVALID", "org policy: BROKEN POLICY_CHAIN@v2")


@pytest.mark.parametrize("typ,key,name", [
    (wa.TYP_REVOCATION, "APPROVAL_SIG", "e57-wb-revocation-typ-in-approval"),       # registered typ, but not the one the APPROVAL context expects
    ("application/x-nonsense", "WB_MALFORMED", "e57-wb-unregistered-typ"),          # not a registered wb typ at all
])
def test_e5_7_wb_wrong_typ(tmp_path, monkeypatch, typ, key, name):
    b = Book(tmp_path)
    L = b.open([(b.P1, ["own"], 1790000000), (b.P2, ["own"], 1790000100)])
    M = b.mandate(SMALL, 1790000200)
    assert L.register_mandate(M, cose_bytes=b.team.wq(["b1"], wa.TYP_MANDATE, cde(M), b.P2))["result"] == "accept"
    assert L.authorize("r_p1", M["id"], {"agent": "ag_x", "class": "publish", "recipient": "blog", "data": []}, ttl=900)["verdict"] == "defer"
    pay = approval_payload(M, L.S.receipts["r_p1"]["action"], "r_p1", True)
    a = b.team.A["cy"]
    items = [__import__("hashlib").sha256(pay).digest()]
    ad, cd, der = a.get_assertion(q.wb_challenge(items, typ), b.team.rp_id, b.team.origin)
    env = q.make_wb(items, a.kid, ad, cd, der, typ=typ)
    real = QuorumRegistry.check            # the live registry refuses such a wb (APPROVAL_SIG); the pack checker must catch what a faulty or hostile writer put in
    monkeypatch.setattr(QuorumRegistry, "check", lambda self, principal, signed_by=None, cose_bytes=None, expect_payload=None, typ=None: None if q.envelope_kind(cose_bytes or b"") == "wb" else real(self, principal, signed_by, cose_bytes, expect_payload, typ))
    r = L.approve("r_p1", cose_bytes=env)
    monkeypatch.setattr(QuorumRegistry, "check", real)
    assert r["result"] == "accept", r                                       # the core is stateless here: the pack checker must catch it
    emit(name, b.pack(), "INVALID", key)


# ---------------------------------------------------------------- ambiguity 1: a REFUSAL (approved=false) under money_over
@pytest.mark.parametrize("signer,verdict,key,name", [
    ("b1", "VALID", "quorum: 2/2 entries meet policy-at-time", "refusal-one-budget-member"),     # one holder of a role the approval rule names (budget), k=2 not needed
    ("cy", "INVALID", "quorum: FAIL WQ_QUORUM@2", "refusal-member-without-named-role"),         # cy holds `access` only: the approval rule for a refund names `budget`
])
def test_refusal_needs_one_signer_with_a_named_role(tmp_path, signer, verdict, key, name):
    b = Book(tmp_path)
    L = b.open([(b.P1, ["own"], 1790000000), (b.P2, ["own"], 1790000100)])
    M = b.mandate(SMALL, 1790000200)
    assert L.register_mandate(M, cose_bytes=b.team.wq(["b1"], wa.TYP_MANDATE, cde(M), b.P2))["result"] == "accept"
    act_ = {"agent": "ag_x", "class": "refund", "recipient": "client", "data": [], "amount": 60000, "currency": "USD"}
    assert L.authorize("r_ref", M["id"], act_, ttl=900)["verdict"] == "defer"
    pay = approval_payload(M, L.S.receipts["r_ref"]["action"], "r_ref", False)
    r = L.approve("r_ref", approved=False, cose_bytes=b.team.wq([signer], wa.TYP_APPROVAL, pay, b.P2))
    assert r["result"] == "accept", r
    emit(name, b.pack(), verdict, key)
