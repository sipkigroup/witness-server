"""Second pass (policy-at-time, approval requirements from the RECEIPT) on ledgers written DIRECTLY through the core with QuorumRegistry,
bypassing the server. Mandatory acceptance item (3): an entry signed under v2 after v3 removed the signer -> WQ_POLICY_STALE,
built from the exact bytes of contract vector w15 (task 00); w16 (same envelope, written in time) is the control."""
import json
import os

import cbor2
import pytest

from app import _paths
import wa_profile as wa
import wq_profile as q
from forms import mandate_from_form
from svidetel_v4 import cose
from svidetel_v4.state import approval_payload
from kit import SOLO_RULES, Team, auth, cde, lines, member, members, pol, run_verify, team_ledger, write_pack

VEC = os.path.join(_paths.CONTRACT_DIR, "v02", "vectors", "wq")
RP, ORIGIN = "witness.test", "https://witness.test"
PRINCIPAL = "dw:" + "ab" * 16
WK = cose.Key.from_seed(cose.ALG_EDDSA, b"\x11" * 32)


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def vector_book(tmp_path, name):
    v = json.load(open(os.path.join(VEC, name + ".json")))
    chain = [(bytes.fromhex(c["policy_hex"]), bytes.fromhex(c["envelope_hex"]), c["t"]) for c in v["chain"]]
    owner = auth("owner")
    g = cbor2.loads(chain[0][0])
    assert g["members"][0]["pub"] == owner.pub               # the vectors' genesis is our pinned key
    principal = g["principal"]
    entry = owner.reg_entry(v["rp"]["rp_id"], v["rp"]["origins"])
    L = team_ledger(str(tmp_path / "led"), WK, principal, entry, chain, v["rp"], Clock(v["at"]))
    r = L.register_mandate(cbor2.loads(bytes.fromhex(v["payload_hex"])), cose_bytes=bytes.fromhex(v["envelope_hex"]))
    assert r["result"] == "accept", r                          # the core (stateless registry) accepts it: only the 2nd pass can catch it
    org = {"principal": principal, "policies": [{"ver": i + 1, "policy": pb, "envelope": e, "t": t} for i, (pb, e, t) in enumerate(chain)]}
    return write_pack(str(tmp_path / "pack"), WK, principal, entry, L, org)


def test_3_signer_removed_in_v3_signed_by_v2_after_v3(tmp_path):
    d = vector_book(tmp_path, "w15-policy-stale")
    rc, out = run_verify(d, "--offline")
    assert "org policy: chain ok (v1..v3)" in out and "ledger: valid" in out, out
    assert rc == 1 and "quorum: FAIL WQ_POLICY_STALE@0" in out and out.strip().splitlines()[-1] == "RESULT: INVALID", out


def test_3_control_same_envelope_in_time(tmp_path):
    d = vector_book(tmp_path, "w16-policy-in-force-at-time")
    rc, out = run_verify(d, "--offline")
    assert rc == 0 and "quorum: 1/1 entries meet policy-at-time" in out and "RESULT: VALID" in out, out


# ------------------------------------------------------------ own keys: one book per test
class Book:
    def __init__(self, tmp_path, t0=1790000000):
        self.tmp = tmp_path
        self.team = Team({n: auth("sp-" + n) for n in ("own", "b1", "b2", "cy", "mal")}, RP, ORIGIN)
        self.entry = self.team.A["own"].reg_entry(RP, [ORIGIN])
        self.clock = Clock(t0)
        A = self.team.A
        self.P1 = pol(PRINCIPAL, 1, None, [member(A["own"], ["owner", "budget", "access"], "own")], SOLO_RULES)
        self.P2 = pol(PRINCIPAL, 2, self.P1, members(member(A["own"], ["owner"], "own"), member(A["b1"], ["budget"], "b1"),
                                                      member(A["b2"], ["budget"], "b2"), member(A["cy"], ["access"], "cy")))
        # v3 removes cy (the only access holder), so the access tiers go too (00: an unsatisfiable rule is POLICY_MALFORMED)
        self.P3 = pol(PRINCIPAL, 3, self.P2, [m for m in self.P2["members"] if m["label"] != "cy"],
                      dict(self.P2["rules"], mandate=self.P2["rules"]["mandate"][:2], approval=self.P2["rules"]["approval"][:2]))

    def open(self, versions):
        self.chain, self.pols = self.team.chain(versions)
        self.L = team_ledger(str(self.tmp / "led"), WK, PRINCIPAL, self.entry, self.chain, self.team.rp, self.clock)
        return self.L

    def mandate(self, form, at):
        self.clock.t = at
        return mandate_from_form(dict({"currency": "USD", "valid_days": 30}, **form), PRINCIPAL, "ag_x", "webauthn-registration:test", now=at - 10)

    def pack(self, chain_override=None):
        org = {"principal": PRINCIPAL, "policies": chain_override or self.pols}
        return write_pack(str(self.tmp / "pack"), WK, PRINCIPAL, self.entry, self.L, org)


BIG = {"purchase": {"enabled": True, "budget": 200000, "max_per_action": 100000}}
SMALL = {"purchase": {"enabled": True, "budget": 10000, "max_per_action": 5000}}


def test_owner_plain_wa_sig_after_policy_counts_as_one_signer(tmp_path):
    """A 0.1-style wa-sig of the pinned owner key passes the core, but after v2 it must meet v2: budget k=2 -> WQ_QUORUM."""
    b = Book(tmp_path)
    L = b.open([(b.P1, ["own"], 1790000000), (b.P2, ["own"], 1790000100)])
    M = b.mandate(BIG, 1790000200)
    assert L.register_mandate(M, cose_bytes=b.team.wa("own", wa.TYP_MANDATE, cde(M)))["result"] == "accept"
    rc, out = run_verify(b.pack(), "--offline")
    assert "ledger: valid" in out and rc == 1 and "quorum: FAIL WQ_QUORUM@0" in out, out


def test_owner_wa_sig_before_policy_is_solo_mode(tmp_path):
    b = Book(tmp_path)
    L = b.open([(b.P1, ["own"], 1790000100), (b.P2, ["own"], 1790000200)])
    M = b.mandate(BIG, 1790000000)                             # written BEFORE the genesis: solo 0.1 rules
    assert L.register_mandate(M, cose_bytes=b.team.wa("own", wa.TYP_MANDATE, cde(M)))["result"] == "accept"
    M2 = b.mandate(BIG, 1790000300)
    assert L.register_mandate(M2, cose_bytes=b.team.wq(["b1", "b2"], wa.TYP_MANDATE, cde(M2), b.P2))["result"] == "accept"
    rc, out = run_verify(b.pack(), "--offline")
    assert rc == 0 and "quorum: 1/1 entries meet policy-at-time" in out, out


@pytest.mark.parametrize("signers,ok", [(["b1"], False), (["b1", "b2"], True)])
def test_approval_requirement_from_receipt_action(tmp_path, signers, ok):
    """Refund of 60000 defers (no refund permission); approval rule money_over 50000 needs budget k=2. The core cannot see it
    (the approval payload carries only the action hash); the second pass takes the action from the RECEIPT."""
    b = Book(tmp_path)
    L = b.open([(b.P1, ["own"], 1790000000), (b.P2, ["own"], 1790000100)])
    M = b.mandate(SMALL, 1790000200)
    assert L.register_mandate(M, cose_bytes=b.team.wq(["b1"], wa.TYP_MANDATE, cde(M), b.P2))["result"] == "accept"
    act = {"agent": "ag_x", "class": "refund", "recipient": "client", "data": [], "amount": 60000, "currency": "USD"}
    assert L.authorize("r_ref", M["id"], act, ttl=900)["verdict"] == "defer"
    pay = approval_payload(M, L.S.receipts["r_ref"]["action"], "r_ref", True)
    assert L.approve("r_ref", cose_bytes=b.team.wq(signers, wa.TYP_APPROVAL, pay, b.P2))["result"] == "accept"
    rc, out = run_verify(b.pack(), "--offline")
    if ok:
        assert rc == 0 and "quorum: 2/2 entries meet policy-at-time" in out, out
    else:
        seq = [ln for ln in out.splitlines() if ln.startswith("quorum:")]
        assert rc == 1 and seq == ["quorum: FAIL WQ_QUORUM@2"], out


def test_batch_by_member_removed_before_entry(tmp_path):
    """wb of 'cy' (access) approved after v3 removed cy: the core finds cy in v2 and accepts; second pass -> WQ_NOT_MEMBER."""
    b = Book(tmp_path)
    L = b.open([(b.P1, ["own"], 1790000000), (b.P2, ["own"], 1790000100), (b.P3, ["own"], 1790000500)])
    M = b.mandate(SMALL, 1790000200)
    assert L.register_mandate(M, cose_bytes=b.team.wq(["b1"], wa.TYP_MANDATE, cde(M), b.P2))["result"] == "accept"
    rids = ["r_p1", "r_p2"]
    for rid in rids:
        assert L.authorize(rid, M["id"], {"agent": "ag_x", "class": "publish", "recipient": "blog", "data": []}, ttl=900)["verdict"] == "defer"
    wb = b.team.wb("cy", [approval_payload(M, L.S.receipts[r]["action"], r, True) for r in rids])
    assert L.approve(rids[0], cose_bytes=wb)["result"] == "accept"     # t = 1790000200: cy is a member of v2
    b.clock.t = 1790000600
    assert L.approve(rids[1], cose_bytes=wb)["result"] == "accept"     # t after v3
    rc, out = run_verify(b.pack(), "--offline")
    assert rc == 1 and lines(out, "quorum:") == ["quorum: FAIL WQ_NOT_MEMBER@4"], out
    assert "batch approvals: 1 envelopes, 2 items" in out


def test_genesis_not_signed_by_pinned_key(tmp_path):
    b = Book(tmp_path)
    A = b.team.A
    G = pol(PRINCIPAL, 1, None, [member(A["mal"], ["owner", "budget", "access"], "mal")], SOLO_RULES)
    L = b.open([(G, ["mal"], 1790000000)])
    M = b.mandate(SMALL, 1789990000)
    assert L.register_mandate(M, cose_bytes=b.team.wa("own", wa.TYP_MANDATE, cde(M)))["result"] == "accept"
    rc, out = run_verify(b.pack(), "--offline")
    assert rc == 1 and "org policy: BROKEN KEY_MISMATCH@v1" in out and "quorum: not checked" in out, out


def test_policy_times_must_increase(tmp_path):
    b = Book(tmp_path)
    L = b.open([(b.P1, ["own"], 1790000100), (b.P2, ["own"], 1790000050)])
    M = b.mandate(SMALL, 1789990000)
    assert L.register_mandate(M, cose_bytes=b.team.wa("own", wa.TYP_MANDATE, cde(M)))["result"] == "accept"
    rc, out = run_verify(b.pack(), "--offline")
    assert rc == 1 and "org policy: BROKEN POLICY_TIME@v2" in out, out


def test_wq_naming_unknown_policy_breaks_the_ledger(tmp_path):
    """A quorum under a policy that is not in org/ cannot even pass the first pass."""
    b = Book(tmp_path)
    L = b.open([(b.P1, ["own"], 1790000000), (b.P2, ["own"], 1790000100)])
    M = b.mandate(BIG, 1790000200)
    assert L.register_mandate(M, cose_bytes=b.team.wq(["b1", "b2"], wa.TYP_MANDATE, cde(M), b.P2))["result"] == "accept"
    rc, out = run_verify(b.pack(chain_override=b.pols[:1]), "--offline")
    assert rc == 1 and "ledger: invalid" in out, out
