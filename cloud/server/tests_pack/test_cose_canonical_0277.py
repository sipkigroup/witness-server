"""r0277 (plan 13.11): the core COSE verifier (svidetel_v4/cose.py) refuses a non-canonical Ed25519 A or R (RFC 8032 5.1.3) before
OpenSSL sees it. ed25519-speccheck case 11 (A with x = 0 and the sign bit set) passed pyca/cryptography alone; now it does not."""
import json
import os

import cbor2
from svidetel_v4 import cose

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures_0269")


def test_speccheck_case_11_is_refused_by_the_core():
    cases = json.load(open(os.path.join(FIX, "ed25519-speccheck-cases.json")))
    got = [cose.Key.public(cose.ALG_EDDSA, bytes.fromhex(c["pub_key"])).verify(bytes.fromhex(c["signature"]), bytes.fromhex(c["message"]))
           for c in cases]
    assert got[11] is False and got[10] is False                # 10-11: non-canonical A
    assert got[8] is False and got[9] is False                  # 8-9: non-canonical R
    assert got[3] is True                                       # the honest mixed-order case still verifies (cofactorless)


def test_canonical_rule():
    p = 2 ** 255 - 19
    assert cose.ed25519_canonical((1).to_bytes(32, "little"))
    assert not cose.ed25519_canonical((1 | 1 << 255).to_bytes(32, "little"))              # x = 0 with the sign bit
    assert not cose.ed25519_canonical(((p - 1) | 1 << 255).to_bytes(32, "little"))
    assert not cose.ed25519_canonical((p + 1).to_bytes(32, "little"))                     # y >= p
    assert not cose.ed25519_canonical(b"\0" * 31)


def test_a_cose_sign1_under_a_non_canonical_key_is_signature_invalid():
    c = json.load(open(os.path.join(FIX, "ed25519-speccheck-cases.json")))[11]
    k = cose.Key.public(cose.ALG_EDDSA, bytes.fromhex(c["pub_key"]))
    pb = cbor2.dumps({cose.H_ALG: cose.ALG_EDDSA, cose.H_KID: k.kid}, canonical=True)
    raw = cbor2.dumps(cbor2.CBORTag(18, [pb, {}, cbor2.dumps({"a": 1}, canonical=True), bytes.fromhex(c["signature"])]), canonical=True)
    try:
        cose.verify1(raw, [k])
        raise AssertionError("accepted")
    except cose.CoseError as e:
        assert str(e) == "SIGNATURE_INVALID"


def test_honest_keys_still_verify():
    k = cose.Key.generate(cose.ALG_EDDSA)
    for _ in range(64):
        raw = cose.sign1(k, cbor2.dumps({"n": os.urandom(8)}, canonical=True), cose.TYP_ENTRY)
        assert cose.verify1(raw, [cose.Key.public(cose.ALG_EDDSA, k.pub)], cose.TYP_ENTRY)
