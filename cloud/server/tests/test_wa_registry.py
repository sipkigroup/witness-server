import glob
import json
import os

import cbor2
import pytest

import wa_profile as wa
from app.registry_wa import WaRegistry
from svidetel_v4 import cose
from app import _paths

VEC = sorted(glob.glob(os.path.join(_paths.CONTRACT_DIR, "vectors", "wa", "*.json")))


@pytest.mark.parametrize("path", VEC, ids=[os.path.basename(p)[:-5] for p in VEC])
def test_contract_wa_vectors_through_waregistry(path):
    v = json.load(open(path))
    reg = WaRegistry.for_account("dw:p", v["reg_entry"])
    got = reg.check("dw:p", None, bytes.fromhex(v["envelope_hex"]), bytes.fromhex(v["payload_hex"]), v["typ"])
    assert got == v["expect"]


def test_vectors_present():
    assert len(VEC) >= 17


def test_unpinned_principal():
    v = json.load(open(VEC[-1]))
    reg = WaRegistry.for_account("dw:p", v["reg_entry"])
    assert reg.check("dw:other", None, bytes.fromhex(v["envelope_hex"]), b"", v["typ"]) == "KEY_NOT_PINNED"


def test_plain_cose_path_equals_registry():
    k = cose.Key.generate(cose.ALG_EDDSA)
    reg = WaRegistry({"p": {"alg": "EdDSA", "pub": k.pub.hex(), "name": "n"}}, "src")
    good = cose.sign1(k, cbor2.dumps({"a": 1}, canonical=True), cose.TYP_MANDATE)
    assert reg.check("p", None, good, cbor2.dumps({"a": 1}, canonical=True), cose.TYP_MANDATE) is None
    assert reg.check("p", None, good, b"other", cose.TYP_MANDATE) == "MANDATE_SIG"
    bad = cose.sign1(cose.Key.generate(cose.ALG_EDDSA), cbor2.dumps({"a": 1}, canonical=True), cose.TYP_MANDATE)
    assert reg.check("p", None, bad, cbor2.dumps({"a": 1}, canonical=True), cose.TYP_MANDATE) == "KEY_MISMATCH"
    assert reg.key("p").kid == k.kid and reg.source == "src"
