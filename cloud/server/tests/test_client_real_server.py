"""0.2.6: the SDK / proxy / hook client verifies the receipt of the REAL server. Found 19.10.2026: every `allow` was blocked (AAR_REQUEST_MISMATCH),
because the client hashed the action without the wire->CBOR conversion of `toolmap_sha256` that the server (app/wire.py) and the page (web/js/cde.js) apply.
The mcp tests ran against contract/stub.py, whose actions carry no `toolmap_sha256`, so they never saw it; the server tests' shim hid the difference on the signing side.
This file uses the real server (TestClient) and the client code (mcp/deus_witness) and never the shim: it calls wa.cde_raw / wire.cbor_form explicitly."""
import base64
import os
import sys

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))
from deus_witness import client as dwc  # noqa: E402
from deus_witness.client import AARError, verify_aar  # noqa: E402

from app import _paths  # noqa: F401,E402
import wa_profile as wa  # noqa: E402
from app import wire  # noqa: E402
from tests.helpers import act  # noqa: E402
from tests.test_flow import setup_agent  # noqa: E402


def _allow(client, owner):
    ag, hdr, m = setup_agent(owner)
    r = act(client, hdr, "read_file", {"path": "/a"}).json()
    assert (r["verdict"], r["status"]) == ("allow", "allowed") and r["aar_b64"]
    assert isinstance(r["action"]["toolmap_sha256"], str) and len(r["action"]["toolmap_sha256"]) == 64     # the wire form is hex: this is the case that broke
    pub = client.get("/v1/witness").json()["pub_hex"]
    return r, pub, hdr


def test_allow_is_verified_by_the_client_against_the_real_server(client, owner):
    r, pub, _ = _allow(client, owner)
    aar = verify_aar(dwc.b64u_dec(r["aar_b64"]), pub, r["action"])
    assert aar["verdict"]["decision"] == "allow"


def test_witness_check_with_sent_call(client, owner):
    r, pub, _ = _allow(client, owner)
    w = dwc.Witness.__new__(dwc.Witness)
    w._pub, w.verify, w._salt = bytes.fromhex(pub), True, None      # 0.2.26: no salt (DW_ARGS_SALT off)
    res = dwc.ActionResult.from_json(r)
    assert w.check(res, sent=("read_file", {"path": "/a"})) is res


def test_tampered_action_is_rejected(client, owner):
    r, pub, _ = _allow(client, owner)
    aar = dwc.b64u_dec(r["aar_b64"])
    for k, v in (("amount", 1), ("recipient", "tool:other"), ("toolmap_sha256", "00" * 32)):
        with pytest.raises(AARError) as e:
            verify_aar(aar, pub, dict(r["action"], **{k: v}))
        assert e.value.args[0] == "REQUEST_MISMATCH" or "REQUEST_MISMATCH" in str(e.value)
    flipped = bytearray(aar)
    flipped[-3] ^= 1
    with pytest.raises(AARError):
        verify_aar(bytes(flipped), pub, r["action"])


def test_request_hash_equals_the_servers_binding(client, owner):
    """CANARY: the client's canonicalisation must equal the server's (wire.cbor_form) and the page's CDE; if someone changes one side, this fails."""
    r, pub, _ = _allow(client, owner)
    import cbor2
    payload = cbor2.loads(dwc.b64u_dec(r["aar_b64"])).value[2]
    bound = cbor2.loads(payload)["action"]["binding_request_hash"]
    import hashlib
    assert dwc.request_hash(r["action"]) == bound == hashlib.sha256(wa.cde_raw(wire.cbor_form(r["action"]))).digest()


VECTORS = [
    {"a": 1}, {"toolmap_sha256": "ab" * 32}, {"toolmap_sha256": "AB" * 32}, {"toolmap_sha256": "ab" * 32 + "\n"}, {"toolmap_sha256": "ab" * 31},
    {"toolmap_sha256": b"\x01" * 32}, {"toolmap_sha256": 5}, {"x": {"toolmap_sha256": "ab" * 32}}, {"toolmap_sha256": "١" * 64}, [],
]


@pytest.mark.parametrize("v", VECTORS, ids=range(len(VECTORS)))
def test_client_and_server_canonicalisation_agree(v):
    assert dwc.cbor_form(v) == wire.cbor_form(v)


def test_shim_equals_production():
    """CANARY for the test shim (testshim.py): the shim must be exactly wa.cde_raw(wire.cbor_form(x)); a shim that drifts hides client/server differences."""
    for v in VECTORS:
        if isinstance(v, dict):
            assert wa.cde(v) == wa.cde_raw(wire.cbor_form(v))
