"""lib/tsa/tsa.py: RFC 3161 request over HTTP (local test TSA, port 8812) and the offline verifier, every failure code."""
import datetime
import hashlib

import pytest
from asn1crypto import tsp

import tsa as T
import testtsa

D = hashlib.sha256(b"batch root").digest()


@pytest.mark.parametrize("name", ["tsa-a", "tsa-b"])
def test_request_and_verify_rsa_and_ecdsa(tsas, tsa_server, name):
    tsr = T.request(D, "%s/%s" % (tsa_server, name))
    r = T.verify(tsr, D, [tsas[name].root_pem])
    assert r["ok"] and r["reason"] is None and r["tsa"] == tsas[name].name and abs(r["gen_time"] - datetime.datetime.now().timestamp()) < 120
    q = tsp.TimeStampReq.load(T.make_query(D, nonce=7)[0])
    assert q["cert_req"].native is True and q["nonce"].native == 7 and q["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha256"


def test_verify_failure_codes(tsas, tmp_path):
    a, b = tsas["tsa-a"], tsas["tsa-b"]
    tsr = a.respond(T.make_query(D)[0])
    assert T.verify(tsr, hashlib.sha256(b"other").digest(), [a.root_pem])["reason"] == "TSA_IMPRINT"
    assert T.verify(tsr, D, [b.root_pem])["reason"] == "TSA_CHAIN"            # the token's own root is never trusted
    bad = bytearray(tsr)
    bad[-20] ^= 1
    assert T.verify(bytes(bad), D, [a.root_pem])["reason"] in ("TSA_SIG", "TSA_MALFORMED")
    assert T.verify(b"\x30\x03\x02\x01\x00", D, [a.root_pem])["reason"] == "TSA_MALFORMED"
    rej = bytes.fromhex("3005" "3003" "020102")                 # TimeStampResp {status: rejection(2)}, no token
    assert T.verify(rej, D, [a.root_pem])["reason"] == "TSA_STATUS"
    noeku = testtsa.TestTSA("no eku", tsa_eku=False)
    assert T.verify(noeku.respond(T.make_query(D)[0]), D, [noeku.root_pem])["reason"] == "TSA_EKU"
    short = testtsa.TestTSA("short", tsa_valid_days=1)
    late = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) + datetime.timedelta(days=5)
    assert T.verify(short.respond(T.make_query(D)[0], gen_time=late), D, [short.root_pem])["reason"] == "TSA_TIME"
    p = tmp_path / "roots"
    p.mkdir()
    (p / "a.pem").write_bytes(a.root_pem)
    assert T.verify(tsr, D, str(p))["ok"] and T.verify(tsr, D, str(p / "a.pem"))["ok"]       # bundle as a dir or a file


def test_signature_over_attributes_is_checked(tsas):
    """Swap the encapsulated TSTInfo for one with another imprint, keeping the signature: message-digest attribute must catch it."""
    a = tsas["tsa-a"]
    good = tsp.TimeStampResp.load(a.respond(T.make_query(D)[0]))
    other = tsp.TimeStampResp.load(a.respond(T.make_query(hashlib.sha256(b"x").digest())[0]))
    sd = good["time_stamp_token"]["content"]
    sd["encap_content_info"] = other["time_stamp_token"]["content"]["encap_content_info"]
    forged = good.dump(force=True)
    assert T.verify(forged, hashlib.sha256(b"x").digest(), [a.root_pem])["reason"] == "TSA_SIG"


class WrongNonce(testtsa.TestTSA):
    def respond(self, query_der, **kw):
        return super().respond(T.make_query(tsp.TimeStampReq.load(query_der)["message_imprint"]["hashed_message"].native, nonce=12345)[0], **kw)


def test_request_rejects_reply_with_wrong_nonce_or_imprint(tsas, tsa_server):
    srv, _ = testtsa.serve(8813, {"n": WrongNonce("nonce"), "a": tsas["tsa-a"]})
    try:
        with pytest.raises(ValueError, match="TSA_NONCE"):
            T.request(D, "http://127.0.0.1:8813/n")
        with pytest.raises(ValueError):
            T.request(b"\x00" * 31, "http://127.0.0.1:8813/a")
    finally:
        srv.shutdown()
        srv.server_close()
