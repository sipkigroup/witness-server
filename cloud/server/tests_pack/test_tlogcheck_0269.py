"""r0269: packtools/tlogcheck.py (offline checker of the public log of batches) and the RFC 3161 checker against attack classes.
Known answers from first sources: the c2sp.org/signed-note example, ed25519-speccheck, a real FreeTSA reply."""
import base64
import hashlib
import json
import os
import random

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization

import tlogcheck as TC
import testtsa
import tsa
from svidetel_v4.checkpoint import merkle_root

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures_0269")
RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw


def _key():
    k = ed25519.Ed25519PrivateKey.generate()
    return k, k.public_key().public_bytes(*RAW)


def _cp(k, pub, origin, leaves, size=None):
    t = TC.Tree(TC.leaf_hash(x) for x in leaves)
    size = len(leaves) if size is None else size
    text = TC.checkpoint_text(origin, size, t.root(0, size))
    return TC.make_note(text, [TC.sign_line(origin, TC.ALG_ED25519, pub, k.sign(text.encode()))]), t


# ------------------------------------------------------------------ C2SP formats, first-source vectors
def test_signed_note_example_of_the_spec():
    """c2sp.org/signed-note, section "Example": vkey + note verify; the key ID is SHA-256(name || 0x0A || 0x01 || pub)[:4]."""
    vk = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
    note = ("This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3m"
            "FXmRKuwHjG1Yu72IneyaQM=\n")
    v = TC.verify_note(note, [vk])
    assert v["text"] == "This is an example message.\n" and v["signers"] == ["example.com/foo"]
    k = TC.parse_vkey(vk)
    assert TC.vkey(k["name"], k["pub"]) == vk
    with pytest.raises(TC.NoteError):                                           # one changed byte of the text
        TC.verify_note(note.replace("example message", "example massage"), [vk])


def test_note_rules():
    k, pub = _key()
    note, _ = _cp(k, pub, "w.example/batches", [b"a", b"b", b"c"])
    vk = TC.vkey("w.example/batches", pub)
    assert TC.open_checkpoint(note, [vk])["size"] == 3
    other_k, other_pub = _key()
    with pytest.raises(TC.NoteError, match="no signature of a known key"):      # unknown keys are ignored, none known = reject
        TC.verify_note(note, [TC.vkey("x.example/other", other_pub)])
    # a known name AND id whose signature fails rejects the whole note even if another known key verifies
    forged = note + TC.sign_line("x.example/other", TC.ALG_ED25519, other_pub, b"\x00" * 64)
    with pytest.raises(TC.NoteError, match="does not verify"):
        TC.verify_note(forged, [vk, TC.vkey("x.example/other", other_pub)])
    sig = note.rstrip("\n").rsplit(" ", 1)[1]
    raw = base64.b64decode(sig)
    nc = sig[:-2] + ("B=" if sig[-2] == "A" else "A=") if sig.endswith("=") and not sig.endswith("==") else None
    if nc and base64.b64decode(nc) == raw:                                       # non-canonical base64 of the same bytes
        with pytest.raises(TC.NoteError, match="non-canonical"):
            TC.parse_note(note.replace(sig, nc))
    with pytest.raises(TC.NoteError):
        TC.parse_note(note + note.splitlines(True)[-1])                          # same key name and id twice
    with pytest.raises(TC.NoteError):
        TC.parse_note(note.replace("\n\n", "\n\x07\n"))                          # control character
    with pytest.raises(TC.NoteError):
        TC.parse_checkpoint("o\n03\n" + TC.b64e(b"\0" * 32) + "\n")              # leading zero in the size


def test_tree_is_rfc9162_and_the_core_tree():
    rnd = random.Random(7)
    for n in list(range(1, 40)) + [64, 65, 100]:
        d = [rnd.randbytes(9) for _ in range(n)]
        t = TC.Tree(TC.leaf_hash(x) for x in d)
        assert t.root() == merkle_root(d)                                         # same bytes as svidetel_v4/checkpoint.py
        for m in range(n):
            assert TC.verify_inclusion(t.lh[m], m, n, t.inclusion(m, n), t.root())
            assert TC.verify_consistency(m, n, t.root(0, m), t.root(), t.consistency(m, n))
        if n > 2:
            p = t.inclusion(1, n)
            assert not TC.verify_inclusion(t.lh[1], 1, n, p[:-1], t.root())        # short path
            assert not TC.verify_inclusion(t.lh[1], 2, n, p, t.root())             # wrong index
            c = t.consistency(n - 1, n)
            assert not TC.verify_consistency(n - 1, n, t.root(0, n - 1), t.root(), c + [b"\0" * 32])
    assert TC.Tree().root() == hashlib.sha256(b"").digest()


def test_cosignature_type_04_of_a_second_witness():
    """c2sp.org/tlog-cosignature Ed25519: message "cosignature/v1\\ntime T\\n" + checkpoint text; signature = 8-byte T || 64 bytes."""
    lk, lpub = _key()
    note, _ = _cp(lk, lpub, "w.example/batches", [b"x"] * 5)
    wk, wpub = _key()
    text = TC.parse_note(note)[0]
    t = 1794500000
    sig = t.to_bytes(8, "big") + wk.sign(TC.cosig_message(text, t))
    cosigned = note + TC.sign_line("witness2.example", TC.ALG_COSIG_ED25519, wpub, sig)
    v = TC.verify_note(cosigned, [TC.vkey("w.example/batches", lpub), TC.vkey("witness2.example", wpub, TC.ALG_COSIG_ED25519)])
    assert v["signers"] == ["w.example/batches", "witness2.example"] and v["cosig_times"] == {"witness2.example": t}
    bad = note + TC.sign_line("witness2.example", TC.ALG_COSIG_ED25519, wpub, (t + 1).to_bytes(8, "big") + sig[8:])
    with pytest.raises(TC.NoteError):                                            # the timestamp is signed
        TC.verify_note(bad, [TC.vkey("witness2.example", wpub, TC.ALG_COSIG_ED25519)])


# ------------------------------------------------------------------ attack classes on the log
def test_split_view_two_checkpoints_of_one_size():
    k, pub = _key()
    vk = TC.vkey("w.example/batches", pub)
    a, _ = _cp(k, pub, "w.example/batches", [b"1", b"2", b"3"])
    b, _ = _cp(k, pub, "w.example/batches", [b"1", b"2", b"EVIL"])
    ca, cb = TC.open_checkpoint(a, [vk]), TC.open_checkpoint(b, [vk])
    assert TC.fork(ca, cb) and not TC.fork(ca, ca)


def test_substituted_root_and_rewritten_history():
    k, pub = _key()
    vk = TC.vkey("w.example/batches", pub)
    leaves = [b"b%d" % i for i in range(10)]
    old_note, t = _cp(k, pub, "w.example/batches", leaves[:7])
    new_note, t2 = _cp(k, pub, "w.example/batches", leaves[:6] + [b"rewritten"] + leaves[7:])
    o, n = TC.open_checkpoint(old_note, [vk]), TC.open_checkpoint(new_note, [vk])
    honest = TC.Tree(TC.leaf_hash(x) for x in leaves).consistency(7, 10)
    assert not TC.verify_consistency(7, 10, o["root"], n["root"], honest)       # history rewritten: no proof makes it consistent
    assert not TC.verify_consistency(7, 10, o["root"], n["root"], t2.consistency(7, 10))
    # a root swapped in the note text breaks the signature
    swapped = old_note.replace(TC.b64e(o["root"]), TC.b64e(n["root"]))
    with pytest.raises(TC.NoteError):
        TC.open_checkpoint(swapped, [vk])
    # inclusion of a leaf against another tree's root fails
    assert not TC.verify_inclusion(TC.leaf_hash(leaves[3]), 3, 7, t.inclusion(3, 7), n["root"])


# ------------------------------------------------------------------ strict Ed25519 (RFC 8032, not ZIP-215)
def test_ed25519_speccheck_vectors():
    """ed25519-speccheck: 0-1 small-order A, 2 small-order R, 3 mixed-order A and R (valid, cofactorless), 4-5 valid only with the
    cofactored equation, 6-7 S >= L, 8-9 non-canonical R, 10-11 non-canonical A. RFC 8032 cofactorless + small-order refusal accepts
    only 3. pyca/cryptography alone accepts 0, 1, 2 and 11 (11 = non-canonical A, which RFC 8032 5.1.3 rejects)."""
    cases = json.load(open(os.path.join(FIX, "ed25519-speccheck-cases.json")))
    got = [TC.ed25519_verify_strict(bytes.fromhex(c["pub_key"]), bytes.fromhex(c["signature"]), bytes.fromhex(c["message"])) for c in cases]
    assert [i for i, ok in enumerate(got) if ok] == [3]


def test_ed25519_malleability_and_encodings():
    k, pub = _key()
    m = b"checkpoint"
    s = k.sign(m)
    assert TC.ed25519_verify_strict(pub, s, m)
    S = int.from_bytes(s[32:], "little")
    mall = s[:32] + (S + TC._L).to_bytes(32, "little")                            # S + L: same point equation, non-canonical S
    assert not TC.ed25519_verify_strict(pub, mall, m)
    ident = (1).to_bytes(32, "little")                                            # identity point as public key
    assert not TC.ed25519_verify_strict(ident, ident + b"\0" * 32, m)
    nonc = (2 ** 255 - 19 + 1).to_bytes(32, "little")                              # y = p + 1: non-canonical encoding of y = 1
    assert not TC.ed25519_verify_strict(nonc, ident + b"\0" * 32, m)
    assert not TC.ed25519_verify_strict(pub[:31], s, m) and not TC.ed25519_verify_strict(pub, s[:63], m)


# ------------------------------------------------------------------ RFC 3161: real reply, attack classes
def test_real_freetsa_reply_verifies_offline():
    ca = os.path.join(tsa.__file__.rsplit(os.sep, 1)[0], "ca", "freetsa.pem")
    assert hashlib.sha256(open(ca, "rb").read()).hexdigest() == "2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438"
    tsr = open(os.path.join(FIX, "freetsa-probe.tsr"), "rb").read()
    r = tsa.verify(tsr, hashlib.sha256(b"dw-r0269-probe").digest(), ca)
    assert r["ok"] and r["gen_time"] == 1794542546 and r["tsa"] == "www.freetsa.org", r
    assert tsa.verify(tsr, hashlib.sha256(b"other").digest(), ca)["reason"] == "TSA_IMPRINT"


@pytest.fixture(scope="module")
def T():
    return testtsa.TestTSA("Real TSA", kind="ec")


def _q(d):
    return tsa.make_query(d)[0]


D = hashlib.sha256(b"root").digest()


def test_honest_token(T):
    assert tsa.verify(T.respond(_q(D)), D, [T.root_pem])["ok"]
    assert tsa.verify(T.respond(_q(D), ess="v1"), D, [T.root_pem])["ok"]          # FreeTSA's form: signingCertificate (SHA-1)


def test_cert_substitution_same_issuer_and_serial(T):
    """CVE-2026-33753 class: the token carries the real TSA certificate AND a forged one with the SAME issuer + serial but the attacker's
    key (self-issued, issuer name copied). The forged one signs. Whichever certificate a checker picks, the result must be a failure."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    import datetime
    ak = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    forged = (x509.CertificateBuilder().subject_name(T.cert.subject).issuer_name(T.cert.issuer).public_key(ak.public_key())
              .serial_number(T.cert.serial_number).not_valid_before(now - testtsa.DAY).not_valid_after(now + testtsa.DAY)
              .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
              .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
              .sign(ak, hashes.SHA256()))
    for order in ([T.cert, forged, T.root], [forged, T.cert, T.root], [forged, T.root]):
        tok = T.respond(_q(D), signer=(forged, ak), certs=order)
        r = tsa.verify(tok, D, [T.root_pem])
        assert not r["ok"] and r["reason"] in ("TSA_MALFORMED", "TSA_CHAIN", "TSA_ESS"), (order, r)


def test_signer_cert_not_the_ess_cert(T):
    """The real TSA signs, but the signed ESS attribute names another certificate (or is missing): TSA_ESS."""
    other, _ = T.issue("Other leaf")
    assert tsa.verify(T.respond(_q(D), ess=other), D, [T.root_pem])["reason"] == "TSA_ESS"
    assert tsa.verify(T.respond(_q(D), ess="none"), D, [T.root_pem])["reason"] == "TSA_ESS"
    assert tsa.verify(T.respond(_q(D), ess="both"), D, [T.root_pem])["reason"] == "TSA_ESS"


def test_leaf_cannot_issue_a_tsa_certificate(T):
    """An end-entity certificate of the same root (e.g. any customer leaf) mints a 'TSA' certificate: chain must stop (basicConstraints)."""
    leaf, leaf_key = T.issue("Customer leaf", eku=False)
    fake, fake_key = T.issue("Fake TSA", issuer=(leaf, leaf_key))
    tok = T.respond(_q(D), signer=(fake, fake_key), extra_certs=[leaf])
    assert tsa.verify(tok, D, [T.root_pem])["reason"] == "TSA_CHAIN"
    ca, ca_key = T.issue("Real intermediate", ca=True, eku=False)                 # control: a real intermediate CA is accepted
    good, good_key = T.issue("TSA under intermediate", issuer=(ca, ca_key))
    assert tsa.verify(T.respond(_q(D), signer=(good, good_key), extra_certs=[ca]), D, [T.root_pem])["ok"]


def test_duplicate_signed_attribute(T):
    assert tsa.verify(T.respond(_q(D), dup_attr=True), D, [T.root_pem])["reason"] == "TSA_SIG"


def test_wrong_root_and_wrong_eku(T):
    other = testtsa.TestTSA("Other", kind="ec")
    assert tsa.verify(T.respond(_q(D)), D, [other.root_pem])["reason"] == "TSA_CHAIN"
    no_eku, k = T.issue("No EKU", eku=False)
    assert tsa.verify(T.respond(_q(D), signer=(no_eku, k)), D, [T.root_pem])["reason"] == "TSA_EKU"
