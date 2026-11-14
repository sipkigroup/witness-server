"""r0286 (POSTKVANT-1311, crypto agility): the checkers verify by a LIST of algorithms; a known key of an algorithm a checker cannot verify
is "cannot check" -- never counted as verified, never a crash; today's Ed25519 notes and packs keep verifying exactly as before.
tlogcheck.py: a C2SP key of another type byte (a placeholder for a future ML-DSA key; the real byte is to be read from C2SP before use)."""
import hashlib
import json
import os
import shutil
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import tlogcheck as TC

RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw
OTHER_TYPE = 0x7f            # not a C2SP type this checker verifies (stand-in for a post-quantum key type)
HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.dirname(HERE)


def _ed():
    k = ed25519.Ed25519PrivateKey.generate()
    return k, k.public_key().public_bytes(*RAW)


def _other_vkey(name, pub=b"\x05" * 1312):
    return "%s+%s+%s" % (name, TC.key_id(name, OTHER_TYPE, pub).hex(), TC.b64e(bytes([OTHER_TYPE]) + pub))


def test_sig_algs_is_a_list_and_ed25519_is_unchanged():
    assert TC.SIG_ALGS == {TC.ALG_ED25519: "Ed25519", TC.ALG_COSIG_ED25519: "Ed25519 timestamped cosignature"}
    k, pub = _ed()
    text = TC.checkpoint_text("w.example/b", 1, b"\x00" * 32)
    note = TC.make_note(text, [TC.sign_line("w.example/b", TC.ALG_ED25519, pub, k.sign(text.encode()))])
    v = TC.verify_note(note, [TC.vkey("w.example/b", pub)])
    assert v["signers"] == ["w.example/b"] and v["unverifiable"] == []
    with pytest.raises(TC.NoteError, match="bad vkey length"):            # a known type keeps its exact length
        TC.parse_vkey("w.example/b+%s+%s" % (TC.key_id("w.example/b", 1, pub + b"x").hex(), TC.b64e(b"\x01" + pub + b"x")))


def test_a_key_of_an_unknown_type_is_parsed_and_its_signature_is_cannot_check():
    vk = TC.parse_vkey(_other_vkey("pq.example/w"))
    assert vk["alg"] == OTHER_TYPE and vk["supported"] is False and len(vk["pub"]) == 1312
    k, pub = _ed()
    text = TC.checkpoint_text("w.example/b", 1, b"\x00" * 32)
    pq_line = TC.EM + "pq.example/w " + TC.b64e(vk["id"] + b"\x09" * 2420) + "\n"
    ed_line = TC.sign_line("w.example/b", TC.ALG_ED25519, pub, k.sign(text.encode()))
    # Ed25519 + the other signature: verified by Ed25519, the other one named as unverifiable (not as a signer)
    v = TC.verify_note(TC.make_note(text, [ed_line, pq_line]), [TC.vkey("w.example/b", pub), vk])
    assert v["signers"] == ["w.example/b"] and v["unverifiable"] == ["pq.example/w"]
    # only the other signature: "cannot check", a NoteError subclass (old callers still reject), never accepted
    with pytest.raises(TC.NoteUnsupported, match="cannot check"):
        TC.verify_note(TC.make_note(text, [pq_line]), [vk])
    # an old checker's view: it does not know the key at all -> ignored, Ed25519 decides (C2SP "unknown keys ignored")
    assert TC.verify_note(TC.make_note(text, [ed_line, pq_line]), [TC.vkey("w.example/b", pub)])["signers"] == ["w.example/b"]


def _run(folder, *flags):
    p = subprocess.run([sys.executable, "-I", os.path.join(SERVER, "packtools", "verify_pack.py"), folder, *flags],
                       capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout


@pytest.mark.parametrize("alg,rc,last", [("EdDSA", 0, "RESULT: VALID"), ("ML-DSA-65", 3, "RESULT: NOT PROVEN")])
def test_verify_pack_witness_alg_list(tmp_path, alg, rc, last):
    """The committed demo pack: its manifest names EdDSA (VALID); a name this checker does not verify: CANNOT CHECK, NOT PROVEN."""
    src = os.path.join(os.path.dirname(SERVER), "web", "demo", "pack")
    if not os.path.isdir(src):
        pytest.skip("no demo pack")
    d = str(tmp_path / "p")
    shutil.copytree(src, d)
    mp = os.path.join(d, "manifest.json")
    m = json.load(open(mp))
    assert m["witness"]["alg"] == "EdDSA"
    m["witness"]["alg"] = alg
    open(mp, "w").write(json.dumps(m, indent=1))
    got_rc, out = _run(d, "--offline")
    assert got_rc == rc and out.rstrip().splitlines()[-1] == last, out
    if rc == 3:
        assert "witness: CANNOT CHECK (key algorithm 'ML-DSA-65' is not one this checker verifies: EdDSA" in out
