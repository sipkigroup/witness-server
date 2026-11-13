"""r0271 (ISPYTANIE-0266-1311 Н4): the offline checker without the package `cryptography` says what to install, no traceback.
Before: `python3 -I tlogcheck.py checkpoint ...` on a Python without it -> UnboundLocalError (InvalidSignature) and a traceback."""
import os
import subprocess
import sys

import tlogcheck as TC

PT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packtools")
# a Python where `import cryptography` fails, as on a fresh system Python (the finder refuses the package and its submodules)
NO_CRYPTO = ("import sys, runpy\n"
             "class _No:\n"
             "    def find_spec(self, name, path=None, target=None):\n"
             "        if name == 'cryptography' or name.startswith('cryptography.'):\n"
             "            raise ModuleNotFoundError(\"No module named 'cryptography'\", name=name)\n"
             "sys.meta_path.insert(0, _No())\n"
             "sys.argv = sys.argv[1:]\n"
             "runpy.run_path(sys.argv[0], run_name='__main__')\n")


def _note(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    k = Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    o = "witness.test/batches"
    text = TC.checkpoint_text(o, 0, TC._h(b""))
    note = TC.make_note(text, [TC.sign_line(o, TC.ALG_ED25519, pub, k.sign(text.encode()))])
    (tmp_path / "cp.note").write_text(note)
    (tmp_path / "vkey").write_text(TC.vkey(o, pub))
    return str(tmp_path / "cp.note"), str(tmp_path / "vkey")


def _run(args, no_crypto):
    cmd = [sys.executable, "-I"] + (["-c", NO_CRYPTO] if no_crypto else []) + [os.path.join(PT, "tlogcheck.py")] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


def test_without_cryptography_one_clear_line(tmp_path):
    n, v = _note(tmp_path)
    r = _run(["checkpoint", n, v], no_crypto=True)
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "Traceback" not in out and "UnboundLocalError" not in out, out
    assert "NOT CHECKED" in out and "pip install cryptography" in out and "uv run --with cryptography" in out, out
    assert "INVALID" not in out, out                      # nothing was checked: never "INVALID"


def test_with_cryptography_still_ok(tmp_path):
    n, v = _note(tmp_path)
    r = _run(["checkpoint", n, v], no_crypto=False)
    assert r.returncode == 0 and r.stdout.startswith("checkpoint OK"), r.stdout + r.stderr
