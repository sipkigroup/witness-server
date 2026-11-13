#!/usr/bin/env python3
"""End-to-end smoke test of a self-hosted witness: your key, your domain, a pack that the SAME verify_pack.py accepts.
usage: python3 e2e_check.py --base https://witness.corp.example [--key-file secrets/witness_ed25519] [--cacert ca.pem] [--insecure] [--ip 10.0.0.9]
It registers a throw-away account "selfcheck-<time>" with a software passkey (the account stays in your database; delete it if you mind),
creates an agent and a mandate, makes one allowed and one denied action, downloads the evidence pack, and checks:
  1. /v1/witness public key == the key derived from your secrets/witness_ed25519 (when --key-file is given);
  2. the pack's verify/verify_pack.py is byte-identical to the one in this repository (cloud/server/packtools/verify_pack.py);
  3. verify_pack.py --offline prints RESULT: VALID; and a pack with one flipped byte of the ledger prints RESULT: INVALID.
Needs: python 3.10+, httpx, cbor2, cryptography. Exit 0 = all checks passed."""
import argparse
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
CLOUD = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(CLOUD, "contract"), os.path.dirname(CLOUD), CLOUD]
import httpx  # noqa: E402
import wa_profile as wa  # noqa: E402
from svidetel_v4 import cose  # noqa: E402
from svidetel_v4.state import approval_payload  # noqa: E402,F401
import testshim  # noqa: E402  (the page's CDE encoder turns the hex `toolmap_sha256` into bytes before signing; the shim does the same here)
testshim.install()

REPO_VERIFY = os.path.join(CLOUD, "server", "packtools", "verify_pack.py")
FORM = {"currency": "USD", "valid_days": 30, "purchase": {"enabled": True, "budget": 20000, "max_per_action": 10000},
        "message": {"domains": ["acme.example"], "to": []}, "forbidden_data": ["home_address", "phone"], "delete": None, "publish": None}


def step(ok, msg):
    print(("ok    " if ok else "FAIL  ") + msg, flush=True)
    if not ok:
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--key-file")
    ap.add_argument("--cacert")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--ip", help="send this X-Real-IP (only for a plain-http local run without the proxy)")
    o = ap.parse_args()
    base = o.base.rstrip("/")
    rp = httpx.URL(base).host
    verify = False if o.insecure else (o.cacert or True)
    hdr = {"Origin": base}
    if o.ip:
        hdr["X-Real-IP"] = o.ip
    c = httpx.Client(base_url=base, timeout=60, verify=verify)
    r = c.get("/healthz")
    step(r.status_code == 200, "GET /healthz -> %s" % r.status_code)
    w = c.get("/v1/witness").json()
    step(w.get("alg") == "EdDSA" and len(w.get("pub_hex", "")) == 64, "GET /v1/witness: pub %s... iss %s" % (w["pub_hex"][:16], w.get("iss")))
    if o.key_file:
        seed = bytes.fromhex(open(o.key_file).read().strip())
        step(cose.Key.from_seed(cose.ALG_EDDSA, seed).pub.hex() == w["pub_hex"], "witness public key == the key in %s (your own key)" % o.key_file)
    auth = wa.SoftAuthenticator()

    def post(path, **j):
        return c.post(path, json=j, headers=hdr)
    j = post("/api/auth/register/begin", display_name="selfcheck-%d" % time.time()).json()
    cred = auth.create_credential(wa.b64u_dec(j["options"]["challenge"]), rp, base)
    r = post("/api/auth/register/finish", flow_id=j["flow_id"], credential=cred)
    step(r.status_code == 200, "register (software passkey) -> %s" % r.status_code)
    r = post("/api/agents", name="selfcheck", preset="demo")
    step(r.status_code == 200, "create agent -> %s" % r.status_code)
    agent, key = r.json()["agent"], r.json()["api_key"]
    m = post("/api/mandates/draft", agent_id=agent["id"], form=FORM).json()["mandate"]
    env = wa.b64u(auth.sign_object(wa.TYP_MANDATE, wa.cde(m), rp, base))
    step(post("/api/mandates", mandate=m, envelope_b64=env).status_code == 200, "sign mandate")
    ah = {"Authorization": "Bearer " + key}
    a = c.post("/v1/actions", json={"tool": "send_email", "args": {"to": "x@acme.example", "subject": "s", "body": "b"}}, headers=ah).json()
    step(a["verdict"] == "allow", "allowed action -> %s" % a["verdict"])
    d = c.post("/v1/actions", json={"tool": "send_email", "args": {"to": "x@other.example", "subject": "s", "body": "b"}}, headers=ah).json()
    step(d["verdict"] == "deny", "denied action -> %s/%s" % (d["verdict"], d["reason"]))
    g = c.get("/v1/actions/" + a["rid"], headers=ah).json()
    step(g.get("proof") is not None, "inclusion proof delivered")
    r = c.get("/api/export")
    step(r.status_code == 200, "download evidence pack (%d bytes)" % len(r.content))
    tmp = tempfile.mkdtemp(prefix="dw-selfcheck-")
    try:
        zipfile.ZipFile(io.BytesIO(r.content)).extractall(tmp)
        same = hashlib.sha256(open(os.path.join(tmp, "verify", "verify_pack.py"), "rb").read()).digest() == hashlib.sha256(open(REPO_VERIFY, "rb").read()).digest()
        step(same, "pack verify/verify_pack.py is byte-identical to cloud/server/packtools/verify_pack.py")
        run = lambda: subprocess.run([sys.executable, "-I", REPO_VERIFY, tmp, "--offline"], capture_output=True, text=True)  # noqa: E731
        p = run()
        print("      " + p.stdout.strip().replace("\n", "\n      "))
        step(p.returncode == 0 and p.stdout.strip().splitlines()[-1] == "RESULT: VALID", "repo verify_pack.py on the self-hosted pack -> RESULT: VALID")
        lp = os.path.join(tmp, "ledger", "ledger.cose")
        b = bytearray(open(lp, "rb").read())
        b[len(b) // 2] ^= 1
        open(lp, "wb").write(bytes(b))
        p = run()
        step(p.returncode != 0 and p.stdout.strip().splitlines()[-1] == "RESULT: INVALID", "one flipped ledger byte -> RESULT: INVALID")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
