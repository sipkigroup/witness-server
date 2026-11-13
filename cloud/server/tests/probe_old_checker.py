"""Builds two packs with the 0.2.2 server and runs the given checker on them (old-checker compatibility probe, OTCHET-RECOVERY 2).
Usage (from cloud/server): python tests/probe_old_checker.py <cloud/server> <verify_pack.py to test> <scratch dir>"""
import os, subprocess, sys, tempfile
sys.path.insert(0, sys.argv[1])                     # cloud/server of the CURRENT tree
from fastapi.testclient import TestClient
from app.config import Config
from app.main import create_app
from tests.helpers import ORIGIN
from tests.org_helpers import Person
from tests.recovery_helpers import add_key, export_to, new_codes, recover, switch_auth

checker = sys.argv[2]
tmp = tempfile.mkdtemp(dir=sys.argv[3])
kf = os.path.join(tmp, "wk"); open(kf, "w").write("a1" * 32)
app = create_app(Config(data_dir=os.path.join(tmp, "data"), witness_key_file=kf, key_pepper="p", rp_id="localhost", origin=ORIGIN,
                        iss="https://witness.test", anchor="off", web_dir=os.path.join(tmp, "web")))
# (a) a second passkey signs a mandate
a = Person(app).register("A")
lap, r = add_key(a)
switch_auth(a, lap)
ag, _ = a.new_agent()
m, r = a.mandate(ag["id"]); assert r.status_code == 200
pa = export_to(a.c, os.path.join(tmp, "a"))
# (b) only a key added with a recovery code, nothing signed by it
b = Person(app).register("B")
ag, _ = b.new_agent(); m, r = b.mandate(ag["id"]); assert r.status_code == 200
codes = new_codes(b)
new, br, f = recover(app, b, codes[0]); assert f.status_code == 200
switch_auth(b, new)
pb = export_to(b.c, os.path.join(tmp, "b"))
for name, d in (("a: second passkey signed a mandate", pa), ("b: key added by recovery code only", pb)):
    p = subprocess.run([sys.executable, "-I", checker, d, "--offline"], capture_output=True, text=True)
    lines = [l for l in p.stdout.splitlines() if l.split(":")[0] in ("registry", "ledger", "keys", "RESULT")]
    print("==", name, "| exit", p.returncode)
    print("\n".join(lines))
