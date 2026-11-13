"""0.2.2: helpers for several passkeys per person and recovery codes (tests of test_recovery*.py)."""
import io
import os
import subprocess
import sys
import zipfile

from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
import wa_profile as wa
import wq_profile as wq
from tests.helpers import H, ORIGIN, RP
from tests.org_helpers import Person


def login_with(person, auth):
    """Sign in with a given SoftAuthenticator (one of the person's passkeys) in the person's own browser (cookie jar)."""
    j = person.post("/api/auth/login/begin").json()
    return person.post("/api/auth/login/finish", flow_id=j["flow_id"], credential=auth.login_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN))


def add_key(person, signer=None, label="laptop"):
    """Adds a NEW passkey to the person's account, confirmed by `signer` (default: the current passkey). -> (new auth, confirm response)."""
    new = wa.SoftAuthenticator()
    j = person.post("/api/auth/keys/add/begin", label=label)
    assert j.status_code == 200, j.text
    j = j.json()
    f = person.post("/api/auth/keys/add/finish", flow_id=j["flow_id"], credential=new.create_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN))
    assert f.status_code == 200, f.text
    f = f.json()
    env = (signer or person.auth).sign_object(f["typ"], wa.b64u_dec(f["payload_b64"]), RP, ORIGIN)
    return new, person.post("/api/auth/keys/add/confirm", confirm_id=f["confirm_id"], envelope_b64=wa.b64u(env))


def remove_key(person, kid_hex, signer=None):
    b = person.post("/api/auth/keys/%s/remove/begin" % kid_hex)
    if b.status_code != 200:
        return b
    b = b.json()
    env = (signer or person.auth).sign_object(b["typ"], wa.b64u_dec(b["payload_b64"]), RP, ORIGIN)
    return person.post("/api/auth/keys/%s/remove" % kid_hex, flow_id=b["flow_id"], envelope_b64=wa.b64u(env))


def stepup_with(person, auth):
    j = person.post("/api/auth/stepup/begin").json()
    return person.post("/api/auth/stepup/finish", flow_id=j["flow_id"], credential=auth.login_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN))


def new_codes(person):
    person.stepup()
    r = person.post("/api/auth/recovery-codes")
    assert r.status_code == 200, r.text
    return r.json()["codes"]


def elapse_phone_wait(app, kid):
    """0.2.15: the waiting time of a phone declared with a recovery code has passed (24-72 h later): its not-before moves to the past."""
    import time
    app.state.ctx.db.x("UPDATE credentials SET phone_nb=? WHERE kid=? AND phone_nb IS NOT NULL", (int(time.time()) - 1, kid))


def recover(app, person, code, label="new phone", client_cls=TestClient, device="phone", wait=True):
    """A NEW browser (no cookie) uses a recovery code, then registers a new passkey. -> (new auth, browser, finish response).
    0.2.14 (R8-06): a recovered key is "laptop" unless declared; these tests model the lost PHONE replaced by a new phone, so they declare it
    (device="phone"), as the person does on the recovery page; device=None leaves the default.
    0.2.15: a declared phone counts as phone only after the delay; wait=True models the person coming back after it (elapse_phone_wait),
    wait=False keeps the key waiting (test_0215.py checks what it may not do then)."""
    br = client_cls(app, base_url=ORIGIN)
    r = br.post("/api/auth/recovery/login", json={"code": code}, headers=H)
    assert r.status_code == 200, r.text
    new = wa.SoftAuthenticator()
    j = br.post("/api/auth/recovery/passkey/begin", json=dict({"label": label}, **({"device": device} if device else {})), headers=H)
    assert j.status_code == 200, j.text
    j = j.json()
    f = br.post("/api/auth/recovery/passkey/finish", json={"flow_id": j["flow_id"],
                                                           "credential": new.create_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)}, headers=H)
    if wait and device == "phone" and f.status_code == 200:
        elapse_phone_wait(app, new.kid)
    return new, br, f


def switch_auth(person, auth):
    """From now on the person signs with `auth` (the lost phone is gone) and is signed in with it."""
    person.auth = auth
    r = login_with(person, auth)
    assert r.status_code == 200, r.text


def revoke_batch(person, mids, signer=None):
    """One wb ceremony (typ revocation) over the revocation payloads of `mids` (browser side: own CDE of each mandate)."""
    from svidetel_v4.state import revocation_payload
    import hashlib
    rows = {m["id"]: m for m in person.c.get("/api/mandates").json()}
    items = [hashlib.sha256(revocation_payload(rows[mid]["mandate"])).digest() for mid in mids]
    a = signer or person.auth
    ad, cd, der = a.get_assertion(wq.wb_challenge(items, wa.TYP_REVOCATION), RP, ORIGIN)
    env = wq.make_wb(items, a.kid, ad, cd, der, typ=wa.TYP_REVOCATION)
    return person.post("/api/mandates/revoke-batch", mandate_ids=mids, envelope_b64=wa.b64u(env))


def export_to(client, dest):
    r = client.get("/api/export")
    assert r.status_code == 200, r.text
    zipfile.ZipFile(io.BytesIO(r.content)).extractall(dest)
    return str(dest)


def run_verify(folder, *flags):
    checker = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packtools", "verify_pack.py")
    p = subprocess.run([sys.executable, "-I", checker, folder, *flags], capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout + p.stderr


__all__ = ["Person", "login_with", "add_key", "remove_key", "stepup_with", "new_codes", "recover", "switch_auth", "revoke_batch",
           "export_to", "run_verify"]
