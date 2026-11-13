"""0.2.16 (open item of 0.2.15): a passkey declared the NEW PHONE with a recovery code may not, for the whole wait (24-72 h), make new
recovery codes or remove any passkey (phone or laptop): 409 PHONE_PENDING. With a stolen code the thief would otherwise burn the owner's
remaining codes (and keep a fresh set) or remove the owner's laptop, the key that can still cancel the claim."""
from app import _paths  # noqa: F401
from tests.org_helpers import Person
from tests.recovery_helpers import add_key, elapse_phone_wait, new_codes, recover, remove_key, stepup_with, switch_auth


def _setup(app, name):
    p = Person(app).register(name)
    lost = p.auth
    lap, r = add_key(p, label="laptop")
    assert r.status_code == 200, r.text
    assert stepup_with(p, p.auth).status_code == 200
    assert p.post("/api/auth/keys/%s/device" % lap.kid.hex(), device="laptop").status_code == 200
    codes = new_codes(p)
    ph, br, f = recover(app, p, codes[0], device="phone", wait=False)
    assert f.status_code == 200 and f.json()["device"] == "phone", f.text
    switch_auth(p, ph)                                                       # from here on: the person (or the thief) holds only the new key
    return p, lost, lap, ph


def test_waiting_phone_cannot_make_new_recovery_codes(app):
    p, lost, lap, ph = _setup(app, "Ann")
    assert stepup_with(p, ph).status_code == 200
    r = p.post("/api/auth/recovery-codes")
    assert r.status_code == 409 and r.json()["error"] == "PHONE_PENDING" and "UTC" in r.json()["detail"], r.text
    assert p.c.get("/api/auth/recovery-codes").json()["remaining"] == 9                # the owner's codes still work
    elapse_phone_wait(app, ph.kid)
    assert stepup_with(p, ph).status_code == 200
    assert p.post("/api/auth/recovery-codes").status_code == 200


def test_waiting_phone_removes_no_key_laptop_or_phone(app):
    p, lost, lap, ph = _setup(app, "Ben")
    r = remove_key(p, lap.kid.hex(), signer=ph)                                       # the laptop (before 0.2.16: allowed)
    assert r.status_code == 409 and r.json()["error"] == "PHONE_PENDING", r.text
    r = remove_key(p, lost.kid.hex(), signer=ph)                                      # the phone (0.2.15 already: DEVICE_LEVEL)
    assert r.status_code == 409, r.text
    keys = {k["kid_hex"] for k in p.c.get("/api/auth/keys").json()["keys"]}
    assert {lap.kid.hex(), lost.kid.hex()} <= keys
    elapse_phone_wait(app, ph.kid)
    assert remove_key(p, lap.kid.hex(), signer=ph).status_code == 200
    assert remove_key(p, lost.kid.hex(), signer=ph).status_code == 200


def test_other_keys_still_remove_and_renew_while_one_waits(app):
    """the rule binds the waiting key only: the owner's laptop may still cancel / remove the claim and make new codes"""
    p, lost, lap, ph = _setup(app, "Cy")
    switch_auth(p, lost)                                                              # the owner still has the phone
    assert stepup_with(p, lost).status_code == 200
    assert p.post("/api/auth/recovery-codes").status_code == 200
    assert remove_key(p, ph.kid.hex(), signer=lost).status_code == 200
