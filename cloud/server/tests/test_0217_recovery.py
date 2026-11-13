"""0.2.17 (R9-03): a passkey declared the new phone with a recovery code (waiting, 0.2.15/0.2.16) adds no passkey at all; a passkey it vouched
for (credentials.vouched_by, e.g. one added before 0.2.17) inherits the wait: no new recovery codes, no removals, no cancelling; "this was not
me" (cancel) and the removal of the waiting key revoke every key it vouched for, with their sessions, as key events in the ownership chain."""
import json

from app import _paths  # noqa: F401
import wa_profile as wa
from tests.helpers import ORIGIN, RP
from tests.org_helpers import Person
from tests.recovery_helpers import elapse_phone_wait, new_codes, recover, remove_key, stepup_with, switch_auth


def add_key(p, signer=None, label="laptop"):
    """A new passkey declared "laptop" (any key may vouch for one), confirmed by `signer` (default: the current one)."""
    new = wa.SoftAuthenticator()
    j = p.post("/api/auth/keys/add/begin", label=label, device="laptop")
    assert j.status_code == 200, j.text
    j = j.json()
    f = p.post("/api/auth/keys/add/finish", flow_id=j["flow_id"], credential=new.create_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN))
    assert f.status_code == 200, f.text
    f = f.json()
    env = (signer or p.auth).sign_object(f["typ"], wa.b64u_dec(f["payload_b64"]), RP, ORIGIN)
    return new, p.post("/api/auth/keys/add/confirm", confirm_id=f["confirm_id"], envelope_b64=wa.b64u(env))


def _setup(app, name):
    p = Person(app).register(name)
    lost = p.auth
    lap, r = add_key(p, label="laptop")
    assert r.status_code == 200, r.text
    assert stepup_with(p, p.auth).status_code == 200
    assert p.post("/api/auth/keys/%s/device" % lap.kid.hex(), device="laptop").status_code == 200
    codes = new_codes(p)
    ph, br, f = recover(app, p, codes[0], device="phone", wait=False)
    assert f.status_code == 200 and f.json().get("phone_not_before"), f.text
    switch_auth(p, ph)
    return p, lost, lap, ph


def _vouched_by_waiting(app, p, lap, ph, label="old"):
    """A laptop key k2 that the WAITING key vouched for (as a database from before 0.2.17 may hold): added by the laptop, then its
    vouched_by pointed at the waiting key."""
    switch_auth(p, lap)
    assert stepup_with(p, lap).status_code == 200
    k2, r = add_key(p, signer=lap, label=label)
    assert r.status_code == 200, r.text
    db = app.state.ctx.db
    db.x("UPDATE credentials SET vouched_by=? WHERE kid=?", (ph.kid, k2.kid))
    return k2


def test_added_key_records_who_vouched(app):
    p = Person(app).register("Kai")
    k2, r = add_key(p, label="laptop")
    assert r.status_code == 200
    row = app.state.ctx.db.one("SELECT vouched_by FROM credentials WHERE kid=?", (k2.kid,))
    assert bytes(row["vouched_by"]) == p.auth.kid


def test_waiting_key_adds_no_key_and_after_the_wait_it_may(app):
    p, lost, lap, ph = _setup(app, "Lea")
    assert stepup_with(p, ph).status_code == 200
    k2, r = add_key(p, signer=ph, label="thief")
    assert r.status_code == 409 and r.json()["error"] == "PHONE_PENDING" and "add passkeys" in r.json()["detail"], r.text
    elapse_phone_wait(app, ph.kid)
    k3, r = add_key(p, signer=ph, label="later")
    assert r.status_code == 200, r.text


def test_key_vouched_by_a_waiting_key_inherits_the_wait(app):
    p, lost, lap, ph = _setup(app, "Max")
    k2 = _vouched_by_waiting(app, p, lap, ph)
    switch_auth(p, k2)
    assert stepup_with(p, k2).status_code == 200
    r = p.post("/api/auth/recovery-codes")
    assert r.status_code == 409 and r.json()["error"] == "PHONE_PENDING", r.text
    r = remove_key(p, lap.kid.hex(), signer=k2)
    assert r.status_code == 409 and r.json()["error"] == "PHONE_PENDING", r.text
    k3, r = add_key(p, signer=k2, label="grandchild")
    assert r.status_code == 409 and r.json()["error"] == "PHONE_PENDING", r.text
    c = p.post("/api/auth/keys/%s/cancel-phone" % ph.kid.hex())                   # nor cancel the claim it descends from
    assert c.status_code == 403, c.text
    elapse_phone_wait(app, ph.kid)                                                    # the wait is over: so is the inherited one
    assert stepup_with(p, k2).status_code == 200
    assert p.post("/api/auth/recovery-codes").status_code == 200


def test_cancel_revokes_the_keys_the_waiting_key_vouched_for(app):
    p, lost, lap, ph = _setup(app, "Ned")
    k2 = _vouched_by_waiting(app, p, lap, ph)
    switch_auth(p, k2)
    assert stepup_with(p, k2).status_code == 200                                      # k2 has a session
    switch_auth(p, lost)
    assert stepup_with(p, lost).status_code == 200
    c = p.post("/api/auth/keys/%s/cancel-phone" % ph.kid.hex())
    assert c.status_code == 200, c.text
    assert c.json()["keys_removed"] == [k2.kid.hex()]
    active = {k["kid_hex"] for k in p.c.get("/api/auth/keys").json()["keys"] if k.get("active")}
    assert k2.kid.hex() not in active and lap.kid.hex() in active and lost.kid.hex() in active
    db = app.state.ctx.db
    row = db.one("SELECT id FROM credentials WHERE kid=?", (k2.kid,))
    assert db.one("SELECT COUNT(*) AS n FROM sessions WHERE credential_id=?", (row["id"],))["n"] == 0
    rows = [json.loads(r["entry_json"]).get("key_device") for r in db.q("SELECT entry_json FROM registry_log WHERE kid=?", (k2.kid,))]
    assert any(r and r.get("stopped") and r["vouched_by"] == ph.kid.hex() and r["by"] == lost.kid.hex() for r in rows)
    assert ph.kid.hex() not in active                                                 # the cancelled key itself is stopped as well


def test_the_cancelled_key_itself_cannot_come_back(app):
    """Before 0.2.17 the cancelled key stayed a laptop key: its holder signed in again, made new recovery codes, removed the owner's laptop."""
    from tests.recovery_helpers import login_with
    p, lost, lap, ph = _setup(app, "Pia")
    switch_auth(p, lost)
    assert stepup_with(p, lost).status_code == 200
    assert p.post("/api/auth/keys/%s/cancel-phone" % ph.kid.hex()).status_code == 200
    assert login_with(p, ph).status_code != 200
    assert remove_key(p, lap.kid.hex(), signer=ph).status_code == 409
    active = {k["kid_hex"] for k in p.c.get("/api/auth/keys").json()["keys"] if k.get("active")}
    assert active == {lost.kid.hex(), lap.kid.hex()}


def test_pack_shows_the_stop(app):
    """The stop is in the ownership chain as the witness's key_device record, and the evidence pack's checker reads it (no new key_event kind:
    a checker of 0.2.16 reads the pack as before)."""
    import sys
    p, lost, lap, ph = _setup(app, "Quin")
    k2 = _vouched_by_waiting(app, p, lap, ph)
    switch_auth(p, lost)
    assert stepup_with(p, lost).status_code == 200
    assert p.post("/api/auth/keys/%s/cancel-phone" % ph.kid.hex()).status_code == 200
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packtools"))
    import verify_pack
    log = [{"row_json": r["entry_json"]} for r in app.state.ctx.db.q("SELECT entry_json FROM registry_log WHERE account_id=? ORDER BY seq", ("keys:" + p.uid,))]
    lines = [x for x, bad in verify_pack._device_lines({"log": log}, "dw:" + p.uid)]
    assert any("CANCELLED" in x and "stopped by the witness" in x for x in lines), lines
    assert any(x.startswith("keys: %s stopped by the witness" % k2.kid.hex()[:8]) for x in lines), lines


def test_removing_the_waiting_key_removes_what_it_vouched_for(app):
    p, lost, lap, ph = _setup(app, "Ola")
    k2 = _vouched_by_waiting(app, p, lap, ph)
    switch_auth(p, lost)
    assert stepup_with(p, lost).status_code == 200
    r = remove_key(p, ph.kid.hex(), signer=lost)
    assert r.status_code == 200, r.text
    active = {k["kid_hex"] for k in p.c.get("/api/auth/keys").json()["keys"] if k.get("active")}
    assert ph.kid.hex() not in active and k2.kid.hex() not in active and lap.kid.hex() in active
