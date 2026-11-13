"""0.2.2: access after a lost phone, without weakening the rest. One test per rule (docs/recovery.md):
 D1 a second passkey is added only with a signature by a CURRENT passkey over the exact new key (not by the new key, not by a cookie)
 D2 the device list; removal is signed too; the last passkey cannot be removed
 D3 a removed passkey never signs in, never steps up, never signs for the ledger; sessions it opened end
 C1 recovery codes: 10, shown once, step-up to make them, only scrypt hashes stored, new set voids the old one
 C2 a code works once and opens ONLY "add a new passkey"; every session ends; the person's devices get a push
 C3 the passkey added with a code is active, recorded "by recovery-code"; the recovery session ends
 M1 mandates signed by a lost key stay valid; the owner revokes them with the new key in one ceremony
 P1 the evidence pack shows every key change and stays VALID; a signature after a key's removal is INVALID"""
import json
import sqlite3

from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
import wa_profile as wa
from tests.helpers import FORM, H, ORIGIN, act
from tests.org_helpers import Person, ctx_of
from tests.recovery_helpers import (add_key, export_to, login_with, new_codes, recover, remove_key, revoke_batch, run_verify,
                                    stepup_with, switch_auth)
from tests.test_push import Clock, Device, FakeSender, subscribe  # noqa: F401  (fixtures below)


def keys_of(p):
    r = p.c.get("/api/auth/keys")
    assert r.status_code == 200, r.text
    return r.json()["keys"]


# ---------------------------------------------------------------- D1
def test_d1_second_passkey_needs_signature_of_current_one(app):
    p = Person(app).register("Alice")
    # signed by the NEW passkey itself: refused, nothing added
    nw = wa.SoftAuthenticator()
    j = p.post("/api/auth/keys/add/begin", label="yubikey").json()
    assert [c["id"] for c in j["options"]["excludeCredentials"]] == [wa.b64u(p.auth.credential_id)]     # the same device never twice
    f = p.post("/api/auth/keys/add/finish", flow_id=j["flow_id"], credential=nw.create_credential(wa.b64u_dec(j["options"]["challenge"]), "localhost", ORIGIN)).json()
    assert f["typ"] == "application/dw-key-event+cbor" and f["kid_hex"] == nw.kid.hex()
    assert login_with(Person(app), nw).status_code == 401                     # created, but NOT active before the confirmation
    self_env = wa.b64u(nw.sign_object(f["typ"], wa.b64u_dec(f["payload_b64"]), "localhost", ORIGIN))
    r = p.post("/api/auth/keys/add/confirm", confirm_id=f["confirm_id"], envelope_b64=self_env)
    assert r.status_code == 409 and r.json()["error"] == "KEY_SELF", r.text
    # the flow is one-time: the refused attempt consumed it
    r = p.post("/api/auth/keys/add/confirm", confirm_id=f["confirm_id"], envelope_b64=wa.b64u(p.auth.sign_object(f["typ"], wa.b64u_dec(f["payload_b64"]), "localhost", ORIGIN)))
    assert r.status_code == 400 and r.json()["error"] == "FLOW_UNKNOWN"
    # a signature by the current passkey over ANOTHER payload: refused
    other = Person(app).register("Mallory")
    new, r = add_key(p, signer=other.auth)                    # someone else's passkey
    assert r.status_code == 409 and r.json()["error"] == "KEY_NOT_ACTIVE", r.text
    j = p.post("/api/auth/keys/add/begin").json()
    n2 = wa.SoftAuthenticator()
    f = p.post("/api/auth/keys/add/finish", flow_id=j["flow_id"], credential=n2.create_credential(wa.b64u_dec(j["options"]["challenge"]), "localhost", ORIGIN)).json()
    wrong = wa.b64u(p.auth.sign_object(f["typ"], b"\xa0", "localhost", ORIGIN))
    r = p.post("/api/auth/keys/add/confirm", confirm_id=f["confirm_id"], envelope_b64=wrong)
    assert r.status_code == 409 and r.json()["error"] == "KEY_EVENT_SIG", r.text
    # a cookie alone (no passkey at all) cannot add one either: without an envelope there is nothing to confirm with
    j = p.post("/api/auth/keys/add/begin").json()
    f = p.post("/api/auth/keys/add/finish", flow_id=j["flow_id"], credential=wa.SoftAuthenticator().create_credential(wa.b64u_dec(j["options"]["challenge"]), "localhost", ORIGIN)).json()
    assert p.post("/api/auth/keys/add/confirm", confirm_id=f["confirm_id"]).status_code == 409
    assert len(keys_of(p)) == 1
    # the honest path
    new, r = add_key(p, label="YubiKey 5")
    assert r.status_code == 200 and r.json()["added_by"] == "passkey" and r.json()["signed_by"] == p.auth.kid.hex(), r.text
    assert login_with(Person(app), new).status_code == 200


# ---------------------------------------------------------------- D2
def test_d2_list_remove_signed_last_key_kept(app):
    p = Person(app).register("Alice")
    ks = keys_of(p)
    assert [(k["label"], k["active"], k["this_session"], k["added_by"]) for k in ks] == [("first passkey", True, True, "registration")]
    r = remove_key(p, p.auth.kid.hex())
    assert r.status_code == 409 and r.json()["error"] == "LAST_KEY", r.text
    new, r = add_key(p, label="laptop")
    assert r.status_code == 200
    ks = keys_of(p)
    assert [k["label"] for k in ks] == ["first passkey", "laptop"] and all(k["active"] for k in ks)
    # removal is a signature too: one by someone else's passkey does nothing
    other = Person(app).register("Mallory")
    r = remove_key(p, new.kid.hex(), signer=other.auth)
    assert r.status_code == 409 and r.json()["error"] == "KEY_NOT_ACTIVE"
    r = remove_key(p, new.kid.hex())
    assert r.status_code == 200 and r.json()["signed_by"] == p.auth.kid.hex(), r.text
    assert [k["active"] for k in keys_of(p)] == [True, False]
    assert remove_key(p, p.auth.kid.hex()).json()["error"] == "LAST_KEY"         # again the only active one
    assert p.post("/api/auth/keys/%s/remove/begin" % ("00" * 32)).status_code == 404
    assert Person(app).register("X").post("/api/auth/keys/%s/remove/begin" % p.auth.kid.hex()).status_code == 404   # not yours


# ---------------------------------------------------------------- D3
def test_d3_removed_key_is_dead_everywhere(app, monkeypatch):
    p = Person(app).register("Alice")
    phone = p.auth
    laptop, r = add_key(p)
    assert r.status_code == 200
    thief = Person(app)                                       # the lost phone, still signed in
    thief.auth, thief.account = phone, p.account
    assert login_with(thief, phone).status_code == 200
    assert thief.c.get("/api/me").status_code == 200
    # the owner, on the laptop, removes the phone
    lap = Person(app)
    lap.auth, lap.account = laptop, p.account
    assert login_with(lap, laptop).status_code == 200
    r = remove_key(lap, phone.kid.hex(), signer=laptop)
    assert r.status_code == 200, r.text
    assert thief.c.get("/api/me").status_code == 401                         # the session the phone opened is gone
    r = login_with(thief, phone)
    assert r.status_code == 401 and r.json()["error"] == "CREDENTIAL_REVOKED"
    r = stepup_with(lap, phone)
    assert r.status_code == 401 and r.json()["error"] == "CREDENTIAL_REVOKED"
    # the ledger refuses a mandate signed by the removed key, accepts one by the laptop
    assert stepup_with(lap, laptop).status_code == 200
    ag = lap.post("/api/agents", name="bot", preset="demo").json()["agent"]
    d = lap.post("/api/mandates/draft", agent_id=ag["id"], form=FORM).json()["mandate"]
    r = lap.post("/api/mandates", mandate=d, envelope_b64=wa.b64u(phone.sign_object(wa.TYP_MANDATE, wa.cde(d), "localhost", ORIGIN)))
    assert r.status_code == 409 and r.json()["error"] == "KEY_REVOKED", r.text
    from app import org as _org
    monkeypatch.setattr(_org, "refuse_revoked", lambda ctx, env: None)    # without the server's own check, the LEDGER's key set refuses it
    r = lap.post("/api/mandates", mandate=d, envelope_b64=wa.b64u(phone.sign_object(wa.TYP_MANDATE, wa.cde(d), "localhost", ORIGIN)))
    assert r.status_code == 409 and r.json()["error"] == "KEY_MISMATCH", r.text
    monkeypatch.undo()
    r = lap.post("/api/mandates", mandate=d, envelope_b64=wa.b64u(laptop.sign_object(wa.TYP_MANDATE, wa.cde(d), "localhost", ORIGIN)))
    assert r.status_code == 200, r.text
    me = lap.c.get("/api/me").json()
    assert me["keycard"]["kid_hex"] == laptop.kid.hex() and [k["kid_hex"] for k in me["signing_keys"]] == [laptop.kid.hex()]


# ---------------------------------------------------------------- C1
def test_c1_codes_shown_once_hashed_stepup(app, cfg):
    p = Person(app).register("Alice")
    ctx_of(app).db.x("UPDATE sessions SET stepup_at=0")                       # the login's fresh signature is long past
    r = p.post("/api/auth/recovery-codes")
    assert r.status_code == 403 and r.json()["error"] == "STEPUP_REQUIRED"
    codes = new_codes(p)
    assert len(codes) == 10 and len(set(codes)) == 10
    assert all(len(c) == 24 and c.count("-") == 4 for c in codes)
    st = p.c.get("/api/auth/recovery-codes").json()
    assert st["total"] == 10 and st["remaining"] == 10 and "codes" not in st
    shown = json.dumps(p.c.get("/api/auth/keys").json()) + json.dumps(st)
    assert not any(c in shown or c.replace("-", "") in shown for c in codes)
    # only hashes: no code (nor its secret part) is anywhere in the database file
    db = ctx_of(app).db
    rows = db.q("SELECT * FROM recovery_codes")
    assert len(rows) == 10 and all(len(bytes(r["hash"])) == 32 and len(bytes(r["salt"])) == 16 for r in rows)
    with open(cfg.data_dir + "/db.sqlite", "rb") as f:
        raw = f.read()
    for c in codes:
        assert c.encode() not in raw and c.replace("-", "")[4:].encode() not in raw
    # a new set voids the old one
    old = codes[0]
    codes2 = new_codes(p)
    r = TestClient(app, base_url=ORIGIN).post("/api/auth/recovery/login", json={"code": old}, headers=H)
    assert r.status_code == 401 and r.json()["error"] == "RECOVERY_INVALID"
    assert TestClient(app, base_url=ORIGIN).post("/api/auth/recovery/login", json={"code": codes2[0]}, headers=H).status_code == 200


# ---------------------------------------------------------------- C2
def test_c2_code_once_only_add_passkey_all_sessions_end(app):
    p = Person(app).register("Alice")
    codes = new_codes(p)
    second = Person(app)
    second.auth, second.account = p.auth, p.account
    assert login_with(second, p.auth).status_code == 200
    br = TestClient(app, base_url=ORIGIN)
    assert br.post("/api/auth/recovery/login", json={"code": "AAAA-BBBB-CCCC-DDDD-EEEE"}, headers=H).status_code == 401
    assert br.post("/api/auth/recovery/login", json={"code": codes[3]}).status_code == 403          # Origin
    r = br.post("/api/auth/recovery/login", json={"code": codes[3].lower().replace("-", " ")}, headers=H)
    assert r.status_code == 200 and r.json()["scope"] == "recovery" and r.json()["codes_left"] == 9, r.text
    assert p.c.get("/api/me").status_code == 401 and second.c.get("/api/me").status_code == 401     # every session ended
    # the recovery session opens nothing but "add a new passkey"
    for m, path in (("GET", "/api/me"), ("GET", "/api/agents"), ("GET", "/api/mandates"), ("GET", "/api/auth/keys"),
                    ("GET", "/api/auth/recovery-codes"), ("POST", "/api/auth/recovery-codes"), ("POST", "/api/agents"),
                    ("POST", "/api/auth/keys/add/begin"), ("POST", "/api/auth/stepup/begin"), ("GET", "/api/export"),
                    ("POST", "/api/auth/logout-all"), ("GET", "/api/org"), ("POST", "/api/mandates/revoke-batch")):
        r = br.request(m, path, json={}, headers=H)
        assert r.status_code == 403 and r.json()["error"] == "RECOVERY_ONLY", (m, path, r.status_code, r.text)
    assert br.get("/api/auth/recovery/state").json()["codes_left"] == 9
    # the same code never works twice
    r = TestClient(app, base_url=ORIGIN).post("/api/auth/recovery/login", json={"code": codes[3]}, headers=H)
    assert r.status_code == 401 and r.json()["error"] == "RECOVERY_INVALID"
    # a full session is not a recovery session
    assert login_with(p, p.auth).status_code == 200
    assert p.post("/api/auth/recovery/passkey/begin").status_code == 401


def test_c2_push_to_devices_on_code_use(tmp_path):
    from tests.test_push import vapid_pem
    from app.config import Config
    from app.main import create_app
    kf = tmp_path / "witness_key"
    kf.write_text("a1" * 32)
    vk = tmp_path / "vapid.pem"
    vapid_pem(vk)
    a = create_app(Config(data_dir=str(tmp_path / "data"), witness_key_file=str(kf), key_pepper="p", rp_id="localhost", origin=ORIGIN,
                          iss="https://witness.test", anchor="off", web_dir="", vapid_key_file=str(vk), push_hosts="push.test",
                          push_allow_http=True, push_per_min=1))
    pu = a.state.ctx.push
    pu.sender, pu.retry_delays, pu.clock = FakeSender(), (0, 0), Clock()
    p = Person(a).register("Alice")
    tablet = Device("https://fcm.push.test/send/tablet")
    assert subscribe(p, tablet).status_code == 200
    other = Person(a).register("Bob")
    assert subscribe(other, Device("https://fcm.push.test/send/bob")).status_code == 200
    codes = new_codes(p)
    assert pu.drain()
    pu.sender.calls.clear()
    assert TestClient(a, base_url=ORIGIN).post("/api/auth/recovery/login", json={"code": codes[0]}, headers=H).status_code == 200
    assert pu.drain()
    assert [(c["endpoint"], c["data"], c["topic"]) for c in pu.sender.calls] == [(tablet.endpoint, {"v": 2, "k": "r"}, "dw-security")]
    # adding / removing a passkey is told the same way, even right after (never merged away, no per-minute limit)
    login_with(p, p.auth)
    new, r = add_key(p)
    assert r.status_code == 200 and pu.drain()
    assert [c["data"] for c in pu.sender.calls][-1] == {"v": 2, "k": "k"}
    assert all(c["endpoint"] == tablet.endpoint for c in pu.sender.calls)    # only the person's own devices


# ---------------------------------------------------------------- C3
def test_c3_recovery_adds_passkey_then_ends(app):
    p = Person(app).register("Alice")
    codes = new_codes(p)
    new, br, f = recover(app, p, codes[0])
    assert f.status_code == 200 and f.json()["added_by"] == "recovery-code" and f.json()["codes_left"] == 9, f.text
    assert br.get("/api/auth/recovery/state").status_code == 401                  # the recovery session is over
    assert br.get("/api/me").status_code == 401
    switch_auth(p, new)
    ks = keys_of(p)
    assert [(k["added_by"], k["active"]) for k in ks] == [("registration", True), ("recovery-code", True)]
    # the registry log names how the key came in
    rows = ctx_of(app).db.q("SELECT entry_json FROM registry_log WHERE account_id=?", ("keys:" + p.uid,))
    ev = json.loads(rows[-1]["entry_json"])["key_event"]
    assert ev["op"] == "add" and ev["by"] == "recovery-code" and ev["kid"] == new.kid.hex() and "envelope_hex" not in ev
    # now the lost phone is removed with the new passkey
    r = remove_key(p, ks[0]["kid_hex"])
    assert r.status_code == 200, r.text
    assert [k["active"] for k in keys_of(p)] == [False, True]


# ---------------------------------------------------------------- M1 + P1
def test_m1_old_mandates_valid_then_one_step_revoke_and_pack(app, tmp_path):
    p = Person(app).register("Alice")
    phone = p.auth
    ags = []
    for i in range(3):
        ag, hdr = p.new_agent("demo", "bot%d" % i)
        m, r = p.mandate(ag["id"])
        assert r.status_code == 200, r.text
        ags.append((ag, hdr, m))
    codes = new_codes(p)
    # the phone is lost: recovery code -> new passkey -> remove the phone
    new, br, f = recover(app, p, codes[0])
    assert f.status_code == 200
    switch_auth(p, new)
    assert remove_key(p, phone.kid.hex()).status_code == 200
    # mandates signed by the lost key stay valid: the agents keep working
    assert act(p.c, ags[0][1], "send_email", {"to": "bob@partner.example", "subject": "s"}).json()["verdict"] == "allow"
    assert {x["status"] for x in p.c.get("/api/mandates").json()} == {"active"}
    rc, out = run_verify(export_to(p.c, tmp_path / "a"), "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    assert "keys: 2 keys (1 added: 0 by passkey, 1 by recovery code (witness-attested); 1 removed)" in out, out
    # the owner finds them by key and revokes them with the NEW passkey in one ceremony
    lst = p.c.get("/api/mandates/by-key/" + phone.kid.hex()).json()
    mids = [x["id"] for x in lst["mandates"]]
    assert sorted(mids) == sorted(m["id"] for _, _, m in ags) and lst["max_per_batch"] == 20
    r = revoke_batch(p, mids, signer=phone)                                   # the lost key cannot do it
    assert r.status_code == 409 and r.json()["error"] == "KEY_REVOKED", r.text
    r = revoke_batch(p, mids)
    assert r.status_code == 200 and r.json()["revoked"] == mids, r.text
    assert {x["status"] for x in p.c.get("/api/mandates").json()} == {"revoked"}
    assert act(p.c, ags[1][1], "send_email", {"to": "bob@partner.example", "subject": "s"}).json()["verdict"] == "deny"
    assert p.c.get("/api/mandates/by-key/" + phone.kid.hex()).json()["mandates"] == []
    rc, out = run_verify(export_to(p.c, tmp_path / "b"), "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    assert "6/6 signatures by a key active at the time" in out, out           # 3 mandates (phone) + 3 revocations (one wb, new key)


def test_m1_batch_must_cover_and_be_typed(app):
    p = Person(app).register("Alice")
    ag, _ = p.new_agent()
    m, r = p.mandate(ag["id"])
    ag2, _ = p.new_agent("demo", "b2")
    m2, _ = p.mandate(ag2["id"])
    import hashlib
    import wq_profile as wq
    from svidetel_v4.state import revocation_payload
    items = [hashlib.sha256(revocation_payload(m)).digest()]
    ad, cd, der = p.auth.get_assertion(wq.wb_challenge(items, wa.TYP_REVOCATION), "localhost", ORIGIN)
    env = wa.b64u(wq.make_wb(items, p.auth.kid, ad, cd, der, typ=wa.TYP_REVOCATION))
    r = p.post("/api/mandates/revoke-batch", mandate_ids=[m["id"], m2["id"]], envelope_b64=env)
    assert r.status_code == 409 and r.json()["error"] == "WB_ITEM"                     # m2 is not in the batch: nothing revoked
    assert {x["status"] for x in p.c.get("/api/mandates").json()} == {"active"}
    ad, cd, der = p.auth.get_assertion(wq.wb_challenge(items), "localhost", ORIGIN)     # an APPROVAL batch over the same items
    env = wa.b64u(wq.make_wb(items, p.auth.kid, ad, cd, der))
    r = p.post("/api/mandates/revoke-batch", mandate_ids=[m["id"]], envelope_b64=env)
    assert r.status_code == 409 and r.json()["error"] == "REVOCATION_SIG", r.text


def _rehash_from(reg, i):
    import hashlib
    prev = bytes.fromhex(reg["log"][i - 1]["hash"]) if i else b""
    for r in reg["log"][i:]:
        r["prev"] = prev.hex()
        body = r.get("entry_json") or r.get("row_json")
        if body is not None:
            r["hash"] = hashlib.sha256(prev + body.encode()).hexdigest()
        prev = bytes.fromhex(r["hash"])
    reg["head"] = prev.hex()


def test_p1_checker_rejects_signature_after_removal(app, tmp_path):
    """A pack whose registry log claims the phone was removed BEFORE it signed a mandate is INVALID, even with a consistent hash chain
    (the second pass of 0.2.2); and a key 'added by passkey' signed by the new key itself is refused."""
    import hashlib
    import os
    p = Person(app).register("Alice")
    phone = p.auth
    laptop, r = add_key(p)
    ag, _ = p.new_agent()
    m, r = p.mandate(ag["id"])
    assert r.status_code == 200
    assert remove_key(p, phone.kid.hex(), signer=laptop).status_code == 200
    assert p.c.get("/api/me").status_code == 401             # this session was opened with the phone: it ended with it
    switch_auth(p, laptop)
    d = export_to(p.c, tmp_path / "pk")
    rc, out = run_verify(d, "--offline")
    assert rc == 0 and "keys: 2 keys (1 added: 1 by passkey, 0 by recovery code (witness-attested); 1 removed)" in out, out

    def resealed(mut):
        import shutil
        d2 = str(tmp_path / ("x%d" % len(os.listdir(tmp_path))))
        shutil.copytree(d, d2)
        reg = json.load(open(os.path.join(d2, "registry.json")))
        mut(reg)
        open(os.path.join(d2, "registry.json"), "w").write(json.dumps(reg))
        man = json.load(open(os.path.join(d2, "manifest.json")))
        man["files"]["registry.json"] = hashlib.sha256(open(os.path.join(d2, "registry.json"), "rb").read()).hexdigest()
        open(os.path.join(d2, "manifest.json"), "w").write(json.dumps(man))
        return run_verify(d2, "--offline")[1]

    def early_removal(reg):
        i = max(k for k, r in enumerate(reg["log"]) if "row_json" in r)
        rj = json.loads(reg["log"][i]["row_json"])
        rj["key_event"]["t"] = 1                     # "removed long ago"
        reg["log"][i]["row_json"] = json.dumps(rj, sort_keys=True, separators=(",", ":"))
        _rehash_from(reg, i)
    out = resealed(early_removal)
    assert "RESULT: INVALID" in out and ("keys: FAIL" in out), out

    def self_vouched(reg):
        i = min(k for k, r in enumerate(reg["log"]) if "row_json" in r)
        rj = json.loads(reg["log"][i]["row_json"])
        ev = rj["key_event"]
        ev["envelope_hex"] = laptop.sign_object("application/dw-key-event+cbor", bytes.fromhex(ev["payload_hex"]), "localhost", ORIGIN).hex()
        reg["log"][i]["row_json"] = json.dumps(rj, sort_keys=True, separators=(",", ":"))
        _rehash_from(reg, i)
    out = resealed(self_vouched)
    assert "keys: FAIL KEY_EVENT_SIGNER" in out and "RESULT: INVALID" in out, out


# ---------------------------------------------------------------- D4: every signing path takes any ACTIVE passkey of a solo account
def test_d4_second_passkey_signs_everything_removed_one_nothing(app, tmp_path):
    import base64
    import hashlib
    import wq_profile as wq
    from svidetel_v4.state import approval_payload
    p = Person(app).register("Alice")
    phone = p.auth
    lap, r = add_key(p)
    assert r.status_code == 200
    switch_auth(p, lap)                                       # from now on: the laptop's passkey
    ag, hdr = p.new_agent()
    m, r = p.mandate(ag["id"])
    assert r.status_code == 200, r.text
    d = act(p.c, hdr, "publish", {"channel": "blog", "text": "one"}).json()
    assert d["verdict"] == "defer"
    r = p.approve(d["rid"])                                   # a single approval by the second passkey
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    rids = [act(p.c, hdr, "publish", {"channel": "blog", "text": "t%d" % i}).json()["rid"] for i in range(3)]
    g = p.c.get("/api/approvals/groups").json()["groups"]
    items = [base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)) for x in g[0]["items_approve_b64"]]
    ad, cd, der = lap.get_assertion(wq.wb_challenge(items), "localhost", ORIGIN)
    r = p.post("/api/approvals/batch", rids=g[0]["rids"], approved=True, envelope_b64=wa.b64u(wq.make_wb(items, lap.kid, ad, cd, der)))
    assert r.status_code == 200 and [x["verdict"] for x in r.json()["results"]] == ["allow"] * 3, r.text
    # the phone is removed: neither its wa-sig nor its batch nor a hand-built wq with it counts any more
    assert remove_key(p, phone.kid.hex()).status_code == 200
    d = act(p.c, hdr, "publish", {"channel": "blog", "text": "two"}).json()
    g = p.c.get("/api/approvals/" + d["rid"]).json()
    pay = approval_payload(g["mandate"], g["action"], d["rid"], True)
    r = p.post("/api/approvals/" + d["rid"], approved=True, envelope_b64=wa.b64u(phone.sign_object(wa.TYP_APPROVAL, pay, "localhost", ORIGIN)))
    assert r.status_code == 409 and r.json()["error"] == "KEY_REVOKED", r.text
    items = [hashlib.sha256(pay).digest()]
    ad, cd, der = phone.get_assertion(wq.wb_challenge(items), "localhost", ORIGIN)
    r = p.post("/api/approvals/batch", rids=[d["rid"]], approved=True, envelope_b64=wa.b64u(wq.make_wb(items, phone.kid, ad, cd, der)))
    assert r.status_code == 409 and "KEY_REVOKED" in r.text, r.text
    assert p.approve(d["rid"]).json()["verdict"] == "allow"
    rc, out = run_verify(export_to(p.c, tmp_path / "pk"), "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    assert "batch approvals" not in out and "keys: 2 keys (1 added: 1 by passkey" in out, out
