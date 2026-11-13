"""0.2.15: (1) a phone declared with a recovery code waits 24 h (24-72 h configurable) before it counts as phone; the other devices are
told at once and can cancel; a team quorum (rule `recovery`, k >= 2) can end the wait early; the evidence pack shows the wait.
(2) delegation in the SIGNED team policy (rules.delegation): put/end draft a policy version; verify_wq refuses the operator (WQ_SELF)
and non-approvers (WQ_NOT_DELEGATE); verify_pack proves both offline; approvals of agents not named say `trust:` (before the transfer)."""
import hashlib
import json
import os
import time

import cbor2
import pytest

from app import _paths  # noqa: F401
from app import levels
import wa_profile as wa
import wq_profile as wq
from svidetel_v4.state import approval_payload
from tests.helpers import H, ORIGIN, RP, act
from tests.org_helpers import MSG_FORM, TEAM_RULES, Person, adopt, ctx_of, policy_hash_now, team
from tests.recovery_helpers import (add_key, elapse_phone_wait, export_to, login_with, new_codes, recover, remove_key, run_verify,
                                    stepup_with, switch_auth)

DAY = 86400


def keys_of(p):
    return {k["kid_hex"]: k for k in p.c.get("/api/auth/keys").json()["keys"]}


def kd_rows(app, uid):
    return [json.loads(r["entry_json"])["key_device"] for r in ctx_of(app).db.q("SELECT entry_json FROM registry_log WHERE account_id=?", ("keys:" + uid,))
            if "key_device" in json.loads(r["entry_json"])]


def laptop_key(p):
    lap, r = add_key(p, label="laptop")
    assert r.status_code == 200, r.text
    assert stepup_with(p, p.auth).status_code == 200
    assert p.post("/api/auth/keys/%s/device" % lap.kid.hex(), device="laptop").status_code == 200
    return lap


def declare_phone(app, p, code, wait=False):
    new, br, f = recover(app, p, code, device="phone", wait=wait)
    assert f.status_code == 200, f.text
    return new, f.json()


def cancel(p, auth, kid):
    assert stepup_with(p, auth).status_code == 200
    return p.post("/api/auth/keys/%s/cancel-phone" % kid.hex())


# ================================================================ (1) the wait of a recovery-declared phone
def test_declared_phone_waits_24h_counts_as_laptop_and_registry_names_not_before(app):
    p = Person(app).register("Rita")
    codes = new_codes(p)
    lost = p.auth
    t0 = int(time.time())
    ph, f = declare_phone(app, p, codes[0])
    assert f["device"] == "phone" and t0 + DAY <= f["phone_not_before"] <= int(time.time()) + DAY and f["delay_h"] == 24
    assert "counts as your phone from" in f["next"]
    ctx = ctx_of(app)
    assert levels.device_of_kid(ctx, ph.kid) == levels.LAPTOP                    # waiting: a laptop key
    switch_auth(p, ph)
    k = keys_of(p)[ph.kid.hex()]
    assert k["counts_as"] == "laptop" and k["device"] == "phone" and k["phone_not_before"] == f["phone_not_before"]
    r = remove_key(p, lost.kid.hex(), signer=ph)                                 # cannot remove the (lost) phone yet
    assert r.status_code == 409 and r.json()["error"] == "DEVICE_LEVEL", r.text
    assert stepup_with(p, ph).status_code == 200                                 # nor mark itself phone through the back door
    r = p.post("/api/auth/keys/%s/device" % ph.kid.hex(), device="phone")
    assert r.status_code == 403 and r.json()["error"] == "DEVICE_LEVEL"
    rows = [x for x in kd_rows(app, p.uid) if x["kid"] == ph.kid.hex()]
    assert rows[-1]["by"] == "recovery-code" and rows[-1]["not_before"] == f["phone_not_before"]
    elapse_phone_wait(app, ph.kid)                                               # 24 h later
    assert levels.device_of_kid(ctx, ph.kid) == levels.PHONE
    assert remove_key(p, lost.kid.hex(), signer=ph).status_code == 200


def test_delay_is_configurable_24_to_72_hours(tmp_path):
    from app.config import Config, ConfigError
    from app.main import create_app
    from fastapi.testclient import TestClient  # noqa: F401
    base = {"DW_DATA_DIR": str(tmp_path / "d"), "DW_WITNESS_KEY_FILE": str(tmp_path / "k"), "DW_RP_ID": "localhost", "DW_ORIGIN": ORIGIN,
            "DW_KEY_PEPPER": "p"}
    assert Config.from_env(base).recovery_phone_delay_h == 24
    assert Config.from_env(dict(base, DW_RECOVERY_PHONE_DELAY_H="72")).recovery_phone_delay_h == 72
    for bad in ("23", "73", "x", "0"):
        with pytest.raises(ConfigError):
            Config.from_env(dict(base, DW_RECOVERY_PHONE_DELAY_H=bad))
    kf = tmp_path / "witness_key"
    kf.write_text("a1" * 32)
    a = create_app(Config(data_dir=str(tmp_path / "data"), witness_key_file=str(kf), key_pepper="p", rp_id="localhost", origin=ORIGIN,
                          iss="https://witness.test", anchor="off", web_dir="", recovery_phone_delay_h=48))
    p = Person(a).register("Max")
    codes = new_codes(p)
    t0 = int(time.time())
    _, f = declare_phone(a, p, codes[0])
    assert f["delay_h"] == 48 and t0 + 2 * DAY <= f["phone_not_before"] <= int(time.time()) + 2 * DAY


def test_push_p_to_every_device_at_once(tmp_path):
    from app.config import Config
    from app.main import create_app
    from tests.test_push import Clock, Device, FakeSender, subscribe, vapid_pem
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
    codes = new_codes(p)
    assert pu.drain()
    pu.sender.calls.clear()
    declare_phone(a, p, codes[0])
    assert pu.drain()
    assert [c["data"] for c in pu.sender.calls] == [{"v": 2, "k": "r"}, {"v": 2, "k": "p"}]   # code used, then "a new phone was declared"
    sw = open(os.path.join(os.path.dirname(__file__), "..", "..", "web", "sw.js"), encoding="utf-8").read()
    assert "p: ['Deus Witness - security'" in sw and "not me - cancel" in sw


def test_cancel_by_the_phone_when_there_is_one_laptop_may_not(app):
    """The person still has the phone; someone used a stolen code to declare their own device "the new phone"."""
    p = Person(app).register("Ann")              # key = phone (unmarked)
    lap = laptop_key(p)
    codes = new_codes(p)
    att, f = declare_phone(app, p, codes[0])
    login_with(p, p.auth)
    r = cancel(p, lap, att.kid)                                                  # the laptop (the agent's computer) may not
    assert r.status_code == 403 and r.json()["error"] == "DEVICE_LEVEL", r.text
    r = cancel(p, p.auth, att.kid)                                               # the phone may
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["cancelled"] is True and j["recovery_codes_stopped"] == 9
    assert p.c.get("/api/auth/recovery-codes").json()["remaining"] == 0          # the rest of the stolen sheet is dead
    k = keys_of(p)[att.kid.hex()]
    assert k["device"] == "laptop" and k["phone_not_before"] is None
    elapse_phone_wait(app, att.kid)
    assert levels.device_of_kid(ctx_of(app), att.kid) == levels.LAPTOP          # never becomes a phone
    rows = [x for x in kd_rows(app, p.uid) if x["kid"] == att.kid.hex()]
    assert rows[-1]["cancelled"] is True and rows[-1]["by"] == p.auth.kid.hex()
    assert cancel(p, p.auth, att.kid).json()["error"] == "NOT_PENDING"
    # 0.2.17 (R9-03): the cancelled key is stopped at once (before: it stayed a laptop key the owner had to remove; its holder could sign in again)
    assert rows[-1]["stopped"] is True and k["active"] is False
    assert remove_key(p, att.kid.hex(), signer=p.auth).json()["error"] == "KEY_NOT_ACTIVE"


def test_cancel_without_a_phone_any_other_live_key_never_a_waiting_one(app):
    p = Person(app).register("Ben")
    orig = p.auth
    assert stepup_with(p, p.auth).status_code == 200
    assert p.post("/api/auth/keys/%s/device" % p.auth.kid.hex(), device="laptop").status_code == 200   # no phone at all
    codes = new_codes(p)
    a1, _ = declare_phone(app, p, codes[0])
    a2, _ = declare_phone(app, p, codes[1])
    login_with(p, a2)
    r = cancel(p, a2, a1.kid)                                                    # another waiting key: no
    assert r.status_code == 403 and "waiting" in r.json()["detail"], r.text
    login_with(p, a1)
    assert cancel(p, a1, a1.kid).status_code == 403                              # itself: no
    login_with(p, orig)
    assert cancel(p, orig, a1.kid).status_code == 200                            # no phone: any other live key that does not wait
    r = remove_key(p, a2.kid.hex(), signer=a1)                                   # 0.2.17 (R9-03): a1 is stopped (before: an ordinary laptop key)
    assert r.status_code == 409 and r.json()["error"] == "KEY_NOT_ACTIVE", r.text


@pytest.fixture(autouse=True)
def _keep_original_auth(monkeypatch):
    orig_register = Person.register

    def reg(self, *a, **kw):
        out = orig_register(self, *a, **kw)
        self._orig = self.auth
        return out
    monkeypatch.setattr(Person, "register", reg)


def test_removing_a_waiting_key_follows_the_cancel_rule(app):
    p = Person(app).register("Cid")
    lap = laptop_key(p)
    codes = new_codes(p)
    att, _ = declare_phone(app, p, codes[0])
    login_with(p, p.auth)
    r = remove_key(p, att.kid.hex(), signer=lap)                                 # the laptop may not clear a recovery (the phone exists)
    assert r.status_code == 403 and r.json()["error"] == "DEVICE_LEVEL", r.text
    assert remove_key(p, att.kid.hex(), signer=p.auth).status_code == 200


def test_all_devices_lost_the_wait_still_holds(app):
    p = Person(app).register("Dan")
    codes = new_codes(p)
    lost = p.auth
    ph, _ = declare_phone(app, p, codes[0])
    switch_auth(p, ph)
    ctx = ctx_of(app)
    # the only live key besides the lost one is waiting: nothing at the phone level for 24 h, whatever is tried
    assert levels.device_of_kid(ctx, ph.kid) == levels.LAPTOP
    assert remove_key(p, lost.kid.hex(), signer=ph).json()["error"] == "DEVICE_LEVEL"
    new, r = add_key(p, signer=ph, label="another phone")                       # a fresh unmarked (= phone) key vouched by the waiting one
    assert r.status_code == 409 and r.json()["error"] == "DEVICE_LEVEL", r.text
    elapse_phone_wait(app, ph.kid)
    assert remove_key(p, lost.kid.hex(), signer=ph).status_code == 200


def test_first_marking_is_closed_during_the_recovery_window(app):
    """An account that never had a phone (all keys marked laptop): the recovered key does not become a phone through the first marking,
    nor by vouching for a fresh phone key, during the window (else the delay is skipped)."""
    p = Person(app).register("Eve")
    assert stepup_with(p, p.auth).status_code == 200
    assert p.post("/api/auth/keys/%s/device" % p.auth.kid.hex(), device="laptop").status_code == 200
    codes = new_codes(p)
    rk, br, f = recover(app, p, codes[0], device=None)                          # not declared: a laptop key
    assert f.json()["device"] == "laptop"
    switch_auth(p, rk)
    assert stepup_with(p, rk).status_code == 200
    r = p.post("/api/auth/keys/%s/device" % rk.kid.hex(), device="phone")
    assert r.status_code == 403 and r.json()["error"] == "DEVICE_LEVEL"
    new, r = add_key(p, signer=rk, label="phone")
    assert r.status_code == 409 and r.json()["error"] == "DEVICE_LEVEL"
    # after the window the first marking is what it was in 0.2.14
    ctx_of(app).db.x("UPDATE credentials SET created_at=created_at-? WHERE kid=?", (DAY + 1, rk.kid))
    assert stepup_with(p, rk).status_code == 200
    assert p.post("/api/auth/keys/%s/device" % rk.kid.hex(), device="phone").status_code == 200


def test_team_quorum_ends_the_wait_never_the_person_never_one(app):
    from tests.test_recovery_org import team_with_recovery
    owner, bob, carol = team_with_recovery(app)
    codes = new_codes(bob)
    ph, _ = declare_phone(app, bob, codes[0])
    switch_auth(bob, ph)
    assert bob.post("/api/orgs/switch", account_id=owner.uid).status_code == 200
    r = owner.post("/api/org/phone-lift", user_id=bob.uid)
    assert r.status_code == 200, r.text
    rq = r.json()
    assert rq["needs"] == [{"role": "any", "k": 2}] and rq["kid_hex"] == ph.kid.hex()
    assert rq["req_id"] not in [x["id"] for x in bob.c.get("/api/sig-requests").json()]      # not asked of the person
    g = owner.c.get("/api/sig-requests/" + rq["req_id"]).json()
    pl = wq.phone_lift_payload("dw:" + bob.uid, ph.kid, rq["not_before"], bytes.fromhex(g["body"]["nonce"]))
    assert wa.b64u_dec(g["payload_b64"]) == pl                                   # the page rebuilds exactly what it signs
    # bob's old key (still the policy's) may not vouch for his own new phone
    e = bob.post("/api/sig-requests/" + rq["req_id"], envelope_b64=wa.b64u(bob._orig.sign_object(wq.TYP_PHONE_LIFT, pl, RP, ORIGIN)))
    assert e.status_code == 409 and e.json()["error"] == "RECOVERY_SELF", e.text
    r = owner.sign_req(rq["req_id"])
    assert r.json()["status"] == "collecting" and levels.device_of_kid(ctx_of(app), ph.kid) == levels.LAPTOP
    r = carol.sign_req(rq["req_id"])
    assert r.status_code == 200 and r.json()["status"] == "done", r.text
    assert levels.device_of_kid(ctx_of(app), ph.kid) == levels.PHONE
    row = [x for x in kd_rows(app, bob.uid) if x["kid"] == ph.kid.hex()][-1]
    assert row["lifted"] is True and row["by"] == "team-quorum" and row["req_id"] == rq["req_id"]
    env = bytes.fromhex(row["envelope_hex"])
    ch = [(bytes(x["policy"]), bytes(x["envelope"]), x["t"]) for x in ctx_of(app).db.q("SELECT * FROM org_policies WHERE account_id=? ORDER BY ver", (owner.uid,))]
    assert wq.verify_wq(env, wq.TYP_PHONE_LIFT, pl, ch, rp={"rp_id": RP, "origins": [ORIGIN]}, rule={"role": "any", "k": 2}) is None


def test_phone_lift_needs_a_recovery_rule(app):
    owner, bob, carol = team(app)                                                # TEAM_RULES: no `recovery`
    codes = new_codes(bob)
    declare_phone(app, bob, codes[0])
    r = owner.post("/api/org/phone-lift", user_id=bob.uid)
    assert r.status_code == 409 and r.json()["error"] == "NO_RECOVERY_RULE"


def test_pack_shows_the_wait_and_a_short_wait_fails(app, tmp_path):
    p = Person(app).register("Fay")
    codes = new_codes(p)
    ph, f = declare_phone(app, p, codes[0])
    switch_auth(p, ph)
    rc, out = run_verify(export_to(p.c, tmp_path / "pack"), "--offline")
    assert rc == 0 and "RESULT: VALID" in out, out
    assert "declared the new phone with a recovery code" in out and "(24 h later)" in out, out
    from packtools.verify_pack import _device_lines
    pr = "dw:" + p.uid
    row = {"row_json": json.dumps({"key_device": {"principal": pr, "kid": "ab" * 32, "device": "phone", "by": "recovery-code", "t": 100,
                                                  "not_before": 100 + 3600}})}
    [(line, bad)] = _device_lines({"log": [row]}, pr)
    assert bad and "RECOVERY_DELAY" in line
    old = {"row_json": json.dumps({"key_device": {"principal": pr, "kid": "ab" * 32, "device": "phone", "by": "recovery-code", "t": 100}})}
    [(line, bad)] = _device_lines({"log": [old]}, pr)
    assert not bad and "before 0.2.15" in line                                    # a 0.2.14 pack stays valid


# ================================================================ (2) delegation in the signed policy: the contract
def _members(n):
    out = []
    for i in range(n):
        a = wa.SoftAuthenticator()
        out.append((a, {"kid": a.kid, "pub": a.pub, "cred": b"c%d" % i, "roles": ["owner", "budget", "access"] if i == 0 else ["budget"], "label": "m%d" % i}))
    out.sort(key=lambda x: x[1]["kid"])
    return out


def _pol(ms, dl=None):
    rules = dict(TEAM_RULES, policy={"role": "owner", "k": 1})
    if dl is not None:
        rules["delegation"] = dl
    return {"v": wq.V_POLICY, "principal": "dw:x", "ver": 2, "prev": b"\0" * 32, "members": [m for _, m in ms], "rules": rules}


def test_contract_validate_delegation():
    ms = _members(3)
    k = [m["kid"].hex() for _, m in ms]
    good = {"agent": "ag_1", "operator": k[0], "approvers": sorted([k[1], k[2]]), "until": None}
    assert wq.validate_policy(_pol(ms, [good])) is None
    assert wq.validate_policy(_pol(ms, [dict(good, approvers=None, until=5)])) is None
    assert wq.validate_policy(_pol(ms, [dict(good, operator="ff" * 32)])) is None             # an operator outside the policy (observer)
    for bad in ([], [dict(good, approvers=[k[0], k[1]])], [dict(good, approvers=[k[2], k[1]] if k[2] > k[1] else [k[1], k[2]][::-1])],
                [dict(good, approvers=["ee" * 32])], [dict(good, operator=k[0].upper())], [dict(good, approvers=[])],
                [dict(good, agent="a b")], [dict(good, agent="")], [good, good], [dict(good, agent="b"), dict(good, agent="a")],
                [dict(good, until=-1)], [dict(good, until=True)], [dict(good, extra=1)], [{k_: v for k_, v in good.items() if k_ != "until"}],
                "x"):
        assert wq.validate_policy(_pol(ms, bad)) == "POLICY_MALFORMED", bad


def _wq_over(ms_auth, pol, pay):
    pb = wa.cde(pol)
    sigs = [wq.wsig_of_wa(a.sign_object(wa.TYP_APPROVAL, pay, RP, ORIGIN)) for a in ms_auth]
    return wq.make_wq(wa.TYP_APPROVAL, pay, hashlib.sha256(pb).digest(), sigs), [(pb, None, 10)]


def test_contract_verify_wq_excludes_the_operator_and_non_approvers():
    ms = _members(3)
    (a0, m0), (a1, m1), (a2, m2) = ms
    rp = {"rp_id": RP, "origins": [ORIGIN]}
    pay = b"approval-payload"
    pol = _pol(ms, [{"agent": "ag_1", "operator": m0["kid"].hex(), "approvers": [m1["kid"].hex()], "until": 1000}])
    env, ch = _wq_over([a0], pol, pay)
    assert wq.verify_wq(env, wa.TYP_APPROVAL, pay, ch, rp=rp, agent="ag_1") == "WQ_SELF"
    assert wq.verify_wq(env, wa.TYP_APPROVAL, pay, ch, rp=rp, agent="ag_2") is None              # another agent: not delegated
    assert wq.verify_wq(env, wa.TYP_APPROVAL, pay, ch, rp=rp) is None                            # a refusal / old caller: no agent
    env, ch = _wq_over(sorted([a0, a1], key=lambda a: a.kid), pol, pay)
    assert wq.verify_wq(env, wa.TYP_APPROVAL, pay, ch, rp=rp, agent="ag_1") == "WQ_SELF"          # the operator inside a quorum
    env, ch = _wq_over([a2], pol, pay)
    assert wq.verify_wq(env, wa.TYP_APPROVAL, pay, ch, rp=rp, agent="ag_1") == "WQ_NOT_DELEGATE"
    env, ch = _wq_over([a1], pol, pay)
    assert wq.verify_wq(env, wa.TYP_APPROVAL, pay, ch, rp=rp, agent="ag_1") is None
    assert wq.verify_wq(env, wa.TYP_APPROVAL, pay, ch, rp=rp, agent="ag_1", at=1000) is None
    assert wq.verify_wq(env, wa.TYP_APPROVAL, pay, ch, rp=rp, agent="ag_1", at=1001) == "WQ_NOT_DELEGATE"   # the term ran out
    assert wq.delegation_code(pol, "ag_1", [m0["kid"]]) == "WQ_SELF" and wq.delegation_code(pol, "ag_1", [m1["kid"]]) is None


def test_contract_key_swap_carries_the_delegation():
    ms = _members(3)
    (a0, m0), (a1, m1), (a2, m2) = ms
    prev = _pol(ms, [{"agent": "ag_1", "operator": m0["kid"].hex(), "approvers": sorted([m1["kid"].hex(), m2["kid"].hex()]), "until": None}])
    new_a = wa.SoftAuthenticator()
    nm = dict(m1, kid=new_a.kid, pub=new_a.pub)
    members = sorted([m0, nm, m2], key=lambda m: m["kid"])
    new = dict(prev, members=members, rules=wq.swap_rules(prev["rules"], m1["kid"], new_a.kid))
    assert wq.validate_policy(new) is None and wq.key_swap(prev, new) == (m1["kid"], new_a.kid)
    stale = dict(new, rules=prev["rules"])                                       # the old kid left in the delegation: not a pure swap
    assert wq.key_swap(prev, stale) is None


# ================================================================ (2) delegation in the signed policy: the server
def _team_agent(app):
    owner, bob, carol = team(app)
    ag, hdr = owner.new_agent("demo", "carol-bot")
    from tests.test_quorum import mandate_draft
    dr = mandate_draft(owner, ag["id"], MSG_FORM)
    assert owner.sign_req(dr["req_id"]).json()["mandate_status"] == "active"
    return owner, bob, carol, ag, hdr


def _defer(owner, hdr, ch):
    r = act(owner.c, hdr, "purchase", {"vendor": ch + ".example", "amount_cents": 5000}).json()
    assert r["verdict"] == "defer", r
    return r


def _policy(app, uid):
    from app import org
    return org.current_policy(ctx_of(app), uid)[0]


def test_delegation_moves_into_the_signed_policy_and_then_changes_only_by_a_version(app, tmp_path):
    owner, bob, carol, ag, hdr = _team_agent(app)
    r0 = _defer(owner, hdr, "before")
    assert owner.approve(r0["rid"]).json()["verdict"] == "allow"                # an approval before any delegation (pack: trust line)
    owner.stepup()
    v = owner.c.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": carol.uid, "approvers": [bob.uid]}, headers=H).json()
    assert v["in_signed_policy"] is False and v["current"]["operator_user_id"] == carol.uid     # period before the transfer: at once
    rq = v["policy_request"]
    assert rq["policy_ver"] == 3 and rq["needs"] == [{"role": "owner", "k": 1}]
    g = owner.c.get("/api/sig-requests/" + rq["req_id"]).json()
    assert g["body"]["rules"]["delegation"] == [{"agent": ag["id"], "operator": carol._orig.kid.hex(), "approvers": [bob._orig.kid.hex()], "until": None}]
    assert g["meta"]["delegation"] == {"agent": ag["id"], "set": True}
    assert owner.sign_req(rq["req_id"]).json()["policy_ver"] == 3
    pol = _policy(app, owner.uid)
    assert wq.delegation_of(pol, ag["id"])["operator"] == carol._orig.kid.hex()
    cur = owner.c.get("/api/agents/%s/delegation" % ag["id"]).json()["current"]
    assert cur["policy_ver"] == 3 and cur["set_by"] == "policy:v3" and cur["approvers"] == [bob.uid]
    # named in the policy: a change waits for the signatures
    owner.stepup()
    v = owner.c.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": bob.uid}, headers=H).json()
    assert v["waits_for_signatures"] is True and v["current"]["operator_user_id"] == carol.uid
    r = _defer(owner, hdr, "mid")
    assert carol.approve(r["rid"]).json()["error"] == "SELF_APPROVAL"           # still carol's agent
    assert bob.approve(r["rid"]).json()["verdict"] == "allow"
    # an operator's wq built by hand (the server cache wiped) is refused by the contract itself
    ctx_of(app).db.x("UPDATE agent_delegations SET ended_at=1 WHERE agent_id=?", (ag["id"],))
    r2 = _defer(owner, hdr, "hand")
    gg = owner.c.get("/api/approvals/" + r2["rid"]).json()
    pay = approval_payload(gg["mandate"], gg["action"], r2["rid"], True)
    env = wq.make_wq(wa.TYP_APPROVAL, pay, policy_hash_now(app, owner.uid), [carol.wsig(wa.TYP_APPROVAL, pay)])
    from app import actions
    acc = ctx_of(app).db.one("SELECT * FROM accounts WHERE id=?", (owner.uid,))
    with pytest.raises(Exception) as e:
        actions.approve_with_envelope(ctx_of(app), acc, r2["rid"], True, env)
    assert getattr(e.value, "code", None) == "WQ_SELF"
    env = wq.make_wq(wa.TYP_APPROVAL, pay, policy_hash_now(app, owner.uid), [owner.wsig(wa.TYP_APPROVAL, pay)])
    with pytest.raises(Exception) as e:
        actions.approve_with_envelope(ctx_of(app), acc, r2["rid"], True, env)
    assert getattr(e.value, "code", None) == "WQ_NOT_DELEGATE"
    # the pending change signed -> v4, cache follows
    assert owner.sign_req(v["policy_request"]["req_id"]).json()["policy_ver"] == 4
    cur = owner.c.get("/api/agents/%s/delegation" % ag["id"]).json()["current"]
    assert cur["operator_user_id"] == bob.uid and cur["approvers"] is None and cur["set_by"] == "policy:v4"
    # the pack proves who confirmed: delegated approvals counted, the early one said on trust
    rc, out = run_verify(export_to(owner.c, tmp_path / "pack"), "--offline")
    assert rc == 0 and "RESULT: VALID" in out, out
    assert "org delegation: 1 approvals of 1 delegated agent(s), 0 by the agent's operator" in out, out
    assert "trust: 1 approval(s) of 1 agent(s) the signed policy names in no delegation" in out, out


def test_end_of_a_signed_delegation_waits_for_the_version_and_a_draft_keeps_delegations(app):
    owner, bob, carol, ag, hdr = _team_agent(app)
    owner.stepup()
    v = owner.c.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": carol.uid}, headers=H).json()
    assert owner.sign_req(v["policy_request"]["req_id"]).json()["policy_ver"] == 3
    # an ordinary team edit (members/rules without `delegation`) keeps the delegation
    assert adopt(owner, [{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": bob.uid, "roles": ["budget"]},
                         {"user_id": carol.uid, "roles": ["access"]}], TEAM_RULES) == 4
    assert wq.delegation_of(_policy(app, owner.uid), ag["id"]) is not None
    owner.stepup()
    h = owner.c.delete("/api/agents/%s/delegation" % ag["id"], headers=H).json()
    assert h["waits_for_signatures"] is True and h["current"] is not None
    assert owner.sign_req(h["policy_request"]["req_id"]).json()["policy_ver"] == 5
    assert "delegation" not in _policy(app, owner.uid)["rules"]
    h = owner.c.get("/api/agents/%s/delegation" % ag["id"]).json()
    assert h["current"] is None and h["history"][0]["ended_by"] == "policy:v5"
    # an approver who leaves the policy cannot stay named in it
    owner.stepup()
    v = owner.c.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": carol.uid, "approvers": [bob.uid]}, headers=H).json()
    assert owner.sign_req(v["policy_request"]["req_id"]).json()["policy_ver"] == 6
    d = owner.post("/api/org/policy/draft", members=[{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": carol.uid, "roles": ["access"]}],
                   rules=dict(TEAM_RULES, approval=[], mandate=[]))
    assert d.status_code == 422 and "delegation" in d.json()["detail"]


def test_key_replacement_of_an_approver_keeps_the_delegation(app):
    from tests.test_recovery_org import lose_and_recover, team_with_recovery
    owner, bob, carol = team_with_recovery(app)
    ag, hdr = owner.new_agent("demo", "bot")
    owner.stepup()
    v = owner.c.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": carol.uid, "approvers": [bob.uid]}, headers=H).json()
    assert owner.sign_req(v["policy_request"]["req_id"]).json()["policy_ver"] == 4
    lost, new = lose_and_recover(app, bob, owner.uid)
    rq = owner.post("/api/org/key-replace", user_id=bob.uid).json()
    owner.sign_req(rq["req_id"])
    assert carol.sign_req(rq["req_id"]).json()["status"] == "done"
    d = wq.delegation_of(_policy(app, owner.uid), ag["id"])
    assert d["approvers"] == [new.kid.hex()]
    cur = owner.c.get("/api/agents/%s/delegation" % ag["id"]).json()["current"]
    assert cur["approvers"] == [bob.uid] and cur["operator_user_id"] == carol.uid
