"""0.2.21: the owner LEARNS about a possible clone of a passkey (a signature counter that went back) and can stop it quickly.

0.2.20 refused SIGN_COUNT_REGRESSION and wrote a log line only. Now (app/keyalert.py):
- the person who holds the passkey gets a security push {v: 2, k: "c"} (fixed text in sw.js) -- at most ONE per key per 10 minutes,
  decided in the database; and a mark on Devices (GET /api/auth/keys -> keys[].clone_alert: numbers and a route from a fixed list);
- no automatic freeze (a clone must not lock the owner out); the key keeps working for a counter that grows;
- the mark goes away only by the owner: the existing signed removal (with another passkey), or "this was me" (clone-dismiss) after a fresh
  step-up made with ANOTHER passkey (with a single passkey: that one); never by good signatures (that is what a clone makes);
- one row per (person, key): 1000 regressions add no rows;
- the very assertion accepted last, sent again (a retry), is refused without an alert."""
import pytest

from app import _paths  # noqa: F401
from app import keyalert, org
from app.config import Config
from app.context import Err
from app.main import create_app
import wa_profile as wa
from tests.helpers import ORIGIN
from tests.org_helpers import Person
from tests.recovery_helpers import add_key, login_with, remove_key, stepup_with
from tests.test_0220_signcount import approval_env, counting, defer, status
from tests.test_flow import setup_agent
from tests.test_push import Clock, Device, FakeSender, subscribe, vapid_pem

ALERT_FIELDS = {"first_at", "last_at", "count", "route", "stored", "got", "notified_at"}


@pytest.fixture()
def papp(tmp_path, monkeypatch):
    kf = tmp_path / "witness_key"
    kf.write_text("a1" * 32)
    vk = tmp_path / "vapid.pem"
    vapid_pem(vk)
    a = create_app(Config(data_dir=str(tmp_path / "data"), witness_key_file=str(kf), key_pepper="p", rp_id="localhost", origin=ORIGIN,
                          iss="https://witness.test", anchor="off", web_dir="", vapid_key_file=str(vk), push_hosts="push.test",
                          push_allow_http=True))
    pu = a.state.ctx.push
    pu.sender, pu.retry_delays, pu.clock = FakeSender(), (0, 0), Clock()
    t = [1_800_000_000]
    monkeypatch.setattr(keyalert, "clock", lambda: t[0])
    a.state.t = t
    return a


def person(app, name, start=5):
    p = Person(app).register(name)
    counting(p.auth, start)
    p.dev = Device("https://fcm.push.test/send/" + name.lower())
    assert subscribe(p, p.dev).status_code == 200
    return p


def clone_pushes(app, p=None):
    pu = app.state.ctx.push
    assert pu.drain()
    return [c for c in pu.sender.calls if c["data"].get("k") == "c" and (p is None or c["endpoint"] == p.dev.endpoint)]


def keys(p):
    r = p.c.get("/api/auth/keys")
    assert r.status_code == 200, r.text
    return r.json()["keys"]


def regress(p, hdr, counter=3, text="x"):
    rid = defer(p.c, hdr, text)
    p.auth.counter = counter
    r = p.post("/api/approvals/" + rid, approved=True, envelope_b64=approval_env(p, rid))
    assert r.status_code == 409 and r.json()["error"] == "SIGN_COUNT_REGRESSION", r.text
    return rid


def total_rows(app):
    db = app.state.ctx.db
    return {t["name"]: db.one('SELECT COUNT(*) AS n FROM "%s"' % t["name"])["n"]
            for t in db.q("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}


# ---- the owner is told -----------------------------------------------------------------------------------------------------------------

def test_regression_pushes_owner_and_marks_device_no_freeze(papp):
    p = person(papp, "Alice")
    ag, hdr, _ = setup_agent(p)                                   # mandate signed at counter 5
    papp.state.ctx.push.sender.calls.clear()
    rid = regress(p, hdr, 3)
    pushes = clone_pushes(papp, p)
    assert [(c["data"], c["topic"]) for c in pushes] == [({"v": 2, "k": "c"}, "dw-security")]    # fixed signal, nothing else
    [k] = keys(p)
    a = k["clone_alert"]
    assert set(a) == ALERT_FIELDS and (a["stored"], a["got"], a["route"], a["count"]) == (5, 3, "approve", 1)
    assert a["first_at"] == a["last_at"] == a["notified_at"] == papp.state.t[0]
    # NO automatic freeze: the passkey keeps working with a counter that grows; the mark stays until the owner acts
    p.auth.counter = 6
    r = p.post("/api/approvals/" + rid, approved=True, envelope_b64=approval_env(p, rid))
    assert r.status_code == 200 and status(p.c, rid) != "pending_approval", r.text
    for c in (7, 8, 9):
        p.auth.counter = c
        assert login_with(p, p.auth).status_code == 200
    assert keys(p)[0]["clone_alert"]["count"] == 1               # good signatures (what a clone makes) never clear it


def test_signin_regression_is_told_too(papp):
    p = person(papp, "Alice", start=10)
    assert login_with(p, p.auth).status_code == 200              # counter 10 stored
    papp.state.ctx.push.sender.calls.clear()
    p.auth.counter = 4
    r = login_with(p, p.auth)
    assert r.status_code == 401 and r.json()["error"] == "SIGN_COUNT_REGRESSION"
    assert len(clone_pushes(papp, p)) == 1
    p.auth.counter = 11
    assert login_with(p, p.auth).status_code == 200
    a = keys(p)[0]["clone_alert"]
    assert (a["route"], a["stored"], a["got"]) == ("login", 10, 4)


# ---- a clone that keeps trying -----------------------------------------------------------------------------------------------------------

def test_1000_regressions_one_push_per_10_min_no_new_rows(papp, capsys):
    p = person(papp, "Alice")
    ag, hdr, _ = setup_agent(p)
    ctx = papp.state.ctx
    rid = regress(p, hdr, 3)                                     # 1st regression: one push
    before = total_rows(papp)
    for i in range(20):                                          # over HTTP, as a clone would
        papp.state.t[0] += 1
        p.auth.counter = 3
        assert p.post("/api/approvals/" + rid, approved=True, envelope_b64=approval_env(p, rid)).json()["error"] == "SIGN_COUNT_REGRESSION"
    p.auth.counter = 4
    env = wa.b64u_dec(approval_env(p, rid))
    for i in range(979):                                         # the same code path, 979 more times (1000 in all)
        with pytest.raises(Err) as e:
            org.check_sign_counts(ctx, env, "approve", p.uid)
        assert e.value.code == "SIGN_COUNT_REGRESSION"
    capsys.readouterr()
    assert len(clone_pushes(papp, p)) == 1                       # <= 1 notification in 10 minutes
    assert total_rows(papp) == before                            # not one row more anywhere (the alert row is updated in place)
    assert ctx.db.one("SELECT COUNT(*) AS n FROM key_alerts")["n"] == 1
    a = keys(p)[0]["clone_alert"]
    assert a["count"] == 1000 and a["got"] == 4
    papp.state.t[0] += keyalert.NOTIFY_GAP_S - 20 - 1            # still inside the window of the first push
    with pytest.raises(Err):
        org.check_sign_counts(ctx, env, "approve", p.uid)
    assert len(clone_pushes(papp, p)) == 1
    papp.state.t[0] += 1                                         # 10 minutes after the first push: one more
    for _ in range(50):
        with pytest.raises(Err):
            org.check_sign_counts(ctx, env, "approve", p.uid)
    assert len(clone_pushes(papp, p)) == 2
    assert total_rows(papp) == before


def test_retry_of_the_last_accepted_assertion_is_no_clone(papp):
    """The identical assertion accepted last, sent again (a retry after a later check failed, OTCHET-0.2.20 open item 5): refused, no
    alert. Another assertion with the same counter (a second authenticator: ECDSA is randomised) is a possible clone."""
    p = person(papp, "Alice")
    ag, hdr, _ = setup_agent(p)
    ctx = papp.state.ctx
    rid = defer(p.c, hdr, "r")
    p.auth.counter = 7
    env = wa.b64u_dec(approval_env(p, rid))
    org.check_sign_counts(ctx, env, "approve", p.uid)            # accepted: counter 7
    papp.state.ctx.push.sender.calls.clear()
    with pytest.raises(Err):
        org.check_sign_counts(ctx, env, "approve", p.uid)        # the very same bytes again
    assert keys(p)[0]["clone_alert"] is None and clone_pushes(papp) == []
    env2 = wa.b64u_dec(approval_env(p, rid))                     # same payload, same counter 7, another signature
    assert env2 != env
    with pytest.raises(Err):
        org.check_sign_counts(ctx, env2, "approve", p.uid)
    assert keys(p)[0]["clone_alert"]["got"] == 7 and len(clone_pushes(papp, p)) == 1


# ---- nobody else sees it; nothing of the client is shown -----------------------------------------------------------------------------------

def test_other_account_sees_nothing(papp):
    a, b = person(papp, "Alice"), person(papp, "Bob")
    ag, hdr, _ = setup_agent(a)
    papp.state.ctx.push.sender.calls.clear()
    regress(a, hdr, 2)
    assert len(clone_pushes(papp, a)) == 1 and clone_pushes(papp, b) == []      # Bob's device hears nothing
    akid = keys(a)[0]["kid_hex"]
    kb = keys(b)
    assert all(k["clone_alert"] is None for k in kb) and akid not in [k["kid_hex"] for k in kb]
    assert keyalert.alerts_of(papp.state.ctx, b.uid) == {}
    r = b.post("/api/auth/keys/%s/clone-dismiss" % akid)           # Bob cannot clear Alice's mark
    assert r.status_code == 404
    assert keys(a)[0]["clone_alert"] is not None


def test_no_client_text_in_push_or_mark(papp):
    p = person(papp, "Alice")
    ag, hdr, _ = setup_agent(p)
    ctx = papp.state.ctx
    papp.state.ctx.push.sender.calls.clear()
    regress(p, hdr, 1, text='<img src=x onerror=alert(1)> https://evil.example/login')
    [c] = clone_pushes(papp, p)
    assert c["data"] == {"v": 2, "k": "c"}                       # no id, no kid, no number, no text: sw.js shows a fixed text
    a = keys(p)[0]["clone_alert"]
    assert set(a) == ALERT_FIELDS and a["route"] in keyalert.ROUTES
    assert all(isinstance(a[f], int) for f in ALERT_FIELDS - {"route"})
    # a "where" that is not one of the server's own routes is never stored as given
    kid = bytes.fromhex(keys(p)[0]["kid_hex"])
    papp.state.t[0] += 1
    keyalert.raise_alert(ctx, kid, 5, 1, '<script>alert(1)</script>')
    keyalert.raise_alert(ctx, kid, "9" * 40, -3, "sigreq:<b>x</b>")
    row = ctx.db.one("SELECT route, stored, got FROM key_alerts WHERE kid=?", (kid,))
    assert (row["route"], row["stored"], row["got"]) == ("sigreq:other", 0xFFFFFFFF, 0)
    assert keyalert._route('<script>') == "other"
    assert "<" not in p.c.get("/api/auth/keys").text


# ---- the way out ----------------------------------------------------------------------------------------------------------------------

def test_dismiss_needs_another_key_then_signed_removal(papp):
    p = person(papp, "Alice")
    p.auth.counter = 6
    B, r = add_key(p)                                            # a second passkey (laptop), confirmed by the first at counter 6
    assert r.status_code == 200, r.text
    p.auth.counter = 7
    ag, hdr, _ = setup_agent(p)                                  # mandate signed at 7
    akid = [k for k in keys(p) if k["added_by"] == "registration"][0]["kid_hex"]
    p.auth.counter = 20
    assert login_with(p, p.auth).status_code == 200              # stored 20
    regress(p, hdr, 12)
    assert [k["kid_hex"] for k in keys(p) if k["clone_alert"]] == [akid]
    # "this was me" confirmed with the suspected key itself: refused while another key exists (the clone could do that)
    p.auth.counter = 21
    assert stepup_with(p, p.auth).status_code == 200
    r = p.post("/api/auth/keys/%s/clone-dismiss" % akid)
    assert r.status_code == 403 and r.json()["error"] == "STEPUP_REQUIRED", r.text
    # no session / foreign Origin
    assert p.c.post("/api/auth/keys/%s/clone-dismiss" % akid, headers={"Origin": "https://evil.example"}).status_code == 403
    # with the other passkey: cleared
    assert stepup_with(p, B).status_code == 200
    r = p.post("/api/auth/keys/%s/clone-dismiss" % akid)
    assert r.status_code == 200 and r.json()["kid_hex"] == akid, r.text
    assert all(k["clone_alert"] is None for k in keys(p))
    assert p.post("/api/auth/keys/%s/clone-dismiss" % akid).status_code == 404
    # it happens again: marked again (the push window of 10 minutes still holds)
    n = len(clone_pushes(papp, p))
    regress(p, hdr, 15)
    assert [k["clone_alert"]["count"] for k in keys(p) if k["kid_hex"] == akid] == [1] and len(clone_pushes(papp, p)) == n
    # stopping it = the EXISTING signed removal, signed by the other passkey; the mark goes with the key
    r = remove_key(p, akid, signer=B)
    assert r.status_code == 200, r.text
    login_with(p, B)
    ks = {k["kid_hex"]: k for k in keys(p)}
    assert ks[akid]["active"] is False and ks[akid]["clone_alert"] is None


def test_single_key_owner_can_clear_and_is_not_locked_out(papp):
    p = person(papp, "Alice")
    ag, hdr, _ = setup_agent(p)
    regress(p, hdr, 2)
    [k] = keys(p)
    assert k["clone_alert"] is not None
    # the only passkey: its removal is refused as before (LAST_KEY); the page sends the person to recovery codes; no new mechanism
    assert p.post("/api/auth/keys/%s/remove/begin" % k["kid_hex"]).json()["error"] == "LAST_KEY"
    p.auth.counter = 30
    assert stepup_with(p, p.auth).status_code == 200             # not frozen: it still signs with a growing counter
    r = p.post("/api/auth/keys/%s/clone-dismiss" % k["kid_hex"])
    assert r.status_code == 200, r.text
    assert keys(p)[0]["clone_alert"] is None
