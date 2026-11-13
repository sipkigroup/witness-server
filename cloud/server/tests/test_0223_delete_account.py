"""0.2.23: POST /api/account/delete -- the person erases their own account (app/account_delete.py)."""
import os

from app import _paths  # noqa: F401
from app import jobs
from tests.helpers import H, act
from tests.org_helpers import Person, ctx_of
from tests.test_flow import setup_agent


def old_stepup(app):
    ctx_of(app).db.x("UPDATE sessions SET stepup_at=0")


def test_no_session_is_401(app):
    p = Person(app)
    assert p.post("/api/account/delete", confirm_name="x").status_code == 401


def test_without_fresh_stepup_is_403(app):
    p = Person(app).register("Alice")
    old_stepup(app)
    r = p.post("/api/account/delete", confirm_name="Alice")
    assert r.status_code == 403 and r.json()["error"] == "STEPUP_REQUIRED"
    assert p.c.get("/api/me").status_code == 200                       # nothing happened
    p.stepup()
    assert p.post("/api/account/delete", confirm_name="Alice").status_code == 200


def test_wrong_or_missing_name_is_400_and_keeps_everything(app):
    p = Person(app).register("Alice")
    for body in ({}, {"confirm_name": ""}, {"confirm_name": "alice"}, {"confirm_name": "Bob"}, {"confirm_name": 5}):
        r = p.post("/api/account/delete", **body)
        assert r.status_code == 400 and r.json()["error"] == "NAME_MISMATCH", body
    assert p.c.get("/api/me").status_code == 200


def test_someone_else_cannot(app):
    a = Person(app).register("Alice")
    b = Person(app).register("Bob")
    tok = a.invite(["observer"])
    assert b.post("/api/org/join", token=tok).status_code == 200
    assert b.post("/api/orgs/switch", account_id=a.uid).status_code == 200      # Bob looks at Alice's account
    r = b.post("/api/account/delete", confirm_name="Alice")
    assert r.status_code == 403                                                 # not an owner there (and not his own account)
    assert a.c.get("/api/me").status_code == 200
    assert ctx_of(app).db.one("SELECT display_name FROM accounts WHERE id=?", (a.uid,))["display_name"] == "Alice"
    # Bob's own account from Bob's own session never touches Alice
    b.post("/api/orgs/switch", account_id=b.uid)
    assert b.post("/api/account/delete", confirm_name="Alice").status_code == 400


def test_team_with_other_members_is_refused(app):
    a = Person(app).register("Alice")
    b = Person(app).register("Bob")
    assert b.post("/api/org/join", token=a.invite(["observer"])).status_code == 200
    r = a.post("/api/account/delete", confirm_name="Alice")
    assert r.status_code == 409 and r.json()["error"] == "TEAM_HAS_MEMBERS"
    assert a.c.get("/api/me").status_code == 200


def test_active_signer_of_another_team_is_refused(app):
    a = Person(app).register("Alice")
    b = Person(app).register("Bob")
    assert b.post("/api/org/join", token=a.invite(["budget"])).status_code == 200
    ctx_of(app).db.x("UPDATE members SET status='active' WHERE user_id=? AND account_id=?", (b.uid, a.uid))
    r = b.post("/api/account/delete", confirm_name="Bob")
    assert r.status_code == 409 and r.json()["error"] == "IN_TEAM"


def test_observer_of_another_team_may_delete_and_leaves_it(app):
    a = Person(app).register("Alice")
    b = Person(app).register("Bob")
    assert b.post("/api/org/join", token=a.invite(["observer"])).status_code == 200
    assert b.post("/api/orgs/switch", account_id=b.uid).status_code == 200
    # Alice still has Bob as a member -> she cannot; Bob can (he is an observer elsewhere)
    assert b.post("/api/account/delete", confirm_name="Bob").status_code == 200
    db = ctx_of(app).db
    assert db.one("SELECT 1 FROM members WHERE user_id=?", (b.uid,)) is None
    assert a.post("/api/account/delete", confirm_name="Alice").status_code == 200


def test_success_erases_and_nobody_can_come_back(app):
    p = Person(app).register("Alice")
    ag, hdr, m = setup_agent(p)
    r = act(p.c, hdr, "send_email", {"to": "bob@partner.example", "subject": "hi", "body": "b"}).json()
    assert r["verdict"] == "allow"
    ctx = ctx_of(app)
    db = ctx.db
    p.stepup()
    ledger = os.path.join(ctx.hub.ledger_dir(p.uid), "ledger.cose")
    assert os.path.getsize(ledger) > 0
    reg_before = db.one("SELECT COUNT(*) n FROM registry_log WHERE account_id=?", (p.uid,))["n"]
    r = p.post("/api/account/delete", confirm_name="  Alice ")
    assert r.status_code == 200 and r.json()["deleted"] is True
    # the session is gone
    assert p.c.get("/api/me").status_code == 401
    # sign-in with the old passkey is impossible
    assert p.login().status_code == 401
    # the agent's API key is dead
    assert act(p.c, hdr, "send_email", {"to": "bob@partner.example", "subject": "hi", "body": "b"}).status_code in (401, 403)
    # data of the account is erased
    for tb in ("agents", "mandates", "actions", "approvals", "data_patterns", "sessions", "members"):
        col = "user_id" if tb in ("sessions", "members") else "account_id"
        assert db.one("SELECT COUNT(*) n FROM %s WHERE %s=?" % (tb, col), (p.uid,))["n"] == 0, tb
    assert db.one("SELECT 1 FROM users WHERE id=?", (p.uid,)) is None
    assert db.one("SELECT display_name FROM accounts WHERE id=?", (p.uid,))["display_name"] is None
    assert db.one("SELECT COUNT(*) n FROM credentials WHERE user_id=? AND revoked_at IS NULL", (p.uid,))["n"] == 0
    # 0.2.34: the journal file is replaced by the hash skeleton; the registry log stays, and the anchor job still runs
    assert not os.path.exists(ledger)
    assert os.path.getsize(os.path.join(os.path.dirname(ledger), "ledger.skeleton.cbor")) > 0
    assert db.one("SELECT COUNT(*) n FROM registry_log WHERE account_id=?", (p.uid,))["n"] == reg_before
    jobs.anchor_once(ctx)
    # a second try finds no session
    assert p.post("/api/account/delete", confirm_name="Alice").status_code == 401
