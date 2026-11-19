"""Task 01 of 0.2: users, members, roles, invites, the rights table, isolation of organisations (ARHITEKTURA-0.2 2.1, 2.6, 2.7)."""
import re

from app import _paths  # noqa: F401
import wa_profile as wa
from app import org
from tests.helpers import H, ORIGIN, act
from tests.org_helpers import MSG_FORM, Person, ctx_of, team
from tests import viewkit  # noqa: E402  (r0352: decisions name the view)

CHANGING = {"POST", "PUT", "DELETE", "PATCH"}
# user-level paths: they act on the person's own session or membership, not on the current organisation
USER_LEVEL = {"/api/orgs/switch", "/api/org/join",
              "/api/team-request",       # 0.2.28: the public Team access form, no account at all (tests/test_0228.py)
              "/api/trial/claim/begin", "/api/trial/claim/finish",     # 0.2.38: before any account role exists: the trial claim (tests/test_0238_trial.py)
              "/api/push/ack"}           # r0276: the service worker's delivery ack, no session; proved by n, changes only push_state (tests/test_1311_r0276_push_ladder.py)


def api_routes(app):
    """(method, path) of every /api/ route of the application: the route table, not a hand-written list."""
    out = []

    def walk(routes):
        for r in routes:
            if hasattr(r, "original_router"):           # FastAPI >= 0.13x wraps included routers (no prefixes are used here)
                walk(r.original_router.routes)
                continue
            p = getattr(r, "path", "")
            if p.startswith("/api/"):
                for m in sorted(getattr(r, "methods", ()) or ()):
                    out.append((m, p))
    walk(app.routes)
    assert len(out) > 30, out
    return out


def fill(path, ids):
    return re.sub(r"\{(\w+)\}", lambda m: ids.get(m.group(1), "x_" + m.group(1)), path)


# (6) observer -> 403 on EVERY changing path of the route table
def test_6_observer_403_on_every_changing_path(app):
    owner, bob, carol = team(app)
    ag, hdr = owner.new_agent("demo", "seen")
    obs = Person(app).register("Oscar", invite=owner.invite(["observer"]))
    assert obs.joined == {"account_id": owner.uid, "status": "active", "roles": ["observer"]}
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=MSG_FORM).json()
    p = act(owner.c, hdr, "publish", {"channel": "news", "text": "t"}).json()
    ids = {"aid": ag["id"], "rid": p["rid"], "sid": d["req_id"], "mid": "m_none", "agent": ag["id"], "id": d["req_id"]}
    obs.stepup()                                          # a fresh passkey signature does not lift the role
    # r0292 (owner 13.11, p.5): the ONE changing path a Viewer may take is "freeze an agent" (tests/test_1311_r0292_viewer_freeze.py)
    changing = [(m, pth) for m, pth in api_routes(app) if m in CHANGING and not pth.startswith("/api/auth/") and pth not in USER_LEVEL
                and pth != "/api/agents/{aid}/freeze"]
    assert len(changing) >= 12, changing
    for m, pth in changing:
        r = obs.c.request(m, fill(pth, ids), json={"approved": True, "envelope_b64": "AA", "roles": ["owner"], "release": True,
                                                    "members": [], "rules": {}, "toolmap": {}, "patterns": {}}, headers=H)
        assert r.status_code == 403, (m, pth, r.status_code, r.text)
    # ... while reading works, and so does the evidence pack
    for pth in ("/api/org", "/api/agents", "/api/feed", "/api/approvals", "/api/mandates", "/api/sig-requests", "/api/me", "/api/orgs"):
        assert obs.c.get(pth).status_code == 200, pth
    assert obs.c.get("/api/sig-requests").json() == []           # nothing to sign
    assert obs.c.get("/api/export").status_code == 200
    # and the observer is not part of any policy
    assert obs.keycard["kid_hex"] not in [m["kid"] for m in owner.c.get("/api/org").json()["policy"]["members"]]
    r = owner.post("/api/org/policy/draft", members=[{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": obs.uid, "roles": ["budget"]}],
                   rules={"policy": {"role": "owner", "k": 1}, "mandate": [], "approval": [], "revocation": {"role": "any", "k": 1},
                          "ceiling": {"role": "owner", "k": 1}})
    assert r.status_code == 422 and r.json()["error"] == "NOT_MEMBER"


def test_rights_table_is_the_only_gate(app):
    """Signers that are not owners cannot change agents, tool maps, patterns, settings, invites, policy (owner rights)."""
    owner, bob, carol = team(app)
    ag, hdr = owner.new_agent("demo", "x")
    bob.stepup()
    for m, pth, j in (("POST", "/api/agents", {"name": "z"}), ("PUT", "/api/agents/%s/toolmap" % ag["id"], {"toolmap": ag["toolmap"]}),
                      ("DELETE", "/api/agents/" + ag["id"], None), ("PUT", "/api/data-patterns", {"patterns": {}}),
                      ("PUT", "/api/org/settings", {"defer_ttl_s": 900}), ("POST", "/api/org/invites", {"roles": ["budget"]}),
                      ("POST", "/api/org/policy/draft", {"members": [], "rules": {}})):
        r = bob.c.request(m, pth, json=j, headers=H)
        assert r.status_code == 403 and r.json()["error"] == "FORBIDDEN", (pth, r.text)
    assert bob.post("/api/mandates/draft", agent_id=ag["id"], form=MSG_FORM).status_code == 200      # a signer may draft a mandate
    assert set(org.RIGHTS) == {"read", "session", "write", "mandate", "sign", "owner", "freeze"}      # r0292: "freeze" -- any active member
    assert all("observer" not in org.RIGHTS[a][0] for a in ("write", "mandate", "sign", "owner"))


def test_pending_member_reads_but_cannot_act(app):
    owner = Person(app).register("Olga")
    bob = Person(app).register("Bob", invite=owner.invite(["budget"]))
    assert bob.c.get("/api/org").json()["you"] == {"user_id": bob.uid, "roles": ["budget"]}
    ag, hdr = owner.new_agent("demo", "x")
    assert bob.post("/api/mandates/draft", agent_id=ag["id"], form=MSG_FORM).status_code == 403
    p = act(owner.c, hdr, "publish", {"channel": "news", "text": "t"}).json()
    assert p["verdict"] == "deny"               # no mandate yet
    m, r = owner.mandate(ag["id"], MSG_FORM)
    assert r.status_code == 200                 # solo org (no policy yet): the owner's wa-sig as in 0.1
    d = act(owner.c, hdr, "purchase", {"vendor": "v.example", "amount_cents": 100}).json()
    assert d["verdict"] == "defer"
    r = bob.post("/api/approvals/" + d["rid"], **viewkit.claim(viewkit.answer(bob.c, d["rid"])), approved=True, envelope_b64=bob.sign(wa.TYP_APPROVAL, b"x"))
    assert r.status_code == 409 and r.json()["error"] in ("APPROVAL_SIG", "WA_CHALLENGE", "KEY_MISMATCH")   # not the pinned key


# (7) isolation: a member of organisation A sees nothing of B on any path
def test_7_member_of_a_sees_nothing_of_b(app):
    owner, bob, carol = team(app)                                 # organisation A
    eve = Person(app).register("Eve")                             # organisation B (solo) with everything in it
    ag_b, hdr_b = eve.new_agent("demo", "b-bot")
    m_b, r = eve.mandate(ag_b["id"], MSG_FORM)
    assert r.status_code == 200
    rid_b = act(eve.c, hdr_b, "publish", {"channel": "news", "text": "secret-b"}).json()["rid"]
    assert org.policy_draft(ctx_of(app), ctx_of(app).db.one("SELECT * FROM accounts WHERE id=?", (eve.uid,)), eve.uid, {})["req_id"]
    sid_b = ctx_of(app).db.one("SELECT id FROM sig_requests WHERE account_id=?", (eve.uid,))["id"]
    ids = {"aid": ag_b["id"], "rid": rid_b, "sid": sid_b, "mid": m_b["id"], "agent": ag_b["id"], "id": sid_b}
    secrets_b = [eve.uid, ag_b["id"], rid_b, sid_b, m_b["id"], "secret-b"]
    bob.stepup()
    owner.stepup()
    for who in (bob, owner):
        for m, pth in api_routes(app):
            if pth.startswith("/api/auth/"):
                continue
            url = fill(pth, ids)
            r = who.c.request(m, url, json={"approved": True, "envelope_b64": wa.b64u(b"\xa0"), "release": True, "account_id": eve.uid,
                                            "token": "x" * 20, "roles": ["budget"], "members": [], "rules": {}, "toolmap": ag_b["toolmap"],
                                            "patterns": {}, "agent_id": ag_b["id"], "form": MSG_FORM}, headers=H)
            if "{" in pth:
                assert r.status_code in (403, 404), (m, pth, r.status_code, r.text)
            body = r.text if not r.headers.get("content-type", "").startswith("application/zip") else ""
            assert not any(s in body for s in secrets_b), (m, pth, body[:300])
    assert owner.post("/api/orgs/switch", account_id=eve.uid).status_code == 404
    assert {o["account_id"] for o in bob.c.get("/api/orgs").json()} == {bob.uid, owner.uid}


# (8) an invite is one-time and expires
def test_8_invite_one_time_and_expiring(app):
    owner = Person(app).register("Olga")
    tok = owner.invite(["access"])
    bob = Person(app).register("Bob", invite=tok)
    assert bob.joined["status"] == "pending"
    eve = Person(app).register("Eve")
    r = eve.post("/api/org/join", token=tok)
    assert r.status_code == 409 and r.json()["error"] == "INVITE_INVALID"
    tok2 = owner.invite(["budget"])
    ctx_of(app).db.x("UPDATE invites SET expires=? WHERE used_by IS NULL", (org.now() - 1,))
    r = eve.post("/api/org/join", token=tok2)
    assert r.status_code == 409 and r.json()["error"] == "INVITE_INVALID"
    # registering with a used / expired invite is refused before the passkey is stored
    m = Person(app)
    j = m.post("/api/auth/register/begin", display_name="M").json()
    cred = m.auth.create_credential(wa.b64u_dec(j["options"]["challenge"]), "localhost", ORIGIN)
    r = m.c.post("/api/auth/register/finish", json={"flow_id": j["flow_id"], "credential": cred, "invite": tok}, headers=H)
    assert r.status_code == 409 and ctx_of(app).db.one("SELECT COUNT(*) AS n FROM users")["n"] == 3
    # step-up and the owner role are needed to invite; the token is stored only as a hash
    assert bob.post("/api/org/invites", roles=["budget"]).status_code == 403
    ctx_of(app).db.x("UPDATE sessions SET stepup_at=0")
    assert owner.post("/api/org/invites", roles=["budget"]).json()["error"] == "STEPUP_REQUIRED"
    assert not ctx_of(app).db.q("SELECT 1 FROM invites WHERE token_hash=?", (tok.encode(),))
    owner.stepup()
    assert owner.post("/api/org/invites", roles=["observer", "budget"]).status_code == 422
    assert owner.post("/api/org/invites", roles=["admin"]).status_code == 422


def test_join_while_logged_in_and_switch(app):
    owner = Person(app).register("Olga")
    eve = Person(app).register("Eve")
    r = eve.post("/api/org/join", token=owner.invite(["observer"]))
    assert r.status_code == 200 and r.json()["status"] == "active"
    assert eve.c.get("/api/org").json()["account_id"] == eve.uid           # still in her own organisation
    orgs = {o["account_id"]: o for o in eve.c.get("/api/orgs").json()}
    assert orgs[owner.uid]["roles"] == ["observer"] and orgs[eve.uid]["current"] is True
    assert eve.post("/api/orgs/switch", account_id=owner.uid).json() == {"account_id": owner.uid}
    assert eve.c.get("/api/org").json()["account_id"] == owner.uid
    assert eve.post("/api/agents", name="x").status_code == 403
    assert eve.post("/api/org/join", token=owner.invite(["budget"])).json()["error"] == "ALREADY_MEMBER"
    me = eve.c.get("/api/me").json()
    assert me["user"]["id"] == eve.uid and me["account"]["id"] == owner.uid and me["roles"] == ["observer"]
    assert me["keycard"]["kid_hex"] == eve.keycard["kid_hex"]


def test_stepup_and_logout_all_are_per_user(app):
    owner = Person(app).register("Olga")
    owner2 = Person(app)
    owner2.auth = owner.auth
    assert owner2.login().status_code == 200
    ctx_of(app).db.x("UPDATE sessions SET stepup_at=0")
    assert owner.post("/api/agents", name="x").json()["error"] == "STEPUP_REQUIRED"
    owner.stepup()
    assert owner.post("/api/agents", name="x").status_code == 200
    assert owner2.post("/api/agents", name="y").json()["error"] == "STEPUP_REQUIRED"     # step-up belongs to one session
    assert owner.post("/api/auth/logout-all").status_code == 204
    assert owner2.c.get("/api/me").status_code == 401


def _readable(x):
    """The export without its base64url byte fields (*_b64): what a person reads, where a name must never appear."""
    if isinstance(x, dict):
        return {k: _readable(v) for k, v in x.items() if not k.endswith("_b64")}
    if isinstance(x, list):
        return [_readable(v) for v in x]
    return x


def test_export_name_check_ignores_bytes():
    x = {"policies": [{"ver": 1, "policy_b64": "xxBobxx", "envelope_b64": "Bob"}], "members": [{"kid_hex": "ab"}]}
    assert "Bob" in str(x) and "Bob" not in str(_readable(x))          # the old check failed on such bytes; the new one does not
    assert "Bob" in str(_readable({"members": [{"label": "Bob"}]}))    # and a real name is still caught


def test_org_view_settings_and_export_org(app):
    owner, bob, carol = team(app)
    o = owner.c.get("/api/org").json()
    assert o["policy_ver"] == 2 and o["policy"]["rules"]["mandate"][0]["amount"] == 50000
    assert {m["user_id"]: (m["status"], m["roles"]) for m in o["members"]} == {
        owner.uid: ("active", ["owner", "budget"]), bob.uid: ("active", ["budget"]), carol.uid: ("active", ["access"])}
    assert all("@" not in m["label"] for m in o["members"])
    assert o["settings"] == org.DEFAULT_SETTINGS
    owner.stepup()
    s = owner.c.put("/api/org/settings", json={"profile": "enterprise", "max_pending": 3}, headers=H).json()
    assert s["profile"] == "enterprise" and s["max_pending"] == 3 and s["defer_ttl_s"] == 3600
    assert owner.c.put("/api/org/settings", json={"advisor": "gpt"}, headers=H).status_code == 422
    x = org.export_org(ctx_of(app), owner.uid)
    assert [p["ver"] for p in x["policies"]] == [1, 2] and x["rp"] == {"rp_id": "localhost", "origins": [ORIGIN]}
    assert {m["kid_hex"] for m in x["members"]} == {owner.keycard["kid_hex"], bob.keycard["kid_hex"], carol.keycard["kid_hex"]}
    # 27.10: "Bob" is looked for in the readable fields only: policy_b64 / envelope_b64 are base64url of signatures and random bytes, which
    # contain "Bob" now and then (~1 run in 100: the flaky failure of the full run); the registry rows are read in their chain order
    assert [s["kind"] for s in x["signatures"]] == ["policy", "policy"] and "Bob" not in str(_readable(x))
    # policy versions are in the registry hash chain (hourly anchor), not as the account's key record
    rows = ctx_of(app).db.q("SELECT * FROM registry_log WHERE account_id=? ORDER BY seq", ("org:" + owner.uid,))
    assert len(rows) == 2 and [r["seq"] for r in rows] == [p["registry_seq"] for p in x["policies"]]
    assert ctx_of(app).hub.entry_of(owner.uid)["pub"] == owner.auth.pub.hex()
