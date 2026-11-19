"""0.2.37: "an agent cannot approve its own held call (Tool Forgery): the approval is a human passkey signature over the call's hash".
Adversary = the agent: it has its key (Authorization: Bearer dwk_...), everything the server tells it (rid, args_sha256, approval_url, texts),
its own authenticator (it may create passkeys and accounts of its own) -- and NOT the owner's session cookie or passkey.
Every attack must be refused and nothing may be recorded as an approval / mandate / repeat slot / allowance / unfreeze."""
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

import wa_profile as wa
import wq_profile as wq
from svidetel_v4.state import approval_payload
from tests.helpers import FORM, H, ORIGIN, RP, Owner, act
from tests.test_0224_critique import Agent, row

EVIL = {"Origin": ORIGIN}


def ctx_of(client):
    return client.app.state.ctx


def snap(client):
    """Everything an approval / mandate / later-run approval / allowance / unfreeze would leave behind."""
    db = ctx_of(client).db
    one = lambda sql: db.one(sql)["n"]
    return {"approvals": one("SELECT COUNT(*) AS n FROM approvals"), "mandates": one("SELECT COUNT(*) AS n FROM mandates"),
            "repeat": one("SELECT COUNT(*) AS n FROM repeat_approvals"), "slots": one("SELECT COUNT(*) AS n FROM repeat_slots"),
            "allow": one("SELECT COUNT(*) AS n FROM allowances"), "sigreq": one("SELECT COUNT(*) AS n FROM sig_requests"),
            "frozen": one("SELECT COUNT(*) AS n FROM agents WHERE frozen_at IS NOT NULL"),
            "unfreeze_rows": one("SELECT COUNT(*) AS n FROM agent_freezes WHERE kind='unfreeze'")}


def agent_client(client):
    """The agent's HTTP client: same app, NO cookies (a fresh jar), only its key."""
    return TestClient(client.app, base_url=ORIGIN)


def agent_cookie_client(client, hdr):
    """Worst case: the agent also tries its API key as the session cookie."""
    c = TestClient(client.app, base_url=ORIGIN)
    c.cookies.set("dw_session", hdr["Authorization"][7:])
    return c


def ok_refused(r):
    return r.status_code in (400, 401, 403, 404, 405, 409, 422)


def agent_variants(client, hdr):
    """(name, client, headers): bare key, key + Origin, key as cookie."""
    return [("bearer", agent_client(client), dict(hdr)), ("bearer+origin", agent_client(client), dict(hdr, **EVIL)),
            ("cookie", agent_cookie_client(client, hdr), dict(EVIL))]


def foreign_env(typ, payload):
    return wa.b64u(wa.SoftAuthenticator().sign_object(typ, payload, RP, ORIGIN))      # the agent's own passkey: a valid wa-sig, wrong key


def make_pending(client, owner, hdr, text="release notes", channel="blog"):
    r = act(client, hdr, "publish", {"channel": channel, "text": text}).json()
    assert (r["verdict"], r["status"]) == ("defer", "pending_approval"), r
    return r


def pub_setup(owner):
    ag, hdr = owner.new_agent("demo")
    m, r = owner.mandate(ag["id"], FORM)
    assert r.status_code == 200, r.text
    return ag, hdr, m


def approval_env(owner, rid, approved=True):
    g = owner.c.get("/api/approvals/" + rid).json()
    return g, owner.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], rid, approved, viewkit.page_view(g)))


# ------------------------------------------------------------------ 1. approve a held / pending call
def test_0237_1_agent_cannot_approve_pending(client, owner):
    ag, hdr, m = pub_setup(owner)
    rid = make_pending(client, owner, hdr)["rid"]
    g, good_env = approval_env(owner, rid)                      # the envelope the OWNER would send; the agent has only a copy of its own making
    before = snap(client)
    pay = approval_payload(g["mandate"], g["action"], rid, True, viewkit.page_view(g))  # the agent can build the exact payload from the public data it was told
    for name, c, h in agent_variants(client, hdr):
        for env in (foreign_env(wa.TYP_APPROVAL, pay), "", "AAAA"):
            r = c.post("/api/approvals/" + rid, json={"approved": True, "envelope_b64": env}, headers=h)
            assert ok_refused(r), (name, r.status_code, r.text)
        for path in ("/api/approvals/batch", "/api/auth/stepup/begin"):
            r = c.post(path, json={"rids": [rid], "approved": True, "envelope_b64": foreign_env(wa.TYP_APPROVAL, pay)}, headers=h)
            assert ok_refused(r), (name, path, r.status_code)
        assert ok_refused(c.get("/api/approvals/" + rid, headers=h)), name
    assert snap(client) == before
    assert row(client, rid)["status"] == "pending_approval"
    # the call is still not allowed and cannot be presented
    assert act(client, hdr, "publish", {"channel": "blog", "text": "release notes"}).json()["verdict"] == "defer"
    assert client.post("/v1/actions/%s/present" % rid, headers=hdr).json()["result"] == "reject"


def test_0237_1b_agent_cannot_approve_with_server_fields_in_its_own_calls(client, owner):
    """The agent's own channel (/v1/actions, present, report, catalog) carries no approval: fields that look like one are ignored."""
    ag, hdr, m = pub_setup(owner)
    r = make_pending(client, owner, hdr)
    rid = r["rid"]
    junk = {"approved": True, "approval": {"approved": True}, "envelope_b64": "AAAA", "repeat": {"rids": ["r_x"]}, "verdict": "allow",
            "status": "approved", "rid": rid, "action": r["action"], "decision": "allow"}
    before = snap(client)
    for body in (dict(tool="publish", args={"channel": "blog", "text": "release notes"}, **junk),
                 dict(tool="publish", args=dict({"channel": "blog", "text": "release notes"}, **junk))):
        j = client.post("/v1/actions", json=body, headers=hdr).json()
        assert j.get("verdict") != "allow" and j.get("status") != "approved", j
    for path, body in (("/v1/actions/%s/report" % rid, {"executed": True, **junk}), ("/v1/actions/%s/present" % rid, junk),
                       ("/v1/catalog", junk), ("/v1/coverage", junk)):
        client.post(path, json=body, headers=hdr)
    assert snap(client) == before
    assert row(client, rid)["status"] == "pending_approval"
    assert client.post("/v1/actions/%s/present" % rid, headers=hdr).json()["result"] == "reject"


def test_0237_1c_agent_cannot_release_held(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_domains=["github.com", "gist.github.com"])
    [(t, v, reason, rid)] = a.tool("WebFetch", {"url": "https://gist.github.com/x?d=1", "prompt": "x"})
    assert v == "defer" and row(client, rid)["status"] == "held"
    x = row(client, rid)
    ash = json.loads(x["action_json"])["args_sha256"]                      # the hash the agent is told
    pay = wq.release_payload(rid, ash, True)
    before = snap(client)
    for name, c, h in agent_variants(client, a.hdr):
        r = c.post("/api/approvals/%s/release" % rid, json={"release": True, "envelope_b64": foreign_env(wq.TYP_RELEASE, pay)}, headers=h)
        assert ok_refused(r), (name, r.status_code, r.text)
        r = c.post("/api/approvals/" + rid, json={"approved": True, "envelope_b64": foreign_env(wa.TYP_APPROVAL, pay)}, headers=h)
        assert ok_refused(r), (name, r.status_code, r.text)
    assert snap(client) == before and row(client, rid)["status"] == "held"
    # the hook judge: a body that claims a decision is classified as a new call, never as a release
    for extra in ({"approved": True}, {"decision": "allow", "rid": rid}, {"release": True, "rid": rid, "permissionDecision": "allow"}):
        body = {"v": 1, "event": {"tool_name": "WebFetch", "tool_input": {"url": "https://gist.github.com/x?d=1", "prompt": "x"}, "cwd": a.proj,
                                  **extra}, "facts": {"home": a.home, "proc_cwd": a.proj, "env": {"CLAUDE_PROJECT_DIR": a.proj, "HOME": a.home}}, **extra}
        j = client.post("/v1/hook/judge", json=body, headers=a.hdr).json()
        for p in j.get("parts", []):
            assert p["result"].get("verdict") != "allow", j
    assert row(client, rid)["status"] == "held" and snap(client) == before
    # even the owner's session with the AGENT's passkey (key stolen, session not) cannot release
    r = owner.post("/api/approvals/%s/release" % rid, release=True, envelope_b64=foreign_env(wq.TYP_RELEASE, pay))
    assert r.status_code == 409, r.text
    assert row(client, rid)["status"] == "held"


def test_0237_1d_attacker_account_cannot_touch_victims_call(client, app, owner):
    ag, hdr, m = pub_setup(owner)
    rid = make_pending(client, owner, hdr)["rid"]
    g = owner.c.get("/api/approvals/" + rid).json()
    pay = approval_payload(g["mandate"], g["action"], rid, True, viewkit.page_view(g))
    evil = Owner(TestClient(app, base_url=ORIGIN)).register("Mallory")          # the agent registers an account of its own
    before = snap(client)
    r = evil.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(evil.c, rid)), approved=True, envelope_b64=evil.sign(wa.TYP_APPROVAL, pay))
    assert r.status_code == 404, r.text
    r = viewkit.release(evil, rid, g["action"]["args_sha256"], True)
    assert r.status_code == 404, r.text
    assert evil.c.get("/api/approvals/" + rid).status_code == 404
    assert snap(client) == before and row(client, rid)["status"] == "pending_approval"


# ------------------------------------------------------------------ 2. unfreeze
def test_0237_2_agent_cannot_unfreeze(client, owner):
    from app import actions as actmod
    ag, hdr, m = pub_setup(owner)
    rid = make_pending(client, owner, hdr)["rid"]
    c = ctx_of(client)
    acc = c.db.one("SELECT * FROM accounts WHERE id=?", (owner.account["id"],))
    actmod.freeze(c, acc, owner.account["id"], ag["id"])
    assert row(client, rid)["status"] == "denied"
    before = snap(client)
    for name, cl, h in agent_variants(client, hdr):
        for path in ("/api/agents/%s/unfreeze" % ag["id"], "/api/auth/stepup/begin", "/api/auth/stepup/finish"):
            r = cl.post(path, json={"credential": {}, "flow_id": "x"}, headers=h)
            assert ok_refused(r), (name, path, r.status_code, r.text)
        r = cl.delete("/api/agents/%s" % ag["id"], headers=h)
        assert ok_refused(r), (name, r.status_code)
    evil = Owner(TestClient(client.app, base_url=ORIGIN)).register("Mallory")
    assert evil.post("/api/agents/%s/unfreeze" % ag["id"]).status_code in (403, 404)       # another account's session
    assert snap(client) == before
    assert ctx_of(client).db.one("SELECT frozen_at FROM agents WHERE id=?", (ag["id"],))["frozen_at"]
    r = act(client, hdr, "publish", {"channel": "blog", "text": "hi"}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "AGENT_FROZEN"), r
    # the owner's session WITHOUT a fresh passkey touch (step-up) cannot unfreeze either
    ctx_of(client).db.x("UPDATE sessions SET stepup_at=0")                 # (the touch of the registration lasts 5 minutes; here it is over)
    r = owner.post("/api/agents/%s/unfreeze" % ag["id"])
    assert r.status_code == 403 and r.json()["error"] == "STEPUP_REQUIRED", r.text
    assert ctx_of(client).db.one("SELECT frozen_at FROM agents WHERE id=?", (ag["id"],))["frozen_at"]


# ------------------------------------------------------------------ 3. sign / change a mandate
def test_0237_3_agent_cannot_sign_or_change_mandate(client, owner):
    ag, hdr, m = pub_setup(owner)
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=dict(FORM, delete={"enabled": True}, publish={"channels": ["blog", "x"]})).json()
    wider = d["mandate"]                                                   # a wider mandate the agent would like to have signed
    mid = ctx_of(client).db.one("SELECT id FROM mandates WHERE agent_id=? AND status='active'", (ag["id"],))["id"]
    before = snap(client)
    sig = foreign_env(wa.TYP_MANDATE, wa.cde(wider))                       # signed with the agent's own passkey
    for name, c, h in agent_variants(client, hdr):
        for path, body in (("/api/mandates/draft", {"agent_id": ag["id"], "form": FORM}), ("/api/mandates", {"mandate": wider, "envelope_b64": sig}),
                           ("/api/mandates/%s/revoke" % mid, {"envelope_b64": sig}), ("/api/mandates/revoke-batch", {"ids": [mid], "envelope_b64": sig}),
                           ("/api/allowances", {"rid": "r_x", "envelope_b64": sig}), ("/api/org/policy/draft", {}), ("/api/org/key-replace", {})):
            r = c.post(path, json=body, headers=h)
            assert ok_refused(r), (name, path, r.status_code, r.text)
        r = c.put("/api/agents/%s/toolmap" % ag["id"], json={"toolmap": {}}, headers=h)
        assert ok_refused(r), (name, r.status_code)
        r = c.put("/api/agents/%s/delegation" % ag["id"], json={}, headers=h)
        assert ok_refused(r), (name, r.status_code)
    # the owner's session with the agent's passkey: the signature is valid but is not the owner's key
    r = owner.post("/api/mandates", mandate=wider, envelope_b64=sig)
    assert r.status_code == 409, r.text
    # an attacker account cannot sign a mandate for the victim's agent
    evil = Owner(TestClient(client.app, base_url=ORIGIN)).register("Mallory")
    r = evil.post("/api/mandates", mandate=wider, envelope_b64=evil.sign(wa.TYP_MANDATE, wa.cde(wider)))
    assert r.status_code in (404, 409), r.text
    assert snap(client) == before
    assert ctx_of(client).db.one("SELECT status FROM mandates WHERE id=?", (mid,))["status"] == "active"
    # and the call the wider mandate would have allowed is still not allowed
    assert act(client, hdr, "delete", {"path": "/x"}).json().get("verdict") != "allow"


# ------------------------------------------------------------------ 4. "approve for later runs"
def test_0237_4_agent_cannot_create_repeat_approval(client, owner):
    ag, hdr, m = pub_setup(owner)
    r = make_pending(client, owner, hdr)
    rid = r["rid"]
    g = owner.c.get("/api/approvals/" + rid).json()
    offer = g.get("repeat_offer")
    assert offer, g
    reserved = ["r_" + "ab" * 8, "r_" + "cd" * 8]                       # ids the agent invents
    wb = foreign_env(wa.TYP_APPROVAL, b"x")                               # the agent cannot build a wb the server accepts: its own passkey is not the owner's
    before = snap(client)
    for name, c, h in agent_variants(client, hdr):
        for rep in ({"rids": reserved}, {"rids": offer.get("rids", reserved)}):
            rr = c.post("/api/approvals/" + rid, json={"approved": True, "envelope_b64": wb, "repeat": rep}, headers=h)
            assert ok_refused(rr), (name, rr.status_code, rr.text)
        assert ok_refused(c.post("/api/repeat-approvals/gid/revoke", json={}, headers=h))
    # owner session + the agent's passkey: refused as well
    rr = owner.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(owner.c, rid)), approved=True, envelope_b64=wb, repeat={"rids": offer.get("rids", reserved)})
    assert rr.status_code in (400, 409), rr.text
    assert snap(client) == before
    assert row(client, rid)["status"] == "pending_approval"
    # the invented ids are no approvals: a repeated call is still a question
    for i in range(2):
        assert act(client, hdr, "publish", {"channel": "blog", "text": "release notes"}).json()["verdict"] == "defer"


# ------------------------------------------------------------------ 5. replay of an old approval onto another call with the same text
def test_0237_5_replay_old_approval_other_args(client, owner):
    ag, hdr, m = pub_setup(owner)
    a = make_pending(client, owner, hdr, text="release notes", channel="blog")
    ra = a["rid"]
    g, env_a = approval_env(owner, ra)
    assert owner.post("/api/approvals/" + ra, **viewkit.claim(viewkit.answer(owner.c, ra)), approved=True, envelope_b64=env_a).json()["verdict"] == "allow"
    ok = act(client, hdr, "publish", {"channel": "blog", "text": "release notes"}).json()
    assert ok["verdict"] == "allow" and ok["rid"] == ra
    # same text, other arguments (other channel / extra arg): a NEW question, not covered by the old approval
    b = act(client, hdr, "publish", {"channel": "news", "text": "release notes"}).json()
    c_ = act(client, hdr, "publish", {"channel": "blog", "text": "release notes", "x": 1}).json()
    for j in (b, c_):
        assert j["verdict"] in ("defer", "deny") and j["rid"] != ra, j        # (an unmapped extra argument is denied outright)
        assert j["verdict"] == "deny" or j["status"] == "pending_approval"
    assert b["verdict"] == "defer" and b["rid"] != c_["rid"]
    before = snap(client)
    # the leaked old envelope (agent has no cookie) and, worse, with the owner's cookie: the signature is over (mandate, action, rid) of A
    for rb in (b["rid"],):
        for name, cl, h in agent_variants(client, hdr):
            r = cl.post("/api/approvals/" + rb, json={"approved": True, "envelope_b64": env_a}, headers=h)
            assert ok_refused(r), (name, r.status_code)
        r = owner.post("/api/approvals/" + rb, **viewkit.claim(viewkit.answer(owner.c, rb)), approved=True, envelope_b64=env_a)
        assert r.status_code == 409, r.text
        assert row(client, rb)["status"] == "pending_approval"
        assert client.post("/v1/actions/%s/present" % rb, headers=hdr).json()["result"] == "reject"
    assert snap(client) == before
    # the approved call can be used once only (replay of the consumed one)
    assert client.post("/v1/actions/%s/present" % ra, headers=hdr).json()["result"] == "accept"
    assert client.post("/v1/actions/%s/present" % ra, headers=hdr).json()["result"] == "reject"
    # a replayed envelope onto the already approved rid is refused too (no second approval row)
    r = owner.post("/api/approvals/" + ra, **viewkit.claim(viewkit.answer(owner.c, ra)), approved=True, envelope_b64=env_a)
    assert r.status_code == 409, r.text
    assert snap(client)["approvals"] == before["approvals"]


# ------------------------------------------------------------------ 6. change the arguments after the approval (TOCTOU)
def test_0237_6_toctou_args_changed_after_approval(client, owner):
    ag, hdr, m = pub_setup(owner)
    a = make_pending(client, owner, hdr, text="benign text", channel="blog")
    ra = a["rid"]
    g = owner.c.get("/api/approvals/" + ra).json()
    shown = g["action"]["args_sha256"]
    assert owner.approve(ra).json()["verdict"] == "allow"
    # (a) other arguments after the approval -> never allowed under the old rid, always a new question
    for args in ({"channel": "blog", "text": "benign text "}, {"channel": "blog", "text": "EVIL text"}, {"channel": "evil", "text": "benign text"},
                 {"text": "benign text", "channel": "blog", "extra": True}, {"channel": "blog", "text": "benign text", "channel ": "evil"}):
        j = act(client, hdr, "publish", args).json()
        assert j["verdict"] in ("defer", "deny") and j["rid"] != ra and (j.get("action") or {}).get("args_sha256") != shown, (args, j)
        assert client.post("/v1/actions/%s/present" % j["rid"], headers=hdr).json()["result"] == "reject"
        assert row(client, j["rid"])["status"] in ("pending_approval", "denied")
    # (b) the approved call itself still says exactly the approved hash; presenting it does not take new arguments
    j = client.post("/v1/actions/%s/present" % ra, json={"tool": "publish", "args": {"channel": "evil", "text": "EVIL"}}, headers=hdr).json()
    assert j["result"] == "accept"
    assert json.loads(row(client, ra)["action_json"])["args_sha256"] == shown
    # (c) swap while pending: A pending, then A' with the same rid asked for -> two different rids; approving A leaves A' open
    p1 = make_pending(client, owner, hdr, text="first", channel="blog")
    p2 = act(client, hdr, "publish", {"channel": "blog", "text": "first, but different"}).json()
    assert p1["rid"] != p2["rid"] and p2["status"] == "pending_approval"
    assert owner.approve(p1["rid"]).json()["verdict"] == "allow"
    assert row(client, p2["rid"])["status"] == "pending_approval"
    assert client.post("/v1/actions/%s/present" % p2["rid"], headers=hdr).json()["result"] == "reject"
    # (d) the approval of A refused for A' even when the owner's own client sends A's payload for A''s rid
    g2 = owner.c.get("/api/approvals/" + p2["rid"]).json()
    wrong = owner.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], p2["rid"], True, viewkit.page_view(g)))      # action of A, rid of A'
    r = owner.post("/api/approvals/" + p2["rid"], **viewkit.claim(viewkit.answer(owner.c, p2["rid"])), approved=True, envelope_b64=wrong)
    assert r.status_code == 409, r.text
    assert row(client, p2["rid"])["status"] == "pending_approval"


# ================================================================== Team: the quorum branch (sig-requests)
# Policy v2 (tests/org_helpers.TEAM_RULES): approvals of money over 50000 need budget k=2 (owner Olga + Bob), the rest k=1.
from tests.org_helpers import ctx_of as _octx, policy_hash_now, team, adopt, Person, TEAM_RULES, MSG_FORM  # noqa: E402
from tests.test_quorum import msg_mandate, deferred_purchase, approval_env as q_env  # noqa: E402
from tests import viewkit  # noqa: E402  (r0352: decisions name the view)


def team_snap(app, rid=None):
    db = _octx(app).db
    n = lambda sql, *a: db.one(sql, a)["n"]
    return {"approvals": n("SELECT COUNT(*) AS n FROM approvals"), "repeat": n("SELECT COUNT(*) AS n FROM repeat_approvals"),
            "status": db.one("SELECT status FROM actions WHERE rid=?", (rid,))["status"] if rid else None}


def sid_of(app, rid):
    r = _octx(app).db.one("SELECT id FROM sig_requests WHERE kind='approval' AND ref=? AND status='collecting'", (rid,))
    return r["id"] if r else None


def collecting(app, sid):
    r = _octx(app).db.one("SELECT status, sigs FROM sig_requests WHERE id=?", (sid,))
    return r["status"], len(json.loads(r["sigs"] or "[]"))


def test_0237_7_team_agent_key_cannot_touch_sig_requests(app):
    owner, bob, carol = team(app)
    ag, hdr, m = msg_mandate(owner)
    d = deferred_purchase(owner, hdr, 70000)
    assert owner.approve(d["rid"]).json()["verdict"] == "collecting"
    sid = sid_of(app, d["rid"])
    pay = json.loads(json.dumps(0))
    client = owner.c
    env = foreign_env(wa.TYP_APPROVAL, b"x")
    before = team_snap(app, d["rid"])
    for name, c, h in agent_variants(client, hdr):
        for r in (c.get("/api/sig-requests", headers=h), c.get("/api/sig-requests/" + sid, headers=h),
                  c.post("/api/sig-requests/" + sid, json={"envelope_b64": env}, headers=h),
                  c.post("/api/approvals/" + d["rid"], json={"approved": True, "envelope_b64": env}, headers=h),
                  c.post("/api/org/policy/draft", json={}, headers=h), c.post("/api/org/invites", json={"roles": ["owner"]}, headers=h)):
            assert ok_refused(r), (name, r.status_code, r.text)
    assert collecting(app, sid) == ("collecting", 1) and team_snap(app, d["rid"]) == before


def test_0237_8_team_quorum_one_person_cannot_fill_it(app):
    from tests.recovery_helpers import add_key
    owner, bob, carol = team(app)
    ag, hdr, m = msg_mandate(owner)
    d = deferred_purchase(owner, hdr, 70000)
    rid = d["rid"]
    r = owner.approve(rid).json()
    assert r["verdict"] == "collecting" and (r["have"], r["need"]) == (1, 2)
    sid = sid_of(app, rid)
    # (a) the same person, the same passkey, again: via the request and via the approval endpoint, also with a fresh assertion
    for _ in range(2):
        r = owner.sign_req(sid)
        assert r.status_code == 409 and r.json()["error"] == "WQ_DUP_SIGNER", r.text
        r = owner.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(owner.c, rid)), approved=True, envelope_b64=q_env(owner, rid))
        assert r.status_code == 409 and r.json()["error"] == "WQ_DUP_SIGNER", r.text
    # (b) the same person with ANOTHER passkey of his own (not a member's key in the policy): not a second signer
    new, cr = add_key(owner, label="laptop2")
    assert cr.status_code == 200, cr.text
    g = owner.c.get("/api/sig-requests/" + sid).json()
    r = owner.post("/api/sig-requests/" + sid, envelope_b64=wa.b64u(new.sign_object(g["typ"], wa.b64u_dec(g["payload_b64"]), RP, ORIGIN)))
    assert r.status_code == 409, r.text
    # (c) a member without the needed role (Carol: access) cannot be the second signer
    r = carol.approve(rid)
    assert r.status_code == 403 and r.json()["error"] == "ROLE_NOT_NEEDED", r.text
    # (d) Bob's valid envelope of ANOTHER call (same vendor text, other amount) fed to this request
    d2 = deferred_purchase(owner, hdr, 80000)
    bob_other = q_env(bob, d2["rid"])
    r = bob.post("/api/sig-requests/" + sid, envelope_b64=bob_other)
    assert r.status_code == 409, r.text
    r = bob.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(bob.c, rid)), approved=True, envelope_b64=bob_other)
    assert r.status_code == 409, r.text
    assert collecting(app, sid) == ("collecting", 1)
    # (e) the owner's own first signature, replayed into the request of the other call
    owner.approve(d2["rid"])
    sid2 = sid_of(app, d2["rid"])
    r = bob.post("/api/sig-requests/" + sid2, envelope_b64=q_env(bob, rid))                  # Bob's signature for call 1 into request 2
    assert r.status_code == 409, r.text
    # (f) a refusal is not an approval: Carol signing "refuse" does not count towards approve
    assert collecting(app, sid) == ("collecting", 1) and collecting(app, sid2) == ("collecting", 1)
    assert team_snap(app, rid)["status"] == "pending_approval" and team_snap(app)["approvals"] == 0
    assert client_act(owner, hdr)["verdict"] == "defer"
    assert owner.c.post("/v1/actions/%s/present" % rid, headers=hdr).json()["result"] == "reject"
    # control: the real second budget signer completes it
    r = bob.approve(rid).json()
    assert r["verdict"] == "allow", r


def client_act(owner, hdr, amount=70000):
    return act(owner.c, hdr, "purchase", {"vendor": "v.example", "amount_cents": amount}).json()


def test_0237_9_team_stale_request_after_threshold_or_membership_change(app):
    owner, bob, carol = team(app)
    ag, hdr, m = msg_mandate(owner)
    d = deferred_purchase(owner, hdr, 70000)
    rid = d["rid"]
    assert owner.approve(rid).json()["verdict"] == "collecting"
    sid = sid_of(app, rid)
    bob_env = q_env(bob, rid)                                  # Bob's valid signature, made while he is still a member
    # (a) a non-owner cannot change the threshold or the members (rule `policy` = owner)
    for who in (bob, carol):
        r = who.post("/api/org/policy/draft", members=[{"user_id": who.uid, "roles": ["owner", "budget"]}], rules=dict(TEAM_RULES, approval=[]))
        assert r.status_code in (403, 409, 422), (who, r.status_code, r.text)
    assert _octx(app).db.one("SELECT COUNT(*) AS n FROM sig_requests WHERE kind='policy' AND status='collecting'")["n"] == 0
    # (b) the OWNER (policy rule: owner k=1) lowers the threshold and drops Bob: the open request names the old policy and cannot be completed
    one = [{"if": "money_over", "amount": 50000, "role": "budget", "k": 1}]
    low = dict(TEAM_RULES, approval=one, mandate=one)
    v = adopt(owner, [{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": carol.uid, "roles": ["access"]}], low)   # 0.2.37: owner + the quorum
    assert v == 3
    r = bob.post("/api/sig-requests/" + sid, envelope_b64=bob_env)
    assert r.status_code in (403, 409), r.text                                   # Bob left; the old request names a policy not in force
    r = bob.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(bob.c, rid)), approved=True, envelope_b64=bob_env)
    assert r.status_code in (403, 409), r.text
    assert collecting(app, sid)[0] != "done" and team_snap(app, rid)["status"] == "pending_approval" and team_snap(app)["approvals"] == 0
    # (c) a wq assembled by hand from the OLD quorum (owner + Bob, old policy hash) is refused by the approval path
    from app import actions
    acc = _octx(app).db.one("SELECT * FROM accounts WHERE id=?", (owner.uid,))
    g = owner.c.get("/api/approvals/" + rid)
    g = g.json()
    pay = approval_payload(g["mandate"], g["action"], rid, True, viewkit.page_view(g))
    old_hash = _octx(app).db.one("SELECT policy_hash FROM sig_requests WHERE id=?", (sid,))["policy_hash"]
    env = wq.make_wq(wa.TYP_APPROVAL, pay, bytes(old_hash), [owner.wsig(wa.TYP_APPROVAL, pay), bob.wsig(wa.TYP_APPROVAL, pay)])
    with pytest.raises(Exception) as e:
        actions.approve_with_envelope(_octx(app), acc, rid, True, env)
    assert team_snap(app)["approvals"] == 0 and team_snap(app, rid)["status"] == "pending_approval"


def test_0237_10_team_replaced_key_cannot_sign(app):
    """A member's lost passkey: after the team's key replacement (owner + Carol sign, rule `recovery`) the OLD key signs nothing.
    (Before the replacement a lost-but-not-replaced key is still the member's active key: that is the design, it needs Bob's session.)"""
    from tests.test_recovery_org import team_with_recovery, lose_and_recover
    owner, bob, carol = team_with_recovery(app)
    ag, hdr, m = msg_mandate(owner)
    lost, new = lose_and_recover(app, bob, owner.uid)
    rq = owner.post("/api/org/key-replace", user_id=bob.uid).json()
    owner.sign_req(rq["req_id"])
    assert carol.sign_req(rq["req_id"]).json()["status"] == "done"
    d = deferred_purchase(owner, hdr, 70000)
    rid = d["rid"]
    assert owner.approve(rid).json()["verdict"] == "collecting"
    sid = sid_of(app, rid)
    g = owner.c.get("/api/sig-requests/" + sid).json()
    old_sig = wa.b64u(lost.sign_object(g["typ"], wa.b64u_dec(g["payload_b64"]), RP, ORIGIN))
    for who in (bob, owner):                                      # from Bob's own session and from the owner's session
        r = who.post("/api/sig-requests/" + sid, envelope_b64=old_sig)
        assert r.status_code == 409, (who, r.text)
        r = who.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(who.c, rid)), approved=True, envelope_b64=old_sig)
        assert r.status_code == 409, (who, r.text)
    for name, c, h in agent_variants(owner.c, hdr):
        assert ok_refused(c.post("/api/sig-requests/" + sid, json={"envelope_b64": old_sig}, headers=h)), name
    assert collecting(app, sid) == ("collecting", 1) and team_snap(app)["approvals"] == 0 and team_snap(app, rid)["status"] == "pending_approval"
    assert bob.approve(rid).json()["verdict"] == "allow"          # control: the NEW key is Bob's now


def test_0237_11_team_operator_cannot_approve_own_agent(app):
    owner, bob, carol = team(app)
    ag, hdr, m = msg_mandate(owner)
    owner.stepup()
    v = owner.c.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": bob.uid}, headers=H).json()
    assert owner.sign_req(v["policy_request"]["req_id"]).json()["status"] == "done"          # the delegation is now in the SIGNED policy
    r = act(owner.c, hdr, "purchase", {"vendor": "d.example", "amount_cents": 5000}).json()
    assert r["verdict"] == "defer", r
    rid = r["rid"]
    base = team_snap(app, rid)
    # Bob runs the agent: every path he has is refused with SELF_APPROVAL
    r = bob.approve(rid)
    assert r.status_code == 409 and r.json()["error"] == "SELF_APPROVAL", r.text
    sid = sid_of(app, rid)
    if sid:
        r = bob.sign_req(sid)
        assert r.status_code == 409 and r.json()["error"] in ("SELF_APPROVAL", "SIGREQ_CLOSED"), r.text
    items = [hashlib.sha256(approval_payload(*_pay_args(owner, rid))).digest()]
    ad, cd, der = bob.auth.get_assertion(wq.wb_challenge(items), RP, ORIGIN)
    r = bob.post("/api/approvals/batch", rids=[rid], approved=True, envelope_b64=wa.b64u(wq.make_wb(items, bob.auth.kid, ad, cd, der)))
    assert r.status_code == 409 or (r.status_code == 200 and not _batch_ok(r.json())), r.text
    from app import actions
    acc = _octx(app).db.one("SELECT * FROM accounts WHERE id=?", (owner.uid,))
    pay = approval_payload(*_pay_args(owner, rid))
    env = wq.make_wq(wa.TYP_APPROVAL, pay, policy_hash_now(app, owner.uid), [bob.wsig(wa.TYP_APPROVAL, pay)])
    with pytest.raises(Exception):
        actions.approve_with_envelope(_octx(app), acc, rid, True, env)
    # the passkey of the agent's operator used from the AGENT's side or another member's session: not his key for that session
    r = carol.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(carol.c, rid)), approved=True, envelope_b64=q_env(bob, rid))
    assert r.status_code == 409, r.text
    assert team_snap(app, rid) == base and base["approvals"] == 0
    assert client_act(owner, hdr, 5000)["verdict"] == "defer"
    # control: a DIFFERENT member (the owner) can
    assert owner.approve(rid).json()["verdict"] == "allow"


def _pay_args(owner, rid):
    g = owner.c.get("/api/approvals/" + rid).json()
    return g["mandate"], g["action"], rid, True


def _batch_ok(j):
    return any(x.get("verdict") == "allow" for x in j.get("results", []))


def test_0237_12_team_owner_lowers_threshold_and_approves_himself(app):
    """0.2.37 (owner decision 24.10): the OWNER alone can no longer lower the quorum threshold, drop a member and approve on his own."""
    owner, bob, carol = team(app)
    ag, hdr, m = msg_mandate(owner)
    d = deferred_purchase(owner, hdr, 70000)
    rid = d["rid"]
    one = [{"if": "money_over", "amount": 50000, "role": "budget", "k": 1}]
    dr = owner.post("/api/org/policy/draft", members=[{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": carol.uid, "roles": ["access"]}],
                    rules=dict(TEAM_RULES, approval=one, mandate=one))
    assert dr.status_code == 200, dr.text
    r = owner.sign_req(dr.json()["req_id"])
    assert r.status_code == 200 and r.json()["status"] == "collecting", r.text           # one signature is not the current quorum
    # the delayed route schedules only; it does not apply now
    dd = owner.post("/api/org/policy/draft", members=[{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": carol.uid, "roles": ["access"]}],
                    rules=dict(TEAM_RULES, approval=one, mandate=one), delayed=True)
    assert owner.sign_req(dd.json()["req_id"]).json()["status"] == "scheduled"
    # ... so the owner's own approval still has only one of two budget signatures
    r = owner.approve(rid)
    assert r.json()["verdict"] == "collecting", r.text
    assert team_snap(app, rid)["status"] == "pending_approval" and team_snap(app)["approvals"] == 0
    assert _octx(app).hub is not None and org_ver(app, owner) == 2


def org_ver(app, owner):
    from app import org
    return org.current_policy(_octx(app), owner.uid)[0]["ver"]


# ================================================================== 0.2.38: the trial branch (an account on the first touch, app/trial.py)
def trial_snap(client):
    db = ctx_of(client).db
    one = lambda sql: db.one(sql)["n"]
    return dict(snap(client), creds=one("SELECT COUNT(*) AS n FROM credentials"), users=one("SELECT COUNT(*) AS n FROM users"),
                claimed=one("SELECT COUNT(*) AS n FROM accounts WHERE trial_claimed_at IS NOT NULL"),
                covered=one("SELECT COUNT(*) AS n FROM actions WHERE status='covered'"),
                allowed=one("SELECT COUNT(*) AS n FROM actions WHERE verdict='allow'"))


def test_0237_13_trial_agent_cannot_claim_or_approve(client, app, tmp_path):
    """The agent holds the TRIAL key (deus-witness try saved it next to the hook) and everything /v1 tells it; the claim went to the browser
    only. It cannot become the account's owner, cannot approve its waiting calls, cannot turn them into allowed ones by any /v1 path, and
    the claim is not in anything the server says to the key. After the person's first touch, the old claim is dead and the agent's own
    passkey is not the owner's."""
    import os as _os
    from tests.test_0238_trial import new_trial, proj, hook, rows, Person
    t = new_trial(client, tmp_path)
    hdr = {"Authorization": "Bearer " + t["api_key"]}
    h = hook(client, t["api_key"], proj(tmp_path), tmp_path)
    h("git push origin main")
    h("ls")
    rs = rows(client, t["agent_id"])
    assert rs and all(x["reason"] == "ESCALATE_TRIAL_CLAIM" and x["status"] == "pending_approval" for x in rs)
    before = trial_snap(client)
    mine = wa.SoftAuthenticator()                                       # the agent's own authenticator
    # (a) everything the server tells the key: the claim is in none of it
    told = []
    for r_ in rs:
        told.append(client.get("/v1/actions/" + r_["rid"], headers=hdr).text)
    told.append(client.post("/v1/hook/judge", json={"v": 1, "event": {"tool_name": "Bash", "tool_input": {"command": "git push origin main"}, "cwd": "/"},
                                                    "facts": {}}, headers=hdr).text)
    told.append(client.get("/v1/salt", headers=hdr).text)
    assert not any(t["claim"] in x for x in told)
    # (b) claim / state / view with the key in every form the agent can send it, and with its own passkey
    for name, c, hh in agent_variants(client, hdr):
        for cl in (None, "", t["api_key"], t["agent_id"], "dwc_" + "A" * 43, rs[0]["rid"]):
            b = c.post("/api/trial/claim/begin", json={"claim": cl}, headers=hh)
            assert ok_refused(b), (name, cl, b.status_code)
            st = c.get("/api/trial/state", headers=dict(hh, **{"X-DW-Claim": cl or ""}))
            assert ok_refused(st), (name, cl, st.status_code)
            cred = mine.create_credential(b"\x00" * 32, RP, ORIGIN)
            f = c.post("/api/trial/claim/finish", json={"flow_id": "x", "credential": cred, "claim": cl}, headers=hh)
            assert ok_refused(f), (name, cl, f.status_code)
        assert ok_refused(c.get("/api/trial", headers=hh)) and ok_refused(c.post("/api/trial/keep", json={}, headers=hh))
        # (c) approve / release / batch / mandate on the waiting rows
        for r_ in rs:
            for path, body in (("/api/approvals/" + r_["rid"], {"approved": True, "envelope_b64": foreign_env(wa.TYP_APPROVAL, b"x")}),
                               ("/api/approvals/%s/release" % r_["rid"], {"release": True, "envelope_b64": foreign_env(wq.TYP_RELEASE, b"x")}),
                               ("/api/approvals/batch", {"rids": [r_["rid"]], "approved": True, "envelope_b64": "AAAA"}),
                               ("/api/mandates", {"mandate": {"agent": t["agent_id"]}, "envelope_b64": foreign_env(wa.TYP_MANDATE, b"x")}),
                               ("/api/mandates/draft", {"agent_id": t["agent_id"], "form": {}}), ("/api/auth/register/finish", {"credential": {}})):
                rr = c.post(path, json=body, headers=hh)
                assert ok_refused(rr), (name, path, rr.status_code, rr.text)
    # (d) its own fields on its own channel never claim or approve
    for path, body in (("/v1/actions/%s/present" % rs[0]["rid"], {"claim": t["claim"][:4], "approved": True}),
                       ("/v1/actions/%s/report" % rs[0]["rid"], {"executed": True, "claim": "x"}), ("/v1/trial", {"claim": "x", "form": {}})):
        client.post(path, json=body, headers=hdr)
    assert client.post("/v1/actions/%s/present" % rs[0]["rid"], headers=hdr).json()["result"] == "reject"
    assert trial_snap(client) == before
    # (e) the agent makes a trial of its OWN and claims it with its own passkey: the victim's rows stay out of reach
    evil = Person(app, None)
    et = client.post("/v1/trial", json={"form": t["form"]}).json()
    evil.claim, evil.auth = et["claim"], mine
    assert evil.claim_it().status_code == 200
    for r_ in rs:
        assert evil.post("/api/approvals/" + r_["rid"], **viewkit.claim(viewkit.answer(evil.c, r_["rid"])), approved=True, envelope_b64=evil.sign(wa.TYP_APPROVAL, b"x")).status_code == 404
        assert evil.c.get("/api/approvals/" + r_["rid"]).status_code == 404
    assert all(x["status"] == "pending_approval" for x in rows(client, t["agent_id"]))
    # (f) the person claims; afterwards the old claim (replayed by anyone) and the agent's passkey are nothing
    me = Person(app, t["claim"])
    assert me.claim_it().status_code == 200
    assert me.claim_it(auth=mine).status_code == 404
    for name, c, hh in agent_variants(client, hdr):
        assert ok_refused(c.post("/api/trial/claim/begin", json={"claim": t["claim"]}, headers=hh))
    m_ = me.c.get("/api/trial").json()
    d = me.post("/api/mandates/draft", agent_id=m_["agent_id"], form=m_["form"]).json()
    r = me.post("/api/mandates", mandate=d["mandate"], envelope_b64=wa.b64u(mine.sign_object(wa.TYP_MANDATE, wa.cde(d["mandate"]), RP, ORIGIN)),
                toolmap_sha256=d["toolmap_sha256"])
    assert r.status_code == 409, r.text                                  # the owner's session + the AGENT's passkey: not the owner's key
    assert all(x["status"] == "pending_approval" for x in rows(client, t["agent_id"]))
    assert ctx_of(client).db.one("SELECT COUNT(*) AS n FROM mandates WHERE agent_id=?", (t["agent_id"],))["n"] == 0
