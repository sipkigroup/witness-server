"""0.2.20: the passkey signature counter (WebAuthn L3 6.1.1 / 7.2 step 21) on EVERY verified passkey signature, not only on sign-in.

Rule (app/org.py sign_count_ok): when the stored or the new counter is non-zero the new one must be strictly greater, else
409 SIGN_COUNT_REGRESSION (sign-in: 401), a "warn" line in the JSON log, and no counter moves; 0 and 0 (synced passkeys) pass.
Stored atomically (one transaction / one conditional UPDATE under the writer lock): of two signatures with one counter only one passes.
The SoftAuthenticator of the tests always writes counter 0; `counting()` makes it write `auth.counter` (assertions) and `auth.reg_counter`
(registration)."""
import json
import threading

import cbor2
from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
from app import org
from app.context import Err
import wa_profile as wa
import wq_profile as wq
from svidetel_v4.state import approval_payload
from tests.helpers import ORIGIN, RP, Owner, act
from tests.test_flow import setup_agent
from tests import viewkit  # noqa: E402  (r0352: decisions name the view)


def counting(auth, start=0, reg=0):
    auth.counter, auth.reg_counter = start, reg
    orig = auth._auth_data

    def _ad(rp_id, flags, sign_count=0, attested=b""):
        return orig(rp_id, flags, auth.reg_counter if attested else auth.counter, attested)
    auth._auth_data = _ad
    return auth


def stored(client, kid=None):
    rows = client.app.state.ctx.db.q("SELECT kid, sign_count FROM credentials")
    if kid is None:
        assert len(rows) == 1
        return rows[0]["sign_count"]
    return [r["sign_count"] for r in rows if bytes(r["kid"]) == kid][0]


def defer(client, hdr, text):
    r = act(client, hdr, "publish", {"channel": "blog", "text": text}).json()
    assert r["verdict"] == "defer", r
    return r["rid"]


def approval_env(o, rid, approved=True):
    g = o.c.get("/api/approvals/" + rid).json()
    return o.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], rid, approved, viewkit.page_view(g)))   # r0352: over the view


def status(client, rid):
    return client.app.state.ctx.db.one("SELECT status FROM actions WHERE rid=?", (rid,))["status"]


def counted_owner(client, start=0, reg=0, name="Alice"):
    o = Owner(client)
    counting(o.auth, start, reg)
    return o.register(name)


# ---- the rule ---------------------------------------------------------------------------------------------------------------------------

def test_rule_table():
    ok = org.sign_count_ok
    assert ok(0, 0) and ok(None, 0)                              # synced passkeys: no counter at all
    assert ok(0, 1) and ok(5, 6) and ok(5, 0x80000000)           # growth (unsigned 32 bit)
    assert not ok(5, 5) and not ok(5, 3) and not ok(5, 0)        # equal / back / reset to 0
    assert not ok(0xFFFFFFFF, 0xFFFFFFFF)                        # no wrap-around: a counter at the top is stuck (spec)


# ---- regression refused, logged; growth stored -----------------------------------------------------------------------------------------

def test_regression_refused_logged_and_nothing_moves(client, capsys):
    o = counted_owner(client, start=5)
    ag, hdr, _ = setup_agent(o)                                   # mandate signed with counter 5
    assert stored(client) == 5
    rid = defer(client, hdr, "a")
    capsys.readouterr()
    o.auth.counter = 3                                           # a copy of the key, behind the original
    r = o.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(o.c, rid)), approved=True, envelope_b64=approval_env(o, rid))
    assert r.status_code == 409 and r.json()["error"] == "SIGN_COUNT_REGRESSION", r.text
    out = [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]
    w = [x for x in out if x.get("msg") == "SIGN_COUNT_REGRESSION"]
    assert w and w[0]["level"] == "warn" and (w[0]["stored"], w[0]["got"], w[0]["route"]) == (5, 3, "approve"), out
    assert stored(client) == 5 and status(client, rid) == "pending_approval"
    o.auth.counter = 5                                           # equal = not greater
    assert o.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(o.c, rid)), approved=False, envelope_b64=approval_env(o, rid, False)).json()["error"] == "SIGN_COUNT_REGRESSION"
    o.auth.counter = 0                                           # a counter that falls back to 0 after a non-zero one
    assert o.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(o.c, rid)), approved=True, envelope_b64=approval_env(o, rid)).json()["error"] == "SIGN_COUNT_REGRESSION"
    o.auth.counter = 6
    r = o.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(o.c, rid)), approved=True, envelope_b64=approval_env(o, rid))
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    assert stored(client) == 6


def test_zero_zero_passes_everywhere(client):
    o = counted_owner(client, start=0)
    ag, hdr, _ = setup_agent(o)
    for i, approved in enumerate((True, True, False)):            # refuse last (a refusal denies look-alikes after it)
        rid = defer(client, hdr, "z%d" % i)
        assert o.approve(rid, approved).status_code == 200
    assert o.login().status_code == 200 and o.login().status_code == 200
    assert stored(client) == 0


def test_growth_passes_and_is_stored(client):
    o = counted_owner(client, start=1)
    ag, hdr, _ = setup_agent(o)
    assert stored(client) == 1
    for c in (2, 10, 0x80000000):                                # 0x80000000: read as unsigned, not as a negative int32
        o.auth.counter = c
        rid = defer(client, hdr, "g%d" % c)
        assert o.approve(rid, True).status_code == 200
        assert stored(client) == c
    o.auth.counter = 0x80000001
    assert o.login().status_code == 200 and stored(client) == 0x80000001
    client.app.state.ctx.db.x("UPDATE credentials SET sign_count=?", (0xFFFFFFFF,))
    o.auth.counter = 0xFFFFFFFF                                  # the top of the range: nothing is greater (no wrap-around)
    rid = defer(client, hdr, "top")
    assert o.approve(rid, True).json()["error"] == "SIGN_COUNT_REGRESSION"


# ---- replay of an old signature --------------------------------------------------------------------------------------------------------

def test_old_signature_replayed_after_a_newer_one_is_refused(client):
    """A signature made at counter 7 and held back (stolen from the page, or produced by a clone) is refused once the key has signed at
    8: 0.2.19 accepted it (the envelope's challenge is the payload's hash, so it stays valid for as long as the action waits)."""
    o = counted_owner(client, start=1)
    ag, hdr, _ = setup_agent(o)
    a, b = defer(client, hdr, "A"), defer(client, hdr, "B")
    o.auth.counter = 7
    old = approval_env(o, a)                                     # not sent now
    o.auth.counter = 8
    assert o.post("/api/approvals/" + b, **viewkit.claim(viewkit.answer(o.c, b)), approved=True, envelope_b64=approval_env(o, b)).status_code == 200
    r = o.post("/api/approvals/" + a, **viewkit.claim(viewkit.answer(o.c, a)), approved=True, envelope_b64=old)
    assert r.status_code == 409 and r.json()["error"] == "SIGN_COUNT_REGRESSION" and status(client, a) == "pending_approval"
    # the same envelope sent twice: the second is refused (by state here; by the counter wherever the state would let it through)
    o.auth.counter = 9
    env = approval_env(o, a)
    assert o.post("/api/approvals/" + a, **viewkit.claim(viewkit.answer(o.c, a)), approved=True, envelope_b64=env).status_code == 200
    assert o.post("/api/approvals/" + a, **viewkit.claim(viewkit.answer(o.c, a)), approved=True, envelope_b64=env).status_code == 409


def test_signin_at_5_then_signature_at_3(client):
    o = counted_owner(client, start=0)
    ag, hdr, _ = setup_agent(o)                                  # counter 0 so far: 0/0
    o.auth.counter = 5
    assert o.login().status_code == 200 and stored(client) == 5  # sign-in moves the stored counter
    rid = defer(client, hdr, "x")
    o.auth.counter = 3
    assert o.approve(rid, True).json()["error"] == "SIGN_COUNT_REGRESSION"
    o.auth.counter = 9                                            # and the other way round: an approval at 9, then a sign-in at 4
    assert o.approve(rid, True).status_code == 200 and stored(client) == 9
    o.auth.counter = 4
    r = o.login()
    assert r.status_code == 401 and r.json()["error"] == "SIGN_COUNT_REGRESSION" and stored(client) == 9


def test_counter_from_registration(client):
    """A passkey registered with counter 7 (first passkey, and one added through keys.py): its signatures must be above 7."""
    o = counted_owner(client, start=3, reg=7)
    assert stored(client) == 7
    ag, hdr = o.new_agent()
    m, r = o.mandate(ag["id"])
    assert r.status_code == 409 and r.json()["error"] == "SIGN_COUNT_REGRESSION"
    o.auth.counter = 8
    m, r = o.mandate(ag["id"])
    assert r.status_code == 200, r.text
    # a second passkey added with registration counter 50, confirmed by the first one (counter 9)
    new = counting(wa.SoftAuthenticator(), start=20, reg=50)
    j = o.post("/api/auth/keys/add/begin", label="laptop").json()
    f = o.post("/api/auth/keys/add/finish", flow_id=j["flow_id"],
               credential=new.create_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)).json()
    o.auth.counter = 9
    env = o.auth.sign_object(f["typ"], wa.b64u_dec(f["payload_b64"]), RP, ORIGIN)
    c = o.post("/api/auth/keys/add/confirm", confirm_id=f["confirm_id"], envelope_b64=wa.b64u(env))
    assert c.status_code == 200, c.text
    assert stored(client, new.kid) == 50 and stored(client, o.auth.kid) == 9
    rid = defer(client, hdr, "k")
    g = o.c.get("/api/approvals/" + rid).json()
    pay = approval_payload(g["mandate"], g["action"], rid, True, viewkit.page_view(g))
    r = o.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(o.c, rid)), approved=True, envelope_b64=wa.b64u(new.sign_object(wa.TYP_APPROVAL, pay, RP, ORIGIN)))
    assert r.json()["error"] == "SIGN_COUNT_REGRESSION"
    new.counter = 51
    r = o.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(o.c, rid)), approved=True, envelope_b64=wa.b64u(new.sign_object(wa.TYP_APPROVAL, pay, RP, ORIGIN)))
    assert r.status_code == 200 and stored(client, new.kid) == 51 and stored(client, o.auth.kid) == 9


def test_forged_counter_never_moves_the_stored_one(client):
    """authData with a huge counter but a signature that does not cover it: refused by the signature check, and the stored counter
    stays (else anyone holding a session could push the counter to 0xFFFFFFFF and lock the passkey out)."""
    o = counted_owner(client, start=2)
    ag, hdr, _ = setup_agent(o)
    rid = defer(client, hdr, "f")
    o.auth.counter = 3
    env = cbor2.loads(wa.b64u_dec(approval_env(o, rid)))
    env["authData"] = env["authData"][:33] + (0xFFFFFFF0).to_bytes(4, "big")
    bad = wa.cde(env)
    r = o.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(o.c, rid)), approved=True, envelope_b64=wa.b64u(bad))
    assert r.status_code == 409 and r.json()["error"] == "WA_SIG"
    ctx = client.app.state.ctx
    org.check_sign_counts(ctx, bad, "test")                       # the helper alone: no exception, nothing stored
    assert stored(client) == 2


# ---- races: one counter, several requests -> exactly one passes ------------------------------------------------------------------------

def _race(fns):
    bar = threading.Barrier(len(fns))
    out = [None] * len(fns)

    def run(i):
        bar.wait()
        try:
            out[i] = fns[i]()
        except Exception as e:  # noqa: BLE001
            out[i] = e
    ts = [threading.Thread(target=run, args=(i,)) for i in range(len(fns))]
    [t.start() for t in ts]
    [t.join(60) for t in ts]
    assert not any(t.is_alive() for t in ts)
    return out


def test_race_same_counter_exactly_one(client):
    """16 different, valid envelopes of one passkey, all with counter 11, checked at once (no hub lock around them: the check alone)."""
    o = counted_owner(client, start=10)
    setup_agent(o)
    o.auth.counter = 11
    envs = [o.auth.sign_object(wa.TYP_APPROVAL, b"payload %d" % i, RP, ORIGIN) for i in range(16)]
    ctx = client.app.state.ctx
    out = _race([lambda e=e: org.check_sign_counts(ctx, e, "race") for e in envs])
    errs = [x for x in out if isinstance(x, Err)]
    assert out.count(None) == 1 and len(errs) == 15 and all(e.code == "SIGN_COUNT_REGRESSION" for e in errs), out
    assert stored(client) == 11


def test_race_signin_and_approval_with_one_counter(client, app):
    """A sign-in (no hub lock) and an approval (hub lock of the account) carrying the same counter at the same moment: one passes."""
    o = counted_owner(client, start=1)
    ag, hdr, _ = setup_agent(o)
    rid = defer(client, hdr, "r")
    o.auth.counter = 4
    env = approval_env(o, rid)
    other = TestClient(app, base_url=ORIGIN)                     # the clone signs in from another browser
    j = other.post("/api/auth/login/begin", json={}, headers={"Origin": ORIGIN}).json()
    cred = o.auth.login_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)
    out = _race([lambda: o.post("/api/approvals/" + rid, **viewkit.claim(viewkit.answer(o.c, rid)), approved=True, envelope_b64=env),
                 lambda: other.post("/api/auth/login/finish", json={"flow_id": j["flow_id"], "credential": cred}, headers={"Origin": ORIGIN})])
    codes = sorted(r.status_code for r in out)
    assert codes in ([200, 401], [200, 409]), [(r.status_code, r.text) for r in out]
    bad = [r for r in out if r.status_code != 200][0]
    assert bad.json()["error"] == "SIGN_COUNT_REGRESSION" and stored(client) == 4


def test_parallel_approvals_with_one_counter(client):
    o = counted_owner(client, start=1)
    ag, hdr, _ = setup_agent(o)
    rids = [defer(client, hdr, "p%d" % i) for i in range(4)]
    o.auth.counter = 5
    envs = [approval_env(o, r) for r in rids]
    out = _race([lambda r=r, e=e: o.post("/api/approvals/" + r, **viewkit.claim(viewkit.answer(o.c, r)), approved=True, envelope_b64=e) for r, e in zip(rids, envs)])
    assert sorted(r.status_code for r in out) == [200, 409, 409, 409]
    assert {r.json()["error"] for r in out if r.status_code == 409} == {"SIGN_COUNT_REGRESSION"}
    assert [status(client, r) for r in rids].count("approved") == 1


# ---- one signature, several effects: counted once ---------------------------------------------------------------------------------------

def test_batch_wb_counts_once(client):
    o = counted_owner(client, start=1)
    ag, hdr, _ = setup_agent(o)
    rids = [defer(client, hdr, "b%d" % i) for i in range(3)]
    g = [x for x in client.get("/api/approvals/groups").json()["groups"] if set(x["rids"]) == set(rids)][0]
    items = [wa.b64u_dec(x) for x in g["items_approve_b64"]]

    def wb(c):
        o.auth.counter = c
        ad, cd, der = o.auth.get_assertion(wq.wb_challenge(items), RP, ORIGIN)
        return wa.b64u(wq.make_wb(items, o.auth.kid, ad, cd, der))
    old = wb(1)                                                  # equal to the stored counter
    r = o.post("/api/approvals/batch", rids=g["rids"], views=g.get("views"), approved=True, envelope_b64=old)
    assert r.status_code == 409 and r.json()["error"] == "SIGN_COUNT_REGRESSION"
    assert all(status(client, x) == "pending_approval" for x in rids)
    r = o.post("/api/approvals/batch", rids=g["rids"], views=g.get("views"), approved=True, envelope_b64=wb(4))
    assert r.status_code == 200 and [x["verdict"] for x in r.json()["results"]] == ["allow"] * 3, r.text      # one counter, three items
    assert stored(client) == 4


def test_quorum_signatures_counted_once_each(app):
    """Team: each member's wa-sig is counted when it is handed in (sig request); the wq the server assembles at quorum is not counted again."""
    from tests.org_helpers import ctx_of, team
    from tests.test_quorum import deferred_purchase, msg_mandate
    owner, bob, carol = team(app)
    ag, hdr, m = msg_mandate(owner)
    counting(owner.auth, 3)
    counting(bob.auth, 6)
    d = deferred_purchase(owner, hdr, 80000)

    def env_of(p):
        g = p.c.get("/api/approvals/" + d["rid"]).json()
        return p.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], d["rid"], True, viewkit.page_view(g)))
    r = owner.post("/api/approvals/" + d["rid"], **viewkit.claim(viewkit.answer(owner.c, d["rid"])), approved=True, envelope_b64=env_of(owner))
    assert r.json()["verdict"] == "collecting", r.text
    bob.auth.counter = 0                                          # bob's key was at 0 (team set-up): 0 after 0 would pass ...
    db = ctx_of(app).db
    db.x("UPDATE credentials SET sign_count=7 WHERE kid=?", (bob.auth.kid,))    # ... so put it at 7 (as a sign-in would)
    bob.auth.counter = 6
    r = bob.post("/api/approvals/" + d["rid"], **viewkit.claim(viewkit.answer(bob.c, d["rid"])), approved=True, envelope_b64=env_of(bob))
    assert r.status_code == 409 and r.json()["error"] == "SIGN_COUNT_REGRESSION", r.text
    bob.auth.counter = 8
    r = bob.post("/api/approvals/" + d["rid"], **viewkit.claim(viewkit.answer(bob.c, d["rid"])), approved=True, envelope_b64=env_of(bob))
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    sc = {bytes(x["kid"]): x["sign_count"] for x in db.q("SELECT kid, sign_count FROM credentials")}
    assert sc[owner.auth.kid] == 3 and sc[bob.auth.kid] == 8


def test_every_envelope_path_checks(client):
    """Mandate revocation (wa-sig of a solo account): a counter behind is refused, ahead passes."""
    o = counted_owner(client, start=4)
    ag, hdr, _ = setup_agent(o)
    row = client.app.state.ctx.db.one("SELECT id, mandate_json FROM mandates WHERE agent_id=? AND status='active'", (ag["id"],))
    from svidetel_v4.state import revocation_payload
    from app import wire
    pay = revocation_payload(wire.cbor_form(json.loads(row["mandate_json"])))
    o.auth.counter = 2
    r = o.post("/api/mandates/%s/revoke" % row["id"], envelope_b64=o.sign(wa.TYP_REVOCATION, pay))
    assert r.status_code == 409 and r.json()["error"] == "SIGN_COUNT_REGRESSION", r.text
    o.auth.counter = 5
    r = o.post("/api/mandates/%s/revoke" % row["id"], envelope_b64=o.sign(wa.TYP_REVOCATION, pay))
    assert r.status_code == 200, r.text
    assert stored(client) == 5


def test_every_call_site_present():
    """Structure guard: each place that accepts a passkey envelope calls the counter check (or is the counted half of a pair)."""
    import os
    app_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app")
    src = {f: open(os.path.join(app_dir, f), encoding="utf-8").read() for f in ("actions.py", "org.py", "keys.py", "allowances.py", "flow/batch.py", "auth.py")}
    assert src["actions.py"].count("org.check_sign_counts(") == 4            # approve/refuse, mandate, revoke, release
    assert src["org.py"].count("check_sign_counts(ctx, env, \"sigreq") == 2          # sig request: genesis policy and every member's wa-sig
    assert src["keys.py"].count("org.check_sign_counts(") == 2               # key events (add / remove), wb revocation of mandates
    assert src["allowances.py"].count("org.check_sign_counts(") == 1
    assert src["flow/batch.py"].count("org.check_sign_counts(") == 1 and "counted=True" in src["flow/batch.py"]
    assert "sign_count_refused" in src["auth.py"] and "credential_current_sign_count=0" in src["auth.py"]
