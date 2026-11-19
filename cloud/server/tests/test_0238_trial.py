"""0.2.38: trial accounts, "an account on the first touch" (app/trial.py). The real thin hook (deus_witness 0.2.28) against the real server.
Adversary of the security tests = the agent: it has the trial key and everything /v1 tells it; not the claim (it went to the browser only)."""
import json
import os
import sys
import threading
import time

import pytest
from fastapi.testclient import TestClient

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))

import wa_profile as wa  # noqa: E402
from svidetel_v4.state import approval_payload  # noqa: E402
from tests.helpers import H, ORIGIN, RP, Owner  # noqa: E402
from tests.test_0216_thin import Via  # noqa: E402

import deus_witness.client as dwc  # noqa: E402
from deus_witness.hook import main as thin  # noqa: E402
from deus_witness.hook.form import default_form  # noqa: E402
from app import stats, trial  # noqa: E402


def ctx_of(client):
    return client.app.state.ctx


def proj(tmp_path, name="p"):
    p = str((tmp_path / name).resolve())
    os.makedirs(p, exist_ok=True)
    return p


def new_trial(client, tmp_path, **extra):
    r = client.post("/v1/trial", json=dict({"form": default_form(proj(tmp_path)), "client": {"name": "deus-witness", "version": "test"}}, **extra))
    assert r.status_code == 200, r.text
    return r.json()


class Person:
    """The human at the browser: has the claim (from the URL fragment) and their own passkey."""

    def __init__(self, app, claim):
        self.c = TestClient(app, base_url=ORIGIN)
        self.claim = claim
        self.auth = wa.SoftAuthenticator()

    def post(self, path, **j):
        return self.c.post(path, json=j, headers=H)

    def claim_it(self, auth=None, claim=None):
        a = auth or self.auth
        b = self.post("/api/trial/claim/begin", claim=claim or self.claim)
        if b.status_code != 200:
            return b
        j = b.json()
        cred = a.create_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)
        return self.post("/api/trial/claim/finish", flow_id=j["flow_id"], credential=cred, claim=claim or self.claim)

    def sign(self, typ, payload):
        return wa.b64u(self.auth.sign_object(typ, payload, RP, ORIGIN))

    def sign_mandate(self):
        v = self.c.get("/api/trial").json()
        d = self.post("/api/mandates/draft", agent_id=v["agent_id"], form=v["form"])
        assert d.status_code == 200, d.text
        m = d.json()["mandate"]
        return self.post("/api/mandates", mandate=m, envelope_b64=self.sign(wa.TYP_MANDATE, wa.cde(m)), toolmap_sha256=d.json()["toolmap_sha256"])

    def approve(self, rid, approved=True):
        g = self.c.get("/api/approvals/" + rid).json()
        v = bytes.fromhex(g["view_sha256"]) if g.get("view_sha256") else None     # r0352: the page signs the view the witness offers
        b = {"view_sha256": g["view_sha256"]} if v else {}
        return self.post("/api/approvals/" + rid, approved=approved, envelope_b64=self.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], rid, approved, v)), **b)


def hook(client, key, p, tmp_path, wait=0, timeout=20, env=None):
    w = dwc.Witness(ORIGIN, key, pin_path=str(tmp_path / "pins" / "w.json"), transport=Via(client))
    s = thin.Settings({"DEUS_WITNESS_KEY": key, "CLAUDE_PROJECT_DIR": p, "HOME": os.environ.get("HOME", "/"), "DEUS_WITNESS_HOOK_WAIT": str(wait),
                       "DEUS_WITNESS_HOOK_TIMEOUT": str(timeout), "DEUS_WITNESS_OPEN_BROWSER": "0", **(env or {})})
    return lambda cmd: thin.judge({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": p}, s, witness=w)


def dec(out):
    h = (out or {}).get("hookSpecificOutput") or {}
    return h.get("permissionDecision"), h.get("permissionDecisionReason", "")


def rows(client, agent_id):
    return ctx_of(client).db.q("SELECT * FROM actions WHERE agent_id=? ORDER BY created_at, rowid", (agent_id,))


def counted(client, step):
    r = ctx_of(client).db.one("SELECT COALESCE(SUM(n_all),0) AS a, COALESCE(SUM(n_own),0) AS o FROM funnel_daily WHERE step=?", (step,))
    return r["a"], r["o"]


# ------------------------------------------------------------------ creation, limits
def test_0238_1_create_no_passkey_nothing_signed(client, tmp_path):
    t = new_trial(client, tmp_path)
    assert t["api_key"].startswith("dwk_") and t["claim"].startswith("dwc_") and t["claim_url"].endswith("/trial.html#c=" + t["claim"])
    db = ctx_of(client).db
    a = db.one("SELECT * FROM accounts WHERE id=(SELECT account_id FROM agents WHERE id=?)", (t["agent_id"],))
    assert a["trial_until"] - a["created_at"] == 7 * 86400 and a["trial_claimed_at"] is None and a["trial_claim"] != t["claim"].encode()
    assert db.one("SELECT COUNT(*) AS n FROM credentials")["n"] == 0 and db.one("SELECT COUNT(*) AS n FROM mandates")["n"] == 0
    assert db.one("SELECT COUNT(*) AS n FROM registry_log")["n"] == 0 and db.one("SELECT COUNT(*) AS n FROM users")["n"] == 0
    f = json.loads(a["trial_form"])
    assert f["purchase"] is None and f["valid_days"] <= 7 and f["command"]["unlisted"] in ("ask", "allow")
    assert json.loads(db.one("SELECT toolmap_json FROM agents WHERE id=?", (t["agent_id"],))["toolmap_json"]) == __import__("app.toolmap", fromlist=["x"]).preset("claude-code")
    assert counted(client, "trial") == (1, 0)
    assert not os.path.exists(os.path.join(ctx_of(client).cfg.data_dir, "ledgers", a["id"]))          # no journal before the first touch
    assert any("tool name" in x for x in t["sent"]) and t["privacy_url"].endswith("/privacy.html")


def test_0238_2_limits_origin_key_off(client, app, tmp_path):
    c = ctx_of(client)
    c.cfg.trial_per_hour = 3                                                                  # 0.2.48: the default is 10
    for _ in range(3):
        new_trial(client, tmp_path)
    r = client.post("/v1/trial", json={"form": default_form(proj(tmp_path))})
    assert r.status_code == 429 and r.json()["error"] == "RATE_LIMIT"                        # 3 per hour per sender network
    c.limiter.w.clear()
    c.cfg.trial_per_day = 1
    new_trial(client, tmp_path)
    c.limiter.w.pop("trial:testclient", None)
    r = client.post("/v1/trial", json={"form": default_form(proj(tmp_path))})
    assert r.status_code == 429                                                              # all senders together, per day
    c.limiter.w.clear()
    assert client.post("/v1/trial", json={"form": {}}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/v1/trial", json={"form": default_form(proj(tmp_path))}, headers={"Authorization": "Bearer dwk_x"}).status_code == 400
    assert client.post("/v1/trial", json={"form": "x"}).status_code == 422
    wide = dict(default_form(proj(tmp_path)), purchase={"enabled": True, "budget": 10 ** 9, "max_per_action": 10 ** 9}, valid_days=365)
    t = client.post("/v1/trial", json={"form": wide}).json()
    f = json.loads(c.db.one("SELECT trial_form FROM accounts WHERE id=(SELECT account_id FROM agents WHERE id=?)", (t["agent_id"],))["trial_form"])
    assert f["purchase"] is None and f["valid_days"] == 7                                    # a trial never drafts purchases or a longer mandate
    c.cfg.trial = "off"
    assert client.post("/v1/trial", json={"form": default_form(proj(tmp_path))}).status_code == 404
    assert client.get("/api/trial/state", headers={"X-DW-Claim": t["claim"]}).status_code == 404


# ------------------------------------------------------------------ before the first touch
def test_0238_3_before_touch_everything_waits_nothing_allowed(client, tmp_path):
    t = new_trial(client, tmp_path)
    p = proj(tmp_path)
    h = hook(client, t["api_key"], p, tmp_path)
    for cmd in ("git push origin main", "ls", "curl https://example.com"):
        d, why = dec(h(cmd))
        # client 0.2.34: an untouched trial is a deny TRIAL_NOT_CLAIMED (after TRIAL_WAIT_S when the hook waits); the held row stays ESCALATE_TRIAL_CLAIM
        assert d == "deny" and "TRIAL_NOT_CLAIMED" in why and "(nothing ran)" in why and "deus-witness try" in why and "receipt r_" in why, (cmd, why)
    rs = rows(client, t["agent_id"])
    assert {x["reason"] for x in rs} == {"ESCALATE_TRIAL_CLAIM"}
    hw = hook(client, t["api_key"], p, tmp_path, wait=30, env={"DEUS_WITNESS_TRIAL_WAIT": "1"})   # waiting hook: DEUS_WITNESS_TRIAL_WAIT (90 s by default) caps the wait for the first touch
    t0 = time.monotonic(); d, why = dec(hw("git push origin main"))
    assert d == "deny" and "TRIAL_NOT_CLAIMED" in why and time.monotonic() - t0 < 10, (d, why)
    assert {x["status"] for x in rs} == {"pending_approval"} and all(x["mandate_id"] is None and x["aar"] is None and x["via"] == "hook" for x in rs)
    n = len(rs)
    h("git push origin main")                                                               # the same call again: the same waiting row
    assert len(rows(client, t["agent_id"])) == n
    st = client.get("/api/trial/state", headers={"X-DW-Claim": t["claim"]}).json()
    assert st["claimed"] is False and len(st["waiting"]) == n and all(w["from_hook"] for w in st["waiting"])
    # the pending bound
    ctx_of(client).cfg.trial_quota = 5000
    for i in range(trial.PENDING_MAX):
        h("make target%d" % i)
    d, why = dec(h("make one-more"))
    assert d == "deny" and "APPROVAL_RATE" in why


def test_0238_4_quota_and_expired_key(client, tmp_path):
    t = new_trial(client, tmp_path)
    c = ctx_of(client)
    c.cfg.trial_quota = 10
    hdr = {"Authorization": "Bearer " + t["api_key"]}
    for i in range(10):
        client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "echo %d" % i}}, headers=hdr)
    r = client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "echo x"}}, headers=hdr)
    assert r.status_code == 429 and "quick start" in r.json()["detail"]
    c.db.x("UPDATE accounts SET trial_until=? WHERE trial_until IS NOT NULL", (int(time.time()) - 1,))
    trial._SEEN.clear()                  # r0288: a use of the last hour (not written yet) would keep it alive: here it was not used since
    r = client.post("/v1/hook/judge", json={"v": 1}, headers=hdr)
    assert r.status_code == 401 and r.json()["error"] == "TRIAL_EXPIRED"


# ------------------------------------------------------------------ the first touch, end to end
def test_0238_5_first_touch_then_mandate_then_approval(client, app, tmp_path):
    t = new_trial(client, tmp_path)
    p = proj(tmp_path)
    h = hook(client, t["api_key"], p, tmp_path)
    assert dec(h("git push origin main"))[0] == "deny"
    rid0 = rows(client, t["agent_id"])[0]["rid"]
    me = Person(app, t["claim"])
    r = me.claim_it()
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["agent_id"] == t["agent_id"] and j["form"]["purchase"] is None and j["keycard"]["kid_hex"]
    db = ctx_of(client).db
    assert db.one("SELECT trial_claim FROM accounts WHERE id=?", (j["account"]["id"],))["trial_claim"] is None       # the claim is dead
    assert me.claim_it(auth=wa.SoftAuthenticator()).status_code == 404                     # a second claim (or a replay) finds nothing
    assert client.get("/api/trial/state", headers={"X-DW-Claim": t["claim"]}).status_code == 404
    # the waiting row is still not approvable as it is, even by the owner
    assert me.post("/api/approvals/" + rid0, approved=True, envelope_b64=me.sign(wa.TYP_APPROVAL, b"x")).status_code in (404, 409)
    assert db.one("SELECT status FROM actions WHERE rid=?", (rid0,))["status"] == "pending_approval"
    r = me.sign_mandate()
    assert r.status_code == 200, r.text
    assert db.one("SELECT status, covered_by FROM actions WHERE rid=?", (rid0,))["status"] == "covered"
    assert counted(client, "hook_touch") == (1, 0)                                          # the first touch, made for a real hook call
    # the hook asks again: now an ordinary question under the signed mandate (approve.html, a ledger entry)
    d, why = dec(h("git push origin main"))
    assert d == "deny" and "/approve.html?rid=" in why and "ESCALATE_TRIAL_CLAIM" not in why
    x = [y for y in rows(client, t["agent_id"]) if y["status"] == "pending_approval"][-1]
    assert x["mandate_id"] is not None and x["via"] == "hook"
    assert me.approve(x["rid"]).json()["verdict"] == "allow"
    assert counted(client, "hook_touch_day2") == (0, 0)                                     # same day: not "returned"
    assert trial.count_touch(ctx_of(client), j["account"]["id"], int(time.time()) + 86400) == "hook_touch_day2"
    assert counted(client, "hook_touch_day2") == (1, 0)
    # listed commands run under the signed mandate (the hook verified the receipt)
    assert dec(h("ls"))[0] in ("allow", None)
    # the account view and keep
    v = me.c.get("/api/trial").json()
    assert v["mandate_id"] and v["expires_at"] > time.time()
    assert me.c.get("/api/me").json()["trial"]["expires_at"] == v["expires_at"]


def test_0238_6_waiting_hook_is_released_by_the_touch(client, app, tmp_path):
    """The plugin's hook WAITS (600 s): the person claims and signs on the page, the hook judges the same call again by itself and waits for
    the approval of the new question; one approval later the call runs. No retry by the agent is needed."""
    t = new_trial(client, tmp_path)
    p = proj(tmp_path)
    h = hook(client, t["api_key"], p, tmp_path, wait=25, timeout=30)
    me = Person(app, t["claim"])
    out = {}

    def person():
        for _ in range(100):
            if rows(client, t["agent_id"]):
                break
            time.sleep(0.05)
        assert me.claim_it().status_code == 200
        assert me.sign_mandate().status_code == 200
        for _ in range(200):
            p_ = [y for y in rows(client, t["agent_id"]) if y["status"] == "pending_approval" and y["mandate_id"]]
            if p_:
                out["approve"] = me.approve(p_[-1]["rid"]).json()
                return
            time.sleep(0.05)
    th = threading.Thread(target=person)
    th.start()
    d, why = dec(h("git push origin main"))
    th.join(30)
    assert out.get("approve", {}).get("verdict") == "allow", out
    assert d == "allow", why
    st = [y["status"] for y in rows(client, t["agent_id"])]
    assert st[0] == "covered" and st[-1] == "consumed", st


# ------------------------------------------------------------------ TTL, keep, internal
def test_0238_7_ttl_erases_unclaimed_and_claimed(client, app, tmp_path):
    c = ctx_of(client)
    c.cfg.trial_per_hour = 10
    a = new_trial(client, tmp_path)
    hook(client, a["api_key"], proj(tmp_path), tmp_path)("git push")
    b = new_trial(client, tmp_path)
    hook(client, b["api_key"], proj(tmp_path, "q"), tmp_path)("git push")
    me = Person(app, b["claim"])
    assert me.claim_it().status_code == 200 and me.sign_mandate().status_code == 200
    n = new_trial(client, tmp_path)
    mn = Person(app, n["claim"])
    assert mn.claim_it().status_code == 200                                                  # claimed, never signed a mandate (no journal)
    k = new_trial(client, tmp_path)
    mk = Person(app, k["claim"])
    assert mk.claim_it().status_code == 200
    assert mk.post("/api/trial/keep").json()["kept"] is True                                 # kept: an ordinary Free account
    aid = lambda t_: c.db.one("SELECT account_id FROM agents WHERE id=?", (t_["agent_id"],))
    ida, idb = aid(a)["account_id"], aid(b)["account_id"]
    u = new_trial(client, tmp_path)                                                          # r0288: made, never used by a hook
    idu = aid(u)["account_id"]
    assert trial.expire_due(c) == 0
    later = int(time.time()) + 8 * 86400
    idn = aid(n)["account_id"]
    assert trial.expire_due(c, later) == 1                                                   # only the unclaimed AND unused one
    assert c.db.one("SELECT 1 AS k FROM accounts WHERE id=?", (idu,)) is None                # unclaimed, never called: nothing left at all
    assert c.db.one("SELECT erased_at FROM accounts WHERE id=?", (idn,))["erased_at"] is None and aid(n) is not None      # claimed, no journal: stays
    assert aid(a) is not None                                                                # r0288: unclaimed but its hook called: kept (90 days)
    assert trial.expire_due(c, int(time.time()) + 91 * 86400) == 1                           # 90 days after its last call: erased
    assert c.db.one("SELECT 1 AS k FROM accounts WHERE id=?", (ida,)) is None                # unclaimed: nothing left at all
    assert aid(a) is None and c.db.one("SELECT COUNT(*) AS n FROM actions WHERE account_id=?", (ida,))["n"] == 0
    assert c.db.one("SELECT idle_warned_at FROM accounts WHERE id=?", (idb,))["idle_warned_at"] is not None   # claimed: warned, not erased
    r = c.db.one("SELECT * FROM accounts WHERE id=?", (idb,))
    assert r["erased_at"] is None and r["trial_until"] is None and r["display_name"]        # claimed + mandate: kept automatically, Free
    assert os.path.exists(os.path.join(c.cfg.data_dir, "ledgers", idb, "ledger.cose"))
    assert client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "ls"}}, headers={"Authorization": "Bearer " + a["api_key"]}).status_code == 401
    assert client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "ls"}}, headers={"Authorization": "Bearer " + b["api_key"]}).status_code != 401
    assert mk.c.get("/api/me").status_code == 200 and aid(k) is not None                     # the kept one stays


def test_0411_single_user_works_on_day_8_and_later(client, app, tmp_path):
    """Open Core (04.11): a person with a passkey is free for good: day 8, day 40 -- the key works, the account is not erased, no expiry."""
    c = ctx_of(client)
    t = new_trial(client, tmp_path)
    me = Person(app, t["claim"])
    assert me.claim_it().status_code == 200 and me.sign_mandate().status_code == 200
    hdr = {"Authorization": "Bearer " + t["api_key"]}
    aid = c.db.one("SELECT account_id FROM agents WHERE id=?", (t["agent_id"],))["account_id"]
    for days in (8, 40):
        c.db.x("UPDATE accounts SET trial_until=? WHERE id=? AND trial_until IS NOT NULL", (int(time.time()) - 1, aid))   # past the 7 days, not swept yet
        assert client.post("/v1/hook/judge", json={"v": 1}, headers=hdr).status_code != 401
        trial.expire_due(c, int(time.time()) + days * 86400)
        assert c.db.one("SELECT erased_at, trial_until FROM accounts WHERE id=?", (aid,))["erased_at"] is None
        assert client.post("/v1/hook/judge", json={"v": 1}, headers=hdr).status_code != 401
    assert me.c.get("/api/me").status_code == 200


def test_0238_8_internal_and_demo_never_counted(client, app, tmp_path):
    t = new_trial(client, tmp_path, internal=True)
    h = hook(client, t["api_key"], proj(tmp_path), tmp_path)
    h("git push")
    me = Person(app, t["claim"])
    assert me.claim_it().status_code == 200 and me.sign_mandate().status_code == 200
    assert counted(client, "hook_touch") == (0, 0) and counted(client, "trial") == (1, 1)
    c = ctx_of(client)
    u = new_trial(client, tmp_path)
    uid = c.db.one("SELECT account_id FROM agents WHERE id=?", (u["agent_id"],))["account_id"]
    c.cfg.demo_account = uid
    assert trial.count_touch(c, uid) is None
    c.cfg.internal_nets = "10.0.0.0/8"
    assert trial.internal_ip(c, "10.1.2.3") and not trial.internal_ip(c, "8.8.8.8") and not trial.internal_ip(c, "testclient")


def test_0238_9_claim_needs_user_verification(client, app, tmp_path):
    t = new_trial(client, tmp_path)
    me = Person(app, t["claim"])
    b = me.post("/api/trial/claim/begin", claim=t["claim"]).json()
    a = wa.SoftAuthenticator()
    att = a.attestation_object(RP)
    import cbor2
    m = cbor2.loads(att)
    ad = bytearray(m["authData"])
    ad[32] &= ~wa.FLAG_UV                                                                  # presence only, no user verification
    att2 = wa.cde({"fmt": "none", "attStmt": {}, "authData": bytes(ad)})
    cred = a.create_credential(wa.b64u_dec(b["options"]["challenge"]), RP, ORIGIN)
    cred["response"]["attestationObject"] = wa.b64u(att2)
    r = me.post("/api/trial/claim/finish", flow_id=b["flow_id"], credential=cred, claim=t["claim"])
    assert r.status_code == 400 and r.json()["error"] == "WA_REGISTRATION"
    assert ctx_of(client).db.one("SELECT trial_claim FROM accounts WHERE id=(SELECT account_id FROM agents WHERE id=?)", (t["agent_id"],))["trial_claim"]
    # a flow of another trial cannot finish this one
    t2 = new_trial(client, tmp_path)
    b2 = me.post("/api/trial/claim/begin", claim=t2["claim"]).json()
    cred = a.create_credential(wa.b64u_dec(b2["options"]["challenge"]), RP, ORIGIN)
    assert me.post("/api/trial/claim/finish", flow_id=b2["flow_id"], credential=cred, claim=t["claim"]).status_code == 400


# ------------------------------------------------------------------ 0.2.44 (K2): reads do not spend the trial quota; defaults; texts
def test_0244_k2_defaults_and_reads_free(client, tmp_path):
    from app.config import Config
    assert Config.trial_quota == 2000 and Config.trial_per_day == 2000
    t = new_trial(client, tmp_path)
    c = ctx_of(client)
    c.cfg.trial_quota = 10
    hdr = {"Authorization": "Bearer " + t["api_key"]}
    for i in range(30):                                                                     # class pass: never spend the quota
        r = client.post("/v1/actions", json={"tool": "Read", "args": {"file_path": "/tmp/x%d" % i}}, headers=hdr)
        assert r.status_code == 200 and r.json()["status"] == "pass", r.text
    for i in range(10):
        client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "echo %d" % i}}, headers=hdr)
    r = client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "echo x"}}, headers=hdr)
    assert r.status_code == 429 and "/signup.html" in r.json()["detail"] and r.json()["detail"].startswith("The quick start limit of 10")
    assert client.post("/v1/actions", json={"tool": "Read", "args": {"file_path": "/tmp/y"}}, headers=hdr).status_code == 429          # exhausted by decisions: fail-closed as before, reads included


def test_0244_k2_daily_ceiling_text(client, tmp_path):
    c = ctx_of(client)
    c.cfg.trial_per_day = 1
    new_trial(client, tmp_path)
    c.limiter.w.pop("trial:testclient", None)
    r = client.post("/v1/trial", json={"form": default_form(proj(tmp_path))})
    assert r.status_code == 429 and "/signup.html" in r.json()["detail"] and "daily limit of trial accounts" in r.json()["detail"]


def test_0245_agent_and_account_quota_skip_reads_but_pass_ceiling(client, tmp_path):
    import app.actions as act
    t = new_trial(client, tmp_path)
    c = ctx_of(client)
    hdr = {"Authorization": "Bearer " + t["api_key"]}
    q0 = act.QUOTA_PER_AGENT_DAY
    act.QUOTA_PER_AGENT_DAY = 5
    c.cfg.trial_quota = 1000
    try:
        for i in range(12):                                                                 # reads beyond the per-agent limit still pass
            r = client.post("/v1/actions", json={"tool": "Read", "args": {"file_path": "/tmp/a%d" % i}}, headers=hdr)
            assert r.status_code == 200 and r.json()["status"] == "pass", r.text
        for i in range(5):
            client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "echo %d" % i}}, headers=hdr)
        r = client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "echo x"}}, headers=hdr)
        assert r.status_code == 429 and "for one agent" in r.json()["detail"]                # decisions are still limited
        assert client.post("/v1/actions", json={"tool": "Read", "args": {"file_path": "/tmp/z"}}, headers=hdr).status_code == 429   # fail-closed as before
        # reads' own ceiling
        act.QUOTA_PER_AGENT_DAY = q0
        c.cfg.pass_per_agent_day = 100
        n = act.passes_used(c, t["account_id"] if "account_id" in t else client_acc(c), time.time())
        c.cfg.pass_per_agent_day = max(1, n)
        r = client.post("/v1/actions", json={"tool": "Read", "args": {"file_path": "/tmp/w"}}, headers=hdr)
        assert r.status_code == 429 and "reads and file checks per day for one agent" in r.json()["detail"]     # r0285: + the hook's rounds
    finally:
        act.QUOTA_PER_AGENT_DAY = q0                    # r0285: was "= 2000": it leaked into the next tests once the default changed


def client_acc(c):
    return c.db.one("SELECT account_id FROM actions LIMIT 1")["account_id"]
