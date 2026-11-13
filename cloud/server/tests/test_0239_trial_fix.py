"""0.2.39: the trial fixes after the prod E2E of 24.10 (release/out/E2E-PLAGIN-PROD-2026-10-24.md).

Bug (reproduced locally): `deus-witness try` run again made a SECOND trial account and overwrote the key file; the browser still had the
first page (or its claim in storage); the person's touch there claimed the FIRST account, signed its rules ("Done", "Nothing is waiting")
while the hook, with the second key, waited for an account nobody would ever claim (4+ min). Fix: `try` again retires the previous
unclaimed trial (POST /v1/trial/retire), the hook stops waiting when its key file changed (TRIAL_REPLACED), the page picks the claim of the
account the call belongs to. Plus: the rate limit says when, test accounts marked internal after the fact (app/mark_internal.py)."""
import io
import os
import threading
import time

from tests.test_0238_trial import CLOUD, Person, counted, ctx_of, dec, new_trial, proj, rows  # noqa: F401
from tests.test_0216_thin import Via as _Via

import httpx
import deus_witness.client as dwc
from deus_witness import trial as dwtrial
from deus_witness.hook import main as thin
from app import mark_internal


class Via(httpx.BaseTransport):
    """tests.test_0216_thin.Via as a full httpx transport (the client's `with httpx.Client(transport=...)`), headers kept."""

    def __init__(self, tc):
        self.tc = tc

    def handle_request(self, request):
        h = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length", "transfer-encoding")}
        r = self.tc.request(request.method, str(request.url), headers=h, content=request.read())
        return httpx.Response(r.status_code, headers={k: v for k, v in r.headers.items() if k.lower() in ("content-type", "retry-after")},
                              content=r.content)


def run_try(client, home, p):
    """The real `deus-witness try` (client) against the in-process server; -> (exit code, printed text, claim link given to the browser)."""
    got, out = [], io.StringIO()
    env = {"DEUS_WITNESS_HOME": home, "HOME": home, "DEUS_WITNESS_URL": "https://witness.test"}
    rc = dwtrial.run(["--url", "https://witness.test", "--project", p], env=env, transport=Via(client),
                     opener=lambda url, new=2: got.append(url) or True, out=out)
    return rc, out.getvalue(), (got[0] if got else None)


def file_hook(client, home, p, tmp_path, wait=25, timeout=40):
    """The hook as the plugin runs it: no DEUS_WITNESS_KEY, the key from the file `try` saved."""
    env = {"DEUS_WITNESS_HOME": home, "CLAUDE_PROJECT_DIR": p, "HOME": home, "DEUS_WITNESS_HOOK_WAIT": str(wait),
           "DEUS_WITNESS_HOOK_TIMEOUT": str(timeout), "DEUS_WITNESS_OPEN_BROWSER": "0"}
    s = thin.Settings(env)
    assert s.key_from_file and s.key.startswith("dwk_")
    w = dwc.Witness("https://witness.test", s.key, pin_path=os.path.join(home, "pins.json"), transport=_Via(client))
    return lambda cmd: thin.judge({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": p}, s, witness=w)


def claim_of(link):
    return link.split("#c=", 1)[1]


def agent_of_key(client, home):
    return dwtrial.load_key({"DEUS_WITNESS_HOME": home})["agent_id"]


def test_0239_1_try_again_never_leaves_the_hook_waiting_for_nobody(client, app, tmp_path):
    """The E2E bug end to end: a call waits before the claim, `try` runs again, the old page is touched. The old hook stops at once
    (TRIAL_REPLACED, nothing ran), the old claim is dead, and the call of the NEW account is released by one touch + one approval."""
    c = ctx_of(client)
    c.cfg.trial_per_hour = 10
    home, p = str(tmp_path / "home"), proj(tmp_path)
    rc, txt, link_a = run_try(client, home, p)
    assert rc == 0 and link_a and "dwc_" not in txt
    ag_a = agent_of_key(client, home)
    old_hook = file_hook(client, home, p, tmp_path)
    res = {}
    th = threading.Thread(target=lambda: res.setdefault("d", dec(old_hook("git push origin main"))))
    th.start()
    for _ in range(200):
        if rows(client, ag_a):
            break
        time.sleep(0.05)
    assert rows(client, ag_a)[0]["reason"] == "ESCALATE_TRIAL_CLAIM"
    t0 = time.time()
    rc, txt, link_b = run_try(client, home, p)                                  # the person runs /deus-witness:try again
    assert rc == 0 and "replaced" in txt and link_b != link_a
    th.join(30)
    d, why = res["d"]
    assert d == "deny" and "TRIAL_REPLACED" in why and "Retry the SAME call" in why, why
    assert time.time() - t0 < 20                                                 # not the 600 s of the plugin
    assert counted(client, "trial") == (1, 0)                                    # the same person's second try is not a second trial
    old = Person(app, claim_of(link_a))                                          # the older page: its claim is dead, it claims nothing
    r = old.claim_it()
    assert r.status_code == 404 and r.json()["error"] == "TRIAL_UNKNOWN"
    assert c.db.one("SELECT COUNT(*) AS n FROM agents WHERE id=?", (ag_a,))["n"] == 0
    # the retried call goes to the new account: waits, one touch + signed rules, one approval -> runs
    ag_b = agent_of_key(client, home)
    h = file_hook(client, home, p, tmp_path)
    me = Person(app, claim_of(link_b))
    out = {}

    def person():
        for _ in range(200):
            if rows(client, ag_b):
                break
            time.sleep(0.05)
        st = me.c.get("/api/trial/state", headers={"X-DW-Claim": me.claim}).json()
        out["waiting"] = [w["rid"] for w in st["waiting"]]
        assert me.claim_it().status_code == 200 and me.sign_mandate().status_code == 200
        for _ in range(200):
            q = [y for y in rows(client, ag_b) if y["status"] == "pending_approval" and y["mandate_id"]]
            if q:
                out["approve"] = me.approve(q[-1]["rid"]).json()
                return
            time.sleep(0.05)
    t2 = threading.Thread(target=person)
    t2.start()
    d, why = dec(h("git push origin main"))
    t2.join(30)
    assert out["waiting"] and d == "allow", (why, out)


def test_0239_2_call_waiting_before_claim_is_decided_after_signing(client, app, tmp_path):
    """The call that waited BEFORE the claim is decided right after the rules are signed (not left hanging): a forbidden one (a secret
    written to .env, the E2E's first call) is denied at once; the page then has nothing waiting, and that is the truth."""
    home, p = str(tmp_path / "home"), proj(tmp_path)
    rc, _, link = run_try(client, home, p)
    ag = agent_of_key(client, home)
    h = file_hook(client, home, p, tmp_path)
    me = Person(app, claim_of(link))
    res = {}
    th = threading.Thread(target=lambda: res.setdefault("d", dec(h("echo API_KEY=fake-test-1234567890abcdef > .env"))))
    th.start()
    for _ in range(200):
        if rows(client, ag):
            break
        time.sleep(0.05)
    t0 = time.time()
    assert me.claim_it().status_code == 200 and me.sign_mandate().status_code == 200
    th.join(30)
    d, why = res["d"]
    assert d == "deny" and time.time() - t0 < 10, why
    assert me.c.get("/api/approvals").json() == []
    st = [y["status"] for y in rows(client, ag)]
    assert "covered" in st and "pending_approval" not in st, st


def test_0239_3_retire_only_an_unclaimed_trial_and_nothing_is_given_back(client, app, tmp_path):
    t = new_trial(client, tmp_path)
    H_ = {"Authorization": "Bearer " + t["api_key"]}
    me = Person(app, t["claim"])
    assert me.claim_it().status_code == 200
    r = client.post("/v1/trial/retire", json={}, headers=H_)
    assert r.status_code == 409 and r.json()["error"] == "TRIAL_CLAIMED"          # it has the person's passkey: never erased by a key
    assert me.c.get("/api/me").status_code == 200
    u = new_trial(client, tmp_path)
    r = client.post("/v1/trial/retire", json={}, headers={"Authorization": "Bearer " + u["api_key"]})
    assert r.status_code == 200 and r.json() == {"ok": True, "retired": True}       # no claim, no key in the answer
    assert client.post("/v1/trial/retire", json={}, headers={"Authorization": "Bearer " + u["api_key"]}).status_code == 401
    assert client.get("/api/trial/state", headers={"X-DW-Claim": u["claim"]}).status_code == 404
    assert client.post("/v1/trial/retire", json={}).status_code == 401


def test_0239_4_try_again_keeps_a_claimed_trial(client, app, tmp_path):
    home, p = str(tmp_path / "home"), proj(tmp_path)
    rc, _, link = run_try(client, home, p)
    key = dwtrial.load_key({"DEUS_WITNESS_HOME": home})["key"]
    assert Person(app, claim_of(link)).claim_it().status_code == 200
    rc, txt, link2 = run_try(client, home, p)
    assert rc == 2 and link2 is None and "already has your passkey" in txt and "--force" in txt
    assert dwtrial.load_key({"DEUS_WITNESS_HOME": home})["key"] == key              # nothing changed
    ctx_of(client).cfg.trial_per_hour = 10
    rc = dwtrial.run(["--url", "https://witness.test", "--project", p, "--force"], env={"DEUS_WITNESS_HOME": home, "HOME": home},
                     transport=Via(client), opener=lambda u, new=2: True, out=io.StringIO())
    assert rc == 0 and dwtrial.load_key({"DEUS_WITNESS_HOME": home})["key"] != key


def test_0239_5_rate_limit_says_when(client, tmp_path):
    ctx_of(client).cfg.trial_per_hour = 3                  # 0.2.48: the default is 10; the message is the same at any limit
    for _ in range(3):
        new_trial(client, tmp_path)
    r = client.post("/v1/trial", json={"form": {"x": 1}})
    j = r.json()
    assert r.status_code == 429 and j["error"] == "RATE_LIMIT"
    assert isinstance(j["retry_after"], int) and 3000 < j["retry_after"] <= 3600 and j["reset_at"] > time.time()
    assert r.headers["retry-after"] == str(j["retry_after"]) and " min (at " in j["detail"] and "UTC" in j["detail"]
    out = io.StringIO()
    rc = dwtrial.run(["--url", "https://witness.test", "--project", proj(tmp_path)], env={"DEUS_WITNESS_HOME": str(tmp_path / "h2")},
                     transport=Via(client), opener=lambda u, new=2: True, out=out)
    assert rc == 1 and "next trial account in" in out.getvalue() and "press its button again" in out.getvalue()


def test_0239_6_mark_internal_after_the_fact(client, app, tmp_path):
    """Our test accounts made before 0.2.38 knew them: marked internal, their counted steps move to `own`; idempotent; dry run writes
    nothing; unknown ids are skipped."""
    c = ctx_of(client)
    c.cfg.trial_per_hour = 10
    home, p = str(tmp_path / "home"), proj(tmp_path)
    run_try(client, home, p)
    ag = agent_of_key(client, home)
    other = new_trial(client, tmp_path)
    assert counted(client, "trial") == (2, 0)
    db = os.path.join(c.cfg.data_dir, "db.sqlite")
    out = io.StringIO()
    assert mark_internal.main(["--db", db, ag, "ag_000000000000", "nonsense"], out=out) == 0
    assert "dry run" in out.getvalue() and "MARK " + ag in out.getvalue() and out.getvalue().count("SKIP") == 2
    assert counted(client, "trial") == (2, 0)
    out = io.StringIO()
    assert mark_internal.main(["--db", db, "--apply", ag], out=out) == 0 and "applied" in out.getvalue()
    assert counted(client, "trial") == (2, 1)
    aid = c.db.one("SELECT account_id FROM agents WHERE id=?", (ag,))["account_id"]
    assert c.db.one("SELECT internal FROM accounts WHERE id=?", (aid,))["internal"] == 1
    assert mark_internal.main(["--db", db, "--apply", ag, aid], out=io.StringIO()) == 0
    assert counted(client, "trial") == (2, 1)                                     # a second run changes nothing
    oid = c.db.one("SELECT account_id FROM agents WHERE id=?", (other["agent_id"],))["account_id"]
    assert c.db.one("SELECT internal FROM accounts WHERE id=?", (oid,))["internal"] == 0


def test_0239_7_deploy_wrapper_pipes_the_script_and_changes_no_etalon(client):
    sh = open(os.path.join(CLOUD, "deploy", "mark-internal.sh"), encoding="utf-8").read()
    assert "docker exec -i -w /app/cloud/server witness python - \"$@\" < \"$src\"" in sh and "set -euo pipefail" in sh
    assert "--apply" in sh and "dry run" in sh
