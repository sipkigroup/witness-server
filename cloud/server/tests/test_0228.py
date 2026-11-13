"""0.2.28: the funnel counters (app/stats.py), the owner-only /internal/stats, the Team access form, and the unattended seam the site now
describes ("approve later, then the same call passes once while the request is open")."""
import os
import time

import pytest
from fastapi.testclient import TestClient

from app import _paths, account_delete, stats  # noqa: F401
from app import actions as A
from app.config import Config
from app.main import create_app
from tests.helpers import FORM, ORIGIN, RP, H, Owner, act
from tests.test_0225 import TG_TOKEN

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB = os.path.join(CLOUD, "web")
TOKEN = "s" * 40
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15"


@pytest.fixture()
def webapp(tmp_path):
    kf = tmp_path / "witness_key"
    kf.write_text("a1" * 32)
    cfg = Config(data_dir=str(tmp_path / "data"), witness_key_file=str(kf), key_pepper="test-pepper", rp_id=RP, origin=ORIGIN,
                 iss="https://witness.test", anchor="off", web_dir=WEB)
    return create_app(cfg)


def counts(app, step):
    r = app.state.ctx.db.one("SELECT COALESCE(SUM(n_all),0) AS a, COALESCE(SUM(n_own),0) AS o FROM funnel_daily WHERE step=?", (step,))
    return r["a"], r["o"]


def with_token(app, tmp_path):
    f = tmp_path / "stats.token"
    f.write_text(TOKEN + "\n")
    app.state.ctx.stats_token = stats.token_sha256({"DW_STATS_TOKEN_FILE": str(f)})
    return {"Authorization": "Bearer " + TOKEN}


# ------------------------------------------------------------------ 1. steps, each once per account
def test_0228_funnel_steps_once_per_account(client, owner):
    app = client.app
    assert counts(app, "registration") == (1, 0)                       # "Alice" is not ours
    ag, hdr = owner.new_agent("demo", "a1")
    _, r = owner.mandate(ag["id"])
    assert r.status_code == 200
    assert counts(app, "agent") == (1, 0) and counts(app, "mandate") == (1, 0) and counts(app, "first_call") == (0, 0)
    assert act(client, hdr, "send_email", {"to": "x@evil.example", "subject": "s", "body": "b"}).json()["verdict"] == "deny"
    assert counts(app, "first_call") == (1, 0)                         # a denied call counts: it went through the witness
    r = act(client, hdr, "publish", {"channel": "blog", "text": "hi"}).json()
    assert r["verdict"] == "defer" and counts(app, "first_approval") == (0, 0)
    assert owner.approve(r["rid"]).json()["verdict"] == "allow"
    assert counts(app, "first_approval") == (1, 0)
    # more of the same never counts again
    ag2, hdr2 = owner.new_agent("demo", "a2")
    owner.mandate(ag2["id"])
    act(client, hdr2, "send_email", {"to": "bob@partner.example", "subject": "s", "body": "b"})
    r = act(client, hdr2, "publish", {"channel": "blog", "text": "again"}).json()
    owner.approve(r["rid"])
    S0228 = ("registration", "agent", "mandate", "first_call", "first_approval")      # 0.2.38 added trial / hook_touch steps (test_0238_trial.py)
    for s in S0228:
        assert counts(app, s) == (1, 0), s
    assert app.state.ctx.db.one("SELECT COUNT(*) AS n FROM funnel_seen")["n"] == 5
    stats._seen.clear()                                                  # a restart forgets the memory: the table still says "seen"
    for s in S0228:
        assert stats.first(app.state.ctx, owner.account["id"], s) is False
        assert counts(app, s) == (1, 0), s


def test_0228_refusal_is_not_an_approval(client, owner):
    ag, hdr = owner.new_agent("demo", "a1")
    owner.mandate(ag["id"])
    r = act(client, hdr, "publish", {"channel": "blog", "text": "hi"}).json()
    assert owner.approve(r["rid"], approved=False).status_code == 200
    assert counts(client.app, "first_approval") == (0, 0)


def test_0228_own_accounts_are_marked(app, monkeypatch):
    Owner(TestClient(app, base_url=ORIGIN)).register("test-runner")
    assert counts(app, "registration") == (1, 1)
    monkeypatch.setenv("DW_STATS_OWN_NAMES", "Carol Owner")
    Owner(TestClient(app, base_url=ORIGIN)).register("Carol Owner")
    Owner(TestClient(app, base_url=ORIGIN)).register("Dave")
    assert counts(app, "registration") == (3, 2)


def test_0228_counting_never_breaks_a_request(client, owner, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("disk full")
    monkeypatch.setattr(stats, "_add", boom)
    ag, hdr = owner.new_agent("demo", "a1")                              # counting fails inside: the agent is still created
    owner.mandate(ag["id"])
    assert act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s", "body": "b"}).json()["verdict"] == "allow"


def test_0228_account_delete_erases_funnel_seen(app):
    from tests.org_helpers import Person, ctx_of
    p = Person(app).register("Alice")
    db = ctx_of(app).db
    assert db.one("SELECT COUNT(*) AS n FROM funnel_seen WHERE account_id=?", (p.uid,))["n"] == 1
    p.stepup()
    assert p.post("/api/account/delete", confirm_name="Alice").status_code == 200
    assert db.one("SELECT COUNT(*) AS n FROM funnel_seen WHERE account_id=?", (p.uid,))["n"] == 0
    assert counts(app, "registration") == (1, 0)                       # the day number stays: it holds no account
    assert "funnel_seen" in account_delete.TABLES_BY_ACCOUNT


# ------------------------------------------------------------------ 2. demo visits: no cookie, no IP, robots left out
def test_0228_demo_visit_counter(webapp):
    c = TestClient(webapp, base_url=ORIGIN)
    for path in ("/demo/", "/demo/index.html", "/demo"):
        r = c.get(path, headers={"User-Agent": UA})
        assert r.status_code == 200 and "set-cookie" not in r.headers, path
    assert counts(webapp, "demo_visit") == (3, 0)
    c.get("/demo/", headers={"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"})
    c.get("/demo/", headers={"User-Agent": "curl/8.4.0"})
    c.get("/demo/", headers={"User-Agent": ""})
    c.head("/demo/", headers={"User-Agent": UA})
    c.get("/demo/demo.json", headers={"User-Agent": UA})                # the page's own files are not visits
    c.get("/index.html", headers={"User-Agent": UA})
    assert counts(webapp, "demo_visit") == (3, 0)
    cols = [r["name"] for r in webapp.state.ctx.db.q("PRAGMA table_info(funnel_daily)")]
    assert cols == ["day", "step", "n_all", "n_own"]                   # nothing about a visitor can be stored
    assert [r["name"] for r in webapp.state.ctx.db.q("PRAGMA table_info(funnel_seen)")] == ["account_id", "step", "t"]    # 0.2.38: t = when the step was passed (the "again on a later day" count)


# ------------------------------------------------------------------ 3. /internal/stats: owner token only
def test_0228_stats_endpoint_needs_the_token(client, owner, tmp_path):
    assert client.get("/internal/stats").status_code == 404             # no token file: the endpoint does not exist
    hdr = with_token(client.app, tmp_path)
    assert client.get("/internal/stats").status_code == 401
    assert client.get("/internal/stats", headers={"Authorization": "Bearer " + "x" * 40}).status_code == 401
    r = client.get("/internal/stats?days=7", headers=hdr)               # the owner's session cookie alone is not enough: the token is
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["total"]["registration"] == {"all": 1, "own": 0, "outside": 1} and j["steps"] == list(stats.STEPS)
    assert j["days"][0]["day"] == stats.day() and j["team_requests"] == []
    assert "Alice" not in r.text and owner.account["id"] not in r.text   # aggregates only
    assert client.get("/internal/stats?days=x", headers=hdr).status_code == 400


def test_0228_stats_token_rules_and_brute_force(client, tmp_path):
    short = tmp_path / "short"
    short.write_text("abc")
    assert stats.token_sha256({"DW_STATS_TOKEN_FILE": str(short)}) == b""
    assert stats.token_sha256({"DW_STATS_TOKEN_FILE": str(tmp_path / "missing")}) == b""
    assert stats.token_sha256({}) == b""
    hdr = with_token(client.app, tmp_path)
    for _ in range(10):
        assert client.get("/internal/stats", headers={"Authorization": "Bearer wrong-wrong-wrong"}).status_code == 401
    # 0.2.30 (review, small 1): strangers' wrong tries never lock the owner out (behind the proxy they all share one address)
    assert client.get("/internal/stats", headers=hdr).status_code == 200


def test_0228_stats_token_from_env_at_startup(tmp_path, monkeypatch):
    f = tmp_path / "tok"
    f.write_text(TOKEN)
    monkeypatch.setenv("DW_STATS_TOKEN_FILE", str(f))
    kf = tmp_path / "witness_key"
    kf.write_text("a1" * 32)
    app = create_app(Config(data_dir=str(tmp_path / "d"), witness_key_file=str(kf), key_pepper="p", rp_id=RP, origin=ORIGIN, anchor="off",
                            web_dir=str(tmp_path / "web")))
    c = TestClient(app, base_url=ORIGIN)
    assert c.get("/internal/stats", headers={"Authorization": "Bearer " + TOKEN}).status_code == 200


# ------------------------------------------------------------------ 4. the Team access form
def test_0228_team_request_form(client, owner, tmp_path, monkeypatch):
    sent = []
    nt = client.app.state.ctx.notify
    nt.sender = lambda kind, s, text: (sent.append((kind, text)), (True, "ok"))[1]
    assert owner.post("/api/notify/channels", kind="telegram", token=TG_TOKEN, chat_id="987654321").status_code == 200
    monkeypatch.setenv("DW_OWNER_ACCOUNT", owner.account["id"])
    sent.clear()
    anon = TestClient(client.app, base_url=ORIGIN)
    assert anon.post("/api/team-request", json={"email": "cto@corp.example", "text": "40 engineers"}).status_code == 403   # no Origin
    for bad, code in (({"email": "nope", "text": "x"}, "TEAM_EMAIL"), ({"email": "a@b.example", "text": ""}, "TEAM_TEXT"),
                      ({"email": "a@b.example", "text": "x" * 2001}, "TEAM_TEXT"), ({"email": ["a@b.example"], "text": "x"}, "TEAM_EMAIL")):
        r = anon.post("/api/team-request", json=bad, headers=H)
        assert r.status_code == 422 and r.json()["error"] == code, bad
    r = anon.post("/api/team-request", json={"email": " cto@corp.example ", "text": "We run 40 agents in CI. "}, headers=H)
    assert r.status_code == 200 and r.json()["ok"] and r.json()["id"] >= 1
    db = client.app.state.ctx.db
    rows = db.q("SELECT * FROM team_requests")
    assert [(x["email"], x["text"]) for x in rows] == [("cto@corp.example", "We run 40 agents in CI.")]
    assert [c["name"] for c in db.q("PRAGMA table_info(team_requests)")] == ["id", "t", "email", "text", "confirmed_at", "flood"]  # no IP, no agent
    assert client.app.state.ctx.notify.drain()
    assert [k for k, _ in sent] == ["telegram"] and "1 new Team access request" in sent[0][1]          # 0.2.30: a summary
    assert "cto@corp.example" not in sent[0][1] and "40 agents" not in sent[0][1]                       # the channel gets no content
    # a robot filling the hidden field: answered "ok", stored nothing
    assert anon.post("/api/team-request", json={"email": "x@y.example", "text": "buy", "website": "http://spam.example"}, headers=H).json() == {"ok": True, "id": 0}
    assert len(db.q("SELECT * FROM team_requests")) == 1
    # the owner reads it with the token
    hdr = with_token(client.app, tmp_path)
    j = client.get("/internal/stats", headers=hdr).json()
    assert [x["email"] for x in j["team_requests"]] == ["cto@corp.example"]


def test_0228_team_request_limits_and_retention(client):
    anon = TestClient(client.app, base_url=ORIGIN)
    ok = [anon.post("/api/team-request", json={"email": "a%d@b.example" % i, "text": "t"}, headers=H).status_code for i in range(6)]
    assert ok == [200] * 5 + [429]                                      # 5 per hour from one address (in memory only)
    db = client.app.state.ctx.db
    db.x("UPDATE team_requests SET t=t-181*86400 WHERE id=1")
    stats.prune_team(client.app.state.ctx)
    assert [r["id"] for r in db.q("SELECT id FROM team_requests")] == [2, 3, 4, 5]
    for i in range(stats.TEAM_MAX_PER_DAY):                              # all senders together: a day cap
        db.x("INSERT INTO team_requests(t,email,text) VALUES(?,?,?)", (int(time.time()), "z@b.example", "t"))
    client.app.state.ctx.limiter.w.clear()
    r = anon.post("/api/team-request", json={"email": "late@b.example", "text": "t"}, headers=H)
    # 0.2.30 (review V1): beyond the soft cap a real buyer is NOT turned away: stored, marked flood, not notified
    assert r.status_code == 200, r.text
    assert db.one("SELECT flood FROM team_requests WHERE email='late@b.example'")["flood"] == 1
    for i in range(stats.TEAM_HARD_PER_DAY):                             # only the storage bound refuses
        db.x("INSERT INTO team_requests(t,email,text,flood) VALUES(?,?,?,1)", (int(time.time()), "z@b.example", "t"))
    client.app.state.ctx.limiter.w.clear()
    assert anon.post("/api/team-request", json={"email": "late2@b.example", "text": "t"}, headers=H).status_code == 429


# ------------------------------------------------------------------ 5. the unattended seam, as the site states it
def test_0228_approve_after_the_run_then_the_same_call_passes_once(client, owner):
    """Site text: no answer within the wait -> the call is refused; approve later, re-run the job before the request expires
    (15 min after it was asked) -> that same call passes once; afterwards, or after expiry, it needs a new approval."""
    ag, hdr = owner.new_agent("demo", "night")
    owner.mandate(ag["id"])
    args = {"channel": "blog", "text": "nightly report"}
    r = act(client, hdr, "publish", args).json()
    assert (r["verdict"], r["status"]) == ("defer", "pending_approval")
    rid = r["rid"]
    assert r["expires"] - int(time.time()) <= A.TTL                    # 15 min from the request
    # (the run ends here: the hook refused the call after its wait) ... the owner approves later
    assert owner.approve(rid).json()["verdict"] == "allow"
    again = act(client, hdr, "publish", args).json()                     # the next run repeats the SAME call
    assert again["rid"] == rid and (again["verdict"], again["reason"]) == ("allow", "OK_APPROVED")
    assert client.post("/v1/actions/%s/present" % rid, json={}, headers=hdr).json()["result"] == "accept"
    third = act(client, hdr, "publish", args).json()                     # once only: a further repeat is a new question
    assert third["rid"] != rid and third["verdict"] == "defer"
    # a different text is never covered by that approval
    assert act(client, hdr, "publish", {"channel": "blog", "text": "other"}).json()["verdict"] == "defer"


def test_0228_approval_after_expiry_is_not_possible_and_repeat_asks_again(client, owner):
    ag, hdr = owner.new_agent("demo", "night")
    owner.mandate(ag["id"])
    args = {"channel": "blog", "text": "late"}
    rid = act(client, hdr, "publish", args).json()["rid"]
    db = client.app.state.ctx.db
    db.x("UPDATE actions SET expires=? WHERE rid=?", (int(time.time()) - 1, rid))
    assert client.get("/api/approvals/" + rid).json()["status"] == "expired"      # nothing left to approve
    again = act(client, hdr, "publish", args).json()
    assert again["rid"] != rid and again["verdict"] == "defer"


# ------------------------------------------------------------------ 6. deploy/voronka.py reads the counters (both ways)
def _voronka():
    import importlib.util
    spec = importlib.util.spec_from_file_location("voronka", os.path.join(CLOUD, "deploy", "voronka.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)                                           # no side effects: main() runs only as a script
    return m


def _walk_funnel(client, owner):
    ag, hdr = owner.new_agent("demo", "a1")
    owner.mandate(ag["id"])
    r = act(client, hdr, "publish", {"channel": "blog", "text": "hi"}).json()
    owner.approve(r["rid"])
    Owner(TestClient(client.app, base_url=ORIGIN)).register("test-ours")


def test_0228_voronka_over_http(client, owner, tmp_path, monkeypatch, capsys):
    import io
    import json as _json
    V = _voronka()
    _walk_funnel(client, owner)
    hdr = with_token(client.app, tmp_path)
    tf = tmp_path / "tok"
    tf.write_text(TOKEN)
    os.chmod(tf, 0o600)
    seen = {}

    def urlopen(req, timeout=None):                                      # urllib -> the test server
        seen["auth"] = req.get_header("Authorization")
        path = req.full_url.split("://", 1)[1].split("/", 1)[1]
        r = client.get("/" + path, headers={"Authorization": req.get_header("Authorization")})
        assert r.status_code == 200, r.text
        return io.BytesIO(r.content)
    monkeypatch.setattr(V.urllib.request, "urlopen", urlopen)
    monkeypatch.setenv("DW_STATS_TOKEN_FILE", str(tf))
    monkeypatch.setattr(V.sys, "argv", ["voronka.py", "--funnel-only", "--stats-url", "https://witness.test", "--days", "7"])
    V.main()
    o = capsys.readouterr().out
    assert seen["auth"] == hdr["Authorization"]
    assert "источник: http" in o and "регистрация 1" in o and "агент создан 1" in o and "первое одобрение 1" in o   # "test-ours" left out
    assert "заявки Team на сервере: 0" in o
    days, tot = V.funnel_table([{"day": "2026-10-23", "steps": {"demo_visit": {"all": 5, "own": 0}, "registration": {"all": 3, "own": 2, "outside": 1}}}])
    assert tot["demo_visit"] == 5 and tot["registration"] == 1 and days[-1].startswith("| 2026-10-23 | 5 | 1 |")
    short = tmp_path / "short"
    short.write_text("x" * 10)
    assert V.read_token(str(short)) is None and V.read_token(str(tmp_path / "none")) is None and V.read_token(str(tf)) == TOKEN
    _json.dumps(o)


def test_0228_voronka_remote_script_reads_the_tables(client, owner, tmp_path):
    import json as _json
    import subprocess
    import sys as _sys
    V = _voronka()
    _walk_funnel(client, owner)
    anon = TestClient(client.app, base_url=ORIGIN)
    assert anon.post("/api/team-request", json={"email": "a@b.example", "text": "t"}, headers=H).status_code == 200
    data = client.app.state.ctx.cfg.data_dir
    code = V.REMOTE % (V.EXCL, "")
    p = subprocess.run([_sys.executable, "-"], input=code, capture_output=True, text=True, env=dict(os.environ, DW_DATA_DIR=data), timeout=60)
    assert p.returncode == 0, p.stderr
    j = _json.loads(p.stdout.strip().splitlines()[-1])
    assert j["team_requests_n"] == 0 and j["team_requests_all"] == 1 and "a@b.example" not in p.stdout   # 0.2.30: not confirmed = not counted
    client.app.state.ctx.db.x("UPDATE team_requests SET confirmed_at=1")
    p = subprocess.run([_sys.executable, "-"], input=code, capture_output=True, text=True, env=dict(os.environ, DW_DATA_DIR=data), timeout=60)
    assert _json.loads(p.stdout.strip().splitlines()[-1])["team_requests_n"] == 1
    st = j["funnel"][0]["steps"]
    assert st["registration"] == {"all": 2, "own": 1, "outside": 1} and st["first_approval"]["outside"] == 1
