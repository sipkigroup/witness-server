"""0.2.46: 429 refusals counted by reason per UTC hour (app/refusals.py, table refusals_429): no IP, no content, one UPSERT, never breaks the refusal."""
import time

import pytest

import app.actions as act
from app import refusals
from tests.test_0238_trial import ctx_of, new_trial, default_form, proj

ACT = {"tool": "Bash", "args": {"command": "echo hi"}}
H0 = lambda: int(time.time()) // 3600 * 3600  # noqa: E731


def rows(c, reason=None):
    refusals.flush(c)
    q = "SELECT * FROM refusals_429" + (" WHERE reason=?" if reason else "")
    return c.db.q(q, (reason,) if reason else ())


def post(client, hdr):
    return client.post("/v1/actions", json=ACT, headers=hdr)


@pytest.fixture()
def ag(client, owner):
    a, hdr = owner.new_agent()
    owner.mandate(a["id"])
    return a, hdr


def test_trial_quota(client, tmp_path):
    c = ctx_of(client)
    t = new_trial(client, tmp_path)
    hdr = {"Authorization": "Bearer " + t["api_key"]}
    c.cfg.trial_quota = 0
    assert post(client, hdr).status_code == 429
    assert post(client, hdr).status_code == 429
    r = rows(c, "TRIAL_QUOTA")
    assert len(r) == 1 and r[0]["n"] == 2 and r[0]["hour"] == H0() and r[0]["agent_id"] == t["agent_id"] and r[0]["account_id"]


def test_trial_day_and_net_hour(client, tmp_path):
    c = ctx_of(client)
    c.cfg.trial_per_hour = 1
    new_trial(client, tmp_path)
    assert client.post("/v1/trial", json={"form": default_form(proj(tmp_path))}).status_code == 429
    r = rows(c, "NET_HOUR")
    assert len(r) == 1 and r[0]["n"] == 1 and r[0]["account_id"] == "" and r[0]["agent_id"] == ""
    c.limiter.w.clear()
    c.cfg.trial_per_hour = 100
    c.cfg.trial_per_day = 1
    new_trial(client, tmp_path)
    c.limiter.w.pop("trial:testclient", None)
    assert client.post("/v1/trial", json={"form": default_form(proj(tmp_path))}).status_code == 429
    assert rows(c, "TRIAL_DAY")[0]["n"] == 1


def test_registrations_per_hour(client):
    from tests.helpers import ORIGIN
    c = ctx_of(client)
    c.cfg.reg_per_hour = 0
    assert client.post("/api/auth/register/begin", json={"display_name": "B"}, headers={"Origin": ORIGIN}).status_code == 429
    assert rows(c, "NET_HOUR")[0]["n"] == 1


def test_account_and_agent_quota(client, ag, monkeypatch):
    a, hdr = ag
    c = ctx_of(client)
    monkeypatch.setattr(c.cfg, "quota_per_day", 0)
    assert post(client, hdr).status_code == 429
    r = rows(c, "ACCOUNT_QUOTA")
    assert len(r) == 1 and r[0]["agent_id"] == a["id"]
    monkeypatch.setattr(c.cfg, "quota_per_day", 100000)
    monkeypatch.setattr(act, "QUOTA_PER_AGENT_DAY", 0)
    assert post(client, hdr).status_code == 429
    assert len(rows(c, "AGENT_QUOTA")) == 1


def test_reads_cap_agent_and_account(client, ag, monkeypatch):
    a, hdr = ag
    c = ctx_of(client)
    monkeypatch.setattr(c.cfg, "pass_per_agent_day", 0)
    assert post(client, hdr).status_code == 429
    monkeypatch.setattr(c.cfg, "pass_per_agent_day", 10 ** 6)
    monkeypatch.setattr(c.cfg, "pass_per_account_day", 0)
    assert post(client, hdr).status_code == 429
    r = rows(c, "READS_CAP")
    assert len(r) == 1 and r[0]["n"] == 2


def test_rate_per_minute(client, ag, monkeypatch):
    a, hdr = ag
    c = ctx_of(client)
    monkeypatch.setattr(c.cfg, "rate_per_min", 1)
    codes = [post(client, hdr).status_code for _ in range(3)]
    assert codes.count(429) >= 1
    r = rows(c, "RATE_MINUTE")
    assert len(r) == 1 and r[0]["n"] == codes.count(429) and r[0]["agent_id"] == a["id"]


def test_table_holds_no_ip_or_content(client):
    cols = [x["name"] for x in ctx_of(client).db.q("PRAGMA table_info(refusals_429)")]
    assert cols == ["hour", "reason", "account_id", "agent_id", "n"]


def test_nothing_is_written_per_refusal_and_flush_error_changes_nothing(client, ag, monkeypatch):
    a, hdr = ag
    c = ctx_of(client)
    monkeypatch.setattr(c.cfg, "quota_per_day", 0)
    before = post(client, hdr)
    assert c.db.q("SELECT * FROM refusals_429") == []            # memory only until the flush
    monkeypatch.setattr(refusals, "_UPSERT", "INSERT INTO no_such_table VALUES(?,?,?,?,?)")
    after = post(client, hdr)
    assert after.status_code == before.status_code == 429 and after.json() == before.json()
    assert refusals.flush(c) == 0 and not refusals._buf(c)       # error: logged, batch dropped, buffer empty
    monkeypatch.undo()


def test_overflow_is_aggregated(client, monkeypatch):
    c = ctx_of(client)
    monkeypatch.setattr(refusals, "MAX_KEYS", 3)
    for i in range(10):
        refusals.note(c, "RATE_MINUTE", "acc%d" % i, "ag%d" % i)
    refusals.note(c, "RATE_MINUTE", "acc0", "ag0")               # an existing key still counts on its own
    assert len(refusals._buf(c)) == 4
    r = {(x["account_id"], x["agent_id"]): x["n"] for x in rows(c)}
    assert r[("", "overflow")] == 7 and r[("acc0", "ag0")] == 2 and sum(r.values()) == 11


def test_prune_keeps_14_days(client):
    c = ctx_of(client)
    now = int(time.time())
    refusals.note(c, "RATE_MINUTE", "a", "b", t=now - 15 * 86400)
    refusals.note(c, "RATE_MINUTE", "a", "b", t=now - 13 * 86400)
    assert len(rows(c)) == 2
    assert refusals.prune(c, now) == 1 and len(rows(c)) == 1
