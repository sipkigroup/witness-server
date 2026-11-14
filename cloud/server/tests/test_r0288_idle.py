"""r0288 (13.11): an account in use is never erased by time; an unused one is warned first;
one wording of "free" everywhere, no "for good" / "forever"; the status page link comes from DW_STATUS_URL only."""
import os
import re
import time

import pytest

from app import trial
from app.config import Config, ConfigError
from tests.test_0238_trial import Person, ctx_of, hook, new_trial, proj

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "web")
DAY = 86400


class FakePush:
    def __init__(self):
        self.idle = []

    def notify_idle(self, uid):
        self.idle.append(uid)


def _claimed(client, app, tmp_path):
    t = new_trial(client, tmp_path)
    me = Person(app, t["claim"])
    assert me.claim_it().status_code == 200 and me.sign_mandate().status_code == 200
    c = ctx_of(client)
    aid = c.db.one("SELECT account_id FROM agents WHERE id=?", (t["agent_id"],))["account_id"]
    c.db.x("UPDATE accounts SET trial_until=NULL WHERE id=?", (aid,))           # what the sweep does on day 7
    return t, me, aid


def _row(c, aid):
    return c.db.one("SELECT erased_at, idle_warned_at, last_hook_at, trial_until FROM accounts WHERE id=?", (aid,))


@pytest.fixture
def push(client, monkeypatch):
    p = FakePush()
    monkeypatch.setattr(ctx_of(client), "push", p)
    return p


def test_used_account_is_never_erased(client, app, tmp_path, push):
    ctx_of(client).cfg.trial_per_hour = 10
    t, me, aid = _claimed(client, app, tmp_path)
    c = ctx_of(client)
    t0 = int(time.time())
    for day in (30, 60, 89, 120, 200, 400):                     # the hook calls every month: never warned, never erased
        trial.seen(c, aid, t0 + day * DAY)
        assert trial.expire_due(c, t0 + (day + 30) * DAY) == 0
        r = _row(c, aid)
        assert r["erased_at"] is None
    assert push.idle == []


def test_unused_claimed_account_warned_then_erased(client, app, tmp_path, push):
    ctx_of(client).cfg.trial_per_hour = 10
    t, me, aid = _claimed(client, app, tmp_path)
    c = ctx_of(client)
    t0 = max(int(time.time()), trial.IDLE_FROM)
    assert trial.expire_due(c, t0 + 70 * DAY) == 0 and _row(c, aid)["idle_warned_at"] is None and push.idle == []
    assert trial.expire_due(c, t0 + 77 * DAY) == 0                  # 90 - 14 days: the push, no erase
    assert push.idle == [aid] and _row(c, aid)["idle_warned_at"] == t0 + 77 * DAY
    assert trial.expire_due(c, t0 + 80 * DAY) == 0 and push.idle == [aid]     # one push per idle time
    assert trial.expire_due(c, t0 + 89 * DAY) == 0 and _row(c, aid)["erased_at"] is None
    assert trial.expire_due(c, t0 + 92 * DAY) == 1
    assert _row(c, aid)["erased_at"] is not None
    r = client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "ls"}}, headers={"Authorization": "Bearer " + t["api_key"]})
    assert r.status_code == 401                                     # its agent key is gone with it


def test_warned_then_used_is_kept_and_needs_a_new_warning(client, app, tmp_path, push):
    ctx_of(client).cfg.trial_per_hour = 10
    t, me, aid = _claimed(client, app, tmp_path)
    c = ctx_of(client)
    t0 = max(int(time.time()), trial.IDLE_FROM)
    assert trial.expire_due(c, t0 + 77 * DAY) == 0 and push.idle == [aid]
    trial.seen(c, aid, t0 + 85 * DAY)                               # the hook called after the warning
    assert trial.expire_due(c, t0 + 95 * DAY) == 0 and _row(c, aid)["erased_at"] is None
    assert trial.expire_due(c, t0 + (85 + 76) * DAY) == 0 and push.idle == [aid, aid]      # a new idle time: a new push first
    assert trial.expire_due(c, t0 + (85 + 89) * DAY) == 0 and _row(c, aid)["erased_at"] is None
    assert trial.expire_due(c, t0 + (85 + 91) * DAY) == 1


def test_sweep_that_was_down_still_gives_the_full_notice(client, app, tmp_path, push):
    ctx_of(client).cfg.trial_per_hour = 10
    t, me, aid = _claimed(client, app, tmp_path)
    c = ctx_of(client)
    t0 = max(int(time.time()), trial.IDLE_FROM)
    assert trial.expire_due(c, t0 + 120 * DAY) == 0 and push.idle == [aid]     # first run long after: only the push
    assert trial.expire_due(c, t0 + 130 * DAY) == 0                            # 10 days after the push: not yet
    assert trial.expire_due(c, t0 + 134 * DAY + 1) == 1                        # 14 days after the push


def test_sign_in_and_dashboard_count_as_use(client, app, tmp_path, push):
    ctx_of(client).cfg.trial_per_hour = 10
    t, me, aid = _claimed(client, app, tmp_path)
    c = ctx_of(client)
    t0 = max(int(time.time()), trial.IDLE_FROM)
    assert trial.expire_due(c, t0 + 77 * DAY) == 0 and push.idle == [aid]
    c.db.x("UPDATE credentials SET last_used_at=? WHERE user_id=?", (t0 + 80 * DAY, aid))    # a passkey sign-in on day 80
    assert trial.expire_due(c, t0 + 92 * DAY) == 0 and _row(c, aid)["erased_at"] is None
    j = me.c.get("/api/me").json()                                  # opening the dashboard is a use too (and it says so)
    assert j["idle"]["warned_at"] == t0 + 77 * DAY and j["idle"]["kept"] is True and j["idle"]["days"] == 90
    assert trial.flush_seen(c) >= 1 and _row(c, aid)["last_hook_at"] >= int(time.time()) - 5


def test_team_and_demo_are_never_idle_erased(client, app, tmp_path, push):
    ctx_of(client).cfg.trial_per_hour = 10
    c = ctx_of(client)
    t1, _, a1 = _claimed(client, app, tmp_path)
    t2, _, a2 = _claimed(client, app, tmp_path)
    c.db.x("INSERT INTO members(account_id, user_id, roles, status) VALUES(?,?,?,?)", (a1, "u_other_person", '["approver"]', "active"))
    c.cfg.demo_account = a2
    t0 = max(int(time.time()), trial.IDLE_FROM)
    assert trial.expire_due(c, t0 + 200 * DAY) == 0 and trial.expire_due(c, t0 + 300 * DAY) == 0
    assert _row(c, a1)["erased_at"] is None and _row(c, a2)["erased_at"] is None and push.idle == []


def test_unclaimed_used_by_hook_keeps_its_claim_link(client, app, tmp_path):
    ctx_of(client).cfg.trial_per_hour = 10
    c = ctx_of(client)
    t = new_trial(client, tmp_path)
    hook(client, t["api_key"], proj(tmp_path), tmp_path)("git push")
    aid = c.db.one("SELECT account_id FROM agents WHERE id=?", (t["agent_id"],))["account_id"]
    assert aid in trial._SEEN and not trial.expired(c, aid, int(time.time()) + 8 * DAY)    # a use not written yet keeps it alive
    trial.flush_seen(c)
    assert _row(c, aid)["trial_until"] >= int(time.time()) + 89 * DAY and aid not in trial._SEEN
    assert trial.expire_due(c, int(time.time()) + 30 * DAY) == 0
    assert client.get("/api/trial/state", headers={"x-dw-claim": t["claim"]}).status_code == 200


def test_no_write_on_the_request_path(client, app, tmp_path):
    """The hook's call only notes the use in memory: the database is written by the hourly sweep (no write in the event loop)."""
    ctx_of(client).cfg.trial_per_hour = 10
    c = ctx_of(client)
    t = new_trial(client, tmp_path)
    aid = c.db.one("SELECT account_id FROM agents WHERE id=?", (t["agent_id"],))["account_id"]
    trial.flush_seen(c)
    client.get("/v1/salt", headers={"Authorization": "Bearer " + t["api_key"]})
    assert _row(c, aid)["last_hook_at"] is None and aid in trial._SEEN
    assert trial.expire_due(c) == 0 and _row(c, aid)["last_hook_at"] is not None


def test_idle_off(client, app, tmp_path, push):
    ctx_of(client).cfg.trial_per_hour = 10
    c = ctx_of(client)
    t, me, aid = _claimed(client, app, tmp_path)
    c.cfg.idle_days = 0
    try:
        assert trial.expire_due(c, int(time.time()) + 999 * DAY) == 0 and push.idle == []
    finally:
        c.cfg.idle_days = 90


BASE = {"DW_DATA_DIR": "/tmp/x", "DW_WITNESS_KEY_FILE": "/tmp/x/k", "DW_KEY_PEPPER": "p", "DW_RP_ID": "localhost", "DW_ORIGIN": "http://localhost:1"}


@pytest.mark.parametrize("env,bad", [({"DW_IDLE_DAYS": "10"}, True), ({"DW_IDLE_DAYS": "0"}, False), ({"DW_IDLE_DAYS": "120", "DW_IDLE_WARN_DAYS": "30"}, False),
                                     ({"DW_IDLE_DAYS": "30", "DW_IDLE_WARN_DAYS": "30"}, True), ({"DW_STATUS_URL": "javascript:alert(1)"}, True),
                                     ({"DW_STATUS_URL": "http://x.example"}, True), ({"DW_STATUS_URL": "https://sipkigroup.github.io/witness-server/"}, False)])
def test_config(env, bad):
    if bad:
        with pytest.raises(ConfigError):
            Config.from_env(dict(BASE, **env))
    else:
        cfg = Config.from_env(dict(BASE, **env))
        if "DW_STATUS_URL" in env:
            assert cfg.status_url == env["DW_STATUS_URL"].rstrip("/")


def test_status_url_only_when_configured(client):
    c = ctx_of(client)
    assert client.get("/api/build").json()["status_url"] is None
    c.cfg.status_url = "https://status.example.org"
    try:
        assert client.get("/api/build").json()["status_url"] == "https://status.example.org"
    finally:
        c.cfg.status_url = ""


def _text(name):
    with open(os.path.join(WEB, name), encoding="utf-8") as f:
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", f.read()))


@pytest.mark.parametrize("page", ["privacy.html", "terms.html", "trial.html", "index.html"])
def test_free_wording(page):
    s = _text(page)
    assert trial.FREE_TEXT in s, page
    assert "10000 actions per day per account" in s, page
    assert not re.search(r"free,? for good|free forever|for good, free|stays for good|it stays, free\)", s, re.I), page
    assert "90 days" in s, page


def test_note_of_a_new_trial(client, tmp_path):
    ctx_of(client).cfg.trial_per_hour = 10
    n = new_trial(client, tmp_path)["note"]
    assert trial.FREE_TEXT in n and "for good" not in n and "90 days" in n
