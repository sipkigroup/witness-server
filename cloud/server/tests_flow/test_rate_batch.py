"""APPROVAL_RATE (§3.4) and batch approval (§3.3). Required (1), (2), (3)."""
import hashlib

import cbor2

from app.flow.wq import wq
import wa_profile as wa
from tests_flow.helpers import FORM, Owner, act, b64d, ledger_entries, set_policy, set_settings


def _defer_publish(client, hdr, n, channel="#team", tag="t"):
    out = []
    for i in range(n):
        r = act(client, hdr, "publish", {"channel": channel, "text": "%s %d" % (tag, i)}).json()
        assert r["verdict"] == "defer", r
        out.append(r["rid"])
    return out


def test_3_sixth_pending_defer_is_approval_rate(client, owner, ctx):
    """max_pending counts decisions (batch groups), fatigue-fix: the 11th pending GROUP is refused (0.2.50: default 10); nothing in the ledger."""
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    for i in range(10):
        _defer_publish(client, hdr, 1, channel="#c%d" % i)
    n = len(ledger_entries(ctx, owner.account["id"]))
    r = act(client, hdr, "publish", {"channel": "#c10", "text": "eleventh"}).json()
    assert (r["verdict"], r["reason"], r["status"]) == ("deny", "APPROVAL_RATE", "denied")
    assert len(ledger_entries(ctx, owner.account["id"])) == n                              # nothing written to the ledger
    assert ctx.db.one("SELECT reason FROM actions WHERE rid=?", (r["rid"],))["reason"] == "APPROVAL_RATE"   # visible in the feed
    assert act(client, hdr, "publish", {"channel": "#c0", "text": "joins a group"}).json()["verdict"] == "defer"   # adds no decision


def test_rate_twelve_in_one_channel_at_defaults(client, owner):
    """fatigue-fix (ZAMECHANIYA 02 p.6): §1 p.3 "12 publications -> one batch" holds at the default max_pending 5; the item cap is one full batch."""
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    _defer_publish(client, hdr, 20)
    r = act(client, hdr, "publish", {"channel": "#team", "text": "21st"}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "APPROVAL_RATE")                       # PENDING_ITEMS_CAP = 20
    assert act(client, hdr, "publish", {"channel": "#other", "text": "x"}).json()["reason"] == "APPROVAL_RATE"


def test_rate_repeat_returns_same_rid(client, owner):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    rids = _defer_publish(client, hdr, 5)
    r = act(client, hdr, "publish", {"channel": "#team", "text": "t 0"}).json()
    assert r["rid"] == rids[0] and r["verdict"] == "defer"


def test_rate_settings_from_org(client, owner, ctx):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    set_settings(ctx, owner.account["id"], max_pending=2, max_defers_hour=20)
    _defer_publish(client, hdr, 2, channel="#a")
    _defer_publish(client, hdr, 1, channel="#b")
    assert act(client, hdr, "publish", {"channel": "#c", "text": "x"}).json()["reason"] == "APPROVAL_RATE"


def test_rate_defers_per_hour(client, owner, ctx):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    set_settings(ctx, owner.account["id"], max_pending=5, max_defers_hour=3)
    rids = sum((_defer_publish(client, hdr, 2, channel="#h%d" % i) for i in range(3)), [])
    for rid in rids:
        assert owner.approve(rid).status_code == 200                # nothing pending any more, but 3 groups of defers this hour
    assert act(client, hdr, "publish", {"channel": "#h3", "text": "x"}).json()["reason"] == "APPROVAL_RATE"
    assert act(client, hdr, "publish", {"channel": "#h0", "text": "x"}).json()["verdict"] == "defer"      # same group: no new decision


def test_rate_hour_item_cap(client, owner, ctx, monkeypatch):
    """The hour counts decisions, but never more than max(HOUR_ITEMS_CAP, max_defers_hour) items (cap lowered here: 60 calls/min per key)."""
    from app.flow import rate
    monkeypatch.setattr(rate, "HOUR_ITEMS_CAP", 4)
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    set_settings(ctx, owner.account["id"], max_pending=5, max_defers_hour=1)
    for rid in _defer_publish(client, hdr, 4, channel="#f"):
        assert owner.approve(rid).status_code == 200
    assert act(client, hdr, "publish", {"channel": "#f", "text": "5th"}).json()["reason"] == "APPROVAL_RATE"


def test_rate_never_touches_allow(client, owner):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    for i in range(5):
        _defer_publish(client, hdr, 1, channel="#c%d" % i)
    r = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s"}).json()
    assert (r["verdict"], r["reason"]) == ("allow", "OK")


def _twelve(client, owner, ctx, n=12, **kw):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    set_settings(ctx, owner.account["id"], max_pending=25, max_defers_hour=40)
    return ag, hdr, _defer_publish(client, hdr, n, **kw)


def test_1_twelve_publish_one_group_one_wb(client, owner, ctx):
    ag, hdr, rids = _twelve(client, owner, ctx)
    g = client.get("/api/approvals/groups").json()["groups"]
    assert len(g) == 1 and g[0]["count"] == 12 and sorted(g[0]["rids"]) == sorted(rids)
    items = [b64d(x) for x in g[0]["items_approve_b64"]]
    env = owner.wb(items)
    r = owner.post("/api/approvals/batch", rids=g[0]["rids"], approved=True, envelope_b64=env)
    assert r.status_code == 200, r.text
    assert [x["verdict"] for x in r.json()["results"]] == ["allow"] * 12
    for rid in rids:
        x = act(client, hdr, "publish", {"channel": "#team", "text": "t %d" % rids.index(rid)}).json()
        assert (x["rid"], x["verdict"], x["status"]) == (rid, "allow", "approved") and x["aar_b64"]
    envs = {bytes(x["envelope"]) for x in ctx.db.q("SELECT envelope FROM approvals WHERE account_id=?", (owner.account["id"],))}
    led = [e["body"]["cose"] for e in ledger_entries(ctx, owner.account["id"]) if e["type"] == "APPROVAL"]
    assert len(led) == 12 and len(set(led)) == 1 and envs == {led[0]} == {b64d(env)}     # same envelope bytes in all 12 APPROVAL entries


def test_2_mixed_channels_409(client, owner, ctx):
    ag, hdr, rids = _twelve(client, owner, ctx, n=2)
    rids += _defer_publish(client, hdr, 1, channel="#other")
    items = [hashlib.sha256(b"x%d" % i).digest() for i in range(3)]
    r = owner.post("/api/approvals/batch", rids=rids, approved=True, envelope_b64=owner.wb(items))
    assert (r.status_code, r.json()["error"]) == (409, "BATCH_MIXED")


def test_2_twentyone_items_409(client, owner, ctx):
    ag, hdr, rids = _twelve(client, owner, ctx, n=21)
    assert [g["count"] for g in client.get("/api/approvals/groups").json()["groups"]] == [20, 1]
    r = owner.post("/api/approvals/batch", rids=rids, approved=True, envelope_b64=owner.wb([hashlib.sha256(b"x").digest()]))
    assert (r.status_code, r.json()["error"]) == (409, "BATCH_SIZE")


def test_2_quorum_item_409(client, owner, ctx):
    ag, hdr, rids = _twelve(client, owner, ctx, n=3)
    set_policy(ctx, owner.account["id"], {"policy": {"role": "owner", "k": 1}, "mandate": [], "approval": [{"if": "access", "role": "access", "k": 2}],
                                          "revocation": {"role": "any", "k": 1}, "ceiling": {"role": "owner", "k": 1}})
    assert client.get("/api/approvals/groups").json()["groups"] == []          # quorum items are not offered as a batch
    r = owner.post("/api/approvals/batch", rids=rids, approved=True, envelope_b64=owner.wb([hashlib.sha256(b"x").digest()]))
    assert (r.status_code, r.json()["error"]) == (409, "BATCH_QUORUM")


def test_batch_items_must_match_rids(client, owner, ctx):
    ag, hdr, rids = _twelve(client, owner, ctx, n=3)
    g = client.get("/api/approvals/groups").json()["groups"][0]
    items = [b64d(x) for x in g["items_approve_b64"]][:2]
    r = owner.post("/api/approvals/batch", rids=g["rids"], approved=True, envelope_b64=owner.wb(items))
    assert (r.status_code, r.json()["error"]) == (409, "WB_ITEM")
    assert ctx.db.one("SELECT COUNT(*) AS n FROM approvals")["n"] == 0


def test_batch_foreign_key_refused(client, owner, ctx):
    ag, hdr, rids = _twelve(client, owner, ctx, n=3)
    g = client.get("/api/approvals/groups").json()["groups"][0]
    other = wa.SoftAuthenticator()
    r = owner.post("/api/approvals/batch", rids=g["rids"], approved=True, envelope_b64=owner.wb([b64d(x) for x in g["items_approve_b64"]], auth=other))
    assert (r.status_code, r.json()["error"]) == (409, "KEY_MISMATCH")
    assert ctx.db.one("SELECT COUNT(*) AS n FROM approvals")["n"] == 0


def test_batch_refuse_all(client, owner, ctx):
    ag, hdr, rids = _twelve(client, owner, ctx, n=4)
    g = client.get("/api/approvals/groups").json()["groups"][0]
    r = owner.post("/api/approvals/batch", rids=g["rids"], approved=False, envelope_b64=owner.wb([b64d(x) for x in g["items_refuse_b64"]]))
    assert r.status_code == 200 and [x["verdict"] for x in r.json()["results"]] == ["refused"] * 4
    assert {x["status"] for x in ctx.db.q("SELECT status FROM actions WHERE rid IN (%s)" % ",".join("?" * 4), rids)} == {"refused"}


def test_batch_approve_items_cannot_refuse(client, owner, ctx):
    """A wb signed over the approve-payloads cannot be used to refuse (and the other way round)."""
    ag, hdr, rids = _twelve(client, owner, ctx, n=2)
    g = client.get("/api/approvals/groups").json()["groups"][0]
    r = owner.post("/api/approvals/batch", rids=g["rids"], approved=False, envelope_b64=owner.wb([b64d(x) for x in g["items_approve_b64"]]))
    assert (r.status_code, r.json()["error"]) == (409, "WB_ITEM")


def test_batch_not_deferred_and_other_tenant(client, owner, owner2, ctx):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    ok = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s"}).json()
    r = owner.post("/api/approvals/batch", rids=[ok["rid"]], approved=True, envelope_b64=owner.wb([hashlib.sha256(b"x").digest()]))
    assert (r.status_code, r.json()["error"]) == (409, "NOT_DEFERRED")
    r = owner2.post("/api/approvals/batch", rids=[ok["rid"]], approved=True, envelope_b64=owner2.wb([hashlib.sha256(b"x").digest()]))
    assert r.status_code == 404


def test_batch_rejects_non_wb_envelope(client, owner, ctx):
    ag, hdr, rids = _twelve(client, owner, ctx, n=1)
    g = client.get("/api/approvals/" + rids[0]).json()
    from svidetel_v4.state import approval_payload
    env = owner.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], rids[0], True))
    r = owner.post("/api/approvals/batch", rids=rids, approved=True, envelope_b64=env)
    assert (r.status_code, r.json()["error"]) == (409, "WB_MALFORMED")


def test_0250_defaults_and_refusal_text(ctx):
    """0.2.50: a newcomer asks ~1 new command a minute: 5 pending / 20 an hour ended the session; now 10 / 120, and the refusal says what to do."""
    from app.flow import store
    from app import org
    from app.hookjudge.reasons import REASONS
    assert (store.DEFAULTS["max_pending"], store.DEFAULTS["max_defers_hour"]) == (10, 120)
    assert (org.DEFAULT_SETTINGS["max_pending"], org.DEFAULT_SETTINGS["max_defers_hour"]) == (10, 120)
    assert REASONS["APPROVAL_RATE"][1].startswith("too many questions at once; answer the waiting ones first")
