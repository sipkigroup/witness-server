"""0.2.29: "approve this call for later runs" (app/repeat.py). One wb over the approval payloads of the pending request and of N receipt ids the
owner's device made up (time limit inside each id); a later IDENTICAL call is recorded under the next id and approved with that signature."""
import base64
import hashlib
import json
import os
import sys
import time

import cbor2
import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))

from app import _paths  # noqa: F401,E402
from app import actions as A  # noqa: E402
from app import repeat as R  # noqa: E402
from app.config import Config, ConfigError  # noqa: E402
import wa_profile as wa  # noqa: E402
import wq_profile as wq  # noqa: E402
from svidetel_v4.state import approval_payload  # noqa: E402
from tests import viewkit  # noqa: E402  (r0352: decisions name the view)
from tests.helpers import FORM, ORIGIN, RP, H, act  # noqa: E402
from tests.test_allowance_0210 import Dev  # noqa: E402

ARGS = {"channel": "blog", "text": "nightly report"}


def wb_for(owner, items):
    a = owner.auth
    ad, cd, der = a.get_assertion(wq.wb_challenge(items), RP, ORIGIN)
    return wq.make_wb(items, a.kid, ad, cd, der)


def items_for(client, rid, rids):
    g = client.get("/api/approvals/" + rid).json()
    v = viewkit.page_view(g)                     # r0352: every item names the view the page showed
    return [hashlib.sha256(approval_payload(g["mandate"], g["action"], r, True, v)).digest() for r in [rid] + rids]


def approve_later(client, owner, rid, uses=2, hours=24, rids=None, items=None, env=None):
    exp = int(time.time()) + hours * 3600
    rids = rids if rids is not None else [R.make_rid(exp) for _ in range(uses)]
    env = env if env is not None else wb_for(owner, items if items is not None else items_for(client, rid, rids))
    return owner.post("/api/approvals/" + rid, approved=True, envelope_b64=wa.b64u(env), repeat={"rids": rids},
                      **viewkit.claim(viewkit.answer(client, rid))), rids, env


def expire(client, rid):
    """the request's 15 minutes are over (the next run comes an hour later)"""
    client.app.state.ctx.db.x("UPDATE actions SET expires=? WHERE rid=?", (int(time.time()) - 1, rid))
    client.get("/api/approvals/" + rid)


def night(owner):
    ag, hdr = owner.new_agent("demo", "night")
    owner.mandate(ag["id"])
    return ag, hdr


def test_0229_rid_carries_the_time_limit():
    exp = int(time.time()) + 24 * 3600
    r = R.make_rid(exp)
    assert R.RID_RE.fullmatch(r) and R.rid_exp(r) == exp
    assert R.rid_exp(A.new_rid()) is None                       # an ordinary rid (26 characters) is never a reserved one
    assert R.rid_exp("r_" + "A" * 31) is None and R.rid_exp(None) is None


def test_0229_offer_on_the_approval_page(client, owner):
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    o = client.get("/api/approvals/" + r["rid"]).json()["repeat_offer"]
    assert o["eligible"] and o["uses"] == [1, 3, 10] and o["hours"] == [1, 24, 72] and o["max_uses"] == 10


def test_0229_next_run_passes_without_a_question_then_used_up(client, owner):
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    assert r["verdict"] == "defer"
    res, rids, env = approve_later(client, owner, r["rid"], uses=3)
    assert res.status_code == 200, res.text
    j = res.json()
    assert j["verdict"] == "allow" and j["repeat"]["uses"] == 3 and j["repeat"]["exp"] == R.rid_exp(rids[0])
    expire(client, r["rid"])                                    # run 1 is long over, the request expired
    for i in range(3):                                          # runs 2, 3 and 4: the same call, no question
        x = act(client, hdr, "publish", ARGS).json()
        assert (x["rid"], x["verdict"], x["reason"], x["status"]) == (rids[i], "allow", "OK_APPROVED", "approved"), x
        assert x["aar_b64"]
        assert client.post("/v1/actions/%s/present" % x["rid"], json={}, headers=hdr).json()["result"] == "accept"
        ap = client.app.state.ctx.db.one("SELECT envelope FROM approvals WHERE rid=?", (x["rid"],))
        assert bytes(ap["envelope"]) == env                     # the receipt's APPROVAL entry holds the owner's own signature
    third = act(client, hdr, "publish", ARGS).json()            # three uses signed: the fourth call is a question again
    assert third["verdict"] == "defer" and R.rid_exp(third["rid"]) is None
    row = client.get("/api/repeat-approvals").json()["items"][0]
    assert (row["uses"], row["used"], row["status"]) == (3, 3, "used_up")


def test_0229_changed_arguments_are_asked_again(client, owner):
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    approve_later(client, owner, r["rid"], uses=3)
    expire(client, r["rid"])
    x = act(client, hdr, "publish", {"channel": "blog", "text": "nightly report!"}).json()
    assert x["verdict"] == "defer" and x["status"] == "pending_approval" and R.rid_exp(x["rid"]) is None
    y = act(client, hdr, "publish", {"channel": "news", "text": "nightly report"}).json()
    assert y["verdict"] == "defer"
    assert client.get("/api/repeat-approvals").json()["items"][0]["used"] == 0


def test_0229_audit_receipt_and_ledger(client, owner):
    """The reserved use is an ordinary RECEIPT defer + APPROVAL in the ledger: the AAR says OK_APPROVED and binds the same request hash."""
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    _, rids, env = approve_later(client, owner, r["rid"], uses=1)
    expire(client, r["rid"])
    x = act(client, hdr, "publish", ARGS).json()
    from deus_witness.client import verify_aar
    pub = client.get("/v1/witness").json()["pub_hex"]
    aar = verify_aar(base64.urlsafe_b64decode(x["aar_b64"] + "=="), pub, x["action"])      # the SDK's own check (as the hook does)
    assert aar["verdict"]["reason"] == "OK_APPROVED"
    L = client.app.state.ctx.hub.ledger(owner.account["id"])
    assert x["rid"] in L.aseq and L.S.receipts[x["rid"]]["verdict"] == "allow"
    ab = aar["mandate"]["approved_by"]
    assert ab["digest"] == L.hashes[L.aseq[x["rid"]]]          # the receipt names the APPROVAL entry ...
    from svidetel_v4 import cose
    body = cose.loads(cose.verify1(L.raws[L.aseq[x["rid"]]], [L.wk], cose.TYP_ENTRY)[0])
    assert body["type"] == "APPROVAL" and body["body"]["receipt"] == x["rid"] and bytes(body["body"]["cose"]) == env   # ... that holds the owner's wb
    t_rec = cose.loads(cose.verify1(L.raws[L.rseq[x["rid"]]], [L.wk], cose.TYP_ENTRY)[0])["t"]
    assert t_rec <= R.rid_exp(x["rid"])                         # recorded before the time written in the signed id (anyone with the ledger can check)


def test_0229_mandate_deny_is_never_bypassed_and_new_mandate_ends_it(client, owner):
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    approve_later(client, owner, r["rid"], uses=3)
    expire(client, r["rid"])
    form = dict(FORM, publish={"channels": ["news"]})           # the owner now publishes only to #news: "blog" is refused
    m, res = owner.mandate(ag["id"], form)
    assert res.status_code == 200, res.text
    x = act(client, hdr, "publish", ARGS).json()
    assert x["verdict"] == "deny" and R.rid_exp(x["rid"]) is None
    assert client.get("/api/repeat-approvals").json()["items"][0]["status"] == "mandate_ended"
    owner.mandate(ag["id"])                                     # back to "publish: ask": a new mandate, the old signature does not apply
    y = act(client, hdr, "publish", ARGS).json()
    assert y["verdict"] == "defer" and R.rid_exp(y["rid"]) is None
    assert client.get("/api/repeat-approvals").json()["items"][0]["used"] == 0      # not even tried under another mandate


def test_0229_revoke_in_one_click(client, owner):
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    approve_later(client, owner, r["rid"], uses=3)
    expire(client, r["rid"])
    gid = client.get("/api/repeat-approvals").json()["items"][0]["id"]
    assert client.post("/api/repeat-approvals/%s/revoke" % gid, headers={"Origin": "https://evil.example"}).status_code == 403
    assert owner.post("/api/repeat-approvals/%s/revoke" % gid).json()["status"] == "revoked"
    x = act(client, hdr, "publish", ARGS).json()
    assert x["verdict"] == "defer" and R.rid_exp(x["rid"]) is None
    assert client.get("/api/repeat-approvals").json()["items"][0]["status"] == "revoked"


def test_0229_time_limit(client, owner):
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    approve_later(client, owner, r["rid"], uses=3, hours=1)
    expire(client, r["rid"])
    client.app.state.ctx.db.x("UPDATE repeat_approvals SET exp=?", (int(time.time()) - 1,))
    x = act(client, hdr, "publish", ARGS).json()
    assert x["verdict"] == "defer" and R.rid_exp(x["rid"]) is None
    assert client.get("/api/repeat-approvals").json()["items"][0]["status"] == "expired"
    # the server also reads the limit from the signed id: a row whose own limit is later does not stretch it
    client.app.state.ctx.db.x("UPDATE repeat_approvals SET exp=?", (int(time.time()) + 10 * 86400,))
    g = client.app.state.ctx.db.one("SELECT * FROM repeat_approvals")
    assert R.find(client.app.state.ctx, g["agent_id"], g["mandate_id"], g["request_hash"], g["reason"], int(time.time())) is not None
    late = int(time.time()) + 2 * 3600                          # after the time inside the ids
    assert R.find(client.app.state.ctx, g["agent_id"], g["mandate_id"], g["request_hash"], g["reason"], late) is None


@pytest.mark.parametrize("case", ["extra_item", "missing_current", "two_limits", "too_far", "too_many", "ordinary_rid", "taken",
                                  "two_uses", "five_hours", "half_hour"])
def test_0229_what_the_owner_signs_is_exactly_what_is_recorded(client, owner, case):
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    other = act(client, hdr, "publish", {"channel": "blog", "text": "other"}).json()
    exp = int(time.time()) + 3600
    rids = [R.make_rid(exp) for _ in range(3)]
    kw = {}
    if case == "extra_item":                                    # one more signed item than the ids sent: the server would not know it
        kw["items"] = items_for(client, r["rid"], rids) + items_for(client, other["rid"], [])
    elif case == "missing_current":
        kw["items"] = items_for(client, r["rid"], rids)[1:]
    elif case == "two_limits":
        rids = [R.make_rid(exp), R.make_rid(exp), R.make_rid(exp + 60)]
    elif case == "two_uses":                                    # 0.2.30: only 1, 3 or 10 uses, what the page offers
        rids = [R.make_rid(exp), R.make_rid(exp)]
    elif case == "five_hours":                                  # 0.2.30: only 1, 24 or 72 hours
        rids = [R.make_rid(int(time.time()) + 5 * 3600)]
    elif case == "half_hour":
        rids = [R.make_rid(int(time.time()) + 1800)]
    elif case == "too_far":
        rids = [R.make_rid(int(time.time()) + 73 * 3600 + 700)]
    elif case == "too_many":
        rids = [R.make_rid(exp) for _ in range(11)]
    elif case == "ordinary_rid":
        rids = [A.new_rid()]
    elif case == "taken":
        rids = [other["rid"]]
    res, _, _ = approve_later(client, owner, r["rid"], rids=rids, **kw)
    assert res.status_code in (400, 409), res.text
    assert res.json()["error"] in ("WB_ITEM", "REPEAT_MALFORMED", "BAD_REQUEST", "REPEAT_ID_TAKEN", "WB_MALFORMED"), res.text
    assert client.get("/api/approvals/" + r["rid"]).json()["status"] == "pending_approval"     # nothing approved
    assert client.get("/api/repeat-approvals").json()["items"] == []


def test_0229_refusal_and_plain_wa_cannot_carry_repeat(client, owner):
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    g = client.get("/api/approvals/" + r["rid"]).json()
    v, cl = viewkit.page_view(g), viewkit.claim(g)      # r0352: over the view, so what is refused is the refusal / the plain wa
    env = owner.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], r["rid"], False, v))
    res = owner.post("/api/approvals/" + r["rid"], approved=False, envelope_b64=env, repeat={"rids": [R.make_rid(int(time.time()) + 3600)]}, **cl)
    assert res.status_code == 400
    env = owner.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], r["rid"], True, v))
    res = owner.post("/api/approvals/" + r["rid"], approved=True, envelope_b64=env, repeat={"rids": [R.make_rid(int(time.time()) + 3600)]}, **cl)
    assert res.status_code == 409 and res.json()["error"] == "WB_MALFORMED"


def test_0229_frozen_agent_is_refused(client, owner):
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    approve_later(client, owner, r["rid"], uses=3)
    expire(client, r["rid"])
    assert owner.post("/api/agents/%s/freeze" % ag["id"]).status_code == 200
    x = act(client, hdr, "publish", ARGS).json()
    assert (x["verdict"], x["reason"]) == ("deny", "AGENT_FROZEN")
    assert client.get("/api/repeat-approvals").json()["items"][0]["used"] == 0


def test_0229_removed_passkey_ends_it_and_the_owner_is_asked(client, owner):
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    approve_later(client, owner, r["rid"], uses=3)
    expire(client, r["rid"])
    db = client.app.state.ctx.db
    kid = db.one("SELECT kid FROM credentials WHERE account_id=?", (owner.account["id"],))["kid"]
    from app import org
    real = org.revoked_kid
    try:
        org.revoked_kid = lambda ctx, k: k == bytes(kid) or real(ctx, k)
        x = act(client, hdr, "publish", ARGS).json()
    finally:
        org.revoked_kid = real
    assert x["verdict"] == "defer" and x["status"] == "pending_approval"     # an ordinary question (the id is spent, never reused)


def test_0229_queue_full_does_not_block_an_already_approved_call(client, owner):
    from tests_flow.helpers import set_settings
    ag, hdr = night(owner)
    set_settings(client.app.state.ctx, owner.account["id"], max_pending=1, max_defers_hour=1000)
    r = act(client, hdr, "publish", ARGS).json()
    approve_later(client, owner, r["rid"], uses=1)
    expire(client, r["rid"])
    act(client, hdr, "publish", {"channel": "news", "text": "q"})           # one question waits: the queue is full
    act(client, hdr, "publish", {"channel": "news2", "text": "q"})          # r0352: a high-risk question may take a reserved place (2): full now
    assert act(client, hdr, "publish", {"channel": "x", "text": "q"}).json()["reason"] == "APPROVAL_RATE"
    x = act(client, hdr, "publish", ARGS).json()                           # asks nothing: passes
    assert (x["verdict"], x["reason"]) == ("allow", "OK_APPROVED")


def test_0229_dangerous_command_is_not_offered(client, owner, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    d = Dev(client, owner, proj.resolve())
    [(_, r)] = d.send("rm -rf /srv/src")   # 0.2.90: inside the project it is a plain delete
    assert r["reason"] == "ESCALATE_COMMAND_DANGER", r
    o = client.get("/api/approvals/" + r["rid"]).json()["repeat_offer"]
    assert not o["eligible"] and "dangerous" in o["why_not"]
    exp = int(time.time()) + 3600
    rids = [R.make_rid(exp)]
    res, _, _ = approve_later(client, owner, r["rid"], rids=rids)
    assert res.status_code == 409 and res.json()["error"] == "REPEAT_NOT_ELIGIBLE"


def test_0229_unlisted_command_next_run(client, owner, tmp_path):
    """The night agent's `make report` (unlisted, not dangerous): approved for 24 h -> the next run passes; `make clean` is asked."""
    proj = tmp_path / "proj"
    proj.mkdir()
    d = Dev(client, owner, proj.resolve())
    [(_, r)] = d.send("make report")
    assert r["reason"] == "ESCALATE_COMMAND"
    res, rids, _ = approve_later(client, owner, r["rid"], uses=1)
    assert res.status_code == 200, res.text
    expire(client, r["rid"])
    [(_, x)] = d.send("make report")
    assert (x["rid"], x["verdict"]) == (rids[0], "allow")
    [(_, y)] = d.send("make clean")
    assert y["verdict"] == "defer"


def test_0229_secret_seen_holds_it_again(client, owner, tmp_path, monkeypatch):
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    approve_later(client, owner, r["rid"], uses=1)
    expire(client, r["rid"])
    monkeypatch.setattr(A, "hold_after_secret", lambda *a, **k: True)       # the agent read a secret in this run
    x = act(client, hdr, "publish", ARGS).json()
    assert x["verdict"] == "defer" and R.rid_exp(x["rid"]) is None
    assert client.get("/api/repeat-approvals").json()["items"][0]["used"] == 0


def test_0229_team_account_not_offered(client, owner, monkeypatch):
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    from app import org
    monkeypatch.setattr(org, "current_policy", lambda ctx, acc_id: ({"members": []}, b"", b""))
    o = R.offer(client.app.state.ctx, owner.account, client.app.state.ctx.db.one("SELECT * FROM actions WHERE rid=?", (r["rid"],)))
    assert not o["eligible"] and "team" in o["why_not"]


def test_0229_account_delete_erases_it(client, owner):
    from app import account_delete
    assert "repeat_approvals" in account_delete.TABLES_BY_ACCOUNT and "repeat_slots" in account_delete.TABLES_BY_ACCOUNT


def test_0229_defer_ttl_from_env(tmp_path):
    base = {"DW_DATA_DIR": str(tmp_path), "DW_WITNESS_KEY_FILE": str(tmp_path / "k"), "DW_KEY_PEPPER": "p", "DW_RP_ID": RP, "DW_ORIGIN": ORIGIN}
    assert Config.from_env(base).defer_ttl_s == 900
    assert Config.from_env(dict(base, DW_DEFER_TTL_S="60")).defer_ttl_s == 60
    with pytest.raises(ConfigError):
        Config.from_env(dict(base, DW_DEFER_TTL_S="5"))


def test_0229_short_ttl_applies(client, owner):
    client.app.state.ctx.cfg.defer_ttl_s = 60
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    assert r["expires"] - int(time.time()) <= 61


def test_0229_morning_after_the_request_expired(client, owner):
    """The night run asked at 03:00, nobody answered, the request expired at 03:15. At 08:00 the owner opens the link: the request itself can
    no longer be approved, but the same call can be approved for the agent's NEXT runs (the envelope lists only the reserved ids)."""
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    expire(client, r["rid"])
    g = client.get("/api/approvals/" + r["rid"]).json()
    assert g["status"] == "expired" and g["repeat_offer"]["eligible"] and g["repeat_offer"]["expired"]
    x = client.app.state.ctx.db.one("SELECT args_preview, preview_cut FROM actions WHERE rid=?", (r["rid"],))
    assert x["preview_cut"] is None and "nightly report" in x["args_preview"]          # the owner still sees what the call was
    exp = int(time.time()) + 24 * 3600
    rids = [R.make_rid(exp)]
    # the expired request itself in the envelope: refused (it cannot be approved any more)
    res, _, _ = approve_later(client, owner, r["rid"], rids=rids)
    assert res.status_code == 409 and res.json()["error"] == "WB_ITEM"
    res, _, _ = approve_later(client, owner, r["rid"], rids=rids, items=items_for(client, r["rid"], rids)[1:])
    assert res.status_code == 200, res.text
    assert res.json()["verdict"] == "later_only" and res.json()["repeat"]["uses"] == 1
    assert client.get("/api/approvals/" + r["rid"]).json()["status"] == "expired"          # nothing was approved in the past
    nxt = act(client, hdr, "publish", ARGS).json()                                       # 09:00: the next run
    assert (nxt["rid"], nxt["verdict"], nxt["reason"]) == (rids[0], "allow", "OK_APPROVED")
    other = act(client, hdr, "publish", {"channel": "blog", "text": "something else"}).json()
    assert other["verdict"] == "defer"


def test_0229_expired_long_ago_is_not_offered_and_previews_are_cut(client, owner):
    from app import jobs
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    db = client.app.state.ctx.db
    db.x("UPDATE actions SET expires=? WHERE rid=?", (int(time.time()) - R.LATER_S - 10, r["rid"]))
    g = client.get("/api/approvals/" + r["rid"]).json()
    assert g["status"] == "expired" and not g["repeat_offer"]["eligible"] and "expired more than 24 hours" in g["repeat_offer"]["why_not"]
    assert db.one("SELECT preview_cut FROM actions WHERE rid=?", (r["rid"],))["preview_cut"] == 1
    r2 = act(client, hdr, "publish", {"channel": "blog", "text": "two"}).json()
    expire(client, r2["rid"])
    jobs.prune_previews(client.app.state.ctx)
    assert db.one("SELECT preview_cut FROM actions WHERE rid=?", (r2["rid"],))["preview_cut"] is None     # still within 24 h
    db.x("UPDATE actions SET expires=? WHERE rid=?", (int(time.time()) - R.LATER_S - 10, r2["rid"]))
    jobs.prune_previews(client.app.state.ctx)
    assert db.one("SELECT preview_cut FROM actions WHERE rid=?", (r2["rid"],))["preview_cut"] == 1
    exp = int(time.time()) + 3600
    rids = [R.make_rid(exp)]
    res, _, _ = approve_later(client, owner, r["rid"], rids=rids, items=items_for(client, r["rid"], rids)[1:])
    assert res.status_code == 409 and res.json()["error"] == "REPEAT_NOT_ELIGIBLE"


def test_0229_late_signature_is_checked(client, owner):
    """Expired request: nothing goes through approve_with_envelope now, so the signature is checked by repeat._check_late."""
    from tests.helpers import Owner
    from fastapi.testclient import TestClient
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    expire(client, r["rid"])
    rids = [R.make_rid(int(time.time()) + 3600)]
    its = items_for(client, r["rid"], rids)[1:]
    stranger = Owner(TestClient(client.app, base_url=ORIGIN)).register("Mallory")
    res, _, _ = approve_later(client, owner, r["rid"], rids=rids, env=wb_for(stranger, its))
    assert res.status_code == 409 and res.json()["error"] in ("KEY_MISMATCH", "APPROVAL_SIG", "WB_SIG"), res.text
    assert client.get("/api/repeat-approvals").json()["items"] == []


def test_0229_late_forged_signature_of_the_owners_key(client, owner):
    ag, hdr = night(owner)
    r = act(client, hdr, "publish", ARGS).json()
    expire(client, r["rid"])
    rids = [R.make_rid(int(time.time()) + 3600)]
    env = cbor2.loads(wb_for(owner, items_for(client, r["rid"], rids)[1:]))
    env["sig"] = bytes([env["sig"][0] ^ 1]) + env["sig"][1:]
    res, _, _ = approve_later(client, owner, r["rid"], rids=rids, env=wa.cde(env))
    assert res.status_code == 409, res.text
    assert client.get("/api/repeat-approvals").json()["items"] == []
