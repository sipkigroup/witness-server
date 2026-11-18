"""pv2 (28.10): the presentation hash on EVERY approval path, not only the single approval page (pv2810): a team's quorum, a batch of the
queue, "approve this call for later runs" (repeat) and "allow in this project" (allowance). Same format (RFC 8785 -> SHA-256 of the
dw-view-1 object), same compatibility: an older page (no view) is accepted and marked "view not signed"; a view claimed but not signed,
or signed but not claimed, is refused. And the check of the view is atomic with the decision (under the same hub.lock).
Per path: matches -> recorded / changed -> refused, nothing decided / older page -> marked. Real server (TestClient), real ledger."""
import hashlib
import json
import threading
import time

import cbor2
import pytest

from app import repeat as R
from app import signview
from svidetel_v4 import cose
from svidetel_v4.state import approval_payload
import wa_profile as wa
import wq_profile as wq
from tests.helpers import ORIGIN, RP, act
from tests.org_helpers import team, ctx_of
from tests.test_quorum import msg_mandate, deferred_purchase
from tests.test_0224_critique import Agent, row

ARGS = {"channel": "blog", "text": "nightly report"}
X = ("view_sha256", "view_signed", "view_signed_sha256")


def _get(p, rid):
    g = p.c.get("/api/approvals/" + rid)
    assert g.status_code == 200, g.text
    return g.json()


def _page(g):
    """the hash the page computes from the answer it got (web/js/signview.js does the same)"""
    return signview.view_hash({k: v for k, v in g.items() if k not in X})


def _entries(app, account_id, typ):
    L = ctx_of(app).hub.ledger(account_id)
    L.sync_now()
    out = []
    for raw in L.raws:
        e = cose.loads(cose.verify1(raw, [L.wk], cose.TYP_ENTRY)[0])
        if e["type"] == typ:
            out.append(e["body"])
    return out


def _approval(app, account_id, rid):
    bs = [b for b in _entries(app, account_id, "APPROVAL") if b["receipt"] == rid]
    return bs[0] if bs else None


def _wb(p, items):
    ad, cd, der = p.auth.get_assertion(wq.wb_challenge(items), RP, ORIGIN)
    return wa.b64u(wq.make_wb(items, p.auth.kid, ad, cd, der))


def _bump(app, rid, what="args_preview"):
    """what the witness holds changes after the page was opened (the page's view is stale now)"""
    ctx_of(app).db.x("UPDATE actions SET %s=COALESCE(%s,'') || ' (changed)' WHERE rid=?" % (what, what), (rid,))


# ============================================================ team quorum (sig_requests)

def _team_purchase(app, amount=70000):
    owner, bob, carol = team(app)
    ag, hdr, m = msg_mandate(owner)
    d = deferred_purchase(owner, hdr, amount)
    return owner, bob, carol, hdr, d["rid"]


def _team_approve(p, rid, sign_view="page", send_view="page", g=None):
    g = g or _get(p, rid)
    page = _page(g)
    sv = page if sign_view == "page" else sign_view
    nv = page if send_view == "page" else send_view
    body = {"approved": True, "envelope_b64": p.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], rid, True, sv))}
    if nv is not None:
        body["view_sha256"] = nv.hex()
    return p.post("/api/approvals/" + rid, **body), page


def _sid(app, rid):
    r = ctx_of(app).db.one("SELECT id FROM sig_requests WHERE kind='approval' AND ref=? AND status='collecting'", (rid,))
    return r["id"] if r else None


def test_pv2_team_server_offers_the_view(app):
    owner, bob, carol, hdr, rid = _team_purchase(app)
    g = _get(owner, rid)
    assert g["view_sha256"] == _page(g).hex()                                   # pv2810 offered none with a team policy
    assert _get(bob, rid)["view_sha256"] == g["view_sha256"]                    # the same view for every signer


def test_pv2_team_quorum_names_the_view_signer_by_signer(app):
    owner, bob, carol, hdr, rid = _team_purchase(app)
    r, page = _team_approve(owner, rid)
    assert r.status_code == 200 and r.json()["verdict"] == "collecting", r.text
    sid = _sid(app, rid)
    sr = owner.c.get("/api/sig-requests/" + sid).json()
    assert sr["body"]["view"] == page.hex()                                     # sign.html checks this against GET /api/approvals/{rid}
    assert cbor2.loads(wa.b64u_dec(sr["payload_b64"]))["view"] == page          # the stored bytes every signer signs
    r = bob.sign_req(sid)                                                        # the second signer on the request page
    assert r.status_code == 200 and r.json()["status"] == "done" and r.json()["verdict"] == "allow", r.text
    b = _approval(app, owner.uid, rid)
    assert b["view"] == page and cbor2.loads(cbor2.loads(b["cose"])["payload"])["view"] == page     # the wq signs it, the entry names it
    g = _get(owner, rid)
    assert g["view_signed"] is True and g["view_signed_sha256"] == page.hex()


def test_pv2_team_second_signer_on_the_approval_page(app):
    owner, bob, carol, hdr, rid = _team_purchase(app)
    r, page = _team_approve(owner, rid)
    assert r.json()["verdict"] == "collecting", r.text
    r, page2 = _team_approve(bob, rid)
    assert page2 == page and r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    assert _approval(app, owner.uid, rid)["view"] == page


def test_pv2_team_changed_view_between_signers_is_refused(app):
    owner, bob, carol, hdr, rid = _team_purchase(app)
    r, page = _team_approve(owner, rid)
    assert r.json()["verdict"] == "collecting", r.text
    sid = _sid(app, rid)
    _bump(app, rid)
    r = bob.sign_req(sid)                                                        # signs the stored bytes, but the rows show another view now
    assert r.status_code == 409 and r.json()["error"] == "VIEW_CHANGED", r.text
    assert row(owner.c, rid)["status"] == "pending_approval" and _approval(app, owner.uid, rid) is None


def test_pvh_a_request_pinned_to_a_stale_view_is_replaced(app):
    """pvh 28.10: the open request names V1, the rows give V2 now -> it can never reach quorum (sign_request refuses V1). A page that
    claims the CURRENT view (checked under the lock) replaces it with a new request over V2; the V1 signature is not carried over."""
    owner, bob, carol, hdr, rid = _team_purchase(app)
    r, v1 = _team_approve(owner, rid)
    assert r.json()["verdict"] == "collecting", r.text
    sid1 = _sid(app, rid)
    _bump(app, rid)
    r, v2 = _team_approve(bob, rid)                                              # bob's reloaded page claims the new view
    assert v2 != v1 and r.status_code == 200 and r.json()["verdict"] == "collecting" and r.json()["have"] == 1, r.text
    sid2 = _sid(app, rid)
    assert sid2 and sid2 != sid1
    assert ctx_of(app).db.one("SELECT status FROM sig_requests WHERE id=?", (sid1,))["status"] == "superseded"
    assert owner.c.get("/api/sig-requests/" + sid2).json()["body"]["view"] == v2.hex()
    assert bob.sign_req(sid1).status_code >= 400                                  # the stale request takes no signature any more
    r = owner.sign_req(sid2)                                                     # the first signer signs again, over V2
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    assert _approval(app, owner.uid, rid)["view"] == v2


def test_pvh_a_stale_page_does_not_replace_a_current_request(app):
    """the other way round: the request names the current view, a stale page claims an old one -> VIEW_CHANGED, the request stays"""
    owner, bob, carol, hdr, rid = _team_purchase(app)
    g_old = _get(bob, rid)
    _bump(app, rid)
    r, v2 = _team_approve(owner, rid)
    sid = _sid(app, rid)
    r, _ = _team_approve(bob, rid, g=g_old)
    assert r.status_code == 409 and r.json()["error"] == "VIEW_CHANGED", r.text
    assert _sid(app, rid) == sid and json.loads(ctx_of(app).db.one("SELECT sigs FROM sig_requests WHERE id=?", (sid,))["sigs"])


def test_pv2_team_claim_without_signature_and_signature_without_claim(app):
    owner, bob, carol, hdr, rid = _team_purchase(app)
    r, _ = _team_approve(owner, rid, sign_view=None)                            # claims the view, signs the 0.1 bytes
    assert r.status_code == 409 and r.json()["error"] == "APPROVAL_SIG", r.text
    r, _ = _team_approve(owner, rid, send_view=None)                            # signs the view, does not say so
    assert r.status_code == 409 and r.json()["error"] == "APPROVAL_SIG", r.text
    r, _ = _team_approve(owner, rid, sign_view=None)                            # again: the empty request of a failed try pins nothing
    assert r.status_code == 409 and r.json()["error"] == "APPROVAL_SIG", r.text
    assert _sid(app, rid) is None or json.loads(ctx_of(app).db.one("SELECT sigs FROM sig_requests WHERE id=?", (_sid(app, rid),))["sigs"]) == []
    r, page = _team_approve(owner, rid)                                          # the honest page still works after all that
    assert r.status_code == 200 and r.json()["verdict"] == "collecting", r.text
    assert owner.c.get("/api/sig-requests/" + _sid(app, rid)).json()["body"]["view"] == page.hex()


def test_pv2_team_older_pages_are_marked(app):
    owner, bob, carol, hdr, rid = _team_purchase(app)
    assert owner.approve(rid).json()["verdict"] == "collecting"                 # 0.1 page: the request names no view
    sid = _sid(app, rid)
    assert "view" not in owner.c.get("/api/sig-requests/" + sid).json()["body"]
    r, _ = _team_approve(bob, rid)                                               # a new page cannot sign other bytes than the request's
    assert r.status_code == 409 and r.json()["error"] == "VIEW_CHANGED" and sid in r.json().get("detail", sid), r.text
    r = bob.sign_req(sid)                                                        # ... it signs on the request page: done, view not signed
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    assert "view" not in _approval(app, owner.uid, rid) and _get(owner, rid)["view_signed"] is False


def test_pv2_team_old_page_after_a_view_request_is_refused(app):
    owner, bob, carol, hdr, rid = _team_purchase(app)
    r, page = _team_approve(owner, rid)
    assert r.json()["verdict"] == "collecting"
    r = bob.approve(rid)                                                         # 0.1 bytes against a request that names the view
    assert r.status_code == 409 and r.json()["error"] == "APPROVAL_SIG", r.text


def test_pv2_team_k1_action_decided_at_once_with_the_view(app):
    owner, bob, carol, hdr, rid = _team_purchase(app, amount=1000)               # below the budget rule: k=1
    r, page = _team_approve(owner, rid)
    assert r.status_code == 409 and r.json()["error"] == "SELF_APPROVAL", r.text      # r0284: the creator of the agent does not confirm its k=1 question
    r, page = _team_approve(bob, rid)
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    assert _approval(app, owner.uid, rid)["view"] == page


# ============================================================ batch from the queue (wb)

def _night(owner, n=3):
    ag, hdr = owner.new_agent("demo", "night")
    owner.mandate(ag["id"])
    rids = []
    for i in range(n):
        r = act(owner.c, hdr, "publish", {"channel": "blog", "text": "report %d" % i}).json()
        assert r["verdict"] == "defer", r
        rids.append(r["rid"])
    return ag, hdr, rids


def _batch(owner, rids, sign_views="page", send_views="page", gs=None):
    gs = gs or [_get(owner, r) for r in rids]
    pages = [_page(g) for g in gs]
    sv = pages if sign_views == "page" else sign_views
    nv = pages if send_views == "page" else send_views
    items = [hashlib.sha256(approval_payload(g["mandate"], g["action"], r, True, sv[i] if sv else None)).digest() for i, (g, r) in enumerate(zip(gs, rids))]
    body = {"rids": rids, "approved": True, "envelope_b64": _wb(owner, items)}
    if nv is not None:
        body["views"] = [v.hex() if isinstance(v, bytes) else v for v in nv]
    return owner.post("/api/approvals/batch", **body), pages


def test_pv2_batch_each_item_names_its_own_view(client, owner):
    ag, hdr, rids = _night(owner)
    r, pages = _batch(owner, rids)
    assert r.status_code == 200 and [x["verdict"] for x in r.json()["results"]] == ["allow"] * 3, r.text
    assert len(set(pages)) == 3                                                  # three different views, one per item
    for rid, page in zip(rids, pages):
        b = _approval(client.app, owner.account["id"], rid)
        assert b["view"] == page and cbor2.loads(b["cose"])["items"]            # the same wb in every entry, each entry its own view
        assert _get(owner, rid)["view_signed_sha256"] == page.hex()


def test_pv2_batch_one_changed_item_refuses_the_whole_batch(client, owner):
    ag, hdr, rids = _night(owner)
    gs = [_get(owner, r) for r in rids]
    _bump(client.app, rids[1], "text_preview")
    r, _ = _batch(owner, rids, gs=gs)
    assert r.status_code == 409 and r.json()["error"] == "VIEW_CHANGED", r.text
    assert [row(client, x)["status"] for x in rids] == ["pending_approval"] * 3     # nothing decided, not even the unchanged items
    r, _ = _batch(owner, rids)                                                   # reloaded list
    assert r.status_code == 200 and [x["verdict"] for x in r.json()["results"]] == ["allow"] * 3, r.text


def test_pv2_batch_claim_and_signature_must_agree(client, owner):
    ag, hdr, rids = _night(owner)
    r, _ = _batch(owner, rids, sign_views=None)                                  # claims views, signed the 0.1 items
    assert r.status_code == 409 and r.json()["error"] == "WB_ITEM", r.text
    r, _ = _batch(owner, rids, send_views=None)                                  # signed views, claims none
    assert r.status_code == 409 and r.json()["error"] == "WB_ITEM", r.text
    r, _ = _batch(owner, rids, sign_views=[b"\x01" * 32] * 3, send_views=[b"\x01" * 32] * 3)
    assert r.status_code == 409 and r.json()["error"] == "VIEW_CHANGED", r.text
    for bad in (["ab" * 32], ["AB" * 32] * 3, [None] * 3, "ab" * 32):
        r, _ = _batch(owner, rids, send_views=bad)
        assert r.status_code == 400, (bad, r.text)
    assert [row(client, x)["status"] for x in rids] == ["pending_approval"] * 3


def test_pv2_batch_from_an_older_page_is_marked(client, owner):
    ag, hdr, rids = _night(owner, 2)
    r, _ = _batch(owner, rids, sign_views=None, send_views=None)
    assert r.status_code == 200 and [x["verdict"] for x in r.json()["results"]] == ["allow"] * 2, r.text
    for rid in rids:
        assert "view" not in _approval(client.app, owner.account["id"], rid) and _get(owner, rid)["view_signed"] is False


# ============================================================ approve for later runs (repeat)

def _later(owner, rid, uses=3, sign_view="page", send_view="page", g=None, late=False):
    g = g or _get(owner, rid)
    page = _page(g)
    sv = page if sign_view == "page" else sign_view
    nv = page if send_view == "page" else send_view
    exp = int(time.time()) + 24 * 3600
    rids = [R.make_rid(exp) for _ in range(uses)]
    items = [hashlib.sha256(approval_payload(g["mandate"], g["action"], r, True, sv)).digest() for r in ([] if late else [rid]) + rids]
    body = {"approved": True, "envelope_b64": _wb(owner, items), "repeat": {"rids": rids}}
    if nv is not None:
        body["view_sha256"] = nv.hex()
    return owner.post("/api/approvals/" + rid, **body), rids, page


def _expire(client, rid):
    client.app.state.ctx.db.x("UPDATE actions SET expires=? WHERE rid=?", (int(time.time()) - 1, rid))
    client.get("/api/approvals/" + rid)


def test_pv2_repeat_names_the_view_now_and_in_every_later_run(client, owner):
    ag, hdr = owner.new_agent("demo", "night")
    owner.mandate(ag["id"])
    rid = act(client, hdr, "publish", ARGS).json()["rid"]
    r, rids, page = _later(owner, rid)
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    assert _approval(client.app, owner.account["id"], rid)["view"] == page
    assert client.app.state.ctx.db.one("SELECT view_sha256 FROM repeat_approvals")["view_sha256"] == page.hex()
    _expire(client, rid)
    x = act(client, hdr, "publish", ARGS).json()                                # the next run: the owner's signature applied
    assert (x["rid"], x["verdict"], x["reason"]) == (rids[0], "allow", "OK_APPROVED"), x
    assert _approval(client.app, owner.account["id"], rids[0])["view"] == page   # it was approved on what the page showed then
    assert client.post("/v1/actions/%s/present" % x["rid"], json={}, headers=hdr).json()["result"] == "accept"


def test_pv2_repeat_changed_view_and_mismatches_are_refused(client, owner):
    ag, hdr = owner.new_agent("demo", "night")
    owner.mandate(ag["id"])
    rid = act(client, hdr, "publish", ARGS).json()["rid"]
    g = _get(owner, rid)
    _bump(client.app, rid)
    r, _, _ = _later(owner, rid, g=g)
    assert r.status_code == 409 and r.json()["error"] == "VIEW_CHANGED", r.text
    r, _, _ = _later(owner, rid, sign_view=None)                                 # claims, not signed
    assert r.status_code == 409 and r.json()["error"] == "WB_ITEM", r.text
    r, _, _ = _later(owner, rid, send_view=None)                                 # signed, not claimed
    assert r.status_code == 409 and r.json()["error"] == "WB_ITEM", r.text
    assert row(client, rid)["status"] == "pending_approval"
    assert client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM repeat_approvals")["n"] == 0


def test_pv2_repeat_from_an_older_page_is_marked(client, owner):
    ag, hdr = owner.new_agent("demo", "night")
    owner.mandate(ag["id"])
    rid = act(client, hdr, "publish", ARGS).json()["rid"]
    r, rids, _ = _later(owner, rid, sign_view=None, send_view=None)
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    _expire(client, rid)
    x = act(client, hdr, "publish", ARGS).json()
    assert x["rid"] == rids[0] and x["verdict"] == "allow", x
    assert "view" not in _approval(client.app, owner.account["id"], rids[0]) and _get(owner, rids[0])["view_signed"] is False


def test_pv2_repeat_after_the_request_expired(client, owner):
    ag, hdr = owner.new_agent("demo", "night")
    owner.mandate(ag["id"])
    rid = act(client, hdr, "publish", ARGS).json()["rid"]
    _expire(client, rid)
    g = _get(owner, rid)
    assert g["status"] == "expired" and g["repeat_offer"]["eligible"] and g["view_sha256"] == _page(g).hex()
    r, rids, page = _later(owner, rid, late=True, g=g)
    assert r.status_code == 200 and r.json()["verdict"] == "later_only", r.text
    x = act(client, hdr, "publish", ARGS).json()
    assert x["rid"] == rids[0] and x["verdict"] == "allow", x
    assert _approval(client.app, owner.account["id"], rids[0])["view"] == page


# ============================================================ allow in this project (allowance)

def _dev(client, owner, tmp_path):
    from tests.test_allowance_0210 import Dev
    proj = tmp_path / "proj"
    proj.mkdir(parents=True)
    d = Dev(client, owner, proj.resolve())
    [(tool, r)] = d.send("pytest -q")
    assert r["reason"] == "ESCALATE_COMMAND", r
    return d, r["rid"]


def _allow_view(g):
    """r0327: the hash a rule signs: the page's view AND the text of trust of the offer (web/js/allowance.js allowViewHash)"""
    from app import allowances as al
    o = g["allowance_offer"]
    obj = al.allow_view(signview.view_of({k: v for k, v in g.items() if k not in X}), o["text_v"], o["text"])
    return hashlib.sha256(signview.jcs(obj)).digest()


def _allow(d, rid, sign_view="allow", send_view="page", g=None):
    """sign_view: "allow" (r0327: page + text of trust, the current page), "page" (the page alone: a page before r0327), bytes or None.
    -> (response, map, the hash signed)"""
    from tests.test_allowance_0210 import _id, DAY
    from app import allowances as al
    from app import wire
    from svidetel_v4.state import mandate_hash
    g = g or _get(d.o, rid)
    page = _page(g)
    sv = _allow_view(g) if sign_view == "allow" else page if sign_view == "page" else sign_view
    nv = page if send_view == "page" else send_view
    o = g["allowance_offer"]
    a = {"v": "deus-aar-0.1", "t": "allowance", "id": _id(), "mandate": mandate_hash(wire.cbor_form(g["mandate"])), "class": "command",
         "commands": o["commands"], "project": o["project"], "nbf": o["t"], "exp": o["t"] + DAY}
    if sv is not None:
        a["view"] = sv
    body = {"rid": rid, "envelope_b64": d.o.sign(al.TYP, wa.cde(a))}
    if nv is not None:
        body["view_sha256"] = nv.hex()
    return d.o.post("/api/allowances", **body), a, sv


def test_pv2_allowance_names_the_view(client, owner, tmp_path):
    d, rid = _dev(client, owner, tmp_path)
    r, a, page = _allow(d, rid)
    assert r.status_code == 200, r.text
    g = _get(owner, rid)
    assert g["status"] == "covered" and g["view_signed"] is True and g["view_signed_sha256"] == page.hex()
    [b] = [b for b in _entries(client.app, owner.account["id"], "ALLOWANCE") if b["allowance"]["id"] == a["id"]]
    assert b["allowance"]["view"] == page
    assert d.verdicts("pytest -q") == [("Bash", "allow", "OK_ALLOWANCE")]          # the permission works as before


def test_pv2_allowance_changed_view_and_mismatches_are_refused(client, owner, tmp_path):
    d, rid = _dev(client, owner, tmp_path)
    g = _get(owner, rid)
    _bump(client.app, rid)
    r, _, _ = _allow(d, rid, g=g)
    assert r.status_code == 409 and r.json()["error"] == "VIEW_CHANGED", r.text
    for sv, nv in ((None, "page"), ("page", None), (b"\x02" * 32, "page")):
        r, _, _ = _allow(d, rid, sign_view=sv, send_view=nv)
        assert r.status_code == 409 and r.json()["error"] == "ALLOWANCE_MISMATCH", (sv, nv, r.text)
    r, _, _ = _allow(d, rid, sign_view=b"\x03" * 31, send_view=None)              # not 32 bytes: the core schema refuses the map
    assert r.status_code == 409 and r.json()["error"] == "ALLOWANCE_MALFORMED", r.text
    assert row(client, rid)["status"] == "pending_approval"
    assert client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM allowances")["n"] == 0


def test_pv2_allowance_from_an_older_page_is_marked(client, owner, tmp_path):
    d, rid = _dev(client, owner, tmp_path)
    r, a, _ = _allow(d, rid, sign_view=None, send_view=None)
    assert r.status_code == 200, r.text
    assert _get(owner, rid)["view_signed"] is False


def test_pv2_core_schema_allowance_view():
    from svidetel_v4.schema import validate_allowance
    a = {"v": "deus-aar-0.1", "t": "allowance", "id": "al_x", "mandate": b"\x00" * 32, "class": "command", "commands": ["pytest"],
         "project": "/p", "nbf": 1, "exp": 2}
    assert validate_allowance(a) is None and validate_allowance(dict(a, view=b"\x01" * 32)) is None
    assert validate_allowance(dict(a, view=b"\x01" * 31)) == "view" and validate_allowance(dict(a, view="01" * 32)) == "view"
    assert validate_allowance(dict(a, other=1)) == "members"


# ============================================================ the pack shows every path

def test_pv2_pack_lists_views_of_every_path(app, tmp_path):
    import os
    import subprocess
    from tests.recovery_helpers import Person, export_to, run_verify
    from tests.test_allowance_0210 import Dev
    p = Person(app).register("Pat")
    ag, hdr, rids = _night(p, 2)
    r, pages = _batch(p, rids)
    assert r.status_code == 200, r.text
    proj = tmp_path / "proj"
    proj.mkdir()
    d = Dev(p.c, p, proj.resolve())
    [(tool, x)] = d.send("pytest -q")
    r, a, apage = _allow(d, x["rid"])
    assert r.status_code == 200, r.text
    folder = export_to(p.c, tmp_path / "pack")
    rc, out = run_verify(folder, "--offline")
    assert rc == 0 and "RESULT: VALID" in out, out
    for rid, page in zip(rids, pages):
        assert "approval %s (approved): view sha256 %s" % (rid, page.hex()) in out, out
    assert "allowance %s: view sha256 %s" % (a["id"], apage.hex()) in out, out
    assert "approval views: 3 signed, 0 not signed" in out, out
    mcp = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "mcp")
    py = os.path.join(mcp, ".venv", "bin", "python")
    if not os.path.exists(py):
        pytest.skip("no mcp/.venv")
    q = subprocess.run([py, "-m", "deus_witness.verify_pack", folder, "--offline"], capture_output=True, text=True, timeout=120, cwd=mcp)
    out2 = q.stdout + q.stderr
    assert q.returncode == 0 and "RESULT: VALID" in out2 and "allowance %s: view sha256 %s" % (a["id"], apage.hex()) in out2, out2


# ============================================================ the race: the view check and the decision under ONE lock

def _spy(app, seen):
    """wrap ctx.view_match: record whether the calling thread holds the account's hub.lock while the view is compared"""
    ctx = ctx_of(app)
    orig = ctx.view_match

    def spy(acc, rid, user, got):
        seen.append(ctx.hub.lock(acc["id"])._is_owned())
        return orig(acc, rid, user, got)
    ctx.view_match = spy
    return orig


@pytest.mark.parametrize("path", ["single", "batch", "repeat", "allowance", "release"])
def test_pv2_view_is_compared_under_the_decision_lock(client, owner, tmp_path, path):
    seen = []
    orig = _spy(client.app, seen)
    try:
        if path == "single":
            from tests.test_pv2810_view import _approve, _pending
            a, rid = _pending(client, owner, tmp_path)
            r, _ = _approve(owner, rid)
        elif path == "batch":
            ag, hdr, rids = _night(owner, 2)
            r, _ = _batch(owner, rids)
        elif path == "repeat":
            ag, hdr = owner.new_agent("demo", "night")
            owner.mandate(ag["id"])
            r, _, _ = _later(owner, act(client, hdr, "publish", ARGS).json()["rid"])
        elif path == "allowance":
            d, rid = _dev(client, owner, tmp_path)
            r, _, _ = _allow(d, rid)
        else:
            from tests.test_pv2810_view import _held, _release
            a, rid = _held(client, owner, tmp_path)
            r, _ = _release(owner, rid)
        assert r.status_code == 200, r.text
        assert seen and all(seen), seen                                          # every comparison ran inside the decision's lock
    finally:
        client.app.state.ctx.view_match = orig


def test_pv2_team_quorum_view_is_compared_under_the_lock(app):
    owner, bob, carol, hdr, rid = _team_purchase(app)
    seen = []
    orig = _spy(app, seen)
    try:
        r, _ = _team_approve(owner, rid)
        assert r.json()["verdict"] == "collecting"
        r = bob.sign_req(_sid(app, rid))
        assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
        assert len(seen) >= 2 and all(seen), seen
    finally:
        ctx_of(app).view_match = orig


def test_pv2_race_a_change_between_check_and_entry_cannot_slip_in(client, owner, tmp_path):
    """A writer that changes the row under the account's lock (here: a second decision, a refusal from another tab) starts at the very
    moment the view has just been compared. Before pv2 the comparison ran BEFORE the lock: the refusal could land between the check
    and the entry. Now the writer waits for the lock: the approval is written from exactly the rows whose view was compared, and the
    concurrent refusal gets NOT_DEFERRED afterwards."""
    from tests.test_pv2810_view import _approve, _pending
    a, rid = _pending(client, owner, tmp_path)
    ctx = ctx_of(client.app)
    orig = ctx.view_match
    other = {}
    g = _get(owner, rid)
    refuse_pay = approval_payload(g["mandate"], g["action"], rid, False)
    refuse_env = owner.sign(wa.TYP_APPROVAL, refuse_pay)

    from app import actions as A
    from app.context import Err
    acc = ctx.db.one("SELECT * FROM accounts WHERE id=?", (owner.account["id"],))

    def writer():                                    # the decision path itself, in another thread (not through the event loop)
        try:
            other["r"] = A.do_approve(ctx, acc, None, rid, False, wa.b64u_dec(refuse_env))
        except Err as e:
            other["r"] = e.code

    def spy(acc, rid_, user, got):
        out = orig(acc, rid_, user, got)
        t = threading.Thread(target=writer)
        t.start()
        t.join(0.5)                                                              # it cannot get in while we hold the lock
        other["finished_inside"] = not t.is_alive()
        other["t"] = t
        return out
    ctx.view_match = spy
    try:
        r, page = _approve(owner, rid, g=g)
    finally:
        ctx.view_match = orig
    other["t"].join(10)
    assert other["finished_inside"] is False                                     # the second decision waited for the first
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text
    assert other["r"] == "NOT_DEFERRED", other["r"]
    assert _approval(client.app, owner.account["id"], rid)["view"] == page and row(client, rid)["status"] == "approved"


# ============================================================ the page's bytes = the server's (web/test/vectors_view_pv2.json)

def _pv2_vectors():
    import os
    from app import wire
    from svidetel_v4.state import allowance_payload, mandate_hash
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    V = json.load(open(os.path.join(here, "web", "test", "vectors_view_pv2810.json"), encoding="utf-8"))
    h = bytes.fromhex(V["view_sha256"])
    h2 = hashlib.sha256(b"second item").digest()
    al = {"v": "deus-aar-0.1", "t": "allowance", "id": "al_AAAAAAAAAAAAAAAAAAAAAAAAAA", "mandate": mandate_hash(wire.cbor_form(V["mandate"])),
          "class": "command", "commands": ["pytest"], "project": "/home/dev/proj", "nbf": 1761600000, "exp": 1761686400}
    rids = ["r_" + "A" * 26, "r_" + "B" * 26]
    out = {"rid": V["rid"], "view_sha256": V["view_sha256"], "view2_sha256": h2.hex(), "rids": rids,
           "allowance": dict(al, mandate=al["mandate"].hex()),
           "allowance_payload_hex": allowance_payload(dict(al, view=h)).hex(), "allowance_payload_old_hex": allowance_payload(al).hex(),
           "batch_items_hex": [hashlib.sha256(approval_payload(V["mandate"], V["action"], r, True, v)).hexdigest() for r, v in zip(rids, (h, h2))],
           "repeat_items_hex": [hashlib.sha256(approval_payload(V["mandate"], V["action"], r, True, h)).hexdigest() for r in [V["rid"]] + rids]}
    return os.path.join(here, "web", "test", "vectors_view_pv2.json"), out


def test_pv2_vectors_of_the_page_are_current():
    import os
    p, out = _pv2_vectors()
    if os.environ.get("PV2_WRITE_VECTORS") == "1":
        json.dump(out, open(p, "w", encoding="utf-8"), indent=1)
    assert json.load(open(p, encoding="utf-8")) == out


def test_pv2_pack_of_a_one_key_account_with_batch_and_later_runs_is_valid(app, tmp_path):
    """Found on the way (pre-existing): a solo account with ONE passkey that approved a batch (wb) or "for later runs" (wb) got
    `ledger: invalid MANDATE_KEY` from both checkers (the wb registry was used only after key changes). Old pages, no views."""
    import os
    import subprocess
    from tests.recovery_helpers import Person, export_to, run_verify
    p = Person(app).register("Pat")
    ag, hdr, rids = _night(p, 2)
    r, _ = _batch(p, rids, sign_views=None, send_views=None)
    assert r.status_code == 200, r.text
    rid = act(p.c, hdr, "publish", ARGS).json()["rid"]
    r, later, _ = _later(p, rid, sign_view=None, send_view=None)
    assert r.status_code == 200, r.text
    _expire(p.c, rid)
    assert act(p.c, hdr, "publish", ARGS).json()["rid"] == later[0]
    folder = export_to(p.c, tmp_path / "pack")
    rc, out = run_verify(folder, "--offline")
    assert rc == 0 and "RESULT: VALID" in out and "approval views: 0 signed, 4 not signed" in out, out
    mcp = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "mcp")
    py = os.path.join(mcp, ".venv", "bin", "python")
    if not os.path.exists(py):
        pytest.skip("no mcp/.venv")
    q = subprocess.run([py, "-m", "deus_witness.verify_pack", folder, "--offline"], capture_output=True, text=True, timeout=120, cwd=mcp)
    assert q.returncode == 0 and "RESULT: VALID" in q.stdout + q.stderr, q.stdout + q.stderr
