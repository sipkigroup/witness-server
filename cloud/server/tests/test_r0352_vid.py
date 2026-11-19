"""r0352 (KAND-ACH-1, polygon "attack on the person" 18.11, ataka-na-cheloveka/ITOGI.md B3 / B3s / B7d / B7e / B8): a go-between cut
view_sha256 out of GET /api/approvals/{rid}; the page then signed the bare format while it showed a text of the go-between's choosing,
and the server accepted it as "an older page". Now: when the witness can build the view of the request, a decision that names no view
is refused (409 VIEW_REQUIRED) on EVERY path -- approval, refusal, release / reject of a hold, batch, later runs (also after expiry),
project permission, a team's request -- and nothing is decided. The r0277 "older page" hash (the view without "omitted") is refused too.
Held as before: a changed view (VIEW_CHANGED), a view claimed but not signed or signed but not claimed (WB_ITEM / ALLOWANCE_MISMATCH)."""
import hashlib
import json
import os

from app import signview
from svidetel_v4.state import approval_payload
import wa_profile as wa
from tests.helpers import act
from tests.test_0224_critique import Agent, row
from tests.test_pv2_view import (_allow, _batch, _dev, _expire, _get, _later, _night, _team_approve, _team_purchase, _page)
from tests.test_pv2810_view import _approve, _held, _pending, _release
from tests import viewkit


def _err(r):
    try:
        return r.json().get("error")
    except ValueError:
        return None


def test_offered_view_is_present_on_every_waiting_request(client, owner, tmp_path):
    a, rid = _pending(client, owner, tmp_path)
    g = _get(owner, rid)
    assert isinstance(g.get("view_sha256"), str) and len(g["view_sha256"]) == 64


def test_b3_single_approval_without_view_is_refused(client, owner, tmp_path):
    a, rid = _pending(client, owner, tmp_path)
    r, _ = _approve(owner, rid, sign_view=None, send_view=None)                 # the bare format, no claim: the downgraded page
    assert r.status_code == 409 and _err(r) == "VIEW_REQUIRED", r.text
    assert row(client, rid)["status"] == "pending_approval"
    r, _ = _approve(owner, rid)                                                  # the honest page still decides
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text


def test_b3_refusal_without_view_is_refused_too(client, owner, tmp_path):
    a, rid = _pending(client, owner, tmp_path)
    r, _ = _approve(owner, rid, approved=False, sign_view=None, send_view=None)
    assert r.status_code == 409 and _err(r) == "VIEW_REQUIRED", r.text
    assert row(client, rid)["status"] == "pending_approval"


def test_b3_the_view_without_omitted_is_no_longer_accepted(client, owner, tmp_path):
    """A go-between that cuts "omitted" (what the first screen does not show whole) made a pre-r0277 page sign the legacy hash."""
    a, rid = _pending(client, owner, tmp_path)
    g = _get(owner, rid)
    old = signview.view_hash({k: v for k, v in g.items() if k not in viewkit.X}, legacy=True)
    if old.hex() == g["view_sha256"]:
        return                                                                   # nothing omitted on this answer: the two hashes are one
    r, _ = _approve(owner, rid, sign_view=old, send_view=old)
    assert r.status_code == 409 and _err(r) == "VIEW_CHANGED", r.text
    assert row(client, rid)["status"] == "pending_approval"


def test_release_and_reject_of_a_hold_without_view_are_refused(client, owner, tmp_path):
    a, rid = _held(client, owner, tmp_path)
    for rel in (True, False):
        r, _ = _release(owner, rid, rel, view=None)
        assert r.status_code == 409 and _err(r) == "VIEW_REQUIRED", r.text
    assert row(client, rid)["status"] == "held"
    r, _ = _release(owner, rid, False)
    assert r.status_code == 200, r.text


def test_b8_batch_without_views_is_refused_whole(client, owner):
    ag, hdr, rids = _night(owner)
    r, _ = _batch(owner, rids, sign_views=None, send_views=None)
    assert r.status_code == 409 and _err(r) == "VIEW_REQUIRED", r.text
    assert [row(client, x)["status"] for x in rids] == ["pending_approval"] * 3
    r, _ = _batch(owner, rids)
    assert r.status_code == 200 and [x["verdict"] for x in r.json()["results"]] == ["allow"] * 3, r.text


def test_b8_batch_refusal_without_views_is_refused(client, owner):
    from tests.test_pv2_view import _wb
    ag, hdr, rids = _night(owner, 2)
    gs = [_get(owner, x) for x in rids]
    items = [hashlib.sha256(approval_payload(g["mandate"], g["action"], x, False)).digest() for g, x in zip(gs, rids)]
    r = owner.post("/api/approvals/batch", rids=rids, approved=False, envelope_b64=_wb(owner, items))
    assert r.status_code == 409 and _err(r) == "VIEW_REQUIRED", r.text
    assert [row(client, x)["status"] for x in rids] == ["pending_approval"] * 2


def test_repeat_without_view_is_refused_now_and_after_expiry(client, owner):
    ag, hdr, rids = _night(owner, 2)
    r, later, _ = _later(owner, rids[0], sign_view=None, send_view=None)
    assert r.status_code == 409 and _err(r) == "VIEW_REQUIRED", r.text
    assert row(client, rids[0])["status"] == "pending_approval"
    _expire(client, rids[1])
    g = _get(owner, rids[1])
    assert g["status"] == "expired" and (g.get("repeat_offer") or {}).get("eligible") and g.get("view_sha256"), g
    r, later, _ = _later(owner, rids[1], sign_view=None, send_view=None, late=True)
    assert r.status_code == 409 and _err(r) == "VIEW_REQUIRED", r.text
    assert client.get("/api/repeat-approvals").json()["items"] == []


def test_b7d_b7e_project_permission_without_view_is_refused(client, owner, tmp_path):
    d, rid = _dev(client, owner, tmp_path)
    r, a, _ = _allow(d, rid, sign_view=None, send_view=None)
    assert r.status_code == 409 and _err(r) == "VIEW_REQUIRED", r.text
    assert client.get("/api/allowances").json()["items"] == []
    r, a, _ = _allow(d, rid)
    assert r.status_code == 200, r.text


def test_team_request_without_view_is_refused(app):
    owner, bob, carol, hdr, rid = _team_purchase(app)
    r, _ = _team_approve(owner, rid, sign_view=None, send_view=None)
    assert r.status_code == 409 and _err(r) == "VIEW_REQUIRED", r.text


def test_team_old_request_naming_no_view_cannot_collect_signatures(app):
    """A request opened before r0352 without a view (stored meta without "view") is refused to the next signer and replaced by the page's."""
    from app import org
    from tests.org_helpers import ctx_of
    owner, bob, carol, hdr, rid = _team_purchase(app)
    r, _ = _team_approve(owner, rid)
    assert r.status_code == 200 and r.json()["verdict"] == "collecting", r.text
    db = ctx_of(app).db
    x = db.one("SELECT id, meta FROM sig_requests WHERE kind='approval' AND ref=? AND status='collecting'", (rid,))
    meta = json.loads(x["meta"])
    meta.pop("view", None)
    g = _get(owner, rid)
    bare = approval_payload(g["mandate"], g["action"], rid, True)                # what a request of an older page stored: no view
    db.x("UPDATE sig_requests SET meta=?, payload=? WHERE id=?", (json.dumps(meta), bare, x["id"]))
    r = bob.post("/api/sig-requests/" + x["id"], envelope_b64=bob.sign(wa.TYP_APPROVAL, bare))
    assert r.status_code == 409 and _err(r) == "VIEW_REQUIRED", r.text
    r, _ = _team_approve(bob, rid)                                               # the approval page over the current view replaces it
    assert r.status_code == 200 and r.json().get("replaced") == x["id"], r.text
    assert org is not None


def test_a_decided_call_answers_as_before_without_a_view(client, owner, tmp_path):
    """No view exists for a decided call: the decision path answers NOT_DEFERRED (not VIEW_REQUIRED)."""
    a, rid = _pending(client, owner, tmp_path)
    assert _approve(owner, rid)[0].status_code == 200
    r, _ = _approve(owner, rid, sign_view=None, send_view=None)
    assert r.status_code == 409 and _err(r) == "NOT_DEFERRED", r.text


def test_page_refuses_to_sign_without_the_view():
    """web/js/signview.js: an answer of a waiting request without view_sha256 is "missing" (the page does not sign); approve.js stops."""
    here = os.path.dirname(os.path.abspath(__file__))
    web = os.path.join(here, "..", "..", "web", "js")
    sv = open(os.path.join(web, "signview.js"), encoding="utf-8").read()
    assert "export function viewExpected" in sv and "missing" in sv
    ap = open(os.path.join(web, "approve.js"), encoding="utf-8").read()
    assert "if (sv.missing) {" in ap and "VIEW_MISSING_TEXT" in ap and "e.code === 'VIEW_REQUIRED' ? VIEW_MISSING_TEXT" in ap
    bj = open(os.path.join(web, "batch.js"), encoding="utf-8").read()
    assert "sv.missing || !sv.view" in bj and "all items name their view, or none does" not in bj
