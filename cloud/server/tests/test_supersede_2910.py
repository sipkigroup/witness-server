"""RT-SUPERSEDE 29.10: the replacement of a team approval request on a changed view (org.approval_request, pvh 28.10).
(1) a cap: from 3 replacements of signed requests on, a 4th is refused (409 VIEW_UNSTABLE, WARN in the server log), nothing is decided;
(2) visibility: old request -> superseded_by + why, new -> replaces + dropped signers, in GET /api/sig-requests/{id} and in the answer of
    POST /api/approvals/{rid}; the push of a replacement is its own kind ("v": the view changed, sign again);
(3) guard: no lever of the AGENT moves the view of a pending call (repeat, final poll, other calls, the scrub of kept write texts);
(4) hub.lock is per process: a second server process on the same data dir is refused at start, a forked process may not take it."""
import json
import os
import subprocess
import sys
import time

import pytest

from app import actions
from app import hub as hubmod
from svidetel_v4.state import approval_payload
import wa_profile as wa
from tests.org_helpers import ctx_of
from tests.test_0224_critique import row
from tests.test_pv2_view import _team_purchase, _team_approve, _get, _page, _sid, _approval, _bump


class FakePush:
    def __init__(self):
        self.sigreq = []

    def notify_sigreq(self, acc, sid, k="s"):
        self.sigreq.append((sid, k))

    def __getattr__(self, n):
        return lambda *a, **kw: None


def _reqs(app, rid):
    return [dict(r) for r in ctx_of(app).db.q("SELECT id, status, sigs, meta FROM sig_requests WHERE kind='approval' AND ref=? ORDER BY rowid", (rid,))]


def _view_cols(app, rid):
    """the row fields the view (signview.KEYS) is built from"""
    r = ctx_of(app).db.one("SELECT * FROM actions WHERE rid=?", (rid,))
    return {k: r[k] for k in r.keys() if k not in ("updated_at", "gave_up_at", "polled_at")}


def _refuse(p, rid):
    g = _get(p, rid)
    page = _page(g)
    env = p.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], rid, False, page))
    return p.post("/api/approvals/" + rid, approved=False, envelope_b64=env, view_sha256=page.hex())


# ------------------------------------------------------------------ (1) the cap
def test_supersede_is_capped_at_three(app, capsys):
    owner, bob, carol, hdr, rid = _team_purchase(app)
    ctx = ctx_of(app)
    base = ctx.db.one("SELECT args_preview FROM actions WHERE rid=?", (rid,))["args_preview"]
    out = []
    for i, flip in enumerate((0, 1, 0, 1, 0, 0)):                      # the last two: the view stays off the open request's (B)
        ctx.db.x("UPDATE actions SET args_preview=? WHERE rid=?", (base + (" (B)" if flip else ""), rid))
        r, _ = _team_approve((owner, bob)[i % 2], rid)
        out.append((r.status_code, r.json().get("error") or r.json().get("verdict")))
    # round 0 opens, rounds 1-3 replace (3 replacements of a signed request), round 4 on: refused
    assert out[:4] == [(200, "collecting")] * 4, out
    assert out[4:] == [(409, "VIEW_UNSTABLE")] * 2, out
    sup = [q for q in _reqs(app, rid) if q["status"] == "superseded"]
    assert len(sup) == 3                                               # the refusal replaced nothing
    assert row(owner.c, rid)["status"] == "pending_approval" and _approval(app, owner.uid, rid) is None
    logs = [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]
    assert any(x["level"] == "WARN" and "VIEW_UNSTABLE" in x["msg"] and x.get("rid") == rid for x in logs), logs
    r = _refuse(owner, rid)                                            # refusing stays open: the safe direction
    assert r.status_code == 200 and r.json()["verdict"] == "refused", r.text


# ------------------------------------------------------------------ (2) visibility
def test_supersede_is_visible_on_both_requests_and_in_the_answer(app):
    owner, bob, carol, hdr, rid = _team_purchase(app)
    ctx = ctx_of(app)
    fp = FakePush()
    ctx.push = fp
    r, v1 = _team_approve(owner, rid)
    assert r.json()["verdict"] == "collecting" and "replaced" not in r.json(), r.text
    sid1 = _sid(app, rid)
    assert fp.sigreq == [(sid1, "s")]                                  # an ordinary request: the ordinary push
    _bump(app, rid)
    r, v2 = _team_approve(bob, rid)
    sid2 = _sid(app, rid)
    j = r.json()
    assert j["verdict"] == "collecting" and j["req_id"] == sid2 and j["replaced"] == sid1, j
    assert j["dropped"] == [owner.auth.kid.hex()], j
    old = owner.c.get("/api/sig-requests/" + sid1).json()
    assert old["status"] == "superseded" and old["meta"]["superseded_by"] == sid2 and old["meta"]["why"] == "view_changed", old
    new = bob.c.get("/api/sig-requests/" + sid2).json()
    assert new["meta"]["replaces"] == sid1 and new["meta"]["dropped"] == [owner.auth.kid.hex()], new
    assert fp.sigreq[-1] == (sid2, "v")                                 # the replacement's push: "the view changed, sign again"
    r = owner.sign_req(sid2)
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text


def test_push_of_a_replacement_carries_its_own_kind(app, monkeypatch):
    from app import push as P
    ctx = ctx_of(app)
    assert isinstance(ctx.push, P.Pusher)
    monkeypatch.setattr(P.Pusher, "enabled", property(lambda self: True))
    q = []
    ctx.push.q.put = q.append
    ctx.push._ensure_worker = lambda: None
    ctx.push.notify_sigreq("acc", "sr_00ff", k="v")
    ctx.push.notify_sigreq("acc", "sr_00fe")
    assert [n["payload"]["k"] for n in q] == ["v", "s"]
    ctx.push.notify_sigreq("acc", "sr_00fd", k="<x>")                   # anything else: the ordinary kind
    assert q[-1]["payload"]["k"] == "s"


# ------------------------------------------------------------------ (3) guard: the agent has no lever on the view of a pending call
def test_guard_agent_actions_do_not_move_a_pending_view(app):
    owner, bob, carol, hdr, rid = _team_purchase(app)
    ctx = ctx_of(app)
    r, v1 = _team_approve(owner, rid)
    assert r.json()["verdict"] == "collecting", r.text
    cols = _view_cols(app, rid)
    agent_id = ctx.db.one("SELECT agent_id FROM actions WHERE rid=?", (rid,))["agent_id"]
    c = owner.c
    for _ in range(3):                                                 # the same call again (the hook retries)
        rr = c.post("/v1/actions", json={"tool": "purchase", "args": {"vendor": "v.example", "amount_cents": 70000}}, headers=hdr)
        assert rr.status_code in (200, 409, 429), rr.text
    c.get("/v1/actions/" + rid + "?final=1", headers=hdr)              # the hook's last poll (gave up)
    c.get("/v1/actions/" + rid, headers=hdr)                           # and polls again
    for args in ({"vendor": "w.example", "amount_cents": 90000}, {"vendor": "v.example", "amount_cents": 70001}):
        c.post("/v1/actions", json={"tool": "purchase", "args": args}, headers=hdr)     # other calls
    actions.scrub_written_texts(ctx, agent_id, before=int(time.time()) + 10 ** 6)      # the scrub of kept write texts (wrun)
    actions.scrub_written_texts(ctx, agent_id, files={"/tmp/x", "a.py"})
    assert _page(_get(bob, rid)) == v1                                 # the view every signer sees: unchanged
    assert _view_cols(app, rid) == cols, "an agent action wrote into the row of a pending call"
    assert [q["status"] for q in _reqs(app, rid)] == ["collecting"]
    r, _ = _team_approve(bob, rid)
    assert r.json()["verdict"] == "allow", r.text
    assert len(_reqs(app, rid)) == 1


# ------------------------------------------------------------------ (4) hub.lock: one process
def test_hub_lock_refused_in_a_forked_process(app):
    h = ctx_of(app).hub
    h.lock("x")                                                        # this process: fine
    pid = h._pid
    try:
        h._pid = -1                                                    # as seen from a child forked after start
        with pytest.raises(RuntimeError):
            h.lock("x")
    finally:
        h._pid = pid


def test_second_server_process_on_the_same_data_dir_is_refused(tmp_path):
    d = str(tmp_path)
    hubmod.claim_data_dir(d)                                           # this process holds it
    hubmod.claim_data_dir(d)                                           # again in the same process (a test app restarted): fine
    code = ("import sys; sys.path.insert(0, %r); from app import hub\n"
            "try:\n    hub.claim_data_dir(%r)\nexcept hub.DataDirBusy:\n    sys.exit(3)\nsys.exit(0)") % (os.getcwd(), d)
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, env=dict(os.environ, PYTHONPATH=os.getcwd()))
    assert p.returncode == 3, p.stdout + p.stderr
