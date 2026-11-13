"""rel 28.10: the ledger (files) and the rows (SQLite) share no transaction. (1) A release stores its request (kind release, status done) only
AFTER the core decided, in one transaction with the row: an exception of the core or of the row write leaves no "done" release. (2) An
approval's rows are written in one transaction; a retry after "ledger written, row not" brings the row in line (409 ALREADY_DECIDED) and
writes nothing to the ledger. (3) On start, held / pending_approval rows whose id the ledger already judged follow the ledger, or are
marked for a person (column reconcile); nothing is executed again, nothing is appended to the ledger."""
import json

from fastapi.testclient import TestClient

from app import wire
from app.main import create_app
from svidetel_v4 import cose
from tests.helpers import ORIGIN
from tests.test_0224_critique import row
from tests.test_pv2810_view import _held, _pending, _release, _approve


def _releases(client, rid, status=None):
    q = "SELECT COUNT(*) AS n FROM sig_requests WHERE kind='release' AND ref=?" + (" AND status=?" if status else "")
    return client.app.state.ctx.db.one(q, (rid, status) if status else (rid,))["n"]


def _ledger(client, owner):
    L = client.app.state.ctx.hub.ledger(owner.account["id"])
    L.sync_now()
    return L


def _restart(client):
    """A new process on the same data directory (database + ledger files): create_app runs the start reconciliation."""
    app2 = create_app(client.app.state.ctx.cfg)
    return TestClient(app2, base_url=ORIGIN, raise_server_exceptions=False)


def _fail_sql(monkeypatch, client, prefix):
    db = client.app.state.ctx.db
    orig = db.x

    def x(sql, args=()):
        if sql.lstrip().startswith(prefix):
            raise RuntimeError("disk full (test)")
        return orig(sql, args)
    monkeypatch.setattr(db, "x", x)
    return lambda: monkeypatch.setattr(db, "x", orig)


def _lenient(client, owner):
    owner.c = TestClient(client.app, base_url=ORIGIN, raise_server_exceptions=False, cookies=owner.c.cookies)


# ---------------------------------------------------------------- (1) release: nothing "done" before the core decided
def test_rel_core_exception_on_release_leaves_no_done_release(client, owner, tmp_path, monkeypatch):
    a, rid = _held(client, owner, tmp_path)
    L = _ledger(client, owner)

    def boom(*a_, **k):
        raise OSError("ledger volume gone (test)")
    monkeypatch.setattr(L, "authorize", boom)
    _lenient(client, owner)
    r, _ = _release(owner, rid)
    assert r.status_code == 503 and r.json()["error"] == "DECISION_NOT_STORED", r.text
    assert _releases(client, rid) == 0                       # was: a "done" release request (in the evidence pack, export.py)
    assert row(client, rid)["status"] == "held" and rid not in L.S.receipts


def test_rel_row_write_failure_after_core_leaves_no_done_release(client, owner, tmp_path, monkeypatch):
    a, rid = _held(client, owner, tmp_path)
    _lenient(client, owner)
    undo = _fail_sql(monkeypatch, client, "UPDATE actions SET verdict=?")
    r, _ = _release(owner, rid)
    undo()
    assert r.status_code == 503 and r.json()["error"] == "DECISION_NOT_STORED", r.text
    assert _releases(client, rid) == 0                       # the request and the row are one transaction: rolled back together
    L = _ledger(client, owner)
    assert row(client, rid)["status"] == "held" and rid in L.S.receipts      # ledger written, row not
    r2, _ = _release(owner, rid)
    assert r2.status_code == 409 and r2.json()["error"] == "HELD_ALREADY_JUDGED", r2.text
    # restart: the core ALLOWED it, but neither that AAR nor the person's release signature is in the rows -> a person decides
    c2 = _restart(client)
    n0 = L.S.nseq
    x = row(c2, rid)
    assert x["status"] == "held" and x["reconcile"] == "manual:held_allowed_in_ledger", dict(x)
    assert x["aar"] is None and _releases(c2, rid) == 0
    L2 = c2.app.state.ctx.hub.ledger(owner.account["id"])
    L2.sync_now()
    assert L2.S.nseq == n0                                   # nothing appended on start
    r3, _ = _release(owner, rid, rel=False)                  # the owner can still clear it
    assert r3.status_code == 200 and row(client, rid)["status"] == "denied", r3.text


def test_rel_reject_writes_request_and_row_together(client, owner, tmp_path, monkeypatch):
    a, rid = _held(client, owner, tmp_path)
    _lenient(client, owner)
    undo = _fail_sql(monkeypatch, client, "UPDATE actions SET status='denied'")
    r, _ = _release(owner, rid, rel=False)
    undo()
    assert r.status_code >= 500 and _releases(client, rid) == 0 and row(client, rid)["status"] == "held", r.text
    r2, _ = _release(owner, rid, rel=False)
    assert r2.status_code == 200 and _releases(client, rid, "done") == 1 and row(client, rid)["status"] == "denied", r2.text


# ---------------------------------------------------------------- (3) start: held rows whose id the ledger already judged
def test_rel_start_held_with_deny_receipt_becomes_denied(client, owner, tmp_path):
    a, rid = _held(client, owner, tmp_path)
    L = _ledger(client, owner)
    x = row(client, rid)
    L.authorize(rid, "m_unknown", wire.cbor_form(json.loads(x["action_json"])), ttl=300, audience="tool")     # the core refused (no mandate)
    assert L.S.receipts[rid]["verdict"] == "deny"
    c2 = _restart(client)
    y = row(c2, rid)
    assert y["status"] == "denied" and y["verdict"] == "deny" and y["reason"] == L.S.receipts[rid]["reason"], dict(y)
    assert y["reconcile"] == "ledger:denied" and y["aar"] is None and _releases(c2, rid) == 0


def test_rel_start_held_with_defer_receipt_becomes_a_question(client, owner, tmp_path):
    a, rid = _pending(client, owner, tmp_path)               # judged by the core: DEFER receipt in the ledger
    client.app.state.ctx.db.x("UPDATE actions SET status='held', reason='ADVISORY_HOLD', hold_reason='ADVISORY_HOLD' WHERE rid=?", (rid,))
    c2 = _restart(client)
    y = row(c2, rid)
    assert y["status"] == "pending_approval" and y["verdict"] == "defer" and y["reconcile"] == "ledger:pending", dict(y)
    owner.c = TestClient(c2.app, base_url=ORIGIN, cookies=owner.c.cookies)
    r, _ = _approve(owner, rid)                              # the person still decides (second human gate)
    assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text


def test_rel_start_leaves_consistent_rows_and_the_ledger_alone(client, owner, tmp_path):
    a, rid = _pending(client, owner, tmp_path)
    a2, hid = _held(client, owner, tmp_path / "h")
    L = _ledger(client, owner)
    n0 = L.S.nseq
    c2 = _restart(client)
    assert row(c2, rid)["status"] == "pending_approval" and row(c2, rid)["reconcile"] is None
    assert row(c2, hid)["status"] == "held" and row(c2, hid)["reconcile"] is None
    L2 = c2.app.state.ctx.hub.ledger(owner.account["id"])
    L2.sync_now()
    assert L2.S.nseq == n0


# ---------------------------------------------------------------- (2) approval: "ledger written, row not"
def _crash_approval(client, owner, tmp_path, monkeypatch, approved):
    a, rid = _pending(client, owner, tmp_path)
    _lenient(client, owner)
    undo = _fail_sql(monkeypatch, client, "UPDATE actions SET status=" + ("'approved'" if approved else "'refused'"))
    r, _ = _approve(owner, rid, approved=approved)
    undo()
    assert r.status_code == 503 and r.json()["error"] == "DECISION_NOT_STORED", r.text
    L = _ledger(client, owner)
    assert (rid in L.aseq) if approved else (rid in L.S.refused)
    x = row(client, rid)
    assert x["status"] == "pending_approval"
    assert client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM approvals WHERE rid=?", (rid,))["n"] == 0     # one transaction
    return rid, L


def test_rel_approve_retry_after_crash_follows_the_ledger(client, owner, tmp_path, monkeypatch):
    rid, L = _crash_approval(client, owner, tmp_path, monkeypatch, True)
    n0 = L.S.nseq
    r, _ = _approve(owner, rid)                              # was: 409 NOT_DEFERRED forever, the row stuck pending without an AAR
    assert r.status_code == 409 and r.json()["error"] == "ALREADY_DECIDED", r.text
    x = row(client, rid)
    assert x["status"] == "approved" and x["reason"] == "OK_APPROVED" and x["reconcile"] == "ledger:approved", dict(x)
    p = cose.loads(cose.verify1(bytes(x["aar"]), [L.wk], cose.TYP_AAR)[0])
    assert p["verdict"]["reason"] == "OK_APPROVED"
    ap = client.app.state.ctx.db.one("SELECT * FROM approvals WHERE rid=?", (rid,))
    assert ap["approved"] == 1 and ap["ledger_seq"] == L.aseq[rid] and ap["envelope"] is not None
    L.sync_now()
    new = [cose.loads(cose.verify1(raw, [L.wk], cose.TYP_ENTRY)[0])["type"] for raw in L.raws[n0:]]
    assert set(new) <= {"CHECKPOINT"}, new                   # no second APPROVAL entry (the proof's checkpoint only, as on every approval)


def test_rel_approve_retry_with_the_opposite_decision_keeps_the_ledger(client, owner, tmp_path, monkeypatch):
    rid, L = _crash_approval(client, owner, tmp_path, monkeypatch, False)
    r, _ = _approve(owner, rid, approved=True)
    assert r.status_code == 409 and r.json()["error"] == "ALREADY_DECIDED", r.text
    x = row(client, rid)
    assert x["status"] == "refused" and x["verdict"] == "deny" and x["aar"] is None, dict(x)


def test_rel_start_after_approval_crash_follows_the_ledger(client, owner, tmp_path, monkeypatch):
    rid, L = _crash_approval(client, owner, tmp_path, monkeypatch, True)
    c2 = _restart(client)
    x = row(c2, rid)
    assert x["status"] == "approved" and x["reconcile"] == "ledger:approved" and x["aar"] is not None and x["proof_json"], dict(x)


# ---------------------------------------------------------------- rec 29.10: manual rows are not re-reconciled; on_allowed in the decision's tx
def test_rec_start_skips_manual_rows_and_leaves_them_unchanged(client, owner, tmp_path, monkeypatch):
    from app import actions
    a, rid = _held(client, owner, tmp_path)
    _lenient(client, owner)
    undo = _fail_sql(monkeypatch, client, "UPDATE actions SET verdict=?")
    _release(owner, rid)
    undo()
    c2 = _restart(client)
    x = dict(row(c2, rid))
    assert x["reconcile"] == "manual:held_allowed_in_ledger"
    seen = []
    orig = actions.reconcile_row
    monkeypatch.setattr(actions, "reconcile_row", lambda ctx, L, r: (seen.append(r["rid"]), orig(ctx, L, r))[1])
    logs = []
    monkeypatch.setattr(actions, "log", lambda lvl, msg, **kw: logs.append((lvl, msg)))
    c3 = _restart(c2)
    assert rid not in seen
    assert not [m for m in logs if m[0] == "ERROR" and "disagree" in m[1]]
    assert dict(row(c3, rid)) == x


def test_rec_approval_and_dirty_mark_are_one_transaction(client, owner, tmp_path, monkeypatch):
    from app import execguard
    a, rid = _pending(client, owner, tmp_path)
    _lenient(client, owner)

    def boom(ctx, r):
        raise RuntimeError("crash between decision and mark (test)")
    monkeypatch.setattr(execguard, "on_allowed", boom)
    r, _ = _approve(owner, rid, approved=True)
    assert r.status_code == 503, r.text
    n = client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM approvals WHERE rid=?", (rid,))["n"]
    assert n == 0 and row(client, rid)["status"] == "pending_approval"      # decision and mark: both or neither


def test_rec_release_and_dirty_mark_are_one_transaction(client, owner, tmp_path, monkeypatch):
    from app import execguard
    a, rid = _held(client, owner, tmp_path)
    _lenient(client, owner)

    def boom(ctx, r):
        raise RuntimeError("crash between decision and mark (test)")
    monkeypatch.setattr(execguard, "on_allowed", boom)
    r, _ = _release(owner, rid)
    assert r.status_code == 503, r.text
    assert _releases(client, rid) == 0 and row(client, rid)["status"] == "held"


def _marking_boom(monkeypatch):
    """on_allowed that writes its mark and then fails: the mark must not outlive the failed decision."""
    from app import execguard

    def boom(ctx, r):
        ctx.db.x("INSERT INTO exec_files(agent_id,path,digest,state,rid,updated_at) VALUES(?,?,?,?,?,?)",
                 (r["agent_id"], "/mark-test", "", "dirty", r["rid"], 1))
        raise RuntimeError("crash after the mark (test)")
    monkeypatch.setattr(execguard, "on_allowed", boom)


def _marks(client):
    return client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM exec_files WHERE path='/mark-test'")["n"]


def test_rec_reconcile_approval_and_dirty_mark_are_one_transaction(client, owner, tmp_path, monkeypatch):
    rid, L = _crash_approval(client, owner, tmp_path, monkeypatch, True)
    _marking_boom(monkeypatch)
    c2 = _restart(client)
    assert _marks(c2) == 0
    assert c2.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM approvals WHERE rid=?", (rid,))["n"] == 0
    assert row(c2, rid)["status"] == "pending_approval"


def test_rec_allowed_call_row_and_dirty_mark_are_one_transaction(client, owner, tmp_path, monkeypatch):
    from tests.test_pv2810_view import Agent
    a = Agent(client, owner, tmp_path)
    _marking_boom(monkeypatch)
    try:
        a.tool("Write", {"file_path": a.proj + "/tests/test_new.py", "content": "def test_n():\n    pass\n"})
    except Exception:  # noqa: BLE001 -- fail closed: the call is not answered
        pass
    assert _marks(client) == 0                               # the mark rolled back with the failed insert
    assert client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM actions WHERE agent_id=?", (a.ag["id"],))["n"] == 1   # the row is kept
