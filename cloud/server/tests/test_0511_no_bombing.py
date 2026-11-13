"""05.11 (docs/PRAVILO-VOPROSA.md, prompt bombing): the same question is not asked twice, and a Deny is remembered for the account's window."""
import pytest

from app import actions as A
from tests.helpers import act


def _setup(client, owner, monkeypatch):
    asked = []
    monkeypatch.setattr(client.app.state.ctx.notify, "approval", lambda row: asked.append(row["rid"]))
    ag, hdr = owner.new_agent("demo")
    assert owner.mandate(ag["id"])[1].status_code == 200
    return ag, hdr, asked


def _ask(client, hdr, text="t", ch="b"):
    return act(client, hdr, "publish", {"channel": ch, "text": text}).json()


def test_ten_identical_calls_one_push_one_rid(client, owner, monkeypatch):
    ag, hdr, asked = _setup(client, owner, monkeypatch)
    rids = {_ask(client, hdr)["rid"] for _ in range(10)}
    assert len(rids) == 1 and len(asked) == 1, (rids, asked)
    assert len(owner.c.get("/api/approvals").json()) == 1


def test_merge_is_not_a_permission_for_repeats(client, owner, monkeypatch):
    """I5: one approval is one use; the merged repeats do not turn it into a standing permission."""
    ag, hdr, asked = _setup(client, owner, monkeypatch)
    r = _ask(client, hdr)
    for _ in range(3):
        assert _ask(client, hdr)["rid"] == r["rid"]
    assert owner.approve(r["rid"], approved=True).status_code == 200
    first = _ask(client, hdr)
    assert first["rid"] == r["rid"] and first["status"] == "approved"
    # the approval is spent once the call ran / was presented; a different call is never covered
    other = _ask(client, hdr, text="other")
    assert other["rid"] != r["rid"] and other["status"] == "pending_approval"


def test_deny_then_same_call_refused_silently_with_reason(client, owner, monkeypatch):
    ag, hdr, asked = _setup(client, owner, monkeypatch)
    r = _ask(client, hdr)
    assert owner.approve(r["rid"], approved=False).json()["verdict"] == "refused"
    n = len(asked)
    for _ in range(5):
        again = _ask(client, hdr)
        assert (again["verdict"], again["reason"], again["status"]) == ("deny", "REFUSED", "denied") and again["approval_url"] is None
    assert len(asked) == n and owner.c.get("/api/approvals").json() == []
    other = _ask(client, hdr, ch="c")                        # a materially different call (another target) is asked as usual
    assert other["status"] == "pending_approval" and len(asked) == n + 1


def test_window_ends_after_15_min_and_is_a_setting(client, owner, monkeypatch):
    ctx = client.app.state.ctx
    ag, hdr, asked = _setup(client, owner, monkeypatch)
    assert A.refusal_block_s(ctx, ag["id"]) == 900
    r = _ask(client, hdr)
    owner.approve(r["rid"], approved=False)
    assert _ask(client, hdr)["reason"] == "REFUSED"
    ctx.db.x("UPDATE actions SET updated_at=updated_at-840 WHERE agent_id=? AND status='refused'", (ag["id"],))       # 14 min ago: still refused
    assert _ask(client, hdr)["reason"] == "REFUSED"
    ctx.db.x("UPDATE actions SET updated_at=updated_at-120 WHERE agent_id=? AND status='refused'", (ag["id"],))       # 16 min ago: asked again
    n = len(asked)
    again = _ask(client, hdr)
    assert again["status"] == "pending_approval" and len(asked) == n + 1
    # the account's own window
    acc = ctx.db.one("SELECT account_id FROM agents WHERE id=?", (ag["id"],))["account_id"]
    from app import org
    org.put_settings(ctx, acc, {"refusal_block_s": 3600})
    assert A.refusal_block_s(ctx, ag["id"]) == 3600
    with pytest.raises(Exception):
        org.put_settings(ctx, acc, {"refusal_block_s": 5})


def test_agent_is_told_when_it_may_ask_again(client, owner, monkeypatch):
    from app.hookjudge import judge as hj
    ctx = client.app.state.ctx
    ag, hdr, asked = _setup(client, owner, monkeypatch)
    r = _ask(client, hdr)
    owner.approve(r["rid"], approved=False)
    again = _ask(client, hdr)
    agent = dict(ctx.db.one("SELECT * FROM agents WHERE id=?", (ag["id"],)))
    t = hj.refused_text(ctx, agent, "publish", again)
    assert t and t.startswith("denied by the owner 0 min ago") and "not asking again until" in t and "UTC" in t, t
