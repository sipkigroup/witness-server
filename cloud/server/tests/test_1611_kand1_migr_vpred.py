"""r1611 (law "Signed = shown"): a "from now on" rule signed before r0327 (no text_v) does not pass silently at its first use.

PREDICTION (written before the run): (1) an old rule (trust_v NULL) + the same command -> verdict ask (ESCALATE_COMMAND), not OK_ALLOWANCE;
the old row ends with end_reason 'text-unsigned-renewed'. (2) answering "from now on" on that question signs a NEW rule with text_v tt-2,
and the next call is silent (OK_ALLOWANCE). (3) a rule with text_v passes silently as before, and is not ended. (4) listing marks the old
rule "text not signed" before use. (5) an old rule does not end for a command it does not cover.
Real server (TestClient), real ledger."""
from app import allowances as al
from tests.test_1611_r0327_tekst_v_podpisi import _old_rule
from tests.test_pv2_view import _allow, _dev


def _items(owner):
    return {x["id"]: x for x in owner.c.get("/api/allowances").json()["items"]}


def test_old_rule_is_asked_then_renewed_with_text(client, owner, tmp_path, monkeypatch):
    d, rid, a, _ = _old_rule(client, owner, tmp_path, monkeypatch)
    it = _items(owner)[a["id"]]
    assert it["text_v"] is None and it["text_signed"] is False and it["note"] == "text not signed" and it["status"] == "active"   # (4)
    [(tool, r)] = d.send("pytest -q")                                                                                           # (1)
    assert r["verdict"] != "allow" and r["reason"] == "ESCALATE_COMMAND", r
    old = _items(owner)[a["id"]]
    assert old["ended_at"] is not None and old["status"] == "text_unsigned_renewed"
    assert client.app.state.ctx.db.one("SELECT end_reason FROM allowances WHERE id=?", (a["id"],))["end_reason"] == "text-unsigned-renewed"
    r2, a2, _ = _allow(d, r["rid"])                                                                                             # (2)
    assert r2.status_code == 200, r2.text
    new = _items(owner)[a2["id"]]
    assert new["text_v"] == "tt-2" and new["text"] == al.TRUST_TEXT and new["text_signed"] is True and new["note"] is None
    assert d.verdicts("pytest -q") == [("Bash", "allow", "OK_ALLOWANCE")]


def test_signed_rule_stays_silent(client, owner, tmp_path):
    d, rid = _dev(client, owner, tmp_path)
    r, a, _ = _allow(d, rid)
    assert r.status_code == 200, r.text
    assert d.verdicts("pytest -q") == [("Bash", "allow", "OK_ALLOWANCE")]                                                       # (3)
    assert _items(owner)[a["id"]]["ended_at"] is None


def test_old_rule_not_ended_by_other_command(client, owner, tmp_path, monkeypatch):
    d, rid, a, _ = _old_rule(client, owner, tmp_path, monkeypatch)
    d.send("ls")                                                                                                                # (5)
    assert _items(owner)[a["id"]]["ended_at"] is None
