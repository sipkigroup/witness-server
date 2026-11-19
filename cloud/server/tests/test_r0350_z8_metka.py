"""r0350 (машина времени Н3, Z8): метка «файл записал агент» без срока давности.

До r0350 метка жила written_lookback_min (24 ч по стенным часам): ~/Notes/tool.sh, записанный агентом, через 24 ч 1 мин считался
программой человека (kod=chelovek), и владельцу предлагали подписать «Allow from now on ... run your program <файл агента>» --
нарушение r0332 и «подписано = показано». Образец: poligon-lyudi/mashina-vremeni/test_mashina_vremeni.py -k Z8 (L2: тонкий хук ->
TestClient -> create_app, часы подменены в процессе)."""
import json
import os
import time

import pytest

from tests.test_1811_r0348_klyuch import Stand

DAY = 86400
SED = "sed -i '' 's/a/b/' "


class Chasy:
    def __init__(self, t0):
        self.t = float(t0)

    def __call__(self):
        return self.t

    def shift(self, d):
        self.t += d


@pytest.fixture()
def S(tmp_path, monkeypatch):
    ch = Chasy(int(time.time()) // 100 * 100)
    monkeypatch.setattr(time, "time", ch)
    monkeypatch.delenv("DEUS_WITNESS_URL", raising=False)
    s = Stand(tmp_path)
    hub = s.app.state.ctx.hub
    hub.clock = ch
    hub._cache.clear()
    s.chasy = ch
    return s


def B(cmd):
    return ("Bash", {"command": cmd})


def _rule_notes(S):
    S.agent()
    v, offs = S.ask(B(SED + "~/Notes/a.md"), answer="rule")
    g = S.app.state.ctx.db.one("SELECT * FROM allowances WHERE account_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
                               (S.owner.account["id"],))
    assert g is not None and json.loads(g["commands"]) == ["(key) write %s/Notes/" % S.H], (v, offs)


def _run_offer(S, tool):
    before = set(S.pending())
    v = S.hook(B(tool))
    offs = S.offers(before)
    o = next(iter(offs.values()), {})
    return v, o, offs


def _run_key(o):
    return any(isinstance(a, str) and a.startswith("(key) run ") for a in (o.get("klyuch") or []))


def test_z8_agent_file_stays_agent_code_after_24h_and_days(S):
    _rule_notes(S)
    tool = S.H + "/Notes/tool.sh"
    S.chasy.shift(10)
    assert S.hook(("Write", {"file_path": tool, "content": "#!/bin/sh\necho hi\n"})) == "silent"
    with open(tool, "w") as f:
        f.write("#!/bin/sh\necho hi\n")
    os.chmod(tool, 0o755)
    v0, o0, _ = _run_offer(S, tool)
    assert v0 != "silent" and not o0.get("eligible") and not (o0.get("klyuch") or []), o0
    for dt in (24 * 3600 + 60, 3 * DAY):      # as the time machine: +24 h 1 min, then +3 days (the 7-day rule still holds)
        S.chasy.shift(dt)
        v1, o1, offs = _run_offer(S, tool)
        assert v1 != "silent", (dt, v1)
        assert not _run_key(o1), (dt, o1)                 # never "run your program <the agent's file>"
        assert not o1.get("eligible"), (dt, o1)
        assert "agent wrote" in (o1.get("why_not") or ""), (dt, o1)


def test_z8_second_question_never_offers_from_now_on(S):
    """the person approves once (a one-time answer) after 24 h: the next question about the same file still offers no "from now on"."""
    _rule_notes(S)
    tool = S.H + "/Notes/tool.sh"
    S.chasy.shift(10)
    assert S.hook(("Write", {"file_path": tool, "content": "#!/bin/sh\necho hi\n"})) == "silent"
    with open(tool, "w") as f:
        f.write("#!/bin/sh\necho hi\n")
    os.chmod(tool, 0o755)
    S.chasy.shift(24 * 3600 + 60)
    v1, o1, offs = _run_offer(S, tool)
    S.owner.approve(next(iter(offs)))
    S.hook(B(tool))
    S.chasy.shift(60)
    v2, o2, _ = _run_offer(S, tool)
    assert v2 != "silent" and not o2.get("eligible") and not _run_key(o2), o2


def test_z8_mark_lookup_on_index(S):
    """the agent's writes are read on an index (agent_id, updated_at): ix_actions_wa / ix_actions_agent_upd, with no lower time bound, not on the agent's whole book."""
    db = S.app.state.ctx.db
    plan = db.q("EXPLAIN QUERY PLAN SELECT rid FROM actions WHERE agent_id=? AND updated_at>=? AND status IN (?,?) "
                "AND exec_json LIKE '%\"wa\"%' ORDER BY updated_at DESC, rowid DESC LIMIT 2001", ("a", 0, "x", "y"))
    assert any(("ix_actions_wa" in str(tuple(r)) or "ix_actions_agent_upd" in str(tuple(r))) and "agent_id=? AND updated_at>?" in str(tuple(r))
               for r in plan), [tuple(r) for r in plan]
    from app import actions as A
    assert A.WA_MARK_SINCE == 0
