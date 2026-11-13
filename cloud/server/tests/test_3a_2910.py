"""RT-0269 p.3a: after a Reject the agent rewrites the risky file with a harmless Write; the next run must not show the old text."""
from tests.test_0224_critique import Agent
from tests.test_r25_s8 import _release, _rid, _page, _writes, PY_NET
from tests.test_late_release_2910 import _db

T2 = "print('second harmless version')\n"


def _bump(a):
    _db(a).x("UPDATE actions SET updated_at=updated_at-5, created_at=created_at-5 WHERE agent_id=?", (a.ag["id"],))


def _reject_first(a):
    a.tool("Write", {"file_path": a.proj + "/f.py", "content": PY_NET})
    v, parts = a.line("python3 f.py ")
    assert v == "ASK", parts
    rid = _rid(parts)
    assert "urlopen" in (_writes(_page(a, rid))["f.py"].get("text") or "")
    _release(a, rid, yes=False)
    _bump(a)


def test_3a_harmless_write_replaces_text_and_clears_mark(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    _reject_first(a)
    a.tool("Write", {"file_path": a.proj + "/f.py", "content": T2})
    v, parts = a.line("python3 f.py ")
    if v != "ALLOW":                       # whatever the reason, the page must not carry the old text
        w = _writes(_page(a, _rid(parts))).get("f.py") or {}
        assert "urlopen" not in (w.get("text") or "")
    assert v == "ALLOW", parts


def test_3a_edit_keeps_mark_but_not_old_text(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    _reject_first(a)
    a.tool("Edit", {"file_path": a.proj + "/f.py", "old_string": "health", "new_string": "ok"})
    v, parts = a.line("python3 f.py ")
    assert v == "ASK", parts               # a partial edit: the rest of the file is unknown, the mark stays
    w = _writes(_page(a, _rid(parts)))["f.py"]
    assert "urlopen" not in (w.get("text") or "")


def test_3a_shell_write_without_text_keeps_mark(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    _reject_first(a)
    a.line("cp /tmp/rt0269-other.py f.py")
    v, parts = a.line("python3 f.py ")
    assert v == "ASK", parts
    w = _writes(_page(a, _rid(parts)))["f.py"]
    assert "urlopen" not in (w.get("text") or "")
