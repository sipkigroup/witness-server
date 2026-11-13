"""11.11 (r0261f, release 0.2.59: the last refusal of harmless work on the blind corpus). A Write / Edit of a file in the shared temp of this
computer (/tmp, /private/tmp, /var/tmp -- outside the project and outside Claude Code's own temp root, e.g. `Write /tmp/readme-check/x.mjs`)
was refused RESOURCE with no button: the mandate's targets are the project and the temp roots it names. Now it is a question (asked ONCE,
no "from now on": a shared temp folder is no folder of the person's to widen), not a refusal. Unchanged (adversaries): a place of an
immutable article (~/.zshrc, LaunchAgents, /etc/hosts, ~/.ssh/config) is refused at once; a system folder (/opt, /usr/local), another
user's home, a mounted volume stay RESOURCE; a link in temp that points at a protected place is judged by where it points.
PRED is written before each check (the outcome measured on the code before the change is in the comment)."""
import os
import shutil
import uuid

import pytest

from tests.helpers import CLIENT_UID  # r0279: the tests' one client (uid 501 on every OS)

from app.hookjudge import mapping
from tests.test_0611_popravki import _offers
from tests.test_1111_zakrytyy_spisok import _d, _v
from tests.test_0290_standing import Dev

pytestmark = pytest.mark.standing


def _w(d, tool, p):
    inp = {"file_path": p, "content": "export const x = 1;\n"} if tool == "Write" else {"file_path": p, "old_string": "a", "new_string": "b"}
    return d.send(None, tool=tool, inp=inp)


@pytest.fixture
def tmpdir_shared():
    p = "/tmp/dw-r0261f-%s" % uuid.uuid4().hex[:10]
    yield p
    shutil.rmtree(os.path.realpath(p), ignore_errors=True)


@pytest.mark.parametrize("tool", ["Write", "Edit"])
@pytest.mark.parametrize("tail", ["/readme-check/example.mjs", "/x.md"])
@pytest.mark.parametrize("root", ["/tmp", "/private/tmp", "/var/tmp"])
def test_shared_temp_write_is_asked_once_not_refused(client, owner, tmp_path, monkeypatch, tool, tail, root):
    d = _d(client, owner, tmp_path, monkeypatch, "t")            # the strict fact (the blind corpus ran under it)
    got = _w(d, tool, root + tail)
    PRED = ("defer",)                                              # before: [("deny", "RESOURCE")]
    assert tuple(r["verdict"] for _, r in got) == PRED, _v(got)
    assert got[0][1]["action"]["recipient"].startswith(mapping.OUTSIDE_WRITE), got
    offers = _offers(d, got)
    PRED = [False]                                                 # once: no "from now on" for a shared temp folder
    assert [bool(o and o.get("eligible")) for o in offers] == PRED, offers


def test_shared_temp_write_without_the_strict_fact_is_asked_too(client, owner, tmp_path):
    home = tmp_path / "h2"
    (home / "proj" / "src").mkdir(parents=True)
    d = Dev(client, owner, (home / "proj").resolve(), home=str(home.resolve()))
    got = _w(d, "Write", "/tmp/readme-check/example.mjs")
    PRED = [("defer", got[0][1]["reason"])]                        # before: RESOURCE; the reason is the core's question for a dangerous part
    assert _v(got) == PRED and got[0][1]["reason"].startswith("ESCALATE_"), _v(got)


def test_question_words_name_the_file(client, owner, tmp_path, monkeypatch):
    d = _d(client, owner, tmp_path, monkeypatch, "q")
    got = _w(d, "Write", "/tmp/readme-check/example.mjs")
    rid = got[0][1]["rid"]
    g = d.c.get("/api/approvals/" + rid).json()
    # r0279: the path as the client's realpath names it (/private/tmp on macOS, /tmp on Linux)
    PRED = "Your agent wants to write a file outside the project: %s/readme-check/example.mjs" % os.path.realpath("/tmp")   # before: refused
    assert g["what"] == PRED, g["what"]
    assert "dangerous command" not in g["what"] and "Other programs" in g["harm"], g
    assert g["allowance_offer"]["eligible"] is False and "shared temporary folder" in g["allowance_offer"]["why_not"], g["allowance_offer"]


# ---------------------------------------------------------------- adversaries: an Н place stays refused, a system folder stays RESOURCE
@pytest.mark.parametrize("tool", ["Write", "Edit"])
@pytest.mark.parametrize("rel,code", [
    ("HOME/.zshrc", "FORBIDDEN_AUTOSTART"),
    ("HOME/Library/LaunchAgents/x.plist", "FORBIDDEN_AUTOSTART"),
    ("/etc/hosts", "FORBIDDEN_AUTOSTART"),
    ("HOME/.ssh/config", "FORBIDDEN_AUTOSTART"),
    ("/tmp/../etc/hosts", "FORBIDDEN_AUTOSTART"),                  # a spelling through temp is the place it names
    ("/opt/homebrew/bin/python3", "RESOURCE"),                     # a system folder: programs that run later
    ("/usr/local/bin/x", "RESOURCE"),
    ("/Users/someone-else/notes.md", "RESOURCE"),
    ("/Volumes/USB/x.md", "RESOURCE"),
    ("/var/root/x", "RESOURCE"),
    ("/private/var/db/x", "RESOURCE"),
])
def test_adversaries_stay_refused(client, owner, tmp_path, monkeypatch, tool, rel, code):
    d = _d(client, owner, tmp_path, monkeypatch, "a")
    got = _w(d, tool, rel.replace("HOME", d.home))
    PRED = code
    assert any(r["verdict"] == "deny" and r["reason"] == PRED for _, r in got), _v(got)


def test_link_in_temp_to_a_protected_place_is_judged_where_it_points(client, owner, tmp_path, monkeypatch, tmpdir_shared):
    d = _d(client, owner, tmp_path, monkeypatch, "l")
    os.makedirs(tmpdir_shared, exist_ok=True)
    rc = os.path.join(d.home, ".zshrc")
    open(rc, "w").write("# rc\n")
    os.symlink(rc, os.path.join(tmpdir_shared, "notes.md"))
    got = _w(d, "Write", tmpdir_shared + "/notes.md")
    PRED = ("deny", "FORBIDDEN_AUTOSTART")                         # the server resolves the link: the write lands in ~/.zshrc
    assert any((r["verdict"], r["reason"]) == PRED for _, r in got), _v(got)


def test_claude_code_temp_stays_silent(client, owner, tmp_path, monkeypatch):
    d = _d(client, owner, tmp_path, monkeypatch, "c")
    got = _w(d, "Write", "/tmp/claude-%d/-Users-u-p/s/scratchpad/a.js" % CLIENT_UID)
    PRED = [("allow", "OK")]
    assert _v(got) == PRED, _v(got)


def test_shared_temp_with_a_secret_is_not_silenced(client, owner, tmp_path, monkeypatch):
    d = _d(client, owner, tmp_path, monkeypatch, "s")
    got = d.send(None, tool="Write", inp={"file_path": "/tmp/readme-check/.env", "content": "AWS_SECRET_ACCESS_KEY=AKIA" "ABCDEFGHIJKLMNOP\n"})
    PRED = False                                                   # never a silent allow
    assert all(r["verdict"] == "allow" for _, r in got) is PRED, _v(got)


# ---------------------------------------------------------------- RT-0259: the mode of open() is read after the whole path expression
@pytest.mark.parametrize("code,mark", [
    ("import os;open(os.path.expanduser('~/Library/LaunchAgents/x.plist'),'w').write('x')", "persist"),    # before: [] (read)
    ("import os;open(os.path.join(os.path.expanduser('~'),'.zshrc'),'a').write('x')", "persist"),
    ("import os;print(open(os.path.expanduser('~/notes/a.md')).read())", None),                           # a read stays a read
])
def test_open_mode_after_a_call_in_the_path(code, mark):
    import shlex
    from app.hookjudge import bashparse as bp
    c = bp.classify("python3 -c %s" % shlex.quote(code), "/Users/u/proj", "/Users/u", project="/Users/u/proj")
    PRED = mark
    assert (c.danger[0].split(":", 1)[0] if c.danger else None) == PRED, c.danger


def test_open_mode_after_a_call_refused_in_the_strict_sandbox(client, owner, tmp_path, monkeypatch):
    d = _d(client, owner, tmp_path, monkeypatch, "o")
    got = d.send("python3 -c \"import os;open(os.path.expanduser('~/Library/LaunchAgents/x.plist'),'w').write('x')\"")
    PRED = ("deny", "FORBIDDEN_AUTOSTART")                 # before: ("allow", "OK_SANDBOXED") -- the kernel held it, the witness did not see it
    assert any((r["verdict"], r["reason"]) == PRED for _, r in got), _v(got)
