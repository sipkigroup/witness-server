"""13.11 (r0279, the first CI of the open server on Linux). The recommended mandate form named realpath(tempfile.gettempdir()) + "/*" as a
write target. On macOS that is the person's own /var/folders/../T; on Linux $TMPDIR is usually unset and gettempdir() is "/tmp", the
machine's SHARED temp folder (every user writes there): `Write /tmp/x` ran silently (allow OK) where macOS asks it once (law r0261f: a
shared temp folder is no folder of the person's to widen). The same on macOS with TMPDIR=/tmp. Law now: a shared temp root (/tmp, /var/tmp,
/dev/shm, /run/shm, /usr/tmp, the /private spellings; or any world-writable folder) is never a write target of a form -- the server's
default form, the client's, and the mandate the server drafts from any form (an old Linux client's "/tmp/*" is dropped, so the page shows
and the passkeys sign the mandate the witness keeps). The person's own temp folder stays a target.
Each platform is a parameter: what the client reports (gettempdir, realpath), not the machine running the tests.
PRED is written before each check (the outcome on r0277, measured on macOS with TMPDIR=/tmp and seen on the Linux CI run 43448942298)."""
import os
import stat
import sys

import pytest

from app.hookjudge import mapping
from app.mandates import mandate_from_form
from tests.test_0290_standing import Dev

pytestmark = pytest.mark.standing

SHARED = ["/tmp", "/tmp/", "/private/tmp", "/var/tmp", "/private/var/tmp", "/dev/shm", "/run/shm", "/usr/tmp"]


# ------------------------------------------------------------------ the law, by name and by mode
@pytest.mark.parametrize("p", SHARED)
def test_shared_temp_roots_are_never_a_personal_temp(p):
    PRED = None                                                    # before: realpath(p) -> "<p>/*" became a write target
    assert mapping.personal_temp(p) is PRED
    assert mapping.shared_temp_root(p)


def test_a_world_writable_temp_is_shared_wherever_it_is(tmp_path):
    d = tmp_path / "sticky"
    d.mkdir()
    os.chmod(d, 0o1777)                                            # the mode of /tmp on every Unix
    assert mapping.personal_temp(str(d)) is None
    os.chmod(d, 0o700)                                             # a TMPDIR of the person's (Linux /run/user/<uid>, macOS T)
    assert mapping.personal_temp(str(d)) == os.path.realpath(str(d))


@pytest.mark.parametrize("t,shared", [("/tmp/*", True), ("/tmp/**", True), ("/private/tmp/*", True), ("/var/tmp/*", True),
                                      ("/dev/shm/*", True), ("/tmp", True), ("/tmp/claude-501/*", False), ("/private/tmp/claude-501/*", False),
                                      ("/tmp/dw-ci/*", False), ("/var/folders/ab/cd/T/*", False), ("/Users/u/proj/*", False),
                                      ("/tmpx/*", False), ("/*", False)])
def test_which_targets_name_a_shared_root(t, shared):
    assert mapping.shared_temp_target(t) is shared


# ------------------------------------------------------------------ the form, per client platform
CLIENTS = {
    "linux, no TMPDIR": "/tmp",
    "linux, TMPDIR=/var/tmp": "/var/tmp",
    "macos, TMPDIR=/tmp": "/private/tmp",
}


@pytest.mark.parametrize("client_tmp", [CLIENTS[k] for k in sorted(CLIENTS)], ids=sorted(CLIENTS))
def test_server_form_names_no_shared_temp(monkeypatch, tmp_path, client_tmp):
    monkeypatch.setattr(mapping.tempfile, "gettempdir", lambda: client_tmp)
    ts = mapping.default_form(str(tmp_path / "proj"))["delete"]["targets"]
    PRED = []                                                      # before: [client_tmp + "/*"]
    assert [t for t in ts if mapping.shared_temp_target(t)] == PRED, ts
    assert any(t.endswith("/claude-501/*") for t in ts), ts      # Claude Code's own temp root of this user stays


def test_server_form_keeps_the_persons_own_temp(monkeypatch, tmp_path):
    own = tmp_path / "run-user-1001"
    own.mkdir(mode=0o700)
    monkeypatch.setattr(mapping.tempfile, "gettempdir", lambda: str(own))
    ts = mapping.default_form(str(tmp_path / "proj"))["delete"]["targets"]
    assert os.path.realpath(str(own)) + "/*" in ts, ts


def test_production_form_uses_the_clients_own_uid(monkeypatch):
    monkeypatch.setattr(mapping, "FORM_UID", None)
    if not hasattr(os, "getuid"):
        pytest.skip("no uid on this OS")
    assert mapping._scratch_targets() == ["/private/tmp/claude-%d/*" % os.getuid(), "/tmp/claude-%d/*" % os.getuid()]


def _client_form():
    sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../mcp")))
    from deus_witness.hook import form
    if not hasattr(form, "personal_temp"):
        pytest.skip("the installed client is older than r0279 (its form still names gettempdir(); the server drops a shared root)")
    return form


@pytest.mark.parametrize("client_tmp", [CLIENTS[k] for k in sorted(CLIENTS)], ids=sorted(CLIENTS))
def test_client_form_names_no_shared_temp(monkeypatch, tmp_path, client_tmp):
    form = _client_form()
    monkeypatch.setattr(form.tempfile, "gettempdir", lambda: client_tmp)
    ts = form.default_form(str(tmp_path / "proj"))["delete"]["targets"]
    assert not [t for t in ts if mapping.shared_temp_target(t)], ts


# ------------------------------------------------------------------ the server drops a shared root from any form it drafts
def test_mandate_drops_a_shared_temp_target_of_an_old_linux_client(tmp_path):
    proj = os.path.realpath(str(tmp_path))
    f = {"delete": {"targets": [proj + "/*", "/tmp/*", "/private/tmp/**", "/var/tmp/*", "/tmp/claude-501/*", "/tmp/dw-own/*"],
                    "allow_irreversible": True}}
    P = mandate_from_form(f, "dw:" + "0" * 32, "ag_000000000000", "x")["permissions"]
    PRED = [proj + "/*", "/tmp/claude-501/*", "/tmp/dw-own/*"]     # before: every target kept, "/tmp/*" made the shared /tmp silent
    assert P["delete"]["targets"] == PRED, P["delete"]


# ------------------------------------------------------------------ end to end: what the agent meets, per client platform
def _dev(client, owner, tmp_path, monkeypatch, client_tmp, form=None):
    monkeypatch.setattr(mapping.tempfile, "gettempdir", lambda: client_tmp)
    home = tmp_path / "h"
    (home / "proj" / "src").mkdir(parents=True)
    d = Dev(client, owner, (home / "proj").resolve(), home=str(home.resolve()))
    if form is not None:
        m, r = owner.mandate(d.ag["id"], form(d.proj))
        assert r.status_code == 200, r.text
    return d


def _v(got):
    return [(r["verdict"], r["reason"]) for _, r in got]


@pytest.mark.parametrize("client_tmp", [CLIENTS[k] for k in sorted(CLIENTS)], ids=sorted(CLIENTS))
@pytest.mark.parametrize("tool", ["Write", "Edit"])
def test_a_file_in_shared_temp_is_asked_on_every_platform(client, owner, tmp_path, monkeypatch, client_tmp, tool):
    d = _dev(client, owner, tmp_path, monkeypatch, client_tmp)
    inp = {"file_path": "/tmp/r0279/x.mjs", "content": "x\n"} if tool == "Write" else \
        {"file_path": "/tmp/r0279/x.mjs", "old_string": "a", "new_string": "b"}
    got = d.send(None, tool=tool, inp=inp)
    PRED = "defer"                                                 # before on Linux / TMPDIR=/tmp: ("allow", "OK"), silent
    assert [r["verdict"] for _, r in got] == [PRED], _v(got)


@pytest.mark.parametrize("client_tmp", [CLIENTS[k] for k in sorted(CLIENTS)], ids=sorted(CLIENTS))
def test_a_shell_write_into_shared_temp_is_not_silent(client, owner, tmp_path, monkeypatch, client_tmp):
    d = _dev(client, owner, tmp_path, monkeypatch, client_tmp)
    got = d.send("echo hi > /tmp/r0279-note.txt")
    PRED = False                                                   # before on Linux: silent (allow OK, the "/tmp/*" target)
    assert all(r["verdict"] == "allow" for _, r in got) is PRED, _v(got)


def test_an_old_linux_form_with_tmp_is_drafted_without_it(client, owner, tmp_path, monkeypatch):
    def old_linux_form(proj):
        f = mapping.default_form(proj)
        f["delete"]["targets"].insert(1, "/tmp/*")                 # what a client before r0279 sends from Linux without TMPDIR
        return f
    d = _dev(client, owner, tmp_path, monkeypatch, "/tmp", form=old_linux_form)
    got = d.send(None, tool="Write", inp={"file_path": "/tmp/r0279/y.md", "content": "y\n"})
    PRED = "defer"                                                 # before: ("allow", "OK")
    assert [r["verdict"] for _, r in got] == [PRED], _v(got)


@pytest.mark.parametrize("client_tmp", [CLIENTS[k] for k in sorted(CLIENTS)], ids=sorted(CLIENTS))
def test_own_scratch_and_project_stay_silent(client, owner, tmp_path, monkeypatch, client_tmp):
    """Adversary of the change (friction): the project and Claude Code's own temp root of this user are not asked because of it."""
    d = _dev(client, owner, tmp_path, monkeypatch, client_tmp)
    got = d.send(None, tool="Write", inp={"file_path": os.path.join(d.proj, "src", "a.py"), "content": "x = 1\n"})
    assert _v(got) == [("allow", "OK")], _v(got)
    got = d.send(None, tool="Write", inp={"file_path": "/private/tmp/claude-501/-h-proj/s1/scratchpad/n.md", "content": "n\n"})
    assert [r["verdict"] for _, r in got] == ["allow"], _v(got)


def test_the_mode_check_is_the_kernels(tmp_path):
    """The world-writable bit is what makes a folder shared (S_IWOTH), not its name: a sticky /tmp mounted elsewhere is shared too."""
    d = tmp_path / "elsewhere-tmp"
    d.mkdir()
    os.chmod(d, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO | stat.S_ISVTX)
    assert mapping.personal_temp(str(d)) is None


# ------------------------------------------------------------------ the client's session start on Linux (found by the same CI run)
def test_client_reads_a_session_birth_time_on_linux(tmp_path):
    """Before r0279 the client read only os.stat().st_birthtime, which Python has on macOS / BSD and not on Linux: every Linux session was
    "session start unknown" and the strict sandbox never counted (fail closed: asked, never silent). On Linux it now reads statx."""
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux only (macOS has st_birthtime)")
    sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../mcp")))
    from deus_witness.hook import sandbox_fact as sf
    if not hasattr(sf, "_linux_birth"):
        pytest.skip("the installed client is older than r0279")
    t = tmp_path / "s.jsonl"
    t.write_text("{}\n")
    if sf._linux_birth(str(t)) is None:
        pytest.skip("this file system keeps no birth time (statx %W = 0): the client fails closed there")
    assert abs(sf._session_start(str(t)) - os.stat(str(t)).st_mtime) < 2
