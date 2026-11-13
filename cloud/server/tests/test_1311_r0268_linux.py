"""r0268 (13.11): Claude Code's Linux / WSL2 sandbox (bubblewrap + socat + its seccomp filter) counts as the strict fact -- only with a
COMPLETE `linux` fact from the client (bwrap, socat, an architecture with the seccomp filter; on WSL2 interop off and the Windows homes'
key places in denyRead). Without it, or with anything missing, the line is asked as before (fail closed).

PRED (written before the run): every Linux case below was asked before r0268 ("platform linux: only macOS Seatbelt"); after it the
complete Linux fact is strict and every incomplete one is still not."""
import copy
import json
import os
import posixpath
import sys

import pytest

from app.hookjudge import sandbox as hsb
from tests.test_v3_sandbox import ASK, OK_SB, STRICT, dev, sb  # noqa: F401  (fixtures)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "mcp"))
from deus_witness.hook import failsafe as _fsafe, sandbox_fact as _sf, strict as _st  # noqa: E402

HOME = os.path.expanduser("~")
LX = {"kind": "linux", "bwrap": True, "socat": True, "arch": "x86_64"}
WIN = "/mnt/c/Users/bob"


def lfact(platform="linux", **over):
    f = copy.deepcopy(STRICT)
    f["platform"] = platform
    f["linux"] = dict(LX, kind=platform)
    if platform == "wsl2":
        f["linux"].update(interop=False, win_homes=[WIN])
        f["deny_read"] = f["deny_read"] + [posixpath.join(WIN, x) for x in hsb.WIN_SECRETS]
    lx = over.pop("linux", None)
    if lx is not None:
        f["linux"].update(lx)
    f.update(over)
    return f


def test_linux_fact_is_strict():
    PRED = (True, [])
    assert hsb.well_formed(lfact()) and hsb.evaluate(lfact(), ["pytest"], HOME) == PRED
    assert hsb.evaluate(lfact(linux={"arch": "aarch64"}), ["pytest"], HOME) == PRED
    assert hsb.evaluate(lfact("wsl2"), ["pytest"], HOME) == PRED


@pytest.mark.parametrize("f,why", [
    (dict(lfact(), linux=None), "no complete Linux sandbox fact"),               # a client before r0268
    ({k: v for k, v in lfact().items() if k != "linux"}, "no complete Linux sandbox fact"),
    (dict(copy.deepcopy(STRICT), platform="wsl"), "only macOS Seatbelt and Linux"),   # a client before r0268 says "wsl"
    (dict(lfact(), platform="wsl1"), "only macOS Seatbelt and Linux"),            # Claude Code refuses WSL1
    (lfact(linux={"kind": "wsl2"}), "no complete Linux sandbox fact"),            # kind and platform differ
    (lfact(linux={"bwrap": False}), "bubblewrap or socat"),
    (lfact(linux={"socat": False}), "bubblewrap or socat"),
    (lfact(linux={"arch": "riscv64"}), "seccomp"),
    (lfact(linux={"arch": ""}), "seccomp"),
    (lfact(weaker=["enableWeakerNestedSandbox"]), "weakening keys"),              # the ACI / container way: never strict
    (lfact(unix_sockets=["/var/run/docker.sock"]), "Unix sockets"),
    (lfact(all_unix_sockets=True), "Unix sockets"),
    (lfact(deny_read=["/nonexistent"]), "denyRead"),
    (lfact("wsl2", linux={"interop": True}), "interop"),
    (lfact("wsl2", linux={"interop": None}), "interop"),
    (lfact("wsl2", deny_read=[HOME]), "denyRead does not cover /mnt/c/Users/bob/AppData"),
    (lfact("wsl2", linux={"win_homes": ["/home/x/../../mnt/c"]}), "of the form"),
    (dict(lfact("wsl2"), linux={k: v for k, v in lfact("wsl2")["linux"].items() if k != "win_homes"}), "not reported"),
])
def test_incomplete_linux_fact_is_not_strict(f, why):
    if f.get("linux") is None and "linux" in f:
        f = {k: v for k, v in f.items() if k != "linux"}
    ok, whys = hsb.evaluate(f, ["pytest"], HOME)
    assert not ok and any(why in w for w in whys), whys


@pytest.mark.parametrize("bad", [{"kind": "linux", "bwrap": "yes", "socat": True, "arch": "x86_64"},
                                 {"kind": "linux", "bwrap": True, "socat": True, "arch": 1},
                                 {"kind": "bsd", "bwrap": True, "socat": True, "arch": "x86_64"},
                                 {"kind": "wsl2", "bwrap": True, "socat": True, "arch": "x86_64", "interop": "off"},
                                 {"kind": "wsl2", "bwrap": True, "socat": True, "arch": "x86_64", "win_homes": ["/mnt/c/Users/a"] * 9},
                                 "linux"])
def test_malformed_linux_fact_is_no_fact(bad):
    f = lfact()
    f["linux"] = bad
    assert not hsb.well_formed(f) and hsb.evaluate(f, ["pytest"], HOME)[0] is False


def test_darwin_fact_unchanged_and_may_carry_no_linux():
    assert hsb.evaluate(copy.deepcopy(STRICT), ["pytest"], HOME) == (True, [])


def test_wsl2_windows_home_is_case_insensitive():
    f = lfact("wsl2", deny_read=[HOME] + ["/mnt/c/users/BOB/" + x.lower() for x in hsb.WIN_SECRETS])
    assert hsb.evaluate(f, ["pytest"], HOME) == (True, [])
    f["allow_read"] = ["/mnt/c/Users/bob/AppData/Local/Google"]       # re-opened inside: not strict
    assert hsb.evaluate(f, ["pytest"], HOME)[0] is False


H = "/home/u"


def test_cred_closed_uses_the_linux_places():
    exact_linux = [posixpath.join(H, s) for s in hsb.SECRETS + hsb.CRED_SOURCES_LINUX]
    exact_mac = [posixpath.join(H, s) for s in hsb.SECRETS + hsb.CRED_SOURCES]
    base = dict(lfact(), env_tokens=[], cred_files=[])
    assert hsb.cred_closed(dict(base, deny_read=exact_linux), H) == (True, [])
    ok, why = hsb.cred_closed(dict(base, deny_read=exact_mac), H)                # macOS places on Linux: the keyring is open
    assert not ok and any(".config/google-chrome" in w or ".local/share/keyrings" in w for w in why), why
    ok, why = hsb.cred_closed(dict(base, deny_read=exact_linux, linux=dict(LX, bwrap=False)), H)
    assert not ok and any("bubblewrap" in w for w in why), why
    assert hsb.cred_closed(dict(base, deny_read=[H]), H) == (True, [])           # ~/ itself as on macOS


# ---- the hook end to end: a real line through the witness ---------------------------------------------------------------------------
def test_linux_fact_end_to_end(dev, sb):  # noqa: F811
    sb(lfact())
    assert dev.v("pytest -q") == [OK_SB]
    sb(lfact(linux={"socat": False}))
    assert dev.v("pytest -q") == [ASK]
    sb({k: v for k, v in lfact().items() if k != "linux"})
    assert dev.v("pytest -q") == [ASK]


# ---- the client's own writer + reader (mcp/deus_witness/hook/strict.py, sandbox_fact.py) on Linux -> the server's judgement ----------
def test_client_setup_on_linux_gives_a_strict_fact(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    managed = tmp_path / "managed"
    managed.mkdir()
    monkeypatch.setattr(_fsafe, "MANAGED_DIR_OVERRIDE", str(managed))
    monkeypatch.setattr(_sf, "_which", lambda n: "/usr/bin/" + n)
    env = {"HOME": str(home)}
    ok = {"which": lambda n: "/usr/bin/" + n, "run": lambda a: (0, ""), "machine": "x86_64"}
    assert _st.setup(env, platform="linux", problems=ok) == 0
    s = json.loads((home / ".claude" / "settings.json").read_text())
    f = _sf.fact({"command": "pytest"}, str(proj), env=env, home=str(home), platform="linux", permission_mode="default")
    f["linux"]["arch"] = "x86_64"                     # the test machine's own architecture aside
    assert f["platform"] == "linux" and f["linux"]["bwrap"] is True
    assert hsb.evaluate(f, ["pytest"], str(home), str(proj)) == (True, []), hsb.evaluate(f, ["pytest"], str(home), str(proj))
    assert hsb.cred_closed(f, str(home))[0] is True, hsb.cred_closed(f, str(home))
    assert not any("Library/" in x for x in s["sandbox"]["filesystem"]["denyRead"])
    # the same settings read as WSL2 with interop on: not strict
    f2 = dict(f, platform="wsl2", linux=dict(f["linux"], kind="wsl2", interop=True, win_homes=[]))
    assert hsb.evaluate(f2, ["pytest"], str(home), str(proj))[0] is False
