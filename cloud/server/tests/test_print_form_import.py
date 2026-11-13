"""0.2.7: `deus-witness-hook --print-form` -> the Mandate page's "Import from JSON" (the real web/js/mandate_import.js, run by node) -> draft -> sign -> the hook's rules work.
Real server (TestClient), real hook CLI, real page module; signing is done WITHOUT the test shim: wa.cde_raw(wire.cbor_form(m)) is called explicitly (the page does the same: cde.js)."""
import json
import os
import shutil
import subprocess
import sys

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))

from app import _paths  # noqa: F401,E402
import wa_profile as wa  # noqa: E402
from app import wire  # noqa: E402
from tests.helpers import act  # noqa: E402

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is needed to run the page module")
ENV = dict(os.environ, PYTHONPATH=os.path.join(CLOUD, "mcp"))


def _printed(project):
    r = subprocess.run([sys.executable, "-m", "deus_witness.hook", "--print-form", str(project)], capture_output=True, text=True, env=ENV, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout


def _import(text, agent="ag"):
    r = subprocess.run([NODE, os.path.join(CLOUD, "web", "test", "import_cli.mjs"), agent], input=text, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _sign_mandate(owner, agent_id, form):
    d = owner.post("/api/mandates/draft", agent_id=agent_id, form=form)
    assert d.status_code == 200, d.text
    m = d.json()["mandate"]
    env = wa.b64u(owner.auth.sign_object(wa.TYP_MANDATE, wa.cde_raw(wire.cbor_form(m)), "localhost", "http://localhost:8810"))
    r = owner.post("/api/mandates", mandate=m, envelope_b64=env)
    assert r.status_code == 200, r.text
    return m


def test_printed_form_imported_signed_and_enforced(client, owner, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    text = _printed(proj)
    imp = _import(text)
    assert imp["errors"] == [] and imp["form"]
    shown = dict(imp["rows"])                                       # what the page shows before signing
    assert "irreversible allowed" in shown["Deleting"] and str(proj.resolve()) in shown["Deleting"]
    assert shown["Purchases"] == "forbidden"

    ag, hdr = owner.new_agent("claude-code", "cc")
    m = _sign_mandate(owner, ag["id"], imp["form"])
    # what was signed == what the page showed
    P = m["permissions"]
    assert P["delete"]["targets"] == json.loads(text)["delete"]["targets"] and P["delete"]["allow_irreversible"] is True
    assert P["message"]["domains"] == json.loads(text)["message"]["domains"] and P["purchase"] is False and "publish" not in P

    inside = str(proj.resolve() / "a.txt")
    r = act(client, hdr, "Write", {"file_path": inside, "content": "x", "_witness": {"path": inside}}).json()
    assert (r["verdict"], r["reason"]) == ("allow", "OK")           # the imported rules are the hook's default rules
    r = act(client, hdr, "Write", {"file_path": "/etc/x", "content": "x", "_witness": {"path": "/etc/x"}}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "RESOURCE")
    r = act(client, hdr, "WebFetch", {"url": "https://evil.example/x", "prompt": "p", "_witness": {"recipient": "webfetch@evil.example"}}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "RECIPIENT")
    r = act(client, hdr, "WebFetch", {"url": "https://pypi.org/x", "prompt": "p", "_witness": {"recipient": "webfetch@pypi.org"}}).json()
    assert (r["verdict"], r["reason"]) == ("allow", "OK")
    r = act(client, hdr, "Bash.danger", {"command": "rm -rf build", "_witness": {"cwd": str(proj), "danger": ["rm-rf:build"], "writes": [], "net": []}}).json()
    assert (r["verdict"], r["reason"]) == ("defer", "ESCALATE_COMMAND_DANGER")  # PROPOSAL-06: its own code, not ESCALATE_PUBLISH
    assert P["command"]["unlisted"] in ("ask", "allow") and "git status" in P["command"]["allow"]   # 0.2.90: the standing mandate says allow
    r = act(client, hdr, "Bash", {"command": "git status", "_witness": {"cwd": str(proj), "danger": [], "writes": [], "net": [], "commands": ["git status"]}}).json()
    assert (r["verdict"], r["reason"]) == ("allow", "OK")           # a listed read-only command runs
    r = act(client, hdr, "Bash", {"command": "make", "_witness": {"cwd": str(proj), "danger": [], "writes": [], "net": [], "commands": ["make"]}}).json()
    assert (r["verdict"], r["reason"]) in (("defer", "ESCALATE_COMMAND"), ("allow", "OK_UNSPECIFIED"))   # 0.2.90: the printed form says allow


def _cmd(client, hdr, proj, line, heads, tool="Bash", danger=()):
    return act(client, hdr, tool, {"command": line, "_witness": {"cwd": str(proj), "danger": list(danger), "writes": [], "net": [], "commands": heads}}).json()


def test_command_class_on_the_server(client, owner, tmp_path):
    """PROPOSAL-06 end to end on the server: every command of the line must be listed; one unlisted command asks about the line (not RECIPIENT)."""
    proj = tmp_path / "proj"; proj.mkdir()
    ag, hdr = owner.new_agent("claude-code", "cc")
    _sign_mandate(owner, ag["id"], {"currency": "USD", "valid_days": 30, "command": {"allow": ["ls", "git status"]}})
    r = _cmd(client, hdr, proj, "ls && git status", ["ls", "git status"])
    assert (r["verdict"], r["reason"]) == ("allow", "OK")
    r = _cmd(client, hdr, proj, "ls && make", ["ls", "make"])
    assert (r["verdict"], r["reason"]) == ("defer", "ESCALATE_COMMAND")     # not deny RECIPIENT: the owner is asked about the line
    r = _cmd(client, hdr, proj, "rm -rf build", ["rm"], tool="Bash.danger", danger=["rm-rf:/p/build"])
    assert (r["verdict"], r["reason"]) == ("defer", "ESCALATE_COMMAND_DANGER")


def test_command_class_unlisted_deny_and_forbidden(client, owner, tmp_path):
    proj = tmp_path / "proj"; proj.mkdir()
    ag, hdr = owner.new_agent("claude-code", "cc")
    _sign_mandate(owner, ag["id"], {"currency": "USD", "valid_days": 30, "command": {"allow": ["ls"], "unlisted": "deny"}})
    assert _cmd(client, hdr, proj, "ls", ["ls"])["reason"] == "OK"
    r = _cmd(client, hdr, proj, "ls; make", ["ls", "make"])
    assert (r["verdict"], r["reason"]) == ("deny", "RESOURCE")
    r = _cmd(client, hdr, proj, "dd of=/dev/sda", ["dd"], tool="Bash.danger", danger=["disk:/dev/sda"])
    assert (r["verdict"], r["reason"]) == ("deny", "RESOURCE")
    ag2, hdr2 = owner.new_agent("claude-code", "cc2")
    _sign_mandate(owner, ag2["id"], {"currency": "USD", "valid_days": 30, "command": False})
    assert _cmd(client, hdr2, proj, "ls", ["ls"])["reason"] == "CLASS_DENIED"


def test_mandate_without_command_asks_every_command(client, owner, tmp_path):
    """compatibility: a mandate without `command` (every form signed before PROPOSAL-06) -> every command is asked, dangerous ones with their own code"""
    proj = tmp_path / "proj"; proj.mkdir()
    ag, hdr = owner.new_agent("claude-code", "cc")
    _sign_mandate(owner, ag["id"], {"currency": "USD", "valid_days": 30})
    assert _cmd(client, hdr, proj, "ls", ["ls"])["reason"] == "ESCALATE_COMMAND"
    assert _cmd(client, hdr, proj, "rm -rf b", ["rm"], tool="Bash.danger", danger=["rm-rf:/p/b"])["reason"] == "ESCALATE_COMMAND_DANGER"


def test_agent_with_the_05_tool_map_is_unchanged(client, owner, tmp_path):
    """compatibility: an agent created before PROPOSAL-06 keeps its -05 map (stored per agent): harmless lines pass, dangerous ones ESCALATE_PUBLISH"""
    proj = tmp_path / "proj"; proj.mkdir()
    ag, hdr = owner.new_agent("claude-code-05", "cc")
    _sign_mandate(owner, ag["id"], {"currency": "USD", "valid_days": 30})
    assert _cmd(client, hdr, proj, "ls", ["ls"])["verdict"] in ("pass", "allow")
    r = _cmd(client, hdr, proj, "rm -rf b", ["rm"], tool="Bash.danger", danger=["rm-rf:/p/b"])
    assert (r["verdict"], r["reason"]) == ("defer", "ESCALATE_PUBLISH")


def test_import_refuses_a_broken_print(tmp_path):
    text = _printed(tmp_path)
    cut = _import(text[:-5])
    assert cut["form"] is None and cut["errors"]
    f = json.loads(text)
    f["delete"]["targets"].append("/a,b/*")
    assert _import(json.dumps(f))["form"] is None
