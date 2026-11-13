"""0.2.58: a Bash call whose tool_input carries a non-empty allowed_domains is never "strict" sandboxed (OTCHET-V3-L2 series 3, p.7:
allowed_domains in tool_input let the network out under a sandbox without strictAllowlist). Empty or absent: as before."""
import pytest

from app import _paths  # noqa: F401
from app.hookjudge import fs as _fs
from app.hookjudge import mapping
from tests.test_v3_sandbox import fact, HOME

PROJ = HOME + "/proj"


def _strict(tool_input, monkeypatch):
    class F(_fs.LocalFS):
        def getcwd(self): return PROJ
        def home(self): return HOME
        def sandbox(self): return fact()
        def scan(self, root): return None
    tok = _fs.use(F())
    try:
        parts = mapping._map({"tool_name": "Bash", "tool_input": tool_input, "cwd": PROJ}, HOME, env={"CLAUDE_PROJECT_DIR": PROJ})
    finally:
        _fs.reset(tok)
    return parts[0].args.get(mapping.RESERVED, {}).get("sandbox")


def test_baseline_is_strict(monkeypatch):
    assert _strict({"command": "pytest -q"}, monkeypatch) == {"strict": True}


@pytest.mark.parametrize("v", [["example.com"], "example.com", {"a": 1}])
def test_nonempty_allowed_domains_is_asked(v, monkeypatch):
    assert _strict({"command": "pytest -q", "allowed_domains": v}, monkeypatch) is None


@pytest.mark.parametrize("v", [[], None, "", {}, False])
def test_empty_allowed_domains_as_before(v, monkeypatch):
    assert _strict({"command": "pytest -q", "allowed_domains": v}, monkeypatch) == {"strict": True}
