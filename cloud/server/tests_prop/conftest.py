import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.dirname(HERE)
for p in (SERVER, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)
sys.path.insert(0, os.path.dirname(SERVER))
import testshim  # noqa: E402

testshim.install()
import pytest  # noqa: E402
from hypothesis import HealthCheck, settings  # noqa: E402

N = int(os.environ.get("PROP_N", "300"))
settings.register_profile("prop", max_examples=N, deadline=None, database=None, print_blob=True,
                          suppress_health_check=list(HealthCheck))
settings.load_profile("prop")


@pytest.fixture(autouse=True)
def _prop_env(monkeypatch):
    """The owner hears the questions (rate.can_hear), like the tests/ suite. The product defaults stay (0.2.90 standing mandate);
    PROP_LEGACY=1 runs the whole thing under the legacy unlisted="ask" default of tests/conftest.py."""
    from app.flow import rate
    monkeypatch.setattr(rate, "can_hear", lambda ctx, agent: True)
    if os.environ.get("PROP_LEGACY") == "1":
        from app.hookjudge import mapping
        from app import execguard
        monkeypatch.setattr(mapping, "DEFAULT_UNLISTED", "ask")
        monkeypatch.setattr(execguard, "WRITTEN_CODE_RISKY", False)


def pytest_terminal_summary(terminalreporter):
    import prop_harness as h
    terminalreporter.section("property examples executed (incl. shrinking re-runs)")
    for k, v in sorted(h.COUNT.items()):
        terminalreporter.write_line("%-40s %d" % (k, v))
