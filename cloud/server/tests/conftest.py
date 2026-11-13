import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))))
import testshim  # noqa: E402  (0.2.4: JSON toolmap_sha256 -> bytes in the Python test clients)

testshim.install()
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import pytest
from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
from app.config import Config
from app.main import create_app
from tests.helpers import Owner, ORIGIN, RP

PORT = 8810


# r0279 (Linux CI 13.11): the tests name ONE client, uid 501 (Claude Code's temp root /private/tmp/claude-501 in their paths). The
# recommended form names the CLIENT's uid; without this pin it took the uid of the process running the tests (1001 on a GitHub runner)
# and every "own scratch" path of the tests fell outside it. Production never sets it (the client builds the form with its own uid).
from app.hookjudge import mapping as _mapping  # noqa: E402
from tests.helpers import CLIENT_UID  # noqa: E402
_mapping.FORM_UID = CLIENT_UID


def _personal_temp_for_the_tests():
    """r0279: the tests model a person whose temp folder is their own (macOS: /var/folders/../T; Linux: a TMPDIR of theirs). pytest's
    tmp_path lies in it, and so the projects and homes of the tests do. On a machine whose temp folder is SHARED (Linux or a CI runner
    without TMPDIR: /tmp) the form rightly names no temp target any more, so the tests would judge a different person. Then the tests
    get a private 0700 folder inside the shared one as their TMPDIR, as macOS gives every user. The person WITHOUT a TMPDIR of theirs is
    tested explicitly (tests/test_1311_r0279_shared_temp.py, test_r0274_home_tmp.py with tmpdir=/tmp)."""
    import atexit
    import shutil
    import tempfile
    if _mapping.personal_temp(tempfile.gettempdir()) is not None:
        return
    d = tempfile.mkdtemp(prefix="dw-tests-%s-" % (os.getuid() if hasattr(os, "getuid") else "u"))     # mode 0700
    os.environ["TMPDIR"] = d
    tempfile.tempdir = d
    atexit.register(shutil.rmtree, d, True)


_personal_temp_for_the_tests()


def pytest_configure(config):
    config.addinivalue_line("markers", "standing: tests of the 0.2.90 standing mandate (unlisted allow); the legacy fixture does not apply")


@pytest.fixture(autouse=True)
def _legacy_unlisted(request, monkeypatch):
    """0.2.90 (standing mandate): the recommended form now says command.unlisted = "allow". The tests written for 0.2.9-0.2.89 assume the
    old default ("ask": an unlisted command is a question) and test the classifier, holds, allowances and pages under it; they run under
    that value here (the core logic is the same, only the last step of _command_rule differs). Tests of the standing mandate itself
    (tests/test_0290_standing.py, marker `standing`) opt out and get the 0.2.90 default; the trenie / proby corpora measure it end to end."""
    if "standing" in request.keywords:
        return
    from app.hookjudge import mapping
    monkeypatch.setattr(mapping, "DEFAULT_UNLISTED", "ask")
    name = os.path.basename(str(getattr(request.node, "fspath", "")))
    if name not in ("test_written_run_2810.py", "test_stash_0272.py"):
        from app import execguard
        monkeypatch.setattr(execguard, "WRITTEN_CODE_RISKY", False)      # 0.2.90 D8 is tested in test_0290_standing / written_run / stash
    from app.flow import rate
    monkeypatch.setattr(rate, "can_hear", lambda ctx, agent: True)      # the queue / freeze tests model an owner who hears the questions


@pytest.fixture()
def cfg(tmp_path):
    kf = tmp_path / "witness_key"
    kf.write_text("a1" * 32)
    return Config(data_dir=str(tmp_path / "data"), witness_key_file=str(kf), key_pepper="test-pepper", rp_id=RP, origin=ORIGIN,
                  iss="https://witness.test", anchor="off", web_dir=str(tmp_path / "web"))


@pytest.fixture()
def app(cfg):
    return create_app(cfg)


@pytest.fixture()
def client(app):
    return TestClient(app, base_url=ORIGIN)


@pytest.fixture()
def owner(client):
    return Owner(client).register("Alice")


@pytest.fixture()
def owner2(app):
    return Owner(TestClient(app, base_url=ORIGIN)).register("Bob")
