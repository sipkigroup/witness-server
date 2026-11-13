import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))))
import testshim  # noqa: E402  (0.2.4: JSON toolmap_sha256 -> bytes in the Python test clients)

testshim.install()
"""tests_flow (02). 0.2.0: the production app of 01 as is: create_app mounts the flow router FIRST, app/actions.py calls the hooks,
QuorumRegistry understands `wb`, POST /api/approvals/{rid}/release is 01's path. (Until the merge these tests ran on the reference seam
flow/seam.py + flow/wbreg.py; both are gone.)"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import pytest
from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
from app.config import Config
from app.main import create_app
from app.flow import advisor
from tests_flow.helpers import Owner, ORIGIN, RP

PORT = 8811


def make_app(tmp):
    kf = tmp / "witness_key"
    kf.write_text("a1" * 32)
    cfg = Config(data_dir=str(tmp / "data"), witness_key_file=str(kf), key_pepper="test-pepper", rp_id=RP, origin=ORIGIN,
                 iss="https://witness.test", anchor="off", web_dir=str(tmp / "web"))
    return create_app(cfg)


@pytest.fixture(autouse=True)
def _heard(monkeypatch):
    from app.flow import rate
    monkeypatch.setattr(rate, "can_hear", lambda ctx, agent: True)      # 0.2.90: the queue tests model an owner who hears the questions


@pytest.fixture(autouse=True)
def _wire():
    yield
    advisor.FN = None


@pytest.fixture()
def app(tmp_path):
    return make_app(tmp_path)


@pytest.fixture()
def ctx(app):
    return app.state.ctx


@pytest.fixture()
def client(app):
    return TestClient(app, base_url=ORIGIN)


@pytest.fixture()
def owner(client):
    return Owner(client).register("Alice")


@pytest.fixture()
def owner2(app):
    return Owner(TestClient(app, base_url=ORIGIN)).register("Bob")


@pytest.fixture(scope="session")
def warm_advisor():
    advisor.warm()
    yield
    advisor.reset()
