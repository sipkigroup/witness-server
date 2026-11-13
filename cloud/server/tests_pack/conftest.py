import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))))
import testshim  # noqa: E402  (0.2.4: JSON toolmap_sha256 -> bytes in the Python test clients)

testshim.install()
"""tests_pack (task 06): evidence pack 0.2, second pass, RFC 3161. Local test TSA on port 8812 (see lib/tsa/testtsa.py)."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.dirname(HERE)
CLOUD = os.path.dirname(SERVER)
for p in (os.path.join(CLOUD, "lib", "tsa"), os.path.join(SERVER, "packtools"), os.path.join(CLOUD, "contract", "v02"), HERE, SERVER):
    if p not in sys.path:
        sys.path.insert(0, p)

import pytest
from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
from app.config import Config
from app.main import create_app
from tests.helpers import ORIGIN, RP, Owner

import testtsa


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


@pytest.fixture(scope="session")
def tsas():
    return {"tsa-a": testtsa.TestTSA("Test TSA A", kind="rsa"), "tsa-b": testtsa.TestTSA("Test TSA B", kind="ec")}


@pytest.fixture(scope="session")
def tsa_server(tsas):
    srv, _ = testtsa.serve(8812, tsas)
    yield "http://127.0.0.1:8812"
    srv.shutdown()
    srv.server_close()


@pytest.fixture()
def providers(tmp_path, tsas, tsa_server, monkeypatch):
    """providers.json with the two local test TSAs (take=true) + DW_TSA_PROVIDERS pointing at it."""
    d = tmp_path / "prov"
    d.mkdir()
    ps = []
    for name, t in tsas.items():
        (d / (name + ".pem")).write_bytes(t.root_pem)
        ps.append({"name": name, "url": "%s/%s" % (tsa_server, name), "ca": name + ".pem", "take": True, "terms": "allowed"})
    path = d / "providers.json"
    path.write_text(json.dumps({"providers": ps}))
    monkeypatch.setenv("DW_TSA_PROVIDERS", str(path))
    return path
