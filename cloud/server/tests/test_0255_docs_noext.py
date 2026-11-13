"""0.2.55: /dl/docs/<name> without extension serves <name>.html (existing files only, [a-z0-9-] only)."""
import os

from fastapi.testclient import TestClient

from app.config import Config
from app.main import create_app
from tests.helpers import ORIGIN, RP


def _client(tmp_path):
    web = tmp_path / "web"
    (web / "dl" / "docs").mkdir(parents=True)
    (web / "dl" / "docs" / "quickstart.html").write_text("<h1>qs</h1>")
    (web / "secret.txt").write_text("x")
    kf = tmp_path / "k"
    kf.write_text("a1" * 32)
    cfg = Config(data_dir=str(tmp_path / "data"), witness_key_file=str(kf), key_pepper="p", rp_id=RP, origin=ORIGIN,
                 iss="https://witness.test", anchor="off", web_dir=str(web))
    return TestClient(create_app(cfg), base_url=ORIGIN)


def test_noext_ok(tmp_path):
    c = _client(tmp_path)
    assert c.get("/dl/docs/quickstart.html").status_code == 200
    r = c.get("/dl/docs/quickstart")
    assert r.status_code == 200 and "qs" in r.text


def test_noext_bad(tmp_path):
    c = _client(tmp_path)
    for p in ("/dl/docs/nope", "/dl/docs/../../etc/passwd", "/dl/docs/%2e%2e/secret", "/dl//docs/quickstart", "/dl/docs//quickstart",
              "/dl/docs/Quickstart", "/dl/docs/quick_start", "/dl/docs/%2e%2e%2fsecret"):
        assert c.get(p).status_code == 404, p
