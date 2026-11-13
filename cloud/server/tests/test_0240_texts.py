"""0.2.40: texts and pages. node2.html is not in the hash list while DW_NODE2 is off (the page answers 404); terms.html is served."""
import pytest


import dataclasses
import os

from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import ORIGIN

REAL_WEB = os.path.join(os.path.dirname(__file__), "..", "..", "web")


@pytest.fixture()
def client(cfg):
    return TestClient(create_app(dataclasses.replace(cfg, web_dir=os.path.abspath(REAL_WEB))), base_url=ORIGIN)


def test_node2_not_listed_when_page_is_404(client):
    assert client.get("/node2.html").status_code == 404
    hs = client.get("/v1/witness").json()["web_js_sha256"]
    assert "node2.html" not in hs
    for name in hs:
        if name.endswith(".html"):
            assert client.get("/" + name).status_code == 200, name


def test_terms_and_privacy_pages(client):
    t = client.get("/terms.html")
    assert t.status_code == 200 and "as is" in t.text and "Sipki LLC" in t.text
    p = client.get("/privacy.html").text
    assert "reverse-proxy access logs" in p and "/terms.html" in p
    assert "terms.html" in client.get("/v1/witness").json()["web_js_sha256"]
