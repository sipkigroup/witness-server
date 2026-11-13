"""0.2.49: per-key rate 300/min (reads in their own window), the 429 text, /.well-known/security.txt, support@ contact, privacy /dev/tty."""
import dataclasses
import os

import pytest
from fastapi.testclient import TestClient

from app import api_agent
from app.main import create_app
from tests.conftest import ORIGIN
from tests.helpers import act

REAL_WEB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "web"))


@pytest.fixture()
def wclient(cfg):
    return TestClient(create_app(dataclasses.replace(cfg, web_dir=REAL_WEB)), base_url=ORIGIN)


def test_default_rate_is_300_with_burst():
    assert api_agent.RATE == 300


def test_429_text_and_refusals(client, owner):
    ag, hdr = owner.new_agent()
    for i in range(api_agent.RATE):
        assert act(client, hdr, "read_file", {"p": i}).status_code == 200
    r = act(client, hdr, "read_file", {"p": "x"})
    assert r.status_code == 429 and r.json()["error"] == "RATE_LIMIT"
    assert r.json()["detail"] == "slow down: %d requests a minute per key; the call did not run" % api_agent.RATE


def test_reads_have_their_own_window(client, owner):
    ag, hdr = owner.new_agent()
    for i in range(api_agent.RATE):
        assert act(client, hdr, "read_file", {"p": i}).status_code == 200
    assert act(client, hdr, "read_file", {}).status_code == 429
    assert client.get("/v1/hook/scanlist", headers=hdr).status_code != 429      # a read still passes while the writes are full


def test_reads_are_limited_too(client, owner):
    ag, hdr = owner.new_agent()
    codes = [client.get("/v1/salt", headers=hdr).status_code for _ in range(api_agent.RATE + 2)]
    assert codes[-1] == 429 and codes.count(429) == 2


def test_security_txt(wclient):
    r = wclient.get("/.well-known/security.txt")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    t = r.text
    assert "Contact: mailto:support@sipkigroup.com" in t
    assert "Policy: https://github.com/sipkigroup/witness/blob/main/SECURITY.md" in t
    exp = [l for l in t.splitlines() if l.startswith("Expires: ")]
    assert len(exp) == 1
    import datetime
    d = datetime.datetime.strptime(exp[0][9:], "%Y-%m-%dT%H:%M:%SZ")
    delta = d - datetime.datetime(2026, 10, 25)
    assert 300 < delta.days < 366                               # RFC 9116: under a year ahead
    assert wclient.head("/.well-known/security.txt").status_code == 200
    assert wclient.get("/.well-known/other.txt").status_code == 404
    assert wclient.get("/.well-known/../OTCHET-02.md").status_code == 404


def test_contact_and_privacy_text(wclient):
    for page in ("/privacy.html", "/terms.html"):
        t = wclient.get(page).text
        assert "support@sipkigroup.com" in t and "@gmail.com" not in t
    p = wclient.get("/privacy.html").text
    assert "not to the terminal output or a file" not in p and "/dev/tty" in p and "history" in p
