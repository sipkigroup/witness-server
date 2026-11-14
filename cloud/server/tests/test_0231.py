"""0.2.31: site text follows the code (first use reported at once, then a summary every 10 min); /pricing/ page."""
import os

from fastapi.testclient import TestClient  # noqa: F401

from app import notify

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read(*p):
    return open(os.path.join(CLOUD, *p), encoding="utf-8").read()


def test_0231_report_text_matches_the_code():
    idx = _read("web", "index.html")
    assert "every use is reported" not in idx
    assert "first use is reported to your channels at once" in idx and "every 10 minutes" in idx
    assert notify.DIGEST_GAP_S == 600


def test_0231_pricing_page_and_link():
    idx = _read("web", "index.html")
    assert 'href="/pricing/"' in idx and "Pricing after early access" not in idx
    pg = _read("web", "pricing", "index.html")
    # r0288 (owner 13.11): one person free, no "for good"; teams free during the beta
    assert "If this ever changes, existing accounts stay free and we announce it in advance." in pg and "Teams: free during the beta" in pg
    assert "Pricing not published yet" not in pg and "Team and Enterprise" not in pg and 'id="teamreq"' in pg
    # 24.10 (ошибка ×2: пин версии ломался на каждом выпуске): не ниже 0.2.31, а не список
    assert tuple(map(int, _read("deploy", "VERSION").strip().split("."))) >= (0, 2, 31)


def test_0231_pricing_is_served(tmp_path):
    from app.config import Config
    from app.main import create_app
    from tests.helpers import ORIGIN, RP
    kf = tmp_path / "k"
    kf.write_text("a1" * 32)
    c = Config(data_dir=str(tmp_path / "d"), witness_key_file=str(kf), key_pepper="p", rp_id=RP, origin=ORIGIN, iss="https://w.test",
               anchor="off", web_dir=os.path.join(CLOUD, "web"))
    cl = TestClient(create_app(c), base_url=ORIGIN)
    for path in ("/pricing/", "/pricing", "/pricing/index.html"):
        r = cl.get(path)
        assert r.status_code == 200 and "Free for one person" in r.text, path
    assert cl.get("/pricing/x.md").status_code == 404
