"""27.10 polygon series 2, N1: the site's static files must reach a returning person after a release.
The release image touches every file to SOURCE_DATE_EPOCH (2025-10-19), so mtime-based Last-Modified/ETag never change between
releases and, without Cache-Control, a browser keeps old JS by heuristic freshness. Static answers: Cache-Control no-cache,
an ETag of the CONTENT (sha256), no Last-Modified, 304 on a matching If-None-Match only."""
import os

from fastapi.testclient import TestClient

from app.main import create_app
from tests.helpers import ORIGIN


def _site(cfg, files):
    for rel, body in files.items():
        p = os.path.join(cfg.web_dir, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(body)
        os.utime(p, (1760832000, 1760832000))           # every release: the same mtime


def test_n1_static_no_cache_content_etag(cfg):
    _site(cfg, {"js/a.js": "export const v = 1;\n", "approve.html": "<!doctype html><p>v1</p>", "css/app.css": "p{}"})
    c = TestClient(create_app(cfg), base_url=ORIGIN)
    for path in ("/js/a.js", "/approve.html", "/css/app.css"):
        r = c.get(path)
        assert r.status_code == 200
        assert r.headers.get("cache-control") == "no-cache", path
        assert "last-modified" not in r.headers, path
        assert r.headers["etag"].startswith('"') and len(r.headers["etag"]) == 34
    e1 = c.get("/js/a.js").headers["etag"]
    r = c.get("/js/a.js", headers={"If-None-Match": e1})
    assert r.status_code == 304 and r.content == b"" and r.headers["etag"] == e1 and r.headers["cache-control"] == "no-cache"
    # a release: same size, same mtime, other content -> other ETag, full body
    _site(cfg, {"js/a.js": "export const v = 2;\n"})
    r = c.get("/js/a.js", headers={"If-None-Match": e1, "If-Modified-Since": "Sun, 19 Oct 2025 00:00:00 GMT"})
    assert r.status_code == 200 and b"v = 2" in r.content and r.headers["etag"] != e1
    h = c.head("/js/a.js")
    assert h.status_code == 200 and h.headers["cache-control"] == "no-cache"
