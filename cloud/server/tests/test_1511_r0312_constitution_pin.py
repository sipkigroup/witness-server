"""r0312: every version of the public constitution is pinned - a hash in web/constitution/versions.json, an immutable copy at
/constitution/v<N>, one leaf in the witness's signed public log - so an edit of the page without a new version is caught
(packtools/constitution_check.py, offline)."""
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import tlog                        # noqa: I001  (first: puts packtools/ on sys.path)
import tlogcheck as TC  # noqa: E402
import constitution_check as CC  # noqa: E402
from app.config import Config
from app.main import create_app
from tests.helpers import ORIGIN, RP

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
PAGE = WEB / "constitution.html"
VERSIONS = WEB / "constitution" / "versions.json"

# Published hashes, never changed once here. A new version APPENDS a line (and a copy file, and an entry in versions.json); an edit of
# a published text or hash fails test_published_versions_are_never_rewritten.
PUBLISHED = {1: "39e384ebd215fc28d22b01470f7f0a6fef83e496914c0de628621ae3f903b4d1",
             2: "2a322f50d5e12243760ffa8c41b62a56cd05fa3e111c1b6eed83fcd30fb0bb73",
             3: "97ac9580ff04b5d43486e25fb7663a899deaec54285f056b6e7a0260ae463867"}


def _vs():
    return json.loads(VERSIONS.read_text())


def _web_copy(tmp_path):
    w = tmp_path / "web"
    (w / "constitution").mkdir(parents=True)
    shutil.copy(PAGE, w / "constitution.html")
    for f in (WEB / "constitution").iterdir():
        shutil.copy(f, w / "constitution" / f.name)
    return w


def _app(tmp_path, web):
    kf = tmp_path / "witness_key"
    kf.write_text("a1" * 32)
    cfg = Config(data_dir=str(tmp_path / "data"), witness_key_file=str(kf), key_pepper="test-pepper", rp_id=RP, origin=ORIGIN,
                 iss="https://witness.test", anchor="off", web_dir=str(web))
    return create_app(cfg)


def _leaves(ctx):
    return [bytes(r["leaf"]) for r in ctx.db.q("SELECT leaf FROM tlog_leaves ORDER BY idx")]


# (a) the current page is the latest version, and says so
def test_current_page_is_the_latest_version():
    ok, why = CC.check_constitution(PAGE.read_bytes(), VERSIONS.read_bytes(), web_dir=str(WEB))
    assert ok, why
    assert _vs()[-1]["path"] and CC.page_hash(PAGE.read_bytes()) == _vs()[-1]["sha256"]


# (b) one changed character without a new version -> INVALID
def test_one_character_edit_without_a_new_version_is_invalid():
    page = PAGE.read_bytes()
    i = page.index(b"Silence is a no")
    edited = page[:i] + b"s" + page[i + 1:]
    ok, why = CC.check_constitution(edited, VERSIONS.read_bytes())
    assert not ok and "no published version" in why, why
    ok, why = CC.check_constitution(page.replace(b"Version 3 (2026-11-15)", b"Version 3 (2026-11-16)"), VERSIONS.read_bytes())
    assert not ok, why
    ok, why = CC.check_constitution((WEB / "constitution" / "v1.html").read_bytes(), VERSIONS.read_bytes())
    assert not ok and "not the latest" in why, why                 # serving an old version as the current page
    # the build tag the server adds when it serves the page is the only thing the hash ignores
    served = page.replace(b'href="/css/app.css"', b'href="/css/app.css?v=0123456789abcdef"')
    assert served != page and CC.check_constitution(served, VERSIONS.read_bytes())[0]


# (c) the copies are unchanged and published hashes are never rewritten
def test_published_versions_are_never_rewritten():
    vs = _vs()
    assert [e["version"] for e in vs][:len(PUBLISHED)] == sorted(PUBLISHED)
    for e in vs:
        assert CC.page_hash((WEB / e["path"]).read_bytes()) == e["sha256"], e
        if e["version"] in PUBLISHED:
            assert e["sha256"] == PUBLISHED[e["version"]], e
    assert len(vs) == len(PUBLISHED), "a new version: add its hash to PUBLISHED"


def test_the_permanent_addresses_serve_the_copies(tmp_path):
    c = TestClient(_app(tmp_path, WEB), base_url=ORIGIN)
    for e in _vs():
        for addr in ("/constitution/v%d" % e["version"], "/constitution/v%d.html" % e["version"]):
            r = c.get(addr)
            assert r.status_code == 200 and r.headers["content-type"].startswith("text/html"), addr
            assert CC.page_hash(r.content) == e["sha256"], addr               # served bytes (with the build tag) -> the same hash
    r = c.get("/constitution.html")
    assert r.status_code == 200 and CC.check_constitution(r.content, c.get("/constitution/versions.json").content)[0]
    assert c.get("/constitution/v99").status_code == 404


# (d) every version is in the signed log, exactly once, also after a restart
def test_every_version_is_logged_once_and_signed(tmp_path):
    web = _web_copy(tmp_path)
    app = _app(tmp_path, web)
    ctx = app.state.ctx
    leaves = _leaves(ctx)
    assert sorted(TC.parse_constitution_leaf(lf) for lf in leaves) == sorted((e["version"], e["sha256"]) for e in _vs())
    ok, why = CC.check_constitution(PAGE.read_bytes(), VERSIONS.read_bytes(), journal=leaves)
    assert ok, why
    # the leaf is under a checkpoint signed by the witness key
    c = TestClient(app, base_url=ORIGIN)
    cp = TC.open_checkpoint(c.get("/checkpoint").text, [c.get("/tlog/vkey").text.strip()])
    lf = c.get("/tlog/leaf", params={"batch": "constitution:1"}).json()
    pr = c.get("/tlog/proof/inclusion", params={"index": lf["index"], "size": cp["size"]}).json()
    assert TC.verify_inclusion(TC.leaf_hash(TC.b64d(lf["leaf_b64"])), lf["index"], cp["size"], [TC.b64d(x) for x in pr["path"]], cp["root"])
    # a restart (and a second call) writes nothing again
    assert tlog.record_constitution(ctx, str(web)) == []
    ctx._tlog = None
    assert tlog.record_constitution(ctx, str(web)) == []
    assert _leaves(ctx) == leaves
    # the log is the anchor: a journal with a version twice, or with another hash for it, is INVALID
    assert not CC.check_constitution(PAGE.read_bytes(), VERSIONS.read_bytes(), journal=leaves + leaves[:1])[0]
    fake = [TC.constitution_leaf(1, "0" * 64) if TC.parse_constitution_leaf(x)[0] == 1 else x for x in leaves]
    ok, why = CC.check_constitution(PAGE.read_bytes(), VERSIONS.read_bytes(), journal=fake)
    assert not ok and "rewritten" in why, why


# (e) a new version that is not in the log does not pass; a rewritten version is not logged again
def test_a_new_version_not_in_the_log_fails(tmp_path):
    web = _web_copy(tmp_path)
    app = _app(tmp_path, web)
    ctx = app.state.ctx
    logged = _leaves(ctx)
    page = PAGE.read_bytes().replace(b"Version 3 (2026-11-15)", b"Version 4 (2026-11-20)").replace(b"<h2>More laws", b"<h2>Other laws")
    page = page.replace(b'data-effective="2026-11-15" data-corrects="by-construction silence-is-a-no"', b'data-effective="2026-11-20" data-corrects=""')
    (web / "constitution" / "v4.html").write_bytes(page)
    vs = _vs() + [dict(_vs()[-1], version=4, date="2026-11-20", sha256=CC.page_hash(page), path="constitution/v4.html", effective="2026-11-20",
                       corrects=[])]
    ok, why = CC.check_constitution(page, json.dumps(vs), journal=logged)
    assert not ok and "version 4 is not in the signed log" in why, why
    # the server logs it on its next start, once
    (web / "constitution" / "versions.json").write_text(json.dumps(vs))
    assert tlog.record_constitution(ctx, str(web)) == [4]
    assert CC.check_constitution(page, json.dumps(vs), journal=_leaves(ctx))[0]
    # versions.json rewritten in place (version 4 with another text): not logged, an ERROR, and INVALID offline
    page2 = page.replace(b"<h2>Other laws", b"<h2>Further laws")
    (web / "constitution" / "v4.html").write_bytes(page2)
    vs[3]["sha256"] = CC.page_hash(page2)
    (web / "constitution" / "versions.json").write_text(json.dumps(vs))
    n = len(_leaves(ctx))
    assert tlog.record_constitution(ctx, str(web)) == [] and len(_leaves(ctx)) == n
    ok, why = CC.check_constitution(page2, json.dumps(vs), journal=_leaves(ctx))
    assert not ok and "rewritten" in why, why


def test_malformed_versions_are_invalid():
    page = PAGE.read_bytes()
    vs = _vs()
    for bad in (vs[1:], [vs[0], dict(vs[1], date="2026-11-01")], [vs[0], dict(vs[1], sha256=vs[0]["sha256"])], [], "x"):
        assert not CC.check_constitution(page, json.dumps(bad))[0], bad


def test_cli(tmp_path, capsys):
    assert CC._cli([str(PAGE), str(VERSIONS)]) == 0
    p = tmp_path / "c.html"
    p.write_bytes(PAGE.read_bytes().replace(b"Silence", b"silence"))
    assert CC._cli([str(p), str(VERSIONS)]) == 2
    assert "INVALID" in capsys.readouterr().out
