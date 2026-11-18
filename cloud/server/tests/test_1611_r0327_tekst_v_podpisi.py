"""r0327 (law "Signed = shown", Constitution): the text of trust shown when a "from now on" rule is signed is part of the signature.

Format: the rule's `view` (bstr 32, already a member of the core's allowance map: no new member, every older checker still reads it) is
SHA-256 over RFC 8785 of {"v": "dw-allow-view-1", "page": <the approval page's dw-view-1 object>, "text_v": <version>, "text": <text, whole>}.
The server accepts only the text of ITS offer; the pack carries the object as views/allowance-<id>.json; the checker rebuilds the hash and
requires a known version (packtools/screencheck.ALLOW_TEXT_SHA256). A rule signed before r0327 (view = the page alone) stays VALID and is
marked. Real server (TestClient), real ledger, real pack and both checkers."""
import hashlib
import json
import os

import pytest

from app import allowances as al
from app import signview
from tests.test_pv2_view import _allow, _dev, _get, _entries, _allow_view, X
from tests.test_0224_critique import row

SC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packtools")


def _sc():
    import importlib.util
    spec = importlib.util.spec_from_file_location("screencheck_r0327", os.path.join(SC_DIR, "screencheck.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _wrapper_of(g, text_v=None, text=None):
    o = g["allowance_offer"]
    obj = al.allow_view(signview.view_of({k: v for k, v in g.items() if k not in X}), text_v or o["text_v"], text if text is not None else o["text"])
    return hashlib.sha256(signview.jcs(obj)).digest()


# ------------------------------------------------------------------ the server

def test_new_rule_signs_page_and_text(client, owner, tmp_path):
    d, rid = _dev(client, owner, tmp_path)
    g = _get(owner, rid)
    assert g["allowance_offer"]["text"] == al.TRUST_TEXT and g["allowance_offer"]["text_v"] == "tt-2"
    r, a, signed = _allow(d, rid, g=g)
    assert r.status_code == 200, r.text
    assert signed == _allow_view(g) and signed != signview.view_hash({k: v for k, v in g.items() if k not in X})
    [b] = [b for b in _entries(client.app, owner.account["id"], "ALLOWANCE") if b["allowance"]["id"] == a["id"]]
    assert b["allowance"]["view"] == signed and set(b["allowance"]) - {"view"} == {"v", "t", "id", "mandate", "class", "commands", "project",
                                                                                    "nbf", "exp"}    # no new member in the core's map
    db = client.app.state.ctx.db
    obj = json.loads(db.one("SELECT view_json FROM shown_views WHERE sha256=?", (signed.hex(),))["view_json"])
    assert obj["v"] == "dw-allow-view-1" and obj["text"] == al.TRUST_TEXT and obj["text_v"] == "tt-2" and obj["page"]["rid"] == rid
    assert hashlib.sha256(signview.jcs(obj)).digest() == signed
    [it] = [x for x in owner.c.get("/api/allowances").json()["items"] if x["id"] == a["id"]]
    assert it["text_v"] == "tt-2" and it["text"] == al.TRUST_TEXT
    assert d.verdicts("pytest -q") == [("Bash", "allow", "OK_ALLOWANCE")]


def test_page_alone_or_another_text_is_refused(client, owner, tmp_path):
    d, rid = _dev(client, owner, tmp_path)
    g = _get(owner, rid)
    r, _, _ = _allow(d, rid, sign_view="page", g=g)                               # a page before r0327: the text is not signed
    assert r.status_code == 409 and r.json()["error"] == "ALLOWANCE_TEXT_NOT_SIGNED", r.text
    for tv, text in (("tt-1", al.TRUST_TEXT_V1),                                 # the old (untrue) text, its own version name
                     ("tt-2", al.TRUST_TEXT_V1),                                 # the old text under the current name
                     ("tt-2", al.TRUST_TEXT + " "),                              # one character changed
                     ("tt-3", al.TRUST_TEXT),                                    # an unknown version name
                     ("am-1", al.TRUST_TEXT)):
        r, _, _ = _allow(d, rid, sign_view=_wrapper_of(g, tv, text), g=g)
        assert r.status_code == 409 and r.json()["error"] == "ALLOWANCE_MISMATCH", (tv, r.text)
    assert row(client, rid)["status"] == "pending_approval"
    assert client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM allowances")["n"] == 0


def test_amendment_offer_names_its_own_text():
    from app import amend
    assert al.text_version(amend.TEXT) == "am-1" and al.text_version(al.TRUST_TEXT) == "tt-2" and al.text_version("x") is None
    assert al.texts()["tt-1"] == al.TRUST_TEXT_V1 != al.TRUST_TEXT


def _old_rule(client, owner, tmp_path, monkeypatch):
    """A rule as the server before r0327 recorded it: view = the page alone, no text (the version check stood aside)."""
    d, rid = _dev(client, owner, tmp_path)
    monkeypatch.setattr(al, "_allow_shown", lambda ctx, acc_id, view, o: (view, None))
    r, a, signed = _allow(d, rid, sign_view="page")
    monkeypatch.undo()
    assert r.status_code == 200, r.text
    return d, rid, a, signed


def test_old_rule_is_listed_as_signed_before_the_text(client, owner, tmp_path, monkeypatch):
    d, rid, a, signed = _old_rule(client, owner, tmp_path, monkeypatch)
    [it] = [x for x in owner.c.get("/api/allowances").json()["items"] if x["id"] == a["id"]]
    assert it["text_v"] is None and it["text"] is None
    # r1611: it stays listed (and valid in the pack) but its first use is asked again: see test_1611_kand1_migr_vpred.py


# ------------------------------------------------------------------ the pack (both checkers)

def _client_verify(folder, *flags):
    from tests.test_0283_shown_views import _client_verify as cv
    return cv(folder, *flags)


def test_pack_new_rule_valid_and_text_named(client, owner, tmp_path):
    from tests.recovery_helpers import export_to, run_verify
    d, rid = _dev(client, owner, tmp_path)
    r, a, signed = _allow(d, rid)
    assert r.status_code == 200, r.text
    folder = export_to(owner.c, tmp_path / "pack")
    obj = json.load(open(os.path.join(folder, "views", "allowance-%s.json" % a["id"]), encoding="utf-8"))
    assert obj["v"] == "dw-allow-view-1" and obj["text"] == al.TRUST_TEXT
    rc, out = run_verify(folder, "--offline", "--require-views")
    assert rc == 0 and out.strip().endswith("RESULT: VALID"), out
    assert "allowance %s: text of trust tt-2 signed with the page" % a["id"] in out, out
    assert "ALLOW_TEXT_NOT_SIGNED" not in out, out
    rc, out2 = _client_verify(folder, "--offline", "--require-views")
    assert rc == 0 and out2.strip().endswith("RESULT: VALID"), out2


def test_pack_edited_text_is_invalid(app, tmp_path):
    """The text in views/allowance-<id>.json is changed (and the manifest re-sealed with the witness key): the passkey signed the old
    object -> VIEW_MISMATCH in both checkers."""
    import cbor2
    from app.export import seal
    from svidetel_v4 import cose
    from tests.recovery_helpers import Person, export_to, run_verify
    from tests.test_allowance_0210 import Dev
    p = Person(app).register("Tia")
    proj = tmp_path / "proj"
    proj.mkdir()
    d = Dev(p.c, p, proj.resolve())
    [(tool, x)] = d.send("pytest -q")
    r, a, signed = _allow(d, x["rid"])
    assert r.status_code == 200, r.text
    folder = export_to(p.c, tmp_path / "pack")
    fp = os.path.join(folder, "views", "allowance-%s.json" % a["id"])
    o = json.load(open(fp, encoding="utf-8"))
    o["text"] = al.TRUST_TEXT_V1                                    # the promise a forger would like the person to have read
    o["text_v"] = "tt-1"
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(o, f)
    files = {}
    for dp, _, fs in os.walk(folder):
        for n in fs:
            full = os.path.join(dp, n)
            rel = os.path.relpath(full, folder)
            if rel not in ("manifest.json", "manifest.cose"):
                files[rel] = open(full, "rb").read()
    sg = cbor2.loads(cose.parse1(open(os.path.join(folder, "manifest.cose"), "rb").read())[2])
    m = json.load(open(os.path.join(folder, "manifest.json")))
    seal(files, app.state.ctx.wk, m["account"], m["principal"], m["witness"]["iss"], m["created_t"], sg["cp_seq"], sg["cp_head"])
    for n in ("manifest.json", "manifest.cose"):
        open(os.path.join(folder, n), "wb").write(files[n])
    rc, out = run_verify(folder, "--offline")
    assert rc != 0 and "VIEW_MISMATCH" in out and out.strip().endswith("RESULT: INVALID"), out
    rc, out2 = _client_verify(folder, "--offline")
    assert rc != 0 and "VIEW_MISMATCH" in out2 and "RESULT: INVALID" in out2, out2


def test_pack_old_rule_valid_and_marked(client, owner, tmp_path, monkeypatch):
    from tests.recovery_helpers import export_to, run_verify
    d, rid, a, signed = _old_rule(client, owner, tmp_path, monkeypatch)
    folder = export_to(owner.c, tmp_path / "pack")
    rc, out = run_verify(folder, "--offline", "--require-views")
    assert rc == 0 and out.strip().endswith("RESULT: VALID"), out
    assert "allowance %s: warning ALLOW_TEXT_NOT_SIGNED" % a["id"] in out, out
    assert "not signed (signed before the text became part of the signature" in out, out


# ------------------------------------------------------------------ the checker's table and rule (offline, standard library)

def test_checker_table_equals_server_versions():
    sc = _sc()
    assert sc.ALLOW_VIEW_V == al.ALLOW_VIEW_V
    assert sc.ALLOW_TEXT_SHA256 == {k: hashlib.sha256(t.encode("utf-8")).hexdigest() for k, t in al.texts().items()}


@pytest.mark.parametrize("case,code", [
    ("good", None), ("old_page", "ALLOW_TEXT_NOT_SIGNED"), ("unknown_text", "ALLOW_TEXT_UNKNOWN"), ("wrong_version", "ALLOW_TEXT_UNKNOWN"),
    ("extra_member", "ALLOW_TEXT_UNKNOWN"), ("page_not_object", "ALLOW_TEXT_UNKNOWN")])
def test_checker_rule(case, code):
    sc = _sc()
    page = {"v": "dw-view-1", "rid": "r1", "status": "pending_approval"}
    good = al.allow_view(page, "tt-2", al.TRUST_TEXT)
    view = {"good": good, "old_page": page, "unknown_text": dict(good, text=al.TRUST_TEXT + "!"), "wrong_version": dict(good, text_v="am-1"),
            "extra_member": dict(good, x=1), "page_not_object": dict(good, page="r1")}[case]
    assert sc.allow_text_check(view)[1] == code


def test_web_text_and_wrapper_match_the_server():
    """web/js/allowance.js keeps TRUST_TEXT = tt-2 and the object's member names (the JS test checks the hash against this vector)."""
    js = open(os.path.join(os.path.dirname(SC_DIR), "..", "web", "js", "allowance.js"), encoding="utf-8").read()
    assert "export const ALLOW_VIEW_V = 'dw-allow-view-1';" in js
    assert "{ v: ALLOW_VIEW_V, page: pageView, text_v: offer.text_v, text: offer.text }" in js
