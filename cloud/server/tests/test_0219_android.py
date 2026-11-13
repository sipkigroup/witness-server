"""0.2.19 (fixes from the Android pass, OTCHET-ANDROID-2026-10-21.md):
- item 7: "Last used" of a passkey moves with every verified SIGNATURE (mandate, approve, refuse), not only with the sign-in;
- item 6: the server sets / clears the readable marker cookie `dw_in` that lets public pages skip /api/me;
- item 8: pubKeyCredParams stays ES256 only -- the verification (app/auth.py _cose_key, wa_profile.verify_envelope) is P-256 only;
- sign_count: documented (not changed) -- a signed approval does not look at the counter."""
import re

from tests.helpers import H, act
from tests.test_flow import setup_agent
import wa_profile as wa

APP = None


def _last_used(client):
    ks = client.get("/api/auth/keys").json()["keys"]
    return [k["last_used_at"] for k in ks]


def _reset(client, owner):
    client.app.state.ctx.db.x("UPDATE credentials SET last_used_at=NULL")


def test_last_used_moves_with_mandate_approve_refuse(client, owner):
    assert _last_used(client) == [None]                      # registration alone: never "used"
    ag, hdr, _ = setup_agent(owner)                          # signs a mandate
    t1 = _last_used(client)[0]
    assert isinstance(t1, int) and t1 > 0
    for approved in (True, False):
        _reset(client, owner)
        r = act(client, hdr, "publish", {"channel": "blog", "text": "t %s" % approved}).json()
        assert r["verdict"] == "defer", r
        assert _last_used(client) == [None]
        assert owner.approve(r["rid"], approved).status_code == 200
        assert isinstance(_last_used(client)[0], int)


def test_last_used_not_moved_by_rejected_signature(client, owner):
    ag, hdr, _ = setup_agent(owner)
    r = act(client, hdr, "publish", {"channel": "blog", "text": "x"}).json()
    _reset(client, owner)
    g = client.get("/api/approvals/" + r["rid"]).json()
    from svidetel_v4.state import approval_payload
    bad = approval_payload(g["mandate"], g["action"], r["rid"], False)       # signed for "refuse", sent as "approve"
    env = owner.sign(wa.TYP_APPROVAL, bad)
    x = owner.post("/api/approvals/" + r["rid"], approved=True, envelope_b64=env)
    assert x.status_code == 409
    assert _last_used(client) == [None]


def test_session_marker_cookie(client):
    from tests.helpers import Owner
    o = Owner(client)
    j = o.post("/api/auth/register/begin", display_name="x").json()
    cred = o.auth.create_credential(wa.b64u_dec(j["options"]["challenge"]), "localhost", "http://localhost:8810")
    r = o.post("/api/auth/register/finish", flow_id=j["flow_id"], credential=cred)
    sc = [v.lower() for k, v in r.headers.multi_items() if k == "set-cookie"]
    sess = [c for c in sc if c.startswith("dw_session=")][0]
    mark = [c for c in sc if c.startswith("dw_in=")][0]
    assert "httponly" in sess
    assert "httponly" not in mark and "samesite=strict" in mark and "dw_in=1" in mark      # readable by the page, carries no secret
    out = client.post("/api/auth/logout", headers=H)
    cleared = [v.lower() for k, v in out.headers.multi_items() if k == "set-cookie"]
    assert any(c.startswith("dw_in=") and ("max-age=0" in c or "1970" in c) for c in cleared)


def test_registration_offers_es256_only(client):
    from tests.helpers import Owner
    j = Owner(client).post("/api/auth/register/begin", display_name="x").json()
    assert j["options"]["pubKeyCredParams"] == [{"type": "public-key", "alg": -7}]       # item 8: RS256/EdDSA are NOT verified server side


def test_public_pages_have_manifest_and_js_guards():
    import glob
    import os
    web = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "web")
    # google<hex>.html — файл подтверждения Search Console (27.10), не страница; удалять нельзя
    pages = [p for p in glob.glob(os.path.join(web, "*.html"))
             if not re.fullmatch(r"google[0-9a-f]+\.html", os.path.basename(p))]
    assert pages
    for p in pages:
        assert 'rel="manifest"' in open(p, encoding="utf-8").read(), p
    ui = open(os.path.join(web, "js", "ui.js"), encoding="utf-8").read()
    assert "hasMarker()" in ui and re.search(r"requireLogin \|\| hasMarker\(\)", ui)          # item 6: no /api/me without a marker on public pages
    rec = open(os.path.join(web, "js", "recover.js"), encoding="utf-8").read()
    assert rec.count("mountNav(false)") >= 3                                             # item 5: header redrawn after the code and after the new passkey
