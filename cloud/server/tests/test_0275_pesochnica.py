"""0.2.75 (sandbox «живой человек», poligon-lyudi/pesochnica): APPROVAL_SIG / N24 (an older module from the browser's cache mixed into a newer
page), N23 (trial passkeys of one day had the same name), N21 (the expired passkey step) - the server's part.
The browser part is in the sandbox itself (cells C10-C19) and in web/test (boot.test.mjs)."""
import dataclasses
import hashlib
import os
import re

from fastapi.testclient import TestClient

from tests.helpers import H, ORIGIN, RP
from tests.test_0238_trial import Person, new_trial
from tests.test_flow import act, setup_agent
import wa_profile as wa

REAL_WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "web")
BROWSER = {"sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty"}


def real(cfg):
    from app.main import create_app
    return TestClient(create_app(dataclasses.replace(cfg, web_dir=os.path.abspath(REAL_WEB))), base_url=ORIGIN)


def test_every_module_address_names_the_build(cfg):
    c = real(cfg)
    b = c.get("/api/build")
    assert b.status_code == 200 and b.headers["cache-control"] == "no-store"
    v = b.json()["build"]
    assert re.fullmatch(r"[0-9a-f]{16}", v)
    for page in ("/approve.html", "/trial.html", "/login.html", "/devices.html", "/mandate.html", "/demo/index.html", "/pricing/index.html"):
        t = c.get(page).text
        src = re.findall(r'<script type="module" src="([^"]+)"', t)
        assert src and all(s.endswith(".js?v=" + v) for s in src), (page, src)
        assert any("js/boot.js?v=" + v in s for s in src), page                 # the build check is its own module graph on every page
        assert re.search(r'href="/?css/app\.css\?v=' + v + '"', t), page
    for name in sorted(os.listdir(os.path.join(REAL_WEB, "js"))):
        if not name.endswith(".js"):
            continue
        j = c.get("/js/" + name).text
        bare = re.findall(r"""(?:\bfrom|\bimport)\s*\(?\s*['"](\./[A-Za-z0-9_]+\.js)['"]""", j)
        assert not bare, (name, bare)                                            # no import without the build in its address
        assert "__DW_BUILD__" not in j, name
    assert "approvalPayload" in c.get("/js/approve.js").text and "./profile.js?v=" + v in c.get("/js/approve.js").text
    assert "BUILD = '%s'" % v in c.get("/js/api.js").text and "MINE = '%s'" % v in c.get("/js/boot.js").text


def test_served_bytes_are_what_is_published_and_cached(cfg):
    c = real(cfg)
    hs = c.get("/api/witness").json()["web_js_sha256"]
    for name in ("js/approve.js", "js/profile.js", "js/boot.js", "approve.html", "trial.html", "css/app.css", "sw.js"):
        body = c.get("/" + name).content
        assert hs[name] == hashlib.sha256(body).hexdigest(), name                # the reader checks what the browser runs
    r = c.get("/js/approve.js")
    assert r.headers["cache-control"] == "no-cache" and "last-modified" not in r.headers
    assert c.get("/js/approve.js", headers={"if-none-match": r.headers["etag"]}).status_code == 304
    hd = c.head("/js/approve.js")
    assert hd.status_code == 200 and int(hd.headers["content-length"]) == len(r.content) and hd.content == b""
    assert c.get("/js/approve.js?v=anything").content == r.content            # the address' build is a cache key only


def test_build_follows_the_content(cfg):
    from app.main import create_app
    w = cfg.web_dir
    os.makedirs(w + "/js")
    open(w + "/js/a.js", "w").write("import { x } from './b.js';\nexport const B = '__DW_BUILD__';\n")
    open(w + "/js/b.js", "w").write("export const x = 1;\n")
    open(w + "/p.html", "w").write('<script type="module" src="js/a.js"></script>')
    c = TestClient(create_app(cfg), base_url=ORIGIN)
    v1 = c.get("/api/build").json()["build"]
    assert c.get("/js/a.js").text == "import { x } from './b.js?v=%s';\nexport const B = '%s';\n" % (v1, v1)
    assert c.get("/p.html").text == '<script type="module" src="js/a.js?v=%s"></script>' % v1
    open(w + "/js/b.js", "w").write("export const x = 2; // changed\n")
    v2 = c.get("/api/build").json()["build"]
    assert v2 != v1 and "./b.js?v=%s'" % v2 in c.get("/js/a.js").text and "a.js?v=%s" % v2 in c.get("/p.html").text


def test_old_page_is_told_to_drop_its_cache(cfg):
    c = real(cfg)
    assert c.get("/api/me", headers=BROWSER).headers.get("clear-site-data") == '"cache"'          # an old api.js: no X-DW-Build
    assert c.post("/api/auth/login/begin", headers=dict(BROWSER, **H), json={}).headers.get("clear-site-data") == '"cache"'
    assert "clear-site-data" not in c.get("/api/me", headers=dict(BROWSER, **{"x-dw-build": "x"})).headers   # a page of 0.2.75+
    assert "clear-site-data" not in c.get("/api/me").headers                                     # an agent / a script
    assert "clear-site-data" not in c.get("/api/approvals", headers=BROWSER).headers             # polling: only /api/me and POSTs
    assert "clear-site-data" not in c.get("/api/build").headers
    assert c.get("/api/build?clear=1").headers.get("clear-site-data") == '"cache"'


def test_approval_sig_says_what_to_do(client, owner):
    _, hdr, _ = setup_agent(owner)
    r = act(client, hdr, "publish", {"channel": "b", "text": "t"}).json()
    g = client.get("/api/approvals/" + r["rid"]).json()
    from svidetel_v4.state import approval_payload
    wrong = owner.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], r["rid"], False))     # signed "refuse", sent as approve
    x = owner.post("/api/approvals/" + r["rid"], approved=True, envelope_b64=wrong)
    j = x.json()
    assert x.status_code == 409 and j["error"] == "APPROVAL_SIG"                                 # still refused: the format is not relaxed
    assert "Nothing was approved" in j["detail"] and "Reload the page" in j["detail"]
    assert "clear-site-data" not in x.headers                                                    # not a browser request
    y = client.post("/api/approvals/" + r["rid"], json={"approved": True, "envelope_b64": wrong}, headers=dict(BROWSER, **H, **{"x-dw-build": "x"}))
    assert y.json()["error"] == "APPROVAL_SIG" and y.headers.get("clear-site-data") == '"cache"'
    assert owner.approve(r["rid"]).status_code == 200


def test_trial_passkeys_have_distinct_names_and_the_sign_in_names_the_account(client, app, tmp_path):
    from tests.test_0238_trial import hook, proj
    names, people = [], []
    for i in range(2):
        t = new_trial(client, tmp_path)
        p = Person(app, t["claim"])
        b = p.post("/api/trial/claim/begin", claim=t["claim"]).json()
        names.append(b["options"]["user"]["name"])
        assert b["options"]["user"]["displayName"] == b["options"]["user"]["name"]
        assert p.claim_it().status_code == 200
        people.append((t, p))
    assert names[0] != names[1]
    for n, (t, p) in zip(names, people):
        assert re.fullmatch(r"Trial \d{4}-\d\d-\d\d \d\d:\d\d UTC - [0-9A-F]{6}", n), n
        assert p.c.get("/api/me").json()["account"]["display_name"].startswith("Trial ")
    # a call of account 2 waits; the sign-in page opened from its link names account 2 and offers only account 2's passkey
    t2, p2 = people[1]
    assert p2.sign_mandate().status_code == 200
    out = hook(client, t2["api_key"], proj(tmp_path, "p2"), tmp_path, wait=0, timeout=5)("python3 hello.py")
    rid = re.search(r"r_[A-Z2-7]{10,}", (out.get("hookSpecificOutput") or {}).get("permissionDecisionReason", ""))
    assert rid, out
    anon = TestClient(app, base_url=ORIGIN)
    plain = anon.post("/api/auth/login/begin", json={}, headers=H).json()
    assert plain["options"]["allowCredentials"] == [] and "hint" not in plain
    hb = anon.post("/api/auth/login/begin", json={"rid": rid.group(0)}, headers=H).json()
    assert hb["hint"]["name"] == names[1] and len(hb["options"]["allowCredentials"]) == 1
    junk = anon.post("/api/auth/login/begin", json={"rid": "r_AAAAAAAAAAAAAAAAAAAAAAAAAA"}, headers=H).json()
    assert junk["options"]["allowCredentials"] == [] and "hint" not in junk
    bad = anon.post("/api/auth/login/begin", json={"rid": ["x"]}, headers=H).json()
    assert "hint" not in bad


def test_login_hint_only_for_trial_accounts(client, owner):
    _, hdr, _ = setup_agent(owner)
    r = act(client, hdr, "publish", {"channel": "b", "text": "t"}).json()
    anon = TestClient(client.app, base_url=ORIGIN)
    b = anon.post("/api/auth/login/begin", json={"rid": r["rid"]}, headers=H).json()
    assert "hint" not in b and b["options"]["allowCredentials"] == []          # a full account's name and keys are never given out by a rid
    assert anon.post("/api/auth/login/begin", headers=H).status_code == 200     # no body: as before


def test_flow_unknown_unchanged(client):
    # the code stays FLOW_UNKNOWN (the page says it in words: web/js/webauthn.js FLOW_EXPIRED_TEXT, trial.js passkeyStepText)
    r = client.post("/api/auth/register/finish", json={"flow_id": "nope", "credential": {}}, headers=H)
    assert r.status_code == 400 and r.json()["error"] == "FLOW_UNKNOWN"
    assert RP == "localhost"
