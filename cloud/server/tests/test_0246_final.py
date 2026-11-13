"""0.2.46 final fixes (OTCHET-0.2.46-FINAL.md): the order of equal git config keys is part of the confirmed set; the reader's error flag;
export tokens end when their issuer leaves the team or stops being an owner; the EXPORT_TOKEN_INVALID hint names a way that exists."""
import os

from app import execguard
from app.hookjudge import execfiles
from tests.org_helpers import TEAM_RULES, adopt, team
from tests.test_0213 import CC, one, project

ASK = "ESCALATE_EXEC_CHANGED"


def _cfg(p, text):
    (p / ".git" / "config").write_text(text)


# ---------------------------------------------------------------- 2. the digest keeps the file order
def test_digest_depends_on_order():
    a = [["diff.external", "/tmp/a"], ["diff.external", "/tmp/b"]]
    assert execguard._gitcfg_digest(a) != execguard._gitcfg_digest(a[::-1])


def test_swapping_two_equal_keys_asks_again(client, owner, tmp_path):
    """git uses the LAST diff.external: swapping the two lines changes the program git runs, so the confirmation must not cover it."""
    p = project(tmp_path)
    _cfg(p, "[diff]\n\texternal = /tmp/a\n\texternal = /tmp/b\n")
    d = CC(client, owner, p)
    r = one(d, "git status")
    assert r["reason"] == ASK
    assert owner.approve(r["rid"]).json()["verdict"] == "allow"
    r2 = one(d, "git status")
    assert r2["rid"] == r["rid"] and d.present(r2["rid"])["result"] == "accept"
    assert one(d, "git status")["reason"] == "OK"
    _cfg(p, "[diff]\n\texternal = /tmp/b\n\texternal = /tmp/a\n")
    assert one(d, "git status")["reason"] == ASK


# ---------------------------------------------------------------- 1. the reader's error flag
def test_reader_flags_what_git_refuses_and_not_what_it_accepts():
    for bad in ("[diff\n\texternal = /e\n", "[core]\n\tnot a key\n", "[core]\n\tx = a\\qb\n", '[core]\n\tx = "a\nb"\n',
                "[core ]\n", '[diff "x" junk]\n', "x = 1\n", "[core]\n\t1x = 1\n", '[core]\n\tx = "a', "[core]\n\tx ; c\n"):
        assert execfiles.read_git_config(bad)[1], repr(bad)
    for good in ("﻿[diff]\n\texternal = /e\n", '[diff "x"] # c\n\ttextconv = "/a#b" ;d\n', "[core]\n\tx\n\ty =\n", "[a.B]\n\tc = d\\\ne\n"):
        assert not execfiles.read_git_config(good)[1], repr(good)
    assert execfiles.parse_git_config("﻿[diff]\n\texternal = /e\n") == [["diff.external", "/e"]]


# ---------------------------------------------------------------- 3. export tokens end with the issuer's right
def _bob_owner_with_token(app):
    owner, bob, carol = team(app)
    adopt(owner, [{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": bob.uid, "roles": ["owner", "budget"]},
                  {"user_id": carol.uid, "roles": ["access"]}], TEAM_RULES)
    ag, hdr = owner.new_agent()
    assert bob.post("/api/orgs/switch", account_id=owner.uid).status_code == 200
    bob.stepup()
    r = bob.post("/api/export-tokens", agent_id=ag["id"])
    assert r.status_code == 200, r.text
    mine = owner.post("/api/export-tokens", agent_id=ag["id"]).json()["export_token"]
    return owner, bob, carol, hdr, r.json()["export_token"], mine


def _get(owner, hdr, tok):
    return owner.c.get("/v1/export", headers=dict(hdr, **{"X-DW-Export-Token": tok}))


def _live(owner):
    return {t["id"]: t["live"] for t in owner.c.get("/api/export-tokens").json()}


def test_removed_member_loses_their_export_tokens(app):
    owner, bob, carol, hdr, tok, mine = _bob_owner_with_token(app)
    assert _get(owner, hdr, tok).status_code == 200
    adopt(owner, [{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": carol.uid, "roles": ["access", "budget"]}], TEAM_RULES)
    r = _get(owner, hdr, tok)
    assert r.status_code == 401 and r.json()["error"] == "EXPORT_TOKEN_INVALID"
    assert sorted(_live(owner).values()) == [False, True]                   # bob's revoked, the owner's own still live
    assert _get(owner, hdr, mine).status_code == 200


def test_demoted_member_loses_their_export_tokens(app):
    owner, bob, carol, hdr, tok, mine = _bob_owner_with_token(app)
    adopt(owner, [{"user_id": owner.uid, "roles": ["owner", "budget"]}, {"user_id": bob.uid, "roles": ["budget"]},
                  {"user_id": carol.uid, "roles": ["access"]}], TEAM_RULES)
    assert _get(owner, hdr, tok).json()["error"] == "EXPORT_TOKEN_INVALID"
    assert sorted(_live(owner).values()) == [False, True]
    assert _get(owner, hdr, mine).status_code == 200


def test_invalid_hint_names_the_dashboard_button_and_the_api(client, owner):
    # 0.2.47: the button exists (web/settings.html, card "Export tokens"), so the hint names it again, and the API
    ag, hdr = owner.new_agent()
    j = client.get("/v1/export", headers=hdr).json()
    assert j["error"] == "EXPORT_TOKEN_INVALID"
    s = j["detail"]
    assert "Settings \u2192 Export tokens" in s and "/api/export-tokens" in s and "coming" not in s
    web = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "web")
    page = open(os.path.join(web, "settings.html"), encoding="utf-8").read()
    assert "<h1>Settings</h1>" in page and "<h2>Export tokens</h2>" in page
