"""r0289 (owner 13.11, TERMS-REVIEW #1): assent to the Terms. The pages that make an account show one line next to the passkey button
("By continuing you agree to the Terms and Privacy", both linked) and send the version of the terms; the account keeps that version and the
time, written in the transaction that binds its first passkey (a user-verified passkey ceremony). Nothing new about the person is stored.
One version everywhere: auth.TERMS_VERSION = the version named on terms.html, privacy.html, trial.html and signup.html."""
import os
import re

import wa_profile as wa
from app import auth
from tests.helpers import H, ORIGIN, RP, Owner
from tests.test_0238_trial import Person, ctx_of, new_trial

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "web")


def _page(name):
    with open(os.path.join(WEB, name), encoding="utf-8") as f:
        return f.read()


def _row(client, aid):
    return ctx_of(client).db.one("SELECT terms_version, terms_at, created_at FROM accounts WHERE id=?", (aid,))


def test_trial_claim_records_the_terms_version_and_time(client, app, tmp_path):
    t = new_trial(client, tmp_path)
    me = Person(app, t["claim"])
    b = me.post("/api/trial/claim/begin", claim=me.claim).json()
    cred = me.auth.create_credential(wa.b64u_dec(b["options"]["challenge"]), RP, ORIGIN)
    r = me.post("/api/trial/claim/finish", flow_id=b["flow_id"], credential=cred, claim=me.claim, terms=auth.TERMS_VERSION)
    assert r.status_code == 200, r.text
    row = _row(client, r.json()["account"]["id"])
    PRED = auth.TERMS_VERSION
    assert row["terms_version"] == PRED and row["terms_at"] is not None
    cred_t = ctx_of(client).db.one("SELECT created_at FROM credentials WHERE account_id=?", (r.json()["account"]["id"],))["created_at"]
    assert row["terms_at"] == cred_t                         # the same moment as the first passkey: one transaction


def test_signup_records_the_terms_version(client):
    o = Owner(client)
    j = o.post("/api/auth/register/begin", display_name="Ann").json()
    cred = o.auth.create_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)
    r = o.post("/api/auth/register/finish", flow_id=j["flow_id"], credential=cred, terms=auth.TERMS_VERSION)
    assert r.status_code == 200, r.text
    row = _row(client, r.json()["account"]["id"])
    assert row["terms_version"] == auth.TERMS_VERSION and row["terms_at"] == row["created_at"]


def test_a_page_without_the_line_or_another_version_records_nothing(client, app, tmp_path):
    a = Owner(client).register("NoLine")                     # a page cached from before r0289 sends no version
    assert _row(client, a.account["id"])["terms_version"] is None
    o = Owner(client)
    j = o.post("/api/auth/register/begin", display_name="Old").json()
    cred = o.auth.create_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)
    r = o.post("/api/auth/register/finish", flow_id=j["flow_id"], credential=cred, terms="1999-01-01")
    assert r.status_code == 200 and _row(client, r.json()["account"]["id"])["terms_version"] is None
    o2 = Owner(client)
    j = o2.post("/api/auth/register/begin", display_name="Odd").json()
    cred = o2.auth.create_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)
    r = o2.post("/api/auth/register/finish", flow_id=j["flow_id"], credential=cred, terms={"x": 1})
    assert r.status_code == 200 and _row(client, r.json()["account"]["id"])["terms_version"] is None


def test_one_version_on_every_page():
    v = auth.TERMS_VERSION
    for p in ("terms.html", "privacy.html"):
        assert "Version %s" % v in _page(p), p
    for p in ("trial.html", "signup.html"):
        s = _page(p)
        line = re.search(r'<p[^>]*id="terms"[^>]*>(.*?)</p>', s, re.S)
        assert line and 'data-terms="%s"' % v in line.group(0), p
        txt = line.group(1)
        assert re.search(r"By continuing you agree to the <a href=\"/terms.html\"[^>]*>Terms</a> and <a href=\"/privacy.html\"[^>]*>Privacy</a>", txt), (p, txt)


def test_terms_page_is_an_agreement_with_the_needed_clauses():
    s = _page("terms.html")
    assert "not a full legal agreement" not in s and "pending legal review" not in s
    for must in ("LIMITATION OF LIABILITY", "DISCLAIMER", "MERCHANTABILITY", "laws of the State of New York", "New York County",
                 "at least 18", "sanctions", "does not guarantee", "decisions stay yours",
                 "Not affiliated with or endorsed by Anthropic", "Claude and Claude Code are trademarks of Anthropic",
                 "the evidence pack of your own journal", "never behind a paywall", "on the limits in force at that time"):
        assert must in s, must
    assert not re.search(r"evidence pack for auditors are the paid part", s)
    assert "®" not in s and "&reg;" not in s


def test_privacy_page_says_the_terms_record_and_the_rights():
    s = _page("privacy.html")
    assert "not legal terms" not in s and "pending legal review" not in s
    for must in ("Your rights", "do not sell or share", "Children", "Security incidents", "which version of the Terms you agreed to"):
        assert must in s, must
