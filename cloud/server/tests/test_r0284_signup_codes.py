"""r0284 item 3: right after the account is created the sign-up page offers the recovery codes ("Save codes" / "Later"); the old "you will
need a new account" sentence is gone; "Later" leaves a reminder on the dashboard (app.js) until the account has codes."""
import os
import re

WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "web")


def rd(*p):
    return open(os.path.join(WEB, *p), encoding="utf-8").read()


def test_signup_page_has_codes_screen_not_the_new_account_text():
    h = rd("signup.html")
    assert "new account" not in h.lower()
    assert re.search(r'id="codesbox"[^>]*hidden', h) and 'id="savecodes"' in h and 'id="later"' in h
    assert "iCloud" in h and "not guaranteed" in h               # the honest sentence about synced passkeys
    assert h.index('id="card"') < h.index('id="codesbox"')


def test_signup_js_makes_codes_and_remembers_later():
    j = rd("js", "signup.js")
    assert "/api/auth/recovery-codes" in j and "codesFile" in j
    assert "$('#codesbox').hidden = false" in j and "dw_codes_later" in j


def test_dashboard_reminds_when_later_was_chosen():
    a = rd("js", "app.js")
    assert "dw_codes_later" in a and "recovery-codes.html" in a and "/api/auth/recovery-codes" in a
