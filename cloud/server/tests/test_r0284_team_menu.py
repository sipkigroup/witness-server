"""r0284 item 4: a solo account does not see the "Team" menu entry; it appears with an invited person (members or open invites).
The server tells the page in /api/me -> "team" (bool); ui.js draws the link only when it is not false."""
import os
import re

from tests.helpers import Owner
from tests.org_helpers import Person

WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "web")


def test_solo_has_no_team(client):
    o = Owner(client).register("Solo")
    assert o.c.get("/api/me").json()["team"] is False


def test_team_appears_with_invite_and_with_member(app):
    o = Person(app).register("Olga")
    assert o.c.get("/api/me").json()["team"] is False
    tok = o.invite(["budget"])
    assert o.c.get("/api/me").json()["team"] is True            # an open invite is already a team in the making
    b = Person(app).register("Bob", invite=tok)
    assert o.c.get("/api/me").json()["team"] is True
    assert b.c.get("/api/me").json()["team"] is True            # the member sees the team too


def test_nav_hides_team_for_solo_and_advanced_has_the_invite_link():
    ui = open(os.path.join(WEB, "js", "ui.js"), encoding="utf-8").read()
    assert re.search(r"me\.team\s*!==\s*false", ui) and "href: 'team.html' }, 'Team'" in ui
    app_html = open(os.path.join(WEB, "app.html"), encoding="utf-8").read()
    adv = app_html[app_html.index('<details id="advanced"'):]
    assert re.search(r'<a[^>]+href="team\.html[^"]*"[^>]*>Invite a person', adv)
