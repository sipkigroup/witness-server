"""r0310 (рекомендация Fable, владелец 14.11): пересогласование словаря одним касанием, без ослабления доказательств.

Мандат, подписанный на старом словаре (mr-vocab-1..5), показывает в вопросах старые фразы (подписано = показано). Человеку
предлагается одна строка «обновить мандат» (под Details вопроса и на странице мандата); действие = тот же мандат, подписанный
passkey заново под текущим словарём; старый заменяется существующим путём (actions.register_mandate -> superseded).
Старый словарь моделируется подменой vocab.doc на время подписи (документ mr-vocab-6 без фраз v6_*, v = "mr-vocab-5")."""
import json
import os
import re

import pytest

from app import actions as act_mod, renew, uxstat, vocab, wire
from tests.helpers import FORM, H, Owner, act
from tests.test_pack import run_verify, unpack

import wa_profile as wa

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "web")


_REAL_DOC = vocab.doc


def _doc5():
    d = _REAL_DOC()
    d["v"] = "mr-vocab-5"
    d["screen"] = {k: v for k, v in d["screen"].items() if not k.startswith("v6_")}
    return d


def _old_mandate(owner, monkeypatch, form=None, preset="demo", name="bot"):
    """An agent with a mandate signed while the server's vocabulary was mr-vocab-5."""
    real = vocab.doc
    monkeypatch.setattr(vocab, "doc", _doc5)
    try:
        ag, hdr = owner.new_agent(preset, name)
        m, r = owner.mandate(ag["id"], form)
        assert r.status_code == 200, r.text
    finally:
        monkeypatch.setattr(vocab, "doc", real)
    return ag, hdr, m


def _row(app, mid):
    return app.state.ctx.db.one("SELECT * FROM mandates WHERE id=?", (mid,))


def _renew(owner, mid, mutate=None, signer=None):
    d = owner.post("/api/mandates/%s/renew/draft" % mid)
    assert d.status_code == 200, d.text
    m = d.json()["mandate"]
    if mutate:
        m = mutate(dict(m))
    env = (signer or owner).sign(wa.TYP_MANDATE, wa.cde(m))
    return d.json(), m, owner.post("/api/mandates/%s/renew" % mid, mandate=m, envelope_b64=env)


# ---------------- 1. the report ----------------
def test_report_counts_active_mandates_by_vocabulary(app, owner, monkeypatch):
    ctx = app.state.ctx
    _old_mandate(owner, monkeypatch, name="old")
    ag, _ = owner.new_agent("demo", "new")
    owner.mandate(ag["id"])
    got = renew.by_vocab(ctx)
    assert got == {"active": 2, "stale": 1, "current": "mr-vocab-6", "by": {"mr-vocab-5": 1, "mr-vocab-6": 1}}, got
    txt = uxstat.metrics_text(ctx)
    assert 'dw_mandates_active_by_vocab{v="mr-vocab-5"} 1' in txt and "dw_mandates_stale_vocab 1" in txt
    from app import stats
    assert stats.report(ctx, 1)["mandates_by_vocab"]["stale"] == 1


def test_a_mandate_that_pins_no_vocabulary_counts_as_none_and_is_not_stale(app, owner):
    ctx = app.state.ctx
    ag, _ = owner.new_agent("demo", "nov")
    m, _ = owner.mandate(ag["id"])
    ctx.db.x("UPDATE mandates SET gateway_doc=NULL WHERE id=?", (m["id"],))      # a mandate of 0.2.0-0.2.3 (no document)
    assert renew.by_vocab(ctx)["by"] == {"none": 1} and renew.by_vocab(ctx)["stale"] == 0


# ---------------- 2. the hint: only on an old vocabulary, never on the first screen ----------------
def test_hint_only_for_an_old_vocabulary(app, owner, monkeypatch):
    _, _, old = _old_mandate(owner, monkeypatch, name="old")
    ag, _ = owner.new_agent("demo", "new")
    new, _ = owner.mandate(ag["id"])
    o = owner.c.get("/api/mandates/%s/renew" % old["id"]).json()
    assert o["show"] is True and o["pinned"] == "mr-vocab-5" and o["current"] == "mr-vocab-6" and "passkey" in o["text"]
    assert owner.c.get("/api/mandates/%s/renew" % new["id"]).json() == {"show": False}


def test_hint_on_the_question_page_is_outside_the_signed_view(app, owner, monkeypatch, client):
    _, hdr, old = _old_mandate(owner, monkeypatch)
    rid = act(client, hdr, "publish", {"channel": "blog", "text": "hi"}).json()["rid"]
    g = client.get("/api/approvals/" + rid).json()
    assert g["status"] == "pending_approval" and g["renew_offer"]["show"] is True
    from app import signview
    assert "renew_offer" not in signview.KEYS
    assert signview.view_hash(g).hex() == g["view_sha256"]          # the hint does not change what the passkey signs


def _between(html, start_id, end_marker):
    a = html.index('id="%s"' % start_id)
    return html[a:html.index(end_marker, a)]


def test_hint_is_not_on_the_first_screen_of_a_question():
    html = open(os.path.join(WEB, "approve.html")).read()
    first = _between(html, "qw", "</section>")                       # first screen: what, harm, command, Details button
    assert "renew" not in first
    more = html[html.index('id="qw_more"'):html.index('id="decide"')]  # under Details (folded at first)
    assert 'id="renew_line"' in more and re.search(r'id="renew_line"[^>]*hidden', more)
    assert re.search(r'<div id="qw_more"[^>]*hidden', html)
    m = open(os.path.join(WEB, "mandate.html")).read()
    assert 'id="renew_line"' in _between(m, "active", "</section>")    # mandate page: in the card of the active mandate


# ---------------- 3. the new mandate is the old one, not wider; the old one is superseded ----------------
def test_renew_makes_the_same_mandate_under_the_current_vocabulary(app, owner, monkeypatch):
    ctx = app.state.ctx
    ag, _, old = _old_mandate(owner, monkeypatch)
    d, m, r = _renew(owner, old["id"])
    assert r.status_code == 200, r.text
    assert d["ends"] == {"allowances": 0, "repeat": 0} and d["replaces"] == old["id"]
    o, n = _row(app, old["id"]), _row(app, m["id"])
    assert (o["status"], n["status"]) == ("superseded", "active")
    om, nm = json.loads(o["mandate_json"]), json.loads(n["mandate_json"])
    assert renew.not_wider(om, nm) is None
    assert {k for k in om if om[k] != nm[k]} <= {"id", "nbf", "toolmap_sha256"} and nm["exp"] == om["exp"]
    og, ng = json.loads(o["gateway_doc"]), json.loads(n["gateway_doc"])
    assert {k for k in og if og[k] != ng[k]} == {"vocab"} and ng["vocab"] == vocab.digest()
    assert renew.pinned_v(ctx, n) == "mr-vocab-6" and renew.pinned_v(ctx, o) == "mr-vocab-5"
    # the questions of the new mandate carry the mr-vocab-6 mark (actions._mark_v6 reads exactly this)
    assert act_mod._pinned_has(ctx, {"id": m["id"]}, "v6_unknown_what") is True
    assert act_mod._pinned_has(ctx, {"id": old["id"]}, "v6_unknown_what") is False
    assert owner.c.get("/api/mandates/%s/renew" % m["id"]).json() == {"show": False}
    assert renew.by_vocab(ctx)["stale"] == 0


def test_renewed_mandate_marks_its_questions_v6(app, owner, monkeypatch, client):
    ctx = app.state.ctx
    _, hdr, old = _old_mandate(owner, monkeypatch)
    _, m, r = _renew(owner, old["id"])
    assert r.status_code == 200, r.text
    row = {"rid": "r_TEST", "exec_json": None}
    act_mod._mark_v6(ctx, row, {"id": m["id"]})
    assert json.loads(row["exec_json"])["v6"] == {"pin": True}
    row = {"rid": "r_TEST", "exec_json": None}
    act_mod._mark_v6(ctx, row, {"id": old["id"]})
    assert json.loads(row["exec_json"])["v6"] == {"pin": False}


WIDER = [
    ("budget", lambda m: dict(m, permissions=dict(m["permissions"], purchase=dict(m["permissions"]["purchase"], budget=10 ** 9)))),
    ("exp", lambda m: dict(m, exp=m["exp"] + 86400)),
    ("nbf earlier", lambda m: dict(m, nbf=m["nbf"] - 10 ** 6)),
    ("command", lambda m: dict(m, permissions=dict(m["permissions"], command={"allow": ["rm"], "unlisted": "allow"}))),
    ("forbidden data dropped", lambda m: dict(m, forbidden_data=[])),
    ("member added", lambda m: dict(m, named_circle=True)),
]


@pytest.mark.parametrize("name,mut", WIDER, ids=[w[0] for w in WIDER])
def test_a_wider_mandate_is_refused_and_the_old_one_stays(app, owner, monkeypatch, name, mut):
    _, _, old = _old_mandate(owner, monkeypatch)
    _, m, r = _renew(owner, old["id"], mut)
    assert r.status_code == 409 and r.json()["error"] in ("RENEW_WIDER", "MANDATE_MALFORMED"), (name, r.text)
    assert _row(app, old["id"])["status"] == "active" and _row(app, m["id"]) is None


def test_another_agent_or_the_old_id_is_refused(app, owner, monkeypatch):
    _, _, old = _old_mandate(owner, monkeypatch)
    ag2, _ = owner.new_agent("demo", "other")
    _, m, r = _renew(owner, old["id"], lambda m: dict(m, agent=ag2["id"]))
    assert r.status_code == 409 and r.json()["error"] == "RENEW_WIDER"
    _, m, r = _renew(owner, old["id"], lambda m: dict(m, id=old["id"]))
    assert r.status_code == 409
    assert _row(app, old["id"])["status"] == "active"


def test_changed_tool_map_is_not_renewed_here(app, owner, monkeypatch):
    ctx = app.state.ctx
    ag, _, old = _old_mandate(owner, monkeypatch)
    tm = json.loads(ctx.db.one("SELECT toolmap_json FROM agents WHERE id=?", (ag["id"],))["toolmap_json"])
    tm["tools"]["read_file2"] = {"class": "pass"}
    ctx.db.x("UPDATE agents SET toolmap_json=? WHERE id=?", (json.dumps(tm), ag["id"]))
    assert owner.c.get("/api/mandates/%s/renew" % old["id"]).json() == {"show": False}
    d = owner.post("/api/mandates/%s/renew/draft" % old["id"])
    assert d.status_code == 409 and d.json()["error"] == "RENEW_MAP_CHANGED"


def test_spent_budget_window_blocks_renewal(app, owner, monkeypatch, client):
    _, hdr, old = _old_mandate(owner, monkeypatch)
    r = act(client, hdr, "purchase", {"vendor": "v.example", "amount_cents": 5000}).json()
    assert r["verdict"] == "allow", r
    d = owner.post("/api/mandates/%s/renew/draft" % old["id"])
    assert d.status_code == 409 and d.json()["error"] == "RENEW_BUDGET_OPEN"
    assert owner.c.get("/api/mandates/%s/renew" % old["id"]).json() == {"show": False}


# ---------------- 4. the passkey is required ----------------
def test_without_the_owners_passkey_nothing_changes(app, owner, owner2, monkeypatch):
    _, _, old = _old_mandate(owner, monkeypatch)
    d = owner.post("/api/mandates/%s/renew/draft" % old["id"]).json()
    m = d["mandate"]
    r = owner.post("/api/mandates/%s/renew" % old["id"], mandate=m)                               # no envelope
    assert r.status_code == 409 and r.json()["error"] == "WA_MALFORMED"
    r = owner.post("/api/mandates/%s/renew" % old["id"], mandate=m, envelope_b64=wa.b64u(b"\xa0"))   # not a signature
    assert r.status_code == 409
    r = owner.post("/api/mandates/%s/renew" % old["id"], mandate=m, envelope_b64=owner2.sign(wa.TYP_MANDATE, wa.cde(m)))   # a stranger's key
    assert r.status_code == 409, r.text
    other = dict(m, nbf=m["nbf"] + 1)                                                              # a signature of another object
    r = owner.post("/api/mandates/%s/renew" % old["id"], mandate=m, envelope_b64=owner.sign(wa.TYP_MANDATE, wa.cde(other)))
    assert r.status_code == 409, r.text
    assert _row(app, old["id"])["status"] == "active" and _row(app, m["id"]) is None
    r = owner2.post("/api/mandates/%s/renew/draft" % old["id"])                                   # another account
    assert r.status_code == 404


# ---------------- 5. the frequency guard ----------------
def test_hint_at_most_once_per_mandate_and_vocabulary_and_once_a_week(app, owner, monkeypatch):
    ctx = app.state.ctx
    acc = ctx.db.one("SELECT * FROM accounts WHERE id=?", (owner.account["id"],))
    _, _, a = _old_mandate(owner, monkeypatch, name="a")
    _, _, b = _old_mandate(owner, monkeypatch, name="b")
    t = renew.now()
    assert renew.offer(ctx, acc, a["id"], t)["show"] is True
    assert renew.offer(ctx, acc, a["id"], t + 3600)["show"] is True                  # the same episode (reload, the other page)
    assert renew.offer(ctx, acc, b["id"], t + 3600)["show"] is False                 # another mandate: not within 7 days
    assert renew.offer(ctx, acc, a["id"], t + renew.OFFER_S + 1)["show"] is False    # the episode is over: never again for this version
    assert renew.offer(ctx, acc, b["id"], t + renew.GAP_S - 1)["show"] is False
    assert renew.offer(ctx, acc, b["id"], t + renew.GAP_S + 1)["show"] is True       # a week later: the next mandate
    renew.dismiss(ctx, acc, b["id"], t + renew.GAP_S + 2)                            # "Not now"
    assert renew.offer(ctx, acc, b["id"], t + renew.GAP_S + 3)["show"] is False
    assert renew.offer(ctx, acc, a["id"], t + 10 * renew.GAP_S)["show"] is False      # still the same vocabulary version


def test_not_now_endpoint_hides_the_hint(app, owner, monkeypatch):
    _, _, old = _old_mandate(owner, monkeypatch)
    assert owner.c.get("/api/mandates/%s/renew" % old["id"]).json()["show"] is True
    assert owner.post("/api/mandates/%s/renew/dismiss" % old["id"]).status_code == 200
    assert owner.c.get("/api/mandates/%s/renew" % old["id"]).json() == {"show": False}
    # the action itself stays possible from the mandate page (the hint is a nudge, not the only way)
    _, m, r = _renew(owner, old["id"])
    assert r.status_code == 200, r.text


def test_team_account_is_not_offered(app, owner, monkeypatch):
    from app import org
    _, _, old = _old_mandate(owner, monkeypatch)
    monkeypatch.setattr(org, "current_policy", lambda ctx, aid: ("pol", b"", b""))
    assert owner.c.get("/api/mandates/%s/renew" % old["id"]).json() == {"show": False}
    assert owner.post("/api/mandates/%s/renew/draft" % old["id"]).json()["error"] == "RENEW_TEAM"


# ---------------- 6. evidence: old and new receipts stay VALID ----------------
def test_evidence_pack_with_the_old_and_the_new_mandate_is_valid(app, owner, monkeypatch, client, tmp_path):
    from app import jobs
    _, hdr, old = _old_mandate(owner, monkeypatch, form=dict(FORM, purchase={"enabled": False}))
    r1 = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s", "body": "b"}).json()
    assert r1["verdict"] == "allow", r1
    d = act(client, hdr, "publish", {"channel": "blog", "text": "hello"}).json()
    owner.approve(d["rid"])
    _, m, r = _renew(owner, old["id"])
    assert r.status_code == 200, r.text
    r2 = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s2", "body": "b"}).json()
    assert r2["verdict"] == "allow" and r2["action"] is not None
    x = app.state.ctx.db.one("SELECT mandate_id FROM actions WHERE rid=?", (r2["rid"],))
    assert x["mandate_id"] == m["id"]
    jobs.anchor_once(app.state.ctx)
    folder = str(unpack(client, tmp_path / "pack"))
    rc, out = run_verify(folder, "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    vs = sorted(os.listdir(os.path.join(folder, "vocab")))
    assert len(vs) == 2, vs                               # both vocabularies the two mandates pinned travel with the pack


def test_a_pending_question_of_the_old_mandate_after_renewal(app, owner, monkeypatch, client):
    """A question asked under the old mandate stays answerable after the update from its own Details (as after any re-signed mandate):
    the update does not drop the question the person is looking at."""
    _, hdr, old = _old_mandate(owner, monkeypatch)
    rid = act(client, hdr, "publish", {"channel": "blog", "text": "hello"}).json()["rid"]
    _, m, r = _renew(owner, old["id"])
    assert r.status_code == 200, r.text
    a = owner.approve(rid)
    assert (a.status_code, a.json().get("verdict")) == (200, "allow"), a.text
