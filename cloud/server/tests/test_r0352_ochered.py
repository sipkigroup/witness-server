"""r0352 (polygon "attack on the person" 18.11, ataka-na-cheloveka/ITOGI.md A1 / A2 / A3):
KAND-ACH-4: a dangerous question is not pushed out by trifles (HIGH_RESERVE places above the limit for high-risk questions while fewer
than HIGH_RESERVE of them wait), and a refusal for the limit is said to the person (GET /api/rate-refusals: one line in the queue).
KAND-ACH-2: the pending list carries the server's risk level of each question (the queue sorts by it and shows it).
KAND-ACH-3: a publication / message whose text names a link or domain not approved before for that (agent, class, recipient) is offered
alone and refused inside a batch (BATCH_OUTLIER), as a money outlier is."""
import hashlib

from app.flow import rate
from svidetel_v4.state import approval_payload
from tests.helpers import act
from tests.test_allowance_0210 import Dev
from tests.test_pv2_view import _wb
from tests_flow.helpers import set_settings
from tests import viewkit

TRIV = ["npm test", "npm run build", "mvn test", "pytest -q", "make", "cargo build", "go test ./...", "node index.js", "ruff format .",
        "tsc --noEmit", "gradle build", "rake test"]
DANGER = "sudo rm -rf /var/log"


def _dev(client, owner, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir(parents=True)
    d = Dev(client, owner, proj.resolve())
    set_settings(client.app.state.ctx, owner.account["id"], max_pending=10, max_defers_hour=120)     # the defaults (Dev raises them)
    return d


def _ask(d, cmd):
    """-> (verdict, reason, rid) of the part of the line that asks (or the first part)."""
    out = d.send(cmd)
    for _, r in out:
        if r["verdict"] in ("defer", "deny") and r.get("reason") not in (None, "OK_ALLOWED"):
            return r["verdict"], r["reason"], r.get("rid")
    _, r = out[0]
    return r["verdict"], r["reason"], r.get("rid")


def _fill(d, n=10):
    asked = []
    for c in TRIV:
        v, why, rid = _ask(d, c)
        if v == "defer":
            assert not rate.high_risk(why), (c, why)
            asked.append(rid)
        if len(asked) == n:
            return asked
    raise AssertionError("not enough trifles asked: %r" % asked)


def test_a1_dangerous_question_is_not_pushed_out_by_trifles(client, owner, tmp_path):
    d = _dev(client, owner, tmp_path)
    _fill(d)
    v, why, _ = _ask(d, "cargo test --release")                       # one more trifle: the limit holds for it
    assert (v, why) == ("deny", "APPROVAL_RATE"), (v, why)
    v, why, rid = _ask(d, DANGER)
    assert v == "defer" and rate.high_risk(why), (v, why)             # the dangerous one takes a reserved place: the person sees it
    rows = client.get("/api/approvals").json()
    top = [x for x in rows if x["rid"] == rid]
    assert top and top[0]["risk"] in ("high", "critical"), top


def test_a1_the_reserve_is_small_a_flood_of_dangerous_questions_still_meets_the_limit(client, owner, tmp_path):
    d = _dev(client, owner, tmp_path)
    _fill(d)
    got = [_ask(d, c) for c in (DANGER, "sudo rm -rf /var/log/a", "sudo rm -rf /var/log/b", "sudo rm -rf /var/log/c")]
    assert [g[0] for g in got[:2]] == ["defer", "defer"], got
    assert all(g[:2] == ("deny", "APPROVAL_RATE") for g in got[2:]), got


def test_a1_refusal_for_the_limit_is_said_to_the_person(client, owner, tmp_path):
    d = _dev(client, owner, tmp_path)
    _fill(d)
    for c in (DANGER, "sudo rm -rf /var/log/a"):
        assert _ask(d, c)[0] == "defer"
    v, why, _ = _ask(d, "sudo rm -rf /var/log/b")
    assert (v, why) == ("deny", "APPROVAL_RATE")
    _ask(d, "cargo test --release")                                   # and a trifle refused too: the dangerous one is named first
    j = client.get("/api/rate-refusals").json()
    assert j["n"] >= 2, j
    assert j["items"][0]["risk"] in ("high", "critical") and "/var/log/b" in j["items"][0]["cmd"], j
    assert "sha256" not in j["items"][0]["cmd"] and j["items"][0]["cmd"].startswith("sudo rm -rf"), j
    assert client.get("/api/rate-refusals", headers={"Cookie": ""}).status_code in (200, 401)


def test_a2_pending_list_carries_the_risk_level(client, owner, tmp_path):
    d = _dev(client, owner, tmp_path)
    _, _, low = _ask(d, "npm test")
    _, _, high = _ask(d, DANGER)
    lv = {x["rid"]: x["risk"] for x in client.get("/api/approvals").json()}
    assert lv[low] in ("low", "medium") and lv[high] in ("high", "critical"), lv


def _posts(owner, texts, channel="#news"):
    ag, hdr = owner.new_agent("demo", "news")
    owner.mandate(ag["id"])
    out = []
    for t in texts:
        r = act(owner.c, hdr, "publish", {"channel": channel, "text": t}).json()
        assert r["verdict"] == "defer", r
        out.append(r["rid"])
    return ag, hdr, out


def _batch_with_views(owner, rids):
    gs = [viewkit.answer(owner.c, r) for r in rids]
    vs = [viewkit.page_view(g) for g in gs]
    items = [hashlib.sha256(approval_payload(g["mandate"], g["action"], r, True, v)).digest() for g, r, v in zip(gs, rids, vs)]
    return owner.post("/api/approvals/batch", rids=rids, approved=True, envelope_b64=_wb(owner, items), views=[v.hex() for v in vs])


EVIL = "URGENT: our database leaked, reset your password at https://acme-login.evil.example now"


def test_a3_a_post_with_a_new_link_is_offered_alone(client, owner):
    texts = ["Weekly update %d: build is green, nothing new" % i for i in range(6)]
    texts[3] = EVIL
    ag, hdr, rids = _posts(owner, texts)
    groups = client.get("/api/approvals/groups").json()["groups"]
    mine = [g for g in groups if set(g["rids"]) & set(rids)]
    alone = [g for g in mine if g["rids"] == [rids[3]]]
    assert alone and alone[0]["outlier"] is True, mine
    assert all(rids[3] not in g["rids"] for g in mine if g is not alone[0]), mine
    r = _batch_with_views(owner, rids)                                 # a hand-made batch with it is refused whole
    assert r.status_code == 409 and r.json()["error"] == "BATCH_OUTLIER" and r.json().get("detail") == rids[3], r.text
    others = [x for i, x in enumerate(rids) if i != 3]
    r = _batch_with_views(owner, others)
    assert r.status_code == 200 and [x["verdict"] for x in r.json()["results"]] == ["allow"] * 5, r.text


def test_a3_a_link_the_owner_approved_before_rides_along(client, owner):
    ag, hdr, rids = _posts(owner, ["Release notes: https://blog.acme.example/r1"])
    assert viewkit.approve(owner, rids[0]).json()["verdict"] == "allow"
    r2 = [act(owner.c, hdr, "publish", {"channel": "#news", "text": "Release notes %d: https://blog.acme.example/r%d" % (i, i)}).json()["rid"]
          for i in (2, 3)]
    r = _batch_with_views(owner, r2)
    assert r.status_code == 200, r.text


def test_a3_domains_of():
    from app.flow.batch import domains_of
    assert domains_of(EVIL) == {"acme-login.evil.example"}
    assert domains_of("Weekly update 3: build is green, nothing new") == set()
    assert "example.com" in domains_of("see www.Example.com/x")
    assert domains_of("updated notes.txt and index.js") == set()                # file names are not hosts
    assert domains_of("https://files.example/a.txt") == {"files.example"}
