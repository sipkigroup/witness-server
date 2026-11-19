"""fatigue-fix (ZAMER-F100, 19.10.2026): suggestions only WIDEN (rules W1-W5 of app/flow/suggest.py), outliers are never batched
(batch.outliers, BATCH_OUTLIER). One test per rule; the property at the end replays the history under every proposal."""
import hashlib
import json

from app.flow import batch, suggest
from app.toolmap import preset
from tests_flow.helpers import FORM, act, b64d, set_settings

NOPURCHASE = dict(FORM, purchase=None)


def _agent(client, owner, ctx, form=NOPURCHASE):
    ag, hdr = owner.new_agent()
    tm = preset("demo")
    tm["tools"]["purchase"].pop("strict")                                          # an order id per call (identical calls fold into one rid)
    tm["tools"]["clean_dir"] = {"class": "delete", "recipient": "$.path", "reversible": True}
    owner.put_toolmap(ag["id"], tm)
    owner.mandate(ag["id"], form)
    set_settings(ctx, owner.account["id"], max_pending=25, max_defers_hour=40)
    return ag, hdr


def _buy(client, owner, hdr, vendor, amounts, approved=True):
    rids = []
    for a in amounts:
        r = act(client, hdr, "purchase", {"vendor": vendor, "amount_cents": a, "order": "o%d" % a}).json()
        assert r["verdict"] == "defer", r
        if approved is not None:
            assert owner.approve(r["rid"], approved=approved).status_code == 200
        rids.append(r["rid"])
    return rids


def _sugg(client):
    return client.get("/api/suggestions").json()["suggestions"]


# ---------------------------------------------------------------- W1: refused / hostile / invalid keys never suggested
def test_w1_refused_vendor_is_never_a_suggestion(client, owner, ctx):
    ag, hdr = _agent(client, owner, ctx)
    _buy(client, owner, hdr, "coffee.example", [800, 1200, 1500])
    _buy(client, owner, hdr, "cloud.example", [5000, 6000, 7000])
    _buy(client, owner, hdr, "cloud.example", [250000], approved=False)          # the owner refused once: the vendor is out
    _buy(client, owner, hdr, "evil.example", [900000], approved=False)           # only ever refused (a hostile-only key)
    s = _sugg(client)
    assert [x["recipient"] for x in s] == ["coffee.example"]
    assert all("evil.example" not in json.dumps(x) for x in s)


def test_w4_small_refusal_at_another_vendor_withholds(client, owner, ctx):
    """The purchase permission has no vendor list: a limit above a refused $9 would let that refused vendor through silently."""
    ag, hdr = _agent(client, owner, ctx)
    _buy(client, owner, hdr, "coffee.example", [800, 1200, 1500])
    _buy(client, owner, hdr, "evil.example", [900], approved=False)
    assert _sugg(client) == []
    assert [w["reason"] for w in suggest.withheld(ctx, owner.account["id"])] == ["REFUSED_AMOUNT_WITHIN_HISTORY"]


def test_w1_invalid_message_keys():
    for bad in ("anna@acme.example@evil.example", "ben@acme.example,leak@evil.example", "Anna <anna@acme.example>", "", "nobody"):
        assert not suggest._valid_key("message", bad), bad
    assert suggest._valid_key("message", "anna@acme.example") and suggest._valid_key("publish", "#team")


# ---------------------------------------------------------------- W2: an unspecified class is never closed
def test_w2_unspecified_publish_and_delete_are_withheld(client, owner, ctx):
    ag, hdr = _agent(client, owner, ctx)
    for i in range(3):
        assert owner.approve(act(client, hdr, "publish", {"channel": "#team", "text": "p%d" % i}).json()["rid"]).status_code == 200
        r = act(client, hdr, "clean_dir", {"path": "cache-tmp/build", "run": i}).json()
        assert r["verdict"] == "defer", r
        assert owner.approve(r["rid"]).status_code == 200
    assert _sugg(client) == []
    w = {(x["class"], x["recipient"]): x["reason"] for x in suggest.withheld(ctx, owner.account["id"])}
    assert w == {("publish", "#team"): "CLOSES_UNSPECIFIED_CLASS", ("delete", "cache-tmp/build"): "CLOSES_UNSPECIFIED_CLASS"}
    # the questions stay questions: another channel is still asked, not refused
    assert act(client, hdr, "publish", {"channel": "#elsewhere", "text": "x"}).json()["verdict"] == "defer"


def test_w2_existing_list_is_extended_never_shrunk(client, owner, ctx):
    ag, hdr = _agent(client, owner, ctx)
    for i in range(3):
        assert owner.approve(act(client, hdr, "clean_dir", {"path": "cache-tmp/logs", "run": i}).json()["rid"]).status_code == 200
    owner.mandate(ag["id"], dict(NOPURCHASE, delete={"targets": ["cache-tmp/build"], "allow_irreversible": False}))
    s = _sugg(client)
    assert [(x["class"], x["recipient"]) for x in s] == [("delete", "cache-tmp/logs")]
    assert s[0]["form"]["delete"] == {"targets": ["cache-tmp/build", "cache-tmp/logs"], "allow_irreversible": False}


# ---------------------------------------------------------------- W3: purchase limits per agent, from all approvals, with headroom
def test_w3_one_purchase_suggestion_per_agent_covering_every_approved_amount(client, owner, ctx):
    ag, hdr = _agent(client, owner, ctx)
    _buy(client, owner, hdr, "coffee.example", [800, 1200, 2500])
    _buy(client, owner, hdr, "office.example", [1500, 4000, 6000, 5990])
    s = [x for x in _sugg(client) if x["class"] == "purchase"]
    assert len(s) == 1 and s[0]["recipient"] == "office.example"                    # the vendor with the most approvals carries it
    p = s[0]["form"]["purchase"]
    assert p["max_per_action"] == 9000                                              # 6000 x 1.5
    assert p["budget"] == 33000                                                     # all seven in one day: 21990 x 1.5 -> 33000
    assert p["max_per_action"] >= 6000 and p["budget"] >= 21990


def test_w3_never_below_the_active_mandate(client, owner, ctx):
    ag, hdr = _agent(client, owner, ctx)
    _buy(client, owner, hdr, "coffee.example", [800, 1200, 1500])
    owner.mandate(ag["id"], dict(FORM, purchase={"enabled": True, "max_per_action": 50000, "budget": 90000}))
    assert _sugg(client) == []                                                      # already covered: nothing to lower


# ---------------------------------------------------------------- W4: a refused amount bounds the proposal
def test_w4_budget_and_limit_stay_below_a_refused_amount(client, owner, ctx):
    ag, hdr = _agent(client, owner, ctx)
    _buy(client, owner, hdr, "coffee.example", [1000, 2000, 3000])
    _buy(client, owner, hdr, "cloud.example", [8000], approved=False)
    s = _sugg(client)
    p, b = s[0]["form"]["purchase"], s[0]["budget"]
    assert (p["max_per_action"], p["budget"], b["refused_min"]) == (5000, 7999, 8000)   # 3000 x 1.5 -> 5000; budget 9000 capped below 8000
    assert p["max_per_action"] < 8000 and p["budget"] < 8000


def test_w4_refusal_inside_the_approved_range_withholds(client, owner, ctx):
    ag, hdr = _agent(client, owner, ctx)
    _buy(client, owner, hdr, "coffee.example", [1000, 2000, 3000])
    _buy(client, owner, hdr, "cloud.example", [2500], approved=False)
    assert _sugg(client) == []
    assert [w["reason"] for w in suggest.withheld(ctx, owner.account["id"])] == ["REFUSED_AMOUNT_WITHIN_HISTORY"]


def test_w4_hostile_over_budget_never_covered(client, owner, ctx):
    ag, hdr = _agent(client, owner, ctx)
    _buy(client, owner, hdr, "cloud.example", [5000, 12000, 20000])
    _buy(client, owner, hdr, "cloud.example", [250000], approved=False)
    _buy(client, owner, hdr, "cloud2.example", [900000], approved=False)       # a second refusal at the same vendor would be REFUSED for an hour
    _buy(client, owner, hdr, "coffee.example", [900, 1100, 1300])
    s = _sugg(client)
    p = s[0]["form"]["purchase"]
    assert p["max_per_action"] < 250000 and p["budget"] < 250000


# ---------------------------------------------------------------- W5: replay
def test_w5_replay_rejects_a_form_that_denies_an_approved_action(owner):
    m = {"v": "deus-aar-0.1", "id": "m1", "principal": "dw:x", "agent": "a1", "nbf": 1000, "exp": 10 ** 9, "currency": "USD",
         "budget_window_s": 86400, "permissions": {}, "forbidden_data": [], "named_circle": False, "key_attestation": "passkey", "pin_source": "x"}
    a = {"class": "publish", "recipient": "#team", "agent": "a1"}
    assert suggest._replay_ok(m, {"currency": "USD", "valid_days": 30}, [a])                           # unspecified -> defer, not deny
    assert not suggest._replay_ok(m, {"currency": "USD", "valid_days": 30, "publish": {"channels": ["#other"]}}, [a])
    buy = {"class": "purchase", "recipient": "v", "amount": 30000, "currency": "USD", "agent": "a1"}
    assert not suggest._replay_ok(m, {"currency": "USD", "valid_days": 30, "purchase": {"enabled": True, "max_per_action": 29000, "budget": 99000}}, [buy])


def test_widen_property_applied_suggestion_denies_nothing_approved(client, owner, ctx):
    """After applying the suggestion, every approved request is asked again: none is denied (defer -> allow only)."""
    ag, hdr = _agent(client, owner, ctx)
    amounts = [800, 1200, 1500, 2500, 6000, 5990]
    _buy(client, owner, hdr, "coffee.example", amounts)
    _buy(client, owner, hdr, "cloud.example", [400000], approved=False)
    s = _sugg(client)
    assert len(s) == 1
    owner.mandate(ag["id"], s[0]["form"])
    for a in amounts:
        r = act(client, hdr, "purchase", {"vendor": "coffee.example", "amount_cents": a, "order": "again%d" % a}).json()
        assert r["verdict"] == "allow", r
    r = act(client, hdr, "purchase", {"vendor": "cloud.example", "amount_cents": 400000, "order": "again"}).json()
    assert r["verdict"] == "deny" and r["reason"] == "PER_ACTION_LIMIT"


# ---------------------------------------------------------------- batch: an outlier never rides with ordinary items
def _groups(client):
    return client.get("/api/approvals/groups").json()["groups"]


def test_batch_outlier_against_history_is_alone(client, owner, ctx):
    ag, hdr = _agent(client, owner, ctx)
    _buy(client, owner, hdr, "cloud.example", [5000, 12000, 20000])
    rids = _buy(client, owner, hdr, "cloud.example", [9000, 15000, 250000], approved=None)
    g = _groups(client)
    assert sorted((x["count"], x["outlier"]) for x in g) == [(1, True), (2, False)]
    assert [x for x in g if x["outlier"]][0]["rids"] == [rids[2]]
    r = owner.post("/api/approvals/batch", rids=rids, approved=True, envelope_b64=owner.wb([hashlib.sha256(b"x").digest()]))
    assert (r.status_code, r.json()["error"]) == (409, "BATCH_OUTLIER")
    ok = [x for x in g if not x["outlier"]][0]                                       # the ordinary two still go in one ceremony
    r = owner.post("/api/approvals/batch", rids=ok["rids"], views=ok.get("views"), approved=True, envelope_b64=owner.wb([b64d(x) for x in ok["items_approve_b64"]]))
    assert r.status_code == 200 and [x["verdict"] for x in r.json()["results"]] == ["allow", "allow"]


def test_batch_outlier_without_history(client, owner, ctx):
    ag, hdr = _agent(client, owner, ctx)
    _buy(client, owner, hdr, "new-shop.example", [3000, 4000, 480000], approved=None)
    assert sorted((x["count"], x["outlier"]) for x in _groups(client)) == [(1, True), (2, False)]


def test_batch_non_money_not_split(client, owner, ctx):
    ag, hdr = _agent(client, owner, ctx)
    for i in range(4):
        act(client, hdr, "publish", {"channel": "#team", "text": "n%d" % i})
    assert [(x["count"], x["outlier"]) for x in _groups(client)] == [(4, False)]
    assert batch.outliers(ctx, owner.account["id"], []) == set()
