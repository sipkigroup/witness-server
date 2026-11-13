"""Suggestions (§3.2), digest (§3.5/3.6), escalation (§3.5), hooks. Required (9), (10)."""
import hashlib

from app.flow import digest, escalate, hooks, suggest
from app.flow.wq import wq
import wa_profile as wa
from tests_flow.helpers import FORM, act, b64d, set_policy, set_settings


def _approved_publishes(client, owner, ctx, n, channel="#team", refuse_last=False):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    set_settings(ctx, owner.account["id"], max_pending=25, max_defers_hour=40)
    for i in range(n):
        r = act(client, hdr, "publish", {"channel": channel, "text": "p%d" % i}).json()
        assert owner.approve(r["rid"], approved=not (refuse_last and i == n - 1)).status_code == 200
    return ag, hdr


def test_9_three_approvals_suggest_channel(client, owner, ctx):
    """fatigue-fix W2: publish is unspecified in the mandate (the core asks) -> "add #team" would close the class and deny every other
    channel; it is withheld, not suggested. Once the owner has a channel list, the same history extends it (only widens)."""
    ag, hdr = _approved_publishes(client, owner, ctx, 3)
    assert client.get("/api/suggestions").json()["suggestions"] == []
    assert [(w["class"], w["recipient"], w["reason"]) for w in suggest.withheld(ctx, owner.account["id"])] == [("publish", "#team", "CLOSES_UNSPECIFIED_CLASS")]
    owner.mandate(ag["id"], dict(FORM, publish={"channels": ["#news"]}))
    s = client.get("/api/suggestions").json()["suggestions"]
    assert len(s) == 1 and (s[0]["class"], s[0]["recipient"], s[0]["approvals"], s[0]["applied"]) == ("publish", "#team", 3, False)
    assert s[0]["form"]["publish"] == {"channels": ["#news", "#team"]}
    d = owner.post("/api/mandates/draft", agent_id=ag["id"], form=s[0]["form"])        # the form is ready for the draft
    assert d.status_code == 200 and d.json()["mandate"]["permissions"]["publish"] == {"channels": ["#news", "#team"]}
    # never applied by itself: the active mandate is unchanged (#team is outside its list)
    assert act(client, hdr, "publish", {"channel": "#team", "text": "next"}).json()["reason"] == "RESOURCE"


def test_9_one_refusal_no_suggestion(client, owner, ctx):
    _approved_publishes(client, owner, ctx, 4, refuse_last=True)
    assert client.get("/api/suggestions").json()["suggestions"] == []


def test_suggest_needs_three(client, owner, ctx):
    _approved_publishes(client, owner, ctx, 2)
    assert client.get("/api/suggestions").json()["suggestions"] == []


def test_suggest_budget_max_with_margin_and_capped(client, owner, ctx):
    """fatigue-fix W3: max approved x 1.5 (not p95 x 1.2: p95 put 5 % of what the owner approved above the limit -> deny);
    budget = the largest approved 24 h sum x 1.5; a quorum cap below the history withholds the suggestion instead of denying the history."""
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"], dict(FORM, purchase=None))
    set_settings(ctx, owner.account["id"], max_pending=25, max_defers_hour=40)
    for a in (1234, 2500, 4100):
        r = act(client, hdr, "purchase", {"vendor": "shop.example", "amount_cents": a}).json()
        assert r["verdict"] == "defer", r
        assert owner.approve(r["rid"]).status_code == 200
    s = client.get("/api/suggestions").json()["suggestions"]
    b = s[0]["budget"]
    assert (b["p95"], b["max_approved"], b["max_day_sum"], b["proposed"], b["budget"], b["cap"]) == (4100, 4100, 7834, 7000, 12000, None)   # 6150 -> 7000, 11751 -> 12000
    assert s[0]["form"]["purchase"] == {"enabled": True, "max_per_action": 7000, "budget": 12000}
    rules = lambda amount: {"policy": {"role": "owner", "k": 1}, "mandate": [{"if": "money_over", "amount": amount, "role": "budget", "k": 2}],
                            "approval": [], "revocation": {"role": "any", "k": 1}, "ceiling": {"role": "owner", "k": 1}}
    set_policy(ctx, owner.account["id"], rules(20000))
    s = client.get("/api/suggestions").json()["suggestions"]
    assert (s[0]["budget"]["proposed"], s[0]["budget"]["budget"], s[0]["budget"]["cap"]) == (7000, 12000, 20000)
    set_policy(ctx, owner.account["id"], rules(3000))                       # below the approved 4100: a solo mandate cannot cover the history
    assert client.get("/api/suggestions").json()["suggestions"] == []
    assert [w["reason"] for w in suggest.withheld(ctx, owner.account["id"])] == ["CAP_BELOW_HISTORY"]


def test_suggest_unit_limits():
    assert suggest.p95([100]) == 100 and suggest.p95(list(range(1, 101))) == 95
    assert suggest.budget_of([1000]) == 2000 and suggest.budget_of([999]) == 2000 and suggest.budget_of([600]) == 1000
    assert suggest.budget_of([20000, 100]) == 30000 and suggest.budget_of([20000], cap=25000) == 25000
    D = 86400
    assert suggest.max_day_sum([(0, 100), (D - 1, 200), (D, 400)]) == 600         # (D-1, 200) and (D, 400) share a window; (0, 100) left it
    assert suggest.max_day_sum([(0, 100), (10, 200)]) == 300 and suggest.max_day_sum([(0, 5)]) == 5


def test_10_digest_counts_F(client, owner, ctx):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    set_settings(ctx, owner.account["id"], max_pending=25, max_defers_hour=40)
    for i in range(12):
        act(client, hdr, "publish", {"channel": "#team", "text": "b%d" % i})
    g = client.get("/api/approvals/groups").json()["groups"][0]
    r = owner.post("/api/approvals/batch", rids=g["rids"], approved=True, envelope_b64=owner.wb([b64d(x) for x in g["items_approve_b64"]]))
    assert r.status_code == 200
    d = client.get("/api/digest?since=0").json()
    assert (d["W"], d["H"], d["F"]) == (12, 12, 1) and d["F100"] == round(100 / 12, 2) and d["A100"] == 100.0
    # a quorum approval with two signatures counts as 2 ceremonies (the row as 01 stores it: the wq envelope)
    x = act(client, hdr, "publish", {"channel": "#q", "text": "quorum"}).json()
    wsig = lambda i: {"kid": bytes([i]) * 32, "authData": b"a", "clientDataJSON": b"c", "sig": b"\0" * 64}
    env = wq.make_wq(wa.TYP_APPROVAL, b"payload", b"\0" * 32, [wsig(1), wsig(2)])
    ctx.db.x("INSERT INTO approvals(rid,account_id,approved,envelope,ledger_seq,t) VALUES(?,?,?,?,?,?)", (x["rid"], owner.account["id"], 1, env, 0, d["until"]))
    d = client.get("/api/digest?since=0").json()
    assert (d["W"], d["H"], d["F"]) == (13, 13, 3)


def test_digest_excludes_pass_and_gateway(client, owner, ctx):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    act(client, hdr, "read_file", {"path": "x"})                                                # pass
    act(client, hdr, "send_email", {"to": "bob@partner.example", "reply_to": "x"})             # gateway TOOL_ARGS_UNMAPPED
    act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "ok"})             # allow
    act(client, hdr, "send_email", {"to": "eve@evil.example", "subject": "no"})                # core deny
    for i in range(11):
        act(client, hdr, "publish", {"channel": "#c%d" % i, "text": "r%d" % i})              # 10 groups defer + the 11th group APPROVAL_RATE
    d = client.get("/api/digest?since=0").json()
    assert d["W"] == 12 and d["by_verdict"] == {"allow": 1, "deny": 1, "defer": 10}
    assert d["approval_rate_refusals"] == 1 and d["gateway_refusals"] == 2
    assert d["pending_by_role"]["access"] == 10 and d["H"] == 0 and d["F"] == 0 and d["F100"] == 0.0


def test_escalation_and_role_filter(client, owner, ctx):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"], dict(FORM, purchase=None))
    set_settings(ctx, owner.account["id"], escalate_after_s=0)
    act(client, hdr, "publish", {"channel": "#team", "text": "e"})
    act(client, hdr, "purchase", {"vendor": "shop.example", "amount_cents": 100})
    q = client.get("/api/approvals/queue?roles=budget").json()["items"]
    assert [i["class"] for i in q] == ["purchase"] and q[0]["role"] == "budget"
    assert [i["class"] for i in client.get("/api/approvals/queue?roles=access").json()["items"]] == ["publish"]
    own = client.get("/api/approvals/queue?roles=owner").json()["items"]
    assert len(own) == 2 and all(i["escalated"] for i in own)                 # escalated after 0 s -> shown to owners
    set_settings(ctx, owner.account["id"], escalate_after_s=600)
    ag2, hdr2 = owner.new_agent(name="b2")
    owner.mandate(ag2["id"])
    act(client, hdr2, "publish", {"channel": "#team", "text": "fresh"})
    assert len(client.get("/api/approvals/queue?roles=owner").json()["items"]) == 2      # the fresh one is not escalated yet


def test_hooks_signatures_and_noop_on_deny(ctx, owner):
    import inspect
    assert list(inspect.signature(hooks.pre_authorize).parameters) == ["ctx", "agent", "mandate_row", "act", "dry_verdict", "dry_reason"]
    assert list(inspect.signature(hooks.on_decided).parameters) == ["ctx", "agent", "row"]
    from fastapi import APIRouter
    assert isinstance(hooks.router, APIRouter)
    paths = {r.path for r in hooks.router.routes}
    assert {"/api/suggestions", "/api/digest", "/api/approvals/batch", "/v1/catalog", "/v1/coverage", "/api/catalog/{aid}", "/api/catalog/{aid}/draft"} <= paths
    agent = {"id": "x", "account_id": owner.account["id"]}
    assert hooks.pre_authorize(ctx, agent, None, {"class": "publish"}, "deny", "DATA_FORBIDDEN") is None
