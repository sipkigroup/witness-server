"""Law §0 p.2: the gateway only tightens. Required (4): 500 random actions x random settings -> allow set with hooks ⊆ allow set without."""
import json
import random

from fastapi.testclient import TestClient

from app import toolmap as tm
from app.flow import hooks
from tests_flow.conftest import make_app
from tests_flow.helpers import FORM, ORIGIN, Owner, act, set_settings

CHANNELS = ["#team", "#ops", "blog"]
TO = ["bob@partner.example", "x@acme.example", "eve@evil.example"]
TEXTS = ["hello", "IBAN DE89370400440532013000", "I live at twelve Baker street", "call 555-123-4567", "card 4111 1111 1111 1111", "ok"]


def _rand_call(rnd, i):
    k = rnd.randrange(4)
    if k == 0:
        return "publish", {"channel": rnd.choice(CHANNELS), "text": "%s %d" % (rnd.choice(TEXTS), i)}
    if k == 1:
        return "send_email", {"to": rnd.choice(TO), "subject": "s%d" % i, "body": rnd.choice(TEXTS)}
    if k == 2:
        return "purchase", {"vendor": "v.example", "amount_cents": rnd.choice([100, 5000, 9000, 15000])}
    return "delete_resource", {"resource": rnd.choice(["cache-tmp", "prod-db"])}


def _rand_settings(rnd):
    return {"max_pending": rnd.randint(0, 6), "max_defers_hour": rnd.randint(0, 25), "escalate_after_s": rnd.choice([0, 600]),
            "advisor": rnd.choice(["off", "heuristic"])}


def test_4_only_tightens_500_random(ctx, owner, warm_advisor):
    """Function level, real core: for each random action under random settings and a random pending backlog, the hook result never
    turns deny/defer into allow, and the final verdict is allow only where the core alone says allow."""
    rnd = random.Random(20261018)
    acc = owner.account["id"]
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"], dict(FORM, publish={"channels": ["#team"]}))
    agent = ctx.db.one("SELECT * FROM agents WHERE id=?", (ag["id"],))
    m = ctx.db.one("SELECT * FROM mandates WHERE agent_id=? AND status='active'", (ag["id"],))
    L = ctx.hub.ledger(acc)
    toolmap = json.loads(agent["toolmap_json"])
    with_hooks, without, kinds = set(), set(), {}
    for i in range(500):
        set_settings(ctx, acc, **_rand_settings(rnd))
        ctx.db.x("DELETE FROM actions WHERE agent_id=?", (ag["id"],))
        for j in range(rnd.randint(0, 8)):                       # random backlog of pending defers
            ctx.db.x("INSERT INTO actions(rid,account_id,agent_id,status,reason,class,created_at,expires) VALUES(?,?,?,?,?,?,?,?)",
                     ("bk%d_%d" % (i, j), acc, ag["id"], "pending_approval", "ESCALATE_PUBLISH", "publish", L.now(), L.now() + 900))
        tool, args = _rand_call(rnd, i)
        a = tm.build_action(ag["id"], toolmap, tool, args, {})
        a["toolmap_sha256"] = bytes.fromhex(json.loads(m["mandate_json"])["toolmap_sha256"])      # 0.2.4: the gateway puts the signed map hash into every action
        _, v, why = L.S.decide_for(m["id"], a, L.now())
        g = hooks.pre_authorize(ctx, agent, m, a, v, why)
        final = v if g is None else g[0]
        assert g is None or g[0] in ("deny", "hold")
        assert not (v in ("deny", "defer") and final == "allow")
        if v == "deny":
            assert g is None                                     # nothing to tighten
        kinds[(v, final)] = kinds.get((v, final), 0) + 1
        if final == "allow":
            with_hooks.add(i)
        if v == "allow":
            without.add(i)
    assert with_hooks <= without
    assert kinds.get(("defer", "deny"), 0) > 0 and kinds.get(("allow", "hold"), 0) > 0      # the property was exercised both ways


def test_4_only_tightens_end_to_end(tmp_path, warm_advisor, monkeypatch):
    """Same random calls through two servers: the 0.1 path (hooks replaced by no-ops) and the production wiring of 0.2 (app/actions.py
    calls app/flow/hooks) with tight random settings; allow(with) ⊆ allow(without)."""
    from app import actions
    rnd = random.Random(5)
    calls = [_rand_call(rnd, i) for i in range(60)]
    res = {}
    real = actions.hooks

    class _NoHooks:
        router = None

        @staticmethod
        def pre_authorize(*a):
            return None

        @staticmethod
        def on_decided(*a):
            return None
    for mode in ("without", "with"):
        d = tmp_path / mode
        d.mkdir()
        monkeypatch.setattr(actions, "hooks", real if mode == "with" else _NoHooks)
        app = make_app(d)
        c = TestClient(app, base_url=ORIGIN)
        o = Owner(c).register("P")
        ag, hdr = o.new_agent()
        o.mandate(ag["id"], dict(FORM, publish={"channels": ["#team"]}))
        if mode == "with":
            set_settings(app.state.ctx, o.account["id"], max_pending=1, max_defers_hour=2, advisor="heuristic")
        res[mode] = {i for i, (tool, args) in enumerate(calls) if act(c, hdr, tool, args).json()["verdict"] == "allow"}
    assert res["with"] <= res["without"] and res["without"]
    assert res["with"] != res["without"]                         # the hooks did tighten something
