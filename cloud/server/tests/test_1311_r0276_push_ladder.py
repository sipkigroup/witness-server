"""r0276 (SVODKA-1311 p.5): HTTP 201 from the push service is not "delivered". The ladder of a question's push stored on the question
(failed / sent -> received -> shown -> opened), the service worker's ack proved by `n`, one retry when the phone says nothing, the hook's
words when the push did not get through, /metrics by the last state. PRED is written before each check."""
import hashlib
import os
import sys

from fastapi.testclient import TestClient

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))

from app import push  # noqa: E402
from app.hookjudge.mapping import DEFAULT_SAFE_COMMANDS, default_form  # noqa: E402
from deus_witness import client as dwc  # noqa: E402
from deus_witness.hook import main as thin  # noqa: E402
from tests.helpers import ORIGIN  # noqa: E402
from tests.test_0216_thin import Via  # noqa: E402
from tests.test_push import pcfg, papp, pc, po, Device, FakeSender, agent_with_mandate, subscribe, defer  # noqa: E402,F401  (fixtures)
from tests_flow.helpers import set_settings  # noqa: E402


EP = "https://push.test/a"


def tok(p, rid, ep=EP):
    return p.ack_token(rid, push.sub_id(ep))


def state(ctx, rid):
    r = ctx.db.one("SELECT push_state, push_tries FROM actions WHERE rid=?", (rid,))
    return r["push_state"], r["push_tries"]


def ack(papp, rid, n, s):
    anon = TestClient(papp, base_url=ORIGIN)            # no session: the phone may be signed out
    r = anon.post("/api/push/ack", json={"id": rid, "n": n, "s": s}, headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 200 and r.json() == {"ok": True} and "clear-site-data" not in {k.lower() for k in r.headers}
    return r


def test_ladder_moves_only_up_and_only_with_n(papp, pc, po):
    ctx, p = papp.state.ctx, papp.state.ctx.push
    ag, hdr = agent_with_mandate(po)
    subscribe(po, Device("https://push.test/a"))
    rid = defer(pc, hdr)["rid"]
    assert p.drain()
    n = p.sender.calls[-1]["data"]["n"]
    PRED = ("sent", 1)
    assert state(ctx, rid) == PRED
    for bad in ("x" * 22, n[:-1] + ("A" if n[-1] != "A" else "B"), None, 7):      # the agent knows the rid, not n
        ack(papp, rid, bad, "opened")
    ack(papp, rid, n, "approved")                                                  # not a state
    assert state(ctx, rid)[0] == "sent"
    ack(papp, rid, n, "shown")
    ack(papp, rid, n, "received")                                                  # late: never down
    PRED = "shown"
    assert state(ctx, rid)[0] == PRED
    ack(papp, rid.lower(), n, "opened")                                            # the case-folded rid of the link
    assert state(ctx, rid)[0] == "opened"
    other = defer(pc, hdr, channel="other")["rid"]
    ack(papp, other, n, "received")                                                # n of one question proves nothing about another
    assert state(ctx, other)[0] in (None, "sent")


def test_failed_then_one_retry_then_no_more(papp, pc, po):
    ctx, p = papp.state.ctx, papp.state.ctx.push
    ag, hdr = agent_with_mandate(po)
    subscribe(po, Device("https://push.test/a"))
    p.sender.codes = [400]                                                         # the push service refused it
    rid = defer(pc, hdr)["rid"]
    assert p.drain()
    PRED = ("failed", 1)
    assert state(ctx, rid) == PRED
    assert p.retry_unreceived() == 0                                               # too early
    p.clock.t += push.RECV_WAIT_S
    PRED = 1
    assert p.retry_unreceived() == PRED
    last = p.sender.calls[-1]
    assert last["data"]["id"] == rid and last["data"]["n"] == tok(p, rid) and last["topic"] == p.sender.calls[0]["topic"]
    assert state(ctx, rid) == ("sent", 2)
    p.clock.t += push.RECV_WAIT_S
    assert p.retry_unreceived() == 0                                               # once only
    assert len(p.sender.calls) == 2


def test_no_retry_when_received_answered_or_late(papp, pc, po):
    ctx, p = papp.state.ctx, papp.state.ctx.push
    set_settings(ctx, po.account["id"], max_pending=100, max_defers_hour=1000)
    hdrs = [agent_with_mandate(po, name="b%d" % i)[1] for i in range(3)]
    subscribe(po, Device("https://push.test/a"))
    r1 = defer(pc, hdrs[0])["rid"]
    r2 = defer(pc, hdrs[1], channel="c2")["rid"]
    r3 = defer(pc, hdrs[2], channel="c3")["rid"]
    assert p.drain() and len(p.sender.calls) == 3
    ack(papp, r1, tok(p, r1), "received")
    ctx.db.x("UPDATE actions SET status='refused' WHERE rid=?", (r2,))           # answered at the computer
    p.clock.t += push.RECV_WAIT_S
    assert p.retry_unreceived() == 0                                               # the account's per-minute limit (3 here) holds retries too
    p.clock.t += 61 - push.RECV_WAIT_S
    PRED = [r3]
    assert p.retry_unreceived() == 1 and [c["data"]["id"] for c in p.sender.calls[3:]] == PRED
    ctx.db.x("UPDATE actions SET push_tries=1, push_state='sent' WHERE rid=?", (r3,))
    p.clock.t += push.RETRY_LATEST_S
    assert p.retry_unreceived() == 0                                               # two minutes late: no more noise


def test_metrics_share_by_last_state(papp, pc, po):
    ctx, p = papp.state.ctx, papp.state.ctx.push
    set_settings(ctx, po.account["id"], max_pending=100, max_defers_hour=1000)
    hdrs = [agent_with_mandate(po, name="m%d" % i)[1] for i in range(3)]
    subscribe(po, Device("https://push.test/a"))
    rids = [defer(pc, h, channel="ch%d" % i)["rid"] for i, h in enumerate(hdrs)]
    assert p.drain()
    ack(papp, rids[0], tok(p, rids[0]), "opened")
    ack(papp, rids[1], tok(p, rids[1]), "received")
    ctx.db.x("UPDATE actions SET push_at=? WHERE rid IN (?,?,?)", (int(__import__("time").time()), *rids))   # /metrics counts by real time
    ctx.stats_token = hashlib.sha256(b"t" * 40).digest()
    t = pc.get("/metrics", headers={"Authorization": "Bearer " + "t" * 40}).text
    PRED = ['dw_push_ladder_7d{state="opened"} 1', 'dw_push_ladder_7d{state="received"} 1', 'dw_push_ladder_7d{state="sent"} 1',
            'dw_push_ladder_7d{state="failed"} 0', 'dw_push_ladder_share_7d{state="opened"} 0.3333']
    for x in PRED:
        assert x in t, x
    assert po.account["id"] not in t and not any(r in t for r in rids) and "push.test" not in t


# ---------------------------------------------------------------- the words the hook (client 0.2.70, unchanged) prints
def _hook(papp, pc, po, tmp_path):
    ctx = papp.state.ctx
    set_settings(ctx, po.account["id"], max_pending=100000, max_defers_hour=1000000)
    proj = (tmp_path / "proj").resolve()
    proj.mkdir()
    ag, hdr = po.new_agent("claude-code", "cc")
    m, r = po.mandate(ag["id"], default_form(str(proj), safe_commands=list(DEFAULT_SAFE_COMMANDS)))
    assert r.status_code == 200, r.text
    key = hdr["Authorization"][7:]
    w = dwc.Witness(ORIGIN, key, pin_path=str(tmp_path / "pins.json"), transport=Via(pc))

    def run(cmd):
        e = {"DEUS_WITNESS_KEY": key, "CLAUDE_PROJECT_DIR": str(proj), "HOME": str(tmp_path / "home"), "DEUS_WITNESS_HOOK_ON_DEFER": "deny",
             "DEUS_WITNESS_HOME": str(tmp_path / "dw"), "DEUS_WITNESS_OPEN_BROWSER": "0", "DEUS_WITNESS_NOTIFY": "0"}
        out = thin.judge({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(proj), "session_id": "s1"}, thin.Settings(e), witness=w)
        h = out.get("hookSpecificOutput") or {}
        return h.get("permissionDecision"), h.get("permissionDecisionReason", ""), out.get("systemMessage") or ""
    return run


def test_hook_says_the_phone_did_not_get_it(papp, pc, po, tmp_path):
    ctx, p = papp.state.ctx, papp.state.ctx.push
    subscribe(po, Device(EP))
    run = _hook(papp, pc, po, tmp_path)
    d, why, sm = run("make build")
    PRED = ("deny", "Notification: sent via phone push (1 device).")
    assert d == PRED[0] and PRED[1] in sm and "open the link above" not in sm, sm     # nothing known yet: as before
    assert p.drain()
    rid = p.sender.calls[-1]["data"]["id"]
    p.clock.t += push.RECV_WAIT_S
    d, why, sm = run("make build")                                                 # the agent repeats the call; the question is the same
    # r0276b: this phone has never acked (an older sw.js): no "did NOT reach", a neutral sentence
    PRED = "Notification: sent via phone push (1 device); if it did not come, open the link above."
    assert PRED in sm and PRED in why and rid in sm and "/approve.html?rid=" in sm and "NOT" not in sm.split("Notification:")[1], sm
    ack(papp, rid, tok(p, rid), "shown")                                          # now it acks: a current service worker
    assert ctx.db.one("SELECT acked FROM push_subs")["acked"] == 1
    d, why, sm = run("make build")
    PRED = "phone push (1 device) - reached your phone but was not opened, open the link above."
    assert PRED in sm, sm
    ack(papp, rid, tok(p, rid), "opened")
    d, why, sm = run("make build")
    PRED = "Notification: sent via phone push (1 device)."
    assert PRED in sm and "open the link above" not in sm, sm


def test_did_not_reach_only_for_a_phone_that_acks(papp, pc, po, tmp_path):
    ctx, p = papp.state.ctx, papp.state.ctx.push
    subscribe(po, Device(EP))
    run = _hook(papp, pc, po, tmp_path)
    run("make build")
    assert p.drain()
    r1 = p.sender.calls[-1]["data"]["id"]
    ack(papp, r1, tok(p, r1), "received")                                         # the phone acked once
    p.clock.t += 61
    run("make install")
    assert p.drain()
    r2 = p.sender.calls[-1]["data"]["id"]
    assert r2 != r1
    p.clock.t += push.RECV_WAIT_S
    d, why, sm = run("make install")
    PRED = "Notification: sent via phone push (1 device) - did NOT reach your phone, open the link above."
    assert PRED in sm, sm


def test_any_open_of_the_question_page_is_opened(papp, pc, po):
    ctx, p = papp.state.ctx, papp.state.ctx.push
    ag, hdr = agent_with_mandate(po)
    subscribe(po, Device(EP))
    rid = defer(pc, hdr)["rid"]
    assert p.drain() and state(ctx, rid)[0] == "sent"
    PRED = "opened"
    assert pc.get("/api/approvals/" + rid).status_code == 200                      # the terminal's link / the list: the signed-in page
    assert state(ctx, rid)[0] == PRED
    other = defer(pc, hdr, channel="x2")["rid"]
    ctx.db.x("UPDATE actions SET push_state=NULL WHERE rid=?", (other,))          # never pushed: the page does not invent a push
    pc.get("/api/approvals/" + other)
    assert state(ctx, other)[0] is None


def test_hook_warns_on_a_new_question_when_the_phone_is_silent(papp, pc, po, tmp_path):
    ctx, p = papp.state.ctx, papp.state.ctx.push
    subscribe(po, Device("https://push.test/a"))
    run = _hook(papp, pc, po, tmp_path)
    run("make build")
    assert p.drain()
    p.clock.t += push.RECV_WAIT_S
    assert p.retry_unreceived() == 1                                               # pushed twice, the phone said nothing
    ctx.db.x("UPDATE push_subs SET acked=1")                                       # (it is a phone whose sw.js acks)
    p.clock.t += push.RECV_WAIT_S + 1
    d, why, sm = run("make install")                                               # a NEW question
    PRED = "phone push (1 device) - your phone did not confirm the last push, open the link above."
    assert PRED in sm, sm


def test_muted_or_no_device_unchanged(papp, pc, po, tmp_path):
    run = _hook(papp, pc, po, tmp_path)
    d, why, sm = run("make build")
    PRED = "Notification: NOT sent"
    assert PRED in sm and "open the link above" not in sm


def test_new_question_quiet_when_the_phone_answered_later(papp, pc, po, tmp_path):
    ctx, p = papp.state.ctx, papp.state.ctx.push
    subscribe(po, Device("https://push.test/a"))
    run = _hook(papp, pc, po, tmp_path)
    run("make build")
    assert p.drain()
    p.clock.t += push.RECV_WAIT_S
    assert p.retry_unreceived() == 1
    first = p.sender.calls[-1]["data"]["id"]
    p.clock.t += 16
    run("make install")
    assert p.drain()
    second = p.sender.calls[-1]["data"]["id"]
    assert second != first
    ack(papp, second, tok(p, second), "received")                             # the phone is back
    p.clock.t += 2 * push.RECV_WAIT_S + 1
    d, why, sm = run("make clean")
    PRED = "did not confirm the last push"
    assert PRED not in sm and "Notification: sent via phone push (1 device)." in sm, sm


def test_warning_survives_the_push_worker_winning_the_race(papp, pc, po, tmp_path, monkeypatch):
    # r0306 (Linux VM, 14.11): the push of the NEW question was sometimes sent by the worker thread before the hook's answer was built,
    # and the "your phone did not confirm the last push" warning vanished. Here the worker always wins (the worst order, every time).
    ctx, p = papp.state.ctx, papp.state.ctx.push
    subscribe(po, Device("https://push.test/a"))
    run = _hook(papp, pc, po, tmp_path)
    run("make build")
    assert p.drain()
    p.clock.t += push.RECV_WAIT_S
    assert p.retry_unreceived() == 1
    ctx.db.x("UPDATE push_subs SET acked=1")
    p.clock.t += push.RECV_WAIT_S + 1
    real = p.delivery

    def worker_first(acc, rids, t=None):
        assert p.drain()                                                           # the new question's push is already sent
        return real(acc, rids, t)
    monkeypatch.setattr(p, "delivery", worker_first)
    d, why, sm = run("make install")
    PRED = "phone push (1 device) - your phone did not confirm the last push, open the link above."
    assert PRED in sm, sm
