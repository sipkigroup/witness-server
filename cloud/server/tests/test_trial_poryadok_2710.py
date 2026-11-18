"""2710u (polygon series 2, proposals 1 and 3).

1. GET /v1/trial/status (the agent key of a trial account): has it a passkey? `deus-witness try` asks it first, makes the new account, and only
   then retires the previous one: a refused new trial (RATE_LIMIT) no longer costs the working one. The real client against this server.
3. A long poll dropped by the client (http.disconnect: the hook killed by Claude Code's timeout, Ctrl-C, a closed session) marks the call
   "the agent stopped waiting" at once, not GRACE_S later; another poll of the same call (still open, or a later one) says it waits."""
import time

import anyio

from app import waiting
from tests.test_0238_trial import Person, ctx_of, new_trial, proj
from tests.test_0239_trial_fix import claim_of, run_try
from tests.test_allowance_0210 import Dev

from deus_witness import trial as dwtrial


def _status(client, key):
    return client.get("/v1/trial/status", headers={"Authorization": "Bearer " + key})


def test_status_unclaimed_claimed_kept(client, app, tmp_path):
    ctx_of(client).cfg.trial_per_hour = 10
    t = new_trial(client, tmp_path)
    r = _status(client, t["api_key"])
    # r0288: a use is written hourly (trial.flush_seen); the stored end moves then, not on this call
    assert r.status_code == 200 and r.json() == {"trial": True, "claimed": False, "expires_at": t["expires_at"]}
    me = Person(app, t["claim"])
    assert me.claim_it().status_code == 200
    assert _status(client, t["api_key"]).json()["claimed"] is True
    assert me.post("/api/trial/keep").status_code == 200
    j = _status(client, t["api_key"]).json()
    assert j["trial"] is False and j["claimed"] is True                  # a kept account: `try` must not overwrite its key either
    assert client.get("/v1/trial/status").status_code == 401
    assert _status(client, "dwk_" + "Z" * 52).status_code == 401


def test_try_again_under_rate_limit_keeps_the_working_trial(client, tmp_path):
    c = ctx_of(client)
    c.cfg.trial_per_hour = 1
    home, p = str(tmp_path / "home"), proj(tmp_path)
    rc, _, link = run_try(client, home, p)
    assert rc == 0 and link
    key = dwtrial.load_key({"DEUS_WITNESS_HOME": home})["key"]
    rc, txt, link2 = run_try(client, home, p)                             # the second try within the hour: refused
    assert rc == 1 and link2 is None and "RATE_LIMIT" in txt and "kept" in txt and "erased" not in txt
    assert dwtrial.load_key({"DEUS_WITNESS_HOME": home})["key"] == key
    assert _status(client, key).json() == {"trial": True, "claimed": False, "expires_at": _status(client, key).json()["expires_at"]}
    assert client.get("/api/trial/state", headers={"X-DW-Claim": claim_of(link)}).status_code == 200     # its page still works
    c.cfg.trial_per_hour = 10
    rc, txt, link3 = run_try(client, home, p)                             # later: replaced, the older one erased only now
    assert rc == 0 and "replaced by a new one" in txt and _status(client, key).status_code == 401


def _poll_and_drop(app, rid, key, drop_after=0.6, wait=20):
    """One GET /v1/actions/{rid}?wait=N through the ASGI app whose client goes away after `drop_after` s. -> seconds it took."""
    t0 = time.time()
    sent = []

    async def receive():
        if not sent:
            sent.append(1)
            return {"type": "http.request", "body": b"", "more_body": False}
        await anyio.sleep(max(0.0, t0 + drop_after - time.time()))
        return {"type": "http.disconnect"}

    async def send(m):
        pass

    path = "/v1/actions/" + rid
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET", "scheme": "https", "path": path,
             "raw_path": path.encode(), "query_string": b"wait=%d" % wait, "root_path": "",
             "headers": [(b"host", b"witness.test"), (b"authorization", ("Bearer " + key).encode())],
             "client": ("127.0.0.1", 5555), "server": ("witness.test", 443)}
    anyio.run(app, scope, receive, send)
    return time.time() - t0


def test_dropped_long_poll_marks_the_call_at_once(client, owner, app, tmp_path):
    pr = tmp_path / "proj"
    pr.mkdir()
    d = Dev(client, owner, pr.resolve())
    [(_, a)] = d.send("uptime")
    key = d.hdr["Authorization"][7:]
    took = _poll_and_drop(app, a["rid"], key)
    assert took < 5, took                                                  # the server stops the poll too, not after 20 s
    assert client.get("/api/approvals/" + a["rid"]).json().get("agent_waiting") is False      # a young call: was "cannot tell" for 35 s
    assert client.get("/v1/actions/%s?wait=1" % a["rid"], headers=d.hdr).status_code == 200    # the agent polls again (it reconnected)
    assert client.get("/api/approvals/" + a["rid"]).json().get("agent_waiting") is True
    assert client.get("/api/approvals/" + a["rid"]).json()["status"] == "pending_approval"     # marked, never cancelled


def test_drop_of_one_poll_while_another_is_open_is_not_gone():
    rid = "r_2710u_two"
    waiting.begin(rid)
    waiting.begin(rid)
    waiting.note(rid)
    waiting.end(rid, dropped=True)                                         # one of two pollers went away
    assert waiting.state(rid, 0.0, now=waiting._started + 1) is True
    waiting.end(rid, dropped=True)                                         # the last one too
    assert waiting.state(rid, 0.0, now=waiting._started + 1) is False
    waiting.note(rid)
    assert waiting.state(rid, 0.0) is True


def test_dropped_long_poll_real_socket(client, owner, app, tmp_path):
    """The same over a real socket (uvicorn, the server of the image): the client's own timeout closes the connection mid-poll."""
    import socket
    import threading

    import httpx
    import uvicorn

    pr = tmp_path / "proj"
    pr.mkdir()
    d = Dev(client, owner, pr.resolve())
    [(_, a)] = d.send("uptime")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="off"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    try:
        for _ in range(100):
            if srv.started:
                break
            time.sleep(0.05)
        t0 = time.time()
        try:
            httpx.get("http://127.0.0.1:%d/v1/actions/%s?wait=20" % (port, a["rid"]), headers=dict(d.hdr, Host="witness.test"), timeout=1.0)
        except httpx.ReadTimeout:
            pass
        st = None
        for _ in range(40):                                                # the server notices within ~0.25 s
            st = client.get("/api/approvals/" + a["rid"]).json().get("agent_waiting")
            if st is False:
                break
            time.sleep(0.1)
        assert st is False and time.time() - t0 < 6, (st, time.time() - t0)
    finally:
        srv.should_exit = True
        th.join(10)
