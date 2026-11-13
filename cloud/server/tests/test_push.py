"""08: Web Push of approval requests. Fake sender for the policy; a real pywebpush round trip to a local fake push service
(decrypts the RFC 8291 payload with the subscriber key and checks the RFC 8292 VAPID JWT)."""
import base64
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import http_ece
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
from app import push
from app.config import Config, ConfigError
from app.main import create_app
from tests.helpers import FORM, H, ORIGIN, Owner, act


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def vapid_pem(path):
    k = ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return k


class Device:
    """A browser's side of a subscription: ECDH key + auth secret (RFC 8291)."""

    def __init__(self, endpoint):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.auth = os.urandom(16)
        self.endpoint = endpoint

    def sub(self):
        pub = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return {"endpoint": self.endpoint, "keys": {"p256dh": b64u(pub), "auth": b64u(self.auth)}}

    def decrypt(self, body):
        return json.loads(http_ece.decrypt(body, private_key=self.key, auth_secret=self.auth, version="aes128gcm"))


@pytest.fixture()
def pcfg(tmp_path):
    kf = tmp_path / "witness_key"
    kf.write_text("a1" * 32)
    vk = tmp_path / "vapid.pem"
    vapid_pem(vk)
    return Config(data_dir=str(tmp_path / "data"), witness_key_file=str(kf), key_pepper="test-pepper", rp_id="localhost", origin=ORIGIN,
                  iss="https://witness.test", anchor="off", web_dir="", vapid_key_file=str(vk), vapid_sub="mailto:ops@witness.test",
                  push_hosts="push.test,127.0.0.1", push_allow_http=True, push_per_min=3)


class FakeSender:
    def __init__(self, codes=None):
        self.calls, self.codes = [], list(codes or [])

    def __call__(self, info, data, ttl, topic):
        self.calls.append({"endpoint": info["endpoint"], "data": json.loads(data), "ttl": ttl, "topic": topic})
        return self.codes.pop(0) if self.codes else 201


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture()
def papp(pcfg):
    a = create_app(pcfg)
    p = a.state.ctx.push
    p.sender = FakeSender()
    p.retry_delays = (0, 0)
    p.clock = Clock()
    return a


@pytest.fixture()
def pc(papp):
    return TestClient(papp, base_url=ORIGIN)


@pytest.fixture()
def po(pc):
    return Owner(pc).register("Alice")


def agent_with_mandate(owner, name="bot"):
    ag, hdr = owner.new_agent("demo", name=name)
    m, r = owner.mandate(ag["id"], form=FORM)
    assert r.status_code == 200, r.text
    return ag, hdr


def subscribe(owner, dev, device="iPhone"):
    return owner.post("/api/push/subscribe", subscription=dev.sub(), device=device)


def defer(client, hdr, text="release notes", channel="blog"):
    r = act(client, hdr, "publish", {"channel": channel, "text": text}).json()
    assert r["verdict"] == "defer", r
    return r


# ---------------- subscriptions ----------------
def test_key_and_subscribe_list_unsubscribe(pc, po):
    k = pc.get("/api/push/key").json()
    assert k["enabled"] is True and len(b64u_dec(k["public_key"])) == 65 and k["per_min"] == 3
    dev = Device("https://fcm.push.test/send/abc")
    r = subscribe(po, dev)
    assert r.status_code == 200, r.text
    sid = r.json()["id"]
    lst = pc.get("/api/push/subscriptions").json()["subscriptions"]
    assert [(s["id"], s["device"], s["service"]) for s in lst] == [(sid, "iPhone", "fcm.push.test")]
    assert "endpoint" not in lst[0]                                    # the capability URL is not echoed back
    assert subscribe(po, dev).status_code == 200                       # idempotent
    assert len(pc.get("/api/push/subscriptions").json()["subscriptions"]) == 1
    assert po.post("/api/push/unsubscribe", endpoint=dev.endpoint).json() == {"ok": True}
    assert pc.get("/api/push/subscriptions").json()["subscriptions"] == []


def test_subscribe_needs_session_origin_stepup(papp, pc, po):
    dev = Device("https://push.test/x")
    anon = TestClient(papp, base_url=ORIGIN)
    assert anon.post("/api/push/subscribe", json={"subscription": dev.sub()}, headers=H).status_code == 401
    assert anon.get("/api/push/key").status_code == 401
    assert pc.post("/api/push/subscribe", json={"subscription": dev.sub()}).status_code == 403                       # no Origin
    assert pc.post("/api/push/subscribe", json={"subscription": dev.sub()}, headers={"Origin": "https://evil.example"}).json()["error"] == "BAD_ORIGIN"
    papp.state.ctx.db.x("UPDATE sessions SET stepup_at=?", (int(time.time()) - 3600,))
    r = subscribe(po, dev)
    assert r.status_code == 403 and r.json()["error"] == "STEPUP_REQUIRED"
    r = po.post("/api/push/unsubscribe", endpoint=dev.endpoint)
    assert r.status_code == 403 and r.json()["error"] == "STEPUP_REQUIRED"


@pytest.mark.parametrize("ep,code", [
    ("http://push.test/x", 200),                    # allowed only because the test config sets push_allow_http
    ("https://evil.example/x", 422), ("https://push.test.evil.example/x", 422), ("https://user:pw@push.test/x", 422),
    ("ftp://push.test/x", 422), ("https://10.0.0.1/x", 422), (123, 422)])
def test_endpoint_allowlist(po, ep, code):
    dev = Device("https://push.test/x")
    s = dev.sub()
    s["endpoint"] = ep
    r = po.post("/api/push/subscribe", subscription=s)
    assert r.status_code == code, r.text
    if code == 422:
        assert r.json()["error"] == "PUSH_ENDPOINT"


def test_bad_keys(po):
    s = Device("https://push.test/x").sub()
    for bad in ({"p256dh": "AAAA", "auth": s["keys"]["auth"]}, {"p256dh": s["keys"]["p256dh"], "auth": "!!"}, {}):
        r = po.post("/api/push/subscribe", subscription=dict(s, keys=bad))
        assert r.status_code == 422 and r.json()["error"] == "PUSH_KEYS", r.text
    assert po.post("/api/push/subscribe", subscription="x").status_code == 400


def test_endpoint_moves_to_last_account_and_isolation(papp, pc, po):
    bob = Owner(TestClient(papp, base_url=ORIGIN)).register("Bob")
    dev = Device("https://push.test/shared")
    assert subscribe(po, dev).status_code == 200
    assert bob.post("/api/push/unsubscribe", endpoint=dev.endpoint).status_code == 200     # Bob cannot remove Alice's device
    assert len(pc.get("/api/push/subscriptions").json()["subscriptions"]) == 1
    assert subscribe(bob, dev).status_code == 200                                            # same browser, Bob logs in and subscribes
    assert pc.get("/api/push/subscriptions").json()["subscriptions"] == []
    assert len(bob.c.get("/api/push/subscriptions").json()["subscriptions"]) == 1


def test_device_quota(po):
    for i in range(push.MAX_SUBS):
        assert subscribe(po, Device("https://push.test/%d" % i)).status_code == 200
    r = subscribe(po, Device("https://push.test/one-more"))
    assert r.status_code == 429 and r.json()["error"] == "QUOTA"


def test_push_disabled_without_vapid(cfg, client, owner):
    k = client.get("/api/push/key").json()
    assert k == {"enabled": False, "public_key": None, "per_min": 6}
    r = owner.post("/api/push/subscribe", subscription=Device("https://fcm.googleapis.com/x").sub())
    assert r.status_code == 503 and r.json()["error"] == "PUSH_DISABLED"


def test_vapid_config_from_env_only(tmp_path):
    base = {"DW_DATA_DIR": str(tmp_path / "d"), "DW_WITNESS_KEY_FILE": "k", "DW_KEY_PEPPER": "p", "DW_RP_ID": "localhost", "DW_ORIGIN": ORIGIN}
    c = Config.from_env(dict(base, DW_VAPID_PRIVATE_KEY_FILE="/run/secrets/vapid", DW_PUSH_PER_MIN="4", DW_PUSH_HOSTS="a.test"))
    assert (c.vapid_key_file, c.push_per_min, c.push_hosts, c.push_allow_http) == ("/run/secrets/vapid", 4, "a.test", False)
    with pytest.raises(ConfigError):
        Config.from_env(dict(base, DW_PUSH_PER_MIN="0"))
    with pytest.raises(ConfigError):
        push.load_vapid(Config(**{**c.__dict__, "vapid_key_file": str(tmp_path / "missing.pem")}))
    bad = tmp_path / "bad.pem"
    bad.write_text("not a key")
    with pytest.raises(ConfigError):
        push.load_vapid(Config(**{**c.__dict__, "vapid_key_file": str(bad)}))
    raw = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value.to_bytes(32, "big")
    v = push.load_vapid(Config(**{**c.__dict__, "vapid_key_file": "", "vapid_key": b64u(raw)}))
    assert len(b64u_dec(push.vapid_public_b64(v))) == 65


# ---------------- sending ----------------
def test_defer_sends_only_opaque_ids(papp, pc, po):
    """P0-4: the push is a signal. No agent name, tool, class, channel, text, amount in the payload (even though RFC 8291 encrypts it)."""
    p = papp.state.ctx.push
    ag, hdr = agent_with_mandate(po, name="release-bot")
    assert subscribe(po, Device("https://push.test/a")).status_code == 200
    assert subscribe(po, Device("https://push.test/b"), "Android").status_code == 200
    text = "the launch password is hunter2"          # (a secret-shaped string would be denied by DLP before any push)
    r = defer(pc, hdr, text=text, channel="blog")
    assert p.drain()
    assert len(p.sender.calls) == 2 and {c["endpoint"] for c in p.sender.calls} == {"https://push.test/a", "https://push.test/b"}
    d = p.sender.calls[0]["data"]
    assert set(d) == {"v", "k", "id", "g", "t"} and d["v"] == 2         # 05.11: "t" = [what, harm], a general sentence of the reason code and d["k"] == "a" and d["id"] == r["rid"]
    assert d["g"] == push.group_of(po.account["id"], ag["id"]) and len(d["g"]) == 16
    blob = json.dumps(d)
    for leak in ("hunter2", "launch", "release-bot", "blog", ag["id"]):          # (05.11: the general sentence of the reason may say "publish")
        assert leak not in blob, leak
    assert p.sender.calls[0]["ttl"] == push.TTL_S and len(p.sender.calls[0]["topic"]) <= 32
    # allowed / denied actions and repeats of a pending one do not push
    act(pc, hdr, "read_file", {"path": "/x"})
    assert defer(pc, hdr, text=text)["rid"] == r["rid"]
    assert act(pc, hdr, "publish", {"channel": "blog", "text": "key sk-" + "A" * 30}).json()["verdict"] == "deny"
    assert p.drain() and len(p.sender.calls) == 2


def test_note_has_no_details():
    n = push.build_note({"account_id": "a", "rid": "r_X", "agent_id": "ag", "tool": "purchase", "amount": 1250, "currency": "USD",
                         "action_json": json.dumps({"class": "purchase", "recipient": "shop.example"}), "expires": 1}, "bot", {})
    assert {k: v for k, v in n["payload"].items() if k != "t"} == {"v": 2, "k": "a", "id": "r_X", "g": push.group_of("a", "ag")}
    assert len(n["payload"]["t"]) == 2 and all(n["payload"]["t"])           # 05.11: what + harm, general text, no details
    assert "shop" not in json.dumps(n["payload"]) and "12" not in json.dumps(n["payload"])


def test_agent_request_does_not_wait_for_push(papp, pc, po):
    p = papp.state.ctx.push
    ag, hdr = agent_with_mandate(po)
    subscribe(po, Device("https://push.test/slow"))
    gate = threading.Event()

    def slow(info, data, ttl, topic):
        gate.wait(5)
        return 201
    p.sender = slow
    t0 = time.time()
    defer(pc, hdr)
    assert time.time() - t0 < 2
    gate.set()
    assert p.drain()


def test_rate_limit_and_summary(papp, pc, po):
    p = papp.state.ctx.push                    # push_per_min = 3; one agent: one push per MIN_GAP_S
    subscribe(po, Device("https://push.test/a"))
    # 0.2.0: the gateway's APPROVAL_RATE (task 02, max_pending 5) would refuse the 6th waiting item; this test is about the push limiter
    papp.state.ctx.db.x("INSERT OR REPLACE INTO org_settings(account_id, max_pending, max_defers_hour) VALUES(?, 25, 40)", (po.account["id"],))
    hdrs = [agent_with_mandate(po, name="bot%d" % i)[1] for i in range(3)]       # three agents (beta limit): 3 pushes at once
    rids = [defer(pc, h, channel="ch%d" % i)["rid"] for i, h in enumerate(hdrs)]
    p.clock.t += push.MIN_GAP_S                # past every agent's gap, still inside the minute: the account limit holds them
    rids += [defer(pc, h, channel="ch%d" % (3 + i))["rid"] for i, h in enumerate(hdrs[:2])]
    assert p.drain()
    assert [c["data"]["id"] for c in p.sender.calls] == rids[:3] and p.stats["limited"] == 2
    assert p.tick() == 0                       # still inside the minute
    p.clock.t += 61
    assert p.tick() == 1
    assert p.sender.calls[-1]["data"] == {"v": 2, "k": "q"}            # no count, no names: the page shows the queue
    assert p.tick() == 0                       # owed once, told once
    p.clock.t += 61
    rid6 = defer(pc, hdrs[0], channel="ch6")["rid"]
    assert p.drain() and p.sender.calls[-1]["data"]["id"] == rid6


def test_one_agent_at_most_once_per_15_s(papp, pc, po):
    """Anti-bombing: an agent that fires defers in a loop wakes the owner once per MIN_GAP_S; the rest goes into one summary."""
    p = papp.state.ctx.push
    ag, hdr = agent_with_mandate(po)
    subscribe(po, Device("https://push.test/a"))
    papp.state.ctx.db.x("INSERT OR REPLACE INTO org_settings(account_id, max_pending, max_defers_hour) VALUES(?, 25, 40)", (po.account["id"],))
    a = defer(pc, hdr, channel="c1")
    defer(pc, hdr, channel="c2")               # another shape, same agent, 0 s later
    p.clock.t += push.MIN_GAP_S - 1
    defer(pc, hdr, channel="c3")
    assert p.drain() and [c["data"]["id"] for c in p.sender.calls] == [a["rid"]] and p.stats["spaced"] == 2
    p.clock.t += 1                             # 15 s after the first push
    c4 = defer(pc, hdr, channel="c4")
    assert p.drain() and p.sender.calls[-1]["data"]["id"] == c4["rid"] and len(p.sender.calls) == 2
    # the undelivered pushes of one agent share a Topic (the push service keeps the newest) and the device tag
    assert p.sender.calls[0]["topic"] == p.sender.calls[1]["topic"] and p.sender.calls[0]["data"]["g"] == p.sender.calls[1]["data"]["g"]
    other, h2 = agent_with_mandate(po, name="other")
    o = defer(pc, h2, channel="c1")            # another agent is not held back by the first one's gap
    assert p.drain() and p.sender.calls[-1]["data"]["id"] == o["rid"] and p.sender.calls[-1]["topic"] != p.sender.calls[0]["topic"]


def test_suspicious_mutes_the_agent_for_an_hour_and_writes_an_event(papp, pc, po):
    p = papp.state.ctx.push
    ag, hdr = agent_with_mandate(po)
    other, h2 = agent_with_mandate(po, name="other")
    subscribe(po, Device("https://push.test/a"))
    papp.state.ctx.db.x("INSERT OR REPLACE INTO org_settings(account_id, max_pending, max_defers_hour) VALUES(?, 25, 40)", (po.account["id"],))
    r = defer(pc, hdr, channel="c1")
    assert p.drain() and len(p.sender.calls) == 1
    assert pc.post("/api/push/suspicious", json={"rid": r["rid"]}).status_code == 403          # no Origin
    assert po.post("/api/push/suspicious", rid="r_NOPE").status_code == 404
    res = po.post("/api/push/suspicious", rid=r["rid"])
    assert res.status_code == 200, res.text
    assert res.json() == {"agent_id": ag["id"], "muted_until": int(p.clock.t) + push.MUTE_S}
    ev = pc.get("/api/push/mutes").json()
    assert ev["mute_s"] == 3600 and ev["min_gap_s"] == 15
    assert [(m["agent_id"], m["rid"], m["reason"], m["active"]) for m in ev["mutes"]] == [(ag["id"], r["rid"], "suspicious", True)]
    p.clock.t += 120
    defer(pc, hdr, channel="c2")               # muted: no push, and the request still waits (it is not approved by silence)
    assert p.drain() and len(p.sender.calls) == 1 and p.stats["muted"] == 1
    assert {x["rid"] for x in pc.get("/api/approvals").json()} >= {r["rid"]}
    p.clock.t += 120
    assert p.tick() == 0                       # nothing owed; the summary never counts a muted agent
    o = defer(pc, h2, channel="c1")            # other agents still wake the owner
    assert p.drain() and p.sender.calls[-1]["data"]["id"] == o["rid"]
    p.clock.t += push.MUTE_S
    x = defer(pc, hdr, channel="c3")           # an hour later the agent can wake the owner again
    assert p.drain() and p.sender.calls[-1]["data"]["id"] == x["rid"]
    # isolation: another account cannot mute (or even see) this account's request
    bob = Owner(TestClient(papp, base_url=ORIGIN)).register("Bob")
    assert bob.post("/api/push/suspicious", rid=x["rid"]).status_code == 404
    assert bob.c.get("/api/push/mutes").json()["mutes"] == []


def test_limit_is_per_account(papp, pc, po):
    p = papp.state.ctx.push
    bob = Owner(TestClient(papp, base_url=ORIGIN)).register("Bob")
    has = [agent_with_mandate(po, name="a%d" % i)[1] for i in range(3)]
    _, hb = agent_with_mandate(bob)
    subscribe(po, Device("https://push.test/alice"))
    subscribe(bob, Device("https://push.test/bob"))
    for i, ha in enumerate(has):
        defer(pc, ha, channel="a%d" % i)
    p.clock.t += push.MIN_GAP_S
    defer(pc, has[0], channel="a3")            # Alice's 4th in the minute: limited
    defer(bob.c, hb, channel="b0")
    assert p.drain()
    eps = [c["endpoint"] for c in p.sender.calls]
    assert eps.count("https://push.test/alice") == 3 and eps.count("https://push.test/bob") == 1


def test_same_request_shape_is_merged(papp, pc, po):
    p = papp.state.ctx.push
    ag, hdr = agent_with_mandate(po)
    subscribe(po, Device("https://push.test/a"))
    a = defer(pc, hdr, text="v1")
    p.clock.t += push.MIN_GAP_S                # past the per-agent gap: still merged (same shape within COALESCE_S)
    b = defer(pc, hdr, text="v2")              # same agent, tool, class, channel; another text -> another rid, one push
    c = defer(pc, hdr, text="v3")
    assert len({a["rid"], b["rid"], c["rid"]}) == 3
    assert p.drain()
    assert len(p.sender.calls) == 1 and p.stats["merged"] == 2
    p.clock.t += push.SUMMARY_DELAY_S
    assert p.tick() == 1 and p.sender.calls[-1]["data"] == {"v": 2, "k": "q"}
    p.clock.t += push.COALESCE_S
    defer(pc, hdr, text="v4")
    assert p.drain() and p.sender.calls[-1]["data"]["k"] == "a"
    # the same group on the device collapses notifications of one agent
    assert p.sender.calls[0]["data"]["g"] == p.sender.calls[-1]["data"]["g"]


def test_summary_skipped_when_nothing_waits(papp, pc, po):
    p = papp.state.ctx.push
    ag, hdr = agent_with_mandate(po)
    subscribe(po, Device("https://push.test/a"))
    a = defer(pc, hdr, text="v1")
    defer(pc, hdr, text="v2")
    assert p.drain()
    for x in pc.get("/api/approvals").json():
        assert po.approve(x["rid"], approved=False).status_code == 200
    p.clock.t += 120
    assert p.tick() == 0 and len(p.sender.calls) == 1


@pytest.mark.parametrize("code", [404, 410])
def test_dead_subscription_deleted(papp, pc, po, code):
    p = papp.state.ctx.push
    ag, hdr = agent_with_mandate(po)
    subscribe(po, Device("https://push.test/dead"))
    subscribe(po, Device("https://push.test/alive"), "Android")
    p.sender = FakeSender()
    p.sender.codes = [code, 201]
    defer(pc, hdr)
    assert p.drain()
    left = pc.get("/api/push/subscriptions").json()["subscriptions"]
    assert [s["device"] for s in left] == ["Android"] and p.stats["gone"] == 1
    assert left[0]["last_ok_at"]
    assert len(p.sender.calls) == 2                      # no retry of a dead subscription


def test_retries_then_success(papp, pc, po):
    p = papp.state.ctx.push
    ag, hdr = agent_with_mandate(po)
    subscribe(po, Device("https://push.test/a"))
    p.sender = FakeSender([503, 429, 201])
    defer(pc, hdr)
    assert p.drain()
    assert len(p.sender.calls) == 3 and p.stats["retry"] == 2 and p.stats["ok"] == 1


def test_network_error_retried_and_failures_drop_subscription(papp, pc, po):
    p = papp.state.ctx.push
    ag, hdr = agent_with_mandate(po)
    subscribe(po, Device("https://push.test/a"))
    calls = []

    def boom(info, data, ttl, topic):
        calls.append(1)
        raise ConnectionError("down")
    p.sender = boom
    defer(pc, hdr, channel="c0")
    assert p.drain() and len(calls) == push.ATTEMPTS
    db = papp.state.ctx.db
    assert db.one("SELECT fail_count FROM push_subs")["fail_count"] == 1
    p.sender = FakeSender([400] * 10)
    for i in range(1, push.MAX_FAILS):
        p.clock.t += 61
        defer(pc, hdr, channel="c%d" % i)
        assert p.drain()
    assert len(p.sender.calls) == push.MAX_FAILS - 1     # 400 is not retried
    assert db.one("SELECT COUNT(*) AS n FROM push_subs")["n"] == 0


def test_test_push_endpoint(papp, pc, po):
    p = papp.state.ctx.push
    r = po.post("/api/push/test")
    assert r.status_code == 409 and r.json()["error"] == "PUSH_NO_DEVICE"
    subscribe(po, Device("https://push.test/a"))
    assert po.post("/api/push/test").json() == {"devices": 1}
    assert p.sender.calls[-1]["data"] == {"v": 2, "k": "t"}
    assert pc.post("/api/push/test", json={}).status_code == 403          # no Origin
    po.post("/api/push/test")
    assert po.post("/api/push/test").status_code == 429


# ---------------- real pywebpush -> local fake push service ----------------
class FakePushService:
    def __init__(self, codes=None):
        self.got, self.codes = [], list(codes or [])
        svc = self

        class Hd(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("content-length", 0)))
                svc.got.append({"path": self.path, "headers": dict(self.headers), "body": body})
                code = svc.codes.pop(0) if svc.codes else 201
                self.send_response(code)
                if 300 <= code < 400:
                    self.send_header("location", svc.base + "/internal")
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        self.srv = HTTPServer(("127.0.0.1", 0), Hd)
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


def verify_vapid(auth_header, public_b64, aud):
    """RFC 8292: Authorization: vapid t=<JWT ES256>, k=<public key>."""
    scheme, rest = auth_header.split(" ", 1)
    assert scheme == "vapid"
    parts = dict(x.strip().split("=", 1) for x in rest.split(","))
    assert parts["k"] == public_b64
    h, c, s = parts["t"].split(".")
    assert json.loads(b64u_dec(h))["alg"] == "ES256"
    claims = json.loads(b64u_dec(c))
    sig = b64u_dec(s)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b64u_dec(public_b64))
    pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), (h + "." + c).encode(), ec.ECDSA(hashes.SHA256()))
    assert claims["aud"] == aud and claims["sub"] == "mailto:ops@witness.test" and claims["exp"] > time.time()
    return claims


def test_real_webpush_roundtrip_to_fake_endpoint(papp, pc, po):
    p = papp.state.ctx.push
    p.sender = p._webpush_send                         # the real sender: pywebpush, aes128gcm, VAPID
    svc = FakePushService()
    try:
        ag, hdr = agent_with_mandate(po, name="mailer")
        dev = Device(svc.base + "/push/dev1")
        assert subscribe(po, dev).status_code == 200
        r = defer(pc, hdr)
        assert p.drain()
        assert len(svc.got) == 1
        g = svc.got[0]
        assert g["path"] == "/push/dev1"
        hd = {k.lower(): v for k, v in g["headers"].items()}
        assert hd["content-encoding"] == "aes128gcm" and hd["ttl"] == str(push.TTL_S) and hd["urgency"] == "high" and len(hd["topic"]) <= 32
        verify_vapid(hd["authorization"], p.public_key, svc.base)
        d = dev.decrypt(g["body"])
        assert {k: v for k, v in d.items() if k != "t"} == {"v": 2, "k": "a", "id": r["rid"], "g": push.group_of(po.account["id"], ag["id"])} and len(d["t"]) == 2
        assert b"release notes" not in g["body"] and "mailer" not in json.dumps(d)
        # the service says 410 -> subscription removed
        svc.codes = [410]
        p.clock.t += 61
        defer(pc, hdr, channel="other")
        assert p.drain() and len(svc.got) == 2
        assert pc.get("/api/push/subscriptions").json()["subscriptions"] == []
    finally:
        svc.close()


def test_redirect_not_followed(papp, po):
    p = papp.state.ctx.push
    svc = FakePushService(codes=[307])
    try:
        import requests
        with pytest.raises(requests.exceptions.TooManyRedirects):
            p._webpush_send(Device(svc.base + "/r").sub(), "{}", 60, "t")
        assert [g["path"] for g in svc.got] == ["/r"]          # /internal never reached
    finally:
        svc.close()


# ---------------- static: PWA files ----------------
def test_pwa_files_served(pc):
    sw = pc.get("/sw.js")
    assert sw.status_code == 200 and "javascript" in sw.headers["content-type"]
    m = pc.get("/manifest.webmanifest")
    assert m.status_code == 200 and m.headers["content-type"].startswith("application/manifest+json")
    mj = m.json()
    assert mj["display"] == "standalone" and mj["start_url"] and mj["scope"] == "/"
    for ic in mj["icons"]:
        r = pc.get("/" + ic["src"])
        assert r.status_code == 200 and r.content[:8] == b"\x89PNG\r\n\x1a\n", ic
    assert pc.get("/js/push.js").status_code == 200
    assert pc.get("/icons/gen_icons.py").status_code == 404 and pc.get("/sw.js.map").status_code == 404
    h = pc.get("/api/witness").json()["web_js_sha256"]
    assert "sw.js" in h and "js/push.js" in h
    for page in ("/app.html", "/approve.html"):
        t = pc.get(page).text
        assert 'rel="manifest"' in t and "apple-touch-icon" in t
