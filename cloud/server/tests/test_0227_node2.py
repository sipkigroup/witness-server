"""0.2.27: node 2 on node 1 (app/node2feed.py) with the real worker (cloud/node2/node2/worker.py, fake AMD), the evidence pack and the
offline checker; the adversary is node 1's operator editing SQLite with the witness key (tests/node2_kit.py)."""
import hashlib
import json
import os
import sqlite3
import time

import cbor2
import pytest
from fastapi.testclient import TestClient

from app import jobs
from app.config import Config, ConfigError
from app.main import create_app
from tests.helpers import ORIGIN, RP, Owner, act
from tests.test_flow import setup_agent
from tests import node2_kit as K

from node2 import attest as A, cosign as C, fakeamd, worker as W


def _cfg(tmp_path, node2="on"):
    kf = tmp_path / "witness_key"
    kf.write_text(K.SEED)
    kw = {"node2": "on", "node2_token_sha256": hashlib.sha256(K.TOKEN.encode()).digest()} if node2 == "on" else {}
    return Config(data_dir=str(tmp_path / "data"), witness_key_file=str(kf), key_pepper="test-pepper", rp_id=RP, origin=ORIGIN,
                  iss="https://witness.test", anchor="off", web_dir=str(tmp_path / "web"), **kw)


class World:
    def __init__(self, tmp_path, tenants=2, policy=fakeamd.RESTRICTIVE_POLICY):
        self.tmp = tmp_path
        self.app = create_app(_cfg(tmp_path))
        self.ctx = self.app.state.ctx
        self.c = TestClient(self.app, base_url=ORIGIN)
        self.t = int(time.time())
        self.owners = []
        for i in range(tenants):
            cl = TestClient(self.app, base_url=ORIGIN)
            o = Owner(cl).register("T%d" % i)
            o.login()
            ag, hdr, _ = setup_agent(o)
            o.hdr = hdr
            self.owners.append(o)
        self.adv = K.Adversary(os.path.join(self.ctx.cfg.data_dir, "db.sqlite"))
        self.w = K.make_worker(K.client_http(self.c), self.ctx.wk.pub, policy=policy)
        self.w.start()                                             # before any batch: the first one it sees is the next one made

    def acts(self, k=1, who=None):
        for o in (who or self.owners):
            for i in range(k):
                act(o.c, o.hdr, "send_email", {"to": "bob@partner.example", "subject": "s%d" % i, "body": "b"})

    def anchor(self):
        self.t += 1800
        return jobs._anchor_once(self.ctx, now=self.t)

    def round(self, k=1):
        self.acts(k)
        bid = self.anchor()
        return bid, self.w.drain()

    def hashes(self, o):
        L = self.ctx.hub.ledger(o.account["id"] if isinstance(o.account, dict) else o.account)
        L.sync_now()
        return list(L.hashes)

    def aid(self, o):
        return o.account["id"] if isinstance(o.account, dict) else o.account

    def pack(self, o, name):
        r = o.c.get("/api/export")
        assert r.status_code == 200, r.text
        return K.unpack(r.content, self.tmp / name)

    def ark(self):
        return "--node2-amd-ark=" + self.w.amd.pins()["Fake"]


@pytest.fixture()
def world(tmp_path):
    return World(tmp_path)


# ---------------------------------------------------------------- off = unchanged

def test_off_no_routes_no_tables_pack_unchanged(client, owner, app, tmp_path):
    ag, hdr, _ = setup_agent(owner)
    act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s", "body": "b"})
    jobs.anchor_once(app.state.ctx)
    for p in ("/v1/node2", "/v1/node2/keys", "/v1/node2/latest", "/v1/node2/alarms", "/v1/node2/chain"):
        assert client.get(p).status_code == 404, p
    for p in ("/internal/node2/hello", "/internal/node2/feed", "/internal/node2/submit"):
        assert client.post(p, json={}).status_code in (404, 405), p
    names = {r["name"] for r in app.state.ctx.db.q("SELECT name FROM sqlite_master WHERE type='table'")}
    assert not [n for n in names if n.startswith("node2")]
    import zipfile, io
    z = zipfile.ZipFile(io.BytesIO(client.get("/api/export").content))
    assert not [n for n in z.namelist() if "node2" in n]
    d = K.unpack(client.get("/api/export").content, tmp_path / "p")
    rc, out, n2 = K.verify(d)
    assert rc == 0 and n2 is None and "node2" not in out and "node 2" not in out


def test_config_flag(tmp_path):
    base = {"DW_DATA_DIR": str(tmp_path), "DW_WITNESS_KEY_FILE": "/x", "DW_RP_ID": "localhost", "DW_ORIGIN": "http://localhost", "DW_KEY_PEPPER": "p"}
    assert Config.from_env(base).node2 == "off"
    with pytest.raises(ConfigError):
        Config.from_env(dict(base, DW_NODE2="yes"))
    with pytest.raises(ConfigError, match="DW_NODE2_TOKEN_FILE"):
        Config.from_env(dict(base, DW_NODE2="on"))
    tf = tmp_path / "tok"
    tf.write_text("short")
    with pytest.raises(ConfigError, match="32"):
        Config.from_env(dict(base, DW_NODE2="on", DW_NODE2_TOKEN_FILE=str(tf)))
    tf.write_text(K.TOKEN + "\n")
    c = Config.from_env(dict(base, DW_NODE2="on", DW_NODE2_TOKEN_FILE=str(tf)))
    assert c.node2 == "on" and c.node2_token_sha256 == hashlib.sha256(K.TOKEN.encode()).digest() and K.TOKEN not in repr(c)


def test_config_token_from_env(tmp_path):
    base = {"DW_DATA_DIR": str(tmp_path), "DW_WITNESS_KEY_FILE": "/x", "DW_RP_ID": "localhost", "DW_ORIGIN": "http://localhost", "DW_KEY_PEPPER": "p",
            "DW_NODE2": "on"}
    want = hashlib.sha256(K.TOKEN.encode()).digest()
    assert Config.from_env(dict(base, DW_NODE2_TOKEN=K.TOKEN)).node2_token_sha256 == want
    for empty in ("", "   "):                       # empty = no token
        with pytest.raises(ConfigError, match="DW_NODE2_TOKEN"):
            Config.from_env(dict(base, DW_NODE2_TOKEN=empty, DW_NODE2_TOKEN_FILE=""))
    with pytest.raises(ConfigError, match="32") as ei:
        Config.from_env(dict(base, DW_NODE2_TOKEN="short-secret"))
    assert "short-secret" not in str(ei.value)
    tf = tmp_path / "tok"                           # the file wins when both are set
    tf.write_text(K.TOKEN)
    other = "z" * 40
    c = Config.from_env(dict(base, DW_NODE2_TOKEN=other, DW_NODE2_TOKEN_FILE=str(tf)))
    assert c.node2_token_sha256 == want and K.TOKEN not in repr(c) and other not in repr(c)


# ---------------------------------------------------------------- the internal API

def test_auth_and_rate_limit(world):
    c = world.c
    assert c.post("/internal/node2/feed", json={}).status_code == 401
    assert c.post("/internal/node2/feed", json={}, headers={"Authorization": "Bearer " + "w" * 40}).json()["error"] == "NODE2_AUTH"
    for _ in range(25):
        r = c.post("/internal/node2/feed", json={}, headers={"Authorization": "Bearer " + "w" * 40})
    assert r.status_code == 429
    assert K.client_http(world.c)("POST", "/internal/node2/feed", {})[0] == 429        # per IP: even the right token waits a minute


def test_hello_refusals(world):
    http = K.client_http(world.c)
    amd = fakeamd.FakeAmd()
    k1 = world.ctx.wk.pub
    w = K.make_worker(http, b"\x07" * 32, amd)
    with pytest.raises(W.WorkerError, match="409"):
        w.start()                                                  # another node 1 key in the attestation
    w = K.make_worker(http, k1, amd)
    w.clock = lambda: time.time() - 3600
    with pytest.raises(W.WorkerError, match="NODE2_STALE"):
        w.start()
    w = K.make_worker(http, k1, amd)
    w.report_fn = lambda rd: amd.report(rd[:32] + b"\x00" * 32, host_data=hashlib.sha256(fakeamd.RESTRICTIVE_POLICY).digest())
    with pytest.raises(W.WorkerError, match="our report_data"):
        w.start()                                                  # the worker itself refuses a report that is not bound
    doc = {"scheme": A.SCHEME, "platform": "aci-sevsnp", "pub": b"\x01" * 32, "node1_pub": k1, "t": int(time.time()),
           "report": amd.report(b"\x00" * 64), "policy": b"x"}
    assert http("POST", "/internal/node2/hello", {"attestation": A.doc_to_json(doc)})[1]["error"] == "NODE2_ATTEST"   # NOT_BOUND
    rd = A.report_data(b"\x01" * 32, k1, doc["t"])
    doc["report"] = amd.report(rd, host_data=hashlib.sha256(b"x").digest(), policy=0x3001F | 1 << 19)
    st, j = http("POST", "/internal/node2/hello", {"attestation": A.doc_to_json(doc)})
    assert st == 422 and j["detail"] == "DEBUG"
    assert world.c.get("/v1/node2").json()["keys"] == 1                         # only the worker of World


def test_flow_cosig_chain_proofs_and_public_views(world):
    for i in range(4):
        bid, r = world.round(k=1 + i)
        assert r == ["cosig"], (i, r)
    s = world.c.get("/v1/node2").json()
    assert s["latest"]["n"] == 4 and s["latest"]["alarms"] == 0 and s["genesis_hex"] and s["keys"] == 1
    chain = world.c.get("/v1/node2/chain?from=1&limit=10").json()
    assert [x["n"] for x in chain] == [1, 2, 3, 4]
    pub = bytes.fromhex(chain[0]["pub_hex"])
    m = C.verify_chain([(W.unb64(x["cose_b64"]), pub) for x in chain], bytes.fromhex(s["genesis_hex"]))
    assert m["n"] == 4 and m["cps"] == 2
    ks = world.c.get("/v1/node2/keys").json()
    assert len(ks) == 1 and ks[0]["facts"]["debug"] is False and ks[0]["facts"]["policy_sha256"] == hashlib.sha256(fakeamd.RESTRICTIVE_POLICY).hexdigest()
    assert ks[0]["problems"] == ["AMD signature: AMD_ARK_NOT_PINNED"]          # the fake AMD root is not AMD's: shown, not hidden
    assert world.c.get("/v1/node2/cosig/" + bid).json()["n"] == 4
    assert world.c.get("/v1/node2/cosig/20200101T000000Z-00000000").status_code == 404
    assert world.c.get("/v1/node2/alarms").json() == []
    assert world.w.step() is None                                              # nothing new
    # every proof the feed gave was from node 2's own size: 3 consecutive extensions, no alarm
    assert world.w.stats == {"cosig": 4, "alarm": 0, "reject": 0, "error": 0}


def test_pack_covered_with_pin_and_without_amd_root(world):
    world.round()
    world.round()
    o = world.owners[0]
    d = world.pack(o, "p1")
    rc, out, n2 = K.verify(d)
    assert rc == 0 and n2.startswith("node2: NOT COVERED (attestation of K2") and "AMD_ARK_NOT_PINNED" in n2, out
    rc, out, n2 = K.verify(d, "--require-node2")
    assert rc == 1 and "NOT COVERED" in n2 and out.strip().splitlines()[-1] == "RESULT: INVALID"
    rc, out, n2 = K.verify(d, world.ark())
    assert rc == 0 and n2.startswith("node2: COVERED through seq") and "genesis taken from this pack" in n2, out
    pin = json.load(open(os.path.join(os.path.dirname(d), "node2-pin.json")))
    assert pin["n"] == 2 and pin["genesis_hex"]
    rc, out, n2 = K.verify(d, world.ark())
    assert "genesis from your pin" in n2
    rc, out, n2 = K.verify(d, world.ark(), "--node2-genesis=" + "00" * 32, "--no-node2-pin-write")
    assert rc == 1 and n2.startswith("node2: ALARM (the co-signature chain does not start at the genesis pinned"), n2
    ef = world.tmp / "expect.json"
    ef.write_text(json.dumps({"policy_sha256": "11" * 32, "measurement": "11" * 48}))
    rc, out, n2 = K.verify(d, world.ark(), "--node2-expect=" + str(ef), "--no-node2-pin-write")
    assert "POLICY_UNEXPECTED" in n2
    ef.write_text(json.dumps({"policy_sha256": hashlib.sha256(fakeamd.RESTRICTIVE_POLICY).hexdigest(), "measurement": "11" * 48}))
    rc, out, n2 = K.verify(d, world.ark(), "--node2-expect=" + str(ef), "--no-node2-pin-write")
    assert n2.startswith("node2: COVERED") and "not compared with published values" not in out
    os.rename(os.path.join(os.path.dirname(d), "node2-pin.json"), os.path.join(os.path.dirname(d), "pin.bak"))
    for b in os.listdir(os.path.join(d, "node2")):
        if b.endswith(".cosig.cose"):
            os.remove(os.path.join(d, "node2", b))                 # no co-signature for any batch of this pack
    rc, out, n2 = K.verify(d, world.ark(), "--no-node2-pin-write")
    assert n2.startswith("node2: NOT COVERED (your newest anchored checkpoint"), n2          # (the pack itself is INVALID: files removed)


def test_allow_all_policy_is_not_covered(tmp_path):
    allow = open(os.path.join(os.path.dirname(A.__file__), "..", "proba", "policy-allow-all-DEBUG.rego"), "rb").read()
    w = World(tmp_path, tenants=1, policy=allow)
    w.round()
    rc, out, n2 = K.verify(w.pack(w.owners[0], "p"), w.ark())
    assert "NOT COVERED" in n2 and "exec" in n2, n2
    assert any("run any command inside the running container" in p for p in w.c.get("/v1/node2/keys").json()[0]["problems"])


def test_outage_then_backfill_no_false_alarm(world):
    world.round()
    for _ in range(5):                                             # node 2 down for 5 batches
        world.acts(2)
        world.anchor()
    assert world.w.drain() == ["cosig"] * 5
    assert world.c.get("/v1/node2").json()["latest"]["n"] == 6


def test_submit_refusals(world):
    bid, _ = world.round()
    http = K.client_http(world.c)
    stranger = C.Signer()
    cs = stranger.sign({"v": C.SCHEME, "n": 2}, C.TYP_COSIG)
    assert http("POST", "/internal/node2/submit", {"kind": "cosig", "bid": bid, "cose_b64": W.b64(cs)})[1]["error"] == "NODE2_KEY_UNKNOWN"
    world.acts(); bid2 = world.anchor()
    j = http("POST", "/internal/node2/feed", {"after": bid, "sizes": {k.hex(): v[0] for k, v in world.w.cos.ledgers.items()}})[1]
    b = W.batch_from_json(j["batch"])
    snap0 = world.w.cos.snapshot()
    kind, cs = world.w.cos.feed(b)
    bad_snap = W.b64(cbor2.dumps(snap0, canonical=True))                       # the state BEFORE this cosig
    st, r = http("POST", "/internal/node2/submit", {"kind": "cosig", "bid": bid2, "cose_b64": W.b64(cs), "snapshot_b64": bad_snap})
    assert (st, r["error"]) == (422, "NODE2_SNAPSHOT")
    st, r = http("POST", "/internal/node2/submit", {"kind": "cosig", "bid": bid, "cose_b64": W.b64(cs),
                                                     "snapshot_b64": W.b64(cbor2.dumps(world.w.cos.snapshot(), canonical=True))})
    assert r["error"] == "NODE2_BATCH"                                         # cosig of bid2 posted as bid
    # a cosig that skips a number does not continue the chain
    world.w.cos.n += 1
    world.acts(); bid3 = world.anchor()
    j = http("POST", "/internal/node2/feed", {"after": bid2, "sizes": {k.hex(): v[0] for k, v in world.w.cos.ledgers.items()}})[1]
    kind, cs3 = world.w.cos.feed(W.batch_from_json(j["batch"]))
    assert kind == "cosig"
    st, r = http("POST", "/internal/node2/submit", {"kind": "cosig", "bid": bid3, "cose_b64": W.b64(cs3),
                                                     "snapshot_b64": W.b64(cbor2.dumps(world.w.cos.snapshot(), canonical=True))})
    assert (st, r["error"]) == (409, "NODE2_CHAIN"), r
    fake_alarm = world.w.cos.s.sign({"v": C.SCHEME, "alarm": "FORK", "bid": bid3, "ledger": b"x" * 32, "before": cs, "after": cs, "proof": [],
                                     "head": b"\x00" * 32}, C.TYP_ALARM)
    st, r = http("POST", "/internal/node2/submit", {"kind": "alarm", "bid": bid3, "cose_b64": W.b64(fake_alarm)})
    assert (st, r["error"]) == (422, "NODE2_ALARM_INVALID")
    assert world.c.get("/v1/node2/alarms").json() == []
    assert world.c.get("/v1/node2").json()["latest"]["n"] == 1


# ---------------------------------------------------------------- the operator adversary (SQLite + witness key)

def _warm(world, k=2):
    for _ in range(k + 1):
        assert world.round()[1] == ["cosig"]


def test_fork_gives_alarm_and_victim_pack_alarm(world):
    _warm(world)
    v = world.owners[0]
    lid = world.adv.lid(world.aid(v))
    size = world.w.cos.ledgers[lid][0]
    world.adv.fork(world.aid(v), world.hashes(v), size)
    assert world.w.drain() == ["alarm"]
    al = world.c.get("/v1/node2/alarms").json()
    assert len(al) == 1 and al[0]["alarm"] == "FORK" and al[0]["ledger_hex"] == lid.hex()
    assert C.verify_alarm(W.unb64(al[0]["cose_b64"]), bytes.fromhex(al[0]["pub_hex"]), world.ctx.wk.pub) == "FORK"
    world.round()                                                  # the next honest batch: co-signed, the alarm counted in it
    assert world.c.get("/v1/node2").json()["latest"]["alarms"] == 1
    rc, out, n2 = K.verify(world.pack(v, "pv"), world.ark())
    assert rc == 1 and n2.startswith("node2: ALARM FORK on YOUR journal") and "definitive" in n2, out
    rc, out, n2 = K.verify(world.pack(world.owners[1], "po"), world.ark())
    assert "1 alarm(s) on other journals" in out and n2.startswith("node2: COVERED"), out


def test_rollback_alarm(world):
    _warm(world)
    v = world.owners[0]
    lid = world.adv.lid(world.aid(v))
    world.adv.rollback(world.aid(v), world.hashes(v), world.w.cos.ledgers[lid][0])
    assert world.w.drain() == ["alarm"]
    assert world.c.get("/v1/node2/alarms").json()[0]["alarm"] == "ROLLBACK"


def test_hidden_alarm_is_caught_by_the_counter(world):
    _warm(world)
    v = world.owners[0]
    lid = world.adv.lid(world.aid(v))
    world.adv.fork(world.aid(v), world.hashes(v), world.w.cos.ledgers[lid][0])
    assert world.w.drain() == ["alarm"]
    world.round()
    assert world.adv.delete_alarms() == 1                          # the operator drops the evidence
    assert world.c.get("/v1/node2/alarms").json() == []
    rc, out, n2 = K.verify(world.pack(world.owners[1], "po"), world.ark())
    assert rc == 1 and "node 1 hides alarms" in n2, out


def test_hidden_slot_victim_not_covered(world):
    _warm(world)
    v = world.owners[0]
    world.adv.hidden_slot(world.aid(v), world.hashes(v))
    assert world.w.drain() == ["cosig"]                            # node 2 never sees the victim: it co-signs
    rc, out, n2 = K.verify(world.pack(v, "pv"), world.ark())
    assert "NOT COVERED" in n2 and "not among the checkpoints node 2 co-signed" in n2, out


def test_rewritten_journal_file_gives_not_proven_alarm(world):
    _warm(world)
    v = world.owners[0]
    world.ctx.hub.forget(world.aid(v))                             # = server restart for this tenant: the file is read again
    K.rewrite_ledger_file(os.path.join(world.ctx.hub.ledger_dir(world.aid(v)), "ledger.cose"))
    world.ctx.hub.forget(world.aid(v))
    world.acts(who=[v])
    world.anchor()
    assert world.w.drain() == ["alarm"]
    a = world.c.get("/v1/node2/alarms").json()[0]
    assert a["alarm"] == "NOT_PROVEN_APPEND_ONLY"
    assert C.verify_alarm(W.unb64(a["cose_b64"]), bytes.fromhex(a["pub_hex"]), world.ctx.wk.pub) == "NOT_PROVEN_APPEND_ONLY"


def test_restart_resumes_chain_with_link_and_pack_covered(world):
    _warm(world)
    old_pub = world.w.cos.s.pub
    w2 = K.make_worker(K.client_http(world.c), world.ctx.wk.pub, world.w.amd)   # same code (policy), new key: a container restart
    w2.start()
    assert w2.cos.n == 3 and w2.cos.s.pub != old_pub
    world.w = w2
    bid, r = world.round()
    assert r == ["cosig"]
    latest = world.c.get("/v1/node2/latest").json()
    assert latest["n"] == 4 and latest["linked"] and latest["pub_hex"] == w2.cos.s.pub.hex()
    rc, out, n2 = K.verify(world.pack(world.owners[0], "p"), world.ark())
    assert n2.startswith("node2: COVERED") and "n=4 of 4" in n2, out
    assert len(world.c.get("/v1/node2/keys").json()) == 2


def test_resume_refuses_other_code(world):
    _warm(world)
    w2 = K.make_worker(K.client_http(world.c), world.ctx.wk.pub, policy=fakeamd.RESTRICTIVE_POLICY + b"# other build\n")
    with pytest.raises(W.WorkerError, match="RESUME_OTHER_CODE"):
        w2.start()


def test_old_snapshot_restart_caught_by_pin(world):
    _warm(world, k=1)
    v = world.owners[0]
    old_state, _ = world.adv.snapshot_rows()                       # the operator keeps node 2's state at n=2
    for _ in range(3):
        world.round()
    K.verify(world.pack(v, "p_seen"), world.ark())                 # the tenant checks at n=5 and keeps the pin
    world.adv.restore_old_state(old_state, keep_n=2)
    w2 = K.make_worker(K.client_http(world.c), world.ctx.wk.pub, world.w.amd)
    w2.start()
    assert w2.cos.n == 2
    world.w = w2
    world.round()
    rc, out, n2 = K.verify(world.pack(v, "p_seen"), world.ark())       # same folder: the same pin file next to it
    assert rc == 1 and n2.startswith("node2: ALARM (the co-signature chain differs from the one you saw before"), out
    rc, out, n2 = K.verify(world.pack(v, "elsewhere/p"), world.ark())  # a tenant without a pin sees nothing (plan R1)
    assert n2.startswith("node2: COVERED"), out


def test_resume_mismatch_stops_the_worker(world):
    _warm(world)
    with sqlite3.connect(world.adv.db_path) as c:                 # the operator hands over a snapshot that is not the last cosig's
        snap = cbor2.loads(c.execute("SELECT snapshot FROM node2_state").fetchone()[0])
        snap["alarms"] = 0
        snap["last_t"] = 1
        c.execute("UPDATE node2_state SET snapshot=?", (cbor2.dumps(snap, canonical=True),))
    w2 = K.make_worker(K.client_http(world.c), world.ctx.wk.pub, world.w.amd)
    with pytest.raises(W.WorkerError, match="RESUME_MISMATCH"):
        w2.start()


def test_node2_page_is_served():
    from app.main import _public
    assert _public("node2.html")
    web = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "web")
    assert os.path.isfile(os.path.join(web, "node2.html")) and os.path.isfile(os.path.join(web, "js", "node2.js"))
