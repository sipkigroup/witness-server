"""TEE mode (DW_TEE): offline TDX quote checker on hand-built bytes, the server with a fake quote provider, and 'off = unchanged'."""
import base64
import hashlib
import json
import os
import shutil
import socket
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import UnixStreamServer

import pytest
from fastapi.testclient import TestClient

from app import tdx_quote as TQ
from app import tee
from app.config import Config, ConfigError
from app.main import create_app
from tests.helpers import ORIGIN, RP, Owner, act
from tests.tee_kit import FakeIntel, FakeProvider

PUB = bytes(range(32))
RD = TQ.report_data(PUB, TQ.ctx_boot("https://witness.test", 1700000000))


@pytest.fixture(scope="module")
def intel():
    return FakeIntel()


def st(r):
    return {n: s for n, s, _ in r["checks"]}


# ---------------------------------------------------------------- offline checker on hand-built quotes

def test_good_quote_full(intel):
    q = intel.quote(RD)
    exp = {"mr_td": hashlib.sha384(b"mrtd").hexdigest(), "rtmr3": hashlib.sha384(b"rtmr3").hexdigest()}
    r = TQ.verify(q, RD, exp, intel.root_pem())
    assert r["verdict"] == "STRUCTURE_AND_BINDING_OK_TCB_NOT_VERIFIED", r["checks"]
    s = st(r)
    assert s["tcb_status"] == TQ.NV and s["intel_root"] == "ok" and s["measurements"] == "ok"
    assert bytes.fromhex(r["body"]["report_data"]) == RD


def test_without_root_and_expectations_is_incomplete(intel):
    r = TQ.verify(intel.quote(RD), RD)
    assert r["verdict"] == "INCOMPLETE" and st(r)["intel_root"] == TQ.NV and st(r)["measurements"] == TQ.NV


def test_layout_offsets(intel):
    q = intel.quote(RD)
    p = TQ.parse_quote(q)
    assert len(p["signed"]) == 48 + 584
    assert q[48 + 520:48 + 584] == RD                              # report_data is the last 64 bytes of the TD 1.0 body
    assert p["body"]["mr_td"] == q[48 + 136:48 + 184]


@pytest.mark.parametrize("what,check", [
    ("flip_body", "quote_sig"), ("wrong_rd", "report_data"), ("debug", "debug"), ("vendor", "structure"),
    ("qe_bind", "qe_binding"), ("measure", "measurements"), ("other_root", "intel_root")])
def test_each_failure_is_caught(intel, what, check):
    exp, root = None, intel.root_pem()
    if what == "flip_body":
        q = intel.quote(RD)
        q = q[:200] + bytes([q[200] ^ 1]) + q[201:]
    elif what == "wrong_rd":
        q = intel.quote(TQ.report_data(bytes(32), bytes(32)))
    elif what == "debug":
        q = intel.quote(RD, td_attributes=(1).to_bytes(8, "little"))
    elif what == "vendor":
        q = intel.quote(RD, vendor=bytes(16))
    elif what == "qe_bind":
        q = intel.quote(RD, qe_rd=bytes(64))
    elif what == "measure":
        q, exp = intel.quote(RD), {"mr_td": "00" * 48}
    else:
        q, root = intel.quote(RD), FakeIntel().root_pem()
    r = TQ.verify(q, RD, exp, root)
    assert r["verdict"] == "FAIL" and st(r)[check] == "FAIL", r["checks"]


def test_qe_report_signed_by_other_pck(intel):
    from cryptography.hazmat.primitives.asymmetric import ec
    other = FakeIntel()
    other.pck_k = ec.generate_private_key(ec.SECP256R1())             # leaf cert stays, the QE report is signed by another key
    r = TQ.verify(other.quote(RD), RD, None, other.root_pem())
    assert st(r)["qe_report_sig"] == "FAIL"


@pytest.mark.parametrize("cut", [10, 100, 700, -1])
def test_truncated_or_trailing(intel, cut):
    q = intel.quote(RD)
    q = q + b"\x01" if cut == -1 else q[:cut]                        # non-zero tail: refused
    r = TQ.verify(q, RD)
    assert r["verdict"] == "FAIL" and st(r)["structure"] == "FAIL"


def test_zero_padding_after_signature_ok(intel):
    # 23.10 L3 Phala: the real dstack quote ends with 70 zero bytes of buffer padding
    r = TQ.verify(intel.quote(RD) + b"\x00" * 70, RD, None, intel.root_pem())
    assert st(r)["structure"] == "ok" and st(r)["quote_sig"] == "ok"


def test_v5_td15_parses(intel):
    q = intel.quote(RD, version=5, td15=True)
    r = TQ.verify(q, RD, None, intel.root_pem())
    assert st(r)["quote_sig"] == "ok" and st(r)["report_data"] == "ok" and "mr_servicetd" in r["body"]


RT = 0x08000001                                                       # dstack runtime event type (cc-eventlog runtime_events.rs)


def _rt(name, payload_hex, version=None):
    """A dstack runtime event in the JSON shape GetQuote returns; digest computed here independently of tdx_quote."""
    pl = bytes.fromhex(payload_hex)
    if version == 2:
        pre = ('{"name":"%s","payload":"%s","type":%d}' % (name, pl.hex(), RT)).encode()
    else:
        pre = RT.to_bytes(4, "little") + b":" + name.encode() + b":" + pl
    e = {"imr": 3, "event_type": RT, "digest": hashlib.sha384(pre).hexdigest(), "event": name, "event_payload": payload_hex}
    if version == 2:
        e["version"], e["preimage"] = 2, pre.hex()
    return e


def test_event_log_replay(intel):
    ev = [{"imr": 0, "event_type": 3, "digest": "00" * 48, "event": "", "event_payload": ""},     # EV_NO_ACTION: not extended
          _rt("app-id", "aa"), _rt("compose-hash", "c0ffee", version=2)]
    d1, d2 = ev[1]["digest"], ev[2]["digest"]
    r3 = TQ.replay_rtmr([d1, d2])
    assert r3 == hashlib.sha384(hashlib.sha384(bytes(48) + bytes.fromhex(d1)).digest() + bytes.fromhex(d2)).digest()
    q = intel.quote(RD, rtmr3=r3)
    r = TQ.verify(q, RD, {"rtmr3": r3.hex(), "app_events": {"compose-hash": "c0ffee"}}, intel.root_pem(), ev[1:])
    assert r["verdict"] == "STRUCTURE_AND_BINDING_OK_TCB_NOT_VERIFIED", r["checks"]
    r = TQ.verify(q, RD, {"app_events": {"compose-hash": "beef"}}, intel.root_pem(), ev[1:])
    assert st(r)["measurements"] == "FAIL"
    r = TQ.verify(intel.quote(RD), RD, None, intel.root_pem(), ev[1:])          # log does not replay to the quoted RTMR3
    assert st(r)["event_log"] == "FAIL"


def test_event_log_payload_is_bound_to_digest(intel):
    """Forged log: real digests (so RTMR3 replays), but a different compose-hash payload. Must FAIL, not report the forged hash."""
    good = [_rt("app-id", "aa"), _rt("compose-hash", "c0ffee")]
    r3 = TQ.replay_rtmr([e["digest"] for e in good])
    q = intel.quote(RD, rtmr3=r3)
    forged = [dict(good[0]), dict(good[1], event_payload="beef")]
    r = TQ.verify(q, RD, {"app_events": {"compose-hash": "beef"}}, intel.root_pem(), forged)
    assert st(r)["event_log"] == "FAIL" and r["verdict"] == "FAIL" and r["app_events"] == {}
    bad_pre = [good[0], dict(_rt("compose-hash", "c0ffee", version=2), preimage="00")]
    assert st(TQ.verify(q, RD, None, intel.root_pem(), bad_pre))["event_log"] == "FAIL"
    dup = [_rt("compose-hash", "c0ffee"), _rt("compose-hash", "beef")]
    assert st(TQ.verify(q, RD, None, intel.root_pem(), dup))["event_log"] == "FAIL"


PHALA = os.path.join(os.path.dirname(__file__), "fixtures", "tdx", "phala-2026-10-23.json")


def _phala():
    with open(PHALA) as f:
        return json.load(f)


def _strip_like_getquote(events):
    """dstack <= 0.5.12 Attestation::get_tdx_event_log_string -> TdxEvent::stripped(): runtime digest "", boot payload ""."""
    out = []
    for e in events:
        e = dict(e)
        if e["event_type"] == RT:
            e["digest"] = ""
        else:
            e["event_payload"] = ""
        out.append(e)
    return out


def test_real_phala_event_log_replays_all_rtmrs():
    """L3 23.10: the event log of a real Phala CVM (API tcb_info) replays to its RTMR0..3; mr-kms twice with two values is legitimate."""
    fx = _phala()
    rep, app = TQ.replay_event_log(fx["event_log"])
    assert sorted(rep) == [0, 1, 2, 3]
    for i in range(4):
        assert rep[i].hex() == fx["rtmr%d" % i], i
    assert app["compose-hash"] == "8fc819691780c50de8e10ed78897d84992bc6f5c94a1681ae71777a0529a9c61"
    assert app["mr-kms"] == ["8ccccca54c5843a09771e32abc8d17105738d90b76d280924e30098eab7c51d0",
                             "165dfd738520683e400310b2d0214f86e02b1605ea28bf2eed47763ddb7f710f"]
    rep2, app2 = TQ.replay_event_log(_strip_like_getquote(fx["event_log"]))   # the socket (GetQuote) form gives the same result
    assert rep2 == rep and app2 == app


def test_real_phala_quote_with_event_log():
    """The demo-cert quote of the same CVM: signature chain to the pinned Intel root, and the event log replays to ITS RTMRs."""
    fx = _phala()
    blob = bytes.fromhex(fx["demo_cert_quote_hex"])          # API "quote" of the cert = quote || 70 zero bytes || dstack extra (vm_config...)
    q = blob[:636 + int.from_bytes(blob[632:636], "little")]   # header 48 + body 584 + sig_len(4) + signature data
    assert b'"image":"dstack-dev-0.5.12"' in blob                 # the dstack version this fixture documents
    root = os.path.join(os.path.dirname(__file__), "..", "..", "tee", "Intel_SGX_RootCA.pem")
    with open(root, "rb") as f:
        pem = f.read()
    for ev in (fx["event_log"], _strip_like_getquote(fx["event_log"])):
        r = TQ.verify(q, None, {"mr_td": fx["mrtd"], "rtmr3": fx["rtmr3"],
                                "app_events": {"compose-hash": "8FC819691780C50DE8E10ED78897D84992BC6F5C94A1681AE71777A0529A9C61",
                                               "mr-kms": ["8ccccca54c5843a09771e32abc8d17105738d90b76d280924e30098eab7c51d0",
                                                          "165dfd738520683e400310b2d0214f86e02b1605ea28bf2eed47763ddb7f710f"]}},
                      pem, ev)
        s = st(r)
        assert s["event_log"] == "ok" and s["measurements"] == "ok", r["checks"]
        assert all(s[k] == "ok" for k in ("structure", "quote_sig", "qe_binding", "qe_report_sig", "pck_chain", "intel_root")), r["checks"]
    r = TQ.verify(q, None, {"app_events": {"mr-kms": "8ccccca54c5843a09771e32abc8d17105738d90b76d280924e30098eab7c51d0"}}, pem,
                  fx["event_log"])
    assert st(r)["measurements"] == "FAIL"                                  # one of the two KMS values is not in the allowed set


def test_stripped_log_keeps_payload_bound(intel):
    """Socket form (digest ""): the digest is derived from the payload, so a forged compose-hash payload breaks the RTMR3 replay."""
    good = [_rt("app-id", "aa"), _rt("compose-hash", "c0ffee")]
    q = intel.quote(RD, rtmr3=TQ.replay_rtmr([e["digest"] for e in good]))
    stripped = [dict(e, digest="") for e in good]
    assert st(TQ.verify(q, RD, {"app_events": {"compose-hash": "c0ffee"}}, intel.root_pem(), stripped))["event_log"] == "ok"
    forged = [stripped[0], dict(stripped[1], event_payload="beef")]
    assert st(TQ.verify(q, RD, None, intel.root_pem(), forged))["event_log"] == "FAIL"
    boot_no_digest = [{"imr": 0, "event_type": 1, "digest": "", "event": "", "event_payload": ""}] + good
    with pytest.raises(ValueError):
        TQ.replay_event_log(boot_no_digest)                                # a boot event cannot be derived: digest required
    with pytest.raises(ValueError):
        TQ.replay_event_log([dict(good[0], event_payload="zz")] + good[1:])   # payload must be hex


def test_repeated_runtime_events_policy():
    ch = _rt("compose-hash", "c0ffee")
    _, app = TQ.replay_event_log([ch, _rt("app-id", "aa"), _rt("app-id", "AA")])           # same payload twice: one value
    assert app["app-id"] == "aa"
    with pytest.raises(ValueError, match="different payloads"):
        TQ.replay_event_log([ch, _rt("app-id", "aa"), _rt("app-id", "bb")])
    with pytest.raises(ValueError, match="compose-hash"):
        TQ.replay_event_log([ch, _rt("compose-hash", "c0ffee")])                          # exactly once, even with the same payload
    with pytest.raises(ValueError, match="exactly once"):
        TQ.replay_event_log([_rt("app-id", "aa")])                                         # RTMR3 runtime events but no compose-hash
    _, app = TQ.replay_event_log([ch, _rt("mr-kms", "01"), _rt("mr-kms", "02"), _rt("mr-kms", "01")])
    assert app["mr-kms"] == ["01", "02", "01"]


def test_non_runtime_event_cannot_claim_compose_hash(intel):
    """A boot-type (non-runtime) entry named compose-hash is replayed but never counted as an app event."""
    fake = {"imr": 3, "event_type": 1, "digest": hashlib.sha384(b"x").hexdigest(), "event": "compose-hash", "event_payload": "beef"}
    q = intel.quote(RD, rtmr3=TQ.replay_rtmr([fake["digest"]]))
    r = TQ.verify(q, RD, {"app_events": {"compose-hash": "beef"}}, intel.root_pem(), [fake])
    assert st(r)["event_log"] == "ok" and st(r)["measurements"] == "FAIL" and r["app_events"] == {}


def test_report_data_scheme_is_domain_separated():
    root = bytes(32)
    assert TQ.ctx_boot("x", 1) != TQ.ctx_batch("x", root)
    assert TQ.key_hash(PUB) != TQ.key_hash(bytes(32)) and len(TQ.report_data(PUB, root)) == 64
    with pytest.raises(ValueError):
        TQ.key_hash(b"short")


def test_cli(intel, tmp_path):
    p = tmp_path / "att.json"
    p.write_text(json.dumps({"quote_b64": base64.b64encode(intel.quote(RD)).decode()}))
    rp = tmp_path / "root.pem"
    rp.write_bytes(intel.root_pem())
    ex = tmp_path / "exp.json"
    ex.write_text(json.dumps({"mr_td": hashlib.sha384(b"mrtd").hexdigest()}))
    base = [str(p), "--pub", PUB.hex(), "--iss", "https://witness.test", "--t", "1700000000"]
    assert TQ.main(base + ["--intel-root", str(rp), "--expect", str(ex)]) == 0
    assert TQ.main(base) == 1                                         # no root, no expectations: incomplete
    assert TQ.main([str(p), "--pub", PUB.hex(), "--iss", "https://witness.test", "--t", "1"]) == 1


# ---------------------------------------------------------------- server: off = unchanged

def test_off_witness_answer_unchanged(client, app):
    ctx = app.state.ctx
    assert ctx.tee is None and app.state.ctx.cfg.tee == "off"
    r = client.get("/v1/witness")
    old = {"iss": "https://witness.test", "alg": "EdDSA", "kid_hex": ctx.wk.kid.hex(), "pub_hex": ctx.wk.pub.hex(), "web_js_sha256": {}}
    assert r.content == json.dumps(old, separators=(",", ":")).encode()
    r = client.get("/v1/witness/tdx/20260101T000000Z-00000000")      # no TEE route: the same 404 as any unknown /v1 path
    assert r.status_code == 404 and r.content == client.get("/v1/no-such-route").content


def test_from_env_off_by_default_and_validation(tmp_path):
    base = {"DW_DATA_DIR": str(tmp_path), "DW_RP_ID": RP, "DW_ORIGIN": ORIGIN, "DW_KEY_PEPPER": "p"}
    with pytest.raises(ConfigError):
        Config.from_env(base)                                         # off: DW_WITNESS_KEY_FILE still required
    c = Config.from_env(dict(base, DW_WITNESS_KEY_FILE="/k"))
    assert c.tee == "off" and c.witness_key_file == "/k" and c.tee_provider is None
    c = Config.from_env(dict(base, DW_TEE="on"))
    assert c.tee == "on" and c.witness_key_file == os.path.join(str(tmp_path), "tee", "witness_key") and c.tee_provider_name == "auto"
    with pytest.raises(ConfigError):
        Config.from_env(dict(base, DW_TEE="on", DW_WITNESS_KEY_FILE="/operator/key"))
    with pytest.raises(ConfigError):
        Config.from_env(dict(base, DW_TEE="maybe", DW_WITNESS_KEY_FILE="/k"))


# ---------------------------------------------------------------- server: on, fake provider

def tee_cfg(tmp_path, provider):
    d = str(tmp_path / "data")
    return Config(data_dir=d, witness_key_file=os.path.join(d, "tee", "witness_key"), key_pepper="test-pepper", rp_id=RP, origin=ORIGIN,
                  iss="https://witness.test", anchor="off", web_dir=str(tmp_path / "web"), tee="on", tee_provider=provider)


def test_on_key_born_inside_and_attested(tmp_path):
    fp = FakeProvider()
    cfg = tee_cfg(tmp_path, fp)
    app = create_app(cfg)
    kf = cfg.witness_key_file
    assert os.path.isfile(kf) and (os.stat(kf).st_mode & 0o777) == 0o600
    c = TestClient(app, base_url=ORIGIN)
    j = c.get("/v1/witness").json()
    assert j == c.get("/api/witness").json()
    a = j["attestation"]
    assert a["deployment"] == "tee" and a["scheme"] == TQ.SCHEME and a["purpose"] == "boot" and a["provider"] == "fake"
    rd = TQ.report_data(bytes.fromhex(j["pub_hex"]), TQ.ctx_boot(j["iss"], a["t"]))
    r = TQ.verify(base64.b64decode(a["quote_b64"]), rd, {"mr_td": a["measurements"]["mr_td"]}, fp.intel.root_pem())
    assert r["verdict"] == "STRUCTURE_AND_BINDING_OK_TCB_NOT_VERIFIED", r["checks"]
    seed = open(kf).read()
    create_app(cfg)                                                   # restart: the key is kept, never regenerated
    assert open(kf).read() == seed


@pytest.mark.parametrize("prov", [FakeProvider(tamper="report_data"), FakeProvider(tamper="flip"),
                                  FakeProvider(fail=OSError("no agent")), FakeProvider(td_attributes=(1).to_bytes(8, "little"))])
def test_on_refuses_start_without_a_valid_quote(tmp_path, prov):
    with pytest.raises(tee.TeeError):
        create_app(tee_cfg(tmp_path, prov))


def test_on_batch_quote(tmp_path):
    from app import jobs
    fp = FakeProvider()
    app = create_app(tee_cfg(tmp_path, fp))
    c = TestClient(app, base_url=ORIGIN)
    ow = Owner(c).register("Alice")
    ag, hdr = ow.new_agent()
    assert act(c, hdr, "read_file", {"p": 1}).status_code == 200
    ctx = app.state.ctx
    bid = jobs.anchor_once(ctx)
    assert bid
    root = bytes(ctx.db.one("SELECT root FROM anchor_batches WHERE id=?", (bid,))["root"])
    a = c.get("/v1/witness/tdx/" + bid).json()
    assert a["purpose"] == "batch" and a["batch"] == bid and a["root_hex"] == root.hex()
    rd = TQ.report_data(ctx.wk.pub, TQ.ctx_batch(bid, root))
    assert TQ.verify(base64.b64decode(a["quote_b64"]), rd, None, fp.intel.root_pem())["verdict"] == "INCOMPLETE"   # no measurements given
    assert st(TQ.verify(base64.b64decode(a["quote_b64"]), rd))["report_data"] == "ok"
    assert c.get("/v1/witness/tdx/../../db.sqlite").status_code == 404
    assert c.get("/v1/witness/tdx/20260101T000000Z-00000000").status_code == 404


def test_keygen_cli(tmp_path, capsys):
    p = str(tmp_path / "k" / "witness_key")
    assert tee.main(["keygen", p]) == 0 and capsys.readouterr().out.startswith("created ")
    s = open(p).read()
    assert tee.main(["keygen", p]) == 0 and capsys.readouterr().out.startswith("exists ") and open(p).read() == s
    assert tee.main([]) == 2


# ---------------------------------------------------------------- real-interface adapters, against local stand-ins

def test_dstack_provider_over_unix_socket(intel):
    d = tempfile.mkdtemp(prefix="dw", dir="/tmp")                     # AF_UNIX path length limit: keep it short
    sock = os.path.join(d, "s")
    seen = {}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen["path"], seen["rd"] = self.path, body["report_data"]
            out = json.dumps({"quote": intel.quote(bytes.fromhex(body["report_data"])).hex(), "event_log": "[]"}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

        def address_string(self):
            return "unix"

    class S(UnixStreamServer, HTTPServer):
        def server_bind(self):
            UnixStreamServer.server_bind(self)
            self.server_name, self.server_port = "unix", 0
    srv = S(sock, H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        q, ev = tee.DstackProvider(sock).quote(RD)
        assert seen == {"path": "/GetQuote", "rd": RD.hex()} and ev == [] and TQ.parse_quote(q)["body"]["report_data"] == RD
        q, ev = tee.TappdProvider(sock).quote(RD)
        assert seen["path"] == "/prpc/Tappd.RawQuote"
    finally:
        srv.shutdown()
        srv.server_close()
        shutil.rmtree(d, ignore_errors=True)


def test_configfs_provider(tmp_path, intel, monkeypatch):
    p = tee.ConfigfsProvider(str(tmp_path))
    q = intel.quote(RD)

    def mk():
        e = tmp_path / "e"
        e.mkdir()
        (e / "provider").write_text("tdx_guest\n")
        (e / "outblob").write_bytes(q)
        (e / "generation").write_text("1\n")
        return str(e)
    monkeypatch.setattr(p, "_mkentry", mk)
    monkeypatch.setattr(p, "_rmentry", lambda x: shutil.rmtree(x))
    out, ev = p.quote(RD)
    assert out == q and ev is None and not (tmp_path / "e").exists()


def test_provider_selection(tmp_path):
    cfg = tee_cfg(tmp_path, None)
    cfg.tee_provider_name = "configfs"
    assert isinstance(tee.provider_for(cfg), tee.ConfigfsProvider)
    cfg.tee_provider_name = "nope"
    with pytest.raises(tee.TeeError):
        tee.provider_for(cfg)


def test_expect_template_notes_are_skipped_and_placeholders_fail(intel):
    """cloud/tee/expect.template.json: _notes are ignored; an unfilled placeholder is a FAIL, never a silent pass."""
    p = os.path.join(os.path.dirname(__file__), "..", "..", "tee", "expect.template.json")
    tpl = json.load(open(p))
    assert any(k.startswith("_") for k in tpl) and "compose-hash" in tpl["app_events"]
    q = intel.quote(RD)
    assert st(TQ.verify(q, RD, tpl, intel.root_pem(), []))["measurements"] == "FAIL"
    filled = {"_comment": "x", "mr_td": hashlib.sha384(b"mrtd").hexdigest().upper()}
    assert st(TQ.verify(q, RD, filled, intel.root_pem()))["measurements"] == "ok"


# ---------------------------------------------------------------- TCB status from Intel PCS collateral (23.10)

from tests.tee_kit import T0, FakePcs                                      # noqa: E402

FX = os.path.join(os.path.dirname(__file__), "fixtures", "tdx")
COL = os.path.join(FX, "phala-2026-10-23-collateral")                     # fetched from Intel PCS 23.10.2026 18:28Z (meta.json)
COL_T = 1792780200                                                        # 2026-10-23T18:30:00Z: inside every validity window


def _real():
    with open(os.path.join(FX, "phala-tdx2-2026-10-23-witness.json")) as f:
        w = json.load(f)
    with open(os.path.join(FX, "phala-tdx2-2026-10-23-expect.json")) as f:
        exp = json.load(f)
    with open(os.path.join(os.path.dirname(__file__), "..", "..", "tee", "Intel_SGX_RootCA.pem"), "rb") as f:
        root = f.read()
    a = w["attestation"]
    rd = TQ.report_data(bytes.fromhex(w["pub_hex"]), TQ.ctx_boot(w["iss"], a["t"]))
    return base64.b64decode(a["quote_b64"]), rd, exp, root, a["event_log"]


def test_real_phala_tcb_is_up_to_date():
    """L3 23.10: the real Phala CVM quote + real Intel PCS collateral -> UpToDate, no advisories, verdict OK (dcap-qvl 0.7.0 agrees)."""
    q, rd, exp, root, ev = _real()
    r = TQ.verify(q, rd, exp, root, ev, COL, COL_T)
    assert r["verdict"] == "OK", r["checks"]
    t = r["tcb"]
    assert (t["status"], t["advisory_ids"], t["fmspc"], t["tcb_eval_data_number"]) == ("UpToDate", [], "20a06f000000", 20)
    assert (t["platform_status"], t["qe_status"], t["pce_svn"], t["qe_isvsvn"]) == ("UpToDate", "UpToDate", 13, 6)
    assert TQ.verify(q, rd, exp, root, ev)["verdict"] == "STRUCTURE_AND_BINDING_OK_TCB_NOT_VERIFIED"    # no collateral: as before
    assert st(TQ.verify(q, rd, exp, None, ev, COL, COL_T))["tcb_status"] == TQ.NV                      # collateral needs the root


def _col_real():
    return TQ.load_collateral(COL)


@pytest.mark.parametrize("what", ["body", "signature", "qe_body"])
def test_real_phala_tampered_collateral_fails(what):
    q, rd, exp, root, ev = _real()
    col = _col_real()
    if what == "body":                                             # a forged TCB level: the bytes Intel signed change
        col["tcb_info.json"] = col["tcb_info.json"].replace(b'"OutOfDate"', b'"UpToDate"', 1)
    elif what == "signature":
        s = col["tcb_info.json"]
        i = s.rindex(b'"signature":"') + 13
        col["tcb_info.json"] = s[:i] + (b"0" if s[i:i + 1] != b"0" else b"1") + s[i + 1:]
    else:
        col["qe_identity.json"] = col["qe_identity.json"].replace(b'"isvprodid":2', b'"isvprodid":3')
    r = TQ.verify(q, rd, exp, root, ev, col, COL_T)
    assert r["verdict"] == "FAIL" and st(r)["tcb_status"] == TQ.FAIL and "signature invalid" in dict(
        (n, d) for n, _, d in r["checks"])["tcb_status"]


@pytest.mark.parametrize("now,why", [(1795375200, "EXPIRED"), (1700000000, "outside")])   # after nextUpdate (22.11) / before issue
def test_real_phala_collateral_out_of_date_window_fails(now, why):
    q, rd, exp, root, ev = _real()
    r = TQ.verify(q, rd, exp, root, ev, COL, now)
    d = dict((n, d) for n, _, d in r["checks"])["tcb_status"]
    assert r["verdict"] == "FAIL" and why in d, d


def test_real_phala_foreign_crl_or_missing_file_fails():
    q, rd, exp, root, ev = _real()
    col = _col_real()
    col["pck_crl.der"] = FakePcs().collateral()["pck_crl.der"]                  # a CRL not signed by Intel's PCK Platform CA
    assert st(TQ.verify(q, rd, exp, root, ev, col, COL_T))["tcb_status"] == TQ.FAIL
    col = _col_real()
    del col["root_ca_crl.der"]
    assert st(TQ.verify(q, rd, exp, root, ev, col, COL_T))["tcb_status"] == TQ.FAIL


def test_real_phala_cli_with_collateral(capsys):
    w = os.path.join(FX, "phala-tdx2-2026-10-23-witness.json")
    with open(w) as f:
        j = json.load(f)
    args = [w, "--pub", j["pub_hex"], "--iss", j["iss"], "--t", str(j["attestation"]["t"]), "--expect",
            os.path.join(FX, "phala-tdx2-2026-10-23-expect.json"), "--intel-root",
            os.path.join(os.path.dirname(__file__), "..", "..", "tee", "Intel_SGX_RootCA.pem"), "--collateral-dir", COL]
    assert TQ.main(args + ["--now", "2026-10-23T18:30:00Z"]) == 0
    assert "verdict: OK" in capsys.readouterr().out
    assert TQ.main(args + ["--now", "2026-12-01T00:00:00Z"]) == 1                # expired collateral: not ok


@pytest.fixture(scope="module")
def pcs():
    return FakePcs()


def test_fake_pcs_up_to_date(pcs):
    r = TQ.verify(pcs.tdx_quote(RD), RD, {"mr_td": hashlib.sha384(b"mrtd").hexdigest()}, pcs.root_pem(), None, pcs.collateral(), T0)
    assert r["verdict"] == "OK", r["checks"]


def test_fake_pcs_pck_in_crl_fails(pcs):
    """PCK leaf revoked by Intel (its serial in the PCK CRL) -> FAIL; PCK CA revoked in the root CRL -> FAIL."""
    for kw in ({"revoked_pck": True}, {"revoked_ca": True}):
        r = TQ.verify(pcs.tdx_quote(RD), RD, None, pcs.root_pem(), None, pcs.collateral(**kw), T0)
        d = dict((n, d) for n, _, d in r["checks"])["tcb_status"]
        assert r["verdict"] == "FAIL" and "REVOKED" in d, d


@pytest.mark.parametrize("kw,quote_kw,status,adv", [
    ({"status": "SWHardeningNeeded", "advisories": ["INTEL-SA-00615"]}, {}, "SWHardeningNeeded", ["INTEL-SA-00615"]),
    ({"status": "ConfigurationNeeded"}, {}, "ConfigurationNeeded", []),
    ({}, {"tee_tcb_svn": bytes([11, 1, 4] + [0] * 13)}, "OutOfDate", ["INTEL-SA-01192"]),       # TEE TCB SVN below the top level
    ({"module_status": "OutOfDate"}, {}, "OutOfDate", []),                                     # TDX module level converges
    ({"status": "ConfigurationNeeded", "qe_status": "OutOfDate"}, {}, "OutOfDateConfigurationNeeded", []),
])
def test_fake_pcs_not_up_to_date_is_its_own_verdict(pcs, kw, quote_kw, status, adv):
    r = TQ.verify(pcs.tdx_quote(RD, **quote_kw), RD, {"mr_td": hashlib.sha384(b"mrtd").hexdigest()}, pcs.root_pem(), None,
                  pcs.collateral(**kw), T0)
    assert r["verdict"] == "TCB_" + status and st(r)["tcb_status"] == status, r["checks"]
    assert r["tcb"]["advisory_ids"] == adv


def test_fake_pcs_revoked_and_mismatches_fail(pcs):
    q = pcs.tdx_quote(RD)
    assert TQ.verify(q, RD, None, pcs.root_pem(), None, pcs.collateral(status="Revoked"), T0)["verdict"] == "FAIL"
    bad = [pcs.tdx_quote(RD, qe_isvsvn=3),                                      # QE below every QE Identity level
           pcs.tdx_quote(RD, mr_signer_seam=b"\x01" * 48),                      # TDX module not signed by Intel
           pcs.tdx_quote(RD, tee_tcb_svn=bytes([11, 1, 1] + [0] * 13))]         # below every TCB level
    for b in bad:
        assert st(TQ.verify(b, RD, None, pcs.root_pem(), None, pcs.collateral(), T0))["tcb_status"] == TQ.FAIL
    other = FakePcs()                                                          # collateral signed under a different root
    assert st(TQ.verify(q, RD, None, pcs.root_pem(), None, other.collateral(), T0))["tcb_status"] == TQ.FAIL


def test_pck_extension_of_the_real_leaf():
    q, *_ = _real()
    from cryptography import x509
    leaf = x509.load_pem_x509_certificates(bytes(TQ.parse_quote(q)["pck_pem"]).rstrip(b"\x00"))[0]
    e = TQ.pck_extensions(leaf)
    assert (e["fmspc"].hex(), e["pce_id"].hex(), e["cpu_svn"].hex(), e["pce_svn"]) == (
        "20a06f000000", "0000", "0505020205ff00020000000000000000", 13)
