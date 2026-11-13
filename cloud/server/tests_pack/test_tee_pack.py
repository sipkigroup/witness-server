"""DW_TEE: the batch quote is named by hash in every anchor record and travels in the evidence pack; verify_pack walks
receipt -> entry -> checkpoint -> batch root -> anchor record -> quote (by SHA-256) -> report_data -> the witness key that signed the
receipt. Failure modes: a batch without a quote, a quote named but missing, a quote over another key or another batch, measurements
that are not the expected ones, one key under quotes of two code versions (OS measurement or compose-hash). Off: the record is the old one."""
import base64
import hashlib
import io
import json
import os
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import jobs
from app import tdx_quote as TQ
from app.config import Config
from app.main import create_app
from tests.helpers import ORIGIN, RP, Owner, act
from tests.tee_kit import FakeIntel, FakeProvider
from kit import CHECKER, reseal, run_verify

RT = 0x08000001


def _rt(name, payload_hex):
    pre = RT.to_bytes(4, "little") + b":" + name.encode() + b":" + bytes.fromhex(payload_hex)
    return {"imr": 3, "event_type": RT, "digest": hashlib.sha384(pre).hexdigest(), "event": name, "event_payload": payload_hex}


def _log(compose):
    ev = [_rt("app-id", "aa"), _rt("compose-hash", compose)]
    return ev, TQ.replay_rtmr([e["digest"] for e in ev])


@pytest.fixture(scope="module")
def intel():
    return FakeIntel()


def _prov(intel, compose="c0ffee", **over):
    ev, r3 = _log(compose)
    return FakeProvider(intel=intel, event_log=ev, rtmr3=r3, **over)


def _cfg(d, provider):
    return Config(data_dir=d, witness_key_file=os.path.join(d, "tee", "witness_key"), key_pepper="test-pepper", rp_id=RP, origin=ORIGIN,
                  iss="https://witness.test", anchor="off", web_dir=os.path.join(d, "..", "web"), tee="on", tee_provider=provider)


class World:
    def __init__(self, tmp_path, provider):
        self.d = str(tmp_path / "data")
        self.tmp = tmp_path
        self.start(provider)
        self.ow = Owner(self.c).register("Alice")
        from tests.test_flow import setup_agent
        self.ag, self.hdr, _ = setup_agent(self.ow)

    def start(self, provider):
        old = getattr(self, "c", None)
        self.app = create_app(_cfg(self.d, provider))
        self.c = TestClient(self.app, base_url=ORIGIN)
        if old is not None:                                   # restart: the owner's session lives in the database, keep the cookie
            self.c.cookies = old.cookies
            self.ow.c = self.c
        self.ctx = self.app.state.ctx

    def act(self, n=1):
        for _ in range(n):
            self.n = getattr(self, "n", 0) + 1                  # distinct args: a repeated call is not a new entry
            r = act(self.c, self.hdr, "send_email", {"to": "bob@partner.example", "subject": "s%d" % self.n, "body": "b"})
            assert r.status_code == 200 and r.json()["verdict"] == "allow", r.text

    def batch(self):
        bid = jobs.anchor_once(self.ctx, tsa=False)
        assert bid
        return bid

    def export(self, name):
        r = self.c.get("/api/export")
        assert r.status_code == 200, r.text
        dest = self.tmp / name
        zipfile.ZipFile(io.BytesIO(r.content)).extractall(dest)
        return str(dest)


def _expect(intel, compose="c0ffee"):
    b = intel.body(bytes(64))
    return {"mr_td": b["mr_td"].hex(), "rtmr0": b["rtmr0"].hex(), "rtmr1": b["rtmr1"].hex(), "rtmr2": b["rtmr2"].hex(),
            "app_events": {"compose-hash": compose}}


def _flags(tmp_path, intel, expect=None):
    rp = tmp_path / "intel_root.pem"
    rp.write_bytes(intel.root_pem())
    f = ["--offline", "--tee-intel-root=%s" % rp]
    if expect is not None:
        ep = tmp_path / "expect.json"
        ep.write_text(json.dumps(expect))
        f.append("--tee-expect=%s" % ep)
    return f


def _lines(out):
    return [ln for ln in out.splitlines() if ln.startswith("tee")]


def test_anchor_record_names_the_quote_and_pack_chain_is_valid(tmp_path, intel):
    w = World(tmp_path, _prov(intel))
    w.act(2)
    b1 = w.batch()
    w.act(1)
    b2 = w.batch()
    for b in (b1, b2):                                      # server side: the anchor record names the quote by hash and by URL
        rec = json.load(open(os.path.join(w.ctx.anchor_dir, b + ".json")))
        att = json.load(open(os.path.join(w.ctx.anchor_dir, b + ".tdx.json")))
        assert rec["tee"]["quote_sha256"] == hashlib.sha256(base64.b64decode(att["quote_b64"])).hexdigest()
        assert rec["tee"]["url"] == "/v1/witness/tdx/" + b and rec["tee"]["scheme"] == TQ.SCHEME
        assert w.c.get(rec["tee"]["url"]).json() == att
        rd = TQ.report_data(w.ctx.wk.pub, TQ.ctx_batch(b, bytes.fromhex(rec["root"])))
        assert att["report_data_hex"] == rd.hex()
    d = w.export("good")
    a = json.load(open(os.path.join(d, "anchors", b1 + ".json")))
    assert a["tee"]["quote"] == "tee/%s.tdx.json" % b1 and a["tee"]["url"] == "https://witness.test/v1/witness/tdx/" + b1
    assert os.path.isfile(os.path.join(d, "tee", "boot.tdx.json")) and os.path.isfile(os.path.join(d, "verify", "tdx_quote.py"))
    for chk in (None, CHECKER):                             # the pack's own copy and the trusted one
        rc, out = run_verify(d, *_flags(tmp_path, intel, _expect(intel)), "--require-tee", checker=chk)
        assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
        assert "tee %s: OK" % b1 in out and "tee %s: OK" % b2 in out and "tee boot: OK" in out, out
        assert "tee: 2 of 2 anchored checkpoints under a batch with a valid quote" in out, out
        assert "receipts 3/3 covered (receipt -> entry -> checkpoint -> batch root -> quote -> witness key" in out, out
        assert "TEE: which code holds the key" not in out          # --tee-expect given: measurements compared
    rc, out = run_verify(d, "--offline", checker=CHECKER)          # no pins: still VALID, but the checker says what it did not prove
    assert rc == 0 and "TEE: which code holds the key" in out and "TEE: that the quotes come from Intel hardware" in out, out


def test_off_anchor_record_and_pack_unchanged(client, owner, app, tmp_path):
    from tests.test_pack import scenario
    scenario(client, owner)
    bid = jobs.anchor_once(app.state.ctx, tsa=False)
    rec = json.load(open(os.path.join(app.state.ctx.anchor_dir, bid + ".json")))
    assert sorted(rec) == ["id", "leaves", "registry_head", "root", "status", "t"]
    r = client.get("/api/export")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert not [n for n in z.namelist() if n.startswith("tee/") or n == "verify/tdx_quote.py"]
    assert "tee" not in json.loads(z.read("anchors/%s.json" % bid))
    z.extractall(tmp_path / "off")
    rc, out = run_verify(str(tmp_path / "off"), "--offline", checker=CHECKER)
    assert rc == 0 and not _lines(out), out
    rc, out = run_verify(str(tmp_path / "off"), "--offline", "--require-tee", "--tee-intel-root=/x.pem", "--tee-expect=/x.json", checker=CHECKER)
    assert rc == 1 and "tee: NONE" in out, out


def test_batch_without_quote_is_disclosed_not_credited(tmp_path, intel):
    p = _prov(intel)
    w = World(tmp_path, p)
    w.act(1)
    b1 = w.batch()
    p.fail = OSError("quote agent down")                   # the agent fails at batch time: the batch stands, the record says so
    w.act(1)
    b2 = w.batch()
    rec = json.load(open(os.path.join(w.ctx.anchor_dir, b2 + ".json")))
    assert rec["tee"]["quote_sha256"] is None and "no quote" in rec["tee"]["error"]
    assert not os.path.exists(os.path.join(w.ctx.anchor_dir, b2 + ".tdx.json"))
    p.fail = None
    d = w.export("gap")
    fl = _flags(tmp_path, intel, _expect(intel))
    rc, out = run_verify(d, *fl, checker=CHECKER)
    assert rc == 0 and "tee %s: NO QUOTE" % b2 in out and "tee %s: OK" % b1 in out, out
    assert "tee: GAP" in out and "tee: 1 of 2 anchored checkpoints" in out, out
    rc, out = run_verify(d, *fl, "--require-tee", checker=CHECKER)
    assert rc == 1 and out.strip().splitlines()[-1] == "RESULT: INVALID", out


def _edit(d, wk, b, fn):
    """Changes tee/<b>.tdx.json and/or anchors/<b>.json, then reseals with the witness key (only the TEE step can fail)."""
    ap, qp = os.path.join(d, "anchors", b + ".json"), os.path.join(d, "tee", b + ".tdx.json")
    a, att = json.load(open(ap)), (json.load(open(qp)) if os.path.exists(qp) else None)
    a, att = fn(a, att)
    json.dump(a, open(ap, "w"), indent=1)
    if att is None:
        if os.path.exists(qp):
            os.remove(qp)
    else:
        json.dump(att, open(qp, "w"))
    reseal(d, wk)


def _requote(intel, a, att, rd):
    att = dict(att, quote_b64=base64.b64encode(intel.quote(rd, rtmr3=_log("c0ffee")[1])).decode(), report_data_hex=rd.hex())
    a = dict(a, tee=dict(a["tee"], quote_sha256=hashlib.sha256(base64.b64decode(att["quote_b64"])).hexdigest()))
    return a, att


@pytest.fixture()
def packed(tmp_path, intel):
    w = World(tmp_path, _prov(intel))
    w.act(2)
    b = w.batch()
    return w, b, w.export("base")


def test_named_quote_missing_or_swapped(packed, tmp_path, intel):
    w, b, d = packed
    fl = _flags(tmp_path, intel, _expect(intel))
    _edit(d, w.ctx.wk, b, lambda a, att: (a, None))                      # the record names a quote, the pack has none
    rc, out = run_verify(d, *fl, checker=CHECKER)
    assert rc == 1 and "tee %s: MISSING QUOTE (TEE_QUOTE_MISSING" % b in out, out
    d2 = w.export("swap")
    att0 = json.load(open(os.path.join(d2, "tee", b + ".tdx.json")))
    other = base64.b64encode(intel.quote(bytes.fromhex(att0["report_data_hex"]), rtmr3=_log("c0ffee")[1])).decode()
    _edit(d2, w.ctx.wk, b, lambda a, att: (a, dict(att, quote_b64=other)))  # a valid quote, but not the one the record names
    rc, out = run_verify(d2, *fl, checker=CHECKER)
    assert rc == 1 and "tee %s: MISMATCH (TEE_QUOTE_MISSING" % b in out, out


def test_quote_over_a_foreign_key_or_another_batch(packed, tmp_path, intel):
    w, b, d = packed
    fl = _flags(tmp_path, intel, _expect(intel))
    root = bytes.fromhex(json.load(open(os.path.join(d, "anchors", b + ".json")))["root"])
    stranger = hashlib.sha256(b"another witness key").digest()
    _edit(d, w.ctx.wk, b, lambda a, att: _requote(intel, a, att, TQ.report_data(stranger, TQ.ctx_batch(b, root))))
    rc, out = run_verify(d, *fl, checker=CHECKER)
    assert rc == 1 and "tee %s: FOREIGN KEY (TEE_BINDING_MISMATCH" % b in out, out
    d2 = w.export("other-batch")
    _edit(d2, w.ctx.wk, b, lambda a, att: _requote(intel, a, att, TQ.report_data(w.ctx.wk.pub, TQ.ctx_batch(b, bytes(32)))))
    rc, out = run_verify(d2, *fl, checker=CHECKER)
    assert rc == 1 and "tee %s: BINDING MISMATCH (TEE_BINDING_MISMATCH" % b in out, out
    d3 = w.export("flip")                                                  # a broken signature
    _edit(d3, w.ctx.wk, b, lambda a, att: _flip(a, att))
    rc, out = run_verify(d3, *fl, checker=CHECKER)
    assert rc == 1 and "tee %s: INVALID (TEE_QUOTE_INVALID: quote_sig" % b in out, out


def _flip(a, att):
    q = bytearray(base64.b64decode(att["quote_b64"]))
    q[200] ^= 1
    att = dict(att, quote_b64=base64.b64encode(bytes(q)).decode())
    return dict(a, tee=dict(a["tee"], quote_sha256=hashlib.sha256(bytes(q)).hexdigest())), att


def test_measurements_not_the_expected(packed, tmp_path, intel):
    w, b, d = packed
    rc, out = run_verify(d, *_flags(tmp_path, intel, dict(_expect(intel), mr_td="00" * 48)), checker=CHECKER)
    assert rc == 1 and "tee %s: MEASUREMENT UNKNOWN (TEE_MEASUREMENT_UNKNOWN: mismatch: mr_td" % b in out, out
    rc, out = run_verify(d, *_flags(tmp_path, intel, _expect(intel, compose="beef")), checker=CHECKER)
    assert rc == 1 and "TEE_MEASUREMENT_UNKNOWN: mismatch: compose-hash" in out, out
    other = FakeIntel()                                                    # a chain that does not end in the pinned root
    rc, out = run_verify(d, *_flags(tmp_path, other, _expect(intel)), checker=CHECKER)
    assert rc == 1 and "TEE_QUOTE_INVALID: intel_root" in out, out


@pytest.mark.parametrize("change", ["compose", "os"])
def test_key_outlived_code_version(tmp_path, intel, change):
    """A new image under the same app-id reads the same key from the volume: its quotes show other code, the key signs on -> alarm."""
    w = World(tmp_path, _prov(intel))
    w.act(1)
    b1 = w.batch()
    seed = open(os.path.join(w.d, "tee", "witness_key")).read()
    new = _prov(intel, compose="beef") if change == "compose" else _prov(intel, mr_td=hashlib.sha384(b"other os").digest())
    w.start(new)                                                           # restart: same data dir, same key, other code
    assert open(os.path.join(w.d, "tee", "witness_key")).read() == seed
    w.act(1)
    b2 = w.batch()
    d = w.export("outlived")
    rc, out = run_verify(d, *_flags(tmp_path, intel), checker=CHECKER)     # no --tee-expect: still caught, from the quotes alone
    assert rc == 1 and "tee: KEY OUTLIVED CODE (TEE_KEY_OUTLIVED_CODE" in out, out
    assert "tee %s: OK" % b1 in out and "tee %s: OK" % b2 in out, out


# ---- 23.10: flags must not be ignored silently
@pytest.mark.parametrize("flag", ["--tee-intel-root=x --require-tee", "--require-tee --offline", "--tee-expectt=x", "--offline=1", "--tee-expect", "--bogus"])
def test_unknown_or_glued_argument_exits_2(tmp_path, flag):
    rc, out = run_verify(str(tmp_path), flag, checker=CHECKER)
    assert rc == 2 and "unknown or malformed argument" in out and "RESULT" not in out


@pytest.mark.parametrize("flags", [[], ["--tee-intel-root=/x.pem"], ["--tee-expect=/x.json"], ["--tee-intel-root=", "--tee-expect=/x.json"]])
def test_require_tee_without_intel_root_or_expect_is_invalid(tmp_path, flags):
    rc, out = run_verify(str(tmp_path), "--offline", "--require-tee", *flags, checker=CHECKER)
    assert rc == 1 and out.rstrip().endswith("RESULT: INVALID") and "--require-tee needs" in out
