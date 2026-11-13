"""r0269: the server side of the public log of batches (app/tlog.py): /checkpoint (C2SP), proofs, the daily stamp with a TSA that
is down and comes back, the receipt's "queued" -> "stamped" status, the evidence pack lines, the JCS args rule and the pinned vocabulary."""
import hashlib
import json
import os

import pytest

import tlogcheck as TC
from app import jobs, tlog
from app import toolmap as tm
from app.signview import jcs
from tests.helpers import act
from tests.test_pack import scenario
import tests.recovery_helpers as rh


def _open(client):
    note = client.get("/checkpoint")
    assert note.status_code == 200 and note.headers["content-type"].startswith("text/plain")
    vk = client.get("/tlog/vkey").text.strip()
    return TC.open_checkpoint(note.text, [vk]), note.text, vk


def test_checkpoint_is_c2sp_signed_by_the_witness_key(client, owner, app):
    cp, note, vk = _open(client)
    assert cp["origin"] == "witness.test/batches" and cp["size"] == 0                       # empty log: size 0, root SHA-256("")
    assert TC.parse_vkey(vk)["pub"].hex() == client.get("/v1/witness").json()["pub_hex"]
    scenario(client, owner)
    b1 = jobs.anchor_once(app.state.ctx)
    cp1, note1, _ = _open(client)
    assert cp1["size"] == 1
    lf = client.get("/tlog/leaf", params={"batch": b1}).json()
    assert TC.parse_batch_leaf(TC.b64d(lf["leaf_b64"]))[0] == b1 and "account" not in TC.b64d(lf["leaf_b64"]).decode()
    scenario(client, owner)
    b2 = jobs.anchor_once(app.state.ctx)
    cp2, note2, _ = _open(client)
    assert cp2["size"] == 2 and b2 != b1
    pr = client.get("/tlog/proof/inclusion", params={"index": 0, "size": 2}).json()
    assert TC.verify_inclusion(TC.leaf_hash(TC.b64d(lf["leaf_b64"])), 0, 2, [TC.b64d(x) for x in pr["path"]], cp2["root"])
    cons = client.get("/tlog/proof/consistency", params={"old": 1, "new": 2}).json()
    assert TC.verify_consistency(1, 2, cp1["root"], cp2["root"], [TC.b64d(x) for x in cons["path"]])
    assert client.get("/tlog/checkpoint/1").text == note1                                     # old checkpoints stay served as signed
    assert client.get("/tlog/proof/inclusion", params={"index": 2, "size": 2}).status_code == 400
    assert client.get("/tlog/proof/consistency", params={"old": 3, "new": 2}).status_code == 400
    assert client.get("/tlog/stamp/..%2Fwitness_key").status_code == 404


def test_the_witness_refuses_to_sign_a_rewritten_log(client, owner, app):
    scenario(client, owner)
    jobs.anchor_once(app.state.ctx)
    _open(client)
    ctx = app.state.ctx
    ctx.db.x("UPDATE tlog_leaves SET leaf=? WHERE idx=0", (TC.batch_leaf("forged", b"\1" * 32),))
    scenario(client, owner)
    jobs.anchor_once(ctx)
    ctx._tlog = None                                                                          # reload from the (tampered) table
    assert client.get("/checkpoint").status_code == 503                                       # no second root over a changed prefix


def test_daily_stamp_tsa_down_then_back(client, owner, app, providers, capsys, monkeypatch):
    """The TSA is down: the receipt is still issued (status "queued"), the stamp row waits; the next try (TSA back) stamps it."""
    ctx = app.state.ctx
    doc = json.loads(providers.read_text())
    good = doc["providers"]
    doc["providers"] = [dict(p, url="http://127.0.0.1:9/down") for p in good]                 # every TSA unreachable
    providers.write_text(json.dumps(doc))
    ag, hdr = scenario(client, owner)
    r = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "t", "body": "b"}).json()
    assert r["verdict"] == "allow" and r["aar_b64"] and r["anchor"] == {"status": "queued"}    # the agent is never blocked
    jobs.anchor_once(ctx)
    res = tlog.stamp_due(ctx, now=1_900_000_000)
    assert res == [(1, "queued")], res
    row = ctx.db.one("SELECT * FROM tlog_stamps WHERE size=1")
    assert row["tries"] == 1 and row["next_try"] == 1_900_000_000 + tlog.RETRY_FIRST and "tsa-a failed" in row["last_err"]
    assert tlog.stamp_due(ctx, now=1_900_000_000 + 10) == []                                 # back-off: not before next_try
    rr = client.get("/v1/actions/%s" % r["rid"], headers=hdr).json()
    assert rr["anchor"]["status"] == "queued" and rr["anchor"].get("log_index") == 0
    doc["providers"] = good
    providers.write_text(json.dumps(doc))
    assert tlog.stamp_due(ctx, now=1_900_000_000 + tlog.RETRY_FIRST) == [(1, "stamped")]
    for n in ("tsa-a", "tsa-b"):
        assert os.path.isfile(os.path.join(ctx.anchor_dir, "tlog-1.tsr.%s" % n))
    rr = client.get("/v1/actions/%s" % r["rid"], headers=hdr).json()
    assert rr["anchor"]["status"] == "stamped" and rr["anchor"]["stamp"]["tsa"] == ["tsa-a", "tsa-b"]
    st = client.get("/tlog/stamps").json()["stamps"][0]
    assert st["status"] == "stamped" and "tlog-1.tsr.tsa-a" in st["files"]
    # one stamp a day: a new batch the same day is not stamped again, the next day it is
    scenario(client, owner)
    jobs.anchor_once(ctx)
    assert tlog.stamp_due(ctx, now=1_900_000_000 + tlog.RETRY_FIRST + 60) == []
    assert tlog.stamp_due(ctx, now=1_900_000_000 + 86400 + 1) == [(2, "stamped")]


def test_nothing_external_configured_says_off(client, owner, app, monkeypatch):
    monkeypatch.setenv("DW_TLOG_TSA", "off")
    scenario(client, owner)
    jobs.anchor_once(app.state.ctx)
    assert tlog.stamp_due(app.state.ctx, force=True) == [(1, "off")]


def test_pack_carries_the_log_and_the_checker_checks_it(client, owner, app, providers, tmp_path):
    ctx = app.state.ctx
    scenario(client, owner)
    b1 = jobs.anchor_once(ctx)
    tlog.stamp_due(ctx, force=True)                                                           # TSA up: checkpoint 1 stamped
    scenario(client, owner)
    b2 = jobs.anchor_once(ctx)                                                                # batch 2: newer than the stamp
    pk = rh.export_to(client, tmp_path / "pk")
    for f in ("tlog/checkpoint.note", "tlog/vkey", "tlog/inclusion/%s.json" % b1, "tlog/stamps/1.note", "tlog/stamps/1.tsr.tsa-a",
              "tlog/stamps/tsa-ca/tsa-a.pem", "verify/tlogcheck.py"):
        assert os.path.isfile(os.path.join(pk, f)), f
    rc, out = rh.run_verify(pk, "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    assert "tlog checkpoint: witness.test/batches size 2" in out
    assert ("tlog %s: leaf 0 of 2 OK; time: no later than TSA tsa-a genTime" % b1) in out, out
    assert ("tlog %s: leaf 1 of 2 OK; time: queued" % b2) in out, out
    rc, out2 = rh.run_verify(pk, "--offline", "--use-pack-code")                         # verify/tlogcheck.py of the pack works too
    assert rc == 0 and ("tlog %s: leaf 0 of 2 OK" % b1) in out2, out2
    # split view: the witness shows somebody else another root for size 2
    k = ctx.wk
    fake = TC.checkpoint_text("witness.test/batches", 2, b"\7" * 32)
    other = TC.make_note(fake, [TC.sign_line("witness.test/batches", TC.ALG_ED25519, k.pub, k.sign(fake.encode()))])
    (tmp_path / "other.note").write_text(other)
    rc, out = rh.run_verify(pk, "--offline", "--checkpoint=%s" % (tmp_path / "other.note"))
    assert rc == 1 and "FORK PROVEN" in out and out.strip().endswith("RESULT: INVALID"), out
    # an honest later checkpoint with its consistency proof
    scenario(client, owner)
    jobs.anchor_once(ctx)
    (tmp_path / "later.note").write_text(client.get("/checkpoint").text)
    (tmp_path / "cons.json").write_text(json.dumps(client.get("/tlog/proof/consistency", params={"old": 2, "new": 3}).json()))
    rc, out = rh.run_verify(pk, "--offline", "--checkpoint=%s" % (tmp_path / "later.note"), "--consistency=%s" % (tmp_path / "cons.json"))
    assert rc == 0 and "2 -> 3 consistent: one view" in out, out
    # a substituted root in the pack's checkpoint breaks the log signature
    p = os.path.join(pk, "tlog", "checkpoint.note")
    t = open(p).read()
    cp = TC.parse_checkpoint(TC.parse_note(t)[0])
    open(p, "w").write(t.replace(TC.b64e(cp["root"]), TC.b64e(b"\5" * 32)))
    rc, out = rh.run_verify(pk, "--offline")
    assert rc == 1 and ("tlog checkpoint: INVALID" in out or "manifest: MISMATCH" in out), out


def test_pack_without_tlog_is_still_valid(client, owner, app, tmp_path, monkeypatch):
    scenario(client, owner)
    jobs.anchor_once(app.state.ctx)
    monkeypatch.setattr(tlog, "pack_files", lambda ctx, bids: {})                              # a pack made before r0269
    pk = rh.export_to(client, tmp_path / "pk")
    rc, out = rh.run_verify(pk, "--offline")
    assert rc == 0 and "tlog" not in out.replace("tlogcheck", ""), out


# ------------------------------------------------------------------ migration: args_sha256 by RFC 8785, vocabulary pinned
def test_args_v2_only_on_request_and_labelled(client, owner, app):
    from tests.test_flow import setup_agent
    ag, hdr, _ = setup_agent(owner)
    a = {"to": "bob@partner.example", "subject": "\u00e9t\u00e9 \U0001f600", "body": "b"}
    old = act(client, hdr, "send_email", a).json()
    assert old["action"], old
    assert "args_v" not in old["action"] and old["action"]["args_sha256"] == tm._args_digest_v1("send_email", a)
    new = act(client, {**hdr, "X-DW-Args-V": "2"}, "send_email", dict(a, subject="s2")).json()
    want = hashlib.sha256(b"mr-args-2\0" + jcs(["send_email", dict(a, subject="s2")])).hexdigest()
    assert new["verdict"] == "allow" and new["action"]["args_v"] == 2 and new["action"]["args_sha256"] == want
    assert tm.args_matches(new["action"], "send_email", dict(a, subject="s2"))
    assert tm.args_matches(old["action"], "send_email", a)                                    # old receipts: old rule, no label
    assert not tm.args_matches(dict(new["action"], args_v=1), "send_email", dict(a, subject="s2"))   # the label is not optional
    assert tm._args_digest_v1("send_email", a) != tm.args_digest_v("send_email", a, v=2)[0]
    assert tm.args_digest_v("t", {"n": 2 ** 60}, v=2) == (tm._args_digest_v1("t", {"n": 2 ** 60}), 1)   # JCS cannot encode it: v1, no label


def test_client_opt_in_roundtrip(cfg, tmp_path, monkeypatch):
    """The open client with DEUS_WITNESS_ARGS_V=2 sends the header and checks the JCS binding; without it nothing changes."""
    import tests.test_0235_salt as S
    for mode in ("off", "on"):
        app, p, hdr = S.mode_app(cfg, tmp_path, mode)
        monkeypatch.setenv("DEUS_WITNESS_ARGS_V", "2")
        w, br = S.new_client(p, hdr, tmp_path)
        r = w.act("send_email", S.args(3))
        assert r.verdict == "allow" and r.action["args_v"] == 2
        assert r.action["args_sha256"] == S.dwc.args_sha256("send_email", S.args(3), w.salt(), 2)
        monkeypatch.delenv("DEUS_WITNESS_ARGS_V")
        w1, _ = S.new_client(p, hdr, tmp_path / ("o" + mode))
        assert "args_v" not in w1.act("send_email", S.args(4)).action


def test_vocabulary_hash_is_inside_the_signed_tool_map(client, owner, app, tmp_path):
    from app import vocab
    from tests.test_flow import setup_agent
    ag, hdr, m = setup_agent(owner)
    row = app.state.ctx.db.one("SELECT gateway_doc FROM mandates ORDER BY created_at DESC LIMIT 1")
    doc = json.loads(row["gateway_doc"])
    assert doc["vocab"] == vocab.digest() and len(doc["vocab"]) == 64
    assert vocab.doc()["reason_words"]                                                        # the closed words, not the agent's
    act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s", "body": "b"})
    jobs.anchor_once(app.state.ctx)
    pk = rh.export_to(client, tmp_path / "pk")
    assert os.path.isfile(os.path.join(pk, "vocab", doc["vocab"] + ".json"))
    rc, out = rh.run_verify(pk, "--offline")
    assert rc == 0 and "vocab: 1 reason vocabulary pinned by signed mandates, 1 present" in out, out
