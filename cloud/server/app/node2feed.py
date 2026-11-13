"""0.2.27: node 2 on node 1 (plan: cloud/node2/PLAN-NODE2-AZURE-SNP-2026-10-22.md, section 3). OFF unless DW_NODE2=on: with it off
no route below exists, no table is created and the evidence pack is byte-for-byte what 0.2.26 made.

Node 2 is an independent co-signer of the journal HEADS (cloud/node2/node2/cosign.py, open code): it never sees entries, only the batch
of each anchor run (root, leaves, the signed checkpoints) and, per journal, an RFC 9162 consistency proof from the last size node 2
itself co-signed. It answers with a signed co-signature (cosig) or a signed ALARM. Node 1 (this server) is the party node 2 watches, so
nothing here is trusted by a user: every object is signed by K2 and checked again offline (verify_pack.py, node 2 section).

Internal (node 2 -> node 1; Bearer token whose SHA-256 is cfg.node2_token_sha256):
  POST /internal/node2/hello   {attestation}            register K2 with its SEV-SNP attestation; -> resume data of the previous instance
  POST /internal/node2/feed    {after, sizes}           the next batch after `after` with proofs from node 2's OWN sizes ({ledger hex: size})
  POST /internal/node2/submit  {kind, bid, cose_b64, snapshot_b64}   a cosig (chain continued, snapshot matches) or an alarm (verified)
Public (self-verifying data; node 1 only relays it):
  GET /v1/node2  /v1/node2/keys  /v1/node2/latest  /v1/node2/cosig/{bid}  /v1/node2/chain?from=&limit=  /v1/node2/alarms

Finding of the stand 22.10 (OTCHET-STEND-2026-10-22.md, item 5): the consistency proof is built AT FEED TIME from the last size node 2
co-signed, never when the batch was made; node 2 sends its sizes itself (no node-1 bookkeeping that could drift after a crash).
The proofs are not under the batch root, so recomputing them is safe."""
import base64
import hashlib
import hmac
import json
import re
import time

import cbor2

from app import _paths  # noqa: F401
from app.context import Err, check_json
from app.log import log

SCHEMA = """
CREATE TABLE IF NOT EXISTS node2_keys(pub BLOB PRIMARY KEY, kid BLOB NOT NULL, t INTEGER, platform TEXT, doc_json TEXT NOT NULL,
  added_at INTEGER NOT NULL, amd TEXT);
CREATE TABLE IF NOT EXISTS node2_sigs(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, bid TEXT NOT NULL, n INTEGER, pub BLOB NOT NULL,
  cose BLOB NOT NULL, hash BLOB NOT NULL UNIQUE, alarm TEXT, ledger BLOB, alarms INTEGER, t INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ix_node2_cosig_n ON node2_sigs(n) WHERE kind='cosig';
CREATE UNIQUE INDEX IF NOT EXISTS ix_node2_cosig_bid ON node2_sigs(bid) WHERE kind='cosig';
CREATE TABLE IF NOT EXISTS node2_state(id INTEGER PRIMARY KEY CHECK (id = 1), snapshot BLOB NOT NULL, last_hash BLOB NOT NULL, t INTEGER);
"""
BID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
HELLO_SKEW_S = 600
MAX_SIZES = 100000
CHAIN_PAGE = 500


def _mods():
    from node2 import attest, cosign
    return cosign, attest


def b64(b):
    return base64.b64encode(bytes(b)).decode()


def unb64(s, code="BAD_REQUEST"):
    try:
        return base64.b64decode(s, validate=True)
    except (TypeError, ValueError):
        raise Err(400, code, "not base64")


def attach(ctx):
    """DW_NODE2=on: tables (CREATE IF NOT EXISTS, nothing else is touched). Off: nothing at all."""
    if getattr(ctx.cfg, "node2", "off") != "on":
        return False
    _mods()                                          # the node 2 package must be importable (DW_NODE2_DIR), or the server does not start
    with ctx.db.lock:
        ctx.db.c.executescript(SCHEMA)
    return True


def enabled(ctx):
    return getattr(ctx.cfg, "node2", "off") == "on"


def ledger_ids(ctx):
    """{ledger id (bytes): account id}: svidetel_v4 Ledger.lid = SHA-256("deus-aar/ledger/" || principal || witness kid)."""
    return {hashlib.sha256(b"deus-aar/ledger/" + a["principal"].encode() + ctx.wk.kid).digest(): a["id"]
            for a in ctx.db.q("SELECT id, principal FROM accounts")}


# ---------------------------------------------------------------- feed

def _batch_after(ctx, after):
    db = ctx.db
    if after:
        if not isinstance(after, str) or not BID.match(after):
            raise Err(400, "BAD_REQUEST", "after: a batch id")
        a = db.one("SELECT t, rowid AS r FROM anchor_batches WHERE id=?", (after,))
        if a is None:
            raise Err(404, "NODE2_UNKNOWN_BATCH", "no batch %s" % after)
        return db.one("SELECT rowid AS r, * FROM anchor_batches WHERE t>? OR (t=? AND rowid>?) ORDER BY t, rowid LIMIT 1", (a["t"], a["t"], a["r"]))
    last = db.one("SELECT b.t, b.rowid AS r FROM node2_sigs s JOIN anchor_batches b ON b.id=s.bid ORDER BY b.t DESC, b.rowid DESC LIMIT 1")
    if last is not None:
        return db.one("SELECT rowid AS r, * FROM anchor_batches WHERE t>? OR (t=? AND rowid>?) ORDER BY t, rowid LIMIT 1", (last["t"], last["t"], last["r"]))
    return db.one("SELECT rowid AS r, * FROM anchor_batches ORDER BY t DESC, rowid DESC LIMIT 1")     # first contact: TOFU from now on


def _proof(ctx, account_id, size, have):
    """PROOF(have, size) (or PROOF(size, have) for an older checkpoint) over the tenant's journal as it is NOW. [] when it cannot be built:
    node 2 then raises NOT_PROVEN_APPEND_ONLY, which is the right answer when node 1 cannot prove its own history."""
    cosign, _ = _mods()
    if not have or have <= 0 or have == size:
        return []
    hub = ctx.hub
    try:
        with hub.lock(account_id):
            L = hub.ledger(account_id)
            L.sync_now()
            hs = list(L.hashes[:max(size, have)])
    except (KeyError, ValueError):
        sk = hub.skeleton(account_id) if ctx.db.one("SELECT 1 FROM accounts WHERE id=? AND erased_at IS NOT NULL", (account_id,)) else None
        if sk is None:
            return []
        hs = list(sk["hashes"])                      # 0.2.34: an erased journal still proves consistency from its hashes
    if have < size <= len(hs):
        return cosign.consistency_proof(hs[:size], have)
    if size < have <= len(hs):
        return cosign.consistency_proof(hs[:have], size)
    return []


def feed(ctx, after, sizes):
    from svidetel_v4 import cose
    b = _batch_after(ctx, after)
    if b is None:
        return None
    leaves = json.loads(b["leaves_json"])
    out = []
    for lv in leaves:
        if lv.get("kind") != "checkpoint":
            continue
        r = ctx.db.one("SELECT cose, account_id FROM checkpoints WHERE digest=? LIMIT 1", (bytes.fromhex(lv["leaf"]),))
        if r is None:
            continue                                  # node 2 answers CP_MISSING: a leaf node 1 cannot show is node 1's problem
        cp = bytes(r["cose"])
        try:
            p = cose.loads(cose.verify1(cp, [ctx.wk], cose.TYP_CHECKPOINT)[0])
            lid, size = bytes(p["ledger"]), int(p["seq"]) + 1
        except Exception:  # noqa: BLE001  (a checkpoint row that is not ours: shown as is, node 2 rejects it)
            out.append({"cose_b64": b64(cp), "proof_b64": []})
            continue
        have = sizes.get(lid.hex())
        out.append({"cose_b64": b64(cp), "proof_b64": [b64(x) for x in _proof(ctx, r["account_id"], size, have)]})
    return {"bid": b["id"], "t": b["t"], "root_b64": b64(b["root"]), "leaves_b64": [b64(bytes.fromhex(x["leaf"])) for x in leaves],
            "checkpoints": out, "extra": sum(1 for x in leaves if x.get("kind") in ("registry", "registry2"))}


# ---------------------------------------------------------------- hello / submit

def hello(ctx, body):
    cosign, attest = _mods()
    try:
        doc = attest.doc_from_json(body.get("attestation"))
    except (attest.AttestError, AttributeError):
        raise Err(400, "NODE2_ATTEST", "attestation document malformed")
    if doc["platform"] != "aci-sevsnp":
        raise Err(422, "NODE2_ATTEST", "platform %s is not supported (only aci-sevsnp)" % doc["platform"][:40])
    if doc["node1_pub"] != ctx.wk.pub:
        raise Err(409, "NODE2_NODE1_KEY", "the attestation names another node 1 key")
    if abs(doc["t"] - int(time.time())) > HELLO_SKEW_S:
        raise Err(422, "NODE2_STALE", "attestation time is more than %d s off" % HELLO_SKEW_S)
    try:
        f = attest.fields(doc["report"])
        attest.check_aci(doc, {"policy_sha256": hashlib.sha256(doc["policy"]).digest(), "measurement": f["measurement"]})
    except attest.AttestError as e:
        raise Err(422, "NODE2_ATTEST", str(e))
    chk = attest.check_full(doc)                     # pinned AMD roots: shown on the site as is ("problems"), never hidden
    amd = "ok" if chk["ok"] else "; ".join(chk["problems"])[:400]
    pub = doc["pub"]
    ctx.db.x("INSERT OR IGNORE INTO node2_keys(pub, kid, t, platform, doc_json, added_at, amd) VALUES(?,?,?,?,?,?,?)",
             (pub, cosign.thumbprint(pub), doc["t"], doc["platform"], json.dumps(attest.doc_to_json(doc), sort_keys=True), int(time.time()), amd))
    log("INFO", "node2 key registered", kid=cosign.thumbprint(pub).hex()[:16], amd=amd[:80])
    last = ctx.db.one("SELECT * FROM node2_sigs WHERE kind='cosig' ORDER BY n DESC LIMIT 1")
    resume = None
    if last is not None:
        st = ctx.db.one("SELECT snapshot FROM node2_state WHERE id=1")
        old = ctx.db.one("SELECT doc_json FROM node2_keys WHERE pub=?", (bytes(last["pub"]),))
        resume = {"snapshot_b64": b64(st["snapshot"]) if st else None, "last_cosig_b64": b64(last["cose"]), "old_pub_hex": bytes(last["pub"]).hex(),
                  "old_attestation": json.loads(old["doc_json"]) if old else None}
    return {"node1_pub_hex": ctx.wk.pub.hex(), "resume": resume}


def _key(ctx, cs):
    cosign, _ = _mods()
    try:
        t = cbor2.loads(cs)
        kid = cbor2.loads(t.value[0]).get(cosign.H_KID)
    except Exception:  # noqa: BLE001
        raise Err(422, "NODE2_COSE", "not a COSE_Sign1")
    r = ctx.db.one("SELECT pub FROM node2_keys WHERE kid=?", (bytes(kid) if isinstance(kid, (bytes, bytearray)) else b"",))
    if r is None:
        raise Err(409, "NODE2_KEY_UNKNOWN", "the signing key was never registered with an attestation (hello)")
    return bytes(r["pub"])


def submit(ctx, body):
    cosign, _ = _mods()
    kind, bid = body.get("kind"), body.get("bid")
    if kind not in ("cosig", "alarm") or not isinstance(bid, str) or not BID.match(bid):
        raise Err(400, "BAD_REQUEST", "kind cosig|alarm and a batch id")
    cs = unb64(body.get("cose_b64"))
    pub = _key(ctx, cs)
    h = hashlib.sha256(cs).digest()
    db = ctx.db
    if db.one("SELECT 1 AS k FROM node2_sigs WHERE hash=?", (h,)):
        return {"ok": True, "duplicate": True}
    b = db.one("SELECT root FROM anchor_batches WHERE id=?", (bid,))
    if b is None:
        raise Err(404, "NODE2_UNKNOWN_BATCH", "no batch %s" % bid)
    if kind == "alarm":
        try:
            why = cosign.verify_alarm(cs, pub, ctx.wk.pub)
            m = cosign.cose_verify(cs, pub, cosign.TYP_ALARM)
        except cosign.Reject as e:
            log("WARN", "node2 alarm refused: not valid evidence", code=str(e), bid=bid)
            raise Err(422, "NODE2_ALARM_INVALID", str(e))
        if m.get("bid") != bid:
            raise Err(422, "NODE2_ALARM_INVALID", "alarm names another batch")
        db.x("INSERT INTO node2_sigs(kind, bid, n, pub, cose, hash, alarm, ledger, alarms, t) VALUES('alarm',?,?,?,?,?,?,?,?,?)",
             (bid, None, pub, cs, h, why, bytes(m["ledger"]), None, int(time.time())))
        log("ERROR", "node2 ALARM: node 2 refused to co-sign a journal head", alarm=why, bid=bid, ledger=bytes(m["ledger"]).hex()[:16])
        return {"ok": True, "alarm": why}
    try:
        m = cosign.verify_cosig(cs, pub)
    except cosign.Reject as e:
        raise Err(422, "NODE2_COSE", str(e))
    if m.get("bid") != bid or bytes(m.get("root", b"")) != bytes(b["root"]):
        raise Err(422, "NODE2_BATCH", "the cosig names another batch or root")
    snap_b = unb64(body.get("snapshot_b64"), "NODE2_SNAPSHOT")
    with db.tx():
        last = db.one("SELECT * FROM node2_sigs WHERE kind='cosig' ORDER BY n DESC LIMIT 1")
        if last is None:
            good = m["n"] == 1 and bytes(m["prev"]) == b"\x00" * 32
        else:
            good = m["n"] == last["n"] + 1 and bytes(m["prev"]) == bytes(last["hash"]) and m.get("alarms", 0) >= (last["alarms"] or 0)
            if good and pub != bytes(last["pub"]):
                good = m.get("link") == {"n": last["n"], "prev_key": bytes(last["pub"]), "prev_head": bytes(last["hash"])}
        if not good:
            log("ERROR", "node2 cosig refused: it does not continue the stored chain", n=m.get("n"), last=last["n"] if last else 0)
            raise Err(409, "NODE2_CHAIN", "the cosig does not continue the stored chain (n %s after %s)" % (m.get("n"), last["n"] if last else 0))
        try:
            snap = cbor2.loads(snap_b)
            c = cosign.Cosigner(ctx.wk.pub, None, snap)
            ok = c.n == m["n"] and c.head == h and c.state_digest() == bytes(m["state"])
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            raise Err(422, "NODE2_SNAPSHOT", "the snapshot does not match the cosig")
        if db.one("SELECT 1 AS k FROM node2_sigs WHERE kind='cosig' AND bid=?", (bid,)):
            raise Err(409, "NODE2_DUPLICATE", "batch %s already has a cosig" % bid)
        db.x("INSERT INTO node2_sigs(kind, bid, n, pub, cose, hash, alarm, ledger, alarms, t) VALUES('cosig',?,?,?,?,?,?,?,?,?)",
             (bid, m["n"], pub, cs, h, None, None, m.get("alarms", 0), int(time.time())))
        db.x("INSERT INTO node2_state(id, snapshot, last_hash, t) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET snapshot=excluded.snapshot, "
             "last_hash=excluded.last_hash, t=excluded.t", (snap_b, h, int(time.time())))
    return {"ok": True, "n": m["n"]}


# ---------------------------------------------------------------- public views

def _sig_view(r):
    cosign, _ = _mods()
    v = {"bid": r["bid"], "pub_hex": bytes(r["pub"]).hex(), "hash_hex": bytes(r["hash"]).hex(), "cose_b64": b64(r["cose"]), "t": r["t"]}
    if r["kind"] == "cosig":
        m = cosign.cose_verify(bytes(r["cose"]), bytes(r["pub"]), cosign.TYP_COSIG)
        v.update({"n": m["n"], "batch_t": m["t"], "cps": m["cps"], "ledgers": m["ledgers"], "alarms": m.get("alarms", 0),
                  "root_hex": bytes(m["root"]).hex(), "linked": "link" in m})
    else:
        v.update({"alarm": r["alarm"], "ledger_hex": bytes(r["ledger"]).hex()})
    return v


def keys(ctx):
    _, attest = _mods()
    out = []
    for r in ctx.db.q("SELECT * FROM node2_keys ORDER BY added_at, rowid"):
        doc = json.loads(r["doc_json"])
        chk = attest.check_full(attest.doc_from_json(doc))
        out.append({"pub_hex": bytes(r["pub"]).hex(), "kid_hex": bytes(r["kid"]).hex(), "t": r["t"], "added_at": r["added_at"],
                    "platform": r["platform"], "attestation": doc, "facts": chk["facts"], "problems": chk["problems"], "trust": chk["trust"],
                    "policy_text": base64.b64decode(doc["policy_b64"]).decode("utf-8", "replace")})
    return out


def latest(ctx):
    r = ctx.db.one("SELECT * FROM node2_sigs WHERE kind='cosig' ORDER BY n DESC LIMIT 1")
    return _sig_view(r) if r else None


def status(ctx):
    first = ctx.db.one("SELECT hash FROM node2_sigs WHERE kind='cosig' AND n=1")
    n_al = ctx.db.one("SELECT COUNT(*) AS k FROM node2_sigs WHERE kind='alarm'")["k"]
    return {"enabled": True, "node1_pub_hex": ctx.wk.pub.hex(), "node1_kid_hex": ctx.wk.kid.hex(), "genesis_hex": bytes(first["hash"]).hex() if first else None,
            "latest": latest(ctx), "alarms_published": n_al, "keys": len(ctx.db.q("SELECT pub FROM node2_keys"))}


def make_router(ctx):
    from fastapi import APIRouter, Request

    r = APIRouter()

    def auth(req):
        ip = req.client.host if req.client else "-"
        if not ctx.limiter.allowed("node2auth:" + ip, 20, 60):
            raise Err(429, "RATE_LIMIT", "too many failed node 2 logins")
        a = req.headers.get("authorization") or ""
        tok = a[7:].strip() if a.startswith("Bearer ") else ""
        if not tok or not hmac.compare_digest(hashlib.sha256(tok.encode()).digest(), ctx.cfg.node2_token_sha256):
            ctx.limiter.hit("node2auth:" + ip, 20, 60)
            raise Err(401, "NODE2_AUTH", "node 2 token required")

    async def body_of(req):
        try:
            j = await req.json()
        except ValueError:
            raise Err(400, "BAD_REQUEST", "JSON body required")
        if not isinstance(j, dict):
            raise Err(400, "BAD_REQUEST", "JSON object required")
        check_json(j)
        return j

    @r.post("/internal/node2/hello")
    async def _hello(req: Request):
        auth(req)
        j = await body_of(req)
        import anyio.to_thread
        return await anyio.to_thread.run_sync(hello, ctx, j)

    @r.post("/internal/node2/feed")
    async def _feed(req: Request):
        auth(req)
        j = await body_of(req)
        sizes = j.get("sizes") or {}
        if not isinstance(sizes, dict) or len(sizes) > MAX_SIZES or not all(
                isinstance(k, str) and len(k) == 64 and isinstance(v, int) and not isinstance(v, bool) and v >= 0 for k, v in sizes.items()):
            raise Err(400, "BAD_REQUEST", "sizes: {ledger hex: size}")
        import anyio.to_thread
        return {"batch": await anyio.to_thread.run_sync(feed, ctx, j.get("after"), {k.lower(): v for k, v in sizes.items()})}

    @r.post("/internal/node2/submit")
    async def _submit(req: Request):
        auth(req)
        j = await body_of(req)
        import anyio.to_thread
        return await anyio.to_thread.run_sync(submit, ctx, j)

    @r.get("/v1/node2")
    def _status():
        return status(ctx)

    @r.get("/v1/node2/keys")
    def _keys():
        return keys(ctx)

    @r.get("/v1/node2/latest")
    def _latest():
        v = latest(ctx)
        if v is None:
            raise Err(404, "NOT_FOUND", "no co-signature yet")
        return v

    @r.get("/v1/node2/cosig/{bid}")
    def _cosig(bid: str):
        if not BID.match(bid):
            raise Err(404, "NOT_FOUND")
        x = ctx.db.one("SELECT * FROM node2_sigs WHERE kind='cosig' AND bid=?", (bid,))
        if x is None:
            raise Err(404, "NOT_FOUND", "batch %s has no co-signature of node 2" % bid)
        return _sig_view(x)

    @r.get("/v1/node2/chain")
    def _chain(req: Request):
        try:
            f = max(1, int(req.query_params.get("from", "1")))
            n = min(CHAIN_PAGE, max(1, int(req.query_params.get("limit", str(CHAIN_PAGE)))))
        except ValueError:
            raise Err(400, "BAD_REQUEST", "from, limit: integers")
        rows = ctx.db.q("SELECT n, pub, cose FROM node2_sigs WHERE kind='cosig' AND n>=? ORDER BY n LIMIT ?", (f, n))
        return [{"n": x["n"], "pub_hex": bytes(x["pub"]).hex(), "cose_b64": b64(x["cose"])} for x in rows]

    @r.get("/v1/node2/alarms")
    def _alarms():
        return [_sig_view(x) for x in ctx.db.q("SELECT * FROM node2_sigs WHERE kind='alarm' ORDER BY id")]
    return r


# ---------------------------------------------------------------- evidence pack (export.py)

def pack_files(ctx, bids):
    """node2/ of a tenant's pack: the cosig of each of its batches (+ that batch's leaves: covered() needs them, they are SHA-256 of
    checkpoints), the whole cosig chain from n=1 (verify_chain), the attestation of every K2 in it, and ALL alarms (each cosig counts them:
    a pack that shows fewer than the count hides one). {} when node 2 never co-signed anything."""
    db = ctx.db
    chain = db.q("SELECT n, pub, cose, hash FROM node2_sigs WHERE kind='cosig' ORDER BY n")
    if not chain:
        return {}
    files = {}
    for bid in bids:
        x = db.one("SELECT cose FROM node2_sigs WHERE kind='cosig' AND bid=?", (bid,))
        b = db.one("SELECT leaves_json FROM anchor_batches WHERE id=?", (bid,))
        if x is None or b is None:
            continue
        files["node2/%s.cosig.cose" % bid] = bytes(x["cose"])
        files["node2/%s.leaves.json" % bid] = json.dumps([lv["leaf"] for lv in json.loads(b["leaves_json"])], indent=0).encode()
    pubs = []
    for x in chain:
        if bytes(x["pub"]) not in pubs:
            pubs.append(bytes(x["pub"]))
    files["node2/chain.json"] = json.dumps({"genesis_hex": bytes(chain[0]["hash"]).hex() if chain[0]["n"] == 1 else None,
                                            "chain": [{"n": x["n"], "pub_hex": bytes(x["pub"]).hex(), "cose_hex": bytes(x["cose"]).hex()} for x in chain]},
                                           indent=0).encode()
    ks = []
    for p in pubs:
        k = db.one("SELECT doc_json FROM node2_keys WHERE pub=?", (p,))
        ks.append({"pub_hex": p.hex(), "attestation": json.loads(k["doc_json"]) if k else None})
    files["node2/keys.json"] = json.dumps(ks, indent=1, sort_keys=True).encode()
    files["node2/alarms.json"] = json.dumps([{"bid": a["bid"], "alarm": a["alarm"], "ledger_hex": bytes(a["ledger"]).hex(), "pub_hex": bytes(a["pub"]).hex(),
                                              "cose_hex": bytes(a["cose"]).hex()} for a in db.q("SELECT * FROM node2_sigs WHERE kind='alarm' ORDER BY id")],
                                            indent=1).encode()
    files["node2/README.txt"] = PACK_README.encode()
    return files


def verify_files():
    import os
    d = os.path.join(_paths.NODE2_DIR, "node2")
    out = {"verify/node2/__init__.py": b""}
    for m in ("cosign", "attest", "amd"):
        with open(os.path.join(d, m + ".py"), "rb") as f:
            out["verify/node2/%s.py" % m] = f.read()
    return out


PACK_README = """Deus Witness - node 2 part of the evidence pack (0.2.27)
==========================================================
Node 2 is a second, independent co-signer of the journal HEADS. It runs in an AMD SEV-SNP confidential container (Azure Container
Instances); its key K2 is born in the container's memory and is bound to an AMD-signed attestation report. Node 1 (the witness that
made this pack) shows node 2 every anchor batch with the checkpoints under it and, per journal, a proof that the new journal tree
EXTENDS the last one node 2 co-signed (RFC 9162 consistency). Node 2 co-signs only if that holds; otherwise it signs an ALARM.

Files: <batch>.cosig.cose (co-signature of the batch), <batch>.leaves.json (leaves of the batch tree), chain.json (all co-signatures
from n = 1), keys.json (attestation of every K2), alarms.json (all alarms node 2 raised; each co-signature counts them).

verify_pack.py prints one line:
  node2: COVERED through seq S   your newest anchored checkpoint is among those node 2 inspected, the chain of co-signatures is
                                 unbroken from the genesis, and every K2 in it is bound to an AMD-signed report of a non-debug guest
  node2: NOT COVERED (reason)    no co-signature, a broken or foreign chain, or a key whose attestation fails: the absence IS the signal
  node2: ALARM (reason)          node 2 signed an alarm about your journal, the chain differs from the one you pinned before, or this
                                 pack hides alarms that node 2 counted -> RESULT: INVALID
The checker keeps a pin (node2-pin.json next to the pack folder, or --node2-pin=FILE): the genesis and the newest co-signature seen.
Keep it: without it a node 2 restarted from an OLD state by the operator is not detected (plan, risk R1).

What it does NOT prove: anything before node 2 first saw your journal (trust on first use); that Microsoft and AMD are honest (they
sign the platform); that the container policy is the published one unless you pass --node2-expect=FILE (policy_sha256, measurement)
or compare the policy text in keys.json yourself. While the policy lets the operator exec into the container (the allow-all probe
policy) node 2 is NOT independent, and the checker says NOT COVERED.
"""
