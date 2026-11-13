"""r0269: the PUBLIC log of anchor batches, its C2SP checkpoint, and the daily external stamp of that checkpoint.

Why: every account ledger is already checkpointed and its checkpoints go into a 30-minute batch whose Merkle root is stamped
(OpenTimestamps; RFC 3161 when a TSA is on) - jobs.anchor_once. What was missing is ONE append-only list of all batches that anybody
can watch: without it the witness could show two people two different batch histories (split view, RFC 9162 section 11.3), and
the time of a receipt rests on the witness's clock alone.

What this module adds (nothing about receipts or ledgers changes):
- Leaf i of the log = packtools/tlogcheck.batch_leaf(batch id, batch root): text, no account ids. Appended in anchor_batches row order
  (existing batches are back-filled on the first run, in the same order).
- GET /checkpoint: a C2SP tlog-checkpoint (signed note, Ed25519 log signature, key name = origin = "<DW_ISS host>/batches", the
  witness key). The witness never signs two roots for one size (size is the primary key) and re-checks that the new tree extends
  the last signed one before it signs (an internal fork = refusal and an ERROR line, not a signature).
- GET /tlog/vkey, /tlog/leaf, /tlog/proof/inclusion, /tlog/proof/consistency, /tlog/checkpoint/<size>, /tlog/stamps,
  /tlog/stamp/<file>: everything a monitor or a second witness (c2sp.org/tlog-witness add-checkpoint: old size + consistency
  proof + checkpoint) needs. A cosignature of type 0x04 added to a stored note is served as is (store_cosigned()).
- stamp_due(): once a day (DW_TLOG_STAMP_EVERY, default 86400 s) and on request (python -m app.jobs tlog-stamp) the TEXT of the
  latest checkpoint is SHA-256'd and stamped: OpenTimestamps (DW_ANCHOR=on) and every allowed TSA of lib/tsa/providers.json
  (DW_TLOG_TSA=on, the default; FreeTSA: free, commercial use allowed, 1 request/s per IP - lib/tsa/USLOVIYA.md) plus DW_TSA_URL.
  A service that is down never blocks anything: the row stays "queued"/"partial" and is retried with back-off; receipts are issued
  as before and say "queued" until a stamped checkpoint covers their batch (receipt_anchor()).
"""
import json
import os
import sys
import threading
import time
import urllib.parse

from app import _paths
from app.log import log

_PT = os.path.join(_paths.SERVER, "packtools")
if _PT not in sys.path:
    sys.path.append(_PT)
import tlogcheck as TC  # noqa: E402

STAMP_EVERY = 86400
RETRY_FIRST = 1800
RETRY_MAX = 6 * 3600
_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS tlog_leaves(idx INTEGER PRIMARY KEY, batch_id TEXT UNIQUE NOT NULL, leaf BLOB NOT NULL, t INTEGER);
CREATE TABLE IF NOT EXISTS tlog_checkpoints(size INTEGER PRIMARY KEY, root BLOB NOT NULL, note TEXT NOT NULL, t INTEGER);
CREATE TABLE IF NOT EXISTS tlog_stamps(size INTEGER PRIMARY KEY, digest BLOB NOT NULL, t INTEGER, status TEXT, ots TEXT, tsa TEXT,
  tries INTEGER DEFAULT 0, next_try INTEGER, last_err TEXT, done_t INTEGER);
"""


def ensure_schema(db):
    for stmt in SCHEMA.strip().split(";"):
        if stmt.strip():
            db.x(stmt)


def origin(cfg):
    o = os.environ.get("DW_TLOG_ORIGIN")
    if o:
        return o
    host = urllib.parse.urlsplit(getattr(cfg, "iss", "") or "").hostname or "witness.invalid"
    return host + "/batches"


def vkey(ctx):
    return TC.vkey(origin(ctx.cfg), ctx.wk.pub)


def _state(ctx):
    st = getattr(ctx, "_tlog", None)
    if st is None:
        ensure_schema(ctx.db)
        rows = ctx.db.q("SELECT idx, leaf FROM tlog_leaves ORDER BY idx")
        if any(r["idx"] != i for i, r in enumerate(rows)):
            raise RuntimeError("tlog_leaves has a gap")
        st = {"tree": TC.Tree(TC.leaf_hash(bytes(r["leaf"])) for r in rows)}
        ctx._tlog = st
    return st


def _catch_up(ctx, tree):
    """r0271 (ISPYTANIE-0266 Н2): append to the in-memory tree the leaves ANOTHER process wrote (python -m app.jobs anchor-once /
    tlog-stamp, deploy/restore-drill.sh on the same database). Before, the tree was read once per process: after a leaf written
    elsewhere /checkpoint served a stale size, an inclusion proof for the new size was refused, and after the other process SIGNED the
    bigger size the server refused to sign anything (503 TLOG_INCONSISTENT) until restarted. The rows must follow the tree without a gap."""
    rows = ctx.db.q("SELECT idx, leaf FROM tlog_leaves WHERE idx>=? ORDER BY idx", (len(tree),))
    for r in rows:
        if r["idx"] != len(tree):
            raise RuntimeError("tlog_leaves has a gap")
        tree.append(TC.leaf_hash(bytes(r["leaf"])))


def sync(ctx):
    """Append every anchor batch the log does not have yet, in anchor_batches row order. -> tree size.
    Several processes may share the database: the leaves another one appended are read first (_catch_up), and the new ones are numbered
    inside one write transaction (BEGIN IMMEDIATE: no other writer between the read of the size and the insert)."""
    _NEW = ("SELECT b.id, b.root, b.t FROM anchor_batches b LEFT JOIN tlog_leaves l ON l.batch_id=b.id "
            "WHERE l.batch_id IS NULL ORDER BY b.rowid")
    with _LOCK:
        st = _state(ctx)
        tree = st["tree"]
        _catch_up(ctx, tree)
        if ctx.db.q(_NEW):
            added = []
            with ctx.db.tx():
                _catch_up(ctx, tree)                 # committed by another process before this one took the write lock
                for i, b in enumerate(ctx.db.q(_NEW)):
                    leaf = TC.batch_leaf(b["id"], bytes(b["root"]))
                    ctx.db.x("INSERT INTO tlog_leaves(idx,batch_id,leaf,t) VALUES(?,?,?,?)", (len(tree) + i, b["id"], leaf, b["t"]))
                    added.append(leaf)
            for leaf in added:
                tree.append(TC.leaf_hash(leaf))
        return len(tree)


def checkpoint(ctx, now=None):
    """-> the latest signed note (str). Signs a new one when the log grew; refuses (RuntimeError) to sign a tree that does not
    extend the last signed checkpoint."""
    size = sync(ctx)
    with _LOCK:
        tree = _state(ctx)["tree"]
        last = ctx.db.one("SELECT size, root, note FROM tlog_checkpoints ORDER BY size DESC LIMIT 1")
        if last is not None and last["size"] == size:
            return last["note"]
        if last is not None and (last["size"] > size or tree.root(0, last["size"]) != bytes(last["root"])):
            log("ERROR", "tlog: the stored log does not extend checkpoint %d: NOT signing" % last["size"])
            raise RuntimeError("TLOG_INCONSISTENT")
        root = tree.root(0, size)
        o = origin(ctx.cfg)
        text = TC.checkpoint_text(o, size, root)
        note = TC.make_note(text, [TC.sign_line(o, TC.ALG_ED25519, ctx.wk.pub, ctx.wk.sign(text.encode()))])
        t = int(time.time()) if now is None else now
        ctx.db.x("INSERT OR IGNORE INTO tlog_checkpoints(size,root,note,t) VALUES(?,?,?,?)", (size, root, note, t))
        return ctx.db.one("SELECT note FROM tlog_checkpoints WHERE size=?", (size,))["note"]


def stored_checkpoint(ctx, size):
    _state(ctx)
    r = ctx.db.one("SELECT note FROM tlog_checkpoints WHERE size=?", (int(size),))
    return r["note"] if r else None


def store_cosigned(ctx, note, cosigner_vkeys):
    """Keep a note that a second witness returned (our signature + its type-0x04 cosignature) in place of ours for that size.
    The note must verify under OUR key, carry the same text as our stored note, and at least one listed cosigner must verify."""
    text, _ = TC.parse_note(note)
    TC.verify_note(note, [vkey(ctx)])
    v = TC.verify_note(note, list(cosigner_vkeys))
    cp = TC.parse_checkpoint(text)
    mine = stored_checkpoint(ctx, cp["size"])
    if mine is None or TC.parse_note(mine)[0] != text or not v["cosig_times"]:
        raise ValueError("not a cosigned copy of a stored checkpoint")
    ctx.db.x("UPDATE tlog_checkpoints SET note=? WHERE size=?", (note, cp["size"]))


def inclusion(ctx, index, size):
    sync(ctx)
    tree = _state(ctx)["tree"]
    return [TC.b64e(h) for h in tree.inclusion(index, size)]


def consistency(ctx, old, new):
    sync(ctx)
    tree = _state(ctx)["tree"]
    return [TC.b64e(h) for h in tree.consistency(old, new)]


def leaf_of(ctx, batch_id=None, index=None):
    _state(ctx)
    if batch_id is not None:
        r = ctx.db.one("SELECT idx, batch_id, leaf, t FROM tlog_leaves WHERE batch_id=?", (batch_id,))
    else:
        r = ctx.db.one("SELECT idx, batch_id, leaf, t FROM tlog_leaves WHERE idx=?", (int(index),))
    return None if r is None else {"index": r["idx"], "batch": r["batch_id"], "leaf_b64": TC.b64e(bytes(r["leaf"])), "t": r["t"]}


# ------------------------------------------------------------------ the daily external stamp
def _note_text(note):
    return TC.parse_note(note)[0]


def _wanted(ctx):
    """-> (ots wanted, [TSA providers]) for the stamp of the log checkpoint."""
    from app import jobs
    use_file = (os.environ.get("DW_TLOG_TSA") or "on").lower() == "on"
    try:
        tsas = jobs.tsa_selected(ctx, use_file)
    except Exception as e:  # noqa: BLE001  (providers file unreadable: the stamp goes on with Bitcoin only)
        log("WARN", "tlog stamp: TSA providers unreadable (%s)" % type(e).__name__)
        tsas = []
    return ctx.cfg.anchor == "on", tsas


def stamp_due(ctx, now=None, force=False, attempt=True):
    """Queue a stamp of the latest checkpoint when the last one is older than DW_TLOG_STAMP_EVERY (or force), then try every
    queued/partial stamp whose time has come. -> list of (size, status). Never raises for a network failure."""
    t = int(time.time()) if now is None else now
    every = int(os.environ.get("DW_TLOG_STAMP_EVERY", STAMP_EVERY))
    note = checkpoint(ctx, now=t)
    size = TC.parse_checkpoint(_note_text(note))["size"]
    last = ctx.db.one("SELECT size, t FROM tlog_stamps ORDER BY size DESC LIMIT 1")
    if size > 0 and (last is None or (size > last["size"] and (force or t - last["t"] >= every))):
        ctx.db.x("INSERT OR IGNORE INTO tlog_stamps(size,digest,t,status,tries,next_try) VALUES(?,?,?,?,?,?)",
                 (size, TC.stamp_digest(_note_text(note)), t, "queued", 0, t))
    out = []
    if not attempt:
        return out
    for r in ctx.db.q("SELECT * FROM tlog_stamps WHERE status IN ('queued','partial') AND next_try<=? ORDER BY size", (t,)):
        out.append((r["size"], _try(ctx, r, t)))
    return out


def _try(ctx, r, t):
    from app import jobs
    ots_on, tsas = _wanted(ctx)
    size, digest = r["size"], bytes(r["digest"])
    name = "tlog-%d" % size
    errs = []
    ots = r["ots"]
    if ots_on and ots is None:
        out = os.path.join(ctx.anchor_dir, name + ".ots")
        try:
            jobs._anchor_mod().stamp(digest.hex(), out)
            ots = "pending"
        except BaseException as e:  # noqa: BLE001  (SystemExit: < 2 calendars; ImportError: no opentimestamps)
            if isinstance(e, KeyboardInterrupt):
                raise
            errs.append("ots: " + (str(e) or type(e).__name__)[:120])
    have = set(json.loads(r["tsa"] or "[]"))
    todo = [p for p in tsas if p["name"] not in have]
    if todo:
        ok, failed = jobs.tsa_stamp(ctx, name, digest, providers=todo)
        have |= set(ok)
        errs += ["tsa %s failed" % n for n in failed]
    need_tsa = {p["name"] for p in tsas}
    if not ots_on and not need_tsa:
        status = "off"                                       # nothing external configured: said so, not retried
    elif (not ots_on or ots) and need_tsa <= have:
        status = "stamped"
    elif ots or have:
        status = "partial"
    else:
        status = "queued"
    tries = (r["tries"] or 0) + (0 if status in ("stamped", "off") else 1)
    nxt = t + min(RETRY_FIRST * (2 ** max(tries - 1, 0)), RETRY_MAX)
    ctx.db.x("UPDATE tlog_stamps SET status=?, ots=?, tsa=?, tries=?, next_try=?, last_err=?, done_t=? WHERE size=?",
             (status, ots, json.dumps(sorted(have)), tries, nxt, "; ".join(errs)[:500] or None,
              t if status in ("stamped", "partial") and r["done_t"] is None else r["done_t"], size))
    if status == "stamped":
        ctx.db.x("UPDATE tlog_stamps SET status='superseded' WHERE size<? AND status IN ('queued','partial')", (size,))
    print("tlog stamp %d: %s%s" % (size, status, (" (" + "; ".join(errs) + ")") if errs else ""))
    return status


def upgrade_stamps(ctx):
    """Bitcoin attestations for the pending .ots of log stamps (same calendars as the batches). -> number upgraded."""
    from app import jobs
    n = 0
    for r in ctx.db.q("SELECT size FROM tlog_stamps WHERE ots='pending'"):
        p = os.path.join(ctx.anchor_dir, "tlog-%d.ots" % r["size"])
        if not os.path.exists(p):
            continue
        try:
            jobs._anchor_mod().upgrade(p)
            atts = jobs._btc_attestations(p)
        except Exception as e:  # noqa: BLE001
            log("WARN", "tlog upgrade failed: " + type(e).__name__)
            continue
        if atts:
            ctx.db.x("UPDATE tlog_stamps SET ots=? WHERE size=?", ("bitcoin:%d" % atts[0][0], r["size"]))
            n += 1
    return n


def stamps(ctx, limit=50):
    _state(ctx)
    out = []
    for r in ctx.db.q("SELECT * FROM tlog_stamps ORDER BY size DESC LIMIT ?", (int(limit),)):
        files = sorted(f for f in os.listdir(ctx.anchor_dir) if f.startswith("tlog-%d." % r["size"])) if os.path.isdir(ctx.anchor_dir) else []
        out.append({"size": r["size"], "digest": bytes(r["digest"]).hex(), "queued_t": r["t"], "status": r["status"], "ots": r["ots"],
                    "tsa": json.loads(r["tsa"] or "[]"), "stamped_t": r["done_t"], "files": files})
    return out


def receipt_anchor(ctx, account_id, cp_seq):
    """Time status of a receipt whose inclusion proof sits under the account checkpoint `cp_seq` (None = no proof yet).
    -> {"status": "queued"} until a stamped log checkpoint covers its batch, then {"status": "stamped", "batch", "log_index",
    "stamp": {"size", "tsa", "ots"}}. Unsigned information next to the receipt: the proof is the files, not this member."""
    out = {"status": "queued"}
    if cp_seq is None:
        return out
    try:
        _state(ctx)
        c = ctx.db.one("SELECT batch_id FROM checkpoints WHERE account_id=? AND seq>=? AND batch_id IS NOT NULL ORDER BY id LIMIT 1",
                       (account_id, cp_seq))
        if c is None:
            return out
        out["batch"] = c["batch_id"]
        lf = ctx.db.one("SELECT idx FROM tlog_leaves WHERE batch_id=?", (c["batch_id"],))
        if lf is None:
            return out
        out["log_index"] = lf["idx"]
        s = ctx.db.one("SELECT size, tsa, ots FROM tlog_stamps WHERE size>? AND status IN ('stamped','partial') ORDER BY size LIMIT 1",
                       (lf["idx"],))
        if s is not None:
            out["status"] = "stamped"
            out["stamp"] = {"size": s["size"], "tsa": json.loads(s["tsa"] or "[]"), "ots": s["ots"]}
    except Exception as e:  # noqa: BLE001  (never fail an answer for an information member)
        log("WARN", "receipt_anchor: " + type(e).__name__)
    return out


# ------------------------------------------------------------------ pack files
def pack_files(ctx, batch_ids):
    """Files for an evidence pack: tlog/checkpoint.note (latest), tlog/vkey, tlog/inclusion/<batch>.json for each batch of the
    account, and the stamps of the smallest stamped checkpoint covering each batch (tlog/stamps/<size>.note + .ots / .tsr.<tsa>)."""
    files = {}
    try:
        note = checkpoint(ctx)
    except Exception as e:  # noqa: BLE001
        log("WARN", "tlog pack: " + type(e).__name__)
        return files
    size = TC.parse_checkpoint(_note_text(note))["size"]
    files["tlog/checkpoint.note"] = note.encode()
    files["tlog/vkey"] = (vkey(ctx) + "\n").encode()
    stamp_sizes = set()
    for bid in batch_ids:
        lf = leaf_of(ctx, batch_id=bid)
        if lf is None or lf["index"] >= size:
            continue
        doc = dict(lf, size=size, path=inclusion(ctx, lf["index"], size))
        s = ctx.db.one("SELECT size FROM tlog_stamps WHERE size>? AND status IN ('stamped','partial') ORDER BY size LIMIT 1", (lf["index"],))
        if s is not None:
            doc["stamp"] = {"size": s["size"], "path": inclusion(ctx, lf["index"], s["size"]),
                            "consistency": consistency(ctx, s["size"], size)}
            stamp_sizes.add(s["size"])
        files["tlog/inclusion/%s.json" % bid] = json.dumps(doc, indent=1).encode()
    for sz in sorted(stamp_sizes):
        n = stored_checkpoint(ctx, sz)
        if n is None:
            continue
        files["tlog/stamps/%d.note" % sz] = n.encode()
        for f in sorted(os.listdir(ctx.anchor_dir)):
            if f.startswith("tlog-%d." % sz) and (f.endswith(".ots") or ".tsr." in f):
                with open(os.path.join(ctx.anchor_dir, f), "rb") as fh:
                    files["tlog/stamps/%d.%s" % (sz, f.split(".", 1)[1])] = fh.read()
                if ".tsr." in f:
                    ca = os.path.join(ctx.anchor_dir, "tsa-ca", f.partition(".tsr.")[2] + ".pem")
                    if os.path.isfile(ca):
                        with open(ca, "rb") as fh:
                            files["tlog/stamps/tsa-ca/%s.pem" % f.partition(".tsr.")[2]] = fh.read()
    return files


# ------------------------------------------------------------------ HTTP
def make_router(ctx):
    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse, Response
    from app.context import Err

    r = APIRouter()
    text = "text/plain; charset=utf-8"
    nocache = {"Cache-Control": "no-store"}

    def _int(v, name):
        try:
            n = int(v)
        except (TypeError, ValueError):
            raise Err(400, "BAD_REQUEST", name + " must be an integer")
        if n < 0:
            raise Err(400, "BAD_REQUEST", name + " must be >= 0")
        return n

    @r.get("/checkpoint")
    def get_checkpoint():
        try:
            return Response(checkpoint(ctx), media_type=text, headers=nocache)
        except RuntimeError:
            raise Err(503, "TLOG_INCONSISTENT")

    @r.get("/tlog/vkey")
    def get_vkey():
        return Response(vkey(ctx) + "\n", media_type=text)

    @r.get("/tlog/checkpoint/{size}")
    def get_old(size: str):
        n = stored_checkpoint(ctx, _int(size, "size"))
        if n is None:
            raise Err(404, "NOT_FOUND")
        return Response(n, media_type=text)

    @r.get("/tlog/leaf")
    def get_leaf(index: str = None, batch: str = None):
        lf = leaf_of(ctx, batch_id=batch) if batch else leaf_of(ctx, index=_int(index, "index"))
        if lf is None:
            raise Err(404, "NOT_FOUND")
        return lf

    @r.get("/tlog/proof/inclusion")
    def get_incl(index: str, size: str):
        i, n = _int(index, "index"), _int(size, "size")
        if not i < n <= sync(ctx):
            raise Err(400, "BAD_REQUEST", "need index < size <= tree size")
        return {"index": i, "size": n, "path": inclusion(ctx, i, n)}

    @r.get("/tlog/proof/consistency")
    def get_cons(old: str, new: str):
        a, b = _int(old, "old"), _int(new, "new")
        if not a <= b <= sync(ctx):
            raise Err(400, "BAD_REQUEST", "need old <= new <= tree size")
        return {"old": a, "new": b, "path": consistency(ctx, a, b)}

    @r.get("/tlog/stamps")
    def get_stamps():
        return JSONResponse({"origin": origin(ctx.cfg), "stamps": stamps(ctx)}, headers=nocache)

    @r.get("/tlog/stamp/{name}")
    def get_stamp_file(name: str, req: Request):
        import re
        if not re.fullmatch(r"tlog-[0-9]{1,12}\.(ots|tsr\.[a-z0-9][a-z0-9-]{0,31})", name):
            raise Err(404, "NOT_FOUND")
        p = os.path.join(ctx.anchor_dir, name)
        if not os.path.isfile(p):
            raise Err(404, "NOT_FOUND")
        with open(p, "rb") as f:
            return Response(f.read(), media_type="application/octet-stream")

    return r
