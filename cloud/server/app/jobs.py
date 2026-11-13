"""Hourly anchor job (ARHITEKTURA 6; 0.2 section 7: RFC 3161 as a second anchor). CLI: python -m app.jobs anchor-once | upgrade-once | tlog-stamp
DW_TSA=on: after the OTS stamp the same batch root is time-stamped by every TSA of lib/tsa/providers.json with "take": true and
"terms": "allowed" (never Sectigo / Apple / GlobalSign / Entrust: EXCLUDED)
(DW_TSA_PROVIDERS = another providers file); replies go to /data/anchors/<batch>.tsr.<tsa>, the TSA root to /data/anchors/tsa-ca/<tsa>.pem.
0.2.9: DW_TSA_URL (+ DW_TSA_CA, the TSA's root, required; DW_TSA_NAME optional) turns the second anchor on for ONE TSA the operator names,
without DW_TSA and without providers.json; checked at start-up (config.py: a bad URL or a missing root = the process does not start).
Off by default (neither variable set = no TSA request at all). EXCLUDED services are refused here too.
A TSA failure never fails the batch (Bitcoin anchor untouched)."""
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.parse
import urllib.request

from app import _paths
from svidetel_v4.checkpoint import inclusion_path, merkle_root, verify_inclusion  # noqa: F401
from app.log import log

UPGRADE_AFTER = 2 * 3600
TSA_DIR = os.environ.get("DW_TSA_DIR") or os.path.join(_paths.CLOUD, "lib", "tsa")
TSA_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
EXPLORERS = (("mempool.space", "https://mempool.space/api"), ("blockstream.info", "https://blockstream.info/api"))


def _anchor_mod():
    from anchor import anchor
    return anchor


def registry_head(db):
    r = db.one("SELECT hash FROM registry_log ORDER BY seq DESC LIMIT 1")
    return bytes(r["hash"]) if r else None


def _tsa_mod():
    if TSA_DIR not in sys.path:
        sys.path.insert(0, TSA_DIR)
    import tsa
    return tsa


# Services whose terms forbid our use (stamps only for their own code-signing certificates, or the public service is gone):
# never queried, whatever a providers file says (research 18.10.2026, USLOVIYA.md). Matched on the name and on the URL host.
EXCLUDED = {"sectigo": "terms: only together with a Sectigo code-signing certificate",
            "apple": "terms: reserved for code signing",
            "globalsign": "terms: free only with a GlobalSign code-signing certificate",
            "entrust": "public TSA business moved to Sectigo (18.09.2025)"}


def _excluded(p):
    host = (urllib.parse.urlsplit(str(p.get("url", ""))).hostname or "").lower()
    return next((n for n in EXCLUDED if n in str(p.get("name", "")).lower() or n in host), None)


def tsa_providers(path=None):
    """Providers we may query -> [{name, url, ca (absolute)}]: "take": true AND "terms": "allowed" (USLOVIYA.md), not EXCLUDED,
    and the root on disk (without it no reply could be verified, so asking would only spend the service's rate)."""
    path = path or os.environ.get("DW_TSA_PROVIDERS") or os.path.join(TSA_DIR, "providers.json")
    with open(path) as f:
        doc = json.load(f)
    base = os.path.dirname(os.path.abspath(path))
    out = []
    for p in doc.get("providers", []):
        if p.get("take") is not True or not TSA_NAME.match(p.get("name", "")):
            continue
        bad = _excluded(p)
        if bad:
            log("WARN", "tsa %s skipped: %s" % (p["name"], EXCLUDED[bad]))
            continue
        if p.get("terms") != "allowed":
            log("WARN", "tsa %s skipped: terms %s (only \"allowed\" is queried)" % (p["name"], p.get("terms", "not stated")))
            continue
        ca = os.path.join(base, p["ca"])
        if not os.path.isfile(ca):
            log("WARN", "tsa %s skipped: root %s missing" % (p["name"], p["ca"]))
            continue
        out.append({"name": p["name"], "url": p["url"], "ca": ca})
    return out


def tsa_env_provider(url, ca, name=""):
    """0.2.9: the provider named by DW_TSA_URL / DW_TSA_CA / DW_TSA_NAME -> {name, url, ca (absolute)}. Raises ValueError (config.py
    turns it into a start-up error): http(s) URL with a host and no user:password, not an EXCLUDED service, the root readable as a
    certificate, a name of [a-z0-9-] (default: the URL host). Setting the URL is the operator's statement that the TSA's terms allow it."""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("an http:// or https:// URL with a host is needed")
    if u.username or u.password:
        raise ValueError("no user:password in the URL (a secret does not belong in an environment variable that is logged)")
    name = name or re.sub(r"[^a-z0-9-]+", "-", u.hostname.lower()).strip("-")[:32].rstrip("-")
    if not TSA_NAME.match(name):
        raise ValueError("DW_TSA_NAME must be 1-32 of a-z 0-9 - (starting with a letter or digit)")
    bad = _excluded({"name": name, "url": url})
    if bad:
        raise ValueError("%s is excluded: %s" % (bad, EXCLUDED[bad]))
    if not ca:
        raise ValueError("DW_TSA_CA (the TSA's root certificate) is required: without it no reply can be verified")
    ca = os.path.abspath(ca)
    try:
        certs = _tsa_mod()._load_bundle(ca) if os.path.isfile(ca) else None
    except Exception as e:  # noqa: BLE001  (not a certificate, asn1crypto missing)
        raise ValueError("DW_TSA_CA %s unreadable as a certificate (%s)" % (ca, type(e).__name__))
    if not certs:
        raise ValueError("DW_TSA_CA %s is not a file with a certificate" % ca)
    return {"name": name, "url": url, "ca": ca}


def tsa_selected(ctx, use_file):
    """Providers of this run: providers.json (DW_TSA=on / tsa=True) and the DW_TSA_URL one (a name already taken by the file is not asked twice)."""
    out = tsa_providers() if use_file else []
    cfg = getattr(ctx, "cfg", None)
    if cfg is not None and getattr(cfg, "tsa_url", ""):
        if any(p["name"] == cfg.tsa_name for p in out):
            log("WARN", "tsa %s: DW_TSA_URL skipped, providers.json has that name" % cfg.tsa_name)
        else:
            out.append({"name": cfg.tsa_name, "url": cfg.tsa_url, "ca": cfg.tsa_ca})
    return out


def tsa_stamp(ctx, bid, root, providers=None, use_file=True):
    """Second anchor: ask each provider for an RFC 3161 token over the batch root; keep only tokens that verify against the
    provider's root. -> (names ok, names failed). Never raises."""
    ok, failed = [], []
    try:
        providers = tsa_selected(ctx, use_file) if providers is None else providers
    except Exception as e:  # noqa: BLE001
        log("ERROR", "tsa: providers file unreadable (%s)" % type(e).__name__)
        return ok, ["providers.json"]
    try:
        T = _tsa_mod()
    except Exception as e:  # noqa: BLE001  (lib/tsa or asn1crypto missing in the image)
        log("ERROR", "tsa: module unavailable (%s)" % type(e).__name__)
        return ok, [p["name"] for p in providers]
    for p in providers:
        try:
            tsr = T.request(root, p["url"])
            r = T.verify(tsr, root, p["ca"])
            if not r["ok"]:
                raise ValueError(r["reason"])
            with open(os.path.join(ctx.anchor_dir, "%s.tsr.%s" % (bid, p["name"])), "wb") as f:
                f.write(tsr)
            cadir = os.path.join(ctx.anchor_dir, "tsa-ca")
            os.makedirs(cadir, exist_ok=True)
            shutil.copyfile(p["ca"], os.path.join(cadir, p["name"] + ".pem"))
            ok.append(p["name"])
        except Exception as e:  # noqa: BLE001  (network, TSA error, bad reply: logged, the batch stays)
            failed.append(p["name"])
            log("WARN", "tsa %s failed for batch %s: %s" % (p["name"], bid, (str(e) or type(e).__name__)[:120]))
    return ok, failed


PROMISE_FRESH_S = 2700      # 0.2.5 (R4-01): promises are given only while the last anchor run is at most 45 min old (runs are 30 min apart, MMD is 60 min)


def promise_allowed(ctx):
    """R4-01: an inclusion promise (MMD 3600) is a signed commitment, so give it only when it can be kept: anchoring is ON (DW_ANCHOR=on), the last anchor
    run did not fail (stamp, OpenTimestamps calendars) and is recent (the loop is alive). Otherwise no promise is issued: the decision and the receipt stand without one."""
    st = getattr(ctx, "anchor_state", None)
    return ctx.cfg.anchor == "on" and bool(st) and st["ok"] and time.time() - st["t"] <= PROMISE_FRESH_S


def anchor_once(ctx, now=None, tsa=None):
    """Same as _anchor_once, and records for promise_allowed() whether this run went through (a failed stamp, an exception: no new promises until a good run)."""
    ctx.anchor_state = dict(getattr(ctx, "anchor_state", None) or {"t": 0, "ok": False})
    try:
        bid = _anchor_once(ctx, now, tsa)
    except BaseException:
        ctx.anchor_state = {"t": time.time(), "ok": False}
        raise
    st = ctx.db.one("SELECT status FROM anchor_batches WHERE id=?", (bid,))["status"] if bid else None
    ctx.anchor_state = {"t": time.time(), "ok": st != "failed"}
    return bid


def _anchor_once(ctx, now=None, tsa=None):
    """Checkpoint every tenant with new entries; Merkle root over sha256(checkpoint) leaves + registry head; stamp (DW_ANCHOR=on) or just record (off).
    tsa: True/False, None = env DW_TSA (on|off). -> batch id or None."""
    db, hub = ctx.db, ctx.hub
    t = int(time.time()) if now is None else now
    leaves, rows = [], []
    for a in db.q("SELECT id FROM accounts ORDER BY created_at, id"):
        aid = a["id"]
        if not hub.has_entries(aid):
            continue
        with hub.lock(aid):
            from app.actions import materialize_proofs
            materialize_proofs(ctx, aid)                              # R-16: pending inclusion proofs share one checkpoint
            L = hub.ledger(aid)
            last = db.one("SELECT * FROM checkpoints WHERE account_id=? ORDER BY id DESC LIMIT 1", (aid,))
            L.sync_now()
            if last is not None and L.S.nseq <= last["ledger_nseq"]:
                if last["batch_id"] is not None:
                    continue
                cp, cid = bytes(last["cose"]), last["id"]            # a stamp failed earlier: anchor the same checkpoint again
            else:
                seq, cp = _cp(L)
                cid = db.x("INSERT INTO checkpoints(account_id,seq,cose,digest,t,batch_id,ledger_nseq) VALUES(?,?,?,?,?,?,?)",
                           (aid, seq, cp, hashlib.sha256(cp).digest(), t, None, L.S.nseq))
            rows.append(cid)
            leaves.append({"account": aid, "kind": "checkpoint", "leaf": hashlib.sha256(cp).hexdigest()})
    for r in db.q("SELECT c.id, c.account_id, c.cose FROM checkpoints c WHERE c.batch_id IS NULL AND c.id IN "
                  "(SELECT MAX(c2.id) FROM checkpoints c2 JOIN accounts a ON a.id=c2.account_id WHERE a.erased_at IS NOT NULL AND c2.batch_id IS NULL GROUP BY c2.account_id)"):
        rows.append(r["id"])                                      # 0.2.34: the checkpoint written when the account was erased still goes into a batch
        leaves.append({"account": r["account_id"], "kind": "checkpoint", "leaf": hashlib.sha256(bytes(r["cose"])).hexdigest()})
    head = registry_head(db)
    prev = db.one("SELECT registry_head FROM anchor_batches ORDER BY t DESC, rowid DESC LIMIT 1")
    head_changed = head is not None and (prev is None or prev["registry_head"] is None or bytes(prev["registry_head"]) != head)
    if not leaves and not head_changed:
        log("INFO", "anchor: nothing new")
        return None
    if head is not None:
        leaves.append({"account": None, "kind": "registry", "leaf": head.hex()})
        h2 = db.one("SELECT hash2 FROM registry_log ORDER BY seq DESC LIMIT 1")["hash2"]
        if h2 is not None:                                    # 0.2.12 (R7-04): the ownership chain is anchored with the registry chain
            leaves.append({"account": None, "kind": "registry2", "leaf": bytes(h2).hex()})
    root = merkle_root([bytes.fromhex(x["leaf"]) for x in leaves])
    bid = "%s-%s" % (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(t)), root.hex()[:8])
    status, calendars = "off", 0
    if ctx.cfg.anchor == "on":
        out = os.path.join(ctx.anchor_dir, bid + ".ots")
        try:
            ok = _anchor_mod().stamp(root.hex(), out)
            status, calendars = "pending", len(ok)
        except SystemExit as e:
            status = "failed"
            log("ERROR", "anchor stamp failed: " + str(e)[:200])
    with db.tx():
        db.x("INSERT INTO anchor_batches(id,t,root,leaves_json,registry_head,status,block_height,checked_json) VALUES(?,?,?,?,?,?,?,?)",
             (bid, t, root, json.dumps(leaves), head, status, None, None))
        if status != "failed":
            for cid in rows:
                db.x("UPDATE checkpoints SET batch_id=? WHERE id=?", (bid, cid))
    rec = {"id": bid, "t": t, "root": root.hex(), "leaves": leaves, "registry_head": head.hex() if head else None, "status": status}
    if getattr(ctx, "tee", None) is not None:                    # DW_TEE=on: a TDX quote bound to this batch root (anchors/<bid>.tdx.json),
        from app import tee                                      # named in the anchor record by its hash (added member; off = the old record)
        rec["tee"] = tee.on_batch(ctx, bid, root)
    with open(os.path.join(ctx.anchor_dir, bid + ".json"), "w") as f:
        json.dump(rec, f)
    try:
        from app import tlog
        tlog.sync(ctx)                                           # r0269: the batch becomes the next leaf of the public log
    except Exception as e:  # noqa: BLE001  (the log is re-synced on the next run and on GET /checkpoint)
        log("ERROR", "tlog sync failed: " + type(e).__name__)
    if status == "pending":
        print("batch %s: stamped calendars=%d" % (bid, calendars))
    elif status == "off":
        print("batch %s: recorded (DW_ANCHOR=off, not stamped) leaves=%d" % (bid, len(leaves)))
    else:
        print("batch %s: FAILED (retry next hour)" % bid)
    use_file = (os.environ.get("DW_TSA") or "off").lower() == "on" if tsa is None else bool(tsa)
    use_url = bool(getattr(ctx.cfg, "tsa_url", "")) and tsa is not False          # 0.2.9: DW_TSA_URL alone turns the second anchor on
    if use_file or use_url:
        ok, failed = tsa_stamp(ctx, bid, root, use_file=use_file)
        why = (" failed=" + ",".join(failed)) if failed else ("" if ok else " (no TSA with take=true and no DW_TSA_URL: see lib/tsa/USLOVIYA.md)")
        print("batch %s: tsa=%d ok%s" % (bid, len(ok), why))
    return bid


def _cp(L):
    """Signed checkpoint of the ledger and the seq it covers (read back from the payload)."""
    from svidetel_v4 import cose
    cp = L.checkpoint_signed()
    seq = cose.loads(cose.verify1(cp, [L.wk], cose.TYP_CHECKPOINT)[0])["seq"]
    return seq, cp


def _btc_attestations(ots_path):
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    an = _anchor_mod()
    d = an._load(ots_path)
    return [(att.height, sub.msg) for sub, att in an._walk(d.timestamp) if isinstance(att, BitcoinBlockHeaderAttestation)]


def _get_json(url, text=False):
    with urllib.request.urlopen(url, timeout=30) as r:
        data = r.read().decode()
    return data if text else json.loads(data)


def check_block(height, msg):
    """Compare the attested merkle root with the block header at `height` on BOTH explorers -> {name: 'OK'|'MISMATCH'|'UNREACHABLE'}."""
    res = {}
    for name, base in EXPLORERS:
        try:
            bh = _get_json("%s/block-height/%d" % (base, height), text=True).strip()
            blk = _get_json("%s/block/%s" % (base, bh))
            res[name] = "OK" if bytes.fromhex(blk["merkle_root"])[::-1] == msg else "MISMATCH"
        except Exception:
            res[name] = "UNREACHABLE"
    return res


def upgrade_once(ctx, now=None):
    db = ctx.db
    t = int(time.time()) if now is None else now
    n = 0
    for b in db.q("SELECT * FROM anchor_batches WHERE status='pending' AND t<=?", (t - UPGRADE_AFTER,)):
        p = os.path.join(ctx.anchor_dir, b["id"] + ".ots")
        if not os.path.exists(p):
            continue
        try:
            _anchor_mod().upgrade(p)
            atts = _btc_attestations(p)
        except Exception as e:  # noqa
            log("WARN", "upgrade failed: " + type(e).__name__)
            continue
        if not atts:
            continue
        height, msg = atts[0]
        chk = check_block(height, msg)
        if "MISMATCH" in chk.values():
            db.x("UPDATE anchor_batches SET status='mismatch', block_height=?, checked_json=? WHERE id=?", (height, json.dumps(chk), b["id"]))
            log("ERROR", "anchor MISMATCH batch=%s block=%d %s" % (b["id"], height, json.dumps(chk)))
        elif all(v == "OK" for v in chk.values()):
            db.x("UPDATE anchor_batches SET status='confirmed', block_height=?, checked_json=? WHERE id=?", (height, json.dumps(chk), b["id"]))
        else:
            log("WARN", "explorers unreachable for batch %s: %s" % (b["id"], json.dumps(chk)))
            continue
        n += 1
        print("batch %s: block %d %s" % (b["id"], height, json.dumps(chk)))
    return n


def main(argv):
    from app.config import Config
    from app.context import Ctx
    if len(argv) != 1 or argv[0] not in ("anchor-once", "upgrade-once", "tlog-stamp"):
        print(__doc__)
        return 64
    ctx = Ctx(Config.from_env())
    if argv[0] == "tlog-stamp":                                  # r0269: stamp the log checkpoint NOW (and retry queued stamps)
        from app import tlog
        tlog.stamp_due(ctx, force=True)
        return 0
    (anchor_once if argv[0] == "anchor-once" else upgrade_once)(ctx)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


def prune_previews(ctx, now=None, batch=500):
    """0.2.24 (critique B): the previews of an action are kept only while it waits for a person.
    (1) a decided action that still has full previews (expired lazily, answered by an allowance, a row from before 0.2.24) -> hash + 80 characters;
    (2) older than cfg.preview_keep_days (30) -> only the hash of its arguments. The receipt, the ledger and the evidence export never used the
    previews (they bind `args_sha256`). -> (cut, dropped)."""
    import json as _json
    from app import actions as _act
    from app import toolmap as _tm
    t = int(time.time()) if now is None else now
    keep = 86400 * (getattr(ctx.cfg, "preview_keep_days", None) or 30)
    cut = dropped = 0
    from app import repeat as _rpt              # 0.2.29: an unanswered question that expired keeps its previews LATER_S (approval for the next runs)
    rows = ctx.db.q("SELECT rid FROM actions WHERE preview_cut IS NULL AND status NOT IN ('pending_approval','approved','held') "
                    "AND NOT (status='expired' AND verdict='defer' AND expires>=?) LIMIT ?", (t - _rpt.LATER_S, batch))
    for r in rows:
        _act.cut_previews(ctx, r["rid"])
        cut += 1
    # 0.2.30 (review, small 5): the 24 hours are only for a request that may still be approved for later runs (a team account, a dangerous
    # command, a held item, a frozen agent ... are never offered it): those are cut like any decided action
    for x in ctx.db.q("SELECT * FROM actions WHERE preview_cut IS NULL AND status='expired' AND verdict='defer' AND expires>=? LIMIT ?",
                      (t - _rpt.LATER_S, batch)):
        acc = ctx.db.one("SELECT * FROM accounts WHERE id=?", (x["account_id"],))
        try:
            why = "no account" if acc is None else _rpt.eligible(ctx, acc, x)
        except Exception:  # noqa - unknown -> cut (the safe side for personal data)
            why = "unknown"
        if why:
            _act.cut_previews(ctx, x["rid"])
            cut += 1
    for r in ctx.db.q("SELECT rid, action_json, args_preview FROM actions WHERE preview_cut=1 AND created_at<? AND status NOT IN "
                      "('pending_approval','approved','held') LIMIT ?", (t - keep, batch)):
        h = None
        try:
            h = _json.loads(r["action_json"]).get("args_sha256") if r["action_json"] else None
        except (TypeError, ValueError, AttributeError):
            pass
        if h is None and isinstance(r["args_preview"], str) and r["args_preview"].startswith(_tm.DECIDED_PREFIX):
            h = r["args_preview"][len(_tm.DECIDED_PREFIX):].split(" ", 1)[0]
        ctx.db.x("UPDATE actions SET args_preview=?, text_preview=NULL, line_text=NULL, preview_cut=2 WHERE rid=?", (_tm.DECIDED_PREFIX + (h or "-"), r["rid"]))
        dropped += 1
    # 0.2.83 (MR-24): the shown objects of signed approvals (previews inside) live as long as the previews, then the pack says VIEW_UNVERIFIABLE
    if ctx.db.one("SELECT 1 AS k FROM sqlite_master WHERE type='table' AND name='shown_views'") is not None:
        ctx.db.x("DELETE FROM shown_views WHERE t<?", (t - keep,))
    _act.scrub_old_written_texts(ctx, now=t)   # 04.11 (privacy D2): risky-write texts out of the look-back go without a new command
    lim = getattr(ctx, "limiter", None)
    if lim is not None and hasattr(lim, "sweep"):
        lim.sweep(now=t)                        # 04.11 (privacy D4): IP keys whose window is over leave memory
    return cut, dropped
