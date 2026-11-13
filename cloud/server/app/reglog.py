"""0.2.12 (R7-04): the registry log keeps a second hash chain that says WHOSE each row is, without saying what it is.

The first chain (hash = sha256(prev || entry_json), since 0.1) proves the order and the content of the rows, but an evidence pack reduces
the rows of other accounts to seq/prev/hash: the checker could not tell an own row cut down to seq/prev/hash (a hidden key removal) from a
foreign one. Every row now also carries
    tag   = HMAC-SHA256(pepper, "dw-registry-tag\\0" + account)[:16]   (account = the row's account without "keys:" / "org:")
    hash2 = sha256("dw-registry-v2\\0" || prev2 || tag || sha256(entry_json))
A pack shows tag and hash2 of every row and sha256(entry_json) of the foreign ones: the checker recomputes the second chain, learns the
account's tag from its own rows and refuses a row with that tag but without its text. Both heads are anchored (jobs.anchor_once), so a
rebuilt second chain shows against the anchors. Rows written before 0.2.12 get tag and hash2 once, at start (backfill): the second chain
covers the whole log, and it is as good as the operator was honest at the upgrade.
"""
import hashlib
import hmac

PREFIXES = ("keys:", "org:")


def owner_of(account_id):
    a = account_id or ""
    for p in PREFIXES:
        if a.startswith(p):
            return a[len(p):]
    return a


def tag_key(pepper: str) -> bytes:
    return hmac.new(pepper.encode(), b"dw-registry-tag-key", hashlib.sha256).digest()


def tag(key: bytes, account_id) -> bytes:
    return hmac.new(key, b"dw-registry-tag\0" + owner_of(account_id).encode(), hashlib.sha256).digest()[:16]


def hash2(prev2: bytes, tg: bytes, body: bytes) -> bytes:
    """body = sha256(entry_json)"""
    return hashlib.sha256(b"dw-registry-v2\0" + prev2 + tg + body).digest()


def append(db, account_id, kid, ej, t):
    """Append one row to both chains (caller holds a transaction). -> seq"""
    last = db.one("SELECT seq, hash, hash2 FROM registry_log ORDER BY seq DESC LIMIT 1")
    seq = (last["seq"] + 1) if last else 1
    prev = bytes(last["hash"]) if last else b""
    prev2 = bytes(last["hash2"]) if last and last["hash2"] is not None else b""
    tg = tag(db.reg_tag_key, account_id)
    db.x("INSERT INTO registry_log(seq,account_id,kid,entry_json,prev,hash,t,tag,hash2) VALUES(?,?,?,?,?,?,?,?,?)",
         (seq, account_id, kid, ej, prev, hashlib.sha256(prev + ej.encode()).digest(), t, tg,
          hash2(prev2, tg, hashlib.sha256(ej.encode()).digest())))
    return seq


def backfill(db):
    """Rows of a database older than 0.2.12 (no hash2): fill tag and hash2 in seq order. A no-op when every row has them."""
    with db.tx():
        if not db.one("SELECT 1 FROM registry_log WHERE hash2 IS NULL LIMIT 1"):
            return 0
        prev2, n = b"", 0
        for r in db.q("SELECT seq, account_id, entry_json, tag, hash2 FROM registry_log ORDER BY seq"):
            if r["hash2"] is not None:
                prev2 = bytes(r["hash2"])
                continue
            tg = tag(db.reg_tag_key, r["account_id"])
            prev2 = hash2(prev2, tg, hashlib.sha256((r["entry_json"] or "").encode()).digest())
            db.x("UPDATE registry_log SET tag=?, hash2=? WHERE seq=?", (tg, prev2, r["seq"]))
            n += 1
        return n


def heads(db):
    """-> (head, head2) of the log, or (None, None) when it is empty."""
    r = db.one("SELECT hash, hash2 FROM registry_log ORDER BY seq DESC LIMIT 1")
    return (bytes(r["hash"]), bytes(r["hash2"]) if r["hash2"] is not None else None) if r else (None, None)
