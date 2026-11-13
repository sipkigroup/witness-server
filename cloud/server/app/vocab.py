"""r0269 (migration plan step 7, P1 of the profile): the reason vocabulary under the human's signature.

The words of a question ("what the agent does", "why it is dangerous") are built by the witness from a CLOSED vocabulary
(app/qwords.py), never written by the agent. This module freezes that vocabulary as one JSON document "mr-vocab-1" and gives its
digest = SHA-256 over RFC 8785 (JCS). The digest goes into the tool map DOCUMENT of the mandate (actions.gateway_doc, member
"vocab"), whose SHA-256 is `toolmap_sha256` INSIDE the passkey-signed mandate: so the signature pins which vocabulary the person
agreed to, without a new member in the mandate itself (the core schema rejects unknown members; old mandates keep their old
document and still verify). Every vocabulary a mandate pinned is kept (table vocabs) and goes into the evidence pack as
vocab/<digest>.json, so a checker can rebuild the words offline (plan step 8, not done here).

Honest limit: pinning says WHICH dictionary was in force; it does not stop the witness from choosing the reason code (profile, risk 2).
"""
import hashlib
import json

V = "mr-vocab-1"


def doc():
    from app import qwords as q
    d = {"v": V, "unknown_what": q.UNKNOWN_WHAT, "unknown_harm": q.UNKNOWN_HARM, "reason_words": q.REASON_WORDS,
         "net_harm": q.NET_HARM, "risk_by_code": q.RISK_BY_CODE, "risk_label": q.RISK_LABEL, "long_harm": q.LONG_HARM,
         "path_harm": [[p.pattern, short, full] for p, short, full in q._PATH_HARM],
         "strict_words": q.STRICT_WORDS, "data_tag_words": q.DATA_TAG_WORDS, "danger_words": q.DANGER_WORDS,
         "push_what": q.PUSH_WHAT, "push_tail": q.PUSH_TAIL}
    return json.loads(json.dumps(d, ensure_ascii=False))


def canonical(d=None):
    from app.signview import jcs
    return jcs(doc() if d is None else d)


def digest(d=None):
    return hashlib.sha256(canonical(d)).hexdigest()


def remember(db, t=0):
    """Store the current vocabulary by digest (idempotent). -> digest."""
    d = doc()
    h = digest(d)
    db.x("CREATE TABLE IF NOT EXISTS vocabs(digest TEXT PRIMARY KEY, json TEXT NOT NULL, t INTEGER)")
    db.x("INSERT OR IGNORE INTO vocabs(digest, json, t) VALUES(?,?,?)", (h, canonical(d).decode("utf-8", "surrogatepass"), int(t)))
    return h


def pack_files(db, digests):
    out = {}
    if db.one("SELECT 1 AS k FROM sqlite_master WHERE type='table' AND name='vocabs'") is None:
        return out
    for h in sorted(set(digests)):
        r = db.one("SELECT json FROM vocabs WHERE digest=?", (h,))
        if r is not None:
            out["vocab/%s.json" % h] = r["json"].encode("utf-8", "surrogatepass")
    return out
