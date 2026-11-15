"""r0269 (migration plan step 7, P1 of the profile): the reason vocabulary under the human's signature.

The words of a question ("what the agent does", "why it is dangerous") are built by the witness from a CLOSED vocabulary
(app/qwords.py), never written by the agent. This module freezes that vocabulary as one JSON document "mr-vocab-1" and gives its
digest = SHA-256 over RFC 8785 (JCS). The digest goes into the tool map DOCUMENT of the mandate (actions.gateway_doc, member
"vocab"), whose SHA-256 is `toolmap_sha256` INSIDE the passkey-signed mandate: so the signature pins which vocabulary the person
agreed to, without a new member in the mandate itself (the core schema rejects unknown members; old mandates keep their old
document and still verify). Every vocabulary a mandate pinned is kept (table vocabs) and goes into the evidence pack as
vocab/<digest>.json, so a checker can rebuild the words offline.
r0277 (mr-vocab-2): member "screen" holds the sentences that were written inline before (send a request, git settings, quiet mode,
"run {n} commands", "You said No ... {when}"); packtools/screencheck.py rebuilds what / harm / risk of each signed view from the
vocabulary the mandate pinned. A mandate that pinned mr-vocab-1 is checked as before (its words are reported as not rebuildable).
r0294 (mr-vocab-3): + screen "net_code_run" / "net_code_now" (law "origin of code"). A mandate that pinned mr-vocab-2 keeps its words: the
question shows that vocabulary's own sentence (actions._pinned_has) and the checker rebuilds both versions.
r0298 (mr-vocab-4): + screen "autostart_what" / "autostart_harm" (a relative write, in a folder the witness cannot tell, to a file that starts
commands by itself: asked once, never "from now on"). A mandate that pinned mr-vocab-2 or -3 keeps "Your agent wants to run a command Witness
cannot fully check" (actions._mark_autostart, exec_json "as".pin false); the checker rebuilds 2, 3 and 4.
r0305 (mr-vocab-5): + screen "defense_what" / "defense_harm" (a program that switches off a protection of the operating system: refused
Н10 everywhere, asked only as a strict doubt). A mandate that pinned mr-vocab-2..4 keeps the generic "a dangerous command" sentence
(actions._mark_defense, exec_json "df".pin false); the checker rebuilds 2, 3, 4 and 5.

Honest limit: pinning says WHICH dictionary was in force; it does not stop the witness from choosing the reason code (profile, risk 2).
"""
import hashlib
import json

V = "mr-vocab-5"     # r0277: + "screen" (every first-screen sentence is a template here: the checker rebuilds what / harm offline)
#                     r0294: + screen net_code_run / net_code_now (a run of code from the network); mr-vocab-2 receipts check as before
#                     r0298: + screen autostart_what / autostart_harm (a file that starts commands by itself, folder unknown); 2 and 3 as before
#                     r0305: + screen defense_what / defense_harm (an OS protection switched off); 2, 3 and 4 as before


def doc():
    from app import qwords as q
    d = {"v": V, "unknown_what": q.UNKNOWN_WHAT, "unknown_harm": q.UNKNOWN_HARM, "reason_words": q.REASON_WORDS,
         "net_harm": q.NET_HARM, "risk_by_code": q.RISK_BY_CODE, "risk_label": q.RISK_LABEL, "long_harm": q.LONG_HARM,
         "path_harm": [[p.pattern, short, full] for p, short, full in q._PATH_HARM],
         "strict_words": q.STRICT_WORDS, "data_tag_words": q.DATA_TAG_WORDS, "danger_words": q.DANGER_WORDS,
         "push_what": q.PUSH_WHAT, "push_tail": q.PUSH_TAIL, "screen": q.SCREEN}
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
