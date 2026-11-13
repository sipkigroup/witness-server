"""0.2.21: the owner LEARNS that a passkey may have been copied, and can stop it.

A signature counter that did not grow (org.sign_count_refused, WebAuthn L3 6.1.1) means a copy of the passkey (clone) or an old signature
sent again. 0.2.20 refused it and wrote a log line; now the person who holds that passkey also gets:
- a security push {v: 2, k: "c"} to their own devices (Pusher.notify_security; the text is FIXED in sw.js, the payload has no id, no kid,
  no number, nothing from the client): at most ONE per key per NOTIFY_GAP_S (10 minutes), decided by one conditional UPDATE in the
  database (several workers / a restart do not reset it);
- a mark on Devices (GET /api/auth/keys -> keys[].clone_alert) with the time, the place (a route from ROUTES, never client text), the
  stored and the presented counter, and how many times it happened.

No automatic freeze: a clone that can freeze the key locks the owner out (DoS). The way out is the owner's: remove the passkey with another
one (the existing signed key event, keys.remove_*), or, with a single passkey, a recovery code (add a new one, then remove this one).

The mark goes away only by the owner: removing the key, or "this was me" (dismiss) with a fresh step-up made with ANOTHER active passkey
(with a single passkey: that one). Not after N good signatures: a growing counter is exactly what the clone produces, so it could clear
the warning before the owner sees it. A new regression raises the mark again (and pushes, outside the 10-minute window).

Storage is bounded: one key_alerts row per (person, passkey); 1000 regressions update that row (n, last_at)."""
import hashlib
import time

from app.context import Err
from app.log import log

NOTIFY_GAP_S = 600
N_MAX = 1_000_000_000
ROUTES = {"login", "approve", "refuse", "mandate", "revoke", "release", "allowance", "key_event", "revoke_batch", "batch",
          "sigreq:policy", "sigreq:mandate", "sigreq:approval", "sigreq:release", "sigreq:key_replace", "sigreq:phone_lift"}
clock = time.time                     # tests move it


def now():
    return int(clock())


def sig_hash(ad, cd, sig):
    """Identity of one assertion: SHA-256(authData || SHA-256(clientDataJSON) || signature). The signature is part of it: ECDSA is randomised,
    so a second authenticator (clone) that signs the same payload at the same counter still differs; only a re-sent identical one matches."""
    return hashlib.sha256(bytes(ad) + hashlib.sha256(bytes(cd)).digest() + bytes(sig)).digest()


def _route(where):
    w = str(where or "")
    return w if w in ROUTES else ("sigreq:other" if w.startswith("sigreq:") else "other")


def raise_alert(ctx, kid, stored, got, where):
    """A regression of passkey `kid` -> the alert row of every person who holds it (active) is raised / updated; a push to that person
    when none was sent for this key in the last NOTIFY_GAP_S. -> list of user ids pushed. Never raises (the refusal is what matters)."""
    kid = bytes(kid)
    t = now()
    route = _route(where)
    stored, got = max(0, min(int(stored or 0), 0xFFFFFFFF)), max(0, min(int(got or 0), 0xFFFFFFFF))
    pushed = []
    users = [r["user_id"] for r in ctx.db.q("SELECT DISTINCT user_id FROM credentials WHERE kid=? AND revoked_at IS NULL AND user_id IS NOT NULL", (kid,))]
    for uid in users:
        with ctx.db.tx() as db:
            db.x("INSERT INTO key_alerts(user_id,kid,first_at,last_at,n,route,stored,got,notified_at,dismissed_at,dismissed_by) "
                 "VALUES(?,?,?,?,1,?,?,?,NULL,NULL,NULL) ON CONFLICT(user_id,kid) DO UPDATE SET "
                 "first_at=CASE WHEN key_alerts.dismissed_at IS NULL THEN key_alerts.first_at ELSE excluded.first_at END, "
                 "n=CASE WHEN key_alerts.dismissed_at IS NULL THEN MIN(key_alerts.n+1, %d) ELSE 1 END, "
                 "last_at=excluded.last_at, route=excluded.route, stored=excluded.stored, got=excluded.got, dismissed_at=NULL, dismissed_by=NULL"
                 % N_MAX, (uid, kid, t, t, route, stored, got))
            due = db.n("UPDATE key_alerts SET notified_at=? WHERE user_id=? AND kid=? AND (notified_at IS NULL OR notified_at<=?)",
                       (t, uid, kid, t - NOTIFY_GAP_S)) == 1
        if due:
            p = getattr(ctx, "push", None)
            if p is not None:
                p.notify_security(uid, "c")
            pushed.append(uid)
            log("WARN", "possible passkey clone: owner notified", account=uid, kid=kid.hex()[:16], route=route, stored=stored, got=got)
    return pushed


def alerts_of(ctx, user_id):
    """{kid bytes: alert dict} of the person's raised (not dismissed) alerts. Only this person's rows: nobody else's key shows."""
    return {bytes(r["kid"]): {"first_at": r["first_at"], "last_at": r["last_at"], "count": r["n"], "route": _route(r["route"]),
                              "stored": r["stored"], "got": r["got"], "notified_at": r["notified_at"]}
            for r in ctx.db.q("SELECT * FROM key_alerts WHERE user_id=? AND dismissed_at IS NULL", (user_id,))}


def dismiss(ctx, user_id, kid, session_cred):
    """"This was me": the owner clears the mark of their own passkey `kid`. The caller checked a fresh step-up; the passkey of that step-up
    (session_cred) must not be the suspected one while another active passkey exists (else the clone itself could clear it).
    -> {"kid_hex", "dismissed_at"}; 404 when there is nothing to clear."""
    r = ctx.db.one("SELECT 1 AS k FROM key_alerts WHERE user_id=? AND kid=? AND dismissed_at IS NULL", (user_id, kid))
    if r is None:
        raise Err(404, "NOT_FOUND", "no possible-clone mark on this passkey")
    others = ctx.db.one("SELECT COUNT(*) AS n FROM credentials WHERE user_id=? AND revoked_at IS NULL AND kid<>?", (user_id, kid))["n"]
    by = bytes(session_cred["kid"]) if session_cred is not None else None
    if by is None or (others and by == kid):
        # 403 STEPUP_REQUIRED: the page asks for a fresh passkey once more; the person chooses another device this time
        raise Err(403, "STEPUP_REQUIRED", "confirm with ANOTHER of your passkeys, not the one that may have been copied")
    t = now()
    if ctx.db.n("UPDATE key_alerts SET dismissed_at=?, dismissed_by=? WHERE user_id=? AND kid=? AND dismissed_at IS NULL",
                (t, by.hex(), user_id, kid)) != 1:
        raise Err(404, "NOT_FOUND", "no possible-clone mark on this passkey")
    log("WARN", "possible passkey clone: dismissed by the owner", account=user_id, kid=kid.hex()[:16], by=by.hex()[:16])
    return {"kid_hex": kid.hex(), "dismissed_at": t}
