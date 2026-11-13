"""0.2.2: recovery after a lost passkey, without weakening the rest (docs/recovery.md).
 - Devices: a user may hold several passkeys (phone, laptop, hardware key). ADDING one is a signature by a passkey that is active NOW
   over the exact new key (wa-sig, typ application/dw-key-event+cbor); REMOVING one is the same kind of signature; the last active
   passkey can never be removed. Each change is a row of the registry log (account_id "keys:<id>"), so the evidence pack shows it.
 - Recovery codes: 10 one-time codes, shown once, only scrypt hashes kept. A code opens a session that can ONLY add a new passkey
   (scope 'recovery'); using it ends every session of the user and sends a push to the user's devices. The key it adds is recorded
   with by = "recovery-code": the registry log shows that only the witness vouches for it (no old passkey signed it).
 - Organisations: replacing a member's lost key is a policy version signed by the OTHER members (rule `recovery`, k >= 2) -- see
   org.key_replace_request; nothing here touches an organisation's policy.
Mandates signed by a removed key stay valid (the signature was good when it was recorded); revoke_batch_view lists them for one
batch revocation (wb of typ revocation) by a current key."""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

import cbor2
from webauthn import verify_registration_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from app import _paths  # noqa: F401
import wa_profile as wa
import wq_profile as wq
from app.context import Err
from app import auth, keyalert, org, reglog, wire
from app import levels
from app.log import log

CODES = 10
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"     # 32 symbols, no I/O/0/1: 5 bits each
CODE_GROUPS = 5                                       # XXXX-XXXX-XXXX-XXXX-XXXX: 1 lookup group (20 bits) + 80 secret bits
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}  # 16 MiB per check; memory-hard (RFC 7914)
RECOVERY_TTL = 15 * 60
LABEL_MAX = 40


def now():
    return int(time.time())


def short(kid):
    return auth.short_kid(kid)


# ---------------------------------------------------------------- registry log rows of key changes
def _append_event(db, account_id, op, kid, by, t, entry=None, payload=None, envelope=None):
    """One registry_log row (hash chain, hourly anchor). account_id "keys:<id>": in the chain, never the account's pinned record."""
    ev = {"principal": "dw:" + account_id, "op": op, "kid": kid.hex(), "t": t, "by": by}
    if entry is not None:
        ev["entry"] = entry
    if payload is not None:
        ev["payload_hex"], ev["envelope_hex"] = payload.hex(), envelope.hex()
    ej = json.dumps({"key_event": ev}, sort_keys=True, separators=(",", ":"))
    return reglog.append(db, "keys:" + account_id, kid, ej, t)      # 0.2.12 (R7-04): also in the ownership chain (a pack cannot hide it)


def _record(pub, cred, ctx):
    return {"alg": "ES256", "pub": pub.hex(), "webauthn": {"rp_id": ctx.cfg.rp_id, "origins": [ctx.cfg.origin],
                                                           "credential_id": bytes_to_base64url(cred)}}


# ---------------------------------------------------------------- devices
def list_keys(ctx, user_id, session_cred=None):
    out = []
    pol_orgs = {}
    for m in ctx.db.q("SELECT m.account_id, m.kid, a.display_name FROM members m JOIN accounts a ON a.id=m.account_id "
                      "WHERE m.user_id=? AND m.status='active' AND m.kid IS NOT NULL", (user_id,)):
        if org.current_policy(ctx, m["account_id"]) is not None:
            pol_orgs.setdefault(bytes(m["kid"]), []).append({"account_id": m["account_id"], "name": m["display_name"]})
    alerts = keyalert.alerts_of(ctx, user_id)       # 0.2.21: possible clone (a counter that went back); only this person's own keys
    for c in ctx.db.q("SELECT * FROM credentials WHERE user_id=? ORDER BY id", (user_id,)):
        kid = bytes(c["kid"])
        out.append({"kid_hex": kid.hex(), "short": short(kid), "label": c["label"] or "passkey", "created_at": c["created_at"],
                    "last_used_at": c["last_used_at"], "added_by": c["added_by"] or "registration",
                    "removed_at": c["revoked_at"], "active": c["revoked_at"] is None, "this_session": c["id"] == session_cred,
                    "credential_id_b64": wa.b64u(bytes(c["credential_id"])),
                    "device": c["device"] or None, "counts_as": levels.device_of(c),     # 0.2.13: phone | laptop (unmarked counts as phone)
                    "phone_not_before": levels.pending_until(c),       # 0.2.15: a recovery-declared phone counts as laptop until then
                    "team_key_in": pol_orgs.get(kid, []),        # organisations whose policy names this key (their quorum replaces it)
                    "clone_alert": alerts.get(kid) if c["revoked_at"] is None else None})
    return out


def _label(x):
    lab = "".join(ch for ch in (x if isinstance(x, str) else "") if ord(ch) >= 32)[:LABEL_MAX].strip()
    return lab or "passkey"


def _reg_options(ctx, user_id, purpose, extra):
    chal = os.urandom(32)
    u = ctx.db.one("SELECT display_name FROM users WHERE id=?", (user_id,))
    name = (u["display_name"] if u else None) or "user"
    uh = bytes.fromhex(user_id) if len(user_id) == 32 else user_id.encode()[:64]
    fid = auth.new_flow(ctx, purpose, dict(extra, challenge=bytes_to_base64url(chal), user_id=user_id))
    return {"flow_id": fid, "options": {
        "rp": {"id": ctx.cfg.rp_id, "name": "Deus Witness"},
        "user": {"id": bytes_to_base64url(uh), "name": name, "displayName": name},
        "challenge": bytes_to_base64url(chal),
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        # every passkey the user already holds is excluded: the same authenticator is never registered twice
        "excludeCredentials": [{"type": "public-key", "id": bytes_to_base64url(bytes(c["credential_id"]))}
                               for c in ctx.db.q("SELECT credential_id FROM credentials WHERE user_id=?", (user_id,))],
        "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"},
        "attestation": "none", "timeout": 300000}}


def _verify_registration(ctx, st, credential):
    """-> (pub 65 bytes, credential id, sign_count). Same rules as the first registration: ES256 only, UV required."""
    import cbor2 as cb
    try:
        v = verify_registration_response(credential=credential, expected_challenge=base64url_to_bytes(st["challenge"]),
                                         expected_rp_id=ctx.cfg.rp_id, expected_origin=ctx.cfg.origin,
                                         require_user_verification=True, supported_pub_key_algs=[-7])
        key = cb.loads(v.credential_public_key)
        if key.get(3) != -7 or key.get(1) != 2 or key.get(-1) != 1:
            raise ValueError("alg")
        pub = b"\x04" + key[-2] + key[-3]
        wa.thumbprint(pub)
    except Exception as e:
        raise Err(400, "WA_REGISTRATION", "registration rejected (%s)" % type(e).__name__)
    if ctx.db.one("SELECT 1 FROM credentials WHERE credential_id=?", (v.credential_id,)):
        raise Err(409, "CREDENTIAL_EXISTS")
    return pub, v.credential_id, v.sign_count


def _device(d):
    if d is None:
        return None
    if d not in levels.DEVICES:
        raise Err(422, "BAD_DEVICE", "device: phone | laptop")
    return d


def add_begin(ctx, user_id, label, device=None):
    return _reg_options(ctx, user_id, "keyadd", {"label": _label(label), "device": _device(device)})


def add_finish(ctx, user_id, flow_id, credential):
    """The new passkey is created but NOT active: -> the key-event payload a CURRENT passkey must sign (add_confirm)."""
    st = auth.take_flow(ctx, flow_id, "keyadd")
    if st.get("user_id") != user_id:
        raise Err(400, "FLOW_UNKNOWN", "flow expired or unknown")
    pub, cred, sc = _verify_registration(ctx, st, credential)
    kid = wa.thumbprint(pub)
    nonce = os.urandom(16)
    payload = wq.key_event_payload("dw:" + user_id, "add", kid, pub, cred, nonce)
    cid = auth.new_flow(ctx, "keyconfirm", {"user_id": user_id, "pub": pub.hex(), "cred": cred.hex(), "sign_count": sc,
                                            "label": st.get("label"), "device": st.get("device"), "payload": payload.hex()})
    return {"confirm_id": cid, "typ": wq.TYP_KEY_EVENT, "payload_b64": wa.b64u(payload), "kid_hex": kid.hex(), "short": short(kid),
            "sign_with": auth.allow_credentials(ctx, user_id),
            "note": "Confirm with a passkey you already use (not the new one): it signs exactly this new key."}


def _check_event_sig(ctx, user_id, payload, env, forbid_kid=None):
    """The envelope is a wa-sig over the key-event payload by an ACTIVE passkey of this user (not forbid_kid). -> signer kid."""
    if wq.envelope_kind(env) != "wa":
        raise Err(409, "WA_MALFORMED", "sign with one passkey (wa-sig)")
    kid = org.env_kid(env)
    if forbid_kid is not None and kid == forbid_kid:
        raise Err(409, "KEY_SELF", "the new passkey cannot vouch for itself: confirm with one you already use")
    entry = org.user_entry(ctx, user_id, kid)
    if entry is None:
        raise Err(409, "KEY_NOT_ACTIVE", "this passkey is not an active key of your account")
    code = wa.verify_envelope(env, wq.TYP_KEY_EVENT, payload, entry)
    if code:
        raise Err(409, "KEY_EVENT_SIG" if code == "MANDATE_SIG" else code)
    org.check_sign_counts(ctx, env, "key_event", user_id)          # 0.2.20
    org.touch_kids(ctx, [kid])                    # 0.2.19
    return kid


def add_confirm(ctx, user_id, confirm_id, env):
    st = auth.take_flow(ctx, confirm_id, "keyconfirm")
    if st.get("user_id") != user_id:
        raise Err(400, "FLOW_UNKNOWN", "flow expired or unknown")
    payload, pub, cred = bytes.fromhex(st["payload"]), bytes.fromhex(st["pub"]), bytes.fromhex(st["cred"])
    kid = wa.thumbprint(pub)
    signer = _check_event_sig(ctx, user_id, payload, env, forbid_kid=kid)
    dev = st.get("device")
    if dev != levels.LAPTOP and levels.device_of_kid(ctx, signer) == levels.LAPTOP and \
            (levels.has_phone_key(ctx, user_id) or levels.phone_ever(ctx, user_id) or levels.recovery_window(ctx, user_id)):
        # 0.2.13: a phone-class key is vouched for by a phone-class key (else a laptop could mint itself a "phone");
        # 0.2.14 (R8-06): also when the phone key is gone now -- the first marking is only for an account that never had one
        raise Err(409, "DEVICE_LEVEL", "a new phone passkey is confirmed with your phone's passkey (or add it as a laptop key; lost "
                                       "phone: use a recovery code and declare the new key your phone there)")
    # 0.2.17 (R9-03): a waiting "new phone" (or a key it vouched for) adds no passkey: else a fresh, non-waiting key does what the wait forbids
    refuse_if_pending(ctx.db.one("SELECT * FROM credentials WHERE kid=? AND user_id=?", (signer, user_id)), "add passkeys", ctx)
    t = now()
    with ctx.hub.lock(user_id):
        with ctx.db.tx() as db:
            if db.one("SELECT 1 FROM credentials WHERE credential_id=?", (cred,)):
                raise Err(409, "CREDENTIAL_EXISTS")
            db.x("INSERT INTO credentials(account_id,user_id,credential_id,pub,kid,sign_count,rp_id,origin,created_at,label,added_by,device,vouched_by) "
                 "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (user_id, user_id, cred, pub, kid, st.get("sign_count") or 0, ctx.cfg.rp_id,
                                                       ctx.cfg.origin, t, st.get("label") or "passkey", "passkey", dev, signer))
            _append_event(db, user_id, "add", kid, "passkey", t, _record(pub, cred, ctx), payload, env)
            if dev == levels.PHONE:
                levels.mark_phone_ever(db, user_id)
        ctx.hub.key_changed(user_id)
    _security_push(ctx, user_id, "k")
    log("WARN", "passkey added", account=user_id, kid=kid[:4].hex(), by=signer[:4].hex())
    return {"kid_hex": kid.hex(), "short": short(kid), "added_by": "passkey", "signed_by": signer.hex()}


def refuse_if_pending(row, what, ctx=None):
    """0.2.16: a passkey that waits to become the phone (declared with a recovery code, 0.2.15) cannot, until the wait ends, make new
    recovery codes (that would burn the owner's remaining codes and keep the thief's new ones) nor remove any passkey, phone or laptop
    (that would remove the owner's way to cancel it). 0.2.17 (R9-03): nor add a passkey; and a passkey it vouched for (credentials.vouched_by,
    any depth) inherits the wait (with ctx). 409 PHONE_PENDING."""
    if row is None:
        return
    nb = levels.pending_lineage(ctx, row) if ctx is not None else levels.pending_until(row)
    if nb is not None:
        raise Err(409, "PHONE_PENDING", "this passkey was declared your new phone with a recovery code and counts as phone from %s UTC; until "
                                        "then it cannot %s. Not you? Cancel it in Devices with another passkey."
                  % (time.strftime("%Y-%m-%d %H:%M", time.gmtime(nb)), what))


def remove_begin(ctx, user_id, kid):
    c = _own_active(ctx, user_id, kid)
    if _active_count(ctx, user_id) <= 1:
        raise Err(409, "LAST_KEY", "this is your only passkey: add another one before removing it")
    payload = wq.key_event_payload("dw:" + user_id, "remove", kid, bytes(c["pub"]), bytes(c["credential_id"]), os.urandom(16))
    fid = auth.new_flow(ctx, "keyremove", {"user_id": user_id, "kid": kid.hex(), "payload": payload.hex()})
    return {"flow_id": fid, "typ": wq.TYP_KEY_EVENT, "payload_b64": wa.b64u(payload), "sign_with": auth.allow_credentials(ctx, user_id)}


def remove_finish(ctx, user_id, kid, flow_id, env):
    st = auth.take_flow(ctx, flow_id, "keyremove")
    if st.get("user_id") != user_id or st.get("kid") != kid.hex():
        raise Err(400, "FLOW_UNKNOWN", "flow expired or unknown")
    payload = bytes.fromhex(st["payload"])
    signer = _check_event_sig(ctx, user_id, payload, env)
    with ctx.hub.lock(user_id):
        c = _own_active(ctx, user_id, kid)
        srow = ctx.db.one("SELECT * FROM credentials WHERE kid=? AND user_id=?", (signer, user_id))
        if levels.pending_until(c) is not None:
            _may_cancel(ctx, user_id, kid, srow)
        if levels.device_of(c) == levels.PHONE and levels.device_of_kid(ctx, signer) != levels.PHONE:
            # 0.2.14 (R8-06): a phone-class key is removed only with a phone-class signature (else the laptop clears the way to "phone")
            raise Err(409, "DEVICE_LEVEL", "removing your phone's passkey needs a signature by a phone passkey. Lost the phone: use a "
                                           "recovery code, declare the new key your phone, then remove the lost one with it")
        refuse_if_pending(srow, "remove passkeys", ctx)             # 0.2.16: a waiting key removes no key at all, phone or laptop
        t = org._fresh_second(ctx, user_id, 0) if ctx.hub.has_entries(user_id) else now()   # entries signed before stay before
        with ctx.db.tx() as db:
            if db.one("SELECT COUNT(*) AS n FROM credentials WHERE user_id=? AND revoked_at IS NULL", (user_id,))["n"] <= 1:
                raise Err(409, "LAST_KEY", "this is your only passkey: add another one before removing it")
            if db.n("UPDATE credentials SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (t, c["id"])) != 1:
                raise Err(409, "KEY_NOT_ACTIVE")
            _append_event(db, user_id, "remove", kid, "passkey", t, None, payload, env)
            if levels.pending_until(c, t) is not None:                 # 0.2.17 (R9-03): what a waiting key vouched for goes with it
                _stop_vouched(db, user_id, kid, t, signer.hex())
            if c["device"] == levels.PHONE:
                levels.mark_phone_ever(db, user_id)
            # sessions opened with the lost key end; so do sessions of unknown origin (opened before 0.2.2 recorded the passkey)
            db.x("DELETE FROM sessions WHERE user_id=? AND (credential_id=? OR credential_id IS NULL)", (user_id, c["id"]))
        ctx.hub.key_changed(user_id)
    _security_push(ctx, user_id, "k")
    log("WARN", "passkey removed", account=user_id, kid=kid[:4].hex(), by=signer[:4].hex())
    return {"kid_hex": kid.hex(), "removed_at": t, "signed_by": signer.hex(),
            "mandates_signed_by_it": len(mandates_by_key(ctx, user_id, kid)),
            "note": "Mandates this passkey signed stay valid (the signature was good when it was recorded). Revoke them in one step "
                    "from Devices if you want them stopped."}


def set_device(ctx, user_id, kid, device, session_cred):
    """0.2.13: mark a passkey as the phone's or this computer's. Marking a key "laptop" only narrows (any session with a fresh step-up);
    marking a laptop key "phone" needs the last passkey signature of this session (step-up) to be by ANOTHER phone-class key -- unless the
    person has no phone-class key at all (first marking). Each change is a registry log row {"key_device": ...} (hash chain, anchored)."""
    device = _device(device)
    if device is None:
        raise Err(422, "BAD_DEVICE", "device: phone | laptop")
    c = _own_active(ctx, user_id, kid)
    cur = levels.device_of(c)
    sess_phone = session_cred is not None and levels.device_of(session_cred) == levels.PHONE
    if device == levels.PHONE and cur == levels.LAPTOP and (levels.has_phone_key(ctx, user_id) or levels.phone_ever(ctx, user_id)
                                                           or levels.recovery_window(ctx, user_id)):
        # 0.2.15: nor while a recovery code was used lately or a declared phone waits (the delay is not skipped through the first marking)
        # 0.2.14 (R8-06): the first marking is for an account that NEVER had a phone key, not one that has none right now
        if not sess_phone or bytes(session_cred["kid"]) == kid:
            raise Err(403, "DEVICE_LEVEL", "marking a key as your phone needs a fresh confirmation with your phone's passkey (step-up on the phone)")
    if device == levels.LAPTOP and levels.pending_until(c) is not None and (session_cred is None or bytes(session_cred["kid"]) != kid):
        _may_cancel(ctx, user_id, kid, session_cred)     # 0.2.15: ending another key's wait is a cancel: the phone (if any) decides
    if device == levels.LAPTOP and cur == levels.PHONE and not sess_phone:
        # 0.2.14 (R8-06): demoting a phone key is not "only narrowing": it clears the way for a laptop to become the phone
        raise Err(403, "DEVICE_LEVEL", "marking your phone's passkey as this computer's needs a fresh confirmation with a phone passkey (step-up on the phone)")
    t = now()
    with ctx.hub.lock(user_id):
        with ctx.db.tx() as db:
            db.x("UPDATE credentials SET device=?, phone_nb=NULL WHERE id=?", (device, c["id"]))     # 0.2.15: an explicit mark ends a wait
            if levels.PHONE in (device, c["device"]):
                levels.mark_phone_ever(db, user_id)
            ej = json.dumps({"key_device": {"principal": "dw:" + user_id, "kid": kid.hex(), "device": device, "was": c["device"], "t": t,
                                            "by": bytes(session_cred["kid"]).hex() if session_cred is not None else None}},
                            sort_keys=True, separators=(",", ":"))
            reglog.append(db, "keys:" + user_id, kid, ej, t)
    _security_push(ctx, user_id, "d")                 # 0.2.14 (R8-06): every class change reaches all the person's devices
    log("WARN", "passkey device class changed", account=user_id, kid=kid[:4].hex(), device=device)
    return {"kid_hex": kid.hex(), "device": device}


def _own_active(ctx, user_id, kid):
    c = ctx.db.one("SELECT * FROM credentials WHERE user_id=? AND kid=?", (user_id, kid)) if isinstance(kid, bytes) else None
    if c is None:
        raise Err(404, "NOT_FOUND")
    if c["revoked_at"] is not None:
        raise Err(409, "KEY_NOT_ACTIVE", "already removed")
    return c


def _active_count(ctx, user_id):
    return ctx.db.one("SELECT COUNT(*) AS n FROM credentials WHERE user_id=? AND revoked_at IS NULL", (user_id,))["n"]


def parse_kid(x):
    try:
        k = bytes.fromhex(x)
    except (TypeError, ValueError):
        raise Err(404, "NOT_FOUND")
    if len(k) != 32:
        raise Err(404, "NOT_FOUND")
    return k


# ---------------------------------------------------------------- recovery codes
def _norm_code(code):
    if not isinstance(code, str) or len(code) > 64:
        return None
    c = "".join(ch for ch in code.upper() if ch not in "- \t")
    if len(c) != 4 * CODE_GROUPS or any(ch not in CODE_ALPHABET for ch in c):
        return None
    return c


_SCRYPT_SLOTS = threading.BoundedSemaphore(4)       # R4-06/08: at most 4 scrypt (16 MiB each) at a time, in worker threads, never under the database lock


def _hash(code, salt):
    with _SCRYPT_SLOTS:
        return hashlib.scrypt(code.encode(), salt=salt, **SCRYPT)


LOOKUP_LEN = 6        # 0.2.5 (R4-07): the lookup group is 6 symbols (30 bits) and only has to be unique inside one user's batch; 0.2.2-0.2.4 codes keep their 4-symbol group
LOOKUPS = (4, LOOKUP_LEN)


def new_codes(ctx, user_id):
    """10 fresh codes; every earlier code of the user stops working. -> the codes (shown ONCE: only hashes are stored).
    The scrypt work is done BEFORE the database lock is taken (R4-06): under it only the DELETE and the INSERTs run."""
    t = now()
    codes, rows, groups, tries = [], [], set(), 0
    while len(codes) < CODES:
        tries += 1
        if tries > 100:                                   # R4-07: a bounded loop, never a hang
            raise Err(503, "TRY_AGAIN", "could not make the codes; try again")
        c = "".join(secrets.choice(CODE_ALPHABET) for _ in range(4 * CODE_GROUPS))
        if c[:LOOKUP_LEN] in groups:
            continue
        groups.add(c[:LOOKUP_LEN])
        salt = os.urandom(16)
        rows.append((user_id, c[:LOOKUP_LEN], salt, _hash(c, salt), t))
        codes.append("-".join(c[i:i + 4] for i in range(0, len(c), 4)))
    with ctx.db.tx() as db:
        db.x("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
        for r in rows:
            db.x("INSERT INTO recovery_codes(user_id,lookup,salt,hash,created_at) VALUES(?,?,?,?,?)", r)
    log("WARN", "recovery codes generated", account=user_id)
    return {"codes": codes, "created_at": t, "remaining": CODES,
            "note": "Shown once. Keep them offline (paper, password manager). Each works once and only lets you add a new passkey."}


def codes_state(ctx, user_id):
    r = ctx.db.one("SELECT COUNT(*) AS n, SUM(used_at IS NULL) AS left, MAX(created_at) AS t FROM recovery_codes WHERE user_id=?", (user_id,))
    return {"total": r["n"] or 0, "remaining": r["left"] or 0, "created_at": r["t"]}


_DUMMY_SALT = os.urandom(16)


def code_owners(ctx, code):
    """0.2.12 (R7-05): the accounts that have a live code in the lookup group of `code` (no scrypt, one indexed query). Empty = the code is
    garbage for certain; non-empty does not say the code is right."""
    c = _norm_code(code)
    if not c:
        return []
    return sorted({r["user_id"] for r in ctx.db.q("SELECT user_id FROM recovery_codes WHERE lookup IN (?,?) AND used_at IS NULL",
                                                  (c[:LOOKUPS[0]], c[:LOOKUPS[1]]))})


def use_code(ctx, code):
    """-> user_id, or Err(401 RECOVERY_INVALID) for an unknown, used or wrong code (one answer for all, same scrypt work)."""
    c = _norm_code(code)
    rows = ctx.db.q("SELECT rowid AS rid, * FROM recovery_codes WHERE lookup IN (?,?) AND used_at IS NULL", (c[:LOOKUPS[0]], c[:LOOKUPS[1]])) if c else []
    hit = None
    for r in rows:
        if hmac.compare_digest(_hash(c, bytes(r["salt"])), bytes(r["hash"])):
            hit = r
    if not rows:
        _hash(c or "X" * 20, _DUMMY_SALT)
    if hit is None or ctx.db.n("UPDATE recovery_codes SET used_at=? WHERE rowid=? AND used_at IS NULL", (now(), hit["rid"])) != 1:
        raise Err(401, "RECOVERY_INVALID", "this recovery code is unknown or was already used")
    return hit["user_id"]


def recovery_login(ctx, resp, uid):
    """After use_code: every session of the user ends, a recovery session (15 min) starts, the user's devices get a push."""
    ctx.db.x("DELETE FROM sessions WHERE user_id=?", (uid,))
    auth.start_session(ctx, resp, uid, uid, None, scope="recovery", ttl=RECOVERY_TTL)
    _security_push(ctx, uid, "r")
    log("WARN", "recovery code used: all sessions ended", account=uid)


def recovery_session(ctx, req, write=False):
    """-> user id of a RECOVERY session (scope 'recovery'), else Err. The only door a recovery code opens."""
    if write and req.headers.get("origin") != ctx.cfg.origin:
        raise Err(403, "BAD_ORIGIN", "Origin not allowed")
    tok = req.cookies.get("dw_session", "")
    r = ctx.db.one("SELECT user_id, scope, expires_at FROM sessions WHERE id_hash=? AND expires_at>?",
                   (hashlib.sha256(tok.encode()).digest(), now())) if tok else None
    if not r or r["scope"] != "recovery":
        raise Err(401, "NO_SESSION", "no recovery session: enter a recovery code first")
    req.state.user = r["user_id"]
    req.state.account = r["user_id"]
    return r["user_id"], r["expires_at"]


def recovery_passkey_begin(ctx, user_id, label, device=None):
    """0.2.14 (R8-06): the recovered key is "laptop" unless the person declares it the new phone HERE (device="phone"): the recovery code
    is an offline factor the agent's computer should not hold, its use ends every session and pushes to every device. Without this a lost
    phone could never be replaced (removing or demoting the lost phone key needs a phone signature)."""
    return _reg_options(ctx, user_id, "keyrecover", {"label": _label(label or "recovered passkey"),
                                                     "device": levels.PHONE if _device(device) == levels.PHONE else levels.LAPTOP})


def recovery_passkey_finish(ctx, req, user_id, flow_id, credential):
    """The new passkey becomes active at once (by = recovery-code), the recovery session ends: sign in with the new passkey."""
    st = auth.take_flow(ctx, flow_id, "keyrecover")
    if st.get("user_id") != user_id:
        raise Err(400, "FLOW_UNKNOWN", "flow expired or unknown")
    pub, cred, sc = _verify_registration(ctx, st, credential)
    kid = wa.thumbprint(pub)
    t = now()
    with ctx.hub.lock(user_id):
        with ctx.db.tx() as db:
            # R4-10: the recovery session is spent HERE, atomically with the insert: of two concurrent finishes only one deletes it (the other: 401)
            if db.n("DELETE FROM sessions WHERE id_hash=? AND scope='recovery'", (auth._tok_hash(req),)) != 1:
                raise Err(401, "NO_SESSION", "this recovery session was already used")
            dev = levels.PHONE if st.get("device") == levels.PHONE else levels.LAPTOP     # 0.2.14 (R8-06): never phone by default
            nb = t + delay_s(ctx) if dev == levels.PHONE else None                       # 0.2.15: a phone only after the delay
            db.x("INSERT INTO credentials(account_id,user_id,credential_id,pub,kid,sign_count,rp_id,origin,created_at,label,added_by,device,phone_nb) "
                 "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (user_id, user_id, cred, pub, kid, sc, ctx.cfg.rp_id, ctx.cfg.origin, t,
                                                       st.get("label") or "recovered passkey", "recovery-code", dev, nb))
            kd = {"principal": "dw:" + user_id, "kid": kid.hex(), "device": dev, "was": None, "t": t, "by": "recovery-code"}
            if nb is not None:
                kd["not_before"] = nb
            ej = json.dumps({"key_device": kd}, sort_keys=True, separators=(",", ":"))
            reglog.append(db, "keys:" + user_id, kid, ej, t)          # the class first, then the key event (the last row says how it came in)
            _append_event(db, user_id, "add", kid, "recovery-code", t, _record(pub, cred, ctx))
            if dev == levels.PHONE:
                levels.mark_phone_ever(db, user_id)
            db.x("DELETE FROM sessions WHERE user_id=?", (user_id,))
        ctx.hub.key_changed(user_id)
    _security_push(ctx, user_id, "p" if nb is not None else "k")      # 0.2.15: p = "a new phone was declared: not you? cancel"
    log("WARN", "passkey added with a recovery code", account=user_id, kid=kid[:4].hex(), phone_not_before=nb)
    out = {"kid_hex": kid.hex(), "short": short(kid), "added_by": "recovery-code", "device": dev, "codes_left": codes_state(ctx, user_id)["remaining"],
           "next": "Sign in with the new passkey. Then, in Devices, remove the lost one and make new recovery codes."}
    if nb is not None:
        out.update(phone_not_before=nb, delay_h=delay_s(ctx) // 3600,
                   next="Sign in with the new passkey. It counts as your phone from %s UTC (%d h from now): until then it confirms only what "
                        "this computer's passkey may, and your other devices were told and can cancel it. Then remove the lost phone in "
                        "Devices with it and make new recovery codes." % (time.strftime("%Y-%m-%d %H:%M", time.gmtime(nb)), delay_s(ctx) // 3600))
    return out


def delay_s(ctx):
    """0.2.15: hours (24..72, DW_RECOVERY_PHONE_DELAY_H) before a phone declared with a recovery code counts as phone."""
    h = getattr(ctx.cfg, "recovery_phone_delay_h", 24)
    return max(24, min(72, h if isinstance(h, int) else 24)) * 3600


def _may_cancel(ctx, user_id, kid, signer_row):
    """0.2.15: who may cancel (or remove) a phone that waits: a phone-class key of the person; when the person has none, any OTHER active
    key that does not wait itself. The waiting key never cancels itself, and a second waiting key never cancels the first."""
    if signer_row is None or signer_row["revoked_at"] is not None or bytes(signer_row["kid"]) == kid:
        raise Err(403, "DEVICE_LEVEL", "cancel with another passkey of yours (your phone's, if you still have it)")
    if levels.pending_lineage(ctx, signer_row) is not None:
        raise Err(403, "DEVICE_LEVEL", "a passkey that is itself waiting to become your phone cannot cancel another one")
    if levels.has_phone_key(ctx, user_id, exclude_kid=kid) and levels.device_of(signer_row) != levels.PHONE:
        raise Err(403, "DEVICE_LEVEL", "cancelling a new phone needs a confirmation with your phone's passkey (step-up on the phone)")


def cancel_phone(ctx, user_id, kid, session_cred):
    """0.2.15: "this was not me": the key declared the new phone with a recovery code loses its claim for good, its sessions end, and every
    unused recovery code stops working (whoever used one may hold the rest). Recorded as a key_device row {cancelled: true}.
    0.2.17 (R9-03): the key is also STOPPED (revoked; the row says {stopped: true}): before, it stayed a laptop key whose holder could sign in
    again, make new recovery codes and remove the owner's keys. So is every key it vouched for (_stop_vouched)."""
    if ctx.db.one("SELECT 1 FROM registry_log WHERE account_id=? AND kid=? AND entry_json LIKE '%\"cancelled\":true%'", ("keys:" + user_id, kid)):
        raise Err(409, "NOT_PENDING", "this passkey is not waiting to become your phone")
    c = _own_active(ctx, user_id, kid)
    if levels.pending_until(c) is None:
        raise Err(409, "NOT_PENDING", "this passkey is not waiting to become your phone")
    _may_cancel(ctx, user_id, kid, session_cred)
    t = now()
    with ctx.hub.lock(user_id):
        with ctx.db.tx() as db:
            if db.n("UPDATE credentials SET device=?, phone_nb=NULL, revoked_at=? WHERE id=? AND phone_nb>?", (levels.LAPTOP, t, c["id"], t)) != 1:
                raise Err(409, "NOT_PENDING", "this passkey is not waiting to become your phone")
            ej = json.dumps({"key_device": {"principal": "dw:" + user_id, "kid": kid.hex(), "device": levels.LAPTOP, "was": levels.PHONE, "t": t,
                                            "by": bytes(session_cred["kid"]).hex(), "cancelled": True, "stopped": True}}, sort_keys=True, separators=(",", ":"))
            reglog.append(db, "keys:" + user_id, kid, ej, t)
            db.x("DELETE FROM sessions WHERE user_id=? AND credential_id=?", (user_id, c["id"]))
            gone = _stop_vouched(db, user_id, kid, t, bytes(session_cred["kid"]).hex())    # 0.2.17 (R9-03): and every key it vouched for
            burned = db.n("UPDATE recovery_codes SET used_at=? WHERE user_id=? AND used_at IS NULL", (t, user_id))
        ctx.hub.key_changed(user_id)
    _security_push(ctx, user_id, "d")
    log("WARN", "declared phone cancelled", account=user_id, kid=kid[:4].hex(), codes_burned=burned, keys_removed=len(gone))
    return {"kid_hex": kid.hex(), "device": levels.LAPTOP, "cancelled": True, "recovery_codes_stopped": burned,
            "keys_removed": [k.hex() for k in gone],
            "stopped": True,
            "next": "This passkey and the passkeys it confirmed no longer work. Make new recovery codes."}


def _stop_vouched(db, user_id, kid, t, by, _depth=0):
    """0.2.17 (R9-03): the witness stops every active passkey that `kid` vouched for (credentials.vouched_by), and theirs: revoked, sessions
    ended, and a registry log row {"key_device": {..., "stopped": true, "vouched_by"}} in the ownership chain (the witness's record, like the
    other key_device rows: no owner signature exists for it, so it is not a key_event). Caller holds a transaction. -> [kid, ...]"""
    out = []
    if _depth >= 16:
        return out
    for c in db.q("SELECT * FROM credentials WHERE user_id=? AND vouched_by=? AND revoked_at IS NULL", (user_id, kid)):
        ck = bytes(c["kid"])
        db.x("UPDATE credentials SET revoked_at=? WHERE id=?", (t, c["id"]))
        db.x("DELETE FROM sessions WHERE user_id=? AND credential_id=?", (user_id, c["id"]))
        ej = json.dumps({"key_device": {"principal": "dw:" + user_id, "kid": ck.hex(), "device": c["device"] or levels.PHONE, "was": c["device"] or levels.PHONE,
                                        "t": t, "by": by, "stopped": True, "vouched_by": kid.hex()}}, sort_keys=True, separators=(",", ":"))
        reglog.append(db, "keys:" + user_id, ck, ej, t)
        out.append(ck)
        out += _stop_vouched(db, user_id, ck, t, by, _depth + 1)
    return out


def lift_phone_wait(db, user_id, kid, by, t, extra=None):
    """0.2.15: the wait ends early (a quorum of the team said so). Caller holds a transaction. -> True when a wait was ended."""
    if db.n("UPDATE credentials SET phone_nb=NULL WHERE user_id=? AND kid=? AND revoked_at IS NULL AND device=? AND phone_nb>?",
            (user_id, kid, levels.PHONE, t)) != 1:
        return False
    kd = {"principal": "dw:" + user_id, "kid": kid.hex(), "device": levels.PHONE, "was": levels.PHONE, "t": t, "by": by, "lifted": True}
    kd.update(extra or {})
    reglog.append(db, "keys:" + user_id, kid, json.dumps({"key_device": kd}, sort_keys=True, separators=(",", ":")), t)
    return True


def _security_push(ctx, user_id, k):
    p = getattr(ctx, "push", None)
    if p is not None:
        p.notify_security(user_id, k)


# ---------------------------------------------------------------- mandates signed by a key; batch revocation
def signers_of(env):
    """kids that signed an envelope (wa-sig: its kid; wq: every wsig; wb: its kid); [] for COSE_Sign1 / garbage."""
    try:
        m = cbor2.loads(env)
    except Exception:
        return []
    if not isinstance(m, dict):
        return []
    if m.get("v") == wq.V_WQ:
        return [w.get("kid") for w in m.get("sigs") or [] if isinstance(w, dict)]
    return [m.get("kid")] if isinstance(m.get("kid"), bytes) else []


def mandates_by_key(ctx, account_id, kid):
    return [x for x in ctx.db.q("SELECT * FROM mandates WHERE account_id=? AND status='active' ORDER BY created_at, rowid", (account_id,))
            if x["envelope"] is not None and kid in signers_of(bytes(x["envelope"]))]


def revoke_batch_view(ctx, account_id, kid):
    """Active mandates of this account that `kid` signed: they stay valid until revoked. The browser computes each revocation payload
    itself (CDE of the mandate) and signs ONE wb of typ revocation over up to 20 of them."""
    out = []
    for x in mandates_by_key(ctx, account_id, kid):
        out.append({"id": x["id"], "agent_id": x["agent_id"], "mandate": json.loads(x["mandate_json"]), "created_at": x["created_at"]})
    return {"kid_hex": kid.hex(), "typ": wa.TYP_REVOCATION, "max_per_batch": wq.MAX_ITEMS, "mandates": out}


def revoke_batch(ctx, acc, user_id, mandate_ids, env):
    """One wb (typ revocation) by a current key revokes every listed mandate (<= 20). Solo account: the signer is an active passkey of
    the account; organisation: a member of the policy in force (rule revocation {any, 1}). -> {"revoked": [...], "ledger_seqs": [...]}."""
    from svidetel_v4.state import revocation_payload
    if not isinstance(mandate_ids, list) or not 1 <= len(mandate_ids) <= wq.MAX_ITEMS or len(set(map(str, mandate_ids))) != len(mandate_ids):
        raise Err(422, "BAD_REQUEST", "mandate_ids: 1..%d distinct ids" % wq.MAX_ITEMS)
    if wq.envelope_kind(env) != "wb":
        raise Err(409, "WB_MALFORMED", "one batch signature (wb, typ revocation) expected")
    org.refuse_revoked(ctx, env)
    try:
        m = cbor2.loads(env)
        items, kid = set(m["items"]), m["kid"]
    except Exception:
        raise Err(409, "WB_MALFORMED")
    aid = acc["id"]
    out, seqs = [], []
    with ctx.hub.lock(aid):
        rows = []
        for mid in mandate_ids:
            x = ctx.db.one("SELECT * FROM mandates WHERE id=? AND account_id=?", (mid, aid)) if isinstance(mid, str) else None
            if x is None:
                raise Err(404, "NOT_FOUND", "mandate %s" % str(mid)[:40])
            if x["status"] != "active":
                raise Err(409, "MANDATE_NOT_ACTIVE", "mandate %s is %s" % (mid, x["status"]))
            pay = revocation_payload(wire.cbor_form(json.loads(x["mandate_json"])))
            if hashlib.sha256(pay).digest() not in items:
                raise Err(409, "WB_ITEM", "the batch does not cover mandate %s" % mid)
            rows.append((x, pay))
        cur = org.current_policy(ctx, aid)
        if cur is None:
            who = ctx.hub.active_keys(aid).get(kid)
            if who is None:
                raise Err(409, "KEY_NOT_ACTIVE", "sign with an active passkey of this account")
            if org.user_entry(ctx, user_id, kid) is None:
                raise Err(409, "KEY_NOT_ACTIVE", "sign with your own passkey")
        else:
            who = {mm["kid"]: mm for mm in cur[0]["members"]}.get(kid)
            if who is None or org.user_entry(ctx, user_id, kid) is None:
                raise Err(409, "WQ_NOT_MEMBER")
            code = wq.wb_requirements_met(cur[0], kid, None, wa.TYP_REVOCATION)
            if code:
                raise Err(409, code)
        for x, pay in rows:
            code = wq.verify_wb(env, wa.TYP_REVOCATION, pay, who, rp=org.rp(ctx))
            if code:
                raise Err(409, code)
        org.check_sign_counts(ctx, env, "revoke_batch", aid)          # 0.2.20: one wb, one counter
        L = ctx.hub.ledger(aid)
        for x, pay in rows:
            res = L.revoke(x["id"], cose_bytes=env)
            if res["result"] != "accept":
                raise Err(409, res["reason"], "stopped at mandate %s; the ones before it are revoked" % x["id"])
            ctx.db.x("UPDATE mandates SET status='revoked' WHERE id=?", (x["id"],))
            out.append(x["id"])
            seqs.append(L.S.nseq - 1)
    return {"revoked": out, "ledger_seqs": seqs}
