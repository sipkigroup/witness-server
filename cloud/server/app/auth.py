"""WebAuthn registration / login (py_webauthn) and cookie sessions. Registration: ES256 (-7) only, residentKey required,
UV required, attestation none. Login: discoverable credential, UV required.
0.2: a session belongs to a USER (the person with the passkey) and names the current organisation (account); every registration makes
a user and the user's own solo account (same id); rights are checked by org.require on every request.
0.2.2: a user may hold several passkeys (app/keys.py); a removed one never signs in again; a session opened with a recovery code
(scope 'recovery') may only add a new passkey (session_account refuses it everywhere else)."""
import hashlib
import json
import os
import secrets
import time

import cbor2
from webauthn import verify_authentication_response, verify_registration_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from app import _paths  # noqa: F401
import wa_profile as wa
from app.context import Err
from app import org, reglog

FLOW_TTL = 300
SESSION_TTL = 7 * 86400
STEPUP_TTL = 300          # R-17: a passkey signature newer than this is needed for sensitive changes


def now():
    return int(time.time())


def short_kid(kid: bytes) -> str:
    h = kid[:8].hex()
    return " ".join(h[i:i + 4] for i in range(0, 16, 4))


def new_flow(ctx, purpose, state):
    fid = secrets.token_hex(12)
    ctx.db.x("DELETE FROM wa_flows WHERE expires_at<?", (now(),))
    ctx.db.x("INSERT INTO wa_flows(id,purpose,state_json,expires_at) VALUES(?,?,?,?)", (fid, purpose, json.dumps(state), now() + FLOW_TTL))
    return fid


def take_flow(ctx, fid, purpose):
    with ctx.db.lock:
        r = ctx.db.one("SELECT * FROM wa_flows WHERE id=?", (fid,)) if isinstance(fid, str) else None
        if r is not None:
            ctx.db.x("DELETE FROM wa_flows WHERE id=?", (fid,))
    if r is None or r["purpose"] != purpose or r["expires_at"] < now():
        raise Err(400, "FLOW_UNKNOWN", "flow expired or unknown")
    return json.loads(r["state_json"])


def register_begin(ctx, display_name):
    chal = os.urandom(32)
    uid = os.urandom(16)
    name = (display_name or "user")[:80]
    fid = new_flow(ctx, "register", {"challenge": bytes_to_base64url(chal), "display_name": name, "user_id": bytes_to_base64url(uid)})
    return {"flow_id": fid, "options": {
        "rp": {"id": ctx.cfg.rp_id, "name": "Deus Witness"},
        "user": {"id": bytes_to_base64url(uid), "name": name, "displayName": name},
        "challenge": bytes_to_base64url(chal),
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"},
        "attestation": "none", "timeout": 300000}}


def verify_registration(ctx, st, credential):
    """-> (credential_id, pub 65 bytes, sign_count) of a registration response checked against the flow state (UV required, ES256 only)."""
    try:
        v = verify_registration_response(credential=credential, expected_challenge=base64url_to_bytes(st["challenge"]),
                                         expected_rp_id=ctx.cfg.rp_id, expected_origin=ctx.cfg.origin,
                                         require_user_verification=True, supported_pub_key_algs=[-7])
        key = cbor2.loads(v.credential_public_key)
        if key.get(3) != -7 or key.get(1) != 2 or key.get(-1) != 1:
            raise ValueError("alg")
        pub = b"\x04" + key[-2] + key[-3]
        wa.thumbprint(pub)
    except Exception as e:
        raise Err(400, "WA_REGISTRATION", "registration rejected (%s)" % type(e).__name__)
    return v.credential_id, pub, v.sign_count


def bind_identity(ctx, db, aid, display_name, cid, pub, sign_count, device, t, new_account=True):
    """The person + their first passkey + the registry entry, inside the caller's transaction. new_account=False (0.2.38, a trial account
    claimed by its first touch): the account row exists already (made by POST /v1/trial without a key) and gets its user and key now."""
    principal = "dw:" + aid
    kid = wa.thumbprint(pub)
    if db.one("SELECT 1 FROM credentials WHERE credential_id=?", (cid,)):
        raise Err(409, "CREDENTIAL_EXISTS")
    last = db.one("SELECT seq FROM registry_log ORDER BY seq DESC LIMIT 1")
    seq = (last["seq"] + 1) if last else 1
    entry = {"alg": "ES256", "pub": pub.hex(),
             "webauthn": {"rp_id": ctx.cfg.rp_id, "origins": [ctx.cfg.origin], "credential_id": bytes_to_base64url(cid)},
             "pin_source": "webauthn-registration:%s:%s:registry-log#%d" % (ctx.cfg.rp_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)), seq)}
    ej = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    if new_account:
        db.x("INSERT INTO accounts(id,principal,display_name,created_at) VALUES(?,?,?,?)", (aid, principal, display_name, t))
    db.x("INSERT INTO users(id,display_name,created_at) VALUES(?,?,?)", (aid, display_name, t))
    db.x("INSERT INTO credentials(account_id,user_id,credential_id,pub,kid,sign_count,rp_id,origin,created_at,label,added_by,device) "
         "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (aid, aid, cid, pub, kid, sign_count, ctx.cfg.rp_id, ctx.cfg.origin, t, "first passkey", "registration",
                                             device if device in ("phone", "laptop") else None))     # 0.2.13: the device class the person chose
    if device == "phone":
        db.x("UPDATE users SET phone_ever=1 WHERE id=?", (aid,))       # 0.2.14 (R8-06)
    org.add_owner(db, aid, aid, kid)
    reglog.append(db, aid, kid, ej, t)                 # 0.2.12 (R7-04): both chains (the row's seq is the one named in pin_source)
    return principal, kid


def register_finish(ctx, flow_id, credential, device=None):
    st = take_flow(ctx, flow_id, "register")
    cid, pub, sign_count = verify_registration(ctx, st, credential)
    aid = org.new_user_id()                 # the user's own (solo) account has the user's id
    t = now()
    with ctx.db.tx() as db:
        principal, kid = bind_identity(ctx, db, aid, st["display_name"], cid, pub, sign_count, device, t)
    from app import stats
    stats.first(ctx, aid, "registration")                  # 0.2.28: after the commit (the display name is there for the "own" mark)
    return ({"id": aid, "principal": principal, "display_name": st["display_name"]},
            {"kid_hex": kid.hex(), "short": short_kid(kid)})


def login_begin(ctx, rid=None):
    chal = os.urandom(32)
    fid = new_flow(ctx, "login", {"challenge": bytes_to_base64url(chal)})
    out = {"flow_id": fid, "options": {"challenge": bytes_to_base64url(chal), "rpId": ctx.cfg.rp_id, "userVerification": "required",
                                       "allowCredentials": [], "timeout": 300000}}
    hint = login_hint(ctx, rid)
    if hint:
        out["options"]["allowCredentials"] = hint.pop("allow")
        out["hint"] = hint
    return out


def login_hint(ctx, rid):
    """0.2.75 (N23): the sign-in page opened from a call's link (approve.html?rid=... -> login.html?next=...) says WHICH account that call
    waits for, and the device offers only that account's passkeys: with two trial accounts in one browser a sign-in without a hint picked
    the first passkey of the list, i.e. the other account. Only for an account made by `deus-witness try` (its passkey is named
    "Trial <minute> UTC - <id>", nothing personal); any other rid, or none -> None (an ordinary sign-in, any passkey)."""
    import re
    if not isinstance(rid, str) or not re.fullmatch(r"r_[A-Z2-7]{1,40}", rid):
        return None
    x = ctx.db.one("SELECT account_id FROM actions WHERE rid=?", (rid,))
    a = ctx.db.one("SELECT id, display_name FROM accounts WHERE id=? AND trial_claimed_at IS NOT NULL", (x["account_id"],)) if x else None
    if not a:
        return None
    creds = ctx.db.q("SELECT credential_id FROM credentials WHERE account_id=? AND revoked_at IS NULL", (a["id"],))
    if not creds:
        return None
    return {"name": a["display_name"] or "", "allow": [{"type": "public-key", "id": bytes_to_base64url(bytes(c["credential_id"]))} for c in creds]}


def _verify_assertion(ctx, st, credential, user_id=None):
    try:
        cid = base64url_to_bytes(credential.get("rawId") or credential["id"])
    except Exception:
        raise Err(400, "BAD_REQUEST")
    c = ctx.db.one("SELECT * FROM credentials WHERE credential_id=?", (cid,))
    if not c or (user_id is not None and c["user_id"] != user_id):
        raise Err(401, "CREDENTIAL_UNKNOWN")
    if c["revoked_at"] is not None:              # 0.2.2: a removed passkey (lost phone) never signs in or confirms anything again
        raise Err(401, "CREDENTIAL_REVOKED", "this passkey was removed from the account")
    try:
        v = verify_authentication_response(credential=credential, expected_challenge=base64url_to_bytes(st["challenge"]),
                                           expected_rp_id=ctx.cfg.rp_id, expected_origin=ctx.cfg.origin,
                                           credential_public_key=_cose_key(bytes(c["pub"])), credential_current_sign_count=0,
                                           require_user_verification=True)
    except Exception as e:
        raise Err(401, "WA_LOGIN", "assertion rejected (%s)" % type(e).__name__)
    # 0.2.20: the counter rule (WebAuthn 7.2 step 21) is the one of every signed envelope (org.sign_count_ok), applied by ONE conditional
    # UPDATE: two sign-ins (or a sign-in and an approval) with one counter cannot both pass, and a stored counter never goes back
    # (0.2.19 compared with a value read before and wrote unconditionally). The library gets 0 so that it never decides on the counter.
    n = int(v.new_sign_count or 0)
    if not ctx.db.n("UPDATE credentials SET sign_count=?, last_sig=NULL, last_used_at=? WHERE id=? AND (COALESCE(sign_count,0) < ? OR (?=0 AND COALESCE(sign_count,0)=0))",
                    (n, now(), c["id"], n, n)):
        row = ctx.db.one("SELECT sign_count FROM credentials WHERE id=?", (c["id"],))
        e = org.sign_count_refused(ctx, bytes(c["kid"]), row["sign_count"] if row is not None else 0, n, "login", c["account_id"])
        raise Err(401, e.code, e.detail)             # 401 as every refused sign-in
    return c


def login_finish(ctx, flow_id, credential):
    """-> (user_id, account_id of the organisation the session starts in = the user's own account)."""
    c = _verify_assertion(ctx, take_flow(ctx, flow_id, "login"), credential)
    return c["user_id"], c["account_id"], c["id"]


def stepup_begin(ctx, req):
    """R-17: a fresh passkey assertion bound to this user and this flow."""
    uid = req.state.user
    chal = os.urandom(32)
    fid = new_flow(ctx, "stepup", {"challenge": bytes_to_base64url(chal), "user_id": uid})
    return {"flow_id": fid, "options": {"challenge": bytes_to_base64url(chal), "rpId": ctx.cfg.rp_id, "userVerification": "required",
                                        "allowCredentials": allow_credentials(ctx, uid), "timeout": 300000}}


def allow_credentials(ctx, uid):
    """0.2.2: every ACTIVE passkey of the user (the phone, the hardware key, ...)."""
    return [{"type": "public-key", "id": bytes_to_base64url(bytes(c["credential_id"]))} for c in org.credentials_of(ctx, uid)]


def stepup_finish(ctx, req, flow_id, credential):
    st = take_flow(ctx, flow_id, "stepup")
    if st.get("user_id") != req.state.user:
        raise Err(400, "FLOW_UNKNOWN", "flow expired or unknown")
    c = _verify_assertion(ctx, st, credential, req.state.user)
    ctx.db.x("UPDATE sessions SET stepup_at=?, credential_id=? WHERE id_hash=?", (now(), c["id"], _tok_hash(req)))


def _session_cred(ctx, req):
    r = ctx.db.one("SELECT c.* FROM sessions s JOIN credentials c ON c.id=s.credential_id WHERE s.id_hash=? AND c.revoked_at IS NULL", (_tok_hash(req),))
    return r


def key_in_policy(ctx, req, acc):
    """0.2.5 (R4-09): in an organisation with a policy, the rights that need a passkey (step-up, reading the protected literals unmasked) belong to the person's key
    that the POLICY names (members.kid). A key added later (a recovery code, a second device) is not in the policy until the quorum swaps it in (key-replace).
    Solo account, or a member who does not sign (kid NULL): no restriction. The key is the one of the last passkey signature of this session (login or step-up)."""
    if acc is None or org.current_policy(ctx, acc["id"]) is None:
        return True
    m = org.member(ctx, acc["id"], req.state.user)
    if m is None or m["kid"] is None:
        return True
    c = _session_cred(ctx, req)
    return c is not None and bytes(c["kid"]) in {mm["kid"] for mm in org.current_policy(ctx, acc["id"])[0]["members"]}


def require_stepup(ctx, req, acc=None):
    r = ctx.db.one("SELECT stepup_at FROM sessions WHERE id_hash=? AND user_id=?", (_tok_hash(req), req.state.user))
    if not r or (r["stepup_at"] or 0) < now() - STEPUP_TTL:
        raise Err(403, "STEPUP_REQUIRED", "confirm with your passkey (signature not older than %d minutes)" % (STEPUP_TTL // 60))
    if not key_in_policy(ctx, req, acc):
        raise Err(403, "KEY_NOT_IN_POLICY", "this passkey is not in the organisation's policy: ask the team to swap it in (key replacement), or use the key the policy names")


def end_all_sessions(ctx, req):
    ctx.db.x("DELETE FROM sessions WHERE user_id=?", (req.state.user,))


def _tok_hash(req):
    return hashlib.sha256(req.cookies.get("dw_session", "").encode()).digest()


def _cose_key(pub: bytes) -> bytes:
    return wa.cde({1: 2, 3: -7, -1: 1, -2: pub[1:33], -3: pub[33:]})


def start_session(ctx, resp, account_id, user_id=None, credential_row_id=None, scope=None, ttl=SESSION_TTL):
    tok = secrets.token_urlsafe(32)
    t = now()
    ctx.db.x("DELETE FROM sessions WHERE expires_at<?", (t,))
    # the login / registration itself is a fresh passkey signature; a recovery session has none (stepup_at NULL)
    ctx.db.x("INSERT INTO sessions(id_hash,account_id,created_at,expires_at,stepup_at,user_id,scope,credential_id) VALUES(?,?,?,?,?,?,?,?)",
             (hashlib.sha256(tok.encode()).digest(), account_id, t, t + ttl, None if scope else t, user_id or account_id, scope, credential_row_id))
    resp.set_cookie("dw_session", tok, httponly=True, samesite="strict", secure=ctx.cfg.secure_cookie, max_age=ttl, path="/")
    # 0.2.19: a readable marker "a session may exist" (no secret, not an authority): public pages ask /api/me only when it is set
    resp.set_cookie("dw_in", "1", httponly=False, samesite="strict", secure=ctx.cfg.secure_cookie, max_age=ttl, path="/")


def session_account(ctx, req, write=False, action=None):
    """-> the account row of the session's current organisation. Rights: org.require(user, account, action); action defaults to
    "read" for GET and "write" (signing roles, active) for a changing request. Sets req.state.user / .account / .member."""
    if write and req.headers.get("origin") != ctx.cfg.origin:
        raise Err(403, "BAD_ORIGIN", "Origin not allowed")
    tok = req.cookies.get("dw_session", "")
    r = ctx.db.one("SELECT a.*, s.user_id AS s_user, s.scope AS s_scope FROM sessions s JOIN accounts a ON a.id=s.account_id "
                   "WHERE s.id_hash=? AND s.expires_at>?", (hashlib.sha256(tok.encode()).digest(), now())) if tok else None
    if not r:
        raise Err(401, "NO_SESSION")
    if r["s_scope"] is not None:                 # 0.2.2: a recovery-code session opens ONLY the "add a new passkey" screen
        raise Err(403, "RECOVERY_ONLY", "signed in with a recovery code: add a new passkey first, then sign in with it")
    req.state.user = r["s_user"] or r["id"]
    req.state.account = r["id"]
    req.state.member = org.require(ctx, req.state.user, r["id"], action or ("write" if write else "read"))
    return r


def switch_org(ctx, req, account_id):
    org.require(ctx, req.state.user, account_id, "read")
    ctx.db.x("UPDATE sessions SET account_id=? WHERE id_hash=?", (account_id, _tok_hash(req)))


def end_session(ctx, req):
    tok = req.cookies.get("dw_session", "")
    if tok:
        ctx.db.x("DELETE FROM sessions WHERE id_hash=?", (hashlib.sha256(tok.encode()).digest(),))
