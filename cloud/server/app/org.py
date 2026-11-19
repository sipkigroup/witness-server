"""Organisations of several people (ARHITEKTURA-0.2 2): users, members, roles, invites, policy chain, signature requests, settings.
An organisation IS an account of 0.1 (principal dw:<id>, one ledger); a user is a person with one passkey; every user also has an
account of their own (solo organisation, same id). One table of rights (`require`), one place that adopts a policy version, one place
that collects wa-sigs into a wq (`sign_request`). Export for task 06: `export_org`."""
import hashlib
import json
import os
import secrets
import time

import cbor2

from app import _paths  # noqa: F401
from app import keyalert, reglog, wire
import wa_profile as wa
import wq_profile as wq
from app.context import Err
from app.log import log

SIGNERS = ("owner", "budget", "access")
ROLES = SIGNERS + ("observer",)
INVITE_TTL = 24 * 3600
SIGREQ_TTL = 24 * 3600          # a mandate / policy draft lives 24 h (2.4)
DEFAULT_SETTINGS = {"profile": "smb", "defer_ttl_s": 3600, "max_pending": 10, "max_defers_hour": 120, "escalate_after_s": 600, "advisor": "off",
                    "refusal_block_s": 900}      # 05.11: after a Deny the same call is refused silently this long (60..86400)
GENESIS_RULES = {"policy": {"role": "owner", "k": 1}, "mandate": [], "approval": [], "revocation": {"role": "any", "k": 1},
                 "ceiling": {"role": "owner", "k": 1}}
REVOCATION_RULE = {"role": "any", "k": 1}           # 0 p.3: stopping is easy -- any one signer, in every version

# The ONE table of rights (2.7). action -> (roles that may, member statuses that may). The observer may only read -- and freeze (r0292).
# "sign": the signature itself is then judged against the policy (a pending / removed member gets WQ_NOT_MEMBER, not a silent 403).
RIGHTS = {
    "read":    (ROLES, ("active", "pending")),
    "session": (ROLES, ("active", "pending", "removed")),     # step-up, logout, switching away
    "write":   (SIGNERS, ("active",)),                       # default of any other changing path (also task 02's routes)
    "mandate": (SIGNERS, ("active",)),
    "sign":    (SIGNERS, ("active", "pending", "removed")),
    "owner":   (("owner",), ("active",)),
    # r0292 (owner 13.11, p.5): "anyone may stop" -- a Viewer (observer) may FREEZE an agent, nothing else; unfreezing is "owner".
    # The rate of a non-owner's freezes is limited (actions.FREEZE_RATE_N per FREEZE_RATE_S); every freeze is journaled with by_user.
    "freeze":  (ROLES, ("active",)),
}


def now():
    return int(time.time())


# ---------------------------------------------------------------- users / members / rights
def member(ctx, account_id, user_id):
    r = ctx.db.one("SELECT * FROM members WHERE account_id=? AND user_id=?", (account_id, user_id))
    if r is None:
        return None
    return {"account_id": r["account_id"], "user_id": r["user_id"], "roles": json.loads(r["roles"] or "[]"),
            "kid": bytes(r["kid"]) if r["kid"] is not None else None, "status": r["status"]}


def require(ctx, user_id, account_id, action):
    """-> member dict, or Err(403). The single rights check of the server (2.7)."""
    if action not in RIGHTS:
        raise ValueError("unknown action %r" % action)
    m = member(ctx, account_id, user_id)
    if m is None:
        raise Err(403, "NOT_MEMBER", "not a member of this organisation")
    roles, statuses = RIGHTS[action]
    if m["status"] not in statuses or not any(r in roles for r in m["roles"]):
        raise Err(403, "FORBIDDEN", "your role in this organisation does not allow this (%s)" % action)
    return m


def credential_of(ctx, user_id):
    """The user's first ACTIVE passkey (0.2.2: a user may hold several; a removed one is never used)."""
    return ctx.db.one("SELECT * FROM credentials WHERE user_id=? AND revoked_at IS NULL ORDER BY id LIMIT 1", (user_id,))


def credentials_of(ctx, user_id):
    return ctx.db.q("SELECT * FROM credentials WHERE user_id=? AND revoked_at IS NULL ORDER BY id", (user_id,))


def user_entry(ctx, user_id, kid=None):
    """Registry record 3.4 of one ACTIVE passkey of the user: the one with `kid` (the kid of the envelope being checked), or the first.
    None when the user holds no such active key (removed / someone else's)."""
    from app.hub import credential_record
    if kid is None:
        c = credential_of(ctx, user_id)
    else:
        c = ctx.db.one("SELECT * FROM credentials WHERE user_id=? AND kid=? AND revoked_at IS NULL", (user_id, kid)) if isinstance(kid, bytes) else None
    return credential_record(c) if c else None


def user_kid(ctx, user_id):
    c = credential_of(ctx, user_id)
    return bytes(c["kid"]) if c else None


def revoked_kid(ctx, kid):
    """0.2.2: kid is a passkey its owner REMOVED (lost). A policy may still name it until the quorum replaces it; the server never counts
    its signature again (defence in depth: the pack checker judges membership by the policy at the entry's time)."""
    return isinstance(kid, bytes) and ctx.db.one("SELECT 1 FROM credentials WHERE kid=? AND revoked_at IS NOT NULL", (kid,)) is not None


def refuse_revoked(ctx, env):
    """Err(409 KEY_REVOKED) when any signer of a wa / wq / wb envelope is a removed passkey."""
    try:
        m = cbor2.loads(env)
    except Exception:
        return
    if not isinstance(m, dict):
        return
    kids = [w.get("kid") for w in m.get("sigs") or [] if isinstance(w, dict)] if m.get("v") == wq.V_WQ else [m.get("kid")]
    if any(revoked_kid(ctx, k) for k in kids):
        raise Err(409, "KEY_REVOKED", "a signature is by a passkey its owner removed")


def touch_kids(ctx, kids):
    """0.2.19: "Last used" of a passkey is also the time of its last SIGNATURE (approve / refuse / mandate / key event / signature request),
    not only of its last sign-in. Called after the signature was verified and accepted; a failure here never fails the request."""
    t = int(time.time())
    try:
        for k in {bytes(k) for k in kids if isinstance(k, (bytes, bytearray))}:
            ctx.db.x("UPDATE credentials SET last_used_at=? WHERE kid=?", (t, k))
    except Exception:
        pass


SIGN_COUNT_REGRESSION = "SIGN_COUNT_REGRESSION"


def _assertions(env):
    """0.2.20: [(kid, authData, clientDataJSON, sig r||s)] of every passkey assertion inside a wa / wq / wb envelope ([] if unparsable)."""
    try:
        m = cbor2.loads(env)
    except Exception:
        return []
    if not isinstance(m, dict):
        return []
    ws = m.get("sigs") if m.get("v") == wq.V_WQ else [m]
    out, seen = [], set()
    for w in ws if isinstance(ws, list) else []:
        if not isinstance(w, dict) or not all(isinstance(w.get(k), bytes) for k in ("kid", "authData", "clientDataJSON", "sig")):
            continue
        if len(w["sig"]) != 64 or len(w["authData"]) < 37 or w["kid"] in seen:
            continue
        seen.add(w["kid"])
        out.append((w["kid"], w["authData"], w["clientDataJSON"], w["sig"]))
    return out


def _signed_by(pub, ad, cd, sig):
    """The key `pub` (65 bytes) signed authData || SHA-256(clientDataJSON): the counter in authData is the authenticator's, not forged."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(pub))
        key.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                   ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sign_count_ok(stored, new):
    """WebAuthn L3 6.1.1 / 7.2 step 21: when either counter is non-zero the new one must be STRICTLY greater; 0 and 0 = no counter
    (synced passkeys of Apple / Google), accepted. Counters are 32-bit unsigned (authData[33:37], big-endian); there is no wrap-around."""
    stored = int(stored or 0)
    return (new == 0 and stored == 0) or new > stored


def sign_count_refused(ctx, kid, stored, new, where, account_id=None, resent=False):
    """A counter that did not grow: log it (security journal, stdout JSON) and -> Err(409 SIGN_COUNT_REGRESSION). The passkey is NOT
    removed: removal is the owner's signed key event (keys.py, ledger); the server has no other freeze (a clone could lock the owner out).
    0.2.21: the person who holds the passkey is told (app/keyalert.py: a mark on Devices, at most one security push per key per 10 min),
    unless `resent` = the very assertion accepted last was sent again (a client retry, not a second authenticator)."""
    from app.log import log
    log("warn", SIGN_COUNT_REGRESSION, route=where, account=account_id, kid=bytes(kid).hex()[:16], stored=int(stored or 0), got=int(new),
        resent=bool(resent))
    if not resent:
        try:
            keyalert.raise_alert(ctx, kid, stored, new, where)
        except Exception as e:  # noqa - telling the owner never turns the refusal into a 500
            log("ERROR", "key alert failed: " + type(e).__name__)
    return Err(409, SIGN_COUNT_REGRESSION, "the signature counter of this passkey did not grow (%d after %d): an old signature, or a "
                                           "copy of the passkey; refused" % (int(new), int(stored or 0)))


def check_sign_counts(ctx, env, where, account_id=None):
    """0.2.20: the signature counter of every passkey that signed `env` (wa: one, wq: each wsig, wb: one), checked and stored ATOMICALLY.
    Called once per envelope a client presents, after the envelope was verified and before its effect is written. Only a counter the
    credential's own key signed is looked at (a forged authData never moves a counter). Unknown kid -> nothing to compare (the caller's
    key checks refuse it). Err(409 SIGN_COUNT_REGRESSION) when one did not grow; then NO counter of the envelope is moved."""
    items = []
    for kid, ad, cd, sig in _assertions(env):
        rows = ctx.db.q("SELECT pub, sign_count FROM credentials WHERE kid=?", (kid,))
        if not rows or not _signed_by(rows[0]["pub"], ad, cd, sig):
            continue
        items.append((kid, int.from_bytes(ad[33:37], "big"), max(int(r["sign_count"] or 0) for r in rows), keyalert.sig_hash(ad, cd, sig)))
    if not items or all(n == 0 and st == 0 for _, n, st, _ in items):
        return                                        # no counters (synced passkeys): nothing to store
    bad = None
    with ctx.db.tx() as db:                           # BEGIN IMMEDIATE under the writer lock: two requests with one counter -> one passes
        for kid, n, _, h in items:
            st = db.one("SELECT MAX(COALESCE(sign_count,0)) AS s FROM credentials WHERE kid=?", (kid,))["s"] or 0
            if not sign_count_ok(st, n):
                # 0.2.21: the identical assertion accepted last, sent again (a retry after a later check failed) is not a second authenticator
                resent = n == st and db.one("SELECT 1 AS k FROM credentials WHERE kid=? AND COALESCE(sign_count,0)=? AND last_sig=?", (kid, st, h)) is not None
                bad = (kid, st, n, resent)
                break
        if bad is None:
            for kid, n, _, h in items:
                if n:
                    db.x("UPDATE credentials SET sign_count=?, last_sig=? WHERE kid=? AND COALESCE(sign_count,0) < ?", (n, h, kid, n))
    if bad is not None:
        raise sign_count_refused(ctx, bad[0], bad[1], bad[2], where, account_id, resent=bad[3])


def env_kid(env):
    try:
        k = cbor2.loads(env).get("kid")
    except Exception:
        return None
    return k if isinstance(k, bytes) else None


def member_credential(ctx, account_id, user_id):
    """The credential a member signs with in this organisation: the active passkey whose kid the member row names, else the first."""
    m = member(ctx, account_id, user_id)
    if m and m["kid"] is not None:
        c = ctx.db.one("SELECT * FROM credentials WHERE user_id=? AND kid=? AND revoked_at IS NULL", (user_id, m["kid"]))
        if c:
            return c
    return credential_of(ctx, user_id)


def label_of(name):
    lab = "".join(ch for ch in (name or "") if ch != "@" and ord(ch) >= 32)[:32]
    return lab or "member"


def add_owner(db, account_id, user_id, kid):
    db.x("INSERT OR REPLACE INTO members(account_id,user_id,roles,kid,status) VALUES(?,?,?,?,?)",
         (account_id, user_id, json.dumps(list(SIGNERS)), kid, "active"))


def orgs_of(ctx, user_id, current):
    out = []
    for r in ctx.db.q("SELECT m.*, a.principal, a.display_name FROM members m JOIN accounts a ON a.id=m.account_id "
                      "WHERE m.user_id=? AND m.status<>'removed' ORDER BY a.created_at, a.id", (user_id,)):
        out.append({"account_id": r["account_id"], "principal": r["principal"], "name": r["display_name"],
                    "roles": json.loads(r["roles"]), "status": r["status"], "current": r["account_id"] == current})
    return out


# ---------------------------------------------------------------- settings
def settings(ctx, account_id):
    r = ctx.db.one("SELECT * FROM org_settings WHERE account_id=?", (account_id,))
    s = dict(DEFAULT_SETTINGS)
    if r:
        s.update({k: r[k] for k in DEFAULT_SETTINGS if r[k] is not None})
    return s


def put_settings(ctx, account_id, b):
    s = settings(ctx, account_id)
    for k in DEFAULT_SETTINGS:
        if k in b:
            s[k] = b[k]

    def rng(k, lo, hi):
        v = s[k]
        return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi
    if s["profile"] not in ("smb", "enterprise") or s["advisor"] not in ("off", "heuristic", "ner") or not rng("defer_ttl_s", 900, 3600) \
            or not rng("max_pending", 1, 100) or not rng("max_defers_hour", 1, 1000) or not rng("escalate_after_s", 60, 86400) or not rng("refusal_block_s", 60, 86400):
        raise Err(422, "BAD_SETTINGS", "profile smb|enterprise, defer_ttl_s 900..3600, max_pending 1..100, max_defers_hour 1..1000, "
                                       "escalate_after_s 60..86400, refusal_block_s 60..86400, advisor off|heuristic|ner")
    ctx.db.x("INSERT OR REPLACE INTO org_settings(account_id,profile,defer_ttl_s,max_pending,max_defers_hour,escalate_after_s,advisor,refusal_block_s) "
             "VALUES(?,?,?,?,?,?,?,?)", (account_id, s["profile"], s["defer_ttl_s"], s["max_pending"], s["max_defers_hour"],
                                        s["escalate_after_s"], s["advisor"], s["refusal_block_s"]))
    return s


# ---------------------------------------------------------------- policy
def chain(ctx, account_id):
    return ctx.hub.chain_of(account_id)


def current_policy(ctx, account_id):
    """-> (policy map, policy bytes, hash) of the version in force, or None (solo account)."""
    r = ctx.db.one("SELECT policy, hash FROM org_policies WHERE account_id=? ORDER BY ver DESC LIMIT 1", (account_id,))
    if not r:
        return None
    pb = bytes(r["policy"])
    return cbor2.loads(pb), pb, bytes(r["hash"])


def has_quorum_rules(policy):
    """Some rule needs k >= 2 (then deferred actions wait defer_ttl_s, 2.4)."""
    if policy is None:
        return False
    rl = policy["rules"]
    return any(q["k"] >= 2 for q in [rl["policy"], rl["revocation"], rl["ceiling"]] + rl["mandate"] + rl["approval"])


POLICY_DELAY_S = 72 * 3600      # 0.2.37: default wait of a delayed policy change (operator: DW_POLICY_DELAY_S seconds, at most 30 days)


def quorum_floor(policy):
    """0.2.37: the CURRENT quorum of a Team policy = the largest k of any of its rules (policy, mandate, approval, ceiling, recovery).
    1 = no quorum anywhere (a single owner organisation): then rule `policy` alone decides, as before."""
    if policy is None:
        return 1
    rl = policy["rules"]
    rs = [rl["policy"], rl["ceiling"]] + list(rl["mandate"]) + list(rl["approval"]) + ([rl["recovery"]] if rl.get("recovery") else [])
    return max([q["k"] for q in rs] + [1])


def policy_delay_s():
    try:
        v = int(os.environ.get("DW_POLICY_DELAY_S", POLICY_DELAY_S))
    except ValueError:
        v = POLICY_DELAY_S
    return min(v, 30 * 24 * 3600) if v > 0 else POLICY_DELAY_S


def defer_ttl(ctx, account_id, default):
    cur = current_policy(ctx, account_id)
    return settings(ctx, account_id)["defer_ttl_s"] if cur and has_quorum_rules(cur[0]) else default


def rp(ctx):
    return {"rp_id": ctx.cfg.rp_id, "origins": [ctx.cfg.origin]}


def policy_json(p):
    return json.loads(json.dumps(p, default=lambda b: b.hex() if isinstance(b, bytes) else str(b)))


def policy_draft(ctx, acc, user_id, body):
    """-> {req_id, typ, payload_b64, policy}. Empty chain: the draft IS the genesis (one member = the account's pinned key, all roles,
    all k = 1; body ignored). Else version N+1 from body {members:[{user_id, roles, label?}], rules}, signed by rule `policy` of N."""
    aid = acc["id"]
    apply_due(ctx, aid)
    ch = chain(ctx, aid)
    meta = {"by": user_id}
    if not ch:
        c = credential_of(ctx, aid)            # 0.2.2: an ACTIVE passkey of the account (the pinned one may have been removed)
        if c is None:
            raise Err(409, "KEY_NOT_PINNED", "the account has no active passkey")
        pub = bytes(c["pub"])
        u = ctx.db.one("SELECT display_name FROM users WHERE id=?", (c["user_id"],))
        members = [{"kid": bytes(c["kid"]), "pub": pub, "cred": bytes(c["credential_id"]), "roles": list(SIGNERS),
                    "label": label_of(u["display_name"] if u else "owner")}]
        pol = {"v": wq.V_POLICY, "principal": acc["principal"], "ver": 1, "prev": None, "members": members, "rules": GENESIS_RULES}
        needs, ph = [("owner", 1)], None
    else:
        prev = cbor2.loads(ch[-1][0])
        ms, seen = [], set()
        raw = body.get("members")
        if not isinstance(raw, list) or not raw:
            raise Err(422, "POLICY_MALFORMED", "members: [{user_id, roles, label?}]")
        for m in raw:
            uid = m.get("user_id") if isinstance(m, dict) else None
            mm = member(ctx, aid, uid) if isinstance(uid, str) else None
            if mm is None or "observer" in mm["roles"] or uid in seen:
                raise Err(422, "NOT_MEMBER", "user_id %s is not a (signing) member of this organisation" % str(uid)[:40])
            seen.add(uid)
            c = member_credential(ctx, aid, uid)
            if c is None:
                raise Err(422, "NOT_MEMBER", "user_id %s has no active passkey" % str(uid)[:40])
            u = ctx.db.one("SELECT display_name FROM users WHERE id=?", (uid,))
            lab = m.get("label") if m.get("label") is not None else label_of(u["display_name"] if u else "")
            roles = m.get("roles")
            if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
                raise Err(422, "POLICY_MALFORMED", "roles")
            ms.append({"kid": bytes(c["kid"]), "pub": bytes(c["pub"]), "cred": bytes(c["credential_id"]), "roles": list(roles), "label": lab})
        ms.sort(key=lambda x: x["kid"])
        rules = body.get("rules")
        if not isinstance(rules, dict) or rules.get("revocation") != REVOCATION_RULE:
            raise Err(422, "POLICY_MALFORMED", "rules.revocation must be {role: any, k: 1} (stopping takes one signature)")
        rules = dict(rules)
        if "delegation" not in rules and prev["rules"].get("delegation"):
            rules["delegation"] = prev["rules"]["delegation"]       # 0.2.15: a draft that does not mention the delegations keeps them
        elif rules.get("delegation") in (None, []):
            rules.pop("delegation", None)                           # explicit null / [] ends every delegation (no empty list in the map)
        keep = {m["kid"].hex() for m in ms}
        for d in rules.get("delegation") or ():
            if isinstance(d, dict) and isinstance(d.get("approvers"), list) and any(k not in keep for k in d["approvers"]):
                raise Err(422, "POLICY_MALFORMED", "the delegation of agent %s names an approver who is not in this version: change the "
                                                   "delegation first" % str(d.get("agent"))[:40])
        if not any("owner" in m["roles"] for m in ms if isinstance(m["roles"], list)):
            raise Err(422, "POLICY_MALFORMED", "at least one member keeps the owner role")
        pol = {"v": wq.V_POLICY, "principal": acc["principal"], "ver": len(ch) + 1, "prev": hashlib.sha256(ch[-1][0]).digest(),
               "members": ms, "rules": rules}
        needs, ph = wq.requirements(prev, wq.TYP_POLICY, None), hashlib.sha256(ch[-1][0]).digest()
        K = quorum_floor(prev)
        if K >= 2:      # 0.2.37: a Team policy changes only with the CURRENT quorum (K distinct members, the owner among them), or after a delay
            if body.get("delayed") is True:
                meta["delayed"], meta["delay_s"] = True, policy_delay_s()
            else:
                needs, meta["floor"] = [("owner", 1), ("any", K)], K
    try:
        bad = wq.validate_policy(pol)
        payload = wa.cde(pol)
    except Exception:
        bad = "POLICY_MALFORMED"
    if bad:
        raise Err(422, bad, "the policy map does not satisfy ARHITEKTURA-0.2 2.2")
    with ctx.hub.lock(aid):
        ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE account_id=? AND kind='policy' AND status='collecting' "
                 "AND (json_extract(meta,'$.by')=? OR expires<=?)", (aid, user_id, now()))      # R3-16: only your own draft (or an expired one)
        sid = new_request(ctx, aid, "policy", str(pol["ver"]), wq.TYP_POLICY, payload, ph, needs, meta)
    return {"req_id": sid, "typ": wq.TYP_POLICY, "payload_b64": wa.b64u(payload), "policy": policy_json(pol), "genesis": not ch,
            "needs": [{"role": r, "k": k} for r, k in needs], "delayed": bool(meta.get("delayed")), "delay_s": meta.get("delay_s")}


def _fresh_second(ctx, account_id, floor):
    """A policy version takes effect at a second no ledger entry of the account has used yet and later than `floor`, so that the second
    pass (policy[v].t <= entry.t < policy[v+1].t) puts every earlier entry under the old version. Caller holds hub.lock(account_id)."""
    L = ctx.hub.ledger(account_id)
    last = max(L.sync_now(), floor)
    for _ in range(40):
        t = int(time.time())
        if t > last:
            return t
        time.sleep(0.05)
    return last + 1


def adopt_policy(ctx, account_id, payload, env):
    """Verify the extended chain, append it to registry_log (hash chain, hourly anchor) and org_policies, sync members, re-base open
    requests. Caller holds hub.lock(account_id). -> new version number."""
    db = ctx.db
    ch = chain(ctx, account_id)
    t = _fresh_second(ctx, account_id, ch[-1][2] if ch else 0)
    cand = ch + [(payload, env, t)]
    bad = wq.verify_policy_chain(cand, rp=rp(ctx))
    if bad:
        raise Err(409, bad[0], "policy version %d" % bad[1])
    pol = cbor2.loads(payload)
    h = hashlib.sha256(payload).digest()
    rec = {"principal": pol["principal"], "ver": pol["ver"], "hash": h.hex()}
    sw = wq.key_swap(cbor2.loads(ch[-1][0]), pol) if ch else None
    if sw is not None:              # 0.2.2: a key replacement is named in the registry log itself (the pack shows the row)
        rec["key_swap"] = {"old_kid": sw[0].hex(), "new_kid": sw[1].hex()}
    ej = json.dumps({"org_policy": rec}, sort_keys=True, separators=(",", ":"))
    with db.tx():
        # account_id "org:<id>": the row is in the registry chain (anchored) but is not the account's pinned key record
        seq = reglog.append(db, "org:" + account_id, None, ej, t)
        db.x("INSERT INTO org_policies(account_id,ver,policy,envelope,hash,registry_seq,t) VALUES(?,?,?,?,?,?,?)",
             (account_id, pol["ver"], payload, env, h, seq, t))
        listed = {}
        for m in pol["members"]:
            c = db.one("SELECT user_id FROM credentials WHERE kid=?", (m["kid"],))
            if c:
                listed[c["user_id"]] = m
        for r in db.q("SELECT * FROM members WHERE account_id=?", (account_id,)):
            roles = json.loads(r["roles"] or "[]")
            if r["user_id"] in listed:
                m = listed.pop(r["user_id"])
                db.x("UPDATE members SET roles=?, kid=?, status='active' WHERE account_id=? AND user_id=?",
                     (json.dumps(m["roles"]), m["kid"], account_id, r["user_id"]))
            elif r["status"] == "active" and roles != ["observer"]:
                db.x("UPDATE members SET status='removed' WHERE account_id=? AND user_id=?", (account_id, r["user_id"]))
                db.x("DELETE FROM push_subs WHERE account_id=? AND user_id=?", (account_id, r["user_id"]))      # R3-07
        for uid, m in listed.items():          # a listed key whose user is not a member row yet (cannot happen via the API; kept safe)
            db.x("INSERT OR REPLACE INTO members(account_id,user_id,roles,kid,status) VALUES(?,?,?,?,?)",
                 (account_id, uid, json.dumps(m["roles"]), m["kid"], "active"))
        from app import export_tokens
        export_tokens.revoke_unentitled(db, account_id)     # 0.2.46: removed or no longer an owner -> the export tokens they issued end
    ctx.hub.policy_changed(account_id)
    from app import delegation
    delegation.sync_from_policy(ctx, account_id, cbor2.loads(ch[-1][0]) if ch else None, pol, t)      # 0.2.15: the signed policy decides
    _rebase(ctx, account_id, pol, h)
    return pol["ver"]


def _rebase(ctx, account_id, pol, h):
    """Open mandate / approval requests move to the new version: wsigs sign only typ+payload, so the signatures of members that stay
    are kept; the needs are recomputed by the new rules. Open policy requests are void (they name the old version)."""
    kids = {m["kid"] for m in pol["members"]}
    ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE account_id=? AND kind='policy' AND status='scheduled'", (account_id,))
    for r in ctx.db.q("SELECT * FROM sig_requests WHERE account_id=? AND status='collecting'", (account_id,)):
        if r["kind"] in ("policy", "phone_lift"):        # 0.2.15: a phone-lift quorum is judged by the version it was opened under
            ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE id=?", (r["id"],))
            continue
        sigs = [s for s in _sigs(r) if s["kid"] in kids]
        meta = json.loads(r["meta"] or "{}")
        needs = _needs_for(ctx, pol, r["kind"], r["typ"], bytes(r["payload"]), meta)
        ctx.db.x("UPDATE sig_requests SET policy_hash=?, needs=?, sigs=? WHERE id=?", (h, json.dumps(needs), _sigs_json(sigs), r["id"]))


def is_team(ctx, account_id):
    """r0284: True when the account has someone besides its first person: another member (not removed) or an open invite."""
    n = ctx.db.one("SELECT COUNT(*) AS n FROM members WHERE account_id=? AND status<>'removed'", (account_id,))["n"]
    if n > 1:
        return True
    return ctx.db.one("SELECT 1 AS k FROM invites WHERE account_id=? AND used_by IS NULL AND expires>=?", (account_id, now())) is not None


# ---------------------------------------------------------------- invites
def create_invite(ctx, account_id, roles):
    if not isinstance(roles, list) or not roles or len(set(roles)) != len(roles) or any(r not in ROLES for r in roles) or \
            ("observer" in roles and len(roles) > 1):
        raise Err(422, "BAD_ROLES", "roles: a non-empty subset of owner/budget/access, or exactly [observer]")
    tok = secrets.token_urlsafe(32)
    ctx.db.x("INSERT INTO invites(token_hash,account_id,roles,expires,used_by) VALUES(?,?,?,?,NULL)",
             (hashlib.sha256(tok.encode()).digest(), account_id, json.dumps(roles), now() + INVITE_TTL))
    return {"url": "%s/join.html?token=%s" % (ctx.cfg.origin, tok), "expires": now() + INVITE_TTL, "roles": roles}


def join(ctx, user_id, token):
    """One-time, 24 h. Observer -> active at once; signing roles -> pending until a policy version lists the member."""
    if not isinstance(token, str) or not 8 <= len(token) <= 200:
        raise Err(409, "INVITE_INVALID")
    th = hashlib.sha256(token.encode()).digest()
    inv = ctx.db.one("SELECT * FROM invites WHERE token_hash=?", (th,))
    if inv is None or inv["used_by"] is not None or inv["expires"] < now():
        raise Err(409, "INVITE_INVALID", "the invite is unknown, used or expired")
    old = member(ctx, inv["account_id"], user_id)
    if old is not None and old["status"] != "removed":
        raise Err(409, "ALREADY_MEMBER")
    with ctx.db.tx():
        if ctx.db.n("UPDATE invites SET used_by=? WHERE token_hash=? AND used_by IS NULL AND expires>=?", (user_id, th, now())) != 1:
            raise Err(409, "INVITE_INVALID", "the invite is unknown, used or expired")
        roles = json.loads(inv["roles"])
        status = "active" if roles == ["observer"] else "pending"
        ctx.db.x("INSERT OR REPLACE INTO members(account_id,user_id,roles,kid,status) VALUES(?,?,?,?,?)",
                 (inv["account_id"], user_id, json.dumps(roles), user_kid(ctx, user_id), status))
    return {"account_id": inv["account_id"], "status": status, "roles": roles}


# ---------------------------------------------------------------- signature requests
def _sigs(r):
    return [{k: bytes.fromhex(v) for k, v in s.items()} for s in json.loads(r["sigs"] or "[]")]


def _sigs_json(sigs):
    return json.dumps([{k: v.hex() for k, v in s.items()} for s in sigs])


def _needs_for(ctx, pol, kind, typ, payload, meta):
    if kind == "mandate":
        return wq.requirements(pol, typ, cbor2.loads(payload))
    if kind == "approval":
        reqs = wq.requirements(pol, typ, None, meta.get("action"))
        return reqs if meta.get("approved") else [(r, 1) for r, _ in reqs]      # refusing (stopping) takes one signer of the role
    return wq.requirements(pol, typ, None)


def new_request(ctx, account_id, kind, ref, typ, payload, policy_hash, needs, meta, expires=None, push_kind="s"):
    sid = "sr_" + secrets.token_hex(8)
    ctx.db.x("INSERT INTO sig_requests(id,account_id,kind,ref,typ,payload,policy_hash,needs,sigs,status,created_at,expires,meta) "
             "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
             (sid, account_id, kind, ref, typ, payload, policy_hash, json.dumps(needs), "[]", "collecting", now(),
              expires or now() + SIGREQ_TTL, json.dumps(meta)))
    if kind in ("mandate", "approval", "policy", "phone_lift") and getattr(ctx, "push", None) is not None:
        ctx.push.notify_sigreq(account_id, sid, k=push_kind)   # 0.2.0 (08 x 01): the signers a quorum still needs get a push (RT-SUP: "v" = a replacement)
    return sid


def request_row(ctx, account_id, sid):
    r = ctx.db.one("SELECT * FROM sig_requests WHERE id=? AND account_id=?", (sid, account_id)) if isinstance(sid, str) else None
    if r is None:
        raise Err(404, "NOT_FOUND")
    return r


def _need_n(needs):
    return max([k for _, k in needs] or [1])


def request_view(r, full=False, ctx=None):
    needs = [tuple(x) for x in json.loads(r["needs"] or "[]")]
    sigs = _sigs(r)
    v = {"id": r["id"], "kind": r["kind"], "ref": r["ref"], "typ": r["typ"], "needs": [{"role": a, "k": k} for a, k in needs],
         "have": len(sigs), "need": _need_n(needs), "status": r["status"], "signed_by": [s["kid"].hex() for s in sigs],
         "created_at": r["created_at"], "expires": r["expires"]}
    if r["status"] == "scheduled":
        v["effective_at"] = (json.loads(r["meta"] or "{}")).get("effective_at")
    if full:
        meta = json.loads(r["meta"] or "{}")
        # 0.2.0 merge (01 <-> 05): `body` = exactly what the browser encodes to CDE and compares with payload_b64 byte for byte (as stub02,
        # the reference of contract 00): policy -> the policy map (bytes as hex), mandate -> the mandate map, approval -> {rid, mandate,
        # action, approved}. The server's own notes go to `meta`.
        if r["kind"] in ("mandate", "policy"):
            body = policy_json(cbor2.loads(bytes(r["payload"])))
        elif r["kind"] == "approval" and ctx is not None:
            x = ctx.db.one("SELECT action_json, mandate_id FROM actions WHERE rid=? AND account_id=?", (r["ref"], r["account_id"]))
            mrow = ctx.db.one("SELECT mandate_json FROM mandates WHERE id=?", (x["mandate_id"],)) if x and x["mandate_id"] else None
            body = {"rid": r["ref"], "approved": bool(meta.get("approved")), "action": json.loads(x["action_json"]) if x else None,
                    "mandate": json.loads(mrow["mandate_json"]) if mrow else None}
            if isinstance(meta.get("view"), str):
                body["view"] = meta["view"]      # pv2: the presentation hash in the stored payload (the page checks it against GET /api/approvals/{rid})
        elif r["kind"] == "phone_lift":
            pm = cbor2.loads(bytes(r["payload"]))
            body = {k: (v_.hex() if isinstance(v_, bytes) else v_) for k, v_ in pm.items()}
        else:
            body = {}
        v.update(payload_b64=wa.b64u(bytes(r["payload"])), policy_hash_b64=wa.b64u(bytes(r["policy_hash"])) if r["policy_hash"] else None,
                 body=body, meta={k: meta[k] for k in ("approved", "delayed", "effective_at", "toolmap_sha256", "agent_id", "recovery", "gateway", "gateway_prev", "phone_lift", "delegation",
                                               "superseded_by", "why", "replaces", "dropped") if k in meta})       # RT-SUP 29.10: a replacement is visible
    return v


def open_requests(ctx, account_id, user_id):
    """Requests the user can sign now: collecting, not expired, a role of the user is needed, not signed by the user yet."""
    m = member(ctx, account_id, user_id)
    kid = m["kid"] if m else None
    out = []
    apply_due(ctx, account_id)
    if m is None or m["status"] != "active" or not any(r in SIGNERS for r in m["roles"]):
        return out                            # the observer signs nothing (2.1)
    for r in ctx.db.q("SELECT * FROM sig_requests WHERE account_id=? AND status='collecting' AND expires>=? ORDER BY created_at",
                      (account_id, now())):
        needs = [tuple(x) for x in json.loads(r["needs"] or "[]")]
        if any(s["kid"] == kid for s in _sigs(r)):
            continue
        if r["kind"] == "phone_lift" and (json.loads(r["meta"] or "{}").get("phone_lift") or {}).get("user_id") == user_id:
            continue                          # 0.2.15: the person whose phone waits does not vouch for it
        if r["kind"] == "approval" and json.loads(r["meta"] or "{}").get("approved"):
            from app import delegation
            if delegation.sigreq_excluded(ctx, account_id, r) == user_id:
                continue                      # 0.2.13: the operator of a delegated agent does not confirm its actions
        if not needs or any(role == "any" or role in m["roles"] for role, _ in needs):
            out.append(request_view(r))
    return out


def wrap_single(env, policy_hash):
    """A plain wa-sig of a member -> wq with that one wsig under the given policy (2.3: the browser always signs a plain wa-sig)."""
    w = wq.wsig_of_wa(env)
    m = cbor2.loads(env)
    return wq.make_wq(m["typ"], m["payload"], policy_hash, [w])


def sign_request(ctx, acc, user_id, sid, env):
    """Add the user's wa-sig to a request; at quorum apply it. -> SigProgress {status, have, need, ...}."""
    aid = acc["id"]
    with ctx.hub.lock(aid):
        r = request_row(ctx, aid, sid)
        if r["status"] != "collecting" or r["expires"] < now():
            raise Err(409, "SIGREQ_CLOSED", "this request is %s" % ("expired" if r["status"] == "collecting" else r["status"]))
        if wq.envelope_kind(env) != "wa":
            raise Err(409, "WA_MALFORMED", "submit the ordinary wa-sig of your passkey")
        typ, payload = r["typ"], bytes(r["payload"])
        kid = env_kid(env)
        entry = user_entry(ctx, user_id, kid)          # 0.2.2: the envelope's own key, if it is an ACTIVE passkey of this user
        code = wa.verify_envelope(env, typ, payload, entry) if entry else "KEY_NOT_PINNED"
        if code:
            raise Err(409, wq.SIG_CODE.get(typ, code) if code == "MANDATE_SIG" else code)
        touch_kids(ctx, [kid])                    # 0.2.19: a verified signature = the passkey was used
        ch = chain(ctx, aid)
        meta = json.loads(r["meta"] or "{}")
        rec = meta.get("recovery")
        if rec and kid.hex() == rec.get("old_kid"):
            raise Err(409, "RECOVERY_SELF", "the key being replaced never signs its own replacement")
        pl = meta.get("phone_lift") if r["kind"] == "phone_lift" else None
        if pl and user_id == pl.get("user_id"):
            raise Err(409, "RECOVERY_SELF", "the person whose new phone waits never vouches for it: two other members do")
        if r["kind"] == "policy" and not ch:                    # genesis: the wa-sig of the pinned key IS the envelope
            pol = cbor2.loads(payload)
            if [m["kid"] for m in pol["members"]] != [kid]:
                raise Err(409, "POLICY_MALFORMED", "genesis is signed by its single member")
            check_sign_counts(ctx, env, "sigreq:policy", aid)         # 0.2.20
            ver = adopt_policy(ctx, aid, payload, env)
            ctx.db.x("UPDATE sig_requests SET sigs=?, status='done' WHERE id=?", (_sigs_json([wq.wsig_of_wa(env)]), sid))
            return {"status": "done", "have": 1, "need": 1, "policy_ver": ver}
        if not ch:
            raise Err(409, "WQ_POLICY_UNKNOWN", "the organisation has no policy")
        pol = cbor2.loads(ch[-1][0])
        cur_hash = hashlib.sha256(ch[-1][0]).digest()
        if bytes(r["policy_hash"] or b"") != cur_hash:
            raise Err(409, "WQ_POLICY_UNKNOWN", "the request names a policy that is not in force")
        members = {m["kid"]: m for m in pol["members"]}
        if kid not in members:
            raise Err(409, "WQ_NOT_MEMBER", "your key is not in policy v%d" % pol["ver"])
        sigs = _sigs(r)
        if any(s["kid"] == kid for s in sigs):
            raise Err(409, "WQ_DUP_SIGNER", "you have signed this request already")
        needs = [tuple(x) for x in json.loads(r["needs"] or "[]")]
        if needs and not any(role == "any" or role in members[kid]["roles"] for role, _ in needs):
            raise Err(403, "ROLE_NOT_NEEDED", "this request needs %s" % ", ".join("%s k=%d" % n for n in needs))
        if r["kind"] == "approval":                 # 0.2.13: delegation (no self-approval) and confirmation levels, before the signature is counted
            from app import delegation, levels
            x = ctx.db.one("SELECT agent_id, action_json, reason, level_min FROM actions WHERE rid=? AND account_id=?", (r["ref"], aid))
            if isinstance(meta.get("view"), str):       # pv2: under this lock, the view the request names must still be the rows' view
                vm = getattr(ctx, "view_match", None)
                if vm is None:
                    raise Err(409, "VIEW_CHANGED", "the witness cannot rebuild the view of this request")
                vm(acc, r["ref"], user_id, bytes.fromhex(meta["view"]))
            else:                                       # r0352 (KAND-ACH-1): a request that names no view, while the witness has one
                vr = getattr(ctx, "view_required", None)
                if vr is None or vr(acc, r["ref"], user_id):
                    from app.signview import VIEW_REQUIRED_TEXT
                    raise Err(409, "VIEW_REQUIRED", VIEW_REQUIRED_TEXT)
            if x is not None:
                delegation.check_approval(ctx, aid, x["agent_id"], [kid], bool(meta.get("approved")), json.loads(x["action_json"] or "{}"))
                if meta.get("approved"):
                    levels.check_signers(ctx, aid, [kid], json.loads(x["action_json"] or "{}"), x["reason"], x["level_min"])
        check_sign_counts(ctx, env, "sigreq:" + str(r["kind"]), aid)   # 0.2.20: counted once, here; the wq built below is not counted again
        sigs.append(wq.wsig_of_wa(env))
        env_q = wq.make_wq(typ, payload, cur_hash, sigs)
        action = meta.get("action") if r["kind"] == "approval" and meta.get("approved") else None
        if r["kind"] == "phone_lift":       # 0.2.15: rule `recovery` of the policy in force (k >= 2 OTHER members)
            rc = pol["rules"].get("recovery")
            code = wq.verify_wq(env_q, typ, payload, ch, rp=rp(ctx), rule=rc) if rc else "WQ_QUORUM"
            if code is None and any(_user_of(ctx, s["kid"]) == pl.get("user_id") for s in sigs):
                code = "RECOVERY_SELF"
        elif r["kind"] == "policy":        # 0.2.2: the same step the pack checker replays (rule `policy`, or `recovery` for a key swap)
            code = wq.policy_step(ch, payload, env_q, rp(ctx))
            if code is None and not rec and meta.get("floor") and len({s["kid"] for s in sigs}) < meta["floor"]:
                code = "WQ_QUORUM"            # 0.2.37: the owner alone is not the current quorum
            if code is None and rec and rec.get("rule") == "recovery":
                # a recovery request completes on what it SHOWS (k of the rule `recovery`), even where the rule `policy` alone would do
                code = wq.verify_wq(env_q, typ, payload, ch, rp=rp(ctx), rule=pol["rules"]["recovery"])
        else:
            agent = x["agent_id"] if r["kind"] == "approval" and meta.get("approved") and x is not None else None
            code = wq.verify_wq(env_q, typ, payload, ch, action=action, rp=rp(ctx), agent=agent)      # 0.2.15: the signed delegation
        if code is None and r["kind"] == "approval" and not meta.get("approved"):
            code = None if _met(members, sigs, needs) else "WQ_QUORUM"
        if code == "WQ_QUORUM":
            ctx.db.x("UPDATE sig_requests SET sigs=? WHERE id=?", (_sigs_json(sigs), sid))
            return {"status": "collecting", "have": len(sigs), "need": _need_n(needs), "req_id": sid}
        if code:
            raise Err(409, code)
        if r["kind"] == "policy" and meta.get("delayed") and not rec:       # 0.2.37: the owner's signature schedules, it does not apply
            eff = now() + int(meta.get("delay_s") or policy_delay_s())
            meta.update(effective_at=eff, env_q_hex=env_q.hex())
            ctx.db.x("UPDATE sig_requests SET sigs=?, status='scheduled', meta=? WHERE id=?", (_sigs_json(sigs), json.dumps(meta), sid))
            _digest(ctx, aid, "policy_delay")
            return {"status": "scheduled", "have": len(sigs), "need": _need_n(needs), "req_id": sid, "effective_at": eff}
        res = _apply(ctx, acc, r, meta, payload, env_q)
        ctx.db.x("UPDATE sig_requests SET sigs=?, status='done' WHERE id=?", (_sigs_json(sigs), sid))
        return dict({"status": "done", "have": len(sigs), "need": _need_n(needs), "req_id": sid}, **res)


def _digest(ctx, aid, kind):
    try:
        if getattr(ctx, "notify", None) is not None:
            ctx.notify.digest(aid, kind)       # 0.2.25 channels (Telegram / Slack / e-mail), queued, never breaks the caller
    except Exception:
        pass


def apply_due(ctx, account_id=None):
    """0.2.37: delayed policy changes whose wait is over -> adopted (the owner's stored wq is judged again against the chain in force;
    a chain that moved on meanwhile voids it). -> number applied. Lazy (every policy / request path) and periodic (main.py)."""
    n = 0
    q = "SELECT * FROM sig_requests WHERE kind='policy' AND status='scheduled' AND json_extract(meta,'$.effective_at')<=?"
    rows = ctx.db.q(q + (" AND account_id=?" if account_id else ""), (now(),) + ((account_id,) if account_id else ()))
    for r in rows:
        aid = r["account_id"]
        with ctx.hub.lock(aid):
            r = ctx.db.one("SELECT * FROM sig_requests WHERE id=? AND status='scheduled'", (r["id"],))
            if r is None:
                continue
            ch = chain(ctx, aid)
            meta = json.loads(r["meta"] or "{}")
            payload = bytes(r["payload"])
            env_q = bytes.fromhex(meta.get("env_q_hex") or "")
            if not ch or bytes(r["policy_hash"] or b"") != hashlib.sha256(ch[-1][0]).digest() or wq.policy_step(ch, payload, env_q, rp(ctx)):
                ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE id=?", (r["id"],))
                continue
            try:
                adopt_policy(ctx, aid, payload, env_q)
            except Err:
                ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE id=?", (r["id"],))
                continue
            ctx.db.x("UPDATE sig_requests SET status='done' WHERE id=?", (r["id"],))
            n += 1
    return n


def scheduled_changes(ctx, account_id):
    out = []
    for r in ctx.db.q("SELECT * FROM sig_requests WHERE account_id=? AND kind='policy' AND status='scheduled' ORDER BY created_at", (account_id,)):
        m = json.loads(r["meta"] or "{}")
        out.append({"id": r["id"], "ver": r["ref"], "effective_at": m.get("effective_at"), "by": m.get("by"), "created_at": r["created_at"]})
    return out


def cancel_scheduled(ctx, acc, user_id, sid):
    """0.2.37: ANY current member (signing role, active, key in the policy in force) stops a scheduled policy change."""
    aid = acc["id"]
    with ctx.hub.lock(aid):
        r = request_row(ctx, aid, sid)
        if r["kind"] != "policy" or r["status"] != "scheduled":
            raise Err(409, "SIGREQ_CLOSED", "no scheduled policy change with this id")
        ch = chain(ctx, aid)
        m = member(ctx, aid, user_id)
        if not ch or m is None or m["status"] != "active" or m["kid"] not in {x["kid"] for x in cbor2.loads(ch[-1][0])["members"]}:
            raise Err(403, "WQ_NOT_MEMBER", "only a current member of the policy in force cancels it")
        ctx.db.x("UPDATE sig_requests SET status='cancelled' WHERE id=?", (sid,))
    _digest(ctx, aid, "policy_delay_cancelled")
    return {"status": "cancelled", "req_id": sid}


def _met(members, sigs, needs):
    """Refusal: one signer holding any needed role (or any member when nothing is needed)."""
    if not needs:
        return bool(sigs)
    return any(role == "any" or role in members[s["kid"]]["roles"] for s in sigs for role, _ in needs)


def _apply(ctx, acc, r, meta, payload, env_q):
    from app import actions as act
    if r["kind"] == "policy":
        return {"policy_ver": adopt_policy(ctx, acc["id"], payload, env_q)}
    if r["kind"] == "mandate":
        m = cbor2.loads(payload)
        try:
            out = act.register_mandate(ctx, acc, m, env_q, meta.get("toolmap_sha256"), meta.get("guards"), counted=True)
        except Err as e:
            if e.code in ("TOOLMAP_CHANGED", "DATA_PATTERNS_CHANGED", "MANDATE_EXISTS", "MANDATE_ID_TAKEN", "NOT_FOUND"):
                ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE id=?", (r["id"],))     # can never apply: draft again
            raise
        return {"mandate_id": out["mandate_id"], "mandate_status": out["status"], "ledger_seq": out["ledger_seq"]}
    if r["kind"] == "phone_lift":
        from app import keys
        pl = meta["phone_lift"]
        t = now()
        with ctx.db.tx() as db:
            done = keys.lift_phone_wait(db, pl["user_id"], bytes.fromhex(pl["kid"]), "team-quorum", t,
                                        {"org": "dw:" + acc["id"], "req_id": r["id"], "payload_hex": payload.hex(), "envelope_hex": env_q.hex()})
        if not done:
            raise Err(409, "NOT_PENDING", "this passkey is no longer waiting (cancelled, removed or already a phone)")
        keys._security_push(ctx, pl["user_id"], "d")
        return {"phone_lifted": pl["kid"]}
    if r["kind"] == "approval":
        vh = bytes.fromhex(meta["view"]) if isinstance(meta.get("view"), str) else None      # pv2: the view the stored payload names
        out = act.approve_with_envelope(ctx, acc, r["ref"], bool(meta.get("approved")), env_q, counted=True, view=vh)
        ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE account_id=? AND kind='approval' AND ref=? AND id<>? AND status='collecting'",
                 (acc["id"], r["ref"], r["id"]))
        return {"verdict": out["verdict"]}
    raise Err(409, "SIGREQ_KIND")


def key_replace_request(ctx, acc, user_id, target_user):
    """0.2.2: a member lost the passkey the policy names. Opens a policy request whose ONLY change is that member's key -> the newest
    active passkey of the same person (added with a recovery code or on another device). Judged by rule `recovery` of the policy in
    force when it has one (k >= 2 OTHER members; the lost key never counts), else by rule `policy`. -> {req_id, needs, old_kid, new_kid}."""
    aid = acc["id"]
    ch = chain(ctx, aid)
    if not ch:
        raise Err(409, "WQ_POLICY_UNKNOWN", "a solo account recovers with a recovery code, not a quorum")
    if not isinstance(target_user, str):
        raise Err(422, "BAD_REQUEST", "user_id")
    tm = member(ctx, aid, target_user)
    prev = cbor2.loads(ch[-1][0])
    by_kid = {m["kid"]: m for m in prev["members"]}
    if tm is None or tm["kid"] not in by_kid:
        raise Err(422, "NOT_MEMBER", "this person holds no key in the policy in force")
    old = tm["kid"]
    new = ctx.db.one("SELECT * FROM credentials WHERE user_id=? AND revoked_at IS NULL AND kid<>? ORDER BY id DESC LIMIT 1", (target_user, old))
    if new is None:
        raise Err(409, "NO_NEW_KEY", "the person has no other active passkey yet: they add one first (recovery code or another device)")
    nk = bytes(new["kid"])
    if nk in by_kid:
        raise Err(409, "NO_NEW_KEY", "that passkey is already in the policy")
    ms = []
    for m in prev["members"]:
        m = dict(m)
        if m["kid"] == old:
            m.update(kid=nk, pub=bytes(new["pub"]), cred=bytes(new["credential_id"]))
        ms.append(m)
    ms.sort(key=lambda x: x["kid"])
    pol = {"v": wq.V_POLICY, "principal": acc["principal"], "ver": len(ch) + 1, "prev": hashlib.sha256(ch[-1][0]).digest(),
           "members": ms, "rules": wq.swap_rules(prev["rules"], old, nk)}       # 0.2.15: the delegations follow the person's new key
    if wq.validate_policy(pol) or wq.key_swap(prev, pol) != (old, nk):
        raise Err(422, "POLICY_MALFORMED")
    rc = prev["rules"].get("recovery")
    needs = [(rc["role"], rc["k"])] if rc else wq.requirements(prev, wq.TYP_POLICY, None)
    payload = wa.cde(pol)
    with ctx.hub.lock(aid):
        ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE account_id=? AND kind='policy' AND status='collecting'", (aid,))
        sid = new_request(ctx, aid, "policy", str(pol["ver"]), wq.TYP_POLICY, payload, hashlib.sha256(ch[-1][0]).digest(), needs,
                          {"by": user_id, "recovery": {"user_id": target_user, "old_kid": old.hex(), "new_kid": nk.hex(), "rule": "recovery" if rc else "policy"}})
    return {"req_id": sid, "needs": [{"role": r, "k": k} for r, k in needs], "old_kid": old.hex(), "new_kid": nk.hex(),
            "rule": "recovery" if rc else "policy", "sign_url": "%s/sign.html?req=%s" % (ctx.cfg.origin, sid)}


def _user_of(ctx, kid):
    r = ctx.db.one("SELECT user_id FROM credentials WHERE kid=? ORDER BY id DESC LIMIT 1", (kid,)) if isinstance(kid, bytes) else None
    return r["user_id"] if r else None


def phone_lift_request(ctx, acc, user_id, target_user):
    """0.2.15: a member declared a new phone with a recovery code; it waits 24-72 h. The team may end the wait early: a request signed
    by rule `recovery` of the policy in force (k >= 2 members, never the person themself). -> {req_id, needs, kid, not_before}."""
    aid = acc["id"]
    ch = chain(ctx, aid)
    if not ch:
        raise Err(409, "WQ_POLICY_UNKNOWN", "only a team with a signed policy can vouch for a new phone")
    pol = cbor2.loads(ch[-1][0])
    rc = pol["rules"].get("recovery")
    if rc is None:
        raise Err(409, "NO_RECOVERY_RULE", "the team policy has no `recovery` rule (k >= 2): the wait cannot be shortened")
    tm = member(ctx, aid, target_user) if isinstance(target_user, str) else None
    if tm is None or tm["status"] != "active":
        raise Err(422, "NOT_MEMBER", "user_id: an active member of this organisation")
    c = ctx.db.one("SELECT * FROM credentials WHERE user_id=? AND revoked_at IS NULL AND device='phone' AND phone_nb>? ORDER BY id DESC LIMIT 1",
                   (target_user, now()))
    if c is None:
        raise Err(409, "NOT_PENDING", "this person has no new phone waiting")
    kid = bytes(c["kid"])
    payload = wq.phone_lift_payload("dw:" + target_user, kid, c["phone_nb"], os.urandom(16))
    with ctx.hub.lock(aid):
        ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE account_id=? AND kind='phone_lift' AND ref=? AND status='collecting'", (aid, kid.hex()))
        sid = new_request(ctx, aid, "phone_lift", kid.hex(), wq.TYP_PHONE_LIFT, payload, hashlib.sha256(ch[-1][0]).digest(), [(rc["role"], rc["k"])],
                          {"by": user_id, "phone_lift": {"user_id": target_user, "kid": kid.hex(), "not_before": c["phone_nb"]}})
    return {"req_id": sid, "needs": [{"role": rc["role"], "k": rc["k"]}], "kid_hex": kid.hex(), "not_before": c["phone_nb"],
            "sign_url": "%s/sign.html?req=%s" % (ctx.cfg.origin, sid)}


def mandate_request(ctx, acc, user_id, m, toolmap_sha256, guards=None, gateway=None):
    """With a policy: the mandate draft opens a quorum request. -> (req_id, needs) or None (solo account)."""
    cur = current_policy(ctx, acc["id"])
    if cur is None:
        return None
    pol, _, h = cur
    needs = wq.requirements(pol, wa.TYP_MANDATE, m)
    sid = new_request(ctx, acc["id"], "mandate", m["id"], wa.TYP_MANDATE, wa.cde(wire.cbor_form(m)), h, needs,
                      {"toolmap_sha256": toolmap_sha256, "guards": list(guards) if guards else None, "agent_id": m["agent"], "by": user_id,
                       "gateway": gateway, "gateway_prev": _prev_gateway(ctx, acc["id"], m["agent"])})        # 0.2.5 (R4-05): the document the hash binds, for the co-signer's page
    return sid, needs


def _prev_gateway(ctx, account_id, agent_id):
    """The gateway document of the agent's mandate in force (None: no mandate / one of 0.2.0-0.2.3): what the co-signer's page compares the new document with."""
    r = ctx.db.one("SELECT gateway_doc FROM mandates WHERE account_id=? AND agent_id=? AND status='active' ORDER BY created_at DESC, rowid DESC LIMIT 1", (account_id, agent_id))
    try:
        return json.loads(r["gateway_doc"]) if r and r["gateway_doc"] else None
    except ValueError:
        return None


SUPERSEDE_CAP = 3          # RT-SUP 29.10: replacements of a signed approval request on a changed view, per action; the next one -> 409 VIEW_UNSTABLE


def approval_request(ctx, acc, user_id, rid, approved, payload, action, expires, view=None, view_current=False):
    """Find or open the request that collects approvals (or refusals) of one deferred action.
    pv2: view = the presentation hash the first signer's page signed (in the stored payload and in meta.view), or None (an older page:
    the approval is marked "view not signed"). A later signer whose page claims another view than the open request names is refused
    (VIEW_CHANGED) -- the stored bytes are what everyone signs; a page that claims none and signs the 0.1 bytes fails the signature check.
    pvh: a request whose view is no longer the rows' view (view_current: the claim was checked under the lock) is superseded, not refused."""
    cur = current_policy(ctx, acc["id"])
    pol, _, h = cur
    replaced = []                                         # RT-SUP 29.10: (id, signer kids) of the signed requests replaced below
    for r in ctx.db.q("SELECT * FROM sig_requests WHERE account_id=? AND kind='approval' AND ref=? AND status='collecting'", (acc["id"], rid)):
        m = json.loads(r["meta"] or "{}")
        if bool(m.get("approved")) == approved:
            if m.get("view") != (view.hex() if view is not None else None):
                if not json.loads(r["sigs"] or "[]"):     # opened by a signature that then failed: it pins nothing, a new one is opened
                    ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE id=?", (r["id"],))
                    continue
                if view is not None and view_current:     # r0352: a request that names no view (an older page) is replaced too
                    # pvh 28.10: view_current = `view` was checked against the rows under this lock (do_approve runs view_fn first), so the request's
                    # view is stale: sign_request refuses it to every signer and it can never reach quorum. Replace it with a request
                    # over the current view; its signatures over the old view are not carried over (every signer signs the new view).
                    # RT-SUP 29.10: at most SUPERSEDE_CAP such replacements per action. A view that keeps changing under the signers (a
                    # writer into a pending row, a lever nobody planned) would otherwise reset the quorum and push every signer each time.
                    n = ctx.db.one("SELECT COUNT(*) AS n FROM sig_requests WHERE account_id=? AND kind='approval' AND ref=? AND status='superseded' "
                                   "AND meta LIKE '%\"why\": \"view_changed\"%'", (acc["id"], rid))["n"]
                    if n >= SUPERSEDE_CAP:
                        log("WARN", "approval request: VIEW_UNSTABLE, the view of a pending action changed again after %d replacements; "
                                    "not replaced, nothing decided" % n, account=acc["id"], rid=rid, req=r["id"])
                        raise Err(409, "VIEW_UNSTABLE", "what this action shows keeps changing (its signature request was replaced %d times): "
                                                        "refuse it or ask the agent again" % n)
                    ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE id=?", (r["id"],))
                    replaced.append((r["id"], [s["kid"].hex() for s in _sigs(r)]))
                    continue
                if view is not None:
                    raise Err(409, "VIEW_CHANGED", "the open signature request of this action names another view (%s): open it on the "
                                                   "request page (sign.html?req=%s)" % ("none: an older page" if not m.get("view") else "changed", r["id"]))
                # no view claimed (an older page) against a request that names one: its signature must be over the stored bytes
                # (which name the view, checked in sign_request) -- the 0.1 bytes fail there with APPROVAL_SIG
            return r["id"]
    meta = {"approved": approved, "action": {"class": action.get("class"), "amount": action.get("amount")}, "by": user_id}
    if view is not None:
        meta["view"] = view.hex()
    if replaced:                                          # RT-SUP: the new request names what it replaces and whose signatures were dropped
        meta["replaces"] = replaced[-1][0]
        meta["dropped"] = sorted({k for _, ks in replaced for k in ks})
    sid = new_request(ctx, acc["id"], "approval", rid, wa.TYP_APPROVAL, payload, h, _needs_for(ctx, pol, "approval", wa.TYP_APPROVAL, payload, meta),
                      meta, expires=expires, push_kind="v" if replaced else "s")
    for old_id, _ in replaced:                            # ... and the old one points to it, with the reason
        o = ctx.db.one("SELECT meta FROM sig_requests WHERE id=?", (old_id,))
        om = json.loads(o["meta"] or "{}")
        om.update(superseded_by=sid, why="view_changed")
        ctx.db.x("UPDATE sig_requests SET meta=? WHERE id=?", (json.dumps(om), old_id))
    return sid


# ---------------------------------------------------------------- export (task 06)
def export_org(ctx, account_id):
    """Everything a third party needs to judge the team part of the pack (ARHITEKTURA-0.2 2.5) -- no names, no e-mail, no observers,
    no refusals that never reached quorum. Bytes as base64url. Stable keys:
    {principal, rp:{rp_id, origins}, policies:[{ver, policy_b64, envelope_b64, hash_hex, t, registry_seq}],
     members:[{kid_hex, roles, status}] (signing members only), signatures:[{req_id, kind, ref, typ, policy_hash_hex, signed_by:[kid_hex], t}]}"""
    acc = ctx.db.one("SELECT principal FROM accounts WHERE id=?", (account_id,))
    pols = [{"ver": r["ver"], "policy_b64": wa.b64u(bytes(r["policy"])), "envelope_b64": wa.b64u(bytes(r["envelope"])),
             "hash_hex": bytes(r["hash"]).hex(), "t": r["t"], "registry_seq": r["registry_seq"]}
            for r in ctx.db.q("SELECT * FROM org_policies WHERE account_id=? ORDER BY ver", (account_id,))]
    mem = [{"kid_hex": bytes(r["kid"]).hex() if r["kid"] is not None else None, "roles": json.loads(r["roles"]), "status": r["status"]}
           for r in ctx.db.q("SELECT * FROM members WHERE account_id=? ORDER BY kid", (account_id,)) if json.loads(r["roles"]) != ["observer"]]
    sigs = [{"req_id": r["id"], "kind": r["kind"], "ref": r["ref"], "typ": r["typ"],
             "policy_hash_hex": bytes(r["policy_hash"]).hex() if r["policy_hash"] else None,
             "signed_by": [s["kid"].hex() for s in _sigs(r)], "t": r["created_at"]}
            for r in ctx.db.q("SELECT * FROM sig_requests WHERE account_id=? AND status='done' AND kind IN ('mandate','approval','policy') "
                              "ORDER BY created_at, id", (account_id,))]
    return {"principal": acc["principal"] if acc else None, "rp": rp(ctx), "policies": pols, "members": mem, "signatures": sigs}


def new_user_id():
    return os.urandom(16).hex()
