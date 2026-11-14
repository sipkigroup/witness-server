"""Web API (cookie session) of ARHITEKTURA 5.1 + organisations of ARHITEKTURA-0.2 2.7. Every handler names its right in
auth.session_account(..., action=...): the one table is org.RIGHTS (the observer may only read)."""
import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import time

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app import _paths  # noqa: F401
import wa_profile as wa
from svidetel_v4.schema import validate_mandate
from app import actions as act
from app.hookjudge import judge as hj
from app import allowances, auth, keyalert, keys, org, repeat, uxstat, waiting, wire, toolmap as tm
from app import delegation, levels, account_delete, stats, trial
from app import signview, maskdep, qwords
from app.context import Err, check_json, canon_rid
from app import refusals
from app.mandates import mandate_from_form
from app.registry_wa import WaRegistry, looks_like_envelope  # noqa: F401
from svidetel_v4.state import revocation_payload

FREE_AGENTS = 25
RECOVERY_FAILS = 10           # 0.2.12 (R7-05): failed recovery-code attempts per account and hour (the right code works until then)


def now():
    return int(time.time())


def make_router(ctx):
    r = APIRouter()
    db, hub = ctx.db, ctx.hub

    async def body(req):
        try:
            b = await req.json()
        except Err:
            raise                                 # 413 from the body limit
        except Exception:
            raise Err(400, "BAD_REQUEST", "JSON body expected")
        check_json(b)
        return b if isinstance(b, dict) else {}

    trusted = [x.strip() for x in (ctx.cfg.trusted_proxy or "").split(",") if x.strip()]

    def _is_trusted(peer):
        try:
            ip = ipaddress.ip_address(peer)
        except ValueError:
            return False
        if not trusted:                       # N-06: default = loopback only; a docker deployment names the NPM container in DW_TRUSTED_PROXY
            return ip.is_loopback
        return any(ip in ipaddress.ip_network(t, strict=False) for t in trusted)

    def client_ip(req):
        """R-11: X-Real-IP is believed only when the TCP peer is the trusted reverse proxy (DW_TRUSTED_PROXY, default: loopback only)."""
        peer = req.client.host if req.client else "?"
        return (req.headers.get("x-real-ip") or peer) if _is_trusted(peer) else peer

    def own_agent(acc, aid):
        a = db.one("SELECT * FROM agents WHERE id=? AND account_id=?", (aid, acc["id"])) if isinstance(aid, str) else None
        if not a:
            raise Err(404, "NOT_FOUND")
        return a

    # 0.2.28: the Team access form of the home page (app/stats.py): e-mail + text only, no account needed; the IP is only a key of the
    # in-memory rate limit (5 per hour), never stored
    @r.post("/api/team-request")
    async def team_request(req: Request):
        if req.headers.get("origin") != ctx.cfg.origin:
            raise Err(403, "BAD_ORIGIN")
        k = "team:" + stats.net_key(client_ip(req))      # 0.2.30: an IPv6 sender is one /64 (one host has a whole /64 to rotate through)
        if not ctx.limiter.allowed(k, 5, 3600):
            raise Err(429, "RATE_LIMIT", "too many requests from here: try again in an hour or write to support@sipkigroup.com")
        b = await body(req)
        out = stats.team_request(ctx, b)
        ctx.limiter.hit(k, 5, 3600)                  # every accepted form counts (a refused one stored nothing)
        return out

    # ---------------- auth ----------------
    @r.post("/api/auth/register/begin")
    async def reg_begin(req: Request):
        if req.headers.get("origin") != ctx.cfg.origin:
            raise Err(403, "BAD_ORIGIN")
        reg_limit = 10 if ctx.cfg.reg_per_hour is None else ctx.cfg.reg_per_hour
        if not ctx.limiter.hit("reg:" + client_ip(req), reg_limit, 3600):
            refusals.note(ctx, "NET_HOUR")
            raise Err(429, "RATE_LIMIT", "%d registrations per hour" % reg_limit)
        b = await body(req)
        dn = b.get("display_name")
        return auth.register_begin(ctx, dn if isinstance(dn, str) else "user")

    @r.post("/api/auth/register/finish")
    async def reg_finish(req: Request):
        if req.headers.get("origin") != ctx.cfg.origin:
            raise Err(403, "BAD_ORIGIN")
        b = await body(req)
        if not isinstance(b.get("credential"), dict):
            raise Err(400, "BAD_REQUEST")
        inv = b.get("invite")
        if inv is not None and not ctx.db.one("SELECT 1 AS k FROM invites WHERE token_hash=? AND used_by IS NULL AND expires>=?",
                                              (hashlib.sha256(str(inv).encode()).digest(), now())):
            raise Err(409, "INVITE_INVALID", "the invite is unknown, used or expired")      # before the passkey is registered
        acc, keycard = auth.register_finish(ctx, b.get("flow_id"), b["credential"], b.get("device"), b.get("terms"))
        if trial.internal_ip(ctx, client_ip(req)):
            db.x("UPDATE accounts SET internal=1 WHERE id=?", (acc["id"],))       # 0.2.38: made from our own network: never counted
        out = {"account": acc, "keycard": keycard, "user": {"id": acc["id"], "display_name": acc["display_name"]}}
        cur = acc["id"]
        if inv is not None:
            try:
                out["joined"] = org.join(ctx, acc["id"], inv)
                cur = out["joined"]["account_id"]
            except Err as e:
                out["joined"] = {"error": e.code}
        resp = JSONResponse(out)
        cr = db.one("SELECT id FROM credentials WHERE kid=?", (bytes.fromhex(keycard["kid_hex"]),))
        auth.start_session(ctx, resp, cur, acc["id"], cr["id"] if cr else None)
        req.state.account = cur
        return resp

    @r.post("/api/auth/login/begin")
    async def login_begin(req: Request):
        if req.headers.get("origin") != ctx.cfg.origin:
            raise Err(403, "BAD_ORIGIN")
        if not ctx.limiter.hit("login:" + client_ip(req), 30, 60):
            raise Err(429, "RATE_LIMIT", "30 login attempts per minute")
        try:
            b = await body(req)
        except Err:
            b = {}
        return auth.login_begin(ctx, b.get("rid") if isinstance(b, dict) else None)     # 0.2.75 (N23): the account a call's link waits for

    @r.post("/api/auth/login/finish")
    async def login_finish(req: Request):
        if req.headers.get("origin") != ctx.cfg.origin:
            raise Err(403, "BAD_ORIGIN")
        b = await body(req)
        if not isinstance(b.get("credential"), dict):
            raise Err(400, "BAD_REQUEST")
        uid, aid, crid = auth.login_finish(ctx, b.get("flow_id"), b["credential"])
        a = db.one("SELECT id, principal, display_name FROM accounts WHERE id=?", (aid,))
        u = db.one("SELECT id, display_name FROM users WHERE id=?", (uid,))
        resp = JSONResponse({"account": dict(a), "user": dict(u) if u else {"id": uid}})
        auth.start_session(ctx, resp, aid, uid, crid)
        req.state.account = aid
        return resp

    @r.post("/api/auth/logout")
    async def logout(req: Request):
        if req.headers.get("origin") != ctx.cfg.origin:
            raise Err(403, "BAD_ORIGIN")
        auth.end_session(ctx, req)
        resp = Response(status_code=204)
        resp.delete_cookie("dw_session", path="/")
        resp.delete_cookie("dw_in", path="/")
        return resp

    @r.post("/api/auth/logout-all")
    async def logout_all(req: Request):
        """R-17: end every session of the account (this one included)."""
        auth.session_account(ctx, req, True, "session")
        auth.end_all_sessions(ctx, req)
        resp = Response(status_code=204)
        resp.delete_cookie("dw_session", path="/")
        resp.delete_cookie("dw_in", path="/")
        return resp

    @r.post("/api/account/delete")
    async def account_delete_(req: Request):
        """0.2.23: erase my own account. Owner of it, fresh step-up (<= 5 min), the account name typed in full (account_delete.py)."""
        acc = auth.session_account(ctx, req, True, "owner")
        auth.require_stepup(ctx, req, acc)
        b = await body(req)
        resp = JSONResponse(account_delete.delete(ctx, req.state.user, acc, b.get("confirm_name"), auth._session_cred(ctx, req)))
        resp.delete_cookie("dw_session", path="/")
        resp.delete_cookie("dw_in", path="/")
        return resp

    @r.post("/api/auth/stepup/begin")
    async def stepup_begin(req: Request):
        auth.session_account(ctx, req, True, "session")
        if not ctx.limiter.hit("stepup:" + req.state.user, 30, 60):
            raise Err(429, "RATE_LIMIT", "30 attempts per minute")
        return auth.stepup_begin(ctx, req)

    @r.post("/api/auth/stepup/finish")
    async def stepup_finish(req: Request):
        auth.session_account(ctx, req, True, "session")
        b = await body(req)
        if not isinstance(b.get("credential"), dict):
            raise Err(400, "BAD_REQUEST")
        auth.stepup_finish(ctx, req, b.get("flow_id"), b["credential"])
        return {"ok": True, "valid_for_s": auth.STEPUP_TTL}

    # ---------------- 0.2.2: devices (several passkeys) and recovery codes -- the person's own, so under /api/auth/ ----------------
    def session_cred(req):
        r = db.one("SELECT credential_id FROM sessions WHERE id_hash=?", (auth._tok_hash(req),))
        return r["credential_id"] if r else None

    @r.get("/api/auth/keys")
    def keys_list(req: Request):
        auth.session_account(ctx, req, False, "session")
        return {"keys": keys.list_keys(ctx, req.state.user, session_cred(req)), "recovery_codes": keys.codes_state(ctx, req.state.user)}

    @r.post("/api/auth/keys/add/begin")
    async def keys_add_begin(req: Request):
        auth.session_account(ctx, req, True, "session")
        if not ctx.limiter.hit("keyadd:" + req.state.user, 10, 3600):
            raise Err(429, "RATE_LIMIT", "10 new passkeys per hour")
        b = await body(req)
        return keys.add_begin(ctx, req.state.user, b.get("label"), b.get("device"))

    @r.post("/api/auth/keys/add/finish")
    async def keys_add_finish(req: Request):
        auth.session_account(ctx, req, True, "session")
        b = await body(req)
        if not isinstance(b.get("credential"), dict):
            raise Err(400, "BAD_REQUEST")
        return keys.add_finish(ctx, req.state.user, b.get("flow_id"), b["credential"])

    def env_of(b):
        try:
            return wa.b64u_dec(b["envelope_b64"])
        except Exception:
            raise Err(409, "WA_MALFORMED")

    @r.post("/api/auth/keys/add/confirm")
    async def keys_add_confirm(req: Request):
        auth.session_account(ctx, req, True, "session")
        b = await body(req)
        return keys.add_confirm(ctx, req.state.user, b.get("confirm_id"), env_of(b))

    @r.post("/api/auth/keys/{kid}/device")
    async def keys_device(kid: str, req: Request):
        """0.2.13: mark a passkey as the phone's or this computer's (confirmation levels). Needs a fresh step-up; to mark one "phone", the
        step-up must have been made with ANOTHER phone passkey (unless there is none yet)."""
        auth.session_account(ctx, req, True, "session")
        r0 = db.one("SELECT stepup_at FROM sessions WHERE id_hash=? AND user_id=?", (auth._tok_hash(req), req.state.user))
        if not r0 or (r0["stepup_at"] or 0) < now() - auth.STEPUP_TTL:
            raise Err(403, "STEPUP_REQUIRED", "confirm with your passkey first")
        return keys.set_device(ctx, req.state.user, keys.parse_kid(kid), (await body(req)).get("device"), auth._session_cred(ctx, req))

    @r.post("/api/auth/keys/{kid}/cancel-phone")
    async def keys_cancel_phone(kid: str, req: Request):
        """0.2.15: "this was not me": a key declared the new phone with a recovery code loses that claim (it stays a laptop key until
        removed), its sessions end, every unused recovery code stops. Needs a fresh step-up with your phone (any other non-waiting key
        when you have no phone)."""
        auth.session_account(ctx, req, True, "session")
        r0 = db.one("SELECT stepup_at FROM sessions WHERE id_hash=? AND user_id=?", (auth._tok_hash(req), req.state.user))
        if not r0 or (r0["stepup_at"] or 0) < now() - auth.STEPUP_TTL:
            raise Err(403, "STEPUP_REQUIRED", "confirm with your passkey first")
        return keys.cancel_phone(ctx, req.state.user, keys.parse_kid(kid), auth._session_cred(ctx, req))

    @r.post("/api/auth/keys/{kid}/clone-dismiss")
    async def keys_clone_dismiss(kid: str, req: Request):
        """0.2.21: "this was me": clear the possible-clone mark of one of your passkeys. Fresh step-up, made with ANOTHER active passkey when
        you have one (app/keyalert.dismiss). Stopping the key is the existing signed removal (remove/begin, remove)."""
        auth.session_account(ctx, req, True, "session")
        r0 = db.one("SELECT stepup_at FROM sessions WHERE id_hash=? AND user_id=?", (auth._tok_hash(req), req.state.user))
        if not r0 or (r0["stepup_at"] or 0) < now() - auth.STEPUP_TTL:
            raise Err(403, "STEPUP_REQUIRED", "confirm with your passkey first")
        return keyalert.dismiss(ctx, req.state.user, keys.parse_kid(kid), auth._session_cred(ctx, req))

    @r.post("/api/auth/keys/{kid}/remove/begin")
    async def keys_remove_begin(kid: str, req: Request):
        auth.session_account(ctx, req, True, "session")
        return keys.remove_begin(ctx, req.state.user, keys.parse_kid(kid))

    @r.post("/api/auth/keys/{kid}/remove")
    async def keys_remove(kid: str, req: Request):
        auth.session_account(ctx, req, True, "session")
        b = await body(req)
        return keys.remove_finish(ctx, req.state.user, keys.parse_kid(kid), b.get("flow_id"), env_of(b))

    @r.get("/api/auth/recovery-codes")
    def codes_get(req: Request):
        auth.session_account(ctx, req, False, "session")
        return keys.codes_state(ctx, req.state.user)

    @r.post("/api/auth/recovery-codes")
    def codes_new(req: Request):                        # `def`: runs in the thread pool, the 10 scrypt never block the event loop (R4-06)
        acc = auth.session_account(ctx, req, True, "session")
        auth.require_stepup(ctx, req, acc)              # a stolen cookie cannot mint codes that open the account later
        keys.refuse_if_pending(auth._session_cred(ctx, req), "make new recovery codes", ctx)     # 0.2.16: a waiting "new phone" cannot
        if not ctx.limiter.hit("codes:" + req.state.user, 3, 3600):
            raise Err(429, "RATE_LIMIT", "3 sets of recovery codes per hour")
        return keys.new_codes(ctx, req.state.user)

    @r.post("/api/auth/recovery/login")
    async def recovery_login(req: Request):
        if req.headers.get("origin") != ctx.cfg.origin:
            raise Err(403, "BAD_ORIGIN")
        if not ctx.limiter.hit("recovery:" + client_ip(req), 10, 3600):
            raise Err(429, "RATE_LIMIT", "10 recovery attempts per hour")
        code = (await body(req)).get("code")
        # 0.2.12 (R7-05): limits by what an attempt can reach, not one ceiling for everybody. A code whose lookup group no live code has is
        # garbage for certain: only garbage pays the global ceiling (R4-08: it bounds the dummy scrypt an attacker with many addresses can
        # make us run). A code that reaches accounts is limited per ACCOUNT, by its FAILED attempts: a flood of garbage from many addresses no
        # longer locks every owner out, and the right code is refused only after 10 wrong ones for that very account in the hour.
        owners = await asyncio.to_thread(keys.code_owners, ctx, code)
        if not owners and not ctx.limiter.hit("recovery:*", 300, 3600):
            raise Err(429, "RATE_LIMIT", "too many recovery attempts; try again later")
        if any(not ctx.limiter.allowed("recovery-fail:" + u, RECOVERY_FAILS, 3600) for u in owners):
            raise Err(429, "RATE_LIMIT", "too many failed attempts for this account; try again in an hour")
        try:
            uid = await asyncio.to_thread(keys.use_code, ctx, code)   # R4-08: the scrypt runs in a worker thread, not on the event loop
        except Err:
            for u in owners:
                ctx.limiter.hit("recovery-fail:" + u, RECOVERY_FAILS, 3600)
            raise
        resp = JSONResponse({"scope": "recovery", "next": "recover.html", "expires_in_s": keys.RECOVERY_TTL,
                             "codes_left": keys.codes_state(ctx, uid)["remaining"],
                             "done": "Every session of this account was ended and your devices were notified."})
        keys.recovery_login(ctx, resp, uid)
        req.state.account = uid
        return resp

    @r.get("/api/auth/recovery/state")
    def recovery_state(req: Request):
        uid, exp = keys.recovery_session(ctx, req)
        u = db.one("SELECT display_name FROM users WHERE id=?", (uid,))
        return {"display_name": u["display_name"] if u else None, "expires_at": exp, "codes_left": keys.codes_state(ctx, uid)["remaining"]}

    @r.post("/api/auth/recovery/passkey/begin")
    async def recovery_pk_begin(req: Request):
        uid, _ = keys.recovery_session(ctx, req, True)
        b = await body(req)
        return keys.recovery_passkey_begin(ctx, uid, b.get("label"), b.get("device"))

    @r.post("/api/auth/recovery/passkey/finish")
    async def recovery_pk_finish(req: Request):
        uid, _ = keys.recovery_session(ctx, req, True)
        b = await body(req)
        if not isinstance(b.get("credential"), dict):
            raise Err(400, "BAD_REQUEST")
        out = keys.recovery_passkey_finish(ctx, req, uid, b.get("flow_id"), b["credential"])
        resp = JSONResponse(out)
        resp.delete_cookie("dw_session", path="/")
        resp.delete_cookie("dw_in", path="/")
        return resp

    @r.get("/api/me")
    def me(req: Request):
        acc = auth.session_account(ctx, req)
        trial.seen(ctx, acc["id"])                 # r0288: a person who opens the dashboard uses the account (at most one write an hour)
        sk = signing_keys(acc, req)
        c = sk[0] if sk else org.credential_of(ctx, req.state.user)
        u = db.one("SELECT id, display_name FROM users WHERE id=?", (req.state.user,))
        return {"account": {"id": acc["id"], "principal": acc["principal"], "display_name": acc["display_name"]},
                "user": {"id": req.state.user, "display_name": u["display_name"] if u else None},
                "roles": req.state.member["roles"], "member_status": req.state.member["status"],
                "keycard": {"kid_hex": bytes(c["kid"]).hex(), "short": auth.short_kid(bytes(c["kid"])), "credential_id_b64": wa.b64u(bytes(c["credential_id"])),
                            "rp_id": c["rp_id"], "origins": [c["origin"]]},
                # 0.2.2: the passkeys that may sign HERE (solo account: every active one; organisation with a policy: the member's key)
                "signing_keys": [{"kid_hex": bytes(x["kid"]).hex(), "credential_id_b64": wa.b64u(bytes(x["credential_id"]))} for x in sk],
                "trial": ({"expires_at": acc["trial_until"]} if "trial_until" in acc.keys() and acc["trial_until"] is not None else None),     # 0.2.38
                "idle": trial.idle_view(ctx, acc["id"]),     # r0288: the account was warned it is unused (null = not)
                "status_url": ctx.cfg.status_url or None,
                "team": org.is_team(ctx, acc["id"])}     # r0284: false = a solo account (the page hides the "Team" entry)

    def signing_keys(acc, req):
        if org.current_policy(ctx, acc["id"]) is not None:
            m = req.state.member
            c = db.one("SELECT * FROM credentials WHERE user_id=? AND kid=? AND revoked_at IS NULL", (req.state.user, m["kid"])) if m["kid"] else None
            return [c] if c else []
        if acc["id"] != req.state.user:
            return [org.member_credential(ctx, acc["id"], req.state.user)] if org.member_credential(ctx, acc["id"], req.state.user) else []
        cur = session_cred(req)
        cs = list(org.credentials_of(ctx, req.state.user))
        return sorted(cs, key=lambda x: x["id"] != cur)          # the passkey of this session first

    # ---------------- agents ----------------
    def agent_view(a):
        m = act.active_mandate(ctx, a["id"])
        return {"id": a["id"], "name": a["name"], "key_prefix": a["key_prefix"], "created_at": a["created_at"],
                "active_mandate_id": m["id"] if m else None, "toolmap": json.loads(a["toolmap_json"]),
                "toolmap_sha256": tm.toolmap_hash(json.loads(a["toolmap_json"])),
                "toolmap_signed": bool(m and m["toolmap_sha256"] == tm.toolmap_hash(json.loads(a["toolmap_json"]))),
                # 0.2.17 (R9-04): hook judge rounds without an action in the last 24 h (they count toward the quota)
                "hook_rounds_24h": hj.rounds_view(ctx, a["id"], now()),
                "frozen_at": a["frozen_at"] if "frozen_at" in a.keys() else None,         # 0.2.24 (T2)
                "frozen_kind": act.frozen_kind(ctx, a["id"]) if "frozen_at" in a.keys() and a["frozen_at"] else None}   # 0.2.25: "freeze" | "auto"

    @r.get("/api/agents")
    def agents(req: Request):
        acc = auth.session_account(ctx, req)
        return [agent_view(a) for a in db.q("SELECT * FROM agents WHERE account_id=? AND disabled_at IS NULL ORDER BY created_at, id", (acc["id"],))]

    @r.post("/api/agents")
    async def agent_new(req: Request):
        acc = auth.session_account(ctx, req, True, "owner")
        auth.require_stepup(ctx, req, acc)          # N-12: a stolen cookie cannot mint a new agent key
        b = await body(req)
        with hub.lock(acc["id"]):
            max_agents = FREE_AGENTS if ctx.cfg.max_agents is None else ctx.cfg.max_agents
            if db.one("SELECT COUNT(*) AS n FROM agents WHERE account_id=? AND disabled_at IS NULL", (acc["id"],))["n"] >= max_agents:
                raise Err(429, "QUOTA", "%d agents per account during the beta" % max_agents)
            key = "dwk_" + base64.b32encode(os.urandom(32)).decode().rstrip("=")
            aid = "ag_" + os.urandom(6).hex()
            name = b.get("name") if isinstance(b.get("name"), str) and b["name"].strip() else "agent"
            pre = b.get("preset")
            if pre is not None and pre not in tm.PRESETS:
                raise Err(422, "TOOLMAP_INVALID", "unknown preset")
            db.x("INSERT INTO agents(id,account_id,name,key_prefix,key_hash,toolmap_json,created_at,created_by) VALUES(?,?,?,?,?,?,?,?)",
                 (aid, acc["id"], name[:80], key[:12], ctx.key_hash(key), json.dumps(tm.preset(pre)), now(), req.state.user))
        stats.first(ctx, acc["id"], "agent")                 # 0.2.28
        return {"agent": agent_view(db.one("SELECT * FROM agents WHERE id=?", (aid,))), "api_key": key}

    @r.put("/api/agents/{aid}/toolmap")
    async def toolmap_put(aid: str, req: Request):
        acc = auth.session_account(ctx, req, True, "owner")
        a = own_agent(acc, aid)
        auth.require_stepup(ctx, req, acc)
        t = (await body(req)).get("toolmap")
        try:
            tm.check_toolmap(t)
        except tm.ToolmapInvalid as e:
            raise Err(422, "TOOLMAP_INVALID", str(e))
        db.x("UPDATE agents SET toolmap_json=? WHERE id=?", (json.dumps(t), a["id"]))
        return {"agent": agent_view(db.one("SELECT * FROM agents WHERE id=?", (aid,)))}

    @r.delete("/api/agents/{aid}")
    def agent_del(aid: str, req: Request):
        acc = auth.session_account(ctx, req, True, "owner")
        own_agent(acc, aid)
        auth.require_stepup(ctx, req, acc)
        db.x("UPDATE agents SET disabled_at=? WHERE id=?", (now(), aid))
        return Response(status_code=204)

    @r.post("/api/agents/{aid}/freeze")
    def agent_freeze(aid: str, req: Request):
        """0.2.24 (critique T2): freeze an agent: cancel everything it waits for and deny its new calls. Any active signer with a fresh
        passkey touch (step-up): stopping is the safe direction. Unfreezing is the owner's (below).
        r0292 (owner 13.11, p.5): a Viewer (observer) may freeze too -- "anyone may stop"; a non-owner's freezes are rate-limited."""
        acc = auth.session_account(ctx, req, True, "freeze")    # any ACTIVE member, the Viewer included (org.RIGHTS["freeze"])
        own_agent(acc, aid)
        auth.require_stepup(ctx, req, acc)
        return act.freeze(ctx, acc, req.state.user, aid, limited="owner" not in req.state.member["roles"])

    @r.post("/api/agents/{aid}/unfreeze")
    def agent_unfreeze(aid: str, req: Request):
        acc = auth.session_account(ctx, req, True, "owner")
        own_agent(acc, aid)
        auth.require_stepup(ctx, req, acc)
        return act.unfreeze(ctx, acc, req.state.user, aid)

    @r.get("/api/agents/{aid}/freezes")
    def agent_freezes(aid: str, req: Request):
        acc = auth.session_account(ctx, req)
        own_agent(acc, aid)
        return {"frozen_at": own_agent(acc, aid)["frozen_at"], "journal": act.freeze_journal(ctx, acc["id"], aid)}

    @r.get("/api/data-patterns")
    def dp_get(req: Request):
        acc = auth.session_account(ctx, req)
        lits = act.literals_of(ctx, acc["id"])
        try:                                                  # R3-11: the values themselves only to active signers; others see classes and counts
            auth.session_account(ctx, req, False, "write")
            if not auth.key_in_policy(ctx, req, acc):         # R4-09: ... and only with the key the policy names
                raise Err(403, "KEY_NOT_IN_POLICY")
            return {"patterns": lits}
        except Err as e:
            if e.status != 403:
                raise
            return {"patterns": {}, "classes": {k: len(v) for k, v in lits.items()}, "masked": True}

    @r.put("/api/data-patterns")
    async def dp_put(req: Request):
        acc = auth.session_account(ctx, req, True, "owner")
        auth.require_stepup(ctx, req, acc)
        p = (await body(req)).get("patterns")
        if not isinstance(p, dict) or sum(len(v) for v in p.values() if isinstance(v, list)) > 500 or not all(
                isinstance(k, str) and 0 < len(k) <= 64 and isinstance(v, list) and all(isinstance(i, str) and len(i) <= 256 for i in v) for k, v in p.items()):
            raise Err(422, "BAD_PATTERNS", "patterns: {class: [literal, ...]}")
        with db.tx():
            db.x("DELETE FROM data_patterns WHERE account_id=?", (acc["id"],))
            for k, v in p.items():
                for lit in v:
                    if lit:
                        db.x("INSERT INTO data_patterns(account_id,class,literal) VALUES(?,?,?)", (acc["id"], k, lit))
        return {"patterns": act.literals_of(ctx, acc["id"]), "mandates_need_resign": act.guard_changed_count(ctx, acc["id"])}

    # ---------------- mandates ----------------
    def pin_source(acc):
        e = hub.entry_of(acc["id"])
        return e["pin_source"]

    @r.post("/api/mandates/draft")
    async def draft(req: Request):
        acc = auth.session_account(ctx, req, True, "mandate")
        b = await body(req)
        a = own_agent(acc, b.get("agent_id"))
        m = mandate_from_form(b.get("form") or {}, acc["principal"], a["id"], pin_source(acc))
        th = tm.toolmap_hash(json.loads(a["toolmap_json"]))
        gp, ga = act.guard_hashes(ctx, acc["id"])
        # 0.2.4 (draft-deus-aar-05 8.6): the map hash goes INTO the mandate that the passkeys sign. The page computes the same hash from the document it shows.
        doc = act.gateway_doc(ctx, acc["id"], json.loads(a["toolmap_json"]))
        m = dict(m, toolmap_sha256=act.gateway_hash(doc))
        out = {"mandate": m, "typ": wa.TYP_MANDATE, "toolmap_sha256": th, "patterns_sha256": gp, "advisor_sha256": ga, "gateway": doc, "gateway_sha256": m["toolmap_sha256"]}
        q = org.mandate_request(ctx, acc, req.state.user, m, th, (gp, ga), doc)      # 2.4: with a policy the draft opens a quorum request (24 h)
        if q is not None:
            out.update(req_id=q[0], needs=[{"role": r, "k": k} for r, k in q[1]], quorum=True,
                       sign_url="%s/sign.html?req=%s" % (ctx.cfg.origin, q[0]))
        return out

    @r.post("/api/mandates")
    async def mandate_post(req: Request):
        """0.1: wa-sig of the solo owner. 0.2 with a policy: a member's wa-sig (= wq of one) or a client-built wq, judged against the
        policy IN FORCE (409 WQ_QUORUM when the rules need more signers: use the draft's sig-request instead)."""
        acc = auth.session_account(ctx, req, True, "mandate")
        b = await body(req)
        m = b.get("mandate")
        try:
            env = wa.b64u_dec(b["envelope_b64"])
            if not looks_like_envelope(env):
                raise ValueError
        except Exception:
            raise Err(409, "WA_MALFORMED")
        if not isinstance(m, dict) or validate_mandate(wire.cbor_form(m)) or _has_float(m):
            raise Err(409, "MANDATE_MALFORMED")
        if m.get("principal") != acc["principal"]:
            raise Err(409, "MANDATE_PRINCIPAL")
        own_agent(acc, m.get("agent"))
        with hub.lock(acc["id"]):
            env = act.mandate_envelope(ctx, acc, wa.TYP_MANDATE, wa.cde(wire.cbor_form(m)), env)
            out = act.register_mandate(ctx, acc, m, env, b.get("toolmap_sha256"),
                                       [b["patterns_sha256"], b["advisor_sha256"]] if "patterns_sha256" in b and "advisor_sha256" in b else None)
            org.touch_kids(ctx, levels.env_kids(env))          # 0.2.19: signing a mandate = the passkey was used
        trial.on_mandate(ctx, acc, m.get("agent"), out.get("mandate_id"))     # 0.2.38: the calls that waited for the first touch are judged again
        return out

    def own_mandate(acc, mid):
        x = db.one("SELECT * FROM mandates WHERE id=? AND account_id=?", (mid, acc["id"])) if isinstance(mid, str) else None
        if not x:
            raise Err(404, "NOT_FOUND")
        return x

    @r.get("/api/mandates/{mid}/revoke")
    def revoke_get(mid: str, req: Request):
        """The bytes a signer signs to revoke (typ application/aar-revocation+cbor); any ONE signer suffices (0 p.3)."""
        acc = auth.session_account(ctx, req)
        x = own_mandate(acc, mid)
        return {"mandate_id": mid, "status": x["status"], "typ": wa.TYP_REVOCATION,
                "payload_b64": wa.b64u(revocation_payload(wire.cbor_form(json.loads(x["mandate_json"]))))}

    @r.post("/api/mandates/{mid}/revoke")
    async def revoke_post(mid: str, req: Request):
        acc = auth.session_account(ctx, req, True, "sign")
        x = own_mandate(acc, mid)
        b = await body(req)
        try:
            env = wa.b64u_dec(b["envelope_b64"])
            if not looks_like_envelope(env):
                raise ValueError
        except Exception:
            raise Err(409, "WA_MALFORMED")
        return act.revoke(ctx, acc, x, env)

    @r.get("/api/mandates")
    def mandates(req: Request):
        acc = auth.session_account(ctx, req)
        return [{"id": x["id"], "agent_id": x["agent_id"], "status": x["status"], "mandate": json.loads(x["mandate_json"]),
                 "ledger_seq": x["ledger_seq"], "created_at": x["created_at"]}
                for x in db.q("SELECT * FROM mandates WHERE account_id=? ORDER BY created_at, rowid", (acc["id"],))]

    # ---------------- feed / budget / approvals ----------------
    @r.get("/api/feed")
    def feed(req: Request, agent_id: str = None, before: int = None, limit: int = 50):
        acc = auth.session_account(ctx, req)
        limit = max(1, min(limit, 200))
        sql, args = "SELECT * FROM actions WHERE account_id=?", [acc["id"]]
        if agent_id:
            sql += " AND agent_id=?"
            args.append(agent_id)
        if before is not None:
            if not -2 ** 63 <= before < 2 ** 63:
                raise Err(400, "BAD_REQUEST", "before outside the 64-bit range")     # 0.2.18: was 500 (OverflowError in sqlite), found by fuzz
            sql += " AND created_at<?"
            args.append(before)
        rows = db.q(sql + " ORDER BY created_at DESC, rowid DESC LIMIT ?", args + [limit])
        items = [{"rid": x["rid"], "t": x["created_at"], "agent_id": x["agent_id"], "tool": x["tool"], "class": x["class"], "recipient": x["recipient"],
                  "amount": x["amount"], "currency": x["currency"], "verdict": x["verdict"], "reason": x["reason"],
                  "status": act.refresh(ctx, x["rid"])["status"], "args_preview": x["args_preview"]} for x in rows]
        for it, x in zip(items, rows):
            if x["line_lead"]:                       # r0281 (blind evaluation #22 / B10): a part of a call: the panel folds it into its lead's row
                it["line_lead"] = x["line_lead"]
        for it, x in zip(items, rows):                # 0.2.43b (C): the hook stopped waiting at its timeout: not run (still approvable)
            if x["gave_up_at"] and it["status"] in ("pending_approval", "held", "expired"):       # late 29.10: held too
                it["gave_up_at"] = x["gave_up_at"]
        return {"items": items, "next_before": rows[-1]["created_at"] if len(rows) == limit else None}

    @r.get("/api/budget")
    def budget(req: Request):
        acc = auth.session_account(ctx, req)
        out = []
        ms = db.q("SELECT * FROM mandates WHERE account_id=? AND status='active' ORDER BY created_at, rowid", (acc["id"],))
        if not ms:
            return out
        with hub.lock(acc["id"]):
            L = hub.ledger(acc["id"])
            t = L.sync_now()
            for x in ms:
                mm = json.loads(x["mandate_json"])
                pu = mm["permissions"].get("purchase")
                if isinstance(pu, dict):
                    out.append({"mandate_id": x["id"], "agent_id": x["agent_id"], "currency": mm["currency"], "budget": pu.get("budget"),
                                "max_per_action": pu.get("max_per_action"), "committed": L.S.committed(t, x["id"], mm["budget_window_s"]),
                                "window_s": mm["budget_window_s"]})
        return out

    @r.get("/api/approvals")
    def approvals(req: Request, status: str = "pending"):
        acc = auth.session_account(ctx, req)
        out = []
        if status == "held":           # 0.2.0 (web ZAMECHANIYA 10): items held by the advisor (4.2), with the advisor's mark
            for x in db.q("SELECT rid FROM actions WHERE account_id=? AND status='held' ORDER BY created_at", (acc["id"],)):
                y = act.refresh(ctx, x["rid"])
                if y["status"] == "held":
                    out.append(dict(_held_extra(y), rid=y["rid"], t=y["created_at"], agent_id=y["agent_id"], tool=y["tool"],
                                    action=json.loads(y["action_json"]), expires=y["expires"], text_preview=qwords.visible(y["text_preview"] or "", True)))
                    if y["gave_up_at"]:                 # late 29.10: the hook said its wait ended (a release still lets the repeat run once)
                        out[-1].update(gave_up_at=y["gave_up_at"], agent_waiting=False)
            return out
        for x in db.q("SELECT rid FROM actions WHERE account_id=? AND status='pending_approval' ORDER BY created_at", (acc["id"],)):
            y = act.refresh(ctx, x["rid"])
            if y["status"] == "pending_approval" and y["mandate_id"] is not None and not act.hidden_sibling(ctx, y):      # 0.2.38: a trial call waiting for the first touch is not approvable
                it = {"rid": y["rid"], "t": y["created_at"], "agent_id": y["agent_id"], "tool": y["tool"],
                      "action": json.loads(y["action_json"]), "expires": y["expires"],
                      "text_preview": (y["text_preview"] or "")[:200]}     # 0.2.76: the Dashboard says the call in words ("run python3 hello.py")
                it["what"] = qwords.words(y)["what"]                # r0281 (#20): the panel says the same line as the question's page
                ws = waiting.state(y["rid"], y["created_at"])       # 27.10 (polygon O3): absent = cannot tell yet
                if y["gave_up_at"]:
                    ws = False                                      # 0.2.43b (C): the hook said so (survives a restart)
                    it["gave_up_at"] = y["gave_up_at"]
                if ws is not None:
                    it["agent_waiting"] = ws
                out.append(it)
        return out

    @r.get("/api/approvals/{rid}")
    def approval_get(rid: str, req: Request):
        rid = canon_rid(rid)
        acc = auth.session_account(ctx, req)
        out = _approval_answer(acc, rid, req.state.user)
        uxstat.mark_shown(ctx, acc["id"], rid, out.get("status"))     # 0.2.96: "approved without reading" (app/uxstat.py)
        vh = _view_offer(acc, out)
        if vh is not None:
            out["view_sha256"] = vh.hex()      # pv2810: the page signs this hash (it computes it itself from the same answer)
        ap = db.one("SELECT view_sha256 FROM approvals WHERE rid=?", (rid,))
        if ap is None and out.get("covered_by"):   # pv2: a request answered by a project permission: does that signature name the view
            ap = db.one("SELECT view_sha256 FROM allowances WHERE id=? AND account_id=?", (out["covered_by"], acc["id"]))
        if ap is not None:                     # pv2810: a decided approval says whether its signature names the view
            out["view_signed"] = bool(ap["view_sha256"])
            if ap["view_sha256"]:
                out["view_signed_sha256"] = ap["view_sha256"]
        return out

    def _view_offer(acc, out):
        """pv2810 / pv2: -> the presentation hash the server expects in the signature, or None (no binding: a decided call, or a view
        that has no JCS form). pv2: also a team account (the quorum's stored payload names the view of the first signer and every later
        signer's page must show the same view) and an expired call that may still be approved for later runs (repeat_offer)."""
        st = out.get("status")
        if st in ("held", "pending_approval") or (st == "expired" and (out.get("repeat_offer") or {}).get("eligible")):
            try:
                return signview.view_hash(out)
            except ValueError:
                return None
        return None

    def _view_parse(got):
        """pv2: the view hash a request claims (64 lower-case hex) -> bytes, None (not claimed: an older page), or 400."""
        if got is None:
            return None
        if not (isinstance(got, str) and len(got) == 64 and all(c in "0123456789abcdef" for c in got)):
            raise Err(400, "BAD_REQUEST", "view_sha256 must be 64 lower-case hex")
        return bytes.fromhex(got)

    def _view_match(acc, rid, user, got):
        """pv2: called UNDER hub.lock(account) by the decision path itself (approve, release, quorum, batch item, repeat, allowance), so
        the view compared is the view of the rows the decision is written from (no window between the check and the entry).
        got = the 32 bytes the page signed and claims. -> got when it is the view the server rebuilds now, else Err(409 VIEW_CHANGED)."""
        ans = _approval_answer(acc, rid, user)
        want = _view_offer(acc, ans)
        if want is None and ans.get("status") not in ("pending_approval", "held"):
            return None                        # no longer waiting: the decision path answers NOT_DEFERRED / NOT_HELD as before
        legacy = False
        if want is not None and want != got:
            try:                               # r0277: a page older than P2 signs the view without "omitted": the same rows, accepted
                legacy = signview.view_hash(ans, legacy=True) == got
            except ValueError:
                legacy = False
        if want is None or (want != got and not legacy):
            raise Err(409, "VIEW_CHANGED", "what this page shows is no longer what the witness holds: reload the page and decide again")
        signview.remember(db, acc["id"], ans, now(), legacy)     # 0.2.83 (MR-24): the shown object goes into the evidence pack (views/)
        return got

    def _view_fn(acc, rid, user, b):
        """pv2: -> a callable the decision path runs under its lock (None: no view claimed, an older page)."""
        got = _view_parse(b.get("view_sha256"))
        return None if got is None else (lambda: ctx.view_match(acc, rid, user, got))

    ctx.view_match = _view_match               # pv2: the batch (flow/batch.py), the quorum (org.py) and allowances use the same check
    ctx.view_parse = _view_parse

    def _approval_answer(acc, rid, user):
        x = act.own_account_action(ctx, acc, rid)
        if x["mandate_id"] is None:
            raise Err(404, "NOT_FOUND")
        mand = json.loads(db.one("SELECT mandate_json FROM mandates WHERE id=?", (x["mandate_id"],))["mandate_json"])
        out = {"rid": rid, "status": x["status"], "action": json.loads(x["action_json"]), "mandate": mand, "expires": x["expires"],
               "tool": x["tool"], "args_preview": qwords.visible(x["args_preview"]), "text_preview": qwords.visible(x["text_preview"] or "", True),
               "preview_note": "Shown by the witness page, not signed. What your passkey signs is the action above, including args_sha256 (a hash of the tool name and ALL arguments)."}
        prj_ = qwords._project_of(x)
        if prj_:                        # r0300 (U28): the project folder, whole: args_preview may be cut before it (an `eval` line's long
            out["project"] = prj_       # danger list); the page names a file as the person knows it (proekt/hello.py). Not signed (not in the view)
        if x["status"] in ("pending_approval", "held") or (x["status"] == "expired" and x["verdict"] == "defer"):
            out.update(qwords.words(x))     # 05.11 (owner rule): what / harm / details in plain words, built here from the reason code and parsed fields; signed with the view
        try:                            # 0.2.77b (red team R2-7): why this call is asked again / why the old approval did not run
            ej_ = json.loads(x["exec_json"]) if x["exec_json"] else {}
        except (TypeError, ValueError, KeyError, IndexError):
            ej_ = {}
        if isinstance(ej_, dict):
            if ej_.get("file_changed_by") == "late_write" and isinstance(ej_.get("file_changed"), str):
                out.update(file_changed=ej_["file_changed"], file_changed_by="late_write")
            aa_ = ej_.get("asked_again")
            if isinstance(aa_, dict) and isinstance(aa_.get("file"), str):
                out["asked_again"] = {"file": aa_["file"], "approved_at": aa_.get("approved_at") if isinstance(aa_.get("approved_at"), int) else None}
        if x["status"] == "pending_approval" and _line_shown(acc):    # 04.11 (L3): one tool call = one question: the parts asked with this one
            sibs = [z for z in db.q("SELECT rid, tool, reason FROM actions WHERE line_lead=? AND account_id=? AND status='pending_approval' "
                                    "ORDER BY created_at, rowid", (rid, acc["id"]))]
            if sibs and not x["line_lead"]:
                out["line_group"] = [_line_part(acc, z["rid"], z["reason"], user) for z in sibs]
                out["line_reasons"] = list(dict.fromkeys([x["reason"]] + [z["reason"] for z in sibs]))
                if "risk" in out:                   # 05.11: a call of several parts: the highest level over the parts (each part's own view carries its own)
                    out["risk"] = qwords.risk_max([out["risk"]] + [((g.get("view") or {}).get("risk") or "high") for g in out["line_group"]])
            if x["line_lead"]:
                out["line_lead"] = x["line_lead"]
                # 05.11 (hole: "Low risk" on a part of a line that goes to the network): a part opened by its own link (an older client
                # prints both links) shows the question of the whole line: risk = the highest over the group, what / harm = the lead's
                lead_row = db.one("SELECT * FROM actions WHERE rid=? AND account_id=?", (x["line_lead"], acc["id"]))
                if lead_row is not None and "risk" in out:
                    grp = [lead_row] + [z for z in db.q("SELECT * FROM actions WHERE line_lead=? AND account_id=? AND status='pending_approval'",
                                                        (x["line_lead"], acc["id"]))]
                    lw = qwords.words(lead_row)
                    out["risk"] = qwords.risk_max([qwords.words(g)["risk"] for g in grp])
                    out["what"], out["harm"] = lw["what"], lw["harm"]
        if x["status"] == "pending_approval":
            ws = waiting.state(rid, x["created_at"])                # 27.10 (polygon O3): the hook that asked still polls (or not)
            if ws is not None:
                out["agent_waiting"] = ws
            if x["gave_up_at"]:                                     # 0.2.43b (C): the hook said its wait ended: the agent was refused
                out["agent_waiting"] = False
                out["gave_up_at"] = x["gave_up_at"]
        if x["status"] == "held":      # 0.2.0: extra members only for a held item (the 0.1 shape of a pending item stays as in the contract)
            out.update(_held_extra(x))
            if x["gave_up_at"]:        # late 29.10: as for a pending item
                out.update(agent_waiting=False, gave_up_at=x["gave_up_at"])
        if x["class"] == "command" and x["status"] == "pending_approval":     # 0.2.10: "allow this command in this project" (PROPOSAL-07)
            out["allowance_offer"] = allowances.offer(ctx, acc, x)
        if x["class"] == "command":     # RT-0.2.55c: every command of the line (the recipient names one; the text preview is cut at 4 KB)
            try:                        # 0.2.56: line_heads is kept for every command row; cmd_meta (project known) for rows written before
                hl = json.loads(x["line_heads"]) if x["line_heads"] else None
                if not isinstance(hl, list):
                    hm = json.loads(x["cmd_meta"]) if x["cmd_meta"] else None
                    hl = hm.get("heads") if isinstance(hm, dict) else None
            except (TypeError, ValueError, IndexError, KeyError):
                hl = None
            if isinstance(hl, list):
                out["line_commands"] = [h for h in hl if isinstance(h, str)][:64]
        lt_ = _line_full(x)
        if lt_ is not None:             # 04.11 (Hypothesis I2): every command of the line, whole (part of the signed view)
            out["line_full"] = [dict(c, cmd=qwords.visible(c["cmd"], True)) for c in lt_["cmds"]]      # 05.11 (RT hole 2): invisible characters shown as marks
            if lt_["cut"]:
                out["text_cut"] = True
        if x["class"] == "command" and (x["recipient"] or "").startswith(("opaque:network", "opaque:obfuscated code")) and x["text_preview"]:
            out["net_code"] = qwords.visible(x["text_preview"][:4096], True)  # s7 (O1): code that talks to a host it does not show (rt2810: or builds what it runs): the person reads the code
        if x["status"] == "covered":
            out["covered_by"] = x["covered_by"]
        if x["status"] == "pending_approval" or (x["status"] == "expired" and x["verdict"] == "defer"):   # 0.2.29: "approve this call for later runs"
            out["repeat_offer"] = repeat.offer(ctx, acc, x)
        if x["status"] == "pending_approval":         # 0.2.13: where it may be confirmed (laptop / phone) and, for a delegated agent, by whom
            out["confirm"] = levels.view(ctx, acc["id"], x)
            d = delegation.current(ctx, x["agent_id"]) if org.current_policy(ctx, acc["id"]) is not None else None
            if d is not None:
                out["confirm"]["delegated"] = {"operator_user_id": d["operator_user_id"], "you_run_this_agent": d["operator_user_id"] == user,
                                               "can_confirm": delegation.eligible_summary(ctx, acc["id"], x["agent_id"])}
        if x["exec_json"]:                            # 0.2.13 (PROPOSAL-08): the files that made this command a question
            try:
                ej = json.loads(x["exec_json"])
                if isinstance(ej.get("written_run"), list):   # 28.10: ESCALATE_WRITTEN_RUN: the files the agent wrote that this command runs
                    wl = [w if isinstance(w, dict) else {"file": w} for w in ej["written_run"] if isinstance(w, (dict, str))][:16]
                    out["written_run"] = {"files": [w["file"] for w in wl if isinstance(w.get("file"), str)],
                                          "writes": [dict({"file": w.get("file"), "by": w.get("by"), "text": w.get("text")},
                                                          **({"cut": True} if w.get("cut") is True and not w.get("text") else {}),
                                                          # N14 0.2.73: what the agent put into git, as the witness saw it written
                                                          **({"git_texts": [{"file": g.get("file"), "text": g.get("text")} for g in w["git_texts"][:4] if isinstance(g, dict)]}
                                                             if isinstance(w.get("git_texts"), list) and w["git_texts"] else {})) for w in wl]}
                uw = ej.get("unseen_write")
                if isinstance(uw, dict) and isinstance(uw.get("paths"), list) and x["status"] in ("pending_approval", "held"):
                    # N4 29.10: an extraction / patch / git checkout: what it writes is not in the line (signed with the view)
                    out["unseen_write"] = {"paths": [p for p in uw["paths"] if isinstance(p, str)][:16], "secret": uw.get("secret") is True}
                if ej.get("changed"):
                    dg, sz, by = ej.get("digests") or {}, ej.get("sizes") or {}, ej.get("written_by") or {}
                    det = [{"file": f, "sha256_12": dg[f][:12] if isinstance(dg.get(f), str) and dg[f] != "unreadable" else None,
                            "size": sz.get(f) if isinstance(sz.get(f), int) else None, "written_by": by.get(f)} for f in ej["changed"]]
                    out["exec_changed"] = {"files": ej["changed"], "root": ej.get("root"), "details": det,      # 0.2.24 (critique V)
                                           "note": "These files are executed by this command and changed since you last confirmed them "
                                                   "(written by the agent or changed on disk). Approving confirms these versions."}
                    rk = _exec_risk(ej)
                    if rk is not None:
                        out["exec_changed"]["risk"] = rk          # s7 (O2): network in the change, or a change the witness could not read
                    gp = [g for g in (ej.get("git_programs") or []) if isinstance(g, dict) and isinstance(g.get("runs"), list)]
                    if gp or ej.get("git_programs_unknown"):  # 0.2.46: git's config names a program git runs (trust on first use is not enough)
                        runs = "; ".join("%s = %s" % (k, v) for g in gp for k, v in g["runs"][:16])
                        out["exec_changed"]["git_programs"] = gp
                        out["exec_changed"]["note"] = (("This repo's git config runs a program: %s. Git runs it on its own for this command "
                                                        "(diff, status, log ...): approve only if you put it there. " % runs) if gp else
                                                       "The hook could not list the programs this repo's git config runs. ") + out["exec_changed"]["note"]
            except (TypeError, ValueError, AttributeError):
                pass
        md = maskdep.masked_dep(x["tool"], x["recipient"], out)   # 29.10 MDEP: the question hinges on a value masked by its name (in the view)
        if md:
            out["masked_dep"] = md
        ap = db.one("SELECT signers, on_behalf_of FROM approvals WHERE rid=?", (rid,))
        if ap is not None and ap["signers"]:
            out["decided_by"] = {"signers": json.loads(ap["signers"]), "on_behalf_of": ap["on_behalf_of"]}
        out["omitted"] = signview.omitted_of(signview.view_of(out, legacy=True))     # r0277 (P2): what the first screen does not show whole (signed)
        return out

    def _line_full(x):
        """04.11 (Hypothesis I2, "signed != shown"): -> {"cmds": [{"cmd": text} | {"cmd": text, "fold": true}], "cut": bool} of a shell line
        (actions._line_text) or None (no such row / the previews were dropped). `fold`: a long echo of plain words the page may fold."""
        try:
            lt = json.loads(x["line_text"]) if "line_text" in x.keys() and x["line_text"] else None
        except (TypeError, ValueError):
            lt = None
        if not isinstance(lt, dict) or not isinstance(lt.get("cmds"), list):
            return None
        cmds = [dict({"cmd": c[0]}, **({"fold": True} if c[1] is True else {})) for c in lt["cmds"]
                if isinstance(c, list) and len(c) == 2 and isinstance(c[0], str)]
        return {"cmds": cmds, "cut": lt.get("cut") is True} if cmds else None

    def _line_shown(acc):
        """04.11 (L3, red team p.5): the parts of one call are asked as ONE question only on a solo account. With a team policy each part is
        its own question (listed, decided alone, by quorum when the policy says so): a lead page never offers a batch the server must refuse."""
        return org.current_policy(ctx, acc["id"]) is None

    def _line_part(acc, prid, reason, user):
        """04.11 (L3, red team p.1: "signed != shown"): a part asked with the lead, as the lead's page must SHOW it: its whole signing view
        (the members of its own GET answer that its approval signs: tool, action with the danger mark, previews, every command of the line,
        the code, the changed / written files, masked values) and that view's hash. The page renders this view and signs exactly it inside
        the part's own approval payload; the batch rebuilds it under the lock (view_match) and refuses another one (VIEW_CHANGED).
        view None: the witness cannot build it (no JCS form): the page must not sign the line (it refuses the call, or decides it part by part)."""
        sa = _approval_answer(acc, prid, user)
        try:
            v, vh = signview.view_of(sa), signview.view_hash(sa).hex()
        except ValueError:
            v, vh = None, None
        return {"rid": prid, "tool": sa.get("tool"), "reason": reason, "mandate": sa["mandate"], "expires": sa.get("expires"), "view": v, "view_sha256": vh,
                "allowance_offer": sa.get("allowance_offer")}      # 05.11: "allow this from now on" is signed for each part on its own (not in the view)

    def _exec_risk(ej):
        """s7 (O2): -> {"dangerous", "files": [{file, lines, hosts, blind}], "note"} for the changed executed files, or None (an older row)."""
        net = ej.get("net")
        if not isinstance(net, dict):
            return None
        files, blind_any, net_any, shown_any = [], False, False, False
        for f in ej.get("changed") or []:
            n = net.get(f) if isinstance(net.get(f), dict) else {"seen": False}
            lines = [str(v)[:200] for v in (n.get("lines") or [])[:5]]
            hosts = [str(v)[:253] for v in (n.get("hosts") or [])[:16]]
            blind = not n.get("seen")
            pv = n.get("preview") if blind and isinstance(n.get("preview"), str) else None
            blind_any, net_any = blind_any or (blind and pv is None), net_any or bool(lines)
            shown_any = shown_any or pv is not None
            fe = {"file": f, "lines": lines, "hosts": hosts, "blind": blind}
            if blind and n.get("after") is True:
                fe["after"] = True                        # r25 (s8 P6): the agent's judged write, then changed again (on disk / a shell write)
            if pv is not None:                            # 0.2.43b: the hook's masked preview of a change the witness did not read
                fe.update(preview=pv[:4096], preview_cut=n.get("preview_cut") is True)
            files.append(fe)
        if not (blind_any or net_any or shown_any):
            return {"dangerous": False, "files": files, "note": "The witness read the agent's change of these files: no network command in it."}
        note = []
        if net_any:
            note.append("The change puts network commands into a file this command runs (shown below): approving lets them run without "
                        "the witness seeing them, and the mandate's domains do not apply to them.")
        if shown_any:
            note.append("A changed file was not written through a call the witness judged (a shell write or a change on disk): its "
                        "content as the agent's machine sent it is shown below (secrets masked, at most 4 KB). Read it before approving.")
        if blind_any:
            note.append("The content of a changed file was not sent to the witness (only its digest and size): you approve it blind. "
                        "Open the file and read it before approving.")
        return {"dangerous": True, "files": files, "note": " ".join(note)}

    def _held_extra(x):
        try:
            from app.flow import advisor
            label, mode = advisor.held_mark(ctx, json.loads(x["action_json"])["args_sha256"], x["account_id"])
        except ImportError:
            label = mode = None
        return {"status": "held", "reason": x["reason"], "adv": "%s-1:%s" % (mode or "heuristic", label or "unknown")}

    @r.post("/api/approvals/{rid}")
    async def approval_post(rid: str, req: Request):
        rid = canon_rid(rid)
        acc = auth.session_account(ctx, req, True, "sign")
        b = await body(req)
        approved = b.get("approved")
        if not isinstance(approved, bool):
            raise Err(400, "BAD_REQUEST", "approved must be boolean")
        x = act.own_account_action(ctx, acc, rid)       # 404 for another tenant's rid before anything else
        try:
            env = wa.b64u_dec(b["envelope_b64"])
        except Exception:
            raise Err(409, "WA_MALFORMED")
        vf = _view_fn(acc, x["rid"], req.state.user, b)      # pv2: checked by the decision path under hub.lock (atomic with the entry)
        live = waiting.awaited(x) if x["status"] == "pending_approval" else None    # N18 0.2.74: read before the decision ends the wait
        res = _file_changed(x["rid"], act.do_approve(ctx, acc, req.state.user, x["rid"], approved, env, b.get("repeat"), view_fn=vf))
        if live is not None and isinstance(res, dict) and res.get("verdict") == "allow" and not res.get("file_changed"):
            res = dict(res, agent_waiting=live)   # the page says "it runs now" (the hook gets the answer) or "when the agent repeats it"
        uxstat.record(ctx, acc["id"], x["rid"], "once" if approved else "deny", b)
        return res

    def _file_changed(rid, res):
        """N3 29.10 (series 8b): the owner let go a page whose file was written since (the agent's present will be refused FILE_CHANGED,
        nothing runs): the answer says so (file_changed = that file), the page does not say "allowed once"."""
        if isinstance(res, dict) and res.get("verdict") == "allow":
            f = act.file_changed_of(ctx, rid)
            if f:
                res = dict(res, file_changed=f)
        return res

    @r.post("/api/approvals/{rid}/release")
    async def approval_release(rid: str, req: Request):
        rid = canon_rid(rid)
        """4.2: release / reject an item held by the advisor (wa-sig typ application/dw-release+cbor over {rid, args_sha256, release})."""
        acc = auth.session_account(ctx, req, True, "sign")
        b = await body(req)
        rel = b.get("release")
        if not isinstance(rel, bool):
            raise Err(400, "BAD_REQUEST", "release must be boolean")
        x = act.own_account_action(ctx, acc, rid)
        try:
            env = wa.b64u_dec(b["envelope_b64"])
        except Exception:
            raise Err(409, "WA_MALFORMED")
        vf = _view_fn(acc, x["rid"], req.state.user, b)
        res = _file_changed(x["rid"], act.release(ctx, acc, req.state.user, x["rid"], rel, env, view_fn=vf))
        uxstat.record(ctx, acc["id"], x["rid"], "once" if rel else "deny", b)
        return res

    # ---------------- 0.2.10: project allowances (PROPOSAL-07) ----------------
    @r.get("/api/allowances")
    def allowances_list(req: Request):
        acc = auth.session_account(ctx, req)
        return {"items": allowances.listing(ctx, acc), "text": allowances.TRUST_TEXT}

    @r.post("/api/allowances")
    async def allowances_new(req: Request):
        """The owner signed "allow this command in this project" on the approval page of `rid` (wa-sig typ application/aar-allowance+cbor)."""
        acc = auth.session_account(ctx, req, True, "sign")
        b = await body(req)
        try:
            env = wa.b64u_dec(b["envelope_b64"])
        except Exception:
            raise Err(409, "WA_MALFORMED")
        rid = canon_rid(b.get("rid"))
        res = allowances.create(ctx, acc, req.state.user, rid, env, view_fn=_view_fn(acc, rid, req.state.user, b))   # pv2
        uxstat.record(ctx, acc["id"], rid, "forward", b)
        return res

    @r.get("/api/ux-guard")
    def ux_guard(req: Request):
        """0.2.96: "approved without reading" of this account, last 7 days (app/uxstat.py)."""
        acc = auth.session_account(ctx, req)
        return uxstat.account_view(ctx, acc["id"])

    @r.post("/api/allowances/{aid}/revoke")
    async def allowances_revoke(aid: str, req: Request):
        """One click: ending an allowance only narrows the mandate, the owner's session is enough (no passkey prompt)."""
        acc = auth.session_account(ctx, req, True)
        return allowances.revoke(ctx, acc, aid)

    # ---------------- 0.2.29: approvals for later runs (app/repeat.py) ----------------
    @r.get("/api/repeat-approvals")
    def repeat_list(req: Request):
        acc = auth.session_account(ctx, req)
        return {"items": repeat.listing(ctx, acc)}

    @r.post("/api/repeat-approvals/{gid}/revoke")
    async def repeat_revoke(gid: str, req: Request):
        """One click: ending it only narrows what the agent may do (no passkey prompt); the ids left are never used."""
        acc = auth.session_account(ctx, req, True)
        return repeat.revoke(ctx, acc, req.state.user, gid)

    # ---------------- organisations (ARHITEKTURA-0.2 2.7) ----------------
    @r.get("/api/orgs")
    def orgs(req: Request):
        auth.session_account(ctx, req, False, "session")
        return org.orgs_of(ctx, req.state.user, req.state.account)

    @r.post("/api/orgs/switch")
    async def orgs_switch(req: Request):
        auth.session_account(ctx, req, True, "session")
        aid = (await body(req)).get("account_id")
        if not isinstance(aid, str) or org.member(ctx, aid, req.state.user) is None:
            raise Err(404, "NOT_FOUND")
        auth.switch_org(ctx, req, aid)
        return {"account_id": aid}

    @r.post("/api/org/invites")
    async def org_invite(req: Request):
        acc = auth.session_account(ctx, req, True, "owner")
        auth.require_stepup(ctx, req, acc)
        return org.create_invite(ctx, acc["id"], (await body(req)).get("roles"))

    @r.post("/api/org/join")
    async def org_join(req: Request):
        auth.session_account(ctx, req, True, "session")       # any signed-in user; rights in the new org come from the invite
        if not ctx.limiter.hit("join:" + req.state.user, 20, 3600):
            raise Err(429, "RATE_LIMIT", "20 attempts per hour")
        return org.join(ctx, req.state.user, (await body(req)).get("token"))

    @r.get("/api/org")
    def org_get(req: Request):
        acc = auth.session_account(ctx, req)
        ms = []
        for x in db.q("SELECT m.*, u.display_name FROM members m LEFT JOIN users u ON u.id=m.user_id WHERE m.account_id=? ORDER BY m.rowid", (acc["id"],)):
            ms.append({"user_id": x["user_id"], "label": org.label_of(x["display_name"]), "roles": json.loads(x["roles"]), "status": x["status"],
                       "kid": bytes(x["kid"]).hex() if x["kid"] is not None else ""})
        org.apply_due(ctx, acc["id"])
        cur = org.current_policy(ctx, acc["id"])
        return {"scheduled_policy": org.scheduled_changes(ctx, acc["id"]), "account_id": acc["id"], "principal": acc["principal"], "name": acc["display_name"], "members": ms,
                "policy": org.policy_json(cur[0]) if cur else None, "policy_ver": cur[0]["ver"] if cur else 0,
                "settings": org.settings(ctx, acc["id"]), "you": {"user_id": req.state.user, "roles": req.state.member["roles"]}}

    @r.post("/api/org/policy/draft")
    async def policy_draft(req: Request):
        acc = auth.session_account(ctx, req, True, "owner")
        return org.policy_draft(ctx, acc, req.state.user, await body(req))

    @r.get("/api/sig-requests")
    def sigreqs(req: Request):
        acc = auth.session_account(ctx, req)
        return org.open_requests(ctx, acc["id"], req.state.user)

    @r.get("/api/sig-requests/{sid}")
    def sigreq_get(sid: str, req: Request):
        acc = auth.session_account(ctx, req)
        return org.request_view(org.request_row(ctx, acc["id"], sid), full=True, ctx=ctx)

    @r.post("/api/sig-requests/{sid}")
    async def sigreq_post(sid: str, req: Request):
        acc = auth.session_account(ctx, req, True, "sign")
        org.request_row(ctx, acc["id"], sid)                   # 404 for another organisation's request before anything else
        try:
            env = wa.b64u_dec((await body(req))["envelope_b64"])
        except Exception:
            raise Err(409, "WA_MALFORMED")
        return org.sign_request(ctx, acc, req.state.user, sid, env)

    @r.post("/api/sig-requests/{sid}/cancel")
    async def sigreq_cancel(sid: str, req: Request):
        """0.2.37: any current member cancels a scheduled (delayed) policy change before it takes effect."""
        acc = auth.session_account(ctx, req, True, "write")
        return org.cancel_scheduled(ctx, acc, req.state.user, sid)

    @r.post("/api/org/key-replace")
    async def org_key_replace(req: Request):
        """0.2.2: open the request that replaces a member's lost key (signed by the other members, rule `recovery`)."""
        acc = auth.session_account(ctx, req, True, "sign")
        return org.key_replace_request(ctx, acc, req.state.user, (await body(req)).get("user_id"))

    @r.post("/api/org/phone-lift")
    async def org_phone_lift(req: Request):
        """0.2.15: a member declared a new phone with a recovery code (it waits 24-72 h): open the request with which k >= 2 OTHER
        members (rule `recovery` of the policy) let it count as a phone now."""
        acc = auth.session_account(ctx, req, True, "sign")
        return org.phone_lift_request(ctx, acc, req.state.user, (await body(req)).get("user_id"))

    @r.get("/api/mandates/by-key/{kid}")
    def mandates_by_key(kid: str, req: Request):
        acc = auth.session_account(ctx, req)
        return keys.revoke_batch_view(ctx, acc["id"], keys.parse_kid(kid))

    @r.post("/api/mandates/revoke-batch")
    async def revoke_batch(req: Request):
        """0.2.2: one passkey ceremony (wb, typ revocation) revokes up to 20 mandates, e.g. every one a lost key signed."""
        acc = auth.session_account(ctx, req, True, "sign")
        b = await body(req)
        return keys.revoke_batch(ctx, acc, req.state.user, b.get("mandate_ids"), env_of(b))

    # ---------------- 0.2.13: confirmation levels and delegation ----------------
    @r.get("/api/confirm-rules")
    def confirm_rules_get(req: Request):
        acc = auth.session_account(ctx, req)
        return levels.get_rules(ctx, acc["id"])

    @r.put("/api/confirm-rules")
    async def confirm_rules_put(req: Request):
        """phone_for: "risky" (default: laptop keys may confirm ordinary project commands) | "all" (every approval on the phone).
        Tightening needs the owner's step-up; loosening back needs that step-up made with a phone passkey."""
        acc = auth.session_account(ctx, req, True, "owner")
        auth.require_stepup(ctx, req, acc)
        return levels.put_rules(ctx, acc["id"], req.state.user, await body(req), auth._session_cred(ctx, req))

    # 0.2.87: which GitHub repositories / refs may produce a verified CI run context (app/runpolicy.py)
    @r.get("/api/run-context-policy")
    def run_context_policy_get(req: Request):
        from app import runpolicy
        acc = auth.session_account(ctx, req)
        return runpolicy.get(ctx, acc["id"])

    @r.put("/api/run-context-policy")
    async def run_context_policy_put(req: Request):
        """Owner with a fresh passkey step-up (a stolen cookie cannot widen where CI evidence may come from)."""
        from app import runpolicy
        acc = auth.session_account(ctx, req, True, "owner")
        auth.require_stepup(ctx, req, acc)
        return runpolicy.put(ctx, acc["id"], req.state.user, await body(req))

    @r.get("/api/agents/{aid}/delegation")
    def delegation_get(aid: str, req: Request):
        acc = auth.session_account(ctx, req)
        own_agent(acc, aid)
        return delegation.view(ctx, acc["id"], aid)

    @r.put("/api/agents/{aid}/delegation")
    async def delegation_put(aid: str, req: Request):
        """Team: the agent is run by `operator_user_id`; its deferred actions are confirmed by others (optional `approvers`, `days`)."""
        acc = auth.session_account(ctx, req, True, "owner")
        auth.require_stepup(ctx, req, acc)
        own_agent(acc, aid)
        return delegation.put(ctx, acc, req.state.user, aid, await body(req))

    @r.delete("/api/agents/{aid}/delegation")
    def delegation_delete(aid: str, req: Request):
        acc = auth.session_account(ctx, req, True, "owner")
        auth.require_stepup(ctx, req, acc)
        own_agent(acc, aid)
        return delegation.end(ctx, acc, req.state.user, aid)

    @r.put("/api/org/settings")
    async def org_settings(req: Request):
        acc = auth.session_account(ctx, req, True, "owner")
        auth.require_stepup(ctx, req, acc)
        out = org.put_settings(ctx, acc["id"], await body(req))
        return dict(out, mandates_need_resign=act.guard_changed_count(ctx, acc["id"]))

    # ---------------- export / witness ----------------
    @r.get("/api/export")
    def export(req: Request):
        from app.export import build_pack
        acc = auth.session_account(ctx, req)             # the observer may take the evidence pack (2.1)
        if not ctx.limiter.hit("export:" + acc["id"], 6, 3600):       # R-16: each export appends a checkpoint to the ledger
            raise Err(429, "RATE_LIMIT", "6 exports per hour")
        data, name = build_pack(ctx, acc["id"])
        return Response(data, media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="%s"' % name})

    # 0.2.46: export tokens for CI (app/export_tokens.py): issuing needs the owner and a fresh passkey signature; revoking only the owner
    @r.get("/api/export-tokens")
    def export_tokens_list(req: Request):
        from app import export_tokens as xt
        acc = auth.session_account(ctx, req, False, "owner")
        return xt.listing(ctx, acc["id"])

    @r.post("/api/export-tokens")
    async def export_token_new(req: Request):
        from app import export_tokens as xt
        acc = auth.session_account(ctx, req, True, "owner")
        auth.require_stepup(ctx, req, acc)          # a stolen cookie cannot mint a way to download the ledger
        b = await body(req)
        with hub.lock(acc["id"]):
            row, tok = xt.issue(ctx, acc["id"], req.state.user, b)
        return {"token": row, "export_token": tok,
                "use": "GET /v1/export with Authorization: Bearer <this agent's key> and X-DW-Export-Token: <export_token>; shown once"}

    @r.delete("/api/export-tokens/{tid}")
    def export_token_del(tid: str, req: Request):
        from app import export_tokens as xt
        acc = auth.session_account(ctx, req, True, "owner")
        xt.revoke(ctx, acc["id"], tid)
        return Response(status_code=204)

    r.include_router(trial.make_router(ctx, client_ip, auth.session_account, auth.require_stepup, body))     # 0.2.38: trial accounts
    return r


_has_float = act._has_float
