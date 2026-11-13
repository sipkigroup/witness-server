"""Stub 0.2 of Deus Witness Cloud: stub.py (imported, not edited) + the new paths of ARHITEKTURA-0.2 2.7 and 8.
REAL verification: verify_wq / verify_policy_chain / verify_wb / wa.verify_envelope. Fixtures (plausible, not computed from history):
suggestions, digest figures, coverage. In memory. Step-up is NOT enforced (stub). Usage: python stub02.py --port 8801 [--rp-id localhost] [--origin ...]"""
import argparse, base64, hashlib, json, os, secrets, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
CONTRACT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, CONTRACT)
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "../../..")))
import cbor2
from fastapi import Request, Response
from fastapi.staticfiles import StaticFiles

import stub as base
import wa_profile as wa
import wq_profile as q
from forms import mandate_from_form
from stub import Err, now, toolmap_hash
from svidetel_v4.schema import validate_mandate
from svidetel_v4.state import approval_payload, revocation_payload

SIGREQ_TTL = 24 * 3600
DEFAULT_SETTINGS = {"profile": "smb", "defer_ttl_s": 3600, "max_pending": 5, "max_defers_hour": 20, "escalate_after_s": 600, "advisor": "off"}
KNOWN_ROLES = ("owner", "budget", "access", "observer")


def policy_json(p):
    """Policy map -> JSON (bytes as hex)."""
    j = json.loads(json.dumps(p, default=lambda b: b.hex() if isinstance(b, bytes) else str(b)))
    return j


def suggest_toolmap(tools):
    """Deterministic name/type heuristic of ARHITEKTURA-0.2 6 -> (toolmap draft, [(tool, arg)] UNKNOWN)."""
    rcpt = {"to", "cc", "bcc", "recipient", "recipients", "email", "channel", "path", "resource"}
    text = {"subject", "body", "text", "content", "message", "html"}
    money = {"amount", "price", "total"}
    draft, unknown = {"version": 1, "default": "deny", "tools": {}}, []
    for t in tools:
        props = (t.get("inputSchema") or {}).get("properties") or {}
        e = {"class": "pass", "strict": True}
        r, tx, am = [], [], None
        for n, spec in props.items():
            ln = n.lower()
            if ln in rcpt:
                r.append("$." + n)
            elif ln in text:
                tx.append("$." + n)
            elif ln in money and isinstance(spec, dict) and spec.get("type") == "integer":
                am = "$." + n
            else:
                unknown.append((t["name"], n))
        if am:
            e["class"] = "purchase"
        elif any(p in ("$.to", "$.email", "$.recipient", "$.recipients") for p in r):
            e["class"] = "message"
        elif "$.channel" in r:
            e["class"] = "publish"
        elif "$.path" in r:
            e["class"] = "file"
        elif "$.resource" in r:
            e["class"] = "delete"
        if r:
            e["recipient"] = r[0] if len(r) == 1 else r
        if tx:
            e["text"] = tx
        if am:
            e["amount"] = am
        draft["tools"][t["name"]] = e
    return draft, unknown


def create_app02(rp_id="localhost", origin="http://localhost:8801", web_dir=None):
    app = base.create_app(rp_id, origin, web_dir="/nonexistent-stub02")   # no static mount yet: it would shadow new paths
    S = app.state.S
    app.router.routes[:] = [r for r in app.router.routes if getattr(r, "path", None) != "/api/mandates/draft"]  # replaced below
    N0 = len(app.router.routes)
    X = dict(members={}, invites={}, chains={}, sigreqs={}, cur={}, settings={}, catalog={}, coverage={}, drafts={})
    app.state.X = X
    rp = {"rp_id": rp_id, "origins": [origin]}

    # ---- helpers ----
    def user_of(req, write=False):
        if write and req.headers.get("origin") not in (None, origin):
            raise Err(403, "BAD_ORIGIN")
        u = S["sessions"].get(req.cookies.get("dw_session", ""))
        if not u:
            raise Err(401, "NO_SESSION")
        return S["accounts"][u]

    def reg_of_user(uid):
        c = S["creds"][uid]
        return {"alg": "ES256", "pub": c["pub"].hex(),
                "webauthn": {"rp_id": rp_id, "origins": [origin], "credential_id": wa.b64u(c["credential_id"])},
                "pin_source": "webauthn-registration:%s:%s:registry-log#%d" % (rp_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(c["created_at"])), c["seq"])}

    def ensure_org(uid):
        X["members"].setdefault(uid, {}).setdefault(uid, {"roles": ["owner", "budget", "access"], "status": "active"})
        X["chains"].setdefault(uid, [])
        X["settings"].setdefault(uid, dict(DEFAULT_SETTINGS))

    def org_of(u):
        ensure_org(u["id"])
        oid = X["cur"].get(u["id"], u["id"])
        mem = X["members"].get(oid, {}).get(u["id"])
        if not mem:
            raise Err(403, "NOT_MEMBER")
        return oid, mem

    def role_ok(mem, *roles):
        return mem["status"] == "active" and any(r in mem["roles"] for r in roles)

    def chain_t(oid):
        return [(e["policy"], e["envelope"], e["t"]) for e in X["chains"][oid]]

    def cur_policy(oid):
        c = X["chains"][oid]
        return cbor2.loads(c[-1]["policy"]) if c else None

    def need_view(needs):
        return [{"role": r, "k": k} for r, k in needs]

    def sr_view(sr, full=False):
        v = {"id": sr["id"], "kind": sr["kind"], "ref": sr["ref"], "typ": sr["typ"], "needs": need_view(sr["needs"]),
             "have": len(sr["sigs"]), "need": max([k for _, k in sr["needs"]] or [1]), "status": sr["status"],
             "signed_by": [s["kid"].hex() for s in sr["sigs"]], "created_at": sr["created_at"], "expires": sr["expires"]}
        if full:
            v.update(payload_b64=wa.b64u(sr["payload"]), policy_hash_b64=wa.b64u(sr["policy_hash"]) if sr["policy_hash"] else None,
                     body=sr["body"])
        return v

    def new_sr(oid, kind, ref, typ, payload, ph, needs, body, action=None):
        sid = secrets.token_hex(8)
        X["sigreqs"][sid] = {"id": sid, "account_id": oid, "kind": kind, "ref": ref, "typ": typ, "payload": payload, "policy_hash": ph,
                             "needs": needs, "sigs": [], "status": "collecting", "created_at": now(), "expires": now() + SIGREQ_TTL,
                             "body": body, "action": action}
        return X["sigreqs"][sid]

    # ---- orgs / members / invites ----
    @app.get("/api/orgs")
    async def orgs(req: Request):
        u = user_of(req)
        ensure_org(u["id"])
        out = [{"account_id": oid, "principal": S["accounts"][oid]["principal"], "name": S["accounts"][oid]["display_name"], "roles": m[u["id"]]["roles"],
                "status": m[u["id"]]["status"], "current": oid == X["cur"].get(u["id"], u["id"])}
               for oid, m in X["members"].items() if u["id"] in m]
        return out

    @app.post("/api/orgs/switch")
    async def orgs_switch(req: Request):
        u = user_of(req, True)
        ensure_org(u["id"])
        oid = (await base_body(req)).get("account_id")
        if oid not in X["members"] or u["id"] not in X["members"][oid]:
            raise Err(404, "NOT_FOUND")
        X["cur"][u["id"]] = oid
        return {"account_id": oid}

    async def base_body(req):
        try:
            b = await req.json()
        except Exception:
            raise Err(400, "BAD_REQUEST", "JSON body expected")
        return b if isinstance(b, dict) else {}

    @app.post("/api/org/invites")
    async def invites(req: Request):
        u = user_of(req, True)
        oid, mem = org_of(u)
        if not role_ok(mem, "owner"):
            raise Err(403, "FORBIDDEN")
        roles = (await base_body(req)).get("roles")
        if not isinstance(roles, list) or not roles or any(r not in KNOWN_ROLES for r in roles) or ("observer" in roles and len(roles) > 1):
            raise Err(422, "BAD_ROLES")
        tok = secrets.token_urlsafe(24)
        X["invites"][hashlib.sha256(tok.encode()).hexdigest()] = {"account_id": oid, "roles": roles, "expires": now() + 24 * 3600, "used_by": None}
        return {"url": "%s/join.html?token=%s" % (origin, tok)}

    @app.post("/api/org/join")
    async def join(req: Request):
        u = user_of(req, True)
        tok = (await base_body(req)).get("token")
        inv = X["invites"].get(hashlib.sha256(str(tok).encode()).hexdigest())
        if not inv or inv["used_by"] or inv["expires"] < now():
            raise Err(409, "INVITE_INVALID")
        ensure_org(u["id"])
        inv["used_by"] = u["id"]
        status = "active" if inv["roles"] == ["observer"] else "pending"
        X["members"][inv["account_id"]][u["id"]] = {"roles": inv["roles"], "status": status}
        return {"account_id": inv["account_id"], "status": status, "roles": inv["roles"]}

    def org_view(oid):
        ms = []
        for uid, m in X["members"][oid].items():
            c = S["creds"][uid]
            ms.append({"user_id": uid, "label": S["accounts"][uid]["display_name"], "roles": m["roles"], "status": m["status"], "kid": c["kid"].hex()})
        c = X["chains"][oid]
        return {"account_id": oid, "principal": S["accounts"][oid]["principal"], "members": ms,
                "policy": policy_json(cbor2.loads(c[-1]["policy"])) if c else None, "policy_ver": len(c), "settings": X["settings"][oid]}

    @app.get("/api/org")
    async def org_get(req: Request):
        u = user_of(req)
        oid, _ = org_of(u)
        return org_view(oid)

    @app.put("/api/org/settings")
    async def org_settings(req: Request):
        u = user_of(req, True)
        oid, mem = org_of(u)
        if not role_ok(mem, "owner"):
            raise Err(403, "FORBIDDEN")
        b = await base_body(req)
        s = dict(X["settings"][oid])
        for k in DEFAULT_SETTINGS:
            if k in b:
                s[k] = b[k]
        if s["profile"] not in ("smb", "enterprise") or s["advisor"] not in ("off", "heuristic", "ner") or not (900 <= s["defer_ttl_s"] <= 3600):
            raise Err(422, "BAD_SETTINGS")
        X["settings"][oid] = s
        return s

    # ---- policy ----
    @app.post("/api/org/policy/draft")
    async def policy_draft(req: Request):
        u = user_of(req, True)
        oid, mem = org_of(u)
        if not role_ok(mem, "owner"):
            raise Err(403, "FORBIDDEN")
        b = await base_body(req)
        chain = X["chains"][oid]
        ms = []
        for m in b.get("members") or []:
            uid = m.get("user_id")
            if uid not in X["members"][oid] or uid not in S["creds"]:
                raise Err(422, "NOT_MEMBER", str(uid))
            c = S["creds"][uid]
            lab = str(m.get("label") or S["accounts"][uid]["display_name"]).replace("@", "")[:32]
            ms.append({"kid": c["kid"], "pub": c["pub"], "cred": c["credential_id"], "roles": list(m.get("roles") or []), "label": lab})
        ms.sort(key=lambda x: x["kid"])
        pol = {"v": q.V_POLICY, "principal": S["accounts"][oid]["principal"], "ver": len(chain) + 1,
               "prev": hashlib.sha256(chain[-1]["policy"]).digest() if chain else None, "members": ms, "rules": b.get("rules") or {}}
        if q.validate_policy(pol):
            raise Err(422, "POLICY_MALFORMED")
        payload = wa.cde(pol)
        if chain:
            needs = q.requirements(cbor2.loads(chain[-1]["policy"]), q.TYP_POLICY, None)
            ph = hashlib.sha256(chain[-1]["policy"]).digest()
        else:
            needs, ph = [("owner", 1)], None
        sr = new_sr(oid, "policy", str(pol["ver"]), q.TYP_POLICY, payload, ph, needs, policy_json(pol))
        return {"req_id": sr["id"], "typ": q.TYP_POLICY, "payload_b64": wa.b64u(payload), "policy": policy_json(pol)}

    # ---- mandate draft (replaces the 0.1 route: with a policy the mandate is collected as a quorum) ----

    @app.post("/api/mandates/draft")
    async def mandate_draft(req: Request):
        u = user_of(req, True)
        oid, mem = org_of(u)
        b = await base_body(req)
        a = S["agents"].get(b.get("agent_id"))
        if not a or a["account_id"] != oid:
            raise Err(404, "NOT_FOUND")
        m = mandate_from_form(b.get("form") or {}, S["accounts"][oid]["principal"], a["id"], reg_of_user(oid)["pin_source"])
        out = {"mandate": m, "typ": wa.TYP_MANDATE, "toolmap_sha256": toolmap_hash(a["toolmap"])}
        pol = cur_policy(oid)
        if pol is not None:
            needs = q.requirements(pol, wa.TYP_MANDATE, m)
            sr = new_sr(oid, "mandate", m["id"], wa.TYP_MANDATE, wa.cde(m), hashlib.sha256(X["chains"][oid][-1]["policy"]).digest(), needs, m)
            out.update(req_id=sr["id"], needs=need_view(needs), quorum=True)
        return out

    # ---- sig requests ----
    @app.get("/api/sig-requests")
    async def sigreqs(req: Request):
        u = user_of(req)
        oid, mem = org_of(u)
        mykid = S["creds"][u["id"]]["kid"]
        out = []
        for sr in X["sigreqs"].values():
            if sr["account_id"] != oid or sr["status"] != "collecting" or sr["expires"] < now() or any(s["kid"] == mykid for s in sr["sigs"]):
                continue
            if any(r == "any" or r in mem["roles"] for r, _ in sr["needs"]) and mem["status"] == "active":
                out.append(sr_view(sr))
        return out

    def get_sr(u, sid):
        oid, mem = org_of(u)
        sr = X["sigreqs"].get(sid)
        if not sr or sr["account_id"] != oid:
            raise Err(404, "NOT_FOUND")
        return oid, mem, sr

    @app.get("/api/sig-requests/{sid}")
    async def sigreq_get(sid: str, req: Request):
        return sr_view(get_sr(user_of(req), sid)[2], True)

    @app.post("/api/sig-requests/{sid}")
    async def sigreq_post(sid: str, req: Request):
        u = user_of(req, True)
        oid, mem, sr = get_sr(u, sid)
        b = await base_body(req)
        if sr["status"] != "collecting" or sr["expires"] < now():
            raise Err(409, "SIGREQ_CLOSED")
        try:
            env = wa.b64u_dec(b["envelope_b64"])
        except Exception:
            raise Err(409, "WA_MALFORMED")
        if q.envelope_kind(env) != "wa":
            raise Err(409, "WA_MALFORMED")
        code = wa.verify_envelope(env, sr["typ"], sr["payload"], reg_of_user(u["id"]))
        if code:
            raise Err(409, q.SIG_CODE.get(sr["typ"]) if code == "MANDATE_SIG" else code)
        kid = S["creds"][u["id"]]["kid"]
        chain = X["chains"][oid]
        if sr["kind"] == "policy" and not chain:           # genesis: the wa-sig of the pinned key IS the envelope
            pol = cbor2.loads(sr["payload"])
            if [m["kid"] for m in pol["members"]] != [kid]:
                raise Err(409, "POLICY_MALFORMED", "genesis: single member = signer")
            cand = [(sr["payload"], env, now())]
            bad = q.verify_policy_chain(cand, rp=rp)
            if bad:
                raise Err(409, bad[0])
            chain.append({"policy": sr["payload"], "envelope": env, "t": now()})
            sr["sigs"].append(q.wsig_of_wa(env))
            sr["status"] = "done"
            return {"status": "done", "have": 1, "need": 1}
        pol = cur_policy(oid)
        if pol is None:
            raise Err(409, "WQ_POLICY_UNKNOWN")
        if kid not in {m["kid"] for m in pol["members"]}:
            raise Err(409, "WQ_NOT_MEMBER")
        if any(s["kid"] == kid for s in sr["sigs"]):
            raise Err(409, "WQ_DUP_SIGNER")
        sr["sigs"].append(q.wsig_of_wa(env))
        wq = q.make_wq(sr["typ"], sr["payload"], sr["policy_hash"], sr["sigs"])
        code = q.verify_wq(wq, sr["typ"], sr["payload"], chain_t(oid), action=sr["action"], rp=rp)
        need = max([k for _, k in sr["needs"]] or [1])
        if code == "WQ_QUORUM":
            return {"status": "collecting", "have": len(sr["sigs"]), "need": need}
        if code:
            sr["sigs"].pop()
            raise Err(409, code)
        # quorum reached: apply
        if sr["kind"] == "policy":
            cand = chain_t(oid) + [(sr["payload"], wq, max(now(), chain[-1]["t"] + 1))]
            bad = q.verify_policy_chain(cand, rp=rp)
            if bad:
                sr["sigs"].pop()
                raise Err(409, bad[0])
            chain.append({"policy": sr["payload"], "envelope": wq, "t": cand[-1][2]})
            newp = cbor2.loads(sr["payload"])
            keep = {m["kid"] for m in newp["members"]}
            for uid, mm in X["members"][oid].items():
                if S["creds"][uid]["kid"] in keep:
                    mm["status"] = "active"
                    mm["roles"] = next(m["roles"] for m in newp["members"] if m["kid"] == S["creds"][uid]["kid"])
                elif mm["roles"] != ["observer"]:
                    mm["status"] = "removed"
            res = {"policy_ver": newp["ver"]}
        elif sr["kind"] == "mandate":
            m = sr["body"]
            if validate_mandate(m):
                raise Err(409, "MANDATE_MALFORMED")
            for o in S["mandates"].values():
                if o["agent_id"] == m["agent"] and o["status"] == "active":
                    o["status"] = "superseded"
            st = S["state"][oid]
            st.mandates[m["id"]] = dict(m)
            st.currency = st.currency or m["currency"]
            S["mandates"][m["id"]] = {"id": m["id"], "account_id": oid, "agent_id": m["agent"], "status": "active", "mandate": m, "ledger_seq": st.nseq,
                                      "created_at": now(), "envelope": wq, "toolmap_sha256": toolmap_hash(S["agents"][m["agent"]]["toolmap"]),
                                      "signed_by": [s["kid"].hex() for s in sr["sigs"]], "policy_ver": len(chain)}
            st.nseq += 1
            res = {"mandate_id": m["id"], "mandate_status": "active"}
        else:
            res = {}
        sr["status"] = "done"
        return dict({"status": "done", "have": len(sr["sigs"]), "need": need}, **res)

    # ---- batch approvals / release ----
    @app.post("/api/approvals/batch")
    async def approvals_batch(req: Request):
        u = user_of(req, True)
        oid, mem = org_of(u)
        b = await base_body(req)
        rids = b.get("rids")
        if not isinstance(rids, list) or not 1 <= len(rids) <= q.MAX_ITEMS or len(set(rids)) != len(rids):
            raise Err(409, "WB_MALFORMED")
        try:
            env = wa.b64u_dec(b["envelope_b64"])
        except Exception:
            raise Err(409, "WB_MALFORMED")
        xs = []
        for rid in rids:
            x = S["actions"].get(rid)
            if not x or x["account_id"] != oid:
                raise Err(404, "NOT_FOUND", str(rid))
            base_expire(x)
            if x["status"] != "pending_approval":
                raise Err(409, "NOT_DEFERRED", str(rid))
            xs.append(x)
        f = xs[0]
        if any((x["agent_id"], x["class"], x["recipient"]) != (f["agent_id"], f["class"], f["recipient"]) for x in xs):
            raise Err(409, "BATCH_NOT_HOMOGENEOUS")
        pol = cur_policy(oid)
        kid = S["creds"][u["id"]]["kid"]
        if pol is not None:
            for x in xs:
                code = q.wb_requirements_met(pol, kid, x["action"])
                if code:
                    raise Err(409, code, x["rid"])
            who = next(m for m in pol["members"] if m["kid"] == kid)
        else:
            who = reg_of_user(u["id"])
        for x in xs:
            mand = S["mandates"][x["mandate_id"]]["mandate"]
            code = q.verify_wb(env, wa.TYP_APPROVAL, approval_payload(mand, x["action"], x["rid"], True), who, rp=rp)
            if code:
                raise Err(409, code, x["rid"])
        for x in xs:
            S["approvals"][x["rid"]] = {"approved": True, "envelope": env, "t": now()}
            x["status"], x["verdict"], x["reason"], x["updated_at"] = "approved", "allow", "OK_APPROVED", now()
        return {"approved": rids, "n": len(rids), "envelope_items": len(cbor2.loads(env)["items"])}

    def base_expire(x):
        if x["status"] in ("pending_approval", "approved") and now() > x["expires"]:
            x["status"] = "expired"

    # ---- revoke (0.2.0 merge: the path of server 01 and web 05; one signature of any signer) ----
    def own_mandate(u, mid):
        oid, mem = org_of(u)
        m = S["mandates"].get(mid)
        if not m or m["account_id"] != oid:
            raise Err(404, "NOT_FOUND")
        return oid, mem, m

    @app.get("/api/mandates/{mid}/revoke")
    async def revoke_get(mid: str, req: Request):
        oid, mem, m = own_mandate(user_of(req), mid)
        return {"mandate_id": mid, "status": m["status"], "typ": wa.TYP_REVOCATION, "payload_b64": wa.b64u(revocation_payload(m["mandate"]))}

    @app.post("/api/mandates/{mid}/revoke")
    async def revoke_post(mid: str, req: Request):
        u = user_of(req, True)
        oid, mem, m = own_mandate(u, mid)
        if m["status"] != "active":
            raise Err(409, "MANDATE_NOT_ACTIVE")
        b = await base_body(req)
        try:
            env = wa.b64u_dec(b["envelope_b64"])
        except Exception:
            raise Err(409, "WA_MALFORMED")
        if q.envelope_kind(env) != "wa":
            raise Err(409, "WA_MALFORMED")
        code = wa.verify_envelope(env, wa.TYP_REVOCATION, revocation_payload(m["mandate"]), reg_of_user(u["id"]))
        if code:
            raise Err(409, code)
        m["status"] = "revoked"
        return {"mandate_id": mid, "status": "revoked"}

    @app.post("/api/approvals/{rid}/release")
    async def approval_release(rid: str, req: Request):
        u = user_of(req, True)
        oid, mem = org_of(u)
        x = S["actions"].get(rid)
        if not x or x["account_id"] != oid:
            raise Err(404, "NOT_FOUND")
        b = await base_body(req)
        rel = b.get("release")
        if not isinstance(rel, bool):
            raise Err(400, "BAD_REQUEST")
        if x["status"] not in ("held", "pending_approval"):
            raise Err(409, "NOT_HELD")
        try:
            env = wa.b64u_dec(b["envelope_b64"])
            payload = q.release_payload(rid, x["action"]["args_sha256"], rel)
        except Exception:
            raise Err(409, "WA_MALFORMED")
        code = wa.verify_envelope(env, q.TYP_RELEASE, payload, reg_of_user(u["id"]))
        if code:
            raise Err(409, "RELEASE_SIG" if code == "MANDATE_SIG" else code)
        x["adv"] = "heuristic-1:released:%s" % S["creds"][u["id"]]["kid"][:4].hex() if rel else x.get("adv", "")
        if rel:
            x["status"] = "pending_approval" if x["status"] == "pending_approval" else "allowed"
            x["verdict"] = "defer" if x["status"] == "pending_approval" else "allow"
            x["reason"] = "ADVISORY_RELEASED"
        else:
            x["status"], x["verdict"], x["reason"] = "denied", "deny", "ADVISORY_REJECTED"
        return {"status": x["status"], "verdict": x["verdict"], "reason": x["reason"]}

    # ---- fixtures: suggestions / digest ----
    @app.get("/api/suggestions")
    async def suggestions(req: Request):
        u = user_of(req)
        oid, _ = org_of(u)
        ag = next((a["id"] for a in S["agents"].values() if a["account_id"] == oid and not a.get("disabled_at")), "ag_demo")
        return {"suggestions": [
            {"id": "sg_1", "agent_id": ag, "kind": "recipient", "class": "publish", "key": "blog", "approved": 12, "rejected": 0, "window_days": 14,
             "proposal": "add channel blog to the mandate"},
            {"id": "sg_2", "agent_id": ag, "kind": "budget", "class": "purchase", "key": "vendor", "approved": 5, "rejected": 0, "window_days": 14,
             "proposal": "budget 4800 (p95 of approved x 1.2, rounded up to 10)", "proposed_budget": 4800}]}

    @app.get("/api/digest")
    async def digest(req: Request, since: int = None):
        u = user_of(req)
        oid, _ = org_of(u)
        t1 = now()
        xs = [x for x in S["actions"].values() if x["account_id"] == oid and (since is None or x["created_at"] >= since)]
        by_v, by_r, by_a = {}, {}, {}
        for x in xs:
            by_v[x["verdict"]] = by_v.get(x["verdict"], 0) + 1
            by_r[x["reason"]] = by_r.get(x["reason"], 0) + 1
            by_a[x["agent_id"]] = by_a.get(x["agent_id"], 0) + 1
        W = sum(by_v.get(k, 0) for k in ("allow", "deny", "defer"))
        H = sum(1 for x in xs if x["status"] in ("approved", "refused"))
        F = len({id(S["approvals"][x["rid"]]["envelope"]) for x in xs if x["rid"] in S["approvals"]})
        pend = [x for x in xs if x["status"] == "pending_approval"]
        return {"since": since or 0, "until": t1, "W": W, "H": H, "F": F, "by_verdict": by_v, "by_reason": by_r, "by_agent": by_a,
                "pending_by_role": {"budget": sum(1 for x in pend if x["class"] in q.MONEY), "access": sum(1 for x in pend if x["class"] not in q.MONEY)},
                "suggestions": (await suggestions(req))["suggestions"], "approval_rate_denials": by_r.get("APPROVAL_RATE", 0),
                "catalog_drift": [a for a, c in X["catalog"].items() if c.get("drift")]}

    # ---- agent paths: catalog / coverage ----
    def agent_key(req):
        h = req.headers.get("authorization", "")
        a = S["keys"].get(hashlib.sha256(h[7:].encode()).hexdigest()) if h.startswith("Bearer dwk_") else None
        if not a or S["agents"][a].get("disabled_at"):
            raise Err(401, "BAD_KEY")
        return S["agents"][a]

    @app.post("/v1/catalog")
    async def catalog_post(req: Request):
        a = agent_key(req)
        tools = (await base_body(req)).get("tools")
        if not isinstance(tools, list) or not all(isinstance(t, dict) and isinstance(t.get("name"), str) for t in tools):
            raise Err(400, "BAD_REQUEST")
        h = hashlib.sha256(json.dumps(sorted(tools, key=lambda t: t["name"]), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        old = X["catalog"].get(a["id"])
        X["catalog"][a["id"]] = {"tools": tools, "sha256": h, "t": now(), "drift": bool(old and old["sha256"] != h)}
        return {"catalog_sha256": h, "n_tools": len(tools), "changed": bool(old and old["sha256"] != h)}

    @app.post("/v1/coverage")
    async def coverage_post(req: Request):
        a = agent_key(req)
        b = await base_body(req)
        if b.get("level") not in ("C0", "C1", "C2", "C3") or not isinstance(b.get("unwitnessed", []), list):
            raise Err(422, "BAD_COVERAGE")
        X["coverage"][a["id"]] = {"level": b["level"], "unwitnessed": b.get("unwitnessed", []), "tool": str(b.get("tool", "")),
                                  "pass_net_tools": b.get("pass_net_tools", []), "t": now(), "operator_declared": True}
        return {"ok": True, "level": b["level"]}

    def own_agent(u, aid):
        oid, _ = org_of(u)
        a = S["agents"].get(aid)
        if not a or a["account_id"] != oid:
            raise Err(404, "NOT_FOUND")
        return a

    @app.get("/api/catalog/{agent}")
    async def catalog_get(agent: str, req: Request):
        a = own_agent(user_of(req), agent)
        c = X["catalog"].get(a["id"])
        draft, unknown = suggest_toolmap(c["tools"]) if c else (None, [])
        return {"agent_id": a["id"], "catalog_sha256": c["sha256"] if c else None, "tools": c["tools"] if c else [], "drift": bool(c and c["drift"]),
                "suggested_toolmap": draft, "unknown": [{"tool": t, "arg": n} for t, n in unknown], "coverage": X["coverage"].get(a["id"])}

    @app.post("/api/catalog/{agent}/draft")
    async def catalog_draft(agent: str, req: Request):
        a = own_agent(user_of(req, True), agent)
        c = X["catalog"].get(a["id"])
        if not c:
            raise Err(409, "NO_CATALOG")
        draft, unknown = suggest_toolmap(c["tools"])
        return {"toolmap_draft": draft, "unknown": [{"tool": t, "arg": n} for t, n in unknown], "applicable": not unknown, "catalog_sha256": c["sha256"]}

    # the 0.1 route /api/approvals/{rid} would swallow /api/approvals/batch: new routes go first
    app.router.routes[:] = app.router.routes[N0:] + app.router.routes[:N0]
    web = web_dir or os.path.normpath(os.path.join(CONTRACT, "../web"))
    if os.path.isdir(web):
        app.mount("/", StaticFiles(directory=web, html=True), name="web")
    return app


if __name__ == "__main__":
    import uvicorn
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8801)
    ap.add_argument("--rp-id", default="localhost")
    ap.add_argument("--origin")
    ap.add_argument("--web")
    o = ap.parse_args()
    uvicorn.run(create_app02(o.rp_id, o.origin or "http://localhost:%d" % o.port, o.web), host="127.0.0.1", port=o.port, log_level="warning")
