"""Stub of Deus Witness Cloud (ARHITEKTURA 5.5): FastAPI, in memory. Implements every path of 5.1-5.2.
Registration: attestation is parsed, NOT verified (fmt none). Login: assertion signature is verified.
Mandates/approvals: wa_profile.verify_envelope for real. Decisions: svidetel_v4.decide (State) without a ledger.
AAR / proof: fake bytes. Usage: python stub.py --port 8801 [--rp-id localhost] [--origin http://localhost:8801]"""
import argparse, asyncio, base64, hashlib, io, json, os, re, secrets, sys, time, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "../..")))
import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

import wa_profile as wa
from forms import mandate_from_form
from svidetel_v4.schema import validate_mandate
from svidetel_v4.state import State, approval_payload, request_hash

TTL = 900
def toolmap_hash(tm):
    return hashlib.sha256(json.dumps(tm, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


PRESETS = {
    "demo": {"version": 1, "default": "deny", "tools": {
        "send_email": {"class": "message", "recipient": "$.to", "text": ["$.subject", "$.body"]},
        "purchase": {"class": "purchase", "recipient": "$.vendor", "amount": "$.amount_cents", "currency": "USD"},
        "delete_resource": {"class": "delete", "recipient": "$.resource", "reversible": {"cache-tmp": True}},
        "publish": {"class": "publish", "recipient": "$.channel", "text": ["$.text"]},
        "read_file": {"class": "pass"}}},
    "filesystem": {"version": 1, "default": "deny", "tools": {
        "write_file": {"class": "file", "recipient": "$.path", "text": ["$.content"]},
        "edit_file": {"class": "file", "recipient": "$.path", "text": ["$.content"]},
        "move_file": {"class": "delete", "recipient": "$.source", "reversible": True},
        "read_file": {"class": "pass"}, "list_directory": {"class": "pass"}, "search_files": {"class": "pass"}}},
    "empty": {"version": 1, "default": "deny", "tools": {}},
}
CLASSES = ("message", "file", "disclosure", "purchase", "sale", "meeting", "refund", "delete", "publish", "pass")
SECRET_RE = [  # patterns of dogfood/ten.py (copied; no values)
    ("telegram_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b")),
    ("api_key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|xox[abprs]-[A-Za-z0-9-]{10,})\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"))]
FAKE_AAR = cbor2.dumps({"stub": "aar not signed"})


class Err(Exception):
    def __init__(self, status, code, detail=""):
        self.status, self.code, self.detail = status, code, detail


def now():
    return int(time.time())


def short_kid(kid: bytes) -> str:
    h = kid[:8].hex()
    return " ".join(h[i:i + 4] for i in range(0, 16, 4))


def jpath(obj, path):
    cur = obj
    for p in path[2:].split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def create_app(rp_id="localhost", origin="http://localhost:8899", web_dir=None):
    app = FastAPI(title="Deus Witness Cloud stub")
    S = dict(accounts={}, creds={}, sessions={}, flows={}, agents={}, keys={}, mandates={}, actions={}, approvals={},
             state={}, patterns={}, feed=[])

    @app.exception_handler(Err)
    async def _err(_, e):
        return JSONResponse({"error": e.code, "detail": e.detail}, status_code=e.status)

    async def body(req):
        try:
            b = await req.json()
        except Exception:
            raise Err(400, "BAD_REQUEST", "JSON body expected")
        return b if isinstance(b, dict) else {}

    def session(req, write=False):
        if write and req.headers.get("origin") not in (None, origin):
            raise Err(403, "BAD_ORIGIN")
        a = S["sessions"].get(req.cookies.get("dw_session", ""))
        if not a:
            raise Err(401, "NO_SESSION")
        return S["accounts"][a]

    def agent_of(req):
        h = req.headers.get("authorization", "")
        a = S["keys"].get(hashlib.sha256(h[7:].encode()).hexdigest()) if h.startswith("Bearer dwk_") else None
        if not a or S["agents"][a].get("disabled_at"):
            raise Err(401, "BAD_KEY")
        return S["agents"][a]

    def reg_entry(acc):
        c = S["creds"][acc["id"]]
        return {"alg": "ES256", "pub": c["pub"].hex(),
                "webauthn": {"rp_id": rp_id, "origins": [origin], "credential_id": wa.b64u(c["credential_id"])},
                "pin_source": "webauthn-registration:%s:%s:registry-log#%d" % (rp_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(c["created_at"])), c["seq"])}

    def start_session(acc, resp):
        tok = secrets.token_urlsafe(32)
        S["sessions"][tok] = acc["id"]
        resp.set_cookie("dw_session", tok, httponly=True, samesite="strict")

    def check_client_data(cd_b64, typ, flow):
        cd = json.loads(wa.b64u_dec(cd_b64))
        if cd.get("type") != typ or cd.get("challenge") != flow["challenge"] or cd.get("origin") != origin:
            raise Err(400, "WA_CLIENTDATA")
        return wa.b64u_dec(cd_b64)

    # ---------------- auth ----------------
    @app.post("/api/auth/register/begin")
    async def reg_begin(req: Request):
        b = await body(req)
        fid, ch = secrets.token_hex(8), wa.b64u(os.urandom(32))
        name = str(b.get("display_name") or "user")
        uid = os.urandom(16)
        S["flows"][fid] = {"purpose": "register", "challenge": ch, "display_name": name, "user_id": uid}
        return {"flow_id": fid, "options": {
            "rp": {"id": rp_id, "name": "Deus Witness"}, "user": {"id": wa.b64u(uid), "name": name, "displayName": name},
            "challenge": ch, "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"residentKey": "required", "userVerification": "required"},
            "attestation": "none", "timeout": 300000}}

    @app.post("/api/auth/register/finish")
    async def reg_finish(req: Request):
        b = await body(req)
        flow = S["flows"].pop(b.get("flow_id"), None)
        if not flow or flow["purpose"] != "register":
            raise Err(400, "FLOW_UNKNOWN")
        r = b["credential"]["response"]
        check_client_data(r["clientDataJSON"], "webauthn.create", flow)
        att = cbor2.loads(wa.b64u_dec(r["attestationObject"]))
        ad = att["authData"]
        if ad[:32] != hashlib.sha256(rp_id.encode()).digest() or not ad[32] & wa.FLAG_AT or not ad[32] & wa.FLAG_UV:
            raise Err(400, "WA_AUTHDATA")
        n = int.from_bytes(ad[53:55], "big")
        cid = ad[55:55 + n]
        key = cbor2.loads(ad[55 + n:])
        if key.get(3) != -7:
            raise Err(400, "WA_ALG", "only ES256")
        pub = b"\x04" + key[-2] + key[-3]
        aid = os.urandom(16).hex()
        acc = {"id": aid, "principal": "dw:" + aid, "display_name": flow["display_name"]}
        S["accounts"][aid] = acc
        S["creds"][aid] = {"credential_id": cid, "pub": pub, "kid": wa.thumbprint(pub), "created_at": now(), "seq": len(S["creds"]) + 1}
        S["state"][aid] = State()
        resp = JSONResponse({"account": acc, "keycard": {"kid_hex": wa.thumbprint(pub).hex(), "short": short_kid(wa.thumbprint(pub))}})
        start_session(acc, resp)
        return resp

    @app.post("/api/auth/login/begin")
    async def login_begin(req: Request):
        fid, ch = secrets.token_hex(8), wa.b64u(os.urandom(32))
        S["flows"][fid] = {"purpose": "login", "challenge": ch}
        return {"flow_id": fid, "options": {"challenge": ch, "rpId": rp_id, "userVerification": "required", "allowCredentials": [], "timeout": 300000}}

    @app.post("/api/auth/login/finish")
    async def login_finish(req: Request):
        b = await body(req)
        flow = S["flows"].pop(b.get("flow_id"), None)
        if not flow or flow["purpose"] != "login":
            raise Err(400, "FLOW_UNKNOWN")
        cred = b["credential"]
        cid = wa.b64u_dec(cred["rawId"] if "rawId" in cred else cred["id"])
        aid = next((a for a, c in S["creds"].items() if c["credential_id"] == cid), None)
        if not aid:
            raise Err(401, "CREDENTIAL_UNKNOWN")
        r = cred["response"]
        cd = check_client_data(r["clientDataJSON"], "webauthn.get", flow)
        ad = wa.b64u_dec(r["authenticatorData"])
        if ad[:32] != hashlib.sha256(rp_id.encode()).digest() or not ad[32] & wa.FLAG_UP or not ad[32] & wa.FLAG_UV:
            raise Err(401, "WA_AUTHDATA")
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), S["creds"][aid]["pub"])
            key.verify(wa.b64u_dec(r["signature"]), ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError):
            raise Err(401, "WA_SIG")
        resp = JSONResponse({"account": S["accounts"][aid]})
        start_session(S["accounts"][aid], resp)
        return resp

    @app.post("/api/auth/logout")
    async def logout(req: Request):
        S["sessions"].pop(req.cookies.get("dw_session", ""), None)
        resp = Response(status_code=204)
        resp.delete_cookie("dw_session")
        return resp

    @app.get("/api/me")
    async def me(req: Request):
        acc = session(req)
        c = S["creds"][acc["id"]]
        return {"account": acc, "keycard": {"kid_hex": c["kid"].hex(), "short": short_kid(c["kid"]),
                                           "credential_id_b64": wa.b64u(c["credential_id"]), "rp_id": rp_id, "origins": [origin]}}

    # ---------------- agents ----------------
    def agent_view(a):
        act = next((m for m in S["mandates"].values() if m["agent_id"] == a["id"] and m["status"] == "active"), None)
        return {"id": a["id"], "name": a["name"], "key_prefix": a["key_prefix"], "created_at": a["created_at"],
                "active_mandate_id": act["id"] if act else None, "toolmap": a["toolmap"],
                "toolmap_sha256": toolmap_hash(a["toolmap"]), "toolmap_signed": bool(act and act.get("toolmap_sha256") == toolmap_hash(a["toolmap"]))}

    def check_toolmap(tm):
        if not isinstance(tm, dict) or tm.get("version") != 1 or tm.get("default") not in ("deny", "pass") or not isinstance(tm.get("tools"), dict):
            raise Err(422, "TOOLMAP_INVALID", "version=1, default deny|pass, tools{}")
        for n, t in tm["tools"].items():
            if not isinstance(t, dict) or t.get("class") not in CLASSES:
                raise Err(422, "TOOLMAP_INVALID", "bad class for " + str(n))
            for k in ("recipient", "amount"):
                if isinstance(t.get(k), str) and not re.fullmatch(r"\$(\.[A-Za-z0-9_]+)+", t[k]):
                    raise Err(422, "TOOLMAP_INVALID", "path " + k)

    @app.get("/api/agents")
    async def agents(req: Request):
        acc = session(req)
        return [agent_view(a) for a in S["agents"].values() if a["account_id"] == acc["id"] and not a.get("disabled_at")]

    @app.post("/api/agents")
    async def agent_new(req: Request):
        acc = session(req, True)
        b = await body(req)
        if sum(1 for a in S["agents"].values() if a["account_id"] == acc["id"] and not a.get("disabled_at")) >= 3:
            raise Err(429, "QUOTA", "3 agents on the free tier")
        key = "dwk_" + base64.b32encode(os.urandom(32)).decode().rstrip("=")
        aid = "ag_" + os.urandom(6).hex()
        a = {"id": aid, "account_id": acc["id"], "name": str(b.get("name") or "agent"), "key_prefix": key[:12],
             "created_at": now(), "toolmap": json.loads(json.dumps(PRESETS.get(b.get("preset") or "demo", PRESETS["demo"])))}
        S["agents"][aid] = a
        S["keys"][hashlib.sha256(key.encode()).hexdigest()] = aid
        return {"agent": agent_view(a), "api_key": key}

    @app.put("/api/agents/{aid}/toolmap")
    async def toolmap_put(aid: str, req: Request):
        acc = session(req, True)
        a = S["agents"].get(aid)
        if not a or a["account_id"] != acc["id"]:
            raise Err(404, "NOT_FOUND")
        tm = (await body(req)).get("toolmap")
        check_toolmap(tm)
        a["toolmap"] = tm
        return {"agent": agent_view(a)}

    @app.delete("/api/agents/{aid}")
    async def agent_del(aid: str, req: Request):
        acc = session(req, True)
        a = S["agents"].get(aid)
        if not a or a["account_id"] != acc["id"]:
            raise Err(404, "NOT_FOUND")
        a["disabled_at"] = now()
        return Response(status_code=204)

    @app.get("/api/data-patterns")
    async def dp_get(req: Request):
        return {"patterns": S["patterns"].get(session(req)["id"], {})}

    @app.put("/api/data-patterns")
    async def dp_put(req: Request):
        acc = session(req, True)
        p = (await body(req)).get("patterns")
        if not isinstance(p, dict):
            raise Err(422, "BAD_PATTERNS")
        S["patterns"][acc["id"]] = p
        return {"patterns": p}

    # ---------------- mandates ----------------
    @app.post("/api/mandates/draft")
    async def draft(req: Request):
        acc = session(req, True)
        b = await body(req)
        a = S["agents"].get(b.get("agent_id"))
        if not a or a["account_id"] != acc["id"]:
            raise Err(404, "NOT_FOUND")
        m = mandate_from_form(b.get("form") or {}, acc["principal"], a["id"], reg_entry(acc)["pin_source"])
        return {"mandate": m, "typ": wa.TYP_MANDATE, "toolmap_sha256": toolmap_hash(a["toolmap"])}

    @app.post("/api/mandates")
    async def mandate_post(req: Request):
        acc = session(req, True)
        b = await body(req)
        m = b.get("mandate")
        try:
            env = wa.b64u_dec(b["envelope_b64"])
        except Exception:
            raise Err(409, "WA_MALFORMED")
        if not isinstance(m, dict) or validate_mandate(m):
            raise Err(409, "MANDATE_MALFORMED")
        if m.get("principal") != acc["principal"] or m.get("agent") not in S["agents"] or S["agents"][m["agent"]]["account_id"] != acc["id"]:
            raise Err(409, "MANDATE_PRINCIPAL")
        if m["id"] in S["mandates"]:
            raise Err(409, "MANDATE_EXISTS")
        code = wa.verify_envelope(env, wa.TYP_MANDATE, wa.cde(m), reg_entry(acc))
        if code:
            raise Err(409, code)
        for o in S["mandates"].values():
            if o["agent_id"] == m["agent"] and o["status"] == "active":
                o["status"] = "superseded"
        st = S["state"][acc["id"]]
        st.mandates[m["id"]] = dict(m)
        st.currency = st.currency or m["currency"]
        S["mandates"][m["id"]] = {"id": m["id"], "account_id": acc["id"], "agent_id": m["agent"], "status": "active", "mandate": m,
                                  "ledger_seq": st.nseq, "created_at": now(), "envelope": env,
                                  "toolmap_sha256": toolmap_hash(S["agents"][m["agent"]]["toolmap"])}
        st.nseq += 1
        return {"mandate_id": m["id"], "status": "active", "ledger_seq": st.nseq - 1, "toolmap_sha256": S["mandates"][m["id"]]["toolmap_sha256"]}

    @app.get("/api/mandates")
    async def mandates(req: Request):
        acc = session(req)
        return [{k: m[k] for k in ("id", "agent_id", "status", "mandate", "ledger_seq", "created_at")} for m in S["mandates"].values() if m["account_id"] == acc["id"]]

    # ---------------- feed / budget / approvals ----------------
    @app.get("/api/feed")
    async def feed(req: Request, agent_id: str = None, before: int = None, limit: int = 50):
        acc = session(req)
        rows = [x for x in S["actions"].values() if x["account_id"] == acc["id"] and (agent_id is None or x["agent_id"] == agent_id)
                and (before is None or x["created_at"] < before)]
        rows.sort(key=lambda x: (-x["created_at"], x["rid"]), reverse=False)
        rows = rows[:min(limit, 200)]
        items = [{"rid": x["rid"], "t": x["created_at"], "agent_id": x["agent_id"], "tool": x["tool"], "class": x["class"], "recipient": x["recipient"],
                  "amount": x["amount"], "currency": x["currency"], "verdict": x["verdict"], "reason": x["reason"], "status": x["status"],
                  "args_preview": x["args_preview"]} for x in rows]
        return {"items": items, "next_before": rows[-1]["created_at"] if len(rows) == min(limit, 200) else None}

    @app.get("/api/budget")
    async def budget(req: Request):
        acc = session(req)
        st = S["state"][acc["id"]]
        out = []
        for m in S["mandates"].values():
            if m["account_id"] == acc["id"] and m["status"] == "active":
                mm = m["mandate"]
                pu = mm["permissions"].get("purchase")
                if isinstance(pu, dict):
                    out.append({"mandate_id": m["id"], "agent_id": m["agent_id"], "currency": mm["currency"], "budget": pu.get("budget"),
                                "max_per_action": pu.get("max_per_action"), "committed": st.committed(now(), m["id"], mm["budget_window_s"]),
                                "window_s": mm["budget_window_s"]})
        return out

    def expire(x):
        if x["status"] in ("pending_approval", "approved") and now() > x["expires"]:
            x["status"] = "expired"

    @app.get("/api/approvals")
    async def approvals(req: Request, status: str = "pending"):
        acc = session(req)
        out = []
        for x in S["actions"].values():
            expire(x)
            if x["account_id"] == acc["id"] and x["status"] == "pending_approval":
                out.append({"rid": x["rid"], "t": x["created_at"], "agent_id": x["agent_id"], "tool": x["tool"], "action": x["action"], "expires": x["expires"]})
        return out

    def own_action(acc, rid):
        x = S["actions"].get(rid)
        if not x or x["account_id"] != acc["id"]:
            raise Err(404, "NOT_FOUND")
        expire(x)
        return x

    @app.get("/api/approvals/{rid}")
    async def approval_get(rid: str, req: Request):
        x = own_action(session(req), rid)
        return {"rid": rid, "status": x["status"], "action": x["action"], "mandate": S["mandates"][x["mandate_id"]]["mandate"], "expires": x["expires"],
                "tool": x.get("tool", ""), "args_preview": x.get("args_preview", ""), "text_preview": x.get("text_preview", ""),
                "preview_note": "Shown by the witness page, not signed. What your passkey signs is the action above, including args_sha256."}

    @app.post("/api/approvals/{rid}")
    async def approval_post(rid: str, req: Request):
        acc = session(req, True)
        x = own_action(acc, rid)
        b = await body(req)
        if x["status"] != "pending_approval":
            raise Err(409, "NOT_DEFERRED")
        approved = b.get("approved")
        if not isinstance(approved, bool):
            raise Err(400, "BAD_REQUEST")
        try:
            env = wa.b64u_dec(b["envelope_b64"])
        except Exception:
            raise Err(409, "WA_MALFORMED")
        mand = S["mandates"][x["mandate_id"]]["mandate"]
        code = wa.verify_envelope(env, wa.TYP_APPROVAL, approval_payload(mand, x["action"], rid, approved), reg_entry(acc))
        if code:
            raise Err(409, code)
        S["approvals"][rid] = {"approved": approved, "envelope": env, "t": now()}
        x["status"] = "approved" if approved else "refused"
        x["updated_at"] = now()
        if approved:
            x["verdict"], x["reason"] = "allow", "OK_APPROVED"
        return {"verdict": "allow" if approved else "refused"}

    @app.get("/api/export")
    async def export(req: Request):
        acc = session(req)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("README.txt", "STUB evidence pack: not a real pack.\n")
            z.writestr("manifest.json", json.dumps({"account": acc["id"], "principal": acc["principal"], "stub": True}))
        return Response(buf.getvalue(), media_type="application/zip")

    witness = {"iss": "https://witness.sipkigroup.com", "alg": "EdDSA", "kid_hex": "00" * 32, "pub_hex": "11" * 32, "web_js_sha256": {}}

    @app.get("/api/witness")
    @app.get("/v1/witness")
    async def witness_get():
        return witness

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "ledgers": len(S["state"]), "last_anchor_t": None}

    # ---------------- agent API ----------------
    def build_action(a, tool, args, acc_id):
        tm = a["toolmap"]
        t = tm["tools"].get(tool)
        if t is None:
            return None if tm["default"] == "pass" else "UNMAPPED"
        if t["class"] == "pass":
            return None
        act = {"agent": a["id"], "class": t["class"],
               "args_sha256": hashlib.sha256(json.dumps([tool, args], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()}
        if "recipient" in t:
            rc = t["recipient"][0] if isinstance(t["recipient"], list) and t["recipient"] else t["recipient"]
            v = jpath(args, rc) if isinstance(rc, str) else None
            act["recipient"] = v if isinstance(v, str) else ("" if v is None else str(v))
        text = " \n".join(str(jpath(args, p)) for p in t.get("text", []) if jpath(args, p) is not None)
        tags = set(n for n, rx in SECRET_RE if rx.search(text))
        for cls, lits in S["patterns"].get(acc_id, {}).items():
            if any(l.lower() in text.lower() for l in lits):
                tags.add(cls)
        act["data"] = sorted(tags)
        if t["class"] in ("purchase", "sale", "refund"):
            act["amount"] = jpath(args, t["amount"]) if isinstance(t.get("amount"), str) else t.get("amount")
            act["currency"] = t.get("currency", "USD")
        if t["class"] == "delete":
            rv = t.get("reversible")
            act["reversible"] = (rv is True) or (isinstance(rv, dict) and rv.get(act["recipient"]) is True)
        return act

    def mask(args):
        s = json.dumps(args, ensure_ascii=False)
        for _, rx in SECRET_RE:
            s = rx.sub("[masked]", s)
        return s[:300]

    def result(x):
        expire(x)
        verdict = x["verdict"]
        r = {"rid": x["rid"], "verdict": "deny" if x["status"] == "expired" and verdict == "allow" else verdict, "reason": x["reason"],
             "status": x["status"], "action": x["action"], "expires": x["expires"], "aar_b64": None, "proof": None, "approval_url": None}
        if x["verdict"] == "allow":
            r["aar_b64"] = wa.b64u(FAKE_AAR)
            r["proof"] = {"entry_b64": wa.b64u(b"stub-entry"), "path_b64": [], "checkpoint_b64": wa.b64u(b"stub-checkpoint"),
                          "approval": ({"approved": True, "envelope_b64": wa.b64u(S["approvals"][x["rid"]]["envelope"])} if x["rid"] in S["approvals"] else None)}
        if x["status"] == "pending_approval":
            r["approval_url"] = "%s/approve.html?rid=%s" % (origin, x["rid"])
        return r

    @app.post("/v1/actions")
    async def action_post(req: Request):
        a = agent_of(req)
        b = await body(req)
        tool, args = b.get("tool"), b.get("args") or {}
        if not isinstance(tool, str) or not isinstance(args, dict):
            raise Err(400, "BAD_REQUEST")
        acc_id, t0 = a["account_id"], now()
        act = build_action(a, tool, args, acc_id)
        row = {"rid": "r_" + base64.b32encode(os.urandom(16)).decode().rstrip("=")[:26], "account_id": acc_id, "agent_id": a["id"], "mandate_id": None,
               "tool": tool, "args_preview": mask(args), "action": None, "class": "", "recipient": None, "amount": None, "currency": None,
               "created_at": t0, "updated_at": t0, "expires": t0 + TTL}
        if act is None or act == "UNMAPPED":
            if act is None and a["toolmap"]["tools"].get(tool, {}).get("class", "pass") == "pass":
                row.update(verdict="pass", reason="PASS", status="pass", **{"class": "pass"})
            else:
                row.update(verdict="deny", reason="TOOL_UNMAPPED", status="denied")
            S["actions"][row["rid"]] = row
            return result(row)
        rh = request_hash(act)
        for x in S["actions"].values():  # repeat of a pending/approved action returns THAT action
            expire(x)
            if x["agent_id"] == a["id"] and x.get("rh") == rh and x["status"] in ("pending_approval", "approved"):
                return result(x)
        mid = next((m["id"] for m in S["mandates"].values() if m["agent_id"] == a["id"] and m["status"] == "active"), None)
        row.update(action=act, rh=rh, mandate_id=mid, **{"class": act["class"]}, recipient=act.get("recipient"), amount=act.get("amount"), currency=act.get("currency"))
        if mid is None:
            row.update(verdict="deny", reason="NO_MANDATE", status="denied")
        else:
            st = S["state"][acc_id]
            _, v, why = st.decide_for(mid, act, t0)
            row.update(verdict=v, reason=why, status={"allow": "allowed", "deny": "denied", "defer": "pending_approval"}[v])
            if act["class"] == "purchase" and v in ("allow", "defer"):
                st.apply("RECEIPT", {"id": row["rid"], "verdict": v, "reason": why, "action": act, "mandate": mid, "ttl": TTL}, t0)
        S["actions"][row["rid"]] = row
        return result(row)

    def own_agent_action(a, rid):
        x = S["actions"].get(rid)
        if not x or x["agent_id"] != a["id"]:
            raise Err(404, "NOT_FOUND")
        return x

    @app.get("/v1/actions/{rid}")
    async def action_get(rid: str, req: Request, wait: int = 0):
        a = agent_of(req)
        x = own_agent_action(a, rid)
        end = time.time() + max(0, min(wait, 25))
        expire(x)
        while x["status"] == "pending_approval" and time.time() < end:
            await asyncio.sleep(0.1)
            expire(x)
        return result(x)

    @app.post("/v1/actions/{rid}/present")
    async def present(rid: str, req: Request):
        x = own_agent_action(agent_of(req), rid)
        expire(x)
        if x["status"] == "consumed":
            return {"result": "reject", "reason": "REPLAY"}
        if x["status"] == "expired":
            return {"result": "reject", "reason": "RECEIPT_EXPIRED"}
        if x["status"] not in ("allowed", "approved"):
            return {"result": "reject", "reason": "NOT_ALLOWED"}
        x["status"] = "consumed"
        return {"result": "accept", "reason": "OK"}

    @app.post("/v1/actions/{rid}/report")
    async def report(rid: str, req: Request):
        x = own_agent_action(agent_of(req), rid)
        b = await body(req)
        if x["status"] != "consumed":
            return {"result": "ignored"}
        x["status"] = "executed" if b.get("executed") else "not_executed"
        return {"result": "released" if not b.get("executed") else "ignored"}

    web = web_dir or os.path.normpath(os.path.join(HERE, "../web"))
    if os.path.isdir(web):
        app.mount("/", StaticFiles(directory=web, html=True), name="web")
    app.state.S = S
    return app


if __name__ == "__main__":
    import uvicorn
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--rp-id", default="localhost")
    ap.add_argument("--origin")
    ap.add_argument("--web")
    o = ap.parse_args()
    uvicorn.run(create_app(o.rp_id, o.origin or "http://localhost:%d" % o.port, o.web), host="127.0.0.1", port=o.port, log_level="warning")
