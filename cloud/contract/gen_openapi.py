"""Builds openapi.yaml (machine form of ARHITEKTURA sections 5.1-5.3)."""
import yaml
R = lambda n: {"$ref": "#/components/schemas/" + n}
obj = lambda props=None, req=None, **kw: dict({"type": "object", "properties": props or {}, **({"required": req} if req else {})}, **kw)
S, I, B = {"type": "string"}, {"type": "integer"}, {"type": "boolean"}
arr = lambda x: {"type": "array", "items": x}
def ok(schema, desc="OK"): return {"description": desc, "content": {"application/json": {"schema": schema}}}
def body(schema): return {"required": True, "content": {"application/json": {"schema": schema}}}
ERR = {"default": {"description": "Error", "content": {"application/json": {"schema": R("Error")}}}}
web, agent = [{"cookieSession": []}], [{"bearerKey": []}]
def op(summary, resp, sec=None, req=None, params=None, status="200", **extra):
    o = {"summary": summary, "responses": dict({status: resp}, **ERR)}
    if sec is not None: o["security"] = sec
    if req: o["requestBody"] = body(req)
    if params: o["parameters"] = params
    o.update(extra); return o
q = lambda n, s, d=None: {"name": n, "in": "query", "schema": s, **({"description": d} if d else {})}
pth = lambda n: {"name": n, "in": "path", "required": True, "schema": S}
nocontent = {"description": "No content"}
P = {}
P["/api/auth/register/begin"] = {"post": op("Start passkey registration", ok(obj({"flow_id": S, "options": R("CreationOptions")}, ["flow_id", "options"])), [], obj({"display_name": S}))}
P["/api/auth/register/finish"] = {"post": op("Finish registration (attestation none, ES256 only); sets dw_session", ok(obj({"account": R("Account"), "keycard": R("Keycard")}, ["account", "keycard"])), [], obj({"flow_id": S, "credential": {"type": "object"}}, ["flow_id", "credential"]))}
P["/api/auth/login/begin"] = {"post": op("Start discoverable-credential login", ok(obj({"flow_id": S, "options": {"type": "object"}}, ["flow_id", "options"])), [], obj())}
P["/api/auth/login/finish"] = {"post": op("Finish login; sets dw_session", ok(obj({"account": R("Account")})), [], obj({"flow_id": S, "credential": {"type": "object"}}, ["flow_id", "credential"]))}
P["/api/auth/logout"] = {"post": op("Logout", nocontent, web, status="204")}
P["/api/auth/logout-all"] = {"post": op("Sign out everywhere: ends every session of the account (0.1.1, R-17)", nocontent, web, status="204")}
P["/api/auth/stepup/begin"] = {"post": op("Start a passkey step-up (R-17)", ok(obj({"flow_id": S, "options": {"type": "object"}}, ["flow_id", "options"])), web, obj())}
P["/api/auth/stepup/finish"] = {"post": op("Finish step-up; later PUT data-patterns / PUT toolmap / POST agents (0.1.2, N-12) / DELETE agent need it within 5 minutes, else 403 STEPUP_REQUIRED", ok(obj({"ok": B, "valid_for_s": I})), web, obj({"flow_id": S, "credential": {"type": "object"}}, ["flow_id", "credential"]))}
P["/api/me"] = {"get": op("Current account and key card", ok(obj({"account": R("Account"), "keycard": R("KeycardFull")})), web)}
P["/api/agents"] = {"get": op("List agents", ok(arr(R("Agent"))), web),
                    "post": op("Create agent; api_key shown once", ok(obj({"agent": R("Agent"), "api_key": {"type": "string", "pattern": "^dwk_[A-Z2-7]{52}$"}}, ["agent", "api_key"])), web,
                               obj({"name": S, "preset": {"type": "string", "enum": ["demo", "filesystem", "empty"]}}, ["name"]))}
P["/api/agents/{id}/toolmap"] = {"put": op("Replace toolmap; 422 TOOLMAP_INVALID", ok(obj({"agent": R("Agent")})), web, obj({"toolmap": R("Toolmap")}, ["toolmap"]), [pth("id")])}
P["/api/agents/{id}"] = {"delete": op("Disable agent (key stops working)", nocontent, web, params=[pth("id")], status="204")}
P["/api/data-patterns"] = {"get": op("Closed-data literals for DLP", ok(obj({"patterns": {"type": "object", "additionalProperties": arr(S)}})), web),
                           "put": op("Replace closed-data literals", ok(obj({"patterns": {"type": "object", "additionalProperties": arr(S)}})), web, obj({"patterns": {"type": "object", "additionalProperties": arr(S)}}, ["patterns"]))}
P["/api/mandates/draft"] = {"post": op("Build the -04 mandate map from the form (section 5.3)", ok(obj({"mandate": R("Mandate"), "typ": {"const": "application/aar-mandate+cbor"}, "toolmap_sha256": S}, ["mandate", "typ"])), web, obj({"agent_id": S, "form": R("MandateForm")}, ["agent_id", "form"]))}
P["/api/mandates"] = {"post": op("Submit mandate + wa-sig envelope; 409 code = -04 code or WA_*", ok(obj({"mandate_id": S, "status": {"const": "active"}, "ledger_seq": I, "toolmap_sha256": S}, ["mandate_id", "status", "ledger_seq"])), web, obj({"mandate": R("Mandate"), "envelope_b64": S, "toolmap_sha256": S}, ["mandate", "envelope_b64"])),
                      "get": op("List mandates", ok(arr(obj({"id": S, "agent_id": S, "status": {"enum": ["active", "revoked", "expired", "superseded"]}, "mandate": R("Mandate"), "ledger_seq": I, "created_at": I}))), web)}
P["/api/feed"] = {"get": op("Action feed, newest first", ok(obj({"items": arr(R("FeedItem")), "next_before": {"type": ["integer", "null"]}}, ["items"])), web, params=[q("agent_id", S), q("before", I), q("limit", {"type": "integer", "maximum": 200, "default": 50})])}
P["/api/budget"] = {"get": op("Budget use per active mandate", ok(arr(obj({"mandate_id": S, "agent_id": S, "currency": S, "budget": {"type": ["integer", "null"]}, "max_per_action": {"type": ["integer", "null"]}, "committed": I, "window_s": I}))), web)}
P["/api/approvals"] = {"get": op("Pending approvals", ok(arr(obj({"rid": S, "t": I, "agent_id": S, "tool": S, "action": R("Action"), "expires": I}))), web, params=[q("status", {"const": "pending"})])}
P["/api/approvals/{rid}"] = {"get": op("Approval details; the browser builds the -04 6.6 payload from mandate+action", ok(obj({"rid": S, "status": S, "action": R("Action"), "mandate": R("Mandate"), "expires": I, "tool": S, "args_preview": S, "text_preview": S, "preview_note": S})), web, params=[pth("rid")]),
                             "post": op("Submit approval wa-sig; 409 APPROVAL_SIG|NOT_DEFERRED|WA_*", ok(obj({"verdict": {"enum": ["allow", "refused"]}}, ["verdict"])), web, obj({"approved": B, "envelope_b64": S}, ["approved", "envelope_b64"]), [pth("rid")])}
P["/api/export"] = {"get": op("Evidence pack zip", {"description": "zip", "content": {"application/zip": {"schema": {"type": "string", "format": "binary"}}}}, web)}
P["/api/witness"] = {"get": op("Witness identity", ok(R("Witness")), [])}
P["/v1/witness"] = {"get": op("Witness identity", ok(R("Witness")), [])}
P["/healthz"] = {"get": op("Health", ok(obj({"ok": B, "ledgers": I, "last_anchor_t": {"type": ["integer", "null"]}})), [])}
P["/v1/actions"] = {"post": op("Submit a tool call for a decision; repeat of a pending/approved identical call returns the same action", ok(R("ActionResult")), agent, obj({"tool": S, "args": {"type": "object"}, "client": obj({"name": S, "version": S})}, ["tool", "args"]))}
P["/v1/actions/{rid}"] = {"get": op("Long poll while pending_approval", ok(R("ActionResult")), agent, params=[pth("rid"), q("wait", {"type": "integer", "minimum": 0, "maximum": 25})])}
P["/v1/actions/{rid}/present"] = {"post": op("CONSUME the receipt (before executing the tool)", ok(obj({"result": {"enum": ["accept", "reject"]}, "reason": S}, ["result"])), agent, obj(), [pth("rid")])}
P["/v1/actions/{rid}/report"] = {"post": op("Report execution", ok(obj({"result": {"enum": ["released", "ignored"]}}, ["result"])), agent, obj({"executed": B}, ["executed"]), [pth("rid")])}
nullable = lambda s: {"anyOf": [s, {"type": "null"}]}
C = {
 "Error": obj({"error": S, "detail": S}, ["error"]),
 "Account": obj({"id": S, "principal": S, "display_name": S}, ["id", "principal"]),
 "Keycard": obj({"kid_hex": S, "short": S}, ["kid_hex", "short"]),
 "KeycardFull": obj({"kid_hex": S, "short": S, "credential_id_b64": S, "rp_id": S, "origins": arr(S)}),
 "CreationOptions": obj({"rp": obj({"id": S, "name": S}), "user": obj(), "challenge": S, "pubKeyCredParams": arr(obj({"type": S, "alg": {"const": -7}})), "authenticatorSelection": obj(), "attestation": {"const": "none"}}, ["rp", "challenge", "pubKeyCredParams"]),
 "Toolmap": obj({"version": {"const": 1}, "default": {"enum": ["deny", "pass"]}, "tools": {"type": "object", "additionalProperties": obj({"class": {"enum": ["message", "file", "disclosure", "purchase", "sale", "meeting", "refund", "delete", "publish", "pass", "command", "http"]}, "dangerous": B, "recipient": {"oneOf": [S, arr(S)]}, "extra_keys": arr(S), "text": arr(S), "amount": {"oneOf": [S, I]}, "currency": S, "reversible": {"oneOf": [B, {"type": "object", "additionalProperties": B}]}}, ["class"])}}, ["version", "default", "tools"]),
 "Agent": obj({"id": S, "name": S, "key_prefix": S, "created_at": I, "active_mandate_id": nullable(S), "toolmap": R("Toolmap"), "toolmap_sha256": S, "toolmap_signed": B}, ["id", "name", "toolmap"]),
 "MandateForm": obj({"currency": S, "valid_days": I,
    "purchase": obj({"enabled": B, "budget": I, "max_per_action": I}), "message": obj({"domains": arr(S), "to": arr(S)}),
    "forbidden_data": arr(S), "delete": nullable(obj({"targets": arr(S), "allow_irreversible": B})), "publish": nullable(obj({"channels": arr(S)})),
    "command": {"oneOf": [{"type": "null"}, {"const": False}, obj({"allow": arr(S), "unlisted": {"enum": ["ask", "allow", "deny"]}, "sandboxed": {"enum": ["ask", "allow"]}})]},
    "http": {"oneOf": [{"type": "null"}, {"const": False}, obj({"allow": arr(S), "unlisted": {"enum": ["ask", "deny"]}})]}}, ["currency", "valid_days"]),
 "Mandate": obj({"v": {"const": "deus-aar-0.1"}, "id": S, "principal": S, "agent": S, "nbf": I, "exp": I, "currency": S, "budget_window_s": I, "permissions": obj(), "forbidden_data": arr(S), "named_circle": B, "key_attestation": {"const": "passkey"}, "pin_source": S}, ["v", "id", "principal", "agent", "nbf", "exp", "currency", "budget_window_s", "permissions", "forbidden_data", "key_attestation"]),
 "Action": obj({"agent": S, "class": S, "recipient": S, "data": arr(S), "amount": I, "currency": S, "reversible": B, "dangerous": B}, ["agent", "class"]),
 "FeedItem": obj({"rid": S, "t": I, "agent_id": S, "tool": S, "class": S, "recipient": nullable(S), "amount": nullable(I), "currency": nullable(S), "verdict": {"enum": ["allow", "deny", "defer", "pass"]}, "reason": S, "status": {"enum": ["pass", "allowed", "denied", "pending_approval", "approved", "refused", "consumed", "executed", "not_executed", "expired", "covered"]}, "args_preview": S}, ["rid", "t", "verdict", "reason", "status"]),
 "ActionResult": obj({"rid": S, "verdict": {"enum": ["allow", "deny", "defer", "pass"]}, "reason": S, "status": S, "action": nullable(R("Action")), "expires": I,
    "aar_b64": nullable(S), "proof": nullable(obj({"entry_b64": S, "path_b64": arr(S), "checkpoint_b64": S, "approval": nullable(obj())})), "approval_url": nullable(S), "promise_b64": nullable(S),
    # r0269 server addition (allow with a receipt only): unsigned time status of the receipt; the proof is the files, not this member
    "anchor": obj({"status": {"enum": ["queued", "stamped"]}, "batch": S, "log_index": I, "stamp": obj({"size": I, "tsa": arr(S), "ots": nullable(S)})}, ["status"])}, ["rid", "verdict", "reason", "status", "expires"]),
 "Witness": obj({"iss": S, "alg": {"const": "EdDSA"}, "kid_hex": S, "pub_hex": S, "web_js_sha256": {"type": "object", "additionalProperties": S}}, ["iss", "alg", "kid_hex", "pub_hex"]),
}
spec = {"openapi": "3.1.0", "info": {"title": "Deus Witness Cloud", "version": "0.1.3", "description": "Machine form of cloud/ARHITEKTURA.md sections 5.1-5.3. Bytes are base64url without padding (*_b64). Times are Unix seconds. Errors: {error, detail}."},
        "servers": [{"url": "https://witness.sipkigroup.com"}, {"url": "http://localhost:8787"}], "paths": P,
        "components": {"securitySchemes": {"cookieSession": {"type": "apiKey", "in": "cookie", "name": "dw_session"}, "bearerKey": {"type": "http", "scheme": "bearer", "description": "dwk_<52 base32 chars>"}}, "schemas": C}}
yaml.safe_dump(spec, open("openapi.yaml", "w"), sort_keys=False, allow_unicode=True)
