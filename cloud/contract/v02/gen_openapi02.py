"""Builds openapi-0.2.yaml: ONLY the new paths of ARHITEKTURA-0.2 2.7 and 8 (the 0.1 paths stay in ../openapi.yaml)."""
import os
import yaml
R = lambda n: {"$ref": "#/components/schemas/" + n}
obj = lambda props=None, req=None, **kw: dict({"type": "object", "properties": props or {}, **({"required": req} if req else {})}, **kw)
S, I, B = {"type": "string"}, {"type": "integer"}, {"type": "boolean"}
arr = lambda x: {"type": "array", "items": x}
nullable = lambda s: {"anyOf": [s, {"type": "null"}]}
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
ROLE = {"enum": ["owner", "budget", "access", "observer"]}
P = {}
P["/api/orgs"] = {"get": op("Organisations of the user (an organisation = an account, principal dw:<id>)", ok(arr(R("OrgRef"))), web)}
P["/api/orgs/switch"] = {"post": op("Switch the current organisation of the session", ok(obj({"account_id": S}, ["account_id"])), web, obj({"account_id": S}, ["account_id"]))}
P["/api/org/invites"] = {"post": op("Owner, step-up. One-time invite link, 24 h; the token is shown once", ok(obj({"url": S}, ["url"])), web, obj({"roles": arr(ROLE)}, ["roles"]))}
P["/api/org/join"] = {"post": op("Join with an invite token; observer is active at once, other roles stay pending until a policy version lists the member", ok(obj({"account_id": S, "status": {"enum": ["pending", "active"]}, "roles": arr(ROLE)}, ["account_id", "status"])), web, obj({"token": S}, ["token"]))}
P["/api/org"] = {"get": op("Members, roles, current policy, settings", ok(R("Org")), web)}
P["/api/org/policy/draft"] = {"post": op("Owner. Build the org-policy map (2.2) and open a signature request; 422 POLICY_MALFORMED", ok(obj({"req_id": S, "typ": {"const": "application/dw-org-policy+cbor"}, "payload_b64": S, "policy": R("PolicyJson")}, ["req_id", "typ", "payload_b64", "policy"])), web, obj({"members": arr(obj({"user_id": S, "roles": arr({"enum": ["owner", "budget", "access"]}), "label": S}, ["user_id", "roles"])), "rules": R("PolicyRules")}, ["members", "rules"]))}
P["/api/sig-requests"] = {"get": op("Pending signature requests the user can sign (role in needs, not signed yet)", ok(arr(R("SigRequest"))), web)}
P["/api/sig-requests/{id}"] = {"get": op("One request with payload_b64 (the bytes the browser must sign as an ordinary wa-sig)", ok(R("SigRequestFull")), web, params=[pth("id")]),
                               "post": op("Submit an ordinary wa-sig of the signer. 409 codes: WA_*, KEY_MISMATCH, WQ_NOT_MEMBER, WQ_DUP_SIGNER, POLICY_*. Quorum reached -> request applied (mandate active / policy version added)", ok(R("SigProgress")), web, obj({"envelope_b64": S}, ["envelope_b64"]), [pth("id")])}
P["/api/org/settings"] = {"put": op("Owner, step-up. Organisation settings", ok(R("OrgSettings")), web, R("OrgSettings"))}
P["/api/mandates/draft"] = {"post": op("0.2 reply of the 0.1 path: with an org policy the draft also opens a quorum request (req_id, needs)", ok(obj({"mandate": {"type": "object"}, "typ": S, "toolmap_sha256": S, "req_id": S, "needs": arr(R("Need")), "quorum": B}, ["mandate", "typ"])), web, obj({"agent_id": S, "form": {"type": "object"}}, ["agent_id", "form"]))}
P["/api/suggestions"] = {"get": op("3.2: groups approved >= 3 times in 14 days and never refused -> 'add to mandate'; only widens (fatigue-fix): an unspecified class is never closed; money = per agent, max approved x 1.5 and the largest 24 h sum x 1.5, rounded up to 10 USD, below every refused amount", ok(obj({"suggestions": arr(R("Suggestion"))}, ["suggestions"])), web)}
P["/api/digest"] = {"get": op("3.5: period figures W/H/F, breakdowns, pending per role, suggestions, APPROVAL_RATE denials, catalog drift", ok(R("Digest")), web, params=[q("since", I, "unix seconds")])}
P["/api/approvals/batch"] = {"post": op("3.3: one wb envelope approves up to 20 homogeneous pending items (k=1 only). 409: WB_MALFORMED, WB_ITEM, WA_*, KEY_MISMATCH, WQ_QUORUM, WQ_NOT_MEMBER, NOT_DEFERRED, BATCH_NOT_HOMOGENEOUS", ok(obj({"approved": arr(S), "n": I, "envelope_items": I}, ["approved", "n"])), web, obj({"rids": {"type": "array", "items": S, "minItems": 1, "maxItems": 20}, "envelope_b64": S}, ["rids", "envelope_b64"]))}
P["/api/approvals/{rid}/release"] = {"post": op("4.2: release or reject an item held by the advisor; wa-sig typ application/dw-release+cbor over {rid, args_sha256 (bstr 32), release}", ok(obj({"status": S, "verdict": S, "reason": S}, ["status", "verdict", "reason"])), web, obj({"release": B, "envelope_b64": S}, ["release", "envelope_b64"]), [pth("rid")])}
P["/api/mandates/{mid}/revoke"] = {"get": op("0.2.0: the bytes to sign to revoke (typ application/aar-revocation+cbor, svidetel_v4 revocation_payload); any ONE signer suffices (0 p.3)", ok(obj({"mandate_id": S, "status": S, "typ": S, "payload_b64": S}, ["mandate_id", "status", "typ", "payload_b64"])), web, params=[pth("mid")]),
                                 "post": op("0.2.0: revoke with an ordinary wa-sig of one signer (wrapped in a wq of one under the policy in force). 409: WA_*, WQ_NOT_MEMBER, MANDATE_NOT_ACTIVE", ok(obj({"mandate_id": S, "status": S, "ledger_seq": I}, ["mandate_id", "status"])), web, obj({"envelope_b64": S}, ["envelope_b64"]), [pth("mid")])}
P["/v1/catalog"] = {"post": op("6: proxy sends tools/list of the MCP server; server stores the catalog and its hash", ok(obj({"catalog_sha256": S, "n_tools": I, "changed": B}, ["catalog_sha256", "n_tools", "changed"])), agent, obj({"tools": arr(obj({"name": S, "description": S, "inputSchema": {"type": "object"}}, ["name"]))}, ["tools"]))}
P["/v1/coverage"] = {"post": op("5.3: operator-declared coverage level (a claim, not a proof)", ok(obj({"ok": B, "level": S}, ["ok", "level"])), agent, obj({"level": {"enum": ["C0", "C1", "C2", "C3"]}, "unwitnessed": arr(S), "tool": S, "pass_net_tools": arr(S)}, ["level"]))}
P["/api/catalog/{agent}"] = {"get": op("Catalog, drift flag, suggested toolmap with UNKNOWN list, declared coverage", ok(R("CatalogView")), web, params=[pth("agent")])}
P["/api/catalog/{agent}/draft"] = {"post": op("Toolmap draft from the catalog; applicable only when unknown is empty (apply = PUT toolmap, step-up)", ok(obj({"toolmap_draft": {"type": "object"}, "unknown": arr(R("Unknown")), "applicable": B, "catalog_sha256": S}, ["toolmap_draft", "unknown", "applicable"])), web, obj(), [pth("agent")])}
C = {
 "Error": obj({"error": S, "detail": S}, ["error"]),
 "Need": obj({"role": {"enum": ["owner", "budget", "access", "any"]}, "k": I}, ["role", "k"]),
 "OrgRef": obj({"account_id": S, "principal": S, "name": S, "roles": arr(ROLE), "status": S, "current": B}, ["account_id", "principal", "roles", "current"]),
 "Member": obj({"user_id": S, "label": S, "roles": arr(ROLE), "status": {"enum": ["pending", "active", "removed"]}, "kid": S}, ["user_id", "roles", "status", "kid"]),
 "OrgSettings": obj({"profile": {"enum": ["smb", "enterprise"]}, "defer_ttl_s": {"type": "integer", "minimum": 900, "maximum": 3600}, "max_pending": I, "max_defers_hour": I, "escalate_after_s": I, "advisor": {"enum": ["off", "heuristic", "ner"]}}),
 "Tier": obj({"if": {"enum": ["money", "money_over", "access"]}, "amount": I, "role": {"enum": ["budget", "access", "owner"]}, "k": I}, ["if", "role", "k"]),
 "PolicyRules": obj({"policy": R("Need"), "mandate": arr(R("Tier")), "approval": arr(R("Tier")), "revocation": R("Need"), "ceiling": R("Need"),
                     "recovery": R("Need"),
                     "delegation": {"type": "array", "minItems": 1, "maxItems": 64, "items": obj({"agent": S, "operator": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                                    "approvers": nullable({"type": "array", "minItems": 1, "items": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}), "until": nullable(I)},
                                    ["agent", "operator", "approvers", "until"])}},
                    ["policy", "mandate", "approval", "revocation", "ceiling"],
                    description="0.2.2: optional `recovery` (k >= 2 other members replace one member's lost key; see openapi-0.2.2-recovery.yaml). "
                                "0.2.15: optional `delegation` (sorted by agent; kids as lowercase hex text; the operator's signature never counts for "
                                "an approval of that agent: WQ_SELF; only the named approvers: WQ_NOT_DELEGATE; see openapi-0.2.15.yaml)"),
 "PolicyJson": obj({"v": {"const": "dw-org-policy-0.1"}, "principal": S, "ver": I, "prev": nullable(S), "members": arr(obj({"kid": S, "pub": S, "cred": S, "roles": arr(S), "label": S})), "rules": R("PolicyRules")}, ["v", "principal", "ver", "members", "rules"], description="bytes members are hex"),
 "Org": obj({"account_id": S, "principal": S, "members": arr(R("Member")), "policy": nullable(R("PolicyJson")), "policy_ver": I, "settings": R("OrgSettings")}, ["account_id", "members", "policy_ver"]),
 "SigRequest": obj({"id": S, "kind": {"enum": ["mandate", "approval", "policy", "phone_lift"]}, "ref": S, "typ": S, "needs": arr(R("Need")), "have": I, "need": I, "status": {"enum": ["collecting", "done"]}, "signed_by": arr(S), "created_at": I, "expires": I}, ["id", "kind", "typ", "needs", "have", "need", "status"]),
 "SigRequestFull": {"allOf": [R("SigRequest"), obj({"payload_b64": S, "policy_hash_b64": nullable(S), "body": {"type": "object"}}, ["payload_b64"])]},
 "SigProgress": obj({"status": {"enum": ["collecting", "done"]}, "have": I, "need": I, "mandate_id": S, "mandate_status": S, "policy_ver": I}, ["status", "have", "need"]),
 "Suggestion": obj({"id": S, "agent_id": S, "kind": {"enum": ["recipient", "budget"]}, "class": S, "key": S, "approved": I, "rejected": I, "window_days": I, "proposal": S, "proposed_budget": I}, ["id", "agent_id", "kind", "class", "key", "approved", "rejected"]),
 "Digest": obj({"since": I, "until": I, "W": I, "H": I, "F": I, "by_verdict": {"type": "object", "additionalProperties": I}, "by_reason": {"type": "object", "additionalProperties": I}, "by_agent": {"type": "object", "additionalProperties": I},
                "pending_by_role": obj({"budget": I, "access": I}), "suggestions": arr(R("Suggestion")), "approval_rate_denials": I, "catalog_drift": arr(S)}, ["since", "until", "W", "H", "F"]),
 "Unknown": obj({"tool": S, "arg": S}, ["tool", "arg"]),
 "CatalogView": obj({"agent_id": S, "catalog_sha256": nullable(S), "tools": arr({"type": "object"}), "drift": B, "suggested_toolmap": nullable({"type": "object"}), "unknown": arr(R("Unknown")),
                     "coverage": nullable(obj({"level": S, "unwitnessed": arr(S), "tool": S, "pass_net_tools": arr(S), "t": I, "operator_declared": {"const": True}}))}, ["agent_id", "drift", "unknown"]),
}
spec = {"openapi": "3.1.0", "info": {"title": "Deus Witness Cloud 0.2 (new paths only)", "version": "0.2.0-draft", "description": "Machine form of cloud/ARHITEKTURA-0.2.md 2.7 and 8. The 0.1 paths are in ../openapi.yaml. Bytes are base64url without padding (*_b64). Errors: {error, detail}."},
        "servers": [{"url": "https://witness.sipkigroup.com"}, {"url": "http://localhost:8801"}], "paths": P,
        "components": {"securitySchemes": {"cookieSession": {"type": "apiKey", "in": "cookie", "name": "dw_session"}, "bearerKey": {"type": "http", "scheme": "bearer"}}, "schemas": C}}
yaml.safe_dump(spec, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "openapi-0.2.yaml"), "w"), sort_keys=False, allow_unicode=True)
