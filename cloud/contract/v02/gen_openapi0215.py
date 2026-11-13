"""Builds openapi-0.2.15.yaml: ONLY the paths added in 0.2.13-0.2.15 (confirmation levels, delegation, the wait of a phone declared with
a recovery code). The 0.1 paths are in ../openapi.yaml, 0.2 in openapi-0.2.yaml, 0.2.2 in openapi-0.2.2-recovery.yaml. Run with the venv."""
import os
import yaml
R = lambda n: {"$ref": "#/components/schemas/" + n}
obj = lambda props=None, req=None, **kw: dict({"type": "object", "properties": props or {}, **({"required": req} if req else {})}, **kw)
S, I, B = {"type": "string"}, {"type": "integer"}, {"type": "boolean"}
arr = lambda x: {"type": "array", "items": x}
nullable = lambda s: {"anyOf": [s, {"type": "null"}]}
HEX64 = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
def ok(schema, desc="OK"): return {"description": desc, "content": {"application/json": {"schema": schema}}}
def body(schema): return {"required": True, "content": {"application/json": {"schema": schema}}}
ERR = {"default": {"description": "Error", "content": {"application/json": {"schema": R("Error")}}}}
web = [{"cookieSession": []}]


def op(summary, resp, req=None, params=None):
    o = {"summary": summary, "responses": {"200": resp, **ERR}, "security": web}
    if req:
        o["requestBody"] = body(req)
    if params:
        o["parameters"] = params
    return o


pth = lambda n: {"name": n, "in": "path", "required": True, "schema": S}
NEED = obj({"role": S, "k": I}, ["role", "k"])
P = {
 "/api/confirm-rules": {
     "get": op("0.2.13: where approvals may be signed: phone_for (risky | all) and the laptop-level reasons", ok(R("ConfirmRules"))),
     "put": op("0.2.13: owner, step-up. Tightening to `all` with any step-up; loosening back only with a step-up by a phone-class key (403 DEVICE_LEVEL)",
               ok(R("ConfirmRules")), obj({"phone_for": {"enum": ["risky", "all"]}}, ["phone_for"]))},
 "/api/auth/keys/{kid}/device": {"post": op("0.2.13/0.2.14: mark a passkey phone or laptop; step-up. Demoting or removing a phone-class key needs a "
                                            "phone-class signature; promoting needs ANOTHER phone-class key, except the first marking of an account that "
                                            "never had a phone (0.2.15: closed while a recovery code was used lately or a declared phone waits). 403 DEVICE_LEVEL",
                                            ok(obj({"kid_hex": S, "device": {"enum": ["phone", "laptop"]}}, ["kid_hex", "device"])),
                                            obj({"device": {"enum": ["phone", "laptop"]}}, ["device"]), [pth("kid")])},
 "/api/auth/keys/{kid}/cancel-phone": {"post": op(
     "0.2.15: \"this was not me\". A key declared the new phone with a recovery code (it waits, phone_not_before) loses the claim for good: it "
     "stays a laptop key, its sessions end, every unused recovery code stops. Step-up with a phone-class key of the person; with no phone, any "
     "OTHER active key that does not wait itself. 403 DEVICE_LEVEL, 409 NOT_PENDING. Recorded as a key_device row {cancelled: true}",
     ok(obj({"kid_hex": S, "device": {"const": "laptop"}, "cancelled": {"const": True}, "recovery_codes_stopped": I, "next": S},
            ["kid_hex", "cancelled", "recovery_codes_stopped"])), None, [pth("kid")])},
 "/api/org/phone-lift": {"post": op(
     "0.2.15: open the request with which k >= 2 OTHER members (rule `recovery` of the team policy) end the wait of a member's recovery-declared "
     "phone; typ application/dw-phone-lift+cbor over CDE {v: dw-phone-lift-0.1, principal, kid, not_before, nonce}. The person never signs it "
     "(409 RECOVERY_SELF). 409 NO_RECOVERY_RULE, NOT_PENDING, WQ_POLICY_UNKNOWN",
     ok(obj({"req_id": S, "needs": arr(NEED), "kid_hex": HEX64, "not_before": I, "sign_url": S}, ["req_id", "needs", "kid_hex", "not_before"])),
     obj({"user_id": S}, ["user_id"]))},
 "/api/agents/{aid}/delegation": {
     "get": op("0.2.13: the agent's delegation (current and the last 50 rows); policy_ver = the signed policy version that set it (null: server-side)",
               ok(R("DelegationView")), None, [pth("aid")]),
     "put": op("Owner, step-up. 0.2.15: drafts policy version N+1 with rules.delegation set for this agent (plus every server-side delegation, moved "
               "in) and opens its signature request (rule `policy`). An agent the policy in force does not name yet is also applied at once "
               "(period before the transfer); a named one changes only when the version is signed (waits_for_signatures). 422 NOT_MEMBER, "
               "SELF_APPROVAL, BAD_DELEGATION, POLICY_MALFORMED; 409 NOT_A_TEAM",
               ok({"allOf": [R("DelegationView"), obj({"can_confirm_now": arr(S), "policy_request": R("PolicyRequest"), "in_signed_policy": B,
                                                      "waits_for_signatures": B}, ["policy_request", "in_signed_policy", "waits_for_signatures"])]}),
               obj({"operator_user_id": S, "approvers": nullable(arr(S)), "days": I}, ["operator_user_id"]), [pth("aid")]),
     "delete": op("Owner, step-up. Named in the signed policy: drafts the version without it (policy_request); else ends the server-side row at once",
                  ok({"allOf": [R("DelegationView"), obj({"policy_request": R("PolicyRequest"), "in_signed_policy": B, "waits_for_signatures": B})]}),
                  None, [pth("aid")])},
}
C = {
 "Error": obj({"error": S, "detail": S}, ["error"]),
 "ConfirmRules": obj({"phone_for": {"enum": ["risky", "all"]}, "levels": {"type": "object"}}, ["phone_for"]),
 "Delegation": obj({"id": I, "agent_id": S, "operator_user_id": S, "approvers": nullable(arr(S)), "until": nullable(I), "set_by": S, "set_at": I,
                    "ended_at": nullable(I), "ended_by": nullable(S), "policy_ver": nullable(I)}, ["agent_id", "operator_user_id", "set_at"]),
 "DelegationView": obj({"current": nullable(R("Delegation")), "history": arr(R("Delegation"))}, ["current", "history"]),
 "PolicyRequest": obj({"req_id": S, "policy_ver": I, "needs": arr(NEED), "sign_url": S, "note": S}, ["req_id", "policy_ver", "needs"]),
}
spec = {"openapi": "3.1.0", "info": {"title": "Deus Witness Cloud 0.2.13-0.2.15 (new paths only)", "version": "0.2.15",
                                     "description": "Confirmation levels (phone / laptop), delegation in the signed team policy (rules.delegation, see "
                                                    "openapi-0.2.yaml PolicyRules), the wait of a phone declared with a recovery code. Errors: {error, detail}."},
        "servers": [{"url": "https://witness.sipkigroup.com"}], "paths": P,
        "components": {"securitySchemes": {"cookieSession": {"type": "apiKey", "in": "cookie", "name": "dw_session"}}, "schemas": C}}
yaml.safe_dump(spec, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "openapi-0.2.15.yaml"), "w"), sort_keys=False, allow_unicode=True)
