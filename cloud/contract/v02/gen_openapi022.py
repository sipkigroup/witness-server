"""Builds openapi-0.2.2-recovery.yaml: ONLY the paths of 0.2.2 (several passkeys, recovery codes, key replacement in a team, batch
revocation). Person-level paths live under /api/auth/ (they act on the person, not on the current organisation). Run with the venv."""
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
web, none = [{"cookieSession": []}], []


def op(summary, resp, sec, req=None, params=None):
    o = {"summary": summary, "responses": {"200": resp, **ERR}, "security": sec}
    if req:
        o["requestBody"] = body(req)
    if params:
        o["parameters"] = params
    return o


pth = lambda n: {"name": n, "in": "path", "required": True, "schema": S}
KEV = {"const": "application/dw-key-event+cbor"}
P = {
 "/api/auth/keys": {"get": op("The person's passkeys (active and removed) and the recovery-code count (never the codes)", ok(obj({"keys": arr(R("Key")), "recovery_codes": R("CodesState")}, ["keys", "recovery_codes"])), web)},
 "/api/auth/keys/add/begin": {"post": op("Registration options for a NEW passkey (excludeCredentials = every passkey of the person)", ok(R("RegOptions")), web, obj({"label": S}))},
 "/api/auth/keys/add/finish": {"post": op("The new passkey is created but NOT active: returns the key-event payload a CURRENT passkey must sign", ok(obj({"confirm_id": S, "typ": KEV, "payload_b64": S, "kid_hex": S, "short": S, "sign_with": arr({"type": "object"})}, ["confirm_id", "typ", "payload_b64", "kid_hex"])), web, obj({"flow_id": S, "credential": {"type": "object"}}, ["flow_id", "credential"]))},
 "/api/auth/keys/add/confirm": {"post": op("wa-sig (typ dw-key-event) by an ACTIVE passkey of the person, not the new one. 409: KEY_SELF, KEY_NOT_ACTIVE, KEY_EVENT_SIG, WA_*", ok(obj({"kid_hex": S, "short": S, "added_by": {"const": "passkey"}, "signed_by": S}, ["kid_hex", "added_by", "signed_by"])), web, obj({"confirm_id": S, "envelope_b64": S}, ["confirm_id", "envelope_b64"]))},
 "/api/auth/keys/{kid}/remove/begin": {"post": op("The key-event payload of a removal. 409 LAST_KEY: the last active passkey is never removed", ok(obj({"flow_id": S, "typ": KEV, "payload_b64": S}, ["flow_id", "typ", "payload_b64"])), web, None, [pth("kid")])},
 "/api/auth/keys/{kid}/remove": {"post": op("wa-sig by an active passkey of the person; the key stops at once, sessions it opened end; what it signed stays valid", ok(obj({"kid_hex": S, "removed_at": I, "signed_by": S, "mandates_signed_by_it": I}, ["kid_hex", "removed_at", "signed_by"])), web, obj({"flow_id": S, "envelope_b64": S}, ["flow_id", "envelope_b64"]), [pth("kid")])},
 "/api/auth/recovery-codes": {"get": op("How many codes are left (never the codes)", ok(R("CodesState")), web),
                              "post": op("Step-up. 10 new one-time codes, shown ONCE (only scrypt hashes are kept); earlier codes stop working", ok(obj({"codes": {"type": "array", "items": S, "minItems": 10, "maxItems": 10}, "created_at": I, "remaining": I}, ["codes", "created_at"])), web)},
 "/api/auth/recovery/login": {"post": op("A recovery code: every session of the person ends, a 15-min session that may ONLY add a passkey starts, the person's devices get a push. 401 RECOVERY_INVALID (unknown, used or wrong: one answer)", ok(obj({"scope": {"const": "recovery"}, "next": S, "expires_in_s": I, "codes_left": I}, ["scope", "codes_left"])), none, obj({"code": S}, ["code"]))},
 "/api/auth/recovery/state": {"get": op("Recovery session only", ok(obj({"display_name": nullable(S), "expires_at": I, "codes_left": I}, ["expires_at", "codes_left"])), web)},
 "/api/auth/recovery/passkey/begin": {"post": op("Recovery session only: registration options for the new passkey. 0.2.14: device = phone declares it the new phone (default laptop); 0.2.15: such a phone counts as phone only after 24 h (24-72 h, DW_RECOVERY_PHONE_DELAY_H)", ok(R("RegOptions")), web, obj({"label": S, "device": {"enum": ["phone", "laptop"]}}))},
 "/api/auth/recovery/passkey/finish": {"post": op("Recovery session only: the new passkey is active at once (by recovery-code, recorded in the registry log); the recovery session ends", ok(obj({"kid_hex": S, "short": S, "added_by": {"const": "recovery-code"}, "codes_left": I, "device": {"enum": ["phone", "laptop"]}, "phone_not_before": I, "delay_h": I, "next": S}, ["kid_hex", "added_by"])), web, obj({"flow_id": S, "credential": {"type": "object"}, "label": S}, ["flow_id", "credential"]))},
 "/api/org/key-replace": {"post": op("Open the policy request that replaces ONE member's lost key by their newest active passkey; needs = rule recovery (k >= 2 others) or rule policy. 409 NO_NEW_KEY, WQ_POLICY_UNKNOWN", ok(obj({"req_id": S, "needs": arr(obj({"role": S, "k": I}, ["role", "k"])), "old_kid": S, "new_kid": S, "rule": {"enum": ["recovery", "policy"]}}, ["req_id", "needs", "old_kid", "new_kid", "rule"])), web, obj({"user_id": S}, ["user_id"]))},
 "/api/mandates/by-key/{kid}": {"get": op("Active mandates of the current account that a key signed (they stay valid until revoked)", ok(obj({"kid_hex": S, "typ": S, "max_per_batch": I, "mandates": arr(obj({"id": S, "agent_id": S, "mandate": {"type": "object"}, "created_at": I}, ["id", "mandate"]))}, ["kid_hex", "mandates"])), web, None, [pth("kid")])},
 "/api/mandates/revoke-batch": {"post": op("One wb envelope of typ revocation (challenge over the items AND the typ) revokes up to 20 mandates. 409: WB_*, KEY_REVOKED, KEY_NOT_ACTIVE, WQ_NOT_MEMBER, MANDATE_NOT_ACTIVE", ok(obj({"revoked": arr(S), "ledger_seqs": arr(I)}, ["revoked"])), web, obj({"mandate_ids": {"type": "array", "items": S, "minItems": 1, "maxItems": 20}, "envelope_b64": S}, ["mandate_ids", "envelope_b64"]))},
}
C = {
 "Error": obj({"error": S, "detail": S}, ["error"]),
 "Key": obj({"kid_hex": S, "short": S, "label": S, "created_at": I, "last_used_at": nullable(I), "added_by": {"enum": ["registration", "passkey", "recovery-code"]},
             "removed_at": nullable(I), "active": B, "this_session": B, "credential_id_b64": S, "team_key_in": arr(obj({"account_id": S, "name": nullable(S)})),
             "device": nullable({"enum": ["phone", "laptop"]}), "counts_as": {"enum": ["phone", "laptop"]}, "phone_not_before": nullable(I)},
            ["kid_hex", "label", "active", "added_by"]),
 "CodesState": obj({"total": I, "remaining": I, "created_at": nullable(I)}, ["total", "remaining"]),
 "RegOptions": obj({"flow_id": S, "options": {"type": "object"}}, ["flow_id", "options"]),
}
spec = {"openapi": "3.1.0", "info": {"title": "Deus Witness Cloud 0.2.2 recovery (new paths only)", "version": "0.2.2",
                                     "description": "Several passkeys per person, recovery codes, key replacement in a team, batch revocation (docs/recovery.md). Bytes base64url without padding (*_b64) or hex (*_hex). Errors: {error, detail}."},
        "servers": [{"url": "https://witness.sipkigroup.com"}], "paths": P,
        "components": {"securitySchemes": {"cookieSession": {"type": "apiKey", "in": "cookie", "name": "dw_session"}}, "schemas": C}}
yaml.safe_dump(spec, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "openapi-0.2.2-recovery.yaml"), "w"), sort_keys=False, allow_unicode=True)
