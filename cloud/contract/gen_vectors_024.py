"""0.2.4: vectors of the JSON wire form of `toolmap_sha256` and of the tool map document (draft-deus-aar-05 8.6). The JS page (web/js/cde.js) and the server
(app/wire.py + wa_profile.cde) must produce the same bytes. Run: server/.venv/bin/python gen_vectors_024.py"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "server"))
from app import wire  # noqa: E402
import wa_profile as wa  # noqa: E402

OUT = os.path.join(HERE, "vectors", "gateway")
os.makedirs(OUT, exist_ok=True)
TM = {"version": 1, "default": "deny", "tools": {
    "send_email": {"class": "message", "recipient": ["$.to", "$.cc"], "text": ["$.subject", "$.body"]},
    "purchase": {"class": "purchase", "recipient": "$.vendor", "amount": "$.amount_cents", "currency": "USD", "strict": True},
    "delete_resource": {"class": "delete", "recipient": "$.resource", "reversible": {"cache-tmp": True}, "strict": True},
    "read_file": {"class": "pass"}}}
DOC = {"v": "dw-gateway-0.2.4", "tools": TM, "patterns": [hashlib.sha256(b"home_address\x0014 Maple Court").hexdigest()], "advisor": "heuristic"}
H = hashlib.sha256(wa.cde_raw(DOC) if hasattr(wa, "cde_raw") else wa.cde(DOC)).hexdigest()
MANDATE = {"v": "deus-aar-0.1", "id": "m-gw-1", "principal": "dw:0123456789abcdef0123456789abcdef", "agent": "ag_1", "nbf": 1000, "exp": 100000, "currency": "USD",
           "budget_window_s": 86400, "permissions": {"purchase": {"max_per_action": 100, "budget": 500}, "message": {"domains": ["acme.example"], "to": []}},
           "forbidden_data": ["phone"], "named_circle": False, "key_attestation": "passkey", "pin_source": "webauthn-registration", "toolmap_sha256": H}
ACTION = {"agent": "ag_1", "class": "pass", "recipient": "tool:read_file", "amount": 0, "data": [], "toolmap_sha256": H}
cde = lambda x: (wa.cde_raw if hasattr(wa, "cde_raw") else wa.cde)(wire.cbor_form(x))
for name, val in (("g01-gateway-doc", DOC), ("g02-mandate-with-toolmap-hash", MANDATE), ("g03-pass-action-with-toolmap-hash", ACTION)):
    b = cde(val)
    json.dump({"id": name, "json": val, "cde_hex": b.hex(), "sha256": hashlib.sha256(b).hexdigest(),
               "note": "toolmap_sha256 is 64 hex in JSON and bstr .size 32 in the CDE bytes (draft-deus-aar-05 6.1, 8.6)"}, open(os.path.join(OUT, name + ".json"), "w"), indent=1, sort_keys=True)
print("gateway vectors:", H)
