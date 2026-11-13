"""Generates vectors/wa/*.json and vectors/cde/*.json. Deterministic key (test only, public in this file)."""
import hashlib, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../..")))
import cbor2
import wa_profile as wa
from forms import mandate_from_form
from svidetel_v4.state import approval_payload

HERE = os.path.dirname(os.path.abspath(__file__))
RP, ORIGIN = "witness.sipkigroup.com", "https://witness.sipkigroup.com"
A = wa.SoftAuthenticator(private_int=int.from_bytes(hashlib.sha256(b"deus-wa-test-vector-key").digest(), "big") % (wa.P256_N - 1) + 1,
                         credential_id=hashlib.sha256(b"cred").digest())
B = wa.SoftAuthenticator(private_int=int.from_bytes(hashlib.sha256(b"deus-wa-other-key").digest(), "big") % (wa.P256_N - 1) + 1)
REG = A.reg_entry(RP, [ORIGIN], "webauthn-registration:%s:2026-10-19T08:00:00Z:registry-log#1")

FORM = {"currency": "USD", "valid_days": 30,
        "purchase": {"enabled": True, "budget": 20000, "max_per_action": 10000},
        "message": {"domains": ["acme.example"], "to": ["bob@partner.example"]},
        "forbidden_data": ["home_address", "phone"],
        "delete": {"targets": ["cache-*"], "allow_irreversible": False}, "publish": None}
MANDATE = mandate_from_form(FORM, "dw:0123456789abcdef0123456789abcdef", "ag_demo", REG["pin_source"], now=1760000000,
                            mid="00112233445566778899aabbccddeeff")
ACTION = {"agent": "ag_demo", "class": "publish", "recipient": "blog", "data": []}
M_PAY = wa.cde(MANDATE)
AP_PAY = approval_payload(MANDATE, ACTION, "r_ABCDEFGHIJKLMNOPQRSTUVWXYZ", True)
AP_PAY_F = approval_payload(MANDATE, ACTION, "r_ABCDEFGHIJKLMNOPQRSTUVWXYZ", False)


def write(d, name, obj):
    os.makedirs(os.path.join(HERE, "vectors", d), exist_ok=True)
    json.dump(obj, open(os.path.join(HERE, "vectors", d, name + ".json"), "w"), indent=1, ensure_ascii=False)


def vec(id, cls, expect, typ, payload, env, note, reg=REG):
    write("wa", id, {"id": id, "class": cls, "expect": expect, "typ": typ, "payload_hex": payload.hex(), "reg_entry": reg,
                     "envelope_hex": env.hex(), "note": note})


def env_of(auth, typ, payload, normalize=True, **kw):
    ad, cd, der = auth.get_assertion(wa.challenge(typ, payload), kw.pop("rp", RP), kw.pop("origin", ORIGIN), **kw)
    return wa.make_envelope(typ, auth.kid, payload, ad, cd, der, normalize=normalize)


TM, TA = wa.TYP_MANDATE, wa.TYP_APPROVAL
vec("v01-mandate", "valid", None, TM, M_PAY, env_of(A, TM, M_PAY), "mandate from the form of ARHITEKTURA 5.3")
vec("v02-approval-true", "valid", None, TA, AP_PAY, env_of(A, TA, AP_PAY), "approval approved=true")
vec("v03-approval-false", "valid", None, TA, AP_PAY_F, env_of(A, TA, AP_PAY_F), "approval approved=false (refusal)")
vec("v04-high-s-normalised", "valid", None, TM, M_PAY, env_of(A, TM, M_PAY, high_s=True, normalize=True),
    "authenticator produced high-S DER; signer replaced s by n-s (3.3)")
vec("i01-foreign-origin", "invalid", "WA_CLIENTDATA", TM, M_PAY, env_of(A, TM, M_PAY, origin="https://evil.example"), "origin not in origins")
vec("i02-cross-origin", "invalid", "WA_CLIENTDATA", TM, M_PAY, env_of(A, TM, M_PAY, cross_origin=True), "crossOrigin true")
vec("i03-type-create", "invalid", "WA_CLIENTDATA", TM, M_PAY, env_of(A, TM, M_PAY, cd_type="webauthn.create"), "clientData type webauthn.create")
ad, cd, der = A.get_assertion(wa.challenge(TM, b"other payload"), RP, ORIGIN)
vec("i04-wrong-challenge", "invalid", "WA_CLIENTDATA", TM, M_PAY, wa.make_envelope(TM, A.kid, M_PAY, ad, cd, der), "challenge computed over another payload")
vec("i05-rpidhash", "invalid", "WA_AUTHDATA", TM, M_PAY, env_of(A, TM, M_PAY, rp_id_hash_of="evil.example"), "rpIdHash of another rp id")
vec("i06-no-uv", "invalid", "WA_AUTHDATA", TM, M_PAY, env_of(A, TM, M_PAY, flags=wa.FLAG_UP), "UV flag clear")
vec("i07-no-up", "invalid", "WA_AUTHDATA", TM, M_PAY, env_of(A, TM, M_PAY, flags=wa.FLAG_UV), "UP flag clear")
vec("i08-high-s", "invalid", "WA_SIG", TM, M_PAY, env_of(A, TM, M_PAY, high_s=True, normalize=False), "valid but high-S signature kept")
vec("i09-payload-substituted", "invalid", "MANDATE_SIG", TM, M_PAY,
    env_of(A, TM, wa.cde(dict(MANDATE, id="ffffffffffffffffffffffffffffffff"))), "envelope signs another mandate; verifier expects the recomputed one")
vec("i10-foreign-kid", "invalid", "KEY_MISMATCH", TM, M_PAY, env_of(B, TM, M_PAY), "envelope signed by another key and carrying its kid")
ad, cd, der = A.get_assertion(wa.challenge(TM, M_PAY), RP, ORIGIN)
extra = wa.cde({"v": wa.V, "typ": TM, "kid": A.kid, "payload": M_PAY, "authData": ad, "clientDataJSON": cd, "sig": wa.der_to_raw_lows(der), "x": 1})
vec("i11-extra-member", "invalid", "WA_MALFORMED", TM, M_PAY, extra, "8 members instead of 7")
m7 = {"v": wa.V, "typ": TM, "kid": A.kid, "payload": M_PAY, "authData": ad, "clientDataJSON": cd, "sig": wa.der_to_raw_lows(der)}
noncde = cbor2.dumps(m7)  # insertion order, not CDE
assert noncde != wa.cde(m7)
vec("i12-non-cde-order", "invalid", "WA_MALFORMED", TM, M_PAY, noncde, "map keys in insertion order, not length-first CDE order")
vec("i13-wrong-typ", "invalid", "APPROVAL_SIG", TA, M_PAY, env_of(A, TM, M_PAY), "mandate envelope offered as approval")

# ---- CDE vectors ----
def to_py(x):
    if isinstance(x, dict):
        if set(x) == {"$bytes"}:
            return bytes.fromhex(x["$bytes"])
        return {k: to_py(v) for k, v in x.items()}
    if isinstance(x, list):
        return [to_py(v) for v in x]
    return x

def cdev(id, value, note=""):
    write("cde", id, {"id": id, "json": value, "cde_hex": cbor2.dumps(to_py(value), canonical=True).hex(), "note": note})

cdev("c01-mandate-5-3", json.loads(json.dumps(MANDATE)), "mandate of ARHITEKTURA 5.3")
for i, (cls, a) in enumerate([("message", {"agent": "ag", "class": "message", "recipient": "x@acme.example", "data": ["phone"]}),
    ("purchase", {"agent": "ag", "class": "purchase", "recipient": "vendor", "data": [], "amount": 1500, "currency": "USD"}),
    ("delete", {"agent": "ag", "class": "delete", "recipient": "prod-db", "data": [], "reversible": False}),
    ("publish", {"agent": "ag", "class": "publish", "recipient": "blog", "data": []}),
    ("file", {"agent": "ag", "class": "file", "recipient": "/tmp/sandbox/a.txt", "data": []})], 2):
    cdev("c%02d-action-%s" % (i, cls), a, "action of class " + cls)
cdev("c07-approval-bstr", {"v": "deus-aar-0.1", "t": "approval", "receipt": "r_AAAA", "mandate": {"$bytes": "00" * 32},
                           "action": {"$bytes": "ff" * 32}, "approved": True}, "approval map with bstr")
cdev("c08-key-lengths", {"a": 1, "bb": 2, "ccc": 3, "aa": 4, "b": 5, "zzzzzzzzzzzzzzzzzzzzzzzz": 6, "aaaaaaaaaaaaaaaaaaaaaaaaa": 7}, "length-first key order")
for i, n in enumerate([0, 23, 24, 255, 256, 65535, 65536, 2 ** 32, 10 ** 15], 9):
    cdev("c%02d-int-%d" % (i, n), {"n": n}, "integer boundary")
cdev("c18-empty-arrays", {"data": [], "x": [[]], "m": {}}, "empty containers")
cdev("c19-null-false", {"a": None, "b": False, "c": True}, "null/false/true")
cdev("c20-unicode", {"s": "Ünḯcode ☃ \U0001F600 и"}, "no NFC normalisation (e + combining acute is kept)")
cdev("c21-negative", {"n": -1, "m": -24, "k": -25, "big": -(2 ** 32) - 1}, "negative integers")
cdev("c22-nested", {"permissions": {"delete": {"targets": ["cache-*"], "allow_irreversible": False}, "publish": None}}, "nested")
print(len(os.listdir(os.path.join(HERE, "vectors/wa"))), len(os.listdir(os.path.join(HERE, "vectors/cde"))))
