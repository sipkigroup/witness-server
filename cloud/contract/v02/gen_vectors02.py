"""Generates vectors/wq, vectors/wb, vectors/policy. Deterministic keys (test only, public in this file).
ECDSA signatures are randomised, so a re-run changes the bytes but not the verdicts. Run: ../../server/.venv/bin/python gen_vectors02.py"""
import hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..")))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "../../..")))
import cbor2
import wa_profile as wa
import wq_profile as q
from forms import mandate_from_form
from svidetel_v4.state import approval_payload

RP, ORIGIN = "witness.sipkigroup.com", "https://witness.sipkigroup.com"
RPD = {"rp_id": RP, "origins": [ORIGIN]}
PRINCIPAL = "dw:0123456789abcdef0123456789abcdef"


def auth(name):
    n = int.from_bytes(hashlib.sha256(b"deus-wq-test-key-" + name.encode()).digest(), "big") % (wa.P256_N - 1) + 1
    return wa.SoftAuthenticator(private_int=n, credential_id=hashlib.sha256(b"cred-" + name.encode()).digest())


A = {n: auth(n) for n in ["owner", "b1", "b2", "b3", "a1", "dual", "out"] + ["x%02d" % i for i in range(17)]}


def member(name, roles, label=None):
    a = A[name]
    return {"kid": a.kid, "pub": a.pub, "cred": a.credential_id, "roles": roles, "label": label or name}


def members(*ms):
    return sorted(ms, key=lambda m: m["kid"])


TIERS_M = [{"if": "money", "role": "budget", "k": 1}, {"if": "money_over", "amount": 50000, "role": "budget", "k": 2},
           {"if": "access", "role": "access", "k": 1}]
RULES = {"policy": {"role": "owner", "k": 1}, "mandate": TIERS_M, "approval": TIERS_M,
         "revocation": {"role": "any", "k": 1}, "ceiling": {"role": "owner", "k": 1}}
TEAM = members(member("owner", ["owner"]), member("b1", ["budget"]), member("b2", ["budget"]), member("b3", ["budget"]),
                member("a1", ["access"]), member("dual", ["budget", "access"]))


def pol(ver, prev, ms=TEAM, rules=RULES):
    return {"v": q.V_POLICY, "principal": PRINCIPAL, "ver": ver, "prev": prev, "members": ms, "rules": rules}


GENESIS = pol(1, None, members(member("owner", ["owner", "budget", "access"])),
              {"policy": {"role": "owner", "k": 1}, "mandate": [], "approval": [], "revocation": {"role": "any", "k": 1},
               "ceiling": {"role": "owner", "k": 1}})


def wsig(name, typ, payload, **kw):
    a = A[name]
    ad, cd, der = a.get_assertion(wa.challenge(typ, payload), RP, ORIGIN, **kw)
    return q.make_wsig(a.kid, ad, cd, der, normalize=not kw.get("high_s"))


def wq_by(names, typ, payload, polmap, **kw):
    return q.make_wq(typ, payload, q.policy_hash(polmap), [wsig(n, typ, payload) for n in names], **kw)


def wa_by(name, typ, payload):
    return A[name].sign_object(typ, payload, RP, ORIGIN)


def build_chain(*entries):
    """entries: (policy_map, envelope_bytes, t) -> list of vector dicts"""
    return [{"policy_hex": cde(p).hex(), "envelope_hex": e.hex(), "t": t} for p, e, t in entries]


cde = wa.cde
P1 = GENESIS
E1 = wa_by("owner", q.TYP_POLICY, cde(P1))
P2 = pol(2, q.policy_hash(P1))
E2 = wq_by(["owner"], q.TYP_POLICY, cde(P2), P1)
TEAM3 = members(*[m for m in TEAM if m["kid"] != A["b3"].kid])
P3 = pol(3, q.policy_hash(P2), TEAM3)
E3 = wq_by(["owner"], q.TYP_POLICY, cde(P3), P2)
T1, T2, T3 = 1760000000, 1760100000, 1760200000
CHAIN3 = build_chain((P1, E1, T1), (P2, E2, T2), (P3, E3, T3))
CHAIN2 = CHAIN3[:2]


def mandate(form):
    return mandate_from_form(form, PRINCIPAL, "ag_demo", "webauthn-registration:%s:2026-10-19T08:00:00Z:registry-log#1" % RP, now=1760000000,
                             mid="00112233445566778899aabbccddeeff")


M_BIG = mandate({"currency": "USD", "valid_days": 30, "purchase": {"enabled": True, "budget": 200000, "max_per_action": 100000}})
M_SMALL = mandate({"currency": "USD", "valid_days": 30, "purchase": {"enabled": True, "budget": 10000, "max_per_action": 5000}})
M_MIXED = mandate({"currency": "USD", "valid_days": 30, "purchase": {"enabled": True, "budget": 10000, "max_per_action": 5000},
                   "message": {"domains": ["acme.example"], "to": []}})
M_ACCESS = mandate({"currency": "USD", "valid_days": 30, "message": {"domains": ["acme.example"], "to": []}})
TM, TA, TR = wa.TYP_MANDATE, wa.TYP_APPROVAL, wa.TYP_REVOCATION


def write(d, name, obj):
    json.dump(obj, open(os.path.join(HERE, "vectors", d, name + ".json"), "w"), indent=1, ensure_ascii=False)


def wqv(id, expect, typ, payload, env, note, chain=None, action=None, at=None):
    write("wq", id, {"id": id, "class": "valid" if expect is None else "invalid", "expect": expect, "typ": typ, "payload_hex": payload.hex(),
                     "envelope_hex": env.hex(), "chain": chain or CHAIN2, "rp": RPD, "action": action, "at": at, "note": note})


for f in os.listdir(os.path.join(HERE, "vectors")):
    for g in os.listdir(os.path.join(HERE, "vectors", f)):
        os.remove(os.path.join(HERE, "vectors", f, g))

MP = {k: cde(v) for k, v in dict(big=M_BIG, small=M_SMALL, mixed=M_MIXED, access=M_ACCESS).items()}
# ---- wq ----
wqv("w01-two-of-three", None, TM, MP["big"], wq_by(["b1", "b3"], TM, MP["big"], P2), "budget 200000 > 50000: budget k=2, two of three budget members sign")
wqv("w02-one-signer-below-threshold", None, TM, MP["small"], wq_by(["b2"], TM, MP["small"], P2), "budget 10000: money tier k=1")
wqv("w03-one-of-two", "WQ_QUORUM", TM, MP["big"], wq_by(["b1"], TM, MP["big"], P2), "k=2 needed, one signature")
wqv("w04-not-member", "WQ_NOT_MEMBER", TM, MP["big"], wq_by(["b1", "out"], TM, MP["big"], P2), "second signer is not in the policy")
w = wsig("b1", TM, MP["big"])
wqv("w05-dup-signer", "WQ_DUP_SIGNER", TM, MP["big"], q.make_wq(TM, MP["big"], q.policy_hash(P2), [w, dict(w)]), "same kid twice")
wqv("w06-policy-unknown", "WQ_POLICY_UNKNOWN", TM, MP["big"], q.make_wq(TM, MP["big"], hashlib.sha256(b"no such policy").digest(),
    [wsig("b1", TM, MP["big"]), wsig("b2", TM, MP["big"])]), "policy hash not in the chain")
bad = wsig("b2", TM, b"another payload")
bad_w = [wsig("b1", TM, MP["big"]), dict(bad)]
wqv("w07-one-signature-broken", "WA_CLIENTDATA", TM, MP["big"], q.make_wq(TM, MP["big"], q.policy_hash(P2), bad_w),
    "b2 signed a challenge of another payload; b1 is fine")
wqv("w08-owner-and-access-not-budget", "WQ_QUORUM", TM, MP["big"], wq_by(["owner", "a1"], TM, MP["big"], P2), "money_over needs budget k=2; owner+access do not count")
wqv("w09-mixed-mandate-both-roles", None, TM, MP["mixed"], wq_by(["b1", "a1"], TM, MP["mixed"], P2), "money (budget k=1) + access (access k=1): one of each")
wqv("w10-mixed-missing-access", "WQ_QUORUM", TM, MP["mixed"], wq_by(["b1", "b2"], TM, MP["mixed"], P2), "mixed mandate: two budget signers, nobody with role access")
wqv("w11-dual-role-person", None, TM, MP["mixed"], wq_by(["dual"], TM, MP["mixed"], P2), "one person holds budget+access and closes both at k=1")
wqv("w12-unsorted-sigs", "WQ_MALFORMED", TM, MP["big"], q.make_wq(TM, MP["big"], q.policy_hash(P2),
    sorted([wsig("b1", TM, MP["big"]), wsig("b2", TM, MP["big"])], key=lambda s: s["kid"], reverse=True), sort=False), "sigs in descending kid order")
m = cbor2.loads(wq_by(["b1", "b2"], TM, MP["big"], P2))
m["extra"] = 1
wqv("w13-extra-member", "WQ_MALFORMED", TM, MP["big"], cde(m), "wq map with a 6th member")
wqv("w14-revocation-any-one", None, TR, cde({"v": "deus-aar-0.1", "t": "revocation", "mandate": hashlib.sha256(b"m").digest()}),
    wq_by(["a1"], TR, cde({"v": "deus-aar-0.1", "t": "revocation", "mandate": hashlib.sha256(b"m").digest()}), P2), "revocation rule any/k=1: one access member is enough")
wqv("w15-policy-stale", "WQ_POLICY_STALE", TM, MP["big"], wq_by(["b1", "b3"], TM, MP["big"], P2),
    "b3 removed in v3; signed by v2; ledger entry written after v3 (second pass)", chain=CHAIN3, at=T3 + 100)
wqv("w16-policy-in-force-at-time", None, TM, MP["big"], wq_by(["b1", "b3"], TM, MP["big"], P2),
    "same envelope, entry written between v2 and v3: policy-at-time ok", chain=CHAIN3, at=T2 + 100)
ACT = {"agent": "ag_demo", "class": "purchase", "recipient": "vendor", "data": [], "amount": 60000, "currency": "USD"}
AP = approval_payload(M_BIG, ACT, "r_ABCDEFGHIJKLMNOPQRSTUVWXYZ", True)
wqv("w17-approval-needs-two", "WQ_QUORUM", TA, AP, wq_by(["b1"], TA, AP, P2), "approval of a 60000 purchase: budget k=2 (needs the action)", action=ACT)
wqv("w18-approval-two-valid", None, TA, AP, wq_by(["b1", "b2"], TA, AP, P2), "same, two budget signers", action=ACT)
wqv("w19-payload-substituted", "MANDATE_SIG", TM, MP["big"], wq_by(["b1", "b2"], TM, MP["small"], P2), "quorum signed another mandate than the expected one")
wqv("w20-policy-at-time-missing-t", "WQ_POLICY_STALE", TM, MP["big"], wq_by(["b1", "b3"], TM, MP["big"], P2),
    "second pass without version time: not provable -> stale", chain=[{"policy_hex": c["policy_hex"], "envelope_hex": c["envelope_hex"], "t": None} for c in CHAIN3], at=T2 + 100)

# ---- policy ----
def polv(id, expect, chain, note):
    write("policy", id, {"id": id, "class": "valid" if expect is None else "invalid", "expect": expect, "chain": chain, "rp": RPD, "note": note})


polv("p01-genesis", None, CHAIN3[:1], "genesis: wa-sig of the pinned key, one member, all roles, all k=1")
polv("p02-v2-by-rule-of-v1", None, CHAIN2, "v2 signed by wq under the rule 'policy' of v1")
polv("p03-three-versions", None, CHAIN3, "v1..v3")
E3b = wq_by(["b1"], q.TYP_POLICY, cde(P3), P2)
polv("p04-v3-not-by-owner", ["WQ_QUORUM", 3], build_chain((P1, E1, T1), (P2, E2, T2), (P3, E3b, T3)), "v3 signed by a budget member; rule requires owner")
P3skip = pol(3, q.policy_hash(P1), TEAM3)
polv("p05-version-skipped", ["POLICY_CHAIN", 2], build_chain((P1, E1, T1), (P3skip, wq_by(["owner"], q.TYP_POLICY, cde(P3skip), P1), T2)), "ver 3 follows ver 1")
P2bad = pol(2, hashlib.sha256(b"x").digest())
polv("p06-prev-mismatch", ["POLICY_CHAIN", 2], build_chain((P1, E1, T1), (P2bad, wq_by(["owner"], q.TYP_POLICY, cde(P2bad), P1), T2)), "prev is not the hash of v1")
MS17 = members(*[member("x%02d" % i, ["owner", "budget", "access"]) for i in range(17)])
P2big = pol(2, q.policy_hash(P1), MS17, {"policy": {"role": "owner", "k": 1}, "mandate": [], "approval": [], "revocation": {"role": "any", "k": 1}, "ceiling": {"role": "owner", "k": 1}})
polv("p07-17-members", ["POLICY_MALFORMED", 2], build_chain((P1, E1, T1), (P2big, wq_by(["owner"], q.TYP_POLICY, cde(P2big), P1), T2)), "17 members, limit 16")
TEAMat = members(member("owner", ["owner"], "ann@example"), member("b1", ["budget"]), member("b2", ["budget"]), member("b3", ["budget"]), member("a1", ["access"]), member("dual", ["budget", "access"]))
P2at = pol(2, q.policy_hash(P1), TEAMat)
polv("p08-label-with-at", ["POLICY_MALFORMED", 2], build_chain((P1, E1, T1), (P2at, wq_by(["owner"], q.TYP_POLICY, cde(P2at), P1), T2)), "label contains '@' (privacy)")
polv("p09-genesis-wrong-key", ["KEY_MISMATCH", 1], build_chain((P1, wa_by("b1", q.TYP_POLICY, cde(P1)), T1)), "genesis signed by a key other than the single member")
G2 = pol(1, None, members(member("owner", ["owner", "budget", "access"]), member("b1", ["budget"])), GENESIS["rules"])
polv("p10-genesis-two-members", ["POLICY_MALFORMED", 1], build_chain((G2, wa_by("owner", q.TYP_POLICY, cde(G2)), T1)), "genesis must have exactly one member")
P3old = pol(3, q.policy_hash(P2), TEAM3)
polv("p11-quorum-names-old-version", ["POLICY_CHAIN", 3], build_chain((P1, E1, T1), (P2, E2, T2), (P3old, wq_by(["owner"], q.TYP_POLICY, cde(P3old), P1), T3)), "v3 quorum collected under v1")
RB = dict(RULES, mandate=[{"if": "money", "role": "budget", "k": 2}])
P2lock = pol(2, q.policy_hash(P1), members(member("owner", ["owner"]), member("b1", ["budget"])), RB)
polv("p12-unsatisfiable-rule", ["POLICY_MALFORMED", 2], build_chain((P1, E1, T1), (P2lock, wq_by(["owner"], q.TYP_POLICY, cde(P2lock), P1), T2)), "budget k=2 with a single budget member would lock the org")

# ---- wb ----
BM = A["b1"]
REGB = BM.reg_entry(RP, [ORIGIN])
PAYS = [approval_payload(M_SMALL, dict(ACT, amount=100 + i, recipient="vendor"), "r_%026d" % i, True) for i in range(22)]
ITEMS = [hashlib.sha256(p).digest() for p in PAYS]


def wbv(id, expect, payload, env, note, reg=REGB, typ=TA):
    write("wb", id, {"id": id, "class": "valid" if expect is None else "invalid", "expect": expect, "typ": typ, "payload_hex": payload.hex(),
                     "envelope_hex": env.hex(), "reg_entry": reg, "rp": RPD, "note": note})


def wb_by(name, items, chal_items=None, **kw):
    a = A[name]
    ad, cd, der = a.get_assertion(q.wb_challenge(chal_items if chal_items is not None else items), RP, ORIGIN, **kw)
    return q.make_wb(items, a.kid, ad, cd, der, normalize=not kw.get("high_s"))


wbv("b01-twelve-items", None, PAYS[5], wb_by("b1", ITEMS[:12]), "12 items, the payload is item #6")
wbv("b02-one-item", None, PAYS[0], wb_by("b1", ITEMS[:1]), "single item")
wbv("b03-twenty-items", None, PAYS[19], wb_by("b1", ITEMS[:20]), "20 items (limit)")
wbv("b04-payload-not-in-items", "WB_ITEM", PAYS[21], wb_by("b1", ITEMS[:12]), "valid wb, but the expected payload is not among the items")
wbv("b05-twenty-one-items", "WB_MALFORMED", PAYS[3], wb_by("b1", ITEMS[:21]), "21 items, limit 20")
wbv("b06-foreign-challenge", "WA_CLIENTDATA", PAYS[0], wb_by("b1", ITEMS[:12], chal_items=ITEMS[1:13]), "signature over the challenge of other items")
wbv("b07-high-s", "WA_SIG", PAYS[0], wb_by("b1", ITEMS[:12], high_s=True), "high-S kept")
wbv("b08-item-not-32-bytes", "WB_MALFORMED", PAYS[0], wb_by("b1", ITEMS[:3] + [ITEMS[3][:31]], chal_items=ITEMS[:4]), "one item of 31 bytes")
wbv("b09-foreign-kid", "KEY_MISMATCH", PAYS[0], wb_by("b2", ITEMS[:12]), "signed by another key, pinned key is b1")
mm = cbor2.loads(wb_by("b1", ITEMS[:12]))
wbv("b10-not-cde", "WB_MALFORMED", PAYS[0], cbor2.dumps(dict(reversed(list(mm.items())))), "map in insertion order, not CDE")
wbv("b11-wrong-typ-expected", "APPROVAL_SIG", M_BIG and cde(M_BIG), wb_by("b1", ITEMS[:12]), "wb offered for a mandate", typ=TM)
print([len(os.listdir(os.path.join(HERE, "vectors", d))) for d in ("wq", "wb", "policy")])
