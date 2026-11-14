"""0.2.2 (recovery): vectors/recovery/*.json -- wb of typ revocation (byte for byte + verdicts), key-event payloads (CDE), policies with
and without the optional rule `recovery` (validate_policy verdicts) and one key swap (policy_step). Deterministic keys (test only).
ECDSA signatures are randomised: a re-run changes envelope bytes, not verdicts. Run: ../../.venv/bin/python gen_vectors022.py"""
import copy, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..")))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "../../..")))
import wa_profile as wa
import wq_profile as q
from svidetel_v4.state import revocation_payload

RP, ORIGIN = "witness.sipkigroup.com", "https://witness.sipkigroup.com"
RPD = {"rp_id": RP, "origins": [ORIGIN]}
PRINCIPAL = "dw:0123456789abcdef0123456789abcdef"
OUT = os.path.join(HERE, "vectors", "recovery")


def auth(name):
    n = int.from_bytes(hashlib.sha256(b"deus-recovery-test-key-" + name.encode()).digest(), "big") % (wa.P256_N - 1) + 1
    return wa.SoftAuthenticator(private_int=n, credential_id=hashlib.sha256(b"cred-" + name.encode()).digest())


A = {n: auth(n) for n in ("phone", "laptop", "olga", "bob", "carol", "olga2")}
MANDATES = [{"v": "deus-aar-0.1", "id": "%032x" % (i + 1), "principal": PRINCIPAL, "agent": "ag_%d" % i} for i in range(3)]


def save(name, obj):
    with open(os.path.join(OUT, name + ".json"), "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)


def wb(signer, items, typ, chal_typ=None):
    a = A[signer]
    ad, cd, der = a.get_assertion(q.wb_challenge(items, chal_typ or typ), RP, ORIGIN)
    return q.make_wb(items, a.kid, ad, cd, der, typ=typ)


def member(n, roles, label):
    a = A[n]
    return {"kid": a.kid, "pub": a.pub, "cred": a.credential_id, "roles": roles, "label": label}


def hx(x):
    if isinstance(x, bytes):
        return x.hex()
    if isinstance(x, dict):
        return {k: hx(v) for k, v in x.items()}
    if isinstance(x, list):
        return [hx(v) for v in x]
    return x


def main():
    os.makedirs(OUT, exist_ok=True)
    for f in os.listdir(OUT):
        os.remove(os.path.join(OUT, f))
    pays = [revocation_payload(m) for m in MANDATES]
    items = [hashlib.sha256(p).digest() for p in pays]
    reg = A["laptop"].reg_entry(RP, [ORIGIN])
    cases = [("r01-revocation-batch", wb("laptop", items, wa.TYP_REVOCATION), wa.TYP_REVOCATION, None),
             ("r02-approval-ceremony-relabelled", wb("laptop", items, wa.TYP_REVOCATION, wa.TYP_APPROVAL), wa.TYP_REVOCATION, "WA_CLIENTDATA"),
             ("r03-approval-batch-offered-as-revocation", wb("laptop", items, wa.TYP_APPROVAL), wa.TYP_REVOCATION, "REVOCATION_SIG"),
             ("r04-other-key", wb("phone", items, wa.TYP_REVOCATION), wa.TYP_REVOCATION, "KEY_MISMATCH")]
    for cid, env, typ, expect in cases:
        assert q.verify_wb(env, typ, pays[0], reg) == expect, cid
        save(cid, {"id": cid, "kind": "wb", "typ": typ, "items_hex": [i.hex() for i in items], "payload_hex": pays[0].hex(),
                   "mandates": MANDATES, "challenge_hex": q.wb_challenge(items, wa.TYP_REVOCATION).hex(),
                   "envelope_hex": env.hex(), "reg_entry": reg, "expect": expect})
    # key events: CDE payload the browser shows and the passkey signs
    for cid, op, who in (("k01-add", "add", "laptop"), ("k02-remove", "remove", "phone")):
        a = A[who]
        nonce = hashlib.sha256(cid.encode()).digest()[:16]
        b = q.key_event_payload(PRINCIPAL, op, a.kid, a.pub, a.credential_id, nonce)
        env = A["phone" if op == "add" else "laptop"].sign_object(q.TYP_KEY_EVENT, b, RP, ORIGIN)
        signer = A["phone" if op == "add" else "laptop"].reg_entry(RP, [ORIGIN])
        assert wa.verify_envelope(env, q.TYP_KEY_EVENT, b, signer) is None
        save(cid, {"id": cid, "kind": "key_event", "fields": hx({"v": q.V_KEY_EVENT, "principal": PRINCIPAL, "op": op, "kid": a.kid, "pub": a.pub,
                                                                  "cred": a.credential_id, "nonce": nonce}),
                   "payload_hex": b.hex(), "typ": q.TYP_KEY_EVENT, "envelope_hex": env.hex(), "signer": signer, "expect": None})
    # policies with the optional recovery rule
    base_rules = {"policy": {"role": "owner", "k": 1}, "mandate": [], "approval": [], "revocation": {"role": "any", "k": 1},
                  "ceiling": {"role": "owner", "k": 1}}
    ms = sorted([member("olga", ["owner", "budget"], "olga"), member("bob", ["budget"], "bob"), member("carol", ["access"], "carol")],
                key=lambda m: m["kid"])
    p = {"v": q.V_POLICY, "principal": PRINCIPAL, "ver": 2, "prev": b"\x11" * 32, "members": ms, "rules": base_rules}
    for cid, rec, expect in (("p01-no-recovery-rule", None, None), ("p02-recovery-any-2", {"role": "any", "k": 2}, None),
                             ("p03-recovery-k1", {"role": "any", "k": 1}, "POLICY_MALFORMED"),
                             ("p04-recovery-unreachable", {"role": "any", "k": 3}, "POLICY_MALFORMED"),
                             ("p05-recovery-budget-2", {"role": "budget", "k": 2}, "POLICY_MALFORMED"),
                             ("p06-revocation-owner-only", None, "POLICY_MALFORMED"),
                             ("p07-revocation-any-2", None, "POLICY_MALFORMED")):
        pp = copy.deepcopy(p)
        if rec:
            pp["rules"]["recovery"] = rec
        if cid == "p06-revocation-owner-only":      # law Z3: stopping is any ONE signer; another rule is not a valid policy
            pp["rules"]["revocation"] = {"role": "owner", "k": 1}
        if cid == "p07-revocation-any-2":
            pp["rules"]["revocation"] = {"role": "any", "k": 2}
        assert q.validate_policy(pp) == expect, cid
        save(cid, {"id": cid, "kind": "policy", "policy": hx(pp), "policy_hex": wa.cde(pp).hex(), "expect": expect})
    # key swap: olga's key replaced by olga2 (k02 of vectors: what policy_step accepts with bob + carol)
    pp = copy.deepcopy(p)
    pp["rules"]["recovery"] = {"role": "any", "k": 2}
    g = {"v": q.V_POLICY, "principal": PRINCIPAL, "ver": 1, "prev": None, "members": [member("olga", ["owner", "budget", "access"], "olga")],
         "rules": base_rules}
    gb = wa.cde(g)
    pp["prev"] = hashlib.sha256(gb).digest()
    b2 = wa.cde(pp)
    ch = [(gb, A["olga"].sign_object(q.TYP_POLICY, gb, RP, ORIGIN), 100)]
    ch.append((b2, q.make_wq(q.TYP_POLICY, b2, hashlib.sha256(gb).digest(), [q.wsig_of_wa(A["olga"].sign_object(q.TYP_POLICY, b2, RP, ORIGIN))]), 200))
    assert q.verify_policy_chain(ch, rp=RPD) is None
    p3 = copy.deepcopy(pp)
    p3["ver"], p3["prev"] = 3, hashlib.sha256(b2).digest()
    for m in p3["members"]:
        if m["kid"] == A["olga"].kid:
            m.update(kid=A["olga2"].kid, pub=A["olga2"].pub, cred=A["olga2"].credential_id)
    p3["members"].sort(key=lambda m: m["kid"])
    b3 = wa.cde(p3)
    env3 = q.make_wq(q.TYP_POLICY, b3, hashlib.sha256(b2).digest(), [q.wsig_of_wa(A[n].sign_object(q.TYP_POLICY, b3, RP, ORIGIN)) for n in ("bob", "carol")])
    assert q.policy_step(ch, b3, env3, RPD) is None
    save("s01-key-swap-by-recovery-quorum", {"id": "s01", "kind": "swap", "chain": [{"policy_hex": c[0].hex(), "envelope_hex": c[1].hex(), "t": c[2]} for c in ch],
                                             "policy_hex": b3.hex(), "envelope_hex": env3.hex(), "rp": RPD,
                                             "swap": [A["olga"].kid.hex(), A["olga2"].kid.hex()], "expect": None})
    print("vectors/recovery: %d files" % len(os.listdir(OUT)))


if __name__ == "__main__":
    main()
