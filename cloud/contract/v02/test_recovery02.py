"""0.2.2 (recovery after a lost passkey): the contract rules, one test per rule.
 R-C1 rule `recovery` is optional; k >= 2; reachable when ANY one member is lost.
 R-C2 key_swap: exactly one member's key replaced, nothing else.
 R-C3 policy_step: the recovery quorum adopts a key swap; the lost key never counts; anything else than a swap still needs rule `policy`.
 R-C4 wb may revoke; the typ is inside the challenge (a batch approval is never a batch revocation).
 R-C5 key events: CDE payload, structure, intervals and activity at time t."""
import copy
import hashlib
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..")))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "../../..")))
import cbor2
import wa_profile as wa
import wq_profile as q
from svidetel_v4.state import revocation_payload

RP = {"rp_id": "localhost", "origins": ["http://localhost:8810"]}
P = "dw:" + "ab" * 16


def sign_wa(a, typ, payload):
    return a.sign_object(typ, payload, RP["rp_id"], RP["origins"][0])


def wq_of(signers, typ, payload, prev_bytes):
    return q.make_wq(typ, payload, hashlib.sha256(prev_bytes).digest(), [q.wsig_of_wa(sign_wa(a, typ, payload)) for a in signers])


def member(a, roles, label):
    return {"kid": a.kid, "pub": a.pub, "cred": a.credential_id, "roles": roles, "label": label}


class Team:
    """owner O (owner+budget), B (budget), C (access); v1 genesis by O, v2 = team with rule recovery {any, 2}."""

    def __init__(self, recovery=True):
        self.O, self.B, self.C = wa.SoftAuthenticator(), wa.SoftAuthenticator(), wa.SoftAuthenticator()
        g = {"v": q.V_POLICY, "principal": P, "ver": 1, "prev": None, "members": [member(self.O, list(q.ROLES), "olga")],
             "rules": {"policy": {"role": "owner", "k": 1}, "mandate": [], "approval": [], "revocation": {"role": "any", "k": 1},
                       "ceiling": {"role": "owner", "k": 1}}}
        g1 = wa.cde(g)
        self.chain = [(g1, sign_wa(self.O, q.TYP_POLICY, g1), 1000)]
        rules = {"policy": {"role": "owner", "k": 1}, "mandate": [], "approval": [], "revocation": {"role": "any", "k": 1},
                 "ceiling": {"role": "owner", "k": 1}}
        if recovery:
            rules["recovery"] = {"role": "any", "k": 2}
        ms = sorted([member(self.O, ["owner", "budget"], "olga"), member(self.B, ["budget"], "bob"), member(self.C, ["access"], "carol")],
                    key=lambda m: m["kid"])
        p2 = {"v": q.V_POLICY, "principal": P, "ver": 2, "prev": hashlib.sha256(g1).digest(), "members": ms, "rules": rules}
        b2 = wa.cde(p2)
        self.p2 = p2
        self.chain.append((b2, wq_of([self.O], q.TYP_POLICY, b2, g1), 2000))
        assert q.verify_policy_chain(self.chain, rp=RP) is None

    def swap(self, old, new):
        """v3 = v2 with `old`'s key replaced by `new` (same roles and label)."""
        p = copy.deepcopy(self.p2)
        p["ver"], p["prev"] = 3, hashlib.sha256(self.chain[-1][0]).digest()
        for m in p["members"]:
            if m["kid"] == old.kid:
                m.update(kid=new.kid, pub=new.pub, cred=new.credential_id)
        p["members"].sort(key=lambda m: m["kid"])
        return p


class TestRecoveryRule(unittest.TestCase):          # R-C1
    def test_optional_and_valid(self):
        t = Team()
        self.assertIsNone(q.validate_policy(t.p2))
        p = copy.deepcopy(t.p2)
        del p["rules"]["recovery"]
        self.assertIsNone(q.validate_policy(p))

    def test_k1_refused(self):
        p = copy.deepcopy(Team().p2)
        p["rules"]["recovery"] = {"role": "any", "k": 1}        # one person alone must never take over another member's key
        self.assertEqual(q.validate_policy(p), "POLICY_MALFORMED")

    def test_unreachable_refused(self):
        p = copy.deepcopy(Team().p2)
        p["rules"]["recovery"] = {"role": "any", "k": 3}        # 3 members: when one is lost only 2 remain
        self.assertEqual(q.validate_policy(p), "POLICY_MALFORMED")
        p["rules"]["recovery"] = {"role": "budget", "k": 2}     # budget holders: olga, bob -> losing one leaves one
        self.assertEqual(q.validate_policy(p), "POLICY_MALFORMED")

    def test_unknown_rule_refused(self):
        p = copy.deepcopy(Team().p2)
        p["rules"]["takeover"] = {"role": "any", "k": 2}
        self.assertEqual(q.validate_policy(p), "POLICY_MALFORMED")


class TestKeySwap(unittest.TestCase):               # R-C2
    def test_swap_detected(self):
        t = Team()
        n = wa.SoftAuthenticator()
        self.assertEqual(q.key_swap(t.p2, t.swap(t.B, n)), (t.B.kid, n.kid))

    def test_more_than_a_swap_is_not_a_swap(self):
        t = Team()
        n = wa.SoftAuthenticator()
        p = t.swap(t.B, n)
        next(m for m in p["members"] if m["kid"] == n.kid)["roles"] = ["budget", "owner"]
        self.assertIsNone(q.key_swap(t.p2, p))
        p = t.swap(t.B, n)
        p["rules"]["policy"] = {"role": "any", "k": 1}
        self.assertIsNone(q.key_swap(t.p2, p))
        p = t.swap(t.B, n)
        for m in p["members"]:
            if m["kid"] == t.C.kid:
                m["label"] = "eve"
        self.assertIsNone(q.key_swap(t.p2, p))
        self.assertIsNone(q.key_swap(t.p2, copy.deepcopy(t.p2)))     # nothing replaced


class TestPolicyStep(unittest.TestCase):            # R-C3
    def test_recovery_quorum_adopts_swap(self):
        t = Team()
        n = wa.SoftAuthenticator()
        b3 = wa.cde(t.swap(t.O, n))                          # the OWNER lost the phone: bob + carol replace the owner's key
        env = wq_of([t.B, t.C], q.TYP_POLICY, b3, t.chain[-1][0])
        self.assertIsNone(q.policy_step(t.chain, b3, env, RP))
        self.assertIsNone(q.verify_policy_chain(t.chain + [(b3, env, 3000)], rp=RP))

    def test_one_other_is_not_enough(self):
        t = Team()
        n = wa.SoftAuthenticator()
        b3 = wa.cde(t.swap(t.O, n))
        self.assertEqual(q.policy_step(t.chain, b3, wq_of([t.B], q.TYP_POLICY, b3, t.chain[-1][0]), RP), "WQ_QUORUM")

    def test_lost_key_never_counts(self):
        t = Team()
        n = wa.SoftAuthenticator()
        b3 = wa.cde(t.swap(t.B, n))                          # bob's key replaced; bob's OLD key + carol is not the recovery quorum
        env = wq_of([t.B, t.C], q.TYP_POLICY, b3, t.chain[-1][0])
        self.assertEqual(q.policy_step(t.chain, b3, env, RP), "WQ_QUORUM")

    def test_recovery_rule_does_not_open_other_changes(self):
        t = Team()
        n = wa.SoftAuthenticator()
        p = t.swap(t.O, n)
        next(m for m in p["members"] if m["kid"] == t.B.kid)["roles"] = ["budget", "owner"]      # + a role: not a pure swap
        b3 = wa.cde(p)
        self.assertEqual(q.policy_step(t.chain, b3, wq_of([t.B, t.C], q.TYP_POLICY, b3, t.chain[-1][0]), RP), "WQ_QUORUM")

    def test_without_recovery_rule_the_policy_rule_applies(self):
        t = Team(recovery=False)
        n = wa.SoftAuthenticator()
        b3 = wa.cde(t.swap(t.O, n))
        self.assertEqual(q.policy_step(t.chain, b3, wq_of([t.B, t.C], q.TYP_POLICY, b3, t.chain[-1][0]), RP), "WQ_QUORUM")
        self.assertIsNone(q.policy_step(t.chain, b3, wq_of([t.O], q.TYP_POLICY, b3, t.chain[-1][0]), RP))   # owner still has the key

    def test_must_name_the_last_version(self):
        t = Team()
        n = wa.SoftAuthenticator()
        b3 = wa.cde(t.swap(t.O, n))
        env = wq_of([t.B, t.C], q.TYP_POLICY, b3, t.chain[0][0])
        self.assertIn(q.policy_step(t.chain, b3, env, RP), ("POLICY_CHAIN", "WQ_NOT_MEMBER"))


class TestWbRevocation(unittest.TestCase):          # R-C4
    def setUp(self):
        self.a = wa.SoftAuthenticator()
        self.reg = self.a.reg_entry(RP["rp_id"], RP["origins"])
        self.ms = [{"id": "%032x" % i, "principal": P} for i in range(3)]
        self.pays = [revocation_payload(m) for m in self.ms]
        self.items = [hashlib.sha256(p).digest() for p in self.pays]

    def wb(self, typ, chal_typ=None):
        ad, cd, der = self.a.get_assertion(q.wb_challenge(self.items, chal_typ or typ), RP["rp_id"], RP["origins"][0])
        return q.make_wb(self.items, self.a.kid, ad, cd, der, typ=typ)

    def test_batch_revocation_valid_for_every_item(self):
        env = self.wb(wa.TYP_REVOCATION)
        for p in self.pays:
            self.assertIsNone(q.verify_wb(env, wa.TYP_REVOCATION, p, self.reg))

    def test_typ_bound_into_challenge(self):
        self.assertNotEqual(q.wb_challenge(self.items, wa.TYP_REVOCATION), q.wb_challenge(self.items))
        env = self.wb(wa.TYP_REVOCATION, chal_typ=wa.TYP_APPROVAL)     # an approval ceremony relabelled as a revocation
        self.assertEqual(q.verify_wb(env, wa.TYP_REVOCATION, self.pays[0], self.reg), "WA_CLIENTDATA")

    def test_approval_batch_is_not_a_revocation(self):
        env = self.wb(wa.TYP_APPROVAL)
        self.assertEqual(q.verify_wb(env, wa.TYP_REVOCATION, self.pays[0], self.reg), "REVOCATION_SIG")
        self.assertEqual(q.verify_wb(self.wb(wa.TYP_REVOCATION), wa.TYP_APPROVAL, self.pays[0], self.reg), "APPROVAL_SIG")

    def test_other_types_stay_malformed(self):
        ad, cd, der = self.a.get_assertion(q.wb_challenge(self.items, wa.TYP_MANDATE), RP["rp_id"], RP["origins"][0])
        env = q.make_wb(self.items, self.a.kid, ad, cd, der, typ=wa.TYP_MANDATE)
        self.assertEqual(q.verify_wb(env, wa.TYP_MANDATE, self.pays[0], self.reg), "WB_MALFORMED")

    def test_revocation_rule_for_wb(self):
        t = Team()
        self.assertIsNone(q.wb_requirements_met(t.p2, t.C.kid, None, wa.TYP_REVOCATION))       # rule revocation {any, 1}
        self.assertEqual(q.wb_requirements_met(t.p2, b"\x01" * 32, None, wa.TYP_REVOCATION), "WQ_NOT_MEMBER")


class TestKeyEvents(unittest.TestCase):             # R-C5
    def test_payload_roundtrip_and_checks(self):
        a = wa.SoftAuthenticator()
        b = q.key_event_payload(P, "add", a.kid, a.pub, a.credential_id, b"\x07" * 16)
        m = q.parse_key_event(b)
        self.assertEqual((m["op"], m["kid"]), ("add", a.kid))
        with self.assertRaises(ValueError):
            q.key_event_payload(P, "add", b"\x00" * 32, a.pub, a.credential_id, b"\x07" * 16)     # kid is not the pub's thumbprint
        with self.assertRaises(ValueError):
            q.key_event_payload(P, "rotate", a.kid, a.pub, a.credential_id, b"\x07" * 16)
        self.assertIsNone(q.parse_key_event(cbor2.dumps({"v": q.V_KEY_EVENT})))
        self.assertIsNone(q.parse_key_event(b + b"\x00"))

    def test_intervals(self):
        k0, k1, k2 = b"\x00" * 32, b"\x01" * 32, b"\x02" * 32
        iv = q.key_intervals(k0, 100, [(200, "add", k1), (300, "remove", k0), (400, "add", k2), (500, "remove", k1)])
        self.assertTrue(q.key_active_at(iv, k0, 299))
        self.assertFalse(q.key_active_at(iv, k0, 300))           # removed at 300: an entry at 300 or later is not signed by k0
        self.assertFalse(q.key_active_at(iv, k1, 199))           # before it was added
        self.assertTrue(q.key_active_at(iv, k1, 200))
        self.assertFalse(q.key_active_at(iv, k1, 500))
        self.assertTrue(q.key_active_at(iv, k2, 10 ** 9))
        self.assertFalse(q.key_active_at(iv, b"\x09" * 32, 150))


if __name__ == "__main__":
    unittest.main()


class TestVectors022(unittest.TestCase):           # the files the browser checks byte for byte (web/test/recovery.test.mjs)
    def test_all(self):
        import glob
        import json
        vs = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(HERE, "vectors", "recovery", "*.json")))]
        self.assertGreaterEqual(len(vs), 12)
        for v in vs:
            with self.subTest(v["id"]):
                if v["kind"] == "wb":
                    self.assertEqual(q.verify_wb(bytes.fromhex(v["envelope_hex"]), v["typ"], bytes.fromhex(v["payload_hex"]), v["reg_entry"]), v["expect"])
                    self.assertEqual(revocation_payload(v["mandates"][0]).hex(), v["payload_hex"])
                elif v["kind"] == "key_event":
                    f = v["fields"]
                    b = q.key_event_payload(f["principal"], f["op"], bytes.fromhex(f["kid"]), bytes.fromhex(f["pub"]), bytes.fromhex(f["cred"]), bytes.fromhex(f["nonce"]))
                    self.assertEqual(b.hex(), v["payload_hex"])
                    self.assertIsNone(wa.verify_envelope(bytes.fromhex(v["envelope_hex"]), v["typ"], b, v["signer"]))
                elif v["kind"] == "policy":
                    self.assertEqual(q.validate_policy(cbor2.loads(bytes.fromhex(v["policy_hex"]))), v["expect"])
                else:
                    ch = [(bytes.fromhex(c["policy_hex"]), bytes.fromhex(c["envelope_hex"]), c["t"]) for c in v["chain"]]
                    pb = bytes.fromhex(v["policy_hex"])
                    self.assertEqual(q.policy_step(ch, pb, bytes.fromhex(v["envelope_hex"]), v["rp"]), v["expect"])
                    self.assertEqual([x.hex() for x in q.key_swap(cbor2.loads(ch[-1][0]), cbor2.loads(pb))], v["swap"])


class TestOpenapi022(unittest.TestCase):
    def test_valid_spec(self):
        import yaml
        from openapi_spec_validator import validate
        spec = yaml.safe_load(open(os.path.join(HERE, "openapi-0.2.2-recovery.yaml")))
        validate(spec)
        old = set(yaml.safe_load(open(os.path.join(HERE, "openapi-0.2.yaml")))["paths"]) | set(yaml.safe_load(open(os.path.join(HERE, "..", "openapi.yaml")))["paths"])
        self.assertFalse(set(spec["paths"]) & old)                       # only new paths
        self.assertEqual(len(spec["paths"]), 14)
        rules = yaml.safe_load(open(os.path.join(HERE, "openapi-0.2.yaml")))["components"]["schemas"]["PolicyRules"]
        self.assertIn("recovery", rules["properties"])
        self.assertNotIn("recovery", rules["required"])
