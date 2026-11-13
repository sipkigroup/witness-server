"""0.2.15 contract: rules.delegation in the org policy (validate_policy, delegation_code, verify_wq(agent=), key_swap with swap_rules),
phone_lift_payload, openapi-0.2.15.yaml (only new paths) and PolicyRules.delegation in openapi-0.2.yaml."""
import hashlib
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import wa_profile as wa  # noqa: E402
import wq_profile as q  # noqa: E402

RP = {"rp_id": "localhost", "origins": ["http://localhost:8080"]}
RULES = {"policy": {"role": "owner", "k": 1}, "mandate": [], "approval": [], "revocation": {"role": "any", "k": 1}, "ceiling": {"role": "owner", "k": 1}}


def members(n):
    out = []
    for i in range(n):
        a = wa.SoftAuthenticator()
        out.append((a, {"kid": a.kid, "pub": a.pub, "cred": bytes([i]) * 8, "roles": ["owner", "budget", "access"] if i == 0 else ["budget"], "label": "m%d" % i}))
    return sorted(out, key=lambda x: x[1]["kid"])


def policy(ms, dl=None):
    r = dict(RULES)
    if dl is not None:
        r["delegation"] = dl
    return {"v": q.V_POLICY, "principal": "dw:p", "ver": 1, "prev": None, "members": [m for _, m in ms], "rules": r}


class TestDelegation(unittest.TestCase):
    def setUp(self):
        self.ms = members(3)
        self.k = [m["kid"].hex() for _, m in self.ms]

    def test_validate(self):
        k = self.k
        d = {"agent": "ag_1", "operator": k[0], "approvers": [k[1], k[2]], "until": None}
        self.assertIsNone(q.validate_policy(policy(self.ms, [d])))
        self.assertIsNone(q.validate_policy(policy(self.ms, [dict(d, approvers=None)])))
        for bad in ([], [dict(d, approvers=[k[2], k[1]])], [dict(d, approvers=[k[0], k[1]])], [dict(d, approvers=["00" * 32])],
                    [dict(d, operator=k[0][:63])], [d, d], [dict(d, agent="x\ty")], [dict(d, until=1.5)]):
            self.assertEqual(q.validate_policy(policy(self.ms, bad)), "POLICY_MALFORMED", bad)

    def test_verify_wq_agent(self):
        (a0, m0), (a1, m1), (a2, m2) = self.ms
        pol = policy(self.ms, [{"agent": "ag_1", "operator": m0["kid"].hex(), "approvers": [m1["kid"].hex()], "until": 50}])
        pb = wa.cde(pol)
        ch = [(pb, None, 10)]
        pay = b"p"

        def env(*auths):
            ws = [q.wsig_of_wa(a.sign_object(wa.TYP_APPROVAL, pay, RP["rp_id"], RP["origins"][0])) for a in sorted(auths, key=lambda a: a.kid)]
            return q.make_wq(wa.TYP_APPROVAL, pay, hashlib.sha256(pb).digest(), ws)
        self.assertEqual(q.verify_wq(env(a0), wa.TYP_APPROVAL, pay, ch, rp=RP, agent="ag_1"), "WQ_SELF")
        self.assertEqual(q.verify_wq(env(a0, a1), wa.TYP_APPROVAL, pay, ch, rp=RP, agent="ag_1"), "WQ_SELF")
        self.assertEqual(q.verify_wq(env(a2), wa.TYP_APPROVAL, pay, ch, rp=RP, agent="ag_1"), "WQ_NOT_DELEGATE")
        self.assertIsNone(q.verify_wq(env(a1), wa.TYP_APPROVAL, pay, ch, rp=RP, agent="ag_1", at=50))
        self.assertEqual(q.verify_wq(env(a1), wa.TYP_APPROVAL, pay, ch, rp=RP, agent="ag_1", at=51), "WQ_NOT_DELEGATE")
        self.assertIsNone(q.verify_wq(env(a0), wa.TYP_APPROVAL, pay, ch, rp=RP, agent="ag_other"))
        self.assertIsNone(q.verify_wq(env(a0), wa.TYP_APPROVAL, pay, ch, rp=RP))       # refusals and old callers pass no agent

    def test_key_swap_follows_the_delegation(self):
        (a0, m0), (a1, m1), _ = self.ms
        prev = dict(policy(self.ms, [{"agent": "ag_1", "operator": m1["kid"].hex(), "approvers": None, "until": None}]), ver=2, prev=b"\1" * 32)
        n = wa.SoftAuthenticator()
        ms = sorted([dict(m1, kid=n.kid, pub=n.pub) if m is m1 else m for _, m in self.ms], key=lambda m: m["kid"])
        new = dict(prev, members=ms, rules=q.swap_rules(prev["rules"], m1["kid"], n.kid))
        self.assertEqual(q.key_swap(prev, new), (m1["kid"], n.kid))
        self.assertEqual(new["rules"]["delegation"][0]["operator"], n.kid.hex())
        self.assertIsNone(q.key_swap(prev, dict(new, rules=dict(new["rules"], delegation=[dict(new["rules"]["delegation"][0], approvers=[m0["kid"].hex()])]))))

    def test_phone_lift_payload(self):
        b = q.phone_lift_payload("dw:u", b"\1" * 32, 100, b"\2" * 16)
        self.assertEqual(wa.cde(__import__("cbor2").loads(b)), b)
        with self.assertRaises(ValueError):
            q.phone_lift_payload("dw:u", b"\1" * 31, 100, b"\2" * 16)
        self.assertEqual(q.SIG_CODE[q.TYP_PHONE_LIFT], "PHONE_LIFT_SIG")


class TestOpenapi0215(unittest.TestCase):
    def test_valid_spec_only_new_paths(self):
        import yaml
        from openapi_spec_validator import validate
        spec = yaml.safe_load(open(os.path.join(HERE, "openapi-0.2.15.yaml")))
        validate(spec)
        old = set()
        for f in ("openapi-0.2.yaml", "openapi-0.2.2-recovery.yaml", os.path.join("..", "openapi.yaml")):
            old |= set(yaml.safe_load(open(os.path.join(HERE, f)))["paths"])
        self.assertFalse(set(spec["paths"]) & old)
        self.assertIn("/api/auth/keys/{kid}/cancel-phone", spec["paths"])
        self.assertIn("/api/org/phone-lift", spec["paths"])
        rules = yaml.safe_load(open(os.path.join(HERE, "openapi-0.2.yaml")))["components"]["schemas"]["PolicyRules"]
        self.assertIn("delegation", rules["properties"])
        self.assertNotIn("delegation", rules["required"])

    def test_paths_exist_on_the_server(self):
        import yaml
        src = open(os.path.join(HERE, "..", "..", "server", "app", "api_web.py"), encoding="utf-8").read()
        for p in yaml.safe_load(open(os.path.join(HERE, "openapi-0.2.15.yaml")))["paths"]:
            self.assertIn('"%s"' % p.replace("{kid}", "{kid}").replace("{aid}", "{aid}"), src, p)


if __name__ == "__main__":
    unittest.main()
