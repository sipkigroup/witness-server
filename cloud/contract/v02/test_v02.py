"""Acceptance of contract 0.2: all vectors through the reference + unit tests + openapi-0.2 + stub02 scenarios.
Run: cd cloud/contract/v02 && ../../server/.venv/bin/python -m unittest -q test_v02"""
import glob, hashlib, json, os, subprocess, sys, time, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..")))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "../../..")))
import cbor2
import wa_profile as wa
import wq_profile as q
from svidetel_v4.state import approval_payload

PORT = 8898
RPID = "localhost"
ORIGIN = "http://localhost:%d" % PORT


def load(pat):
    out = []
    for f in sorted(glob.glob(os.path.join(HERE, pat))):
        with open(f) as h:
            out.append(json.load(h))
    return out


def chain_of(v):
    return [(bytes.fromhex(c["policy_hex"]), bytes.fromhex(c["envelope_hex"]), c["t"]) for c in v["chain"]]


WQ, WB, POL = load("vectors/wq/*.json"), load("vectors/wb/*.json"), load("vectors/policy/*.json")


class TestVectorCounts(unittest.TestCase):
    def test_counts(self):
        self.assertGreaterEqual(len(WQ), 16)
        self.assertGreaterEqual(len(WB), 8)
        self.assertGreaterEqual(len(POL), 8)

    def test_stale_vector_present(self):
        self.assertTrue(any(v["expect"] == "WQ_POLICY_STALE" and v["at"] is not None for v in WQ))

    def test_all_codes_of_the_task_covered(self):
        got = {v["expect"] for v in WQ}
        for c in ("WQ_QUORUM", "WQ_NOT_MEMBER", "WQ_DUP_SIGNER", "WQ_POLICY_UNKNOWN", "WQ_MALFORMED", "WQ_POLICY_STALE", "MANDATE_SIG"):
            self.assertIn(c, got)
        self.assertTrue(any(str(c).startswith("WA_") for c in got))
        self.assertIsNone(next(v["expect"] for v in WQ if v["id"].startswith("w01")))
        gw = {v["expect"] for v in WB}
        for c in (None, "WB_ITEM", "WB_MALFORMED", "WA_CLIENTDATA", "WA_SIG"):
            self.assertIn(c, gw)
        gp = {v["expect"][0] if v["expect"] else None for v in POL}
        for c in (None, "WQ_QUORUM", "POLICY_CHAIN", "POLICY_MALFORMED"):
            self.assertIn(c, gp)


def _mk_wq(v):
    def t(self):
        got = q.verify_wq(bytes.fromhex(v["envelope_hex"]), v["typ"], bytes.fromhex(v["payload_hex"]), chain_of(v),
                          action=v["action"], rp=v["rp"], at=v["at"])
        self.assertEqual(got, v["expect"])
        self.assertEqual(v["class"] == "valid", v["expect"] is None)
        self.assertEqual(q.envelope_kind(bytes.fromhex(v["envelope_hex"])), "wq")
    return t


def _mk_wb(v):
    def t(self):
        got = q.verify_wb(bytes.fromhex(v["envelope_hex"]), v["typ"], bytes.fromhex(v["payload_hex"]), v["reg_entry"])
        self.assertEqual(got, v["expect"])
    return t


def _mk_pol(v):
    def t(self):
        got = q.verify_policy_chain(chain_of(v), rp=v["rp"])
        self.assertEqual(list(got) if got else None, v["expect"])
    return t


class TestWq(unittest.TestCase):
    pass


class TestWb(unittest.TestCase):
    pass


class TestPolicyVectors(unittest.TestCase):
    pass


for _v in WQ:
    setattr(TestWq, "test_" + _v["id"].replace("-", "_"), _mk_wq(_v))
for _v in WB:
    setattr(TestWb, "test_" + _v["id"].replace("-", "_"), _mk_wb(_v))
for _v in POL:
    setattr(TestPolicyVectors, "test_" + _v["id"].replace("-", "_"), _mk_pol(_v))


class TestUnits(unittest.TestCase):
    def setUp(self):
        self.p2 = cbor2.loads(bytes.fromhex(WQ[0]["chain"][1]["policy_hex"]))
        self.p1 = cbor2.loads(bytes.fromhex(WQ[0]["chain"][0]["policy_hex"]))

    def test_envelope_kind(self):
        self.assertEqual(q.envelope_kind(bytes.fromhex(load("../vectors/wa/v01-mandate.json")[0]["envelope_hex"])), "wa")
        self.assertEqual(q.envelope_kind(bytes.fromhex(WB[0]["envelope_hex"])), "wb")
        self.assertIsNone(q.envelope_kind(b"\xd2\x84\x40\xa0\x40\x40"))
        self.assertIsNone(q.envelope_kind(b"junk"))
        self.assertIsNone(q.envelope_kind(wa.cde({"v": "other"})))

    def test_policy_hash_is_sha256_of_cde(self):
        self.assertEqual(q.policy_hash(self.p2), hashlib.sha256(wa.cde(self.p2)).digest())
        self.assertEqual(q.policy_hash(self.p2), q.policy_hash(cbor2.loads(wa.cde(self.p2))))

    def test_validate_ok(self):
        self.assertIsNone(q.validate_policy(self.p1))
        self.assertIsNone(q.validate_policy(self.p2))

    def test_validate_bad(self):
        import copy
        def bad(f):
            p = copy.deepcopy(self.p2)
            f(p)
            return q.validate_policy(p)
        self.assertEqual(bad(lambda p: p["members"].reverse()), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p["members"].append(p["members"][0])), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p["members"][0].update(roles=["observer"])), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p["members"][0].update(roles=["owner", "owner"])), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p["members"][0].update(roles=[])), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p["members"][0].update(kid=b"\x00" * 32)), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p.update(prev=None)), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p.update(ver=True)), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p["rules"].pop("ceiling")), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p["rules"]["policy"].update(k=True)), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p["rules"]["policy"].update(role="root")), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p["rules"]["mandate"][1].pop("amount")), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p["rules"]["mandate"][0].update(amount=5)), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p["members"][0].update(label="x" * 33)), "POLICY_MALFORMED")
        self.assertEqual(bad(lambda p: p.update(extra=1)), "POLICY_MALFORMED")
        self.assertEqual(q.validate_policy("x"), "POLICY_MALFORMED")

    def test_requirements_mandate(self):
        big = {"permissions": {"purchase": {"budget": 200000, "max_per_action": 1}}}
        self.assertEqual(q.requirements(self.p2, wa.TYP_MANDATE, big), [("budget", 2)])
        edge = {"permissions": {"purchase": {"budget": 50000}}}
        self.assertEqual(q.requirements(self.p2, wa.TYP_MANDATE, edge), [("budget", 1)])      # == X is not over X
        self.assertEqual(q.requirements(self.p2, wa.TYP_MANDATE, {"permissions": {"purchase": True}}), [("budget", 2)])  # no limit = unbounded
        self.assertEqual(q.requirements(self.p2, wa.TYP_MANDATE, {"permissions": {"purchase": False}}), [])
        self.assertEqual(q.requirements(self.p2, wa.TYP_MANDATE, {"permissions": {"sale": {"min_price": 70000}}}), [("budget", 2)])
        mixed = {"permissions": {"purchase": {"budget": 10}, "message": {"domains": ["a"]}}}
        self.assertEqual(q.requirements(self.p2, wa.TYP_MANDATE, mixed), [("access", 1), ("budget", 1)])
        self.assertEqual(q.requirements(self.p2, wa.TYP_MANDATE, {"permissions": {"publish": None, "message": False}}), [])

    def test_requirements_other(self):
        self.assertEqual(q.requirements(self.p2, wa.TYP_REVOCATION, {}), [("any", 1)])
        self.assertEqual(q.requirements(self.p2, wa.TYP_CEILING, {}), [("owner", 1)])
        self.assertEqual(q.requirements(self.p2, q.TYP_POLICY, {}), [("owner", 1)])
        self.assertEqual(q.requirements(self.p2, wa.TYP_APPROVAL, None), [])        # payload has only a hash: stateless part
        money = {"class": "purchase", "amount": 60000}
        self.assertEqual(q.requirements(self.p2, wa.TYP_APPROVAL, None, money), [("budget", 2)])
        self.assertEqual(q.requirements(self.p2, wa.TYP_APPROVAL, None, {"class": "purchase", "amount": 40000}), [("budget", 1)])
        self.assertEqual(q.requirements(self.p2, wa.TYP_APPROVAL, None, {"class": "publish"}), [("access", 1)])

    def test_policy_at(self):
        ch = [(b"a", None, 100), (b"b", None, 200), (b"c", None, 300)]
        self.assertIsNone(q.policy_at(ch, 99))
        self.assertEqual(q.policy_at(ch, 100), 1)
        self.assertEqual(q.policy_at(ch, 199), 1)
        self.assertEqual(q.policy_at(ch, 200), 2)
        self.assertEqual(q.policy_at(ch, 10 ** 9), 3)

    def test_stale_boundaries(self):
        v = next(x for x in WQ if x["id"].startswith("w15"))
        ch = chain_of(v)
        args = (bytes.fromhex(v["envelope_hex"]), v["typ"], bytes.fromhex(v["payload_hex"]), ch)
        t2, t3 = ch[1][2], ch[2][2]
        self.assertIsNone(q.verify_wq(*args, rp=v["rp"], at=t2))
        self.assertIsNone(q.verify_wq(*args, rp=v["rp"], at=t3 - 1))
        self.assertEqual(q.verify_wq(*args, rp=v["rp"], at=t3), "WQ_POLICY_STALE")
        self.assertEqual(q.verify_wq(*args, rp=v["rp"], at=t2 - 1), "WQ_POLICY_STALE")
        self.assertIsNone(q.verify_wq(*args, rp=v["rp"]))        # first pass (no time): the policy is merely known

    def test_release_payload(self):
        h = hashlib.sha256(b"x")
        p = q.release_payload("r_1", h.hexdigest(), True)
        self.assertEqual(p, q.release_payload("r_1", h.digest(), True))
        self.assertEqual(cbor2.loads(p), {"rid": "r_1", "args_sha256": h.digest(), "release": True})
        self.assertNotEqual(p, q.release_payload("r_1", h.digest(), False))
        self.assertRaises(ValueError, q.release_payload, "r_1", b"short", True)
        self.assertRaises(ValueError, q.release_payload, "r_1", h.digest(), 1)

    def test_release_signature_roundtrip(self):
        a = wa.SoftAuthenticator()
        reg = a.reg_entry("localhost", [ORIGIN])
        p = q.release_payload("r_1", hashlib.sha256(b"x").digest(), True)
        env = a.sign_object(q.TYP_RELEASE, p, "localhost", ORIGIN)
        self.assertIsNone(wa.verify_envelope(env, q.TYP_RELEASE, p, reg))
        self.assertEqual(wa.verify_envelope(env, q.TYP_RELEASE, q.release_payload("r_1", hashlib.sha256(b"x").digest(), False), reg), "MANDATE_SIG")

    def test_make_wq_sorts_and_roundtrips(self):
        v = WQ[0]
        m = cbor2.loads(bytes.fromhex(v["envelope_hex"]))
        self.assertEqual(sorted(s["kid"] for s in m["sigs"]), [s["kid"] for s in m["sigs"]])
        again = q.make_wq(m["typ"], m["payload"], m["policy"], list(reversed(m["sigs"])))
        self.assertEqual(again.hex(), v["envelope_hex"])

    def test_wb_challenge_domain_separated(self):
        items = [hashlib.sha256(b"a").digest()]
        self.assertNotEqual(q.wb_challenge(items), wa.challenge(wa.TYP_APPROVAL, wa.cde(items)))
        self.assertEqual(len(q.wb_challenge(items)), 32)

    def test_wb_with_member_map(self):
        v = WB[0]
        pol = cbor2.loads(bytes.fromhex(WQ[0]["chain"][1]["policy_hex"]))
        b1 = next(m for m in pol["members"] if m["label"] == "b1")
        self.assertIsNone(q.verify_wb(bytes.fromhex(v["envelope_hex"]), v["typ"], bytes.fromhex(v["payload_hex"]), b1, rp=v["rp"]))
        self.assertEqual(q.wb_requirements_met(pol, b1["kid"], {"class": "publish"}), "WQ_QUORUM")     # access tier, b1 is budget only
        a1 = next(m for m in pol["members"] if m["label"] == "a1")
        self.assertIsNone(q.wb_requirements_met(pol, a1["kid"], {"class": "publish"}))
        self.assertEqual(q.wb_requirements_met(pol, b1["kid"], {"class": "purchase", "amount": 60000}), "WQ_QUORUM")
        self.assertIsNone(q.wb_requirements_met(pol, b1["kid"], {"class": "purchase", "amount": 100}))
        self.assertEqual(q.wb_requirements_met(pol, b"\x01" * 32, {"class": "purchase", "amount": 1}), "WQ_NOT_MEMBER")

    def test_wsig_matches_wa_verifier(self):
        """a wsig is exactly the wa-sig of the signer: the reference checks it through wa_profile.verify_envelope"""
        v = WQ[0]
        m = cbor2.loads(bytes.fromhex(v["envelope_hex"]))
        pol = cbor2.loads(bytes.fromhex(v["chain"][1]["policy_hex"]))
        mem = {x["kid"]: x for x in pol["members"]}
        for w in m["sigs"]:
            one = wa.cde(dict(v="deus-aar-wa-0.1", typ=m["typ"], kid=w["kid"], payload=m["payload"], authData=w["authData"], clientDataJSON=w["clientDataJSON"], sig=w["sig"]))
            reg = {"alg": "ES256", "pub": mem[w["kid"]]["pub"].hex(), "webauthn": {"rp_id": v["rp"]["rp_id"], "origins": v["rp"]["origins"]}}
            self.assertIsNone(wa.verify_envelope(one, m["typ"], m["payload"], reg))
            self.assertEqual(q.wsig_of_wa(one), w)

    def test_verify_wq_requires_rp(self):
        v = WQ[0]
        self.assertRaises(ValueError, q.verify_wq, bytes.fromhex(v["envelope_hex"]), v["typ"], bytes.fromhex(v["payload_hex"]), chain_of(v))


class TestOpenapi02(unittest.TestCase):
    NEW = ["/api/orgs", "/api/orgs/switch", "/api/org/invites", "/api/org/join", "/api/org", "/api/org/policy/draft", "/api/sig-requests",
           "/api/sig-requests/{id}", "/api/org/settings", "/api/suggestions", "/api/digest", "/api/approvals/batch", "/api/approvals/{rid}/release",
           "/v1/catalog", "/v1/coverage", "/api/catalog/{agent}", "/api/catalog/{agent}/draft"]

    def spec(self):
        import yaml
        with open(os.path.join(HERE, "openapi-0.2.yaml")) as h:
            return yaml.safe_load(h)

    def test_valid(self):
        spec = self.spec()
        try:
            from openapi_spec_validator import validate
            validate(spec)
            return
        except ImportError:
            pass
        py = os.path.normpath(os.path.join(HERE, "../.venv/bin/python"))
        if os.path.exists(py):
            r = subprocess.run([py, "-c", "import sys,yaml;from openapi_spec_validator import validate;validate(yaml.safe_load(open(sys.argv[1])))",
                                os.path.join(HERE, "openapi-0.2.yaml")], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr[-500:])
            return
        self.structural(spec)

    def structural(self, spec):
        import jsonschema
        for n, s in spec["components"]["schemas"].items():
            jsonschema.Draft202012Validator.check_schema(s)

    def test_structure_and_refs(self):
        spec = self.spec()
        self.structural(spec)
        names = set(spec["components"]["schemas"])
        txt = json.dumps(spec)
        import re
        for ref in re.findall(r'#/components/schemas/([A-Za-z]+)', txt):
            self.assertIn(ref, names)

    def test_paths_are_exactly_the_new_ones(self):
        spec = self.spec()
        self.assertEqual(set(spec["paths"]), set(self.NEW) | {"/api/mandates/draft", "/api/mandates/{mid}/revoke"})   # revoke: 0.2.0 merge (01 + 05)
        with open(os.path.join(HERE, "../openapi.yaml")) as h:
            old = set(__import__("yaml").safe_load(h)["paths"])
        self.assertEqual(set(spec["paths"]) & old, {"/api/mandates/draft"})       # the only 0.1 path with a 0.2 reply

    def test_every_operation_has_responses_and_security(self):
        for p, item in self.spec()["paths"].items():
            for m, o in item.items():
                self.assertIn("responses", o, p)
                self.assertIn("security", o, p)


def _client(app, origin):
    from fastapi.testclient import TestClient
    return TestClient(app, base_url=origin, headers={"Origin": origin})


class TestStub02(unittest.TestCase):
    def setUp(self):
        import stub02
        self.origin = "http://localhost:8801"
        self.app = stub02.create_app02(RPID, self.origin, web_dir="/nonexistent")
        self.S = self.app.state.S

    def person(self, name):
        c = _client(self.app, self.origin)
        a = wa.SoftAuthenticator()
        r = c.post("/api/auth/register/begin", json={"display_name": name}).json()
        fin = c.post("/api/auth/register/finish", json={"flow_id": r["flow_id"], "credential": a.create_credential(wa.b64u_dec(r["options"]["challenge"]), RPID, self.origin)})
        self.assertEqual(fin.status_code, 200, fin.text)
        return c, a, fin.json()["account"]["id"]

    def sign(self, a, typ, payload_b64):
        return wa.b64u(a.sign_object(typ, wa.b64u_dec(payload_b64), RPID, self.origin))

    def team(self):
        """owner + 3 budget members + genesis + policy v2 'budget k=2 over 50000' """
        O, ao, oid = self.person("owner")
        bs = [self.person("b%d" % i) for i in (1, 2, 3)]
        for c, a, uid in bs:
            tok = O.post("/api/org/invites", json={"roles": ["budget"]}).json()["url"].split("token=")[1]
            self.assertEqual(c.post("/api/org/join", json={"token": tok}).json()["status"], "pending")
            c.post("/api/orgs/switch", json={"account_id": oid})
        genesis = O.post("/api/org/policy/draft", json={"members": [{"user_id": oid, "roles": ["owner", "budget", "access"]}], "rules": {
            "policy": {"role": "owner", "k": 1}, "mandate": [], "approval": [], "revocation": {"role": "any", "k": 1}, "ceiling": {"role": "owner", "k": 1}}}).json()
        r = O.post("/api/sig-requests/" + genesis["req_id"], json={"envelope_b64": self.sign(ao, genesis["typ"], genesis["payload_b64"])})
        self.assertEqual((r.status_code, r.json()["status"]), (200, "done"), r.text)
        tiers = [{"if": "money", "role": "budget", "k": 1}, {"if": "money_over", "amount": 50000, "role": "budget", "k": 2}]
        v2 = O.post("/api/org/policy/draft", json={"members": [{"user_id": oid, "roles": ["owner"]}] + [{"user_id": uid, "roles": ["budget"]} for _, _, uid in bs],
                                                   "rules": {"policy": {"role": "owner", "k": 1}, "mandate": tiers, "approval": tiers,
                                                             "revocation": {"role": "any", "k": 1}, "ceiling": {"role": "owner", "k": 1}}}).json()
        r = O.post("/api/sig-requests/" + v2["req_id"], json={"envelope_b64": self.sign(ao, v2["typ"], v2["payload_b64"])})
        self.assertEqual((r.status_code, r.json()["status"]), (200, "done"), r.text)
        return O, ao, oid, bs

    def agent_and_draft(self, O, oid, budget):
        ag = O.post("/api/agents", json={"name": "bot", "preset": "demo"}).json()
        form = {"currency": "USD", "valid_days": 30, "purchase": {"enabled": True, "budget": budget, "max_per_action": budget}, "delete": None, "publish": None}
        d = O.post("/api/mandates/draft", json={"agent_id": ag["agent"]["id"], "form": form}).json()
        return ag, d

    def test_two_signers_active_one_collecting(self):
        O, ao, oid, bs = self.team()
        self.assertEqual(O.get("/api/org").json()["policy_ver"], 2)
        ag, d = self.agent_and_draft(O, oid, 200000)
        self.assertEqual(d["needs"], [{"role": "budget", "k": 2}])
        (c1, a1, _), (c2, a2, _), (c3, a3, _) = bs
        listed = c1.get("/api/sig-requests").json()
        self.assertEqual([x["id"] for x in listed], [d["req_id"]])
        full = c1.get("/api/sig-requests/" + d["req_id"]).json()
        self.assertEqual(wa.b64u_dec(full["payload_b64"]), wa.cde(d["mandate"]))
        r1 = c1.post("/api/sig-requests/" + d["req_id"], json={"envelope_b64": self.sign(a1, wa.TYP_MANDATE, full["payload_b64"])}).json()
        self.assertEqual((r1["status"], r1["have"], r1["need"]), ("collecting", 1, 2))
        self.assertEqual([m for m in O.get("/api/mandates").json() if m["status"] == "active"], [])
        dup = c1.post("/api/sig-requests/" + d["req_id"], json={"envelope_b64": self.sign(a1, wa.TYP_MANDATE, full["payload_b64"])})
        self.assertEqual((dup.status_code, dup.json()["error"]), (409, "WQ_DUP_SIGNER"))
        self.assertEqual(c1.get("/api/sig-requests").json(), [])              # already signed: not offered again
        r2 = c3.post("/api/sig-requests/" + d["req_id"], json={"envelope_b64": self.sign(a3, wa.TYP_MANDATE, full["payload_b64"])}).json()
        self.assertEqual((r2["status"], r2["mandate_status"]), ("done", "active"))
        act = [m for m in O.get("/api/mandates").json() if m["status"] == "active"]
        self.assertEqual([m["id"] for m in act], [d["mandate"]["id"]])
        # the stored envelope is a real wq that the reference accepts
        env = self.S["mandates"][d["mandate"]["id"]]["envelope"]
        self.assertEqual(q.envelope_kind(env), "wq")
        ch = [(e["policy"], e["envelope"], e["t"]) for e in self.app.state.X["chains"][oid]]
        self.assertIsNone(q.verify_policy_chain(ch, rp={"rp_id": RPID, "origins": [self.origin]}))
        self.assertIsNone(q.verify_wq(env, wa.TYP_MANDATE, wa.cde(d["mandate"]), ch, rp={"rp_id": RPID, "origins": [self.origin]}))

    def test_bad_signatures_rejected(self):
        O, ao, oid, bs = self.team()
        ag, d = self.agent_and_draft(O, oid, 200000)
        full = O.get("/api/sig-requests/" + d["req_id"]).json()
        c1, a1, _ = bs[0]
        c2, a2, _ = bs[1]
        # owner is a member but not a budget signer: his signature is valid and counted, the quorum still lacks budget signers
        r = O.post("/api/sig-requests/" + d["req_id"], json={"envelope_b64": self.sign(ao, wa.TYP_MANDATE, full["payload_b64"])})
        self.assertEqual((r.status_code, r.json()["status"]), (200, "collecting"))
        # signature over another payload
        bad = c1.post("/api/sig-requests/" + d["req_id"], json={"envelope_b64": wa.b64u(a1.sign_object(wa.TYP_MANDATE, b"other", RPID, self.origin))})
        self.assertEqual((bad.status_code, bad.json()["error"]), (409, "MANDATE_SIG"))
        # a stranger (not a member)
        X, ax, _ = self.person("stranger")
        self.assertEqual(X.get("/api/org").status_code, 200)             # own org only
        self.assertEqual(X.get("/api/sig-requests/" + d["req_id"]).status_code, 404)
        # two budget signers + owner: done
        for c, a in ((c1, a1), (c2, a2)):
            r = c.post("/api/sig-requests/" + d["req_id"], json={"envelope_b64": self.sign(a, wa.TYP_MANDATE, full["payload_b64"])}).json()
        self.assertEqual(r["status"], "done")

    def test_observer_cannot_change(self):
        O, ao, oid, bs = self.team()
        ob, aob, _ = self.person("observer")
        tok = O.post("/api/org/invites", json={"roles": ["observer"]}).json()["url"].split("token=")[1]
        self.assertEqual(ob.post("/api/org/join", json={"token": tok}).json()["status"], "active")
        ob.post("/api/orgs/switch", json={"account_id": oid})
        self.assertEqual(ob.post("/api/org/invites", json={"roles": ["budget"]}).status_code, 403)
        self.assertEqual(ob.put("/api/org/settings", json={"advisor": "heuristic"}).status_code, 403)
        self.assertEqual(ob.post("/api/org/policy/draft", json={"members": [], "rules": {}}).status_code, 403)
        self.assertEqual(ob.get("/api/org").status_code, 200)
        self.assertEqual(ob.get("/api/sig-requests").json(), [])
        self.assertEqual(O.put("/api/org/settings", json={"advisor": "heuristic", "defer_ttl_s": 900}).json()["advisor"], "heuristic")
        self.assertEqual(O.put("/api/org/settings", json={"defer_ttl_s": 10}).status_code, 422)

    def test_batch_approval_with_wb(self):
        O, ao, oid, bs = self.team()
        ag, d = self.agent_and_draft(O, oid, 20000)
        (c1, a1, _), (c2, a2, _), _ = bs
        r = c1.post("/api/sig-requests/" + d["req_id"], json={"envelope_b64": self.sign(a1, wa.TYP_MANDATE, wa.b64u(wa.cde(d["mandate"])))}).json()
        self.assertEqual(r["status"], "done")         # 20000 <= 50000: money tier k=1
        rids = []
        # create the pending actions through the in-memory state (the agent key is hashed; publish needs no key in this scenario)
        mid = d["mandate"]["id"]
        for i in range(3):
            act = {"agent": ag["agent"]["id"], "class": "publish", "recipient": "blog", "data": [], "args_sha256": hashlib.sha256(b"a%d" % i).hexdigest()}
            rid = "r_%026d" % i
            self.S["actions"][rid] = {"rid": rid, "account_id": oid, "agent_id": ag["agent"]["id"], "mandate_id": mid, "tool": "publish", "args_preview": "", "action": act,
                                      "class": "publish", "recipient": "blog", "amount": None, "currency": None, "verdict": "defer", "reason": "ESCALATE_PUBLISH",
                                      "status": "pending_approval", "created_at": int(time.time()), "updated_at": int(time.time()), "expires": int(time.time()) + 900}
            rids.append(rid)
        mand = self.S["mandates"][mid]["mandate"]
        pays = [approval_payload(mand, self.S["actions"][r]["action"], r, True) for r in rids]
        items = [hashlib.sha256(p).digest() for p in pays]
        ad, cd, der = a2.get_assertion(q.wb_challenge(items), RPID, self.origin)
        env = wa.b64u(q.make_wb(items, a2.kid, ad, cd, der))
        # b2 is a budget member; items are publish (access) with no approval rule for access in this policy -> no requirement
        r = c2.post("/api/approvals/batch", json={"rids": rids, "envelope_b64": env})
        self.assertEqual((r.status_code, r.json().get("n")), (200, 3), r.text)
        self.assertTrue(all(self.S["actions"][x]["status"] == "approved" for x in rids))
        # a second batch with a missing item is refused (items from the first batch re-used for a new action)
        act = {"agent": ag["agent"]["id"], "class": "publish", "recipient": "blog", "data": [], "args_sha256": hashlib.sha256(b"zz").hexdigest()}
        self.S["actions"]["r_new"] = dict(self.S["actions"][rids[0]], rid="r_new", action=act, status="pending_approval")
        r = c2.post("/api/approvals/batch", json={"rids": ["r_new"], "envelope_b64": env})
        self.assertEqual((r.status_code, r.json()["error"]), (409, "WB_ITEM"))
        # homogeneity
        self.S["actions"]["r_odd"] = dict(self.S["actions"][rids[0]], rid="r_odd", recipient="other", status="pending_approval")
        self.S["actions"]["r_odd2"] = dict(self.S["actions"][rids[0]], rid="r_odd2", status="pending_approval")
        r = c2.post("/api/approvals/batch", json={"rids": ["r_odd", "r_odd2"], "envelope_b64": env})
        self.assertEqual((r.status_code, r.json()["error"]), (409, "BATCH_NOT_HOMOGENEOUS"))
        # money over the k=1 threshold cannot be batched
        self.S["actions"]["r_big"] = dict(self.S["actions"][rids[0]], rid="r_big", status="pending_approval", **{"class": "purchase"})
        self.S["actions"]["r_big"]["action"] = {"agent": ag["agent"]["id"], "class": "purchase", "recipient": "blog", "data": [], "amount": 90000, "currency": "USD", "args_sha256": "00" * 32}
        r = c2.post("/api/approvals/batch", json={"rids": ["r_big"], "envelope_b64": env})
        self.assertEqual((r.status_code, r.json()["error"]), (409, "WQ_QUORUM"))

    def test_release_with_real_signature(self):
        O, ao, oid = self.person("o")
        ag = O.post("/api/agents", json={"name": "bot"}).json()
        h = hashlib.sha256(b"txt").hexdigest()
        self.S["actions"]["r_h"] = {"rid": "r_h", "account_id": oid, "agent_id": ag["agent"]["id"], "status": "held", "verdict": "defer", "reason": "ADVISORY_HOLD",
                                    "action": {"agent": ag["agent"]["id"], "class": "message", "recipient": "x@a.example", "data": [], "args_sha256": h}}
        wrong = wa.b64u(ao.sign_object(q.TYP_RELEASE, q.release_payload("r_h", h, False), RPID, self.origin))
        r = O.post("/api/approvals/r_h/release", json={"release": True, "envelope_b64": wrong})
        self.assertEqual((r.status_code, r.json()["error"]), (409, "RELEASE_SIG"))
        good = wa.b64u(ao.sign_object(q.TYP_RELEASE, q.release_payload("r_h", h, True), RPID, self.origin))
        r = O.post("/api/approvals/r_h/release", json={"release": True, "envelope_b64": good})
        self.assertEqual((r.status_code, r.json()["status"]), (200, "allowed"), r.text)
        self.S["actions"]["r_h2"] = dict(self.S["actions"]["r_h"], rid="r_h2", status="held")
        rej = wa.b64u(ao.sign_object(q.TYP_RELEASE, q.release_payload("r_h2", h, False), RPID, self.origin))
        r = O.post("/api/approvals/r_h2/release", json={"release": False, "envelope_b64": rej})
        self.assertEqual(r.json()["reason"], "ADVISORY_REJECTED")

    def test_fixtures_catalog_coverage_digest(self):
        O, ao, oid = self.person("o")
        ag = O.post("/api/agents", json={"name": "bot"}).json()
        A = _client(self.app, self.origin)
        A.headers["Authorization"] = "Bearer " + ag["api_key"]
        tools = [{"name": "send_mail", "description": "", "inputSchema": {"properties": {"to": {"type": "string"}, "body": {"type": "string"}, "priority": {"type": "string"}}}},
                 {"name": "buy", "inputSchema": {"properties": {"price": {"type": "integer"}, "vendor": {"type": "string"}}}}]
        r1 = A.post("/v1/catalog", json={"tools": tools}).json()
        self.assertFalse(r1["changed"])
        self.assertTrue(A.post("/v1/catalog", json={"tools": tools[:1]}).json()["changed"])
        A.post("/v1/catalog", json={"tools": tools})
        self.assertEqual(A.post("/v1/coverage", json={"level": "C1", "unwitnessed": ["bash"], "tool": "doctor-0.2"}).json(), {"ok": True, "level": "C1"})
        self.assertEqual(A.post("/v1/coverage", json={"level": "C9"}).status_code, 422)
        v = O.get("/api/catalog/" + ag["agent"]["id"]).json()
        self.assertEqual(sorted((u["tool"], u["arg"]) for u in v["unknown"]), [("buy", "vendor"), ("send_mail", "priority")])
        self.assertEqual(v["suggested_toolmap"]["tools"]["send_mail"]["class"], "message")
        self.assertEqual(v["coverage"]["level"], "C1")
        self.assertTrue(v["coverage"]["operator_declared"])
        self.assertFalse(O.post("/api/catalog/%s/draft" % ag["agent"]["id"], json={}).json()["applicable"])
        self.assertEqual(O.get("/api/suggestions").json()["suggestions"][0]["kind"], "recipient")
        dg = O.get("/api/digest").json()
        for k in ("W", "H", "F", "pending_by_role", "suggestions", "approval_rate_denials"):
            self.assertIn(k, dg)
        self.assertEqual(O.get("/api/orgs").json()[0]["account_id"], oid)
        self.assertEqual(httpx_status(self.app, self.origin, "/api/digest"), 401)

    def test_old_paths_still_work_and_policy_less_org_is_solo(self):
        O, ao, oid = self.person("solo")
        ag = O.post("/api/agents", json={"name": "bot"}).json()
        d = O.post("/api/mandates/draft", json={"agent_id": ag["agent"]["id"], "form": {"currency": "USD", "valid_days": 30,
                                                                                         "purchase": {"enabled": True, "budget": 10, "max_per_action": 10}}}).json()
        self.assertNotIn("req_id", d)
        env = ao.sign_object(wa.TYP_MANDATE, wa.cde(d["mandate"]), RPID, self.origin)
        self.assertEqual(O.post("/api/mandates", json={"mandate": d["mandate"], "envelope_b64": wa.b64u(env)}).status_code, 200)


def httpx_status(app, origin, path):
    from fastapi.testclient import TestClient
    return TestClient(app, base_url=origin).get(path).status_code


class TestStubProcess(unittest.TestCase):
    def test_runs_on_port(self):
        import httpx
        p = subprocess.Popen([sys.executable, os.path.join(HERE, "stub02.py"), "--port", str(PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            ok = False
            for _ in range(60):
                try:
                    if httpx.get(ORIGIN + "/healthz").status_code == 200:
                        ok = True
                        break
                except Exception:
                    time.sleep(0.25)
            self.assertTrue(ok)
            self.assertEqual(httpx.get(ORIGIN + "/api/digest").status_code, 401)            # new route is reachable, not shadowed
            self.assertEqual(httpx.post(ORIGIN + "/api/approvals/batch", json={}).status_code, 401)   # and not swallowed by /api/approvals/{rid}
        finally:
            p.terminate()          # own process, by PID
            p.wait(10)


if __name__ == "__main__":
    unittest.main()
