import glob, json, os, subprocess, sys, time, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "../..")))
import cbor2
import httpx
import wa_profile as wa
from svidetel_v4.state import approval_payload

PORT = 8899
ORIGIN = "http://localhost:%d" % PORT


def load(pat):
    out = []
    for f in sorted(glob.glob(os.path.join(HERE, pat))):
        with open(f) as h:
            out.append(json.load(h))
    return out


def to_py(x):
    if isinstance(x, dict):
        return bytes.fromhex(x["$bytes"]) if set(x) == {"$bytes"} else {k: to_py(v) for k, v in x.items()}
    if isinstance(x, list):
        return [to_py(v) for v in x]
    return x


class TestVectors(unittest.TestCase):
    def test_wa_vectors(self):
        vs = load("vectors/wa/*.json")
        self.assertGreaterEqual(len(vs), 12)
        self.assertGreaterEqual(sum(v["class"] == "valid" for v in vs), 4)
        for v in vs:
            with self.subTest(v["id"]):
                got = wa.verify_envelope(bytes.fromhex(v["envelope_hex"]), v["typ"], bytes.fromhex(v["payload_hex"]), v["reg_entry"])
                self.assertEqual(got, v["expect"])
                self.assertEqual(v["class"] == "valid", v["expect"] is None)

    def test_recipient_vectors(self):
        from svidetel_v4.decide import decide
        vs = load("vectors/recipient/*.json")
        self.assertGreaterEqual(len(vs), 8)
        for v in vs:
            with self.subTest(v["id"]):
                M = {"id": "m", "principal": "p", "agent": "a", "nbf": 0, "exp": 10 ** 9, "key_attestation": "software", "v": "deus-aar-0.1",
                     "permissions": {"message": {"domains": v["mandate_domains"]}}, "forbidden_data": [], "budget_window_s": 86400,
                     "named_circle": False, "currency": "USD", "_sig_valid": True}
                a = {"class": "message", "agent": "a", "t": 100, "amount": 0, "recipient": v["recipient"], "data": []}
                verdict, why = decide(M, a, {}, 100)
                self.assertEqual(verdict + ("" if verdict == "allow" else " " + why), v["expect"])

    def test_wa_is_envelope(self):
        v = load("vectors/wa/v01-mandate.json")[0]
        self.assertTrue(wa.is_envelope(bytes.fromhex(v["envelope_hex"])))
        self.assertFalse(wa.is_envelope(b"\xd2\x84"))

    def test_cde_vectors(self):
        vs = load("vectors/cde/*.json")
        self.assertGreaterEqual(len(vs), 15)
        for v in vs:
            with self.subTest(v["id"]):
                self.assertEqual(cbor2.dumps(to_py(v["json"]), canonical=True).hex(), v["cde_hex"])

    def test_high_s_roundtrip(self):
        a = wa.SoftAuthenticator()
        reg = a.reg_entry("localhost", [ORIGIN])
        p = b"payload"
        self.assertIsNone(wa.verify_envelope(a.sign_object(wa.TYP_MANDATE, p, "localhost", ORIGIN, high_s=True), wa.TYP_MANDATE, p, reg))


class TestOpenapi(unittest.TestCase):
    def test_valid(self):
        import yaml
        from openapi_spec_validator import validate
        spec = yaml.safe_load(open(os.path.join(HERE, "openapi.yaml")))
        validate(spec)
        paths = set(spec["paths"])
        for p in ["/api/auth/register/begin", "/api/auth/register/finish", "/api/auth/login/begin", "/api/auth/login/finish", "/api/auth/logout",
                  "/api/me", "/api/agents", "/api/agents/{id}/toolmap", "/api/agents/{id}", "/api/data-patterns", "/api/mandates/draft", "/api/mandates",
                  "/api/feed", "/api/budget", "/api/approvals", "/api/approvals/{rid}", "/api/export", "/api/witness", "/v1/witness", "/healthz",
                  "/v1/actions", "/v1/actions/{rid}", "/v1/actions/{rid}/present", "/v1/actions/{rid}/report"]:
            self.assertIn(p, paths)

    def test_fixtures_parse(self):
        self.assertGreaterEqual(len(glob.glob(os.path.join(HERE, "fixtures/*.json"))), 12)
        for f in load("fixtures/*.json"):
            self.assertIsNotNone(f)


class TestStub(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = subprocess.Popen([sys.executable, os.path.join(HERE, "stub.py"), "--port", str(PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                if httpx.get(ORIGIN + "/healthz").status_code == 200:
                    return
            except Exception:
                time.sleep(0.25)
        raise RuntimeError("stub did not start")

    @classmethod
    def tearDownClass(cls):
        cls.p.terminate()   # own process only, by PID
        cls.p.wait(10)

    def test_scenario(self):
        H = {"Origin": ORIGIN}
        c = httpx.Client(base_url=ORIGIN, headers=H)
        auth = wa.SoftAuthenticator()
        # register
        r = c.post("/api/auth/register/begin", json={"display_name": "Tester"}).json()
        ch = wa.b64u_dec(r["options"]["challenge"])
        self.assertEqual(r["options"]["pubKeyCredParams"], [{"type": "public-key", "alg": -7}])
        fin = c.post("/api/auth/register/finish", json={"flow_id": r["flow_id"], "credential": auth.create_credential(ch, "localhost", ORIGIN)})
        self.assertEqual(fin.status_code, 200, fin.text)
        self.assertEqual(fin.json()["keycard"]["kid_hex"], auth.kid.hex())
        me = c.get("/api/me").json()
        reg = {"alg": "ES256", "pub": auth.pub.hex(), "webauthn": {"rp_id": "localhost", "origins": [ORIGIN]}}
        # login in a second client
        c2 = httpx.Client(base_url=ORIGIN, headers=H)
        l = c2.post("/api/auth/login/begin", json={}).json()
        lf = c2.post("/api/auth/login/finish", json={"flow_id": l["flow_id"], "credential": auth.login_credential(wa.b64u_dec(l["options"]["challenge"]), "localhost", ORIGIN)})
        self.assertEqual(lf.status_code, 200, lf.text)
        # agent
        ag = c.post("/api/agents", json={"name": "bot", "preset": "demo"}).json()
        key, aid = ag["api_key"], ag["agent"]["id"]
        self.assertRegex(key, r"^dwk_[A-Z2-7]{52}$")
        A = httpx.Client(base_url=ORIGIN, headers={"Authorization": "Bearer " + key})
        self.assertEqual(A.post("/v1/actions", json={"tool": "send_email", "args": {"to": "x@evil.example"}}).json()["reason"], "NO_MANDATE")
        # mandate
        form = {"currency": "USD", "valid_days": 30, "purchase": {"enabled": True, "budget": 20000, "max_per_action": 10000},
                "message": {"domains": ["acme.example"], "to": []}, "forbidden_data": ["home_address", "phone"], "delete": None, "publish": None}
        m = c.post("/api/mandates/draft", json={"agent_id": aid, "form": form}).json()["mandate"]
        self.assertEqual(m["principal"], me["account"]["principal"])
        env = auth.sign_object(wa.TYP_MANDATE, wa.cde(m), "localhost", ORIGIN)
        bad = c.post("/api/mandates", json={"mandate": dict(m, exp=m["exp"] + 1), "envelope_b64": wa.b64u(env)})
        self.assertEqual((bad.status_code, bad.json()["error"]), (409, "MANDATE_SIG"))
        ok = c.post("/api/mandates", json={"mandate": m, "envelope_b64": wa.b64u(env)})
        self.assertEqual(ok.status_code, 200, ok.text)
        # actions
        d = A.post("/v1/actions", json={"tool": "send_email", "args": {"to": "x@evil.example", "subject": "s", "body": "b"}}).json()
        self.assertEqual((d["verdict"], d["reason"]), ("deny", "RECIPIENT"))
        al = A.post("/v1/actions", json={"tool": "send_email", "args": {"to": "bob@acme.example", "subject": "s", "body": "b"}}).json()
        self.assertEqual(al["verdict"], "allow")
        self.assertEqual(A.post("/v1/actions", json={"tool": "mystery", "args": {}}).json()["reason"], "TOOL_UNMAPPED")
        self.assertEqual(A.post("/v1/actions", json={"tool": "read_file", "args": {"path": "/a"}}).json()["verdict"], "pass")
        self.assertEqual(A.post("/v1/actions", json={"tool": "purchase", "args": {"vendor": "v", "amount_cents": 99999999}}).json()["verdict"], "deny")
        pub = A.post("/v1/actions", json={"tool": "publish", "args": {"channel": "blog", "text": "hi"}}).json()
        self.assertEqual((pub["verdict"], pub["status"]), ("defer", "pending_approval"))
        self.assertIn("approve.html?rid=" + pub["rid"], pub["approval_url"])
        self.assertEqual(A.post("/v1/actions", json={"tool": "publish", "args": {"channel": "blog", "text": "hi"}}).json()["rid"], pub["rid"])
        # approval
        pend = c.get("/api/approvals?status=pending").json()
        self.assertEqual([x["rid"] for x in pend], [pub["rid"]])
        det = c.get("/api/approvals/" + pub["rid"]).json()
        pay = approval_payload(det["mandate"], det["action"], pub["rid"], True)
        e2 = auth.sign_object(wa.TYP_APPROVAL, pay, "localhost", ORIGIN)
        forged = c.post("/api/approvals/" + pub["rid"], json={"approved": False, "envelope_b64": wa.b64u(e2)})
        self.assertEqual((forged.status_code, forged.json()["error"]), (409, "APPROVAL_SIG"))
        self.assertEqual(c.post("/api/approvals/" + pub["rid"], json={"approved": True, "envelope_b64": wa.b64u(e2)}).json(), {"verdict": "allow"})
        again = A.post("/v1/actions", json={"tool": "publish", "args": {"channel": "blog", "text": "hi"}}).json()
        self.assertEqual((again["verdict"], again["rid"]), ("allow", pub["rid"]))
        self.assertEqual(A.post("/v1/actions/%s/present" % pub["rid"], json={}).json()["result"], "accept")
        self.assertEqual(A.post("/v1/actions/%s/present" % pub["rid"], json={}).json()["result"], "reject")
        self.assertEqual(A.post("/v1/actions/%s/report" % pub["rid"], json={"executed": True}).status_code, 200)
        feed = c.get("/api/feed").json()
        self.assertGreaterEqual(len(feed["items"]), 6)
        self.assertEqual(c.get("/api/budget").json()[0]["budget"], 20000)
        # isolation: another account sees nothing
        self.assertEqual(httpx.get(ORIGIN + "/api/me").status_code, 401)


if __name__ == "__main__":
    unittest.main()
