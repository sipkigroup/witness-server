"""TEST-ONLY RFC 3161 time-stamp authority: own root CA, TSA certificate with the critical timeStamping EKU, TimeStampResp
signed with RSA (PKCS#1 v1.5) or ECDSA P-256. Used by tests and by a local HTTP TSA (default port 8812). Never a real anchor.

    ca = TestTSA("test-tsa-a", kind="rsa"); tsr = ca.respond(make_query(digest)[0]); ca.root_pem
    serve(8812, {"a": ca_a, "b": ca_b}) -> (http server, thread)   POST /<name> with application/timestamp-query"""
import datetime
import hashlib
import http.server
import threading

from asn1crypto import algos, cms, core, tsp, x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DAY = datetime.timedelta(days=1)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Deus Witness TEST")])


class TestTSA:
    def __init__(self, name, kind="ec", now=None, tsa_eku=True, tsa_valid_days=3650):
        now = now or datetime.datetime.now(datetime.timezone.utc)
        self.name, self.kind = name, kind
        gen = (lambda: rsa.generate_private_key(65537, 2048)) if kind == "rsa" else (lambda: ec.generate_private_key(ec.SECP256R1()))
        self.root_key, self.key = gen(), gen()
        self.root = (x509.CertificateBuilder().subject_name(_name(name + " root")).issuer_name(_name(name + " root"))
                     .public_key(self.root_key.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(now - DAY).not_valid_after(now + 3650 * DAY)
                     .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                     .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
                     .sign(self.root_key, hashes.SHA256()))
        b = (x509.CertificateBuilder().subject_name(_name(name)).issuer_name(self.root.subject)
             .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - DAY).not_valid_after(now + tsa_valid_days * DAY)
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
        if tsa_eku:
            b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        self.cert = b.sign(self.root_key, hashes.SHA256())
        self.serial = 1

    @property
    def root_pem(self):
        return self.root.public_bytes(serialization.Encoding.PEM)

    def respond(self, query_der, gen_time=None, imprint=None):
        """TimeStampResp DER for a TimeStampReq. imprint: override the hashed message (negative tests)."""
        q = tsp.TimeStampReq.load(query_der)
        gt = gen_time or datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        self.serial += 1
        mi = q["message_imprint"].native
        if imprint is not None:
            mi = dict(mi, hashed_message=imprint)
        tst = tsp.TSTInfo({"version": "v1", "policy": "1.3.6.1.4.1.99999.1.1", "message_imprint": mi,
                           "serial_number": self.serial, "gen_time": gt, "nonce": q["nonce"].native,
                           "tsa": ax509.GeneralName({"directory_name": ax509.Name.load(self.cert.subject.public_bytes())})})
        econtent = tst.dump()
        acert = ax509.Certificate.load(self.cert.public_bytes(serialization.Encoding.DER))
        aroot = ax509.Certificate.load(self.root.public_bytes(serialization.Encoding.DER))
        ess = tsp.SigningCertificateV2({"certs": [{"cert_hash": hashlib.sha256(acert.dump()).digest()}]})
        attrs = cms.CMSAttributes([
            cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
            cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha256(econtent).digest()]}),
            cms.CMSAttribute({"type": "signing_certificate_v2", "values": [ess]})])
        data = attrs.dump()
        if self.kind == "rsa":
            sig = self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
            salg = "sha256_rsa"
        else:
            sig = self.key.sign(data, ec.ECDSA(hashes.SHA256()))
            salg = "sha256_ecdsa"
        si = cms.SignerInfo({"version": "v1",
                             "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber(
                                 {"issuer": acert.issuer, "serial_number": acert.serial_number})}),
                             "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
                             "signed_attrs": attrs,
                             "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": salg}),
                             "signature": sig})
        certs = [acert, aroot] if q["cert_req"].native else []
        sd = cms.SignedData({"version": "v3", "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
                             "encap_content_info": {"content_type": "tst_info", "content": core.ParsableOctetString(econtent)},
                             "certificates": certs, "signer_infos": [si]})
        resp = tsp.TimeStampResp({"status": {"status": "granted"},
                                  "time_stamp_token": cms.ContentInfo({"content_type": "signed_data", "content": sd})})
        return resp.dump()


def serve(port, tsas, host="127.0.0.1"):
    """Local HTTP TSA: POST /<name> -> TimeStampResp of tsas[name]. -> (server, thread); stop with server.shutdown()."""
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            t = tsas.get(self.path.strip("/"))
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if t is None:
                self.send_response(404)
                self.end_headers()
                return
            out = t.respond(body)
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer((host, port), H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, th
