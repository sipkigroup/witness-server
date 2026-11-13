"""Hand-built TDX quotes (DCAP v4/v5 layout) signed by test keys with a self-made 'Intel' chain, and a fake quote provider.
Nothing here is real Intel material: a check against the real Intel root must fail on these quotes."""
import datetime
import hashlib
import json
import os
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from app import tdx_quote as TQ


def _raw_sig(key, msg):
    r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _raw_pub(key):
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]


def _cert(subject, issuer_name, pub, issuer_key, ca, ext=None):
    now = datetime.datetime(2026, 1, 1)
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ext is not None:
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(TQ.SGX_EXT_OID), ext), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def _der(tag, body):
    n = len(body)
    ln = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + body


def _oid(s):
    a = [int(x) for x in s.split(".")]
    out = bytes([40 * a[0] + a[1]])
    for n in a[2:]:
        enc = [n & 0x7F]
        while n > 0x7F:
            n >>= 7
            enc.append(0x80 | (n & 0x7F))
        out += bytes(reversed(enc))
    return _der(0x06, out)


def _int(n):
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return _der(0x02, b)


def sgx_extension(fmspc, cpu_svn, pce_svn, pce_id=b"\x00\x00"):
    o = TQ.SGX_EXT_OID
    ent = lambda oid, v: _der(0x30, _oid(oid) + v)
    tcb = b"".join(ent("%s.2.%d" % (o, i + 1), _int(c)) for i, c in enumerate(cpu_svn))
    tcb += ent(o + ".2.17", _int(pce_svn)) + ent(o + ".2.18", _der(0x04, bytes(cpu_svn)))
    return _der(0x30, ent(o + ".1", _der(0x04, bytes(16))) + ent(o + ".2", _der(0x30, tcb)) + ent(o + ".3", _der(0x04, pce_id))
                + ent(o + ".4", _der(0x04, fmspc)) + ent(o + ".5", _der(0x0A, b"\x00")))


class FakeIntel:
    """A root CA, an intermediate, a PCK leaf, and an attestation key: everything a quote needs."""

    def __init__(self):
        self.root_k, self.int_k, self.pck_k, self.att_k = (ec.generate_private_key(ec.SECP256R1()) for _ in range(4))
        self.root = _cert("Fake SGX Root CA", "Fake SGX Root CA", self.root_k.public_key(), self.root_k, True)
        self.inter = _cert("Fake SGX PCK Platform CA", "Fake SGX Root CA", self.int_k.public_key(), self.root_k, True)
        self.leaf = _cert("Fake SGX PCK Certificate", "Fake SGX PCK Platform CA", self.pck_k.public_key(), self.int_k, False)

    def root_pem(self):
        return self.root.public_bytes(serialization.Encoding.PEM)

    def chain_pem(self):
        return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (self.leaf, self.inter, self.root)) + b"\x00"

    def body(self, rd, **over):
        f = {n: bytes(k) for n, k in TQ.TD10_FIELDS}
        f["mr_td"] = hashlib.sha384(b"mrtd").digest()
        for i in range(4):
            f["rtmr%d" % i] = hashlib.sha384(b"rtmr%d" % i).digest()
        f["report_data"] = bytes(rd)
        f.update(over)
        return f

    def quote(self, rd, version=4, vendor=TQ.INTEL_QE_VENDOR_ID, td15=False, auth=b"auth-data-0123", qe_rd=None, qe_base=None, **over):
        f = self.body(rd, **over)
        fields = TQ.TD10_FIELDS + (TQ.TD15_EXTRA if td15 else ())
        if td15:
            f.setdefault("tee_tcb_svn2", bytes(16))
            f.setdefault("mr_servicetd", bytes(48))
        body = b"".join(f[n] for n, _ in fields)
        assert len(body) == (TQ.TD15_BODY_LEN if td15 else TQ.TD10_BODY_LEN)
        header = struct.pack("<HHIHH", version, 2, TQ.TEE_TYPE_TDX, 0, 0) + vendor + bytes(20)
        if version == 5:
            body = struct.pack("<HI", 3 if td15 else 2, len(body)) + body
        signed = header + body
        att_pub = _raw_pub(self.att_k)
        qe_report = bytearray(qe_base if qe_base is not None else os.urandom(TQ.QE_REPORT_LEN))
        qe_report[320:384] = qe_rd if qe_rd is not None else hashlib.sha256(att_pub + auth).digest() + bytes(32)
        qe_report = bytes(qe_report)
        pem = self.chain_pem()
        cd = (qe_report + _raw_sig(self.pck_k, qe_report) + struct.pack("<H", len(auth)) + auth
              + struct.pack("<HI", TQ.CERT_TYPE_PCK_CHAIN, len(pem)) + pem)
        sd = _raw_sig(self.att_k, signed) + att_pub + struct.pack("<HI", TQ.CERT_TYPE_QE_REPORT, len(cd)) + cd
        return signed + struct.pack("<I", len(sd)) + sd


class FakeProvider:
    """Stands in for dstack/configfs: answers with a quote over whatever report_data it is given (or a broken one on demand)."""
    name = "fake"

    def __init__(self, intel=None, event_log=None, tamper=None, fail=None, **over):
        self.intel, self.over = intel or FakeIntel(), over
        self.event_log, self.tamper, self.fail = event_log, tamper, fail
        self.calls = []

    def quote(self, rd):
        self.calls.append(bytes(rd))
        if self.fail:
            raise self.fail
        q = self.intel.quote(rd if self.tamper != "report_data" else bytes(64), **self.over)
        if self.tamper == "flip":
            q = q[:100] + bytes([q[100] ^ 1]) + q[101:]
        return q, self.event_log


T0 = 1790000000                                       # fake collateral is valid T0 - 1 day .. T0 + 30 days
FMSPC = bytes.fromhex("20a06f000000")
CPU_SVN = bytes([5, 5, 2, 2, 5, 255, 0, 2] + [0] * 8)
QE_MRSIGNER = bytes(range(32))


def _iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakePcs(FakeIntel):
    """FakeIntel whose PCK leaf carries a real-shaped SGX extension, plus a TCB signing key: makes the whole Intel PCS collateral
    (TCB Info, QE Identity, root CA CRL, PCK CRL) for check_tcb. Statuses, advisories and revoked serials are chosen by the test."""

    def __init__(self, pce_svn=13, cpu_svn=CPU_SVN):
        super().__init__()
        self.tcb_k = ec.generate_private_key(ec.SECP256R1())
        self.tcb_cert = _cert("Fake SGX TCB Signing", "Fake SGX Root CA", self.tcb_k.public_key(), self.root_k, False)
        self.leaf = _cert("Fake SGX PCK Certificate", "Fake SGX PCK Platform CA", self.pck_k.public_key(), self.int_k, False,
                          ext=sgx_extension(FMSPC, cpu_svn, pce_svn))

    def qe_base(self, isvsvn=6):
        b = bytearray(TQ.QE_REPORT_LEN)
        b[48:64] = bytes.fromhex("11000000000000000000000000000000")
        b[128:160] = QE_MRSIGNER
        b[256:258] = (2).to_bytes(2, "little")
        b[258:260] = isvsvn.to_bytes(2, "little")
        return bytes(b)

    def tdx_quote(self, rd, tee_tcb_svn=bytes([11, 1, 5] + [0] * 13), qe_isvsvn=6, **over):
        return self.quote(rd, qe_base=self.qe_base(qe_isvsvn), tee_tcb_svn=tee_tcb_svn, **over)

    def _crl(self, issuer_name, key, revoked=()):
        b = (x509.CertificateRevocationListBuilder().issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
             .last_update(datetime.datetime.fromtimestamp(T0 - 86400, datetime.timezone.utc))
             .next_update(datetime.datetime.fromtimestamp(T0 + 30 * 86400, datetime.timezone.utc)))
        for sn in revoked:
            b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(sn).revocation_date(
                datetime.datetime.fromtimestamp(T0 - 3600, datetime.timezone.utc)).build())
        return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def _signed(self, key, obj):
        raw = json.dumps(obj, separators=(",", ":"))
        return ('{"%s":%s,"signature":"%s"}' % (key, raw, _raw_sig(self.tcb_k, raw.encode()).hex())).encode()

    def collateral(self, status="UpToDate", advisories=(), module_status="UpToDate", qe_status="UpToDate", revoked_pck=False,
                   revoked_ca=False):
        pem = lambda *cs: b"".join(c.public_bytes(serialization.Encoding.PEM) for c in cs)
        comps = lambda svns: [{"svn": v} for v in svns]
        lv = lambda sgx, tdx, st, adv: {"tcb": {"sgxtcbcomponents": comps(sgx), "pcesvn": 13, "tdxtcbcomponents": comps(tdx)},
                                       "tcbDate": "2025-08-13T00:00:00Z", "tcbStatus": st, "advisoryIDs": list(adv)}
        ti = {"id": "TDX", "version": 3, "issueDate": _iso(T0 - 86400), "nextUpdate": _iso(T0 + 30 * 86400), "fmspc": FMSPC.hex().upper(),
              "pceId": "0000", "tcbType": 0, "tcbEvaluationDataNumber": 20,
              "tdxModule": {"mrsigner": "00" * 48, "attributes": "0000000000000000", "attributesMask": "FFFFFFFFFFFFFFFF"},
              "tdxModuleIdentities": [{"id": "TDX_01", "mrsigner": "00" * 48, "attributes": "0000000000000000",
                                       "attributesMask": "FFFFFFFFFFFFFFFF",
                                       "tcbLevels": [{"tcb": {"isvsvn": 11}, "tcbDate": "2025-08-13T00:00:00Z", "tcbStatus": module_status},
                                                     {"tcb": {"isvsvn": 2}, "tcbDate": "2024-01-01T00:00:00Z", "tcbStatus": "OutOfDate"}]}],
              "tcbLevels": [lv(list(CPU_SVN), [5, 0, 5] + [0] * 13, status, advisories),
                            lv([2] * 5 + [255, 0, 2] + [0] * 8, [5, 0, 2] + [0] * 13, "OutOfDate", ["INTEL-SA-01192"])]}
        qi = {"id": "TD_QE", "version": 2, "issueDate": _iso(T0 - 86400), "nextUpdate": _iso(T0 + 30 * 86400), "tcbEvaluationDataNumber": 20,
              "miscselect": "00000000", "miscselectMask": "FFFFFFFF", "attributes": "11000000000000000000000000000000",
              "attributesMask": "FBFFFFFFFFFFFFFF0000000000000000", "mrsigner": QE_MRSIGNER.hex().upper(), "isvprodid": 2,
              "tcbLevels": [{"tcb": {"isvsvn": 4}, "tcbDate": "2024-03-13T00:00:00Z", "tcbStatus": qe_status}]}
        return {"tcb_info.json": self._signed("tcbInfo", ti), "tcb_info_issuer_chain.pem": pem(self.tcb_cert, self.root),
                "qe_identity.json": self._signed("enclaveIdentity", qi), "qe_identity_issuer_chain.pem": pem(self.tcb_cert, self.root),
                "pck_crl.der": self._crl("Fake SGX PCK Platform CA", self.int_k, [self.leaf.serial_number] if revoked_pck else []),
                "pck_crl_issuer_chain.pem": pem(self.inter, self.root),
                "root_ca_crl.der": self._crl("Fake SGX Root CA", self.root_k, [self.inter.serial_number] if revoked_ca else [])}
