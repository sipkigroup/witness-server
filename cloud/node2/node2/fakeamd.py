"""TEST ONLY: a fake AMD key hierarchy (ARK -> ASK -> VCEK) and SNP reports signed by the fake VCEK, with the same shapes as the real
Genoa ones of 2026-10-22 (RSA-PSS SHA-384 certificates, P-384 VCEK, raw 64-byte hwID, DER INTEGER TCB extensions, report VERSION 3).
Its ARK is NOT in amd.ARK_PINS: a report from here is accepted only by a checker that is explicitly given this ARK's pin."""
import datetime
import hashlib
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from node2 import amd, attest

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
RESTRICTIVE_POLICY = (b'package policy\n\napi_version := "0.10.0"\n\n'
                      b'containers := [{"id": "sha256:test-node2-image", "command": ["python", "-m", "node2.worker"], "exec_processes": []}]\n\n'
                      b'mount_device := data.framework.mount_device\ncreate_container := data.framework.create_container\n'
                      b'exec_in_container := data.framework.exec_in_container\nexec_external := data.framework.exec_external\n'
                      b'allow_properties_access := false\nallow_dump_stacks := false\nallow_runtime_logging := false\n')
TCB = 0x541700000000000A                              # bl 10, tee 0, snp 23, ucode 84 (the probe's value)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake AMD (tests)")])


def _der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    return bytes([2, len(b)]) + b


class FakeAmd:
    def __init__(self, chip_id=b"\x42" * 64, tcb=TCB):
        self.chip_id, self.tcb = chip_id, tcb
        now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        end = now + datetime.timedelta(days=3650)
        self.ark_key = rsa.generate_private_key(65537, 2048)
        self.ask_key = rsa.generate_private_key(65537, 2048)
        self.vcek_key = ec.generate_private_key(ec.SECP384R1())

        def cert(subj, iss, pub, key, ca, exts=()):
            b = (x509.CertificateBuilder().subject_name(_name(subj)).issuer_name(_name(iss)).public_key(pub)
                 .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(end)
                 .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
            for oid, val in exts:
                b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), val), critical=False)
            return b.sign(key, hashes.SHA384(), rsa_padding=PSS)
        self.ark = cert("ARK-Fake", "ARK-Fake", self.ark_key.public_key(), self.ark_key, True)
        self.ask = cert("SEV-Fake", "ARK-Fake", self.ask_key.public_key(), self.ark_key, True)
        t = {"bl": tcb & 0xFF, "tee": tcb >> 8 & 0xFF, "snp": tcb >> 48 & 0xFF, "ucode": tcb >> 56 & 0xFF}
        self.vcek = cert("SEV-VCEK", "SEV-Fake", self.vcek_key.public_key(), self.ask_key, False,
                         [(amd.OID_HWID, chip_id)] + [(oid, _der_int(t[k])) for k, oid in amd.OID_TCB.items()])

    def pins(self):
        return {"Fake": hashlib.sha256(self.ark.public_bytes(serialization.Encoding.DER)).hexdigest()}

    def vcek_der(self):
        return self.vcek.public_bytes(serialization.Encoding.DER)

    def chain_pem(self):
        return self.ask.public_bytes(serialization.Encoding.PEM) + self.ark.public_bytes(serialization.Encoding.PEM)

    def report(self, report_data, host_data=None, measurement=b"\x11" * 48, policy=0x3001F, version=3):
        r = bytearray(attest.synth_report(report_data, host_data=host_data or b"\x00" * 32, measurement=measurement, policy=policy))
        struct.pack_into("<I", r, 0, version)
        struct.pack_into("<I", r, 0x34, 1)                # SIGNATURE_ALGO = ECDSA P-384 with SHA-384
        struct.pack_into("<Q", r, 0x180, self.tcb)        # REPORTED_TCB
        r[0x1A0:0x1E0] = self.chip_id
        sig = self.vcek_key.sign(bytes(r[:amd.SIGNED_LEN]), ec.ECDSA(hashes.SHA384()))
        rr, ss = decode_dss_signature(sig)
        r[amd.OFF_SIG:amd.OFF_SIG + 72] = rr.to_bytes(72, "little")
        r[amd.OFF_SIG + 72:amd.OFF_SIG + 144] = ss.to_bytes(72, "little")
        return bytes(r)

    def provider(self, policy=RESTRICTIVE_POLICY, **kw):
        """A report function for the worker: report_data -> report (host_data = SHA-256 of the policy text, as ACI does)."""
        return lambda rd: self.report(rd, host_data=hashlib.sha256(policy).digest(), **kw)
