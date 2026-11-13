"""AMD SEV-SNP report signature and the VCEK -> ASK -> ARK chain (self-contained: cryptography only). Status: L2 on the real ACI
reports of 2026-10-22 (proba/: report-RD1/RD2/skr.bin, kds/vcek-Genoa.der, kds/cert_chain-Genoa.pem, thim-vcek.pem).

What is checked here:
  - ARK is self-signed and its SHA-256 (DER) is one of the PINNED AMD roots (ARK_PINS; a test may pass its own pin);
  - ASK is signed by ARK, VCEK by ASK (RSA-PSS SHA-384, as AMD issues them), all valid at `at`;
  - the VCEK hwID extension (1.3.6.1.4.1.3704.1.4) equals the report's CHIP_ID (real Genoa VCEK: RAW 64 bytes, no DER wrapper;
    a DER OCTET STRING is accepted too);
  - the VCEK TCB extensions (bl, tee, snp, ucode SPL) equal the report's REPORTED_TCB;
  - the report signature: ECDSA P-384 / SHA-384 over bytes 0x000..0x29F, r and s little-endian 72 bytes each at 0x2A0.
NOT checked: revocation (AMD CRL), a minimum TCB policy. Those need the network or a policy decision; the caller says so.
"""
import datetime
import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

SIGNED_LEN = 0x2A0
OFF_SIG = 0x2A0
OFF_TCB, OFF_CHIP = 0x180, 0x1A0
# SHA-256 of the DER of the AMD Root Keys, fetched from https://kdsintf.amd.com/vcek/v1/<product>/cert_chain (proba/kds/):
#   Genoa 2026-10-22 (and again 2026-10-23, same bytes) -- seen on real hardware (ACI eastus, 3 reports, L2);
#   Milan 2026-10-23 (proba/kds/cert_chain-Milan.pem) -- the ARK is pinned from KDS, no Milan REPORT was checked yet (L1 for Milan:
#   same report/TCB layout as Genoa per the SEV-SNP ABI; ACI may land on either). Turin is NOT pinned: its TCB_VERSION layout differs
#   (FMC field), the TCB comparison below would be wrong for it.
ARK_PINS = {"Genoa": "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
            "Milan": "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd"}
OID_HWID = "1.3.6.1.4.1.3704.1.4"
OID_TCB = {"bl": "1.3.6.1.4.1.3704.1.3.1", "tee": "1.3.6.1.4.1.3704.1.3.2", "snp": "1.3.6.1.4.1.3704.1.3.3", "ucode": "1.3.6.1.4.1.3704.1.3.8"}


class AmdError(Exception):
    """str(e) = reason code."""


def load_certs(blob):
    """PEM (one or more) or DER -> [Certificate]."""
    if isinstance(blob, str):
        blob = blob.encode()
    if b"-----BEGIN" in blob:
        return x509.load_pem_x509_certificates(blob)
    return [x509.load_der_x509_certificate(blob)]


def _issued(child, parent):
    pub = parent.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            p = child.signature_algorithm_parameters
            if not isinstance(p, padding.PSS):
                raise AmdError("AMD_CERT_ALG")
            pub.verify(child.signature, child.tbs_certificate_bytes, p, child.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        else:
            raise AmdError("AMD_CERT_ALG")
    except InvalidSignature:
        raise AmdError("AMD_CERT_SIG")
    if child.issuer != parent.subject:
        raise AmdError("AMD_CERT_ISSUER")


def _valid(c, at):
    if not c.not_valid_before_utc <= at <= c.not_valid_after_utc:
        raise AmdError("AMD_CERT_EXPIRED")


def _ext_raw(cert, oid):
    for e in cert.extensions:
        if e.oid.dotted_string == oid:
            return e.value.value
    return None


def _der_int(v):
    """DER INTEGER (tag 2) -> int; the TCB extensions of a real VCEK are DER INTEGERs."""
    if len(v) < 3 or v[0] != 2 or v[1] != len(v) - 2:
        raise AmdError("AMD_VCEK_EXT")
    return int.from_bytes(v[2:], "big")


def _hwid(v):
    if v is None:
        raise AmdError("AMD_VCEK_EXT")
    if len(v) == 64:
        return v                                         # real Genoa VCEK, 2026-10-22
    if len(v) == 66 and v[0] == 4 and v[1] == 64:
        return v[2:]                                     # DER OCTET STRING (what the synthetic tests of snp.py assumed)
    raise AmdError("AMD_VCEK_EXT")


def verify(report, vcek, chain, at=None, pins=None):
    """report: 1184 bytes; vcek: DER/PEM bytes; chain: PEM bytes with ASK and ARK (any order). pins: {name: sha256 hex of ARK DER}
    (default ARK_PINS). -> {"product": name, "ark_sha256", "vcek_sha256", "tcb": {...}}. Raises AmdError."""
    at = at or datetime.datetime.now(datetime.timezone.utc)
    pins = ARK_PINS if pins is None else pins
    if not isinstance(report, bytes) or len(report) != 0x4A0:
        raise AmdError("SNP_FORMAT")
    try:
        v = load_certs(vcek)[0]
        cs = load_certs(chain)
    except (ValueError, IndexError):
        raise AmdError("AMD_CERT_MALFORMED")
    arks = [c for c in cs if c.subject == c.issuer]
    asks = [c for c in cs if c.subject != c.issuer]
    if len(arks) != 1 or len(asks) != 1:
        raise AmdError("AMD_CHAIN_SHAPE")
    ark, ask = arks[0], asks[0]
    fp = hashlib.sha256(ark.public_bytes(serialization.Encoding.DER)).hexdigest()
    name = next((n for n, h in pins.items() if h == fp), None)
    if name is None:
        raise AmdError("AMD_ARK_NOT_PINNED")
    _issued(ark, ark)
    _issued(ask, ark)
    _issued(v, ask)
    for c in (ark, ask, v):
        _valid(c, at)
    if _hwid(_ext_raw(v, OID_HWID)) != report[OFF_CHIP:OFF_CHIP + 64]:
        raise AmdError("AMD_VCEK_CHIP")
    tcb = int.from_bytes(report[OFF_TCB:OFF_TCB + 8], "little")
    want = {"bl": tcb & 0xFF, "tee": tcb >> 8 & 0xFF, "snp": tcb >> 48 & 0xFF, "ucode": tcb >> 56 & 0xFF}
    for k, oid in OID_TCB.items():
        raw = _ext_raw(v, oid)
        if raw is None or _der_int(raw) != want[k]:
            raise AmdError("AMD_VCEK_TCB")
    pub = v.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp384r1":
        raise AmdError("AMD_VCEK_KEY")
    r = int.from_bytes(report[OFF_SIG:OFF_SIG + 72], "little")
    s = int.from_bytes(report[OFF_SIG + 72:OFF_SIG + 144], "little")
    try:
        pub.verify(encode_dss_signature(r, s), report[:SIGNED_LEN], ec.ECDSA(hashes.SHA384()))
    except InvalidSignature:
        raise AmdError("SNP_REPORT_SIG")
    return {"product": name, "ark_sha256": fp, "vcek_sha256": hashlib.sha256(v.public_bytes(serialization.Encoding.DER)).hexdigest(),
            "tcb": want}
