"""Binding of the node 2 key to an AMD SEV-SNP attestation report (scheme deus-node2-snp-v1). Status: ACI path L2 (one real report), CVM path L1.

report_data (64 bytes) = key_hash || ctx
  key_hash = SHA-256("deus-node2-snp-v1:key"  0x00 || pub_Ed25519(32))
  ctx      = SHA-256("deus-node2-snp-v1:boot" 0x00 || node1_pub(32) || t(uint64 BE))
Two platforms, two shapes of evidence:
  aci-sevsnp     Confidential Containers on ACI. L2 (one real report, eastus, 2026-10-22, proba/OTCHET-PROBA-2026-10-22.md):
                 the container sees /dev/sev-guest; the SNP_GET_REPORT ioctl takes OUR 64-byte report_data verbatim (VMPL 0,
                 report VERSION 3, Genoa). HOST_DATA = SHA-256 of the ccePolicy rego TEXT (base64-decoded), confirmed.
                 The Microsoft sidecar (mcr.microsoft.com/aci/skr, POST /attest/raw {"runtime_data": b64}) does NOT pass
                 report_data through: it puts SHA-256(runtime_data) || 0^32, so node 2 calls the ioctl itself.
                 VCEK + ASK/ARK: /security-context-*/host-amd-cert-base64 (THIM JSON) or AMD KDS; both verified the signature.
                 MEASUREMENT = Microsoft UVM launch measurement, listed in /security-context-*/reference-info-base64 (COSE).
  azure-cvm-vtpm DCasv5 CVM (still L0 hypothesis, not probed): the paravisor (HCL) holds the report; REPORT_DATA[0:32] =
                 SHA-256(runtime_data JSON with the vTPM AK); our key_hash goes into a TPM2_Quote (extraData) by that AK;
                 "which code" = PCRs, NOT the SNP MEASUREMENT.
Here: field layout, binding, policy-hash and DEBUG checks; check_full() adds the VCEK -> ASK -> ARK chain and the report signature
(amd.py, self-contained, L2 on the probe's real reports) and the known allow-all policy forms. The TPM quote of the CVM path: tpm.py (deus-mir).
"""
import base64 as _b64
import hashlib
import re as _re
import struct

SCHEME = "deus-node2-snp-v1"
REPORT_LEN = 0x4A0
OFF_POLICY, OFF_REPORT_DATA, OFF_MEASUREMENT, OFF_HOST_DATA = 0x008, 0x050, 0x090, 0x0C0
POLICY_DEBUG_BIT = 19
VERSIONS = (2, 3, 5)                                 # real ACI 2026-10-22: 3


class AttestError(Exception):
    pass


def key_hash(pub):
    return hashlib.sha256(SCHEME.encode() + b":key\x00" + pub).digest()


def boot_ctx(node1_pub, t):
    return hashlib.sha256(SCHEME.encode() + b":boot\x00" + node1_pub + struct.pack(">Q", t)).digest()


def report_data(pub, node1_pub, t):
    return key_hash(pub) + boot_ctx(node1_pub, t)


def fields(report):
    if not isinstance(report, bytes) or len(report) != REPORT_LEN:
        raise AttestError("SNP_FORMAT")
    version = int.from_bytes(report[0:4], "little")
    if version not in VERSIONS:
        raise AttestError("SNP_FORMAT")
    return {"version": version, "guest_svn": int.from_bytes(report[4:8], "little"),
            "vmpl": int.from_bytes(report[0x30:0x34], "little"),
            "reported_tcb": int.from_bytes(report[0x180:0x188], "little"), "chip_id": report[0x1A0:0x1E0],
            "policy": int.from_bytes(report[OFF_POLICY:OFF_POLICY + 8], "little"),
            "report_data": report[OFF_REPORT_DATA:OFF_REPORT_DATA + 64],
            "measurement": report[OFF_MEASUREMENT:OFF_MEASUREMENT + 48],
            "host_data": report[OFF_HOST_DATA:OFF_HOST_DATA + 32]}


def check_aci(doc, expect):
    """doc: {"scheme","platform":"aci-sevsnp","pub","node1_pub","t","report","policy"} (bytes values).
    expect: {"measurement": UVM measurement (Microsoft reference value), "policy_sha256": what the user recomputed from the
    open image with `az confcom acipolicygen`}. -> dict of checks; raises AttestError on the first failure."""
    if doc.get("scheme") != SCHEME or doc.get("platform") != "aci-sevsnp":
        raise AttestError("SCHEME")
    f = fields(doc["report"])
    if f["policy"] >> POLICY_DEBUG_BIT & 1:
        raise AttestError("DEBUG")                       # a debuggable guest proves nothing
    if f["report_data"] != report_data(doc["pub"], doc["node1_pub"], doc["t"]):
        raise AttestError("NOT_BOUND")
    pol = hashlib.sha256(doc["policy"]).digest()
    if f["host_data"] != pol:
        raise AttestError("POLICY_NOT_BOUND")            # the policy shown is not the one the platform enforced
    if pol != expect["policy_sha256"]:
        raise AttestError("POLICY_UNEXPECTED")           # other code than the published image
    if f["measurement"] != expect["measurement"]:
        raise AttestError("MEASUREMENT_UNEXPECTED")      # other utility VM than Microsoft's published one
    return {"bound": True, "policy": pol.hex(), "measurement": f["measurement"].hex(), "vmpl": f["vmpl"],
            "reported_tcb": "%016x" % f["reported_tcb"],
            "not_checked_here": ["VCEK chain + report signature (snp.py)", "TCB minimum / CRL (AMD KDS)",
                                 "the policy forbids exec into the container (read it: allow_exec / exec_processes)"]}


def check_cvm_runtime(doc):
    """Azure CVM half of the chain: REPORT_DATA[0:32] = SHA-256(runtime_data) and the AK is listed in runtime_data.
    The TPM quote half (AK signs PCRs + extraData = key_hash(pub)) is tpm.py's job. -> AK as listed (JWK dict)."""
    import json
    f = fields(doc["report"])
    rt = doc["runtime_data"]
    if f["report_data"][:32] != hashlib.sha256(rt).digest():
        raise AttestError("RUNTIME_NOT_BOUND")
    keys = {k.get("kid"): k for k in json.loads(rt).get("keys", [])}
    if "HCLAkPub" not in keys:
        raise AttestError("NO_AK")
    return keys["HCLAkPub"]


def synth_report(rd, host_data=b"\x00" * 32, measurement=b"\x11" * 48, policy=0x30000):
    """TEST ONLY: a report with the given fields (signature bytes are zero; snp.py tests sign their own)."""
    r = bytearray(REPORT_LEN)
    struct.pack_into("<I", r, 0, 5)
    struct.pack_into("<Q", r, OFF_POLICY, policy)
    r[OFF_REPORT_DATA:OFF_REPORT_DATA + 64] = rd
    r[OFF_MEASUREMENT:OFF_MEASUREMENT + 48] = measurement
    r[OFF_HOST_DATA:OFF_HOST_DATA + 32] = host_data
    return bytes(r)


# ---------- wire form of the attestation document (JSON: node 2 -> node 1 -> site / evidence pack -> user) ----------


def doc_to_json(doc):
    out = {"scheme": doc["scheme"], "platform": doc["platform"], "pub_hex": doc["pub"].hex(), "node1_pub_hex": doc["node1_pub"].hex(),
           "t": int(doc["t"]), "report_b64": _b64.b64encode(doc["report"]).decode(), "policy_b64": _b64.b64encode(doc["policy"]).decode()}
    if doc.get("vcek"):
        out["vcek_b64"] = _b64.b64encode(doc["vcek"]).decode()
    if doc.get("chain"):
        out["chain_pem"] = doc["chain"].decode() if isinstance(doc["chain"], bytes) else doc["chain"]
    return out


def doc_from_json(j):
    """-> doc with bytes values. Raises AttestError("DOC_MALFORMED")."""
    try:
        d = {"scheme": str(j["scheme"]), "platform": str(j["platform"]), "pub": bytes.fromhex(j["pub_hex"]),
             "node1_pub": bytes.fromhex(j["node1_pub_hex"]), "t": int(j["t"]), "report": _b64.b64decode(j["report_b64"], validate=True),
             "policy": _b64.b64decode(j["policy_b64"], validate=True)}
        if j.get("vcek_b64"):
            d["vcek"] = _b64.b64decode(j["vcek_b64"], validate=True)
        if j.get("chain_pem"):
            d["chain"] = str(j["chain_pem"]).encode()
    except (KeyError, TypeError, ValueError):
        raise AttestError("DOC_MALFORMED")
    if len(d["pub"]) != 32 or len(d["node1_pub"]) != 32 or not 0 <= d["t"] < 2 ** 63:
        raise AttestError("DOC_MALFORMED")
    return d


# The allow-all policy of the probe (proba/policy-allow-all-DEBUG.rego) and any policy written in that style. This catches the probe's
# form only; a generated confcom policy says what it allows in its container list: READ it (exec_processes, allow_* flags).
_ALLOW = _re.compile(rb'\b(exec_in_container|exec_external|create_container|load_fragment)\s*:=\s*\{[^}]*"allowed"\s*:\s*true')


def policy_warnings(policy):
    """-> list of plain-language problems of the container policy text (empty = none of the known bad forms)."""
    w = []
    for m in sorted({x.group(1).decode() for x in _ALLOW.finditer(policy)}):
        w.append({"exec_in_container": "the policy lets the operator run any command inside the running container (exec)",
                  "exec_external": "the policy lets the operator start any process in the utility VM",
                  "create_container": "the policy lets any container image start (not only the published node 2 image)",
                  "load_fragment": "the policy accepts policy fragments added later"}[m])
    return w


def check_full(doc, expect=None, pins=None, at=None):
    """Everything a user can check offline about one K2 key -> {"ok": bool, "problems": [...], "trust": [...], "facts": {...}}.
    ok = bound to the report, not DEBUG, policy bound, AMD signature + chain to a pinned ARK, no known allow-all form in the policy,
    and (when `expect` is given) the policy hash and measurement are the published ones. Never raises on a bad document."""
    from node2 import amd
    res = {"ok": False, "problems": [], "trust": [], "facts": {}}
    try:
        f = fields(doc["report"])
        res["facts"] = {"version": f["version"], "measurement": f["measurement"].hex(), "host_data": f["host_data"].hex(),
                        "reported_tcb": "%016x" % f["reported_tcb"], "chip_id": f["chip_id"].hex(), "vmpl": f["vmpl"],
                        "debug": bool(f["policy"] >> POLICY_DEBUG_BIT & 1), "policy_sha256": hashlib.sha256(doc["policy"]).hexdigest()}
        exp = expect or {"policy_sha256": hashlib.sha256(doc["policy"]).digest(), "measurement": f["measurement"]}
        check_aci(doc, exp)
    except AttestError as e:
        res["problems"].append("attestation: %s" % e)
        return res
    if expect is None:
        res["trust"].append("the policy hash and the measurement were not compared with published values (no expectation given)")
    if doc.get("vcek") and doc.get("chain"):
        try:
            a = amd.verify(doc["report"], doc["vcek"], doc["chain"], at=at, pins=pins)
            res["facts"]["amd"] = a["product"]
            if a["product"] not in amd.ARK_PINS:
                res["trust"].append("the AMD root of this key is not a pinned AMD root: the caller supplied it (%s)" % a["product"])
        except amd.AmdError as e:
            res["problems"].append("AMD signature: %s" % e)
    else:
        res["problems"].append("AMD signature: no VCEK certificate and chain with the report")
    for w in policy_warnings(doc["policy"]):
        res["problems"].append("policy: " + w)
    res["trust"].append("AMD revocation list and a minimum TCB are not checked offline")
    res["ok"] = not res["problems"]
    return res
