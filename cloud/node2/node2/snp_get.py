"""SNP report providers for node 2. ACI: read the report straight from /dev/sev-guest (probe 2026-10-22: the
sidecar /attest/raw substitutes report_data, so it is NOT used). Fake provider for tests (no hardware)."""
import ctypes
import fcntl
import struct

SNP_GET_REPORT = 0xC0205300  # _IOWR('S', 0, struct snp_guest_request_ioctl)
REPORT_LEN = 1184


class SnpGetError(Exception):
    pass


def dev_sev_guest(report_data, dev="/dev/sev-guest"):
    """Report with the given 64-byte report_data, from the guest device (VMPL0)."""
    if len(report_data) != 64:
        raise SnpGetError("report_data must be 64 bytes")
    req = ctypes.create_string_buffer(report_data + struct.pack("<I", 0) + b"\x00" * 28, 96)
    resp = ctypes.create_string_buffer(4000)
    io = ctypes.create_string_buffer(struct.pack("<B7xQQQ", 1, ctypes.addressof(req), ctypes.addressof(resp), 0), 32)
    try:
        with open(dev, "rb+", buffering=0) as fd:
            fcntl.ioctl(fd, SNP_GET_REPORT, io, True)
    except OSError as e:
        raise SnpGetError("ioctl %s: %r" % (dev, e))
    st, size = struct.unpack_from("<II", resp.raw, 0)
    if st != 0 or size != REPORT_LEN:
        raise SnpGetError("firmware status %d, size %d" % (st, size))
    rep = resp.raw[32:32 + size]
    if rep[0x50:0x90] != report_data:
        raise SnpGetError("report_data in report differs from requested")
    return rep


def fake(report_data, **kw):
    """Test provider: synthetic report (NOT signed by AMD) with the requested report_data."""
    from node2 import attest
    if len(report_data) != 64:
        raise SnpGetError("report_data must be 64 bytes")
    return attest.synth_report(report_data, **kw)


def aci_context(pattern="/security-context-*"):
    """ACI security context (probe 2026-10-22): security-policy-base64 = the ccePolicy (base64 of the rego text whose SHA-256 is
    HOST_DATA), host-amd-cert-base64 = base64 of the THIM JSON {vcekCert, certificateChain (ASK+ARK PEM), tcbm}.
    -> {"policy": rego bytes, "vcek": PEM bytes, "chain": PEM bytes}. Raises SnpGetError."""
    import base64
    import glob
    import json
    import os
    for d in sorted(glob.glob(pattern)):
        try:
            with open(os.path.join(d, "security-policy-base64"), "rb") as f:
                pol = base64.b64decode(f.read().strip())
            with open(os.path.join(d, "host-amd-cert-base64"), "rb") as f:
                thim = json.loads(base64.b64decode(f.read().strip()))
            return {"policy": pol, "vcek": thim["vcekCert"].encode(), "chain": thim["certificateChain"].encode()}
        except (OSError, ValueError, KeyError) as e:
            raise SnpGetError("security context %s: %r" % (d, e))
    raise SnpGetError("no %s directory (not an ACI confidential container?)" % pattern)
