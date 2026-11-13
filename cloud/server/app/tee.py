"""TEE mode (Intel TDX confidential VM, e.g. Phala dstack): OFF unless DW_TEE=on. Design: cloud/tee/DIZAIN-TDX.md.

With DW_TEE=on:
  - the witness key is born inside the CVM (ensure_key: O_EXCL, 0600, never read from outside; Config fixes its path);
  - at start the server takes a TDX quote whose report_data = key_hash(pub) || ctx_boot(iss, t), checks it locally (tdx_quote.verify:
    structure, signatures, report_data) and refuses to start if anything fails (fail closed: no "tee" claim without a quote);
  - /api/witness and /v1/witness gain an "attestation" object (nothing else changes; with DW_TEE unset the answer is byte-for-byte the old one);
  - every anchor batch gets a quote bound to its Merkle root (anchors/<bid>.tdx.json, GET /v1/witness/tdx/{bid}); the anchor record
    anchors/<bid>.json names it by hash (`tee` member) and the evidence pack carries it (tee/<bid>.tdx.json, checked by verify_pack).
Quote providers (dstack and tappd checked 23.10.2026 against the public spec Dstack-TEE/dstack docs/guest-api-v0.md @250334c;
still to be confirmed on a real CVM, see cloud/tee/OTCHET-PHALA-PODGOTOVKA-2026-10-23.md):
  dstack   - guest agent, prpc over the Unix socket /var/run/dstack.sock (newer images also /var/run/dstack/dstack.sock),
             POST /GetQuote, Content-Type application/json, {"report_data": hex <= 64 bytes, zero-padded} ->
             {"quote": hex, "event_log": JSON string, "report_data": hex, "vm_config": str}. event_log is the STRIPPED form
             (L3 Phala 23.10, dstack-dev-0.5.12: Attestation::get_tdx_event_log_string -> TdxEvent::stripped(): runtime events
             digest "", boot events event_payload ""); tdx_quote.replay_event_log derives runtime digests from the payload, so the
             binding stays strict. The Phala API tcb_info.event_log is the full form; both are read. The unversioned path is the frozen
             v0 surface, served by 0.5.x and (as an alias of /v0) by 0.6+; v1 has no GetQuote (Attest replaces it).
  tappd    - deprecated agent, /var/run/tappd.sock, POST /prpc/Tappd.RawQuote {"report_data": hex, exactly 64 bytes}
  configfs - Linux configfs-tsm (kernel >= 6.7): /sys/kernel/config/tsm/report/<entry>/{inblob,outblob,provider,generation}
A provider object can be injected only from code (Config.tee_provider), never from the environment: tests use a fake one."""
import base64
import http.client
import json
import os
import secrets
import socket
import time

from app.config import ConfigError
from app import tdx_quote as TQ
from app.log import log


class TeeError(ConfigError):
    """TEE mode is on but no valid quote can be produced: the process does not start."""


# ---------------------------------------------------------------- the key is born here

def ensure_key(path):
    """Creates the witness Ed25519 seed inside the CVM if it does not exist yet (O_EXCL, mode 0600). Never overwrites. -> True if created."""
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w") as f:
        f.write(secrets.token_bytes(32).hex())
        f.flush()
        os.fsync(f.fileno())
    return True


# ---------------------------------------------------------------- providers

class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.path)
        self.sock = s


def _post_unix(sock, url, body):
    c = _UnixHTTP(sock)
    try:
        c.request("POST", url, body=json.dumps(body), headers={"Content-Type": "application/json"})
        r = c.getresponse()
        data = r.read()
        if r.status != 200:
            raise TeeError("quote agent %s%s answered %d" % (sock, url, r.status))
        return json.loads(data)
    finally:
        c.close()


def _hexbytes(v):
    v = v[2:] if isinstance(v, str) and v.startswith("0x") else v
    return bytes.fromhex(v)


class DstackProvider:
    name = "dstack"
    SOCK = "/var/run/dstack.sock"
    SOCKS = ("/var/run/dstack.sock", "/run/dstack.sock", "/var/run/dstack/dstack.sock", "/run/dstack/dstack.sock")  # dstack SDK order
    URL = "/GetQuote"

    def __init__(self, sock=None):
        self.sock = sock or self.found() or self.SOCK

    @classmethod
    def found(cls):
        return next((p for p in cls.SOCKS if os.path.exists(p)), None)

    def quote(self, rd64):
        j = _post_unix(self.sock, self.URL, {"report_data": rd64.hex()})
        ev = j.get("event_log")
        if isinstance(ev, str):
            ev = json.loads(ev) if ev else None
        return _hexbytes(j["quote"]), ev


class TappdProvider(DstackProvider):
    name = "tappd"
    SOCK = "/var/run/tappd.sock"
    SOCKS = ("/var/run/tappd.sock", "/run/tappd.sock", "/var/run/dstack/tappd.sock", "/run/dstack/tappd.sock")
    URL = "/prpc/Tappd.RawQuote"


class ConfigfsProvider:
    """configfs-tsm report interface. The kernel produces outblob when it is read after inblob was written; `generation` counts writes,
    so a concurrent writer to the same entry is detected (we use a private entry anyway)."""
    name = "configfs"
    BASE = "/sys/kernel/config/tsm/report"

    def __init__(self, base=None):
        self.base = base or self.BASE

    def _mkentry(self):
        p = os.path.join(self.base, "dw-%d-%s" % (os.getpid(), secrets.token_hex(4)))
        os.mkdir(p)
        return p

    def quote(self, rd64):
        p = self._mkentry()
        try:
            with open(os.path.join(p, "provider")) as f:
                prov = f.read().strip()
            if prov != "tdx_guest":
                raise TeeError("configfs-tsm provider is %r, not tdx_guest" % prov)
            with open(os.path.join(p, "inblob"), "wb") as f:
                f.write(rd64)
            with open(os.path.join(p, "outblob"), "rb") as f:
                out = f.read()
            with open(os.path.join(p, "generation")) as f:
                gen = int(f.read().strip() or 0)
            if gen != 1:
                raise TeeError("configfs-tsm entry written %d times: concurrent use" % gen)
            return out, None
        finally:
            self._rmentry(p)

    def _rmentry(self, p):
        try:
            os.rmdir(p)                                   # configfs: removing the entry directory releases it
        except OSError:
            pass


PROVIDERS = {"dstack": DstackProvider, "tappd": TappdProvider, "configfs": ConfigfsProvider}


def provider_for(cfg):
    if getattr(cfg, "tee_provider", None) is not None:
        return cfg.tee_provider
    want = cfg.tee_provider_name or "auto"
    if want != "auto":
        if want not in PROVIDERS:
            raise TeeError("DW_TEE_PROVIDER must be auto|dstack|tappd|configfs")
        return PROVIDERS[want]()
    if DstackProvider.found():
        return DstackProvider()
    if TappdProvider.found():
        return TappdProvider()
    if os.path.isdir(ConfigfsProvider.BASE):
        return ConfigfsProvider()
    raise TeeError("DW_TEE=on but no quote interface found (dstack.sock, tappd.sock, configfs-tsm)")


# ---------------------------------------------------------------- attestation

class Attestor:
    def __init__(self, cfg, wk, provider=None, clock=time.time):
        self.cfg, self.wk, self.clock = cfg, wk, clock
        self.p = provider or provider_for(cfg)
        self.intel_root = None
        if cfg.tee_intel_root:
            try:
                with open(cfg.tee_intel_root, "rb") as f:
                    self.intel_root = f.read()
            except OSError as e:
                raise TeeError("DW_TEE_INTEL_ROOT unreadable: %s" % type(e).__name__)
        self.boot = None

    def _take(self, ctx32, purpose, extra):
        rd = TQ.report_data(self.wk.pub, ctx32)
        try:
            q, ev = self.p.quote(rd)
        except TeeError:
            raise
        except Exception as e:  # noqa: any failure of the agent is a refusal, not a crash
            raise TeeError("quote provider %s failed: %s" % (getattr(self.p, "name", "?"), type(e).__name__))
        r = TQ.verify(q, rd, None, self.intel_root, ev)
        failed = [(n, d) for n, st, d in r["checks"] if st == TQ.FAIL]
        if failed:
            raise TeeError("own quote does not check: %s" % failed)
        b = r["body"]
        att = {"type": "tdx-quote", "scheme": TQ.SCHEME, "deployment": "tee", "purpose": purpose, "provider": getattr(self.p, "name", "?"),
               "quote_b64": base64.b64encode(q).decode(), "event_log": ev, "report_data_hex": rd.hex(),
               "measurements": {k: b[k] for k in ("mr_td", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "mr_config_id", "td_attributes", "xfam")},
               "checked_here": {n: st for n, st, _ in r["checks"]},
               "note": "measurements are copied from the quote for convenience; trust only what YOUR checker derives from quote_b64 "
                       "(server/app/tdx_quote.py) against measurements YOU rebuilt from the published image"}
        att.update(extra)
        return att

    def boot_attestation(self):
        t = int(self.clock())
        self.boot = self._take(TQ.ctx_boot(self.cfg.iss, t), "boot", {"iss": self.cfg.iss, "t": t})
        return self.boot

    def batch_attestation(self, bid, root):
        return self._take(TQ.ctx_batch(bid, bytes(root)), "batch", {"batch": bid, "root_hex": bytes(root).hex()})


def start(ctx):
    """Called by Ctx when cfg.tee == "on". Raises TeeError (process refuses to start)."""
    a = Attestor(ctx.cfg, ctx.wk)
    a.boot_attestation()
    log("INFO", "tee: boot quote taken", provider=getattr(a.p, "name", "?"))
    return a


def quote_sha256(att):
    """SHA-256 (hex) of the raw quote bytes of an attestation document: what an anchor record names (DIZAIN-TDX.md 3)."""
    import hashlib
    return hashlib.sha256(base64.b64decode(att["quote_b64"])).hexdigest()


def on_batch(ctx, bid, root):
    """After an anchor batch is cut: quote bound to its root -> anchors/<bid>.tdx.json. -> the `tee` member of the anchor record
    (anchors/<bid>.json): {"scheme", "quote_sha256", "quote": "<bid>.tdx.json", "url": "/v1/witness/tdx/<bid>"}; when the quote could
    not be taken: {"scheme", "quote_sha256": null, "error": "..."} (disclosed, the batch stands). None when DW_TEE is off."""
    a = getattr(ctx, "tee", None)
    if a is None or not bid:
        return None
    try:
        att = a.batch_attestation(bid, root)
    except TeeError as e:
        log("ERROR", "tee: batch quote failed: %s" % str(e)[:200])
        return {"scheme": TQ.SCHEME, "quote_sha256": None, "error": "no quote: " + str(e)[:120]}
    p = os.path.join(ctx.anchor_dir, bid + ".tdx.json")
    with open(p, "w") as f:
        json.dump(att, f)
    return {"scheme": TQ.SCHEME, "quote_sha256": quote_sha256(att), "quote": bid + ".tdx.json", "url": "/v1/witness/tdx/" + bid}


def make_router(ctx):
    from fastapi import APIRouter
    from fastapi.responses import JSONResponse
    from app.context import Err
    import re
    r = APIRouter()
    BID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")

    @r.get("/v1/witness/tdx/{bid}")
    @r.get("/api/witness/tdx/{bid}")
    def tdx_batch(bid: str):
        if not BID.match(bid):
            raise Err(404, "NOT_FOUND")
        p = os.path.join(ctx.anchor_dir, bid + ".tdx.json")
        if not os.path.isfile(p):
            raise Err(404, "NOT_FOUND")
        with open(p) as f:
            return JSONResponse(json.load(f))
    return r


def main(argv=None):
    """python -m app.tee keygen PATH   - create the key inside the CVM (no-op if it exists). Prints only the public key."""
    import sys
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] != "keygen":
        print("usage: python -m app.tee keygen PATH")
        return 2
    from app.hub import load_witness_key
    made = ensure_key(argv[1])
    print(("created " if made else "exists ") + load_witness_key(argv[1]).pub.hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
