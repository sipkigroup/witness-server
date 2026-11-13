"""Node 2 work loop (0.2.27): start -> key K2 in memory -> SEV-SNP report bound to K2 -> hello to node 1 (resume the chain of the previous
instance, or start a new one) -> every DW_NODE2_EVERY seconds: take the next batch, check it, co-sign or sign an alarm, send it back.
Run: python -m node2.worker   (environment below; the container image: cloud/node2/Dockerfile)

  DW_NODE1_URL         https://<node 1>          node 1 base URL (outgoing calls only; node 2 listens on nothing)
  DW_NODE1_PUB         hex, 32 bytes             node 1's witness key, pinned in the container's environment: every checkpoint
                                                 signature is checked against it (a wrong pin = every batch is rejected, nothing signed)
  DW_NODE2_TOKEN_FILE  path                      the feed token in a file, or
  DW_NODE2_TOKEN       string (>= 32 chars)      the feed token itself (ACI: a secureValue environment variable)
  DW_NODE2_SNP         sev-guest | fake          report provider; fake = TESTS ONLY (no AMD signature: users see NOT COVERED)
  DW_NODE2_EVERY       seconds (default 60)
  DW_NODE2_LISTEN      port (default empty = off) the public READ-ONLY view (stage 1, 2026-10-23): GET /node2 and
                                                 GET /node2/attestation, JSON, nothing else. Why node 2 serves it itself: node 1 can
                                                 drop node 2's alarms from its own /v1/node2/alarms; here they cannot be dropped.
                                                 Every object in it is signed by K2 or AMD, so the channel itself needs no trust.

Rules this loop keeps (OTCHET-STEND-2026-10-22.md):
  - the key never leaves memory; a restart is a NEW key, continued only through Cosigner.resume (never Cosigner(state=...));
  - resume only from an instance whose attestation shows the SAME policy (HOST_DATA) and measurement: trust is in the code, not in a key;
  - a snapshot that does not match the last cosig (RESUME_MISMATCH) stops the loop: a silent fresh start would fork the chain;
  - the consistency proof is asked from node 2's OWN sizes ({ledger: size}), so a node-1 crash cannot cause false alarms;
  - (stage 1) ONE key per process: node 1 being down or off (DW_NODE2 off -> 404) is retried with the same key (a fresh report with a
    new t when the old one is older than HELLO_REFRESH_S, node 1 refuses attestations > 600 s off); a fatal refusal (other node-1 key,
    RESUME_*) halts co-signing but keeps the view up with the reason, so the container does not restart into a new key."""
import base64
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

import cbor2

from node2 import attest, cosign


VERSION = "node2-0.3.0"
HELLO_REFRESH_S = 300
KEEP_COSIGS = 50
KEEP_ALARMS = 200


class WorkerError(Exception):
    pass


class FatalError(WorkerError):
    """Retrying cannot help (another node-1 key, an unbound report, a resume that would fork the chain): halt, keep the view."""


def b64(b):
    return base64.b64encode(bytes(b)).decode()


def unb64(s):
    return base64.b64decode(s, validate=True)


def urllib_http(base, token, timeout=30):
    """-> http(method, path, body) -> (status, json). Outgoing HTTPS only; the token goes in the Authorization header."""
    def call(method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base.rstrip("/") + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"null")
            except ValueError:
                return e.code, None
    return call


def batch_from_json(j):
    return {"bid": j["bid"], "t": j["t"], "root": unb64(j["root_b64"]), "leaves": [unb64(x) for x in j["leaves_b64"]],
            "checkpoints": [{"cose": unb64(c["cose_b64"]), "proof": [unb64(p) for p in c.get("proof_b64", [])]} for c in j["checkpoints"]],
            "extra": int(j.get("extra", 0))}


class Worker:
    def __init__(self, http, node1_pub, report_fn, context=None, clock=time.time, log=None, platform="aci-sevsnp"):
        """report_fn(report_data 64 bytes) -> SNP report; context = {"policy": rego bytes, "vcek": PEM/DER, "chain": PEM} (ACI security context)."""
        self.http, self.k1, self.report_fn, self.ctx = http, node1_pub, report_fn, context or {}
        self.clock, self.platform = clock, platform
        self.log = log or (lambda *a: print(*a, file=sys.stderr, flush=True))
        self.cos = None
        self.cursor = None
        self.doc = None
        self.stats = {"cosig": 0, "alarm": 0, "reject": 0, "error": 0}
        self.signer = None
        self.status, self.reason, self.last_error, self.last_ok = "starting", None, None, None
        self.started = int(self.clock())
        self.recent, self.alarms_seen = [], []       # what node 2 itself signed in this process (the view; node 1 cannot drop it)
        self.lock = threading.Lock()

    def _call(self, method, path, body=None):
        st, j = self.http(method, path, body)
        if st != 200:
            raise WorkerError("%s %s -> %s %s" % (method, path, st, (j or {}).get("error") if isinstance(j, dict) else j))
        return j

    def prepare(self):
        """Key K2 (once per process) and a report bound to it with t = now."""
        if self.signer is None:
            self.signer = cosign.Signer()
        t = int(self.clock())
        rd = attest.report_data(self.signer.pub, self.k1, t)
        rep = self.report_fn(rd)
        f = attest.fields(rep)
        if f["report_data"] != rd:
            raise FatalError("the report does not carry our report_data")
        doc = {"scheme": attest.SCHEME, "platform": self.platform, "pub": self.signer.pub, "node1_pub": self.k1, "t": t, "report": rep,
               "policy": self.ctx.get("policy", b"")}
        if self.ctx.get("vcek"):
            doc["vcek"], doc["chain"] = self.ctx["vcek"], self.ctx["chain"]
        with self.lock:
            self.doc, self.status = doc, "waiting for node 1"
        return f

    def hello(self):
        if self.doc is None or int(self.clock()) - self.doc["t"] > HELLO_REFRESH_S:
            self.prepare()
        f = attest.fields(self.doc["report"])
        signer = self.signer
        j = self._call("POST", "/internal/node2/hello", {"attestation": attest.doc_to_json(self.doc)})
        if not isinstance(j, dict) or bytes.fromhex(j.get("node1_pub_hex") or "") != self.k1:
            raise FatalError("node 1 answers with another witness key than the pinned DW_NODE1_PUB")
        rs = j.get("resume")
        if rs:
            old = attest.doc_from_json(rs["old_attestation"]) if rs.get("old_attestation") else None
            if old is None:
                raise FatalError("RESUME_NO_ATTESTATION: node 1 has a chain but no attestation of the key that signed it")
            of = attest.fields(old["report"])
            if of["host_data"] != f["host_data"] or of["measurement"] != f["measurement"]:
                raise FatalError("RESUME_OTHER_CODE: the previous instance ran another policy or measurement; not continuing its chain")
            try:
                cos = cosign.Cosigner.resume(self.k1, signer, cbor2.loads(unb64(rs["snapshot_b64"])), unb64(rs["last_cosig_b64"]),
                                             bytes.fromhex(rs["old_pub_hex"]))
            except (cosign.Reject, KeyError, TypeError, ValueError) as e:
                raise FatalError("RESUME_MISMATCH: %s (stopping: a fresh start would fork the co-signature chain)" % e)
            self.log("node2: resumed chain at n=%d (previous key %s...)" % (cos.n, rs["old_pub_hex"][:16]))
        else:
            cos = cosign.Cosigner(self.k1, signer)
            self.log("node2: new chain (no previous co-signature at node 1)")
        with self.lock:
            self.cos, self.status, self.last_ok = cos, "co-signing", int(self.clock())
        return signer.pub

    def start(self):
        self.prepare()
        return self.hello()

    def halt(self, why):
        with self.lock:
            self.status, self.reason = "halted", str(why)
        self.log("node2: HALTED: %s (the view stays up; co-signing stopped)" % why)

    def connect(self, every=60, sleep=time.sleep, limit=None):
        """hello until it works (same key), or until a fatal refusal (-> halted). -> True if co-signing."""
        i = 0
        while limit is None or i < limit:
            i += 1
            try:
                self.hello()
                return True
            except FatalError as e:
                self.halt(e)
                return False
            except (WorkerError, OSError, ValueError, KeyError, TypeError, attest.AttestError) as e:
                self.stats["error"] += 1
                with self.lock:
                    self.last_error = "%s: %s" % (int(self.clock()), str(e)[:300])
                self.log("node2: hello: %s (retry in %d s)" % (e, every))
            sleep(every)
        return False

    def _remember(self, kind, bid, out):
        with self.lock:
            item = {"kind": kind, "bid": bid, "cose_b64": b64(out), "seen_t": int(self.clock())}
            if kind == "cosig":
                item["n"] = self.cos.n
                self.recent = (self.recent + [item])[-KEEP_COSIGS:]
            else:
                self.alarms_seen = (self.alarms_seen + [item])[-KEEP_ALARMS:]
            self.last_ok = int(self.clock())

    def view(self, full=True):
        """The public read-only view (JSON-able). Everything in it is checkable offline: verify_node2.py."""
        with self.lock:
            doc = attest.doc_to_json(self.doc) if self.doc else None
            if not full:
                return {"attestation": doc}
            cos = self.cos
            return {"v": VERSION, "status": self.status, "reason": self.reason, "started": self.started, "last_ok": self.last_ok,
                    "last_error": self.last_error, "k2_pub_hex": self.signer.pub.hex() if self.signer else None,
                    "k2_kid_hex": self.signer.kid.hex() if self.signer else None, "node1_pub_hex": self.k1.hex(),
                    "chain": {"n": cos.n, "head_hex": cos.head.hex(), "alarms": cos.alarms, "alarm_head_hex": cos.alarm_head.hex(),
                              "ledgers": len(cos.ledgers)} if cos else None,
                    "stats": dict(self.stats), "attestation": doc, "cosigs": list(self.recent), "alarms": list(self.alarms_seen)}

    def step(self):
        """One batch. -> "cosig" | "alarm" | "reject:<code>" | None (nothing new)."""
        sizes = {lid.hex(): v[0] for lid, v in self.cos.ledgers.items()}
        j = self._call("POST", "/internal/node2/feed", {"after": self.cursor, "sizes": sizes})
        if not j.get("batch"):
            return None
        try:
            batch = batch_from_json(j["batch"])
        except (KeyError, TypeError, ValueError):
            self.stats["reject"] += 1
            self.cursor = j["batch"].get("bid") if isinstance(j["batch"], dict) else self.cursor
            return "reject:FEED_MALFORMED"
        try:
            kind, out = self.cos.feed(batch)
        except cosign.Reject as e:
            self.stats["reject"] += 1
            self.log("node2: batch %s rejected: %s" % (batch["bid"], e))
            self.cursor = batch["bid"]
            return "reject:%s" % e
        body = {"kind": kind, "bid": batch["bid"], "cose_b64": b64(out)}
        if kind == "cosig":
            body["snapshot_b64"] = b64(cbor2.dumps(self.cos.snapshot(), canonical=True))
        self._call("POST", "/internal/node2/submit", body)
        self._remember(kind, batch["bid"], out)
        self.stats[kind] += 1
        if kind == "alarm":
            self.log("node2: ALARM for batch %s" % batch["bid"])
        self.cursor = batch["bid"]
        return kind

    def drain(self, limit=10000):
        out = []
        for _ in range(limit):
            r = self.step()
            if r is None:
                break
            out.append(r)
        return out

    def run_forever(self, every=60, sleep=time.sleep, limit=None):
        i = 0
        while limit is None or i < limit:
            i += 1
            try:
                self.drain()
            except Exception as e:  # noqa: BLE001 -- a crash = container restart = a NEW key; count it, keep the key, go on
                self.stats["error"] += 1
                with self.lock:
                    self.last_error = "%s: %s" % (int(self.clock()), str(e)[:300])
                self.log("node2: %s" % e)
            sleep(every)


MAX_CONN = 32


def serve_view(worker, port, host="0.0.0.0"):
    """Public read-only view: GET /node2 and GET /node2/attestation (JSON). No request body is read, no other path or method
    exists, at most MAX_CONN connections at a time, 5 s socket timeout. Returns the server (serve_forever runs in a daemon thread)."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    slots = threading.BoundedSemaphore(MAX_CONN)

    class H(BaseHTTPRequestHandler):
        server_version, sys_version, timeout = "node2", "", 5
        protocol_version = "HTTP/1.0"

        def _send(self, code, obj, head=False):
            b = json.dumps(obj, sort_keys=True).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if not head:
                self.wfile.write(b)

        def _route(self, head):
            path = self.path.split("?", 1)[0]
            if path in ("/node2", "/node2/"):
                return self._send(200, worker.view(), head)
            if path == "/node2/attestation":
                return self._send(200, worker.view(full=False), head)
            return self._send(404, {"error": "NOT_FOUND"}, head)

        def do_GET(self):
            self._route(False)

        def do_HEAD(self):
            self._route(True)

        def log_message(self, *a):
            pass

    class S(ThreadingHTTPServer):
        daemon_threads = True

        def process_request(self, request, client_address):
            if not slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            super().process_request(request, client_address)

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                slots.release()

    srv = S((host, int(port)), H)
    threading.Thread(target=srv.serve_forever, daemon=True, name="node2-view").start()
    return srv


def _token(e):
    if e.get("DW_NODE2_TOKEN_FILE"):
        with open(e["DW_NODE2_TOKEN_FILE"]) as f:
            return f.read().strip()
    return (e.get("DW_NODE2_TOKEN") or "").strip()


def main(env=None, forever=True):
    e = os.environ if env is None else env
    from node2 import snp_get
    url, pub = e.get("DW_NODE1_URL", ""), e.get("DW_NODE1_PUB", "")
    if not url.startswith("https://") or len(pub) != 64:
        print("DW_NODE1_URL (https://...) and DW_NODE1_PUB (64 hex) are required", file=sys.stderr)
        return 2
    try:
        token = _token(e)
    except OSError as ex:
        print("DW_NODE2_TOKEN_FILE unreadable: %s" % type(ex).__name__, file=sys.stderr)
        return 2
    if len(token) < 32:
        print("the feed token (DW_NODE2_TOKEN_FILE or DW_NODE2_TOKEN) must be at least 32 characters", file=sys.stderr)
        return 2
    prov = (e.get("DW_NODE2_SNP") or "sev-guest").lower()
    if prov == "sev-guest":
        report_fn, ctx_fn = snp_get.dev_sev_guest, snp_get.aci_context
    elif prov == "fake":
        report_fn, ctx_fn = snp_get.fake, (lambda: {"policy": b""})
        print("node2: DW_NODE2_SNP=fake -- TEST MODE, the attestation proves nothing", file=sys.stderr)
    else:
        print("DW_NODE2_SNP must be sev-guest|fake", file=sys.stderr)
        return 2
    every = int(e.get("DW_NODE2_EVERY") or 60)
    w = Worker(urllib_http(url, token), bytes.fromhex(pub), report_fn, None)
    if e.get("DW_NODE2_LISTEN"):
        serve_view(w, int(e["DW_NODE2_LISTEN"]))
    try:
        w.ctx = ctx_fn()
        w.prepare()
        print("node2: K2 %s (kid %s), %s" % (w.signer.pub.hex(), w.signer.kid.hex(), VERSION), file=sys.stderr, flush=True)
    except Exception as ex:  # noqa: BLE001 -- no report = nothing to sign with; say why on the view and in the log
        w.halt("SNP: %s" % ex)
    if w.status != "halted" and w.connect(every):
        w.run_forever(every)
    while forever:                                   # halted: keep the view (and the reason) up; no restart into a new key
        time.sleep(3600)
    return 1 if w.status == "halted" else 0


if __name__ == "__main__":
    sys.exit(main())
