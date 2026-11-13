"""Application context: config, database, hub, limiters. Built once per app."""
import collections
import hashlib
import os
import re
import threading
import time

from app import _paths  # noqa: F401
from app.config import Config
from app.db import DB
from app.hub import WitnessHub, load_witness_key


_RID_CI = re.compile(r"[rR]_[A-Za-z2-7]{1,40}")


def canon_rid(rid):
    """0.2.43b: a receipt id from a client (link, path, body) is matched without regard to case: OpenShell lowercases the reason code
    (a-z0-9_ only), so `r_abc...` must find `r_ABC...`. Only the case is folded; anything not of the form r_ + base32 comes back unchanged
    (and is then simply not found). Non-strings are returned as they are."""
    if isinstance(rid, str) and _RID_CI.fullmatch(rid):
        return "r_" + rid[2:].upper()
    return rid


class Err(Exception):
    def __init__(self, status, code, detail="", extra=None):
        self.status, self.code, self.detail = status, code, detail
        self.extra = extra          # 0.2.39: more fields of the error body (e.g. retry_after: also sent as the Retry-After header)


class LedgerErased(Err, KeyError):
    """0.2.34: the account was deleted; its journal is replaced by a hash skeleton (app/erase.py). 410 on the API."""
    def __init__(self, account_id=""):
        Err.__init__(self, 410, "LEDGER_ERASED", "the account was deleted: only the hash skeleton of its journal is kept")
        KeyError.__init__(self, account_id)


INT_MAX = 2 ** 63 - 1       # SQLite INTEGER range; also the ceiling for any number a client may send


def check_json(doc, int_code="BAD_REQUEST"):
    """Reject what the rest of the server cannot store or serialise: strings that are not valid Unicode (lone surrogates), floats that are
    inf/nan, integers outside int64. Iterative (the JSON parser already bounded the depth). Raises Err(400)."""
    stack = [doc]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            try:
                v.encode("utf-8")
            except UnicodeEncodeError:
                raise Err(400, "BAD_REQUEST", "string is not valid Unicode (lone surrogate)")
        elif isinstance(v, bool) or v is None:
            continue
        elif isinstance(v, int):
            if not -INT_MAX - 1 <= v <= INT_MAX:
                raise Err(400, int_code, "integer outside the 64-bit range")
        elif isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise Err(400, "BAD_REQUEST", "number must be finite")
        elif isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)


class Limiter:
    """Sliding window per key (in memory; one process)."""

    SWEEP_EVERY_S = 300

    def __init__(self):
        self.w = collections.defaultdict(collections.deque)
        self.win = {}                    # key -> its window (04.11, privacy D4: a key whose window is over is dropped, IP keys included)
        self.l = threading.Lock()
        self._swept = time.time()

    def sweep(self, now=None):
        """Drop keys with no timestamp inside their window. Runs from the hourly job and every SWEEP_EVERY_S on use. -> keys dropped."""
        now = time.time() if now is None else now
        with self.l:
            return self._sweep(now)

    def _sweep(self, now):
        self._swept = now
        gone = [k for k, d in self.w.items() if not d or d[-1] <= now - self.win.get(k, 0)]
        for k in gone:
            self.w.pop(k, None)
            self.win.pop(k, None)
        return len(gone)

    def _seen(self, key, window, now):
        """Called under self.l, after the key's deque was used (a key just hit keeps its newest stamp: never dropped here)."""
        self.win[key] = max(window, self.win.get(key, 0))
        if now - self._swept >= self.SWEEP_EVERY_S:
            self._sweep(now)

    def allowed(self, key, limit, window, now=None):
        """0.2.12: would `hit` pass? (nothing is counted: the caller counts only failures, with hit)"""
        now = time.time() if now is None else now
        with self.l:
            d = self.w[key]
            while d and d[0] <= now - window:
                d.popleft()
            ok = len(d) < limit
            self._seen(key, window, now)
            return ok

    def reset_in(self, key, limit, window, now=None):
        """0.2.39: seconds until `allowed` passes again for this key (0 = it passes now)."""
        now = time.time() if now is None else now
        with self.l:
            d = self.w[key]
            while d and d[0] <= now - window:
                d.popleft()
            self._seen(key, window, now)
            if len(d) < limit:
                return 0
            return max(1, int(d[len(d) - limit] + window - now + 0.999))

    def hit(self, key, limit, window, now=None, weight=1):
        """weight (0.2.17, R9-02): a request that costs more takes more of the window (a long judge body)."""
        now = time.time() if now is None else now
        with self.l:
            d = self.w[key]
            while d and d[0] <= now - window:
                d.popleft()
            if len(d) + max(1, weight) > limit:
                self._seen(key, window, now)
                return False
            d.extend([now] * max(1, weight))
            self._seen(key, window, now)
            return True


class Ctx:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        os.makedirs(cfg.data_dir, exist_ok=True)
        if cfg.tee == "on":
            from app import tee
            tee.ensure_key(cfg.witness_key_file)                  # TEE mode: the key is born here, inside the CVM, and never leaves it
        self.wk = load_witness_key(cfg.witness_key_file)          # raises KeyFileError: the process does not start
        self.tee = None
        if cfg.tee == "on":
            self.tee = tee.start(self)                            # TeeError (a ConfigError): no valid quote -> the process does not start
        self.db = DB(os.path.join(cfg.data_dir, "db.sqlite"))
        from app import reglog
        self.db.reg_tag_key = reglog.tag_key(cfg.key_pepper)     # 0.2.12 (R7-04): ownership tags of registry rows; older rows filled once
        reglog.backfill(self.db)
        self.hub = WitnessHub(cfg, self.db, self.wk)
        self.limiter = Limiter()
        self.anchor_dir = os.path.join(cfg.data_dir, "anchors")
        os.makedirs(self.anchor_dir, exist_ok=True)

    def key_hash(self, key: str) -> bytes:
        return hashlib.sha256(self.cfg.key_pepper.encode() + key.encode()).digest()
