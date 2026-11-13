"""WitnessHub: one svidetel_v4 Ledger per tenant, built lazily and kept for `ttl` seconds.
The ledger path is built ONLY from the account id taken from the database (uuid4 hex), never from input."""
import json
import os
import re
import threading
import time

from app import _paths  # noqa: F401
from svidetel_v4 import cose
from svidetel_v4.ledger import Ledger

from app.registry_wa import QuorumRegistry

ACC_RE = re.compile(r"^[0-9a-f]{32}$")


def credential_record(c):
    """Registry record (3.4) of one credentials row: what a wa-sig by that passkey is checked against."""
    from webauthn.helpers import bytes_to_base64url
    return {"alg": "ES256", "pub": bytes(c["pub"]).hex(),
            "webauthn": {"rp_id": c["rp_id"], "origins": [c["origin"]], "credential_id": bytes_to_base64url(bytes(c["credential_id"]))}}


class KeyFileError(Exception):
    pass


class DataDirBusy(Exception):
    """RT-SUP 29.10: another server process holds this data dir (see claim_data_dir)."""


_HELD = {}          # realpath of a data dir -> (pid, fd of its server.lock) held by this process


def claim_data_dir(data_dir):
    """RT-SUP 29.10: ONE server process per data dir. hub.lock is a threading.RLock of this process: it orders the decisions of one tenant
    (quorum replacement, approve, the ledger append) only among the threads of ONE process. A second process (uvicorn --workers N, a
    second instance on the same volume) would hold its own locks and its own ledger cache and race the first through the database and
    the ledger files. So a second process is REFUSED at start (fail closed), not warned about: a warning would let both run and split the
    decisions. flock on <data_dir>/server.lock: the kernel drops it when the process dies (no stale lock after a crash). The same process
    may claim again (a test restarting the app). A process forked AFTER the claim shares the lock: WitnessHub.lock refuses there.
    Not covered: CLI tools (app.jobs / app.migrate) run as their own process take no claim."""
    path = os.path.realpath(data_dir)
    held = _HELD.get(path)
    if held and held[0] == os.getpid():
        return
    try:
        import fcntl
    except ImportError:                         # no flock (Windows): a warning is all this platform gets
        from app.log import log
        log("WARN", "server.lock: no flock on this platform; run ONE server process per data dir (hub.lock is per process)")
        return
    os.makedirs(path, exist_ok=True)
    fd = os.open(os.path.join(path, "server.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise DataDirBusy("another server process uses %s (hub.lock is per process: run ONE process, no --workers)" % data_dir)
    os.ftruncate(fd, 0)
    os.write(fd, str(os.getpid()).encode())
    _HELD[path] = (os.getpid(), fd)


def release_data_dir(data_dir):
    """Give the claim of claim_data_dir back (closes the server.lock descriptor). A server holds it for the life of its process and never
    calls this; a test that builds many apps in one process does, or every app leaks one descriptor."""
    held = _HELD.pop(os.path.realpath(data_dir), None)
    if held and held[0] == os.getpid():
        try:
            os.close(held[1])
        except OSError:
            pass


def load_witness_key(path):
    """Ed25519 seed (32 bytes, hex text) from a read-only file. No file / bad file -> error, never a generated key."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            seed = bytes.fromhex(f.read().strip())
    except (OSError, ValueError) as e:
        raise KeyFileError("witness key file unusable: %s (%s)" % (path, type(e).__name__))
    if len(seed) != 32:
        raise KeyFileError("witness key must be 32 bytes (64 hex)")
    return cose.Key.from_seed(cose.ALG_EDDSA, seed)


class WitnessHub:
    def __init__(self, cfg, db, witness_key, ttl=900, clock=time.time):
        self.cfg, self.db, self.wk, self.ttl, self.clock = cfg, db, witness_key, ttl, clock
        self.root = os.path.join(cfg.data_dir, "ledgers")
        self._cache = {}                    # account_id -> [Ledger, last_used]
        self._locks = {}                    # account_id -> RLock (composite operations on one tenant)
        self._g = threading.Lock()
        self._pid = os.getpid()

    def lock(self, account_id):
        """ONLY ONE PROCESS (RT-SUP 29.10): a threading.RLock orders the threads of this process, nothing else. The server claims its
        data dir at start (claim_data_dir: a second process is refused); a process forked after this hub was built is refused here."""
        if os.getpid() != self._pid:
            raise RuntimeError("hub.lock taken in a forked process (pid %d, built in %d): run ONE server process" % (os.getpid(), self._pid))
        with self._g:
            return self._locks.setdefault(account_id, threading.RLock())

    def entry_of(self, account_id):
        """Registry record 3.4 of the tenant's passkey (from credentials + registry_log)."""
        r = self.db.one("SELECT entry_json FROM registry_log WHERE account_id=? ORDER BY seq DESC LIMIT 1", (account_id,))
        return json.loads(r["entry_json"]) if r else None

    def active_keys(self, account_id):
        """0.2.2: {kid: registry record} of the passkeys of the account's own user that are active now (not removed). A solo account
        is signed by any of them; the pinned record of registration stays the account's identity (entry_of)."""
        out = {}
        for c in self.db.q("SELECT * FROM credentials WHERE user_id=? AND revoked_at IS NULL ORDER BY id", (account_id,)):
            out[bytes(c["kid"])] = credential_record(c)
        return out

    def key_changed(self, account_id):
        """A passkey was added or removed: the cached ledger's registry gets the new key set (same Ledger object, same file)."""
        with self._g:
            hit = self._cache.get(account_id)
        if hit:
            hit[0].reg.keys = self.active_keys(account_id)

    def chain_of(self, account_id):
        """0.2: the organisation's policy chain [(policy, envelope, t)], version 1 first; [] = solo account (0.1 behaviour)."""
        return [(bytes(r["policy"]), bytes(r["envelope"]), r["t"])
                for r in self.db.q("SELECT policy, envelope, t FROM org_policies WHERE account_id=? ORDER BY ver", (account_id,))]

    def policy_changed(self, account_id):
        """A new policy version: the cached ledger gets the new chain in its registry (same Ledger object, same file)."""
        with self._g:
            hit = self._cache.get(account_id)
        if hit:
            hit[0].reg.chain = self.chain_of(account_id)

    def ledger_dir(self, account_id):
        if not ACC_RE.match(account_id):
            raise ValueError("bad account id")
        return os.path.join(self.root, account_id)

    def ledger(self, account_id):
        now = self.clock()
        with self._g:
            for k in [k for k, v in self._cache.items() if now - v[1] > self.ttl]:
                del self._cache[k]
            hit = self._cache.get(account_id)
            if hit:
                hit[1] = now
                return hit[0]
        acc = self.db.one("SELECT principal, erased_at FROM accounts WHERE id=?", (account_id,))
        if acc and acc["erased_at"] is not None:
            from app.context import LedgerErased
            raise LedgerErased(account_id)                  # never open (= create) a journal file of an erased account
        entry = self.entry_of(account_id)
        if not acc or not entry:
            raise KeyError(account_id)
        L = Ledger(self.ledger_dir(account_id), self.wk, QuorumRegistry.for_account(acc["principal"], entry, self.chain_of(account_id), wa_with_policy=False,
                                                                           keys=self.active_keys(account_id)),
                   acc["principal"],
                   clock=self.clock, require_cose=True, independence="separate-party")
        with self._g:
            self._cache[account_id] = [L, now]
        return L

    def forget(self, account_id):
        """0.2.23: drop the cached ledger object of an account that was deleted (the file stays)."""
        with self._g:
            self._cache.pop(account_id, None)

    def skeleton(self, account_id):
        """0.2.34: the hash skeleton of an erased account's journal (app/erase.py) or None."""
        from app import erase
        return erase.load_skeleton(self, account_id)

    def count(self):
        return self.db.one("SELECT COUNT(*) AS n FROM accounts")["n"]

    def has_entries(self, account_id):
        r = self.db.one("SELECT erased_at FROM accounts WHERE id=?", (account_id,))
        if r is not None and r["erased_at"] is not None:
            return False
        p = os.path.join(self.ledger_dir(account_id), "ledger.cose")
        return os.path.exists(p) and os.path.getsize(p) > 0
