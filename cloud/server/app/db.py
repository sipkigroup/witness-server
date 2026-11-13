"""SQLite (WAL) index. 0.2.18: ONE writer connection guarded by `lock` (re-entrant; every write, every `tx()` and every `with db.lock:`
block), and a pool of READ connections: a plain SELECT outside the writer lock runs in parallel with the other readers and the writer
(WAL), always on committed data (a pool of at most READERS connections). A thread that holds the writer lock reads on the writer connection (it sees its own transaction).
Atomicity that 0.2.17 got from the global lock is kept by statements and transactions: a check-and-set is one conditional UPDATE or a
`tx()` (BEGIN IMMEDIATE); a multi-statement read-modify-write of one tenant stays under that tenant's hub.lock.
Each write bumps the write generation of the table it names (`gen`), after it is committed: `cached()` answers from memory only while the
generation it read before its SELECT is still current, so a cached row is never older than the last committed write of its table.
`hook_rounds` (R9-04: judge rounds without an action) are buffered (RoundBuffer) and written in one transaction per batch; the quota counts
the buffer too, and any other read of the table writes the buffer first."""
import atexit
import collections
import os
import re
import sqlite3
import threading
import time
import weakref
from contextlib import contextmanager

SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
_WRITES = re.compile(r"^\s*(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|REPLACE\s+INTO|UPDATE(?:\s+OR\s+\w+)?|DELETE\s+FROM|ALTER\s+TABLE|DROP\s+TABLE(?:\s+IF\s+EXISTS)?|CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?)\s+[\"`]?(\w+)", re.I)
CACHE_TTL_S = 5.0
READERS = int(os.environ.get("DW_DB_READERS", "1"))                   # read connections (DW_DB_READERS). One by default: under the GIL parallel tiny SELECTs convoy (OTCHET-0.2.18)
MMAP = int(os.environ.get("DW_DB_MMAP", str(256 * 1024 * 1024)))
_READ = re.compile(r"^\s*(?:SELECT|WITH|PRAGMA\s+table_info|EXPLAIN)\b", re.I)


class WriterLock:
    """Re-entrant lock that knows whether the calling thread holds it (reads inside a held block use the writer connection)."""

    def __init__(self):
        self._l = threading.RLock()
        self._tl = threading.local()

    def held(self):
        return getattr(self._tl, "n", 0) > 0

    def acquire(self, blocking=True, timeout=-1):
        ok = self._l.acquire(blocking, timeout)
        if ok:
            self._tl.n = getattr(self._tl, "n", 0) + 1
        return ok

    def release(self):
        self._tl.n -= 1
        self._l.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
        return False


class RoundBuffer:
    """0.2.18: judge rounds that end without an action (`need`, `refuse`; R9-04) are kept here and written in ONE transaction per batch
    (at most FLUSH_S old, at most FLUSH_N rows) instead of two autocommit statements per round. They count in the quota (`count`) before
    they are written; a row leaves the buffer only after its batch is committed, so a count never misses a round (it may count a round
    twice for the instant between that commit and its removal, which only errs on the strict side)."""
    FLUSH_S = 0.5
    FLUSH_N = 256

    def __init__(self, db):
        self.db = db
        self.l = threading.Lock()
        self.fl = threading.Lock()            # one flush at a time
        self.pending = []                     # (account_id, agent_id, t, kind, code)
        self.inflight = []
        self.oldest = None
        self.last_purge = 0

    def add(self, account_id, agent_id, t, kind, code=None):
        with self.l:
            self.pending.append((account_id, agent_id, t, kind, code))
            if self.oldest is None:
                self.oldest = time.time()
            due = len(self.pending) >= self.FLUSH_N or time.time() - self.oldest >= self.FLUSH_S
        if due:
            self.flush()

    def count(self, account_id, agent_id, since):
        """-> (rounds of the account, rounds of the agent) after `since` that are not yet (or just now) in the table."""
        with self.l:
            rows = self.pending + self.inflight
        acc = sum(1 for r in rows if r[0] == account_id and r[2] > since)
        ag = sum(1 for r in rows if r[1] == agent_id and r[2] > since)
        return acc, ag

    def __len__(self):
        return len(self.pending) + len(self.inflight)

    def flush(self):
        with self.fl:
            with self.l:
                if not self.pending:
                    return 0
                self.inflight, self.pending, self.oldest = self.pending, [], None
                batch = self.inflight
            try:
                with self.db.lock:
                    self.db.c.execute("BEGIN IMMEDIATE")
                    try:
                        self.db.c.executemany("INSERT INTO hook_rounds(account_id,agent_id,t,kind,code) VALUES(?,?,?,?,?)", batch)
                        t = int(time.time())
                        if t - self.last_purge >= 60:            # only the last day counts: older rows go, once a minute, not per round
                            self.db.c.execute("DELETE FROM hook_rounds WHERE t<?", (t - 2 * 86400,))
                            self.last_purge = t
                    except BaseException:
                        self.db.c.execute("ROLLBACK")
                        raise
                    self.db.c.execute("COMMIT")
                    self.db.gen["hook_rounds"] += 1
            except BaseException:
                with self.l:                   # not written: back to the buffer (still counted), next flush retries
                    self.pending[:0], self.inflight = batch, []
                    self.oldest = self.oldest or time.time()
                raise
            with self.l:
                self.inflight = []
            return len(batch)


_LIVE = weakref.WeakSet()


def _flush_all():
    for d in list(_LIVE):
        try:
            d.rounds.flush()
        except Exception:  # noqa: BLE001  -- a closed or broken database: nothing to keep
            pass


def _purge_runs(last=[0.0]):
    """RT №8 N4: expired run_checks rows (0.2.63) are swept by this existing flusher thread, once a minute, not only by runcheck.create()."""
    if time.time() - last[0] < 60:
        return
    last[0] = time.time()
    for d in list(_LIVE):
        try:
            d.n("DELETE FROM run_checks WHERE exp<?", (int(time.time()),))
        except Exception:  # noqa: BLE001  -- closed database, or a schema without the table
            pass


def _flusher():
    while True:
        time.sleep(RoundBuffer.FLUSH_S)
        _flush_all()
        _purge_runs()


threading.Thread(target=_flusher, name="dw-db-rounds", daemon=True).start()
atexit.register(_flush_all)


class NeedsMigration(Exception):
    pass


class DB:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path
        self.c = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)      # the ONE writer
        self.c.row_factory = sqlite3.Row
        self.lock = WriterLock()
        self.gen = collections.defaultdict(int)        # table -> write generation (caches compare it; see cached())
        self._rpool = [None] * max(1, READERS)          # read connections, made on first use
        self._rlocks = [threading.Lock() for _ in self._rpool]
        self._cache = {}
        self.rounds = RoundBuffer(self)
        self.tx_dirty = None
        with self.lock:
            self.c.execute("PRAGMA journal_mode=WAL")
            self.c.execute("PRAGMA mmap_size=%d" % MMAP)
            self.c.execute("PRAGMA secure_delete=ON")      # 0.2.34: deleted rows (recipients, previews) are overwritten with zeros, not left in free pages
            self.c.execute("PRAGMA foreign_keys=OFF")
            tables = {r["name"] for r in self.c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "accounts" in tables and ("schema_migrations" not in tables or not self.c.execute(
                    "SELECT 1 FROM schema_migrations WHERE name='002_org'").fetchone()):
                self.c.close()               # 0.2: a 0.1 database is never migrated behind the owner's back (ARHITEKTURA-0.2 11, risk 2)
                raise NeedsMigration("database %s is 0.1: stop, then run  python -m app.migrate --db %s --backup <copy>" % (path, path))
            with open(SCHEMA, encoding="utf-8") as f:
                self.c.executescript(f.read())
            # databases created before the review of 2026-10-18 (R-03, R-05): add the new columns
            for table, col, typ in (("mandates", "toolmap_sha256", "TEXT"), ("actions", "text_preview", "TEXT"), ("sessions", "stepup_at", "INTEGER"),
                                    ("push_subs", "user_id", "TEXT"),
                                    ("mandates", "patterns_sha256", "TEXT"), ("mandates", "advisor_sha256", "TEXT"), ("mandates", "patterns_items", "TEXT"), ("mandates", "gateway_doc", "TEXT"), ("actions", "promise", "BLOB"),      # 0.2.4: gateway document inside the signature, inclusion promise; 0.2.0: the person who subscribed (pushes go to people, by role)
                                    ("credentials", "label", "TEXT"), ("credentials", "revoked_at", "INTEGER"),     # 0.2.3: recovery, devices
                                    ("credentials", "last_used_at", "INTEGER"), ("credentials", "added_by", "TEXT"),
                                    ("sessions", "scope", "TEXT"), ("sessions", "credential_id", "INTEGER"),
                                    ("actions", "cmd_meta", "TEXT"), ("actions", "allowances", "TEXT"), ("actions", "covered_by", "TEXT"),     # 0.2.10
                                    ("registry_log", "tag", "BLOB"), ("registry_log", "hash2", "BLOB"),                                          # 0.2.12
                                    ("actions", "exec_json", "TEXT"), ("credentials", "device", "TEXT"), ("approvals", "signers", "TEXT"),       # 0.2.13
                                    ("approvals", "on_behalf_of", "TEXT"), ("actions", "level_min", "TEXT"),
                                    ("users", "phone_ever", "INTEGER"), ("credentials", "phone_nb", "INTEGER"),
                                    ("credentials", "vouched_by", "BLOB"),
                                    ("credentials", "last_sig", "BLOB"),      # 0.2.14 (R8-06); 0.2.17 (R9-03); 0.2.21: hash of the last accepted assertion
                                    ("actions", "taint", "INTEGER"), ("actions", "preview_cut", "INTEGER"), ("agents", "frozen_at", "INTEGER"),   # 0.2.24
                                    ("actions", "hold_reason", "TEXT"),                                                                          # 0.2.25
                                    ("org_settings", "refusal_block_s", "INTEGER"), ("actions", "write_paths", "TEXT"), ("repeat_approvals", "end_note", "TEXT"),                                # 0.2.30 (B1)
                                    ("team_requests", "confirmed_at", "INTEGER"), ("team_requests", "flood", "INTEGER"),                         # 0.2.30 (V1)
                                    ("accounts", "erased_at", "INTEGER"), ("accounts", "args_salt", "BLOB"),                                     # 0.2.34 (crypto-shredding)
                                    ("accounts", "trial_until", "INTEGER"), ("accounts", "trial_claim", "BLOB"), ("accounts", "trial_claimed_at", "INTEGER"),
                                    ("accounts", "trial_form", "TEXT"), ("accounts", "internal", "INTEGER"), ("actions", "via", "TEXT"),
                                    ("funnel_seen", "t", "INTEGER"),
                                    ("actions", "line_heads", "TEXT"),
                                    ("exec_files", "net", "TEXT"),                                                                               # s7 (O2)
                                    ("actions", "gave_up_at", "INTEGER"),
                                    ("approvals", "view_sha256", "TEXT"),
                                    ("repeat_approvals", "view_sha256", "TEXT"), ("allowances", "view_sha256", "TEXT"),   # pv2: the view signed for later runs / a project permission         # pv2810: the presentation hash signed (NULL = view not signed)                                                                       # 0.2.43b (C): the hook stopped waiting                                                                              # s7 (O2)                                                                          # 0.2.56 (RT-0.2.55c)                                                                             # 0.2.38 (trial accounts)
                                    ("actions", "line_text", "TEXT"),    # 04.11 (Hypothesis I2): every command of a shell line, whole and masked
                                    ("actions", "line_lead", "TEXT"),    # 04.11 (L3): rid of the question that stands for this one (one tool call = one question)
                                    ("actions", "deny_key", "TEXT"),     # 05.11 (RT hole 1): normalized key of a dangerous shell line, to keep a refused line refused in the window
                                    ("sandbox_sessions", "strict", "INTEGER"),   # r0261c (д): the session had a strict Bash fact
                                    ("allowances", "branch", "TEXT"), ("allowances", "end_reason", "TEXT"),   # 0.2.96: "from now on" ends on a branch change
                                    ("actions", "shown_at", "INTEGER"),  # 0.2.96: the first time a person's page loaded this question ("approved unread")
                                    ("actions", "reconcile", "TEXT")):   # rel 28.10: "ledger:<outcome>" brought in line on start / "manual:<why>" left for a person
                cols = {r["name"] for r in self.c.execute("PRAGMA table_info(%s)" % table)}
                if col not in cols:
                    self.c.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, typ))
            # 0.2.38: the TTL sweep of trial accounts and the claim look-up on indexes
            self.c.execute("CREATE INDEX IF NOT EXISTS ix_accounts_trial ON accounts(trial_until) WHERE trial_until IS NOT NULL")
            self.c.execute("CREATE INDEX IF NOT EXISTS ix_accounts_claim ON accounts(trial_claim) WHERE trial_claim IS NOT NULL")
            # 0.2.24: the "agent saw a secret" look-up (T3) and the preview clean-up (B) on indexes, not on the whole book
            self.c.execute("CREATE INDEX IF NOT EXISTS ix_actions_taint ON actions(agent_id, updated_at) WHERE taint IS NOT NULL")
            self.c.execute("CREATE INDEX IF NOT EXISTS ix_actions_preview ON actions(created_at) WHERE preview_cut IS NULL OR preview_cut=1")
            # 0.2.14 (R8-06): a person who has an explicitly marked phone key has had one (idempotent, only ever sets the mark)
            self.c.execute("UPDATE users SET phone_ever=1 WHERE phone_ever IS NULL AND id IN (SELECT user_id FROM credentials WHERE device='phone')")
        _LIVE.add(self)

    # ---- connections ----
    def _new_reader(self):
        c = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA query_only=1")
        c.execute("PRAGMA mmap_size=%d" % MMAP)          # pages of a table another connection just wrote are read from the shared mapping
        return c

    @contextmanager
    def _reader(self):
        """A read connection (one of READERS, each under its own lock, chosen by thread), or the writer's when this thread holds it."""
        if self.lock.held():
            yield self.c
            return
        i = threading.get_ident() % len(self._rpool)
        lk = self._rlocks[i]
        with lk:
            c = self._rpool[i]
            if c is None:
                c = self._rpool[i] = self._new_reader()
            yield c

    def _is_read(self, sql, flush_rounds=True):
        if flush_rounds and "hook_rounds" in sql and len(self.rounds) and not (self.lock.held() and self.c.in_transaction):
            self.rounds.flush()                  # read-your-writes for every reader of the table (the quota uses rounds.count instead)
        return _READ.match(sql) is not None

    def _wrote(self, sql):
        m = _WRITES.match(sql)
        if m:
            t = m.group(1).lower()
            if self.tx_dirty is not None and self.lock.held():
                self.tx_dirty.add(t)             # bumped after COMMIT
            else:
                self.gen[t] += 1

    def q(self, sql, args=()):
        if self._is_read(sql):
            with self._reader() as c:
                return c.execute(sql, args).fetchall()
        with self.lock:
            rows = self.c.execute(sql, args).fetchall()
            self._wrote(sql)
            return rows

    def one(self, sql, args=(), flush_rounds=True):
        if self._is_read(sql, flush_rounds):
            with self._reader() as c:
                cur = c.execute(sql, args)
                try:
                    return cur.fetchone()
                finally:
                    cur.close()                  # ends the read at once: the connection's next statement sees the newest commit
        with self.lock:
            cur = self.c.execute(sql, args)
            try:
                return cur.fetchone()
            finally:
                cur.close()
                self._wrote(sql)

    def x(self, sql, args=()):
        self._is_read(sql)
        with self.lock:
            cur = self.c.execute(sql, args)
            self._wrote(sql)
            return cur.lastrowid

    def n(self, sql, args=()):
        """-> number of rows changed (UPDATE/DELETE): compare-and-set on one statement."""
        self._is_read(sql)
        with self.lock:
            k = self.c.execute(sql, args).rowcount
            self._wrote(sql)
            return k

    @contextmanager
    def tx(self):
        with self.lock:
            if self.tx_dirty is not None:        # nested (same thread holds it): one transaction
                yield self
                return
            self.c.execute("BEGIN IMMEDIATE")
            self.tx_dirty = set()
            try:
                yield self
            except BaseException:
                self.c.execute("ROLLBACK")
                raise
            else:
                self.c.execute("COMMIT")
            finally:
                for t in self.tx_dirty:
                    self.gen[t] += 1
                self.tx_dirty = None

    def cached(self, key, tables, load):
        """Row(s) from memory while no table in `tables` was written since they were read; else load() again. The generations are read
        BEFORE load(), so a write committed during load() makes the entry stale at once. CACHE_TTL_S bounds an entry anyway: a write by
        another process (a maintenance script on the same file) does not bump the generations of this one."""
        g = tuple(self.gen[t] for t in tables)
        e = self._cache.get(key)
        t = time.monotonic()
        if e is not None and e[0] == g and t - e[2] < CACHE_TTL_S:
            return e[1]
        v = load()
        if len(self._cache) > 50000:
            self._cache.clear()
        self._cache[key] = (g, v, t)
        return v

    def close(self):
        _LIVE.discard(self)
        try:
            self.rounds.flush()
        except Exception:  # noqa: BLE001
            pass
        for i, lk in enumerate(self._rlocks):
            with lk:
                if self._rpool[i] is not None:
                    self._rpool[i].close()
                    self._rpool[i] = None
        self.c.close()
