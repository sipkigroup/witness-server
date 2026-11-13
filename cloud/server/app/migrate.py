"""Database migrations of Witness Cloud. Run with the server STOPPED:
    python -m app.migrate --db <data_dir>/db.sqlite --backup <copy.sqlite>
The copy is taken (SQLite online backup, WAL included) BEFORE anything is changed and is the rollback: stop the server, put the copy back.
Idempotent: an applied migration is recorded in schema_migrations and a second run changes nothing (and takes no copy).
Prints `migrated 002_org: users=N members=N`."""
import argparse
import os
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MIGRATIONS = os.path.join(os.path.dirname(HERE), "migrations")
NAME = "002_org"
# columns added in place by app/db.py since the review of 2026-10-18 (a database older than that gets them here first)
REVIEW_COLUMNS = (("mandates", "toolmap_sha256", "TEXT"), ("actions", "text_preview", "TEXT"), ("sessions", "stepup_at", "INTEGER"),
                  ("mandates", "patterns_sha256", "TEXT"), ("mandates", "advisor_sha256", "TEXT"), ("mandates", "patterns_items", "TEXT"), ("mandates", "gateway_doc", "TEXT"), ("actions", "promise", "BLOB"))


class MigrateError(Exception):
    pass


def _tables(c):
    return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def applied(c, name=NAME):
    return "schema_migrations" in _tables(c) and c.execute("SELECT 1 FROM schema_migrations WHERE name=?", (name,)).fetchone() is not None


def migrate(db_path, backup_path, out=print):
    """-> (users_added, members_added) or None when already applied."""
    if not os.path.isfile(db_path):
        raise MigrateError("no database at %s" % db_path)
    c = sqlite3.connect(db_path, isolation_level=None)
    try:
        if "accounts" not in _tables(c):
            raise MigrateError("%s is not a Witness Cloud database (no accounts table)" % db_path)
        if applied(c):
            out("migrated %s: users=0 members=0 (already applied, no changes)" % NAME)
            return None
        if os.path.exists(backup_path):
            raise MigrateError("backup %s already exists: refusing to overwrite an earlier copy" % backup_path)
        os.makedirs(os.path.dirname(os.path.abspath(backup_path)), exist_ok=True)
        dst = sqlite3.connect(backup_path)
        try:
            c.backup(dst)
        finally:
            dst.close()
        n_users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0] if "users" in _tables(c) else 0
        n_members = c.execute("SELECT COUNT(*) FROM members").fetchone()[0] if "members" in _tables(c) else 0
        pre = []
        for table, col, typ in REVIEW_COLUMNS:
            if col not in {r[1] for r in c.execute("PRAGMA table_info(%s)" % table)}:
                pre.append("ALTER TABLE %s ADD COLUMN %s %s;" % (table, col, typ))
        with open(os.path.join(MIGRATIONS, NAME + ".sql"), encoding="utf-8") as f:
            body = f.read()
        script = ("BEGIN IMMEDIATE;\n" + "\n".join(pre) + "\n" + body +
                  "\nCREATE TABLE IF NOT EXISTS schema_migrations(name TEXT PRIMARY KEY, t INTEGER);\n"
                  "INSERT INTO schema_migrations(name, t) VALUES('%s', %d);\nCOMMIT;\n" % (NAME, int(time.time())))
        try:
            c.executescript(script)
        except BaseException:
            if c.in_transaction:
                c.execute("ROLLBACK")
            raise
        du = c.execute("SELECT COUNT(*) FROM users").fetchone()[0] - n_users
        dm = c.execute("SELECT COUNT(*) FROM members").fetchone()[0] - n_members
        bad = c.execute("PRAGMA integrity_check").fetchone()[0]
        if bad != "ok":
            raise MigrateError("integrity_check after migration: %s (restore %s)" % (bad, backup_path))
        out("migrated %s: users=%d members=%d" % (NAME, du, dm))
        return du, dm
    finally:
        c.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", required=True)
    ap.add_argument("--backup", required=True)
    o = ap.parse_args(argv)
    try:
        migrate(o.db, o.backup)
    except (MigrateError, sqlite3.Error) as e:
        print("migrate: FAILED: %s" % e, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
