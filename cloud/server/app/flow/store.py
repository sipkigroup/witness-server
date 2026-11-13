"""Storage of the flow (02): own tables (prefix flow_), read-only views of 01's org tables (org_settings, org_policies) that may not exist yet.
Owner: task 02. 01's tables are only READ here; when absent, the defaults of ARHITEKTURA-0.2 §2.6/§3.4/§3.5 apply."""
import json
import sqlite3
import time

import cbor2

DEFAULTS = {"max_pending": 10, "max_defers_hour": 120, "escalate_after_s": 600, "advisor": "off", "defer_ttl_s": 900, "profile": "smb"}

FLOW_SCHEMA = """
CREATE TABLE IF NOT EXISTS flow_catalogs(account_id TEXT, agent_id TEXT, catalog_json TEXT, sha256 TEXT, prev_sha256 TEXT, drift INTEGER, t INTEGER,
  PRIMARY KEY(agent_id));
CREATE TABLE IF NOT EXISTS flow_catalog_log(account_id TEXT, agent_id TEXT, sha256 TEXT, drift INTEGER, t INTEGER);
CREATE TABLE IF NOT EXISTS flow_coverage(agent_id TEXT PRIMARY KEY, account_id TEXT, coverage_json TEXT, t INTEGER);
CREATE TABLE IF NOT EXISTS flow_escalations(rid TEXT PRIMARY KEY, account_id TEXT, t INTEGER);
CREATE TABLE IF NOT EXISTS flow_held(rid TEXT PRIMARY KEY, account_id TEXT, label TEXT, mode TEXT, t INTEGER);
"""


def now():
    return int(time.time())


def ensure(ctx):
    """Create the flow_ tables once per database (idempotent)."""
    if getattr(ctx.db, "_flow_ready", False):
        return
    with ctx.db.lock:
        for stmt in [x.strip() for x in FLOW_SCHEMA.split(";") if x.strip()]:
            ctx.db.x(stmt)
    ctx.db._flow_ready = True


def _table_exists(ctx, name):
    return ctx.db.one("SELECT 1 AS k FROM sqlite_master WHERE type='table' AND name=?", (name,)) is not None


def settings(ctx, account_id):
    """org_settings of 01 (§2.6) merged over the defaults; a missing table/row/NULL column -> default."""
    out = dict(DEFAULTS)
    if _table_exists(ctx, "org_settings"):
        try:
            r = ctx.db.one("SELECT * FROM org_settings WHERE account_id=?", (account_id,))
        except sqlite3.Error:
            r = None
        if r is not None:
            for k in DEFAULTS:
                try:
                    v = r[k]
                except (IndexError, KeyError):
                    continue
                if v is not None:
                    out[k] = v
    return out


def current_policy(ctx, account_id):
    """Current org policy map (§2.2) or None (account without policy = solo mode 0.1, every requirement k=1)."""
    if not _table_exists(ctx, "org_policies"):
        return None
    try:
        r = ctx.db.one("SELECT policy FROM org_policies WHERE account_id=? ORDER BY ver DESC LIMIT 1", (account_id,))
    except sqlite3.Error:
        return None
    if r is None or r["policy"] is None:
        return None
    try:
        return cbor2.loads(bytes(r["policy"]))
    except Exception:
        return None


def jl(s, default=None):
    try:
        return json.loads(s) if s else default
    except ValueError:
        return default
