-- 002_org (ARHITEKTURA-0.2 2.6): organisations of several people. Applied ONLY by `python -m app.migrate --db <db> --backup <copy>`
-- (the copy is the rollback). One transaction; app/migrate.py records the name in schema_migrations and never applies it twice.
-- Principal and ledger path of every account stay as they are: an account of 0.1 becomes a solo organisation of its own user.
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, display_name TEXT, created_at INTEGER);
-- credentials: + user_id, UNIQUE(account_id) dropped (table rebuilt); an existing row -> user_id = account_id
CREATE TABLE credentials_002(id INTEGER PRIMARY KEY, account_id TEXT REFERENCES accounts,
  user_id TEXT,
  credential_id BLOB UNIQUE NOT NULL, pub BLOB NOT NULL, kid BLOB NOT NULL, sign_count INTEGER, rp_id TEXT, origin TEXT, created_at INTEGER);
INSERT INTO credentials_002(id, account_id, user_id, credential_id, pub, kid, sign_count, rp_id, origin, created_at)
  SELECT id, account_id, account_id, credential_id, pub, kid, sign_count, rp_id, origin, created_at FROM credentials;
DROP TABLE credentials;
ALTER TABLE credentials_002 RENAME TO credentials;
-- sessions: + user_id (session = user + current organisation)
ALTER TABLE sessions ADD COLUMN user_id TEXT;
UPDATE sessions SET user_id = account_id;
CREATE TABLE IF NOT EXISTS members(account_id TEXT, user_id TEXT, roles TEXT, kid BLOB, status TEXT, PRIMARY KEY(account_id, user_id));
CREATE TABLE IF NOT EXISTS invites(token_hash BLOB PRIMARY KEY, account_id TEXT, roles TEXT, expires INTEGER, used_by TEXT);
CREATE TABLE IF NOT EXISTS org_policies(account_id TEXT, ver INTEGER, policy BLOB, envelope BLOB, hash BLOB, registry_seq INTEGER, t INTEGER,
  PRIMARY KEY(account_id, ver));
CREATE TABLE IF NOT EXISTS sig_requests(id TEXT PRIMARY KEY, account_id TEXT, kind TEXT, ref TEXT, typ TEXT, payload BLOB,
  policy_hash BLOB, needs TEXT, sigs TEXT, status TEXT, created_at INTEGER, expires INTEGER, meta TEXT);
CREATE TABLE IF NOT EXISTS org_settings(account_id TEXT PRIMARY KEY, profile TEXT, defer_ttl_s INTEGER, max_pending INTEGER,
  max_defers_hour INTEGER, escalate_after_s INTEGER, advisor TEXT);
-- every account of 0.1 = one user (same id) = the single active member with all signing roles
INSERT INTO users(id, display_name, created_at) SELECT id, display_name, created_at FROM accounts WHERE id NOT IN (SELECT id FROM users);
INSERT INTO members(account_id, user_id, roles, kid, status)
  SELECT c.account_id, c.user_id, '["owner","budget","access"]', c.kid, 'active' FROM credentials c
  WHERE NOT EXISTS (SELECT 1 FROM members m WHERE m.account_id = c.account_id AND m.user_id = c.user_id);
CREATE INDEX IF NOT EXISTS ix_members_user ON members(user_id);
CREATE INDEX IF NOT EXISTS ix_credentials_user ON credentials(user_id);
CREATE INDEX IF NOT EXISTS ix_sigreq_acc ON sig_requests(account_id, status);
