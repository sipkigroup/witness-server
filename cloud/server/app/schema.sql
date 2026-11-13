-- ARHITEKTURA 4.2 + ARHITEKTURA-0.2 2.6 (a fresh database is created in the form AFTER migrations/002_org.sql) (+ columns marked NEW: aar/proof_json on actions, ledger_nseq on checkpoints, size on anchor leaves)
CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY, principal TEXT UNIQUE NOT NULL, display_name TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS credentials(id INTEGER PRIMARY KEY, account_id TEXT REFERENCES accounts,   -- 0.2 (002_org): no UNIQUE(account_id)
  user_id TEXT,                          -- 0.2: the person who holds the passkey (users.id); account_id = the user's own (solo) account
  credential_id BLOB UNIQUE NOT NULL, pub BLOB NOT NULL, kid BLOB NOT NULL, sign_count INTEGER, rp_id TEXT, origin TEXT, created_at INTEGER,
  label TEXT, revoked_at INTEGER, last_used_at INTEGER,     -- 0.2.2: several passkeys per user (devices); removed = revoked_at set
  added_by TEXT);                        -- 0.2.2: registration | passkey (signed by a current key) | recovery-code
CREATE TABLE IF NOT EXISTS registry_log(seq INTEGER PRIMARY KEY, account_id TEXT, kid BLOB, entry_json TEXT, prev BLOB, hash BLOB NOT NULL, t INTEGER,
  tag BLOB, hash2 BLOB);                 -- 0.2.12 (R7-04): whose row it is, second chain over (tag, sha256(entry_json)), app/reglog.py
CREATE TABLE IF NOT EXISTS sessions(id_hash BLOB PRIMARY KEY, account_id TEXT, created_at INTEGER, expires_at INTEGER,
  stepup_at INTEGER,                     -- R-17: time of the last passkey signature in this session
  user_id TEXT,                          -- 0.2: session = user + current organisation (account_id)
  scope TEXT,                            -- 0.2.2: NULL = full session; 'recovery' = may only add a new passkey (recovery code)
  credential_id INTEGER);                -- 0.2.2: credentials.id of the passkey that opened it (removing the key ends it)
CREATE TABLE IF NOT EXISTS wa_flows(id TEXT PRIMARY KEY, purpose TEXT, state_json TEXT, expires_at INTEGER);
CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY, account_id TEXT, name TEXT, key_prefix TEXT, key_hash BLOB UNIQUE,
  toolmap_json TEXT NOT NULL, created_at INTEGER, disabled_at INTEGER);
CREATE TABLE IF NOT EXISTS data_patterns(account_id TEXT, class TEXT, literal TEXT);
CREATE TABLE IF NOT EXISTS mandates(id TEXT PRIMARY KEY, account_id TEXT, agent_id TEXT, mandate_json TEXT, envelope BLOB,
  status TEXT CHECK(status IN ('active','revoked','expired','superseded')), ledger_seq INTEGER, created_at INTEGER,
  toolmap_sha256 TEXT,
  patterns_sha256 TEXT, advisor_sha256 TEXT, patterns_items TEXT,
  gateway_doc TEXT);                     -- 0.2.4: the tool map document whose SHA-256 is `toolmap_sha256` INSIDE the signed mandate (draft-deus-aar-05 8.6)
  --   -- R3-06: the protected literals and the advisor mode at signing; a change -> deny until re-signed
  -- (was: toolmap_sha256 TEXT);                  -- R-03: hash of the tool map at the moment the passkey signed the mandate
CREATE TABLE IF NOT EXISTS actions(rid TEXT PRIMARY KEY, account_id TEXT, agent_id TEXT, mandate_id TEXT, tool TEXT,
  args_preview TEXT, action_json TEXT, request_hash BLOB, verdict TEXT, reason TEXT, status TEXT, amount INTEGER, currency TEXT,
  expires INTEGER, created_at INTEGER, updated_at INTEGER,
  class TEXT, recipient TEXT,            -- NEW: feed columns
  aar BLOB, proof_json TEXT,             -- NEW: AAR and inclusion proof kept so that repeats never append entries
  text_preview TEXT,
  promise BLOB,                          -- 0.2.4 (see below)
  cmd_meta TEXT, allowances TEXT, covered_by TEXT);   -- 0.2.10: {project, heads, outside} of a command line; allowance ids that let it through; the allowance that answered a pending one
  -- 0.2.4: inclusion promise (draft-deus-aar-05 9.5) given with the AAR                    -- R-05: masked text (<= 4 KB) shown on the approval page
CREATE TABLE IF NOT EXISTS approvals(rid TEXT PRIMARY KEY, account_id TEXT, approved INTEGER, envelope BLOB, ledger_seq INTEGER, t INTEGER);
CREATE TABLE IF NOT EXISTS checkpoints(id INTEGER PRIMARY KEY, account_id TEXT, seq INTEGER, cose BLOB, digest BLOB, t INTEGER, batch_id TEXT,
  ledger_nseq INTEGER);                  -- NEW: ledger length right after the checkpoint (to detect new entries)
CREATE TABLE IF NOT EXISTS anchor_batches(id TEXT PRIMARY KEY, t INTEGER, root BLOB, leaves_json TEXT, registry_head BLOB, status TEXT,
  block_height INTEGER, checked_json TEXT);
CREATE TABLE IF NOT EXISTS push_subs(id TEXT PRIMARY KEY, account_id TEXT NOT NULL, endpoint TEXT UNIQUE NOT NULL,   -- 08: Web Push subscriptions
  p256dh TEXT NOT NULL, auth TEXT NOT NULL, device TEXT, created_at INTEGER, last_ok_at INTEGER, fail_count INTEGER DEFAULT 0, user_id TEXT);
CREATE INDEX IF NOT EXISTS ix_push_acc ON push_subs(account_id);
CREATE TABLE IF NOT EXISTS push_mutes(account_id TEXT NOT NULL, agent_id TEXT NOT NULL, rid TEXT, user_id TEXT,   -- P0-4: "suspicious"
  reason TEXT, t INTEGER NOT NULL, until INTEGER NOT NULL);                       -- = the event log; mute active while until > now
CREATE INDEX IF NOT EXISTS ix_push_mutes ON push_mutes(account_id, agent_id, until);
CREATE INDEX IF NOT EXISTS ix_actions_acc ON actions(account_id, created_at);
CREATE INDEX IF NOT EXISTS ix_actions_proof_pending ON actions(account_id, created_at) WHERE aar IS NOT NULL AND proof_json IS NULL;   -- materialize_proofs: O(pending), not O(book)
CREATE INDEX IF NOT EXISTS ix_actions_rep ON actions(agent_id, request_hash, status);
CREATE INDEX IF NOT EXISTS ix_actions_agent ON actions(agent_id, created_at);      -- 0.2.18: the per-agent daily quota counts on an index
CREATE INDEX IF NOT EXISTS ix_agents_key ON agents(key_hash);
-- 0.2 (ARHITEKTURA-0.2 2.6, migrations/002_org.sql): users, members, invites, policies, signature requests, settings
CREATE TABLE IF NOT EXISTS schema_migrations(name TEXT PRIMARY KEY, t INTEGER);
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, display_name TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS members(account_id TEXT, user_id TEXT, roles TEXT, kid BLOB, status TEXT, PRIMARY KEY(account_id, user_id));
CREATE TABLE IF NOT EXISTS invites(token_hash BLOB PRIMARY KEY, account_id TEXT, roles TEXT, expires INTEGER, used_by TEXT);
CREATE TABLE IF NOT EXISTS org_policies(account_id TEXT, ver INTEGER, policy BLOB, envelope BLOB, hash BLOB, registry_seq INTEGER, t INTEGER,
  PRIMARY KEY(account_id, ver));
CREATE TABLE IF NOT EXISTS sig_requests(id TEXT PRIMARY KEY, account_id TEXT, kind TEXT, ref TEXT, typ TEXT, payload BLOB,
  policy_hash BLOB, needs TEXT, sigs TEXT, status TEXT, created_at INTEGER, expires INTEGER,
  meta TEXT);                            -- 01: json of what the request applies on completion (toolmap hash, approved, ...)
CREATE TABLE IF NOT EXISTS org_settings(account_id TEXT PRIMARY KEY, profile TEXT, defer_ttl_s INTEGER, max_pending INTEGER,
  max_defers_hour INTEGER, escalate_after_s INTEGER, advisor TEXT);
CREATE INDEX IF NOT EXISTS ix_members_user ON members(user_id);
CREATE INDEX IF NOT EXISTS ix_credentials_user ON credentials(user_id);
CREATE INDEX IF NOT EXISTS ix_sigreq_acc ON sig_requests(account_id, status);
INSERT OR IGNORE INTO schema_migrations(name, t) VALUES('002_org', CAST(strftime('%s','now') AS INTEGER));
-- 0.2.2: recovery codes (10 one-time codes; only scrypt hashes are kept; `lookup` = the first group, it finds the row, not the user)
CREATE TABLE IF NOT EXISTS recovery_codes(user_id TEXT NOT NULL, lookup TEXT NOT NULL, salt BLOB NOT NULL, hash BLOB NOT NULL,
  created_at INTEGER NOT NULL, used_at INTEGER);
CREATE INDEX IF NOT EXISTS ix_recovery_lookup ON recovery_codes(lookup);
CREATE INDEX IF NOT EXISTS ix_recovery_user ON recovery_codes(user_id);
-- 0.2.10 (PROPOSAL-07): "allow this command in this project" -- owner-signed allowances (the truth is the ALLOWANCE / ALLOWANCE_END entries of the ledger)
CREATE TABLE IF NOT EXISTS allowances(id TEXT PRIMARY KEY, account_id TEXT NOT NULL, agent_id TEXT NOT NULL, mandate_id TEXT NOT NULL,
  commands TEXT NOT NULL, project TEXT NOT NULL, nbf INTEGER NOT NULL, exp INTEGER NOT NULL, envelope BLOB, ledger_seq INTEGER,
  created_at INTEGER NOT NULL, created_by TEXT, from_rid TEXT, ended_at INTEGER, end_seq INTEGER);
CREATE INDEX IF NOT EXISTS ix_allowances_acc ON allowances(account_id, created_at);
-- 0.2.96 ("approved without reading"): one row per decision a person made on an approval page. read_ms = from the question shown to
-- the button pressed (the page's own clock, capped by what the server saw between the first load and the decision); details = the
-- person opened "Details"; kind once | forward ("from now on") | deny. No text of the call, no address: counts and times only.
CREATE TABLE IF NOT EXISTS decision_ux(account_id TEXT NOT NULL, rid TEXT NOT NULL, t INTEGER NOT NULL, kind TEXT NOT NULL,
  read_ms INTEGER, details INTEGER, PRIMARY KEY(account_id, rid));
CREATE INDEX IF NOT EXISTS ix_decision_ux_t ON decision_ux(account_id, t);
-- 0.2.13 (PROPOSAL-08): files that commands execute -- the version the owner confirmed ('ok') or a write the witness allowed ('dirty'), per agent
CREATE TABLE IF NOT EXISTS exec_files(agent_id TEXT NOT NULL, path TEXT NOT NULL, digest TEXT NOT NULL, state TEXT NOT NULL, rid TEXT, updated_at INTEGER,
  net TEXT,                              -- s7 (O2): what the witness saw of a judged write: network lines/hosts, never the text
  PRIMARY KEY(agent_id, path));
CREATE TABLE IF NOT EXISTS exec_roots(agent_id TEXT NOT NULL, root TEXT NOT NULL, first_seen INTEGER, truncated INTEGER, PRIMARY KEY(agent_id, root));
-- 0.2.13: confirmation levels (which passkey may confirm what) and team delegation (whose agent, who confirms for it)
CREATE TABLE IF NOT EXISTS confirm_rules(account_id TEXT PRIMARY KEY, phone_for TEXT NOT NULL, updated_at INTEGER, updated_by TEXT);
CREATE TABLE IF NOT EXISTS agent_delegations(id INTEGER PRIMARY KEY, account_id TEXT NOT NULL, agent_id TEXT NOT NULL, operator_user_id TEXT NOT NULL,
  approvers TEXT, set_by TEXT NOT NULL, set_at INTEGER NOT NULL, ended_at INTEGER, ended_by TEXT);
CREATE INDEX IF NOT EXISTS ix_deleg_agent ON agent_delegations(agent_id, ended_at);
-- 0.2.17 (R9-04): rounds of POST /v1/hook/judge that end without an action (kind 'need' = the witness asked for file-system facts,
-- 'refuse' = the event could not be judged, code = the refusal code). They count toward the daily quota and the owner sees them per agent.
CREATE TABLE IF NOT EXISTS hook_rounds(account_id TEXT NOT NULL, agent_id TEXT NOT NULL, t INTEGER NOT NULL, kind TEXT NOT NULL, code TEXT);
CREATE INDEX IF NOT EXISTS ix_hook_rounds_agent ON hook_rounds(agent_id, t);
CREATE INDEX IF NOT EXISTS ix_hook_rounds_account ON hook_rounds(account_id, t);
-- 0.2.21: "possible clone" of a passkey (a signature counter that went back, org.sign_count_refused). ONE row per (person, key): a clone
-- that sends a regression 1000 times moves `n` and `last_at`, never adds rows. notified_at: the last push (at most one per key per
-- 10 minutes, app/keyalert.py). dismissed_at: the owner said "this was me" (fresh step-up with ANOTHER passkey when there is one);
-- a new regression raises it again. Only server values are stored (route from a fixed list, integers): no text from the client.
CREATE TABLE IF NOT EXISTS key_alerts(user_id TEXT NOT NULL, kid BLOB NOT NULL, first_at INTEGER NOT NULL, last_at INTEGER NOT NULL,
  n INTEGER NOT NULL, route TEXT, stored INTEGER, got INTEGER, notified_at INTEGER, dismissed_at INTEGER, dismissed_by TEXT,
  PRIMARY KEY(user_id, kid));
-- 0.2.24 (critique T2): the journal of "freeze agent": who froze / unfroze it and when, how many waiting requests were cancelled.
-- agents.frozen_at (added in place by db.py) is the live mark: every new call of a frozen agent is denied AGENT_FROZEN.
CREATE TABLE IF NOT EXISTS agent_freezes(id INTEGER PRIMARY KEY, account_id TEXT NOT NULL, agent_id TEXT NOT NULL, kind TEXT NOT NULL,
  t INTEGER NOT NULL, by_user TEXT, cancelled INTEGER);
CREATE INDEX IF NOT EXISTS ix_agent_freezes ON agent_freezes(agent_id, t);
-- 0.2.25: notification channels (app/notify.py): Telegram / Slack / e-mail; secret_enc = AES-256-GCM of the token / webhook URL / address
CREATE TABLE IF NOT EXISTS notify_channels(id TEXT PRIMARY KEY, account_id TEXT NOT NULL, user_id TEXT, kind TEXT NOT NULL,
  label TEXT NOT NULL, secret_enc BLOB NOT NULL, verified INTEGER NOT NULL DEFAULT 0, code_hash TEXT, code_exp INTEGER, code_tries INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL, last_ok_at INTEGER, fail_count INTEGER DEFAULT 0, last_error TEXT);
CREATE INDEX IF NOT EXISTS ix_notify_acc ON notify_channels(account_id);
-- 0.2.28: the funnel (app/stats.py): one number per UTC day and step, no personal data; funnel_seen = which account already passed a step
-- (erased with the account); team_requests = the Team access form (only the e-mail and the text typed; deleted after 180 days)
CREATE TABLE IF NOT EXISTS funnel_daily(day TEXT NOT NULL, step TEXT NOT NULL, n_all INTEGER NOT NULL DEFAULT 0, n_own INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(day, step));
CREATE TABLE IF NOT EXISTS funnel_seen(account_id TEXT NOT NULL, step TEXT NOT NULL, PRIMARY KEY(account_id, step));
CREATE TABLE IF NOT EXISTS team_requests(id INTEGER PRIMARY KEY, t INTEGER NOT NULL, email TEXT NOT NULL, text TEXT NOT NULL);
-- 0.2.29: "approve this call for later runs" (app/repeat.py): one wb signed by the owner over the approval payloads of a pending request and of
-- up to 10 receipt ids made up by the owner's device (the time limit is inside each id). A later IDENTICAL call of the agent (same request hash,
-- same mandate, same reason) is recorded under the next unused id and approved with that same signature. The truth of each use is in the ledger
-- (RECEIPT defer + APPROVAL with the wb); these rows only say which ids are left and whether the owner revoked the rest.
CREATE TABLE IF NOT EXISTS repeat_approvals(id TEXT PRIMARY KEY, account_id TEXT NOT NULL, agent_id TEXT NOT NULL, mandate_id TEXT NOT NULL,
  request_hash BLOB NOT NULL, reason TEXT NOT NULL, tool TEXT, class TEXT, recipient TEXT, from_rid TEXT NOT NULL, envelope BLOB NOT NULL,
  uses INTEGER NOT NULL, exp INTEGER NOT NULL, created_at INTEGER NOT NULL, created_by TEXT, ended_at INTEGER, ended_by TEXT);
CREATE INDEX IF NOT EXISTS ix_repeat_agent ON repeat_approvals(agent_id, request_hash);
CREATE INDEX IF NOT EXISTS ix_repeat_acc ON repeat_approvals(account_id, created_at);
CREATE TABLE IF NOT EXISTS repeat_slots(rid TEXT PRIMARY KEY, account_id TEXT NOT NULL, repeat_id TEXT NOT NULL, n INTEGER NOT NULL, used_at INTEGER);
CREATE INDEX IF NOT EXISTS ix_repeat_slots ON repeat_slots(repeat_id, n);
-- 0.2.46: export tokens (app/export_tokens.py): the owner gives CI a short, read-only right to download the evidence pack; bound to ONE agent
-- (the request must also carry that agent's key); the token itself is stored only as a hash
CREATE TABLE IF NOT EXISTS export_tokens(id TEXT PRIMARY KEY, account_id TEXT NOT NULL, agent_id TEXT NOT NULL, token_hash BLOB UNIQUE NOT NULL,
  label TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_by TEXT, revoked_at INTEGER, last_used_at INTEGER,
  uses INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_export_tokens_acc ON export_tokens(account_id, created_at);
-- 0.2.46: 429 refusals by reason and UTC hour (app/refusals.py); no IP, no request content; 14 days. Like export_tokens: created by CREATE IF NOT EXISTS
-- on every start (no separate migration file; migrations/ holds only the 0.1 -> 0.2 step)
CREATE TABLE IF NOT EXISTS refusals_429(hour INTEGER NOT NULL, reason TEXT NOT NULL, account_id TEXT NOT NULL DEFAULT '', agent_id TEXT NOT NULL DEFAULT '',
  n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(hour, reason, account_id, agent_id));
-- 0.2.63 (RT-0.2.41 F1): `deus-witness run` (app/runcheck.py): one row per run nonce (only its hash), how many SessionStart calls and judged
-- PreToolUse calls carried it. Added by CREATE IF NOT EXISTS like export_tokens: a 0.2.62 server ignores the table (rollback-safe)
CREATE TABLE IF NOT EXISTS run_checks(nonce_hash BLOB PRIMARY KEY, account_id TEXT NOT NULL, agent_id TEXT NOT NULL, created_at INTEGER NOT NULL,
  exp INTEGER NOT NULL, starts INTEGER NOT NULL DEFAULT 0, judged INTEGER NOT NULL DEFAULT 0, sessions TEXT NOT NULL DEFAULT '[]');
CREATE INDEX IF NOT EXISTS ix_run_checks_agent ON run_checks(agent_id, exp);
-- 0.2.83 (Mandate Receipt MR-24): the shown object (signing view, app/signview.py) whose hash a person's passkey signed, stored when the server
-- checked the claimed hash against its rows (api_web._view_match). Content-addressed per account; the evidence pack carries it as views/<key>.json
-- so a third party recomputes the signed hash. Kept as long as the previews (cfg.preview_keep_days, jobs.prune_previews), then the pack says
-- VIEW_UNVERIFIABLE for that approval. Added by CREATE IF NOT EXISTS: a 0.2.82 server ignores the table (rollback-safe)
CREATE TABLE IF NOT EXISTS shown_views(account_id TEXT NOT NULL, sha256 TEXT NOT NULL, view_json TEXT NOT NULL, t INTEGER NOT NULL,
  PRIMARY KEY(account_id, sha256));
CREATE INDEX IF NOT EXISTS ix_shown_views_t ON shown_views(t);
-- 0.2.85 (app/runctx.py): the CI run context signed by the witness (COSE_Sign1, typ application/dw-run-context+cbor), exported as runs/<id>.cose;
-- claimed_json = what the CI job declared (no secrets: refused by shape). action_sessions: the session id a newer hook sends with a judge request,
-- per decision (rid), for the "session" link. Added by CREATE IF NOT EXISTS: a 0.2.84 server ignores both tables (rollback-safe)
CREATE TABLE IF NOT EXISTS run_contexts(id TEXT PRIMARY KEY, account_id TEXT NOT NULL, agent_id TEXT NOT NULL, t INTEGER NOT NULL, cose BLOB NOT NULL,
  claimed_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_run_contexts_acc ON run_contexts(account_id, t);
CREATE TABLE IF NOT EXISTS action_sessions(rid TEXT PRIMARY KEY, account_id TEXT NOT NULL, agent_id TEXT NOT NULL, session_id TEXT NOT NULL, t INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_action_sessions_agent ON action_sessions(agent_id, session_id);
-- 0.2.86 (app/gh_oidc.py): one GitHub OIDC token makes one verified run context. Only the token's SHA-256 is kept (the token is a bearer
-- credential until it expires and is never stored). CREATE IF NOT EXISTS: a 0.2.85 server ignores it (rollback-safe)
CREATE TABLE IF NOT EXISTS run_context_oidc(token_sha256 TEXT PRIMARY KEY, account_id TEXT NOT NULL, rc_id TEXT NOT NULL, t INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_run_context_oidc_acc ON run_context_oidc(account_id);
-- 0.2.87 (app/runpolicy.py): the owner's run-context policy (allowed GitHub repositories / refs / ids, require_verified, audience).
-- CREATE IF NOT EXISTS: a 0.2.86 server ignores it (rollback-safe; the policy is then simply not enforced)
CREATE TABLE IF NOT EXISTS run_context_policy(account_id TEXT PRIMARY KEY, policy_json TEXT NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT);
-- 0.2.88 (app/hookjudge/freshness.py): the first view of a session's Claude Code settings (the hook's settings digest, the sandbox fact's
-- settings key) and whether they changed since (sticky: the strict sandbox is then off until a new session). CREATE IF NOT EXISTS: a 0.2.87
-- server ignores it (rollback-safe)
CREATE TABLE IF NOT EXISTS sandbox_sessions(account_id TEXT NOT NULL, agent_id TEXT NOT NULL, session_id TEXT NOT NULL, sdig TEXT, fkey TEXT,
  changed INTEGER NOT NULL, t INTEGER NOT NULL, PRIMARY KEY(agent_id, session_id));
CREATE INDEX IF NOT EXISTS ix_sandbox_sessions_t ON sandbox_sessions(agent_id, t);
-- r0269: public log of anchor batches (app/tlog.py): leaves, signed C2SP checkpoints, daily external stamps of a checkpoint
CREATE TABLE IF NOT EXISTS tlog_leaves(idx INTEGER PRIMARY KEY, batch_id TEXT UNIQUE NOT NULL, leaf BLOB NOT NULL, t INTEGER);
CREATE TABLE IF NOT EXISTS tlog_checkpoints(size INTEGER PRIMARY KEY, root BLOB NOT NULL, note TEXT NOT NULL, t INTEGER);
CREATE TABLE IF NOT EXISTS tlog_stamps(size INTEGER PRIMARY KEY, digest BLOB NOT NULL, t INTEGER, status TEXT, ots TEXT, tsa TEXT,
  tries INTEGER DEFAULT 0, next_try INTEGER, last_err TEXT, done_t INTEGER);
CREATE TABLE IF NOT EXISTS vocabs(digest TEXT PRIMARY KEY, json TEXT NOT NULL, t INTEGER);   -- r0269: reason vocabularies pinned by mandates (app/vocab.py)
