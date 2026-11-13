"""0.2.23: "Delete account" -- the person erases THEIR OWN account (the solo account whose id is the user's id).

Who may: the owner, signed in to their own account, with a passkey signature newer than auth.STEPUP_TTL (the same step-up as inviting a
member) and the account name typed in full. A passkey that still waits to become the phone after a recovery code (PHONE_PENDING) may not:
a thief with a recovery code must not be able to wipe the account within the wait.
Refused while other people are attached (409 TEAM_HAS_MEMBERS: remove them or ask them to leave first) and while the person is an
active signing member of SOMEBODY ELSE's team (409 IN_TEAM: their key is in that team's policy; the team must swap it out first).

Erased: sessions, agents (and their API keys), mandates, requests and approvals with their text previews, closed-data literals, allowances,
files-state of commands, delegations, the MCP tool catalogs and coverage reports (flow_*), push subscriptions, invites, signature requests, settings, recovery codes, clone alerts, the user row,
the display name. The passkeys are NOT dropped from the tables: each is marked removed (a removed passkey never signs in or confirms
anything again, org.revoked_kid) and loses its label; its public key stays because the packs issued before (and the skeleton's checkpoint) are checked with it.

Journal (0.2.34, app/erase.py): the witness writes a last signed checkpoint and replaces data/ledgers/<id>/ledger.cose by
ledger.skeleton.cbor = the list of entry hashes + that checkpoint. What the journal held in clear text is gone: the recipient of every
action, the lists of the mandates (to / domains / targets / commands), the hash of the arguments (args_sha256) and the approvals' request
hashes. The skeleton still proves that entries existed and in which order (inclusion and consistency proofs are built from the hashes), but
not what they said, so the account's decisions cannot be re-checked after the deletion. Packs issued earlier stay valid: they carry their
own copy. Only the account's OWN journal is replaced; the registry log is shared by all accounts and stays.

Kept, on purpose (the page says so too):
- the hash skeleton of the journal and its checkpoint (anchored in external time-stamps), and the registry log entries (app/reglog.py):
  append-only hash chains whose heads are published in anchors; the registry log is shared with other accounts, taking a row out would
  break the proof for everybody else. The registry holds public keys and the pseudonymous account id, no recipients and no texts.
  Backups made before the deletion still hold the old journal until they rotate (deploy/backup.sh keeps 14 daily archives).
- the account row itself (opaque id, principal, creation time) with an empty name, so that the anchor job and the skeleton keep working."""
import json
import time

from app import erase
from app import levels
from app.context import Err

TABLES_BY_ACCOUNT = ("agents", "data_patterns", "mandates", "actions", "approvals", "push_subs", "push_mutes", "invites", "org_settings",
                     "allowances", "confirm_rules", "agent_delegations", "hook_rounds", "sig_requests",
                     "agent_freezes", "notify_channels",          # 0.2.25
                     "funnel_seen",                              # 0.2.28 (the day counters hold no account)
                     "export_tokens", "refusals_429",            # 0.2.46
                     "repeat_approvals", "repeat_slots",          # 0.2.29
                     "run_checks",                               # 0.2.63
                     "shown_views",                              # 0.2.83
                     "run_contexts", "action_sessions",           # 0.2.85
                     "run_context_oidc",                         # 0.2.86
                     "run_context_policy",                       # 0.2.87
                     "sandbox_sessions")                         # 0.2.88
# 04.11 (privacy D3): the MCP proxy's tables (app/flow/store.py: tool catalogs, coverage strings, holds) are made lazily -> erased when present
FLOW_TABLES = ("flow_catalogs", "flow_catalog_log", "flow_coverage", "flow_held", "flow_escalations")


def check(ctx, user_id, acc, name, cred):
    if acc["id"] != user_id:
        raise Err(403, "NOT_OWN_ACCOUNT", "switch to your own account first: only the person can delete their own account")
    if not isinstance(name, str) or name.strip() != (acc["display_name"] or "").strip() or not name.strip():
        raise Err(400, "NAME_MISMATCH", "type the account name exactly as shown")
    if cred is not None and levels.pending_lineage(ctx, cred) is not None:
        raise Err(409, "PHONE_PENDING", "this passkey is still waiting to count as your phone: it cannot delete the account yet")
    others = ctx.db.q("SELECT user_id FROM members WHERE account_id=? AND user_id<>? AND status<>'removed'", (user_id, user_id))
    if others:
        raise Err(409, "TEAM_HAS_MEMBERS", "%d other member(s) are in this account: remove them (or ask them to leave) first" % len(others))
    for m in ctx.db.q("SELECT roles, status FROM members WHERE user_id=? AND account_id<>? AND status<>'removed'", (user_id, user_id)):
        roles = json.loads(m["roles"] or "[]")
        if m["status"] == "active" and roles != ["observer"]:
            raise Err(409, "IN_TEAM", "you sign for another team: ask that team to replace your key first")


def delete(ctx, user_id, acc, name, cred):
    check(ctx, user_id, acc, name, cred)
    return _erase(ctx, user_id, acc, lambda: check(ctx, user_id, acc, name, cred))


def erase_unasked(ctx, user_id, acc, why="trial expired"):
    """0.2.38: the same erase without the person's request (an unkept trial account past its time, app/trial.py). Refused (Err 409) while
    other people are attached, exactly like the person's own deletion."""
    def recheck():
        if ctx.db.q("SELECT user_id FROM members WHERE account_id=? AND user_id<>? AND status<>'removed'", (user_id, user_id)):
            raise Err(409, "TEAM_HAS_MEMBERS", why + ": other members are attached")
    if acc["id"] != user_id:
        raise Err(403, "NOT_OWN_ACCOUNT")
    recheck()
    return _erase(ctx, user_id, acc, recheck)


def _erase(ctx, user_id, acc, recheck):
    aid, t = acc["id"], int(time.time())
    with ctx.hub.lock(aid):
        with ctx.db.tx() as db:
            recheck()                                                  # again under the lock: nobody joined in between
            cpinfo = erase.prepare(ctx, aid, t)                        # 0.2.34: last checkpoint + hash skeleton written (journal still there)
            ag = [r["id"] for r in db.q("SELECT id FROM agents WHERE account_id=?", (aid,))]
            for a in ag:
                db.x("DELETE FROM exec_files WHERE agent_id=?", (a,))
                db.x("DELETE FROM exec_roots WHERE agent_id=?", (a,))
            for tb in TABLES_BY_ACCOUNT:
                db.x("DELETE FROM %s WHERE account_id=?" % tb, (aid,))
            for tb in FLOW_TABLES:
                if db.one("SELECT 1 AS k FROM sqlite_master WHERE type='table' AND name=?", (tb,)) is not None:
                    db.x("DELETE FROM %s WHERE account_id=?" % tb, (aid,))
            db.x("DELETE FROM sessions WHERE user_id=? OR account_id=?", (user_id, aid))
            db.x("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
            db.x("DELETE FROM key_alerts WHERE user_id=?", (user_id,))
            db.x("DELETE FROM members WHERE account_id=? OR user_id=?", (aid, user_id))
            db.x("UPDATE credentials SET revoked_at=COALESCE(revoked_at,?), label=NULL WHERE user_id=?", (t, user_id))
            db.x("DELETE FROM users WHERE id=?", (user_id,))
            db.x("UPDATE accounts SET display_name=NULL, erased_at=?, args_salt=NULL WHERE id=?", (t, aid))
            if cpinfo is not None:
                erase.store_checkpoint(db, aid, cpinfo, t)
        erase.finish(ctx, aid)                                         # 0.2.34: committed -> the journal file goes; only ledger.skeleton.cbor stays
    ctx.hub.forget(aid)
    from app import stats
    stats.forget(aid)
    return {"ok": True, "deleted": True, "kept": ["hash skeleton of the witness journal (hashes only, no content; anchored)", "registry log entries (public keys)", "opaque account id"], "erased": ["witness journal content (recipients, argument hashes, mandates)"]}
