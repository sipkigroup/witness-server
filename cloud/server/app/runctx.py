"""0.2.85 (Ц3, AIUC-1 E015.2, SOC 2 CC8.1): the CI run context, signed by the witness, inside the evidence pack.

Before 0.2.85 the run's metadata (repository, commit, run id, actor) lay NEXT TO the pack (spec/ci-evidence/out/ci-run.json), signed by
nobody. Now the CI job declares it to the witness and the witness signs a RUN_CONTEXT record:

  POST /v1/run-context      Bearer <agent key> + X-DW-Export-Token <owner-issued CI token for this agent>
  {"repository", "commit", "run_id", "run_attempt", "workflow", "actor", "started_at", "session_ids"}   (all optional but one)

The record (COSE_Sign1 by the witness key, typ TYP_RUN, canonical CBOR) names the claimed values AS SENT, the ledger position at which it
was recorded (`at_seq`, `at_head` = hash of that ledger entry) and the decisions it covers: the RECEIPT entries of this agent
  - whose hook request carried one of `session_ids` (link "session": a client that sends the session id with the judge request), or
  - made since `started_at` up to now (link "window": every client, the 0.2.54 hook included -- it does not send the session id).
The evidence pack carries it as runs/<id>.cose (hashed in the witness-signed manifest); packtools/run_context.py checks the signature,
the ledger position and every linked receipt.

Why not a new ledger entry type: a checker of client <= 0.2.54 (aar_ref/schema.validate_body) answers MALFORMED -> RESULT: INVALID for a
type it does not know, so a RUN_CONTEXT entry would break every pack checked by the published client. The record is bound to the chain
by position (`at_head`) instead, and to the pack by the signed manifest.

Without a token it does NOT prove that the values are true ("declared"): the witness signs that the holder of the owner's CI token said
so at time t. Nothing secret is stored: unknown members are refused, and a value shaped like a token (GitHub, JWT, our own keys) is refused.

0.2.86: "verified: github-oidc". The body may carry `github_oidc_token`: a GitHub Actions OIDC token whose audience is the witness origin
(app/gh_oidc.py checks the RS256 signature against GitHub's JWKS, iss, aud, exp/nbf/iat). Then repository, commit (= sha), run_id,
run_attempt, workflow, workflow_ref, actor, ref (and event_name, repository_id, runner_environment) are taken FROM THE TOKEN; a body value
that differs from the token is refused (400 RUN_CONTEXT_MISMATCH: nothing is signed). The record says verified "github-oidc" and carries
`oidc` = {iss, aud, kid, jwk_sha256 (RFC 7638 thumbprint of GitHub's key), jwks ("github" | "test-file"), token_sha256, iat, exp}. The
token itself is not stored (it is a bearer credential until it expires); one token makes one record (409 OIDC_TOKEN_REUSED).
started_at and session_ids stay declared by the CI job (the token does not name them). Offline, a third party checks the witness's
signature over "the witness verified a GitHub token with these claims", not GitHub's signature (the token is not in the pack).

0.2.87: the owner's run-context policy (app/runpolicy.py: allowed repositories / refs / repository ids, require_verified, agent-scoped
audience) is checked before signing: outside it -> 403 RUN_CONTEXT_POLICY. `repository_owner_id` is taken from the token as well."""
import base64
import json
import os
import re
import time

import cbor2

from app.context import Err

TYP_RUN = "application/dw-run-context+cbor"
V = "dw-run-context-1"
NOTE = "declared by the CI job (holder of the owner's export token); the witness did not check these values"
NOTE_OIDC = ("repository, commit, run_id, run_attempt, workflow, workflow_ref, actor, ref taken from a GitHub Actions OIDC token whose RS256 "
             "signature, issuer, audience and validity the witness checked against GitHub's key set; started_at and session_ids declared by the CI job")
VERIFIED = "github-oidc"
TOKEN_KEY = "github_oidc_token"
# body member -> token claim(s) it must equal (0.2.86); "workflow" may name the workflow or its workflow_ref
MATCH = {"repository": ("repository",), "commit": ("sha",), "run_id": ("run_id",), "run_attempt": ("run_attempt",), "actor": ("actor",),
         "workflow": ("workflow", "workflow_ref")}
CLAIM_KEYS = ("repository", "commit", "run_id", "run_attempt", "workflow", "actor", "started_at", "session_ids")
MAX_RECEIPTS = 5000
MAX_SESSIONS = 50
PER_DAY = 500                                # run contexts per account per day
WINDOW_MAX_S = 7 * 86400                     # a "window" link never reaches further back than this
_PRINT = re.compile(r"[\x20-\x7e]+")         # printable ASCII only (no control, no bidi, no look-alikes)
_COMMIT = re.compile(r"[0-9a-f]{7,64}")
_SESSION = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_RFC3339 = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z")
# shapes of secrets that must never be written into a signed record (it is copied into every pack and cannot be erased from them)
_SECRET = re.compile(r"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|dwk_|dwx_|"
                     r"xox[abpr]-|sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|-----BEGIN)")
LIMITS = {"repository": 200, "run_id": 64, "run_attempt": 16, "workflow": 200, "actor": 100}


def _bad(detail):
    raise Err(400, "BAD_RUN_CONTEXT", detail)


def _text(k, v):
    if not isinstance(v, str) or not 0 < len(v) <= LIMITS[k] or not _PRINT.fullmatch(v) or v != v.strip():
        _bad("%s: printable ASCII, 1..%d characters, no space at either end" % (k, LIMITS[k]))
    return v


def started_t(v):
    """-> unix seconds of `started_at` (an integer, or RFC 3339 UTC 'YYYY-MM-DDTHH:MM:SS[.f]Z')."""
    if isinstance(v, int) and not isinstance(v, bool):
        if not 0 < v < 2 ** 40:
            _bad("started_at: unix seconds")
        return v
    m = _RFC3339.fullmatch(v) if isinstance(v, str) and len(v) <= 40 else None
    if not m:
        _bad("started_at: unix seconds or RFC 3339 UTC (2026-11-02T10:00:00Z)")
    import calendar
    try:
        return calendar.timegm(time.strptime(v[:19], "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        _bad("started_at: not a date")


def validate(b):
    """-> the claimed map as it will be signed (only the members sent; each checked for shape and for secrets)."""
    if not isinstance(b, dict):
        _bad("a JSON object expected")
    extra = sorted(set(b) - set(CLAIM_KEYS))
    if extra:
        _bad("unknown member(s) %s: only %s (nothing secret is accepted)" % (", ".join(extra)[:200], ", ".join(CLAIM_KEYS)))
    c = {}
    for k in ("repository", "run_id", "run_attempt", "workflow", "actor"):
        if b.get(k) is not None:
            c[k] = _text(k, b[k])
    if b.get("commit") is not None:
        if not isinstance(b["commit"], str) or not _COMMIT.fullmatch(b["commit"]):
            _bad("commit: a git object id, 7..64 lowercase hex digits")
        c["commit"] = b["commit"]
    if b.get("started_at") is not None:
        started_t(b["started_at"])
        c["started_at"] = b["started_at"]
    if b.get("session_ids") is not None:
        s = b["session_ids"]
        if not isinstance(s, list) or len(s) > MAX_SESSIONS or not all(isinstance(x, str) and _SESSION.fullmatch(x) for x in s) or len(set(s)) != len(s):
            _bad("session_ids: up to %d distinct ids, [A-Za-z0-9._:-]{1,128}" % MAX_SESSIONS)
        c["session_ids"] = sorted(s)
    if not c:
        _bad("nothing declared: send at least one of %s" % ", ".join(CLAIM_KEYS))
    for k, v in c.items():
        for x in (v if isinstance(v, list) else [v]):
            if isinstance(x, str) and _SECRET.search(x):
                raise Err(400, "SECRET_REFUSED", "%s looks like a secret (a token or a key): it is not written into a signed record" % k)
    return c


def session_of(body):
    """The session id a hook request names (a newer client: top-level `session_id`, or `event.session_id`) -> str | None. Never raises:
    a malformed one is ignored (the call is judged as before, it is just not linked by session)."""
    if not isinstance(body, dict):
        return None
    s = body.get("session_id")
    if s is None and isinstance(body.get("event"), dict):
        s = body["event"].get("session_id")
    return s if isinstance(s, str) and _SESSION.fullmatch(s) else None


def note_session(ctx, agent, rid, session_id):
    """The judge request named a session: remember it for this decision (rid). Best effort, never raises."""
    if not session_id or not rid:
        return
    try:
        ctx.db.x("INSERT OR IGNORE INTO action_sessions(rid, account_id, agent_id, session_id, t) VALUES(?,?,?,?,?)",
                 (rid, agent["account_id"], agent["id"], session_id, int(time.time())))
    except Exception:      # noqa: BLE001  the decision stands; only the link is missing
        pass


def _new_id():
    return "rc_" + base64.b32encode(os.urandom(10)).decode().rstrip("=")


def _from_oidc(ctx, agent, body):
    """0.2.86: body with `github_oidc_token` -> (claimed, oidc) with the token's values; None when no token was sent.
    0.2.87: the token's audience may also be the agent-scoped <origin>/agents/<agent id>; the owner's run-context policy
    (app/runpolicy.py) is applied to the verified claims before anything is signed or the token is spent."""
    from app import runpolicy
    if not isinstance(body, dict) or TOKEN_KEY not in body:
        runpolicy.check_declared(ctx, agent["account_id"])
        return None
    from app import gh_oidc
    tok = body[TOKEN_KEY]
    rest = {k: v for k, v in body.items() if k != TOKEN_KEY}
    declared = validate(rest) if rest else {}
    scoped = runpolicy.agent_audience(ctx.cfg.origin, agent["id"])
    v = gh_oidc.verify(tok, (ctx.cfg.origin, scoped))
    c = v["claims"]
    runpolicy.check_verified(ctx, agent["account_id"], c, v["aud"], scoped)
    diff = [k for k, cl in MATCH.items() if k in declared and declared[k] not in [c.get(x) for x in cl]]
    if diff:
        raise Err(400, "RUN_CONTEXT_MISMATCH", "the body differs from the verified GitHub OIDC token in: %s (nothing was signed)" % ", ".join(diff))
    claimed = {"repository": c["repository"], "commit": c["sha"], "run_id": c["run_id"], "run_attempt": c["run_attempt"], "actor": c["actor"]}
    for k in ("workflow", "workflow_ref", "ref", "event_name", "repository_id", "repository_owner_id", "runner_environment"):
        if k in c:
            claimed[k] = c[k]
    for k in ("started_at", "session_ids"):
        if k in declared:
            claimed[k] = declared[k]
    oidc = {"iss": gh_oidc.ISSUER, "aud": v["aud"], "kid": v["kid"], "jwk_sha256": v["jwk_sha256"], "jwks": v["jwks"],
            "token_sha256": v["token_sha256"], "iat": v["iat"], "exp": v["exp"]}
    return claimed, oidc


def attest(ctx, agent, token_row, body):
    """-> {"id", "at_seq", "link", "receipts", "cose_b64", ...}. Signs and stores the run context (see the module text)."""
    from svidetel_v4 import cose
    got = _from_oidc(ctx, agent, body)
    claimed, oidc = got if got else (validate(body), None)
    acc = agent["account_id"]
    t0 = int(time.time())
    n = ctx.db.one("SELECT COUNT(*) AS n FROM run_contexts WHERE account_id=? AND t>?", (acc, t0 - 86400))["n"]
    if n >= PER_DAY:
        raise Err(429, "QUOTA", "%d run contexts a day per account" % PER_DAY)
    sessions = claimed.get("session_ids") or []
    hub = ctx.hub
    with hub.lock(acc):
        L = hub.ledger(acc)
        with L._tx():
            if L.S.nseq == 0:
                raise Err(409, "EMPTY_LEDGER", "nothing recorded yet: declare the run context after the agent's calls (at the end of the job)")
            t = L.now()
            at_seq, at_head, rseq = L.S.nseq - 1, L.head, dict(L.rseq)
    link, window, rows = "none", None, []
    if sessions:
        q = "SELECT rid FROM action_sessions WHERE agent_id=? AND session_id IN (%s) ORDER BY t, rid" % ",".join("?" * len(sessions))
        rows = [r["rid"] for r in ctx.db.q(q, (agent["id"], *sessions))]
        if rows:
            link = "session"
    if not rows and "started_at" in claimed:
        lo = max(started_t(claimed["started_at"]), t - WINDOW_MAX_S)
        rows = [r["rid"] for r in ctx.db.q("SELECT rid FROM actions WHERE agent_id=? AND created_at>=? AND created_at<=? ORDER BY created_at, rid",
                                           (agent["id"], lo, t))]
        link, window = "window", [lo, t]
    rec = sorted(((rseq[r], r) for r in set(rows) if r in rseq and rseq[r] <= at_seq))
    truncated = len(rec) > MAX_RECEIPTS
    rec = rec[-MAX_RECEIPTS:]
    rid = _new_id()
    payload = {"v": V, "type": "RUN_CONTEXT", "id": rid, "account": acc, "agent": agent["id"], "ledger": L.lid, "at_seq": at_seq,
               "at_head": at_head, "t": t, "claimed": claimed, "claimed_by": "export-token:" + str(token_row["id"]), "note": NOTE,
               "link": link, "receipts": [[r, s] for s, r in rec], "truncated": truncated}
    if window:
        payload["window"] = window
    if oidc:                                         # 0.2.86: a declared record keeps the 0.2.85 shape exactly
        payload.update(verified=VERIFIED, oidc=oidc, note=NOTE_OIDC)
        try:
            ctx.db.x("INSERT INTO run_context_oidc(token_sha256, account_id, rc_id, t) VALUES(?,?,?,?)", (oidc["token_sha256"], acc, rid, t))
        except Exception:      # noqa: BLE001  (sqlite3.IntegrityError: the primary key)
            raise Err(409, "OIDC_TOKEN_REUSED", "this GitHub OIDC token was already used for a run context: request a new one")
    raw = cose.sign1(ctx.wk, cbor2.dumps(payload, canonical=True), TYP_RUN)
    ctx.db.x("INSERT INTO run_contexts(id, account_id, agent_id, t, cose, claimed_json) VALUES(?,?,?,?,?,?)",
             (rid, acc, agent["id"], t, raw, json.dumps(claimed, sort_keys=True)))
    out = {"id": rid, "at_seq": at_seq, "t": t, "link": link, "receipts": len(rec), "truncated": truncated, "note": payload["note"],
           "verified": VERIFIED if oidc else "declared", "cose_b64": base64.urlsafe_b64encode(raw).decode().rstrip("=")}
    if oidc:
        out.update(claimed=claimed, kid=oidc["kid"], token_sha256=oidc["token_sha256"])
    return out


def pack_files(ctx, account_id):
    """runs/<id>.cose for every run context of the account (export.build_pack; the manifest hashes them)."""
    if ctx.db.one("SELECT 1 AS k FROM sqlite_master WHERE type='table' AND name='run_contexts'") is None:
        return {}
    return {"runs/%s.cose" % r["id"]: bytes(r["cose"]) for r in ctx.db.q("SELECT id, cose FROM run_contexts WHERE account_id=? ORDER BY t, id", (account_id,))}
