"""0.2.87 (Ц3): the owner's policy for CI run contexts -- which GitHub repositories and refs may produce a VERIFIED run context.

Where it lives, and why not in the mandate: a mandate is per agent and is about what the agent may DO (tools, paths, ceilings); changing it
needs a passkey re-signature of the whole mandate and re-arms every guard. The run-context policy is about WHERE the CI evidence may come
from, is the same for every agent of the account (an org pins its repositories once), and must be tightened in seconds after a leak. So
it is an account setting (table run_context_policy), changed only by the owner with a fresh passkey step-up (as /api/confirm-rules):

  GET /api/run-context-policy            -> {"allow": [...], "require_verified": bool, "audience": "any"|"agent", "updated_at", ...}
  PUT /api/run-context-policy            {"allow": [rule, ...], "require_verified": false, "audience": "any"}

  rule = {"repository": "owner/name" | "owner/*",            (required; compared without case, as GitHub does)
          "refs": ["refs/heads/main", "refs/tags/v*"],       (optional; exact, or a prefix ending in "*"; absent/empty = any ref)
          "repository_id": "123456",                         (optional; GitHub's immutable numeric id of the repository)
          "repository_owner_id": "7890"}                     (optional; immutable numeric id of the owner/org)

Checked in POST /v1/run-context after the GitHub OIDC token is verified and BEFORE anything is signed or the token is spent:
  - `allow` empty -> as 0.2.86 (any repository);
  - `allow` not empty -> the token's repository / ref / repository_id / repository_owner_id must satisfy one rule, else
    403 RUN_CONTEXT_POLICY (nothing signed; the token is not marked used);
  - `require_verified` -> a run context without a GitHub OIDC token ("declared") is 403 RUN_CONTEXT_POLICY;
  - `audience` "agent" -> only a token whose `aud` is the agent-scoped audience <origin>/agents/<agent id> is accepted (403 otherwise);
    "any" (default) accepts the origin or the agent-scoped audience.

What the ids buy (a name is not an identity): a repository name can be renamed, transferred, or deleted and re-created by someone else
("repo-jacking"); the numeric ids cannot be reused. A rule with repository_id/repository_owner_id is satisfied only by THAT repository /
owner, whatever it is called now.

What the agent-scoped audience buys ("token stolen before use", OTCHET-0286 caveat 3): GitHub signs `aud` into the token. A job that asks
for audience <origin>/agents/<agent id> gets a token that no other agent -- in this account or any other -- accepts, so a token copied out
of that job cannot be spent elsewhere. With the origin audience the token is good in any account until its first use. The ids in the
policy narrow WHAT this account accepts; only the scoped audience stops ANOTHER account from accepting a token minted for this one."""
import json
import re
import time

from app.context import Err

MAX_RULES = 50
MAX_REFS = 20
_OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})"
_REPO = re.compile(r"(%s)/([A-Za-z0-9._-]{1,100}|\*)" % _OWNER)
_REF = re.compile(r"refs/[A-Za-z0-9._/+@-]{1,240}\*?|refs/\*")
_ID = re.compile(r"[0-9]{1,20}")
DEFAULT = {"allow": [], "require_verified": False, "audience": "any"}
RULE_KEYS = {"repository", "refs", "repository_id", "repository_owner_id"}


def _bad(detail):
    raise Err(422, "BAD_RUN_CONTEXT_POLICY", detail)


def _idv(k, v):
    if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
        v = str(v)
    if not isinstance(v, str) or not _ID.fullmatch(v):
        _bad("%s: GitHub's numeric id (digits), as in the token's %s claim" % (k, k))
    return v


def _rule(i, r):
    if not isinstance(r, dict) or set(r) - RULE_KEYS or "repository" not in r:
        _bad("allow[%d]: an object with repository (required), refs, repository_id, repository_owner_id" % i)
    repo = r["repository"]
    if not isinstance(repo, str) or not _REPO.fullmatch(repo) or repo.split("/")[1] in (".", ".."):
        _bad("allow[%d].repository: owner/name or owner/* (GitHub names)" % i)
    out = {"repository": repo}
    refs = r.get("refs")
    if refs is not None:
        if not isinstance(refs, list) or len(refs) > MAX_REFS or not all(isinstance(x, str) and _REF.fullmatch(x) and "*" not in x[:-1] for x in refs) \
                or len(set(refs)) != len(refs):
            _bad("allow[%d].refs: up to %d distinct refs (refs/heads/main), a trailing * for a prefix (refs/tags/v*)" % (i, MAX_REFS))
        if refs:
            out["refs"] = refs
    for k in ("repository_id", "repository_owner_id"):
        if r.get(k) is not None:
            out[k] = _idv(k, r[k])
    if repo.endswith("/*") and "repository_id" in out:
        _bad("allow[%d]: repository_id names one repository; with owner/* use repository_owner_id" % i)
    return out


def validate(b):
    if not isinstance(b, dict) or set(b) - set(DEFAULT):
        _bad("an object with allow, require_verified, audience")
    allow = b.get("allow", [])
    if not isinstance(allow, list) or len(allow) > MAX_RULES:
        _bad("allow: a list of up to %d rules" % MAX_RULES)
    rules = [_rule(i, r) for i, r in enumerate(allow)]
    if len({json.dumps(r, sort_keys=True) for r in rules}) != len(rules):
        _bad("allow: repeated rule")
    rv = b.get("require_verified", False)
    aud = b.get("audience", "any")
    if not isinstance(rv, bool) or aud not in ("any", "agent"):
        _bad("require_verified: true|false; audience: any|agent")
    return {"allow": rules, "require_verified": rv, "audience": aud}


def get(ctx, account_id):
    r = ctx.db.one("SELECT policy_json, updated_at, updated_by FROM run_context_policy WHERE account_id=?", (account_id,))
    if not r:
        return dict(DEFAULT, updated_at=None, updated_by=None)
    return dict(json.loads(r["policy_json"]), updated_at=r["updated_at"], updated_by=r["updated_by"])


def put(ctx, account_id, user_id, b):
    p = validate(b)
    t = int(time.time())
    ctx.db.x("INSERT OR REPLACE INTO run_context_policy(account_id, policy_json, updated_at, updated_by) VALUES(?,?,?,?)",
             (account_id, json.dumps(p, sort_keys=True), t, user_id))
    return dict(p, updated_at=t, updated_by=user_id)


def agent_audience(origin, agent_id):
    return origin.rstrip("/") + "/agents/" + agent_id


def _deny(detail):
    raise Err(403, "RUN_CONTEXT_POLICY", detail + " (the owner's run-context policy; nothing was signed)")


def _ref_ok(pats, ref):
    if not pats:
        return True
    if not isinstance(ref, str):
        return False
    return any(ref.startswith(p[:-1]) if p.endswith("*") else ref == p for p in pats)


def matches(rule, c):
    """rule (validated) vs the verified token claims -> bool."""
    repo = c.get("repository") or ""
    owner, _, name = rule["repository"].partition("/")
    ro, _, rn = repo.partition("/")
    if ro.lower() != owner.lower() or (name != "*" and rn.lower() != name.lower()):
        return False
    for k in ("repository_id", "repository_owner_id"):
        if k in rule and c.get(k) != rule[k]:
            return False
    return _ref_ok(rule.get("refs"), c.get("ref"))


def check_declared(ctx, account_id):
    """A run context without a token: refused only when the owner requires verified ones."""
    if get(ctx, account_id)["require_verified"]:
        _deny("a GitHub OIDC token is required (require_verified): declared run contexts are refused")


def check_verified(ctx, account_id, claims, aud, scoped_aud):
    p = get(ctx, account_id)
    if p["audience"] == "agent" and aud != scoped_aud:
        _deny("the token's audience must be %s (audience: agent), not %s" % (scoped_aud, aud))
    if p["allow"] and not any(matches(r, claims) for r in p["allow"]):
        _deny("repository %s, ref %s, repository_id %s, repository_owner_id %s is not allowed"
              % (claims.get("repository"), claims.get("ref") or "-", claims.get("repository_id") or "-", claims.get("repository_owner_id") or "-"))
