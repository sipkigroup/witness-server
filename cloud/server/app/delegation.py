"""0.2.13 (Team): delegation "junior -> senior". An agent of the organisation is assigned to the person who runs it (its operator, X).
The dangerous actions of that agent -- every deferred action -- are then confirmed by OTHER people, never by X:
  - who: the members the organisation's policy already requires for the approval (rules.approval -> roles, k; no second mechanism),
    minus X, and -- if the owner named them -- only the listed approvers ("the senior" or a group);
  - self-approval is refused (409 SELF_APPROVAL): X's signature is not counted in a quorum and a quorum envelope that contains it is rejected;
    X may still REFUSE (stopping is never harder than going);
  - an impossible rule blocks (APPROVER_NONE: the action is denied at once, not let through): nobody left with the role, the approvers' term
    ran out, or (with confirmation levels) nobody of them has a phone key for an action that needs one;
  - silence is a refusal: the request expires after the organisation's defer_ttl_s (RECEIPT_EXPIRED), nothing is approved by time;
  - the record: each delegation is a row (who set it, when, for which agent, operator, approvers, until; an end is a new row state, never a
    delete), and every approval stores the signers and "on behalf of" (approvals.signers / on_behalf_of).
Setting or ending a delegation needs the owner role and a fresh passkey signature (step-up).
0.2.15: the delegation lives in the SIGNED team policy (rules.delegation, contract wq_profile): `put` / `end` draft the next policy
version and it takes effect when rule `policy` of the version in force signs it (sig_requests, like any policy change); the table
agent_delegations is then a cache rewritten from the adopted policy (sync_from_policy). Each draft also carries every delegation the
server still holds outside the policy (set before 0.2.15): signing it moves them in. Period before the transfer: an agent that is NOT
named in the policy in force keeps the 0.2.13 behaviour (the server applies put / end at once, the evidence pack says `trust:`);
once named, only a new signed version changes it."""
import hashlib
import json
import time

from app import _paths  # noqa: F401
import cbor2

import wa_profile as wa
import wq_profile as wq
from app import org
from app.context import Err
from app import levels
from app.log import log

MAX_APPROVERS = 20
MAX_DAYS = 366


def _now():
    return int(time.time())


def current(ctx, agent_id):
    return ctx.db.one("SELECT * FROM agent_delegations WHERE agent_id=? AND ended_at IS NULL ORDER BY id DESC LIMIT 1", (agent_id,))


def _view(r):
    if r is None:
        return None
    ap = json.loads(r["approvers"]) if r["approvers"] else None
    return {"id": r["id"], "agent_id": r["agent_id"], "operator_user_id": r["operator_user_id"],
            "approvers": ap.get("users") if isinstance(ap, dict) else None, "until": ap.get("until") if isinstance(ap, dict) else None,
            "set_by": r["set_by"], "set_at": r["set_at"], "ended_at": r["ended_at"], "ended_by": r["ended_by"],
            "policy_ver": ap.get("policy_ver") if isinstance(ap, dict) else None}        # 0.2.15: the signed version that set it (None: server-side)


def view(ctx, acc_id, agent_id):
    hist = [_view(r) for r in ctx.db.q("SELECT * FROM agent_delegations WHERE account_id=? AND agent_id=? ORDER BY id DESC LIMIT 50", (acc_id, agent_id))]
    return {"current": _view(current(ctx, agent_id)), "history": hist}


def _signing_member(ctx, acc_id, uid):
    m = org.member(ctx, acc_id, uid) if isinstance(uid, str) else None
    return m is not None and m["status"] == "active" and any(r in org.SIGNERS for r in m["roles"])


def put(ctx, acc, user_id, agent_id, body):
    """Assign the agent to its operator; optional approvers (user ids) and `days` (their term)."""
    if org.current_policy(ctx, acc["id"]) is None:
        raise Err(409, "NOT_A_TEAM", "delegation needs an organisation with a signed policy (Team)")
    if not ctx.db.one("SELECT 1 AS k FROM agents WHERE id=? AND account_id=?", (agent_id, acc["id"])):
        raise Err(404, "NOT_FOUND")
    b = body if isinstance(body, dict) else {}
    op = b.get("operator_user_id")
    m = org.member(ctx, acc["id"], op) if isinstance(op, str) else None
    if m is None or m["status"] != "active":
        raise Err(422, "NOT_MEMBER", "operator_user_id: an active member of this organisation")
    ap = b.get("approvers")
    if ap is not None:
        if not isinstance(ap, list) or not 1 <= len(ap) <= MAX_APPROVERS or not all(isinstance(u, str) for u in ap) or len(set(ap)) != len(ap):
            raise Err(422, "BAD_DELEGATION", "approvers: 1..%d distinct user ids, or null (anyone the policy allows)" % MAX_APPROVERS)
        if op in ap:
            raise Err(422, "SELF_APPROVAL", "the operator cannot confirm the actions of their own agent")
        for u in ap:
            if not _signing_member(ctx, acc["id"], u):
                raise Err(422, "NOT_MEMBER", "approver %s is not an active signing member" % u[:40])
    days = b.get("days")
    if days is not None and (not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= MAX_DAYS):
        raise Err(422, "BAD_DELEGATION", "days: 1..%d" % MAX_DAYS)
    t = _now()
    meta = {"users": ap, "until": t + days * 86400 if days else None}
    pol = org.current_policy(ctx, acc["id"])[0]
    entry = _entry(ctx, acc["id"], pol, agent_id, op, ap, meta["until"])
    in_policy = wq.delegation_of(pol, agent_id) is not None
    with ctx.hub.lock(acc["id"]):
        if not in_policy:           # period before the transfer: as 0.2.13 (at once, server-side); the draft below moves it into the policy
            with ctx.db.tx():
                ctx.db.x("UPDATE agent_delegations SET ended_at=?, ended_by=? WHERE agent_id=? AND ended_at IS NULL", (t, user_id, agent_id))
                ctx.db.x("INSERT INTO agent_delegations(account_id,agent_id,operator_user_id,approvers,set_by,set_at) VALUES(?,?,?,?,?,?)",
                         (acc["id"], agent_id, op, json.dumps(meta), user_id, t))
        req = _draft(ctx, acc, user_id, agent_id, entry)
    out = view(ctx, acc["id"], agent_id)
    out["can_confirm_now"] = eligible_summary(ctx, acc["id"], agent_id)
    out.update(policy_request=req, in_signed_policy=in_policy, waits_for_signatures=in_policy)
    return out


def end(ctx, acc, user_id, agent_id):
    if not ctx.db.one("SELECT 1 AS k FROM agents WHERE id=? AND account_id=?", (agent_id, acc["id"])):
        raise Err(404, "NOT_FOUND")
    cur = org.current_policy(ctx, acc["id"])
    if cur is not None and wq.delegation_of(cur[0], agent_id) is not None:
        with ctx.hub.lock(acc["id"]):       # 0.2.15: named in the signed policy -> ended only by the next signed version
            req = _draft(ctx, acc, user_id, agent_id, None)
        out = view(ctx, acc["id"], agent_id)
        out.update(policy_request=req, in_signed_policy=True, waits_for_signatures=True)
        return out
    ctx.db.x("UPDATE agent_delegations SET ended_at=?, ended_by=? WHERE agent_id=? AND account_id=? AND ended_at IS NULL", (_now(), user_id, agent_id, acc["id"]))
    return view(ctx, acc["id"], agent_id)


# ---------------------------------------------------------------- 0.2.15: the delegation in the signed policy
def _member_kid(ctx, acc_id, uid, pol=None):
    m = org.member(ctx, acc_id, uid) if isinstance(uid, str) else None
    if m is None or m["kid"] is None:
        return None
    k = bytes(m["kid"])
    if pol is not None and k not in {mm["kid"] for mm in pol["members"]}:
        return None
    return k.hex()


def _entry(ctx, acc_id, pol, agent_id, op, approvers, until):
    """The rules.delegation entry (kids as hex) of a delegation set by user ids."""
    ok = _member_kid(ctx, acc_id, op)
    if ok is None:
        raise Err(422, "NOT_MEMBER", "the operator has no passkey this organisation knows")
    ap = None
    if approvers is not None:
        ap = []
        for u in approvers:
            k = _member_kid(ctx, acc_id, u, pol)
            if k is None:
                raise Err(422, "NOT_MEMBER", "approver %s holds no key in the signed policy in force" % u[:40])
            ap.append(k)
        ap = sorted(set(ap))
        if ok in ap:
            raise Err(422, "SELF_APPROVAL", "the operator cannot confirm the actions of their own agent")
    return {"agent": agent_id, "operator": ok, "approvers": ap, "until": until}


def _legacy_entries(ctx, acc_id, pol):
    """Delegations the server holds for agents the policy does not name (set before 0.2.15): moved in by the next signed version."""
    named = {d["agent"] for d in pol["rules"].get("delegation") or ()}
    out = {}
    for r in ctx.db.q("SELECT * FROM agent_delegations WHERE account_id=? AND ended_at IS NULL", (acc_id,)):
        if r["agent_id"] in named:
            continue
        ap = json.loads(r["approvers"]) if r["approvers"] else {}
        try:
            out[r["agent_id"]] = _entry(ctx, acc_id, pol, r["agent_id"], r["operator_user_id"], ap.get("users") if isinstance(ap, dict) else None,
                                        ap.get("until") if isinstance(ap, dict) else None)
        except Err:
            continue                  # an approver who left the policy: that one stays server-side (the owner sets it again)
    return out


def _draft(ctx, acc, user_id, agent_id, entry):
    """Open the policy request of version N+1 = N with rules.delegation changed for `agent_id` (entry None: removed). Caller holds the lock."""
    aid = acc["id"]
    ch = org.chain(ctx, aid)
    prev = cbor2.loads(ch[-1][0])
    dl = {d["agent"]: d for d in prev["rules"].get("delegation") or ()}
    dl.update(_legacy_entries(ctx, aid, prev))
    if entry is None:
        dl.pop(agent_id, None)
    else:
        dl[agent_id] = entry
    rules = {k: v for k, v in prev["rules"].items() if k != "delegation"}
    if dl:
        rules["delegation"] = [dl[a] for a in sorted(dl)]
    pol = {"v": wq.V_POLICY, "principal": prev["principal"], "ver": len(ch) + 1, "prev": hashlib.sha256(ch[-1][0]).digest(),
           "members": prev["members"], "rules": rules}
    if wq.validate_policy(pol):
        raise Err(422, "POLICY_MALFORMED", "the delegation does not fit the signed policy (ARHITEKTURA-0.2 2.2, rules.delegation)")
    payload = wa.cde(pol)
    ph = hashlib.sha256(ch[-1][0]).digest()
    needs = wq.requirements(prev, wq.TYP_POLICY, None)
    ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE account_id=? AND kind='policy' AND status='collecting' "
             "AND json_extract(meta,'$.delegation.agent')=?", (aid, agent_id))
    sid = org.new_request(ctx, aid, "policy", str(pol["ver"]), wq.TYP_POLICY, payload, ph, needs,
                          {"by": user_id, "delegation": {"agent": agent_id, "set": entry is not None}})
    return {"req_id": sid, "policy_ver": pol["ver"], "needs": [{"role": r, "k": k} for r, k in needs],
            "sign_url": "%s/sign.html?req=%s" % (ctx.cfg.origin, sid),
            "note": "In force when the team signs policy version %d (rule `policy`); then the evidence pack proves it." % pol["ver"]}


def sync_from_policy(ctx, acc_id, prev_pol, pol, t):
    """After a policy version is adopted: the cache follows rules.delegation (agents of this account only). Agents never named in a
    signed version keep their server-side rows (period before the transfer)."""
    new = {d["agent"]: d for d in pol["rules"].get("delegation") or ()}
    old = {d["agent"] for d in ((prev_pol or {}).get("rules") or {}).get("delegation") or ()}
    by = "policy:v%d" % pol["ver"]
    for agent, d in new.items():
        if not ctx.db.one("SELECT 1 AS k FROM agents WHERE id=? AND account_id=?", (agent, acc_id)):
            continue
        op = user_of_kid(ctx, bytes.fromhex(d["operator"]))
        users = None if d["approvers"] is None else sorted({user_of_kid(ctx, bytes.fromhex(k)) or k for k in d["approvers"]})
        cur = current(ctx, agent)
        if cur is not None and cur["operator_user_id"] == op:
            ap = json.loads(cur["approvers"]) if cur["approvers"] else {}
            cu = ap.get("users") if isinstance(ap, dict) else None
            if (None if cu is None else sorted(cu)) == users and (ap.get("until") if isinstance(ap, dict) else None) == d["until"] \
                    and isinstance(ap, dict) and ap.get("policy_ver"):
                continue        # unchanged since the version that set it (a server-side row is re-recorded once: "moved into vN")
        ctx.db.x("UPDATE agent_delegations SET ended_at=?, ended_by=? WHERE agent_id=? AND ended_at IS NULL", (t, by, agent))
        ctx.db.x("INSERT INTO agent_delegations(account_id,agent_id,operator_user_id,approvers,set_by,set_at) VALUES(?,?,?,?,?,?)",
                 (acc_id, agent, op or d["operator"], json.dumps({"users": users, "until": d["until"], "policy_ver": pol["ver"]}), by, t))
    for agent in old - set(new):
        ctx.db.x("UPDATE agent_delegations SET ended_at=?, ended_by=? WHERE agent_id=? AND account_id=? AND ended_at IS NULL", (t, by, agent, acc_id))
    if new or old:
        log("INFO", "delegations follow the signed policy", account=acc_id, ver=pol["ver"], named=len(new))


def user_of_kid(ctx, kid):
    r = ctx.db.one("SELECT user_id FROM credentials WHERE kid=? ORDER BY id DESC LIMIT 1", (kid,)) if isinstance(kid, bytes) else None
    if not r or r["user_id"] is None:
        return None
    u = r["user_id"]
    return u.hex() if isinstance(u, bytes) else str(u)


def _approvers(r, now=None):
    """-> None (anyone the policy allows) or the set of listed approvers (empty when their term ran out)."""
    ap = json.loads(r["approvers"]) if r["approvers"] else {}
    users = ap.get("users") if isinstance(ap, dict) else None
    if users is None:
        return None
    until = ap.get("until")
    if until is not None and (now or _now()) > until:
        return set()
    return set(users)


def check_approval(ctx, acc_id, agent_id, kids, approved, action=None):
    """Before an approval of an action of `agent_id` is applied. -> (signer user ids, operator or None). Err 409 SELF_APPROVAL / NOT_DELEGATE."""
    signers = [user_of_kid(ctx, k) for k in kids]
    r = current(ctx, agent_id) if org.current_policy(ctx, acc_id) is not None else None
    if r is None:
        if approved and _creator_self_approves(ctx, acc_id, agent_id, signers, action):
            raise Err(409, "SELF_APPROVAL", "you made this agent: in a team another member confirms its actions")
        return signers, None
    if not approved:
        return signers, r["operator_user_id"]          # a refusal is accepted from anyone who may sign, the operator too
    if r["operator_user_id"] in signers:
        raise Err(409, "SELF_APPROVAL", "the person who runs this agent cannot confirm its actions: another member of the team confirms them")
    ap = _approvers(r)
    if ap is not None and any(u not in ap for u in signers):
        raise Err(409, "NOT_DELEGATE", "this agent's actions are confirmed only by the approvers the owner named" +
                  (" (their term ran out: the owner must renew it)" if not ap else ""))
    return signers, r["operator_user_id"]


def _creator_self_approves(ctx, acc_id, agent_id, signers, action=None):
    """r0284 (law Z2): with no delegation the agent's operator is the member who made it (agents.created_by). True when that member is among
    the signers, the approval rule for this action asks one signature (k = 1 everywhere: a quorum needs the others anyway), AND another active signing member of the policy exists (a one-person team is not locked). Agents made before r0284 have no
    creator: unchanged."""
    a = ctx.db.one("SELECT created_by FROM agents WHERE id=?", (agent_id,))
    mk = a["created_by"] if a is not None and "created_by" in a.keys() else None
    cur = org.current_policy(ctx, acc_id)
    if not mk or mk not in signers or cur is None:
        return False
    reqs = wq.requirements(cur[0], wa.TYP_APPROVAL, None, {"class": (action or {}).get("class"), "amount": (action or {}).get("amount")}) or [("any", 1)]
    if any(k >= 2 for _, k in reqs):
        return False            # a quorum: other members must sign anyway, the creator's signature alone decides nothing
    for m in cur[0]["members"]:
        uid = user_of_kid(ctx, m["kid"])
        if uid is None or uid == mk or not set(m["roles"]) & set(org.SIGNERS):
            continue
        mm = org.member(ctx, acc_id, uid)
        if mm is not None and mm["status"] == "active" and not org.revoked_kid(ctx, m["kid"]):
            return True
    return False


def _candidates(ctx, acc_id, r, pol, need_phone):
    """Policy members who may confirm for this delegation: user id -> roles."""
    ap = _approvers(r)
    out = {}
    for m in pol["members"]:
        uid = user_of_kid(ctx, m["kid"])
        if uid is None or uid == r["operator_user_id"] or (ap is not None and uid not in ap):
            continue
        mm = org.member(ctx, acc_id, uid)
        if mm is None or mm["status"] != "active" or org.revoked_kid(ctx, m["kid"]):
            continue
        if need_phone and levels.device_of_kid(ctx, m["kid"]) == levels.LAPTOP:
            continue
        out[uid] = list(m["roles"])
    return out


def unsatisfiable(ctx, acc_id, agent_id, action, reason, level_min=None):
    """True when the agent is delegated and nobody can complete the approval rule for this action (-> deny APPROVER_NONE)."""
    cur = org.current_policy(ctx, acc_id)
    r = current(ctx, agent_id) if cur is not None else None
    if r is None:
        return False
    pol = cur[0]
    need_phone = levels.required(ctx, acc_id, action, reason, level_min) == levels.PHONE
    cand = _candidates(ctx, acc_id, r, pol, need_phone)
    reqs = wq.requirements(pol, wa.TYP_APPROVAL, None, {"class": action.get("class"), "amount": action.get("amount")}) or [("any", 1)]
    for role, k in reqs:
        n = sum(1 for roles in cand.values() if (role == "any" and set(roles) & set(org.SIGNERS)) or role in roles)
        if n < k:
            return True
    return False


def eligible_summary(ctx, acc_id, agent_id):
    cur = org.current_policy(ctx, acc_id)
    r = current(ctx, agent_id)
    if cur is None or r is None:
        return []
    return sorted(_candidates(ctx, acc_id, r, cur[0], False))


def sigreq_excluded(ctx, acc_id, sid_row):
    """Push / open-request filter: the operator of the agent of an approval request is not asked to sign it."""
    if sid_row["kind"] != "approval":
        return None
    x = ctx.db.one("SELECT agent_id FROM actions WHERE rid=? AND account_id=?", (sid_row["ref"], acc_id))
    r = current(ctx, x["agent_id"]) if x else None
    return r["operator_user_id"] if r else None

