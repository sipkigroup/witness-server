"""Escalation and role filter of the approval queue (ARHITEKTURA-0.2 §3.5): money classes -> `budget`, others -> `access`;
not decided within `escalate_after_s` (600) -> marked `escalated` and shown to owners too. Panel only (no mail, no push)."""
import json

from app.flow import store

MONEY = ("purchase", "sale", "refund")


def role_of(cls):
    return "budget" if cls in MONEY else "access"


def sweep(ctx, account_id, t=None):
    """Mark every pending action of the account older than escalate_after_s. -> number of new marks."""
    store.ensure(ctx)
    t = store.now() if t is None else t
    after = int(store.settings(ctx, account_id)["escalate_after_s"])
    rows = ctx.db.q("SELECT rid FROM actions WHERE account_id=? AND status='pending_approval' AND expires>=? AND created_at<=? "
                    "AND rid NOT IN (SELECT rid FROM flow_escalations WHERE account_id=?)", (account_id, t, t - after, account_id))
    for r in rows:
        ctx.db.x("INSERT OR IGNORE INTO flow_escalations(rid,account_id,t) VALUES(?,?,?)", (r["rid"], account_id, t))
    return len(rows)


def escalated(ctx, account_id):
    store.ensure(ctx)
    return {r["rid"] for r in ctx.db.q("SELECT rid FROM flow_escalations WHERE account_id=?", (account_id,))}


def queue(ctx, account_id, roles, t=None):
    """Pending approvals visible to a person with `roles` (list). Solo account / roles=None -> all. Each item carries role and escalated flag."""
    t = store.now() if t is None else t
    sweep(ctx, account_id, t)
    esc = escalated(ctx, account_id)
    out = []
    for x in ctx.db.q("SELECT * FROM actions WHERE account_id=? AND status='pending_approval' AND expires>=? ORDER BY created_at, rowid", (account_id, t)):
        need = role_of(x["class"])
        e = x["rid"] in esc
        if roles is None or need in roles or (e and "owner" in roles):
            out.append({"rid": x["rid"], "t": x["created_at"], "agent_id": x["agent_id"], "tool": x["tool"], "class": x["class"],
                        "recipient": x["recipient"], "amount": x["amount"], "role": need, "escalated": e,
                        "action": json.loads(x["action_json"]) if x["action_json"] else None, "expires": x["expires"]})
    return out


def pending_by_role(ctx, account_id, t=None):
    q = queue(ctx, account_id, None, t)
    out = {"budget": 0, "access": 0, "escalated": 0}
    for i in q:
        out[i["role"]] += 1
        out["escalated"] += 1 if i["escalated"] else 0
    return out
