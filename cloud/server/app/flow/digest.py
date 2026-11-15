"""Digest (ARHITEKTURA-0.2 §3.5, §3.6) over a period: W, H, F, A100, F100, breakdowns, pending by role, APPROVAL_RATE refusals,
catalog drift, suggestions. Derived from `actions`, `approvals` and the flow_ tables only (no counters to drift).
W = witnessed actions (allow + deny + defer; no pass, no gateway refusals/holds). H = human decisions per item. F = passkey ceremonies
for approvals: one wa-sig = 1, one batch wb = 1 (however many items), one quorum wq = number of signatures in it."""
import json

import cbor2

from app.flow import escalate, store, suggest

# Refusals of the gateway (no ledger entry). RECIPIENT and REFUSED are gateway codes only in the forms noted in gateway().
GATE_ONLY = ("APPROVAL_RATE", "TOOL_UNMAPPED", "TOOL_ARGS_UNMAPPED", "TOOLMAP_CHANGED", "DATA_PATTERNS_CHANGED", "ADVISOR_CHANGED", "NO_MANDATE", "ADVISORY_HOLD", "ADVISORY_REJECTED",
             # 06.11: the Constitution v1's immutable articles (app/constitution.py): refused by the gateway, no ledger entry
             "FORBIDDEN_SECRET_READ", "FORBIDDEN_GIT_HOOKS", "FORBIDDEN_AUTOSTART", "FORBIDDEN_WIPE", "FORBIDDEN_REMOTE_SHELL",
             "FORBIDDEN_HIDDEN_CHARS", "FORBIDDEN_FORCE_PUSH", "FORBIDDEN_DEFENSE_OFF")


def gateway(x):
    if x["status"] == "held" or x["reason"] in GATE_ONLY:
        return True
    if x["reason"] == "REFUSED" and x["status"] == "denied":       # repeat of a refused action (owner refusals have status 'refused')
        return True
    if x["reason"] == "RECIPIENT" and x["mandate_id"] is None:     # extra recipient needing approval, refused before the core
        return True
    return False


def ceremonies(env):
    try:
        m = cbor2.loads(bytes(env))
    except Exception:
        return 1
    if isinstance(m, dict) and m.get("v") == "deus-aar-wq-0.1" and isinstance(m.get("sigs"), list):
        return len(m["sigs"])
    return 1


def first_verdict(x):
    if x["status"] in ("pending_approval", "approved", "refused", "expired") or x["reason"] in ("OK_APPROVED",) or (x["reason"] or "").startswith("ESCALATE_"):
        return "defer"
    return x["verdict"]


def digest(ctx, account_id, since=None, t=None):
    store.ensure(ctx)
    t = store.now() if t is None else t
    since = t - 86400 if since is None else since
    rows = ctx.db.q("SELECT * FROM actions WHERE account_id=? AND created_at>=? AND created_at<=?", (account_id, since, t))
    W, by_verdict, by_reason, by_agent, rate_refusals, gate = 0, {}, {}, {}, 0, 0
    for x in rows:
        if x["reason"] == "APPROVAL_RATE":
            rate_refusals += 1
        if x["status"] == "pass" or x["class"] == "pass":      # 0.2.4: a pass with a receipt is not a decision about the owner's authority either
            continue
        if gateway(x):
            gate += 1
            continue
        W += 1
        v = first_verdict(x)
        by_verdict[v] = by_verdict.get(v, 0) + 1
        by_reason[x["reason"]] = by_reason.get(x["reason"], 0) + 1
        by_agent[x["agent_id"]] = by_agent.get(x["agent_id"], 0) + 1
    aps = ctx.db.q("SELECT envelope, approved FROM approvals WHERE account_id=? AND t>=? AND t<=?", (account_id, since, t))
    H = len(aps)
    envs = {}
    for a in aps:
        if a["envelope"] is not None:
            envs[bytes(a["envelope"])] = None
    F = sum(ceremonies(e) for e in envs)
    drift = [{"agent_id": r["agent_id"], "catalog_sha256": r["sha256"], "t": r["t"]}
             for r in ctx.db.q("SELECT agent_id, sha256, t FROM flow_catalog_log WHERE account_id=? AND drift=1 AND t>=? AND t<=? ORDER BY t", (account_id, since, t))]
    cov = [dict(json.loads(r["coverage_json"]), agent_id=r["agent_id"]) for r in ctx.db.q("SELECT * FROM flow_coverage WHERE account_id=? ORDER BY agent_id", (account_id,))]
    return {"since": since, "until": t, "W": W, "H": H, "F": F,
            "A100": round(100.0 * H / W, 2) if W else None, "F100": round(100.0 * F / W, 2) if W else None,
            "by_verdict": by_verdict, "by_reason": by_reason, "by_agent": by_agent, "gateway_refusals": gate,
            "approval_rate_refusals": rate_refusals, "pending_by_role": escalate.pending_by_role(ctx, account_id, t),
            "catalog_drift": drift, "coverage": cov, "suggestions": suggest.suggestions(ctx, account_id, t)}
