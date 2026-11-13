"""Seams 01 <-> 02 (ARHITEKTURA-0.2 §8). 01 calls, 02 implements.
pre_authorize: after the dry decision `L.S.decide_for`, before `L.authorize`. on_decided: after the row of the action is stored.
Law §0 p.2: these functions only TIGHTEN (allow -> hold/deny, defer -> deny), never the other way."""
from app.flow import advisor, escalate, rate
from app.flow.api import router  # noqa: F401  (FastAPI APIRouter: /api/suggestions, /api/digest, /api/approvals/batch|groups, /v1/catalog, /v1/coverage, /api/catalog/*)


def pre_authorize(ctx, agent, mandate_row, act, dry_verdict, dry_reason):
    """-> None | ("deny", code) | ("hold", code). APPROVAL_RATE (dry defer only), ADVISORY_HOLD (dry allow only)."""
    if dry_verdict == "defer":
        return rate.check(ctx, agent, dry_verdict, act=act)
    if dry_verdict == "allow":
        return advisor.check(ctx, agent, mandate_row, act, dry_verdict)
    return None


def on_decided(ctx, agent, row):
    """Digest counters are derived from `actions`/`approvals` (no extra state); here: escalation sweep of the agent's account."""
    escalate.sweep(ctx, agent["account_id"])
    return None
