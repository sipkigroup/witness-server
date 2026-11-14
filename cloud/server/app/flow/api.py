"""Router of the flow (ARHITEKTURA-0.2 §8): /api/suggestions, /api/digest, /api/approvals/batch, /api/approvals/groups, /api/approvals/queue,
/v1/catalog, /v1/coverage, /api/catalog/{agent}, /api/catalog/{agent}/draft. Module-level APIRouter; the context is app.state.ctx.
NOTE for 01: include this router BEFORE api_web's (else POST /api/approvals/{rid} catches "batch" and GET /api/approvals/{rid} catches "groups")."""
from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from app import _paths  # noqa: F401
import wa_profile as wa
from app import auth
from app import refusals
from app.context import Err, check_json
from app.flow import batch, catalog, digest, escalate, suggest

router = APIRouter()
AGENT_RATE = 300


def _ctx(req):
    return req.app.state.ctx


async def _body(req):
    try:
        b = await req.json()
    except Err:
        raise
    except Exception:
        raise Err(400, "BAD_REQUEST", "JSON body expected")
    check_json(b)
    return b if isinstance(b, dict) else {}


def _agent_of(ctx, req):
    """Bearer dwk_ key -> agent row (same rules as api_agent: disabled keys refused, 300 requests/min per key)."""
    h = req.headers.get("authorization", "")
    if not h.startswith("Bearer dwk_") or len(h) > 200:
        raise Err(401, "BAD_KEY")
    a = ctx.db.one("SELECT * FROM agents WHERE key_hash=? AND disabled_at IS NULL", (ctx.key_hash(h[7:]),))
    if not a:
        raise Err(401, "BAD_KEY")
    req.state.account = a["account_id"]
    rate = AGENT_RATE if ctx.cfg.rate_per_min is None else ctx.cfg.rate_per_min
    if not ctx.limiter.hit("key:" + a["id"], rate, 60):
        refusals.note(ctx, "RATE_MINUTE", a["account_id"], a["id"])
        raise Err(429, "RATE_LIMIT", "slow down: %d requests a minute per key; the call did not run" % rate)
    return a


def _own_agent(ctx, acc, aid):
    a = ctx.db.one("SELECT * FROM agents WHERE id=? AND account_id=?", (aid, acc["id"])) if isinstance(aid, str) else None
    if not a:
        raise Err(404, "NOT_FOUND")
    return a


@router.get("/api/suggestions")
def suggestions(req: Request):
    ctx = _ctx(req)
    acc = auth.session_account(ctx, req)
    return {"suggestions": suggest.suggestions(ctx, acc["id"])}


@router.get("/api/digest")
def get_digest(req: Request, since: int = None):
    ctx = _ctx(req)
    acc = auth.session_account(ctx, req)
    return digest.digest(ctx, acc["id"], since)


@router.get("/api/approvals/groups")
def groups(req: Request):
    ctx = _ctx(req)
    acc = auth.session_account(ctx, req)
    return {"groups": batch.groups(ctx, acc)}


@router.get("/api/approvals/queue")
def queue(req: Request, roles: str = None):
    """Pending approvals filtered by role (budget: money classes, access: the rest; escalated also to owner). roles = comma list; none = all."""
    ctx = _ctx(req)
    acc = auth.session_account(ctx, req)
    rs = [x for x in roles.split(",") if x] if roles else None
    return {"items": escalate.queue(ctx, acc["id"], rs)}


@router.post("/api/approvals/batch")
async def approvals_batch(req: Request):
    ctx = _ctx(req)
    acc = auth.session_account(ctx, req, True)
    b = await _body(req)
    try:
        env = wa.b64u_dec(b["envelope_b64"])
    except Exception:
        raise Err(409, "WB_MALFORMED")
    res = await run_in_threadpool(batch.do_batch, ctx, acc, b.get("rids"), b.get("approved"), env, b.get("views"),   # pv2: per-item views
                                  getattr(req.state, "user", None))
    from app import uxstat                      # 0.2.96: "approved without reading" counts a batch item as a decision too
    rs_ = [x for x in (res.get("results") or []) if isinstance(x, dict)] if isinstance(res, dict) else []
    in_ = {x.get("rid") for x in rs_}
    for x in rs_:
        # r0281 (blind evaluation B8): a part of a call (line_lead) decided with its lead in this batch is the SAME human decision:
        # one passkey prompt, one question on the page; it is not counted a second time
        ll_ = ctx.db.one("SELECT line_lead FROM actions WHERE rid=? AND account_id=?", (x.get("rid"), acc["id"])) if isinstance(x.get("rid"), str) else None
        if ll_ is not None and ll_["line_lead"] and ll_["line_lead"] in in_:
            continue
        if x.get("verdict") in ("allow", "refused"):
            uxstat.record(ctx, acc["id"], x.get("rid"), "once" if res.get("approved") is True else "deny", b)
    return res


@router.post("/v1/catalog")
async def catalog_post(req: Request):
    ctx = _ctx(req)
    a = _agent_of(ctx, req)
    tools = catalog.check_catalog(await _body(req))
    return catalog.store_catalog(ctx, a, tools)


@router.post("/v1/coverage")
async def coverage_post(req: Request):
    ctx = _ctx(req)
    a = _agent_of(ctx, req)
    return catalog.store_coverage(ctx, a, await _body(req))


@router.get("/api/catalog/{aid}")
def catalog_get(aid: str, req: Request):
    ctx = _ctx(req)
    acc = auth.session_account(ctx, req)
    return catalog.get_catalog(ctx, _own_agent(ctx, acc, aid))


@router.post("/api/catalog/{aid}/draft")
async def catalog_draft(aid: str, req: Request):
    ctx = _ctx(req)
    acc = auth.session_account(ctx, req, True)
    b = await _body(req)
    return catalog.draft(ctx, _own_agent(ctx, acc, aid), b.get("decisions"))
