"""Agent API (Bearer dwk_ key) of ARHITEKTURA 5.2, plus the public witness record."""
import json
import os
import time

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from app import _paths  # noqa: F401
from app import actions as act
from app import erase
from app import trial
from app import refusals
from app import runcheck
from app import waiting
from app.context import Err, check_json, canon_rid
from app.hookjudge import judge as hj
import wa_profile as wa

RATE = 300     # requests per minute per key (0.2.49: was 60; DW_RATE_PER_MIN overrides). Hook steps share one window up to 3x, reads (GET) have their own


def make_router(ctx):
    r = APIRouter()
    db = ctx.db

    def agent_of(req, scope="key:", mult=1, weight=1):
        h = req.headers.get("authorization", "")
        if not h.startswith("Bearer dwk_") or len(h) > 200:
            raise Err(401, "BAD_KEY")
        kh = ctx.key_hash(h[7:])
        a = db.cached(("agent_key", kh), ("agents",), lambda: db.one("SELECT * FROM agents WHERE key_hash=? AND disabled_at IS NULL", (kh,)))     # 0.2.18: until agents is written
        if not a:
            raise Err(401, "BAD_KEY")
        if trial.expired(ctx, a["account_id"]):
            raise Err(401, "TRIAL_EXPIRED", "this quick start account has expired and is being erased: run `deus-witness try` again, or sign up")
        req.state.account = a["account_id"]
        rate = RATE if ctx.cfg.rate_per_min is None else ctx.cfg.rate_per_min
        if not ctx.limiter.hit(scope + a["id"], rate * mult, 60, weight=weight):
            refusals.note(ctx, "RATE_MINUTE", a["account_id"], a["id"])
            raise Err(429, "RATE_LIMIT", "slow down: %d requests a minute per key; the call did not run" % (rate * mult))
        return a

    async def body(req):
        try:
            b = await req.json()
        except Err:
            raise                                 # 413 from the body limit
        except Exception:
            raise Err(400, "BAD_REQUEST", "JSON body expected")
        check_json(b, "BAD_AMOUNT")
        return b if isinstance(b, dict) else {}

    def salt_capable(req):
        """0.2.35: deus-witness >= 0.2.26 sends X-DW-Args-Salt: 1 (it hashes with GET /v1/salt). See erase.salt_for."""
        return req.headers.get("x-dw-args-salt") == "1"

    @r.get("/v1/salt")
    async def salt_get(req: Request):
        """0.2.35: the salt of the key's account for args_sha256 = HMAC-SHA-256(salt, "dw-args1\\0" + canonical [tool, args]).
        {"alg": "dw-args1", "mode": off|transition|on, "salt": base64url | null}; null (off) = hash with the bare SHA-256. The salt is the
        account's own secret towards third parties: it is given only against the agent key, never in a public page or in the journal."""
        a = agent_of(req, "read:", 1)                     # 0.2.49: reads count in their own window
        mode = getattr(ctx.cfg, "args_salt", "off")
        s = await run_in_threadpool(erase.account_salt, ctx, a["account_id"]) if mode != "off" else None
        return {"alg": "dw-args1", "alg2": "mr-args-2", "mode": mode, "salt": wa.b64u(s) if s is not None else None}

    @r.post("/v1/actions")
    async def action_post(req: Request):
        a = agent_of(req)
        b = await body(req)
        tool, args = b.get("tool"), b.get("args")
        args = {} if args is None else args
        if not isinstance(tool, str) or not tool or not isinstance(args, dict):
            raise Err(400, "BAD_REQUEST", "tool (string) and args (object) required")
        # r0269: X-DW-Args-V: 2 = the client hashes [tool, args] with RFC 8785 (rule mr-args-2, toolmap.args_digest_v); the action
        # says so (`args_v: 2`). Absent = the old rule, what every deployed client checks.
        tok = act.tm.ARGS_V.set(2 if req.headers.get("x-dw-args-v") == "2" else 1)
        try:
            return await run_in_threadpool(act.do_action, ctx, a, tool, args, salt_capable(req))
        finally:
            act.tm.ARGS_V.reset(tok)

    @r.post("/v1/trial/retire")
    async def trial_retire(req: Request):
        """0.2.39: `deus-witness try` again erases the previous trial account while it has no passkey (app/trial.py retire)."""
        if not trial.enabled(ctx):
            raise Err(404, "NOT_FOUND")
        a = agent_of(req)
        return await run_in_threadpool(trial.retire, ctx, a)

    @r.get("/v1/trial/status")
    async def trial_status(req: Request):
        """2710u: has this trial account a passkey? `deus-witness try` asks before it makes a new one (app/trial.py status)."""
        if not trial.enabled(ctx):
            raise Err(404, "NOT_FOUND")
        a = agent_of(req, "read:", 1)
        return await run_in_threadpool(trial.status, ctx, a)

    @r.get("/v1/actions/{rid}")
    async def action_get(rid: str, req: Request, wait: int = 0, final: int = 0):
        rid = canon_rid(rid)
        a = agent_of(req, "read:", 1)         # 0.2.49: status reads (the long poll too) have their own window; the judge, present and report share the key's
        act.own_agent_action(ctx, a, rid)
        end = time.time() + max(0, min(wait, 25))
        last_poll, final = final == 1, False      # 0.2.43b (C): `final=1` = the hook's last poll (it gives up when this one ends by time)
        told = dropped = False
        first = True
        if wait > 0:
            waiting.begin(rid)
        try:
            while True:
                if wait > 0:
                    waiting.note(rid)         # 27.10 (polygon O3): the agent is still waiting for this call (app/waiting.py)
                x = act.refresh(ctx, rid)
                if x is None:             # 0.2.39: erased while waiting (a trial replaced by a newer `deus-witness try`)
                    raise Err(404, "NOT_FOUND")
                if first and wait > 0 and x["gave_up_at"]:
                    await run_in_threadpool(act.clear_gave_up, ctx, rid)    # 0.2.43b: polled again (the same call repeated): waiting again
                first = False
                if x["status"] not in ("pending_approval", "held") or time.time() >= end:
                    # late 29.10: a held call waits for a human like a question: the hook that gives up on it is marked the same way
                    told = last_poll and x["status"] in ("pending_approval", "held") and time.time() >= end     # 0.2.43b (C): the hook SAYS it is its last poll
                    final = told or (0 < wait < waiting.MAX_WAIT and x["status"] in ("pending_approval", "held"))     # s7 (Z3): the hook's last poll (guessed)
                    if told:
                        await run_in_threadpool(act.mark_gave_up, ctx, rid)
                    if x["aar"] is not None and x["proof_json"] is None:    # R-16: inclusion proofs are made on demand, in a batch
                        await run_in_threadpool(act.materialize_proofs, ctx, x["account_id"])
                        x = act.refresh(ctx, rid)
                    return act.to_result(ctx, x)
                await _sleep(0.25)
                dw = req.scope.get("dw_dropped")      # app/main.py DropWatch
                if wait > 0 and dw is not None and dw.is_set():
                    # 2710u (polygon series 2, proposal 3): the client went away mid-poll (the hook killed by Claude Code's timeout,
                    # Ctrl-C, a closed session): our hooks and SDKs never re-poll after a dropped connection, so it stopped waiting
                    # NOW, not GRACE_S later. Nobody reads this answer.
                    dropped = True
                    return act.to_result(ctx, x)
        finally:
            if wait > 0:
                waiting.end(rid, dropped, final=final, told=told)

    @r.post("/v1/actions/{rid}/present")
    async def present(rid: str, req: Request):
        rid = canon_rid(rid)
        a = agent_of(req, "key:", 3)
        return await run_in_threadpool(act.do_present, ctx, a, rid)

    @r.post("/v1/actions/{rid}/report")
    async def report(rid: str, req: Request):
        rid = canon_rid(rid)
        a = agent_of(req, "key:", 3)
        b = await body(req)
        if not isinstance(b.get("executed"), bool):
            raise Err(400, "BAD_REQUEST", "executed must be boolean")
        return await run_in_threadpool(act.do_report, ctx, a, rid, b["executed"])

    # ---- 0.2.16: the thin Claude Code hook (app/hookjudge) ----
    @r.post("/v1/hook/judge")
    async def hook_judge(req: Request):
        # one hook call = up to a few rounds (the classifier asks for file-system facts). 0.2.17 (R9-02): the SAME window as every other
        # request of the key (`key:`; the judge may fill it up to 3x the per-key rate, the other requests only up to 1x), a long body takes
        # more of it (hj.weight), the quota is checked before the classifier runs (hj.judge), and an account classifies at most
        # hj.MAX_CONCURRENT requests at a time
        a = agent_of(req, "key:", 3)                     # the key first: nobody without one makes the server read a body
        raw = await req.body()
        w = hj.weight(len(raw))
        if w > 1 and not ctx.limiter.hit("key:" + a["id"], (RATE if ctx.cfg.rate_per_min is None else ctx.cfg.rate_per_min) * 3, 60, weight=w - 1):
            refusals.note(ctx, "RATE_MINUTE", a["account_id"], a["id"])
            raise Err(429, "RATE_LIMIT", "slow down: a long request takes more of the per-key rate (%d a minute); the call did not run" % ((RATE if ctx.cfg.rate_per_min is None else ctx.cfg.rate_per_min) * 3))
        b = await body(req)
        if not await _enter_judge(a["account_id"]):
            raise Err(429, "RATE_LIMIT", "at most %d judge requests at a time per account" % hj.MAX_CONCURRENT)
        try:
            res = await run_in_threadpool(hj.judge, ctx, a, b, salt_capable(req))
        finally:
            hj.leave(a["account_id"])
        run_nonce = req.headers.get("x-dw-run")
        if run_nonce and isinstance(res, dict) and "need" not in res and b.get("part") is None:
            await run_in_threadpool(runcheck.judged, ctx, a, run_nonce)       # 0.2.63: one judged call of a `deus-witness run`
        return res

    # ---- 0.2.63 (RT-0.2.41 F1): the witness counts what a `deus-witness run` saw (app/runcheck.py) ----
    @r.post("/v1/hook/run")
    async def run_new(req: Request):
        a = agent_of(req, "key:", 1)
        return await run_in_threadpool(runcheck.create, ctx, a)

    @r.post("/v1/hook/run/start")
    async def run_start(req: Request):
        a = agent_of(req, "key:", 1)
        b = await body(req)
        return await run_in_threadpool(runcheck.start, ctx, a, req.headers.get("x-dw-run"), b.get("session"))

    @r.get("/v1/hook/run/{nonce}")
    async def run_view(nonce: str, req: Request):
        a = agent_of(req, "read:", 1)
        return await run_in_threadpool(runcheck.view, ctx, a, nonce)

    @r.get("/v1/export")
    async def export_ci(req: Request):
        """0.2.46: the evidence pack for CI. The agent key ALONE opens nothing here: the owner's export token for this agent is required too
        (app/export_tokens.py: read-only, short, revocable, bound to the agent). Same zip as /api/export."""
        from starlette.responses import Response
        from app import export_tokens as xt
        from app.export import build_pack
        a = agent_of(req, "key:", 1)
        if "frozen_at" in a.keys() and a["frozen_at"]:
            raise Err(403, "AGENT_FROZEN", "this agent is frozen: the owner unfreezes it, or exports from the dashboard")
        await run_in_threadpool(xt.take, ctx, a, req.headers.get("x-dw-export-token"))
        data, name = await run_in_threadpool(build_pack, ctx, a["account_id"])
        return Response(data, media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="%s"' % name,
                                                                     "Cache-Control": "no-store"})

    @r.post("/v1/run-context")
    async def run_context(req: Request):
        """0.2.85 (app/runctx.py): the CI job declares its run (repository, commit, run id, workflow, actor, start, session ids); the
        witness signs it as a RUN_CONTEXT record bound to the ledger position and the decisions of the run; the pack carries it in runs/.
        Agent key AND the owner's export token (the CI token), like GET /v1/export: the agent's key alone declares nothing."""
        from app import export_tokens as xt
        from app import runctx
        a = agent_of(req, "key:", 1)
        if "frozen_at" in a.keys() and a["frozen_at"]:
            raise Err(403, "AGENT_FROZEN", "this agent is frozen: the owner unfreezes it first")
        tok = await run_in_threadpool(xt.check, ctx, a, req.headers.get("x-dw-export-token"))
        b = await body(req)
        return await run_in_threadpool(runctx.attest, ctx, a, tok, b)

    @r.get("/v1/hook/status")
    async def hook_status(req: Request, project: str = ""):
        """0.2.89: SessionStart of client 0.2.57 -- trial account? does the signed mandate cover this project? who hears a question?"""
        a = agent_of(req, "read:", 1)
        return await run_in_threadpool(hj.status, ctx, a, project)

    @r.get("/v1/hook/scanlist")
    async def hook_scanlist(req: Request):
        agent_of(req, "read:", 1)
        return scanlist_signed()

    _signed = {}

    def scanlist_signed():
        lst = hj.scan_list()
        if _signed.get("rev") != lst["rev"]:
            import cbor2
            from svidetel_v4 import cose
            cb = cose.sign1(ctx.wk, cbor2.dumps(lst, canonical=True), TYP_SCANLIST)
            _signed.update(rev=lst["rev"], body={"rev": lst["rev"], "typ": TYP_SCANLIST, "cose_b64": wa.b64u(cb)})
        return _signed["body"]

    return r


TYP_SCANLIST = "application/dw-scanlist+cbor"


async def _enter_judge(account_id):
    """0.2.18: a judge request that finds the account's slots taken waits up to hj.ENTER_WAIT_S for one (the 3 agents of an account
    working at the same time are normal), then 429; at most hj.MAX_WAITING wait per account, the others get 429 at once. The bound itself (hj.MAX_CONCURRENT classifying at once, R9-02) is unchanged."""
    if hj.enter(account_id):
        return True
    if not hj.wait_begin(account_id):
        return False                              # hj.MAX_WAITING already wait: a burst gets 429 at once
    try:
        end = time.time() + hj.ENTER_WAIT_S
        while not hj.enter(account_id):
            if time.time() >= end:
                return False
            await _sleep(0.02)
        return True
    finally:
        hj.wait_end(account_id)


async def _sleep(s):
    import asyncio
    await asyncio.sleep(s)
