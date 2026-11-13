"""Batch approval with ONE passkey ceremony (ARHITEKTURA-0.2 §3.3): envelope `wb` over the SHA-256 of every item's approval payload.
Group = one agent, one class, one recipient, the same `approved`; <= 20 items; no item whose approval needs k >= 2 (those go one by one,
by quorum). The same `wb` bytes go into EVERY APPROVAL entry of the batch. Answer: a verdict per rid.
fatigue-fix (ZAMER-F100: hostile_in_benign_batch = 5): a money item whose amount is out of line with its group -- more than
OUTLIER_X x the largest amount the owner approved for this (agent, class, recipient) in 14 days, or, with no such history, more than
OUTLIER_X x the smallest pending amount of the group -- is offered ALONE (its own group of one) and never accepted in a batch with
other items (BATCH_OUTLIER): "$9000 at the vendor we buy coffee from" must not ride along with "approve 3"."""
import hashlib
import json

from app import _paths  # noqa: F401
import wa_profile as wa
from svidetel_v4.state import approval_payload
from app import actions as A
from app.context import Err, canon_rid
from app.flow import store
from app.flow.wq import wq

MAX_ITEMS = 20
OUTLIER_X = 2
HISTORY_S = 14 * 86400
MONEY = ("purchase", "sale", "refund")


def _rp(ctx):
    return {"rp_id": ctx.cfg.rp_id, "origins": [ctx.cfg.origin]}


def needs_quorum(policy, action):
    """True when the approval of this action needs k >= 2 of some role under the current policy (solo account: never)."""
    if policy is None:
        return False
    return any(k >= 2 for _, k in wq.requirements(policy, wa.TYP_APPROVAL, None, action))


def _key(x):
    return (x["agent_id"], x["class"], x["recipient"] or "")


def outliers(ctx, account_id, ys, t=None):
    """rids of the money items of ONE group (same _key) that must be decided alone (see the module doc)."""
    money = [y for y in ys if y["class"] in MONEY and isinstance(y["amount"], int)]
    if not money:
        return set()
    t = store.now() if t is None else t
    k = _key(money[0])
    r = ctx.db.one("SELECT MAX(a.amount) AS m FROM approvals p JOIN actions a ON a.rid=p.rid WHERE p.account_id=? AND p.approved=1 AND p.t>? "
                   "AND a.agent_id=? AND a.class=? AND COALESCE(a.recipient,'')=?", (account_id, t - HISTORY_S, k[0], k[1], k[2]))
    ref = r["m"] if r is not None and r["m"] is not None else min(y["amount"] for y in money)
    return {y["rid"] for y in money if y["amount"] > OUTLIER_X * ref}


def payloads(L, rids, approved, views=None):
    """-> [(rid, payload_bytes, sha256)] from the ledger state (the exact bytes Ledger.approve will check).
    pv2: views = [32 bytes per rid] (each item's own presentation hash inside its own approval payload) or None."""
    out = []
    for i, rid in enumerate(rids):
        rc = L.S.receipts.get(rid)
        if rc is None:
            raise Err(409, "NOT_DEFERRED", rid)
        p = approval_payload(L.S.mandates[rc["mandate"]], rc["action"], rid, approved, views[i] if views else None)
        out.append((rid, p, hashlib.sha256(p).digest()))
    return out


def awaited(y):
    """N19 0.2.74 (series 10): the agent's hook polls for this call NOW (its own wait, or the same call sent again: same request_hash, same
    rid). Such a call is never offered inside a batch: the owner gets its own row with Review (one call, one decision), and a batch of the
    agent's older calls of the same kind (often ones it gave up on) is not what that one live call waits for. gave_up_at = it said it gave up."""
    from app import waiting
    return waiting.awaited(y) is True


def groups(ctx, acc):
    """Ready homogeneous groups of the pending queue (<= 20 each; quorum items excluded), with the items to sign for approve and for refuse."""
    policy = store.current_policy(ctx, acc["id"])
    rows = []
    for x in ctx.db.q("SELECT rid FROM actions WHERE account_id=? AND status='pending_approval' ORDER BY created_at, rowid", (acc["id"],)):
        y = A.refresh(ctx, x["rid"])
        if y["status"] == "pending_approval" and y["mandate_id"] is not None and not needs_quorum(policy, json.loads(y["action_json"])) \
                and not awaited(y) and not A.hidden_sibling(ctx, y):
            rows.append(y)
    by = {}
    for y in rows:
        by.setdefault(_key(y), []).append(y)
    out = []
    with ctx.hub.lock(acc["id"]):
        L = ctx.hub.ledger(acc["id"]) if rows else None
        chunks, outs = [], set()
        for k in sorted(by):
            out_r = outliers(ctx, acc["id"], by[k])
            outs |= out_r
            ys = [y for y in by[k] if y["rid"] not in out_r]
            chunks += [(k, ys[i:i + MAX_ITEMS]) for i in range(0, len(ys), MAX_ITEMS)]
            chunks += [(k, [y]) for y in by[k] if y["rid"] in out_r]
        for k, chunk in chunks:
            rids = [y["rid"] for y in chunk]
            ok = payloads(L, rids, True)
            no = payloads(L, rids, False)
            out.append({"agent_id": k[0], "class": k[1], "recipient": k[2], "count": len(chunk), "rids": rids,
                        "outlier": len(chunk) == 1 and chunk[0]["rid"] in outs,
                        "items_approve_b64": [wa.b64u(h) for _, _, h in ok], "items_refuse_b64": [wa.b64u(h) for _, _, h in no],
                        "challenge_approve_b64": wa.b64u(wq.wb_challenge([h for _, _, h in ok])),
                        "challenge_refuse_b64": wa.b64u(wq.wb_challenge([h for _, _, h in no])),
                        "items": [{"rid": y["rid"], "tool": y["tool"], "amount": y["amount"], "text_preview": y["text_preview"] or "",
                                   "args_preview": y["args_preview"], "action": json.loads(y["action_json"]), "expires": y["expires"]} for y in chunk]})
    return out


def _signer_check(ctx, acc_id, policy, env, pay, action):
    """verify_wb against the signer: a member of the current policy (team) or an ACTIVE passkey of the account (solo, 0.2.2)."""
    import cbor2
    from app import org
    kid = cbor2.loads(env)["kid"]
    if org.revoked_kid(ctx, kid):
        return "KEY_REVOKED"
    if policy is not None:
        mem = {m["kid"]: m for m in policy["members"]}.get(kid)
        if mem is None:
            return "WQ_NOT_MEMBER"
        code = wq.verify_wb(env, wa.TYP_APPROVAL, pay, mem, rp=_rp(ctx))
        return code or wq.wb_requirements_met(policy, kid, action)
    who = ctx.hub.active_keys(acc_id).get(kid)
    return wq.verify_wb(env, wa.TYP_APPROVAL, pay, who) if who else "KEY_MISMATCH"


def approve_one(ctx, acc, rid, approved, env, view=None):
    """One item of the batch: 01's actions.approve_with_envelope when it exists, else the core directly (under hub.lock, like do_approve)."""
    f = getattr(A, "approve_with_envelope", None)
    if f is not None:
        return f(ctx, acc, rid, approved, env, counted=True, view=view)     # 0.2.20: one wb = one counter, checked once in do_batch
    L = ctx.hub.ledger(acc["id"])
    res = L.approve(rid, cose_bytes=env, approved=approved, issue_aar=True)
    if res["result"] != "accept":
        raise Err(409, res["reason"])
    t = A.now()
    ctx.db.x("INSERT OR REPLACE INTO approvals(rid,account_id,approved,envelope,ledger_seq,t) VALUES(?,?,?,?,?,?)",
             (rid, acc["id"], 1 if approved else 0, env, L.aseq.get(rid), t))
    if not approved:
        ctx.db.x("UPDATE actions SET status='refused', verdict='deny', reason='REFUSED', updated_at=? WHERE rid=?", (t, rid))
        return {"verdict": "refused"}
    pj = A.proof_json(L.receipt_proof(rid, approval=True), approval=env)
    ctx.db.x("UPDATE actions SET status='approved', verdict='allow', reason='OK_APPROVED', aar=?, proof_json=?, updated_at=? WHERE rid=?",
             (res["aar"], json.dumps(pj), t, rid))
    return {"verdict": "allow"}


def _views(ctx, rids, views):
    """pv2: the batch request's `views` (one 64-hex presentation hash per rid, in the order of rids) -> [bytes] | None (not claimed)."""
    if views is None:
        return None
    if not isinstance(views, list) or len(views) != len(rids):
        raise Err(400, "BAD_REQUEST", "views: one view_sha256 per rid, in the order of rids")
    parse = getattr(ctx, "view_parse", None)
    if parse is None:
        raise Err(409, "VIEW_CHANGED", "the witness cannot rebuild the views of this batch")
    out = [parse(v) for v in views]
    if any(v is None for v in out):
        raise Err(400, "BAD_REQUEST", "views: one view_sha256 per rid, in the order of rids")
    return out


def do_batch(ctx, acc, rids, approved, env, views=None, user_id=None):
    """pv2: views = the presentation hash of EACH item (the page builds each item's view from its own GET /api/approvals/{rid} and signs it
    inside that item's approval payload; the wb lists the hashes of those payloads). Checked under hub.lock against the rows, item by item,
    before the first entry: one changed item refuses the whole batch (VIEW_CHANGED). No views (an older page): accepted as before, every
    APPROVAL is marked "view not signed"; views claimed but not signed (or signed but not claimed) -> WB_ITEM."""
    if isinstance(rids, list):
        rids = [canon_rid(r) for r in rids]
    if not isinstance(rids, list) or not rids or not all(isinstance(r, str) for r in rids) or len(set(rids)) != len(rids):
        raise Err(400, "BAD_REQUEST", "rids: non-empty list of distinct strings")
    if len(rids) > MAX_ITEMS:
        raise Err(409, "BATCH_SIZE", "at most %d items in one batch" % MAX_ITEMS)
    if not isinstance(approved, bool):
        raise Err(400, "BAD_REQUEST", "approved must be boolean")
    if wq.envelope_kind(env) != "wb":
        raise Err(409, "WB_MALFORMED")
    vs = _views(ctx, rids, views)
    with ctx.hub.lock(acc["id"]):
        rows = [A.own_account_action(ctx, acc, r) for r in rids]          # 404 for a rid of another tenant
        for x in rows:
            if x["status"] != "pending_approval" or x["mandate_id"] is None:
                raise Err(409, "NOT_DEFERRED", x["rid"])
        # 04.11 (L3): the parts of ONE tool call (hookjudge/judge.py _one_question) are asked as one question: a lead and the parts linked to
        # it (actions.line_lead), all of one agent; they differ in tool and class, and one wb decides exactly them
        leads = {x["line_lead"] or x["rid"] for x in rows}
        line = len(rows) >= 2 and len(leads) == 1 and next(iter(leads)) in {x["rid"] for x in rows} and len({x["agent_id"] for x in rows}) == 1 \
            and all(x["line_lead"] is None for x in rows if x["rid"] in leads) and store.current_policy(ctx, acc["id"]) is None
        # (red team p.5: with a team policy the parts are separate questions again, actions.hidden_sibling; such a batch is BATCH_MIXED)
        if line and approved and vs is None:
            # red team p.1/p.2: the parts of one call are approved only over the view of EVERY part the lead's page showed (no "view not signed")
            raise Err(409, "LINE_VIEW", "the parts of one call are approved with the view of every part")
        if not line and len({_key(x) for x in rows}) != 1:
            raise Err(409, "BATCH_MIXED", "one agent, one class, one recipient per batch")
        if len(rows) >= 2 and not line:
            group = [A.refresh(ctx, y["rid"]) for y in ctx.db.q("SELECT rid FROM actions WHERE account_id=? AND status='pending_approval' AND agent_id=? "
                                                                  "AND class=? AND COALESCE(recipient,'')=?", (acc["id"],) + _key(rows[0]))]
            bad = outliers(ctx, acc["id"], [y for y in group if y["status"] == "pending_approval"]) & {x["rid"] for x in rows}
            if bad:
                raise Err(409, "BATCH_OUTLIER", sorted(bad)[0])
        policy = store.current_policy(ctx, acc["id"])
        acts = [json.loads(x["action_json"]) for x in rows]
        if any(needs_quorum(policy, a) for a in acts):
            raise Err(409, "BATCH_QUORUM", "an item needs k >= 2: approve it alone, by quorum")
        if vs is not None:                                                # pv2: each item's view = the rows' view now (same lock as the entries)
            vs = [ctx.view_match(acc, r, user_id, v) for r, v in zip(rids, vs)]
        L = ctx.hub.ledger(acc["id"])
        L.sync_now()
        pays = payloads(L, rids, approved, vs)
        import cbor2
        if sorted(cbor2.loads(env)["items"]) != sorted(h for _, _, h in pays):
            raise Err(409, "WB_ITEM", "the batch envelope must list exactly the items of these rids")
        for (rid, p, _), a in zip(pays, acts):                            # everything is checked BEFORE the first entry is written
            code = _signer_check(ctx, acc["id"], policy, env, p, a)
            if code:
                raise Err(409, code, rid)
        from app import org
        org.check_sign_counts(ctx, env, "batch", acc["id"])                # 0.2.20: once for the whole batch, before the first entry
        from app import waiting
        live = {x["rid"]: waiting.awaited(x) for x in rows}               # N18 0.2.74: before the decision (it ends the wait)
        order = list(range(len(pays)))
        if line:
            # 04.11 (red team p.3): ONE tool call is decided all or nothing. Every check of every part's decision (approve_with_envelope:
            # delegation, the device level of an approval, the signature over each part's payload) runs BEFORE the first entry: one part that
            # fails refuses the batch and nothing is written. The lead is written last: a refusal of the lead withdraws the parts still
            # waiting, so each part gets its own signed refusal first; and an approval that fails on a part leaves the lead (the question the
            # owner sees) waiting instead of approving it without that part.
            f = getattr(A, "approve_with_envelope", None)
            if f is not None:
                for i, (rid, _, _) in enumerate(pays):
                    f(ctx, acc, rid, approved, env, counted=True, view=vs[i] if vs else None, dry=True)
            lead = next(iter(leads))
            order = [i for i in order if pays[i][0] != lead] + [i for i in order if pays[i][0] == lead]
        res = {}
        for i in order:
            rid = pays[i][0]
            try:
                r = dict(approve_one(ctx, acc, rid, approved, env, vs[i] if vs else None), rid=rid)
                if live.get(rid) is not None:
                    r["agent_waiting"] = live[rid]
                res[rid] = r
            except Err as e:
                res[rid] = {"rid": rid, "verdict": "error", "error": e.code}
                if line and approved:                                     # the rest of this call is not approved without this part
                    for j in order[order.index(i) + 1:]:
                        res[pays[j][0]] = {"rid": pays[j][0], "verdict": "error", "error": "NOT_WRITTEN"}
                    break
        out = [res[rid] for rid, _, _ in pays]
        return {"approved": approved, "count": len(out), "results": out}
