"""r0310 (Fable recommendation, owner 14.11): re-consent to the current reason vocabulary in one passkey touch.

A mandate pins the vocabulary its questions are worded in (app/vocab.py: digest in the signed tool map document). Signed = shown: a
person who signed under mr-vocab-1..5 keeps seeing the older, less clear sentences (actions._pinned_has, qwords.V6_SWAP). Measured on
production 14.11: 145 of 260 active mandates. This module lets that person sign the SAME mandate again under the current vocabulary:

  - the new mandate is the old one member for member, except id (new), nbf (now), exp (the old exp, never later) and toolmap_sha256
    (the hash of the CURRENT gateway document, which must equal the old signed one except its member "vocab"): `not_wider` checks it at
    draft time and again under the account lock before the ledger is written; nothing in it can grant more;
  - it is signed by the owner's passkey exactly like a mandate signed on the mandate page (wa-sig over the CDE of the mandate, typ
    application/aar-mandate+cbor), and recorded by actions.register_mandate, which supersedes the active one (the existing path);
  - the old mandate, its receipts and its evidence packs stay as they were (superseded is an index status; the ledger keeps both);
  - a purchase budget is counted per mandate id by the core: a new id would start a new spending window, so re-consent is refused while
    the old mandate has spent anything in its current window (RENEW_BUDGET_OPEN): never more money than signed;
  - a team account (org policy) is not offered it: a k-of-n mandate is not re-signed by one signature (the team signs on the mandate page);
  - project permissions ("from now on") and repeat approvals name the old mandate's hash: they end (narrower, not wider); the page says
    how many before the passkey prompt.

The hint (one line under Details of a question, and on the mandate page) is a nudge, not a nag: an EPISODE of OFFER_S (it stays through
reloads and on both pages) at most once per (mandate, vocabulary version), at most one episode per GAP_S per account; "Not now" ends it.
"""
import json
import os
import time

from app import vocab
from app.context import Err

OFFER_S = 86400            # one episode: shown for a day from the first time the page asked
GAP_S = 7 * 86400          # at most one episode a week per account
TEXT = "Clearer wording is available — update the mandate (confirm with passkey)"
SAME = ("v", "principal", "agent", "currency", "budget_window_s", "permissions", "forbidden_data", "named_circle", "key_attestation",
        "pin_source")
CHANGED = ("id", "nbf", "exp", "toolmap_sha256")


def now():
    return int(time.time())


def _table(db):
    db.x("CREATE TABLE IF NOT EXISTS renew_offers(account_id TEXT NOT NULL, mandate_id TEXT NOT NULL, vocab_v TEXT NOT NULL, "
         "first_at INTEGER NOT NULL, closed_at INTEGER, PRIMARY KEY(account_id, mandate_id, vocab_v))")


# ---------------- which vocabulary a mandate pinned ----------------
def _pinned_doc(ctx, m_row):
    """-> (digest or None, vocabulary document or None) of the vocabulary the mandate's stored gateway document names."""
    try:
        d = json.loads(m_row["gateway_doc"]) if m_row["gateway_doc"] else None
    except (TypeError, ValueError, KeyError, IndexError):
        return None, None
    dg = d.get("vocab") if isinstance(d, dict) else None
    if not isinstance(dg, str):
        return None, None
    v = ctx.db.one("SELECT json FROM vocabs WHERE digest=?", (dg,))
    try:
        return dg, (json.loads(v["json"]) if v is not None else None)
    except (TypeError, ValueError):
        return dg, None


def pinned_v(ctx, m_row):
    """"mr-vocab-N", "none" (pins no vocabulary: shown the current words already) or "unknown" (a digest this server does not hold)."""
    dg, doc = _pinned_doc(ctx, m_row)
    if dg is None:
        return "none"
    return doc["v"] if isinstance(doc, dict) and isinstance(doc.get("v"), str) else "unknown"


def stale(ctx, m_row, cur=None):
    """True when the pinned vocabulary lacks sentences the current one has (its questions use older words). A mandate that pins none, or
    a digest the server does not hold, is not stale (actions._pinned_has shows it the current words already)."""
    dg, doc = _pinned_doc(ctx, m_row)
    if dg is None or not isinstance(doc, dict):
        return False
    cur = vocab.doc() if cur is None else cur
    if dg == vocab.digest(cur):
        return False
    old = doc.get("screen") if isinstance(doc.get("screen"), dict) else {}
    return bool(set(cur["screen"]) - set(old))


def by_vocab(ctx, account_id=None):
    """Active mandates by the vocabulary they pinned: {"active": n, "stale": n, "current": "mr-vocab-6", "by": {"mr-vocab-3": n, ...}}."""
    cur = vocab.doc()
    q, a = "SELECT * FROM mandates WHERE status='active'", ()
    if account_id is not None:
        q, a = q + " AND account_id=?", (account_id,)
    by, n, st = {}, 0, 0
    for r in ctx.db.q(q, a):
        n += 1
        k = pinned_v(ctx, r)
        by[k] = by.get(k, 0) + 1
        st += 1 if stale(ctx, r, cur) else 0
    return {"active": n, "stale": st, "current": cur["v"], "by": dict(sorted(by.items()))}


# ---------------- may this mandate be re-signed as is ----------------
def _old(ctx, acc, mid):
    r = ctx.db.one("SELECT * FROM mandates WHERE id=? AND account_id=?", (mid, acc["id"])) if isinstance(mid, str) else None
    if r is None:
        raise Err(404, "NOT_FOUND")
    return r


def not_wider(old, new):
    """None when `new` grants nothing `old` did not: every member equal except id, nbf (not earlier), exp (not later), toolmap_sha256
    (checked against the gateway document by `_same_map`). Else a short reason."""
    if not isinstance(old, dict) or not isinstance(new, dict):
        return "not a mandate"
    if set(new) != set(old):
        return "members differ: %s" % sorted(set(new) ^ set(old))
    for k in old:
        if k in CHANGED:
            continue
        if new[k] != old[k]:
            return "member %s differs" % k
    if new.get("id") == old.get("id"):
        return "the id is the old one"
    if not (isinstance(new.get("nbf"), int) and isinstance(new.get("exp"), int)):
        return "nbf / exp"
    if new["nbf"] < old["nbf"] or new["exp"] > old["exp"]:
        return "the time is wider than the old mandate's"
    return None


def _same_map(ctx, acc, old_row, new_doc):
    """The old SIGNED gateway document (verified against the hash inside the old mandate) equals the current one except "vocab"."""
    from app import actions as act
    sg = act.signed_gateway(old_row)
    if sg is None or sg[0] is None:
        return False
    a = {k: v for k, v in sg[0].items() if k != "vocab"}
    b = {k: v for k, v in new_doc.items() if k != "vocab"}
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def _ends(ctx, acc, mid, t):
    al = ctx.db.one("SELECT COUNT(*) AS n FROM allowances WHERE account_id=? AND mandate_id=? AND ended_at IS NULL AND exp>=?",
                    (acc["id"], mid, t))["n"]
    rp = ctx.db.one("SELECT COUNT(*) AS n FROM repeat_approvals WHERE account_id=? AND mandate_id=? AND ended_at IS NULL AND exp>=? AND uses>0",
                    (acc["id"], mid, t))["n"]
    return {"allowances": al, "repeat": rp}


def why_not(ctx, acc, old_row, t=None, doc=None):
    """None when the mandate may be re-signed under the current vocabulary now, else an error code (the hint is not offered)."""
    from app import actions as act, org
    t = now() if t is None else t
    if old_row["status"] != "active":
        return "MANDATE_NOT_ACTIVE"
    if not stale(ctx, old_row):
        return "RENEW_NOT_NEEDED"
    if org.current_policy(ctx, acc["id"]) is not None:
        return "RENEW_TEAM"
    m = json.loads(old_row["mandate_json"])
    if not isinstance(m.get("exp"), int) or m["exp"] <= t + 60:
        return "RENEW_EXPIRING"
    ag = ctx.db.one("SELECT * FROM agents WHERE id=? AND account_id=?", (old_row["agent_id"], acc["id"]))
    if ag is None:
        return "NOT_FOUND"
    doc = act.gateway_doc(ctx, acc["id"], json.loads(ag["toolmap_json"])) if doc is None else doc
    if not _same_map(ctx, acc, old_row, doc):
        return "RENEW_MAP_CHANGED"
    pu = (m.get("permissions") or {}).get("purchase")
    if isinstance(pu, dict):
        with ctx.hub.lock(acc["id"]):
            L = ctx.hub.ledger(acc["id"])
            tt = L.sync_now()
            if L.S.committed(tt, m["id"], m.get("budget_window_s", 86400)) > 0:
                return "RENEW_BUDGET_OPEN"
    return None


MESSAGES = {"MANDATE_NOT_ACTIVE": "this mandate is no longer active",
            "RENEW_NOT_NEEDED": "this mandate already shows the current wording",
            "RENEW_TEAM": "a team's mandate is signed again by the team on the mandate page",
            "RENEW_EXPIRING": "this mandate is about to end: sign a new one on the mandate page",
            "NOT_FOUND": "unknown agent",
            "RENEW_MAP_CHANGED": "the agent's tools, the protected data or the advisor mode changed since you signed: review and sign on the mandate page",
            "RENEW_BUDGET_OPEN": "this mandate spent money in its current budget window: a new mandate would start a new window, so update "
                                 "it after the window ends"}


def _refuse(code):
    raise Err(409, code, MESSAGES.get(code, code))


# ---------------- the hint and its frequency guard ----------------
def offer(ctx, acc, mid, t=None, mark=True):
    """-> {"show": bool, ...}. show only for a stale, re-signable mandate, inside an open episode or when a new one may start."""
    t = now() if t is None else t
    r = _old(ctx, acc, mid)          # r0311: a mandate of another account is 404 (it was 200 {"show": false}: an existence oracle)
    if why_not(ctx, acc, r, t) is not None:
        return {"show": False}
    _table(ctx.db)
    cur = vocab.V
    ep = ctx.db.one("SELECT first_at, closed_at FROM renew_offers WHERE account_id=? AND mandate_id=? AND vocab_v=?", (acc["id"], mid, cur))
    if ep is not None:
        show = ep["closed_at"] is None and t < ep["first_at"] + OFFER_S
    else:
        last = ctx.db.one("SELECT MAX(first_at) AS t FROM renew_offers WHERE account_id=?", (acc["id"],))["t"]
        show = last is None or t >= last + GAP_S
        if show and mark:
            ctx.db.x("INSERT OR IGNORE INTO renew_offers(account_id, mandate_id, vocab_v, first_at) VALUES(?,?,?,?)", (acc["id"], mid, cur, t))
    out = {"show": bool(show)}
    if show:
        out.update(mandate_id=mid, agent_id=r["agent_id"], text=TEXT, pinned=pinned_v(ctx, r), current=cur,
                   url="mandate.html?agent=%s&renew=%s" % (r["agent_id"], mid))
    return out


def dismiss(ctx, acc, mid, t=None):
    """"Not now": the episode of this (mandate, vocabulary) ends; it is not offered again for this vocabulary version."""
    t = now() if t is None else t
    _old(ctx, acc, mid)
    _table(ctx.db)
    ctx.db.x("INSERT OR IGNORE INTO renew_offers(account_id, mandate_id, vocab_v, first_at) VALUES(?,?,?,?)", (acc["id"], mid, vocab.V, t))
    ctx.db.x("UPDATE renew_offers SET closed_at=? WHERE account_id=? AND mandate_id=? AND vocab_v=? AND closed_at IS NULL",
             (t, acc["id"], mid, vocab.V))
    return {"ok": True}


def _close(ctx, acc, mid, t):
    _table(ctx.db)
    ctx.db.x("UPDATE renew_offers SET closed_at=? WHERE account_id=? AND mandate_id=? AND closed_at IS NULL", (t, acc["id"], mid))


# ---------------- draft and register ----------------
def draft(ctx, acc, mid, t=None):
    """-> what the page signs: {mandate, typ, gateway, gateway_sha256, replaces, ends}. The page checks the gateway hash and compares the
    mandate with the active one it shows (web/js/mandate.js renewCheck) before the passkey prompt."""
    import wa_profile as wa
    from app import actions as act
    t = now() if t is None else t
    r = _old(ctx, acc, mid)
    ag = ctx.db.one("SELECT * FROM agents WHERE id=? AND account_id=?", (r["agent_id"], acc["id"]))
    doc = act.gateway_doc(ctx, acc["id"], json.loads(ag["toolmap_json"])) if ag is not None else None
    code = why_not(ctx, acc, r, t, doc)
    if code:
        _refuse(code)
    old = json.loads(r["mandate_json"])
    new = dict(old, id=os.urandom(16).hex(), nbf=t, exp=old["exp"], toolmap_sha256=act.gateway_hash(doc))
    bad = not_wider(old, new)
    if bad:                                   # cannot happen by construction; a refusal, never a wider mandate
        raise Err(500, "RENEW_INTERNAL", bad)
    return {"mandate": new, "typ": wa.TYP_MANDATE, "gateway": doc, "gateway_sha256": new["toolmap_sha256"], "replaces": mid,
            "ends": _ends(ctx, acc, mid, t), "pinned": pinned_v(ctx, r), "current": vocab.V}


def register(ctx, acc, mid, m, env, t=None):
    """The signed re-consent: checks again under the account lock that `m` is the old mandate re-signed (not wider, same map but the
    vocabulary), then records it by the existing path (actions.register_mandate supersedes the old one)."""
    from app import actions as act, org, levels, wire
    t = now() if t is None else t
    if not isinstance(m, dict):
        raise Err(409, "MANDATE_MALFORMED")
    with ctx.hub.lock(acc["id"]):
        r = _old(ctx, acc, mid)
        if m.get("agent") != r["agent_id"]:
            raise Err(409, "RENEW_WIDER", "not the agent of the mandate it replaces")
        ag = ctx.db.one("SELECT * FROM agents WHERE id=? AND account_id=?", (r["agent_id"], acc["id"]))
        doc = act.gateway_doc(ctx, acc["id"], json.loads(ag["toolmap_json"]))
        code = why_not(ctx, acc, r, t, doc)
        if code:
            _refuse(code)
        bad = not_wider(json.loads(r["mandate_json"]), wire.wire_form(m))
        if bad:
            raise Err(409, "RENEW_WIDER", "the signed mandate is not the old one re-signed: " + bad)
        if wire.wire_form(m).get(wire.KEY) != act.gateway_hash(doc):
            raise Err(409, "TOOLMAP_CHANGED", "the tool map, the protected data or the advisor mode changed after the draft; draft again")
        import wa_profile as wa
        env = act.mandate_envelope(ctx, acc, wa.TYP_MANDATE, wa.cde(wire.cbor_form(m)), env)
        out = act.register_mandate(ctx, acc, m, env, None, None)
        org.touch_kids(ctx, levels.env_kids(env))
        _close(ctx, acc, mid, t)
    out["replaced"] = mid
    return out
