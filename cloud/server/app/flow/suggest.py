"""Learning of rights (ARHITEKTURA-0.2 §3.2): a deterministic function over the approval history. Output = a ready `form` for
POST /api/mandates/draft. Never applied by itself (the owner drafts, signs, the old mandate becomes superseded).

fatigue-fix (ZAMER-F100, 19.10.2026): a suggestion only WIDENS the active mandate. 0.2.0 turned questions into refusals (128 of 500
benign calls denied after applying the suggestions); the rules below are each covered by a test (tests_flow/test_suggest_widen.py):
  W1  a group (agent, class, recipient) approved >= 3 times within 14 days and never refused is a candidate; a recipient that the owner
      refused even once, or that is not a valid key of its class, is never suggested (message: one mailbox, as the core canonicalises it).
  W2  list classes (message, publish, delete): the recipient is ADDED to a list the mandate already has. A class the mandate leaves
      unspecified (the core asks: defer) is never closed by a suggestion: in the core a list denies everything outside it (RESOURCE /
      RECIPIENT), so "add #x" would turn every other channel's question into a refusal. Such groups are withheld (`withheld()`, reason
      CLOSES_UNSPECIFIED_CLASS).
  W3  purchase: the core has no vendor dimension, so the limits are per agent, from ALL its approved purchases in the window:
      max_per_action = max approved x 1.5 rounded UP to 1000 cents (p95 left 5 % of what the owner approved above the limit: deny);
      budget (the mandate's 24 h window) = the largest approved sum in any 24 h x 1.5, rounded up, >= max_per_action. Both never below
      the active mandate's values (only widen), never above the policy's `money_over` quorum threshold.
  W4  money the owner refused bounds the proposal: max_per_action and budget stay strictly below the smallest refused amount of the agent;
      when the approved history already reaches it (the owner's decisions are not monotonic in the amount) nothing is suggested
      (withheld, REFUSED_AMOUNT_WITHIN_HISTORY).
  W5  replay: every action approved in the window, judged by the core under the proposed mandate, is not denied (allow or, for a class
      left unspecified, defer as before). A proposal that fails the replay is withheld (REPLAY_DENIES_APPROVED).
  W6  (0.2.9) command (PROPOSAL-06): only a command of the narrow read-only list (W6_READONLY_COMMANDS, the 0.2.9 list: ls, cat, git status ...)
      is ever suggested; any other command, a variant ("git branch [write]", "ls [env LD_PRELOAD]", "./ls") and a dangerous one stay the owner's
      call (withheld, NOT_READ_ONLY). It is ADDED to command.allow; a mandate that leaves `command` unspecified gets {allow: [...], unlisted: "ask"}:
      that only widens (unlisted commands are asked exactly as before, W2 holds). `command: false` or `unlisted: "deny"` is never touched."""
import hashlib
import json
import math

from app import _paths  # noqa: F401
from svidetel_v4.decide import canon_addr, decide
from app.context import Err
from app.flow import store
from app.mandates import mandate_from_form
# 0.2.51: the learning digest (W6) stays on the narrow 0.2.9 read-only list, on purpose separate from the default mandate's list
# (app.toolmap's list grew in 0.2.51): a draft built from approvals proposes only these commands.
W6_READONLY_COMMANDS = ("ls", "pwd", "cd", "cat", "head", "tail", "wc", "echo", "grep", "rg", "which", "file", "stat", "du", "df", "date", "uname",
                        "git status", "git log", "git diff", "git show", "git branch")

WINDOW_S = 14 * 86400
MIN_APPROVALS = 3
ROUND_CENTS = 1000
MARGIN = 1.5                       # W3: headroom over the largest approved amount / 24 h sum
DAY_S = 86400                      # mandates_from_form: budget_window_s
MONEY = ("purchase", "sale", "refund")
FORM_CLASSES = ("purchase", "message", "delete", "publish", "command", "http")   # http (0.2.43): carried over, never suggested   # command (PROPOSAL-06): carried over; only read-only list entries are suggested (W6)
LISTS = {"message": ("message", "to"), "publish": ("publish", "channels"), "delete": ("delete", "targets")}


def p95(xs):
    s = sorted(xs)
    return s[max(0, math.ceil(0.95 * len(s)) - 1)]


def round_up(x):
    return int(math.ceil(x / ROUND_CENTS) * ROUND_CENTS)


def budget_of(amounts, cap=None):
    """W3: max approved x MARGIN rounded UP to 1000 cents (capped). Kept under the 0.2.0 name: it is the per-action limit now."""
    b = round_up(max(amounts) * MARGIN)
    return min(b, cap) if cap is not None else b


def max_day_sum(points):
    """points: [(t, amount)] -> the largest sum of amounts inside any window (t - 24 h, t] (the core's budget window)."""
    pts = sorted(points)
    best, j, run = 0, 0, 0
    for t, a in pts:
        run += a
        while pts[j][0] <= t - DAY_S:
            run -= pts[j][1]
            j += 1
        best = max(best, run)
    return best


def money_cap(policy):
    """Lowest `money_over` amount of the mandate rules that needs k >= 2 (above it the mandate needs a quorum); None = no cap."""
    if not policy:
        return None
    xs = [t["amount"] for t in policy.get("rules", {}).get("mandate", []) if t.get("if") == "money_over" and t.get("k", 1) >= 2]
    return min(xs) if xs else None


def form_of(m):
    """Mandate map (as produced by mandates.mandate_from_form) -> form; classes the form cannot express are listed in `lossy`."""
    P = m.get("permissions", {})
    f = {"currency": m.get("currency", "USD"), "valid_days": max(1, min(365, (m.get("exp", 0) - m.get("nbf", 0)) // 86400 or 30)),
         "forbidden_data": list(m.get("forbidden_data", []))}
    pu = P.get("purchase")
    if isinstance(pu, dict):
        f["purchase"] = {"enabled": True, "max_per_action": pu.get("max_per_action", 0), "budget": pu.get("budget", 0)}
    elif pu is False:
        f["purchase"] = {"enabled": False}
    ms = P.get("message")
    if isinstance(ms, dict):
        f["message"] = {"domains": list(ms.get("domains", [])), "to": list(ms.get("to", []))}
    elif ms is False:
        f["message"] = {"domains": [], "to": []}
    d = P.get("delete")
    if isinstance(d, dict):
        f["delete"] = {"targets": list(d.get("targets", [])), "allow_irreversible": bool(d.get("allow_irreversible"))}
    p = P.get("publish")
    if isinstance(p, dict):
        f["publish"] = {"channels": list(p.get("channels", []))}
    c = P.get("command")
    if isinstance(c, dict):
        f["command"] = {"allow": list(c.get("allow") or [])}
        if c.get("unlisted") is not None:
            f["command"]["unlisted"] = c["unlisted"]
    elif c is False:
        f["command"] = False
    hp = P.get("http")
    if isinstance(hp, dict):
        f["http"] = {"allow": list(hp.get("allow") or [])}
        if hp.get("unlisted") is not None:
            f["http"]["unlisted"] = hp["unlisted"]
    elif hp is False:
        f["http"] = False
    lossy = sorted(c for c in P if c not in FORM_CLASSES)
    return f, lossy


def _has_list(form, cls):
    sec, key = LISTS[cls]
    v = form.get(sec)
    return isinstance(v, dict) and isinstance(v.get(key), list) and (cls != "message" or bool(v.get("domains") or v.get("to")))


def _covered(form, cls, rcpt):
    if cls in LISTS:
        sec, key = LISTS[cls]
        return rcpt in (form.get(sec) or {}).get(key, [])
    return False


def _valid_key(cls, rcpt):
    """W1: only a key the core can match. message: exactly one mailbox as the core canonicalises it (no list, no double @, no <...>)."""
    if not rcpt or len(rcpt) > 256:
        return False
    if cls == "message":
        return "<" not in rcpt and canon_addr(rcpt) is not None
    return not rcpt.endswith("*")          # R3-09: in the core a trailing '*' is a PREFIX grant, wider than any approved call


def _command_form(form, rcpt):
    """W6 -> (form with rcpt added to command.allow, None) | (None, why) | (None, None) when already allowed."""
    if rcpt not in W6_READONLY_COMMANDS:
        return None, "NOT_READ_ONLY"
    c = form.get("command")
    if c is False or (isinstance(c, dict) and c.get("unlisted") == "deny"):
        return None, "COMMAND_CLOSED_BY_OWNER"
    if isinstance(c, dict) and (c.get("unlisted") == "allow" or rcpt in (c.get("allow") or [])):
        return None, None
    f = json.loads(json.dumps(form))
    f["command"] = dict(c) if isinstance(c, dict) else {"unlisted": "ask"}
    f["command"]["allow"] = list(f["command"].get("allow") or []) + [rcpt]
    return f, None


def _extend_list(form, cls, rcpt):
    f = json.loads(json.dumps(form))
    sec, key = LISTS[cls]
    f[sec][key] = list(f[sec][key]) + [rcpt]
    return f


def _purchase_limits(base, approved, refused_min, cap):
    """W3 + W4 -> (max_per_action, budget, why_withheld). approved: [(t, amount)] of the agent in the window."""
    amounts = [a for _, a in approved]
    mx, bd = budget_of(amounts), max(round_up(max_day_sum(approved) * MARGIN), 0)
    old = base.get("purchase") if (base.get("purchase") or {}).get("enabled") else None
    if old:
        mx, bd = max(mx, old.get("max_per_action", 0)), max(bd, old.get("budget", 0))
    if cap is not None:
        mx, bd = min(mx, cap), min(bd, cap)
    if refused_min is not None:
        if max(amounts) >= refused_min:
            return None, None, "REFUSED_AMOUNT_WITHIN_HISTORY"
        mx, bd = min(mx, refused_min - 1), min(bd, refused_min - 1)
    bd = max(bd, mx)
    if max(amounts) > mx or max_day_sum(approved) > bd:
        return None, None, "CAP_BELOW_HISTORY"                  # a capped proposal would deny what the owner approved (W5)
    return mx, bd, None


def _replay_ok(m, form, actions):
    """W5: every approved action of the window, judged by the core under the proposed permissions, is not denied."""
    try:
        P = mandate_from_form(form, m["principal"], m["agent"], m.get("pin_source"), now=m["nbf"], mid=m["id"])["permissions"]
    except Err:
        return False
    M = dict(m, permissions=P, _sig_valid=True, _revoked=False)
    for a in actions:
        v, _ = decide(M, a, {"mandate_committed": 0, "principal_committed": 0, "ceiling": None}, m["nbf"])
        if v == "deny":
            return False
    return True


def analyse(ctx, account_id, t=None):
    """-> (suggestions, withheld). withheld: [{agent_id, class, recipient, approvals, reason}] (W2/W4/W5; for the owner and the tests)."""
    t = store.now() if t is None else t
    policy = store.current_policy(ctx, account_id)
    cap = money_cap(policy)
    rows = ctx.db.q("SELECT a.agent_id, a.class, a.recipient, a.amount, a.action_json, a.created_at, p.approved FROM approvals p "
                    "JOIN actions a ON a.rid=p.rid WHERE p.account_id=? AND p.t>? ORDER BY p.t, p.rid", (account_id, t - WINDOW_S))
    groups, money = {}, {}
    for r in rows:
        g = groups.setdefault((r["agent_id"], r["class"], r["recipient"] or ""), {"ok": 0, "no": 0})
        g["ok" if r["approved"] else "no"] += 1
        if r["class"] == "purchase" and isinstance(r["amount"], int):
            mg = money.setdefault(r["agent_id"], {"approved": [], "refused": []})
            mg["approved" if r["approved"] else "refused"].append((r["created_at"], r["amount"]))
    approved_acts = {}
    for r in rows:
        if r["approved"] and r["action_json"]:
            approved_acts.setdefault(r["agent_id"], []).append(store.jl(r["action_json"], {}))
    out, withheld = [], []
    active = {}
    for (agent_id, cls, rcpt), g in sorted(groups.items()):
        if g["ok"] < MIN_APPROVALS or g["no"] or not _valid_key(cls, rcpt):
            continue                                                               # W1
        if cls in MONEY and cls != "purchase":
            continue
        if agent_id not in active:
            m = ctx.db.one("SELECT id, mandate_json FROM mandates WHERE agent_id=? AND status='active' ORDER BY created_at DESC, rowid DESC LIMIT 1", (agent_id,))
            active[agent_id] = (m["id"], json.loads(m["mandate_json"])) if m else None
        if active[agent_id] is None:
            continue
        mid, mm = active[agent_id]
        base, lossy = form_of(mm)
        held = lambda why: withheld.append({"agent_id": agent_id, "class": cls, "recipient": rcpt, "approvals": g["ok"], "reason": why})
        budget = None
        if cls in LISTS:
            if _covered(base, cls, rcpt):
                continue
            if not _has_list(base, cls):
                held("CLOSES_UNSPECIFIED_CLASS")                                     # W2
                continue
            form = _extend_list(base, cls, rcpt)
        elif cls == "command":
            form, why = _command_form(base, rcpt)
            if why:
                held(why)                                                            # W6
            if form is None:
                continue
        elif cls == "purchase":
            mg = money.get(agent_id) or {"approved": [], "refused": []}
            if not mg["approved"]:
                continue
            refused_min = min((a for _, a in mg["refused"]), default=None)
            mx, bd, why = _purchase_limits(base, mg["approved"], refused_min, cap)
            if why:
                held(why)                                                            # W4
                continue
            old = base.get("purchase") if (base.get("purchase") or {}).get("enabled") else {}
            if old and old.get("max_per_action", 0) >= mx and old.get("budget", 0) >= bd:
                continue                                                             # already covered
            form = json.loads(json.dumps(base))
            form["purchase"] = {"enabled": True, "max_per_action": mx, "budget": bd}
            amounts = [a for _, a in mg["approved"]]
            budget = {"p95": p95(amounts), "max_approved": max(amounts), "max_day_sum": max_day_sum(mg["approved"]),
                      "proposed": mx, "budget": bd, "cap": cap, "refused_min": refused_min, "vendors": "all (the core has no vendor dimension)"}
        else:
            continue
        if not _replay_ok(mm, form, approved_acts.get(agent_id, [])):
            held("REPLAY_DENIES_APPROVED")                                           # W5
            continue
        s = {"agent_id": agent_id, "class": cls, "recipient": rcpt, "approvals": g["ok"], "refusals": 0, "window_days": 14,
             "supersedes": mid, "form": form, "lossy": lossy, "draft": {"path": "POST /api/mandates/draft", "body": {"agent_id": agent_id, "form": form}},
             "applied": False}
        if budget is not None:
            s["budget"] = budget
        # 0.2.0 merge (02 <-> 05): members of openapi-0.2 Suggestion; id = stable hash of the group (the page links mandate.html?suggest=<id>)
        s.update(id="sg_" + hashlib.sha256(json.dumps([agent_id, cls, rcpt]).encode()).hexdigest()[:16],
                 kind="budget" if cls == "purchase" else "recipient", key=rcpt, approved=g["ok"], rejected=0,
                 proposal="%s %s" % (cls, rcpt), **({"proposed_budget": budget["proposed"]} if budget else {}))
        out.append(s)
    # W3: one purchase suggestion per agent (the limits are per agent): the vendor with the most approvals carries it
    best = {}
    for s in out:
        if s["class"] == "purchase" and (s["agent_id"] not in best or s["approvals"] > best[s["agent_id"]]["approvals"]):
            best[s["agent_id"]] = s
    out = [s for s in out if s["class"] != "purchase" or best[s["agent_id"]] is s]
    return out, withheld


def suggestions(ctx, account_id, t=None):
    return analyse(ctx, account_id, t)[0]


def withheld(ctx, account_id, t=None):
    return analyse(ctx, account_id, t)[1]
