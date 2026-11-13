"""0.2.29: "approve this call for later runs" -- one passkey prompt approves the pending request AND up to MAX_USES identical calls of the
same agent that come later, until a time the owner chose (1 / 24 / 72 h). For agents without a person at the keyboard (cron, `claude -p`, CI):
the owner answers in the morning, the next scheduled run makes the same call and it runs without a new question.

How (no change of the core, no new ledger entry type): the owner's device makes up N receipt ids for the future uses ("reserved rids", the
expiry is written INTO each id, see rid_exp) and signs ONE batch envelope `wb` over the approval payloads of the current request and of those
N ids (same mandate hash, same action hash). The witness core already accepts a wb approval of a deferred receipt. When a later call of the
agent is EXACTLY the same action (same request hash: tool, every argument, recipient, amount ...) under the SAME active mandate and the core
again defers it for the same reason, the gateway records it under the next unused reserved id (RECEIPT defer) and applies the owner's
signature to it (APPROVAL with that same wb): the call is allowed (OK_APPROVED) and its receipt names the APPROVAL entry that holds the
owner's signature. So:
  - changed arguments = another action hash: not in the signed list, asked again;
  - a deny of the mandate is never turned into an allow: the core accepts an approval only of a deferred receipt;
  - at most N uses: only N ids were signed (the server cannot make more);
  - a new or revoked mandate ends it (the payloads carry the old mandate's hash); a removed passkey ends it (KEY_REVOKED);
  - the time limit is in the signed ids: the server refuses a later use, and anyone with the ledger can see a use after it
    (the RECEIPT time against the time in the id);
  - revoke: one click (only narrows); the server then never uses the remaining ids. Honest limit: the revocation is kept by the server,
    not by the ledger (the signatures exist until their time is up).
Not offered (asked every time, as before): a dangerous command, a command whose executed files changed (the hash does not see file
contents), a held item (advisor, secret seen, egress), a team account (one signature does not stand in for a quorum).
At use the gateway also applies what it applies to an allowed call: a frozen agent, the hold after a secret was seen, the egress holds.

0.2.30 (hostile review B1): the request hash of a command covers its line, not the files the line runs. `bash nightly.sh` approved for
later runs, then the agent rewrites nightly.sh (a Write the mandate allows in the project) -> the next run used to pass on the old signature.
Now an approval for later runs of a COMMAND ends (end_note "file_written", the owner is asked as usual and told in a summary) as soon as
the witness has let this agent write, since the request was made, a file the command may run (files_written):
  - a file the line names (`bash nightly.sh`, `./nightly.sh`, `python3 run.py`) when the line runs project code;
  - a file of the command's ecosystem (execguard.runs_source: test_x.py for pytest, a .js for npm, a .sh for make ...);
  - any code-shaped file (a script or source file) when the line runs project code (a shell, an interpreter, `./x`, a build tool): a chain
    "write gen.py, run it, gen.py rewrites nightly.sh" starts with a code write.
Not offered at all when such a write happened between the request and the owner's answer. Why this and not digests of the run files:
the released hook (<= 0.2.23) reports digests only of the executed-config shapes the server lists (conftest.py, Makefile ...), and those
ARE bound already (they are inside the hashed arguments and an exec change is never offered); hashing every script/source file would
cut the bounded walk (an incomplete walk is asked about) and a new kind of fact breaks older hooks. Writes the witness judged are seen by
the server for every hook version. Honest limit: a change the witness does not see as a write (a program the owner or an allowance let
run that rewrites the script, a human edit, `git checkout`) is not detected for a plain script; the page says so.
"""
import base64
import hashlib
import json
import os
import re
import time

import cbor2

from app import _paths  # noqa: F401
import wa_profile as wa
import wq_profile as wq
from svidetel_v4.state import approval_payload
from app import org
from app.context import Err
from app.log import log

MAX_USES = 10                 # + the current request = 11 items of one wb (the wb profile allows 20)
USES = (1, 3, 10)
HOURS = (1, 24, 72)
MAX_S = 72 * 3600
SKEW_S = 600
NOT_OFFERED = ("ESCALATE_COMMAND_DANGER", "ESCALATE_EXEC_CHANGED")
LATER_S = 24 * 3600           # a request that expired unanswered may still be approved for the NEXT runs this long after it expired
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
RID_RE = re.compile(r"r_[A-Z2-7]{32}")
ID_RE = re.compile(r"ra_[A-Z2-7]{26}")


def _now():
    return int(time.time())


def new_id():
    return "ra_" + base64.b32encode(os.urandom(16)).decode().rstrip("=")[:26]


def rid_exp(rid):
    """A reserved receipt id: "r_" + 7 base32 characters of the expiry (35 bits, big-endian, seconds) + 25 random base32 characters.
    -> the expiry, or None when `rid` is not of this form (an ordinary rid has 26 characters after "r_")."""
    if not isinstance(rid, str) or not RID_RE.fullmatch(rid):
        return None
    v = 0
    for c in rid[2:9]:
        v = (v << 5) | B32.index(c)
    return v


def make_rid(exp, rand=os.urandom):
    """The server never makes the ids the owner signs (the page does, web/js/repeat.js); this is for tests and tools."""
    e = "".join(B32[(exp >> (5 * (6 - i))) & 31] for i in range(7))
    return "r_" + e + base64.b32encode(rand(16)).decode().rstrip("=")[:25]


def expired_open(x, now=None):
    """An unanswered question of the core (verdict defer) that expired less than LATER_S ago: the night run asked, nobody answered, the
    owner reads the link in the morning. It can no longer be approved itself, only for the agent's next runs."""
    now = _now() if now is None else now
    return x["status"] == "expired" and x["verdict"] == "defer" and x["expires"] is not None and now <= x["expires"] + LATER_S


def eligible(ctx, acc, x, action=None):
    """-> None when the request x (waiting, or expired unanswered less than LATER_S ago) may be approved for later runs, else the reason."""
    if x["mandate_id"] is None or not (x["status"] == "pending_approval" or expired_open(x)):
        return ("this request expired more than %d hours ago: the agent asks again in its next run" % (LATER_S // 3600)
                if x["status"] == "expired" and x["verdict"] == "defer" else "only a request that waits for your approval")
    if org.current_policy(ctx, acc["id"]) is not None:
        return "a team's rules need their signatures for each call: approve once"
    if x["reason"] in NOT_OFFERED:
        return ("a dangerous command is asked every time" if x["reason"] == "ESCALATE_COMMAND_DANGER"
                else "the command runs files that changed since you confirmed them: it is asked every time")
    try:
        a = action if action is not None else json.loads(x["action_json"])
    except (TypeError, ValueError):
        return "this request cannot be approved for later runs"
    if a.get("dangerous") is True or a.get("exec_changed"):
        return "a dangerous command, or one whose executed files changed, is asked every time"
    if "exec_json" in x.keys() and x["exec_json"] and '"written_run"' in x["exec_json"]:
        return "it runs a file the agent wrote (shown on this page): approve once"             # r25 (s8 P2)
    m = ctx.db.one("SELECT status FROM mandates WHERE id=?", (x["mandate_id"],))
    if m is None or m["status"] != "active":
        return "the mandate of this request is no longer active"
    ag = ctx.db.one("SELECT frozen_at FROM agents WHERE id=?", (x["agent_id"],))
    if ag is None or ag["frozen_at"]:
        return "the agent is frozen"
    if x["class"] == "command":
        hit = files_written(ctx, x["agent_id"], _heads_of(x), x["created_at"])
        if hit:
            return ("the agent changed a file this command runs after it asked (%s): approve once" %
                    ", ".join(p.rsplit("/", 1)[-1] for p in hit[:3]))
    return None


SHELLS = ("sh", "bash", "zsh", "ksh", "dash", "fish", "ash", "mksh", "pwsh", "powershell", "source", ".", "env", "exec", "nohup", "xargs",
          "time", "nice", "timeout", "watch", "sudo", "doas", "eval")


def _code_ext():
    from app import execguard as eg
    out = set(eg.SCRIPT_EXT)
    for v in eg.SOURCE_EXT.values():
        out.update(v)
    return tuple(sorted(out))


def runs_project_code(heads):
    """A command line runs code that may live in the project: a shell / wrapper, a path-like program (`./x`, `scripts/run`), or a command of
    an ecosystem that executes project files (python, node, make, cargo, ...)."""
    from app import execguard as eg
    for h in heads or ():
        if not isinstance(h, str) or not h:
            continue
        w = h.split("[", 1)[0].split()
        w0 = w[0] if w else ""
        if "/" in w0 or "\\" in w0 or eg.fold(w0.rsplit("/", 1)[-1]) in SHELLS or eg.families_of_command(h):
            return True
    return False


def code_shaped(path):
    from app import execguard as eg
    name = eg.fold(path.replace("\\", "/").rsplit("/", 1)[-1])
    return bool(eg.families_of_path(path)) or name.endswith(_code_ext())


def written_paths(ctx, agent_id, since):
    """{path: rid} of every file the witness let this agent write at or after `since` (all targets of a write, not only the first)."""
    from app import actions as act
    out = {}
    for r in ctx.db.q("SELECT rid, recipient, write_paths FROM actions WHERE agent_id=? AND class='delete' AND updated_at>=? AND status IN (%s) "
                      "ORDER BY updated_at LIMIT 2000" % ",".join("?" * len(act.SEEN_STATUSES)), (agent_id, since) + act.SEEN_STATUSES):
        ps = []
        try:
            ps = json.loads(r["write_paths"]) if r["write_paths"] else []
        except (TypeError, ValueError):
            ps = []
        for p in ([r["recipient"]] if r["recipient"] else []) + [p for p in ps if isinstance(p, str)]:
            out.setdefault(p, r["rid"])
    return out


def files_written(ctx, agent_id, heads, since, args=None):
    """0.2.30 (B1) -> sorted paths the agent wrote since `since` that a command line with these heads may run. `args` (the live call, when
    there is one) adds the files the line names (`bash nightly`, a script without an extension)."""
    from app import actions as act
    from app import execguard as eg
    paths = written_paths(ctx, agent_id, since)
    if not paths:
        return []
    code = runs_project_code(heads)
    hit = []
    for p in paths:
        if eg.runs_source(heads, p) or (code and code_shaped(p)) or (code and args is not None and act._names_a_written_file(args, [p])):
            hit.append(p)
    return sorted(hit)


def _heads_of(x):
    try:
        m = json.loads(x["cmd_meta"]) if x["cmd_meta"] else None
    except (TypeError, ValueError, KeyError, IndexError):
        m = None
    if isinstance(m, dict) and isinstance(m.get("heads"), list):
        return [h for h in m["heads"] if isinstance(h, str)]
    return [x["recipient"]] if x["recipient"] else []


def end_if_written(ctx, g, action, args, t):
    """At use: an approval for later runs of a command whose files the agent wrote since the request -> ended (True); the owner is asked."""
    if g["class"] != "command":
        return False
    x = ctx.db.one("SELECT created_at FROM actions WHERE rid=?", (g["from_rid"],))
    since = x["created_at"] if x is not None else g["created_at"]
    w = args.get("_witness") if isinstance(args, dict) else None
    heads = [h for h in (w.get("commands") or []) if isinstance(h, str)] if isinstance(w, dict) and isinstance(w.get("commands"), list) else []
    if not heads and action.get("recipient"):
        heads = [action["recipient"]]
    hit = files_written(ctx, g["agent_id"], heads, since, args)
    if not hit:
        return False
    note = json.dumps({"why": "file_written", "files": hit[:16], "t": t}, ensure_ascii=False)
    ctx.db.x("UPDATE repeat_approvals SET ended_at=?, ended_by=?, end_note=? WHERE id=? AND ended_at IS NULL", (t, "witness", note, g["id"]))
    log("INFO", "repeat approval ended: the agent wrote a file the command runs", id=g["id"], n=len(hit))
    if getattr(ctx, "notify", None) is not None:
        ctx.notify.digest(g["account_id"], "repeat_ended")
    return True


def offer(ctx, acc, x):
    why = eligible(ctx, acc, x)
    return {"eligible": why is None, "why_not": why, "uses": list(USES), "hours": list(HOURS), "max_uses": MAX_USES,
            "max_hours": MAX_S // 3600, "t": _now(), "expired": x["status"] == "expired", "command": x["class"] == "command"}


def create(ctx, acc, user_id, rid, env, rq, view_fn=None):
    """POST /api/approvals/{rid} with `repeat`: {"rids": [reserved ids]} and a wb envelope over exactly the approval payloads of `rid` and of
    these ids. Approves `rid` (the one approval path, actions.approve_with_envelope) and records the reserved ids for later identical calls.
    An expired unanswered `rid` (expired_open): the envelope lists ONLY the reserved ids (the expired one cannot be approved any more); the
    signature, the passkey level and the counter are checked here as approve_with_envelope checks them.
    pv2: view_fn (api_web._view_match, run here under hub.lock) = the presentation hash of the page that offered "for later runs"; it is a
    member of EVERY approval payload of the wb (this request and each reserved id: the later runs are approved on what this page showed),
    it is kept with the reserved ids and written into each later APPROVAL entry. No view claimed (an older page): as before."""
    from app import actions as act
    rids = rq.get("rids") if isinstance(rq, dict) else None
    if not isinstance(rids, list) or len(rids) not in USES or len(set(rids)) != len(rids):
        raise Err(400, "BAD_REQUEST", "repeat.rids: %s distinct ids" % " or ".join(map(str, USES)))   # 0.2.30: what the page offers, nothing between
    exps = {rid_exp(r) for r in rids}
    if None in exps or len(exps) != 1:
        raise Err(409, "REPEAT_MALFORMED", "every id carries the same time limit")
    exp = exps.pop()
    if not isinstance(env, bytes) or wq.envelope_kind(env) != "wb":
        raise Err(409, "WB_MALFORMED")
    with ctx.hub.lock(acc["id"]):
        x = act.own_account_action(ctx, acc, rid)
        why = eligible(ctx, acc, x)
        if why:
            raise Err(409, "REPEAT_NOT_ELIGIBLE", why)
        now = _now()
        if not any(h * 3600 - SKEW_S <= exp - now <= h * 3600 + SKEW_S for h in HOURS):      # 0.2.30: 1, 24 or 72 hours (+- the clock skew)
            raise Err(409, "REPEAT_MALFORMED", "the time limit must be %s hours from now (reload the page)" % ", ".join(map(str, HOURS)))
        for r in rids:
            if ctx.db.one("SELECT 1 AS k FROM actions WHERE rid=?", (r,)) or ctx.db.one("SELECT 1 AS k FROM repeat_slots WHERE rid=?", (r,)):
                raise Err(409, "REPEAT_ID_TAKEN")
        L = ctx.hub.ledger(acc["id"])
        L.sync_now()
        rc = L.S.receipts.get(rid)
        if rc is None or any(r in L.S.receipts for r in rids):
            raise Err(409, "REPEAT_ID_TAKEN" if rc is not None else "NOT_DEFERRED")
        M = L.S.mandates[rc["mandate"]]
        late = x["status"] == "expired"
        view = view_fn() if view_fn is not None else None      # pv2: the rows' view now, under the same lock as the entry
        want = sorted(hashlib.sha256(approval_payload(M, rc["action"], r, True, view)).digest() for r in ([] if late else [rid]) + rids)
        try:
            items = cbor2.loads(env)["items"]
        except Exception:
            raise Err(409, "WB_MALFORMED")
        if not isinstance(items, list) or sorted(items) != want:
            raise Err(409, "WB_ITEM", "the envelope must list exactly this request and the reserved ids, nothing else")
        if late:
            out = {"verdict": "later_only"}
            _check_late(ctx, acc, x, rc, M, env, rids, view)
        else:
            out = act.approve_with_envelope(ctx, acc, rid, True, env, view=view)      # signature, passkey level, counters, ledger APPROVAL
            if out.get("verdict") != "allow":
                return out
        rh = ctx.db.one("SELECT request_hash FROM actions WHERE rid=?", (rid,))["request_hash"]
        gid = new_id()
        with ctx.db.tx():
            ctx.db.x("INSERT INTO repeat_approvals(id,account_id,agent_id,mandate_id,request_hash,reason,tool,class,recipient,from_rid,envelope,uses,exp,"
                     "created_at,created_by,view_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (gid, acc["id"], x["agent_id"], x["mandate_id"], rh, x["reason"], x["tool"], x["class"], x["recipient"], rid, env, len(rids),
                      exp, now, user_id, view.hex() if view else None))
            for i, r in enumerate(rids):
                ctx.db.x("INSERT INTO repeat_slots(rid,account_id,repeat_id,n,used_at) VALUES(?,?,?,?,NULL)", (r, acc["id"], gid, i))
    return dict(out, repeat={"id": gid, "uses": len(rids), "exp": exp})


def _check_late(ctx, acc, x, rc, M, env, rids, view=None):
    """What approve_with_envelope checks for a solo account, for a wb that approves only reserved ids (nothing is written to the ledger now)."""
    from app import levels
    org.refuse_revoked(ctx, env)
    entry = ctx.hub.active_keys(acc["id"]).get(org.env_kid(env))
    if entry is None:
        raise Err(409, "KEY_MISMATCH")
    for r in rids:
        code = wq.verify_wb(env, wa.TYP_APPROVAL, approval_payload(M, rc["action"], r, True, view), entry)
        if code:
            raise Err(409, code)
    levels.check_signers(ctx, acc["id"], levels.env_kids(env), rc["action"], x["reason"], x["level_min"])
    org.check_sign_counts(ctx, env, "approve", acc["id"])
    org.touch_kids(ctx, levels.env_kids(env))


def find(ctx, agent_id, mandate_id, rh, reason, t):
    """-> (repeat row, reserved rid) for a later call: the same agent, mandate, request hash and core reason, not ended, in time, an id left."""
    for g in ctx.db.q("SELECT * FROM repeat_approvals WHERE agent_id=? AND mandate_id=? AND request_hash=? AND ended_at IS NULL AND exp>=? "
                      "ORDER BY created_at", (agent_id, mandate_id, rh, t)):
        if g["reason"] != reason:
            continue
        s = ctx.db.one("SELECT rid FROM repeat_slots WHERE repeat_id=? AND used_at IS NULL ORDER BY n LIMIT 1", (g["id"],))
        if s is not None and rid_exp(s["rid"]) is not None and t <= rid_exp(s["rid"]):
            return g, s["rid"]
    return None


def use(ctx, acc_id, g, rid, t):
    """The reserved receipt `rid` is in the ledger (defer) and in actions: apply the owner's signature. -> True when allowed. The id is
    spent first, whatever happens (it is never offered twice); a failure leaves an ordinary question for the owner."""
    from app import actions as act
    ctx.db.x("UPDATE repeat_slots SET used_at=? WHERE rid=? AND used_at IS NULL", (t, rid))
    acc = ctx.db.one("SELECT * FROM accounts WHERE id=?", (acc_id,))
    try:
        vh = g["view_sha256"] if "view_sha256" in g.keys() else None          # pv2: the view the owner's page showed when it signed
        out = act.approve_with_envelope(ctx, acc, rid, True, bytes(g["envelope"]), counted=True, view=bytes.fromhex(vh) if vh else None)
    except Err as e:
        log("WARN", "repeat approval not applied", rid=rid, code=e.code)
        return False
    return out.get("verdict") == "allow"


def revoke(ctx, acc, user_id, gid):
    with ctx.hub.lock(acc["id"]):
        g = ctx.db.one("SELECT * FROM repeat_approvals WHERE id=? AND account_id=?", (gid, acc["id"])) if isinstance(gid, str) else None
        if g is None:
            raise Err(404, "NOT_FOUND")
        if g["ended_at"] is None:
            ctx.db.x("UPDATE repeat_approvals SET ended_at=?, ended_by=? WHERE id=? AND ended_at IS NULL", (_now(), user_id, gid))
        g = ctx.db.one("SELECT ended_at FROM repeat_approvals WHERE id=?", (gid,))
    return {"id": gid, "status": "revoked", "ended_at": g["ended_at"]}


def _end_note(g):
    try:
        return json.loads(g["end_note"]) if g["end_note"] else None
    except (TypeError, ValueError, KeyError, IndexError):
        return None


def status_of(ctx, g, used, now):
    if g["ended_at"] is not None:
        n = _end_note(g)
        return "file_changed" if isinstance(n, dict) and n.get("why") == "file_written" else "revoked"
    m = ctx.db.one("SELECT status FROM mandates WHERE id=?", (g["mandate_id"],))
    if m is None or m["status"] != "active":
        return "mandate_ended"
    if now > g["exp"]:
        return "expired"
    if used >= g["uses"]:
        return "used_up"
    return "active"


def listing(ctx, acc):
    names = {a["id"]: a["name"] for a in ctx.db.q("SELECT id, name FROM agents WHERE account_id=?", (acc["id"],))}
    now = _now()
    out = []
    for g in ctx.db.q("SELECT * FROM repeat_approvals WHERE account_id=? ORDER BY created_at DESC, rowid DESC", (acc["id"],)):
        u = ctx.db.one("SELECT COUNT(used_at) AS n, MAX(used_at) AS last FROM repeat_slots WHERE repeat_id=?", (g["id"],))
        p = ctx.db.one("SELECT args_preview FROM actions WHERE rid=?", (g["from_rid"],))
        out.append({"id": g["id"], "agent_id": g["agent_id"], "agent": names.get(g["agent_id"], ""), "tool": g["tool"], "class": g["class"],
                    "recipient": g["recipient"] or "", "args_preview": p["args_preview"] if p else "", "from_rid": g["from_rid"],
                    "uses": g["uses"], "used": u["n"], "last_used": u["last"], "exp": g["exp"], "created_at": g["created_at"],
                    "ended_at": g["ended_at"], "status": status_of(ctx, g, u["n"], now),
                    "ended_files": [p.rsplit("/", 1)[-1] for p in ((_end_note(g) or {}).get("files") or [])][:16]})
    return out
