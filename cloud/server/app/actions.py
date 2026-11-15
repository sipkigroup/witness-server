"""Action life cycle on top of the ledger (ARHITEKTURA 5.2): authorize, repeat, approve, present, report.
0.2 (ARHITEKTURA-0.2 2.4, 3.4, 4.2, 8): approvals by quorum (wq) or batch (wb) through ONE path `approve_with_envelope`, the approval
requirements of the org policy are checked here BEFORE Ledger.approve (the core does not see them); the flow hooks of task 02 are called
after the dry decision (`pre_authorize`, may only tighten: deny or hold) and after every decision (`on_decided`); `held` + release."""
import base64
import hashlib
import hmac
import json
import os
import re
import shlex
import time

import cbor2

from app import _paths  # noqa: F401
import wa_profile as wa
import wq_profile as wq
from svidetel_v4.state import approval_payload, request_hash, revocation_payload
from svidetel_v4.schema import validate_mandate
from app import erase
from app import jobs
from app import stats
from app import trial
from app import merklecache
from app.context import Err
from app import org
from app.hookjudge import runners as _runners
from app.hookjudge import inline as _inline
from app.hookjudge import strict_policy
from app.hookjudge import datarule as _datarule
from app import toolmap as tm
from app import wire
from app import allowances as al
from app import constitution
from app import amend
from app import provenance
from app import execguard
from app import levels
from app import delegation
from app import egress
from app import refusals
from app import repeat as rpt
from app.registry_wa import looks_like_envelope
from app.log import log

try:                                    # task 02 (ARHITEKTURA-0.2 8); without app/flow the server behaves as without hooks
    from app.flow import hooks
    from app.flow import advisor
except ImportError:
    advisor = None

    class hooks:                        # noqa: N801  (same surface as app/flow/hooks.py)
        router = None

        @staticmethod
        def pre_authorize(ctx, agent, mandate_row, act, dry_verdict, dry_reason):
            return None

        @staticmethod
        def on_decided(ctx, agent, row):
            return None

TTL = 900
REFUSAL_BLOCK_S = 3600
# r0285 (PARALLEL-I-KVOTA-1311): the quota counts ACTIONS (one per part of a judged call) that are not reads (class `pass`: Read, Grep,
# Glob, LS). The hook's fact rounds (`need`) and the reads have their own high ceiling (cfg.pass_per_*). Before r0285 every `need` round and
# every read of the hook counted: 2.45 units per call of the dev corpus (968 calls -> 1118 actions + 1254 rounds), so one agent that
# works 8 h (~175 calls/h) used up its 2000 in ~4.7 h. Now ~1.1 units per call (1085 / 968), and the limits are x2 of a full day:
QUOTA_PER_DAY = 10000          # account: ~3 agents x 8 h x 195 actions/h (dev corpus, 5.6 active h) = 4700, x2
QUOTA_PER_AGENT_DAY = 4000     # N-12: one agent cannot eat the quota of the others; ~8 h at the busy pace of the load model (400 actions/h) = 3200
QUOTA_WARN = 0.8               # r0285: from this share on, the judge's answer carries `quota` (the hook tells the person once)
STATUS_OF = {"allow": "allowed", "deny": "denied", "defer": "pending_approval"}
WAITING = ("pending_approval", "approved", "held")


# 0.2.24 (critique T3): "the agent saw a secret". A read of a credential file the witness let through (or the owner approved), or a call whose
# own arguments carry a secret shape, marks the agent for `cfg.secret_taint_min` minutes; during that window every OUTGOING call the mandate
# would allow (WebFetch / WebSearch / Bash.net / message / publish / a command that runs code) is held for the owner (ESCALATE_SECRET_SEEN).
SECRET_READ_TOOLS = ("Read.secret", "Grep.secret", "NotebookRead.secret")
SECRET_TAGS = ("api_key", "private_key", "telegram_token", "bearer", "secret_assign")
TAINT_SEEN_IF_ALLOWED = 1       # a read of a secret: counts once the agent got it (allowed / approved / consumed / executed)
TAINT_HOLDS = 2                 # the secret is in the agent's own arguments: it has it, whatever the verdict
SEEN_STATUSES = ("allowed", "approved", "consumed", "executed")
QUIET_HEADS = ("cp", "mv", "ln", "rm", "touch", "chmod", "chown", "mkdir", "rmdir")     # file operations that print no content
WRITTEN_LOOKBACK_MIN = 24 * 60   # 0.2.25: writes this long before the secret still count (DW_WRITTEN_LOOKBACK_MIN)
# 0.2.25: auto-freeze after a flood of APPROVAL_RATE refusals (DW_AUTOFREEZE_N refusals within DW_AUTOFREEZE_MIN minutes; N=0 turns it off).
# 10 in 10 min: the reference load gives 0 APPROVAL_RATE in 500 honest calls (OTCHET-FATIGUE-FIX), an honest agent that hits the limit stops
# after 1-3 retries (it gets a deny that says why), the bombing of the check (50 calls) gives 45 in seconds. 3 per hour (the critique's figure)
# would freeze an honest night agent that just waits for its 5 queued questions; a freeze costs the owner a passkey touch.
AUTOFREEZE_N = 10
AUTOFREEZE_MIN = 10
# r25 (s8, noise C6/B3): print to the agent only, never send out and never run project code: `type` (a shell builtin that names a program),
# `ruff` (Rust, no plugins: it reads files, `--fix` writes them). After a secret the agent already has, their output stays on the machine.
# NOT here: mypy / pylint / flake8 (their config loads plugins = project code), curl / wget / nc (send), anything that runs a file.
LOCAL_HEADS = ("type", "ruff")
TEXT_HEADS = ("sort", "uniq", "cut", "tr", "diff", "cmp", "comm", "nl", "tac", "rev", "column", "basename", "dirname", "realpath")   # never run a file



# 0.2.75 (sandbox «живой человек», APPROVAL_SIG): the signed bytes are not the approval the witness builds for this request. Seen in
# practice only from a page whose code was partly an OLDER copy kept by the browser (a signature without the view member). Said in words
# for every page, also an old one (it shows the detail after the code); the signature format is not relaxed.
STALE_PAGE_TEXT = ("Nothing was approved: the signature does not match this request. If this page was opened before an update, your browser "
                   "may have run an outdated copy of it. Reload the page (on a phone: close the tab and open the link again) and decide again.")


def now():
    return int(time.time())


def taint_of(tool, act, args):
    w = args.get("_witness") if isinstance(args, dict) else None
    if isinstance(act, dict) and set(act.get("data") or ()) & set(SECRET_TAGS):
        return TAINT_HOLDS
    if tool in SECRET_READ_TOOLS:
        return TAINT_SEEN_IF_ALLOWED
    if tool == "Bash.danger" and isinstance(w, dict) and any(isinstance(d, str) and d.startswith("secrets:") for d in (w.get("danger") or [])):
        heads = w.get("commands")
        if isinstance(heads, list) and heads and all(isinstance(h, str) and h in QUIET_HEADS for h in heads):
            return None                     # `cp .env.example .env.local`: the file is moved, its content never reaches the agent
        return TAINT_SEEN_IF_ALLOWED        # `cat ~/.ssh/id_rsa`, `< .env`
    return None


def refusal_block_s(ctx, agent_id):
    """05.11 (prompt bombing): how long a Deny keeps the same call refused without a question: the account's setting (default 15 min)."""
    try:
        a = ctx.db.one("SELECT account_id FROM agents WHERE id=?", (agent_id,))
        return int(org.settings(ctx, a["account_id"])["refusal_block_s"])
    except Exception:      # noqa: BLE001  the default stays; never loosens fail-closed
        return 900


def deny_key(args):
    """05.11 (RT, hole 1): a normalized key of what a shell line does that is dangerous: the witness's own marks (bashparse: kind + program), the
    hosts of the line, the deleted paths, and for each command of the line that runs a program named by a mark: program + its first two words
    (`git push origin`, `gh pr list`; no flags, no `VAR=x`, no `-c k=v`, no quotes, no branch). Spaces, comments, env prefixes, `cd . &&` and
    other commands of the line are not in it. Used ONLY to keep a refused line refused in the window (wider than the exact hash = fail
    closed); an approval is never matched by it (I5: an approval is the exact request hash). None: nothing dangerous to key."""
    w = args.get("_witness") if isinstance(args, dict) else None
    if not isinstance(w, dict):
        return None
    ent, progs = set(), set()
    for d in (w.get("danger") or []):
        if not isinstance(d, str):
            continue
        kind, _, rest = d.partition(":")
        rest = re.sub(r"\s*\[[^\]]*\]\s*$", "", rest).strip()
        if kind in ("exit", "net-out", "publish", "money", "purchase", "message", "disclosure"):
            toks = rest.split()
            pr = toks[0].rsplit("/", 1)[-1] if toks else ""
            ent.add("%s:%s" % (kind if kind != "net-out" else "exit", pr))
            progs.add(pr)
        else:
            if rest.split():
                progs.add(rest.split()[-1].rsplit("/", 1)[-1])
            ent.add("%s:%s" % (kind, rest))
    if not ent and not w.get("net") and not w.get("deletes"):
        return None
    if progs:
        try:
            from app.hookjudge.bashparse import line_texts
            segs = [t for t, _f in line_texts(args.get("command"))]
        except Exception:      # noqa: BLE001  no sub-commands in the key: the key stays coarse (wider = fail closed)
            segs = []
        for seg in segs:
            try:
                toks = shlex.split(seg, comments=True)
            except ValueError:
                toks = seg.split()
            while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
                toks.pop(0)                                     # VAR=x prefixes
            if not toks or toks[0].rsplit("/", 1)[-1] not in progs:
                continue
            rest = [t for t in toks[1:] if not t.startswith("-") and not re.match(r"^[A-Za-z_][A-Za-z0-9_.]*=", t)]
            ent.add("cmd:" + " ".join([toks[0].rsplit("/", 1)[-1]] + rest[:2]))
    for n in (w.get("net") or []):
        if isinstance(n, str):
            ent.add("net:" + n.rsplit("@", 1)[-1].lower())
    for p_ in (w.get("deletes") or []):
        if isinstance(p_, str):
            ent.add("del:" + os.path.normpath(p_))
    return hashlib.sha256(json.dumps(sorted(ent), ensure_ascii=False).encode()).hexdigest()


def refused_like(ctx, agent_id, mandate_id, tool, cls, recipient, t0, rh=None, dk=None):
    """0.1.1 (item 7) / N-11: the latest call of this agent the owner REFUSED within REFUSAL_BLOCK_S under this mandate with the same
    (tool, class, recipient), or None. 0.2.73 (N15): also what the agent is told (judge.refused_text): which call that was.
    0.2.90 (QA 03.11, D12): for a shell line (tool Bash*) the recipient is the program name (`curl`), so one No to `curl .../b04` refused
    EVERY curl for an hour: with `rh` given, a shell line is matched by its exact request hash (the same line again), nothing wider."""
    q = "SELECT rid, request_hash, args_preview, updated_at FROM actions WHERE agent_id=? AND status='refused' AND tool=? AND class=? AND recipient=? AND updated_at>?"
    a = (agent_id, (tool or "")[:200], cls, (recipient or "")[:300], t0 - refusal_block_s(ctx, agent_id))
    if rh is not None and isinstance(tool, str) and tool.startswith("Bash"):
        q, a = q + " AND request_hash=?", a + (rh,)
    if mandate_id is not None:
        q, a = q + " AND mandate_id=?", a + (mandate_id,)
    r = ctx.db.one(q + " ORDER BY updated_at DESC LIMIT 1", a)
    if r is None and dk and isinstance(tool, str) and tool.startswith("Bash"):
        # 05.11 (RT hole 1): the same dangerous act in other words (extra space, quotes, comment, env prefix, `cd . &&`, another branch)
        q2 = "SELECT rid, request_hash, args_preview, updated_at FROM actions WHERE agent_id=? AND status='refused' AND tool=? AND deny_key=? AND updated_at>?"
        a2 = (agent_id, (tool or "")[:200], dk, t0 - refusal_block_s(ctx, agent_id))
        if mandate_id is not None:
            q2, a2 = q2 + " AND mandate_id=?", a2 + (mandate_id,)
        r = ctx.db.one(q2 + " ORDER BY updated_at DESC LIMIT 1", a2)
    return r


def secret_seen(ctx, agent_id, t0):
    """-> (rid, time) of the earliest call that marked the agent within the window, or None."""
    win = 60 * (getattr(ctx.cfg, "secret_taint_min", None) or 30)
    r = ctx.db.one("SELECT rid, updated_at FROM actions WHERE agent_id=? AND taint IS NOT NULL AND updated_at>? AND (taint=? OR status IN (%s)) "
                   "ORDER BY updated_at ASC LIMIT 1" % ",".join("?" * len(SEEN_STATUSES)),
                   (agent_id, t0 - win, TAINT_HOLDS) + SEEN_STATUSES)
    return (r["rid"], r["updated_at"]) if r else None


def written_since(ctx, agent_id, t, limit=200, after=None, content_only=False):
    """Paths the witness let this agent write at or after t (Write / Edit / Bash.write ...): the recipients of its allowed `delete` actions.
    after=(rowid, created_at) of a page (N1 29.10): only writes inserted after that page or decided after the second it was made."""
    extra, xa = "", ()
    if content_only:      # N15 lever 2: rm / chmod / touch / mkdir / git from the repo's own objects put no text of the agent anywhere
        extra += " AND (exec_json IS NULL OR exec_json NOT LIKE '%%\"nc\": true%%')"
    if after is not None:
        extra, xa = extra + " AND (rowid>? OR updated_at>?)", (after[0], after[1] or 0)
    out = []
    for r in ctx.db.q("SELECT rid, agent_id, status, created_at, exec_json, recipient FROM actions WHERE agent_id=? AND class='delete' AND updated_at>=? "
                      "AND status IN (%s) AND recipient IS NOT NULL AND recipient<>''%s ORDER BY rowid LIMIT ?" % (",".join("?" * len(SEEN_STATUSES)), extra),
                      (agent_id, t) + SEEN_STATUSES + xa + (4 * limit,)):
        if r["recipient"] in out or unrun_write(ctx, r):
            continue                              # N7 0.2.71: a write whose line never ran is no write
        out.append(r["recipient"])
        if len(out) >= limit:
            break
    return out


PAIRED_FILE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit", "Write.danger")


def _line_hash(tool, args):
    """RT-0269 p.2: one digest for all the parts of one shell line (Bash / Bash.write / Bash.net ...): the command and its directory.
    0.2.80 (red team 01.11, G7): a file tool call to git's configuration / hooks / an agent's settings is two parts, the write ("Write",
    allowed by the mandate) and "Write.danger" (the owner decides); both carry one digest "w:..." of the call (the same arguments), so a
    write whose other part was refused / expired / given up on is known as never run (unrun_write). A plain file write has no digest."""
    if tool in PAIRED_FILE_TOOLS and isinstance(args, dict):
        w = args.get("_witness") if isinstance(args.get("_witness"), dict) else {}
        if not (isinstance(w.get("path"), str) and isinstance(w.get("danger"), list) and w["danger"]):
            return None
        body = {k: v for k, v in args.items() if k != "_witness"}
        try:
            s = json.dumps([w["path"], sorted(str(d) for d in w["danger"]), body], sort_keys=True, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return None
        return "w:" + hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()[:32]
    if not (isinstance(tool, str) and (tool == "Bash" or tool.startswith("Bash.")) and isinstance(args, dict) and isinstance(args.get("command"), str)):
        return None
    w = args.get("_witness") if isinstance(args.get("_witness"), dict) else {}
    cwd = w.get("cwd") if isinstance(w.get("cwd"), str) else ""
    return hashlib.sha256(("%s\0%s" % (args["command"], cwd)).encode("utf-8", "surrogatepass")).hexdigest()[:32]


def _row_line(x):
    try:
        ej = json.loads(x["exec_json"]) if x["exec_json"] else None
    except (TypeError, ValueError, KeyError, IndexError):
        return None
    return ej.get("line") if isinstance(ej, dict) else None


def page_files(x):
    """RT-0269 p.2: the files the page of this row named / showed (exec_json written_run), or []."""
    try:
        ej = json.loads(x["exec_json"]) if x["exec_json"] else None
    except (TypeError, ValueError, KeyError, IndexError):
        return []
    wr = ej.get("written_run") if isinstance(ej, dict) else None
    return [w["file"] for w in wr if isinstance(w, dict) and isinstance(w.get("file"), str)] if isinstance(wr, list) else []


def page_files_changed(ctx, x):
    """RT-0269 p.2 (showing is not running): a file the page of the question `x` showed was written AFTER the question -- by ANY agent of the
    account, by any write the witness sees (Write / Edit / Bash.write, every path of a line: write_paths). The owner approved (or released)
    the old text; what would run is another. The write parts of the question's OWN line (same command and directory, same agent) are not
    counted: the page shows that line, and its re-send after the approval records them again. -> the changed file, or None. "After": a write row inserted after the question (rowid) or
    decided after the second it was asked (a write that waited for its own approval); the write of the same line, recorded just before its
    run in the same second, is not counted (the page shows it).
    N6 0.2.71 (series 8c): a write of a whole DIRECTORY over the file changes it only if it may: a restore of the latest stash whose files
    git named by their object hashes (exec_json "xf", bashparse._stash_files) changes the files it names and no other -- unless git's
    objects / index / refs could have been changed after the page (a "gt" line of any agent of the account, a write under a `.git`
    directory): then, as for tar / unzip / patch / an unknown list, the whole directory counts (fail closed). N7: a write whose line never
    ran (unrun_write) changes nothing."""
    files = page_files(x)
    if not files:
        return None
    q = ctx.db.one("SELECT rowid AS n, created_at FROM actions WHERE rid=?", (x["rid"],))
    if q is None:
        return None
    ln = _row_line(x)
    rows = ctx.db.q("SELECT rid, agent_id, status, created_at, recipient, write_paths, exec_json FROM actions WHERE account_id=? AND class='delete' "
                    "AND status IN (%s) AND (rowid>? OR updated_at>?) LIMIT 2000" % ",".join("?" * len(SEEN_STATUSES)),
                    (x["account_id"],) + SEEN_STATUSES + (q["n"], q["created_at"] or 0))
    gt = None
    for r in rows:
        if ln and r["agent_id"] == x["agent_id"] and _row_line(r) == ln:
            continue                               # the write of the question's own line (re-sent after the approval): the page shows that line
        ws = {r["recipient"]} if r["recipient"] else set()
        try:
            wp = json.loads(r["write_paths"]) if r["write_paths"] else []
        except (TypeError, ValueError):
            wp = []
        ws |= {p for p in wp if isinstance(p, str)} if isinstance(wp, list) else set()
        xf = _row_xf(r)
        hit = None
        for f in files:
            fn = os.path.normpath(f)
            for w in ws:
                if hit is not None or not isinstance(w, str) or not w:
                    continue
                wn = os.path.normpath(w)
                if wn == fn or _under(wn, fn):
                    hit = f                        # the file itself, or a path under a page directory
                    continue
                if not _under(fn, wn):
                    continue
                known = xf.get(wn) if xf is not None else None
                if known is not None:
                    if gt is None:
                        gt = _git_changed_since(ctx, x["account_id"], q)
                    if not gt:
                        if fn in known or any(_under(k, fn) for k in known):
                            hit = f                # git says the restore rewrites this file
                        continue                   # N6: git says this file is not in the stash: not changed by this write
                hit = f                            # a directory over it (`tar x`, `cp -r`, an unknown restore): fail closed
        if hit is not None and not unrun_write(ctx, r):
            return hit                             # N7: a write whose line never ran (question expired / refused) changed nothing
    return None


def late_project_write(ctx, x):
    """0.2.77 (red team 31.10, H2; RT-0269 p.32): a command approved AFTER its hook stopped waiting (gave_up_at) is kept for "the same call
    again" (the quickstart path: approve, then the agent repeats). page_files_changed() guards only the files the page SHOWED; `python3
    tool.py` shows no file, so the agent could rewrite tool.py (a listed project write, no question) and the repeat ran the new text on
    the old approval. Closed by default: a write the witness let through AFTER the question -- any agent of the account -- into the
    question's project (cmd_meta.project), or to a path the line names, or anywhere when the project is unknown, means the approval is not
    for what would run now (FILE_CHANGED, asked again). Not counted, as in page_files_changed: the write parts of the question's own line
    (same agent, same line) and a write whose line never ran (unrun_write). -> the written path, or None. A repeat with nothing written
    since (the quickstart path) keeps its approval."""
    if x["class"] != "command":
        return None
    q = ctx.db.one("SELECT rowid AS n, created_at FROM actions WHERE rid=?", (x["rid"],))
    if q is None:
        return None
    try:
        meta = json.loads(x["cmd_meta"]) if x["cmd_meta"] else None
    except (TypeError, ValueError, KeyError, IndexError):
        meta = None
    proj = meta.get("project") if isinstance(meta, dict) and isinstance(meta.get("project"), str) and meta["project"].startswith("/") else None
    text = x["text_preview"] or ""
    ln = _row_line(x)
    try:
        ej0 = json.loads(x["exec_json"]) if x["exec_json"] else {}
    except (TypeError, ValueError):
        ej0 = {}
    ldocs = ej0.get("ldocs") if isinstance(ej0, dict) and isinstance(ej0.get("ldocs"), list) else []
    rows = ctx.db.q("SELECT rid, agent_id, status, created_at, recipient, write_paths, exec_json FROM actions WHERE account_id=? AND class='delete' "
                    "AND status IN (%s) AND (rowid>? OR updated_at>?) LIMIT 2000" % ",".join("?" * len(SEEN_STATUSES)),
                    (x["account_id"],) + SEEN_STATUSES + (q["n"], q["created_at"] or 0))
    for r in rows:
        if ln and r["agent_id"] == x["agent_id"] and _row_line(r) == ln:
            continue
        ws = [r["recipient"]] if r["recipient"] else []
        try:
            wp = json.loads(r["write_paths"]) if r["write_paths"] else []
        except (TypeError, ValueError):
            wp = []
        ws += [p for p in wp if isinstance(p, str)] if isinstance(wp, list) else []
        hit = None
        same = r["agent_id"] == x["agent_id"]
        for w in ws:
            if not isinstance(w, str) or not w:
                continue
            if re.match(r"^(agent|git)-config:", w):
                w = w.split(":", 1)[1]
            wn = os.path.normpath(w)
            # 0.2.77b (red team R2-4): the SAME agent's write anywhere counts too: a file of the line may be a link out of the project
            # (`tool.py -> /tmp/t.py`, a repo can ship it) and the server has no realpath of the line's words; this also covers a script
            # that imports a file outside the project. Another agent's write outside the project does not (its own work elsewhere).
            if proj is None or same or wn == os.path.normpath(proj) or _under(wn, os.path.normpath(proj)) or (w in text):
                if _late_inert(w, text, ldocs):
                    continue                # R2-7: a document the line neither names nor can run (notes.md) keeps the approval
                hit = w
                break
        if hit is not None and not unrun_write(ctx, r):
            return hit
    return None


LATE_INERT_EXT = (".md", ".markdown", ".rst", ".adoc", ".log")


def _line_docs(args):
    """0.2.77b (R2-7): the file names of documents (LATE_INERT_EXT) a shell line names, ["*"] when it has a glob; [] when none."""
    cmd = args.get("command") if isinstance(args, dict) else None
    if not isinstance(cmd, str):
        return []
    if re.search(r"[*?\[]", cmd):
        return ["*"]
    return sorted({os.path.basename(t) for t in re.findall(r"[^\s'\"<>|;&()=`]+", cmd) if t.lower().endswith(LATE_INERT_EXT)})[:16]


def _late_inert(w, text, docs=None):
    """0.2.77b (red team R2-7): a write that cannot change what an approved command runs: a document (.md, .rst, .adoc, .log) that the
    line does not name (neither its path nor its file name) and that no command family executes (execguard.families_of_path). The agent
    writing notes while it waits for a late approval then does not void it. Everything else (code, configuration, data, .txt: requirements
    / CMakeLists) still does. Known limit: a project script that itself runs or evaluates a .md file."""
    from app import execguard as _eg
    if not isinstance(w, str) or not w.lower().endswith(LATE_INERT_EXT):
        return False
    name = os.path.basename(w)
    if not name or w in text or name in text or (isinstance(docs, list) and ("*" in docs or name in docs)):
        return False
    try:
        return not _eg.families_of_path(w)
    except Exception:  # noqa: BLE001 -- unsure: not inert
        return False


def _row_xf(r):
    """N6: exec_json "xf" of a write row -> {normalized directory: {normalized files}} or None."""
    try:
        ej = json.loads(r["exec_json"]) if r["exec_json"] else None
    except (TypeError, ValueError, KeyError, IndexError):
        return None
    xf = ej.get("xf") if isinstance(ej, dict) else None
    if not isinstance(xf, dict):
        return None
    out = {}
    for d, fs_ in xf.items():
        if isinstance(d, str) and isinstance(fs_, list) and all(isinstance(p, str) for p in fs_):
            out[os.path.normpath(d)] = {os.path.normpath(p) for p in fs_}
    return out


HEAD_MOVING_GIT = ("commit", "reset", "checkout", "switch", "merge", "pull", "rebase", "cherry-pick", "revert", "am", "update-ref",
                   "symbolic-ref", "commit-tree", "branch", "worktree", "bisect", "replace", "filter-branch", "filter-repo", "fast-import")


def _moves_head(args):
    """N6 0.2.71: a shell line that may move HEAD / a branch / the stash's base (by the parser's heads; `stash branch` by the text)."""
    for h in _commands_of(args):
        w = str(h).split()
        if len(w) >= 2 and w[0].rsplit("/", 1)[-1] == "git" and w[1] in HEAD_MOVING_GIT:
            return True
    cmd = args.get("command") if isinstance(args, dict) else None
    return isinstance(cmd, str) and re.search(r"\bstash\s+branch\b", cmd) is not None


def _git_changed_since(ctx, account_id, q):
    """N6: git's own answer for `git stash pop` (diff-tree HEAD stash) names every file the pop rewrites only while HEAD is the stash's
    base and the stash is a real one. Not trusted when, within the look-back (any agent of the account, any decision: an attempt counts),
    a line changed git's objects / index / refs / remotes ("gt": `stash store`, `commit-tree`, `update-index` ...), may have moved HEAD
    ("hm": commit, reset, checkout, switch, merge, pull, rebase ...), or wrote under a `.git` directory."""
    look = now() - 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN)
    since = min(look, q["created_at"] or look)
    if ctx.db.one("SELECT 1 AS k FROM actions WHERE account_id=? AND updated_at>=? AND (exec_json LIKE '%\"gt\": true%' OR "
                  "exec_json LIKE '%\"hm\": true%') LIMIT 1", (account_id, since)) is not None:
        return True
    for r in ctx.db.q("SELECT recipient, write_paths FROM actions WHERE account_id=? AND class='delete' AND updated_at>=? LIMIT 4000",
                      (account_id, since)):
        ps = [r["recipient"] or ""]
        try:
            wp = json.loads(r["write_paths"]) if r["write_paths"] else []
        except (TypeError, ValueError):
            wp = []
        ps += [p for p in wp if isinstance(p, str)] if isinstance(wp, list) else []
        if any(re.search(r"(^|/)\.git(/|$)", p) for p in ps):
            return True
    return False


UNRUN_STATUSES = ("expired", "refused", "denied", "not_executed")


def unrun_write(ctx, r):
    """N7 0.2.71 (series 8c): a write row of a shell line that never ran. The hook runs a line only after every part of it was let go and
    presented; a write part stays 'allowed' (never presented) when another part of THE SAME line (same agent, same line hash, made in the
    same judging) was refused, expired, denied or given up on. Such a write changed nothing: not a risky write, not "written", not a change
    of a shown file. Anything else (the other part still waits, or ran) counts as written (fail closed).
    0.2.80 (G7): a paired file write (line "w:...", see _line_hash: Write / Edit / MultiEdit / NotebookEdit to git's configuration, hooks,
    an agent's settings) never ran when EVERY other row of the same call (same agent, same digest, made within the same judging) was
    refused, expired, denied or given up on; one that still waits, was approved or ran -- or no other row found -- keeps it written."""
    try:
        ln = _row_line(r)
        if not ln:
            return False
        if ln.startswith("w:"):
            if r["status"] not in ("allowed", "approved"):
                return False
            rows = ctx.db.q("SELECT status, gave_up_at FROM actions WHERE agent_id=? AND rid<>? AND created_at BETWEEN ? AND ? "
                            "AND exec_json LIKE ? LIMIT 16", (r["agent_id"], r["rid"], (r["created_at"] or 0) - 2,
                                                              (r["created_at"] or 0) + 2, '%"line": "' + ln + '"%'))
            # 0.2.81 (red team R4-3): a row the hook GAVE UP on (gave_up_at, still pending / held) does not make the write unrun: under
            # DEUS_WITNESS_HOOK_ON_DEFER=ask the terminal's yes then runs the write with no receipt, and the server cannot tell the mode.
            # Fail closed: only refused / expired / denied / not executed rows (the hook never runs those) take the write as never run.
            # A row given up on and THEN refused / expired keeps gave_up_at: the yes may have come before the refusal -- written as well.
            return bool(rows) and len(rows) < 16 and all(y["status"] in UNRUN_STATUSES and not y["gave_up_at"] for y in rows)
        if r["status"] != "allowed":
            return False
        rows = ctx.db.q("SELECT status, gave_up_at FROM actions WHERE agent_id=? AND rid<>? AND created_at BETWEEN ? AND ? "
                        "AND exec_json LIKE ? LIMIT 16", (r["agent_id"], r["rid"], (r["created_at"] or 0) - 2, (r["created_at"] or 0) + 2,
                                                          '%"line": "' + ln + '"%'))
    except (KeyError, IndexError, TypeError):
        return False
    return any(y["status"] in UNRUN_STATUSES or (y["status"] in ("pending_approval", "held") and y["gave_up_at"]) for y in rows)


def _dirfiles(tool, act, args):
    """N6 0.2.71: `_witness.dirfiles` of a Bash.write (mapping: every write of the line is a restore of the latest stash whose files git
    named) -> {directory: [files under it]} for the directories this row writes, or None."""
    if tool != "Bash.write" or act.get("class") != "delete" or not isinstance(args, dict):
        return None
    w = args.get("_witness") if isinstance(args.get("_witness"), dict) else {}
    df = w.get("dirfiles")
    if not isinstance(df, dict) or not df:
        return None
    out = {}
    for d, fs_ in df.items():
        if not (isinstance(d, str) and d.startswith("/") and isinstance(fs_, list) and len(fs_) <= 256):
            return None
        dn = os.path.normpath(d)
        if not all(isinstance(p, str) and _under(os.path.normpath(p), dn) for p in fs_):
            return None
        out[dn] = sorted({os.path.normpath(p) for p in fs_})
    return out


def _names_a_written_file(args, paths):
    w = args.get("_witness") if isinstance(args, dict) else None
    cmd = args.get("command") if isinstance(args, dict) else None
    if not isinstance(cmd, str) or not paths:
        return bool(paths) and not isinstance(cmd, str)
    cwd = w.get("cwd") if isinstance(w, dict) and isinstance(w.get("cwd"), str) else None
    for p in paths:
        forms = {p, os.path.basename(p)}
        if cwd:
            try:
                forms.add(os.path.relpath(p, cwd))
            except ValueError:
                pass
        if any(f and f in cmd for f in forms):
            return True
    return False


def secret_confirmed_at(ctx, agent_id):
    """0.2.25: the last ESCALATE_SECRET_SEEN hold of this marked agent the owner let go: the files written before it were on that page, so
    only later writes count again (otherwise every pytest of the window would be asked). -> (rowid, created_at) of that page, or None.
    N1 29.10 (series 8b): the moment is when the PAGE was made (created_at / rowid), not when the owner decided (updated_at): a write
    between the two was never shown; a release that ended FILE_CHANGED (nothing ran) is no showing at all."""
    r = ctx.db.one("SELECT rowid AS n, created_at FROM actions WHERE agent_id=? AND hold_reason='ESCALATE_SECRET_SEEN' AND status IN (%s) "
                   "AND (exec_json IS NULL OR exec_json NOT LIKE '%%\"file_changed\"%%') ORDER BY rowid DESC LIMIT 1"
                   % ",".join("?" * len(SEEN_STATUSES)), (agent_id,) + SEEN_STATUSES)
    return (r["n"], r["created_at"]) if r is not None else None


def _commands_of(args):
    w = args.get("_witness") if isinstance(args, dict) else None
    c = w.get("commands") if isinstance(w, dict) else None
    return [x for x in c if isinstance(x, str)] if isinstance(c, list) else []


NC_HEADS = ("rm", "rmdir", "chmod", "chown", "chgrp", "touch", "mkdir")


def no_content_write(tool, args, git_taint=False):
    """N15 lever 2 (coordinator 29.10): a shell write that puts no text of the agent into any file: every command of the line is rm / rmdir /
    chmod / chown / chgrp / touch / mkdir, or git taking text from the repository's own objects (stash, pull, merge, switch, checkout /
    restore from the index or HEAD: bashparse repo_extract, nothing foreign). Not: sed -i, a redirect or a here-document, cp / mv / ln, tar,
    patch, git apply / am, a variable or a substitution in the line. Fail closed: anything the parser is unsure of has content."""
    if tool != "Bash.write" or not isinstance(args, dict) or not isinstance(args.get("command"), str):
        return False
    cmd = args["command"]
    w = args.get("_witness") if isinstance(args.get("_witness"), dict) else {}
    cwd = w.get("cwd") if isinstance(w.get("cwd"), str) and w.get("cwd").startswith("/") else None
    if cwd is None or re.search(r"[<>`]|\$\(|<<", cmd):
        return False
    # RT-0270 p.2 (fail closed): a command run by another (xargs, find -exec, a wrapper) takes words the line does not show
    if re.search(r"(?:^|[\s;&|(])(?:xargs|parallel|find|env|sudo|doas|nice|nohup|timeout|time|command|builtin|exec|eval|source|watch|"
                 r"stdbuf|ionice|chroot|su|xe|rush)(?=$|[\s;&|)])|(?:^|\s)\.(?=\s)|\$|[*?\[{]", cmd):
        return False
    try:
        from app.hookjudge import bashparse as _bp
        c = _bp.classify(cmd, cwd, None, project=w.get("project") if isinstance(w.get("project"), str) else None)
    except Exception:  # noqa: BLE001
        return False
    if c.danger or getattr(c, "opaque", False) or c.net or getattr(c, "xforeign", None) or not c.heads:
        return False
    if git_taint or getattr(c, "gtamper", False):
        if getattr(c, "repo_extract", None) or any(str(h).split(" ", 1)[0].rsplit("/", 1)[-1] == "git" for h in c.heads):
            return False                       # RT-0270: the index / refs may hold a text the witness never saw
    for h in c.heads:
        h0 = str(h).split(" ", 1)[0].rsplit("/", 1)[-1]
        if h0 in NC_HEADS:
            if re.search(r"\[[^\]]*(?:via|unsure)", str(h)):
                return False                   # RT-0270: run through xargs / the parser is unsure
            continue
        if h0 == "git" and getattr(c, "repo_extract", None):
            continue
        return False
    return True


def secret_hold_files(ctx, agent_id, args, s_time):
    """0.2.25 (OTCHET-0.2.24, objection 1). A marked agent runs a command: the files that make it a hold.
    (1) the line names a file the agent wrote (`python3 t.py`), (2) the command runs code of a file the agent wrote (`pytest` after writing
    test_x.py / conftest.py / a module; `npm test` after a .js; `make` after a .sh: execguard.runs_source). Both look at the writes since
    LOOKBACK before the secret, not only after it: a script written first and run after the read is the same channel. Writes the owner already
    saw on a released hold do not count again (secret_confirmed_at)."""
    look = 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN)
    paths = written_since(ctx, agent_id, s_time - look, after=secret_confirmed_at(ctx, agent_id), content_only=True)   # N1: writes after that page count
    if not paths:
        return []
    named = [p for p in paths if _names_a_written_file(args, [p])]
    cmds = _commands_of(args)
    runs = [p for p in paths if p not in named and execguard.runs_source(cmds, p)]
    return sorted(named + runs)


def scrub_written_texts(ctx, agent_id, files=None, before=None, upto=None, by=None):
    """RT3 (privacy): drop the kept text of risky writes -- of these files (their run was decided) or written before `before` (out of the
    look-back: no run will show it). The mark itself stays (a later run is still held).
    upto={path: rowid} (N1 29.10): for these files only the write the page showed and older ones; a later write (made while the page
    waited) was never shown: its text stays for the next page."""
    only_old = not files and before is not None   # 04.11 (privacy D2): only the look-back cut -> only rows older than it (500 per call)
    for x in ctx.db.q("SELECT rowid AS n, rid, exec_json, updated_at FROM actions WHERE agent_id=? AND exec_json LIKE '%\"wrun\"%' AND exec_json LIKE '%\"text\"%'"
                      + (" AND COALESCE(updated_at, 0)<?" if only_old else "") + " LIMIT 500", (agent_id, before) if only_old else (agent_id,)):
        try:
            ej = json.loads(x["exec_json"])
        except (TypeError, ValueError):
            continue
        wr = ej.get("wrun") if isinstance(ej, dict) else None
        if not isinstance(wr, dict):
            continue
        old = before is not None and (x["updated_at"] or 0) < before
        ch = False
        for p, v in wr.items():
            if isinstance(v, dict) and "text" in v and (old or (files and p in files and (upto is None or p not in upto or x["n"] <= upto[p]))):
                v.pop("text"); ch = True
                if not old:
                    v["cut"] = True       # r25 (s8 P4): the page says the text was shown on a decided request, not "could not read"
                    if by:
                        v["cut_by"] = by  # N6 0.2.71: that request; if it ends FILE_CHANGED (nothing ran), "you let run" is taken back
        if ch:
            ctx.db.x("UPDATE actions SET exec_json=? WHERE rid=?", (json.dumps(ej, ensure_ascii=False), x["rid"]))


def scrub_old_written_texts(ctx, now=None):
    """04.11 (privacy D2): the hourly job's half of the look-back cut. scrub_written_texts(before=...) also runs when the agent makes its
    next command call; an agent that goes quiet would keep the texts until the account is deleted. -> number of agents scrubbed."""
    t = int(time.time()) if now is None else now
    before = t - 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN)
    ags = [r["agent_id"] for r in ctx.db.q("SELECT DISTINCT agent_id FROM actions WHERE COALESCE(updated_at, 0)<? AND exec_json LIKE '%\"wrun\"%' "
                                            "AND exec_json LIKE '%\"text\"%'", (before,))]
    for a in ags:
        scrub_written_texts(ctx, a, before=before)
    return len(ags)


TEXT_WRITE_TOOLS = ("Write", "Write.danger", "Write.outside", "Edit", "MultiEdit", "NotebookEdit")


def git_kept_texts(ctx, agent_id, mark, is_dir, args, upto_rid, since):
    """N14 0.2.73 (polygon series 9, 3a / 3b): the risky mark of `mark` was set by a git line (`git stash pop`, `git restore f13.py`):
    what it brought back is what the agent had put into git, and the witness saw that text when the agent WROTE it (a Write / Edit kept
    its masked text on its row). -> [{"file", "text"}] (at most 4): for a file mark the file itself, for a directory mark the files under
    it that this command line names; the newest kept text of a seen write made before the git line. [] when none is kept (scrubbed, out of
    the look-back, never seen): the page stays "blind"."""
    w = args.get("_witness") if isinstance(args, dict) and isinstance(args.get("_witness"), dict) else {}
    cwd = w.get("cwd") if isinstance(w.get("cwd"), str) else None
    if is_dir:
        if not cwd or not isinstance(args.get("command"), str):
            return []
        toks = {os.path.normpath(os.path.join(cwd, t)) for t in re.split(r"[\s<>|();&`\"']+", args["command"]) if t and not t.startswith("-")}
        want = sorted(t for t in toks if _under(t, mark))[:4]
    else:
        want = [mark]
    if not want:
        return []
    r0 = ctx.db.one("SELECT rowid AS n FROM actions WHERE rid=?", (upto_rid,)) if isinstance(upto_rid, str) else None
    lim = r0["n"] if r0 is not None else None
    out, left = [], set(want)
    for x in ctx.db.q("SELECT rowid AS n, tool, exec_json FROM actions WHERE agent_id=? AND updated_at>=? AND status IN (%s) AND exec_json LIKE '%%\"wrun\"%%' "
                      "AND (? IS NULL OR rowid<?) ORDER BY rowid DESC LIMIT 400" % ",".join("?" * len(SEEN_STATUSES)),
                      (agent_id, since) + SEEN_STATUSES + (lim, lim)):
        if not left or x["tool"] not in TEXT_WRITE_TOOLS:
            continue
        try:
            wr = json.loads(x["exec_json"]).get("wrun")
        except (TypeError, ValueError, AttributeError):
            continue
        for f in sorted(left):
            v = wr.get(f) if isinstance(wr, dict) else None
            if isinstance(v, dict) and not v.get("clear") and isinstance(v.get("text"), str) and v["text"]:
                out.append({"file": f, "text": v["text"]})
                left.discard(f)
    return out


def written_run_info(ctx, agent_id, since, with_cut=False, src=None):
    """-> {path: {"text"?, "by"?, "dir"?}}: the risky writes of this agent since `since` (the latest write of a file wins).
    with_cut=True -> (that, cut): cut is True when the query limit dropped rows (the caller must not trust the map to be complete).
    src={} (N1 29.10): filled with {path: rid of the write row that set the mark} (what a page shows is that write)."""
    out = {}
    rows = ctx.db.q("SELECT rid, agent_id, status, created_at, exec_json FROM actions WHERE agent_id=? AND updated_at>=? AND status IN (%s) "
                    "AND exec_json LIKE '%%\"wrun\"%%' ORDER BY updated_at DESC, rowid DESC LIMIT 201" % ",".join("?" * len(SEEN_STATUSES)),
                    (agent_id, since) + SEEN_STATUSES)
    cut = len(rows) > 200       # 29.10: the newest 200 rows are read (they were the OLDEST 200: newer marks were dropped)
    for x in reversed(rows[:200]):
        if unrun_write(ctx, x):
            continue                              # N7 0.2.71: the line never ran (its question expired / was refused): nothing was written
        try:
            wr = json.loads(x["exec_json"]).get("wrun")
        except (TypeError, ValueError, AttributeError):
            continue
        if isinstance(wr, dict):
            for p, v in wr.items():
                if isinstance(p, str):
                    if isinstance(v, dict) and v.get("clear"):
                        out.pop(p, None)          # RT-0269 p.3a: a later harmless whole-file Write took the mark off
                        if src is not None:
                            src.pop(p, None)
                    else:
                        out[p] = v if isinstance(v, dict) else {}
                        if src is not None:
                            src[p] = x["rid"]
    return (out, cut) if with_cut else out


WRUN_MAX_MARKS = 1000   # 29.10 (hang): risky-write marks of one agent carried path by path; past it a copy marks its destination whole
WRUN_TEXT_PATHS = 16    # the written text is kept on this many paths of one write (the page of the run shows 16 files)
_COPY_RX = re.compile(r"\b(?:cp|mv|rsync|ln)\b")


def _under(p, d):
    d = d.rstrip("/")
    return p.startswith(d + "/") if d else False


SCRIPT_LOOKBACK_S = 7 * 86400   # r0262: how far back a written file's findings count for its run (findings only, no text)


def script_findings_of_write(tool, args, wr):
    """r0262 (П3 rest of RT-0259): {path: findings} for the paths of this write whose TEXT the witness reads: Write / Edit / MultiEdit
    (the text of the call; an Edit's new text only), a shell heredoc / tee body of one file (inline.written_texts). Never raises."""
    out = {}
    try:
        w = dict(args.get("_witness")) if isinstance(args, dict) and isinstance(args.get("_witness"), dict) else {}
        pl = strict_policy.PLACE.get()
        for k_ in ("project", "home", "cwd"):          # a Write's witness names only its path: the event's place (judge.py)
            if not isinstance(w.get(k_), str) and isinstance(pl, dict) and isinstance(pl.get(k_), str):
                w[k_] = pl[k_]
        if not (isinstance(w.get("home"), str) and isinstance(w.get("project") or w.get("cwd"), str)):
            return {}                                # the place is not known here (a plain /v1/actions call): judged at the run
        if tool in ("Write", "Write.danger", "Edit", "MultiEdit"):
            for p_ in wr or {}:
                t_ = execguard._written_text(tool, args, p_)
                if isinstance(t_, str):
                    out[p_] = strict_policy.script_findings(w, p_, t_)
        elif tool == "Bash.write" and isinstance(args.get("command"), str):
            texts, targets = _inline.written_texts(args["command"])
            cwd = w.get("cwd") if isinstance(w.get("cwd"), str) else None
            if len(texts) == 1 and len(targets) == 1 and cwd:
                tp = os.path.normpath(os.path.join(cwd, targets[0]))
                for p_ in wr or {}:
                    if strict_policy._same_path(p_, tp):
                        out[p_] = strict_policy.script_findings(w, p_, texts[0])
    except Exception:      # noqa: BLE001  no findings: the run is judged as before
        return {}
    return out


def written_sf(ctx, agent_id, since):
    """r0263: {path: findings} kept as "wsf" by writes of this agent since `since` (the newest write of a path wins; [] = cleared)."""
    out = {}
    rows = ctx.db.q("SELECT rid, agent_id, status, created_at, exec_json FROM actions WHERE agent_id=? AND updated_at>=? AND status IN (%s) "
                    "AND exec_json LIKE '%%\"wsf\"%%' ORDER BY updated_at DESC, rowid DESC LIMIT 201" % ",".join("?" * len(SEEN_STATUSES)),
                    (agent_id, since) + SEEN_STATUSES)
    for x in reversed(rows[:200]):
        if unrun_write(ctx, x):
            continue
        try:
            m = json.loads(x["exec_json"]).get("wsf")
        except (TypeError, ValueError, AttributeError):
            continue
        if isinstance(m, dict):
            for p, f in m.items():
                if isinstance(p, str) and isinstance(f, list):
                    out[p] = f
    return out


def written_sf_of_write(ctx, agent_id, tool, args, wr, t0):
    """r0263: -> {path: findings} to keep as "wsf" for the paths of this write that are NOT run marks (wrun has their findings), or None.
    A whole-file Write replaces what was kept (a clean one clears it); an Edit / a shell write adds to it."""
    if tool not in ("Write", "Write.danger", "Edit", "MultiEdit", "Bash.write") or not isinstance(args, dict):
        return None
    w = args.get("_witness") if isinstance(args.get("_witness"), dict) else {}
    ps = [w["path"]] if isinstance(w.get("path"), str) else [x for x in (w.get("writes") or []) if isinstance(x, str)][:8]
    ps = [p for p in ps if p not in (wr or {})]
    if not ps:
        return None
    new = script_findings_of_write(tool, args, {p: "risky" for p in ps})
    if not new:
        return None
    look = max(SCRIPT_LOOKBACK_S, 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN))
    old = None
    out = {}
    for p, f in new.items():
        f = f if isinstance(f, list) else []
        if tool not in ("Write", "Write.danger"):
            if old is None:
                old = written_sf(ctx, agent_id, t0 - look)
            f = (old.get(p) or []) + [x for x in f if x not in (old.get(p) or [])]
        if f:
            out[p] = f[:48]
        else:
            if old is None:
                old = written_sf(ctx, agent_id, t0 - look)
            if old.get(p):
                out[p] = []                           # a clean whole-file Write takes the kept findings off
    return out or None


def script_runs(ctx, agent_id, args, t0):
    """r0262: [(path, findings)] of the files this Bash line runs (strict_policy.run_targets) whose text the witness judged when the agent
    wrote them (the newest write of each path wins; a later clean whole-file Write clears them)."""
    w = args.get("_witness") if isinstance(args, dict) and isinstance(args.get("_witness"), dict) else {}
    tg = strict_policy.run_targets(args.get("command") if isinstance(args, dict) else None, w.get("cwd"))
    if not tg:
        return []
    look = max(SCRIPT_LOOKBACK_S, 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN))
    wi = written_run_info(ctx, agent_id, t0 - look)
    for p, f in written_sf(ctx, agent_id, t0 - look).items():     # r0263: findings kept without a run mark
        if p not in wi or not (isinstance(wi[p], dict) and wi[p].get("sf")):
            wi[p] = {"sfc": True, "sf": f}
    out = []
    tg2 = [strict_policy.split_target(t) for t in tg]       # r0263: (path, "npm:x" | "make:t" | None)
    for p, v in sorted(wi.items()):
        if not isinstance(v, dict):
            continue
        tags = {tag for t, tag in tg2 if strict_policy._same_path(p, t)}
        if not tags:
            continue
        if v.get("sfc"):
            sf = v.get("sf")
        elif v.get("by") in ("Write", "Write.danger", "Edit", "MultiEdit") and isinstance(v.get("text"), str):
            sf = strict_policy.script_findings(w, p, v["text"])     # judged on the kept (masked) text, in this line's place
        else:
            sf = None
        sf = strict_policy.for_tags(sf, tags)
        if sf:
            out.append((p, sf))
    return out


def carry_written_marks(ctx, agent_id, args, wr, t0):
    """RT3/RT4: a shell write that names a risky file carries its mark to what it writes (cp a.py b.py; cat a.py > b.py; tee b.py < a.py);
    a moved / copied DIRECTORY carries the marks of the risky files under it to the new place. -> (marks {path: "risky" | {"dir": True}}
    or None, the source info or None).
    29.10 (hang, OTCHET-SHUM-ZHIVYE-2910 §4): one linear pass (the dict is no longer copied per mark). Past WRUN_MAX_MARKS marks of the agent
    (or a look-back the query cut) the copy is not followed file by file: every destination is marked WHOLE ({"dir": True}: a path named under
    it, or a copy of anything under it, is risky again). Fail closed: the mark is coarser, never lost."""
    cmd_ = args["command"]
    w0 = args.get("_witness") if isinstance(args.get("_witness"), dict) else {}
    cwd0 = w0.get("cwd") if isinstance(w0.get("cwd"), str) else None
    ctoks = set(re.split(r"[\s<>|();&`\"']+", cmd_))
    dsts = [x for x in (w0.get("writes") or []) if isinstance(x, str)] + ([w0["path"]] if isinstance(w0.get("path"), str) else [])
    look0 = t0 - 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN)
    info, cut = written_run_info(ctx, agent_id, look0, with_cut=True)
    if not info:
        return wr, None
    out = dict(wr or {})
    tpaths = {os.path.normpath(os.path.join(cwd0, t_)) for t_ in ctoks if t_ and not t_.startswith("-")} if cwd0 else set()
    copy = bool(cwd0 and _COPY_RX.search(cmd_))
    room = WRUN_MAX_MARKS - len(info)
    src, whole, add = None, room <= 0, {}
    # RT-0269 p.3 (R4): a token that IS a destination of this write is not its source (`cp other.py f.py` over a risky f.py: f.py gets the
    # unknown file, not its old text). Only the exact spellings that resolve to a destination are taken out.
    dset = {os.path.normpath(d) for d in dsts}
    dtoks = {t_ for t_ in ctoks if t_ and (os.path.normpath(t_) in dset or (cwd0 and os.path.normpath(os.path.join(cwd0, t_)) in dset))}
    blind = []
    for rp_, inf in info.items():
        fm = ctoks & _forms(rp_, cwd0, cmd_)
        if isinstance(inf, dict) and inf.get("dir") and any(t_ == rp_.rstrip("/") or _under(t_, rp_) for t_ in tpaths):
            src, whole = inf, True                    # a token names the directory marked whole, or a path under it
        elif fm - dtoks:
            src = inf
            for d in dsts:
                if d != rp_:
                    add[d] = "risky"
        elif fm:
            blind.append(rp_)                         # RT-0269 p.3: named only as the destination: overwritten by an unknown text
        elif copy:
            for d_ in tpaths:
                if not _under(rp_, d_):
                    continue
                rest = rp_[len(d_.rstrip("/")) + 1:]
                for dd in dsts:
                    if dd.rstrip("/") != d_.rstrip("/"):
                        src = inf
                        if not whole:
                            add[os.path.join(dd.rstrip("/"), rest)] = {"dir": True} if isinstance(inf, dict) and inf.get("dir") else "risky"
                            whole = len(add) > room
    if src is None and cut and copy and dsts:
        src, whole = {}, True                         # the look-back was cut: a copy may take a mark the map no longer shows
    if src is None and blind:
        for d in dsts:
            if os.path.normpath(d) in {os.path.normpath(b) for b in blind}:
                out[d] = out.get(d) or "risky"        # the mark stays on the risky file, its text is now unknown (the page: not read)
        return (out or None), {"blind": True}
    if src is None:
        return (out or None), None
    if whole:
        for d in dsts:
            out[d] = {"dir": True}                    # the destination whole: coarser, never lost
    else:
        out.update(add)
    return (out or None), src



def _strip_heredocs(line):
    """The line without the bodies of its here-documents and comments (bashparse._normalize: heredocs found as bash finds them).
    Anything the parser is unsure of (a delimiter it does not accept, a body that never ends, ...): the whole raw line (fail closed)."""
    try:
        from app.hookjudge.bashparse import _normalize
        one, _docs, _bal, why = _normalize(line)
    except Exception:  # noqa: BLE001 -- the parser failed: keep the whole line
        return line
    return line if why else one


def _procsub_heads(line):
    """29.10 (OTCHET-SHUM-ZHIVYE-2910 §5.2): the programs of `<(...)` / `>(...)` of the line, outside here-document bodies; a capture that
    is only digits and signs or ends with `:` (`>(5`, `<(note:` in a text) is no program. `$X` is kept (a variable program runs code)."""
    return [h for h in re.findall(r"[<>]\(\s*([^\s)]+)", _strip_heredocs(line or ""))
            if re.search(r"[A-Za-z_]", h) and not h.endswith(":")]

def seen_writes(ctx, agent_id, since):
    """N1 29.10: {(path, "w:" write rid | "k:" write key)} the owner saw: shown on the page (exec_json written_run[].w / .k) of a call the owner let go (approved /
    released, then run or still waiting), not ended FILE_CHANGED (exec_json file_changed: nothing ran, the file was another)."""
    out = set()
    for x in ctx.db.q("SELECT exec_json FROM actions WHERE agent_id=? AND updated_at>=? AND status IN (%s) AND exec_json LIKE '%%\"written_run\"%%' "
                      "ORDER BY updated_at DESC LIMIT 500" % ",".join("?" * len(SEEN_STATUSES)), (agent_id, since) + SEEN_STATUSES):
        try:
            ej = json.loads(x["exec_json"])
        except (TypeError, ValueError):
            continue
        if not isinstance(ej, dict) or ej.get("file_changed"):
            continue
        for w in ej.get("written_run") or []:
            if isinstance(w, dict) and isinstance(w.get("file"), str):
                for t_ in ("w", "k"):
                    if isinstance(w.get(t_), str):
                        out.add((w["file"], t_ + ":" + w[t_]))
    return out


def write_key(tool, args, path):
    """N1 29.10: a risky write of `path` as a digest of what the page of a run shows about it (never shown itself): the tool, the path and
    ALL its arguments (the whole text of a Write / an edit; a shell line and its directory). The page that shows a write keeps its key
    (exec_json written_run[].k): a later write with the SAME key (the same line re-run, the same text written again) tells the owner
    nothing new; any other text is unseen until a page shows it. What a line copies from another risky file is not in the key: a new
    text of that file is a risky write of its own, unseen, and holds the next run by itself (written_run_files: any unseen risky write)."""
    a = {k: v for k, v in args.items() if k != "_witness"} if isinstance(args, dict) else {}
    w = args.get("_witness") if isinstance(args, dict) and isinstance(args.get("_witness"), dict) else {}
    base = [tool, path, a, w.get("cwd") if isinstance(tool, str) and tool.startswith("Bash") else None]
    return hashlib.sha256(json.dumps(base, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8", "surrogatepass")).hexdigest()[:32]


def write_state_key(tool, args, path):
    """RT-0270 p.3: the key of a write whose text is not in the call: the line AND the digests the hook reported (`_witness.exec.files`)
    for every other file the line names (the archive, the patch, the copied file). A named file the report does not cover (or no report)
    -> None: only the write itself (its rid) can be shown, a repeat of the line is a new, unseen text."""
    w = args.get("_witness") if isinstance(args, dict) and isinstance(args.get("_witness"), dict) else {}
    cmd = args.get("command") if isinstance(args, dict) and isinstance(args.get("command"), str) else None
    cwd = w.get("cwd") if isinstance(w.get("cwd"), str) and w.get("cwd").startswith("/") else None
    rep = execguard.report_of(args)
    if cmd is None or cwd is None or rep is None:
        return None
    files = rep[1]
    written = {os.path.normpath(x) for x in (w.get("writes") or []) if isinstance(x, str)} | {os.path.normpath(path)}
    try:
        from app.hookjudge import bashparse as _bp
        heads = {str(h).split(" ", 1)[0] for h in _bp.classify(cmd, cwd, None).heads}
    except Exception:  # noqa: BLE001
        return None
    toks = [t for t in re.split(r"[\s<>|();&]+", cmd) if t and not t.startswith("-") and t not in heads]
    state = {}
    for t in toks:
        if re.search(r"[$`*?\[{'\"]", t):
            return None                        # a name the server cannot resolve: unknown input
        if "/" not in t and "." not in t:
            continue                           # a subcommand / a word (xf, pop, main): no file
        ap = os.path.normpath(t if t.startswith("/") else os.path.join(cwd, t))
        if ap in written:
            continue
        dg = files.get(ap)
        if not isinstance(dg, str) or dg == "unreadable":
            return None                        # an input whose content the witness does not know
        state[ap] = dg
    if not state:
        return None
    base = [tool, path, {k: v for k, v in args.items() if k != "_witness"}, cwd, sorted(state.items())]
    return "s" + hashlib.sha256(json.dumps(base, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8", "surrogatepass")).hexdigest()[:31]


def git_tainted(ctx, agent_id, t0):
    """RT-0270 29.10: this agent sent a line that changed git's objects / index / refs / remotes (exec_json "gt", any decision: an attempt
    counts) within the look-back: no later restore from the repository is taken as its own seen work."""
    look = 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN)
    return ctx.db.one("SELECT 1 AS k FROM actions WHERE agent_id=? AND updated_at>=? AND exec_json LIKE '%\"gt\": true%' LIMIT 1",
                      (agent_id, t0 - look)) is not None


def _line_gtamper(tool, args):
    """RT-0270: the shell line changes git's objects / index / refs / remotes (bashparse gtamper)."""
    if not (isinstance(tool, str) and tool.startswith("Bash") and isinstance(args, dict) and isinstance(args.get("command"), str)
            and "git" in args["command"]):
        return False
    w = args.get("_witness") if isinstance(args.get("_witness"), dict) else {}
    try:
        from app.hookjudge import bashparse as _bp
        return bool(getattr(_bp.classify(args["command"], w.get("cwd") if isinstance(w.get("cwd"), str) else "/", None), "gtamper", False))
    except Exception:  # noqa: BLE001 -- unsure: a git line the parser cannot judge counts as a change
        return True


def mark_file_changed(ctx, rid, f, by=None):
    """N1/N3 29.10: the page of `rid` showed a file written since (page_files_changed): the decision on it is not a showing (seen_writes,
    secret_confirmed_at skip it) and the owner is told so. Idempotent. 0.2.77b (red team R2-7): `by` = "late_write" when the file is
    not one the page showed but a write after a late approval (late_project_write): `file_changed_by` says so, and the page / answer say
    "after your approval the agent wrote a file", not "the file you saw changed"."""
    x = ctx.db.one("SELECT exec_json FROM actions WHERE rid=?", (rid,))
    try:
        ej = json.loads(x["exec_json"]) if x is not None and x["exec_json"] else {}
    except (TypeError, ValueError):
        ej = {}
    if not isinstance(ej, dict) or ej.get("file_changed"):
        return
    ej["file_changed"] = f if isinstance(f, str) else True
    if by:
        ej["file_changed_by"] = by
    ctx.db.x("UPDATE actions SET exec_json=? WHERE rid=?", (json.dumps(ej, ensure_ascii=False), rid))
    _uncut(ctx, rid)


def _uncut(ctx, rid):
    """N6 0.2.71: the decision on `rid` ended FILE_CHANGED (nothing ran) after its approval had dropped the texts it showed (cut_previews):
    the write rows no longer say "shown on a request you let run" (`cut`); their text is gone (privacy), the page says it was not kept."""
    for y in ctx.db.q("SELECT rid, exec_json FROM actions WHERE exec_json LIKE ? LIMIT 500", ('%"cut_by": "' + rid + '"%',)):
        try:
            ej = json.loads(y["exec_json"])
        except (TypeError, ValueError):
            continue
        wr = ej.get("wrun") if isinstance(ej, dict) else None
        if not isinstance(wr, dict):
            continue
        for v in wr.values():
            if isinstance(v, dict) and v.get("cut_by") == rid:
                v.pop("cut", None)
                v.pop("cut_by", None)
        ctx.db.x("UPDATE actions SET exec_json=? WHERE rid=?", (json.dumps(ej, ensure_ascii=False), y["rid"]))


def file_changed_of(ctx, rid):
    """N3: -> the file the page of `rid` showed that was written since (marks the row), or None."""
    x = refresh(ctx, rid)
    if x is None:
        return None
    f = page_files_changed(ctx, x)
    if f:
        mark_file_changed(ctx, rid, f)
    return f


def _line_extract(args):
    """N4 29.10: the server's own reading of a shell line -> (extract paths, whole-directory extracts): what `tar x` / `unzip` / `patch` /
    `git checkout|merge|...` put into the project, whose text is not in the line (bashparse RT-0269 p.4). Never trusts the hook's list."""
    w = args.get("_witness") if isinstance(args, dict) and isinstance(args.get("_witness"), dict) else {}
    cmd = args.get("command") if isinstance(args, dict) else None
    cwd = w.get("cwd") if isinstance(w.get("cwd"), str) and w.get("cwd").startswith("/") else None
    if not isinstance(cmd, str) or cwd is None:
        return [], []
    try:
        from app.hookjudge import bashparse as _bp
        c = _bp.classify(cmd, cwd, None, project=w.get("project") if isinstance(w.get("project"), str) else None)
    except Exception:  # noqa: BLE001 -- a line the parser cannot read: nothing is widened, nothing is said
        return [], []
    ex = [x for x in (getattr(c, "xforeign", None) or []) if isinstance(x, str)]   # N15: not what git takes from the repo's own objects
    xd = [x for x in (getattr(c, "xdirs", None) or []) if isinstance(x, str)]
    return ex, xd


def extract_dir_recipient(tool, args, v):
    """N4 29.10 (series 8b, RT4): `tar xf s.tar` / `patch -p0 < s.diff` / `unzip a.zip` in the project write files INSIDE the directory
    (the hook names the directory itself: /proj). The mandate's `<project>/*` never matched `/proj`, so a plain extraction in the project
    was refused RESOURCE "writes: only inside the project". A Bash.write target that the server's own parse finds to be a whole-directory
    extraction is judged as `<dir>/` (what is written is under it); anything else (rm, mv, cp onto the directory) is judged as before."""
    if tool != "Bash.write" or not isinstance(v, str) or not v.startswith("/") or v.endswith("/"):
        return v
    _ex, xd = _line_extract(args)
    return v + "/" if os.path.normpath(v) in {os.path.normpath(x) for x in xd} else v


def clean_in_project(mark, path, project):
    """r0271 (Н1): a written-run mark (written_run_info value) the owner's "from now on" rule covers: the witness read the whole text when
    it was written (no gate, not unseen / opaque), no script findings, not a directory marked whole, the path inside `project`."""
    if not isinstance(mark, dict) or not isinstance(path, str) or not isinstance(project, str) or not project.startswith("/"):
        return False
    if mark.get("g") or mark.get("dir") or mark.get("sf"):
        return False
    pr = os.path.normpath(project).rstrip("/") + "/"
    p_ = os.path.normpath(path)
    # the paths are the hook's (resolved on the agent's machine, as the rule's project is): compared as text, never resolved here
    return p_.startswith(pr) and "/.git/" not in p_[len(pr) - 1:] + "/"


def allowance_keeps(ctx, agent_id, wrf, project, t0):
    """r0271 (Н1): the written files that still hold a run the owner's "from now on" rule for `project` allowed (see clean_in_project)."""
    wi = written_run_info(ctx, agent_id, t0 - 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN))
    return [f for f in wrf if not clean_in_project(wi.get(f), f, project)]


def _unseen_risky(ctx, agent_id, since):
    """-> (all risky marks {path: info}, the paths among them whose write no page the owner signed has shown): written_run_files."""
    src = {}
    allp = written_run_info(ctx, agent_id, since, src=src)
    if not allp:
        return allp, set()
    seen = seen_writes(ctx, agent_id, since)
    return allp, {p for p in allp if not ((src.get(p) and (p, "w:" + src[p]) in seen)
                                          or (isinstance(allp[p], dict) and isinstance(allp[p].get("k"), str) and (p, "k:" + allp[p]["k"]) in seen))}


def stores_unseen_risky(ctx, agent_id, tool, args, t0):
    """RT-0271 0.2.72 (cloud/OTCHET-N6-N7-N10-0271.md p.9): the shell line puts the work tree's text into git (`git stash` / push / save /
    create, `git add`, `git commit`: bashparse gstore) while this agent has an UNSEEN risky write under that repository. The text then lies in
    git's objects / index, a harmless Write takes the mark off the file, and an "own" restore (`git stash pop`, `git restore f`,
    `git checkout -- f`) brings it back unmarked: `python3 f9.py` ran it unasked. Such a line counts as changing git's objects / index
    ("gt", git_tainted): no later restore is "own". A line the parser cannot read counts (fail closed); a stash with no risky write, or
    after the owner saw it, does not."""
    if not (isinstance(tool, str) and tool.startswith("Bash") and isinstance(args, dict) and isinstance(args.get("command"), str)
            and "git" in args["command"]):
        return False
    w = args.get("_witness") if isinstance(args.get("_witness"), dict) else {}
    try:
        from app.hookjudge import bashparse as _bp
        c = _bp.classify(args["command"], w.get("cwd") if isinstance(w.get("cwd"), str) else "/", None,
                         project=w.get("project") if isinstance(w.get("project"), str) else None)
        tops = [t for t in (getattr(c, "gstore", None) or []) if isinstance(t, str) and (t == "*" or t.startswith("/"))]
    except Exception:  # noqa: BLE001 -- a git line the parser cannot judge: as _line_gtamper
        return True
    if not tops:
        return False
    look = 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN)
    allp, paths = _unseen_risky(ctx, agent_id, t0 - look)
    # only a FILE mark: a harmless Write can take it off (RT-0269 p.3a), which is what the bypass needs. A directory marked whole
    # ({"dir": True}: tar / an unknown restore) keeps its mark whatever is written under it, so the run after the restore is held anyway.
    files = [os.path.normpath(p) for p in paths if not (isinstance(allp.get(p), dict) and allp[p].get("dir"))]
    if not files:
        return False
    if "*" in tops:
        return True
    for t in tops:
        for t_ in {os.path.normpath(t), os.path.realpath(t)}:
            if any(p_ == t_ or _under(p_, t_) for p_ in files):
                return True
    return False


from app.hookjudge.mapping import OUTSIDE_WRITE as OUTSIDE_WRITE_HEAD  # noqa: E402
from app.hookjudge.mapping import auto_quiet_place, is_auto_profile  # noqa: E402  r0296


def written_run_files(ctx, agent_id, args, t0):
    """28.10 (adaptive red team №1): the files marked risky when this agent wrote them (execguard.written_run) that this command line names
    or runs, written within the look-back and after the owner last released such a hold (what the owner saw then does not count again)."""
    look = 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN)
    scrub_written_texts(ctx, agent_id, before=t0 - look)
    # r25 (s8 P2/P3): a question or a secret hold whose page showed the risky writes (exec_json "written_run") and that the owner let go
    # counts as seen, like a released WRITTEN_RUN hold (otherwise B6 release -> B7 the same line held again: two touches for one command).
    # N1 29.10 (series 8b, E2 -> E3): "seen" is per file and per WRITE: the write whose text the page showed (exec_json written_run[].w),
    # on a page the owner signed (approved / released) and that did not end FILE_CHANGED. A write made after the page (a second process
    # rewrote the file between the question and the decision) is unseen, whenever the owner decided.
    allp, paths = _unseen_risky(ctx, agent_id, t0 - look)
    if not paths:
        return []
    # r25 (s8 P5): the page names first the risky files this line itself names (`bash f8b.sh`), even ones the owner let go before, then
    # the rest of the unseen risky writes (what makes it a question is unchanged: an unseen risky write + a line that runs code)
    named = sorted(p for p in allp if _names_a_written_file(args, [p]))
    # RT5 (28.10, round 5: 19 bypasses through path spellings, pushd, globs, tar, git mv, imports): matching the risky file's NAME in the
    # line is a game the agent wins. The rule is structural now: after a risky write of this agent (not yet released), the next line that
    # runs code at all -- an interpreter, a build / test runner, or a program given by its path -- is held once, whatever it names. The
    # owner sees the risky writes on the page; releasing it clears them (`since` above). git, readers and static analysers are not runs.
    line = args.get("command") if isinstance(args, dict) and isinstance(args.get("command"), str) else ""
    heads = list(_commands_of(args))                                  # the parser's heads (quotes, nesting, xargs / find -exec / carried children)
    # 0611 (friction, real corpus: `sed -i ... ~/notes/x.md; grep -c x` held after an earlier risky write): the hook's pseudo-command of a
    # shadow-copied write outside the project (mapping.OUTSIDE_WRITE) names a WRITE, not a program; as an unknown head it counted as a run.
    # The line's real programs stay in the list (sed [write], grep ... are judged as before). A program the agent names like the marker
    # has a blank in its name: the parser makes that line opaque (asked), so it never reaches here as an allowed line.
    heads = [h for h in heads if not (isinstance(h, str) and h.startswith(OUTSIDE_WRITE_HEAD))]
    heads += _procsub_heads(line)                                     # process substitution: `tee >(python3)`
    gh = _git_hooks(args)
    if not _line_runs_code(heads, line, gh):
        return []
    # 11.11 (r0260, class (а) of the dev hold-out): a line whose ONLY code is inline Python that edits files (`python3 - <<'EOF' p='x.py';
    # s=open(p).read() ... EOF`, `cp x x.bak && python3 -c '...'`) runs no file the agent wrote: its whole program is in the line, it runs
    # nothing but itself and a short list of stdlib modules, and no written file can be imported in place of one (hookjudge/inline.py).
    # Before, after one risky write every such edit was held -- ~15 holds in a row, each edit renewing the mark for the next one.
    # What the edit WRITES keeps its own marks (persistence, git hooks, outside the project); `python3 x.py`, pytest, an unquoted
    # heredoc, `PYTHONPATH=...`, exec / runpy / subprocess in the code: held as before.
    words0 = [w.strip("'\"") for w in re.split(r"\s+", line or "") if w]
    if all(_inline.PY_NAME.fullmatch(h) for h in heads if isinstance(h, str) and _runners.head_runs_code(h, words0, gh)) \
            and _inline.edit_only_line(line, sorted(set(allp) | set(paths))):
        return []
    # 0.2.81 (red team R4-1/R4-2): a risky family file (x.mk, jest.config.py, package.json, .husky/*) run by ITS OWN family tool
    # (`make -f x.mk`, `npx jest`) is asked by ESCALATE_EXEC_CHANGED, as before: left out here only when EVERY program of the line that
    # runs code is a tool of that file's family. Any other runner (`python3 x.mk`, `sudo make`, an unknown program) -> asked here.
    words = [w.strip("'\"") for w in re.split(r"\s+", line or "") if w]
    rh = [h for h in heads if isinstance(h, str) and _runners.head_runs_code(h, words, gh)]

    def _native(p):
        fp = set(execguard.families_of_path(p))
        return bool(fp and rh) and all(set(execguard.families_of_command(h)) & fp for h in rh)

    named = [p for p in named if not _native(p)]
    rest = {p for p in paths - set(named) if not _native(p)}
    return named + sorted(rest)


_HOOK_CFG = re.compile(r"(\.pre-commit-config\.ya?ml|\.?lefthook(-local)?\.(ya?ml|json|toml)|\.lintstagedrc.*|lint-staged\.config\..*|"
                       r"\.?simple-git-hooks.*|\.overcommit\.ya?ml)")


def _git_hooks(args):
    """RT7 (28.10): the names of the git hooks the exec report shows -> set (None: no report). Hooks of the git dir and of core.hooksPath
    (`_witness.exec.git`, .sample files are never reported), .husky/*, and the configs of hook managers (pre-commit, lint-staged, lefthook,
    simple-git-hooks, overcommit: their usual hooks are taken as installed)."""
    w = args.get("_witness") if isinstance(args, dict) else None
    ex = w.get("exec") if isinstance(w, dict) else None
    if not isinstance(ex, dict):
        return None
    out = set()
    g = ex.get("git")
    for ap in (g if isinstance(g, dict) else {}):
        if isinstance(ap, str) and not re.search(r"/(config|config\.worktree|info/attributes)$", ap):
            out.add(ap.rsplit("/", 1)[-1])
    f = ex.get("files")
    for rel in (f if isinstance(f, dict) else {}):
        if not isinstance(rel, str):
            continue
        parts = rel.split("/")
        if len(parts) >= 2 and parts[-2] == "hooks" and parts[0] == ".git" or parts[0] == ".husky":
            if not parts[-1].endswith(".sample"):
                out.add(parts[-1])
        elif _HOOK_CFG.fullmatch(parts[-1]):
            out.update(_runners.HOOK_MANAGER_HOOKS)
    return out


# RT6 (28.10): ONE registry (app/hookjudge/runners.py). Before, the rule looked at two of five disagreeing tables and 104 of 126 runners
# passed after a risky write (python2, pypy3, java, swift, bazel, xcodebuild, eslint, vim, gdb, m4, sqlite3, tmux, `git bisect run` ...).
CODE_RUNNERS = _runners.ALL_RUNNERS
RUNNERS = _runners.SHELLS | _runners.INTERPRETERS | _runners.WRAPPER_WORDS | {"uv", "pipx"}


def _runs_code(head, words=()):
    """RT6, the rule INVERTED: after a risky write a head runs code unless it is on the explicit list of programs that do not
    (runners.NOT_RUNNERS: the default read-only list, the local writes, static analysers, readers whose exec flags are checked in `words`).
    An unknown program is a run: the list of runners is never complete (m4, erb, gnuplot, ed are languages too); the list of non-runners is."""
    return _runners.head_runs_code(head, words)


def _line_runs_code(heads, line, git_hooks=None):
    """`find` runs code only with -exec / -execdir / -ok / -okdir (fatigue E 28.10: `find . -name '*.py'` is a read); `tar --to-command`,
    `man -P`, `zip -TT`, `sort --compress-program`, `rg --pre` are runs (runners.READER_EXEC). RT7: `git commit` with hooks installed."""
    words = [w.strip("'\"") for w in re.split(r"\s+", line or "") if w]
    return any(_runners.head_runs_code(h, words, git_hooks) for h in heads if isinstance(h, str))


def _is_runner(head):
    return head in RUNNERS or _runners.is_python(head)


def _forms(path, cwd, line=None):
    """The spellings of `path` in a command line: absolute, basename, relative to cwd and (RT4) to every `cd DIR` of the line."""
    f = {path, os.path.basename(path), "./" + os.path.basename(path)}
    cwds = [cwd] if cwd else []
    if cwd and isinstance(line, str):
        for d in re.findall(r"(?:^|[;&|(]\s*)cd\s+([^\s;&|)]+)", line):
            cwds.append(os.path.normpath(os.path.join(cwds[-1], d.strip("'\""))))
    for c in cwds:
        try:
            r = os.path.relpath(path, c)
            f |= {r, "./" + r}
        except ValueError:
            pass
    return f


def _fed_to_runner(line, forms):
    """RT4: the file goes INTO an interpreter: a pipeline stage names it and a later stage of the SAME pipeline is a runner
    (`cat f | python3`, `sed -n p f | sh`); `cat f && python3 app.py` is not."""
    for chain in re.split(r"&&|\|\||;|\n", line):
        stages = chain.split("|")
        for i, st in enumerate(stages[:-1]):
            if set(re.split(r"[\s<>()`\"'$]+", st)) & forms:
                if any(x.split() and _is_runner(x.split()[0].rsplit("/", 1)[-1]) for x in stages[i + 1:]):
                    return True
    return False


def _runs_written_file(cmds, path, cwd, line=None):
    """28.10: a command of the line RUNS this file: it is the program (`./m.py`, `/p/m.py`), an interpreter's script (`python3 m.py`,
    `bash < m.sh`, `source m.sh`). Naming it as data (`cp a m.py`, `cat m.py`, `git add m.py`) is not running it."""
    forms = _forms(path, cwd, line)
    for c in cmds:
        toks = c.replace("<", " < ").split()
        if not toks:
            continue
        if toks[0] in forms and toks[0] != os.path.basename(path) or toks[0] == path:
            return True
        head = toks[0].rsplit("/", 1)[-1]
        if _is_runner(head):
            if any(t in forms for t in toks[1:]):
                return True
    return False


def hold_after_secret(ctx, agent_id, tool, act, args, t0):
    """0.2.24 (T3): network / message / publish of a marked agent: always held. A command that runs code: held when it runs a file the agent
    wrote (secret_hold_files). Running the project's own code the agent did not touch (pytest after reading .env) is not held: a changed
    executed file the witness did not see as a write (conftest.py, package.json ...) is asked by execguard anyway."""
    if not outgoing(tool, act, args):
        return False
    s = secret_seen(ctx, agent_id, t0)
    if s is None:
        return False
    if tool == "Write.outside":
        return outside_text_risky(act, args)       # 06.11 (r0260): a note written outside the project is not a run (see below)
    if act.get("class") == "command":
        return bool(secret_hold_files(ctx, agent_id, args, s[1]))
    return True


# 06.11 (r0260, friction: the owner's note `Write ~/notes/TODAY.md "# note"` held ESCALATE_SECRET_SEEN every day). A file tool's
# write outside the project (Write.outside: the hook kept a shadow copy) went through the COMMAND rule above: "the line names a file the
# agent wrote" -- the note it wrote yesterday -- as if writing it were running it. It runs nothing; what it can do with a secret is put it
# into a file on this machine, like a write inside the project (never held). It is held only where that file can leave the machine by
# itself or the text visibly carries a credential: a cloud-synced folder / a mounted volume, the core's data tags on the call (a secret
# shape or the account's closed data), a secret shape or a `PASSWORD=` / `token:` value in the text (toolmap.mask_value), a text the
# witness cannot read. Residual (stated): a secret the agent re-encodes (base64, split) into a note in a folder synced by a tool the
# witness does not know -- the same as into a project file pushed later.
SYNC_PLACES = re.compile(r"(?i)/Library/(?:Mobile Documents|CloudStorage|Group Containers/[^/]*(?:dropbox|onedrive|google))/|"
                         r"/(?:Dropbox|Google Drive|GoogleDrive|OneDrive|iCloud Drive|iCloudDrive|Box|Box Sync|pCloud Drive|MEGA|Yandex\.Disk|"
                         r"Nextcloud|ownCloud|Syncthing|Sync|Resilio Sync)(?:[ -][^/]*)?(?:/|$)|^/Volumes/|^/(?:mnt|media|net|Network)/")


def outside_text_risky(act, args) -> bool:
    w = args.get("_witness") if isinstance(args, dict) else None
    path = w.get("path") if isinstance(w, dict) else None
    if not isinstance(path, str) or SYNC_PLACES.search(path) or (act.get("data") if isinstance(act, dict) else None):
        return True
    parts = []
    for k in ("content", "new_string", "new_source"):
        if isinstance(args.get(k), str):
            parts.append(args[k])
    if isinstance(args.get("edits"), list):
        parts += [e.get("new_string") for e in args["edits"] if isinstance(e, dict) and isinstance(e.get("new_string"), str)]
    if not parts or any(not isinstance(x, str) for x in parts):
        return True
    txt = "\n".join(parts)
    return tm.mask_value(txt, {}, len(txt) + 64) != txt


def outgoing(tool, act, args):
    """Can this call carry data out of the machine (or run code that can)? A read of a secret is not (it is asked on its own)."""
    c = act.get("class")
    if c in ("disclosure", "message", "http"):                   # 0.2.43: an HTTP request of a sandbox (PROPOSAL-08-http) leaves the machine
        return True
    if c == "publish":
        return tool not in SECRET_READ_TOOLS
    if c == "command":
        w = args.get("_witness") if isinstance(args, dict) else None
        heads = w.get("commands") if isinstance(w, dict) else None
        if not isinstance(heads, list):
            return True                     # a command of another integration: the witness cannot tell what it runs
        return any(h not in tm.CC_READONLY_COMMANDS and h not in QUIET_HEADS and h not in TEXT_HEADS and h not in LOCAL_HEADS
                   for h in heads)   # `python3 t.py`, `curl`
    return False


def mark_gave_up(ctx, rid):
    """0.2.43b (C): the hook's last long poll ended with the call still waiting (`GET /v1/actions/{rid}?final=1`): the agent was told
    "refused: nobody approved it within N s" and did not run it. The call stays approvable (the agent may repeat the same call), but the
    journal says "not run: timeout" instead of an open wait. late 29.10: a held call too (the owner may still release it; the repeat then
    gets that released row, late_release_reuse)."""
    ctx.db.x("UPDATE actions SET gave_up_at=? WHERE rid=? AND status IN ('pending_approval','held') AND gave_up_at IS NULL", (now(), rid))


def _sans_adv(a):
    return {k: v for k, v in a.items() if k != "adv"}


def _content_in_hash(tool, cls):
    """RT-0269 p.1: the whole effect of the call is in its request hash (a fetch: the URL; Write / Edit: path and text), so a late
    release may be handed to the repeat. A command or any row derived from a shell line (Bash.write / Bash.net / ...) runs or copies files
    whose content is NOT in the hash: never."""
    if cls == "command" or not isinstance(tool, str):
        return False
    return not (tool == "Bash" or tool.startswith("Bash.") or tool.startswith("Bash:"))


def late_release_reuse(ctx, agent, m, tool, act, t0):
    """late 29.10 (OTCHET-R1-HELD-WAIT-2910, remark 2): the hook gave up waiting on a held call (`final=1`, gave_up_at), THEN the owner
    released it: the row is allowed, nobody presented it. The agent repeats the call: without this it is a new action that the same or
    another rule holds again (a fetch after a secret: always held) -- a second touch for a call the owner already let go.
    Handed out only when ALL hold: same agent and active mandate; a held row (hold_reason) the owner RELEASED (a done release request
    with release true; a row the core allowed by itself is never handed out); status allowed (not presented, not reported, not rejected);
    not expired, and the ledger would accept its present now (check_present: not used, not expired, reservation active); the request is
    the same byte for byte (request_hash of the canonical action, the advisor's release label `adv` aside; args_sha256 covers the tool
    and ALL arguments); never a command (RT-0269 p.1: _content_in_hash -- what runs is not in the hash). Once: gave_up_at
    is cleared when it is handed out, so a second repeat is judged anew. Caller: _do_action, under hub.lock."""
    rh0 = request_hash(_sans_adv(act))
    for x in ctx.db.q("SELECT * FROM actions WHERE agent_id=? AND mandate_id=? AND tool=? AND status='allowed' AND gave_up_at IS NOT NULL "
                      "AND hold_reason IS NOT NULL AND expires>? ORDER BY created_at DESC LIMIT 16", (agent["id"], m["id"], tool[:200], t0)):
        try:
            a = wire.cbor_form(json.loads(x["action_json"]))
        except (TypeError, ValueError):
            continue
        if not isinstance(a, dict) or request_hash(_sans_adv(a)) != rh0:
            continue
        rq = ctx.db.one("SELECT meta FROM sig_requests WHERE account_id=? AND kind='release' AND ref=? AND status='done' ORDER BY created_at DESC LIMIT 1",
                        (x["account_id"], x["rid"]))
        try:
            if rq is None or json.loads(rq["meta"]).get("release") is not True:
                continue
        except (TypeError, ValueError, AttributeError):
            continue
        L = ctx.hub.ledger(x["account_id"])
        if L.S.check_present(x["rid"], L.sync_now(), True, request_hash(a)):
            continue                                  # used, expired, reservation gone: never handed out
        if not _content_in_hash(x["tool"], x["class"]):
            continue                                  # RT-0269 p.1: a command (or a shell-derived row) runs files the hash does not cover:
            #                                           another agent of the account, or a write the witness does not see (`tar x`, `patch`),
            #                                           changes what runs. Judged anew (a second touch), never handed out
        if not ctx.db.n("UPDATE actions SET gave_up_at=NULL WHERE rid=? AND status='allowed' AND gave_up_at IS NOT NULL", (x["rid"],)):
            continue
        log("INFO", "late release: repeat gets the released row", rid=x["rid"], account=x["account_id"])
        return refresh(ctx, x["rid"])
    return None


def clear_gave_up(ctx, rid):
    ctx.db.x("UPDATE actions SET gave_up_at=NULL WHERE rid=? AND gave_up_at IS NOT NULL", (rid,))


def cut_previews(ctx, rid):
    """0.2.24 (critique B): the action is decided: keep only the hash of its arguments and a short masked excerpt (<= 80 characters)."""
    x = ctx.db.one("SELECT args_preview, action_json, preview_cut, exec_json FROM actions WHERE rid=?", (rid,))
    if x is None or x["preview_cut"]:
        return
    if x["exec_json"] and '"written_run"' in x["exec_json"]:   # 28.10: the written file's text goes with the other previews
        try:
            ej = json.loads(x["exec_json"])
            files = [w.get("file") for w in ej.get("written_run") or [] if isinstance(w, dict)]
            shown = {w["file"]: w["w"] for w in ej.get("written_run") or [] if isinstance(w, dict) and isinstance(w.get("file"), str) and isinstance(w.get("w"), str)}
            ej["written_run"] = [{k: v for k, v in w.items() if k not in ("text", "git_texts")} for w in ej.get("written_run") or [] if isinstance(w, dict)]
            x = dict(x, exec_json=json.dumps(ej, ensure_ascii=False))
            ctx.db.x("UPDATE actions SET exec_json=? WHERE rid=?", (x["exec_json"], rid))
            ag = ctx.db.one("SELECT * FROM actions WHERE rid=?", (rid,))
            # r25 (s8 P4): only a run the owner LET GO (approved / released) drops the text on the write rows: after a Reject, a refusal,
            # an expiry or a freeze the file was not run and the next run's page shows the text again (it still goes at the look-back, 24 h)
            # N6 0.2.71 (series 8c): nor a decision that ends FILE_CHANGED (a shown file was written since: nothing runs). Checked here,
            # before the texts go: the next page must show the text again, and must not say "you let run".
            fc_ = None
            if ag is not None and ag["status"] in SEEN_STATUSES:
                fc_ = ej.get("file_changed") or page_files_changed(ctx, ag)
                if fc_:
                    mark_file_changed(ctx, rid, fc_)
                    x = dict(x, exec_json=ctx.db.one("SELECT exec_json FROM actions WHERE rid=?", (rid,))["exec_json"])
            if ag is not None and ag["status"] in SEEN_STATUSES and not fc_:
                upto = {}
                for f_, w_ in shown.items():         # N1 29.10: a write made after the page keeps its text (it was never shown)
                    r_ = ctx.db.one("SELECT rowid AS n FROM actions WHERE rid=?", (w_,))
                    upto[f_] = r_["n"] if r_ is not None else -1
                scrub_written_texts(ctx, ag["agent_id"], files=set(f for f in files if isinstance(f, str)), upto=upto or None, by=rid)   # RT3: and on the write rows
        except (TypeError, ValueError, AttributeError):
            pass
    if x["exec_json"] and '"preview"' in x["exec_json"]:     # 0.2.43b: the file previews of exec_changed go with the other previews
        try:
            ej = json.loads(x["exec_json"])
            for n in (ej.get("net") or {}).values():
                if isinstance(n, dict):
                    n.pop("preview", None)
            ctx.db.x("UPDATE actions SET exec_json=? WHERE rid=?", (json.dumps(ej, ensure_ascii=False), rid))
        except (TypeError, ValueError, AttributeError):
            pass
    try:
        h = json.loads(x["action_json"]).get("args_sha256") if x["action_json"] else None
    except (TypeError, ValueError, AttributeError):
        h = None
    ctx.db.x("UPDATE actions SET args_preview=?, text_preview=NULL, line_text=NULL, preview_cut=1 WHERE rid=? AND preview_cut IS NULL",
             (tm.decided_preview(h, x["args_preview"]), rid))


def new_rid():
    return "r_" + base64.b32encode(os.urandom(16)).decode().rstrip("=")[:26]


def path_b64(path):
    """Merkle path as a list of base64url strings; each item = side byte ('L'|'R') || 32-byte sibling hash."""
    return [wa.b64u(s.encode() + h) for s, h in path]


def proof_json(proof, approval=None):
    """proof: dict of Ledger.receipt_proof -> JSON of ActionResult.proof (approval carries entry/path of the APPROVAL entry + the envelope)."""
    out = {"entry_b64": wa.b64u(proof["entry"]), "path_b64": path_b64(proof["path"]), "checkpoint_b64": wa.b64u(proof["checkpoint"]), "approval": None}
    if approval is not None:
        a = proof["approval"]
        out["approval"] = {"approved": True, "envelope_b64": wa.b64u(approval), "entry_b64": wa.b64u(a["entry"]), "path_b64": path_b64(a["path"])}
    return out


def _batch_paths(hashes, indices):
    """Inclusion paths of several leaves in ONE tree, sharing subtree roots (same result as checkpoint.inclusion_path per leaf)."""
    return merklecache.inclusion_paths(hashes, indices)


def materialize_proofs(ctx, account_id):
    """R-16: allowed actions are answered with the AAR at once and get their inclusion proof LATER, all pending ones of the tenant under
    ONE signed checkpoint (one CHECKPOINT entry per batch instead of one per allow). Returns the number of proofs made."""
    with ctx.hub.lock(account_id):
        rows = ctx.db.q("SELECT rid FROM actions WHERE account_id=? AND aar IS NOT NULL AND proof_json IS NULL ORDER BY created_at", (account_id,))
        if not rows:
            return 0
        L = ctx.hub.ledger(account_id)
        with L._tx():
            rids = [r["rid"] for r in rows if r["rid"] in L.rseq]
            if not rids:
                return 0
            cpseq, cpb = L._checkpoint_locked()
            hs = L.hashes[:cpseq + 1]
            paths = _batch_paths(hs, {L.rseq[r] for r in rids})
            with ctx.db.tx():
                for rid in rids:
                    s = L.rseq[rid]
                    pj = proof_json({"entry": L.raws[s], "path": paths[s], "checkpoint": cpb})
                    ctx.db.x("UPDATE actions SET proof_json=? WHERE rid=?", (json.dumps(pj), rid))
        return len(rids)


def refresh(ctx, rid):
    """Row with lazy expiry: pending_approval / approved past `expires` become expired. 0.2.18: no lock around SELECT+UPDATE: the expiry
    is ONE conditional UPDATE (status still waiting AND past expires), so a concurrent approval or present is never overwritten."""
    x = ctx.db.one("SELECT * FROM actions WHERE rid=?", (rid,))
    if x and x["status"] in WAITING and now() > x["expires"]:
        t = now()
        if ctx.db.n("UPDATE actions SET status='expired', updated_at=? WHERE rid=? AND status IN ('pending_approval','approved','held') AND expires<?", (t, rid, t)):
            if x["status"] != "pending_approval" or t > x["expires"] + rpt.LATER_S:
                cut_previews(ctx, rid)      # 0.2.29: an unanswered question keeps its previews LATER_S more (approval for the next runs); jobs.prune_previews cuts it then
            else:                           # 0.2.30: ... only when it may be approved for later runs (not a team account, a dangerous command ...)
                y = ctx.db.one("SELECT * FROM actions WHERE rid=?", (rid,))
                acc = ctx.db.one("SELECT * FROM accounts WHERE id=?", (y["account_id"],)) if y is not None else None
                try:
                    why = "no account" if acc is None else rpt.eligible(ctx, acc, y)
                except Exception:  # noqa - unknown -> cut
                    why = "unknown"
                if why:
                    cut_previews(ctx, rid)
        x = ctx.db.one("SELECT * FROM actions WHERE rid=?", (rid,))
    return x


def _anchor_of(ctx, account_id, proof):
    """r0269: time status of a receipt (app/tlog.receipt_anchor) from the account checkpoint its inclusion proof sits under."""
    from app import tlog
    from svidetel_v4 import cose
    seq = None
    try:
        if proof and proof.get("checkpoint_b64"):
            seq = cose.loads(cose.parse1(wa.b64u_dec(proof["checkpoint_b64"]))[2])["seq"]
    except Exception:  # noqa: BLE001  (an unreadable proof: no time claim, "queued")
        seq = None
    return tlog.receipt_anchor(ctx, account_id, seq)


def to_result(ctx, x):
    verdict = x["verdict"]
    if x["status"] == "expired" and verdict == "allow":
        verdict = "deny"
    if verdict == "hold":
        verdict = "defer" if x["status"] == "held" else "deny"     # held by the gateway: to the agent it is waiting for a human
    r = {"rid": x["rid"], "verdict": verdict, "reason": x["reason"], "status": x["status"],
         "action": json.loads(x["action_json"]) if x["action_json"] else None, "expires": x["expires"],
         "aar_b64": None, "proof": None, "promise_b64": None, "approval_url": None}
    if x["verdict"] == "allow" and x["aar"] is not None:
        r["aar_b64"] = wa.b64u(bytes(x["aar"]))
        r["proof"] = json.loads(x["proof_json"]) if x["proof_json"] else None
        r["anchor"] = _anchor_of(ctx, x["account_id"], r["proof"])   # r0269: "queued" until a stamped log checkpoint covers it (unsigned info)
    if x["promise"]:
        r["promise_b64"] = wa.b64u(bytes(x["promise"]))          # 0.2.4: for every decision that has a ledger entry, not only allow (draft-deus-aar-05 9.5)
    if x["status"] in ("pending_approval", "held"):
        r["approval_url"] = "%s/%s.html?rid=%s" % (ctx.cfg.origin, "trial" if x["reason"] == trial.REASON else "approve", x["rid"])
    keys = x.keys()
    if "covered_by" in keys and x["covered_by"] and x["status"] == "covered":
        r["covered_by"] = x["covered_by"]               # 0.2.10: the owner answered with a project allowance: send the same call again
    if "allowances" in keys and x["allowances"] and x["verdict"] == "allow":
        r["allowed_by"] = json.loads(x["allowances"])   # 0.2.10: the allowances that let this line through (the AAR names the recorded one)
    return r


def literals_of(ctx, account_id):
    rows = ctx.db.cached(("literals", account_id), ("data_patterns",),      # 0.2.18: until data_patterns is written
                         lambda: ctx.db.q("SELECT class, literal FROM data_patterns WHERE account_id=?", (account_id,)))
    out = {}
    for r in rows:
        out.setdefault(r["class"], []).append(r["literal"])
    return out


def guard_hashes(ctx, account_id):
    """R3-06: sha256 of the protected literals and of the advisor mode. They are not part of the signed mandate bytes, so the hash taken when
    the signers signed is stored beside the mandate; a different value at action time means nobody signed it (-> deny)."""
    items = pattern_items(ctx, account_id)
    return (hashlib.sha256(b"dw-patterns\0" + json.dumps(items).encode()).hexdigest(), _advisor_hash(org.settings(ctx, account_id)["advisor"]))


ADVISOR_RANK = {"off": 0, "heuristic": 1, "ner": 2}


def _advisor_hash(mode):
    return hashlib.sha256(b"dw-advisor\0" + str(mode).encode()).hexdigest()


GATEWAY_V = "dw-gateway-0.2.4"
PROMISE_MMD = 3600          # draft-deus-aar-05 9.5: the witness declares it (<= 3600); the hourly anchor job (jobs.anchor_once) makes it achievable


def gateway_doc(ctx, account_id, toolmap):
    """0.2.4 (draft-deus-aar-05 8.6): the tool map DOCUMENT that the mandate signature binds. The tool map of the spec is "a CBOR map in CDE, its members are a matter
    of the gateway": here {v, tools: the agent tool map, patterns: sorted sha256 of the protected literals, advisor: mode}. `toolmap_sha256` of the signed mandate
    is SHA-256 over its CDE bytes, so the tool map, the protected literals (R3-06) and the advisor mode (R3-06) are inside the signature."""
    from app import vocab                           # r0269: the reason vocabulary (mr-vocab-1, JCS SHA-256) is pinned by the same signature
    return {"v": GATEWAY_V, "tools": toolmap, "patterns": pattern_items(ctx, account_id), "advisor": org.settings(ctx, account_id)["advisor"],
            "vocab": vocab.remember(ctx.db, now())}


def gateway_bytes(doc):
    return getattr(wa, "cde_raw", wa.cde)(doc)          # R4-03: never the test shim; the document has no wire-form member


def gateway_hash(doc):
    return hashlib.sha256(gateway_bytes(doc)).hexdigest()


def signed_gateway(m_row):
    """-> None for a mandate of 0.2.0-0.2.3 (the map hash is only in the row), else (doc or None, signed hash hex). doc is None when the stored document does
    not hash to the value inside the signed mandate (the row was changed behind the signature): the caller refuses with TOOLMAP_CHANGED."""
    try:
        h = json.loads(m_row["mandate_json"]).get(wire.KEY)
    except (TypeError, ValueError):
        return None
    if h is None:
        return None
    try:
        doc = json.loads(m_row["gateway_doc"]) if m_row["gateway_doc"] else None
        if doc is not None and gateway_hash(doc) != h:
            doc = None
    except (TypeError, ValueError):
        doc = None
    return doc, h


def _pattern_key(ctx, account_id):
    return hmac.new(ctx.cfg.key_pepper.encode(), b"dw-patterns-v2\0" + account_id.encode(), hashlib.sha256).digest()


def pattern_items(ctx, account_id):
    """0.2.5 (R4-02): sorted HMAC-SHA256(k_account, class + NUL + literal) of every protected literal, no plaintext. k_account is derived from the server's secret
    (DW_KEY_PEPPER) and the account id and never leaves the server: the document goes into the evidence pack, and a bare sha256 of a low-entropy literal
    (phone, card, name) would be brute-forced offline by whoever holds the pack. The server compares the sets; the pack checker needs no values."""
    k = _pattern_key(ctx, account_id)
    return sorted({hmac.new(k, ("%s\0%s" % (c, l)).encode(), hashlib.sha256).hexdigest() for c, ls in literals_of(ctx, account_id).items() for l in ls})


def _legacy_pattern_items(ctx, account_id):
    """0.2.2-0.2.4 form, bare sha256: read only to honour mandates signed before 0.2.5 (their stored items / signed documents hold it); never written."""
    return {hashlib.sha256(("%s\0%s" % (c, l)).encode()).hexdigest() for c, ls in literals_of(ctx, account_id).items() for l in ls}


def guard_weakened(ctx, account_id, m):
    """-> None | "DATA_PATTERNS_CHANGED" | "ADVISOR_CHANGED". A protected literal that was there at signing is gone, or the advisor is weaker.
    Adding literals or raising the advisor mode only denies more, so it needs no new signature."""
    if m["patterns_items"] is not None and not set(json.loads(m["patterns_items"])) <= set(pattern_items(ctx, account_id)) | _legacy_pattern_items(ctx, account_id):
        return "DATA_PATTERNS_CHANGED"
    if m["advisor_sha256"] is not None:
        signed = next((r for k, r in ADVISOR_RANK.items() if _advisor_hash(k) == m["advisor_sha256"]), None)
        if signed is None or ADVISOR_RANK.get(org.settings(ctx, account_id)["advisor"], 0) < signed:
            return "ADVISOR_CHANGED"
    return None


def guard_changed_count(ctx, account_id):
    """How many active mandates no longer match the protected data / advisor mode (they deny until signed again)."""
    return sum(1 for m in ctx.db.q("SELECT * FROM mandates WHERE account_id=? AND status='active'", (account_id,)) if guard_weakened(ctx, account_id, m))


def _explicit_data(m):
    """12.11 (r0263): the data classes the owner NAMED in the signed mandate (`forbidden_data`): they stay refused in any text."""
    try:
        fd = json.loads(m["mandate_json"]).get("forbidden_data") if m is not None and m["mandate_json"] else None
    except (TypeError, ValueError, KeyError, IndexError, AttributeError):
        return ()
    return tuple(x for x in fd if isinstance(x, str)) if isinstance(fd, list) else ()


def active_mandate(ctx, agent_id):
    return ctx.db.cached(("active_mandate", agent_id), ("mandates",),       # 0.2.18: until mandates is written
                         lambda: ctx.db.one("SELECT * FROM mandates WHERE agent_id=? AND status='active' ORDER BY created_at DESC, rowid DESC LIMIT 1", (agent_id,)))


def _check_amount(act):
    """F1: an integer outside int64 cannot be stored; refuse it BEFORE the ledger is written (nothing may enter the ledger without its row)."""
    a = act.get("amount") if isinstance(act, dict) else None
    if isinstance(a, int) and not isinstance(a, bool) and not -(2 ** 63) <= a <= 2 ** 63 - 1:
        raise Err(400, "BAD_AMOUNT", "amount outside the 64-bit range")


def _insert_after_authorize(ctx, row):
    """The ledger entry already exists, so the row MUST be stored. If the full row cannot be written, store it without the free-text/number columns."""
    try:
        _insert(ctx, row)
    except Exception:
        log("error", "action row not storable, stored reduced", rid=row["rid"])
        _insert(ctx, dict(row, args_preview="[unstorable]", text_preview=None, line_text=None, preview_cut=1, amount=None, currency=None, recipient="", action_json=json.dumps({"class": row["class"]})))


def _line_text(tool, args, lits):
    """04.11 (Hypothesis I2, "signed != shown"): every simple command of a shell line, whole and masked, for the approval page (the text
    preview stops at 4 KB: `echo "<4 KB>" ; cat ~/.ssh/id_rsa` showed only the echo). -> JSON {"cmds": [[text, foldable], ...], "cut": the
    text preview is cut} or None (not a shell line). Dropped with the text preview once the action is decided."""
    cmd = args.get("command") if isinstance(args, dict) else None
    if not tm.shell_tool(tool) or not isinstance(cmd, str):
        return None
    from app.hookjudge.bashparse import line_texts, MAX_CMD
    try:
        cmds = [[tm.mask_value(t, lits, MAX_CMD, True), bool(f)] for t, f in line_texts(cmd)]
    except (RecursionError, ValueError, TypeError, IndexError):
        cmds = [[tm.mask_value(cmd, lits, MAX_CMD, True), False]]
    return json.dumps({"cmds": cmds, "cut": len(cmd) > tm.TEXT_PREVIEW_CHARS}, ensure_ascii=False)


def _insert(ctx, row):
    ah = row.pop("_args_sha256", None)
    if row.get("status") not in WAITING and not row.get("preview_cut"):
        h = None
        try:
            h = json.loads(row["action_json"]).get("args_sha256") if row.get("action_json") else None
        except (TypeError, ValueError, AttributeError):
            pass
        row = dict(row, args_preview=tm.decided_preview(h or ah, row.get("args_preview")), text_preview=None, line_text=None, preview_cut=1)
    cols = ",".join(row)
    ctx.db.x("INSERT INTO actions(%s) VALUES(%s)" % (cols, ",".join("?" * len(row))), tuple(row.values()))
    stats.first(ctx, row.get("account_id"), "first_call")          # 0.2.28: the account's first call through the witness (any verdict)


def do_action(ctx, agent, tool, args, capable=True, via=None, quiet=False, created=None):
    """via (0.2.38): "hook" for a call judged by /v1/hook/judge (the Claude Code hook): kept on the row (actions.via) for the 04.11 count.
    04.11 (L3): quiet=True: a new question is stored but nobody is told yet (no push, no channel message); its rid is appended to `created`.
    The hook judge asks for ONE call's parts this way and announces ONE question for the whole call (hookjudge/judge.py, announce())."""
    return _decided(ctx, agent, _do_action(ctx, agent, tool, args, capable, via, quiet, created))


def announce(ctx, agent, rid):
    """04.11 (L3): the push and the channel messages of a question that was stored quietly (do_action quiet=True)."""
    x = refresh(ctx, rid)
    if x is None or x["status"] not in ("pending_approval", "held"):
        return
    row = dict(x)
    lits = literals_of(ctx, agent["account_id"])
    if getattr(ctx, "push", None) is not None:
        ctx.push.notify_defer(row, agent["name"], lits)
    if getattr(ctx, "notify", None) is not None:
        ctx.notify.approval(row)


def cancel_unasked(ctx, rid, reason):
    """04.11 (L3): a question stored quietly for a call that another part of the same line refuses: nobody was told, nobody is asked."""
    t = now()
    if ctx.db.n("UPDATE actions SET status='denied', verdict='deny', reason=?, updated_at=? WHERE rid=? AND status IN ('pending_approval','held')", (reason, t, rid)):
        cut_previews(ctx, rid)


def link_line(ctx, rid, lead):
    """04.11 (L3): `rid` is asked together with the question `lead` (the same tool call): the owner sees and decides ONE question."""
    ctx.db.x("UPDATE actions SET line_lead=? WHERE rid=? AND line_lead IS NULL AND rid<>?", (lead, rid, lead))


def hidden_sibling(ctx, y):
    """04.11 (L3): a question that is decided with its lead (not listed, not announced) while the lead still waits."""
    ll = y["line_lead"] if "line_lead" in y.keys() else None
    if not ll:
        return False
    if org.current_policy(ctx, y["account_id"]) is not None:
        return False             # 04.11 (red team p.5): a team policy came in while it waited: each part is its own question again (listed, decidable)
    z = ctx.db.one("SELECT status, expires FROM actions WHERE rid=?", (ll,))
    return z is not None and z["status"] == "pending_approval" and now() <= z["expires"]


def _used4(ctx, agent, t0):
    """-> (actions of the account, of the agent, hook rounds of the account, of the agent) in the last 24 h (rounds: written and buffered)."""
    acc, since = agent["account_id"], t0 - 86400
    r = ctx.db.one("SELECT (SELECT COUNT(*) FROM actions WHERE account_id=? AND created_at>?) AS acc, (SELECT COUNT(*) FROM hook_rounds WHERE account_id=? AND t>?) AS racc, "
                   "(SELECT COUNT(*) FROM actions WHERE agent_id=? AND created_at>?) AS ag, (SELECT COUNT(*) FROM hook_rounds WHERE agent_id=? AND t>?) AS rag",
                   (acc, since, acc, since, agent["id"], since, agent["id"], since), flush_rounds=False)     # the buffer is counted below
    b_acc, b_ag = ctx.db.rounds.count(acc, agent["id"], since)
    return r["acc"], r["ag"], r["racc"] + b_acc, r["rag"] + b_ag


def quota_used(ctx, agent, t0):
    """-> (actions of the account, of the agent) in the last 24 h, reads included (they are taken off only near a limit: passes_used).
    r0285: the hook's judge rounds without an action no longer count here (rounds_used, the reads' ceiling)."""
    a, g, _, _ = _used4(ctx, agent, t0)
    return a, g


def rounds_used(ctx, agent, t0):
    """r0285: -> (judge rounds without an action of the account, of the agent) in the last 24 h, written and buffered."""
    _, _, ra, rg = _used4(ctx, agent, t0)
    return ra, rg


def passes_used(ctx, account_id, t0, agent_id=None):
    """0.2.44 (K2): the rows of the last 24 h that were class `pass` (Read, Grep, Glob, LS...: nothing for a person to decide, no ledger entry).
    A trial account does not spend its daily quota on them. r0285: the hook's reads too (status consumed, class pass: before, only the
    MCP path's status `pass` was taken off, and the hook's Read / Grep / Glob spent the quota the pages said they do not)."""
    if agent_id is not None:       # 0.2.45: the same for one agent
        return ctx.db.one("SELECT COUNT(*) AS n FROM actions WHERE agent_id=? AND created_at>? AND (status='pass' OR class='pass')", (agent_id, t0 - 86400))["n"]
    return ctx.db.one("SELECT COUNT(*) AS n FROM actions WHERE account_id=? AND created_at>? AND (status='pass' OR class='pass')", (account_id, t0 - 86400))["n"]


def _free_at(ctx, t0, over, account_id, agent_id=None):
    """r0285: when the rolling 24-h count is below its limit again: the (over+1)-th oldest counted action of the window + 24 h."""
    col, val = ("agent_id", agent_id) if agent_id is not None else ("account_id", account_id)
    r = ctx.db.one("SELECT created_at FROM actions WHERE %s=? AND created_at>? AND status<>'pass' AND COALESCE(class,'')<>'pass' "
                   "ORDER BY created_at LIMIT 1 OFFSET ?" % col, (val, t0 - 86400, max(0, int(over))))
    return int(r["created_at"]) + 86400 if r else t0 + 86400


def _hhmm(t):
    return time.strftime("%H:%M UTC", time.gmtime(t))


def check_quota(ctx, agent, t0=None):
    """The daily quotas (account, agent). 0.2.17 (R9-04): the hook's judge rounds that end without an action (`need`, `refuse`, table
    hook_rounds) are bounded too, and (R9-02) the judge checks them BEFORE it classifies anything. Raises 429 QUOTA.
    0.2.18: atomic with the use that follows only under hub.lock(account) (do_action, hookjudge._round): every use of the quota is there.
    r0285: actions that are not reads count (QUOTA_PER_DAY, QUOTA_PER_AGENT_DAY); reads and rounds share the reads' ceiling (cfg.pass_per_*);
    the refusal says when the limit frees up. -> None, or {"used", "limit", "of": "account"|"agent"} from QUOTA_WARN of a limit on."""
    t0 = now() if t0 is None else t0
    used, mine, r_acc, r_ag = _used4(ctx, agent, t0)
    raw_acc, raw_ag = used, mine
    quota = QUOTA_PER_DAY if ctx.cfg.quota_per_day is None else ctx.cfg.quota_per_day
    acc = agent["account_id"]
    n_acc = n_ag = None                     # allowed reads (class pass) in 24 h, counted only near a limit
    trial_q = trial.info(ctx, acc) is not None
    if trial_q:
        quota = min(quota, int(getattr(ctx.cfg, "trial_quota", 2000)))        # 0.2.38: a trial account has its own quota until kept
    if used >= quota * QUOTA_WARN:
        n_acc = passes_used(ctx, acc, t0)
        used -= n_acc                                                         # 0.2.44 (K2): allowed reads (class pass) do not spend it
    if used >= quota:
        free = _hhmm(_free_at(ctx, t0, used - quota, acc))
        if trial_q:
            refusals.note(ctx, "TRIAL_QUOTA", acc, agent["id"])
            raise Err(429, "QUOTA", "The quick start limit of %d actions a day is used up (reads such as Read, Grep and Glob do not count). It counts the "
                      "last 24 hours: the next action is possible at %s; to keep working now, sign up (free during the beta): %s/signup.html" % (quota, free, ctx.cfg.origin))
        refusals.note(ctx, "ACCOUNT_QUOTA", acc, agent["id"])
        raise Err(429, "QUOTA", "The daily limit of %d actions of this account is used up (reads such as Read, Grep and Glob do not count). It counts "
                  "the last 24 hours: the next action is possible at %s." % (quota, free))
    if mine >= QUOTA_PER_AGENT_DAY * QUOTA_WARN:     # 0.2.45: and the limit of one agent
        n_ag = passes_used(ctx, acc, t0, agent["id"])
        mine -= n_ag
    if mine >= QUOTA_PER_AGENT_DAY:
        refusals.note(ctx, "AGENT_QUOTA", acc, agent["id"])
        raise Err(429, "QUOTA", "The daily limit for one agent (%d actions) is used up (reads such as Read, Grep and Glob do not count). It counts the "
                  "last 24 hours: the next action of this agent is possible at %s; another agent of the account can go on." % (
                      QUOTA_PER_AGENT_DAY, _hhmm(_free_at(ctx, t0, mine - QUOTA_PER_AGENT_DAY, acc, agent["id"]))))
    # 0.2.45: reads are free of the action quotas but not unlimited: their own ceiling, shared with the hook's rounds (r0285)
    cap_ag, cap_acc = int(ctx.cfg.pass_per_agent_day), int(ctx.cfg.pass_per_account_day)
    if raw_ag + r_ag >= cap_ag and (n_ag if n_ag is not None else passes_used(ctx, acc, t0, agent["id"])) + r_ag >= cap_ag:
        refusals.note(ctx, "READS_CAP", acc, agent["id"])
        raise Err(429, "QUOTA", "%d reads and file checks per day for one agent (it counts the last 24 hours)" % cap_ag)
    if raw_acc + r_acc >= cap_acc and (n_acc if n_acc is not None else passes_used(ctx, acc, t0)) + r_acc >= cap_acc:
        refusals.note(ctx, "READS_CAP", acc, agent["id"])
        raise Err(429, "QUOTA", "%d reads and file checks per day per account (it counts the last 24 hours)" % cap_acc)
    near = [(used / quota if quota else 0, used, quota, "account")]
    if n_ag is not None:
        near.append((mine / QUOTA_PER_AGENT_DAY, mine, QUOTA_PER_AGENT_DAY, "agent"))
    share, u, lim, of = max(near)            # below QUOTA_WARN of raw rows nothing was taken off: the share is below it too
    return {"used": int(u), "limit": int(lim), "of": of} if share >= QUOTA_WARN else None


def _do_action(ctx, agent, tool, args, capable=True, via=None, quiet=False, created=None):
    acc = agent["account_id"]
    t0 = now()
    with ctx.hub.lock(acc):
        check_quota(ctx, agent, t0)
        toolmap = json.loads(agent["toolmap_json"])
        lits = literals_of(ctx, acc)
        m = active_mandate(ctx, agent["id"])
        # R-03: the tool map that decides whether the signed mandate applies is bound to the mandate (hash stored when the passkey signed it).
        th = tm.toolmap_hash(toolmap)
        bound = m is not None and m["toolmap_sha256"] == th
        sg = signed_gateway(m) if m is not None else None       # 0.2.4: the hash is inside the signed mandate (draft-deus-aar-05 8.6)
        if sg is not None:
            bound = sg[0] is not None and sg[0]["tools"] == toolmap       # the document checked against the signature; the live map against the document
        salt = erase.salt_for(ctx, acc, capable)         # 0.2.34/35: None unless DW_ARGS_SALT=on (or transition and a capable client)
        row = {"rid": new_rid(), "account_id": acc, "agent_id": agent["id"], "mandate_id": None, "tool": tool[:200],
               "args_preview": tm.mask_args(args, lits, shell=tm.shell_tool(tool)), "text_preview": tm.text_preview(toolmap, tool, args, lits),
               "action_json": None, "request_hash": None, "verdict": None, "reason": None,
               "status": None, "amount": None, "currency": None, "expires": t0 + TTL, "created_at": t0, "updated_at": t0,
               "class": "", "recipient": None, "aar": None, "proof_json": None, "_args_sha256": tm.args_hash(tool, args, salt)}
        if via == "hook":
            row["via"] = "hook"

        def refuse(reason):
            row.update(verdict="deny", reason=reason, status="denied")
            _insert(ctx, row)
            return to_result(ctx, refresh(ctx, row["rid"]))
        auto_fz = False
        if "frozen_at" in agent.keys() and agent["frozen_at"]:
            if frozen_kind(ctx, agent["id"]) != "auto":
                return refuse("AGENT_FROZEN")           # 0.2.24 (critique T2): the owner froze this agent; nothing runs until unfrozen
            # 0.2.89 (QA 03.11, D5): an AUTOMATIC freeze (a flood of unanswered questions) stops the questions, not the work: what the
            # signed mandate allows by itself (ls, Read, a listed command) still runs; every call that would ask is refused AGENT_FROZEN
            # (no new question, no notification) until the owner unfreezes it. The owner's own Freeze still stops everything.
            auto_fz = True
        if m is not None and not bound:
            return refuse("TOOLMAP_CHANGED")            # a changed map needs a new passkey-signed mandate
        if m is not None and sg is not None:
            mg = dict(m, patterns_items=json.dumps(sg[0]["patterns"]), advisor_sha256=_advisor_hash(sg[0]["advisor"]))     # from the signed document
            why = guard_weakened(ctx, acc, mg)
            if why:
                return refuse(why)
        elif m is not None:
            if m["patterns_items"] is None or m["advisor_sha256"] is None:      # a mandate signed before 0.2.2: adopt today's state once
                gp, ga = guard_hashes(ctx, acc)
                ctx.db.x("UPDATE mandates SET patterns_sha256=?, patterns_items=COALESCE(patterns_items,?), advisor_sha256=COALESCE(advisor_sha256,?) WHERE id=?",
                         (gp, json.dumps(pattern_items(ctx, acc)), ga, m["id"]))
                m = active_mandate(ctx, agent["id"])
            why = guard_weakened(ctx, acc, m)
            if why:
                return refuse(why)      # fewer protected literals / weaker advisor than the signers saw: only a new signed mandate can accept that
        if toolmap["default"] == "pass" and not bound:
            toolmap = dict(toolmap, default="deny")     # default:pass is honoured only for a signed map
        act = tm.build_action(agent["id"], toolmap, tool, args, lits, pass_receipt=sg is not None, salt=salt)
        if isinstance(act, dict) and act.get("data"):
            # 12.11 (r0263, L3 Б1): a personal-data format in text that stays on this computer (a commit trailer, a file of the project)
            # is no leak; the data rule keeps acting on what can leave (hookjudge/datarule)
            act = _datarule.local_text(act, tool, args, _explicit_data(m))
            # 0.2.95 (Н3): a service's no-reply address (the co-author trailer) or the person's own git address is no personal data
            act = _datarule.benign_addresses(act, tool, args, _explicit_data(m))
        if act is None:
            row.update(verdict="pass", reason="PASS", status="pass", **{"class": "pass"})
            _insert(ctx, row)
            return to_result(ctx, refresh(ctx, row["rid"]))
        if act == tm.UNMAPPED:
            return refuse("TOOL_UNMAPPED")
        tn = taint_of(tool, act, args)
        if tn is not None:
            row["taint"] = tn
        # r0275 (STAC): a call that reads a file the agent made from a credential (app/provenance.py): judged as that credential below
        hit_ = provenance.copy_read(ctx, acc, tool, args, t0)
        if hit_ is not None and hit_[2] and row.get("taint") is None:
            row["taint"] = TAINT_SEEN_IF_ALLOWED      # the agent sees the credential's text: "secret seen" once it runs (0.2.24)
        fx_ = provenance.effect_keys(tool, act, args) + (["sec:" + hit_[1]] if hit_ is not None and hit_[2] else [])
        if fx_:
            row["fx_keys"] = json.dumps(fx_, ensure_ascii=False)       # r0275: what the call does, kept to recognise it under another tool
        if tm.unmapped_args(toolmap, tool, args):
            return refuse("TOOL_ARGS_UNMAPPED")         # R-02: an argument that may carry a recipient but is not mapped
        if act.get("class") == "delete" and "recipient" in act:
            act["recipient"] = extract_dir_recipient(tool, args, act["recipient"])     # N4 29.10: `tar xf s.tar` in the project
        if sg is not None:
            act["toolmap_sha256"] = bytes.fromhex(sg[1])       # A.toolmap_sha256 (draft-deus-aar-05 8.6): covered by the request hash, compared by the witness (step 4a)
        L = ctx.hub.ledger(acc) if m is not None else None
        # 0.2.57 (L2 OTCHET-V3-L2 finding 4): a ledger object freshly opened by the hub (first call after the process starts, or after the
        # hub's cache dropped it) holds an EMPTY state until a transaction catches it up with the file. The project allowances (0.2.10), the
        # V3 sandbox cover and the per-recipient checks below asked the core with that empty state: NO_MANDATE -> no allowance, a needless
        # question, and for a call with several recipients (to + cc) a cold NO_MANDATE on an extra recipient replaced the action, so the core
        # never judged the first recipient. One catch-up here, the same timestamp for every dry decision of this call.
        tnow = L.sync_now() if L is not None else None
        # 0.2.13 (PROPOSAL-08): a command line that will execute a file changed since the owner confirmed it carries `exec_changed` (the core asks,
        # whatever the list or an allowance say); a write to such a file is remembered (marked dirty once the write is allowed)
        if act["class"] == "command":
            changed, ex_json = execguard.check(ctx, agent["id"], tool, args)
            if changed:
                act["exec_changed"] = changed
        else:
            ex_json = execguard.written(tool, args)
            gt_ = tool == "Bash.write" and isinstance(args.get("command"), str) and "git" in args["command"] and \
                git_tainted(ctx, agent["id"], t0)      # RT-0270: the agent changed git's objects / index / refs / remotes before
            wri_ = {}
            wr = execguard.written_run(tool, args, git_taint=gt_, info=wri_)      # 28.10 (adaptive red team №1): a write a later run must not take unseen
            src = None
            if tool == "Bash.write" and isinstance(args.get("command"), str):
                wr, src = carry_written_marks(ctx, agent["id"], args, wr, t0)
            if wr:
                ej_ = json.loads(ex_json) if ex_json else {}
                by = "shell" if tool == "Bash.write" else tool
                wt = (src or {}).get("text") if src else (args.get("command") if tool == "Bash.write" else None)
                if not isinstance(wt, str) and len(wr) == 1:
                    wt = execguard._written_text(tool, args, next(iter(wr)))
                # what the agent put there, masked (<= 4 KB): the page of the run shows it; dropped once a run of it is let go (cut_previews; r25: kept after a Reject, at most the look-back).
                # 29.10 (hang): masked ONCE per write, kept on the first WRUN_TEXT_PATHS paths only (the page shows 16 files)
                txt = tm.mask_value(wt, lits, tm.TEXT_PREVIEW_CHARS, tool == "Bash.write" and not src) if isinstance(wt, str) else None
                ej_["wrun"] = {}
                # 04.11 (D8 under the strict sandbox): the gate the written text reaches stays on the mark; a partial write (Edit, an
                # append, a copy of a marked file) keeps the gate of the mark it builds on -- only a whole-file Write replaces the text
                g_old = {} if tool in ("Write", "Write.danger") else written_run_info(
                    ctx, agent["id"], t0 - 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN))
                g_src = (src or {}).get("g") if isinstance(src, dict) else None
                sf_map = script_findings_of_write(tool, args, wr)      # r0262: what the text would do when a later call runs it
                for i_, p_ in enumerate(sorted(wr)):
                    # RT-0270 p.3: a text NOT in the call (tar / patch / git / a copy from outside): "seen" by its arguments would take a new
                    # archive under the same name as shown; the key is then the state of its inputs the hook reported, or none (only this write)
                    k_ = write_state_key(tool, args, p_) if wri_.get("unseen") and not src else write_key(tool, args, p_)
                    v_ = {"by": by}
                    if k_ is not None:
                        v_["k"] = k_
                    if txt is not None and i_ < WRUN_TEXT_PATHS:
                        v_["text"] = txt
                    if isinstance(wr[p_], dict) and wr[p_].get("dir"):
                        v_["dir"] = True
                    g_ = wri_.get("gate") or g_src or (g_old.get(p_) or {}).get("g")
                    if g_:
                        v_["g"] = g_
                    # r0262: the findings of the text (strict_policy.script_findings): a whole-file Write replaces them, a partial write
                    # (Edit, a shell append) adds to those of the mark it builds on, a copy carries the source's
                    sf_ = sf_map.get(p_) if p_ in sf_map else ((src or {}).get("sf") if isinstance(src, dict) else None)
                    if tool not in ("Write", "Write.danger"):
                        old_sf = (g_old.get(p_) or {}).get("sf") if isinstance(g_old.get(p_), dict) else None
                        if isinstance(old_sf, list):
                            sf_ = old_sf + [f for f in (sf_ or []) if f not in old_sf]
                    if sf_:
                        v_["sf"] = sf_[:48]               # r0263: tagged findings of a package.json / Makefile (per script / target)
                    if p_ in sf_map or sf_:
                        v_["sfc"] = True                  # judged when written (an empty list: nothing of the list in it)
                    ej_["wrun"][p_] = v_
                ex_json = json.dumps(ej_, ensure_ascii=False)
            if tool in ("Write", "Write.danger", "Edit", "MultiEdit", "NotebookEdit"):
                # RT-0269 p.3a: a write whose text the witness SEES and that is not risky replaces what was kept for the file: after a Reject the
                # next run's page must not show the old (risky) text. A whole-file Write that is harmless takes the mark off (like a clean first
                # write); a partial edit cannot (the rest of the file is unknown): the mark stays, the old text goes. A write with no text
                # (Bash.write) never gets here: it keeps the mark.
                w_ = args.get("_witness") if isinstance(args, dict) else None
                ps_ = ([w_["path"]] if isinstance(w_, dict) and isinstance(w_.get("path"), str) else [])
                ps_ = [p_ for p_ in ps_ if p_ not in (wr or {}) and isinstance(execguard._written_text(tool, args, p_), str)]
                if ps_:
                    old_ = written_run_info(ctx, agent["id"], t0 - 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN))
                    cl_ = {p_: ({"by": tool, "clear": True} if tool in ("Write", "Write.danger") else {"by": tool})
                           for p_ in ps_ if p_ in old_}
                    if cl_:
                        ej_ = json.loads(ex_json) if ex_json else {}
                        ej_["wrun"] = dict(ej_.get("wrun") or {}, **cl_)
                        ex_json = json.dumps(ej_, ensure_ascii=False)
        # r0263 (П3 rest): the findings of a written text that is no run mark (wrun): a package.json whose `release` script publishes, a
        # Makefile target that pushes, a .js that hands `npm publish` to execSync -- kept on the row as "wsf" (findings only, never the
        # text); a later strict line that runs the file (`npm run release`, `make release`, `node x.js`) carries them (script_runs).
        try:
            wsf_ = written_sf_of_write(ctx, agent["id"], tool, args, wr, t0)
        except Exception:      # noqa: BLE001  no findings kept: the run is judged as before
            wsf_ = None
        if wsf_:
            ej_ = json.loads(ex_json) if ex_json else {}
            if isinstance(ej_, dict):
                ej_["wsf"] = wsf_
                ex_json = json.dumps(ej_, ensure_ascii=False)
        if act["class"] == "delete" and no_content_write(tool, args, git_taint=bool(tool == "Bash.write" and git_tainted(ctx, agent["id"], t0))):
            ej_ = json.loads(ex_json) if ex_json else {}
            if isinstance(ej_, dict):
                ej_["nc"] = True       # N15 lever 2: puts no text of the agent into a file (secret_hold_files skips it)
                ex_json = json.dumps(ej_, ensure_ascii=False)
        if _line_gtamper(tool, args) or stores_unseen_risky(ctx, agent["id"], tool, args, t0):    # RT-0271 0.2.72: stash / add / commit
            ej_ = json.loads(ex_json) if ex_json else {}
            if isinstance(ej_, dict):
                ej_["gt"] = True       # RT-0270: this line changes git's objects / index / refs / remotes (git_tainted reads it)
                ex_json = json.dumps(ej_, ensure_ascii=False)
        try:
            nf_ = provenance.fetch_marks(ctx, agent["id"], tool, args, t0)
        except Exception:      # noqa: BLE001  no mark: the run's words stay the general ones
            nf_ = None
        if nf_:
            ej_ = json.loads(ex_json) if ex_json else {}
            if isinstance(ej_, dict):
                ej_["nf"] = nf_            # r0294: these paths now hold code from the network: {path: host} (provenance.fetches)
                ex_json = json.dumps(ej_, ensure_ascii=False)
        sec_ = provenance.carry(tool, args, hit_)
        if sec_:
            ej_ = json.loads(ex_json) if ex_json else {}
            if isinstance(ej_, dict):
                ej_["sec"] = dict(list(sec_.items())[:64])    # r0275: these paths now hold a credential's text (provenance.copies)
                ex_json = json.dumps(ej_, ensure_ascii=False)
        xf_ = _dirfiles(tool, act, args)
        if xf_ is not None:
            ej_ = json.loads(ex_json) if ex_json else {}
            if isinstance(ej_, dict):
                ej_["xf"] = xf_        # N6 0.2.71: the files this whole-directory restore really writes (git's object hashes)
                ex_json = json.dumps(ej_, ensure_ascii=False)
        if _line_hash(tool, args):
            ej_ = json.loads(ex_json) if ex_json else {}
            if isinstance(ej_, dict):
                # RT-0269 p.2: the write of THIS line is not "a change after the question"; N7 0.2.71: every part of a shell line
                # (the command too) carries it, so a write whose line never ran (its question expired / was refused) is known
                ej_["line"] = _line_hash(tool, args)
                ld_ = _line_docs(args) if act["class"] == "command" else None
                if ld_:
                    ej_["ldocs"] = ld_     # 0.2.77b (R2-7): documents the line names (the text preview is dropped after the decision)
                if _moves_head(args):
                    ej_["hm"] = True   # N6 0.2.71: may move HEAD: a later `git stash pop` is not judged by git's file list
                ex_json = json.dumps(ej_, ensure_ascii=False)
        if ex_json:
            row["exec_json"] = ex_json
        w_ = args.get("_witness") if isinstance(args, dict) else None
        if act["class"] == "command" and isinstance(w_, dict) and w_.get("net"):
            row["level_min"] = levels.PHONE         # 0.2.13: a command line that also talks to the network is confirmed on the phone
        # 0.2.10 (PROPOSAL-07): the hook's project of a command line; an owner-signed allowance may cover an unlisted command of it
        meta = al.project_meta(args) if act["class"] == "command" else None
        if meta is not None:
            so_ = w_.get("sbx_open") if isinstance(w_, dict) else None
            so_ = [h[:253] for h in so_ if isinstance(h, str)][:16] if isinstance(so_, list) else []
            # 10.11 (r0260): the write hosts that took the strict fact away from this line (hookjudge/sandbox.write_open): the words of
            # the question say why (qwords); never read by a decision
            sc_ = {"sbx_closed": True} if so_ and isinstance(w_, dict) and w_.get("sbx_closed") is True else {}
            # 11.11 (r0260): the credential sources were closed (hookjudge/sandbox.cred_closed): the words do not claim the keychain is open
            row["cmd_meta"] = json.dumps(dict(meta, sbx_open=so_, **sc_) if so_ else meta, ensure_ascii=False)
        if act["class"] == "command" and isinstance(w_, dict) and isinstance(w_.get("commands"), list):
            # 0.2.56 (RT-0.2.55c): every command of the line, kept ALWAYS (cmd_meta only when the hook knows the project): the approval page
            # lists them, so a second command hidden after the 4 KB text preview (`pytest<5000 spaces>; python3 x.py`) is shown to the owner
            row["line_heads"] = json.dumps([h[:256] for h in w_["commands"] if isinstance(h, str)][:64], ensure_ascii=False)
        dk_ = deny_key(args) if tool.startswith("Bash") else None
        if dk_:
            row["deny_key"] = dk_                    # 05.11 (RT hole 1)
        lt_ = _line_text(tool, args, lits)
        if lt_ is not None:
            row["line_text"] = lt_
        if meta is not None and (m is None or al.team(ctx, acc)):
            meta = None                                         # no mandate / a team account: allowances do not apply
        if m is not None and L is not None and not al.team(ctx, acc):
            al.reset_stale(ctx, acc, agent["id"], L, al.project_meta(args), tnow)   # 0.2.96: "from now on" ends on another git branch
        base, used = act, []
        # 06.11 (r0260): the owner's amendments ("from now on" for a KIND of act: a host + method, a folder outside the project, the agent's
        # memory, `gh <sub>` reads) apply to every part of a shell line and to a write outside the project (app/amend.py)
        ameta = al.project_meta(args) if m is not None and isinstance(tool, str) and tool.split(".")[0] in ("Bash", "Write", "Edit", "MultiEdit") \
            and not al.team(ctx, acc) else None
        if meta is not None:
            act = al.cover(L, m["id"], act, meta, tnow)
            used += [act["allowance"]] if "allowance" in act else []
            act = al.sandbox_cover(L, m["id"], act, meta, w_, tnow, args.get("command") if isinstance(args, dict) else None)      # V3 / 0.2.82
            act = al.held_mark_cover(L, m["id"], act, tool, args, w_, tnow)      # 10.11 (r0260): a mark the strict sandbox holds itself
        elif m is not None and not al.team(ctx, acc) and isinstance(tool, str) and tool.startswith("Bash") and isinstance(w_, dict) \
                and w_.get("home_tmp") is not None:
            act = al.home_tmp_cover(L, m["id"], act, w_, tnow, args.get("command") if isinstance(args, dict) else None)   # 11.11 (б)
        if m is not None and tool == "Bash.net":
            act = al.exit_ask(L, m["id"], act, tool, tnow)        # 0.2.91: a host of a shell line outside the domains is asked, not refused
            act = al.code_net_cover(L, m["id"], act, tool, args, w_, tnow)     # 10.11 (r0260, Р-1011 А): a host only code names, sandboxed
        if ameta is not None:
            act = amend.cover(L, m["id"], act, tool, args, ameta, tnow)
            used += [act["allowance"]] if "allowance" in act and act["allowance"] not in used else []
        # 11.11 (r0261, поворот: ЗАКРЫТЫЙ СПИСОК): under a fresh strict fact (and the code option) a Bash line is decided by ONE table,
        # hookjudge/strict_policy.py: an immutable article -> refused (below, constitution), a reason of the list -> asked (the line's
        # command part), anything else -> every part the core would ask about runs as sandboxed (OK_SANDBOXED). Outside the fact: unchanged.
        if m is not None and L is not None:
            # r0296: a quiet outside write after the owner's No / not a data file under the profile -> asked (before the strict step:
            # under a strict fact the line is then held by the sandbox, as without the profile)
            act = refused_outside_write(ctx, agent["id"], L, m["id"], act, tnow, t0, tool, args, ameta)
            used += [act["allowance"]] if "allowance" in act and act["allowance"] not in used else []
            act = unlisted_allow_gate(L, m["id"], act, tool, args, tnow)     # r0305
        sv_ = None
        if m is not None and L is not None and isinstance(tool, str) and tool.startswith("Bash") and not al.team(ctx, acc) \
                and al.in_strict_sandbox(L, m["id"], al.project_meta(args), w_):
            sv_ = strict_policy.verdict(tool, args)
            if sv_.refuse is None:                    # r0262: a file the agent wrote, run by this later line: its text's findings
                sv_ = strict_policy.with_scripts(sv_, script_runs(ctx, agent["id"], args, t0))
            act, sv_ = strict_policy.soften_data(L, m["id"], act, tool, args, sv_, tnow)    # r0261b: the data rule on what LEAVES
            act = strict_policy.cover(L, m["id"], act, tool, args, sv_, tnow, al.project_meta(args))
            used += [act["allowance"]] if "allowance" in act and act["allowance"] not in used else []
        if m is not None and L is not None and tool in strict_policy.FILE_TOOLS and not al.team(ctx, acc) and al.code_option(L, m["id"]):
            # r0261b: Write / Edit under the code option: a file another program runs later outside the sandbox (С3) is asked, as a
            # shell write of it is; the narrow "from now on" is this path in this project
            act = strict_policy.write_cover(L, m["id"], act, tool, args, tnow, (ameta or {}).get("project"))
            used += [act["allowance"]] if "allowance" in act and act["allowance"] not in used else []
        if m is not None and L is not None and tool in strict_policy.FILE_TOOLS and not al.team(ctx, acc):
            act = later_run_write(L, m["id"], act, tool, args, tnow)     # r0305 (W5): .envrc, .husky, CI ... outside the strict session
        if m is not None and L is not None and tool in strict_policy.FILE_TOOLS:
            # r0261f (0.2.59): a file in the shared temp the mandate does not name is asked once, not refused RESOURCE with no button
            act = strict_policy.temp_write_ask(L, m["id"], act, tool, args, tnow)
        asked_ = [act] if m is not None and ameta is not None and L.S.decide_for(m["id"], act, tnow)[1] == "defer" else []
        # R-02: every further recipient (cc, bcc, list members) must be allowed on its own; the first refusal decides.
        tmap = toolmap["tools"].get(tool, {})
        for extra in ([] if m is None else tm.recipient_values(tmap, args)[1:]):
            ea = dict(base, recipient=extract_dir_recipient(tool, args, extra))
            if ea["class"] == "delete":
                ea["reversible"] = tm.reversible_of(tmap, extra)      # N-01: each target has its own reversibility
            if meta is not None:
                ea = al.cover(L, m["id"], ea, meta, tnow)
                ea = al.sandbox_cover(L, m["id"], ea, meta, w_, tnow, args.get("command") if isinstance(args, dict) else None)
                ea = al.held_mark_cover(L, m["id"], ea, tool, args, w_, tnow)
            elif m is not None and not al.team(ctx, acc) and isinstance(tool, str) and tool.startswith("Bash") and isinstance(w_, dict) \
                    and w_.get("home_tmp") is not None:
                ea = al.home_tmp_cover(L, m["id"], ea, w_, tnow, args.get("command") if isinstance(args, dict) else None)   # 11.11 (б)
            if m is not None and tool == "Bash.net":
                ea = al.exit_ask(L, m["id"], ea, tool, tnow)
                ea = al.code_net_cover(L, m["id"], ea, tool, args, w_, tnow)
            if ameta is not None:
                ea = amend.cover(L, m["id"], ea, tool, args, ameta, tnow)
            ea = refused_outside_write(ctx, agent["id"], L, m["id"], ea, tnow, t0, tool, args, ameta)   # r0296 (before the strict step)
            ea = unlisted_allow_gate(L, m["id"], ea, tool, args, tnow)                                # r0305
            if sv_ is not None:
                ea = strict_policy.soften_data(L, m["id"], ea, tool, args, sv_, tnow)[0]
                ea = strict_policy.cover(L, m["id"], ea, tool, args, sv_, tnow, al.project_meta(args))
            _, ev, ewhy = L.S.decide_for(m["id"], ea, tnow)
            if ev == "defer" and ameta is not None:
                asked_.append(ea)
            if ev == "allow" and "allowance" in ea:
                used.append(ea["allowance"])
                if "allowance" not in act and L.S.decide_for(m["id"], act, tnow)[1] == "allow":
                    act = ea                              # 0.2.10: `cd x && pytest`: the receipt records the command the allowance let through
            elif ev == "allow" and ea.get("sandboxed") is True and "allowance" not in act and "sandboxed" not in act \
                    and L.S.decide_for(m["id"], act, tnow)[1] == "allow":
                act = ea                                  # V3: `ls && pytest`: the receipt records the runner the sandbox let through
            if ev != "allow":
                if ev == "deny":
                    act = ea                              # the refusal is judged and recorded by the core for THAT address
                    break
                if ev == "defer" and L.S.decide_for(m["id"], act, tnow)[1] == "defer":
                    continue                              # 0.1.3: the first target already needs the owner (e.g. move_file with no delete permission): the owner judges the whole call
                if ev == "defer" and act["class"] == "command":
                    act = ea                              # PROPOSAL-06: `ls && make` with only `ls` listed: the owner is asked about the line, under the unlisted command
                    continue                              # (a later command of the line that is denied still decides)
                return refuse("RECIPIENT")
        if asked_:
            ids_, why_ = amend.plan(tool, args, asked_, amend.home_of(args, ameta))
            cm_ = json.loads(row["cmd_meta"]) if row.get("cmd_meta") else dict(ameta, heads=[], outside=[])    # (a Bash.net row: not a command row)
            cm_.update({"amend": ids_} if ids_ else {"amend_why": why_})
            row["cmd_meta"] = json.dumps(cm_, ensure_ascii=False)
        _check_amount(act)
        rh = request_hash(act)
        # 0.1.1 (item 7), widened by N-11: the owner REFUSED an action with this (tool, class, recipient) under the active mandate -> for an hour
        # any variant (changed text, one more space) is denied, no new approval request (approval fatigue)
        if m is not None and refused_like(ctx, agent["id"], m["id"], tool, act["class"], act.get("recipient"), t0, rh=rh, dk=row.get("deny_key")) is not None:
            row.update(action_json=json.dumps(wire.wire_form(act), ensure_ascii=False), request_hash=rh, **{"class": act["class"]},
                       recipient=(act.get("recipient") or "")[:300], mandate_id=m["id"])
            return refuse("REFUSED")
        for x in ctx.db.q("SELECT rid FROM actions WHERE agent_id=? AND request_hash=? AND status IN ('pending_approval','approved','held') ORDER BY created_at DESC",
                          (agent["id"], rh)):
            y = refresh(ctx, x["rid"])
            if y["status"] in WAITING:
                if y["status"] == "approved" and page_files_changed(ctx, y):
                    mark_file_changed(ctx, y["rid"], page_files_changed(ctx, y))     # N1: not a showing of what runs now
                    continue                      # RT-0269 p.2 (2d): a file the page showed was written since: the approval is for the old text
                lw_ = late_project_write(ctx, y) if y["status"] == "approved" and y["gave_up_at"] else None
                if lw_ is not None:
                    log("INFO", "late approval not reused: the project was written since the question", rid=y["rid"], account=y["account_id"])
                    mark_file_changed(ctx, y["rid"], lw_, by="late_write")
                    try:                          # 0.2.77b (R2-7): the new question says why it is asked again (approve.js asked_again)
                        ej_ = json.loads(row.get("exec_json") or "{}")
                        if isinstance(ej_, dict) and "asked_again" not in ej_:
                            ej_["asked_again"] = {"rid": y["rid"], "file": lw_[:1024], "approved_at": y["updated_at"]}
                            row["exec_json"] = json.dumps(ej_, ensure_ascii=False)
                    except (TypeError, ValueError):
                        pass
                    continue                      # 0.2.77 (H2): approved after the hook gave up, then a write in the project: asked again
                if y["gave_up_at"]:
                    clear_gave_up(ctx, y["rid"])  # N2 29.10 (R1a2): the same call sent again: its hook waits for it again (the page must not
                    y = refresh(ctx, y["rid"])    # say "no longer waiting"; the long poll clears it too, but the page may be read before)
                return to_result(ctx, y)          # a repeat returns THAT action, not a new one
        if m is not None:
            y = late_release_reuse(ctx, agent, m, tool, act, t0)
            if y is not None:
                return to_result(ctx, y)          # late 29.10: released after the hook gave up: the repeat gets that row (one touch)
        amount = act.get("amount") if isinstance(act.get("amount"), int) and not isinstance(act.get("amount"), bool) else None
        row.update(action_json=json.dumps(wire.wire_form(act), ensure_ascii=False), request_hash=rh, **{"class": act["class"]},
                   recipient=(act.get("recipient") or "")[:300], amount=amount, currency=act.get("currency"))
        if act["class"] == "delete":
            # 0.2.30 (B1): EVERY path this write changes (a Bash line may write several; `recipient` holds only the first): an approval for
            # later runs of a command ends when the agent writes a file that command runs (app/repeat.py files_written)
            wp = sorted({v for v in tm.recipient_values(tmap, args) if isinstance(v, str) and v.startswith("/") and len(v) <= 1024})[:64]
            if wp:
                row["write_paths"] = json.dumps(wp, ensure_ascii=False)
        if m is None and trial.info(ctx, acc) is not None:
            # 0.2.38: a trial account before its first touch: no mandate, no journal. The call waits for the person (it is NOT allowed and
            # can never be approved as it is: approve/release refuse a row without a mandate); signing the drafted mandate covers it and the
            # hook sends it again, judged under the mandate.
            if ctx.db.one("SELECT COUNT(*) AS n FROM actions WHERE agent_id=? AND reason=? AND status='pending_approval' AND expires>?",
                          (agent["id"], trial.REASON, t0))["n"] >= trial.PENDING_MAX:
                return refuse("APPROVAL_RATE")
            row.update(verdict="defer", reason=trial.REASON, status="pending_approval", expires=t0 + _ttl(ctx, acc, "defer"))
            _insert(ctx, row)
            return to_result(ctx, refresh(ctx, row["rid"]))
        if m is None:
            row.update(verdict="deny", reason="NO_MANDATE", status="denied")
            _insert(ctx, row)
            return to_result(ctx, refresh(ctx, row["rid"]))
        L = ctx.hub.ledger(acc)
        row.update(mandate_id=m["id"])
        # 0.2 (3.4, 8): dry decision of the core, then the gateway hooks; they may only turn it into deny (not written to the ledger) or hold
        _, dv, dwhy = L.S.decide_for(m["id"], act, L.sync_now())
        # 0.2.29: the owner approved THIS exact call for later runs (app/repeat.py): no question, so the rate of questions does not apply;
        # what holds an allowed call (a secret seen, egress) holds this one too, and then the owner is asked as usual
        rp = None
        if dv == "defer" and dwhy not in rpt.NOT_OFFERED and not al.team(ctx, acc):
            rp = rpt.find(ctx, agent["id"], m["id"], rh, dwhy, t0)
            if rp is not None and (hold_after_secret(ctx, agent["id"], tool, act, args, t0) or egress.hold(tool, act, args)):
                rp = None
            if rp is not None and rpt.end_if_written(ctx, rp[0], act, args, t0):
                rp = None                                    # 0.2.30 (B1): the agent wrote a file this command runs: ended, the owner is asked
        gate = None if rp is not None else _hook_pre(ctx, agent, m, act, dv, dwhy)
        if dv != "deny":
            nz_ = (sv_.refuse if sv_ is not None else constitution.check(tool, args))   # r0261: under the strict fact the article is judged
            #                                                                              on what the line RUNS (strict_policy.article)         # v1 (06.11): an immutable article (Н1-Н8): refused at once, no question, nobody notified;
            if nz_ is not None:                          # the agent is told why and what to do instead (reasons.py), the journal keeps the row.
                gate, rp = ("deny", nz_[0]), None        # Never an allow; an earlier "approve later runs" does not cover it either.
            if nz_ is None and hit_ is not None and hit_[2] and provenance.n1(hit_[1]):
                gate, rp = ("deny", constitution.SECRET), None     # r0275: a copy of a private key / token store is that file (Н1)
        sbx_code = dv == "allow" and act.get("sandboxed") is True and act.get("class") == "command" and al.code_option(L, m["id"]) \
            if m is not None and L is not None else False     # 0.2.82: this line runs in the strict sandbox under the code option
        if not sbx_code and m is not None and L is not None and dv == "allow" and act.get("class") == "command" and tool == "Bash" \
                and al.line_contained(L, m["id"], meta, w_, args.get("command") if isinstance(args, dict) else None):
            sbx_code = True                                  # v1 П3 (06.11): a LISTED line the strict sandbox contains is a sandboxed run too
        in_sbx = sbx_code or (m is not None and L is not None and act.get("class") == "command" and isinstance(tool, str)
                              and tool.startswith("Bash") and al.in_strict_sandbox(L, m["id"], meta, w_))
        if gate is None and dv == "allow" and not sbx_code and sv_ is None and hold_after_secret(ctx, agent["id"], tool, act, args, t0):
            # (r0261: not under the strict fact -- a secret seen stays on the computer; what would carry it out is С1 on its own line)
            gate = ("hold", "ESCALATE_SECRET_SEEN")          # 0.2.24 (critique T3): may only tighten, like the advisor's hold (the owner releases it)
        if gate is None and dv == "allow" and hit_ is not None and hit_[2] and not in_sbx and not sbx_code and sv_ is None:
            gate = ("hold", provenance.HOLD)                 # r0275: a read of a copy of a credential the mandate would let through
        # r25 (s8 P2, P3): the files are found whenever the owner is asked about this line anyway -- a question of the core (dv "defer":
        # an unlisted `bash f8b.sh`) or a secret hold -- and shown on THAT page (text of the write, Dangerous true, the reason). No new
        # question: the defer stays the core's signed question, the secret hold stays a hold. Only an allowed line becomes a WRITTEN_RUN hold.
        wq_ = act.get("class") == "command" and dv != "deny" and (
            (gate is None and dv in ("allow", "defer")) or rp is not None or gate == ("hold", "ESCALATE_SECRET_SEEN"))
        wrf = written_run_files(ctx, agent["id"], args, t0) if wq_ else []
        if wrf and in_sbx:
            # 04.11 (OTCHET-0258 D8, rule bcc4411): in the strict sandbox under the code option a written file runs with a receipt, no
            # hold -- unless its written text VISIBLY reaches a gate (G1-G4, the agent's harness: execguard.gate_text).
            # v1 П3 / Н7 (06.11, Р-0611-D8): a text the witness could not read ("unseen": a copy, a download, a shell write) or cannot
            # parse ("opaque": obfuscated) is what the OS sandbox is FOR -- the same code typed into the line already runs OK_SANDBOXED
            # (sandbox.contained: opaque), so holding the file was a question an adversary skips by inlining. Measured: 70 of the 73
            # in-sandbox holds of the owner's corpus were "unseen" copies into the scratch directory. Outside the sandbox: held as before (С5).
            wg_ = written_run_info(ctx, agent["id"], t0 - 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN))
            # Any line under the fact (not only a contained one): the written file runs inside the OS bounds whatever else the line
            # does, and what else it does (an exit, a write outside the project) is judged on its own.
            # Only an UNSEEN write triggers (written_run_files also lists, for the page, files the line names that the owner already let
            # go: under the sandbox filter those became the trigger -- the owner's corpus held 34 lines on one downloaded directory the
            # owner had released each time).
            unseen_ = _unseen_risky(ctx, agent["id"], t0 - 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN))[1]
            # 10.11 (r0260, law 2): G1 (a delete outside the project) and G2 (the network) of a written text are what the kernel holds
            # (EPERM, refused connection) -- the same text typed into the line runs OK_SANDBOXED (sandbox.code_contained). Still held:
            # G3 (secrets: the keychain is not a path denyRead covers) and G4 (persistence: .envrc / .husky / a hook inside the project
            # runs later OUTSIDE the sandbox).
            if sv_ is not None:
                # 11.11 (r0261, closed list): G3 (a secret named in the text) is closed by the strict fact's denyRead; held only a text that
                # writes a place another program runs later OUTSIDE the sandbox (С3): G4 (rc files, LaunchAgents ...) or a place of the
                # list inside the project (.envrc, .husky/, CI files ...: strict_policy.later_text; execguard's gates do not name them)
                # 13.11 (r0271, ISPYTANIE-0266 Н1): tried and measured -- holding also a READ text that reaches G1 / G2 / G3 here put
                # 8 more questions on the dev corpus (2 days: after one write of a security test that names key paths, every later run
                # of the day was held) and 6 on the harmless probes the kernel contains (src/tool.py, run.sh, npm run nuke: EPERM /
                # refused connection); G2 + G3 alone: the same 8 on dev. The kernel holds those; kept as before: only what runs later
                # OUTSIDE the sandbox (G4, later_text) holds a run in quiet mode.
                wrf = [f for f in wrf if f in unseen_ and ((wg_.get(f) or {}).get("g") == "G4"
                                                           or strict_policy.later_text((wg_.get(f) or {}).get("text")))]
            else:
                wrf = [f for f in wrf if f in unseen_ and (wg_.get(f) or {}).get("g") not in (None, "unseen", "opaque", "G1", "G2")]
            if wrf:
                sbx_code = False
        elif wrf and dv == "allow" and dwhy == "OK_ALLOWANCE" and isinstance(act.get("project"), str):
            # 13.11 (r0271, ISPYTANIE-0266 Н1): outside the strict sandbox a "from now on" rule (pytest, npm test, make, mypy ...) the owner
            # signed for THIS project says "the agent can then run code it wrote in this project without asking you" (TRUST_TEXT). The
            # 0.2.90 rule (every code-like file the agent wrote is risky) held every such run after any write: the rule never took a
            # question off. Now, under the rule, a written file still holds the run only when its stored mark shows something the owner
            # did not trust: a text the witness could not read or parse, a text that reaches a gate (network, secrets, persistence, a
            # write / delete outside the project), findings of a script (publish, push ...), a directory marked whole, or a path outside
            # the rule's project. A clean text the witness READ inside the project runs under the rule, as the signed text promises.
            wrf = allowance_keeps(ctx, agent["id"], wrf, act["project"], t0)
        if wrf:
            if gate is None and (dv == "allow" or rp is not None) and not sbx_code:
                gate = ("hold", "ESCALATE_WRITTEN_RUN")      # 28.10: runs a file the agent wrote unseen / with network code (the owner releases it)
                # 0.2.82: not when the line runs in the strict sandbox under the option "code in the strict sandbox" (the file's code is
                # contained: no network, no write outside the project; the receipt says sandboxed). Nor the hold after a secret was seen
                # (above): every way out of the sandbox is asked on its own line.
            ej_ = json.loads(row["exec_json"]) if row.get("exec_json") else {}
            wsrc = {}
            if sbx_code:
                wrf = []                                     # 0.2.90: a run the strict sandbox contains shows nobody the written files: the mark
                                                             # stays (seen_writes counts "allowed" pages), the next run OUTSIDE the sandbox is held
            wi = written_run_info(ctx, agent["id"], t0 - 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN), src=wsrc)
            # the page names the files and shows what was written; N1 29.10: `w` = the write row it shows (what the owner sees is THAT write)
            ej_["written_run"] = [dict(wi.get(f) or {}, file=f, **({"w": wsrc[f]} if wsrc.get(f) else {})) for f in wrf[:16]]
            for w_ in ej_["written_run"]:
                # N14 0.2.73: a mark set by a git line (stash pop / restore / checkout under "gt"): what comes back is what the agent put into
                # git; the witness saw that text when the agent wrote it (Write / Edit): shown, labelled as such, instead of "blind"
                if w_.get("by") == "shell" and isinstance(w_.get("text"), str) and re.search(r"(^|[\s;&|(])git\s", w_["text"]):
                    gx = git_kept_texts(ctx, agent["id"], w_["file"], bool(w_.get("dir")), args, w_.get("w"),
                                        t0 - 60 * (getattr(ctx.cfg, "written_lookback_min", None) or WRITTEN_LOOKBACK_MIN))
                    if gx:
                        w_["git_texts"] = gx
            if _line_hash(tool, args):
                ej_["line"] = _line_hash(tool, args)        # RT-0269 p.2
            row["exec_json"] = json.dumps(ej_, ensure_ascii=False)
        if act.get("class") == "command" and dv != "deny" and isinstance(args, dict) and isinstance(args.get("command"), str):
            ux_, _xd = _line_extract(args)
            if ux_:
                # N4 29.10 (series 8b, RT4b/c): a line that extracts an archive / applies a patch / checks out git objects into the project
                # writes a text the witness never sees. Its page says so (unseen_write: the paths; secret: the agent read a secret within
                # the window) and Dangerous is true, as for a run of a written file. Signed with the view.
                ej_ = json.loads(row["exec_json"]) if row.get("exec_json") else {}
                ej_["unseen_write"] = {"paths": ux_[:16], "secret": bool(secret_seen(ctx, agent["id"], t0))}
                row["exec_json"] = json.dumps(ej_, ensure_ascii=False)
        eg = egress.hold(tool, act, args) if gate is None and dv == "allow" else None
        if eg:
            gate = ("hold", eg)                              # 0.2.25: a query string / upload to a user-content host, a request catcher, a hidden destination
        if gate is None and dv == "allow" and dwhy == "OK_UNSPECIFIED" and act.get("class") == "disclosure" and egress.non_loopback(act.get("recipient")):
            gate = ("hold", egress.CODE_UNSPECIFIED)         # 0.2.90 (G2): a mandate with no `message` class names no destination: a non-loopback
                                                             # exit is held for the owner, never OK_UNSPECIFIED under "allowed by default"
        if (gate is not None and gate[0] == "hold") or (gate is None and dv == "defer" and rp is None):
            _mark_refused_before(ctx, agent, row, act, args, t0, hit_)     # r0275: the owner refused the same effect through another call
            _mark_net_code(ctx, agent, row, act, args, t0, m)          # r0294: the line runs code downloaded in this session
            _mark_autostart(ctx, row, act, m)                          # r0298: autostart in an unknown folder: which words the mandate pinned
            _mark_defense(ctx, row, act, m)                            # r0305: an OS protection switched off (asked only as a strict doubt)
        if gate is not None and gate[0] == "deny":
            res = refuse(gate[1])
            if gate[1] == "APPROVAL_RATE":
                auto_freeze_check(ctx, agent, t0)            # 0.2.25: a flood of refused questions freezes the agent
            return res
        if dv == "defer" and delegation.unsatisfiable(ctx, acc, agent["id"], act, dwhy, row.get("level_min")):
            return refuse("APPROVER_NONE")          # 0.2.13: a delegated agent whose approval rule nobody can complete: blocked, never let through
        if gate is not None and gate[0] == "hold" and auto_fz:
            return refuse("AGENT_FROZEN")               # 0.2.89: a hold is a question too
        if gate is not None and gate[0] == "hold":
            row.update(verdict="hold", reason=gate[1], status="held", expires=t0 + _ttl(ctx, acc, "defer"), hold_reason=gate[1])
            _insert(ctx, row)
            if created is not None:
                created.append(row["rid"])
            if getattr(ctx, "push", None) is not None and not quiet:
                ctx.push.notify_defer(row, agent["name"], lits)  # 0.2.0: an item held by the advisor waits for a human like a defer
            if getattr(ctx, "notify", None) is not None and not quiet:
                ctx.notify.approval(row)                         # 0.2.25: Telegram / Slack / email channels of the account
            return to_result(ctx, refresh(ctx, row["rid"]))
        if rp is not None:
            row["rid"] = rp[1]                                   # 0.2.29: the next id the owner signed in advance
        v = _authorize_row(ctx, L, row, m["id"], act, _ttl(ctx, acc, dv))
        if v == "allow" and used:
            row["allowances"] = json.dumps(sorted(set(used)))      # 0.2.10: every allowance this line needed (the receipt names the recorded one)
        if v == "allow":
            try:                                             # rec 29.10: the row and the dirty mark of an allowed write are ONE transaction
                with ctx.db.tx():
                    _insert(ctx, dict(row))
                    execguard.on_allowed(ctx, row)           # 0.2.13: an allowed write to an executed file marks it dirty
            except Exception:  # noqa: BLE001 -- the ledger entry exists: keep the row (without the mark) and fail closed (the call is not answered "allow")
                log("ERROR", "allow: row + dirty mark not stored together; row stored without the mark, call fails", rid=row["rid"])
                _insert_after_authorize(ctx, row)
                raise
        else:
            _insert_after_authorize(ctx, row)
        if v == "defer" and auto_fz:                     # 0.2.89 (D5): asked while auto-frozen: refused, nobody is notified (as freeze() does)
            ctx.db.x("UPDATE actions SET status='denied', verdict='deny', reason='AGENT_FROZEN', updated_at=? WHERE rid=? AND status='pending_approval'",
                     (now(), row["rid"]))
            return to_result(ctx, refresh(ctx, row["rid"]))
        if v == "defer" and rp is not None and rpt.use(ctx, acc, rp[0], row["rid"], t0):
            if getattr(ctx, "notify", None) is not None:
                ctx.notify.digest(acc, "repeat_used")            # 0.2.30 (V4): the owner learns of every use (a summary, no arguments)
            return to_result(ctx, refresh(ctx, row["rid"]))      # allow OK_APPROVED: the APPROVAL entry holds the owner's signature
        if v == "defer" and created is not None:
            created.append(row["rid"])
        if v == "defer" and getattr(ctx, "push", None) is not None and not quiet:
            ctx.push.notify_defer(row, agent["name"], lits)      # 08: queued; the push service is never awaited here
        if v == "defer" and getattr(ctx, "notify", None) is not None and not quiet:
            ctx.notify.approval(row)                             # 0.2.25: queued; a channel is never awaited here
        return to_result(ctx, refresh(ctx, row["rid"]))


def refused_outside_write(ctx, agent_id, L, mid, act, now, t0, tool=None, args=None, ameta=None):
    """r0296 (profile "auto mode + Witness", Authorization Drift): a write outside the project that the signed list lets run quietly
    (the profile's "(write outside the project) /*", an owner's own folder entry, or `unlisted: "allow"`) is ASKED again -- marked dangerous,
    so no list covers it -- when the owner refused a call of this agent within provenance.REFUSED_WINDOW_S whose effect touched the same
    place (`sed -i note` -> No, then `Edit note`) -- or the witness itself refused one (`rm -rf ~/Documents` FORBIDDEN_WIPE, then `Write
    ~/Documents/a.txt ""`). The question then carries "You said No to this ... ago" (_mark_refused_before). Only
    narrows: an allow becomes a question, never the other way; an owner's "from now on" (OK_ALLOWANCE) is the owner's later word and stays.
    Under the profile also: a place that is not a plain data file (mapping.auto_quiet_place: dotfiles, Library, bin, code, no extension ...)
    is asked -- another program could run it before an undo."""
    if not isinstance(act, dict) or act.get("class") != "command" or act.get("dangerous") is True or "allowance" in act \
            or act.get("sandboxed") is True:          # the strict sandbox holds the line (the OS keeps it from writing there): as before
        return act
    rc = act.get("recipient")
    if not isinstance(rc, str) or not rc.startswith(OUTSIDE_WRITE_HEAD):
        return act
    try:
        d0_ = L.S.decide_for(mid, act, now)[1:]
        if d0_ not in (("allow", "OK"), ("allow", "OK_UNSPECIFIED")):
            return act
        pth = rc[len(OUTSIDE_WRITE_HEAD):].strip()
        key = "out:" + (provenance._canon(pth) or "")
        M = L.S.mandates.get(mid)
        # r0305 (SHAG0 v40, witness-vectors W2 / X3): under `unlisted: "allow"` (the core's OK_UNSPECIFIED: no entry of the list names
        # this write) a write or delete OUTSIDE the project is asked -- "other commands run without asking" is about commands, not about
        # files of other projects or the person's notes (a Makefile of another project runs before any undo). An owner's own folder entry
        # (OK) and the auto profile's data files stay quiet with their shadow copy.
        not_data = (is_auto_profile(((M or {}).get("permissions") or {}).get("command")) and not auto_quiet_place(pth)) \
            or d0_ == ("allow", "OK_UNSPECIFIED")
        if not not_data and provenance.refused_place(ctx, agent_id, key, t0) is None:
            return act
        b = dict(act, dangerous=True)
        if L.S.decide_for(mid, b, now)[1] != "defer":
            return act
        if not_data and ameta is not None:
            # the owner's "from now on" for this folder (app/amend.py, offered on the question) covers it, as without the profile.
            # amend.cover wants OK_ALLOWANCE, but the profile's own entry matches the folder id first (the core answers OK): accept both,
            # only for an active amendment of this mandate and project that lists the id
            hm_ = amend.home_of(args, ameta)
            id_ = amend.id_for(tool, b, args, hm_)
            if id_ is not None and amend.line_ok(tool, args, hm_):
                for gid in amend.active(L, mid, ameta["project"], id_, now):
                    c = dict(b, recipient=id_, dangerous=False, allowance=gid, project=ameta["project"])
                    if L.S.decide_for(mid, c, now)[1:] in (("allow", "OK_ALLOWANCE"), ("allow", "OK")):
                        return c
        return b
    except Exception:      # noqa: BLE001  fail closed: asked
        log("ERROR", "refused outside-write check failed")
        return dict(act, dangerous=True)


# r0305 (witness-vectors 0.1 under `unlisted: allow`: E6, E8, H1, O8, X2): "run other commands without asking" never covers what cannot
# be undone or seen -- a recursive delete, root rights, a hand-off to another app or the browser, code from a variable, a local service's
# socket. Under unlisted "ask" these are asked anyway (not on the list); only the silence of OK_UNSPECIFIED is narrowed.
_ALLOW_NEVER_SILENT = re.compile(r"^(?:rm \[[^\]]*\brecursive\b|find \[[^\]]*\bdelete\b|(?:sudo|doas|pkexec|su|runas)(?:\s|$)|"
                                 r"(?:open|xdg-open|osascript|start|explorer(?:\.exe)?)(?:\s|$|\s*\[))")
_EVAL_FROM_VAR = re.compile(r"(?:^|\s)-[A-Za-z]*[ce]\s+[\"']?\$|(?:^|[\s;&|(])eval\s|--unix-socket\b|docker\.sock\b")


def later_run_write(L, mid, act, tool, args, now):
    """r0305 (witness-vectors W5; reverses r0261c (д) П2 for these files): a Write / Edit of a file INSIDE the project that another program
    runs later by itself, outside the agent and Witness -- direnv runs .envrc on `cd` in the person's shell, a hooks manager runs .husky /
    .githooks on the person's commit, CI runs workflows on push, the editor runs tasks.json -- is asked ONCE (the danger `autostart` with
    its own detail: qwords autostart words, never "from now on"). "Its run is judged when it runs" does not hold there: nothing of it runs
    through the agent. Under the session's fresh strict fact (`sbx_session`) the closed list's С3 asks it already (strict_policy.write_cover,
    with its narrow "from now on"): unchanged. Only an allowed write is turned into a question; anything else as it was."""
    from app.hookjudge.bashparse import AUTOSTART as _AS, LATER_RUN_DETAIL, is_later_run_path
    w = args.get("_witness") if isinstance(args, dict) else None
    pth = w.get("path") if isinstance(w, dict) else None
    if not isinstance(act, dict) or "allowance" in act or not isinstance(w, dict) or w.get("sbx_session") is True or w.get("danger") \
            or not is_later_run_path(pth) or not isinstance(w.get("project"), str) or act.get("dangerous") is True:
        return act
    try:
        if L.S.decide_for(mid, act, now)[1] != "allow":
            return act
        b = dict(act, **{"class": "command"}, recipient=(_AS + ":" + LATER_RUN_DETAIL % pth)[:300], dangerous=True)
        b.pop("reversible", None)
        b.pop("sandboxed", None)
        return b if L.S.decide_for(mid, b, now)[1] == "defer" else act
    except Exception:      # noqa: BLE001  fail closed: asked
        log("ERROR", "later-run write check failed")
        return act


def unlisted_allow_gate(L, mid, act, tool, args, now):
    """r0305: an action the core lets through ONLY because of `unlisted: "allow"` (OK_UNSPECIFIED) whose command head is one of the
    above, or whose line runs code from a variable / talks to a local service's socket, is asked (marked dangerous: no list covers it).
    Only narrows; anything else unchanged."""
    if not isinstance(act, dict) or act.get("class") != "command" or act.get("dangerous") is True or "allowance" in act \
            or act.get("sandboxed") is True or not (isinstance(tool, str) and tool.startswith("Bash")):
        return act
    rc = str(act.get("recipient") or "")
    text = args.get("command") if isinstance(args, dict) and isinstance(args.get("command"), str) else ""
    if not (_ALLOW_NEVER_SILENT.match(rc) or _EVAL_FROM_VAR.search(text)):
        return act
    try:
        if L.S.decide_for(mid, act, now)[1:] != ("allow", "OK_UNSPECIFIED"):
            return act
        b = dict(act, dangerous=True)
        return b if L.S.decide_for(mid, b, now)[1] == "defer" else act
    except Exception:      # noqa: BLE001  fail closed: asked
        log("ERROR", "unlisted-allow gate failed")
        return dict(act, dangerous=True)


def _mark_refused_before(ctx, agent, row, act, args, t0, hit=None):
    """r0275: a question whose effect overlaps a call the owner refused in this session says so (exec_json "rb", qwords); a question
    about a read of a copy of a credential names the credential (exec_json "sc")."""
    if hit is not None and hit[2]:
        ej_ = json.loads(row["exec_json"]) if row.get("exec_json") else {}
        if isinstance(ej_, dict):
            ej_["sc"] = {"copy": hit[0][:1024], "src": hit[1][:1024]}
            row["exec_json"] = json.dumps(ej_, ensure_ascii=False)
    try:
        keys = json.loads(row["fx_keys"]) if row.get("fx_keys") else []
        if act.get("class") == "command":
            keys = keys + provenance.run_keys(ctx, agent["id"], args, t0)
        rb = provenance.refused_before(ctx, agent["id"], keys, t0, row.get("rid"))
        if rb is None:
            return
        ej_ = json.loads(row["exec_json"]) if row.get("exec_json") else {}
        if isinstance(ej_, dict):
            ej_["rb"] = rb
            row["exec_json"] = json.dumps(ej_, ensure_ascii=False)
    except Exception:      # noqa: BLE001  no mark: the question is asked as before
        log("ERROR", "refused-before mark not made", rid=row.get("rid"))


def _mark_net_code(ctx, agent, row, act, args, t0, m=None):
    """r0294 (law "origin of code"): a question about a shell line that runs code downloaded in this agent's session -- or that downloads
    and runs it itself -- carries exec_json "dl" {"host", "at", "path"?, "pin"}: qwords says it in the one short line of harm. "pin" False:
    the vocabulary the agent's mandate pinned has no such sentence (a mandate signed before mr-vocab-3): its own nearest sentence is shown
    (signed words stay inside what the owner agreed to) and the fact goes under Details; a new mandate gets the new words."""
    if act.get("class") != "command" or not isinstance(args, dict) or not isinstance(args.get("command"), str):
        return
    try:
        nc = provenance.net_code(ctx, agent["id"], args, t0)
        if nc is None:
            return
        nc["pin"] = _pinned_has(ctx, m, "net_code_run")
        ej_ = json.loads(row["exec_json"]) if row.get("exec_json") else {}
        if isinstance(ej_, dict):
            ej_["dl"] = nc
            row["exec_json"] = json.dumps(ej_, ensure_ascii=False)
    except Exception:      # noqa: BLE001  no mark: the question is asked with the general words
        log("ERROR", "net-code mark not made", rid=row.get("rid"))


def _mark_autostart(ctx, row, act, m=None):
    """r0298: a question whose recipient is the danger `autostart` (bashparse.AUTOSTART: a relative write, in a folder the witness cannot
    tell, to a file that starts commands by itself) carries exec_json "as" {"pin"}: True = the vocabulary the agent's mandate pinned holds
    qwords SCREEN autostart_* (mr-vocab-4 or later; or none pinned) -> those words; False = a mandate signed before -> its own nearest
    sentence ("cannot fully check"): signed = shown, the evidence pack stays VALID. No mark (an error) -> the older words, as with False."""
    if act.get("class") != "command" or not str(act.get("recipient") or "").startswith("autostart:"):
        return
    try:
        ej_ = json.loads(row["exec_json"]) if row.get("exec_json") else {}
        if isinstance(ej_, dict):
            ej_["as"] = {"pin": bool(_pinned_has(ctx, m, "autostart_harm"))}
            row["exec_json"] = json.dumps(ej_, ensure_ascii=False)
    except Exception:      # noqa: BLE001  no mark: the older words
        log("ERROR", "autostart mark not made", rid=row.get("rid"))


def _mark_defense(ctx, row, act, m=None):
    """r0305: a question whose recipient is the danger `defense` (bashparse.DEFENSE: an OS protection switched off) -- refused Н10 at once
    everywhere, so it is asked only when the strict policy found it in text a program may run (a doubt) -- carries exec_json "df" {"pin"}:
    True = the mandate pinned mr-vocab-5 or later (or none) -> qwords SCREEN defense_*; False = a mandate signed before -> the older
    vocabulary's own sentence ("a dangerous command"): signed = shown, the evidence pack stays VALID."""
    if act.get("class") != "command" or not str(act.get("recipient") or "").startswith("defense:"):
        return
    try:
        ej_ = json.loads(row["exec_json"]) if row.get("exec_json") else {}
        if isinstance(ej_, dict):
            ej_["df"] = {"pin": bool(_pinned_has(ctx, m, "defense_harm"))}
            row["exec_json"] = json.dumps(ej_, ensure_ascii=False)
    except Exception:      # noqa: BLE001  no mark: the older words
        log("ERROR", "defense mark not made", rid=row.get("rid"))


def _pinned_has(ctx, m, key):
    """True when the vocabulary the mandate's signed tool map document pins holds screen sentence `key`, or the mandate pins none
    (nothing to stay inside of); False when it pins an older vocabulary without it."""
    try:
        mid = m.get("id") if isinstance(m, dict) else (m["id"] if m is not None else None)
        r = ctx.db.one("SELECT gateway_doc FROM mandates WHERE id=?", (mid,)) if mid else None
        d = json.loads(r["gateway_doc"]) if r is not None and r["gateway_doc"] else None
        dg = d.get("vocab") if isinstance(d, dict) else None
        if not isinstance(dg, str):
            return True
        v = ctx.db.one("SELECT json FROM vocabs WHERE digest=?", (dg,))
        if v is None:
            return True
        doc = json.loads(v["json"])
        return isinstance(doc, dict) and isinstance(doc.get("screen"), dict) and key in doc["screen"]
    except Exception:      # noqa: BLE001  unknown: the older sentence (honest in any vocabulary since mr-vocab-1)
        return False


def _ttl(ctx, account_id, verdict):
    """2.4: a deferred action of an organisation whose rules need k >= 2 waits `defer_ttl_s` (900..3600) instead of 900 s."""
    base = getattr(ctx.cfg, "defer_ttl_s", None) or TTL           # 0.2.29: DW_DEFER_TTL_S (local tests only below 900)
    return org.defer_ttl(ctx, account_id, base) if verdict == "defer" else base


def _authorize_row(ctx, L, row, mid, act, ttl):
    res = L.authorize(row["rid"], mid, act, ttl=ttl, audience="tool")
    v = res["verdict"]
    row.update(mandate_id=mid, verdict=v, reason=res["reason"], status=STATUS_OF[v], expires=L.S.receipts[row["rid"]]["expires"])
    if v == "allow":
        row.update(aar=res["aar"])                  # R-16: proof_json is made later, in a batch (materialize_proofs)
    try:                                            # 0.2.4 (draft-deus-aar-05 9.5): the inclusion promise of the RECEIPT entry, given with the AAR
        if jobs.promise_allowed(ctx):               # 0.2.5 (R4-01): only when it can be kept (DW_ANCHOR=on, the last anchor run fine and recent)
            row.update(promise=L.promise(L.rseq[row["rid"]], mmd=PROMISE_MMD))
    except Exception as e:  # noqa: BLE001  -- a promise is an extra; the decision stands without it
        log("ERROR", "promise not issued: " + type(e).__name__)
    return v


def _hook_pre(ctx, agent, m, act, dv, dwhy):
    """pre_authorize may only tighten (0 p.2): deny or hold of an action the core would not refuse; anything else is ignored."""
    try:
        g = hooks.pre_authorize(ctx, agent, m, act, dv, dwhy)
    except Exception as e:  # noqa: BLE001  -- a broken hook never decides; the core verdict stands
        log("ERROR", "flow.pre_authorize failed: " + type(e).__name__)
        return None
    if g is None:
        return None
    if isinstance(g, tuple) and len(g) == 2 and g[0] in ("deny", "hold") and isinstance(g[1], str) and g[1]:
        if g[0] == "hold" and dv != "allow":
            return None                             # 4.2: the advisor holds only what the core would allow
        if dv == "deny":
            return None                             # nothing to tighten: the core refuses and records it
        return (g[0], g[1][:64])
    log("ERROR", "flow.pre_authorize returned an unknown value; ignored")
    return None


def _decided(ctx, agent, result):
    """on_decided of task 02 after every answer to the agent (digest counters, escalation)."""
    try:
        hooks.on_decided(ctx, agent, refresh(ctx, result["rid"]))
    except Exception as e:  # noqa: BLE001
        log("ERROR", "flow.on_decided failed: " + type(e).__name__)
    return result


def do_present(ctx, agent, rid):
    x = own_agent_action(ctx, agent, rid)
    with ctx.hub.lock(x["account_id"]):
        x = refresh(ctx, rid)
        if x["mandate_id"] is None:
            return {"result": "reject", "reason": "NOT_ALLOWED"}
        fz = ctx.db.one("SELECT frozen_at FROM agents WHERE id=?", (agent["id"],))
        if fz is not None and fz["frozen_at"] and not (x["status"] == "allowed" and frozen_kind(ctx, agent["id"]) == "auto"):
            return {"result": "reject", "reason": "AGENT_FROZEN"}       # 0.2.24 (T2): an approval given before the freeze is not used
            #                                                             0.2.89 (D5): under an automatic freeze the mandate's own allow is
        if x["class"] == "command" and x["status"] in ("approved", "allowed") and page_files_changed(ctx, x):
            # RT-0269 p.2 (2a / 2b): written while the hook waited (or after it gave up): the owner let go the text the page showed, not
            # what would run now. Not consumed; the repeat is judged anew (a new question with the new text)
            log("INFO", "present refused: a file the page showed changed since", rid=rid, account=x["account_id"])
            mark_file_changed(ctx, rid, page_files_changed(ctx, x))      # N1: nothing ran: this decision showed nothing the agent runs now
            return {"result": "reject", "reason": "FILE_CHANGED"}
        L = ctx.hub.ledger(x["account_id"])
        r = L.tool_present(rid, tool="tool", request=wire.cbor_form(json.loads(x["action_json"])))
        if r["result"] == "accept":
            ctx.db.x("UPDATE actions SET status='consumed', updated_at=? WHERE rid=?", (now(), rid))
            execguard.on_consumed(ctx, x)               # 0.2.13: an approved command with exec_changed ran: those versions are now confirmed
            return {"result": "accept", "reason": "OK"}
        return {"result": "reject", "reason": r["reason"]}


def do_report(ctx, agent, rid, executed):
    x = own_agent_action(ctx, agent, rid)
    with ctx.hub.lock(x["account_id"]):
        x = refresh(ctx, rid)
        if x["mandate_id"] is None:
            return {"result": "ignored"}
        L = ctx.hub.ledger(x["account_id"])
        r = L.tool_report(rid, bool(executed))
        if r["result"] == "released":
            ctx.db.x("UPDATE actions SET status='not_executed', updated_at=? WHERE rid=?", (now(), rid))
        elif x["status"] == "consumed":
            ctx.db.x("UPDATE actions SET status=?, updated_at=? WHERE rid=?", ("executed" if executed else "not_executed", now(), rid))
        return {"result": r["result"]}


def own_agent_action(ctx, agent, rid):
    x = ctx.db.one("SELECT * FROM actions WHERE rid=? AND agent_id=?", (rid, agent["id"])) if isinstance(rid, str) else None
    if not x:
        raise Err(404, "NOT_FOUND")
    return x


def own_account_action(ctx, acc, rid):
    x = ctx.db.one("SELECT 1 AS k FROM actions WHERE rid=? AND account_id=?", (rid, acc["id"])) if isinstance(rid, str) else None
    if not x:
        raise Err(404, "NOT_FOUND")
    return refresh(ctx, rid)


def _pending(ctx, acc, rid):
    """-> (row, Ledger, receipt, mandate map) of a deferred action of this account, or Err(409 NOT_DEFERRED). Caller holds hub.lock."""
    x = own_account_action(ctx, acc, rid)
    if x["status"] != "pending_approval" or x["mandate_id"] is None:      # 0.2.38: a trial call waiting for the first touch is never approved as it is
        raise Err(409, "NOT_DEFERRED")
    L = ctx.hub.ledger(acc["id"])
    L.sync_now()
    rc = L.S.receipts.get(rid)
    if rc is None:
        raise Err(409, "NOT_DEFERRED")
    if rid in L.aseq or rid in L.S.refused:             # rel 28.10: the ledger decided already (a crash between the entry and the row)
        k = reconcile_row(ctx, L, x)
        raise Err(409, "ALREADY_DECIDED", "the witness already recorded a decision for this action (%s); nothing new was recorded" % k)
    return x, L, rc, L.S.mandates[rc["mandate"]]


def _store_approval(ctx, aid, rid, approved, env, aseq, t, signers, behalf, view_hex, aar, pj):
    """rel 28.10: the rows of a decision the ledger holds (APPROVAL entry): approvals, the superseded requests, the action. Caller: in ctx.db.tx()."""
    ctx.db.x("INSERT OR REPLACE INTO approvals(rid,account_id,approved,envelope,ledger_seq,t,signers,on_behalf_of,view_sha256) VALUES(?,?,?,?,?,?,?,?,?)",
             (rid, aid, 1 if approved else 0, env, aseq, t, signers, behalf, view_hex))
    ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE account_id=? AND kind='approval' AND ref=? AND status='collecting'", (aid, rid))
    if not approved:
        ctx.db.x("UPDATE actions SET status='refused', verdict='deny', reason='REFUSED', updated_at=? WHERE rid=?", (t, rid))
    else:
        ctx.db.x("UPDATE actions SET status='approved', verdict='allow', reason='OK_APPROVED', aar=?, proof_json=?, updated_at=? WHERE rid=?",
                 (aar, json.dumps(pj), t, rid))


def _approval_entry(L, rid):
    """-> body of the last APPROVAL entry of `rid` in the ledger, or None."""
    from svidetel_v4 import cose
    s = L.aseq.get(rid)
    seqs = [s] if s is not None else range(len(L.raws) - 1, max(-1, L.rseq.get(rid, 0) - 1), -1)
    for i in seqs:
        e = cose.loads(cose.verify1(L.raws[i], [L.wk], cose.TYP_ENTRY)[0])
        if e["type"] == "APPROVAL" and e["body"].get("receipt") == rid:
            return e["body"], i
    return None, None


RECONCILE_WINDOW_S = 7 * 86400                       # rel 28.10: rows older than this are not looked at on start (lazy expiry decides them)


def reconcile_row(ctx, L, x):
    """rel 28.10: a waiting row (held / pending_approval) against the ledger; the ledger's verdict is above the row. Caller holds hub.lock,
    L synced. Nothing is executed or appended to the ledger; only the row is brought in line, or marked for a person (column reconcile).
    -> "ok" (consistent) | "denied" | "pending" | "approved" | "refused" | "manual:<why>"."""
    rid, st = x["rid"], x["status"]
    rc = L.S.receipts.get(rid)
    if rc is None:
        return "ok"                                   # no judgement in the ledger: the row is what it says
    t = now()
    v, approved, refused = rc["verdict"], rid in L.aseq, rid in L.S.refused
    out = None
    if st == "held":
        if approved or refused:
            out = "manual:held_with_approval"
        elif v == "deny":
            ctx.db.x("UPDATE actions SET status='denied', verdict='deny', reason=?, mandate_id=?, expires=?, updated_at=? WHERE rid=? AND status='held'",
                     (rc.get("reason") or "DENIED", rc["mandate"], rc["expires"], t, rid))
            out = "denied"
        elif v == "defer":                            # the core asked a person: an ordinary question now (the approval is a second human gate)
            a = rc["action"]
            ctx.db.x("UPDATE actions SET status='pending_approval', verdict='defer', reason=?, mandate_id=?, expires=?, action_json=?, request_hash=?, "
                     "updated_at=? WHERE rid=? AND status='held'",
                     (rc.get("reason"), rc["mandate"], rc["expires"], json.dumps(wire.wire_form(a), ensure_ascii=False), request_hash(a), t, rid))
            out = "pending"
        else:                                         # allow: the AAR of that decision and the person's release signature are not recoverable
            out = "manual:held_allowed_in_ledger"
    elif st == "pending_approval":
        if approved or refused:
            body, seq = _approval_entry(L, rid)
            if body is None:
                out = "manual:approval_entry_missing"
            else:
                ok = bool(body.get("approved", True))
                env = body.get("cose")
                vh = body.get("view").hex() if isinstance(body.get("view"), bytes) else None
                aar = L._aar_approved(rid) if ok else None
                pj = proof_json(L.receipt_proof(rid, approval=True), approval=env) if ok else None
                with ctx.db.tx():
                    _store_approval(ctx, x["account_id"], rid, ok, env, L.aseq.get(rid) if ok else seq, t, None, None, vh, aar, pj)
                    if ok:
                        execguard.on_allowed(ctx, x)      # same tx as the decision: a failure leaves the row pending, the next start retries
                out = "approved" if ok else "refused"
        elif v == "defer":
            return "ok"
        elif v == "deny":
            ctx.db.x("UPDATE actions SET status='denied', verdict='deny', reason=?, updated_at=? WHERE rid=? AND status='pending_approval'",
                     (rc.get("reason") or "DENIED", t, rid))
            out = "denied"
        else:
            out = "manual:pending_allowed_in_ledger"
    else:
        return "ok"
    if out.startswith("manual:"):
        ctx.db.x("UPDATE actions SET reconcile=? WHERE rid=?", (out, rid))
        log("ERROR", "reconcile: row and ledger disagree; left for a person, nothing runs", rid=rid, account=x["account_id"], row_status=st,
            receipt_verdict=v, outcome=out)
    else:
        ctx.db.x("UPDATE actions SET reconcile=? WHERE rid=?", ("ledger:" + out, rid))
        log("WARN", "reconcile: row brought in line with the ledger", rid=rid, account=x["account_id"], row_status=st, receipt_verdict=v, outcome=out)
        if out in ("denied", "approved", "refused"):
            cut_previews(ctx, rid)
    return out


def reconcile_on_start(ctx, window_s=None):
    """rel 28.10: on start, every recent held / pending_approval row whose id the ledger already judged is brought in line (reconcile_row).
    One account at a time under its hub.lock; a failing account is logged and skipped (the start never stops on it). -> {outcome: count}."""
    t = now()
    w = RECONCILE_WINDOW_S if window_s is None else window_s
    rows = ctx.db.q("SELECT rid, account_id FROM actions WHERE status IN ('held','pending_approval') AND mandate_id IS NOT NULL AND "
                    "COALESCE(expires, created_at, 0) >= ? AND COALESCE(reconcile,'') NOT LIKE 'manual:%' ORDER BY account_id", (t - w,))
    nman = ctx.db.one("SELECT COUNT(*) AS n FROM actions WHERE status IN ('held','pending_approval') AND mandate_id IS NOT NULL AND "
                      "COALESCE(expires, created_at, 0) >= ? AND COALESCE(reconcile,'') LIKE 'manual:%'", (t - w,))["n"]
    if nman:
        log("INFO", "reconcile on start: rows already marked manual are skipped", manual=nman)
    by = {}
    for r in rows:
        by.setdefault(r["account_id"], []).append(r["rid"])
    out = {}
    for aid, rids in by.items():
        try:
            a = ctx.db.one("SELECT erased_at FROM accounts WHERE id=?", (aid,))
            if a is None or a["erased_at"] is not None or not ctx.hub.has_entries(aid):
                continue
            with ctx.hub.lock(aid):
                L = ctx.hub.ledger(aid)
                L.sync_now()
                for rid in rids:
                    x = ctx.db.one("SELECT * FROM actions WHERE rid=?", (rid,))
                    if x is None:
                        continue
                    k = reconcile_row(ctx, L, x)
                    out[k] = out.get(k, 0) + 1
        except Exception as e:  # noqa: BLE001
            log("ERROR", "reconcile on start failed for an account", account=aid, error=type(e).__name__)
            out["error"] = out.get("error", 0) + 1
    if any(k != "ok" for k in out):
        log("WARN", "reconcile on start", **{k.replace(":", "_"): n for k, n in out.items()})
    return out


def approve_with_envelope(ctx, acc, rid, approved, env, counted=False, view=None, view_fn=None, dry=False):
    """The ONE approval path (single wa-sig, quorum wq, batch wb; task 02 calls it per item of a batch). -> {"verdict": "allow"|"refused"}.
    Checks BEFORE Ledger.approve what the core cannot: with an org policy, the requirements of the approval rules for THIS action
    (class, amount) and that a wq names the policy in force. Solo account (no policy): exactly 0.1 (wa-sig of the pinned key, or wb).
    0.2.20: the signature counters of the envelope are checked and stored before the ledger entry; counted=True when they already were
    (a wq the server assembled from signatures counted one by one in org.sign_request; the items of one wb after the first, flow/batch).
    pv2810: view = the presentation hash (32 bytes) the page signed, or None (an older page).
    pv2: view_fn = the check of the claimed view against the rows (api_web._view_match), run HERE under hub.lock, after the request is
    known to be waiting and before anything is verified or written: the view compared is the view of the rows this decision is
    written from (no window between the check and the entry).
    04.11 (red team p.3): dry=True runs every check of this decision (waiting, signer, delegation, device level, signature, policy) and
    writes nothing: the batch of ONE tool call's parts checks all of them before the first entry (all or nothing)."""
    with ctx.hub.lock(acc["id"]):
        x, L, rc, M = _pending(ctx, acc, rid)
        if view_fn is not None:
            view = view_fn()
        payload = approval_payload(M, rc["action"], rid, approved, view)
        kind = wq.envelope_kind(env) if looks_like_envelope(env) else None
        cur = org.current_policy(ctx, acc["id"])
        action = {"class": rc["action"].get("class"), "amount": rc["action"].get("amount")}
        rp = org.rp(ctx)
        if kind is None:
            raise Err(409, "WA_MALFORMED")
        org.refuse_revoked(ctx, env)                 # 0.2.2: a removed passkey never counts, even inside a client-built wq
        kids = levels.env_kids(env)
        signer_users, behalf = delegation.check_approval(ctx, acc["id"], x["agent_id"], kids, approved, rc["action"])     # 0.2.13: no self-approval (Team)
        if approved:
            levels.check_signers(ctx, acc["id"], kids, rc["action"], x["reason"], x["level_min"])        # 0.2.13: a laptop key never confirms a phone action
        if cur is None:
            if kind == "wq":
                raise Err(409, "WQ_POLICY_UNKNOWN", "the organisation has no policy")
            entry = ctx.hub.active_keys(acc["id"]).get(org.env_kid(env))       # 0.2.2: any ACTIVE passkey of the account
            if entry is None:
                raise Err(409, "KEY_MISMATCH")
            code = wa.verify_envelope(env, wa.TYP_APPROVAL, payload, entry) if kind == "wa" else \
                wq.verify_wb(env, wa.TYP_APPROVAL, payload, entry)
            if code:
                raise Err(409, code, STALE_PAGE_TEXT if code == "APPROVAL_SIG" else "")
        else:
            pol, pb, h = cur
            if kind == "wa":                     # one member's plain wa-sig = a wq with one wsig under the policy in force
                if cbor2.loads(env).get("kid") not in {m["kid"] for m in pol["members"]}:
                    raise Err(409, "WQ_NOT_MEMBER")
                env, kind = org.wrap_single(env, h), "wq"
            if kind == "wq":
                code = wq.verify_wq(env, wa.TYP_APPROVAL, payload, [(pb, None, None)], action=action if approved else None, rp=rp,
                                    agent=x["agent_id"] if approved else None)        # 0.2.15: rules.delegation of the signed policy
                if code is None and not approved:
                    reqs = wq.requirements(pol, wa.TYP_APPROVAL, None, action)
                    mem = {m["kid"]: m for m in pol["members"]}
                    signers = [w["kid"] for w in cbor2.loads(env)["sigs"]]
                    if reqs and not any(r in mem[k]["roles"] for k in signers for r, _ in reqs):
                        code = "WQ_QUORUM"
            else:
                kid = cbor2.loads(env).get("kid")
                who = {m["kid"]: m for m in pol["members"]}.get(kid)
                code = wq.verify_wb(env, wa.TYP_APPROVAL, payload, who, rp=rp) if who else "WQ_NOT_MEMBER"
                code = code or wq.wb_requirements_met(pol, kid, action) or (wq.delegation_code(pol, x["agent_id"], [kid]) if approved else None)
            if code:
                raise Err(409, code)
        if dry:
            return None
        if not counted:
            org.check_sign_counts(ctx, env, "approve" if approved else "refuse", acc["id"])      # 0.2.20
        res = L.approve(rid, cose_bytes=env, approved=approved, issue_aar=True, view=view)
        if res["result"] != "accept":
            raise Err(409, res["reason"])
        t = now()
        org.touch_kids(ctx, kids)                      # 0.2.19: approve / refuse = the passkey was used (devices: "Last used")
        try:                                           # rel 28.10: the rows of one decision in ONE transaction (all or nothing)
            pj = proof_json(L.receipt_proof(rid, approval=True), approval=env) if approved else None
            with ctx.db.tx():
                _store_approval(ctx, acc["id"], rid, approved, env, L.aseq.get(rid), t, json.dumps(signer_users), behalf,
                                view.hex() if view else None, res.get("aar"), pj)
                if approved:
                    execguard.on_allowed(ctx, x)          # 0.2.13: an approved write to an executed file marks it dirty (same tx as the decision)
        except Exception as e:  # noqa: BLE001 -- the APPROVAL entry is in the ledger: a retry or the next start brings the row in line
            log("ERROR", "approve: ledger written, row not; reconciled on retry / at the next start", rid=rid, account=acc["id"],
                error=type(e).__name__)
            raise Err(503, "DECISION_NOT_STORED", "the witness recorded the decision but could not store it; send it again")
        if not approved:
            out = {"verdict": "refused"}
            for z in ctx.db.q("SELECT rid FROM actions WHERE line_lead=? AND status='pending_approval'", (rid,)):
                cancel_unasked(ctx, z["rid"], "REFUSED")        # 04.11 (L3): the other parts of the same call were asked with this one
        else:
            out = {"verdict": "allow"}
        cut_previews(ctx, rid)                            # 0.2.24 (critique B): decided -> hash + short excerpt
    _decided_row(ctx, x["agent_id"], rid)
    if approved:
        stats.first(ctx, acc["id"], "first_approval")     # 0.2.28: the first passkey approval of the account
        if "via" in x.keys() and x["via"] == "hook":
            trial.count_touch(ctx, acc["id"])             # 0.2.38: a human touch on a real call of the Claude Code hook (04.11 count)
    return out


def do_approve(ctx, acc, user_id, rid, approved, env, repeat=None, view=None, view_fn=None):
    """POST /api/approvals/{rid}. Solo account: the wa-sig decides at once (0.1). With a policy: the wa-sig of a member goes into the
    signature request of this action; at quorum the wq is handed to approve_with_envelope. -> {"verdict": allow|refused|collecting, ...}.
    pv2: view_fn (see approve_with_envelope) is run under hub.lock on every path: one approval, a team's request, later runs."""
    if repeat is not None:                                  # 0.2.29: approve now and the same call in later runs (one wb)
        if approved is not True:
            raise Err(400, "BAD_REQUEST", "only an approval can be given for later runs")
        return rpt.create(ctx, acc, user_id, rid, env, repeat, view_fn=view_fn)
    if org.current_policy(ctx, acc["id"]) is None or wq.envelope_kind(env) != "wa":
        return approve_with_envelope(ctx, acc, rid, approved, env, view=view, view_fn=view_fn)
    with ctx.hub.lock(acc["id"]):
        x, L, rc, M = _pending(ctx, acc, rid)
        if view_fn is not None:
            view = view_fn()
        # pv2: the team's request names the view of the page that opened it; every signer's page must show the same view
        payload = approval_payload(M, rc["action"], rid, approved, view)
        sid = org.approval_request(ctx, acc, user_id, rid, approved, payload, rc["action"], x["expires"], view=view,
                                   view_current=view_fn is not None)   # pvh: a stale request is replaced only on a checked view
        p = org.sign_request(ctx, acc, user_id, sid, env)
        sm = json.loads((ctx.db.one("SELECT meta FROM sig_requests WHERE id=?", (sid,)) or {"meta": None})["meta"] or "{}")
    out = {"verdict": p["verdict"] if p["status"] == "done" else "collecting", "req_id": sid, "have": p["have"], "need": p["need"]}
    if sm.get("replaces"):                                  # RT-SUP 29.10: this signature opened a request that replaced one (the view changed)
        out.update(replaced=sm["replaces"], dropped=sm.get("dropped") or [], why="view_changed")
    return out


def _decided_row(ctx, agent_id, rid):
    a = ctx.db.one("SELECT * FROM agents WHERE id=?", (agent_id,))
    if a is not None:
        _decided(ctx, a, {"rid": rid})


def register_mandate(ctx, acc, m, env, toolmap_sha256=None, guards=None, counted=False):
    """Record a signed mandate (wa-sig of a solo account, or wq) in the ledger and the index; supersedes the agent's active one.
    m is the JSON (wire) form: `toolmap_sha256` (0.2.4) is 64 hex here and `bstr .size 32` in the signed CBOR. When it is present the server recomputes the gateway
    document (tool map + protected literals + advisor mode) and requires its hash to be the signed value (409 TOOLMAP_CHANGED); the document is stored with the row.
    -> {mandate_id, status, ledger_seq, toolmap_sha256}."""
    m = wire.wire_form(m)           # a quorum request carries the CBOR map (bytes): the same member in its JSON form
    mc = wire.cbor_form(m) if isinstance(m, dict) else m
    if not isinstance(mc, dict) or validate_mandate(mc) or _has_float(mc):
        raise Err(409, "MANDATE_MALFORMED")
    if m.get("principal") != acc["principal"]:
        raise Err(409, "MANDATE_PRINCIPAL")
    ag = ctx.db.one("SELECT * FROM agents WHERE id=? AND account_id=?", (m.get("agent"), acc["id"])) if isinstance(m.get("agent"), str) else None
    if not ag:
        raise Err(404, "NOT_FOUND")
    toolmap = json.loads(ag["toolmap_json"])
    th = tm.toolmap_hash(toolmap)
    if toolmap_sha256 is not None and toolmap_sha256 != th:
        raise Err(409, "TOOLMAP_CHANGED", "the tool map changed after the draft; draft again")
    with ctx.hub.lock(acc["id"]):
        gp, ga = guard_hashes(ctx, acc["id"])
        if guards is not None and list(guards) != [gp, ga]:
            raise Err(409, "DATA_PATTERNS_CHANGED", "the protected data or the advisor mode changed after the draft; draft again")
        doc = None
        claimed = m.get(wire.KEY)
        if claimed is None:                     # 0.2.5 (R4-04): a NEW mandate always binds the gateway document; only mandates recorded before 0.2.4 keep the old rule
            raise Err(409, "MANDATE_OLD_FORM", "the mandate must carry toolmap_sha256 (draft the mandate again)")
        if claimed is not None:                 # 0.2.4: the map hash is inside the signature; it must be the hash of the document the server holds NOW
            if not isinstance(mc.get(wire.KEY), bytes):
                raise Err(409, "MANDATE_MALFORMED")
            doc = gateway_doc(ctx, acc["id"], toolmap)
            if gateway_hash(doc) != claimed:
                raise Err(409, "TOOLMAP_CHANGED", "the tool map, the protected data or the advisor mode changed after the draft; draft again")
        if ctx.db.one("SELECT 1 AS k FROM mandates WHERE id=? AND account_id<>?", (m["id"], acc["id"])):      # R-06: ids are global
            raise Err(409, "MANDATE_ID_TAKEN")
        if not counted:                                       # 0.2.20 (a quorum's signatures were counted in org.sign_request)
            org.check_sign_counts(ctx, env, "mandate", acc["id"])
        L = ctx.hub.ledger(acc["id"])
        res = L.register_mandate(mc, cose_bytes=env)          # CDE is rebuilt by the core from the presented map
        if res["result"] != "accept":
            raise Err(409, res["reason"])
        seq = L.S.nseq - 1
        with ctx.db.tx():
            ctx.db.x("UPDATE mandates SET status='superseded' WHERE agent_id=? AND status='active'", (m["agent"],))
            ctx.db.x("INSERT INTO mandates(id,account_id,agent_id,mandate_json,envelope,status,ledger_seq,created_at,toolmap_sha256,patterns_sha256,advisor_sha256,patterns_items,gateway_doc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (m["id"], acc["id"], m["agent"], json.dumps(m), env, "active", seq, now(), th, gp, ga, json.dumps(pattern_items(ctx, acc["id"])),
                      json.dumps(doc) if doc is not None else None))
            ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE account_id=? AND kind='mandate' AND ref=? AND status='collecting'", (acc["id"], m["id"]))
    stats.first(ctx, acc["id"], "mandate")                     # 0.2.28
    return {"mandate_id": m["id"], "status": "active", "ledger_seq": seq, "toolmap_sha256": th, "gateway_sha256": claimed}


def mandate_envelope(ctx, acc, typ, payload, env):
    """With a policy the ledger gets a wq naming the policy IN FORCE (2.4): a member's wa-sig is wrapped, a client-built wq is checked
    against the current version only (an older or unknown one -> WQ_POLICY_UNKNOWN). Solo account: the envelope as is."""
    cur = org.current_policy(ctx, acc["id"])
    kind = wq.envelope_kind(env) if looks_like_envelope(env) else None
    org.refuse_revoked(ctx, env)                     # 0.2.2
    if cur is None:
        if kind == "wq":
            raise Err(409, "WQ_POLICY_UNKNOWN", "the organisation has no policy")
        return env
    pol, pb, h = cur
    if kind == "wa":
        if cbor2.loads(env).get("kid") not in {m["kid"] for m in pol["members"]}:
            raise Err(409, "WQ_NOT_MEMBER")
        env = org.wrap_single(env, h)
    elif kind != "wq":
        raise Err(409, "WQ_MALFORMED")
    code = wq.verify_wq(env, typ, payload, [(pb, None, None)], rp=org.rp(ctx))
    if code:
        raise Err(409, code)
    return env


def revoke(ctx, acc, rowm, env):
    """Revocation: any ONE signer (0 p.3). -> {"mandate_id", "status": "revoked"}."""
    with ctx.hub.lock(acc["id"]):
        if rowm["status"] != "active":
            raise Err(409, "MANDATE_NOT_ACTIVE")
        m = json.loads(rowm["mandate_json"])
        env = mandate_envelope(ctx, acc, wa.TYP_REVOCATION, revocation_payload(wire.cbor_form(m)), env)
        org.check_sign_counts(ctx, env, "revoke", acc["id"])          # 0.2.20
        L = ctx.hub.ledger(acc["id"])
        res = L.revoke(m["id"], cose_bytes=env)
        if res["result"] != "accept":
            raise Err(409, res["reason"])
        ctx.db.x("UPDATE mandates SET status='revoked' WHERE id=?", (m["id"],))
    return {"mandate_id": m["id"], "status": "revoked", "ledger_seq": L.S.nseq - 1}


def release(ctx, acc, user_id, rid, rel, env, view=None, view_fn=None):
    """4.2: a human decides an item held by the advisor with a wa-sig (typ dw-release) over {rid, args_sha256, release}.
    release -> ordinary authorize (the core decides, `adv` records the release); reject -> deny ADVISORY_REJECTED (no ledger entry)."""
    with ctx.hub.lock(acc["id"]):
        x = own_account_action(ctx, acc, rid)
        if x["status"] != "held":
            raise Err(409, "NOT_HELD")
        if rel:
            # held 28.10: a held row is written WITHOUT a ledger entry (do_action); the release is the core's first judgement of this id.
            # A receipt already in the ledger means the row and the ledger disagree (a crash between L.authorize and the row update of an
            # earlier release; a row set to held by hand): L.authorize would raise DUPLICATE_RECEIPT_ID (500) AFTER the release request
            # was stored as done. Refused here, before anything is written; nothing runs. Reject stays possible (it only denies the row).
            L0 = ctx.hub.ledger(acc["id"])
            L0.sync_now()
            if rid in L0.S.receipts:
                log("ERROR", "release refused: held row already has a ledger receipt", rid=rid, account=acc["id"],
                    receipt_verdict=L0.S.receipts[rid].get("verdict"))
                raise Err(409, "HELD_ALREADY_JUDGED", "the witness already recorded a decision for this action; it cannot be released "
                          "again -- reject it, and the agent asks anew")
        if view_fn is not None:
            view = view_fn()                        # pv2: under hub.lock, atomic with the decision (see approve_with_envelope)
        a = wire.cbor_form(json.loads(x["action_json"]))
        try:
            payload = wq.release_payload(rid, a["args_sha256"], rel, view)        # pv2810: view = the presentation hash, or None
        except Exception:
            raise Err(409, "RELEASE_MALFORMED")
        if wq.envelope_kind(env) != "wa":
            raise Err(409, "WA_MALFORMED")
        kid = org.env_kid(env)                      # 0.2.2: the passkey that signed (one of the user's ACTIVE passkeys)
        entry = org.user_entry(ctx, user_id, kid)
        if entry is None:
            raise Err(409, "KEY_MISMATCH", "sign with one of your active passkeys")
        cur = org.current_policy(ctx, acc["id"])
        if cur is not None:
            if kid not in {m["kid"] for m in cur[0]["members"]}:
                raise Err(409, "WQ_NOT_MEMBER")
        elif kid not in ctx.hub.active_keys(acc["id"]):
            raise Err(409, "KEY_MISMATCH", "only the owner's passkeys decide for a solo account")
        code = wa.verify_envelope(env, wq.TYP_RELEASE, payload, entry)
        if code:
            raise Err(409, "RELEASE_SIG" if code == "MANDATE_SIG" else code)
        org.touch_kids(ctx, [kid])                # 0.2.19
        # 0.2.14 (R8-07): a release lets the action go exactly like an approval does -> the same two checks as approve_with_envelope
        delegation.check_approval(ctx, acc["id"], x["agent_id"], [kid], bool(rel), json.loads(x["action_json"]))        # no self-release by the agent's operator (Team)
        if rel and cur is not None:
            dc = wq.delegation_code(cur[0], x["agent_id"], [kid])       # 0.2.15: and the signed policy's delegation
            if dc:
                raise Err(409, "SELF_APPROVAL" if dc == "WQ_SELF" else "NOT_DELEGATE")
        if rel:
            levels.check_signers(ctx, acc["id"], [kid], json.loads(x["action_json"]), x["reason"], x["level_min"])   # a laptop key never releases a phone action
        org.check_sign_counts(ctx, env, "release", acc["id"])         # 0.2.20 (a gate: kept before the core; a resent identical signature passes, 0.2.21)
        # rel 28.10: the release request (status done) is stored only AFTER the core decided, in ONE transaction with the row: an exception of
        # the core leaves nothing (no "done" release in the pack, export.py), a failed row write leaves no done request either.
        smeta = {"release": rel, "by": user_id, **({"view": view.hex()} if view else {})}
        wsig = org._sigs_json([wq.wsig_of_wa(env)])
        t = now()
        if not rel:
            with ctx.db.tx():
                _store_release(ctx, acc["id"], rid, payload, cur, smeta, wsig)
                ctx.db.x("UPDATE actions SET status='denied', verdict='deny', reason='ADVISORY_REJECTED', updated_at=? WHERE rid=?", (t, rid))
        else:
            if "adv" in a:                     # 4.2: "<mode>-1:<label>:released:<kid 8 hex>" (label/mode the advisor recorded at hold time)
                label, mode = advisor.held_mark(ctx, a["args_sha256"], acc["id"]) if advisor else (None, None)
                a["adv"] = advisor.adv_released(mode, label, kid) if advisor else \
                    (a["adv"] + ":" if a["adv"] else "") + "released:" + kid[:4].hex()
            row = {"rid": rid}
            L = ctx.hub.ledger(acc["id"])
            try:
                _authorize_row(ctx, L, row, x["mandate_id"], a, _ttl(ctx, acc["id"], L.S.decide_for(x["mandate_id"], a, L.sync_now())[1]))
            except Exception as e:  # noqa: BLE001 -- the core did not decide: nothing of the release is stored
                log("ERROR", "release: the core raised; nothing stored", rid=rid, account=acc["id"], error=type(e).__name__,
                    in_ledger=rid in L.S.receipts)
                raise Err(503, "DECISION_NOT_STORED", "the witness could not record the decision; nothing was released")
            try:
                with ctx.db.tx():
                    _store_release(ctx, acc["id"], rid, payload, cur, smeta, wsig)
                    ctx.db.x("UPDATE actions SET verdict=?, reason=?, status=?, expires=?, aar=?, action_json=?, request_hash=?, updated_at=?, promise=? WHERE rid=?",
                             (row["verdict"], row["reason"], row["status"], row["expires"], row.get("aar"), json.dumps(wire.wire_form(a), ensure_ascii=False),
                              request_hash(a), t, row.get("promise"), rid))
                    if row["verdict"] == "allow":
                        execguard.on_allowed(ctx, x)      # 0.2.13: a released write to an executed file marks it dirty (same tx as the decision)
            except Exception as e:  # noqa: BLE001 -- the ledger has the receipt, the row does not: held stays held (Release -> 409), start reconciles
                log("ERROR", "release: ledger written, row not; reconciled at the next start", rid=rid, account=acc["id"], error=type(e).__name__,
                    receipt_verdict=row.get("verdict"))
                raise Err(503, "DECISION_NOT_STORED", "the witness recorded the decision but could not store it; nothing runs until it is "
                          "reconciled")
        y = refresh(ctx, rid)
        if y["status"] not in WAITING:
            cut_previews(ctx, rid)                    # 0.2.24 (critique B)
    _decided_row(ctx, y["agent_id"], rid)
    if rel and "via" in x.keys() and x["via"] == "hook":
        trial.count_touch(ctx, acc["id"])                 # 0.2.38: a release of a held hook call is a human touch too
    return {"status": y["status"], "verdict": to_result(ctx, y)["verdict"], "reason": y["reason"]}


def _store_release(ctx, aid, rid, payload, cur, smeta, wsig):
    """rel 28.10: the release request of a decided held item (kind release, status done). Caller: inside ctx.db.tx(), after the core."""
    sid = org.new_request(ctx, aid, "release", rid, wq.TYP_RELEASE, payload, cur[2] if cur else None, [("any", 1)], smeta)
    ctx.db.x("UPDATE sig_requests SET sigs=?, status='done' WHERE id=?", (wsig, sid))
    return sid


def _has_float(x):
    if isinstance(x, float):
        return True
    if isinstance(x, dict):
        return any(_has_float(v) for v in x.values())
    if isinstance(x, list):
        return any(_has_float(v) for v in x)
    return False


# r0292 (owner 13.11, p.5): a person who is not an owner (a Viewer, an Approver) freezes at most FREEZE_RATE_N times per FREEZE_RATE_S
# (counted from the durable journal agent_freezes, so a restart does not reset it). The owner is never limited: the owner can always stop.
FREEZE_RATE_N = 5
FREEZE_RATE_S = 3600


def freeze(ctx, acc, user_id, agent_id, kind="freeze", limited=False):
    """0.2.24 (critique T2, approval bombing): one passkey touch stops an agent. Every request of it that waits for a person (pending_approval,
    held) is cancelled (denied AGENT_FROZEN: nobody can approve it any more; the ledger receipt simply expires unapproved), an approved one can no
    longer be presented, and every new call is denied AGENT_FROZEN until the owner unfreezes it. Journal: table agent_freezes + the log."""
    with ctx.hub.lock(acc["id"]):
        t = now()
        if limited and ctx.db.one("SELECT COUNT(*) AS n FROM agent_freezes WHERE account_id=? AND by_user=? AND t>? AND kind IN ('freeze','freeze-again')",
                                  (acc["id"], user_id, t - FREEZE_RATE_S))["n"] >= FREEZE_RATE_N:
            raise Err(429, "FREEZE_RATE", "you froze %d agents in the last hour: ask an owner (owners are not limited)" % FREEZE_RATE_N)
        first = ctx.db.n("UPDATE agents SET frozen_at=? WHERE id=? AND account_id=? AND frozen_at IS NULL", (t, agent_id, acc["id"]))
        rids = [r["rid"] for r in ctx.db.q("SELECT rid FROM actions WHERE agent_id=? AND status IN ('pending_approval','held')", (agent_id,))]
        for rid in rids:
            ctx.db.x("UPDATE actions SET status='denied', verdict='deny', reason='AGENT_FROZEN', updated_at=? WHERE rid=? AND status IN ('pending_approval','held')",
                     (t, rid))
            ctx.db.x("UPDATE sig_requests SET status='superseded' WHERE account_id=? AND ref=? AND status='collecting'", (acc["id"], rid))
            cut_previews(ctx, rid)
        ctx.db.x("INSERT INTO agent_freezes(account_id,agent_id,kind,t,by_user,cancelled) VALUES(?,?,?,?,?,?)",
                 (acc["id"], agent_id, kind if first else kind + "-again", t, user_id, len(rids)))
        a = ctx.db.one("SELECT frozen_at FROM agents WHERE id=?", (agent_id,))
    log("info", "agent frozen", agent=agent_id, cancelled=len(rids), kind=kind)
    return {"agent_id": agent_id, "frozen_at": a["frozen_at"], "cancelled": len(rids)}


def unfreeze(ctx, acc, user_id, agent_id):
    with ctx.hub.lock(acc["id"]):
        t = now()
        k = ctx.db.n("UPDATE agents SET frozen_at=NULL WHERE id=? AND account_id=? AND frozen_at IS NOT NULL", (agent_id, acc["id"]))
        if k:
            ctx.db.x("INSERT INTO agent_freezes(account_id,agent_id,kind,t,by_user,cancelled) VALUES(?,?,?,?,?,?)",
                     (acc["id"], agent_id, "unfreeze", t, user_id, 0))
    if k:
        log("info", "agent unfrozen", agent=agent_id)
    return {"agent_id": agent_id, "frozen_at": None, "changed": bool(k)}


def freeze_journal(ctx, account_id, agent_id, limit=50):
    return [dict(r) for r in ctx.db.q("SELECT kind, t, by_user, cancelled FROM agent_freezes WHERE account_id=? AND agent_id=? ORDER BY t DESC, id DESC LIMIT ?",
                                     (account_id, agent_id, limit))]


def auto_freeze_check(ctx, agent, t0):
    """0.2.25 (critique T2): N APPROVAL_RATE refusals (0.2.26: of N different requests) of one agent within M minutes -> the agent is frozen like the owner's button does (its
    waiting requests are cancelled, new calls denied AGENT_FROZEN) with journal kind "auto". Only the owner unfreezes it (passkey).
    Returns the freeze result or None."""
    n = getattr(ctx.cfg, "autofreeze_n", None)
    n = AUTOFREEZE_N if n is None else n
    if n <= 0:
        return None
    win = 60 * (getattr(ctx.cfg, "autofreeze_min", None) or AUTOFREEZE_MIN)
    from app.flow import rate as _rate
    if not _rate.can_hear(ctx, agent):
        return None                                      # 0.2.90 (L2 chel01, p.1): refusals nobody was told about are not a flood on the owner
    # 0.2.26 (P3): DISTINCT requests. A run that retries the call refused behind its own unanswered requests (often left by an earlier run)
    # asks the owner nothing new and is not a flood; a flood of new questions is many different requests and is counted as before
    k = ctx.db.one("SELECT COUNT(DISTINCT COALESCE(request_hash, rid)) AS n FROM actions WHERE agent_id=? AND reason='APPROVAL_RATE' AND created_at>?",
                   (agent["id"], t0 - win))["n"]
    if k < n:
        return None
    a = ctx.db.one("SELECT frozen_at FROM agents WHERE id=?", (agent["id"],))
    if a is not None and a["frozen_at"]:
        return None
    r = freeze(ctx, {"id": agent["account_id"]}, None, agent["id"], kind="auto")
    log("WARN", "agent frozen automatically", agent=agent["id"], refusals=k, window_min=win // 60)
    if getattr(ctx, "notify", None) is not None:
        ctx.notify.frozen(agent["account_id"], agent["id"], k, win // 60)
    return r


def frozen_kind(ctx, agent_id):
    """The journal kind of the freeze in force ("freeze" | "auto"), or None."""
    r = ctx.db.one("SELECT kind FROM agent_freezes WHERE agent_id=? ORDER BY t DESC, id DESC LIMIT 1", (agent_id,))
    if r is None or r["kind"] == "unfreeze":
        return None
    return r["kind"].replace("-again", "")
