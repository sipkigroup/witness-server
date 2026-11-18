"""0.2.16: POST /v1/hook/judge - the thin Claude Code hook sends RAW facts, the witness classifies and decides.

Request (agent key):
  {"v": 1,
   "event":  the PreToolUse event as Claude Code gave it (tool_name, tool_input as is, cwd),
   "facts":  {"home": the hook's ~, "proc_cwd": the hook's os.getcwd(), "env": {CLAUDE_PROJECT_DIR, HOME, DEUS_WITNESS_EXEC_SCAN},
              "fs": {"realpath": {path: realpath | null (unresolvable)}, "isdir": {path: bool}, "exists": {path: bool},
                    "gitref": {"<top>\n<ref>": null | {"commit", "paths", "more", "special"}} (0.2.53, hook 0.2.37+),
                    "samefile": {path: credential file it is a hard link of}, "archive": {path: null | {"links", "more"}} (0.2.73, hook 0.2.49+)},
              "exec": the fingerprint report of the project ({root, files, git, truncated, rev}) | "off" | null},
   "client": {"name", "version"},
   "part":   null | index (re-judge only that part, after the owner answered with a project allowance),
   "nonce":  0.2.17 (R9-01): a fresh random string of the hook for this call (>= 128 bits; base64url, 22..86 characters)}
Answer, one of:
  {"v": 1, "need": {"realpath": [...], "isdir": [...], "exists": [...], "gitref": [[top, ref], ...], "archive": [...], "scan": root}, "scan_rev": rev}
        the classifier asked something the facts do not answer: the hook adds the answers and sends again (the server keeps no state);
        0.2.43b: also {"preview": [absolute paths]} (only to a hook with client.caps "preview", once per call): changed executed files the
        witness could not read; the hook answers facts.exec.preview (masked text <= 4 KB per file, execguard.previews_of);
  {"v": 1, "refuse": code, "detail": str, "texts": {...}}
        the event cannot be judged (EVENT_MALFORMED, RESERVED_KEY, EVENT_TOO_LARGE, HOOK_ERROR): the hook denies;
  {"v": 1, "n_parts": n, "parts": [{"i", "tool", "args", "summary", "result": ActionResult, "why": text}], "texts": {code: [kind, text]},
   "statement_b64": COSE_Sign1 (witness key, typ TYP_STATEMENT) of the statement below}
        each part was put through the core exactly as POST /v1/actions does (same args, same receipt, same ledger). The hook verifies
        every receipt against the pinned witness key, checks that the judged args are its own tool_input plus the server's `_witness`,
        consumes (present) and answers Claude Code.
0.2.17 (R9-01): the SET of parts is signed and bound to the request. The statement (canonical CBOR) is
  {"v": "dw-judge-1", "nonce": the hook's nonce, "request_sha256": SHA-256 of the canonical JSON of the request body (request_sha256()),
   "part": null | index, "n_parts": n, "parts": [wire tool of every part, in order],
   "judged": [{"i", "tool", "args_sha256", "rid", "verdict", "status", "reason"} of every part judged, in order], "t": seconds}.
  The hook accepts the answer only when the statement verifies against the pinned key, carries its own nonce and the hash of exactly the
  body it sent, and every part is judged (or the last judged one refused the line); a part list that was cut, reordered or replayed from
  another call is denied.
Classification is the 0.2.15 hook's code (bashparse / mapping / execfiles), run against the user's file system through the facts (fs.py)."""
from __future__ import annotations

import time
import hashlib
import json
import re
import threading

from app.context import Err

from app import constitution

from . import execfiles, fs, mapping, reasons

ENV_KEYS = ("CLAUDE_PROJECT_DIR", "HOME", "DEUS_WITNESS_EXEC_SCAN", "TMPDIR")    # 0.2.93 (r0263): TMPDIR (client 0.2.61) for `$TMPDIR/x`
MAX_FACTS = 3 * fs.MAX_QUESTIONS
TYP_STATEMENT = "application/dw-hook-judge+cbor"
NONCE = re.compile(r"[A-Za-z0-9_-]{22,86}")
# 0.2.17 (R9-02): the price of one request. A Bash line longer than this is refused before the classifier runs (EVENT_TOO_LARGE: the hook
# denies), never seconds of CPU of the witness (parsing costs ~7 ms per KB, linear in the length). Measured: OTCHET-0.2.17.md.
MAX_CMD = 32 * 1024
WEIGHT_UNIT = 32 * 1024         # a request takes 1 + len(body) // WEIGHT_UNIT of the key's window
MAX_CONCURRENT = 2              # judge requests of one account classified at the same time; more wait (ENTER_WAIT_S), then 429
ENTER_WAIT_S = 5.0              # 0.2.18: how long a request waits for a slot; at most MAX_WAITING wait per account, the rest -> 429 at once
MAX_WAITING = 16                # r0285: was 2. A key brings at most main.PER_KEY_INFLIGHT (8) into the judge at once and an account has a few agents
#                                 (Claude Code + subagents: 10 calls at once each); waiting costs a coroutine and a parsed body, not a thread
_WAITING = {}
_RUNNING = {}
_RUNNING_LOCK = threading.Lock()


def weight(n_bytes: int) -> int:
    return 1 + max(0, int(n_bytes)) // WEIGHT_UNIT


def enter(account_id) -> bool:
    with _RUNNING_LOCK:
        if _RUNNING.get(account_id, 0) >= MAX_CONCURRENT:
            return False
        _RUNNING[account_id] = _RUNNING.get(account_id, 0) + 1
        return True


def wait_begin(account_id) -> bool:
    """0.2.18: may this request wait for a judge slot? (a burst of one account is answered 429 at once, as in 0.2.17)"""
    with _RUNNING_LOCK:
        if _WAITING.get(account_id, 0) >= MAX_WAITING:
            return False
        _WAITING[account_id] = _WAITING.get(account_id, 0) + 1
        return True


def wait_end(account_id) -> None:
    with _RUNNING_LOCK:
        n = _WAITING.get(account_id, 0) - 1
        if n > 0:
            _WAITING[account_id] = n
        else:
            _WAITING.pop(account_id, None)


def leave(account_id) -> None:
    with _RUNNING_LOCK:
        n = _RUNNING.get(account_id, 0) - 1
        if n > 0:
            _RUNNING[account_id] = n
        else:
            _RUNNING.pop(account_id, None)


def request_sha256(body) -> str:
    """The hook's binding of its request: SHA-256 of the canonical JSON (sorted keys, no spaces, ASCII) of the body as sent."""
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
# codes whose text the hook may need besides the ones of the parts (it builds them from a status or its own checks)
ALWAYS = ("APPROVAL_REFUSED", "RECEIPT_EXPIRED", "FILE_CHANGED", "REQUEST_MISMATCH", "HOOK_ERROR", "EVENT_MALFORMED", "EVENT_TOO_LARGE", "RESERVED_KEY")

_SCAN_LIST = None


def scan_list():
    global _SCAN_LIST
    if _SCAN_LIST is None:
        _SCAN_LIST = execfiles.scan_list()
    return _SCAN_LIST


def texts_for(codes) -> dict:
    out = {}
    for c in list(codes) + list(ALWAYS):
        if isinstance(c, str) and c in reasons.REASONS:
            out[c] = list(reasons.REASONS[c])
    return out


def _bad(detail):
    raise Err(400, "BAD_REQUEST", detail)


def _facts(body) -> dict:
    f = body.get("facts")
    if not isinstance(f, dict):
        _bad("facts (object) required")
    for k in ("home", "proc_cwd"):
        if not isinstance(f.get(k), str) or not f[k].startswith("/") or len(f[k]) > fs.MAX_PATH:
            _bad("facts.%s: an absolute path" % k)
    env = f.get("env") or {}
    if not isinstance(env, dict):
        _bad("facts.env: object")
    env = {k: v for k, v in env.items() if k in ENV_KEYS and isinstance(v, str)}
    sfs = f.get("fs") or {}
    if not isinstance(sfs, dict):
        _bad("facts.fs: object")
    n = 0
    clean = {}
    for kind, typ in (("realpath", (str, type(None))), ("isdir", bool), ("exists", bool)):
        d = sfs.get(kind) or {}
        if not isinstance(d, dict):
            _bad("facts.fs.%s: object" % kind)
        for k, v in d.items():
            if not isinstance(v, typ) or len(k) > fs.MAX_PATH or (isinstance(v, str) and len(v) > fs.MAX_PATH):
                _bad("facts.fs.%s: path -> %s" % (kind, "realpath" if kind == "realpath" else "bool"))
        n += len(d)
        clean[kind] = d
    if "gitref" in sfs:                              # 0.2.53: {"<top>\n<ref>": gitref.answer(...)}; absent = an older hook (not asked)
        g = sfs["gitref"] if sfs["gitref"] is not None else {}
        if not isinstance(g, dict):
            _bad("facts.fs.gitref: object")
        for k, v in g.items():
            if len(k) > fs.MAX_PATH + 1100 or not _gitref_value(v):
                _bad("facts.fs.gitref: <top>\\n<ref> -> null or {commit, paths, more, special}")
            n += 1 + (len(v.get("paths") or ()) if isinstance(v, dict) else 0)
        clean["gitref"] = g
    if "samefile" in sfs:                            # 0.2.73 (N13): {path: the credential file it is a hard link of}
        sf = sfs["samefile"] if sfs["samefile"] is not None else {}
        if not isinstance(sf, dict) or not all(isinstance(v, str) and 0 < len(v) <= fs.MAX_PATH and len(k) <= fs.MAX_PATH for k, v in sf.items()):
            _bad("facts.fs.samefile: path -> path")
        n += len(sf)
        clean["samefile"] = sf
    if "shadow" in sfs:                              # 0.2.90: {path: null | {copy, sha256, size} | {absent: true} | {failed: str}}
        sd = sfs["shadow"] if sfs["shadow"] is not None else {}
        if not isinstance(sd, dict) or not all(len(k) <= fs.MAX_PATH and _shadow_value(v) for k, v in sd.items()):
            _bad("facts.fs.shadow: path -> null or {copy, sha256, size} | {absent} | {failed}")
        n += len(sd)
        clean["shadow"] = sd
    if "archive" in sfs:                             # 0.2.73 (N13): {archive path: null or {links: [[hard|sym, name, target]], more}}
        ar = sfs["archive"] if sfs["archive"] is not None else {}
        if not isinstance(ar, dict) or not all(len(k) <= fs.MAX_PATH and _archive_value(v) for k, v in ar.items()):
            _bad("facts.fs.archive: path -> null or {links, more}")
        n += sum(1 + len(v["links"]) if isinstance(v, dict) else 1 for v in ar.values())
        clean["archive"] = ar
    if "sample" in sfs:                              # r0335: {path of a .env template: true | false | null} (samplefile.answer)
        sm = sfs["sample"] if sfs["sample"] is not None else {}
        if not isinstance(sm, dict) or len(sm) > 16 or not all(isinstance(k, str) and len(k) <= fs.MAX_PATH and (v is None or isinstance(v, bool))
                                                               for k, v in sm.items()):
            _bad("facts.fs.sample: path -> true, false or null")
        n += len(sm)
        clean["sample"] = sm
    if n > MAX_FACTS:
        raise Err(413, "BODY_TOO_LARGE", "too many file-system facts")
    ex = f.get("exec")
    if ex is not None and ex != "off" and not isinstance(ex, dict):
        _bad("facts.exec: object, \"off\" or null")
    out = {"home": f["home"], "proc_cwd": f["proc_cwd"], "env": env, "fs": clean, "exec": ex}
    wh = f.get("which")                              # 0.2.89 (client 0.2.57): {python tool named on the line: its realpath on Claude Code's PATH}
    if isinstance(wh, dict) and len(wh) <= 16 and all(isinstance(k, str) and WHICH_NAME.fullmatch(k) and (v is None or (
            isinstance(v, list) and 1 <= len(v) <= 2 and all(isinstance(x, str) and x.startswith("/") and len(x) <= fs.MAX_PATH for x in v)))
            for k, v in wh.items()):
        out["which"] = dict(wh)                      # malformed or absent = no fact: EXEC_CHANGED asks as before
    pg = f.get("prog")                               # r0338 (client r0338): the identity of the line's programs by their files (progid.fact)
    if _prog_fact(pg):
        out["prog"] = {"v": pg["v"], "w": dict(pg["w"]), "p": dict(pg["p"])}     # malformed or absent = no fact: judged by the name
    gs = f.get("git_self")                           # 0.2.95 (client 0.2.63): SHA-256 of the person's own git user.email (datarule.own_addresses)
    if isinstance(gs, list) and 0 < len(gs) <= 4 and all(isinstance(x, str) and re.fullmatch(r"[0-9a-f]{64}", x) for x in gs):
        out["git_self"] = list(gs)                   # malformed or absent = no fact: an address in the line is judged as before
    gh = f.get("git_head")                           # 0.2.96 (client 0.2.65): the project's git branch (.git/HEAD), ends a "from now on"
    if isinstance(gh, str) and 0 < len(gh) <= 256 and gh.isprintable():     # of the project on another branch (allowances.reset_stale)
        out["git_head"] = gh                         # malformed or absent = no fact: nothing ends
    hz = f.get("harness")                            # 0.2.91 (client 0.2.59, friction 04.11): what the hook's own lock K1 finds in this call (a
    if isinstance(hz, str) and 0 < len(hz) <= 4096:  # path or word of the agent's harness): the call is ASKED (agent-config), so the owner can
        out["harness"] = hz                          # approve it; before, the line was allowed here and the hook refused it with no button
        if f.get("harness_held") is True:            # 06.11 (law 2, client r0260): the hook found the words only where Claude Code's strict
            out["harness_held"] = True               # sandbox holds the place itself (heredoc / quoted text, Seatbelt-held paths); the
            #                                          witness drops the mark ONLY when it judges the line strict (mapping.py)
    if "sandbox" in f:                               # V3: the hook's view of Claude Code's sandbox; a malformed one counts as none (asked)
        from . import sandbox as _sb
        out["sandbox"] = f["sandbox"] if _sb.well_formed(f["sandbox"]) else None
    return out


WHICH_NAME = re.compile(r"[A-Za-z][A-Za-z0-9._+-]{0,31}")
_PROG_ZONES = frozenset({"sys", "proj", "tmp", "home", "other"})
_PROG_NAME = re.compile(r"[A-Za-z0-9_.+-]{1,64}")


def _prog_ident(v) -> bool:
    if v is None:
        return True
    if not isinstance(v, dict) or not set(v) <= {"path", "real", "link", "dev", "ino", "nlink", "size", "zone", "same"}:
        return False
    sm = v.get("same", [])
    return (all(isinstance(v.get(k), str) and v[k].startswith("/") and len(v[k]) <= fs.MAX_PATH for k in ("path", "real"))
            and v.get("zone") in _PROG_ZONES and isinstance(v.get("link", False), bool)
            and all(isinstance(v.get(k, 0), int) and not isinstance(v.get(k, 0), bool) and v.get(k, 0) >= 0 for k in ("dev", "ino", "nlink", "size"))
            and isinstance(sm, list) and len(sm) <= 128 and all(isinstance(x, str) and _PROG_NAME.fullmatch(x) for x in sm))


def _prog_fact(pg) -> bool:
    """r0338: {"v": 1, "w": {word: ident | null}, "p": {path: ident | null}} (progid.fact), at most 64 + 64 entries."""
    return (isinstance(pg, dict) and pg.get("v") == 1 and isinstance(pg.get("w"), dict) and isinstance(pg.get("p"), dict)
            and len(pg["w"]) <= 64 and len(pg["p"]) <= 64
            and all(isinstance(k, str) and 0 < len(k) <= 64 and _prog_ident(v) for k, v in pg["w"].items())
            and all(isinstance(k, str) and k.startswith("/") and len(k) <= fs.MAX_PATH and _prog_ident(v) for k, v in pg["p"].items()))


def _shadow_value(v) -> bool:
    if v is None:
        return True
    if not isinstance(v, dict):
        return False
    if set(v) == {"absent"}:
        return v["absent"] is True
    if set(v) == {"failed"}:
        return isinstance(v["failed"], str) and len(v["failed"]) <= 200
    return (set(v) == {"copy", "sha256", "size"} and isinstance(v["copy"], str) and 0 < len(v["copy"]) <= fs.MAX_PATH
            and isinstance(v["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", v["sha256"]) is not None
            and isinstance(v["size"], int) and not isinstance(v["size"], bool) and 0 <= v["size"] <= 2 ** 40)


def _archive_value(v) -> bool:
    if v is None:
        return True
    lk = v.get("links") if isinstance(v, dict) else None
    return (isinstance(v, dict) and set(v) == {"links", "more"} and isinstance(v["more"], bool) and isinstance(lk, list) and len(lk) <= 64
            and all(isinstance(x, list) and len(x) == 3 and x[0] in ("hard", "sym") and all(isinstance(y, str) and len(y) <= 1024 for y in x[1:])
                    for x in lk))


def _gitref_value(v) -> bool:
    if v is None:
        return True
    if not isinstance(v, dict) or not isinstance(v.get("commit"), bool):
        return False
    if not v["commit"]:
        return set(v) == {"commit"}
    ps, sp = v.get("paths"), v.get("special")
    return (set(v) == {"commit", "paths", "more", "special"} and isinstance(v["more"], bool)
            and isinstance(ps, list) and len(ps) <= 1000 and all(isinstance(p, str) and 0 < len(p) <= fs.MAX_PATH for p in ps)
            and isinstance(sp, list) and len(sp) <= 64 and all(isinstance(x, str) and len(x) <= fs.MAX_PATH + 64 for x in sp))


def _vk_rp(fx):
    """r0331 + r0338: the realpath facts the shadow vector reads -- the ones the witness asked, and the real file of every path word the
    hook reported a program identity for (progid: the file run, so `~/x.sh` is no longer "no fact of where it really is")."""
    out = dict(fx.rp) if isinstance(fx.rp, dict) else {}
    pg = getattr(fx, "prog", None)
    if isinstance(pg, dict):
        for k, v in (pg.get("p") or {}).items():
            if isinstance(v, dict) and isinstance(v.get("real"), str) and k not in out:
                out[k] = v["real"]
    return out


class _Facts(fs.FactsFS):
    """FactsFS + the revision of the fingerprint list: a report made with another list is not used (the hook re-fetches the list)."""

    def __init__(self, facts, rev):
        super().__init__(facts)
        r = self.report
        if isinstance(r, dict):
            self.report = {k: r[k] for k in ("root", "files", "git", "truncated", "none", "sizes", "gitcfg", "gitcfg_cut", "hookspath", "preview") if k in r} if r.get("rev") == rev else None

    def realpath(self, p):
        if p in self.rp and self.rp[p] is None:
            raise ValueError("the hook could not resolve this path")      # what os.path.realpath raised on the user's machine
        return super().realpath(p)


def too_costly(body) -> bool:
    """0.2.17 (R9-02): a Bash line the classifier would spend too long on (longer than MAX_CMD)."""
    ev = body.get("event")
    inp = ev.get("tool_input") if isinstance(ev, dict) else None
    cmd = inp.get("command") if isinstance(inp, dict) and isinstance(ev, dict) and ev.get("tool_name") == "Bash" else None
    return isinstance(cmd, str) and len(cmd) > MAX_CMD


import contextvars  # noqa: E402
_LAST_PLACE = contextvars.ContextVar("dw_last_place", default=None)    # r0262: the place classify_event saw (same request)


def classify_event(body: dict):
    """-> ("need", need) | ("refuse", code, detail) | ("parts", [Mapped])."""
    _LAST_PLACE.set(None)
    facts = _facts(body)
    if too_costly(body):
        return ("refuse", "EVENT_TOO_LARGE", "(a shell line longer than %d KB is not judged)" % (MAX_CMD // 1024))
    rev = scan_list()["rev"]
    fx = _Facts(facts, rev)
    from app import runctx as _runctx
    fx.sid = _runctx.session_of(body)                # 06.11 (law 2): the session's own temp folder (sandbox.in_temp)
    tok = fs.use(fx)
    try:
        try:
            env_ = facts["env"]
            if isinstance(env_, dict) and "TMPDIR" in env_ and "tmpdir" not in client_caps(body):
                # 0.2.94 (r0264, L3 12.11): a hook that does not say "tmpdir" (client 0.2.61) refuses the whole call HOOK_ERROR when asked
                # the realpath of <its TMPDIR>/x (not a word of its line, R9-05). For it $TMPDIR stays unknown: the 0.2.92 question.
                env_ = {k: v for k, v in env_.items() if k != "TMPDIR"}
            from . import bashparse as _bp_
            vtok_ = _bp_.vk_begin()                  # r0331: what the shadow vector reads of the line (decides nothing, asks no fact)
            try:
                parts = mapping.map_event(body.get("event"), home=facts["home"], env=env_)
            finally:
                vk_ = _bp_.vk_end(vtok_)
            try:                                     # r0262: where a written file's text is judged (strict_policy.PLACE, actions);
                ev_ = body.get("event") if isinstance(body.get("event"), dict) else {}      # never in `body` (its hash is signed)
                cwd_ = ev_.get("cwd") if isinstance(ev_.get("cwd"), str) else None
                # only what the hook already answered: never a new fact question (no extra round, the same parts as before)
                e_ = facts["env"] if isinstance(facts.get("env"), dict) else {}
                pr_ = e_.get("CLAUDE_PROJECT_DIR") if isinstance(e_.get("CLAUDE_PROJECT_DIR"), str) and e_["CLAUDE_PROJECT_DIR"].startswith("/") else cwd_
                rp_ = (lambda q: fx.rp[q] if isinstance(q, str) and isinstance(fx.rp.get(q), str) else q)
                _LAST_PLACE.set({"project": rp_(pr_) if isinstance(pr_, str) and pr_.startswith("/") else None, "home": facts["home"],
                                 "cwd": rp_(cwd_) if isinstance(cwd_, str) and cwd_.startswith("/") else None,
                                 "vk": vk_, "rp": _vk_rp(fx)})     # r0331: the vector's (shadow) only
            except Exception:      # noqa: BLE001
                _LAST_PLACE.set(None)
        except mapping.Refuse as e:
            if fx.complete():
                return ("refuse", str(e), "")
            parts = None
        except Exception as e:      # noqa: BLE001  the 0.2.15 hook denied HOOK_ERROR on any exception while mapping
            if fx.complete():
                # 0.2.17 (R9-04): the exception's name stays in the server log; the answer says nothing about the classifier's insides
                from app.log import log
                log("info", "hook judge: classifier error", error=type(e).__name__)
                return ("refuse", "HOOK_ERROR", "")
            parts = None
    finally:
        fs.reset(tok)
    if not fx.complete():
        if fx.n > fs.MAX_QUESTIONS:
            return ("refuse", "EVENT_TOO_LARGE", "(too many paths to resolve)")
        return ("need", fx.need())
    return ("parts", parts)


def _round(ctx, agent, kind, code=None):
    """0.2.17 (R9-04): a round without an action is counted (quota) and kept for the owner (per agent, GET /api/agents).
    0.2.18: the quota is checked again and the round taken under the account's lock (the same lock as every action of the account), so
    parallel rounds and actions never pass the quota; the round goes into the database buffer (one transaction per batch, db.RoundBuffer)."""
    from app import actions as act
    t = act.now()
    with ctx.hub.lock(agent["account_id"]):
        act.check_quota(ctx, agent, t)
        ctx.db.rounds.add(agent["account_id"], agent["id"], t, kind, code)


def rounds_view(ctx, agent_id, t0):
    """-> {need, refuse, suspicious} of the last 24 h, for the owner. Suspicious: many refusals, or many fact rounds that never ended in a
    judged call (someone probing what the classifier extracts from a line)."""
    n = {k: 0 for k in ("need", "refuse")}
    for r in ctx.db.q("SELECT kind, COUNT(*) AS n FROM hook_rounds WHERE agent_id=? AND t>? GROUP BY kind", (agent_id, t0 - 86400)):
        if r["kind"] in n:
            n[r["kind"]] = r["n"]
    acts = ctx.db.one("SELECT COUNT(*) AS n FROM actions WHERE agent_id=? AND created_at>?", (agent_id, t0 - 86400))["n"]
    n["suspicious"] = n["refuse"] >= 20 or (n["need"] >= 100 and n["need"] > 3 * acts)
    return n


def _args_sha256(tool, args, salt=None) -> str:
    """The binding of a judged call (toolmap.build_action's args_sha256), also for a refusal that built no action (TOOL_UNMAPPED ...).
    0.2.35: with the account salt (DW_ARGS_SALT) the same HMAC as toolmap._args_digest."""
    raw = json.dumps([tool, args], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8", "surrogatepass")
    if salt is not None:
        import hmac
        return hmac.new(salt, b"dw-args1\0" + raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


def client_caps(body) -> set:
    """0.2.43b: what the hook says it can (client.caps): "preview" (answers need.preview), "final" (marks its last long poll)."""
    c = body.get("client") if isinstance(body, dict) else None
    caps = c.get("caps") if isinstance(c, dict) else None
    return {x for x in caps if isinstance(x, str)} if isinstance(caps, list) else set()


def _preview_need(ctx, agent, body, parts):
    """0.2.43b: -> the paths to ask the hook a preview of (once: a body that carries facts.exec.preview is never asked again), or []."""
    ex = (body.get("facts") or {}).get("exec")
    if "preview" not in client_caps(body) or not isinstance(ex, dict) or "preview" in ex:
        return []
    from app import execguard
    out = []
    for m in parts:
        if m.tool in execguard.COMMAND_TOOLS:
            out += [p for p in execguard.blind_paths(ctx, agent["id"], m.tool, m.args) if p not in out]
    return out[:execguard.MAX_PREVIEWS]


def statement(ctx, body, only, parts, out) -> str:
    """0.2.17 (R9-01): the signed statement of this answer (see the module doc) -> COSE_Sign1, base64url."""
    import cbor2
    import wa_profile as wa
    from svidetel_v4 import cose
    return wa.b64u(cose.sign1(ctx.wk, cbor2.dumps(statement_payload(body, only, parts, out), canonical=True), TYP_STATEMENT))


def statement_payload(body, only, parts, out) -> dict:
    from app.actions import now
    return {"v": "dw-judge-1", "nonce": body.get("nonce") if isinstance(body.get("nonce"), str) else None, "request_sha256": request_sha256(body),
          "part": only, "n_parts": len(parts), "parts": [m.tool for m in parts],
          "judged": [{"i": p["i"], "tool": p["tool"], "args_sha256": ((p["result"].get("action") or {}).get("args_sha256")) or p.get("ash") or _args_sha256(p["tool"], p["args"]),
                      "rid": p["result"].get("rid"), "verdict": p["result"].get("verdict"), "status": p["result"].get("status"),
                      "reason": p["result"].get("reason")} for p in out],
            "t": now()}


def refused_text(ctx, agent, tool, res):
    """0.2.73 (N15, polygon series 9): after the owner refused `ln .env hl2.txt`, `cat .env` (another call, the same tool and target
    "secrets:...") was told "the owner refused this action within the last hour". -> the text naming the refused call, or None."""
    from app import actions as act
    try:
        x = ctx.db.one("SELECT request_hash, mandate_id, class, recipient, created_at FROM actions WHERE rid=?", (res.get("rid"),))
        if x is None:
            return None
        r = act.refused_like(ctx, agent["id"], x["mandate_id"], tool, x["class"], x["recipient"], x["created_at"])
    except Exception:      # noqa: BLE001  the general text stays
        return None
    if r is None:
        return None
    t = time.strftime("%H:%M UTC", time.gmtime(r["updated_at"]))
    until = time.strftime("%H:%M UTC", time.gmtime(r["updated_at"] + act.refusal_block_s(ctx, agent["id"])))
    ago = max(0, (x["created_at"] - r["updated_at"]) // 60)
    if r["request_hash"] and r["request_hash"] == x["request_hash"]:
        return "denied by the owner %d min ago (at %s); not asking again until %s" % (ago, t, until)
    shown = " ".join(str(r["args_preview"] or "").split())[:120]
    return ("the owner did not refuse this call. At %s the owner refused another call of the same kind (%s, target %s%s); every "
            "call with the same tool and target is refused without a new question until %s. If this one is needed, tell the user why; it can be "
            "asked again after that" % (t, tool, (x["recipient"] or "-")[:160], ": " + shown if shown else "", until))


LATEST_CLIENT = "0.2.79"          # 0.2.90 / 0.2.89 (QA D9): the newest client on PyPI that this witness knows; SessionStart of 0.2.57+ compares


def notify_view(ctx, agent) -> dict:
    """0.2.89 (friction 03.11): who hears about a question of this agent: {"push": devices that a push would wake, "channels": verified
    Telegram / Slack / e-mail kinds, "muted": the agent's pushes are muted}. Counts only: no endpoint, no address. The hook says it in its
    answer ("Notification: sent via ... / NOT sent") and SessionStart warns about an account nobody would hear. Never raises."""
    acc = agent["account_id"]
    out = {"push": 0, "channels": [], "muted": False}
    try:
        p = getattr(ctx, "push", None)
        if p is not None and getattr(p, "enabled", False):
            out["push"] = len(p.subs_for(acc))
            out["muted"] = bool(p.muted_until(acc, agent["id"]))
        if getattr(ctx, "notify", None) is not None:
            out["channels"] = sorted({r["kind"] for r in ctx.db.q("SELECT kind FROM notify_channels WHERE account_id=? AND verified=1", (acc,))})
    except Exception:      # noqa: BLE001  a count is an extra; the decision never depends on it
        pass
    return out


def status(ctx, agent, project) -> dict:
    """0.2.89, GET /v1/hook/status (the agent key; SessionStart of client 0.2.57): what will make this session ask or refuse.
    trial: a trial account; mandate: {"active", "covers": a write inside `project` is in the signed delete.targets}; notify: notify_view.
    `project` is the hook's CLAUDE_PROJECT_DIR (an absolute path; only compared, never stored)."""
    from app import actions as act
    import json as _json
    from svidetel_v4.decide import _res_match
    r = ctx.db.one("SELECT trial_until FROM accounts WHERE id=?", (agent["account_id"],))
    m = act.active_mandate(ctx, agent["id"])
    mv = {"active": m is not None}
    if m is not None and isinstance(project, str) and project.startswith("/") and len(project) <= fs.MAX_PATH:
        try:
            dl = (_json.loads(m["mandate_json"]).get("permissions") or {}).get("delete")
            mv["covers"] = bool(isinstance(dl, dict) and _res_match(dl.get("targets"), project.rstrip("/") + "/x"))
        except (ValueError, TypeError, AttributeError):
            pass
    return {"v": 1, "trial": bool(r is not None and r["trial_until"] is not None), "mandate": mv, "notify": notify_view(ctx, agent),
            "latest": {"client": LATEST_CLIENT}}


def _one_question(ctx, agent, out, created, only):
    """04.11 (L3, friction: `curl -sI https://example.com; echo "rc=$?"` made two questions, two pushes, two rows, both expired in 45 s).
    The parts of ONE tool call are judged one by one (each keeps its own receipt: the hook checks and consumes them one by one), but the
    owner is asked ONCE:
      - a part refuses the line (deny / refused / expired): the questions the earlier parts stored are withdrawn at once, quietly (nobody was
        told yet): the line is refused, no question;
      - several parts wait for the owner: the first is the lead (listed, announced, decided on the approval page); the others are linked to it
        (actions.line_lead): hidden from the list, no push, no channel message; the page signs ONE batch (wb) over the lead and its linked parts
        (flow/batch.py), a refusal of the lead refuses them all. The lead's page names every reason (api_web line_group);
      - a team policy (quorum): the old way, one question per part;
      - a held part is a different gate (the owner releases it): announced on its own.
    Parts that were allowed stay allowed with their own receipts: the owner's decision widens nothing."""
    from app import actions as act
    from app import org
    hard = next((p for p in out if p["result"].get("verdict") == "deny" or p["result"].get("status") in ("refused", "expired")), None)
    mine = [p for p in out if p["result"].get("rid") in created]
    if hard is not None:
        code = hard["result"].get("reason") or "DENIED"
        for p in mine:
            if p is hard or p["result"].get("status") not in ("pending_approval", "held"):
                continue
            act.cancel_unasked(ctx, p["result"]["rid"], code)
            p["result"] = act.to_result(ctx, act.refresh(ctx, p["result"]["rid"]))
            p["why"] = reasons.explain(str(p["result"].get("reason") or ""), p["tool"])
        return
    pend = [p for p in out if p["result"].get("verdict") == "defer" and p["result"].get("status") == "pending_approval"]
    group = only is None and len(pend) >= 2 and org.current_policy(ctx, agent["account_id"]) is None
    lead = None
    if group:
        first = act.refresh(ctx, pend[0]["result"]["rid"])
        lead = first["line_lead"] or first["rid"]
        for p in pend[1:]:
            if p["result"]["rid"] in created:
                act.link_line(ctx, p["result"]["rid"], lead)
    for p in mine:
        rid = p["result"]["rid"]
        if group and p in pend and rid != lead:
            continue                                      # asked together with the lead
        act.announce(ctx, agent, rid)


def judge(ctx, agent, body: dict, capable=True) -> dict:
    from app import actions as act
    from app import erase
    if body.get("v") != 1:
        _bad("v: 1")
    only = body.get("part")
    if only is not None and (not isinstance(only, int) or isinstance(only, bool) or only < 0):
        _bad("part: null or a part index")
    nonce = body.get("nonce")
    if nonce is not None and (not isinstance(nonce, str) or not NONCE.fullmatch(nonce)):
        _bad("nonce: base64url, 22..86 characters")
    qnear = act.check_quota(ctx, agent)                  # 0.2.17 (R9-02): the quota first, the classifier (the costly part) after
    from app import stats
    stats.day7(ctx, agent["account_id"])                 # r0285: the hook still comes on day 7 (one dict lookup once counted / too early)
    r = classify_event(body)
    if r[0] == "need":
        _round(ctx, agent, "need")
        return {"v": 1, "need": r[1], "scan_rev": scan_list()["rev"]}
    if r[0] == "refuse":
        _round(ctx, agent, "refuse", r[1])
        return {"v": 1, "refuse": r[1], "detail": r[2], "texts": texts_for([r[1]])}
    parts = r[1]
    try:                                                 # 0.2.90: an agent created before "Write.outside" was in the preset keeps its map:
        _tools = set((json.loads(agent["toolmap_json"]) or {}).get("tools") or {})      # for it the write is judged as before (RESOURCE)
    except (KeyError, TypeError, ValueError):
        _tools = set()
    for i_, m_ in enumerate(parts):
        if m_.tool == "Write.outside" and "Write.outside" not in _tools:
            a_ = dict(m_.args)
            a_[mapping.RESERVED] = {"path": (m_.args.get(mapping.RESERVED) or {}).get("path")}
            parts[i_] = mapping.Mapped(body["event"]["tool_name"], a_, "%s %s" % (body["event"]["tool_name"], a_[mapping.RESERVED]["path"]))
    if only is not None and only >= len(parts):
        _bad("part: no such part")
    ask = _preview_need(ctx, agent, body, parts)
    if ask:                                              # 0.2.43b: a changed executed file the witness could not read: the hook shows it
        _round(ctx, agent, "need")
        return {"v": 1, "need": {"preview": ask}, "scan_rev": scan_list()["rev"]}
    out = []
    from app import runctx
    sid = runctx.session_of(body)                        # 0.2.85: optional; the 0.2.54 hook does not send it
    from . import freshness
    fresh_ = freshness.note(ctx, agent, sid, body, parts)
    if not fresh_:
        freshness.strip_strict(parts)                     # 0.2.88: settings changed in this session / no session / no view: not strict
    freshness.session_strict(ctx, agent, sid, parts, fresh_)     # r0261c (д): Write / Edit С3 only in a session with a strict fact
    created = []                                         # 04.11 (L3): the questions this call stored; announced once, after every part is judged
    from . import strict_policy as _sp
    pl_ = _LAST_PLACE.get()
    ptok_ = _sp.PLACE.set(pl_ if isinstance(pl_, dict) else None)
    try:
        res = _judge_parts(ctx, agent, body, parts, only, capable, created, sid, out)
        if qnear and isinstance(res, dict):
            res["quota"] = qnear                         # r0285: near a daily limit (outside the signed statement; decides nothing)
        return res
    finally:
        _sp.PLACE.reset(ptok_)


def _judge_parts(ctx, agent, body, parts, only, capable, created, sid, out):
    from app import actions as act
    from app import erase
    from app import runctx
    for i, m in enumerate(parts):
        if only is not None and i != only:
            continue
        res = act.do_action(ctx, agent, m.tool, m.args, capable, via="hook", quiet=True, created=created)
        if sid:
            runctx.note_session(ctx, agent, res.get("rid"), sid)          # 0.2.85: the decision belongs to this session (RUN_CONTEXT link)
        why = reasons.explain(str(res.get("reason") or ""), m.tool)
        if res.get("reason") == "REFUSED":
            why = refused_text(ctx, agent, m.tool, res) or why          # 0.2.73 (N15): which call the owner refused
        if res.get("reason") in constitution.CODES:
            nz_ = constitution.check(m.tool, m.args)                    # 06.11 (v1): which part of the call the article refuses
            if nz_ is not None and nz_[0] == res.get("reason"):
                why += " (found: %s)" % nz_[1][:160]
        if res.get("reason") == "APPROVAL_RATE":
            from app.flow import rate
            why += " (" + rate.backlog_text(ctx, agent["id"], act.now()) + "). Answer the waiting ones at " + ctx.cfg.origin + "/approve.html first"     # 0.2.26 (P3): how many wait and when a place frees
        out.append({"i": i, "tool": m.tool, "args": m.args, "summary": m.summary, "result": res, "why": why,
                    "ash": _args_sha256(m.tool, m.args, erase.salt_for(ctx, agent["account_id"], capable))})
        if res.get("verdict") == "deny" or res.get("status") in ("refused", "expired"):
            break                                         # the first refusal decides (as the 0.2.15 hook did): nothing more is judged
    _one_question(ctx, agent, out, created, only)
    from app import vektor as _vk                      # r0330: the consequence vector in SHADOW (next to the verdict; decides nothing)
    _vk.note(ctx, agent, [(m.tool, m.args) for m in parts], [p["result"].get("rid") for p in out], _LAST_PLACE.get())
    res = {"v": 1, "n_parts": len(parts), "parts": [{k: v for k, v in p.items() if k != "ash"} for p in out], "texts": texts_for([p["result"].get("reason") for p in out]),
           "statement_b64": statement(ctx, body, only, parts, out)}
    if any(p["result"].get("status") in ("pending_approval", "held") for p in out):
        res["notify"] = notify_view(ctx, agent)          # 0.2.89: outside the signed statement (a count for the person, decides nothing)
        _delivery(ctx, agent, res["notify"], [p["result"].get("rid") for p in out if p["result"].get("status") in ("pending_approval", "held")])
    return res


def _delivery(ctx, agent, nv, rids):
    """r0276 (SVODKA-1311 p.5): the phone push of this question did not get through (push.Pusher.delivery). Said in the words the hook
    already prints: a client of 0.2.57+ writes "Notification: sent via <channels>", so the push count becomes one channel entry that says
    what happened ("phone push - did NOT reach your phone, open the link above"); `delivery` is the same for a client that reads it.
    Nothing here changes a decision or the signed statement. Never raises."""
    try:
        p = getattr(ctx, "push", None)
        if p is None or not getattr(p, "enabled", False) or not nv.get("push") or nv.get("muted"):
            return
        d = p.delivery(agent["account_id"], rids)
        if d is None:
            return
        n = nv["push"]
        nv["delivery"] = d
        nv["push"] = 0
        head, sep, tail = d["text"].partition(" - ")
        if not sep:
            head, _, tail = d["text"].partition("; ")          # r0276b: the neutral sentence: "phone push (1 device); if it did not come, ..."
            sep = "; "
        nv["channels"] = list(nv.get("channels") or []) + ["%s (%d device%s)%s%s" % (head, n, "" if n == 1 else "s", sep, tail)]
    except Exception:      # noqa: BLE001
        pass
