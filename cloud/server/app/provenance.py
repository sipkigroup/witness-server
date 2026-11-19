"""r0275 (red team 13.11, SVODKA-DNYA-1311 p.2): the memory of a session across tools.

1. Provenance (STAC, arXiv 2509.25624: chains of harmless calls). A file the agent's shell line wrote while that line read a credential
   (`cp -r ~/.ssh src/s`, `dd if=~/.ssh/id_rsa of=src/k.bin`, `rsync ~/.aws/ src/a/` -- asked as a dangerous command and approved) IS the
   credential under another name. Before r0275 the copy was a plain project file: `Read src/k.bin` / `cat src/s/config` / `curl -F
   f=@src/k.bin` read or carried it with no question and no "secret seen" mark. Now a later call of any agent of the account that reads such
   a copy (Read / Grep / NotebookRead / a shell line naming it, a directory or a glob holding it) is judged as reading the credential it
   was made from: a credential article Н1 names (a private key, a token store) -> refused FORBIDDEN_SECRET_READ, as the original; any
   other credential (~/.ssh/config ...) -> held for the owner (ESCALATE_SECRET_COPY) where the mandate would let it through, except inside
   the strict sandbox (there a read of a secret stays on the computer, as `cat .env` of the project: r0261). The read marks the agent
   "secret seen" (its later outgoing calls are held, 0.2.24). The call is never rewritten (the client binds its receipt to the call it
   sent). A copy carries on through further copies; a whole-file Write the witness judged ends it. Lines that only look at the copy,
   move or delete it (ls, stat, rm, mv, cp ...) are not reads: no hold, the provenance moves with a copy.

2. Refused effects (Cursor 09.2025; Authorization Drift, arXiv 2611.09113): after the owner's No, the agent reaches the same EFFECT with
   another tool (Read after `cat`, Edit after `sed -i`, a script after `rm -rf`, `gh api` after `git push`). Every judged call keeps the
   keys of its effect (actions.fx_keys): a secret it reads, a place outside the project it writes / deletes, a host it reaches, a program
   that publishes, a place of persistence. When a call would be ASKED and a call with an overlapping effect was refused by the owner within
   REFUSED_WINDOW_S, the question says so (exec_json "rb": the server's words "You said No to this ... minutes ago", signed with the view).
   Never an allow is turned into anything here and no new question is made: the mark tells the tired person that the agent works around
   the No (measured r0275: every cross-tool bypass of the scenario set was already asked or refused; what was missing is the memory).
"""
from __future__ import annotations

import fnmatch
import json
import posixpath
import re
import shlex

REFUSED_WINDOW_S = 8 * 3600          # a working session; the exact repeat is refused for refusal_block_s (actions.refused_like)
COPY_LOOKBACK_S = 24 * 3600          # as WRITTEN_LOOKBACK_MIN: a copy older than that is no longer known
SEEN = ("allowed", "approved", "consumed", "executed")
# programs that do not print a file's text: listing, metadata, moving, deleting (constitution._LOOK_ONLY + the quiet file operations)
NOT_A_READ = {"ls", "stat", "test", "[", "[[", "du", "file", "wc", "realpath", "readlink", "basename", "dirname", "rm", "rmdir", "unlink",
              "mv", "cp", "ln", "touch", "chmod", "chown", "mkdir", "shred", "sha256sum", "sha1sum", "sha512sum", "shasum", "md5", "md5sum",
              "b2sum", "cksum"}
HOLD = "ESCALATE_SECRET_COPY"        # a read of a copy the mandate would let through: held for the owner
VCS = {"git", "gh", "hub", "glab"}


def _canon(p):
    if not isinstance(p, str) or not p:
        return None
    p = posixpath.normpath(p)
    for pre in ("/private/var/", "/private/tmp/"):
        if p.startswith(pre):
            p = p[len("/private"):]
    return p


def _within(a, b):
    """a == b or a lies under b"""
    return a == b or a.startswith(b.rstrip("/") + "/")


def _w(args):
    w = args.get("_witness") if isinstance(args, dict) else None
    return w if isinstance(w, dict) else {}


def _heads(w):
    return {h.split(" ", 1)[0].rsplit("/", 1)[-1] for h in (w.get("commands") or []) if isinstance(h, str) and not h.startswith("(")}


def _mark_source(d):
    """'secrets:<p> (read as ...)' -> <p> (the credential, first in the detail)"""
    return d[len("secrets:"):].split(" (read as ", 1)[0].split(" is a hard link of ", 1)[0].strip()


# ---- 1. provenance ----------------------------------------------------------------------------------------------------------------
def copies(ctx, account_id, t0):
    """-> {copy path (canonical): (credential path, rowid of the write)} of the account's agents within COPY_LOOKBACK_S, with the key
    "" -> {path: rowid of the latest whole-file Write the witness judged} (such a write replaces the text: no longer a copy)."""
    out = {}
    try:
        rows = ctx.db.q("SELECT rowid AS n, rid, agent_id, status, created_at, exec_json FROM actions WHERE account_id=? AND class='delete' "
                        "AND created_at>? AND status IN (%s) AND exec_json LIKE '%%\"sec\"%%' ORDER BY rowid LIMIT 2000"
                        % ",".join("?" * len(SEEN)), (account_id, t0 - COPY_LOOKBACK_S) + SEEN)
    except Exception:      # noqa: BLE001  no column / no table: nothing known
        return {}
    from app.actions import unrun_write
    for r in rows:
        try:
            sec = json.loads(r["exec_json"]).get("sec")
        except (TypeError, ValueError, AttributeError):
            continue
        if not isinstance(sec, dict) or unrun_write(ctx, r) or _waits(ctx, r):
            continue
        for p, src in sec.items():
            cp = _canon(p)
            if cp and isinstance(src, str):
                out[cp] = (src, r["n"])
    if not out:
        return out
    wr = {}
    for r in ctx.db.q("SELECT rowid AS n, recipient FROM actions WHERE account_id=? AND class='delete' AND created_at>? AND tool IN ('Write','Write.danger') "
                      "AND status IN (%s) ORDER BY rowid LIMIT 2000" % ",".join("?" * len(SEEN)), (account_id, t0 - COPY_LOOKBACK_S) + SEEN):
        cp = _canon(r["recipient"])
        if cp:
            wr[cp] = r["n"]
    out[""] = wr
    return out


def _waits(ctx, r):
    """the line of this write still waits for the owner (another part of it pending / held, the hook did not give up): it has not run.
    Once approved the line is sent again and runs; a part given up on may have run on a yes in the terminal (counted: fail closed)."""
    from app.actions import _row_line
    ln = _row_line(r)
    if not ln or ln.startswith("w:"):
        return False
    y = ctx.db.one("SELECT COUNT(*) AS n FROM actions WHERE agent_id=? AND rid<>? AND created_at BETWEEN ? AND ? AND exec_json LIKE ? "
                   "AND status IN ('pending_approval','held') AND gave_up_at IS NULL",
                   (r["agent_id"], r["rid"], (r["created_at"] or 0) - 2, (r["created_at"] or 0) + 2, '%"line": "' + ln + '"%'))
    return bool(y and y["n"])


def _hit(path, cps):
    """-> (copy, credential) when reading `path` reads a copy (the copy itself, a file inside a copied directory, a directory holding a
    copy, a glob naming it), else None. A file the witness saw written whole after the copy is no copy."""
    p = _canon(path)
    if not p:
        return None
    wr = cps.get("") or {}
    glob = bool(re.search(r"[*?\[]", p))
    for c, v in cps.items():
        if not c:
            continue
        src, n = v
        if _within(p, c) and p != c:
            if wr.get(p, -1) > n:
                continue
            return p, src.rstrip("/") + p[len(c):]          # a file inside a copied directory: the same file of the credential directory
        if (_within(c, p) or (glob and fnmatch.fnmatchcase(c, p))) and not wr.get(c, -1) > n:
            return c, src
    return None


def _line_paths(cmd, cwd):
    try:
        from app.hookjudge.bashparse import line_texts
        segs = [t for t, _f in line_texts(cmd)]
    except Exception:      # noqa: BLE001
        segs = [cmd]
    out = []
    for seg in segs:
        try:
            toks = shlex.split(seg, comments=True)
        except ValueError:
            toks = seg.split()
        for t in toks[1:]:
            for v in {t, t.split("=", 1)[1] if "=" in t else t}:
                v = v.lstrip("@<>")
                if not v or v.startswith("-") or "$" in v:
                    continue
                out.append(v if v.startswith("/") else posixpath.join(cwd or "/", v))
    return out


def copy_read(ctx, account_id, tool, args, t0):
    """-> (copy path, credential path, reads) when the call names a copy of a credential, else None. `reads` is False for a shell
    write part (its line is judged by its other parts; the write carries the provenance on, carry()) and for a line whose every
    program only lists / moves / deletes (ls, stat, rm, mv, cp ...). The call itself is never changed: the client checks that the
    receipt is for exactly the call it sent (REQUEST_MISMATCH)."""
    if not isinstance(tool, str) or not isinstance(args, dict):
        return None
    base = tool.split(".", 1)[0]
    if base not in ("Read", "Grep", "NotebookRead", "Bash"):
        return None
    cps = copies(ctx, account_id, t0)
    if not cps:
        return None
    w = _w(args)
    if base == "Bash":
        cmd = args.get("command")
        if not isinstance(cmd, str):
            return None
        cwd = w.get("cwd") if isinstance(w.get("cwd"), str) else w.get("project")
        for p in _line_paths(cmd, cwd if isinstance(cwd, str) else None):
            hit = _hit(p, cps)
            if hit:
                heads = _heads(w)
                return hit[0], hit[1], tool != "Bash.write" and not (heads and heads <= NOT_A_READ)
        return None
    p = w.get("path") if isinstance(w.get("path"), str) else (args.get("file_path") or args.get("notebook_path") or args.get("path"))
    hit = _hit(p, cps) if isinstance(p, str) else None
    return (hit[0], hit[1], True) if hit else None


def n1(src):
    """the credential is one article Н1 refuses to read (a private key, a token store ...)"""
    from app import constitution
    return isinstance(src, str) and bool(constitution._SECRET_FILE.search(src))


def carry(tool, args, hit=None):
    """-> {written path: credential} for a shell write part whose line reads a credential (a mark) or a copy of one (`hit` of
    copy_read), or {}"""
    if tool != "Bash.write":
        return {}
    w = _w(args)
    src = None
    wr = [_canon(p) for p in (w.get("writes") or []) if isinstance(p, str) and p.startswith("/")]
    proj = _canon(w.get("project")) if isinstance(w.get("project"), str) else None
    for d in w.get("danger") or []:
        if isinstance(d, str) and d.startswith("secrets:"):
            s_ = _mark_source(d)
            # the credential READ by the line, not a file of a secret's name it writes (`cp .env.example .env.local`: the mark names
            # the destination; its text is the example's)
            # Only a credential from OUTSIDE the project (~/.ssh, ~/.aws ...): a copy of the project's own .env.example stays what a
            # project file is (judged by its name; `grep -r .` of a project with a .env is no read of a secret either: 0.2.12 R7-06)
            if s_.startswith("/") and not any(_within(_canon(s_), q) for q in wr) and not (proj and _within(_canon(s_), proj)):
                src = s_
                break
    if src is None and hit:
        src = hit[1]
    if src is None:
        return {}
    return {p: src for p in (w.get("writes") or []) if isinstance(p, str) and p.startswith("/")}


# ---- 2. refused effects ---------------------------------------------------------------------------------------------------------------
_ABS = re.compile(r"(?:^|[\s(=:'\"])((?:/|~/)[^\s()'\",;]+)")


def _paths_in(s):
    return [m.group(1).rstrip("/") or "/" for m in _ABS.finditer(s or "")]


def effect_keys(tool, act, args):
    """-> sorted list of "kind:value" keys of what the call does to the world (kinds: sec, out, net, exit, persist)."""
    if not isinstance(tool, str):
        return []
    w = _w(args)
    project = _canon(w.get("project")) if isinstance(w.get("project"), str) else None
    keys = set()
    for d in w.get("danger") or []:
        if not isinstance(d, str):
            continue
        k, _, det = d.partition(":")
        det = re.sub(r"\s*\[[^\]]*\]\s*$", "", det).strip()
        if k == "secrets":
            s_ = _mark_source(d)
            keys.add("sec:" + (_canon(s_) if s_.startswith("/") else s_))
        elif k in ("rm-rf", "write-outside", "delete-outside"):
            for p in _paths_in(det) or ([det] if det.startswith(("/", "~")) else []):
                keys.add("out:" + (_canon(p) if p.startswith("/") else p))
        elif k in ("exit", "net-out", "publish"):
            pr = det.split()[0].rsplit("/", 1)[-1] if det.split() else ""
            if pr:
                keys.add("exit:" + ("vcs" if pr in VCS else pr))
        elif k == "persist":
            for p in _paths_in(det) or [det]:
                keys.add("persist:" + (_canon(p) if p.startswith("/") else p))
    for h in w.get("commands") or []:
        if isinstance(h, str) and h.startswith("(write outside the project) "):
            keys.add("out:" + _canon(h[len("(write outside the project) "):].strip()))
    for p in (w.get("deletes") or []) + (w.get("writes") or []):
        if isinstance(p, str) and p.startswith("/") and project and not _within(_canon(p), project):
            keys.add("out:" + _canon(p))
    if tool == "Write.outside" and isinstance(w.get("path"), str):
        keys.add("out:" + _canon(w["path"]))
    if tool.endswith(".secret") and isinstance(w.get("path"), str):
        keys.add("sec:" + _canon(w["path"]))
    if tool in ("Write", "Edit", "MultiEdit") and isinstance(w.get("path"), str) and isinstance(args, dict):
        # a file the agent writes whose text reaches a gate (execguard G1-G4): a later run of it reaches that effect (run_keys)
        txt = args.get("content") if tool == "Write" else args.get("new_string")
        if tool == "MultiEdit" and isinstance(args.get("edits"), list):
            txt = "\n".join(e.get("new_string") for e in args["edits"] if isinstance(e, dict) and isinstance(e.get("new_string"), str))
        if isinstance(txt, str) and txt:
            try:
                from app import execguard
                g = execguard.gate_text(txt[:65536], w.get("project") if isinstance(w.get("project"), str) else None,
                                        home=w.get("home") if isinstance(w.get("home"), str) else None)
            except Exception:      # noqa: BLE001
                g = None
            if g in GATE_KEYS:
                keys.add("wrote:%s|%s" % (_canon(w["path"]), g))
    for n in w.get("net") or []:
        if isinstance(n, str):
            keys.add("net:" + n.rsplit("@", 1)[-1].lower())
    if tool in ("WebFetch",) and isinstance(act, dict) and isinstance(act.get("recipient"), str):
        keys.add("net:" + act["recipient"].rsplit("@", 1)[-1].lower())
    return sorted(k for k in keys if len(k) <= 600)[:32]


def _same(a, b):
    ka, _, va = a.partition(":")
    kb, _, vb = b.partition(":")
    if ka != kb:
        return False
    if va == "*" or vb == "*" or va == vb:
        return True
    if ka in ("sec", "out", "persist"):
        if va.startswith("~/") or vb.startswith("~/"):
            r, o = (va[1:], vb) if va.startswith("~/") else (vb[1:], va)
            o = o[1:] if o.startswith("~/") else o
            return o.endswith(r) or (r + "/") in (o + "/") or o.endswith(r.rsplit("/", 1)[0])
        return _within(va, vb) or _within(vb, va)
    return False


GATE_KEYS = {"G1": "out:*", "G2": "net:*", "G3": "sec:*", "G4": "persist:*"}


def run_keys(ctx, agent_id, args, t0):
    """keys of the files this agent wrote that this line names: their written text reaches a gate (execguard G1-G4) -- the run of the
    file reaches that effect. From the written-run marks (shell writes) and the write rows' own keys ("wrote:<path>|G")."""
    cmd = args.get("command") if isinstance(args, dict) else None
    if not isinstance(cmd, str):
        return []
    w = _w(args)
    cwd = w.get("cwd") if isinstance(w.get("cwd"), str) else w.get("project")
    named = {_canon(p) for p in _line_paths(cmd, cwd if isinstance(cwd, str) else None)}
    out = set()
    try:
        from app.actions import written_run_info, WRITTEN_LOOKBACK_MIN
        for f, info in written_run_info(ctx, agent_id, t0 - 60 * WRITTEN_LOOKBACK_MIN).items():
            g = info.get("g") if isinstance(info, dict) else None
            if _canon(f) in named and g in GATE_KEYS:
                out.add(GATE_KEYS[g])
        # r0353 (передача человеку): a write still waiting for the person (pending / held) counts too -- only the WORDS of a later run's
        # question use these keys ("You said No to this ..."); the write was asked with the same mark (actions.handoff_write)
        for r in ctx.db.q("SELECT fx_keys FROM actions WHERE agent_id=? AND (class='delete' OR tool IN ('Write', 'Edit', 'MultiEdit', "
                          "'NotebookEdit')) AND created_at>? AND status IN (%s) "
                          "AND fx_keys LIKE '%%\"wrote:%%' ORDER BY rowid DESC LIMIT 500" % ",".join("?" * (len(SEEN) + 2)),
                          (agent_id, t0 - 60 * WRITTEN_LOOKBACK_MIN) + SEEN + ("pending_approval", "held")):
            for k in json.loads(r["fx_keys"]):
                if isinstance(k, str) and k.startswith("wrote:"):
                    p, _, g = k[len("wrote:"):].rpartition("|")
                    if p in named and g in GATE_KEYS:
                        out.add(GATE_KEYS[g])
    except Exception:      # noqa: BLE001  no keys: no mark
        pass
    return sorted(out)


def refused_before(ctx, agent_id, keys, t0, rid=None):
    """-> {"rid", "at", "tool", "key"} of the latest call of this agent the owner refused within REFUSED_WINDOW_S whose effect overlaps
    one of `keys`, or None."""
    if not keys:
        return None
    try:
        rows = ctx.db.q("SELECT rid, tool, fx_keys, updated_at FROM actions WHERE agent_id=? AND created_at>? AND status='refused' "
                        "AND fx_keys IS NOT NULL AND updated_at>? ORDER BY updated_at DESC LIMIT 200",
                        (agent_id, t0 - REFUSED_WINDOW_S - 7200, t0 - REFUSED_WINDOW_S))     # created_at: the agent's index
    except Exception:      # noqa: BLE001
        return None
    for r in rows:
        if r["rid"] == rid:
            continue
        try:
            rk = json.loads(r["fx_keys"])
        except (TypeError, ValueError):
            continue
        for k in keys:
            if k.startswith("wrote:"):
                continue                                   # a write's own text, not an effect it has now
            for q in rk if isinstance(rk, list) else []:
                if isinstance(q, str) and _same(k, q):
                    return {"rid": r["rid"], "at": r["updated_at"], "tool": (r["tool"] or "").split(".", 1)[0], "key": q.split(":", 1)[0]}
    return None


PLACE_KINDS = ("out", "persist")


def refused_place(ctx, agent_id, key, t0):
    """r0296 (profile "auto mode + Witness"): -> rid of the latest call of this agent, within REFUSED_WINDOW_S, that the owner refused
    (status refused) or the witness refused (denied: an article such as FORBIDDEN_WIPE, the mandate) whose ONLY effects on the world were
    places outside the project (out:, persist:) and one of them overlaps `key` (an "out:<path>" key) -- so the No was about that place.
    A refused line that also sent, published or read a secret is not counted (its No may have been about that part); its question keeps
    the r0275 mark where one is asked. None when there is none."""
    if not isinstance(key, str) or not key.startswith("out:"):
        return None
    try:
        rows = ctx.db.q("SELECT rid, fx_keys FROM actions WHERE agent_id=? AND created_at>? AND status IN ('refused','denied') "
                        "AND fx_keys IS NOT NULL AND updated_at>? ORDER BY updated_at DESC LIMIT 400",
                        (agent_id, t0 - REFUSED_WINDOW_S - 7200, t0 - REFUSED_WINDOW_S))
    except Exception:      # noqa: BLE001
        return None
    for r in rows:
        try:
            rk = json.loads(r["fx_keys"])
        except (TypeError, ValueError):
            continue
        if not isinstance(rk, list):
            continue
        world = [q for q in rk if isinstance(q, str) and not q.startswith("wrote:")]
        if world and all(q.split(":", 1)[0] in PLACE_KINDS for q in world) and any(_same(key, q) for q in world):
            return r["rid"]
    return None


KIND_WORDS = {"sec": "reading a secret", "out": "changing files outside the project", "net": "sending data to this site",
              "exit": "publishing", "persist": "a change that starts by itself later"}


def words(rb, created_at):
    """the short line of the question (harm) when the owner refused the same effect before; None when there is no mark"""
    if not isinstance(rb, dict) or not isinstance(rb.get("at"), int):
        return None
    mins = max(1, int(((created_at or rb["at"]) - rb["at"]) // 60)) if isinstance(created_at, int) else None
    from app.qwords import SCREEN as S        # r0277: the words are templates of the pinned vocabulary (mr-vocab-2 "screen")
    when = S["when_min"].format(n=mins) if mins is not None and mins < 120 else (S["when_h"].format(n=mins // 60) if mins is not None else S["when_earlier"])
    return S["refused_before"].format(when=when)


def detail(rb):
    k = KIND_WORDS.get(rb.get("key") if isinstance(rb, dict) else None, "the same effect")
    t = rb.get("tool") if isinstance(rb, dict) and isinstance(rb.get("tool"), str) else "another tool"
    return "You refused %s when the agent asked through %s. This request reaches the same effect another way." % (k, t or "another tool")


# ---- 3. code from the network (r0294, red team 13.11 "take-home task": ISPYTANIE-BINANCE-GEMINI-1311, not closed p.1) -----------------
# The law: when the agent runs code that came from the network in this agent's session (curl / wget -o, git clone, gh repo clone, a file a
# shell line wrote from a download, what an extraction / copy / rename of such a file wrote), the question about that run says so on the
# first screen, in one line of harm with the host and how long ago ("Runs code downloaded from github.com 3 min ago -- it can do anything
# you can."). A line that fetches and runs in one go (`npx github:o/r`, `uvx --from git+URL`, `pip install git+URL`, `git clone URL && make`)
# says "Runs code from <host>". Only WORDS change: no call is asked that was not asked before (friction is unchanged), nothing is allowed.
# The record is the server's own parse of the line the agent sent ("nf": {path: host} on the rows of the line), never the agent's words.
# Honest limits: an extraction into a folder marks the whole folder (the server does not see the archive's members), so a later run of any
# file under it is said as downloaded (an upper bound); code fetched by a program the parser does not know (a script that downloads) is
# not seen; the host is the URL's, not where a redirect ended.
FETCH_LOOKBACK_S = 24 * 3600
NF_MAX = 64
_WRAP = {"sudo", "doas", "env", "nohup", "nice", "time", "command", "exec", "builtin", "caffeinate", "stdbuf", "chronic"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "mksh"}
_INTERP = {"node", "nodejs", "ruby", "perl", "php", "lua", "tclsh", "Rscript", "ts-node", "tsx", "osascript", "pwsh", "julia"}
_DIR_RUNNERS = {"pytest", "py.test", "tox", "nox", "cargo", "go", "just", "rake", "gradle", "mvn", "ant", "bazel", "meson", "ninja", "cmake",
                "poetry", "pipenv", "hatch", "pdm", "npx", "bunx", "direnv", "pre-commit", "mix", "dotnet", "swift", "composer", "bundle"}
_PKG = {"npm", "yarn", "pnpm", "bun"}
_PKG_RUN = {"test", "t", "tst", "run", "run-script", "rum", "urn", "start", "restart", "stop", "install", "i", "in", "ins", "inst", "insta",
            "instal", "isnt", "isnta", "isntal", "add", "ci", "clean-install", "install-clean", "it", "cit", "install-test", "exec", "x",
            "rebuild", "rb", "build", "dlx", "pack", "publish", "link", "ln", "prepare", "dev"}
_GH_SHORT = {"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org", "gist": "gist.github.com"}
_URL_HOST = re.compile(r"^(?:git\+)?(?:https?|ftp|git|ssh|git\+ssh|git\+https)://(?:[^/@\s]*@)?([A-Za-z0-9.\-]+|\[[0-9A-Fa-f:.]+\])(?::\d+)?(?:[/?#]|$)", re.I)
_SCP_HOST = re.compile(r"^(?:git\+)?[A-Za-z0-9._\-]+@([A-Za-z0-9.\-]+):[^/]")


def host_of(spec):
    """-> the host a package / repository spec fetches from (a URL, git+URL, user@host:path, github:o/r), or None"""
    if not isinstance(spec, str) or not spec:
        return None
    s = spec.split("=", 1)[1] if spec.startswith(("--from=", "--spec=")) else spec
    s = s.split("@", 1)[1].strip() if re.match(r"^[A-Za-z0-9_.\-]+ @ ", s) else s
    m = _URL_HOST.match(s) or _SCP_HOST.match(s)
    if m:
        return m.group(1).lower()
    m = re.match(r"^(github|gitlab|bitbucket|gist):[A-Za-z0-9_.\-]", s)
    return _GH_SHORT[m.group(1)] if m else None


def _segs(cmd):
    """the simple commands of a line, in order (the parser's split; a subshell's `( ... )` and `;` inside it split here too)"""
    try:
        from app.hookjudge.bashparse import line_texts
        segs = [t for t, _f in line_texts(cmd)]
    except Exception:      # noqa: BLE001
        segs = [cmd]
    out = []
    for s in segs:
        for p in re.split(r"\s*(?:;|&&|\|\||\n)\s*", s.strip().lstrip("(").rstrip(")")):
            p = p.strip().lstrip("(").rstrip(")").strip()
            if p:
                out.append(p)
    return out


def _toks(seg):
    try:
        t = shlex.split(seg, comments=True)
    except ValueError:
        t = seg.split()
    while t and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t[0]) or t[0].rsplit("/", 1)[-1] in _WRAP):
        w = t.pop(0).rsplit("/", 1)[-1]
        if w in ("timeout", "nice", "stdbuf") and t and not t[0].startswith("-") and re.match(r"^[0-9.]+[smhd]?$", t[0]):
            t.pop(0)
        while w in ("env", "sudo", "nice", "nohup", "stdbuf", "doas") and t and t[0].startswith("-"):
            o = t.pop(0)
            if o in ("-n", "-u", "-g", "-C") and w in ("nice", "sudo", "doas", "stdbuf") and t:
                t.pop(0)                          # `nice -n 5 make`, `sudo -u bob x`: the option's value is no program
    if t and t[0].rsplit("/", 1)[-1] == "timeout":
        t = t[1:]
        while t and t[0].startswith("-"):
            t.pop(0)
        t = t[1:] if t else t
    return t


def _abs(p, cwd):
    if not isinstance(p, str) or not p or "$" in p or p.startswith("~") or p == "-":
        return None
    return _canon(p if p.startswith("/") else posixpath.join(cwd or "/", p))


def _url_base(u):
    b = re.sub(r"[?#].*$", "", u).rstrip("/").rsplit("/", 1)[-1]
    return b if b and "." not in b[:1] and not _URL_HOST.match(b) and b != u else None


def _redirect(toks):
    for i, t in enumerate(toks):
        if t in (">", ">>", "1>", "&>") and i + 1 < len(toks):
            return toks[i + 1]
        m = re.match(r"^(?:1|&)?>>?(.+)$", t)
        if m and not m.group(1).startswith("&"):
            return m.group(1)
    return None


def _fetch_of(toks, cwd):
    """-> ({abs path: host} a fetch writes, the new cwd or None) for one simple command"""
    if not toks:
        return {}, None
    p = toks[0].rsplit("/", 1)[-1]
    out = {}
    if p == "cd":
        d = next((t for t in toks[1:] if not t.startswith("-")), None)
        return {}, _abs(d, cwd) if d else None
    if p in ("curl", "wget"):
        urls = [t for t in toks[1:] if _URL_HOST.match(t)]
        if not urls:
            return {}, None
        h = _URL_HOST.match(urls[0]).group(1).lower()
        dests, odir, remote = [], None, False
        i = 1
        while i < len(toks):
            t = toks[i]
            nxt = toks[i + 1] if i + 1 < len(toks) else None
            if p == "curl":
                if t in ("-o", "--output") and nxt:
                    dests.append(nxt)
                    i += 1
                elif t.startswith("--output="):
                    dests.append(t.split("=", 1)[1])
                elif t == "--output-dir" and nxt:
                    odir = nxt
                    i += 1
                elif t in ("-O", "--remote-name", "--remote-name-all") or (re.match(r"^-[A-Za-z]+$", t) and "O" in t):
                    remote = True
                elif re.match(r"^-[A-Za-z]*o.+$", t) and not t.startswith("--"):
                    dests.append(t.split("o", 1)[1])
            else:
                if t in ("-O", "--output-document") and nxt:
                    dests.append(nxt)
                    i += 1
                elif t.startswith("--output-document="):
                    dests.append(t.split("=", 1)[1])
                elif t.startswith("-O") and len(t) > 2:
                    dests.append(t[2:])
                elif t in ("-P", "--directory-prefix") and nxt:
                    odir = nxt
                    i += 1
                elif t.startswith("--directory-prefix="):
                    odir = t.split("=", 1)[1]
            i += 1
        if p == "wget" and not dests:
            remote = True
        rd = _redirect(toks)
        if rd:
            dests.append(rd)
        if remote:
            for u in urls:
                b = _url_base(u)
                dests.append(b if b else "index.html")
        base = _abs(odir, cwd) if odir else cwd
        for d in dests:
            a = _abs(d, base)
            if a and d != "-":
                out[a] = h
        return out, None
    if p == "git" and "clone" in toks[1:]:
        args = toks[toks.index("clone") + 1:]
        vals = {"-b", "--branch", "--depth", "-o", "--origin", "-c", "--config", "--reference", "--reference-if-able", "--filter", "-j",
                "--jobs", "--separate-git-dir", "--template", "-u", "--upload-pack", "--shallow-since", "--shallow-exclude", "--bundle-uri",
                "--server-option", "--revision"}
        pos, i = [], 0
        while i < len(args):
            if args[i] in vals:
                i += 2
                continue
            if not args[i].startswith("-"):
                pos.append(args[i])
            i += 1
        if pos:
            h = host_of(pos[0])
            if h:
                d = pos[1] if len(pos) > 1 else re.sub(r"\.git$", "", pos[0].rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1])
                a = _abs(d, cwd)
                if a:
                    out[a] = h
        return out, None
    if p == "gh" and toks[1:3] == ["repo", "clone"]:
        pos = [t for t in toks[3:] if not t.startswith("-")]
        if pos and not pos[0].startswith("-"):
            h = host_of(pos[0]) or "github.com"
            d = pos[1] if len(pos) > 1 else re.sub(r"\.git$", "", pos[0].rstrip("/").rsplit("/", 1)[-1])
            a = _abs(d, cwd)
            if a:
                out[a] = h
        return out, None
    return {}, None


def _run_of(toks, cwd):
    """-> [(abs path, True when a folder's code runs)] the code one simple command runs (a script, ./prog, a build / test / package
    runner in a folder); [] for a command that runs no file"""
    if not toks:
        return []
    p = toks[0].rsplit("/", 1)[-1]
    a = toks[1:]
    first = next((t for t in a if not t.startswith("-")), None)
    if "/" in toks[0] and p not in ("python", "python3"):
        r = _abs(toks[0], cwd)
        return [(r, False)] if r else []
    if p in ("source", "."):
        r = _abs(first, cwd)
        return [(r, False)] if r else []
    if p in _SHELLS:
        if "-c" in a or "-s" in a:
            return []
        r = _abs(first, cwd)
        return [(r, False)] if r else []
    if re.fullmatch(r"(python|pypy)[0-9.]*", p):
        i = 0
        while i < len(a) and a[i].startswith("-"):
            if a[i] in ("-m", "-c") or a[i].startswith(("-m", "-c")):
                if a[i:i + 2][-1:] == ["pip"] or a[i] == "-mpip":
                    return _pip_runs(a[i + 2:] if a[i] == "-m" else a[i + 1:], cwd)
                return [(cwd, True)] if cwd else []              # -m / -c: the current folder is first on the import path
            if a[i] in ("-W", "-X", "--check-hash-based-pycs"):
                i += 1
            i += 1
        r = _abs(a[i], cwd) if i < len(a) else None
        return [(r, False)] if r else []
    if p in _INTERP or p in ("deno", "bun") and first in ("run",) or p == "bun" and first and first.endswith((".js", ".ts", ".mjs", ".cjs", ".tsx")):
        rest = a[a.index("run") + 1:] if p in ("deno", "bun") and "run" in a else a
        f = next((t for t in rest if not t.startswith("-")), None)
        if p == "bun" and f and "/" not in f and "." not in f:
            return [(cwd, True)] if cwd else []                  # `bun run dev`: a script of the folder's package.json
        if p in ("node", "nodejs") and ("-e" in a or "--eval" in a or "-p" in a):
            return [(cwd, True)] if cwd else []
        r = _abs(f, cwd)
        return [(r, False)] if r else []
    if p in ("make", "gmake", "bmake"):
        d = cwd
        for i, t in enumerate(a):
            if t == "-C" and i + 1 < len(a):
                d = _abs(a[i + 1], cwd)
            elif t.startswith("--directory="):
                d = _abs(t.split("=", 1)[1], cwd)
            elif t.startswith("-C") and len(t) > 2:
                d = _abs(t[2:], cwd)
        return [(d, True)] if d else []
    if p in _PKG:
        d = cwd
        for i, t in enumerate(a):
            if t in ("--prefix", "-C", "--dir", "--cwd") and i + 1 < len(a):
                d = _abs(a[i + 1], cwd)
            elif t.startswith(("--prefix=", "--dir=", "--cwd=")):
                d = _abs(t.split("=", 1)[1], cwd)
        sub = first
        if sub is None and p in ("yarn", "pnpm", "bun"):
            sub = "install"
        return [(d, True)] if d and (sub in _PKG_RUN or (p in ("yarn", "pnpm") and sub not in ("info", "why", "list", "ls", "view",
                                                                                           "outdated", "audit", "config", "help", "-v"))) else []
    if p in ("pip", "pip3") or re.fullmatch(r"pip[0-9.]+", p):
        return _pip_runs(a, cwd)
    if p == "uv":
        if first in ("run", "sync", "build") or a[:2] == ["pip", "install"]:
            return _pip_runs(a[2:], cwd) if a[:2] == ["pip", "install"] else ([(cwd, True)] if cwd else [])
        return []
    if p in _DIR_RUNNERS:
        return [(cwd, True)] if cwd else []
    return []


def _pip_runs(a, cwd):
    if not a or a[0] not in ("install", "wheel", "download") and "install" not in a[:1]:
        return []
    out = []
    i = 1
    while i < len(a):
        t = a[i]
        if t in ("-e", "--editable", "-r", "--requirement", "-c", "--constraint") and i + 1 < len(a):
            r = _abs(a[i + 1], cwd)
            if r:
                out.append((r, t in ("-e", "--editable")))
            i += 2
            continue
        if not t.startswith("-") and not host_of(t) and (t in (".", "..") or t.startswith(("./", "../", "/")) or t.endswith((".whl", ".tar.gz", ".zip", ".tgz"))):
            r = _abs(t, cwd)
            if r:
                out.append((r, not t.endswith((".whl", ".tar.gz", ".zip", ".tgz"))))
        i += 1
    return out


def _remote_now(toks):
    """-> the host when this one command fetches code and runs it itself (npx github:o/r, uvx --from git+URL, pip install git+URL,
    npm i URL, pipx run --spec URL, go run host/x@v), else None"""
    if not toks:
        return None
    p = toks[0].rsplit("/", 1)[-1]
    a = toks[1:]
    specs = []
    if p in ("npx", "bunx") or (p in ("pnpm", "yarn") and a[:1] == ["dlx"]) or (p == "npm" and a[:1] in (["exec"], ["x"])):
        specs = [t.split("=", 1)[1] if t.startswith("--package=") else t for t in a if not t.startswith("-") or t.startswith("--package=")]
        specs = specs[:3]
    elif p in ("uvx", "pipx") or (p == "uv" and a[:2] == ["tool", "run"]):
        for i, t in enumerate(a):
            if t in ("--from", "--spec", "--with") and i + 1 < len(a):
                specs.append(a[i + 1])
            elif t.startswith(("--from=", "--spec=", "--with=")):
                specs.append(t)
        specs += [t for t in a if not t.startswith("-")][:2]
    elif p in ("pip", "pip3") or re.fullmatch(r"(python|pypy)[0-9.]*", p) and a[:2] == ["-m", "pip"] or (p == "uv" and a[:1] == ["pip"]):
        specs = [t for t in a if not t.startswith("-")]
    elif p in _PKG and a[:1] and a[0] in ("install", "i", "add", "in", "ins", "isntall"):
        specs = [t for t in a[1:] if not t.startswith("-")]
    elif p == "go" and a[:1] in (["run"], ["install"]):
        for t in a[1:]:
            m = re.match(r"^([a-z0-9.\-]+\.[a-z]{2,})/[^@\s]+@", t)
            if m:
                return m.group(1).lower()
    elif p in ("cargo",) and "install" in a[:1]:
        for i, t in enumerate(a):
            if t == "--git" and i + 1 < len(a):
                specs.append(a[i + 1])
    for s in specs:
        h = host_of(s)
        if h:
            return h
    return None


def line_fetch(cmd, cwd):
    """-> ({abs path: host} the line downloads into, [(abs path, is folder, cwd at that point)] what it runs AFTER a fetch in the same
    line that lies in what it fetched -> host, host of a command that fetches and runs at once or None). Never raises."""
    try:
        if not isinstance(cmd, str) or len(cmd) > 20000:
            return {}, None
        got, now, c = {}, None, cwd
        for seg in _segs(cmd):
            t = _toks(seg)
            if not t:
                continue
            f, nc = _fetch_of(t, c)
            if nc:
                c = nc
                continue
            for r, _d in _run_of(t, c):
                for fp, h in got.items():
                    if r and _within(r, fp):
                        now = now or h
            now = now or _remote_now(t)
            got.update(f)
        return dict(list(got.items())[:NF_MAX]), now
    except Exception:      # noqa: BLE001
        return {}, None


def line_runs(cmd, cwd):
    """-> [(abs path, is folder)] every file / folder whose code the line runs (cd inside the line followed). Never raises."""
    out = []
    try:
        c = cwd
        for seg in _segs(cmd):
            t = _toks(seg)
            if t and t[0] == "cd":
                d = next((x for x in t[1:] if not x.startswith("-")), None)
                c = _abs(d, c) or c
                continue
            out += [x for x in _run_of(t, c) if x[0]]
    except Exception:      # noqa: BLE001
        pass
    return out


def fetch_marks(ctx, agent_id, tool, args, t0):
    """-> {path: host} for the row of a shell part: the paths the line downloads into, and -- for a shell write part -- the paths it writes
    while it names a downloaded path (an extraction, a copy, a rename: the provenance moves on). {} for anything else."""
    if not (isinstance(tool, str) and tool.split(".", 1)[0] == "Bash" and isinstance(args, dict) and isinstance(args.get("command"), str)):
        return {}
    w = _w(args)
    cwd = w.get("cwd") if isinstance(w.get("cwd"), str) else w.get("project")
    cwd = cwd if isinstance(cwd, str) else None
    out, _now = line_fetch(args["command"], cwd)
    if tool == "Bash.write":
        wr = [_canon(p) for p in (w.get("writes") or []) if isinstance(p, str) and p.startswith("/")]
        if wr:
            known = fetches(ctx, agent_id, t0)
            known.update(out)
            if known:
                named = [_canon(p) for p in _line_paths(args["command"], cwd)]
                h = next((known[k] for n in named if n for k in known if _within(n, k) or _within(k, n)), None)
                if h:
                    for p in wr:
                        if p and p not in out:
                            out[p] = h if not isinstance(h, tuple) else h[0]
    return {k: (v[0] if isinstance(v, tuple) else v) for k, v in list(out.items())[:NF_MAX]}


def fetches(ctx, agent_id, t0):
    """-> {path: (host, at)} of what this agent downloaded (or extracted / copied from a download) within FETCH_LOOKBACK_S, from rows that
    ran; a whole-file Write the witness judged after it ends the mark of that path (its text is the agent's now, judged as such)."""
    out = {}
    try:
        rows = ctx.db.q("SELECT rowid AS n, rid, agent_id, status, created_at, exec_json, tool, recipient FROM actions WHERE agent_id=? AND "
                        "created_at>? AND status IN (%s) AND exec_json LIKE '%%\"nf\"%%' ORDER BY rowid LIMIT 2000"
                        % ",".join("?" * len(SEEN)), (agent_id, t0 - FETCH_LOOKBACK_S) + SEEN)
        if not rows:
            return {}                     # the common case: nothing downloaded in this session (one indexed query, no more)
        rows = list(rows) + list(ctx.db.q(
            "SELECT rowid AS n, rid, agent_id, status, created_at, NULL AS exec_json, tool, recipient FROM actions WHERE agent_id=? AND "
            "rowid>? AND status IN (%s) AND tool IN ('Write','Write.danger') ORDER BY rowid LIMIT 2000" % ",".join("?" * len(SEEN)),
            (agent_id, rows[0]["n"]) + SEEN))
        rows.sort(key=lambda r: r["n"])
    except Exception:      # noqa: BLE001
        return {}
    from app.actions import unrun_write
    for r in rows:
        if r["tool"] in ("Write", "Write.danger"):
            cp = _canon(r["recipient"])
            if cp:
                out.pop(cp, None)
            continue
        try:
            nf = json.loads(r["exec_json"]).get("nf")
        except (TypeError, ValueError, AttributeError):
            continue
        if not isinstance(nf, dict) or unrun_write(ctx, r) or _waits(ctx, r):
            continue
        for p, h in nf.items():
            cp = _canon(p)
            if cp and isinstance(h, str) and (cp not in out or out[cp][0] != h):
                out[cp] = (h, r["created_at"] or 0)
    return out


def net_code(ctx, agent_id, args, t0):
    """-> {"host", "at" (0 = in this very line), "path"} when the shell line runs code downloaded in this agent's session (or downloads and
    runs it itself), else None"""
    cmd = args.get("command") if isinstance(args, dict) else None
    if not isinstance(cmd, str):
        return None
    w = _w(args)
    cwd = w.get("cwd") if isinstance(w.get("cwd"), str) else w.get("project")
    cwd = cwd if isinstance(cwd, str) else None
    _got, now = line_fetch(cmd, cwd)
    if now:
        return {"host": now[:253], "at": 0}
    runs = line_runs(cmd, cwd)
    if not runs:
        return None
    known = fetches(ctx, agent_id, t0)
    best = None
    for r, _d in runs:
        for fp, (h, at) in known.items():
            if _within(r, fp) and (best is None or at > best["at"]):
                best = {"host": h[:253], "at": int(at), "path": fp[:1024]}
    return best


def net_code_words(nc, created_at, pinned_has=True):
    """-> the one short line of harm for a run of downloaded code (vocabulary "screen" net_code_*), or the older vocabulary's own sentence
    when the mandate pinned a vocabulary without it (r0294: an owner's signed words stay inside what they agreed to; the fact is under
    Details), or None"""
    from app.qwords import SCREEN as S, DANGER_WORDS
    if not isinstance(nc, dict) or not isinstance(nc.get("host"), str):
        return None
    if not pinned_has:
        return DANGER_WORDS["install"][1]
    from app.qwords import _clean
    h = _clean(nc["host"], 60)
    at = nc.get("at")
    if not at or not isinstance(at, int):
        return S["net_code_now"].format(t=h)
    mins = max(1, int(((created_at or at) - at) // 60)) if isinstance(created_at, int) else None
    when = S["when_min"].format(n=mins) if mins is not None and mins < 120 else (S["when_h"].format(n=mins // 60) if mins is not None else S["when_earlier"])
    return S["net_code_run"].format(t=h, when=when)


def net_code_detail(nc):
    """the line under Details: where the code came from (the host quoted here is what the first screen's {t} names)"""
    from app.qwords import _clean
    if not isinstance(nc, dict) or not isinstance(nc.get("host"), str):
        return None
    if nc.get("path"):
        return "Downloaded from %s: %s" % (_clean(nc["host"], 60), _clean(nc["path"], 300))
    return "Code from %s, fetched by this command" % _clean(nc["host"], 60)
