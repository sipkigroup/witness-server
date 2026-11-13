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
        for r in ctx.db.q("SELECT fx_keys FROM actions WHERE agent_id=? AND class='delete' AND created_at>? AND status IN (%s) "
                          "AND fx_keys LIKE '%%\"wrote:%%' ORDER BY rowid DESC LIMIT 500" % ",".join("?" * len(SEEN)),
                          (agent_id, t0 - 60 * WRITTEN_LOOKBACK_MIN) + SEEN):
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


KIND_WORDS = {"sec": "reading a secret", "out": "changing files outside the project", "net": "sending data to this site",
              "exit": "publishing", "persist": "a change that starts by itself later"}


def words(rb, created_at):
    """the short line of the question (harm) when the owner refused the same effect before; None when there is no mark"""
    if not isinstance(rb, dict) or not isinstance(rb.get("at"), int):
        return None
    mins = max(1, int(((created_at or rb["at"]) - rb["at"]) // 60)) if isinstance(created_at, int) else None
    when = "%d min ago" % mins if mins is not None and mins < 120 else ("%d h ago" % (mins // 60) if mins is not None else "earlier")
    return "You said No to this %s; the agent is trying another way." % when


def detail(rb):
    k = KIND_WORDS.get(rb.get("key") if isinstance(rb, dict) else None, "the same effect")
    t = rb.get("tool") if isinstance(rb, dict) and isinstance(rb.get("tool"), str) else "another tool"
    return "You refused %s when the agent asked through %s. This request reaches the same effect another way." % (k, t or "another tool")
