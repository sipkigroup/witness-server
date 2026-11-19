"""r0330 (ARHIV-RESHENIY-OPUS-1611 §2, plan step 1): the CONSEQUENCE VECTOR of one call, in SHADOW mode.

A deterministic function, no model, no I/O of its own: it reads what the server already computed for the call (the parts the hook judge
mapped and their `_witness`: danger / net / writes / commands / outside_writes / carried / sandbox; the written-run marks of this agent the
caller passes in; the immutable articles of app/constitution) and returns

    {"v": 1, "zapis": {...}, "chtenie": ..., "set": [...], "kod": ..., "dengi": ..., "publ": [...], "zashch": [...], "otkat": ...,
     "neprozr": [axes the grammar could not compute], "uroven": "U0".."U3", "pochemu": [axis:value that set the level]}

Axes (the plan's names): zapis = "запись и удаление" (zones), chtenie = "чтение", set = "сеть" (destinations: host, method, identity),
kod = "чужой код", dengi = "деньги", publ = "публикация", zashch = "защиты ОС и наблюдение", otkat = "откат".

Levels (max over the axes):  U0 silent with a receipt; U1 silent once the person said "from now on" for this consequence; U2 asked every
time; U3 refused without a question (articles Н1-Н10, app/constitution.check).
LAW OF THE UNKNOWN: an axis the grammar did not compute is "neprozr" (opaque) and the level is at least U2. Inside the strict sandbox
(`_witness.sandbox.strict`) the code / network of the line is held by the kernel: those axes fall to U1 (never below), nothing else does.

SHADOW: the vector is written next to the verdict (actions.shadow, the log); it never changes a verdict. Every entry point is wrapped:
an exception here yields {"v": 1, "oshibka": ...} with level U2 (an error is opaque, never silence) and the verdict is untouched.
Only zones and hosts are kept, never a path or a command text (the row outlives the decided preview).
"""
from __future__ import annotations

import re

V = 1
LEVELS = ("U0", "U1", "U2", "U3")
OPAQUE = "neprozr"

# tools with no consequence outside the agent's own conversation (Claude Code's internal tools)
INTERNAL_TOOLS = frozenset({"TodoWrite", "TodoRead", "Task", "Agent", "ExitPlanMode", "EnterPlanMode", "BashOutput", "KillShell", "KillBash",
                            "AskUserQuestion", "Skill", "SlashCommand", "ToolSearch", "TaskOutput", "TaskStop", "TaskCreate", "TaskGet",
                            "TaskList", "TaskUpdate", "Monitor"})
READ_TOOLS = frozenset({"Read", "Grep", "Glob", "LS", "NotebookRead"})
WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})

# programs whose network use the line names (the method is read from their flags); any other program that reaches the network makes
# the method opaque
_SEND_FLAG = re.compile(r"(?:^|\s)(?:-d|--data(?:-[a-z]+)?|-F|--form(?:-string)?|--json|--post-data|--post-file|--body-data|--body-file"
                        r"|-T|--upload-file|-X\s*['\"]?(?:POST|PUT|PATCH|DELETE)|--request[=\s]+['\"]?(?:POST|PUT|PATCH|DELETE)"
                        r"|--method[=\s]+['\"]?(?:POST|PUT|PATCH|DELETE))(?=[\s=@'\"]|$)", re.I)
_FILE_FLAG = re.compile(r"(?:^|\s)(?:-d|--data(?:-[a-z]+)?|-F|--form|--json|--post-file|--body-file|-T|--upload-file)[\s=]+['\"]?[^\s'\"]*@"
                        r"|(?:^|\s)(?:--post-file|--body-file|-T|--upload-file)(?=[\s=])", re.I)
_CONFIG_FLAG = re.compile(r"(?:^|\s)(?:-K|--config|-q|--disable|-e|--execute|--input-file|-i)(?=[\s=]|$)")
_IDENTITY = re.compile(r"(?i)(?:-H|--header)[\s=]+['\"]?\s*(?:authorization|cookie|x-api-key|x-auth-token|private-token|proxy-authorization)\s*:"
                       r"|(?:^|\s)(?:-u|--user|--oauth2-bearer|--negotiate|--netrc(?:-file|-optional)?|-n|-b|--cookie)(?=[\s=]|$)"
                       r"|\$\{?[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|AUTH)[A-Z0-9_]*\}?"
                       r"|\b(?:gh|glab)\s+auth\s+token\b")
_FETCHER_BASES = frozenset({"curl", "wget", "http", "https", "xh", "httpie", "aria2c", "fetch"})
_AMOUNT = re.compile(r"(?i)(?:--amount[=\s]+|\bamount[=:]\s*|-d\s+amount=)['\"]?(\d{1,15})")
_PUBLISH_HEAD = re.compile(r"(?i)^(?:git push|(?:npm|yarn|pnpm|cargo|poetry|flit|hatch|uv|twine|gem) (?:publish|upload|push)"
                           r"|(?:docker|podman|helm) push|gh (?:pr|issue|release|repo|gist|api|secret)|glab (?:mr|issue|release)"
                           r"|(?:vercel|netlify|wrangler|flyctl|fly|firebase|heroku) (?:deploy|publish|release))\b")
_IDN = re.compile(r"(?:^|\.)xn--|[^\x00-\x7f]")
_LOOPBACK = re.compile(r"^(?:localhost|127(?:\.\d{1,3}){3}|::1|0\.0\.0\.0)$", re.I)
_INLINE_STDIN = re.compile(r"<<-?\s*['\"]?\w|<<<|\|\s*(?:python[0-9.]*|node|ruby|perl|php|bash|sh|zsh|lua|deno|bun)(?:\s+-)?\s*(?:$|[;&|)])")

# danger categories the vector knows (bashparse / mapping / sandbox); any other category is an opaque axis "prochee"
_KNOWN_DANGER = {"secrets", "persist", "autostart", "defense", "git-config", "agent-config", "witness", "write-outside", "rm-rf",
                 "pipe-to-shell", "net-out", "exit", "money", "opaque", "disk", "sql-drop", "loopback-write", "git-destroy", "git-force-push", "witness-off", "git-no-verify"}


def _lv(x):
    return LEVELS.index(x)


class _Acc:
    """axes being filled; `up(level, why)` raises the level and remembers why"""

    def __init__(self):
        self.zapis = {"zony": [], "udalenie": False}
        self.chtenie = None
        self.set = []
        self.kod = "net"
        self.dengi = None
        self.publ = []
        self.zashch = []
        self.otkat = None
        self.neprozr = []
        self.level = "U0"
        self.why = []
        self.strict = False
        self.exits = []
        self.kod_why = []
        self.remote = False                               # r0331: the remote command of an ssh line (no project, no person's code)
        self.udal = []                                    # r0331: the remote commands' own vectors (host, level, code, zones)

    def up(self, level, why):
        if _lv(level) > _lv(self.level):
            self.level, self.why = level, [why]
        elif level == self.level and why not in self.why and _lv(level) > 0:
            self.why.append(why)

    def zone(self, z):
        if z not in self.zapis["zony"]:
            self.zapis["zony"].append(z)

    def opaque(self, axis):
        if axis not in self.neprozr:
            self.neprozr.append(axis)
        self.up("U2", axis + ":" + OPAQUE)

    def code(self, value, why=None):
        order = ("net", "proekt", "chelovek", "agent", "skachannyy", OPAQUE)
        if order.index(value) > order.index(self.kod):
            self.kod = value
        if why and value == OPAQUE and len(self.kod_why) < 4 and why[:40] not in self.kod_why:
            self.kod_why.append(why[:40])                 # a program's base name and the rule, never a path


def _w(args):
    w = args.get("_witness") if isinstance(args, dict) else None
    return w if isinstance(w, dict) else {}


def _in(p, d):
    return isinstance(p, str) and isinstance(d, str) and d.startswith("/") and (p == d or p.startswith(d.rstrip("/") + "/"))


def _temp(p, home):
    try:
        from app.hookjudge.bashparse import temp_in
        return bool(temp_in(p, home))
    except Exception:  # noqa: BLE001
        return bool(re.match(r"^(/private)?/(tmp|var/folders)/", p or ""))


def _base(head):
    h = (head or "").split(" [", 1)[0].strip("'\"\\")
    first = h.split(" ", 1)[0]
    try:
        from app.hookjudge.runners import canon
        return canon(first.rsplit("/", 1)[-1]), first, h
    except Exception:  # noqa: BLE001
        return first.rsplit("/", 1)[-1], first, h


def _write_zone(acc, path, w, home, deleting=False):
    project = w.get("project") if isinstance(w.get("project"), str) else None
    if deleting:
        acc.zapis["udalenie"] = True
    if project and _in(path, project):
        acc.zone("proekt")
        git = bool(w.get("branch"))
        if deleting:
            acc.up("U1", "zapis:udalenie_v_proekte")      # an untracked file is not in git: a delete is not proven reversible
        elif not git:
            acc.up("U1", "zapis:proekt_bez_git")
        acc.otkat_add("git" if git else "net")
    elif _temp(path, home):
        acc.zone("vremennaya")
    else:
        acc.zone("sistema")
        acc.up("U2", "zapis:sistema")
        acc.otkat_add("net")


def _otkat_add(self, v):
    order = ("ne_nuzhen", "git", "snimok", "net")
    if self.otkat is None or order.index(v) > order.index(self.otkat):
        self.otkat = v


_Acc.otkat_add = _otkat_add


def _danger(acc, d, w, home, cmd):
    if not isinstance(d, str):
        return
    cat, _, det = d.partition(":")
    if cat not in _KNOWN_DANGER:
        acc.opaque("prochee")
        return
    if cat == "secrets":
        acc.chtenie = "sekret"
        acc.up("U2", "chtenie:sekret")
    elif cat in ("persist", "autostart"):
        acc.zone("avtozapusk")
        acc.up("U2", "zapis:avtozapusk")
        acc.otkat_add("net")
    elif cat == "agent-config" or cat == "witness":
        acc.zone("konfig_agenta")
        acc.up("U2", "zapis:konfig_agenta")
    elif cat == "write-outside" or cat == "disk":
        acc.zone("sistema")
        acc.up("U2", "zapis:sistema")
        acc.otkat_add("net")
    elif cat == "defense":
        acc.zashch.append("os")
        acc.up("U2", "zashch:os")
    elif cat == "witness-off":                       # r0333: the witness itself removed / stopped (Н3)
        acc.zashch.append("witness")
        acc.up("U2", "zashch:witness")
    elif cat in ("git-config", "git-no-verify"):       # r0345: the hooks switched off for one command (Н3)
        acc.zashch.append("git")
        acc.up("U2", "zashch:git")
    elif cat in ("rm-rf", "sql-drop", "git-destroy"):
        acc.zapis["udalenie"] = True
        acc.zone("sistema" if cat == "rm-rf" else ("baza" if cat == "sql-drop" else "git_istoriya"))
        acc.up("U2", "zapis:udalenie_" + cat)
        acc.otkat_add("net")
    elif cat == "pipe-to-shell":
        acc.code("skachannyy")
        acc.up("U2", "kod:skachannyy")
    elif cat in ("net-out", "loopback-write"):
        acc.set.append({"host": "localhost" if cat == "loopback-write" else None, "prog": _base(det)[0][:40], "metod": "otpravka",
                        "lichnost": "net"})
    elif cat == "exit":
        acc.exits.append(det)
    elif cat == "money":
        m = _AMOUNT.search(cmd or "")
        acc.dengi = {"prog": _base(det)[0][:40], "summa": int(m.group(1)) if m else None}
        acc.up("U2", "dengi")
    elif cat == "git-force-push":
        acc.publ.append("git:force")
        acc.up("U2", "publ")
    elif cat == "opaque":
        if det.startswith("remote service CLI: "):
            acc.set.append({"host": None, "prog": det[len("remote service CLI: "):][:40], "metod": OPAQUE, "lichnost": "akkaunt"})
            acc.opaque("set")
        else:
            acc.code(OPAQUE, "metka_parsera")
            acc.opaque("kod")


# ---------------------------------------------------------------------------------------------------------------------------------
# r0331 (ARHIV-RESHENIY-OPUS-1611 §2-§3, the catalogue of forms): forms the vector COMPUTES that r0330 left opaque. Shadow only: none of
# this is read by a decision. Each form reads the simple commands the parser recorded for the vector (bashparse._vk_cmd: the program, its
# words after quote removal, the directory it ran in, its stdin) -- `place["vk"]` -- and the realpath facts of the call (`place["rp"]`);
# with no record (a plain /v1/actions call, an older path) every form below stays as r0330 had it (opaque).
#   1. ssh / scp / rsync over ssh: the host, the kind (a remote command, a tunnel -L/-R/-D/-W, a file out, a file in); the remote command is
#      judged as a CALL OF ITS OWN on another machine (no project, no marks, no fact of this machine: the carrier lends it nothing).
#   2. a program / script by a path outside the project that this agent did not write (written_run marks): "chelovek" -- the person's own
#      code outside the project; a temp folder, a link, a non-ASCII path, a file this line made: still opaque (never toward silence).
#   3. variables: a literal assigned once in the same line is substituted before the "code from a variable" check; a value from the
#      environment / a substitution stays opaque.
#   4. gh / az: a read (list / view / show ...) is a network read as the person's account (U1); a change / run (create, run, rerun,
#      delete ...) is "publ:vneshniy_servis" (U2); any other sub-command stays opaque.
REMOTE_HOME = "/(remote home)"
_SSH_VAL = set("bcDEeFIiJLlmOopQRSWw")
_SSH_TUNNEL = set("LRDW")
_SSH_FLAG_OK = set("46qvtTnNfCKkyBg")
_SSH_VAL_OK = set("plicmbeLRDW")                          # -o is read by its key below; -F -J -E -S -O -I -Q -w: not computed
_SSH_O_OK = frozenset({"connecttimeout", "batchmode", "serveraliveinterval", "serveralivecountmax", "loglevel", "connectionattempts", "port",
                       "user", "identitiesonly", "compression", "requesttty", "identityfile"})
_HOST_OK = re.compile(r"^(?:[A-Za-z0-9_.+-]+@)?(?:[A-Za-z0-9_.-]+|\[[0-9A-Fa-f:.]+\])$")
_REMOTE_OP = re.compile(r"^(?:[A-Za-z0-9_.+-]+@)?(?:[A-Za-z0-9_.-]+|\[[0-9A-Fa-f:.]+\]):")
_RSYNC_SHORT_OK = set("avzrlptgoDhHPnucixWSAXEqRLkKOJdmyb0C")
_RSYNC_LONG_OK = frozenset({"--archive", "--verbose", "--compress", "--recursive", "--links", "--perms", "--times", "--group", "--owner",
                            "--devices", "--specials", "--human-readable", "--partial", "--progress", "--dry-run", "--update", "--checksum",
                            "--itemize-changes", "--whole-file", "--sparse", "--acls", "--xattrs", "--quiet", "--relative", "--copy-links",
                            "--hard-links", "--delete", "--delete-after", "--delete-before", "--delete-during", "--delete-excluded",
                            "--stats", "--inplace", "--append", "--append-verify", "--ignore-existing", "--existing", "--size-only",
                            "--no-perms", "--no-owner", "--no-group", "--no-times", "--omit-dir-times", "--prune-empty-dirs", "--safe-links",
                            "--copy-unsafe-links", "--mkpath", "--numeric-ids", "--one-file-system", "--cvs-exclude", "--no-motd",
                            "--exclude", "--include", "--filter", "--exclude-from", "--include-from", "--files-from", "--chmod", "--timeout",
                            "--bwlimit", "--max-size", "--min-size", "--info", "--out-format", "--contimeout", "--modify-window",
                            "--compare-dest", "--copy-dest", "--link-dest", "--backup", "--suffix", "--from0", "--protect-args", "-s"})
_RSYNC_VAL = frozenset({"--exclude", "--include", "--filter", "--exclude-from", "--include-from", "--files-from", "--chmod", "--timeout",
                        "--bwlimit", "--max-size", "--min-size", "--info", "--out-format", "--contimeout", "--modify-window",
                        "--compare-dest", "--copy-dest", "--link-dest", "--suffix", "-e", "--rsh", "-f"})
_RSH_OK = re.compile(r"^ssh(?:\s+-[46qCTx]+|\s+-p\s*\d{1,5}|\s+-o\s*(?:ConnectTimeout|BatchMode|Port|User)=\S+)*$")
_GH_CHANGE = {"pr": {"create", "edit", "close", "reopen", "merge", "comment", "review", "ready", "lock", "unlock"},
              "issue": {"create", "edit", "close", "reopen", "comment", "delete", "transfer", "pin", "unpin", "lock", "unlock", "develop"},
              "run": {"rerun", "cancel", "delete"}, "workflow": {"run", "enable", "disable"},
              "release": {"create", "edit", "delete", "upload", "delete-asset"},
              "repo": {"create", "edit", "delete", "fork", "archive", "unarchive", "rename", "sync", "set-default"},
              "label": {"create", "edit", "delete", "clone"}, "secret": {"set", "delete"}, "variable": {"set", "delete"},
              "gist": {"create", "edit", "delete", "rename"}, "cache": {"delete"}}
_GH_EXTRA_READ = {("auth", "status"), ("secret", "list"), ("variable", "list"), ("cache", "list"), ("gist", "list"), ("gist", "view"),
                  ("repo", "list"), ("release", "list"), ("ruleset", "list"), ("ruleset", "view")}
_AZ_CHANGE = frozenset({"create", "delete", "update", "set", "start", "stop", "restart", "deallocate", "deploy", "invoke", "add", "remove",
                        "assign", "purge", "scale", "upload", "import", "resize", "redeploy", "reimage", "generalize", "capture",
                        "rename", "move", "cancel", "enable", "disable", "approve", "reject", "renew", "restore", "swap", "sync", "put",
                        "patch", "run", "execute", "attach", "detach", "reset", "rotate", "regenerate", "grant", "revoke", "unassign"})
_AZ_SECRETISH = re.compile(r"(?i)key|secret|token|credential|password|connection|sas|cert|login|logout")
_HUMAN_DIR_RUNNERS = frozenset({"pytest", "py.test", "tox", "nox", "jest", "vitest", "mocha", "make", "gmake"})
_PKG_TEST = frozenset({"npm", "pnpm", "yarn"})


def _vk_of(pl):
    v = pl.get("vk") if isinstance(pl, dict) else None
    if not isinstance(v, dict) or v.get("cut") or not isinstance(v.get("cmds"), list):
        return None
    return v


def _abs(word, here, home):
    """a word as a path, with no file-system question: ~ / ~/x, relative to `here`; None when it is not a literal path"""
    import posixpath
    if not isinstance(word, str) or not word or re.search(r"[$`*?\[\]{}]", word) or re.match(r"~[^/]", word):
        return None
    if word == "~" or word.startswith("~/"):
        if not isinstance(home, str) or not home.startswith("/"):
            return None
        word = home + word[1:]
    if not word.startswith("/"):
        if not isinstance(here, str) or not here.startswith("/") or here.startswith("/(unknown"):
            return None
        word = posixpath.join(here, word)
    return posixpath.normpath(word)


def _unpriv(p):
    return p[len("/private"):] if isinstance(p, str) and p.startswith("/private/") else p


def _person_path(p, home, pl, writes, marks, dir_=False):
    """r0331 (form 2): -> "chelovek" | "agent" | None (opaque) for code at path `p` (a directory when dir_: code under it) outside the project"""
    if not isinstance(p, str) or not p.startswith("/") or re.search(r"[^\x21-\x7e]", p):
        return None                                       # a blank / a Cyrillic look-alike / a control character: not computed
    if re.match(r"^/(?:dev|proc)/", p):
        return None                                       # r0332: `sh <(echo ..)`, `sh /dev/stdin`: a pipe, the code is in the line
    if _temp(p, home) or (isinstance(home, str) and _in(p, home.rstrip("/") + "/Downloads")):
        return None                                       # anyone writes there (the agent's scratch, a download): whose code is unknown
    if any(isinstance(x, str) and (p == x or _in(x, p) or _in(p, x)) for x in writes or ()):
        return None                                       # this line writes it: its identity is not its name
    rp = pl.get("rp") if isinstance(pl, dict) else None
    real = rp.get(p) if isinstance(rp, dict) else None
    if not isinstance(real, str):
        return None                                       # the hook did not report where it really is: a link is not ruled out
    if _unpriv(real.rstrip("/")) != _unpriv(p.rstrip("/")):
        return None                                       # a symlink (`~/.claude/tools/x.sh -> /tmp/y.sh`): never the person's by its name
    pl = pl if isinstance(pl, dict) else {}
    if pl.get("wa_cut"):
        return None                                       # r0332: the record of the agent's writes was cut: whose code is unknown
    pu, ru = _unpriv(p), _unpriv(real)
    for m in list(marks or ()) + list(pl.get("wa") or ()):
        mu = _unpriv(m) if isinstance(m, str) else None
        if isinstance(m, str) and (m in (p, real) or mu in (pu, ru) or _in(pu, mu) or _in(ru, mu) or (dir_ and (_in(mu, pu) or _in(mu, ru)))):
            return "agent"                                # the agent wrote / changed it (written_run marks; r0332: ANY write of it, "wa")
    return "chelovek"


def _code_targets(e):
    """-> (path words, dir_) of what a recorded simple command runs as code, or None when it is not one file / folder read here"""
    name, args = e.get("name") or "", [a for a in (e.get("args") or []) if isinstance(a, str)]
    if e.get("nargs", 0) > len(args):
        return None
    try:
        from app.hookjudge import runners as R
    except Exception:  # noqa: BLE001
        return None
    argv0 = e.get("argv0") or ""
    if "/" in argv0:
        if R.is_python(name) or name in R.SHELLS or R.is_interpreter(name):
            pass                                          # `server/.venv/bin/python f.py`: the interpreter by path AND its file
        else:
            return [argv0], False
    out = [argv0] if "/" in argv0 else []
    if name in R.SHELLS:
        if any(a == "-c" or (a.startswith("-") and not a.startswith("--") and ("c" in a[1:] or "s" in a[1:])) for a in args):
            return None
        ops, skip = [], False
        for a in args:
            if skip:
                skip = False
                continue
            if a in ("-o", "+o", "-O", "+O"):
                skip = True
                continue
            if a.startswith(("-", "+")):
                continue
            ops.append(a)
            break
        return (out + ops, False) if ops and ops[0] != "-" else None
    if R.is_python(name):
        k = 0
        while k < len(args):
            a = args[k]
            if a == "-m" and k + 1 < len(args):
                return (out + [e.get("here") or ""], True) if args[k + 1] in ("pytest", "unittest") else None
            if a.startswith("-m") and len(a) > 2:
                return (out + [e.get("here") or ""], True) if a[2:] in ("pytest", "unittest") else None
            if a in ("-c",) or re.fullmatch(r"-[A-Za-z]*c\S*", a):
                return None
            if a in ("-W", "-X", "-Q"):
                k += 2
                continue
            if a == "-":
                # r0349: `python3 - ARG ... <<'EOF'`: the program is the heredoc / here-string (the law of inline code judges it); the
                # words after `-` are its sys.argv, data. With stdin from elsewhere (`python3 - x < f.py`): the first word, as before
                return None if (e.get("hd") or e.get("hs")) else ((out + [args[k + 1]], False) if k + 1 < len(args) else None)
            if a.startswith("-"):
                k += 1
                continue
            return (out + [a], False) if a != "-" else None
        return None
    if R.is_interpreter(name) or name in R.INLINE_INTERPRETERS:
        ev = R.INLINE_CODE_OPTS.get(name, frozenset())
        ops = [a for a in args if not a.startswith("-")]
        if any(a in ev for a in args) or not ops or ops[0] in ("-", "run", "eval"):
            return None
        return out + [ops[0]], False
    if name in _HUMAN_DIR_RUNNERS or (name in _PKG_TEST and args[:1] in (["test"], ["t"], ["run"])):
        if any(a in ("-f", "--file", "--makefile", "-C", "--directory", "--prefix", "-c", "--rootdir", "--config", "-p") or
               a.startswith(("--file=", "--makefile=", "--directory=", "--prefix=", "--rootdir=", "--config=", "-p")) for a in args):
            return None                                   # the code is elsewhere / a plugin by name: not "this folder"
        return out + [e.get("here") or ""], True
    return None


def _human_code(entries, home, pl, writes, marks):
    """r0331 (form 2): every recorded run of one head -> "chelovek" / "agent" / None (opaque)"""
    if not entries:
        return None
    got = set()
    for e in entries:
        t = _code_targets(e)
        if t is None:
            return None
        words, dir_ = t
        for i, wd in enumerate(words):
            p = _abs(wd, e.get("here"), home)
            r = _person_path(p, home, pl, writes, marks, dir_=dir_ and i == len(words) - 1)
            if r is None:
                return None
            got.add(r)
    return "agent" if "agent" in got else "chelovek"


def run_paths(place, home=None):
    """r0332: -> (paths, names, opaque) of what the line recorded in `place` (the parser's record, place["vk"]) RUNS as code: the files
    given to an interpreter / a shell and a program by its path, with ~ spelled out (paths); the base names of such files whose place the
    record does not resolve (names); opaque True when a carrier of the line runs a command the record does not unwrap (xargs, eval,
    source, a carrier program). Inline code (`python3 -c`, `bash -c`) is no file: the law of inline code judges it (actions.unknown_code),
    the parser unwraps a shell's -c. None when there is no record. Decides nothing by itself (actions.written_runs)."""
    vk = _vk_of(place)
    if vk is None:
        return None
    home = home or (place.get("home") if isinstance(place, dict) else None)
    out, names, opaque = set(), set(), False
    try:
        from app.hookjudge import runners as R
    except Exception:  # noqa: BLE001
        return None
    for e in vk["cmds"]:
        if not isinstance(e, dict):
            opaque = True
            continue
        name = e.get("name") or ""
        t = _code_targets(e)
        if t is None:
            if name in R.CARRIERS or name in ("source", ".", "xargs", "eval", "exec", "env", "command", "builtin", "parallel", "watch"):
                opaque = True
            continue
        words, dir_ = t
        for i, wd in enumerate(words):
            if dir_ and i == len(words) - 1:
                continue                                  # a runner of a folder (pytest, make): the folder's code, not a written file
            ap = _abs(wd, e.get("here"), home)
            if ap is None:
                if isinstance(wd, str) and wd.strip():
                    names.add(wd.rstrip("/").rsplit("/", 1)[-1])
                else:
                    opaque = True
            else:
                out.add(ap)
    return out, names, opaque


def _ssh_opts(args, flags_ok, val_ok):
    """-> (operands, tunnel, ok): the operands after ssh-style options; ok False on an option the vector does not compute"""
    k, tunnel = 0, False
    while k < len(args):
        a = args[k]
        if a == "--":
            return args[k + 1:], tunnel, True
        if not a.startswith("-") or a == "-":
            return args[k:], tunnel, True
        body, k = a[1:], k + 1
        while body:
            ch, body = body[0], body[1:]
            if ch in _SSH_VAL:
                v = body
                if not v:
                    if k >= len(args):
                        return [], tunnel, False
                    v, k = args[k], k + 1
                if ch == "o":
                    key = re.split(r"[=\s]", v.strip(), 1)[0].lower()
                    if key not in _SSH_O_OK:
                        return [], tunnel, False          # ProxyCommand / LocalCommand / KnownHostsCommand / Include / ForwardAgent ...
                elif ch not in val_ok:
                    return [], tunnel, False
                if ch in _SSH_TUNNEL:
                    tunnel = True
                body = ""
            elif ch not in flags_ok:
                return [], tunnel, False                  # -A (agent forwarding), -X / -Y (the display), -M, -s, -G, ...
    return [], tunnel, True


def _remote_vector(line):
    """the remote command, judged as a call of its own on another machine: no project, no marks, no fact of this machine"""
    from app.hookjudge import bashparse as B
    from app.hookjudge import fs as F
    tok = F.use(F.FactsFS({"home": REMOTE_HOME, "proc_cwd": REMOTE_HOME}))
    try:
        c = B.classify(line, REMOTE_HOME, REMOTE_HOME, project=None)
    finally:
        F.reset(tok)
    w2 = {"danger": list(c.danger), "writes": list(c.writes), "deletes": list(c.deletes), "net": list(c.net), "commands": list(c.heads),
          "outside": list(c.heads), "project": None, "cwd": REMOTE_HOME, "home": REMOTE_HOME}
    sub = _Acc()
    sub.remote = True
    _bash(sub, w2, line, REMOTE_HOME, set(), None)
    _net_levels(sub)
    return sub


def _ssh_entry(acc, e, home, w):
    """r0331 (form 1): one recorded ssh / scp / rsync -> True when computed (its axes added to acc), False when it stays opaque"""
    name, args = e.get("name"), [a for a in (e.get("args") or []) if isinstance(a, str)]
    if e.get("nargs", 0) > len(args) or e.get("remote"):
        return False
    if name == "ssh":
        ops, tunnel, ok = _ssh_opts(args, _SSH_FLAG_OK, _SSH_VAL_OK)
        if not ok or not ops:
            return False
        if len(ops) > 1 and ops[1].startswith("-") and ops[1] != "--":
            more, t2, ok = _ssh_opts(ops[1:], _SSH_FLAG_OK, _SSH_VAL_OK)    # OpenSSH reads options after the host too (`ssh h -N`)
            if not ok:
                return False
            ops, tunnel = ops[:1] + more, tunnel or t2
        host = ops[0][len("ssh://"):] if ops[0].startswith("ssh://") else ops[0]
        host = re.sub(r":\d{1,5}$", "", host) if ops[0].startswith("ssh://") else host
        if not _HOST_OK.match(host) and not _IDN.search(host):
            return False
        h = host.rsplit("@", 1)[-1].strip("[]").lower()
        line = " ".join(ops[1:])
        if e.get("hd") is not None:
            if re.search(r"(?m)^DW_R0331_EOF$", e["hd"]):
                return False
            line = (line + " <<'DW_R0331_EOF'\n" + e["hd"] + "\nDW_R0331_EOF") if line else e["hd"]
        elif e.get("hs") is not None:
            import shlex
            line = (line + " <<< " + shlex.quote(e["hs"])) if line else e["hs"]
        if e.get("fed") or e.get("stdin_file"):
            return False                                  # the remote side reads a stdin the line does not show
        ent = {"host": h[:255], "prog": "ssh", "lichnost": "akkaunt"}
        if _IDN.search(h):
            ent["idn"] = True
        if tunnel:
            acc.set.append(dict(ent, metod="tunnel"))
        if not line.strip():
            return tunnel                                 # `ssh h` alone: an interactive session / stdin -- not computed
        sub = _remote_vector(line)
        acc.set.append(dict(ent, metod="komanda"))
        acc.udal.append({"host": h[:255], "uroven": sub.level, "kod": sub.kod, "zony": sub.zapis["zony"], "neprozr": sub.neprozr,
                         "pochemu": sub.why[:3]})
        if sub.chtenie == "sekret":
            acc.chtenie = "sekret"
        if sub.neprozr:
            acc.opaque("udalenno")                        # what runs there is not computed: opaque, at least U2
        else:
            acc.up(LEVELS[max(_lv(sub.level), 1)], "udalenno:" + (sub.why[0] if sub.why else "komanda"))
        return True
    if name in ("scp", "rsync"):
        if name == "scp":
            ops, _, ok = _ssh_opts(args, set("rpqCv46BTO3"), set("Pilco"))
            if not ok:
                return False
        else:
            ops, k = [], 0
            while k < len(args):
                a = args[k]
                k += 1
                if a.startswith("--"):
                    o, eq, v = a.partition("=")
                    if o not in _RSYNC_LONG_OK and o not in ("--rsh",):
                        return False                      # --rsync-path / --password-file / --log-file / --daemon / anything else
                    if o in _RSYNC_VAL and not eq:
                        if k >= len(args):
                            return False
                        v, k = args[k], k + 1
                    if o == "--rsh" and not _RSH_OK.match(v.strip()):
                        return False
                    continue
                if a.startswith("-") and len(a) > 1:
                    body = a[1:]
                    while body:
                        ch, body = body[0], body[1:]
                        if ch in "ef":
                            v = body or (args[k] if k < len(args) else None)
                            if not body:
                                k += 1
                            if v is None or (ch == "e" and not _RSH_OK.match(v.strip())):
                                return False
                            body = ""
                        elif ch not in _RSYNC_SHORT_OK:
                            return False
                    continue
                ops.append(a)
        if len(ops) < 2 or any("::" in o or o.startswith(("rsync://", "scp://")) for o in ops):
            return False
        rem = [bool(_REMOTE_OP.match(o)) and not o.startswith(("/", "./", "~")) for o in ops]
        if not any(rem) or (rem[-1] and any(rem[:-1])):
            return False                                  # no remote side (a local copy: the parser's) / remote to remote
        hosts = {o.split(":", 1)[0].rsplit("@", 1)[-1].strip("[]").lower() for o, r in zip(ops, rem) if r}
        if len(hosts) != 1:
            return False
        h = hosts.pop()
        ent = {"host": h[:255], "prog": name, "lichnost": "akkaunt"}
        if _IDN.search(h):
            ent["idn"] = True
        if rem[-1]:
            acc.set.append(dict(ent, metod="fayl"))       # a file OUT of this machine
            if name == "rsync" and any(a.startswith("--delete") for a in args):
                acc.zapis["udalenie"] = True
                acc.zone("udalennaya")
            return True
        dst = _abs(ops[-1], e.get("here"), home)
        if dst is None:
            return False
        acc.set.append(dict(ent, metod="chtenie"))        # a file IN: a read of that host, written here
        _write_zone(acc, dst, w, home)
        return True
    return False


def _cli_entry(acc, e):
    """r0331 (form 4): one recorded gh / az -> True when computed (a read or a change), False when it stays opaque"""
    name, args = e.get("name"), [a for a in (e.get("args") or []) if isinstance(a, str)]
    if e.get("nargs", 0) > len(args) or e.get("fed") or e.get("stdin_file") or any(a.startswith("@") for a in args):
        return False
    if name == "gh":
        try:
            from app.hookjudge.sandbox import _gh_read
            rd = _gh_read(["gh"] + args)
        except Exception:  # noqa: BLE001
            rd = False
        pos = [a for a in args if not a.startswith("-")]
        pair = tuple(pos[:2])
        if rd or (pair in _GH_EXTRA_READ and not any(a in ("--web", "-w", "--show-token", "-t") for a in args)):
            acc.set.append({"host": "api.github.com", "prog": "gh", "metod": "chtenie", "lichnost": "akkaunt"})
            return True
        if len(pair) == 2 and pair[1] in _GH_CHANGE.get(pair[0], ()) or (pair[:1] == ("api",) and not rd and len(pos) >= 2):
            acc.publ.append(("gh:" + " ".join(pair))[:60])
            acc.set.append({"host": "api.github.com", "prog": "gh", "metod": "izmenenie", "lichnost": "akkaunt"})
            acc.up("U2", "publ:vneshniy_servis")
            return True
        return False
    if name == "az":
        path = []
        for a in args:
            if a.startswith("-"):
                break
            path.append(a)
        if not path or len(path) > 6 or any(_AZ_SECRETISH.search(x) for x in path) or path[0] in ("rest", "extension", "config", "cloud"):
            return False
        verb = path[-1]
        if verb in ("list", "show", "version") or re.fullmatch(r"(?:list|show)-[a-z-]+", verb):
            acc.set.append({"host": "management.azure.com", "prog": "az", "metod": "chtenie", "lichnost": "akkaunt"})
            return True
        if verb in _AZ_CHANGE or verb.split("-", 1)[0] in _AZ_CHANGE:
            acc.publ.append(("az:" + " ".join(path))[:60])
            acc.set.append({"host": "management.azure.com", "prog": "az", "metod": "izmenenie", "lichnost": "akkaunt"})
            acc.up("U2", "publ:vneshniy_servis")
            return True
        return False
    return False


_ASSIGN = re.compile(r"(?:^|(?<=[;&|\n(]))[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=((?:'[^'\n]*'|\"[^\"$`\\\n]*\"|[^\s;&|<>()'\"$`\\])*)(?=[\s;&|)]|$)")


def _lit_subst(cmd):
    """r0331 (form 3): the line with `$X` / `${X}` replaced by the literal X was assigned ONCE earlier in the line (`D=/tmp/x; rm -rf $D`).
    A name assigned twice, read / looped over / appended to, or assigned anything with a `$`, a backquote or a substitution keeps its `$`."""
    if not isinstance(cmd, str) or "$" not in cmd:
        return cmd
    names = re.findall(r"(?:^|[\s;&|(])(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)\+?=", cmd)
    bad = {n for n in names if names.count(n) > 1}
    bad |= set(re.findall(r"\b(?:read|for|select|mapfile|readarray|getopts|unset|local|declare|typeset)\s+(?:-\w+\s+)*([A-Za-z_][A-Za-z0-9_]*)", cmd))
    out, pos = cmd, 0
    while True:
        m = _ASSIGN.search(out, pos)
        if m is None:
            return out
        pos = max(m.end(), pos + 1)
        n, v = m.group(1), m.group(2)
        if n in bad or re.search(r"[$`]", v):
            continue
        lit = re.sub(r"'([^']*)'|\"([^\"]*)\"", lambda q: q.group(1) if q.group(1) is not None else q.group(2), v)
        if re.search(r"[\s'\"]", lit):
            continue                                       # a value with blanks: word splitting, not one word
        out = out[:m.end()] + re.sub(r"\$(?:\{%s\}|%s(?![A-Za-z0-9_]))" % (n, n), lambda _: lit, out[m.end():])


def _bash(acc, w, cmd, home, marks, pl=None):
    """one Bash call: the shared `_witness` of its parts"""
    project = w.get("project") if isinstance(w.get("project"), str) else None
    # r0331: the line as recorded for the vector -- what only a remote shell's text added is not this machine's (judged in _ssh_entry)
    vk = None if acc.remote else _vk_of(pl)
    rdm, rhd, rnt = (set(vk["rd"]), set(vk["rh"]), set(vk["rn"])) if vk else (set(), set(), set())
    by_hid = {}
    for e in (vk["cmds"] if vk else []):
        if isinstance(e, dict) and not e.get("remote"):
            by_hid.setdefault(e.get("hid"), []).append(e)
    rhd -= set(by_hid)                                    # a head this machine ALSO runs stays this machine's
    done_hid, done_prog, done_hosts = set(), set(), set()
    if vk:
        for hid, es in by_hid.items():
            if es[0].get("name") in ("ssh", "scp", "rsync"):
                n0 = len(acc.set)
                if all(_ssh_entry(acc, e, home, w) for e in es):
                    done_hid.add(hid)
                    done_hosts |= {x.get("host") for x in acc.set[n0:] if x.get("host")}
        for prog in ("gh", "az"):
            es = [e for x in by_hid.values() for e in x if e.get("name") == prog]
            if es and all(_cli_entry(acc, e) for e in es):
                done_prog.add(prog)
                done_hid |= {e.get("hid") for e in es}
    for p in w.get("writes") or []:
        _write_zone(acc, p, w, home, deleting=p in (w.get("deletes") or []))
    for p in w.get("outside_writes") or []:
        acc.zone("vne_proekta")
        acc.up("U1", "zapis:vne_proekta")
        acc.otkat_add("snimok")
    # --- network: hosts the classifier found; the method from the grammar of the line (sandbox.net_read_line: the allow-list of reads)
    try:
        from app.hookjudge.sandbox import net_read_line
        rd = net_read_line(cmd) if isinstance(cmd, str) else None
    except Exception:  # noqa: BLE001
        rd = None
    own = rd["marks"] if rd else (lambda d: False)
    for d in w.get("danger") or []:
        if d in rdm or (isinstance(d, str) and d.startswith("exit:") and d[5:].split(" [", 1)[0] in {x.split(" [", 1)[0] for x in rhd}):
            continue                                      # r0331: a mark of the remote command's text (its own vector)
        if isinstance(d, str) and (d.startswith("opaque:remote service CLI: ") and d[len("opaque:remote service CLI: "):] in done_prog
                                   or d.startswith("exit:") and _base(d[5:])[0] in done_prog):
            continue                                      # r0331 (form 4): gh / az read or change, computed above
        if own(d):                                        # the mark of a read the grammar recognised (`gh pr view`): a read as the person
            prog = d.split(": ", 1)[1] if d.startswith("opaque:") else _base(d.partition(":")[2])[0]
            if not any(e.get("prog") == _base(prog)[0] for e in acc.set):
                acc.set.append({"host": None, "prog": _base(prog)[0][:40], "metod": "chtenie", "lichnost": "akkaunt"})
            continue
        _danger(acc, d, w, home, cmd)
    read_hosts = set(rd["hosts"]) if rd else set()
    read_heads = set(rd["heads"]) if rd else set()
    heads = [h for h in (w.get("commands") or []) if isinstance(h, str) and h not in rhd]
    bases = [_base(h)[0] for h in heads]
    other_net = any(b not in _FETCHER_BASES and b not in ("git", "gh", "npm", "pnpm", "yarn", "pip", "pip3") and h not in done_hid and
                    b in ("ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "lftp", "mosh") for b, h in zip(bases, heads))
    ident = "token" if _IDENTITY.search(cmd or "") else "net"
    send = bool(_SEND_FLAG.search(cmd or ""))
    sendf = bool(_FILE_FLAG.search(cmd or ""))
    cfg = any(b in ("curl", "wget") for b in bases) and bool(_CONFIG_FLAG.search(cmd or "") and re.search(r"(?:^|\s)(?:-K|--config|--input-file|-i|-e|--execute)(?=[\s=]|$)", cmd or ""))
    sbx_hosts = set(((w.get("sbx_code") or {}).get("hosts") or [])) if isinstance(w.get("sbx_code"), dict) else set()
    for n in w.get("net") or []:
        if not isinstance(n, str):
            continue
        host = n.rsplit("@", 1)[-1].strip("[]").lower()
        if host in rnt or host[:255] in done_hosts:
            continue                                      # r0331: a host of the remote side / one ssh / scp / rsync entry computed
        e = {"host": host[:255], "metod": None, "lichnost": ident}
        if _IDN.search(host):
            e["idn"] = True                               # a look-alike host (Cyrillic letters): another destination than it reads as
        if host in read_hosts and not send and not cfg and ident == "net":
            e["metod"] = "chtenie"
        elif sendf:
            e["metod"] = "fayl"
        elif send:
            e["metod"] = "otpravka"
        else:
            e["metod"] = OPAQUE                           # a program / form the grammar does not read (ssh, code, -K, an alias)
        if host in sbx_hosts or other_net:
            e["metod"] = OPAQUE
        acc.set.append(e)
    # exits (a program acting as the person outside the session): a publication is named; the rest is opaque
    for det in acc.exits:
        b = _base(det)[0]
        if _PUBLISH_HEAD.search(det.split(" [", 1)[0]):
            acc.publ.append(det.split(" [", 1)[0][:60])
            acc.up("U2", "publ")
        elif "[packages]" in det or b in ("pip", "pip3", "npm", "pnpm", "yarn", "brew", "gem", "cargo", "go", "uv", "poetry", "bun"):
            acc.code("skachannyy")
            acc.up("U2", "kod:skachannyy")
        else:
            acc.set.append({"host": None, "prog": b[:40], "metod": OPAQUE, "lichnost": "akkaunt"})
            acc.opaque("set")
    # --- foreign code: what the line runs
    try:
        from app.hookjudge import runners as R
    except Exception:  # noqa: BLE001
        R = None
    words = [x.strip("'\"") for x in re.split(r"\s+", cmd or "") if x]
    writes = set(w.get("writes") or [])
    outside = set(x for x in (w.get("outside") or []) if isinstance(x, str))
    try:
        from app import actions as A                      # the closed-grammar law of the gate (r0323 / r0329): pure functions of the head
    except Exception:  # noqa: BLE001
        A = None
    if A is None or A._EVAL_FROM_VAR.search(_lit_subst(cmd or "")):   # r0331 (form 3): a literal of the line is not "from a variable"
        acc.code(OPAQUE, "peremennaya")                                  # code from a variable, a local service's socket: not computed
    edit_only = None
    for h in heads:
        if h.startswith("("):
            continue                                      # a pseudo-command (a write outside the project): its own axis
        b, first, plain = _base(h)
        if h in done_hid:
            continue                                      # r0331 (forms 1, 4): ssh / scp / rsync / gh / az computed above
        if R is None:
            acc.code(OPAQUE, "net_reestra")
            break
        tags = [t.strip() for t in h.split(" [", 1)[1].rstrip("]").split(",")] if " [" in h else []
        if b in ("sudo", "doas", "su", "runuser", "pkexec"):
            acc.code(OPAQUE, "prava:" + b)                              # another user's rights: the consequence is not the program's own
            continue
        if h in read_heads:
            continue                                      # a network read the grammar recognised (`gh pr view`): the network axis
        if R.is_python(b) and set(tags) <= {"eval"}:
            if edit_only is None:
                try:
                    # r0349: the edit-only list AND the closed form (hookjudge/pyform: files only by computed paths, nothing rebound) --
                    # only then are the writes the parser recorded the code's whole consequence
                    from app.hookjudge import inline as _inl
                    edit_only = bool(A._py_edit_only(cmd or "")) and _inl.closed_line(cmd or "", home)
                except Exception:  # noqa: BLE001
                    edit_only = False
            if edit_only and (tags or _INLINE_STDIN.search(cmd or "")):
                continue                                  # Python of the closed edit-only grammar (inline.edit_only): its writes are known
        uc = A.unknown_code(h, cmd or "")
        if uc and uc.startswith("code in the line"):
            acc.code("agent")                             # code in the line: the agent wrote it now
            continue
        if uc and not uc.startswith("a program of the agent"):
            acc.code(OPAQUE, "neizvestnyy_kod:" + b)
            continue
        if any(t not in A._DATA_TAGS for t in tags):
            acc.code(OPAQUE, "flag:" + b)                              # a flag outside the grammar the witness reads (`git status [-c]`, `make [--eval]`)
            continue
        if not R.head_runs_code(h, words):
            if R.closed_grammar(b) or ("/" in first and A._SYSTEM_PROG.match(first) and R.closed_grammar(first.rsplit("/", 1)[-1])):
                continue                                  # the shelf "form": runs no text it is handed; its effects are the other axes
            acc.code(OPAQUE, "tekst_programme:" + b)                              # tar / zip / man / less / patch: may run a text they are handed
            continue
        if b in R.WRAPPER_WORDS and " " in plain:         # `nice ls`, `timeout 5 ls`: the program after the wrapper decides
            b = _base(plain.split(" ", 1)[1])[0]
            if R.closed_grammar(b) and b not in R.CARRIERS and " [" not in h:
                continue
        far = project is None or h in outside             # the program ran outside the project (or there is no project)
        if "/" in first:
            p = first if first.startswith("/") else None
            cwd = w.get("cwd") if isinstance(w.get("cwd"), str) else project
            if p is None and first.startswith("~"):
                p = _abs(first, cwd, home) or "/(unknown)"   # r0331: `~/x.sh` is the home's, never "<cwd>/~/x.sh" (r0330 read it as the project's)
            if p is None and isinstance(cwd, str):
                import posixpath
                p = posixpath.normpath(posixpath.join(cwd, first))
            if p in writes or any(_in(p, x) for x in writes):
                acc.code(OPAQUE, "sdelana_v_stroke")                          # a program this line made (a link, a copy): its identity is not its name
            elif p in marks or any(isinstance(m, str) and (p == m or _in(p, m)) for m in (pl or {}).get("wa") or ()):
                acc.code("agent")                         # r0332: any write of the agent (wa), not only a risky one
            elif not far and project and _in(p, project):
                acc.code("proekt")
            else:
                hc = _human_code(by_hid.get(h), home, pl, writes, marks) if vk else None
                if hc:
                    acc.code(hc)                          # r0331 (form 2): the person's own program outside the project / the agent's
                else:
                    acc.code(OPAQUE, "put_vne_proekta")                      # a program by a path outside the project: identity not computed
            continue
        if b in R.CARRIERS or b in ("vim", "vi", "nvim", "view", "ex", "emacs", "ed", "xargs", "parallel", "watch", "eval", "source", "."):
            acc.code(OPAQUE, "nositel:" + b)                              # a carrier: no rule is ever given to it (§3 p.2); what it carries is opaque here
            continue
        if R.is_interpreter(b) or b in R.INLINE_INTERPRETERS:
            if b in R.SHELLS and _INLINE_STDIN.search(cmd or ""):
                acc.code("agent")                         # a heredoc / here-string / pipe into a shell: code in the line
            elif b in R.SHELLS and len(heads) > 1 and not any(x.endswith((".sh", ".bash", ".zsh")) for x in words) and \
                    re.search(r"(?:^|[\s;&|(])(?:\S*/)?%s\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*c" % re.escape(b), cmd or ""):
                # r0332: only a shell with -c was unwrapped (`cd ~/notes && bash ./job.txt` ran a FILE: it read as "no code")
                continue                                  # `bash -c '...'`: the parser unwrapped it, its commands are the other heads
            elif marks:
                acc.code("agent")
            else:
                hc = _human_code(by_hid.get(h), home, pl, writes, marks) if (far and vk) else None
                acc.code(hc or (OPAQUE if far else "proekt"), "vne_proekta:" + b)   # a script outside the project: r0331 form 2, else opaque
            continue
        if b in R.TASK_RUNNERS or b in R.MAKE_RUNNERS:
            hc = _human_code(by_hid.get(h), home, pl, writes, marks) if (far and vk and not marks) else None
            acc.code("agent" if marks else (hc or (OPAQUE if far else "proekt")), "vne_proekta:" + b)
            continue
        acc.code(OPAQUE, "vne_grammatiki:" + b)                                  # a program outside the known grammar: its consequence is not computed
    if acc.kod == OPAQUE:
        acc.opaque("kod")
    elif acc.kod == "agent":
        acc.up("U2", "kod:agent")
    elif acc.kod == "skachannyy":
        acc.up("U2", "kod:skachannyy")
    elif acc.kod == "proekt":
        acc.up("U1", "kod:proekt")
    elif acc.kod == "chelovek":
        acc.up("U1", "kod:chelovek")                      # r0331: the person's code outside the project, untouched by the agent
    acc.strict = bool((w.get("sandbox") or {}).get("strict")) if isinstance(w.get("sandbox"), dict) else False


def _net_levels(acc):
    for e in acc.set:
        if e.get("metod") == "komanda" and not e.get("idn"):
            continue                                      # r0331: an ssh command's level is its remote vector's (_ssh_entry)
        if e.get("metod") == "tunnel" and not e.get("idn"):
            acc.up("U2", "set:tunnel")
        elif e.get("metod") == "chtenie" and e.get("lichnost") in ("net", "akkaunt") and not e.get("idn"):
            acc.up("U1", "set:chtenie")
        elif e.get("idn"):
            acc.up("U2", "set:idn")
        elif e.get("metod") == OPAQUE or e.get("lichnost") == OPAQUE:
            if "set" not in acc.neprozr:
                acc.neprozr.append("set")
            acc.up("U2", "set:" + OPAQUE)
        else:
            acc.up("U2", "set:%s/%s" % (e.get("metod"), e.get("lichnost")))


def vector(parts, written_marks=None, place=None):
    """parts: [(tool, args), ...] of ONE call (the hook judge's mapped parts; one pair for a direct call). written_marks: the paths this
    agent wrote with a run mark (actions.written_run_info) that the line names or runs, or None. place: {"project", "home"} of the call
    as the hook judge resolved it (hookjudge.judge._LAST_PLACE), or None. -> the vector (see the module doc)."""
    acc = _Acc()
    pl = place if isinstance(place, dict) else {}
    marks = set(written_marks or ())
    seen_bash = False
    try:
        from app import constitution
    except Exception:  # noqa: BLE001
        constitution = None
    nart = None
    for tool, args in parts:
        if not isinstance(tool, str) or not isinstance(args, dict):
            acc.opaque("prochee")
            continue
        w = _w(args)
        home = w.get("home") or w.get("sbx_home") or pl.get("home")
        if constitution is not None and nart is None:
            try:
                nart = constitution.check(tool, args)
            except Exception:  # noqa: BLE001
                nart = None
        base = tool.split(".", 1)[0]
        if base == "Bash":
            if seen_bash:
                continue                                  # the parts of one line share their `_witness`
            seen_bash = True
            _bash(acc, w, args.get("command") if isinstance(args.get("command"), str) else "", home, marks, pl)
        elif tool.endswith(".secret"):
            acc.chtenie = "sekret"
            acc.up("U2", "chtenie:sekret")
        elif base in READ_TOOLS:
            acc.chtenie = acc.chtenie or "obychnoe"
            for d in w.get("danger") or []:
                _danger(acc, d, w, home, None)
        elif tool == "Write.outside":
            acc.zone("vne_proekta")
            acc.up("U1", "zapis:vne_proekta")
            acc.otkat_add("snimok")
        elif base in WRITE_TOOLS or tool == "Write.danger":
            ds = [d for d in (w.get("danger") or []) if isinstance(d, str)]
            for d in ds:
                _danger(acc, d, w, home, None)
            p = w.get("path")
            if not ds and isinstance(p, str):
                proj = w.get("project") if isinstance(w.get("project"), str) else pl.get("project")
                if isinstance(proj, str) and _in(p, proj):
                    acc.zone("proekt")
                    acc.otkat_add("git" if w.get("branch") else "net")
                    if not w.get("branch"):
                        acc.up("U1", "zapis:proekt_otkat_ne_dokazan")    # the mapping does not send the git fact with a file write
                elif _temp(p, home):
                    acc.zone("vremennaya")
                else:
                    acc.zone(OPAQUE)
                    acc.opaque("zapis")                   # a plain write whose zone the vector cannot place
        elif tool in ("WebFetch", "WebSearch"):
            r = w.get("recipient")
            host = r.rsplit("@", 1)[-1].lower() if isinstance(r, str) else None
            if host is None:
                acc.set.append({"host": None, "metod": OPAQUE, "lichnost": "net"})
            else:
                e = {"host": host[:255], "metod": "chtenie", "lichnost": "net"}
                if _IDN.search(host):
                    e["idn"] = True
                acc.set.append(e)
        elif tool in INTERNAL_TOOLS:
            pass
        else:
            acc.opaque("instrument")                      # mcp__* and any tool the vector has no grammar for
    _net_levels(acc)
    # the strict sandbox holds code and network by the kernel: those axes fall to U1 (the law of the unknown, the third shelf)
    if acc.strict and acc.level == "U2" and all(x.split(":", 1)[0] in ("kod", "set") for x in acc.why):
        acc.level, acc.why = "U1", ["sandbox:" + ",".join(acc.why)]
    if nart is not None:
        acc.level, acc.why = "U3", ["N:" + str(nart[0])]
        if nart[0] not in acc.zashch:
            acc.zashch.append(nart[0])
    if acc.otkat is None:
        acc.otkat = "ne_nuzhen"
    return {"v": V, "zapis": acc.zapis, "chtenie": acc.chtenie or "net", "set": acc.set[:16], "kod": acc.kod, "dengi": acc.dengi,
            "publ": acc.publ[:8], "zashch": acc.zashch[:8], "otkat": acc.otkat, "neprozr": acc.neprozr, "uroven": acc.level,
            "pochemu": acc.why[:6], "sandbox": acc.strict,
            **({"kod_pochemu": acc.kod_why} if acc.kod_why else {}), **({"udalenno": acc.udal[:4]} if acc.udal else {})}


def safe_vector(parts, written_marks=None, place=None):
    """the shadow entry point: never raises; an error is an opaque vector at U2 (never silence)"""
    try:
        return vector(parts, written_marks, place)
    except Exception as e:  # noqa: BLE001
        return {"v": V, "oshibka": type(e).__name__, "neprozr": ["oshibka"], "uroven": "U2", "pochemu": ["oshibka"]}


def enabled():
    """DW_SHADOW=off turns the shadow off (the invariant test runs every vector both ways)"""
    import os
    return os.environ.get("DW_SHADOW", "on") != "off"


def note(ctx, agent, parts, rids, place=None):
    """r0330: compute the vector of one call and keep it next to its verdict (actions.shadow of every row of the call: the
    journal of actions; the signed statement and the answer to the hook are untouched).
    Decides nothing: it runs after the call's parts were judged, writes only the shadow column, and swallows every error."""
    if not enabled():
        return None
    try:
        rids = [r for r in rids if isinstance(r, str)]
        vec = call_vector(ctx, agent, parts, rids, place)
        import json
        js = json.dumps(vec, ensure_ascii=False, sort_keys=True)
        if rids:
            ctx.db.x("UPDATE actions SET shadow=? WHERE rid IN (%s)" % ",".join("?" * len(rids)), (js,) + tuple(rids))
        return vec
    except Exception:  # noqa: BLE001
        return None


def call_vector(ctx, agent, parts, rids, place=None):
    """r0348: the vector of one call with this agent's written marks and writes (the same the shadow keeps); `rids`: the call's own
    rows (their writes are not "earlier"). Used by the shadow (note) and, BEFORE the parts are judged, by the key of the call
    (app/klyuch.py). Never raises (an error is an opaque vector at U2)."""
    rids = [r for r in rids if isinstance(r, str)]
    marks = set()
    try:
        from app import actions as A
        src = {}
        look = 60 * (getattr(ctx.cfg, "written_lookback_min", None) or A.WRITTEN_LOOKBACK_MIN)
        info = A.written_run_info(ctx, agent["id"], A.now() - look, src=src)
        marks = {p for p in info if src.get(p) not in rids}
    except Exception:  # noqa: BLE001  no marks known: the code axis falls back to the line alone
        marks = set()
    try:
        # r0332 (the law of the written mark): every write of the agent in the window (not only risky ones; no write takes it off)
        # tells "the agent's code" from "the person's": a script the agent rewrote is never kod=chelovek
        from app import actions as A
        aw, cut = A.agent_written(ctx, agent["id"], A.WA_MARK_SINCE, with_cut=True)     # r0350 (Z8): the mark has no age
        place = dict(place) if isinstance(place, dict) else {}
        place["wa"] = sorted(p for p, v in aw.items() if v.get("rid") not in rids)
        if cut:
            place["wa_cut"] = True
    except Exception:  # noqa: BLE001  not known: the person's code is not computed (opaque), never toward silence
        place = dict(place) if isinstance(place, dict) else {}
        place["wa_cut"] = True
    return safe_vector(parts, marks, place)
