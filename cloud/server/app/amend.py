"""06.11 (r0260, Constitution v1 p.2): the owner's "Allow this from now on" as an AMENDMENT of the Constitution -- one KIND of act, narrow.

Law 1 of the owner: trust is given once and remembered. Before this module "from now on" existed only for an unlisted shell command of
the project's own toolbox (allowances.why_not); a request to the internet, a note written outside the project, `gh` or the agent's
memory were "only once" -- the same question every day. An amendment is the SAME signed object as a project allowance (wa-sig typ
application/aar-allowance+cbor: commands, project, mandate hash, nbf, exp; one click revokes it; the core matches it byte-exact,
svidetel_v4/decide.py _allowance_covers): its `commands` hold KIND identifiers instead of program names:

  "(network GET) <host>"               a request with no data to exactly this host (no subdomain, no other port, no redirect)
  "(network send) <host>"              a request that carries data in its body to exactly this host (never a FILE upload: Н2)
  "(write outside the project) <dir>/" a file written directly in this folder (not in its sub-folders) outside the project
  "(agent memory) <dir>/"              a note in this memory folder of the agent (~/.claude/projects/<p>/memory/)
  "(agent instructions) <file>"        this CLAUDE.md
  "(program) gh <sub>"                 `gh <sub> <read verb>` (pr / issue / run / workflow / release / repo / search) in this project
  10.11 (r0260, "from now on" everywhere -- a narrow form for the questions that had none):
  "(program) gh <sub> [GH_CONFIG_DIR=<dir>]"  the same reads with gh's configuration taken from exactly this folder
  "(program) az <path>; az <path2>"    Azure CLI reads (`az account show`, `az group list` ...: the words before the options end in show /
                                       list), exactly these sub-command paths; never keyvault / secrets / tokens / credentials / `az rest`
  "(program) npm view" ...             a read of a registry or of the local machine with exactly this sub-command: npm / pnpm / yarn
                                       view|info|show|search|outdated, docker info|version|ps|images, launchctl list|print, crontab -l
  10.11 (r0260, decision Р-1011-сеть-в-строгой: inside the strict sandbox a network READ is not asked; publication still is):
  "(publish) git push <remote> <branch>"  a push of exactly this branch to exactly this remote (no force: Н8; no tags / --all / refspec)
  "(publish) npm publish"              the project's package (no other registry / config / one-time code)
  "(publish) gh <noun> <verb> [-R r]"  gh pr create|comment|merge, gh issue create|comment, gh release create (no file: --body-file,
                                       -F, an asset, `@file` -- Н2), in this repository
  "(remote) ssh <host> <command>"      exactly this command on exactly this host (no ssh option: tunnels, ProxyCommand, agent)
  "(search path) PYTHONPATH=<dirs>"    a line that sets exactly this module search path (PYTHONPATH / NODE_PATH; literal absolute
                                       folders, `~` / $HOME allowed); never LD_* / DYLD_* / NODE_OPTIONS / PYTHONSTARTUP or any other
                                       variable that injects code
  Under the strict sandbox fact a danger mark the sandbox holds (sandbox.contained / code_contained, the hook's held K1 word) no longer
  blocks the amendment of another part of the line (before: `rm -rf build && curl https://h` offered nothing).

The gateway (actions._do_action) maps the part of a call that the core would ASK about (defer) to its kind identifier and, when an active
amendment of THIS mandate and THIS project lists it, sends the core the action with that identifier as the recipient and `dangerous`
cleared; the core must then answer OK_ALLOWANCE, else nothing changes. Order (what an amendment can never open):
  1. the core's deny stays a deny (DATA_FORBIDDEN on a credential in the call, RECIPIENT, RESOURCE ...): only a defer is turned;
  2. the immutable articles Н1-Н8 (constitution.check) -- a line that breaks one is never covered;
  3. every danger mark of the WHOLE line must be of a kind an amendment can cover: a secret read, `| sh`, force-push, rm -rf, an opaque
     part, a git hook, persistence ... anywhere in the line -> no part of it is covered;
  4. a changed executed file (exec_changed) still asks (the core checks it before any allowance);
  5. after the allow the usual holds still apply: a secret seen earlier (ESCALATE_SECRET_SEEN), egress (a user-content host with data,
     a request catcher, data + redirects, a FILE upload -> ESCALATE_DATA).
What an amendment is never offered for: a host from a variable, a request that follows redirects (curl -L, wget, httpie --follow), a file
upload, a request catcher or a user-content host for "send", a folder that is the home itself, hidden (a `.` component under ~), ~/Library,
outside the home; `gh api` / `gh auth` / `gh secret` / `gh gist` / `gh extension` / `gh repo <write>` / any write verb.
"""
from __future__ import annotations

import posixpath
import re
import shlex

from app import egress

NET_GET = "(network GET) "
NET_SEND = "(network send) "
DIR = "(write outside the project) "          # = hookjudge.mapping.OUTSIDE_WRITE (a folder: ends with "/"; the pseudo-command names a file)
MEMORY = "(agent memory) "
INSTRUCTIONS = "(agent instructions) "
PROGRAM = "(program) "
EXIT_PREFIX = "(network) "                    # = allowances.EXIT_PREFIX (a shell line's host the mandate's domains do not list)
SEARCH = "(search path) "
PUBLISH = "(publish) "                        # 10.11 (r0260, Р-1011-сеть-в-строгой): a publication the person wants to decide, narrow
REMOTE = "(remote) "                          # 10.11: exactly this command on exactly this machine over ssh
from app.hookjudge.strict_policy import PREFIXES as _STRICT_KINDS     # r0261: the reasons of the closed list (exact, this project)
KINDS = (NET_GET, NET_SEND, DIR, MEMORY, INSTRUCTIONS, PROGRAM, SEARCH, PUBLISH, REMOTE) + _STRICT_KINDS
FETCHERS = ("curl", "wget", "http", "https", "xh", "xhs")
MAX_IDS = 8                                   # = svidetel_v4 ALLOWANCE_MAX_COMMANDS

TEXT = ("Allowing this kind of request from now on is an amendment of your rules for this project: exactly what is listed (this host and "
        "this method, files directly in this folder, this memory folder, this program's read commands), for this agent, until the date "
        "shown. It never covers a line that also reads a secret, pipes a download into a shell, force-pushes, deletes outside the project, "
        "uploads a file, or changes a file a command runs; those are refused or asked each time. Revoke it in one tap under Settings -> "
        "Allowances.")

_URL = re.compile(r"(?i)\b(?:https?)://(?:[^/\s@'\"]*@)?([a-z0-9.-]+)(?::([0-9]{1,5}))?")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::[0-9]{1,5})?")
_MEMORY = re.compile(r"^(/[^\x00]+)/\.claude/projects/[^/]+/memory$")
_INSTR = re.compile(r"(^|/)CLAUDE\.md$")
_REDIRECT_CURL = re.compile(r"(?:^|\s)(?:-[a-zA-Z]*L[a-zA-Z]*|--location(?:-trusted)?)(?=\s|$)")
_REDIRECT_HTTPIE = re.compile(r"(?:^|\s)(?:--follow|-[a-zA-Z]*F[a-zA-Z]*)(?=\s|$)")
_CONFIG_CURL = re.compile(r"(?:^|\s)(?:-K|--config|--proxy|-x|--connect-to|--resolve|--unix-socket|--abstract-unix-socket|--next|-:)(?=[\s=]|$)")
# what makes curl / wget / httpie send a FILE or a credential the line does not show: headers / cookies / a query from a file, a cookie jar,
# user:password, a bearer token, a client certificate, a list of URLs from a file (wget -i)
_FROM_FILE = re.compile(r"(?:^|\s)(?:--url-query|--variable|-b|--cookie|--load-cookies|-c|--cookie-jar|-u|--user|--oauth2-bearer|"
                        r"--proxy-user|-E|--cert|--key|--netrc(?:-file|-optional)?|-n|-i|--input-file|--aws-sigv4|--negotiate|--ntlm|--digest)"
                        r"(?=[\s=]|$)|(?:^|\s)-[a-zA-Z]*[bHu](?=\S)|=@|\s@")
GH_READ = {"pr": {"list", "view", "status", "diff", "checks"}, "issue": {"list", "view", "status"}, "run": {"list", "view", "watch"},
           "workflow": {"list", "view"}, "release": {"list", "view"}, "repo": {"view"}, "search": None}
GH_MARK = "opaque:remote service CLI: gh"
GH_BAD_FLAGS = re.compile(r"(?:^|\s)(?:--body-file|--input|-F|--field|-f|--raw-field|--attach|--web|-w|--hostname)(?=[\s=]|$)|@")


# 10.11 (r0260): read-only sub-commands of programs that leave the session (a registry, the cloud, launchd), offered "from now on"
READ_CLI = {"npm": {"view", "info", "show", "v", "search", "outdated"}, "pnpm": {"view", "info", "outdated"}, "yarn": {"info", "outdated"},
            "docker": {"info", "version", "ps", "images"}, "launchctl": {"list", "print"}, "crontab": {"-l"}, "az": None}
AZ_READ_END = {"show", "list"}
AZ_NEVER = re.compile(r"(?i)keyvault|secret|credential|token|password|passwd|\bkeys?\b|login|logout|\brest\b|\bad\b|\bsp\b|"
                      r"\brole\b|connection|sas\b|--body|--file|@|appsettings|\bconfig\b|publish|access|kubeconfig|"
                      r"\benv\b|environment|\bvars?\b|identity|certificate|\bcert\b|signing")    # output that carries a secret
SEARCH_VARS = ("PYTHONPATH", "NODE_PATH")
# output of the read fed to a program that runs it: not a read any more
PIPE_RUN = re.compile(r"\|\s*(?:sudo\s+|env\s+|command\s+|exec\s+)*(?:\S*/)?(?:(?:ba|z|da|k|c|tc|fi)?sh|python[0-9.]*|node|perl|ruby|php|"
                      r"osascript|eval|source|xargs|bun|deno|lua)\b")
_SEG_END = re.compile(r"[;&|)\n]")


def program_id(prog, text, heads):
    """`prog` read sub-commands of the line -> "(program) prog a b; prog c d" (the sorted exact sub-command paths), or None when any call of
    `prog` on the line is not one of READ_CLI's reads, carries a tag (an env variable before it, a variant), or is built at run time."""
    if prog not in READ_CLI or not isinstance(text, str) or re.search(r"[`$]\(|\$\{?%s" % prog, text) or PIPE_RUN.search(text):
        return None
    hs = [h for h in heads if isinstance(h, str) and h.split(" ")[0] == prog]
    if not hs or any("[" in h for h in hs):
        return None
    paths = set()
    for m in re.finditer(r"(?:^|[\s;&|(])%s(?=\s|$)" % re.escape(prog), text):
        seg = _SEG_END.split(text[m.end():], 1)[0]
        try:
            w = shlex.split(seg)
        except ValueError:
            return None
        if prog == "az":
            path = []
            for x in w:
                if x.startswith("-"):
                    break
                path.append(x)
            if not path or path[-1] not in AZ_READ_END or AZ_NEVER.search(seg) or not all(re.fullmatch(r"[a-z][a-z0-9-]{0,40}", x) for x in path):
                return None
        else:
            if not w or w[0] not in READ_CLI[prog] or (prog == "crontab" and w != ["-l"]):
                return None
            path = [w[0]]
        paths.add(prog + " " + " ".join(path))
    if not paths or len(paths) > 6:
        return None
    i = PROGRAM + "; ".join(sorted(paths))
    return i if len(i) <= 200 else None


GH_WRITE = {("pr", "create"): 0, ("pr", "comment"): 1, ("pr", "merge"): 1, ("issue", "create"): 0, ("issue", "comment"): 1,
            ("release", "create"): 1}                                  # -> the number of positional words allowed (a number / a tag)
GH_WRITE_VALUE = {"-t", "--title", "-b", "--body", "-B", "--base", "-H", "--head", "-l", "--label", "-a", "--assignee", "-r", "--reviewer",
                  "-m", "--milestone", "-n", "--notes", "--target", "-R", "--repo", "-p", "--project"}
GH_WRITE_FLAGS = {"--draft", "-d", "--squash", "--merge", "--rebase", "-s", "--delete-branch", "--auto", "--fill", "-f", "--prerelease",
                  "--latest", "--generate-notes", "--verify-tag", "--fill-first", "--fill-verbose"}
NPM_PUBLISH_VALUE = {"--access": {"public", "restricted"}, "--tag": None}
NPM_PUBLISH_FLAGS = {"--dry-run", "--provenance"}
_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,120}")
PUBLISH_PROGS = ("git", "npm", "pnpm", "yarn", "gh", "ssh", "scp", "rsync", "sftp")


def _push_id(s):
    rest = [x for x in s[2:] if x not in ("-u", "--set-upstream")]
    if len(rest) != 2 or not all(_NAME.fullmatch(x) and ".." not in x for x in rest) or rest[1] == "HEAD":
        return None                                   # bare `git push`: the target is not on the line; a refspec / force / tags: never
    return PUBLISH + "git push %s %s" % (rest[0], rest[1])


def _npm_publish_id(s):
    k = 2
    while k < len(s):
        o, eq, v = s[k].partition("=")
        k += 1
        if o in NPM_PUBLISH_FLAGS and not eq:
            continue
        if o not in NPM_PUBLISH_VALUE:
            return None
        if not eq:
            if k >= len(s):
                return None
            v, k = s[k], k + 1
        allowed = NPM_PUBLISH_VALUE[o]
        if (allowed is not None and v not in allowed) or not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", v):
            return None
    return PUBLISH + "npm publish"


def _gh_write_id(s):
    npos = GH_WRITE.get((s[1], s[2]))
    if npos is None:
        return None
    pos, repo, k = 0, None, 3
    while k < len(s):
        a = s[k]
        k += 1
        if a.startswith("@"):
            return None
        o, eq, v = a.partition("=") if a.startswith("--") else (a, "", "")
        if o in GH_WRITE_FLAGS and not eq:
            continue
        if o in GH_WRITE_VALUE:
            if not eq:
                if k >= len(s):
                    return None
                v, k = s[k], k + 1
            if v.startswith("@"):
                return None
            if o in ("-R", "--repo"):
                if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", v) or repo not in (None, v):
                    return None
                repo = v
            continue
        if a.startswith("-"):
            return None                               # --body-file, -F, --web, --editor, --hostname, anything unknown
        pos += 1
        if not re.fullmatch(r"[A-Za-z0-9_.#/-]{1,100}", a):
            return None
    if pos > npos:
        return None                                   # `gh release create v1 dist/app.zip`: files uploaded
    return PUBLISH + "gh %s %s" % (s[1], s[2]) + (" -R %s" % repo if repo else "")


def _ssh_id(s):
    if len(s) < 3 or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,100}", s[1]):
        return None                                   # an option (-o, -R, -L, -D, -A, -i ...) or no command (an interactive shell)
    i = REMOTE + "ssh %s %s" % (s[1], shlex.join(s[2:]))
    return i if len(i) <= 200 else None


def publish_id(text):
    """10.11 (r0260): the line's ONE publication as a narrow id, or None (two publications, a form that is not narrow, a word of these
    programs that is not at the start of a simple command, a line the simple grammar cannot read)."""
    from app.hookjudge import sandbox as hsb
    segs = hsb._segments(text) if isinstance(text, str) else None
    if segs is None:
        return None
    for p in PUBLISH_PROGS:
        if len(re.findall(r"(?<![\w.-])%s(?![\w./:-])" % re.escape(p), text)) != sum(1 for x in segs if x[0] == p):
            return None
    ids = []
    for x in segs:
        if x[0] == "git" and len(x) > 1 and x[1] == "push":
            ids.append(_push_id(x))
        elif x[0] in ("npm", "pnpm", "yarn") and len(x) > 1 and x[1] == "publish":
            ids.append(_npm_publish_id(x))
        elif x[0] == "gh" and len(x) > 2 and (x[1], x[2]) in GH_WRITE:
            ids.append(_gh_write_id(x))
        elif x[0] == "ssh":
            ids.append(_ssh_id(x))
        elif x[0] in ("scp", "rsync", "sftp") or (x[0] == "git" and len(x) > 1 and x[1] in ("remote", "config", "-c")):
            return None
    if len(ids) != 1 or ids[0] is None:
        return None
    return ids[0]


def search_id(mark, text, home):
    """"opaque:code injected through PYTHONPATH=... (search path)" -> "(search path) PYTHONPATH=/a:/b" when every assignment of that
    variable on the line is the same literal list of absolute folders (`~/` / $HOME/ expanded), else None."""
    if not isinstance(mark, str) or not isinstance(text, str):
        return None
    m = re.match(r"opaque:code injected through (%s)=" % "|".join(SEARCH_VARS), mark)
    if not m or not mark.endswith("(search path)"):
        return None
    var = m.group(1)
    vals = set(re.findall(r"(?:^|[\s;&|(])(?:export\s+)?%s=(\S*)" % var, text))
    if len(vals) != 1:
        return None
    out = []
    for d in next(iter(vals)).strip("'\"").split(":"):
        for pre in ("~/", "$HOME/", "${HOME}/"):
            if d.startswith(pre):
                if not _clean_abs(home) or home == "/":
                    return None                       # the home folder is not known for this line
                d = home + "/" + d[len(pre):]
                break
        d = d.rstrip("/") or d
        if not _clean_abs(d) or d == "/" or re.search(r"[$`'\"\\ ]", d):
            return None
        out.append(d)
    i = SEARCH + var + "=" + ":".join(out)
    return i if len(i) <= 200 else None


def _witness(args):
    w = args.get("_witness") if isinstance(args, dict) else None
    return w if isinstance(w, dict) else {}


def _clean_abs(p) -> bool:
    return isinstance(p, str) and p.startswith("/") and len(p) <= 900 and "\x00" not in p and "*" not in p and posixpath.normpath(p) == p


def folder_id(path, home):
    """A file written outside the project -> the folder amendment that may cover it, or None (never offered for that place)."""
    if not _clean_abs(path) or not _clean_abs(home) or home == "/":
        return None
    d, name = posixpath.split(path)
    if not name or name.startswith("."):
        return None                                   # a dot-file (.env, .npmrc, .gitattributes ...) is never covered by a folder
    m = _MEMORY.match(d)
    if m and m.group(1) == home:
        return MEMORY + d + "/"
    if _INSTR.search(path) and (path == home + "/.claude/CLAUDE.md" or not path.startswith(home + "/.")):
        return INSTRUCTIONS + path
    if not d.startswith(home + "/"):
        return None                                   # outside the home directory (/etc, /usr, /Volumes): asked each time
    rel = d[len(home) + 1:].split("/")
    if any(s.startswith(".") for s in rel) or rel[0] in ("Library", "bin", "Applications"):
        return None                                   # hidden folders (~/.local/bin is on PATH, ~/.config ...), ~/Library, ~/bin
    return DIR + d + "/"


def _mark_path(det):
    """The path of an agent-config mark ("/p" or "(hook) /p", the hook's K1 finding), or None."""
    d = det[len("(hook) "):] if det.startswith("(hook) ") else det
    return d if _clean_abs(d) else None


def mark_id(mark, w, home):
    """A danger mark of the classifier ("kind:detail") -> the amendment id that may cover it, or None (that mark is never covered)."""
    if not isinstance(mark, str):
        return None
    kind, _, det = mark.partition(":")
    if kind == "agent-config":
        p = _mark_path(det)
        if p is None:
            return None
        mm = _MEMORY.match(p)
        if mm:                                        # the memory folder itself (`cd ~/.claude/projects/p/memory && ...`)
            return MEMORY + p + "/" if mm.group(1) == home else None
        i = folder_id(p, home)
        return i if i is not None and i.startswith((MEMORY, INSTRUCTIONS)) else None
    t = w.get("_text")
    if mark == GH_MARK or (kind == "exit" and det.startswith("gh ")):
        return gh_id(w) or _publish_of(t, ("gh",))
    if (kind in ("net-out", "exit") and (det == "git push" or det.startswith("git push "))) or \
            mark == "exit:npm publish" or mark == "opaque:remote service CLI: npm":
        return _publish_of(t, ("git", "npm"))
    heads = [h for h in (w.get("commands") or []) if isinstance(h, str)]
    if kind == "exit" and det.split(" ")[0] in READ_CLI:
        return program_id(det.split(" ")[0], t, heads)
    if mark == "opaque:remote service CLI: az":
        return program_id("az", t, heads)
    if kind == "opaque" and det.startswith("code injected through "):
        return search_id(mark, t, home if _clean_abs(home) else w.get("sbx_home"))
    return None


def _publish_of(text, progs):
    i = publish_id(text)
    return i if i is not None and i[len(PUBLISH):].split(" ")[0] in progs else None


def gh_id(w, text=None):
    """`gh <sub> <read verb>` -> "(program) gh <sub>" when every gh call of the line is that one sub-command with a read verb and none of
    the flags that upload, call the API or point gh at another host / template; else None."""
    heads = [h for h in (w.get("commands") or []) if isinstance(h, str)]
    gh = {h.replace(" [env GH_CONFIG_DIR]", "") for h in heads if h.split(" ")[0] == "gh"}
    if len(gh) != 1:
        return None
    h = next(iter(gh))
    parts = h.split(" ")
    if len(parts) != 2 or parts[1] not in GH_READ:
        return None
    t = text if isinstance(text, str) else w.get("_text")
    if not isinstance(t, str) or GH_BAD_FLAGS.search(t.replace("GH_CONFIG_DIR=", "GH_CONFIG_DIR_")) or PIPE_RUN.search(t):
        return None
    cfg = ""
    cd_ = set(re.findall(r"(?:^|[\s;&|(])(?:export\s+)?GH_CONFIG_DIR=(\S+)", t))
    if cd_:                                           # 10.11 (r0260): gh's configuration from exactly one literal folder, named in the id
        home = w.get("home") if _clean_abs(w.get("home")) else w.get("sbx_home") if _clean_abs(w.get("sbx_home")) else None
        d = next(iter(cd_)).rstrip(";").strip("'\"") if len(cd_) == 1 else None
        if d is not None and home and (d.startswith("~/") or d.startswith("$HOME/")):
            d = home + "/" + d.split("/", 1)[1]
        if d is None or not _clean_abs(d.rstrip("/")):
            return None
        cfg = " [GH_CONFIG_DIR=%s]" % d.rstrip("/")
    if re.search(r"\bGH_(?!CONFIG_DIR=)[A-Z_]+=|\bGITHUB_[A-Z_]*=", t):
        return None
    verbs = GH_READ[parts[1]]
    for m in re.finditer(r"(?:^|[\s;&|(])gh\s+(\S+)(?:\s+(\S+))?", t):
        if m.group(1) != parts[1]:
            return None
        if verbs is not None and (m.group(2) or "") not in verbs:
            return None
    i = PROGRAM + h + cfg
    return i if len(i) <= 200 else None


def _fetch_segments(text):
    """The simple commands of `text` whose program is a fetcher (split on unquoted ; & | and newlines), joined; None when the line is
    not that simple (an unterminated quote, a heredoc, a substitution)."""
    if not isinstance(text, str) or "<<" in text or "$(" in text or "`" in text:
        return None
    segs, cur, q = [], [], None
    for ch in text:
        if q:
            cur.append(ch)
            q = None if ch == q else q
        elif ch in "'\"":
            q = ch
            cur.append(ch)
        elif ch in ";&|\n":
            segs.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if q:
        return None
    segs.append("".join(cur))
    out = []
    for sg in segs:
        w = [x for x in sg.split() if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", x)]
        if w and w[0].rsplit("/", 1)[-1] in FETCHERS:
            out.append(sg)
    return " ; ".join(out) if out else None


def net_id(host, text, heads, strict=False):
    """A host of a shell line (Bash.net) -> "(network GET|send) <host>", or None (redirects, a file upload, a config file, a catcher ...)."""
    if not isinstance(host, str) or not _HOST.fullmatch(host) or not isinstance(text, str) or egress._LOOPBACK.match(host):
        return None                                   # loopback: one name for every local service (a GET to a browser's debugging port
        #                                               closes a tab): asked each time, as before
    if re.search(r"://[^/\s]*@", text):
        return None                                   # user:password in the URL
    ports = {(m.group(2) or "") for m in _URL.finditer(text) if m.group(1).lower().rstrip(".") == host}
    if len(ports) != 1:
        return None                                   # the host is not written as a URL in the line, or with two different ports
    port = ports.pop()
    schemes = {m.group(0).split(":", 1)[0].lower() for m in _URL.finditer(text) if m.group(1).lower().rstrip(".") == host}
    if len(schemes) != 1:
        return None                                   # r0348: http and https of one host on one line
    if port and port not in ("80", "443"):
        host = host + ":" + port                      # exact: another port of the same host is another service
    pfx = "http://" if schemes == {"http"} else ""   # r0348 (round 4, laundering): plain http is another destination than https
    names = {h.split()[0].rsplit("/", 1)[-1] for h in heads if isinstance(h, str) and h.split()}
    if strict:
        text = _fetch_segments(text)                  # 10.11 (r0260): the flags of THIS request, not `python3 -c` of a contained part
        if text is None:
            return None
    if not names or not names <= {"curl", "wget", "http", "https", "xh", "xhs", "head", "tail", "grep", "jq", "cat", "wc", "sort", "cut",
                                   "tr", "echo", "date", "sleep", "printf"}:
        return None                                   # only a plain fetcher (and filters of its output) -- not a program that does its own I/O
    if "curl" in names and (_REDIRECT_CURL.search(text) or _CONFIG_CURL.search(text)):
        return None                                   # П6: a redirect to another host is a new address; a config file / proxy hides the target
    if "wget" in names and not re.search(r"--max-redirect[=\s]+0\b", text):
        return None
    if names & {"http", "https", "xh", "xhs"} and _REDIRECT_HTTPIE.search(text):
        return None
    if egress._FILE_UP.search(text) or _FROM_FILE.search(text):
        return None                                   # Н2: the witness never reads an uploaded file, so no secret scan: asked each time
    send = bool(egress._UPLOAD.search(text)) or (bool(names & {"http", "https", "xh", "xhs"}) and bool(egress._HTTPIE_DATA.search(text)))
    k = egress.kind_of_host(host.split(":")[0])
    if k == "catcher" or (send and k == "user"):
        return None                                   # a request catcher reads the path; anyone can read what is sent to a user-content host
    return (NET_SEND if send else NET_GET) + pfx + host


def id_for(tool, a, args, home):
    """The amendment id that may cover the action `a` (one recipient of one part), or None."""
    if not isinstance(a, dict) or a.get("class") != "command":
        return None
    rc = a.get("recipient")
    if not isinstance(rc, str):
        return None
    w = _witness(args)
    from app.hookjudge import strict_policy as _sp
    if rc.startswith(_sp.PREFIXES):
        return rc if w.get("sandbox") == {"strict": True} and len(rc) <= 400 else None   # r0261: a reason of the closed list, exactly
    if rc.startswith(DIR):
        return folder_id(rc[len(DIR):], home)
    if tool == "Bash.net" and rc.startswith(EXIT_PREFIX):
        i = net_id(rc[len(EXIT_PREFIX):], args.get("command"), _net_heads(w), strict=w.get("sandbox") == {"strict": True})
        if i is None:                                 # 10.11: the host of `ssh host cmd` (the same id as its command part)
            p = publish_id(args.get("command"))
            if p is not None and p.startswith(REMOTE + "ssh ") and p[len(REMOTE + "ssh "):].split(" ")[0].split("@")[-1].lower() == \
                    rc[len(EXIT_PREFIX):].lower():
                return p
        return i
    if tool == "Bash" and rc == "ssh":
        p = publish_id(args.get("command"))
        return p if p is not None and p.startswith(REMOTE) else None
    if tool == "Bash" and rc in FETCHERS:            # the fetcher's own command part of the same line: covered by the same host amendment
        net = [n for n in (w.get("net") or []) if isinstance(n, str)]
        if len(net) != 1 or not net[0].startswith("webfetch@"):
            return None
        return net_id(net[0].split("@", 1)[1], args.get("command"), _net_heads(w), strict=w.get("sandbox") == {"strict": True})
    if rc == GH_MARK or rc.startswith("exit:gh "):
        return gh_id(w, args.get("command")) or _publish_of(args.get("command"), ("gh",))
    if rc.startswith("agent-config:"):
        return mark_id(rc, w, home)
    if tool == "Bash" and rc.split(" ")[0] in READ_CLI:  # 10.11: the unlisted head itself (`launchctl list`, `npm view`)
        return program_id(rc.split(" ")[0], args.get("command"), w.get("commands") or [])
    if rc.startswith(("exit:", "net-out:", "opaque:remote service CLI: ", "opaque:code injected through ")):
        return mark_id(rc, dict(w, _text=args.get("command")), home)
    return None


def _net_heads(w):
    """The heads net_id judges. 10.11 (r0260): under the strict fact a program that does not leave the sandbox (hookjudge/sandbox.code_exit
    false: `python3 -c ...`, `make`, `ls`) runs contained -- what it does is not this host's request; only the programs that leave count."""
    heads = [h for h in (w.get("commands") or []) if isinstance(h, str)]
    if w.get("sandbox") != {"strict": True}:
        return heads
    from app.hookjudge import sandbox as hsb
    return [h for h in heads if hsb.code_exit(h)]


def line_ok(tool, args, home):
    """Rule 2 and 3 of the module doc: the whole line may be covered by amendments at all."""
    from app import constitution
    strict_ = tool.startswith("Bash") and _witness(args).get("sandbox") == {"strict": True}
    if any(isinstance(d, str) and (d.startswith("defense:") or (d.startswith("autostart:") and ("in an unknown directory" in d or d.startswith("autostart:copy into ") or not strict_)))
           for d in _witness(args).get("danger") or []):
        #                                               r0305: W5 (a file run later, inside the project) under the strict fact is the
        #                                               closed list's С3 with its own narrow "from now on" (strict_policy.LATER)
        return False                                  # r0298: autostart in an unknown folder -- never "from now on", strict fact or not
        #                                               r0305: nor an OS protection switched off (Н10; a strict doubt is asked once)
    if tool.startswith("Bash") and _witness(args).get("sandbox") == {"strict": True}:
        # r0261 (closed list): under the strict fact only the immutable articles (judged on what runs) block "from now on"; every other
        # mark of the line is silent there (hookjudge/strict_policy.py)
        from app.hookjudge import strict_policy as _sp
        nz_ = _sp.article(tool, args)
        return isinstance(args.get("command"), str) and (nz_ is None or nz_[0] == "DOUBT")
    if constitution.check(tool, args) is not None:
        return False
    w = _witness(args)
    if tool.startswith("Bash") and not isinstance(args.get("command"), str):
        return False
    for d in w.get("danger") or []:
        if _held(d, w):
            continue                                  # 10.11 (r0260): held by the strict sandbox: never blocks an amendment of another part
        if mark_id(d, dict(w, _text=args.get("command")), home) is None:
            return False
    return True


def _held(d, w):
    """10.11 (r0260): under the strict fact (only then is `sandbox` in the witness), a danger mark the sandbox holds itself and that may
    stand apart from the rest of the line: hookjudge/sandbox.splittable (an allow-list of kinds, on a line the parser read whole)."""
    from app.hookjudge import sandbox as hsb
    return hsb.splittable(d, w)


def home_of(args, meta):
    """The user's home the hook reported for this call (mapping puts it into _witness.home), or None."""
    h = _witness(args).get("home")
    return h if _clean_abs(h) and h != "/" else None


def active(L, mid, project, ident, now):
    for gid, g in sorted(L.S.allowances.items(), key=lambda kv: -kv[1]["seq"]):
        if g["mandate"] == mid and not g["ended"] and g["nbf"] <= now <= g["exp"] and g["project"] == project and ident in g["commands"]:
            yield gid


def covered_marks(L, mid, project, w, text, now):
    """10.11 (r0260): the search-path marks of a line ("opaque:code injected through PYTHONPATH=...") that an active amendment of this
    mandate and project covers -- the strict-sandbox gate then judges the rest of the line as if they were not there (the program
    the variable feeds runs inside the sandbox like any other code). Any other mark: never."""
    out = []
    if L is None or not isinstance(w, dict) or not isinstance(project, str):
        return out
    home = w.get("home") if _clean_abs(w.get("home")) else w.get("sbx_home")
    for d in w.get("danger") or []:
        i = search_id(d, text, home) if isinstance(d, str) and d.startswith("opaque:code injected through ") else None
        if i is not None and next(active(L, mid, project, i, now), None) is not None:
            out.append(d)
    return out


def cover(L, mid, a, tool, args, meta, now):
    """Gateway step: a part the core would ASK about (defer), covered by an active amendment of this mandate and project -> the action
    with the kind identifier, `dangerous` cleared, `allowance` + `project` (the core answers OK_ALLOWANCE). Anything else: unchanged."""
    if meta is None or not isinstance(a, dict) or a.get("class") != "command" or "allowance" in a or a.get("sandboxed") is True:
        return a
    if L.S.decide_for(mid, a, now)[1] != "defer":
        return a
    home = home_of(args, meta)
    ident = id_for(tool, a, args, home)
    if ident is None or not line_ok(tool, args, home):
        return a
    for gid in active(L, mid, meta["project"], ident, now):
        b = dict(a, recipient=ident, dangerous=False, allowance=gid, project=meta["project"])
        if L.S.decide_for(mid, b, now)[1:] == ("allow", "OK_ALLOWANCE"):
            return b
    return a


def plan(tool, args, asked, home):
    """The ids an amendment must list so that every asked recipient of this part is covered: (ids, None) or (None, why)."""
    if not line_ok(tool, args, home):
        return None, "the line also does something no amendment covers (a secret, a download run by a shell, a force-push, a delete " \
                     "outside the project, an unreadable part ...): approve it once"
    ids = []
    from app.hookjudge import strict_policy as _sp
    if any(isinstance(a, dict) and str(a.get("recipient", "")).startswith(_sp.PREFIXES) for a in asked):
        ids = _sp.verdict(tool, args).ids()           # r0261: one amendment lists every reason of the line (the gateway covers only all)
        for a in asked:                               # r0261b: a reason the gateway added to the line's verdict (the data question)
            rc_ = str((a or {}).get("recipient", "")) if isinstance(a, dict) else ""
            if rc_.startswith(_sp.PREFIXES) and rc_ not in ids:
                ids.insert(0, rc_)
    for a in asked:
        if isinstance(a, dict) and str(a.get("recipient", "")).startswith(_sp.PREFIXES):
            continue
        i = id_for(tool, a, args, home)
        if i is None:
            return None, "%s: this kind of request is asked each time" % str((a or {}).get("recipient", ""))[:120]
        if i not in ids:
            ids.append(i)
    if not ids or len(ids) > MAX_IDS:
        return None, "nothing in this call can be allowed from now on" if not ids else "too many different kinds in one call"
    return ids, None
