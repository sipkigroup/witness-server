"""r0353 («салями» через Makefile, ферма 18->19.11: 51 из 825 цепочек сработали МОЛЧА, все -- агент вписывает скрипт / команду в цель
Makefile, срабатывает при `make` человека). A task-runner file of the project (Makefile / GNUmakefile / *.mk, justfile, Taskfile.yml,
package.json "scripts", tox.ini commands, noxfile.py sessions) is a list of commands the PERSON runs later (`make build`, `just x`, `task x`,
`npm run x`, `tox`, `nox`): what the agent writes into a recipe runs then with the person's rights, outside Witness. Each step of the
chain is harmless alone (write a small script, chmod it, write `build:\\n\\t./sync.sh`); the composition is the later run.

The law: a write whose NEW text adds a recipe command that does more than an ordinary build -- runs a script or program of the project
(`./x.sh`, `scripts/x`, `sh x.sh`, `python tools/x.py`), reaches the network (curl, wget, nc, ssh ...), writes or reads outside the
project (`~`, `$HOME`, /etc, a start-up place), starts something by itself later (crontab, launchctl, systemctl, nohup ... &), runs a
text nobody sees (`| sh`, eval, base64 -d, `python -c`) -- is asked once at the write (actions.taskrun_write; shell form: bashparse
_taskrun_line), with the danger `autostart` and its own detail (the pinned vocabulary is unchanged: "a file that starts commands by
itself", only "Allow once"). An ordinary edit of a build target (compiler flags, `$(CC) -O2 -o $@ $<`, `pytest -q`, `go build ./...`,
`$(MAKE) -C sub`, `npm run lint`) stays silent. Facts only, no decision.

  kind(path)                  -> "make" | "just" | "task" | "npm" | "tox" | "nox" | None
  added(path, new, old="")    -> [(command, why)] the risky recipe commands in `new` that are not in `old` (Edit), or []
  line_added(cmd, path)       -> [(command, why)] for a SHELL line that writes `path` (the text it carries: quoted words, heredoc bodies;
                                 a decoded / hidden text -> one finding)
  RUNNER[kind]                -> the command the person types ("make", "just", "task", "npm run", "tox", "nox")
Honest limits: `cp other Makefile` / `mv` / a link bring a text the witness does not see (not judged here: a copy of a file the agent
wrote is still judged when the agent runs it); a recipe that calls a program by a make variable (`$(TOOL)`) is judged by the variable's
name only when it names an interpreter (`$(PYTHON) x.py`).
"""
from __future__ import annotations

import json
import re

RUNNER = {"make": "make", "just": "just", "task": "task", "npm": "npm run", "tox": "tox", "nox": "nox", "lint": "pylint",
          "cmake": "cmake --build", "setup": "pip install", "conda": "conda activate", "compose": "docker compose up"}
DETAIL = "the agent added a command that will run when you run %s: %s (write to %s)"
DETAIL_HIDDEN = "the agent wrote a text Witness cannot read into the file %s runs (write to %s)"
RUNS_WHEN = "will run when you run "

_MAKE = re.compile(r"(?:^|/)(?:GNUmakefile|[Mm]akefile|[^/]+\.mk)$")
_JUST = re.compile(r"(?:^|/)\.?[Jj]ustfile$")
_TASK = re.compile(r"(?:^|/)[Tt]askfile(?:\.dist)?\.ya?ml$")


def kind(path):
    if not isinstance(path, str) or not path:
        return None
    p = path.replace("\\", "/").rstrip("/")
    b = p.rsplit("/", 1)[-1]
    if _MAKE.search(p):
        return "make"
    if _JUST.search(p):
        return "just"
    if _TASK.search(p):
        return "task"
    if b == "package.json" and "/node_modules/" not in p:
        return "npm"
    if b == "tox.ini":
        return "tox"
    if b == "noxfile.py":
        return "nox"
    if b in _LINT_FILES:
        return "lint"
    if b == "CMakeLists.txt" or (b.endswith(".cmake") and "/build/" not in p and "/_deps/" not in p):
        return "cmake"
    if b == "setup.py" and "/site-packages/" not in p and "/node_modules/" not in p:
        return "setup"
    if _CONDA.search(p):
        return "conda"
    if _COMPOSE.search(b):
        return "compose"
    return None


# r0355 (противник AOAI 19.11, RAZBOR 20.11 п.1: `envs/myenv/etc/conda/activate.d/x.sh` with `curl .. | bash` / `rm -rf ~/Library/Photos`
# written silently): conda runs every script of an environment's activate.d / deactivate.d at `conda activate` / `conda deactivate`
# (the person's shell, the person's rights), and a package's post-link / pre-unlink script at `conda install` / `conda remove`. The same
# law as a recipe of make: each line of the script is a command the person runs later; one that does more than set the environment
# (the network, outside the project, a hidden text, a program left running) is asked at the write. `export X=..` / `echo` stay silent.
_CONDA = re.compile(r"(?:^|/)etc/conda/(?:activate|deactivate)\.d/[^/]+$|(?:^|/)[^/]*(?:post-link|pre-link|pre-unlink)\.(?:sh|bat)$")
# r0355 (RAZBOR 20.11 п.2: docker-compose.yml with `volumes: - ~:/mnt/home` and `command: rm -rf /mnt/home/Documents/..` written
# silently): `docker compose up` runs each service as `docker run -v SRC:DST IMAGE COMMAND` -- a bind mount of a folder outside the
# project (the home, `~/.ssh`, `/`, the Docker socket) hands that folder to a program in the container with the person's rights. Asked
# at the write, as a recipe is (r0354 judges the same mount on a `docker run` line).
_COMPOSE = re.compile(r"^(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$")


# r0354 (противник AOAI 19.11: `add_custom_target(wipe ALL COMMAND rm -rf ~/Pictures)` in CMakeLists.txt, `os.system('rm -rf ~/Documents')`
# in setup.py -- written silently, run by the person's `cmake --build` / `pip install .`): the same law as a make recipe. CMake: every
# COMMAND of add_custom_target / add_custom_command / execute_process (execute_process runs already at configure time). setup.py: the
# command strings the code hands to os.system / os.popen / subprocess, a tree delete (shutil.rmtree), the network modules.
_CM_CMD = re.compile(r"\bCOMMAND\s+(.+?)(?=\s+(?:COMMAND|DEPENDS|WORKING_DIRECTORY|COMMENT|BYPRODUCTS|OUTPUT|VERBATIM|USES_TERMINAL|"
                     r"RESULT_VARIABLE|RESULTS_VARIABLE|OUTPUT_VARIABLE|ERROR_VARIABLE|INPUT_FILE|OUTPUT_FILE|ERROR_FILE|TIMEOUT|JOB_POOL|"
                     r"SOURCES|COMMAND_EXPAND_LISTS|ECHO_OUTPUT_VARIABLE|COMMAND_ECHO|MAIN_DEPENDENCY|IMPLICIT_DEPENDS|DEPFILE)\b|\s*\))", re.S)
_PY_RUN = re.compile(r"\b(os\.system|os\.popen|subprocess\.\w+|shutil\.rmtree|os\.exec\w*|os\.spawn\w*)\s*\(")
_PY_NET = re.compile(r"\b(?:urllib\.request|urlopen|requests\.(?:get|post|put)|httpx\.|socket\.socket|http\.client)")


# r0354 (противник AOAI 19.11: `.pylintrc` with `init-hook='import os; os.system("curl .. | sh")'` written silently): pylint runs the
# init-hook of its configuration as Python code at every start -- a config that is code, run later by the person (`pylint src`, the
# editor's linter). Only the init-hook values are read (load-plugins of a project module stays the exec-changed question at the run);
# an init-hook that only edits sys.path (the ordinary use) stays silent; one that runs a program, reaches the network, deletes, opens a
# file for writing, decodes or evaluates text, or names a place outside the project is asked at the write, as a recipe of make is.
_LINT_FILES = {".pylintrc", "pylintrc", ".pylintrc.toml", "pylintrc.toml", "setup.cfg", "pyproject.toml"}
_INIT_HOOK = re.compile(r"""(?im)^\s*init[-_]hook\s*[=:]\s*(?:(['"]{1,3})(.*?)\1|(.*?))\s*$""")
_LINT_CODE = re.compile(r"\b(?:os\.(?:system|popen|exec\w*|spawn\w*|remove|unlink|rmdir|removedirs|kill)|subprocess|shutil\.(?:rmtree|move|copy\w*)|"
                        r"exec\s*\(|eval\s*\(|compile\s*\(|__import__|importlib|urllib|requests|httpx|http\.client|socket|ftplib|"
                        r"base64|codecs\.decode|marshal|pickle|ctypes|pty|open\s*\([^)]*[\x27\x22][wax+]|Path\([^)]*\)\s*\.\s*(?:write_\w+|unlink))")


def _lint_found(text, root=None, home=None):
    out = []
    for m in _INIT_HOOK.finditer(text or ""):
        v = (m.group(2) if m.group(2) is not None else m.group(3) or "").strip()
        if not v:
            continue
        why = "runs code when you run pylint" if _LINT_CODE.search(v) else _line_why(v, root, False, home)
        if why:
            out.append(("init-hook " + v[:150], why))
    return out


# ---------------------------------------------------------------- one command of a recipe
_NET = {"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "telnet", "ftp", "tftp", "rsync", "aria2c", "http", "https",
        "xh", "lftp"}
_LATER = {"crontab", "launchctl", "systemctl", "at", "batch", "nohup", "setsid", "disown", "osascript", "schtasks", "loginctl", "tmux",
          "screen"}
_INTERP = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "mksh", "source", ".", "python", "python2", "python3", "pypy", "pypy3",
           "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "lua", "tclsh", "rscript", "ts-node", "tsx", "pwsh", "powershell",
           "julia", "groovy", "elixir", "awk"}
_WRAP = {"sudo", "doas", "env", "exec", "command", "builtin", "time", "nice", "ionice", "stdbuf", "timeout", "xargs", "caffeinate",
         "chronic", "then", "do", "else", "if", "while", "until", "!", "{", "("}
_SYS = re.compile(r"^/(?:usr/(?:local/)?(?:s?bin)|s?bin|opt/homebrew/s?bin)/")
_SCRIPT_EXT = re.compile(r"\.(?:sh|bash|zsh|py|pyw|js|mjs|cjs|ts|mts|pl|rb|php|lua|ps1|bat|cmd|command|R|jl|exs|groovy)$", re.I)
_HOME = re.compile(r"(?:^|[\s=:'\"(])(?:~(?:/|$|[\s'\"])|\$\$?\{?HOME\}?|\$\(HOME\)|/(?:etc|Library|System|root|var/spool/cron)/)")
_ABS = re.compile(r"(?:^|[\s=:'\"(<>])(/[A-Za-z0-9_.][^\s'\";|&)]*)")
_ABS_OK = re.compile(r"^/(?:usr|bin|sbin|dev|tmp|private/tmp|var/tmp|opt/homebrew|proc)(?:/|$)")
_PIPE_SH = re.compile(r"\|\s*(?:sudo\s+|env\s+)?(?:/\S*/)?(?:ba|z|da|k|fi)?sh\b|\|\s*(?:sudo\s+)?(?:/\S*/)?(?:python3?|perl|ruby|node)\b"
                      r"(?:\s+-)?\s*(?:$|[;&|)])")
_HIDDEN = re.compile(r"\bbase(?:64|32)\s+(?:-\w*[dD]\w*|--decode)\b|\bxxd\s+-r\b|\bopenssl\s+(?:enc|base64)\b.*-d\b|\b(?:gunzip|zcat|"
                     r"bunzip2|xz\s+-d|unxz)\b|\beval\b|\b(?:python3?|perl|ruby|node|php)\s+-[A-Za-z]*[ce]\b|\b(?:ba|z)?sh\s+-[A-Za-z]*c\b")
_PERSIST = re.compile(r"\.(?:bash|zsh)rc\b|\.(?:bash_)?profile\b|\.zprofile\b|\.zshenv\b|LaunchAgents|LaunchDaemons|/autostart/|"
                      r"systemd/user|\.config/fish|/cron|\.git/hooks|\.ssh/|authorized_keys|\.gitconfig|\.claude/|\.mcp\.json|"
                      r"deus[-_]witness", re.I)
_URL = re.compile(r"\b(?:https?|ftp|wss?)://", re.I)
_MVAR = re.compile(r"^\$[({]([A-Za-z_][A-Za-z0-9_]*)[)}]$")
_SEG = re.compile(r"&&|\|\||;|\||&(?!&)|\$\(|`|\n")


def _words(seg):
    return [w.strip("'\"") for w in re.split(r"[ \t]+", seg.strip()) if w.strip("'\"")]


def _seg_why(seg, root):
    """-> why this one command of a recipe is more than a build step, or None"""
    ws = _words(seg)
    while ws and (ws[0] in _WRAP or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", ws[0]) or (ws[0].startswith("-") and len(ws[0]) <= 3)
                  or ws[0] in ("@", "-", "+", "@-", "-@", "+@", "@+")):
        w0 = ws.pop(0)
        if w0 == "timeout" and ws:
            ws.pop(0)
    if not ws:
        return None
    w = ws[0].lstrip("@-+")
    if not w:
        return None
    mv = _MVAR.match(w)
    name = (mv.group(1) if mv else w).rsplit("/", 1)[-1].lower()
    if name in _NET:
        return "uses the network (%s)" % name
    if name in _LATER:
        return "starts something that keeps running or runs later (%s)" % name
    if name in _INTERP or re.fullmatch(r"python[\d.]*", name):
        rest = [a for a in ws[1:] if a]
        # `python -m pytest`, `node --version`: a module or flag, no file of the project; `-c` / `-e` code is caught by _HIDDEN
        for a in rest:
            if a in ("-m", "--module"):
                return None
            if a.startswith("-"):
                continue
            if "/" in a or _SCRIPT_EXT.search(a) or a.startswith("."):
                return "runs a script of the project (%s %s)" % (name, a)
            return None
        return None
    if mv:
        return None                                  # `$(CC)`, `$(MAKE)`: a build tool named by a variable
    if root and w.startswith(root.rstrip("/") + "/"):
        return "runs a script of the project (%s)" % w
    if w.startswith(("./", "../", "~", "$HOME", "${HOME}", "$$HOME", "$(CURDIR)", "${CURDIR}", "$(PWD)", "$$PWD", "{toxinidir}")):
        return "runs a script of the project (%s)" % w
    if w.startswith("/") and not _SYS.match(w):
        return "runs a program by its path (%s)" % w
    if re.fullmatch(r"[A-Za-z0-9_.][\w.-]*(?:/[\w.+-]+)+", w) and not re.match(r"^[sy]/", w):     # `scripts/x.sh`, `bin/tool` (not a sed `s/a/b/g`)
        return "runs a script of the project (%s)" % w
    return None


def _under(a, d):
    return isinstance(d, str) and d.startswith("/") and d.rstrip("/") != "" and (a == d.rstrip("/") or a.startswith(d.rstrip("/") + "/"))


def _outside(a, root, home):
    """an absolute path of a recipe line reaches outside the project: not under the project and either not a shared system / temp place
    or under the person's home. r0353 (19.11, Linux): a home that lies under /tmp (a container's HOME=/tmp, a test stand in /tmp) is still
    the home -- `cp out /tmp/h/.local/bin/` is the same write as `cp out ~/.local/bin/`, whatever folder the home happens to be in."""
    if _under(a, root):
        return False
    return not _ABS_OK.match(a) or _under(a, home)


def _line_why(line, root, recipe=True, home=None):
    """-> why this recipe line does more than a build, or None. `recipe` False: a line that is not a command (a variable, a rule head):
    only what it says anywhere (network, home, start-up places, hidden text). `home`: the person's home (an absolute path under it is
    outside the project even where the home lies in a temp folder)."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if _PIPE_SH.search(s):
        return "pipes a text into a shell"
    if _HIDDEN.search(s):
        return "runs a text nobody sees (decoded or inline code)"
    if _URL.search(s) and recipe:
        return "names an address on the network"
    if _PERSIST.search(s):
        return "touches a place that starts programs by itself"
    if _HOME.search(" " + s) or any(_outside(a, root, home) for a in _ABS.findall(" " + s)):
        return "reaches outside the project (your home folder or the system)"
    if re.search(r"(?:^|[^&])&\s*$", s) and recipe:
        return "leaves a program running in the background"
    if not recipe:
        return None
    for seg in _SEG.split(s):
        why = _seg_why(seg, root)
        if why:
            return why
    return None


# ---------------------------------------------------------------- recipe lines per file kind
_SHELL_CALL = re.compile(r"\$\((?:shell)\s+([^)]*)\)|`([^`\n]+)`")


def _recipes(k, text):
    """-> [(line, is_command)] of the text as the file's runner reads it"""
    out = []
    if k == "npm":
        sc = None
        try:
            d = json.loads(text)
            sc = d.get("scripts") if isinstance(d, dict) else None
        except (TypeError, ValueError):
            sc = None
        if isinstance(sc, dict):
            return [(str(v), True) for v in sc.values() if isinstance(v, str)]
        # an Edit's fragment: every "key": "value" pair that is not plainly metadata / a dependency
        for m in re.finditer(r"\"([^\"\\]+)\"\s*:\s*\"((?:[^\"\\]|\\.)*)\"", text):
            key, val = m.group(1), m.group(2).replace('\\"', '"')
            if key in _NPM_META or key.startswith((".", "@")) or re.match(r"^[\^~<>=*\d]|^(?:workspace|file|link|npm|git\+?\w*|https?):", val):
                continue
            out.append((val, True))
        return out
    if k == "cmake":
        for m in _CM_CMD.finditer(text):
            out.append((re.sub(r"\s+", " ", m.group(1)).strip(), True))
        return out
    if k == "setup":
        for m in _PY_RUN.finditer(text):
            seg = text[m.end():m.end() + 400].split(")", 1)[0]
            ws = re.findall(r"[\"']([^\"']*)[\"']", seg)
            if ws:
                out.append((("rm -rf " if m.group(1) == "shutil.rmtree" else "") + " ".join(ws), True))
        for m in _PY_NET.finditer(text):
            out.append(("curl python " + m.group(0), True))      # code that talks to the network when the package is installed
        return out
    if k == "nox":
        for m in re.finditer(r"session\.(?:run|run_always|run_install)\s*\(([^)]*)\)", text):
            ws = re.findall(r"[\"']([^\"']*)[\"']", m.group(1))
            if ws:
                out.append((" ".join(ws), True))
        for m in re.finditer(r"\b(?:os\.system|os\.popen|subprocess\.\w+|urllib\.request\.\w+|requests\.\w+|socket\.\w+|httpx\.\w+)\s*\(", text):
            out.append(("curl python " + m.group(0), True))     # code of the session that runs a program / talks to the network
        return out
    if k == "conda":
        return [(raw, True) for raw in text.replace("\r", "").split("\n")]
    for raw in text.replace("\r", "").split("\n"):
        if k == "make":
            if raw.startswith("\t"):
                out.append((raw[1:], True))
            elif re.match(r"^[^\s#=:][^=]*?::?(?!=)[^;]*;(.*)$", raw):
                out.append((raw.split(";", 1)[1], True))
            else:
                out.append((raw, False))
        elif k == "just":
            out.append((raw, raw[:1] in (" ", "\t")))
        elif k == "task":
            m = re.match(r"^\s*-?\s*(?:(?:cmd|sh)\s*:\s*)?(.*)$", raw)
            body = (m.group(1) if m else raw).strip().strip("'\"")
            is_cmd = bool(re.match(r"^\s*-\s+(?!task:)|^\s*(?:cmd|sh)\s*:", raw)) or (raw[:1] in (" ", "\t") and ":" not in body.split(" ")[0])
            out.append((body, is_cmd))
        elif k == "tox":
            m = re.match(r"^\s*commands(?:_pre|_post)?\s*=\s*(.*)$", raw)
            if m:
                out.append((m.group(1), True))
            elif raw[:1] in (" ", "\t"):
                out.append((raw, True))
            else:
                out.append((raw, False))
        for m in _SHELL_CALL.finditer(raw):
            out.append(((m.group(1) or m.group(2) or ""), True))   # `$(shell ..)` of make, a backquote of just / make: runs at parse time
    return out


_NPM_META = {"name", "version", "description", "main", "module", "browser", "types", "typings", "type", "license", "author", "homepage",
             "url", "email", "directory", "packageManager", "private", "unpkg", "jsdelivr", "source", "umd:main", "react-native", "style",
             "sass", "bin", "man", "funding", "engines", "os", "cpu", "exports", "imports", "default", "import", "require", "node"}


def added(path, new, old="", root=None, home=None):
    k = kind(path)
    if k is None or not isinstance(new, str) or not new:
        return []
    if k == "lint":
        old_ = {c for c, _ in _lint_found(old, root, home)} if isinstance(old, str) and old else set()
        return [f for f in _lint_found(new, root, home) if f[0] not in old_][:8]
    if k == "compose":
        old_ = {c for c, _ in _compose_found(old, path, root, home)} if isinstance(old, str) and old else set()
        return [f for f in _compose_found(new, path, root, home) if f[0] not in old_][:8]
    seen_old = {ln.strip() for ln, _ in _recipes(k, old)} if isinstance(old, str) and old else set()
    out = []
    for ln, is_cmd in _recipes(k, new):
        s = ln.strip()
        if not s or s in seen_old:
            continue
        why = _line_why(s, root, is_cmd, home)
        if why:
            out.append((s[:160], why))
    return list(dict.fromkeys(out))[:8]


# ---------------------------------------------------------------- compose (r0355)
_CMP_ITEM = re.compile(r"^(\s*)-\s*(?:['\"]([^'\"]+)['\"]|([^\s#'\"]+))\s*(?:#.*)?$")
_CMP_KEY = re.compile(r"^(\s*)([A-Za-z_][\w.-]*)\s*:\s*(.*?)\s*$")


def _compose_src(src, path, root, home):
    """-> the absolute host path of a bind source, or None (a named volume, a value Witness cannot read)"""
    import posixpath
    s = (src or "").strip().strip("'\"")
    if not s or not re.match(r"^(?:~|\$\{?HOME\}?|\$\{?PWD\}?|/|\.)", s):
        return None                                      # a named volume (`data:/var/lib/pg`)
    hm = home if isinstance(home, str) and home.startswith("/") else None
    m = re.match(r"^(?:~|\$\{HOME(?::?-[^}]*)?\}|\$HOME)(?=/|$)", s)
    if m:
        if not hm:
            return "~" + s[m.end():]
        s = hm + s[m.end():]
    m = re.match(r"^(?:\$\{PWD(?::?-[^}]*)?\}|\$PWD)(?=/|$)", s)
    if m:
        s = "." + s[m.end():]
    if "$" in s:
        return "$"                                        # a variable Witness cannot read: outside for sure? no -- unknown
    if not s.startswith("/"):
        base = posixpath.dirname(path) if isinstance(path, str) and path.startswith("/") else (root or "")
        if not base:
            return None
        s = posixpath.join(base, s)
    return posixpath.normpath(s)


def _compose_found(text, path, root, home):
    """the bind mounts of a compose text whose host folder is outside the project -> [(what, why)]. Short syntax (`- SRC:DST[:mode]`,
    `volumes: [SRC:DST]`) and long syntax (`- type: bind` / `source: SRC`) under any `volumes:` key of a service. The service's
    `command:` / `entrypoint:` is named with it (what runs with that folder)."""
    if not isinstance(text, str) or not text:
        return []
    lines = text.replace("\r", "").split("\n")
    cmds = []
    for ln in lines:
        m = _CMP_KEY.match(ln)
        if m and m.group(2) in ("command", "entrypoint") and m.group(3):
            cmds.append(m.group(3).strip()[:120])
    srcs = []
    vol_ind = None
    for ln in lines:
        if not ln.strip() or ln.strip().startswith("#"):
            continue
        ind = len(ln) - len(ln.lstrip())
        m = _CMP_KEY.match(ln)
        if vol_ind is not None and ind <= vol_ind and not (ind == vol_ind and ln.lstrip().startswith("-")):
            vol_ind = None
        if m and m.group(2) == "volumes" and not ln.lstrip().startswith("-"):
            vol_ind = ind
            v = m.group(3)
            if v.startswith("["):
                for it in re.findall(r"['\"]?([^,\[\]'\"]+)['\"]?", v):
                    srcs.append(it.strip().split(":")[0])
            continue
        if vol_ind is None:
            continue
        mi = _CMP_ITEM.match(ln)
        if mi:
            it = mi.group(2) or mi.group(3)
            if ":" in it:
                srcs.append(it.rsplit(":", 2)[0] if it.count(":") >= 2 and not re.match(r"^[A-Za-z]:", it) else it.split(":")[0])
            continue
        ms = re.match(r"^\s*-?\s*(?:source|src)\s*:\s*['\"]?([^'\"#\s]+)", ln)
        if ms:
            srcs.append(ms.group(1))
    out = []
    for s0 in srcs:
        a = _compose_src(s0, path, root, home)
        if a is None:
            continue
        if a == "$" or a.startswith("~") or _outside(a, root, home) or (isinstance(home, str) and a == home.rstrip("/")):
            what = "mounts %s into a container" % s0
            if cmds:
                what += " that runs: %s" % cmds[0]
            out.append((what[:160], "reaches outside the project (your home folder or the system)"))
    return list(dict.fromkeys(out))


# ---------------------------------------------------------------- the shell form
_HEREDOC = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1[^\n]*\n(.*?)(?:\n[ \t]*\2[ \t]*(?:\n|$)|$)", re.S)
_QUOTE = re.compile(r"\$'((?:[^'\\]|\\.)*)'|'([^']*)'|\"((?:[^\"\\]|\\.)*)\"")


def _unesc(s):
    return s.replace("\\t", "\t").replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\")


def line_added(cmd, path, root=None, home=None):
    """a shell line that writes the task-runner file `path`: the text it carries (heredoc bodies, quoted words) read as the file's lines;
    the witness does not know which of the line's words land in the file, so every carried line counts as a command (over, never under).
    A decoder / an inline interpreter in the same line that writes the file: the text is hidden -> one finding."""
    k = kind(path)
    if k is None or not isinstance(cmd, str):
        return []
    base = path.rsplit("/", 1)[-1]
    texts = [m.group(3) for m in _HEREDOC.finditer(cmd)]
    rest = _HEREDOC.sub("\n", cmd)
    for m in _QUOTE.finditer(rest):
        t = m.group(1) if m.group(1) is not None else (m.group(2) if m.group(2) is not None else m.group(3))
        if t is None or t.rstrip("/").endswith(base) or re.fullmatch(r"[%\\ntsd ]*", t):
            continue
        texts.append(_unesc(t) if m.group(2) is None or "\\" in t else t)
    out = []
    if k == "lint":
        return _lint_found("\n".join(texts), root, home)[:8]     # r0354: only the init-hook values the line carries
    if k == "compose":
        return _compose_found("\n".join(texts), path, root, home)[:8]     # r0355: the mounts the line carries
    if k in ("cmake", "setup"):
        found = []
        for t in texts:
            for ln, is_cmd in _recipes(k, t):
                why = _line_why(ln.strip(), root, is_cmd, home)
                if why:
                    found.append((ln.strip()[:160], why))
        return list(dict.fromkeys(found))[:8]
    if re.search(r"\bbase(?:64|32)\s+(?:-\w*[dD]\w*|--decode)\b|\bxxd\s+-r\b|\b(?:gunzip|zcat)\b|\bopenssl\b", rest):
        out.append(("(hidden text)", "writes a decoded text nobody sees"))
    for t in texts:
        if k in ("npm", "nox", "tox"):
            # a JSON / Python / ini text: its commands are read as the runner reads them (package.json "scripts", session.run, commands =)
            for ln, is_cmd in _recipes(k, t):
                s = ln.strip()
                why = _line_why(s, root, is_cmd, home) if s else None
                if why:
                    out.append((s[:160], why))
            continue
        for raw in t.replace("\r", "").split("\n"):
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            is_cmd = True
            if k == "make" and not raw.startswith("\t") and re.match(r"^[^\s#=:][^=]*?::?(?!=)", s) and ";" not in s:
                is_cmd = False                      # `build: deps` (a rule head) / `X = y` is no command
            elif k in ("make", "just", "tox") and re.match(r"^[A-Za-z_][\w.]*\s*[:?+!]?=", s):
                is_cmd = False
            why = _line_why(s, root, is_cmd, home)
            if why:
                out.append((s[:160], why))
    return list(dict.fromkeys(out))[:8]


def written_text(tool, inp):
    """(new, old) a Write / Edit / MultiEdit puts into / takes out of its file"""
    if not isinstance(inp, dict):
        return None, ""
    if tool == "Write":
        v = inp.get("content")
        return (v if isinstance(v, str) else None), ""
    if tool == "Edit":
        v, o = inp.get("new_string"), inp.get("old_string")
        return (v if isinstance(v, str) else None), (o if isinstance(o, str) else "")
    if tool == "MultiEdit" and isinstance(inp.get("edits"), list):
        es = [e for e in inp["edits"] if isinstance(e, dict)]
        return ("\n".join(e["new_string"] for e in es if isinstance(e.get("new_string"), str)) or None,
                "\n".join(e["old_string"] for e in es if isinstance(e.get("old_string"), str)))
    return None, ""


SOFT = "runs a script of the project ("
_PREFIXES = ("$(CURDIR)/", "${CURDIR}/", "$(PWD)/", "${PWD}/", "$$PWD/", "{toxinidir}/", "./")


def script_path(why, root):
    """the file of the project a soft finding runs, as an absolute path (or None)"""
    import posixpath
    m = re.match(r"runs a script of the project \((?:\S+ )?(\S+)\)$", why or "")
    if not m or not isinstance(root, str) or not root.startswith("/"):
        return None
    w = m.group(1).strip("'\"")
    for pre in _PREFIXES:
        if w.startswith(pre):
            w = w[len(pre):]
    p = posixpath.normpath(w if w.startswith("/") else posixpath.join(root, w))
    return p if p == root or p.startswith(root.rstrip("/") + "/") else None


def split(found, root):
    """-> (hard findings, soft findings, [paths of the soft ones]). Hard: the network, outside the project, a start-up place, a hidden
    text, a program that stays running -- asked whatever else. Soft: a script / program of the project -- asked when the agent wrote that
    file (actions.taskrun_write: the composition of the chain, «салями»), or later when it writes it (recipe key)."""
    hard, soft, paths = [], [], []
    for c, why in found:
        if why.startswith(SOFT):
            p = script_path(why, root)
            if p is None:
                hard.append((c, why))
            else:
                soft.append((c, why))
                if p not in paths:
                    paths.append(p)
        else:
            hard.append((c, why))
    return hard, soft, paths[:16]


def detail(path, found):
    k = kind(path) or "make"
    c, _why = found[0]
    if c == "(hidden text)":
        return DETAIL_HIDDEN % (RUNNER[k], path)
    return DETAIL % (RUNNER[k], c, path)
