"""11.11 (r0260): Python code typed INTO the line (a quoted heredoc `python3 - <<'EOF'` or `python3 -c '...'`) -- what it runs and what
in it is only TEXT. Three users, one parser (each fails closed: anything this module cannot read is judged as before):

(а) actions.written_run_files: after a risky write, every line that runs code is held (RT5, 28.10: matching the written file's NAME is a
    game the agent wins). A line whose only code is inline Python that runs nothing but itself and a short list of stdlib modules is not
    a run of a written file: its whole program is in the line (the owner and the parser see it), and it cannot reach a written file as
    code -- no exec / eval / compile / import machinery / subprocess / os.system, no import outside the list, no `sys.path`, and no
    written file that could shadow a stdlib module (`python3 -` puts the working directory first on sys.path: a written textwrap.py IS
    imported, measured 11.11). What the code WRITES is judged on its own marks (persistence, git hooks, outside the project).
(в) bashparse: the file-API scan of interpreter code is lexical; a string literal that is code being written into a file
    (`s.replace('A', 'x = open(os.path.expanduser("~/.ssh/id_rsa"))')`) made `secrets:~/.ssh/id_rsa` and the immutable article Н1
    refused a harmless edit. blank_text() blanks such TEXT literals (and comments) before the scan; a path literal stays. Code that
    builds or runs code (exec, subprocess ...) is never blanked. A real read through a blanked literal (`t = 'cat ~/.ssh/x'; open(t[4:])`)
    becomes a path not shown: asked (opaque), no longer refused -- the residual (report r0260 11.11).
(в) toolmap DLP: a token-shaped value inside a quoted heredoc that only goes into a local file (`cat > f <<'EOF'`, edit-only Python)
    on a line with no network and no exit is not refused (DATA_*): the line is asked as dangerous instead (dlp_inert_text).
"""
from __future__ import annotations

import ast
import io
import re
import shlex
import sys
import tokenize
import warnings

PY_NAME = re.compile(r"python(?:[23](?:\.\d{1,2})?)?")
# modules an edit script imports; none of them runs a file it is given (runpy, importlib, pickle, subprocess, code ... are not here)
ALLOWED_IMPORTS = frozenset({"os", "sys", "re", "json", "pathlib", "textwrap", "glob", "difflib", "collections", "itertools", "string",
                             "datetime", "time", "hashlib", "shutil", "fnmatch", "csv", "tomllib", "typing", "functools", "math", "io",
                             "unicodedata", "copy", "pprint", "dataclasses", "enum", "operator", "bisect", "heapq", "statistics",
                             "uuid", "random", "base64", "struct", "zlib"})
BAD_CALLS = frozenset({"exec", "eval", "compile", "__import__", "getattr", "setattr", "delattr", "globals", "locals", "vars", "breakpoint",
                       "execfile", "input", "help"})
BAD_ATTR = re.compile(r"^(?:system|popen|exec\w*|spawn\w*|posix_spawn\w*|fork\w*|startfile|kill\w*|run_path|run_module|import_module|"
                      r"load_module|exec_module|path|modules|meta_path|path_hooks|path_importer_cache|settrace|setprofile|"
                      r"addaudithook|remote_exec|_\w*)$")
STDLIB = frozenset(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
_TEXT_CH = re.compile(r"[\n\r\t()=;{}\"'<>|`$\\]")


def _tree(code):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(code)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None


# r0261d (class 2, decision of Deus): the project's own code (`from app.hookjudge import bashparse`) under the closed list -- a module that is
# not of the standard library and not a known network / process / publishing package; its TEXT literals are text (write_open, _text_view)
NET_PKGS = frozenset({"requests", "httpx", "aiohttp", "urllib3", "httplib2", "pycurl", "websocket", "websockets", "socketio", "grpc", "zmq",
                      "paramiko", "fabric", "invoke", "sh", "plumbum", "pexpect", "ptyprocess", "sarge", "delegator", "boto3", "botocore",
                      "aiobotocore", "s3fs", "gcsfs", "google", "azure", "github", "gitlab", "git", "pygit2", "dulwich", "twine", "pip",
                      "setuptools", "distutils", "docker", "kubernetes", "openai", "anthropic", "slack_sdk", "telegram", "tweepy",
                      "selenium", "playwright", "pyppeteer", "mechanize", "scrapy", "treq", "twisted", "tornado", "gevent", "eventlet",
                      "trio", "anyio", "uvloop", "dns", "scapy", "nmap", "ftputil", "pysftp", "smbclient", "keyring", "cryptography",
                      "nacl", "jwt", "stripe", "redis", "pymongo", "psycopg", "psycopg2", "pymysql", "mysql", "sqlalchemy", "celery",
                      "kombu", "pika", "nats", "kafka", "confluent_kafka", "ray", "dask", "fsspec", "smart_open", "pexpect", "cffi",
                      "ctypes", "pwn", "pwntools", "pyautogui", "pynput", "Foundation", "AppKit", "objc", "applescript", "osascript"})


def edit_only(code, ext=False):
    """-> the set of top-level modules the code imports when it is "edit-only" Python (see the module text), else None.
    ext (r0261d): also the project's own modules (not stdlib, not NET_PKGS), when no network word is left once its TEXT literals are
    blanked (the code itself calls no urlopen / requests / socket ...)."""
    if not isinstance(code, str) or len(code) > 64 * 1024:
        return None
    t = _tree(code)
    if t is None:
        return None
    mods = set()
    for n in ast.walk(t):
        if isinstance(n, ast.Import):
            for a in n.names:
                mods.add(a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom):
            if n.level or not n.module:
                return None
            mods.add(n.module.split(".")[0])
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in BAD_CALLS:
            return None
        elif isinstance(n, ast.Attribute) and BAD_ATTR.match(n.attr) and not (n.attr == "path" and isinstance(n.value, ast.Name) and n.value.id == "os"):
            if ext and (n.attr in ("__name__", "__file__", "__doc__") or (re.fullmatch(r"_[A-Za-z]\w*", n.attr) and not (
                    isinstance(n.value, ast.Name) and n.value.id in ALLOWED_IMPORTS))):
                continue                              # r0261d: a private helper of the project's module (`bp._text_view`), never os._x
            return None                               # os.system, sys.path, sys.modules, pickle.load, x._private ... (os.path is the one exception)
        elif isinstance(n, ast.Name) and n.id.startswith("__") and n.id not in ("__name__", "__file__"):
            return None
    if ext:
        if any(m not in ALLOWED_IMPORTS and (m in STDLIB or m in NET_PKGS or not m.isidentifier()) for m in mods):
            return None
        from .sandbox import NET_TEXT
        nb = _blank_text_literals(code, hosts=True)  # r0261e: a bare URL literal is named, not fetched (no network package is imported)
        if nb is None or NET_TEXT.search(nb) or re.search(r"\b(?:open|Path)\s*\(\s*0\b", nb):
            return None                               # a literal the code opens / reads as a program is not proved text here
        return mods
    if not mods <= ALLOWED_IMPORTS:
        return None
    return mods


def blank_text(code):
    """(в) -> `code` with TEXT literals blanked to '' and comments dropped; `code` itself when it does not parse, builds / runs code, or
    nothing changes. A TEXT literal holds a newline, a tab, a quote, a bracket, `=`, `;`, `$`, a backslash ..., or a blank while not
    starting like a path (/, ~, .). A path literal ('~/.ssh/id_rsa', 'src/a.py', '~/Library/Application Support/x') is kept."""
    from .bashparse import CODE_PROC, code_obfuscated
    if not isinstance(code, str) or _tree(code) is None or code_obfuscated(code) or CODE_PROC.search(code):
        return code
    lines = code.splitlines(keepends=True)
    offs, k = [], 0
    for ln in lines:
        offs.append(k)
        k += len(ln)
    reps = []
    try:
        for tk in tokenize.generate_tokens(io.StringIO(code).readline):
            if tk.type == tokenize.COMMENT:
                reps.append((tk.start, tk.end, ""))
            elif tk.type == tokenize.STRING:
                pre = re.match(r"[A-Za-z]*", tk.string).group(0).lower()
                if "f" in pre:
                    continue
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        v = ast.literal_eval(tk.string)
                except (ValueError, SyntaxError, MemoryError, RecursionError):
                    continue
                if isinstance(v, bytes):
                    v = v.decode("latin-1")
                if not isinstance(v, str):
                    continue
                if _TEXT_CH.search(v) or (" " in v and not v.startswith(("/", "~", "."))):
                    reps.append((tk.start, tk.end, "''"))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return code
    if not reps:
        return code
    out, last = [], 0
    for (r0, c0), (r1, c1), new in reps:
        a, b = offs[r0 - 1] + c0, offs[r1 - 1] + c1
        out.append(code[last:a])
        out.append(new)
        last = b
    out.append(code[last:])
    s = "".join(out)
    return s if _tree(s) is not None else code


# ---- the line: which of its programs are inline Python, and their code ---------------------------------------------------------------
_SEP = {";", "&&", "||", "|", "&", "(", ")", "\n"}
_REDIR = {">", ">>", ">&", "&>", "2>", "1>", ">|"}
_WRAPPERS = {"env", "nice", "nohup", "time", "exec", "command", "builtin", "sudo", "doas", "xargs", "timeout", "caffeinate", "arch", "uv", "poetry", "pipenv", "pyenv", "conda"}


def _tokens(one):
    try:
        lx = shlex.shlex(one, posix=True, punctuation_chars=";&|()<>")
        lx.whitespace_split = True
        lx.commenters = ""
        return list(lx)
    except ValueError:
        return None


def _segments(toks):
    seg, out = [], []
    for t in toks:
        if t in _SEP or (set(t) <= set(";&|()") and t):
            out.append(seg)
            seg = []
        else:
            seg.append(t)
    out.append(seg)
    return [s for s in out if s]


def _tail_ok(rest):
    """after the program's own words: only redirections of OUTPUT (`2>&1`, `> out.txt`, `2>/dev/null`)."""
    i = 0
    while i < len(rest):
        t = rest[i]
        if t in ("2", "1") and i + 1 < len(rest) and rest[i + 1] in _REDIR:
            i += 1
            continue
        if t in _REDIR:
            if i + 1 >= len(rest) or rest[i + 1] in _REDIR or rest[i + 1].startswith("<"):
                return False
            i += 2
            continue
        return False
    return True


def py_codes(line, with_ops=False):
    """-> (codes, n_python) -- the code of every inline Python program of the line and how many Python programs it starts -- or None
    when the line cannot be read this way (unbalanced, a substitution, an unquoted heredoc delimiter for Python ...).
    r0349: `python3 - ARG ... <<'EOF'` (the program from the heredoc, the words after `-` are its sys.argv: DATA, never code) is read too;
    with_ops: codes is [(code, operands)] -- the operands with a literal `NAME=value` of the line substituted for `$NAME` / `${NAME}`
    (a value set once, with no expansion of its own); an operand that keeps a `$` stays as it is (pyform: not a computed path)."""
    from .bashparse import _normalize
    if not isinstance(line, str):
        return None
    try:
        one, docs, balanced, unsure = _normalize(line)
    except Exception:      # noqa: BLE001
        return None
    if isinstance(one, str):
        # r0349: a plain command substitution with no quote, parenthesis, backtick or `$` of its own (`$(date +%H:%M)`) is one word for
        # the purpose of finding the Python programs (the parser classifies it as a line of its own); any other one: not read
        one = re.sub(r"\$\([^()`'\"\\$;&|<>\n]*\)", "__SUB__", one)
    if not balanced or unsure is not None or not isinstance(one, str) or re.search(r"\$\(|`|<\(|>\(", one):
        return None
    toks = _tokens(one)
    if toks is None:
        return None
    hd = [i for i, t in enumerate(toks) if t == "__HEREDOC__"]
    if len(hd) != len(docs):
        return None
    codes, npy, k = [], 0, 0
    lvars, seen = {}, set()
    for seg in _segments(toks):
        nh = sum(1 for t in seg if t == "__HEREDOC__")
        pos, k = k, k + nh
        if all(re.fullmatch(r"[A-Za-z_]\w*=.*", t_, re.S) for t_ in seg):
            for t_ in seg:
                n_, v_ = t_.split("=", 1)
                ok_ = n_ not in seen and not re.search(r"[$`\\]", v_)
                seen.add(n_)
                if ok_:
                    lvars[n_] = v_
                else:
                    lvars.pop(n_, None)
            continue
        base = seg[0].rsplit("/", 1)[-1]
        if not PY_NAME.fullmatch(base):
            if (base in _WRAPPERS or "=" in seg[0]) and any(PY_NAME.fullmatch(w_.rsplit("/", 1)[-1]) for w_ in seg[1:]):
                return None                           # `env X=1 python3`, `nice python3`, `X=1 python3`: not this grammar
            continue
        npy += 1
        if seg[0] != base:
            return None                               # a path (`./python3`, `.venv/bin/python`): a file the agent may have written
        w = seg[1:]
        ops = []
        if w[:1] == ["-"] and "<<" in w and w.index("<<") > 1 and w[w.index("<<") + 1:w.index("<<") + 2] == ["__HEREDOC__"]:
            # r0349: `python3 - ARG ... <<'EOF'`: the words between `-` and the heredoc are sys.argv[1:] (an operand is never an option
            # of python after `-`); none of them may be a redirection or a here-string (stdin is the heredoc)
            i_ = w.index("<<")
            ops = w[1:i_]
            if any(o_ in _REDIR or o_.startswith(("<", ">")) or o_ == "__HEREDOC__" for o_ in ops):
                return None
            w = ["-"] + w[i_:]
        if w[:3] == ["-", "<<", "__HEREDOC__"] or w[:2] == ["<<", "__HEREDOC__"]:
            if nh != 1 or not _tail_ok(w[3 if w[0] == "-" else 2:]):
                return None
            if pos >= len(docs) or not docs[pos][2]:
                return None                           # an unquoted delimiter: the shell expands $(...) inside the body
            codes.append((docs[pos][1], [_lsub(o_, lvars) for o_ in ops]) if with_ops else docs[pos][1])
        elif len(w) >= 2 and w[0] == "-c" and nh == 0:
            if not _tail_ok(w[2:]):
                return None
            codes.append((w[1], []) if with_ops else w[1])
        else:
            return None
    return codes, npy


def _lsub(o, lvars):
    m = re.fullmatch(r"\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})", o)
    if m and (m.group(1) or m.group(2)) in lvars:
        return lvars[m.group(1) or m.group(2)]
    return o


def closed_line(line, home=None):
    """r0349: -> True when every Python program of the line is inline code of the CLOSED form (hookjudge/pyform.closed: only files by
    computed paths, nothing rebound, nothing run) and of the edit-only list. The caller (vektor) judges the line's other programs."""
    from .pyform import closed
    r = py_codes(line, with_ops=True)
    if r is None:
        return False
    codes, npy = r
    if not codes or len(codes) != npy:
        return False
    if re.search(r"(?:^|[\s;&|(])(?:PYTHON\w*|PATH|VIRTUAL_ENV)=", line):
        return False
    return all(edit_only(c_) is not None and closed(c_, o_, home) is None for c_, o_ in codes)


def edit_only_line(line, risky_paths=()):
    """(а) -> True when every Python program of the line is inline edit-only code and no written file (risky_paths) could be imported in
    its place: its name (or its folder's name) is a stdlib module or one the code imports. The caller checks the line's OTHER programs."""
    r = py_codes(line)
    if r is None:
        return False
    codes, npy = r
    if not codes or len(codes) != npy:
        return False
    if re.search(r"(?:^|[\s;&|(])(?:PYTHON\w*|PATH|VIRTUAL_ENV)=", line):
        return False
    imported = set()
    for c in codes:
        m = edit_only(c)
        if m is None:
            return False
        imported |= m
    names = STDLIB | imported
    for p in risky_paths:
        if not isinstance(p, str):
            return False
        parts = p.rstrip("/").split("/")
        stem = parts[-1].split(".")[0]
        parent = parts[-2] if len(parts) >= 2 else ""
        if stem in names or parent in names:
            return False
    return True


# ---- (в) DLP: text that only goes into a local file -------------------------------------------------------------------------------
_WRITE_HEADS = {"cat", "tee"}


def dlp_inert_text(line, witness):
    """-> the line with its INERT text cut out (bodies of quoted heredocs that `cat > f` / `tee f` / edit-only Python only put into a
    local file), or None when nothing is inert or the line may send it anywhere: the hook saw network on it, a program that leaves the
    machine (sandbox.code_exit), a network word outside quotes and bodies, or code that talks to the network."""
    from . import sandbox as _sbx
    from .bashparse import _normalize, code_net
    if not isinstance(line, str) or not isinstance(witness, dict):
        return None
    if witness.get("net") or not isinstance(witness.get("commands"), list) or not witness["commands"]:
        return None
    if any(_sbx.code_exit(h) for h in witness["commands"]):
        return None
    from .runners import head_runs_code
    words = [w_.strip("'\"") for w_ in re.split(r"\s+", line) if w_]
    runs = [h for h in witness["commands"] if not isinstance(h, str) or head_runs_code(h, words)]
    if any(not _py_head(h) for h in runs) or (runs and not edit_only_line(line, ())):
        return None                                   # a program that may run the written file (`cat > x.sh <<'EOF' ... && bash x.sh`)
    sk = _sbx.skeleton(line)
    if sk is line or _sbx.NET_TEXT.search(sk):
        return None
    try:
        one, docs, balanced, unsure = _normalize(line)
    except Exception:      # noqa: BLE001
        return None
    if not balanced or unsure is not None or re.search(r"\$\(|`|<\(|>\(", one or ""):
        return None
    toks = _tokens(one)
    if toks is None or sum(1 for t in toks if t == "__HEREDOC__") != len(docs):
        return None
    inert, k = [], 0
    for seg in _segments(toks):
        n = sum(1 for t in seg if t == "__HEREDOC__")
        if n == 1 and docs[k][2]:
            body = docs[k][1]
            head = seg[0].rsplit("/", 1)[-1]
            ok = False
            if head in _WRITE_HEADS and "<<" in seg:
                outs = [seg[i + 1] for i, t in enumerate(seg[:-1]) if t in (">", ">>")] if head == "cat" else \
                    [t for t in seg[1:] if not t.startswith("-") and t not in ("<<", "__HEREDOC__")]
                ok = bool(outs) and all(o not in ("/dev/stdout", "/dev/stderr", "/dev/tty") and not o.startswith("/dev/") for o in outs)
            elif _py_head(seg[0]) and edit_only(body) is not None:
                hosts, unseen = code_net(_blank_text_literals(body) or body)    # r0261d: a host in a TEXT literal is text
                ok = not hosts and not unseen
            if ok:
                inert.append(body)
        k += n
    for seg in _segments(toks):
        if _py_head(seg[0]) and len(seg) >= 3 and seg[1] == "-c" and edit_only(seg[2]) is not None and \
                code_net(_blank_text_literals(seg[2]) or seg[2]) == ([], None):
            inert.append(seg[2])
    if not inert:
        return None
    out = line
    for b in inert:
        if b and b in out:
            out = out.replace(b, "", 1)
    return out if out != line else None


# ---- r0261b: text an inline program only writes, for the immutable articles (strict_policy._text_article) ---------------------------
def _py_head(w):
    """r0261d: a Python interpreter word: `python3`, or a path to one in a bin folder (`.venv/bin/python`, `/usr/bin/python3`)."""
    return isinstance(w, str) and bool(PY_NAME.fullmatch(w.rsplit("/", 1)[-1])) and ("/" not in w or "/bin/" in "/" + w)


def inert_cut(line, witness, spaced=False, ext=False):
    """-> (line without its INERT text, unreadable, other_runs) or None when nothing can be cut. Inert: the body of a QUOTED heredoc that
    `cat > f` / `tee f` writes, or that edit-only Python reads as its program (edit_only: no exec / system / subprocess / import
    machinery), and the code of an edit-only `python3 -c`: there only the TEXT literals are blanked (_blank_text_literals: a path the
    code itself removes or opens stays, `shutil.rmtree('..')` is an act). A quoted heredoc fed to python3 that does not parse (cut by the
    friction stand, broken) is cut whole and marks the result `unreadable` (the caller asks, never refuses).
    `other_runs`: another program of the line runs code (`... && bash x.sh`): what was written may run. Network is not judged here."""
    from .bashparse import _normalize
    from .runners import head_runs_code
    if not isinstance(line, str) or not isinstance(witness, dict) or not isinstance(witness.get("commands"), list):
        return None
    try:
        one, docs, balanced, unsure = _normalize(line)
    except Exception:      # noqa: BLE001
        return None
    if not balanced or unsure is not None or not isinstance(one, str) or re.search(r"\$\(|`|<\(|>\(", one):
        return None
    toks = _tokens(one)
    if toks is None or sum(1 for t in toks if t == "__HEREDOC__") != len(docs):
        return None
    inert, unread, k = [], False, 0
    for seg in _segments(toks):
        n = sum(1 for t in seg if t == "__HEREDOC__")
        if n == 1 and docs[k][2]:
            body = docs[k][1]
            head = seg[0].rsplit("/", 1)[-1]
            if head in _WRITE_HEADS and "<<" in seg:
                outs = [seg[i + 1] for i, t in enumerate(seg[:-1]) if t in (">", ">>")] if head == "cat" else \
                    [t for t in seg[1:] if not t.startswith("-") and t not in ("<<", "__HEREDOC__")]
                if outs and all(not o.startswith("/dev/") for o in outs):
                    inert.append(body)
            elif (PY_NAME.fullmatch(seg[0]) or (ext and _py_head(seg[0]))) and (seg[1:3] == ["-", "<<"] or seg[1:2] == ["<<"]):
                if _tree(body) is None:
                    inert.append(body)
                    unread = True
                elif edit_only(body, ext) is not None:
                    nb = _blank_text_literals(body, spaced, hosts=ext)
                    if nb is not None and nb != body:
                        inert.append((body, nb))
        elif (PY_NAME.fullmatch(seg[0]) or (ext and _py_head(seg[0]))) and len(seg) >= 3 and seg[1] == "-c" and n == 0:
            if edit_only(seg[2], ext) is not None:
                nb = _blank_text_literals(seg[2], spaced, hosts=ext)
                if nb is not None and nb != seg[2]:
                    inert.append((seg[2], nb))
        k += n
    if not inert:
        return None
    words = [w_.strip("'\"") for w_ in re.split(r"\s+", line) if w_]
    pc = py_codes(line)                               # r0261c: a python that runs a FILE (`python3 tools/x.py`) is another program
    py_inline = pc is not None and len(pc[0]) == pc[1]
    other = any(not isinstance(h, str) or (head_runs_code(h, words) and
                                           not (py_inline and PY_NAME.fullmatch(h.split(" ")[0].rsplit("/", 1)[-1])))
                for h in witness["commands"])
    if ext and other and all(not isinstance(h, str) or not head_runs_code(h, words) or _py_head(h.split(" ")[0])
                             for h in witness["commands"]):
        # r0261d (closed credentials): what another PYTHON of the line runs (pytest, the project's module) is the project's code, which may reach a listed host
        # anyway (Р-1011-сеть-в-строгой); only TEXT literals of Python are still cut then -- a written heredoc body (`cat > x.sh`) stays,
        # and a shell / node / any other runner keeps the whole text (`... write('curl ...') ; bash x.sh`: what was written runs)
        inert = [b for b in inert if isinstance(b, tuple)]
        other = False
    out = line
    for b in inert:
        old, new = b if isinstance(b, tuple) else (b, "")
        if old and old in out:
            out = out.replace(old, new, 1)
        elif old and isinstance(b, tuple):
            # r0261e: `python -c "... \"text\" ..."` -- the shell read `\"` as `"`; the raw line holds the code double-quote escaped
            for esc in (lambda x: x.replace('"', '\\"'), lambda x: x.replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")):
                if esc(old) in out:
                    out = out.replace(esc(old), esc(new), 1)
                    break
    return (out, unread, other) if out != line else None


# r0261e: a bare host / URL literal (`'api.github.com'`, `'https://pypi.org/simple'`) -- text when the project's own Python only names it (ext)
_HOST_LIT = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*://)?[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.[A-Za-z]{2,}(?::\d+)?(?:/\S*)?")


_FILE_EXT = frozenset("py pyc pyi txt md rst json jsonl sh bash zsh js mjs cjs ts tsx jsx yml yaml toml cfg ini conf log csv tsv html htm css "
                      "lock db sqlite sqlite3 env pem key crt pub der p12 pfx gpg asc plist xml svg png jpg jpeg gif pdf zip tar gz tgz whl "
                      "so dylib dll exe bin out tmp bak orig patch diff c h cc cpp hpp rs go rb pl php java kt swift lua sql ipynb".split())


def _blank_text_literals(code, spaced=False, hosts=False):
    """r0261b: `code` (edit-only Python: the caller checked edit_only) with every TEXT string literal (as blank_text decides: a newline,
    a quote, `;`, `$`, a blank not starting like a path ...) replaced by the number 0 -- no quote is added, so the code stays the same
    word of the shell line. A path literal stays. Unlike blank_text this does not stop at code-running WORDS inside literals (os.system
    in a test string): edit_only proved on the tree that nothing runs. -> the new code, or None when it cannot be done."""
    lines = code.splitlines(keepends=True)
    offs, k = [], 0
    for ln in lines:
        offs.append(k)
        k += len(ln)
    reps = []
    try:
        for tk in tokenize.generate_tokens(io.StringIO(code).readline):
            if tk.type != tokenize.STRING:
                continue
            if "f" in re.match(r"[A-Za-z]*", tk.string).group(0).lower():
                return None
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    v = ast.literal_eval(tk.string)
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                return None
            if isinstance(v, bytes):
                v = v.decode("latin-1")
            if isinstance(v, str) and (_TEXT_CH.search(v) or (" " in v and (spaced or not v.startswith(("/", "~", ".")))) or
                                       (hosts and _HOST_LIT.fullmatch(v) and ("://" in v or v.rsplit(".", 1)[-1].lower() not in _FILE_EXT))):
                reps.append((tk.start, tk.end))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None
    out, last = [], 0
    for (r0, c0), (r1, c1) in reps:
        a, b = offs[r0 - 1] + c0, offs[r1 - 1] + c1
        out.append(code[last:a])
        out.append("0")
        last = b
    out.append(code[last:])
    s = "".join(out)
    return s if _tree(s) is not None else None


def runs_text(line, heads, spaced=False, ext=False):
    """r0261c (class (а)): the line as it RUNS for a search of named hosts / publications -- the text an edit-only inline program only
    writes is cut (inert_cut: quoted heredoc bodies of `cat > f` / `tee f`, TEXT literals of edit-only Python). The line itself when
    nothing can be cut, a body cannot be read, or another program of the line runs code (what was written may run)."""
    if not isinstance(line, str) or not isinstance(heads, (list, tuple)):
        return line
    ic = inert_cut(line, {"commands": list(heads)}, spaced, ext)
    if ic is None:
        return line
    out, unread, other = ic
    return line if (unread or other) else out


# ---- r0261c (class (г)): a file written and run on the SAME line -------------------------------------------------------------------
_RUN_HEADS = {"bash", "sh", "zsh", "dash", "ksh", "source", ".", "python", "python3", "node", "perl", "ruby"}


def written_texts(line):
    """-> (texts, targets): the TEXT a line writes into files by `cat > f <<EOF` / `tee f <<EOF` (the body) and by edit-only inline Python
    (its string constants), and the files `cat` / `tee` write. ([], []) when the line cannot be read this way."""
    from .bashparse import _normalize
    try:
        one, docs, balanced, unsure = _normalize(line)
    except Exception:      # noqa: BLE001
        return [], []
    if not balanced or unsure is not None or not isinstance(one, str):
        return [], []
    toks = _tokens(one)
    if toks is None or sum(1 for t in toks if t == "__HEREDOC__") != len(docs):
        return [], []
    texts, targets, k = [], [], 0
    for seg in _segments(toks):
        n = sum(1 for t in seg if t == "__HEREDOC__")
        head = seg[0].rsplit("/", 1)[-1]
        code = None
        if n == 1 and k < len(docs):
            body = docs[k][1]
            if head in _WRITE_HEADS and "<<" in seg:
                outs = [seg[i + 1] for i, t in enumerate(seg[:-1]) if t in (">", ">>")] if head == "cat" else \
                    [t for t in seg[1:] if not t.startswith("-") and t not in ("<<", "__HEREDOC__")]
                if outs:
                    texts.append(body)
                    targets += outs
            elif PY_NAME.fullmatch(seg[0]):
                code = body
        elif n == 0 and PY_NAME.fullmatch(seg[0]) and len(seg) >= 3 and seg[1] == "-c":
            code = seg[2]
        if isinstance(code, str) and edit_only(code) is not None:
            t = _tree(code)
            for nd in ast.walk(t) if t is not None else ():
                if isinstance(nd, ast.Constant) and isinstance(nd.value, str) and nd.value.strip():
                    texts.append(nd.value)
        k += n
    return texts[:32], targets


def runs_written(line, writes):
    """-> True when a program of the line runs a file the line writes (`bash x.sh`, `sh x.sh`, `./x.sh`, `source x.sh`, `python3 x.py`):
    `writes` = the parser's write targets (absolute) and the `cat` / `tee` targets (as written)."""
    names = {w.rstrip("/").rsplit("/", 1)[-1] for w in writes if isinstance(w, str) and w}
    if not names:
        return False
    from .strict_policy import _segments as _segs
    for a in _segs(line):
        h = a[0].rsplit("/", 1)[-1]
        if h in names and (a[0].startswith("./") or "/" in a[0]):
            return True
        if h in _RUN_HEADS or PY_NAME.fullmatch(h):
            ops = [x for x in a[1:] if not x.startswith("-")]
            if ops and ops[0].rsplit("/", 1)[-1] in names:
                return True
    return False
