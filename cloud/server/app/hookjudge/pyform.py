"""r0349 (Р-1811-rychag): the CLOSED FORM of inline Python -- a static reading (ast, nothing runs) of code typed into the line
(`python3 - [ARG ...] <<'EOF'`, `python3 -c '...'`) that decides whether its whole consequence is "these files are read / written".

inline.edit_only (r0260) already says the code runs nothing but itself and a list of stdlib modules; the file paths it reads and writes
are found by the lexical scan of bashparse (_code_fs_scan: open(PATH, MODE), Path(PATH).write_text ...). The lexical scan reads the
TEXT of a call; the consequence of the code depends on what its names are BOUND to. Measured holes (tests r0349): `o = open;
o('/x/.zshrc', 'a')` (open under another name), `m = 'w'; open(p, m)` (a mode the scan takes for a read), `p = Path(x); p.write_text()`
(a method on a path in a variable), `p = 'a.md'; p += '/../../.zshrc'` (the scan keeps the first value), `open(p, 'w', opener=f)`.

closed(code, operands) -> None when the code is of the closed form, else why not. The closed form (law: silence only for a consequence
the witness COMPUTED; anything else is not below a question):
  * imports only from CLOSED_IMPORTS, no `as` alias of a module or of a name, no `from x import *`;
  * no name, attribute or keyword the edit-only list forbids (exec, eval, compile, __import__, getattr, ..., any `_x` attribute);
  * `open`, `Path` and the modules are never rebound and never used as a value -- only called (`open(...)`, `Path(...)`, `json.load`);
  * open(PATH[, MODE][, encoding= / errors= / newline= / buffering=]): MODE a string literal, PATH computed (below);
  * Path(PATH) [/ 'lit' ...] used only as `Path(...).read_text / write_text / read_bytes / write_bytes / exists / is_file / is_dir()`;
    a Path object is never kept in a variable;
  * sys only as sys.argv[N] / sys.stdin / sys.stdout / sys.stderr / sys.exit; os only as os.path.<pure function> / os.sep / os.linesep;
  * a PATH is computed from string literals, `~` (os.path.expanduser), os.path.join, `+`, sys.argv[N] of a literal operand of the line,
    and names bound EXACTLY ONCE in the whole code by a plain `name = <computed>` (any other binding: for, with-as, +=, a function
    argument, a second assignment -- not computed).
writes(code, operands) -> [(path, "w" | "r")] of the closed form (the paths as the code names them; relative to the line's cwd).
"""
from __future__ import annotations

import ast
import re
import warnings

CLOSED_IMPORTS = frozenset({"json", "re", "pathlib", "os", "sys", "datetime", "collections", "textwrap", "difflib", "string", "itertools",
                            "functools", "math", "unicodedata", "statistics", "bisect", "heapq", "operator", "copy", "enum", "typing",
                            "dataclasses", "time", "html", "csv", "fnmatch"})
_OS_PATH = frozenset({"join", "expanduser", "exists", "isfile", "isdir", "basename", "dirname", "splitext", "split", "normpath",
                      "isabs", "getsize"})
_SYS_OK = frozenset({"argv", "stdin", "stdout", "stderr", "exit"})
_PATH_OK = frozenset({"read_text", "write_text", "read_bytes", "write_bytes", "exists", "is_file", "is_dir"})
_PATH_WRITE = frozenset({"write_text", "write_bytes"})
_OPEN_KW = frozenset({"mode", "encoding", "errors", "newline", "buffering"})
_BAD_NAMES = frozenset({"exec", "eval", "compile", "__import__", "getattr", "setattr", "delattr", "globals", "locals", "vars", "breakpoint",
                        "execfile", "input", "help", "__builtins__", "builtins", "memoryview", "classmethod", "staticmethod", "super",
                        "object", "type"})
MAX_CODE = 64 * 1024


def _tree(code):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(code)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None


class _Not(Exception):
    pass


class _Reader:
    def __init__(self, tree, operands, home):
        self.t, self.ops, self.home = tree, [o for o in operands], home
        self.mods = set()                       # module names bound by `import x`
        self.names = {}                         # name -> imported module of `from m import name`
        self.binds = {}                         # name -> [value node | None (not a plain assignment)]
        self.files = []
        self.parent = {}

    # ------------------------------------------------------------------ pass 1: imports and bindings
    def scan(self):
        for n in ast.walk(self.t):
            for ch in ast.iter_child_nodes(n):
                self.parent[ch] = n
        for n in ast.walk(self.t):
            if isinstance(n, ast.Import):
                for a in n.names:
                    top = a.name.split(".")[0]
                    if top not in CLOSED_IMPORTS or a.asname:
                        raise _Not("import %s" % a.name)
                    self.mods.add(top)
            elif isinstance(n, ast.ImportFrom):
                if n.level or not n.module or n.module.split(".")[0] not in CLOSED_IMPORTS:
                    raise _Not("from %s import" % n.module)
                for a in n.names:
                    if a.name == "*" or a.asname or a.name.startswith("_"):
                        raise _Not("from %s import %s" % (n.module, a.name))
                    if n.module.split(".")[0] == "os" and not (n.module == "os.path" and a.name in _OS_PATH):
                        raise _Not("from %s import %s" % (n.module, a.name))
                    self.names[a.name] = n.module
            elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                self.binds.setdefault(n.targets[0].id, []).append(n.value)
            elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                p = self.parent.get(n)
                if not (isinstance(p, ast.Assign) and len(p.targets) == 1 and p.targets[0] is n):
                    self.binds.setdefault(n.id, []).append(None)          # for / with-as / += / tuple unpacking / del: not computed
            elif isinstance(n, ast.arg):
                self.binds.setdefault(n.arg, []).append(None)             # a function argument
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.binds.setdefault(n.name, []).append(None)
            elif isinstance(n, ast.ExceptHandler) and n.name:
                self.binds.setdefault(n.name, []).append(None)            # `except E as name`
            elif isinstance(n, (ast.Global, ast.Nonlocal)):
                raise _Not("global / nonlocal")
            elif type(n).__name__ in ("Match", "TypeAlias", "TypeVar", "ParamSpec", "TypeVarTuple"):
                raise _Not("a %s statement" % type(n).__name__)       # binds names the walk above does not see
            elif isinstance(n, (ast.Subscript, ast.Attribute, ast.Starred)) and isinstance(getattr(n, "ctx", None), (ast.Store, ast.Del)):
                b = n.value
                while isinstance(b, (ast.Subscript, ast.Attribute)):
                    b = b.value
                if isinstance(b, ast.Name) and (b.id in ("sys", "os", "open", "Path") or b.id in self.mods):
                    raise _Not("a module changed in place (%s)" % b.id)     # `sys.argv[1] = ...`, `os.path.join = ...`
        for nm in ("open", "Path", "sys", "os") + tuple(self.mods) + tuple(self.names):
            if nm in self.binds:
                raise _Not("%s is rebound" % nm)

    # ------------------------------------------------------------------ the value of a path expression
    def path(self, e, depth=0):
        if depth > 32:
            raise _Not("path too deep")
        if isinstance(e, ast.Constant) and isinstance(e.value, str):
            return e.value
        if isinstance(e, ast.Name):
            b = self.binds.get(e.id)
            if not b or len(b) != 1 or b[0] is None:
                raise _Not("the path name %s is not bound once" % e.id)
            return self.path(b[0], depth + 1)
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
            return self.path(e.left, depth + 1) + self.path(e.right, depth + 1)
        if isinstance(e, ast.Subscript) and self._is(e.value, "sys", "argv"):
            k = e.slice
            if not (isinstance(k, ast.Constant) and isinstance(k.value, int) and not isinstance(k.value, bool) and 1 <= k.value <= len(self.ops)):
                raise _Not("sys.argv index not shown")
            v = self.ops[k.value - 1]
            if not isinstance(v, str) or re.search(r"[$`*?\[{]", v):
                raise _Not("an operand that is not a literal")
            return v
        if isinstance(e, ast.Call) and not e.keywords:
            f = e.func
            if self._os_path(f, "expanduser") and len(e.args) == 1:
                v = self.path(e.args[0], depth + 1)
                if v == "~" or v.startswith("~/"):
                    if not isinstance(self.home, str):
                        raise _Not("home not known")
                    return self.home + v[1:]
                if v.startswith("~"):
                    raise _Not("~user")
                return v
            if self._os_path(f, "join") and e.args:
                parts = [self.path(a, depth + 1) for a in e.args]
                out = ""
                for p in parts:
                    out = p if p.startswith("/") else (out.rstrip("/") + "/" + p if out else p)
                return out
        raise _Not("a path that is not computed (%s)" % type(e).__name__)

    def _is(self, e, mod, attr):
        return isinstance(e, ast.Attribute) and e.attr == attr and isinstance(e.value, ast.Name) and e.value.id == mod and mod in self.mods

    def _os_path(self, f, fn):
        if isinstance(f, ast.Attribute) and f.attr == fn and isinstance(f.value, ast.Attribute) and f.value.attr == "path" and \
                isinstance(f.value.value, ast.Name) and f.value.value.id == "os" and "os" in self.mods:
            return True
        return isinstance(f, ast.Name) and f.id == fn and self.names.get(fn) == "os.path"

    def _path_obj(self, e, depth=0):
        """Path(PATH) [/ 'lit' ...] -> the path, else raise"""
        if depth > 16:
            raise _Not("path too deep")
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Div):
            return self._path_obj(e.left, depth + 1).rstrip("/") + "/" + self.path(e.right)
        if isinstance(e, ast.Call) and self._path_ctor(e.func) and len(e.args) == 1 and not e.keywords:
            v = self.path(e.args[0])
            if v == "~" or v.startswith("~/"):
                raise _Not("Path('~') is not expanded by Path()")
            return v
        raise _Not("a Path not computed")

    def _path_ctor(self, f):
        return (isinstance(f, ast.Name) and f.id == "Path" and self.names.get("Path") == "pathlib") or \
            (isinstance(f, ast.Attribute) and f.attr == "Path" and isinstance(f.value, ast.Name) and f.value.id == "pathlib" and "pathlib" in self.mods)

    # ------------------------------------------------------------------ pass 2: every use
    def check(self):
        for n in ast.walk(self.t):
            if isinstance(n, ast.Name):
                if n.id in _BAD_NAMES or (n.id.startswith("__") and n.id not in ("__name__", "__file__")):
                    raise _Not("the name %s" % n.id)
                if n.id == "open" or (n.id == "Path" and "Path" in self.names) or n.id in ("sys", "os") or n.id in self.mods:
                    p = self.parent.get(n)
                    if n.id == "open" or n.id == "Path":
                        if not (isinstance(p, ast.Call) and p.func is n):
                            raise _Not("%s used as a value" % n.id)
                    elif not isinstance(p, ast.Attribute):
                        raise _Not("the module %s used as a value" % n.id)
                elif n.id in self.names and n.id != "Path":
                    p = self.parent.get(n)
                    if self.names[n.id] == "os.path" and not (isinstance(p, ast.Call) and p.func is n):
                        raise _Not("%s used as a value" % n.id)
            elif isinstance(n, ast.Attribute):
                if n.attr.startswith("_"):
                    raise _Not("the attribute %s" % n.attr)
                v = n.value
                if isinstance(v, ast.Name) and v.id == "sys" and "sys" in self.mods and n.attr not in _SYS_OK:
                    raise _Not("sys.%s" % n.attr)
                if self._is(n, "sys", "argv"):
                    p = self.parent.get(n)
                    if not (isinstance(p, ast.Subscript) and p.value is n and isinstance(p.ctx, ast.Load)):
                        raise _Not("sys.argv used other than sys.argv[N]")      # .insert / .pop / a copy: what argv[N] names is not known
                if isinstance(v, ast.Name) and v.id == "os" and "os" in self.mods and n.attr not in ("path", "sep", "linesep"):
                    raise _Not("os.%s" % n.attr)
                if isinstance(v, ast.Attribute) and v.attr == "path" and isinstance(v.value, ast.Name) and v.value.id == "os" and \
                        n.attr not in _OS_PATH:
                    raise _Not("os.path.%s" % n.attr)
                if isinstance(v, ast.Name) and v.id == "os" and n.attr == "path":
                    p = self.parent.get(n)
                    if not isinstance(p, ast.Attribute):
                        raise _Not("os.path used as a value")
                if isinstance(v, ast.Name) and v.id == "pathlib" and n.attr != "Path":
                    raise _Not("pathlib.%s" % n.attr)
                if isinstance(v, ast.Name) and v.id == "pathlib" and n.attr == "Path":
                    p = self.parent.get(n)
                    if not (isinstance(p, ast.Call) and p.func is n):
                        raise _Not("pathlib.Path used as a value")
            elif isinstance(n, ast.Call):
                self._call(n)

    def _call(self, n):
        f = n.func
        if isinstance(f, ast.Name) and f.id == "open":
            if any(k.arg not in _OPEN_KW for k in n.keywords) or not n.args or len(n.args) > 3:
                raise _Not("open() with a keyword or form outside the closed list")
            mode = "r"
            md = n.args[1] if len(n.args) > 1 else next((k.value for k in n.keywords if k.arg == "mode"), None)
            if md is not None:
                if not (isinstance(md, ast.Constant) and isinstance(md.value, str) and re.fullmatch(r"[rwaxbt+]{1,4}", md.value)):
                    raise _Not("open() with a mode that is not a literal")
                mode = md.value
            for k in n.keywords:
                if k.arg in ("encoding", "errors", "newline") and not (isinstance(k.value, ast.Constant) and isinstance(k.value.value, (str, type(None)))):
                    raise _Not("open() %s= not a literal" % k.arg)
            self.files.append((self.path(n.args[0]), "w" if re.search(r"[wax+]", mode) else "r"))
            return
        if self._path_ctor(f):
            p = self.parent.get(n)
            q = n
            while isinstance(p, ast.BinOp) and isinstance(p.op, ast.Div) and p.left is q:
                q, p = p, self.parent.get(p)
            if not (isinstance(p, ast.Attribute) and p.attr in _PATH_OK and p.value is q and isinstance(self.parent.get(p), ast.Call)
                    and self.parent[p].func is p):
                raise _Not("a Path used other than Path(...).%s()" % "/".join(sorted(_PATH_OK)))
            self.files.append((self._path_obj(q), "w" if p.attr in _PATH_WRITE else "r"))
            return


def _read(code, operands=(), home=None):
    if not isinstance(code, str) or len(code) > MAX_CODE:
        raise _Not("code not readable")
    t = _tree(code)
    if t is None:
        raise _Not("code does not parse")
    r = _Reader(t, operands, home)
    r.scan()
    r.check()
    return r


def closed(code, operands=(), home=None):
    """-> None when `code` is of the closed form (module text), else why not"""
    try:
        _read(code, operands, home)
        return None
    except _Not as e:
        return str(e) or "not closed"
    except (RecursionError, MemoryError, ValueError, TypeError):
        return "code not readable"


def files(code, operands=(), home=None):
    """-> [(path, "w" | "r")] of closed code, or None"""
    try:
        return list(_read(code, operands, home).files)
    except (_Not, RecursionError, MemoryError, ValueError, TypeError):
        return None


# the reasons of `closed` that are a HOLE of the lexical scan (the scan would name another file or none): what the code binds a name to
HOLE = re.compile(r"used as a value|is rebound|not bound once|mode that is not a literal|keyword or form outside|Path used other than|"
                  r"^the name (?:exec|eval|compile|__import__|getattr|setattr|vars|globals|locals|type|object|super|__builtins__)")
