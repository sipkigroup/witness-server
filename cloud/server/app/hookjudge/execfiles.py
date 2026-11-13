"""0.2.13 (PROPOSAL-08), server-side since 0.2.16: files that a later command EXECUTES (conftest.py, package.json scripts, Makefile, build.rs,
.git/hooks ...).

The tables (which file belongs to which family, which command executes which family) live in app/execguard.py and ONLY on the server.
The thin hook (0.2.16) gets a signed, versioned list of file shapes to fingerprint (`scan_list()`, GET /v1/hook/scanlist): names, name
prefixes/suffixes and directory rules WITHOUT the families and without the commands that execute them. It walks the project with that
list and reports {root, files: {relative path: sha256}, git: {absolute path: sha256}, truncated}; the server judges the report.

`scan()` below is the reference walk (the 0.2.15 hook's), used when the classifier runs on the machine it judges (LocalFS: tests, the
fatigue harness); a test keeps it equal to the hook's list-driven walk (deus_witness/hook/fingerprint.py)."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time

from app.execguard import (DIRS, EXECUTORS, NAMES, PREFIXES, SUB_EXECUTORS, SUFFIXES, families_of_command, families_of_path,  # noqa: F401
                           fold, GITCFG_KEYS, MAX_GITCFG_ENTRIES, MAX_GITCFG_VALUE)


# ---------------------------------------------------------------- the scan (hook side)
SKIP_DIRS = {"node_modules", ".venv", "venv", "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
             "target", ".next", ".cache", ".gradle", ".idea", ".hg", ".svn", "coverage", ".terraform", ".eggs", "site-packages", "bower_components"}
MAX_ENTRIES = 20000
MAX_FILES = 200
MAX_DEPTH = 10
MAX_BYTES = 4 * 1024 * 1024
MAX_SECONDS = 0.5
_GO_LINES = re.compile(rb"^\s*(go|toolchain|replace)\b")


def file_digest(path: str, root: str) -> str:
    """SHA-256 hex of what the file means for execution: its content (go.mod: only the go / toolchain / replace lines, the rest is ordinary
    dependency bookkeeping); a symlink also binds the target's real path (a link swapped to another file is a change). 'unreadable' on error."""
    h = hashlib.sha256()
    try:
        if os.path.islink(path):
            h.update(b"link:" + os.path.realpath(path).encode("utf-8", "surrogateescape") + b"\0")
        with open(path, "rb") as f:
            data = f.read(MAX_BYTES + 1)
        if os.path.basename(path) == "go.mod":
            keep, block = [], False
            for line in data.splitlines():
                s = line.strip()
                if block:
                    keep.append(line)
                    block = s != b")"
                elif _GO_LINES.match(line):
                    keep.append(line)
                    block = s.endswith(b"(")
            data = b"\n".join(keep)
        h.update(data)
        return h.hexdigest()
    except (OSError, ValueError):
        return "unreadable"


_EXEC_NAMES = sorted({n for names in EXECUTORS.values() for n in names})


def _bin_extras(bindir, out, root):
    """0.2.14 (R8-02): the executables of the listed commands inside the project (<venv>/bin/pytest, node_modules/.bin/jest): `pytest`
    with an activated environment, `npm test` -> jest run THESE files. Only names of known commands are read (bounded)."""
    try:
        have = set(os.listdir(bindir))
    except OSError:
        return
    for n in _EXEC_NAMES:
        for v in (n, n + ".exe", n + ".cmd", n + "-script.py"):
            if v in have:
                full = os.path.join(bindir, v)
                out[os.path.relpath(full, root)] = full


def _venv_extras(d, out, root):
    """A virtual environment inside the project: the interpreter runs its site-packages/*.pth and sitecustomize.py at start; its bin/
    holds the commands themselves."""
    for b in ("bin", "Scripts"):
        _bin_extras(os.path.join(d, b), out, root)
    for lib in ("lib", "Lib"):
        base = os.path.join(d, lib)
        try:
            pys = [os.path.join(base, x, "site-packages") for x in os.listdir(base) if x.startswith("python")] if lib == "lib" else [os.path.join(base, "site-packages")]
        except OSError:
            continue
        for sp in pys:
            try:
                names = sorted(os.listdir(sp))
            except OSError:
                continue
            for n in names[:2000]:
                if n.endswith(".pth") or n in ("sitecustomize.py", "usercustomize.py"):
                    full = os.path.join(sp, n)
                    out[os.path.relpath(full, root)] = full


def _git_config_value(path, section, key):
    """The last `key` of `[section]` in a git config file (enough for core.hooksPath; includes are not followed)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read(MAX_BYTES).splitlines()
    except OSError:
        return None
    cur, val = None, None
    for line in lines:
        t = line.strip()
        if not t or t[0] in "#;":
            continue
        if t.startswith("["):
            cur = t[1:t.find("]")].strip().split()[0].lower() if "]" in t else None
            continue
        if cur == section and "=" in t:
            k, v = t.split("=", 1)
            if k.strip().lower() == key.lower():
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] == '"':
                    v = v[1:-1]
                val = v
    return val


def _git_dirs(root):
    """-> (git dir, common git dir) of the working copy at root: `.git` a directory, or a file `gitdir: <path>` (git worktree; Claude Code's
    .claude/worktrees/*) whose `commondir` names the shared .git. (None, None) when root is not a working copy top."""
    g = os.path.join(root, ".git")
    if os.path.isdir(g):
        return g, g
    if not os.path.isfile(g):
        return None, None
    try:
        with open(g, "r", encoding="utf-8", errors="replace") as f:
            line = f.read(4096).strip().splitlines()[0]
    except (OSError, IndexError):
        return None, None
    if not line.startswith("gitdir:"):
        return None, None
    gd = line[len("gitdir:"):].strip()
    gd = os.path.normpath(gd if os.path.isabs(gd) else os.path.join(root, gd))
    common = gd
    try:
        with open(os.path.join(gd, "commondir"), "r", encoding="utf-8", errors="replace") as f:
            cd = f.read(4096).strip()
        if cd:
            common = os.path.normpath(cd if os.path.isabs(cd) else os.path.join(gd, cd))
    except OSError:
        pass
    return (gd, common) if os.path.isdir(gd) else (None, None)


def git_files(root):
    """0.2.14 (R8-04): every file git itself executes or obeys for this working copy, by ABSOLUTE path: config (+ config.worktree),
    info/attributes, hooks/* of the git dir and of the common git dir, and the hooks of core.hooksPath (husky, .githooks), wherever they are."""
    gd, common = _git_dirs(root)
    if gd is None:
        return {}
    out = {}
    for base in dict.fromkeys((gd, common)):
        for rel in ("config", "config.worktree", "info/attributes"):
            p = os.path.join(base, rel)
            if os.path.isfile(p):
                out[p] = file_digest(p, root)
    hooks_dirs = [os.path.join(common, "hooks")]
    hp = None
    for cfg in (os.path.join(gd, "config.worktree"), os.path.join(common, "config")):
        hp = hp or _git_config_value(cfg, "core", "hooksPath")
    if hp:
        hp = os.path.expanduser(hp)
        hooks_dirs.append(os.path.normpath(hp if os.path.isabs(hp) else os.path.join(root, hp)))
    for hd in hooks_dirs:
        try:
            names = sorted(os.listdir(hd))
        except OSError:
            continue
        for n in names[:64]:
            p = os.path.join(hd, n)
            if not n.endswith(".sample") and os.path.isfile(p):
                out[p] = file_digest(p, root)
    return dict(sorted(out.items()))


_ESC = {"n": "\n", "t": "\t", "b": "\b", '"': '"', "\\": "\\"}
_GSP = " \t\n\r"                                            # 0.2.47: git's isspace (sane_ctype): not \f \v, not Unicode blanks


def _galpha(c):
    return "a" <= c <= "z" or "A" <= c <= "Z"              # ASCII only, as git (str.isalpha takes "é")


def _gkey(c):
    return _galpha(c) or "0" <= c <= "9" or c == "-"


def _gbytes(s):
    """Text read with errors="surrogateescape" -> as git prints it (bytes joined first, then decoded with replace): a continuation or an
    escape may join the halves of a UTF-8 sequence that a decode-first reader would turn into two U+FFFD."""
    try:
        return s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        return s


def read_config_text(path, limit):
    """0.2.47: a git config file as read_git_config wants it: utf-8 with surrogateescape (git's bytes survive), newline="" (a lone \\r is
    git's blank, not a line end; CRLF is handled by the reader). -> (text, longer than limit). OSError / ValueError for the caller."""
    with open(path, "r", encoding="utf-8", errors="surrogateescape", newline="") as f:
        text = f.read(limit + 1)
    return text[:limit], len(text) > limit


def parse_git_config(text: str) -> list:
    """0.2.46: a git config file -> [[key, value], ...] in file order, as `git config --list --no-includes` names them: section and variable
    lower case, a subsection as written (`[a "B"]`) or lower case (`[a.B]`, the old spelling); a variable without `=` is "true". See
    read_git_config (the same reader, with its flag)."""
    return read_git_config(text)[0]


def read_git_config(text: str) -> tuple:
    """-> (entries as parse_git_config, bad). 0.2.47: aligned with git (config.c git_parse_source / get_base_var / get_extended_base_var /
    parse_value; checked against `git config --file F --list --no-includes -z`): a UTF-8 BOM at the start is skipped, CRLF is LF, a lone
    CR is a blank, blanks are " \\t\\r\\n" only, keys and section names ASCII, several headers and a key may share one line (`[a][b] k = v`),
    comments # ; outside quotes, quotes, escapes \\n \\t \\b \\" \\\\, a backslash before the line end continues the value (blanks after it
    at the start of the value are dropped like any leading blank; inside the value they are kept), blanks at both ends dropped.
    The text is best read with read_config_text (surrogateescape, newline=""); a str with U+FFFD or universal newlines works too.

    bad (fail-closed: the caller reports the config as cut and the server asks): every line git calls fatal ("bad config line": a broken
    header or one with junk after the subsection, a blank in a header without a quoted subsection, a line that is not `key [= value]`, a
    key not starting with an ASCII letter, an unknown escape, a newline or the end of the file inside quotes; git then runs nothing), and,
    though git takes them, what this reader is not sure of: a key before any section, an empty section name, a backslash at the very end
    of the file, a NUL (git cuts the value there). After a bad line the reader goes on from the next line: more keys only cost a question."""
    text = text.replace("\r\n", "\n")
    if text.startswith("﻿"):                          # git skips a UTF-8 BOM at the start (and then runs what follows)
        text = text[1:]
    out, sect, i, n = [], None, 0, len(text)
    bad = "\0" in text

    def eol(k):
        while k < n and text[k] != "\n":
            k += 1
        return k

    def header(j):
        """text[j] follows "[" -> (section name, index after "]"), or (None, None) where git refuses the header."""
        name = []
        while j < n:
            c = text[j]
            j += 1
            if c == "]":
                return "".join(name).lower(), j
            if c == "\n":
                return None, None
            if c in _GSP:                                   # git: a blank in a header only before a quoted subsection
                while j < n and text[j] in _GSP and text[j] != "\n":
                    j += 1
                if j >= n or text[j] != '"':
                    return None, None
                j, sub = j + 1, []
                while j < n:
                    c = text[j]
                    j += 1
                    if c == "\n":
                        return None, None
                    if c == '"':
                        if j < n and text[j] == "]":
                            return ("".join(name).lower() + "." + "".join(sub) if name else ""), j + 1     # `[ "x"]`: unsure
                        return None, None                   # junk after the subsection
                    if c == "\\":
                        if j >= n or text[j] == "\n":
                            return None, None
                        c = text[j]
                        j += 1
                    sub.append(c)
                return None, None
            if not (_gkey(c) or c == "."):
                return None, None
            name.append(c)
        return None, None

    def value(j):
        """text[j] follows "=" -> (value, index after it, bad)."""
        buf, ln, quote, space, comment, vbad = [], 0, False, "", False, False
        while True:
            if j >= n:
                return "".join(buf), j, vbad or quote          # the end of the file inside quotes
            c = text[j]
            j += 1
            if c == "\n":
                return "".join(buf), j, vbad or quote          # a newline inside quotes
            if comment:
                continue
            if c in _GSP and not quote:
                if ln:                                         # leading blanks (also after a continuation) are dropped, inner ones kept
                    space += c
                continue
            if not quote and c in "#;":
                comment = True
                continue
            if space:
                buf.append(space)
                ln, space = ln + len(space), ""
            if c == '"':
                quote = not quote
                continue
            if c == "\\":
                if j >= n:
                    return "".join(buf), j, True               # git takes it (a continuation into the end); we are unsure
                nx = text[j]
                j += 1
                if nx == "\n":
                    continue
                if nx not in _ESC:
                    vbad = True                                # git: an unknown escape is fatal
                buf.append(_ESC.get(nx, nx))
                ln += 1
                continue
            buf.append(c)
            ln += 1

    while i < n:
        c = text[i]
        if c in _GSP:
            i += 1
        elif c in "#;":
            i = eol(i)
        elif c == "[":
            name, j = header(i + 1)
            if not name:
                bad, sect = True, None                        # a broken header: nothing below it is attributed to a section
                i = eol(i) if j is None else j
                continue
            sect, i = name, j                                 # the line goes on: another header or a key may follow
        elif not _galpha(c):
            bad, i = True, eol(i)                             # a key not starting with a letter, junk
        else:
            j = i
            while j < n and _gkey(text[j]):
                j += 1
            key = text[i:j].lower()
            while j < n and text[j] in " \t":
                j += 1
            if j < n and text[j] not in "=\n":
                bad, i = True, eol(i)                         # not `key [= value]` (also `key ; comment`, `key_x`)
                continue
            if j >= n or text[j] == "\n":
                val, i = "true", j
            else:
                val, i, vb = value(j + 1)
                bad = bad or vb
            if sect is None:
                bad = True                                    # a key before any section (git lists it bare; no program key looks so)
            else:
                out.append([_gbytes(sect + "." + key), _gbytes(val)])
    return out, bad


def git_config_programs(root) -> tuple:
    """0.2.46: -> ({absolute path of config / config.worktree of the git dir and the common git dir: [[key, value] matching GITCFG_KEYS]}, cut).
    Only those keys leave the machine (values cut at MAX_GITCFG_VALUE); the server decides which of them run a program."""
    gd, common = _git_dirs(root)
    if gd is None:
        return {}, False
    rx = re.compile(GITCFG_KEYS, re.I)
    out, cut = {}, False
    for base in dict.fromkeys((gd, common)):
        for rel in ("config", "config.worktree"):
            p = os.path.join(base, rel)
            if not os.path.isfile(p):
                continue
            try:
                text, longer = read_config_text(p, MAX_BYTES)          # 0.2.47: git's bytes and line ends (was errors="replace", universal newlines)
            except (OSError, ValueError):
                cut = True
                continue
            if longer:
                cut = True
            try:
                entries, bad = read_git_config(text)
            except Exception:      # noqa: BLE001  a reader fault is "not sure", never a silent empty list
                entries, bad = [], True
            if bad:
                cut = True                                  # git would refuse the file; the reader is not sure what it read -> the server asks
            ent = [[k, v[:MAX_GITCFG_VALUE]] for k, v in entries if rx.fullmatch(k)]
            if len(ent) > MAX_GITCFG_ENTRIES:
                ent, cut = ent[:MAX_GITCFG_ENTRIES], True
            out[p] = ent
    return out, cut


def _prio(rel):
    """0.2.14 (R8-03): the order in which the bounded report keeps files: an exact name or directory rule first (conftest.py, package.json,
    .git/hooks/*), then a name pattern (*.mk, *.pth, jest.config.*); shallow before deep. The agent's cheap junk (a000.mk ...) cannot push a
    named file out of the report; it can only make the report incomplete, and the server asks about an incomplete report."""
    parts = rel.replace("\\", "/").split("/")
    name = fold(parts[-1])
    named = name in NAMES or any(len(parts) > 1 and fold(parts[-2]) == d.split("/")[-1] for d, f, fam in DIRS)
    return (0 if named else 1, len(parts), rel)


def scan(root: str | None, max_seconds: float = MAX_SECONDS) -> dict | None:
    """-> {"root": root, "files": {relative path: digest}, "git": {absolute path: digest}, "truncated": bool} for every executed file under
    `root` (bounded walk) and git's own files (R8-04), or None. truncated: the walk did not see everything or the report was cut (the server
    then treats the state as unknown and asks)."""
    if not isinstance(root, str) or not os.path.isabs(root) or not os.path.isdir(root):
        return None
    found = {}                                              # relative path -> absolute path
    budget = {"n": 0, "trunc": False, "end": time.monotonic() + max_seconds}
    extras = {}
    stack = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        if time.monotonic() > budget["end"]:
            budget["trunc"] = True
            break
        try:
            it = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            continue
        for e in it:
            budget["n"] += 1
            if budget["n"] > MAX_ENTRIES:
                budget["trunc"] = True
                stack = []
                break
            try:
                is_dir = e.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                if e.name == ".git":
                    continue
                if os.path.isfile(os.path.join(e.path, "pyvenv.cfg")):
                    _venv_extras(e.path, extras, root)
                    continue
                if e.name == "node_modules":
                    _bin_extras(os.path.join(e.path, ".bin"), extras, root)
                    continue
                if e.name in SKIP_DIRS:
                    continue
                if depth + 1 <= MAX_DEPTH:
                    stack.append((e.path, depth + 1))
                else:
                    budget["trunc"] = True
                continue
            rel = os.path.relpath(e.path, root)
            if families_of_path(rel):
                found[rel] = e.path
    found.update(extras)
    out = {}
    for rel in sorted(found, key=_prio):
        if len(out) >= MAX_FILES:
            budget["trunc"] = True
            break
        out[rel] = file_digest(found[rel], root)
    rep = {"root": root, "files": dict(sorted(out.items())), "truncated": bool(budget["trunc"])}
    g = git_files(root)
    if g:
        rep["git"] = g
    return rep


# ---------------------------------------------------------------- 0.2.16: the list the thin hook fingerprints by
GO_MOD_KEEP = r"^\s*(go|toolchain|replace)\b"


def scan_list() -> dict:
    """What the hook needs to walk a project like scan() above, and nothing more: file shapes (no families: the hook does not learn which
    command executes what), the executable names looked up in a project's bin directories, the bounds, and the digest filter of go.mod.
    `rev` is a hash of the content: the judge refuses a report made with another revision (the hook re-fetches the list)."""
    body = {"v": "dw-scanlist-1",
            "names": sorted(NAMES), "prefixes": sorted({p for p, _ in PREFIXES}), "suffixes": sorted({s for s, _ in SUFFIXES}),
            "dirs": [list(x) for x in sorted({(d, f) for d, f, _ in DIRS})], "bin_names": list(_EXEC_NAMES), "skip_dirs": sorted(SKIP_DIRS),
            "limits": {"entries": MAX_ENTRIES, "files": MAX_FILES, "depth": MAX_DEPTH, "bytes": MAX_BYTES, "seconds": MAX_SECONDS},
            "line_filters": {"go.mod": GO_MOD_KEEP},
            "venv_site": {"suffixes": [".pth"], "names": ["sitecustomize.py", "usercustomize.py"]},
            "prescan_tools": ["Bash"],
            # 0.2.46: the keys of git's own config files (config, config.worktree of the git dir and the common git dir; includes NOT followed)
            # the hook sends as `gitcfg` = {absolute path: [[key, value], ...]} (key as `git config --list` names it, regex matched in full,
            # case-insensitive; at most max_entries per file, values cut at max_value; `gitcfg_cut: true` when it had to cut or could not read)
            "git_config": {"files": ["config", "config.worktree"], "keys": GITCFG_KEYS, "max_entries": MAX_GITCFG_ENTRIES,
                           "max_value": MAX_GITCFG_VALUE}}       # the hook may send the walk with the first request of these tools (one round less)
    body["rev"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]
    return body
