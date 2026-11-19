"""r0347 (closed exam 2, EX2-088): a write that points a package manager of the project at ANOTHER server -- the supply chain swapped.

`.npmrc` with `registry=https://cdn-telemetry.example.net/npm/` is a few bytes of an ordinary project file, and its run is later and not
the agent's: the person's next `npm install` takes every package (and its install scripts) from that host, outside Witness. Before r0347
it was silent under every mandate. The law: a Write / Edit / MultiEdit of a package-source setting of the project (npm / yarn / pnpm /
bun registry, pip / uv / poetry / pdm index, cargo source / registry index, the Gradle / Maven wrapper's distribution) whose NEW text names
a server that is not the package manager's own public one is asked once at the write (actions.registry_write). Any other write of these
files stays silent (their run is judged when it runs: ESCALATE_EXEC_CHANGED after the agent's write, execguard). Facts only, no decision
(mapping makes the write's danger part; bashparse the shell form's mark).

  foreign(path, text) -> [(key, url)] of the settings in `text` (the text the write puts in) that name a server not on KNOWN, or []
                         when `path` is no package-source file / nothing foreign is named. An expansion (`${NPM_REGISTRY}`) names no
                         server: not judged here (its value is the person's environment).
"""
from __future__ import annotations

import re

# file name (folded) -> the family of keys read in it
_NPM = {".npmrc", ".yarnrc", ".yarnrc.yml", ".yarnrc.yaml", "bunfig.toml"}
_PIP = {"pip.conf", "pip.ini", "uv.toml", "pipfile", "poetry.toml"}
_TOML_PY = {"pyproject.toml"}
_CARGO = {"config", "config.toml"}                     # only under .cargo/
_WRAP = {"gradle-wrapper.properties", "maven-wrapper.properties"}
_REQ = re.compile(r"^(requirements|constraints)[\w.-]*\.(txt|in)$")

# the key that names where packages come from (as written: `registry=`, `@scope:registry=`, `npmRegistryServer:`, `index-url =` ...)
_KEY_NPM = re.compile(r"^(?:@[\w.-]+:)?registry$|^npmregistryserver$|^url$", re.I)
_KEY_PIP = re.compile(r"^(?:extra[-_])?index[-_]url$|^find[-_]links$|^url$|^index$", re.I)
_KEY_CARGO = re.compile(r"^(?:registry|index|proxy|git)$", re.I)
_KEY_WRAP = re.compile(r"^(?:distributionurl|wrapperurl)$", re.I)
_REQ_OPT = re.compile(r"(?:^|\s)(?:-i|--index-url|--extra-index-url|-f|--find-links)(?:\s*=\s*|\s+)(\S+)", re.I)
# a [section] of pyproject.toml whose `url` is a package index (uv, poetry, pdm, hatch's pip)
_PY_SECTION = re.compile(r"^\[\[?\s*tool\.(?:uv(?:\.index|\.pip)?|poetry\.source|pdm\.source|hatch\.envs\.[\w.-]+|pixi)\s*\]?\]$", re.I)

KNOWN = ("https://registry.npmjs.org", "https://registry.npmjs.com", "https://registry.yarnpkg.com", "https://npm.pkg.github.com",
         "https://pypi.org/simple", "https://pypi.org/pypi", "https://pypi.python.org/simple", "https://files.pythonhosted.org",
         "https://download.pytorch.org/whl",
         "https://index.crates.io", "sparse+https://index.crates.io", "https://github.com/rust-lang/crates.io-index",
         "https://services.gradle.org/distributions", "https://repo.maven.apache.org/maven2", "https://repo1.maven.org/maven2")
_URL = re.compile(r"(?:sparse\+)?[a-z][a-z0-9+.-]*://[^\s\"'<>,\]]+", re.I)


def _fold(n):
    return n.strip().rstrip(". ").casefold()


def kind(path):
    """-> "npm" | "pip" | "pyproject" | "cargo" | "wrap" | "req" | None for the file at `path` (by its name, as execguard folds it)."""
    if not isinstance(path, str) or not path:
        return None
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    if not parts:
        return None
    n = _fold(parts[-1])
    if n in _NPM:
        return "npm"
    if n in _PIP:
        return "pip"
    if n in _TOML_PY:
        return "pyproject"
    if n in _CARGO and len(parts) >= 2 and _fold(parts[-2]) == ".cargo":
        return "cargo"
    if n in _WRAP:
        return "wrap"
    if _REQ.match(n):
        return "req"
    return None


def known(url):
    u = url.strip().replace("\\:", ":").rstrip("/")
    lo = u.casefold()
    for k in KNOWN:
        if lo == k or lo.startswith(k + "/"):
            return True
    return False


def _kv(line):
    """`key = value`, `key: value`, `key=value` -> (key, value) or None (quotes taken off the key)."""
    m = re.match(r"\s*([\"']?)([^\s=\"']+)\1\s*=\s*(.*)$", line) or re.match(r"\s*([\"']?)([@\w.-]+)\1\s*:\s+(.*)$", line)
    if not m:
        return None
    k = m.group(2)
    if k.startswith("//"):
        return None                                      # `//registry.npmjs.org/:_authToken=...`: a credential for a host, no source
    return k, m.group(3)


def foreign(path, text):
    k = kind(path)
    if k is None or not isinstance(text, str) or "://" not in text:
        return []
    out = []
    section = ""
    for raw in text.replace("\r", "\n").split("\n"):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line
            continue
        if k == "req":
            for m in _REQ_OPT.finditer(line):
                u = _URL.search(m.group(1))
                if u and not known(u.group(0)):
                    out.append(("index-url", u.group(0)))
            continue
        kv = _kv(line)
        urls = _URL.findall(line.replace("\\:", ":"))
        if not urls:
            continue
        key = kv[0] if kv else ""
        last = key.rsplit(".", 1)[-1]
        if k == "npm":
            hit = bool(_KEY_NPM.search(last)) and last.lower() != "url" or "scopes" in section.lower()
        elif k == "pip":
            hit = bool(_KEY_PIP.search(last))
        elif k == "pyproject":
            hit = (bool(_KEY_PIP.search(last)) and (last.lower() not in ("url", "index") or _PY_SECTION.match(section) is not None))
        elif k == "cargo":
            hit = bool(_KEY_CARGO.search(last)) or section.lower().startswith(("[source", "[registries", "[registry", "[http"))
        else:
            hit = bool(_KEY_WRAP.search(last))
        if hit:
            out += [(key or "url", u) for u in urls if not known(u)]
    return list(dict.fromkeys(out))[:8]


DETAIL = "write to %s (the project's packages would then come from %s, not the package manager's own server)"


def line_foreign(cmd):
    """A SHELL line that writes a package-source file (`cat > requirements.txt <<EOF -i https://..`, `echo registry=.. > .yarnrc`):
    the witness does not know which bytes land in the file, so every server the line names that is not on KNOWN counts. -> [url]"""
    if not isinstance(cmd, str) or "://" not in cmd:
        return []
    return list(dict.fromkeys(u for u in _URL.findall(cmd.replace("\\:", ":")) if not known(u)))[:8]


def written_text(tool, inp):
    """-> the text a Write / Edit / MultiEdit puts into its file (content, new_string, every edit's new_string), or None."""
    if not isinstance(inp, dict):
        return None
    if tool == "Write":
        v = inp.get("content")
        return v if isinstance(v, str) else None
    if tool == "Edit":
        v = inp.get("new_string")
        return v if isinstance(v, str) else None
    if tool == "MultiEdit" and isinstance(inp.get("edits"), list):
        return "\n".join(e["new_string"] for e in inp["edits"] if isinstance(e, dict) and isinstance(e.get("new_string"), str)) or None
    return None
