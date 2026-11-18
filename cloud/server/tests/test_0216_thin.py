"""0.2.16: the thin hook (deus_witness.hook: raw facts -> POST /v1/hook/judge) decides EXACTLY as the 0.2.15 hook (the classifier in the
client), on the whole hostile set of reviews 6-8 and on the owner-fatigue session.

The reference is the published 0.2.15 wheel itself (fixtures/thin0216/deus_witness-0.2.15-py3-none-any.whl, loaded as `dw0215`), not a
copy of its code in this repository.
  (1) classification: for every captured event / line (58 events, 130 lines, 9542 fuzz inputs) the parts the server builds from the thin
      hook's facts (tool, args with `_witness`, summary) equal the parts of dw0215 map_event on the same machine. Same args -> the core
      gives the same verdict (it sees nothing else).
  (2) decisions end to end: two fresh servers, the same mandate; the explicit hostile set + the fatigue session (240 lines, 40 hostile,
      5 exec attacks) through dw0215's hook (POST /v1/actions) and through the thin hook (/v1/hook/judge) -> the same Claude Code decision
      and the same text (receipt ids aside), every receipt verified against the witness key by the client.
Plus the protocol: signed fingerprint list, fact rounds, refusals, the old path still served, what the thin hook refuses to do."""
import base64
import gzip
import json
import os
import re
import shutil
import sys
import zipfile

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))
sys.path.insert(0, CLOUD)
from fastapi.testclient import TestClient  # noqa: E402

from app import _paths  # noqa: E402,F401
from app.config import Config  # noqa: E402
from app.main import create_app  # noqa: E402
from app.hookjudge import judge as hj  # noqa: E402
from app.hookjudge import execfiles  # noqa: E402
from app.hookjudge.bashparse import LW_LIST, TX_NAMES, TX_TAG_ORDER, classify  # noqa: E402
from deus_witness import client as dwc  # noqa: E402
from deus_witness.hook import fingerprint  # noqa: E402
from deus_witness.hook import main as thin  # noqa: E402
from tests.helpers import ORIGIN, RP, Owner  # noqa: E402
from tests_flow.helpers import set_settings  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "thin0216")
CORPUS = json.loads(gzip.open(os.path.join(FIX, "hostile_r678.json.gz"), "rt").read())


@pytest.fixture(scope="module")
def ref(tmp_path_factory):
    """The 0.2.15 wheel, unpacked as package `dw0215` (its imports are relative)."""
    d = tmp_path_factory.mktemp("ref")
    with zipfile.ZipFile(os.path.join(FIX, "deus_witness-0.2.15-py3-none-any.whl")) as z:
        z.extractall(d)
    shutil.move(str(d / "deus_witness"), str(d / "dw0215"))
    sys.path.insert(0, str(d))
    import importlib
    mods = {n: importlib.import_module("dw0215." + n) for n in ("client", "hook.main", "hook.mapping", "hook.execfiles")}
    assert mods["client"].__name__ == "dw0215.client" and "0.2.15" in open(str(d / "dw0215" / "__init__.py")).read()
    yield mods
    sys.path.remove(str(d))


def _project(base):
    """A project with something of everything the classifier and the fingerprint walk look at."""
    p = os.path.realpath(str(base / "work" / "shop"))
    for d in ("src/shop", "tests", "node_modules/.bin", ".git/hooks", ".github/workflows", "build", "docs", ".venv/bin", ".venv/lib/python3.12/site-packages"):
        os.makedirs(os.path.join(p, d), exist_ok=True)
    files = {"conftest.py": "a=1\n", "tests/conftest.py": "b=1\n", "package.json": "{}\n", "Makefile": "all:\n", "pyproject.toml": "[x]\n",
             "go.mod": "module x\ngo 1.22\nrequire y v1\n", "src/shop/cart.py": "x=1\n", ".env": "T=1\n", ".git/config": "[core]\n",
             ".git/hooks/pre-commit": "#!/bin/sh\n", ".git/hooks/pre-push.sample": "x", ".github/workflows/ci.yml": "on: push\n",
             "node_modules/.bin/jest": "", "node_modules/.bin/tsc": "", ".venv/pyvenv.cfg": "x", ".venv/bin/pytest": "",
             ".venv/lib/python3.12/site-packages/evil.pth": "import os\n", "README.md": "r\n"}
    for k, v in files.items():
        with open(os.path.join(p, k), "w") as f:
            f.write(v)
    os.symlink("/etc", os.path.join(p, "etc-link"))
    os.symlink(os.path.join(p, "src"), os.path.join(p, "src-link"))
    return p


class Local:
    """The thin hook's transport replaced by a direct call of the server's classifier (no ledger): what /v1/hook/judge classifies."""

    def __init__(self, cached=True):
        self.rounds, self.cached = 0, cached

    def scan_list(self, rev=None, cached_only=False):
        return None if cached_only and not self.cached else hj.scan_list()

    def judge(self, ev, env):
        facts = thin.Facts(ev, env)
        facts.prescan(self, ev.get("tool_name"))            # as the hook does: with a cached list, the walk goes with the first request
        for _ in range(thin.MAX_ROUNDS):
            self.rounds += 1
            r = hj.classify_event(facts.body(ev))
            if r[0] != "need":
                return r
            facts.answer(dict(r[1], scan_rev=hj.scan_list()["rev"]), self)
        raise AssertionError("too many rounds")


def _ref_parts(ref, ev, env):
    try:
        return ("parts", [(m.tool, m.args, m.summary) for m in ref["hook.mapping"].map_event(ev, env=env)])
    except ref["hook.mapping"].Refuse as e:
        return ("refuse", str(e))
    except Exception as e:      # noqa: BLE001  the 0.2.15 hook: HOOK_ERROR
        return ("refuse", "HOOK_ERROR:" + type(e).__name__)


def _thin_parts(loc, ev, env):
    try:
        r = loc.judge(ev, env)
    except thin.Fail as e:
        return ("refuse", "CLIENT:" + e.code)
    if r[0] == "refuse":
        return ("refuse", r[1] if r[1] != "HOOK_ERROR" else "HOOK_ERROR:" + r[2])
    return ("parts", [(m.tool, _strip_sizes(m.args), m.summary) for m in r[1]])


def _strip_sizes(args):
    """0.2.22: the thin hook adds the optional `exec.sizes`. It is not in the 0.2.15 reference, so it is removed before the comparison
    - but first checked on its own: same keys as `files`, non-negative integers (bool is not an integer here)."""
    ex = args.get("_witness", {}).get("exec") if isinstance(args, dict) and isinstance(args.get("_witness"), dict) else None
    if isinstance(ex, dict) and "gitcfg" in ex:
        # 0.2.46: the thin hook (0.2.33) adds `exec.gitcfg` with its own reader; it must equal the server's reference reader on this project
        want, cut = execfiles.git_config_programs(ex["root"])
        assert ex["gitcfg"] == want and ex.get("gitcfg_cut", False) is cut, (ex["gitcfg"], want)
        ex = {k: v for k, v in ex.items() if k not in ("gitcfg", "gitcfg_cut")}
        args = dict(args, _witness=dict(args["_witness"], exec=ex))
    if not isinstance(ex, dict) or "sizes" not in ex:
        return args
    sz = ex["sizes"]
    assert isinstance(sz, dict) and set(sz) == set(ex.get("files", {})), "sizes keys differ from files"
    assert all(type(v) is int and v >= 0 for v in sz.values()), sz
    return dict(args, _witness=dict(args["_witness"], exec={k: v for k, v in ex.items() if k != "sizes"}))


# 0.2.53: mkdir / touch / cp / mv / ln / chmod / rm / rmdir / git add|commit|checkout|switch|restore|mv|rm are in the default mandate, each form
# with every path checked (bashparse._local_write). That is a deliberate difference from 0.2.15: their identifiers carry the tags of the check
# ("touch [outside]") and their plain form's writes are the exact ones (`cp a .` writes ./a, not .). The tags are taken off before the
# comparison; a line that still differs must be one of these commands (counted, bounded), and end to end the thin hook may only be STRICTER there.
LW_TAGS = {"outside", "unsure", "protected", "recursive", "dir", "force"}


TX_TAGS = set(TX_TAG_ORDER)          # 0.2.54: find / sed / awk / jq get variant tags (only ever stricter than 0.2.15)


def _lw_head(h):
    base, _, rest = h.partition(" [")
    if (base not in LW_LIST and base not in TX_NAMES) or not rest:
        return h
    drop = TX_TAGS if base in TX_NAMES else LW_TAGS
    keep = [x for x in rest[:-1].split(", ") if x not in drop]
    return base + (" [%s]" % ", ".join(keep) if keep else "")


# rt2810 (cloud/OTCHET-RT2810-PRAVKI.md): obfuscated interpreter code, code injected through the environment and /dev/tcp sockets are
# dangerous now (or a host of the line): only ever stricter than 0.2.15, which asked them as ordinary commands.
# r0335: the closed read-only forms of programs that read the machine's state (bashparse.STATE_READERS, docker ps): own identifiers
R0335_CLOSED = ("docker ps", "top -l", "vm_stat", "sysctl read", "scutil --get", "sw_vers", "netstat", "ruff check", "sqlite3 read",
                "printf", "hostname", "spctl --status", "unzip -l", "zip", "sips", "--version")      # r0341: closed forms (test_1711_r0341)


def _r0335_closed(ev):
    from app.hookjudge.mapping import DEFAULT_SAFE_COMMANDS
    if not isinstance(ev, dict) or ev.get("tool_name") != "Bash":
        return False
    from app.hookjudge.bashparse import classify
    hs = classify(ev["tool_input"]["command"], ev.get("cwd") or "/", "/nonexistent-home").heads
    return bool(hs) and any(h in R0335_CLOSED for h in hs) and all(h in DEFAULT_SAFE_COMMANDS for h in hs)


RT2810 = ("opaque:obfuscated code", "opaque:code injected through", "opaque:network: /dev/tcp", "opaque:network: /inet", "opaque:network: listening")


# 0.2.43b (cloud/OTCHET-0.2.43b-PESOCHNICA.md): a file written and run in the same line has its text judged ("opaque:runs F written in this
# line", "... written in this line"), LD_PRELOAD / DYLD_* are "code injected through" (above): again only stricter than 0.2.15.
NEW_0243B = ("opaque:runs ",)


NEW_0289_DANGER = ("opaque:command name starting with '--'",)   # 0.2.89: a program named `--version` would look like the version entry
# 0.2.90 (the standing mandate, OTCHET-0258.md): the four gates are dangers of their own (persist / exit / net-out / loopback-write /
# write-outside), deletions and shadow-copied writes outside the project are named (`deletes`, `outside_writes`, `shadow`, the pseudo-command
# "(write outside the project) ..."), `rm -rf <inside>` / `find <inside> -delete` are deletes, interpreter code and heredocs are scanned for
# their file consequences, `$VAR` / aliases / base64 literals are read. Lines touching those forms may differ from 0.2.15 (bounded, n90).
NEW_0290_DANGER = ("persist:", "exit:", "net-out:", "loopback-write:", "write-outside:", "rm-rf:", "secrets:", "witness:")   # 0.2.91: witness
# 0.2.91 (client 0.2.59): the hook's lock K1 reports what it found (fact `harness`); the witness asks about the line (agent-config:(hook) ..):
# a question where 0.2.15 had one from the hook itself (refused with no button) or the same question with one danger more
NEW_0291_HARNESS = "agent-config:(hook) "


def _has_0291(b) -> bool:
    return b[0] == "parts" and any(isinstance(x, dict) and isinstance(x.get("_witness"), dict) and
                                   any(str(d).startswith(NEW_0291_HARNESS) for d in x["_witness"].get("danger") or [])
                                   for _, x, _s in b[1])
NEW_0290_KEYS = ("deletes", "outside_writes", "shadow")
NEW_0290_LINE = re.compile(r"<<-?\s*['\"]?\w|base64|\$[A-Za-z_{]|\balias\b|\brm\b|rmdir|unlink|python[23]?\b|\bnode\b|\bperl\b|\bruby\b|\bfind\b|\bcurl\b|\bwget\b|"
                           r"\bgit (push|pull|fetch|clone|ls-remote)|\bpip3?\b|\bnpm\b|\bnpx\b|\buv\b|\bcargo\b|\bgo\b|\bgh\b|\bdocker\b|\bopen\b|\bsudo\b|\bosascript\b|crontab|launchctl|security|"
                           r"\bfor\b|\bexport\b|CLAUDE_|\.zshrc|\.bashrc|LaunchAgents|\.claude|\.mcp\.json|\bssh\b|\bscp\b|\brsync\b|\bnc\b|\bdig\b|nslookup|\bping\b")


def _norm_0290(b):
    """-> b without the 0.2.90 keys / dangers / pseudo-commands (what 0.2.15 could not say), and whether anything was taken off."""
    if b[0] != "parts":
        return b, False
    out, touched = [], False
    for tool, args, summary in b[1]:
        w = args.get("_witness") if isinstance(args, dict) else None
        if isinstance(w, dict):
            w2 = {k: v for k, v in w.items() if k not in NEW_0290_KEYS}
            if len(w2) != len(w):
                touched = True
                if isinstance(w.get("outside_writes"), list):
                    w2["writes"] = sorted(set(list(w2.get("writes") or []) + list(w["outside_writes"])))
            if isinstance(w2.get("commands"), list) and any(str(h).startswith("(write outside the project) ") for h in w2["commands"]):
                touched = True
                w2["commands"] = [h for h in w2["commands"] if not str(h).startswith("(write outside the project) ")]
            if isinstance(w2.get("danger"), list) and any(str(d).startswith(NEW_0290_DANGER) for d in w2["danger"]):
                touched = True
            args = dict(args, _witness=w2)
        out.append((tool, args, summary))
    return ("parts", out), touched


def _line_0290(ev) -> bool:
    inp = ev.get("tool_input") if isinstance(ev, dict) else None
    c = inp.get("command") if isinstance(inp, dict) else None
    return isinstance(c, str) and NEW_0290_LINE.search(c) is not None


def _is_new_danger(d) -> bool:
    return d.startswith(RT2810 + NEW_0243B + NEW_0289_DANGER) or "written in this line" in d


def _drop_0243b(b):
    if b[0] != "parts":
        return b
    out = []
    for t, x, s in b[1]:
        if isinstance(x, dict) and isinstance(x.get("_witness"), dict) and x["_witness"].get("danger"):
            w = dict(x["_witness"], danger=[d for d in x["_witness"]["danger"] if not _is_new_danger(d)])
            x = dict(x, _witness=w)
        out.append((t, x, s))
    return (b[0], out)


def _rt2810_stricter(a, b) -> bool:
    if a[0] != "parts" or b[0] != "parts":
        return False
    if any(t == "Bash.danger" for t, _, _ in a[1]) and _drop_0243b(b) == a:
        return True                                   # 0.2.43b: dangerous before too, one more reason now
    da = [d for _, x, _ in a[1] if isinstance(x, dict) for d in (x.get("_witness") or {}).get("danger") or []]
    db = [d for t, x, _ in b[1] if t == "Bash.danger" and isinstance(x, dict) for d in (x.get("_witness") or {}).get("danger") or []]
    new = [d for d in db if d not in da]
    return bool(new) and all(_is_new_danger(d) for d in new) and not any(t == "Bash.danger" for t, _, _ in a[1])


def _heredoc_prefix_0411(ev, a, b) -> bool:
    """04.11 (Hypothesis I3, monotone): a heredoc read as unsure (opaque) now also judges what bash runs BEFORE it (bashparse._Unsure.at):
    b is a's line, still opaque, with more found (danger / writes / hosts / commands), never less, and every tool of a is still asked."""
    inp = ev.get("tool_input") if isinstance(ev, dict) else None
    c = inp.get("command") if isinstance(inp, dict) else None
    if not (isinstance(c, str) and "<<" in c) or a[0] != "parts" or b[0] != "parts":
        return False
    from app.hookjudge.bashparse import _normalize
    try:
        at = getattr(_normalize(c)[3], "at", None)
    except Exception:          # noqa: BLE001
        at = None
    if not (isinstance(at, int) and at > 0):
        return False           # only a line whose unsure heredoc has a prefix bash runs (the 04.11 change)
    wa = [x.get("_witness") or {} for _, x, _ in a[1] if isinstance(x, dict)]
    wb = [x.get("_witness") or {} for _, x, _ in b[1] if isinstance(x, dict)]
    if not wa or not wb or not any(d.startswith("opaque:") for w in wb for d in w.get("danger") or []):
        return False
    if not {t for t, _, _ in a[1]} <= {t for t, _, _ in b[1]}:
        return False
    for k in ("danger", "writes", "net", "commands"):
        if not {json.dumps(v, sort_keys=True) for w in wa for v in w.get(k) or []} <= {json.dumps(v, sort_keys=True) for w in wb for v in w.get(k) or []}:
            return False
    return True


RT0269_HEADS = ("git", "patch", "tar", "bsdtar", "gtar", "unzip", "perl", "ruby")


def _rt0269_writes(a, b) -> bool:
    """RT-0269 p.4 (deliberate): a line of 0.2.15 that wrote nothing now writes (git stash / merge / pull / checkout / reset --hard, patch,
    tar x, unzip, perl -pi): b is a plus a Bash.write part and the written paths in _witness. Nothing else may differ."""
    if a[0] != "parts" or b[0] != "parts":
        return False
    out = []
    for tool, args, summary in b[1]:
        w = args.get("_witness") if isinstance(args, dict) else None
        if not isinstance(w, dict) or not w.get("writes"):
            out.append((tool, args, summary))
            continue
        if not all(str(h).split(" ", 1)[0] in RT0269_HEADS for h in w.get("commands") or []):
            return False
        if tool == "Bash.write":
            continue
        out.append((tool, dict(args, _witness=dict(w, writes=[])), summary))
    return ("parts", out) == a


# 0.2.89 (friction 03.11, OTCHET-0257.md): read-only diagnostics on the recommended list get their own identifiers or tags ("git stash list",
# "git tag list", "git config get", "--version", "ps [env]"), a content search outside the project gets a second head
# "<name> [outside]" (an ordinary question instead of DANGER), `rm -rf build` (a regenerated folder of the project) is a plain delete. Such a
# line is counted with the 0.2.53 ones (bounded); end to end the thin hook may allow it only when every head is on the recommended list.
NEW_0289 = {"git config get", "git remote", "git stash list", "git stash show", "git tag list", "ps", "lsof", "whoami", "id", "npm ls", "npm list",
            "pip list", "pip3 list", "pip freeze", "pip3 freeze", "pip show", "pip3 show", "uv pip"}


def _is_0289(h) -> bool:
    return h == "--version" or h.partition(" [")[0] in NEW_0289 or h.endswith(" [outside]")


def _lw_norm(r):
    """-> (r with the 0.2.53 tags taken off, touches a 0.2.53 command?)."""
    if r[0] != "parts":
        return r, False
    out, touched = [], False
    for tool, args, summary in r[1]:
        w = args.get("_witness") if isinstance(args, dict) else None
        if isinstance(w, dict) and isinstance(w.get("commands"), list):
            touched = touched or any(h.partition(" [")[0] in LW_LIST or h.partition(" [")[0] in TX_NAMES or _is_0289(h) for h in w["commands"])
            w = dict(w, commands=[_lw_head(h) for h in w["commands"]])
            if isinstance(w.get("outside"), list):
                w["outside"] = [_lw_head(h) for h in w["outside"]]
            args = dict(args, _witness=w)
            if summary.startswith("Bash: ") and not summary.startswith("Bash: writes"):
                summary = "Bash: " + ", ".join(_lw_head(h) for h in w["commands"][:4]) + (" ..." if len(w["commands"]) > 4 else "") \
                    if w["commands"] and summary != "Bash: (no command)" and not w.get("danger") else summary
        out.append((tool, args, summary))
    return ("parts", out), touched


def _events(proj):
    out = [{"tool_name": e["tool_name"], "tool_input": e["tool_input"], "cwd": proj} for e in CORPUS["events"]]
    out += [{"tool_name": "Bash", "tool_input": {"command": c}, "cwd": proj} for c in CORPUS["commands"]]
    return out


def test_corpus_is_the_captured_hostile_set():
    assert (len(CORPUS["events"]), len(CORPUS["commands"])) == (58, 130) and len(CORPUS["fuzz"]) >= 9000
    joined = json.dumps(CORPUS)
    for needle in (">|", "<<", ".git/", "heredoc" if False else "EOF"):           # R6-01, R7-01, R8: the attacks are in it
        assert needle in joined, needle


@pytest.mark.parametrize("which", ["explicit", "fuzz", "session", "cwd-elsewhere"])
def test_same_parts_as_0215_on_the_hostile_set(ref, tmp_path, monkeypatch, which):
    proj = _project(tmp_path)
    env = {"CLAUDE_PROJECT_DIR": proj, "HOME": "/nonexistent-home"}
    if which == "explicit":
        evs = _events(proj)
        evs += [{"tool_name": t, "tool_input": i, "cwd": proj} for t, i in (
            ("Write", {"file_path": ".git/config", "content": "x"}), ("Edit", {"file_path": "etc-link/passwd", "old_string": "a", "new_string": "b"}),
            ("Read", {"file_path": ".env"}), ("Read", {"file_path": "~/.ssh/id_ed25519"}), ("Grep", {"pattern": ".", "glob": "*.env*"}),
            ("Grep", {"pattern": ".", "path": "src-link"}), ("Glob", {"pattern": "**"}), ("LS", {"path": "../.."}), ("NotebookRead", {"notebook_path": ".env"}),
            ("WebFetch", {"url": "https://Evil.Example:8443/x"}), ("WebSearch", {"query": "q"}), ("mcp__gh__create_issue", {"title": "t"}),
            ("NotebookEdit", {"notebook_path": "n.ipynb", "new_source": "x"}), ("MultiEdit", {"file_path": "src-link/shop/cart.py", "edits": []}),
            ("Bash", {"command": ["rm"]}), ("Write", {"content": "x"}), ("Bash", {"command": "ls", "_witness": {}}))]
        evs += [{"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "relative/dir"}, "not a dict", {"tool_name": 5}]
    elif which == "fuzz":
        evs = [{"tool_name": "Bash", "tool_input": {"command": c}, "cwd": proj} for c in CORPUS["fuzz"]]
    elif which == "session":
        sys.path.insert(0, os.path.join(CLOUD, "e2e", "fatigue"))
        import dev_session as ds
        evs = [{"tool_name": "Bash", "tool_input": {"command": line}, "cwd": proj} for line, _ in ds.SESSION() + ds.HOSTILE()]
        for (t, i), line in ds.EXEC_ATTACKS():
            evs += [{"tool_name": t, "tool_input": i, "cwd": proj}, {"tool_name": "Bash", "tool_input": {"command": line}, "cwd": proj}]
    else:                                   # the session's cwd outside the project, and a project that is the home directory
        evs = [{"tool_name": "Bash", "tool_input": {"command": c}, "cwd": str(tmp_path)} for c in CORPUS["commands"][:60]]
        env = {"CLAUDE_PROJECT_DIR": proj + "/src", "HOME": proj}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("DEUS_WITNESS_EXEC_SCAN", raising=False)
    loc, diff, n, lw, rt, r69, n90 = Local(cached=which in ("explicit", "fuzz")), [], 0, 0, 0, 0, 0     # both ways to the walk: sent at once (cached list) / asked by the witness
    n91 = n411 = 0
    for ev in evs:
        a = _ref_parts(ref, ev, env)
        b = _thin_parts(loc, ev if isinstance(ev, dict) else ev, env) if isinstance(ev, dict) else ("refuse", "EVENT_MALFORMED")
        if b == ("refuse", "CLIENT:EVENT_MALFORMED") or b == ("refuse", "CLIENT:RESERVED_KEY"):
            b = ("refuse", b[1].split(":", 1)[1])     # the hook refuses the envelope itself, before sending: the same code
        n += 1
        b, touched = _lw_norm(b)
        h91 = _has_0291(b)
        b, t90 = _norm_0290(b)
        if a != b:
            if h91:
                n91 += 1                              # 0.2.91: the K1 finding asked by the witness (see NEW_0291_HARNESS)
                continue
            if _heredoc_prefix_0411(ev, a, b):
                n411 += 1                             # 04.11 (I3): the part before an unsure heredoc is judged too (stricter, never softer)
                continue
            if t90 or _line_0290(ev):
                n90 += 1                              # 0.2.90: a gate, a named deletion / outside write, a read form (see NEW_0290_*)
                continue
            if _rt2810_stricter(a, b):
                rt += 1                               # rt2810: asked as dangerous now (see RT2810)
                continue
            if _rt0269_writes(a, b):
                r69 += 1                              # RT-0269 p.4: git stash / merge / pull / reset --hard ... now write the work tree
                continue
            if touched:
                lw += 1                               # 0.2.53: a command of the local-write list (exact writes): see LW_TAGS
                continue
            if _r0335_closed(ev):
                lw += 1                               # r0335: the closed read-only form of a state reader has its own identifier
                continue
            diff.append((ev, a, b))
    assert not diff, "%d of %d differ; first: %r" % (len(diff), n, diff[0])
    assert lw <= max(30, n // 10), (lw, n)
    assert rt <= 10, rt
    assert r69 <= 20, r69
    assert n90 <= max(60, n // 3), (n90, n)
    assert n91 <= max(30, n // 4), (n91, n)
    assert n411 <= max(30, n // 4), (n411, n)
    assert n == len(evs)
    if which == "fuzz":
        assert loc.rounds <= 3 * n                     # facts rounds stay bounded


def test_fingerprint_walk_equals_the_reference_walk(ref, tmp_path):
    proj = _project(tmp_path)
    for i in range(250):                                       # past MAX_FILES: the bounded report keeps the same files
        open(os.path.join(proj, "docs", "a%03d.mk" % i), "w").close()
    with open(os.path.join(proj, ".git", "config"), "w") as f:
        f.write('[core]\n\thooksPath = "hooks-elsewhere"\n')
    os.makedirs(os.path.join(proj, "hooks-elsewhere"))
    open(os.path.join(proj, "hooks-elsewhere", "pre-push"), "w").close()
    spec = fingerprint.Spec(hj.scan_list())
    a, b = ref["hook.execfiles"].scan(proj, max_seconds=30), None
    spec.max_seconds = 30
    b = fingerprint.scan(proj, spec)
    assert a == b and a["truncated"] and len(a["files"]) == execfiles.MAX_FILES and a["git"]
    assert execfiles.scan(proj, max_seconds=30) == a                        # the server's reference walk (LocalFS) too
    assert fingerprint.scan(str(tmp_path / "missing"), spec) is None and fingerprint.scan("relative", spec) is None


def test_scan_list_carries_shapes_not_meaning():
    lst = hj.scan_list()
    s = json.dumps(lst)
    for fam in ('"py"', '"js"', '"ci"', '"editor"', '"maven"', "famil", "EXECUTORS", "executes"):
        assert fam not in s, fam                           # the family names and the command -> family rule are not sent
    assert all(isinstance(lst[k], list) and all(isinstance(x, (str, list)) for x in lst[k]) for k in ("names", "prefixes", "suffixes", "dirs", "bin_names"))
    spec = fingerprint.Spec(lst)
    from app import execguard
    for p in ["conftest.py", "a/b/PACKAGE.JSON", "x.pth", ".pth", "Dockerfile.dev", ".git/hooks/pre-commit", ".git/hooks/x.sample", "init.d/a.gradle",
              ".yarn/plugins/a/b.js", "src/main.py", "README.md", "lib/x.mk", "node_modules/x/y.js", ".venv/bin/pytest", "gradle/wrapper/x.jar"]:
        assert spec.listed(p) == bool(execguard.families_of_path(p)), p


# ---------------------------------------------------------------- (2) decisions end to end
def _server(tmp, name):
    d = tmp / name
    d.mkdir()
    kf = d / "witness_key"
    kf.write_text("a1" * 32)
    cfg = Config(data_dir=str(d / "data"), witness_key_file=str(kf), key_pepper="test-pepper", rp_id=RP, origin=ORIGIN, iss="https://witness.test",
                 anchor="off", web_dir=str(d / "web"), rate_per_min=1000000, quota_per_day=1000000)
    app = create_app(cfg)
    c = TestClient(app, base_url=ORIGIN)
    o = Owner(c).register("Dev")
    set_settings(app.state.ctx, o.account["id"], max_pending=100000, max_defers_hour=1000000)
    return c, o


RID = re.compile(r"r_[A-Z2-7]{26}")


class Via:
    """An httpx transport into the in-process server (the SDK's own httpx.Client, the server's TestClient behind it)."""

    def __init__(self, tc):
        self.tc = tc

    def handle_request(self, request):
        import httpx
        h = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length", "transfer-encoding")}
        r = self.tc.request(request.method, str(request.url), headers=h, content=request.read())
        return httpx.Response(r.status_code, headers={"content-type": r.headers.get("content-type", "application/json")}, content=r.content)

    def close(self):
        pass


def _drop_art(t):
    """0.2.89: the reason text without the regenerated folders a plain `rm -rf` deleted (they join the [changed: ...] list)."""
    t = re.sub(r"(, )?[^\s\[,]+/(?:node_modules/\.cache|build)(?=[\],])", "", t)
    return t.replace("[changed: , ", "[changed: ")


NOTIFY_0257 = re.compile(r" Notification: [^.]*\.")       # 0.2.57: who was told (the 0.2.15 hook did not say)


def _norm(out):
    h = (out or {}).get("hookSpecificOutput") or {}
    return h.get("permissionDecision"), NOTIFY_0257.sub("", RID.sub("r_X", h.get("permissionDecisionReason", "")))


def test_same_decisions_as_0215_end_to_end(ref, tmp_path, monkeypatch):
    sys.path.insert(0, os.path.join(CLOUD, "e2e", "fatigue"))
    import dev_session as ds
    from app.hookjudge.mapping import DEFAULT_SAFE_COMMANDS, default_form
    proj = _project(tmp_path)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", proj)
    monkeypatch.delenv("DEUS_WITNESS_EXEC_SCAN", raising=False)
    lines = [{"tool_name": "Bash", "tool_input": {"command": line}, "cwd": proj} for line, _ in ds.SESSION() + ds.HOSTILE()]
    for (t, i), line in ds.EXEC_ATTACKS():
        lines += [{"tool_name": t, "tool_input": dict(i, **({"file_path": os.path.join(proj, i["file_path"])} if "file_path" in i else {})), "cwd": proj},
                  {"tool_name": "Bash", "tool_input": {"command": line}, "cwd": proj}]
    lines += _events(proj)
    sides = {}
    for side in ("fat", "thin"):
        c, o = _server(tmp_path, side)
        sides[side] = {"c": c, "o": o, "agents": []}
    out = {"fat": [], "thin": []}
    stats = {"allow": 0, "ask": 0, "deny": 0, None: 0}
    for k in range(0, len(lines), 200):                       # a new agent every 200 lines: the per-agent daily quota (2000) is not the subject
        chunk = lines[k:k + 200]
        for side in ("fat", "thin"):
            s = sides[side]
            ag, hdr = s["o"].new_agent("claude-code", "cc%d" % k)
            m, r = s["o"].mandate(ag["id"], default_form(proj))
            assert r.status_code == 200, r.text
            key = hdr["Authorization"][7:]
            pins = tmp_path / ("pins-" + side)
            if side == "fat":
                W, judge, S = ref["client"].Witness, ref["hook.main"].judge, ref["hook.main"].Settings
            else:
                W, judge, S = dwc.Witness, thin.judge, thin.Settings
            w = W(ORIGIN, key, pin_path=str(pins / "witness.json"), transport=Via(s["c"]))
            # 0.2.22: the thin hook's default is deny, the 0.2.15 reference's is ask; the decisions are compared with ask set on both sides
            st = S({"DEUS_WITNESS_KEY": key, "CLAUDE_PROJECT_DIR": proj, "HOME": os.environ.get("HOME", "/"), "DEUS_WITNESS_HOOK_ON_DEFER": "ask"} if side == "thin"
                   else {"DEUS_WITNESS_KEY": key, "DEUS_WITNESS_HOOK_ON_DEFER": "ask"})
            for ev in chunk:
                out[side].append(_norm(judge(ev, st, witness=w)))
    rank = {"allow": 0, "ask": 1, "deny": 2}
    diff, lw, rt, n90, n91 = [], 0, 0, 0, 0
    for i, (a, b) in enumerate(zip(out["fat"], out["thin"])):
        if a == b:
            continue
        if b[0] == "ask" and "agent-config" in b[1] and rank.get(b[0], 3) >= min(rank.get(a[0], 3), 1):
            n91 += 1                                  # 0.2.91: the K1 finding asked by the witness: a question, never an allow
            continue
        if a[0] == b[0] == "deny" and any(k in a[1] and k in b[1] for k in ("FORBIDDEN_",)):
            continue                                  # 06.11 (Constitution v1): the same refusal; the thin side also carries its reason text
        m42 = re.search(r"\[changed: ([^\]]*)\]", a[1]) if a[0] == "ask" and "ESCALATE_EXEC_CHANGED" in a[1] else None
        if b[0] == "allow" and m42 and all(re.search(r"/\.git/config(\.worktree)?$", x.strip()) for x in m42.group(1).split(",")):
            lw += 1                                   # r0342 (17.11): a change of git's config without a program key is no execution: allowed now
            continue
        inp = lines[i]["tool_input"]
        cl = classify(inp["command"], proj, os.environ.get("HOME", "/"), project=proj) if isinstance(inp.get("command"), str) else None
        heads = cl.heads if cl else []
        if cl and (any(str(d).startswith(NEW_0290_DANGER) for d in cl.danger) or cl.deletes or _line_0290(lines[i]) or cl.opaque
                   or any(not w.startswith(proj) for w in cl.writes)) and (
                rank.get(b[0], 3) >= rank.get(a[0], 3) or b[0] != "allow" or cl.deletes or _line_0290(lines[i])):
            n90 += 1                                  # 0.2.90: the gates ask (stricter); a delete inside the project / a read form runs
            continue
        if cl and any(_is_new_danger(d) for d in cl.danger) and rank.get(b[0], 3) >= rank.get(a[0], 3) and b[0] != "allow":
            rt += 1                                   # rt2810: asked (as dangerous) or refused, never allowed where 0.2.15 asked
            continue
        if any(h.partition(" [")[0] in LW_LIST for h in heads) and (a[0] == b[0] == "allow" or rank.get(b[0], 3) > rank.get(a[0], 3)):
            lw += 1                                   # 0.2.53: listed now, every path checked: the thin hook allows it or is stricter
            continue
        if a[0] == b[0] and "ESCALATE_EXEC_CHANGED" in b[1] and (_drop_art(b[1]) == a[1] or "ESCALATE_EXEC_CHANGED" not in a[1] and
                                                                   re.search(r"\[changed: [^\]]*/(node_modules/\.cache|build)[\],]", b[1])):
            lw += 1                                   # 0.2.89: `rm -rf node_modules/.cache` ran (a plain delete now): what npm runs changed
            continue                                  # -> asked once as EXEC_CHANGED (stricter reason, the same question)
        if any(_is_0289(h) or h.partition(" [")[0] == "rm" for h in heads) and (rank.get(b[0], 3) >= rank.get(a[0], 3) or (
                b[0] == "allow" and all(h in DEFAULT_SAFE_COMMANDS for h in heads))):
            lw += 1                                   # 0.2.89: the read-only diagnostics / rm -rf build: listed now, or stricter
            continue
        if any(h.partition(" [")[0] in TX_NAMES for h in heads) and (a[0] == b[0] or rank.get(b[0], 3) > rank.get(a[0], 3)
                                                                     or (b[0] == "allow" and all(h in DEFAULT_SAFE_COMMANDS for h in heads))):
            lw += 1                                   # 0.2.54: find / sed / awk / jq: listed, variant tags in the question text, or stricter
            continue
        if b[0] == "allow" and any(h in R0335_CLOSED for h in heads) and all(h in DEFAULT_SAFE_COMMANDS for h in heads):
            lw += 1                                   # r0335: a state reader's closed read-only form is listed now (ruff check src)
            continue
        diff.append((inp, a, b))
    assert not diff, "%d of %d differ; first: %r" % (len(diff), len(lines), diff[:3])
    assert lw <= 40, lw
    assert rt <= 10, rt
    assert n90 <= len(lines) // 3, (n90, len(lines))
    assert n91 <= 20, n91
    for d, _ in out["thin"]:
        stats[d] = stats.get(d, 0) + 1
    # the set is not trivial: every kind of answer occurs, and nothing hostile of the fatigue set runs unasked
    assert stats["allow"] > 20 and stats["ask"] > 100 and stats["deny"] > 5, stats
    hostile = out["thin"][len(ds.SESSION()):len(ds.SESSION()) + len(ds.HOSTILE())]
    assert all(d in ("ask", "deny") for d, _ in hostile)


# ---------------------------------------------------------------- the protocol
@pytest.fixture()
def agent(client, owner, tmp_path):
    from app.hookjudge.mapping import default_form
    set_settings(client.app.state.ctx, owner.account["id"], max_pending=1000, max_defers_hour=10000)
    ag, hdr = owner.new_agent("claude-code", "cc")
    owner.mandate(ag["id"], default_form(str(tmp_path)))
    return hdr


def _body(cmd, cwd, **facts):
    f = {"home": "/home/u", "proc_cwd": "/", "env": {"CLAUDE_PROJECT_DIR": cwd}, "fs": {}, "exec": "off"}
    f.update(facts)
    return {"v": 1, "event": {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": cwd}, "facts": f, "client": {"name": "t", "version": "0"}}


def test_judge_asks_for_facts_then_decides(client, agent, tmp_path):
    p = str(tmp_path.resolve())
    r = client.post("/v1/hook/judge", json=_body("tac a > b", p), headers=agent).json()
    assert set(r["need"]) == {"realpath"} and p + "/b" in r["need"]["realpath"] and "parts" not in r
    rp = {x: os.path.realpath(x) for x in r["need"]["realpath"]}
    r = client.post("/v1/hook/judge", json=_body("tac a > b", p, fs={"realpath": rp}), headers=agent).json()
    assert [x["tool"] for x in r["parts"]] == ["Bash.write", "Bash"] and r["n_parts"] == 2
    assert r["parts"][0]["args"]["command"] == "tac a > b" and r["parts"][0]["args"]["_witness"]["writes"] == [p + "/b"]
    res = r["parts"][0]["result"]
    assert res["verdict"] == "allow" and res["action"]["args_sha256"] == dwc.args_sha256("Bash.write", r["parts"][0]["args"])
    pub = client.get("/v1/witness").json()["pub_hex"]
    dwc.verify_aar(dwc.b64u_dec(res["aar_b64"]), pub, res["action"])            # an ordinary receipt: the pack and its checks are unchanged
    assert r["parts"][1]["result"]["reason"] == "ESCALATE_COMMAND" and "not on the owner's list" in r["parts"][1]["why"]
    assert r["texts"]["ESCALATE_COMMAND"][0] == "ask"
    # a client cannot hide a path: an unresolvable one is the error os.path.realpath raised (0.2.15: HOOK_ERROR), never a guess
    rp[p + "/b"] = None
    r = client.post("/v1/hook/judge", json=_body("tac a > b", p, fs={"realpath": rp}), headers=agent).json()
    assert r["refuse"] == "HOOK_ERROR" and r["detail"] == ""         # 0.2.17 (R9-04): the exception name stays in the server log


def test_judge_refusals_and_bad_requests(client, agent, tmp_path):
    p = str(tmp_path.resolve())
    b = _body("ls", p)
    b["event"]["tool_input"]["_witness"] = {"danger": []}
    r = client.post("/v1/hook/judge", json=b, headers=agent).json()
    assert r["refuse"] == "RESERVED_KEY" and r["texts"]["RESERVED_KEY"][0] == "deny"
    assert client.post("/v1/hook/judge", json=dict(_body("ls", p), v=2), headers=agent).status_code == 400
    assert client.post("/v1/hook/judge", json=_body("ls", p, home="relative"), headers=agent).status_code == 400
    assert client.post("/v1/hook/judge", json=_body("ls", p, fs={"isdir": {"/x": "yes"}}), headers=agent).status_code == 400
    assert client.post("/v1/hook/judge", json=_body("ls", p), headers={"Authorization": "Bearer dwk_nope"}).status_code == 401
    many = {"/p%d" % i: "/p%d" % i for i in range(hj.MAX_FACTS + 1)}
    r = client.post("/v1/hook/judge", json=_body("ls", p, fs={"realpath": many}), headers=agent)
    assert r.status_code == 413


def test_report_of_another_list_revision_is_asked_again(client, agent, tmp_path):
    p = str(tmp_path.resolve())
    rp = {p: p, "/home/u": "/home/u"}
    old = {"root": p, "files": {}, "truncated": False, "rev": "0" * 32}
    r = client.post("/v1/hook/judge", json=_body("ls", p, fs={"realpath": rp}, exec=old), headers=agent).json()
    assert r["need"] == {"scan": p} and r["scan_rev"] == hj.scan_list()["rev"]
    new = dict(old, rev=hj.scan_list()["rev"])
    r = client.post("/v1/hook/judge", json=_body("ls", p, fs={"realpath": rp}, exec=new), headers=agent).json()
    assert r["parts"][0]["args"]["_witness"]["exec"] == {"root": p, "files": {}, "truncated": False}


def test_scanlist_is_signed_by_the_witness_key(client, agent, tmp_path):
    j = client.get("/v1/hook/scanlist", headers=agent).json()
    pub = client.get("/v1/witness").json()["pub_hex"]
    import cbor2
    lst = cbor2.loads(dwc.open_signed(dwc.b64u_dec(j["cose_b64"]), pub, dwc.TYP_SCANLIST))
    assert lst == json.loads(json.dumps(hj.scan_list())) and j["rev"] == lst["rev"]
    with pytest.raises(dwc.AARError):
        dwc.open_signed(dwc.b64u_dec(j["cose_b64"]), pub, dwc.TYP_AAR)               # not usable as anything else
    other = "11" * 32
    with pytest.raises(dwc.AARError):
        dwc.open_signed(dwc.b64u_dec(j["cose_b64"]), other, dwc.TYP_SCANLIST)
    assert client.get("/v1/hook/scanlist").status_code == 401


def test_thin_hook_with_the_real_server(client, agent, tmp_path, monkeypatch):
    """the hook as Claude Code runs it, through HTTP: fact rounds, the signed list (fetched once, then cached), receipts verified and consumed"""
    p = str(tmp_path.resolve())
    (tmp_path / "conftest.py").write_text("x=1\n")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", p)
    key = agent["Authorization"][7:]
    pins = tmp_path / "pins"
    w = dwc.Witness(ORIGIN, key, pin_path=str(pins / "witness.json"), transport=Via(client))
    s = thin.Settings({"DEUS_WITNESS_KEY": key, "CLAUDE_PROJECT_DIR": p, "DEUS_WITNESS_HOOK_ON_DEFER": "ask"})
    s_default = thin.Settings({"DEUS_WITNESS_KEY": key, "CLAUDE_PROJECT_DIR": p})                 # 0.2.22: the default for a held call is deny
    d0, why0 = _norm(thin.judge({"tool_name": "Bash", "tool_input": {"command": "make build > out.txt"}, "cwd": p}, s_default, witness=w))
    assert d0 == "deny" and "ESCALATE_COMMAND" in why0 and "not on the owner's list" in why0
    d, why = _norm(thin.judge({"tool_name": "Bash", "tool_input": {"command": "make build > out.txt"}, "cwd": p}, s, witness=w))
    assert d == "ask" and "ESCALATE_COMMAND" in why and "not on the owner's list" in why    # the write part is allowed, `make` is not listed
    d, why = _norm(thin.judge({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": p}, s, witness=w))
    assert d == "allow" and "receipt r_X" in why
    assert (pins / "scanlist.json").exists()
    rows = client.app.state.ctx.db.q("SELECT tool, status, action_json FROM actions ORDER BY created_at")
    assert rows[-1]["status"] == "consumed" and json.loads(rows[-1]["action_json"])["args_sha256"]
    # the old (<= 0.2.15) path is still served: POST /v1/actions with the client-built args
    r = client.post("/v1/actions", json={"tool": "Bash", "args": {"command": "ls", "_witness": {"cwd": p, "danger": [], "writes": [], "net": [], "commands": ["ls"]}}},
                    headers=agent).json()
    assert r["verdict"] == "allow"


def test_thin_hook_refuses_what_it_must_not_do(tmp_path, monkeypatch):
    """a witness answer that is not about THIS call, a scan of another directory, endless fact rounds: deny, never allow"""
    from tests.hookfake import FakeW
    p = str(tmp_path.resolve())
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", p)
    s = thin.Settings({"DEUS_WITNESS_KEY": "k", "CLAUDE_PROJECT_DIR": p})
    ev = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": p}

    class Swap(FakeW):
        def hook_judge(self, body):
            r = super().hook_judge(body)
            if "parts" in r:
                r["parts"][0]["args"] = dict(r["parts"][0]["args"], command="rm -rf /")
            return r
    assert _norm(thin.judge(ev, s, witness=Swap("allow", "allowed")))[1].startswith("Blocked by Deus Witness: REQUEST_MISMATCH")

    class Elsewhere(FakeW):
        def hook_judge(self, body):
            return {"v": 1, "need": {"scan": "/"}, "scan_rev": "x"}
    d, why = _norm(thin.judge(ev, s, witness=Elsewhere("allow", "allowed")))
    assert d == "deny" and "another directory" in why

    class Endless(FakeW):
        def hook_judge(self, body):
            self.rounds = getattr(self, "rounds", 0) + 1
            return {"v": 1, "need": {"exists": [p + "/x%d" % self.rounds]}}       # 0.2.17: paths of this call (R9-05)
    w = Endless("allow", "allowed")
    d, why = _norm(thin.judge(ev, s, witness=w))
    assert d == "deny" and "kept asking" in why and w.rounds == thin.MAX_ROUNDS

    class Garbage(FakeW):
        def hook_judge(self, body):
            return {"v": 1, "parts": []}
    assert _norm(thin.judge(ev, s, witness=Garbage("allow", "allowed")))[0] == "deny"
