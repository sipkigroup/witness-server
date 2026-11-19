"""0.2.10 (PROPOSAL-07): "allow this command in this project" -- an owner-signed addition to the agent's mandate.

When the owner approves on the phone a shell command the mandate does not list (defer ESCALATE_COMMAND, never ESCALATE_COMMAND_DANGER), they
may instead sign an ALLOWANCE: these exact command identifiers (as the hook names them, variant suffix and all: `pytest`, not `pytest [env X]`),
for this project (the realpath the hook reports as `_witness.project`), until `exp` (30 days by default, at most 90). The ledger records it
(entry ALLOWANCE, wa-sig typ application/aar-allowance+cbor over the allowance map); the core then decides a matching command allow
OK_ALLOWANCE (svidetel_v4/decide.py), and the AAR names the ALLOWANCE entry (`mandate.allowed_by`). One click ends it (entry ALLOWANCE_END).

What the gateway adds (the core cannot know it):
  - eligibility (`why_not`, 0.2.11: an explicit list of what MAY be allowed, `_listed`; everything else is asked): a dangerous command, a variant
    (`[...]`), a program called by path, `sudo`, shells, interpreters, wrappers that
    build a command line, tools that run code from their arguments (find -exec, sed `e`, awk system()), installers and downloaders, and what
    publishes or changes where code goes (git push / remote / config) are NEVER allowed for a project: they are asked each time;
  - the hook's `_witness.outside`: a command that ran outside the project, or named a path outside it, is not covered;
  - a team account (org policy): allowances are not offered (a k-of-n mandate is not widened by one signature) and not applied.
Honest limit: allowing `pytest` / `npm test` / `make` for a project means trusting the project's code -- and the agent can edit that code.
"""
import base64
import hashlib
import json
import os
import re
import time

import cbor2

from app import _paths  # noqa: F401
import wa_profile as wa
import wq_profile as wq
from svidetel_v4.schema import ALLOWANCE_MAX_S, validate_allowance
from svidetel_v4.state import allowance_payload, mandate_hash
from app import org
from app import wire
from app.context import Err
from app.registry_wa import looks_like_envelope

TYP = getattr(wa, "TYP_ALLOWANCE", "application/aar-allowance+cbor")
DEFAULT_DAYS = 1                # 0.2.51: the approval page preselects 1 day (was 30) and offers "Allow for 24 h" first
# 0.2.96 (plan 13.11 p.2, permission laundering, arXiv 2610.22987): "from now on" is narrow and does not pile up.
#  - the term is a ceiling: at most MAX_DAYS (the core still accepts 90; this witness signs no longer than 30 days). A rule also ends
#    earlier: revoked (one tap), the mandate ended, or the project's git branch changed (reset_stale);
#  - it never reaches past the project it was signed for (the core matches `project` byte-exact) nor past the branch it was given on;
#  - at most MAX_PER_PROJECT live rules per agent and project. Why 20: a project's own toolbox that may be allowed at all is short
#    (test runner, linter, type checker, build, git add / commit: 5-10 identifiers, up to 8 per rule), plus a few narrow amendments
#    (a host, a folder, gh reads); the friction stand with "from now on" on every eligible question (TR_VPRED) stays well under it per
#    project. More than 20 live rules in ONE project is the shape of laundering (many narrow rules that add up to a wide one), so the
#    21st is refused: revoke one first. A fixed number is a Goodhart risk on its own; the guard is that each rule is still exact.
DAYS = (1, 7, 30)
MAX_DAYS = 30
MAX_PER_PROJECT = 20
NBF_SKEW_S = 600
ID_RE = re.compile(r"al_[A-Z2-7]{26}")

# the screen text (web/js/approve.js shows it as is; a test keeps the two equal)
TRUST_TEXT = ("Allowing a command for this project means trusting the project's code: pytest, npm test, make, cargo test and go test run "
              "the project's tests, conftest.py, plugins, scripts and build files, npm install and pip install -e . install the dependencies "
              "the project declares, and the agent can change those files. In practice the agent can then run code it wrote in this project "
              "without asking you when Witness could read what it wrote and that text does not reach the network, your keys or files outside this "
              "project. Dangerous commands the agent types (recursive delete, force-push, reading secrets, a download piped into a shell) are still "
              "asked every time, and so is anything outside this project. Inside the project's code Witness looks for them too, but it cannot "
              "promise to find every one: allow only a project whose code you trust.")

# r0327 (law "Signed = shown"): the text of trust shown when a rule is signed is part of the signature. Every version ever offered is kept
# here, by a short name; a rule names the version it was signed with (allowances.trust_v) and the list shows THAT text. The evidence
# checker (packtools/screencheck.ALLOW_TEXT_SHA256) keeps the SHA-256 of each version (a test keeps the two equal).
#   tt-1: the text up to r0325 (it promised that dangerous commands are asked every time, also inside project code: not true)
#   tt-2: the honest text of r0326 (TRUST_TEXT above)       am-1: the text of an amendment of a kind of request (app/amend.TEXT)
TRUST_TEXT_V1 = ("Allowing a command for this project means trusting the project's code: pytest, npm test, make, cargo test and go test run "
                 "the project's tests, conftest.py, plugins, scripts and build files, npm install and pip install -e . install the dependencies "
                 "the project declares, and the agent can change those files. In practice the agent can then run code it wrote in this project "
                 "without asking you when Witness could read what it wrote and that text does not reach the network, your keys or files outside this "
                 "project. Dangerous commands (recursive delete, force-push, reading secrets, a download piped into a shell) are still "
                 "asked every time, and so is anything outside this project.")
ALLOW_VIEW_V = "dw-allow-view-1"


def texts():
    """-> {version: text} of every trust text a "from now on" rule may have been signed with."""
    from app import amend
    return {"tt-1": TRUST_TEXT_V1, "tt-2": TRUST_TEXT, "am-1": amend.TEXT}


def text_version(text):
    """-> the version name of this exact text, or None."""
    for k, t in texts().items():
        if t == text:
            return k
    return None


def allow_view(page, text_v, text):
    """r0327: the object a rule's `view` hashes (SHA-256 over RFC 8785): the approval page's signing view (dw-view-1) AND the text of trust
    shown next to the button, whole. No new member in the signed allowance map (the core schema and every older checker keep working):
    the existing `view` names both. web/js/allowance.js allowView builds the same object."""
    return {"v": ALLOW_VIEW_V, "page": page, "text_v": text_v, "text": text}


DEFENSE_WHY = ("this switches off a protection of your computer: Witness never allows it from now on")     # r0305
LATER_WHY = "another program runs this file later by itself (direnv, a git hook, CI, the editor): it is asked every time, approve it once"
AUTOSTART_WHY = ("this changes a file that starts commands by itself, in a folder Witness cannot tell: it is asked every time, approve it "
                 "once")

AUTOSTART_COPY_WHY = ("this copies files Witness cannot see into a folder whose files start commands by themselves: it is asked every "
                      "time, approve it once")                           # r0304 (bashparse._mass_copy)

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "busybox", "csh", "tcsh", "pwsh", "powershell", "cmd"}
INTERPRETERS = {"python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php", "deno", "bun", "lua", "tclsh", "Rscript", "julia",
                "osascript", "java", "jshell", "groovy", "irb", "ipython", "jupyter",
                # 0.2.11 (R6-03): TypeScript / JavaScript runners are interpreters too: `tsx -e '<code>'` is `node -e`
                "tsx", "ts-node", "ts-node-dev", "ts-node-esm", "tsm", "esno", "esr", "swc-node", "babel-node", "vite-node", "esbuild-register",
                "nodemon", "jiti", "sucrase-node", "coffee", "luajit", "pypy", "pypy3", "elixir", "iex", "erl", "escript", "clojure", "clj", "bb",
                "kotlin", "kotlinc", "scala", "dotnet", "csi", "pwsh", "gjs", "qjs", "rhino", "jjs", "racket", "guile", "sbcl", "ghci", "runghc",
                "stack", "cabal", "swift", "go-script", "gorun", "zx", "cmd.exe", "wscript", "cscript", "mshta", "tsc-node"}
PRINTS_ENV = {"printenv", "set", "export", "declare", "typeset", "compgen", "jq"}      # jq: `jq -n env`
CODE_FROM_ARGS = {"env", "eval", "exec", "source", ".", "xargs", "parallel", "watch", "find", "sed", "awk", "gawk", "mawk", "nawk",
                  "command", "builtin", "nohup", "time", "timeout", "nice", "script", "expect", "tmux", "screen", "at", "crontab",
                  "vim", "vi", "nvim", "emacs", "less", "more", "man", "git-shell"}
FETCH_OR_REMOTE = {"curl", "wget", "fetch", "http", "https", "iwr", "aria2c", "xh", "httpie", "ssh", "scp", "sftp", "rsync", "nc", "ncat",
                   "netcat", "telnet", "ftp", "mosh", "socat", "gh", "aws", "gcloud", "az", "gsutil", "rclone", "doctl", "heroku", "flyctl",
                   "vercel", "netlify", "wrangler", "firebase", "terraform", "pulumi", "kubectl", "helm", "docker", "podman"}
PRIVILEGE = {"sudo", "doas", "su", "pkexec", "chroot", "systemctl", "launchctl", "service", "brew", "apt", "apt-get", "dnf", "yum", "pacman",
             "snap", "port", "chown", "dd", "mount", "umount", "kill", "killall", "pkill", "shutdown", "reboot"}
DOWNLOAD_AND_RUN = {"npx", "pnpx", "bunx", "uvx", "pipx", "pip", "pip3", "gem", "poetry", "conda", "mamba"}
SUB_NEVER = {("git", "push"), ("git", "remote"), ("git", "config"), ("git", "clone"), ("git", "submodule"), ("git", "credential"),
             ("git", "daemon"), ("git", "send-email"), ("git", "archive"), ("git", "bundle"), ("git", "filter-branch"), ("git", "worktree"),
             ("npm", "add"), ("npm", "exec"), ("npm", "x"), ("npm", "publish"),
             ("npm", "login"), ("npm", "adduser"), ("npm", "token"), ("npm", "config"), ("npm", "set"), ("npm", "link"), ("npm", "update"),
             ("npm", "uninstall"), ("npm", "init"), ("npm", "create"), ("yarn", "add"), ("yarn", "dlx"), ("yarn", "global"),
             ("yarn", "publish"), ("yarn", "config"), ("yarn", "link"), ("yarn", "up"), ("yarn", "create"),
             ("pnpm", "add"), ("pnpm", "dlx"), ("pnpm", "publish"), ("pnpm", "exec"), ("pnpm", "link"),
             ("pnpm", "update"), ("pnpm", "create"), ("uv", "pip"), ("uv", "tool"), ("uv", "add"), ("uv", "run"), ("uv", "sync"),
             ("cargo", "install"), ("cargo", "publish"), ("cargo", "login"), ("cargo", "owner"), ("cargo", "yank"), ("cargo", "run"),
             ("go", "install"), ("go", "get"), ("go", "run")}
TOOL_NEVER = set()
# 0.2.10: installing what the PROJECT declares (lockfile, its requirements, `-e .`) is trusting the project; naming a package or another index is a
# variant of the hook ("npm install [packages]", "pip install [--index-url]") and never allowed for a project
PROJECT_INSTALL = {"npm install", "npm i", "npm ci", "pnpm install", "pnpm i", "yarn", "yarn install", "pip install", "pip3 install"}
PY_MODULE_NEVER = {"pip", "ensurepip", "pipx", "twine", "uv", "poetry", "conda", "http", "smtpd", "webbrowser", "venv", "virtualenv", "build_ext"}


# 0.2.11 (R6-03): what MAY be allowed for a project is this explicit list -- test runners, linters, type checkers and build tools that run the
# PROJECT's files (their options that load code or configuration from elsewhere are variants of the hook, `<id> [<option>]`), git work on the
# project's history, and commands that only read or change files (their paths are judged by the mandate and by `_witness.outside`).
# Anything not listed -- an interpreter or runner we do not know (tsx, ts-node, bun, deno, `npx <anything>`, `python -c`, `ruby -e` ...)
# -- is asked each time. Before 0.2.11 it was the other way round (a list of what is never allowed) and every new runner slipped through.
PROJECT_TOOLS = {"pytest", "py.test", "tox", "nox", "ruff", "black", "isort", "flake8", "pylint", "mypy", "pyright", "jest", "vitest", "mocha",
                 "tsc", "eslint", "prettier", "make", "yarn"}
PROJECT_FILES = {"ls", "pwd", "cd", "cat", "head", "tail", "wc", "echo", "grep", "rg", "which", "file", "stat", "du", "df", "date", "uname",
                 "tree", "diff", "cmp", "comm", "sort", "uniq", "cut", "tr", "nl", "tac", "column", "basename", "dirname", "realpath",
                 "sha256sum", "sha1sum", "md5sum", "shasum", "true", "false", "test", "[", "sleep",
                 "mkdir", "touch", "rm", "rmdir", "mv", "cp", "ln", "chmod"}
PROJECT_SUB = {"git": {"status", "log", "diff", "show", "branch", "blame", "ls-files", "add", "commit", "checkout", "switch", "restore",
                       "stash", "merge", "fetch", "pull", "tag", "mv", "rm", "reset", "cherry-pick", "revert", "grep", "shortlog", "describe",
                       "rev-parse", "reflog"},
               "npm": {"test", "t", "run", "run-script", "start", "build", "ci", "install", "i"},
               "pnpm": {"test", "t", "run", "start", "build", "lint", "install", "i"},
               "yarn": {"test", "run", "start", "build", "lint", "install"},
               "cargo": {"test", "build", "check", "clippy", "fmt", "doc", "bench"},
               "go": {"test", "build", "vet", "fmt"},
               "make": None}                          # `make <target>`: any target of the project's Makefile
NPX_TOOLS = {"jest", "vitest", "mocha", "tsc", "eslint", "prettier"}       # `npx <tool>` = the project's node_modules/.bin/<tool> (else [fetch])
PY_MODULES = {"pytest", "mypy", "build", "unittest", "ruff", "black", "isort", "flake8", "pylint", "tox", "nox", "pyright"}


def _listed(cid):
    words = cid.split(" ")
    if cid in PROJECT_INSTALL or (len(words) == 1 and (cid in PROJECT_TOOLS or cid in PROJECT_FILES)):
        return True
    if len(words) == 2 and words[0] in PROJECT_SUB:
        return PROJECT_SUB[words[0]] is None or words[1] in PROJECT_SUB[words[0]]
    if len(words) == 2 and words[0] == "npx":
        return words[1] in NPX_TOOLS
    if len(words) == 3 and re.fullmatch(r"python[0-9.]*", words[0]) and words[1] == "-m":
        return words[2] in PY_MODULES
    return False


GIT_REWRITES_TREE = frozenset({"pull", "merge", "cherry-pick", "revert", "rebase", "am"})   # stash: only your own tree's changes come back


def why_not(cid):
    """-> None when the command identifier may be allowed for a project, else the reason shown to the owner.
    0.2.11 (R6-03): None only for an identifier of the explicit list above (_listed); the reasons below name why the others are asked."""
    if not isinstance(cid, str) or not cid or len(cid) > 200 or "*" in cid:
        return "not a command identifier"
    if "[" in cid:
        return "a variant of the command (%s): it runs other code or configuration than the plain command; it is asked each time" % cid[cid.index("["):]
    words = cid.split(" ")
    if words[0] == "sudo":
        return "a command with elevated rights is asked each time"
    if "/" in words[0]:
        return "a program called by path (%s) is asked each time: allow commands by name" % words[0]
    if words[0] == "git" and len(words) > 1 and words[1] in GIT_REWRITES_TREE:   # 0.2.55 (RT V3-г): a merge brings files you have not seen
        return ("git %s brings in commits you have not seen and can rewrite tracked files, .claude/settings.json and .mcp.json included: "
                "it is asked each time" % words[1])
    if _listed(cid):
        return None
    name, sub = words[0], (words[1] if len(words) > 1 else "")
    if re.fullmatch(r"python[0-9.]*", name) and sub == "-m" and len(words) == 3:
        mod = words[2]
        if mod.split(".")[0] in PY_MODULE_NEVER:
            return "python -m %s installs or publishes packages, or serves files to the network: it is asked each time" % mod
        return ("python -m %s is not a test runner or build tool this version knows (%s): it could run any code; "
                "it is asked each time" % (mod, ", ".join(sorted(PY_MODULES))))
    if name in SHELLS or name in INTERPRETERS or re.fullmatch(r"(python|pypy|ruby|perl|php|node)[0-9.]*", name):
        return "a shell or an interpreter (%s) runs any code it is given, not the project's: it is asked each time" % name
    if name in PRINTS_ENV:
        return "%s prints environment variables, where secrets live: it is asked each time" % name
    if name in CODE_FROM_ARGS:
        return "%s runs commands or code taken from its own arguments: it is asked each time" % name
    if name in FETCH_OR_REMOTE:
        return "%s talks to other machines or services: it is asked each time" % name
    if name in PRIVILEGE:
        return "%s changes the system, not the project: it is asked each time" % name
    if name in DOWNLOAD_AND_RUN or name in TOOL_NEVER or (name, sub) in SUB_NEVER:
        return ("%s installs, downloads or publishes code, or changes where the project's code goes: it is asked each time" % cid)
    return ("%s is not a test runner, build tool or file command this version knows: allowing it for the project could let it run any "
            "code it is given; it is asked each time" % cid)


def _now():
    return int(time.time())


def new_id():
    return "al_" + base64.b32encode(os.urandom(16)).decode().rstrip("=")[:26]


def project_meta(args):
    """The hook's `_witness.project` (absolute realpath) and `_witness.outside` -> {project, outside} or None (an old hook: no allowance)."""
    w = args.get("_witness") if isinstance(args, dict) else None
    if not isinstance(w, dict):
        return None
    p, out, heads = w.get("project"), w.get("outside", []), w.get("commands", [])
    if not (isinstance(p, str) and p.startswith("/") and 1 < len(p) <= 1024 and "\x00" not in p):
        return None
    if not (isinstance(out, list) and all(isinstance(x, str) for x in out)) or not isinstance(heads, list):
        return None
    r = {"project": p, "outside": out[:64], "heads": [h for h in heads if isinstance(h, str)][:64]}
    br = w.get("branch")
    if isinstance(br, str) and 0 < len(br) <= 256:
        r["branch"] = br                                 # 0.2.96: the project's git branch (client 0.2.65); absent = no git / older hook
    return r


def live_count(ctx, acc_id, agent_id, project, now=None):
    """0.2.96: live "from now on" rules of this agent in this project (not ended, not expired)."""
    now = _now() if now is None else now
    return ctx.db.one("SELECT COUNT(*) AS n FROM allowances WHERE account_id=? AND agent_id=? AND project=? AND ended_at IS NULL AND exp>=?",
                      (acc_id, agent_id, project, now))["n"]


def reset_stale(ctx, acc_id, agent_id, L, meta, now):
    """0.2.96: the call reports the project's git branch (or none) and a live rule of this agent and project was given on ANOTHER branch
    -> that rule ends (ledger ALLOWANCE_END, cause "revoked"; allowances.end_reason = "branch"), before any cover step reads the ledger.
    A rule is never carried to another branch: the files a `pytest` or a `make` runs are the branch's files. Called under hub.lock.
    -> the ids ended. Another project's rules are not touched: they never apply here (the core matches the project byte-exact)."""
    if meta is None:
        return []
    cur = meta.get("branch")
    out = []
    for g in ctx.db.q("SELECT id, branch FROM allowances WHERE account_id=? AND agent_id=? AND project=? AND ended_at IS NULL AND exp>=?",
                      (acc_id, agent_id, meta["project"], now)):
        if (g["branch"] or None) == (cur or None):
            continue
        try:
            res = L.end_allowance(g["id"], "revoked")
        except Exception:  # noqa: BLE001  an unknown id in the ledger (never expected): mark it ended here, it covers nothing
            res = {"result": "reject", "reason": "ALLOWANCE_UNKNOWN"}
        ctx.db.x("UPDATE allowances SET ended_at=?, end_seq=?, end_reason='branch' WHERE id=? AND ended_at IS NULL",
                 (_now(), res.get("seq"), g["id"]))
        out.append(g["id"])
    return out


def renew_unsigned(ctx, acc_id, agent_id, L, meta, a, now):
    """r1611 (law "Signed = shown"): a live rule signed BEFORE r0327 (allowances.trust_v is NULL: the text of trust was not part of its
    signature) does not pass silently at its first use: when it WOULD cover this action it ends (ledger ALLOWANCE_END "revoked";
    end_reason = "text-unsigned-renewed") before cover() reads the ledger, so the call is asked as any unlisted command and the human's
    "from now on" signs the current text as a NEW rule. No migration: the mark is trust_v IS NULL. Called under hub.lock. -> ids ended."""
    if meta is None or not isinstance(a, dict) or a.get("class") != "command":
        return []
    rc = a.get("recipient", "")
    out = []
    for g in ctx.db.q("SELECT id, commands FROM allowances WHERE account_id=? AND agent_id=? AND project=? AND ended_at IS NULL AND exp>=? "
                      "AND nbf<=? AND trust_v IS NULL", (acc_id, agent_id, meta["project"], now, now)):
        if rc not in json.loads(g["commands"]):
            continue
        try:
            res = L.end_allowance(g["id"], "revoked")
        except Exception:  # noqa: BLE001  unknown to the ledger (never expected): mark it ended here, it covers nothing
            res = {"result": "reject", "reason": "ALLOWANCE_UNKNOWN"}
        ctx.db.x("UPDATE allowances SET ended_at=?, end_seq=?, end_reason='text-unsigned-renewed' WHERE id=? AND ended_at IS NULL",
                 (_now(), res.get("seq"), g["id"]))
        out.append(g["id"])
    return out


def team(ctx, account_id):
    return org.current_policy(ctx, account_id) is not None


def cover(L, mid, a, meta, now):
    """Gateway step before the core decides: if the core would ask about this command (defer ESCALATE_COMMAND) and an active ALLOWANCE of
    mandate `mid` covers it for the hook's project, the action is sent with `allowance` + `project` (the core checks them again and records
    OK_ALLOWANCE). Anything else: the action unchanged (a listed command never carries an allowance; its receipt stays as before)."""
    if meta is None or a.get("class") != "command" or a.get("dangerous") is True:
        return a
    rc = a.get("recipient", "")
    if rc in meta["outside"] or why_not(rc):
        return a
    if L.S.decide_for(mid, a, now)[1:] != ("defer", "ESCALATE_COMMAND"):
        return a
    for gid, g in sorted(L.S.allowances.items(), key=lambda kv: -kv[1]["seq"]):
        if g["mandate"] == mid and not g["ended"] and g["nbf"] <= now <= g["exp"] and g["project"] == meta["project"] and rc in g["commands"]:
            b = dict(a, allowance=gid, project=meta["project"])
            if L.S.decide_for(mid, b, now)[1:] == ("allow", "OK_ALLOWANCE"):
                return b
    return a


# r0348: a "never" of these words is not replaced by a key rule (the key is tried only where the old way said "only once" because of
# the line's form: a dangerous mark, an unlisted head, a kind no amendment names)
KEY_NEVER = (DEFENSE_WHY, LATER_WHY, AUTOSTART_WHY, AUTOSTART_COPY_WHY)
KEY_NEVER_START = ("only a pending shell command", "a team's mandate", "the mandate of this request", "the agent's hook does not report",
                   "this project already has", "your Witness client asks about every line", "a file in a shared temporary folder")


def offer(ctx, acc, x):
    """What the approval page may offer for the pending action row x: {eligible, why_not, commands, project, t, days, default_days,
    max_days, typ, text}. Built from the row and the ledger; the owner's device builds and signs the payload itself.
    r0348: when the old way gives no rule, the KEY of the question (app/klyuch.py: its consequences) may (r0349, Р-1611 п.3: write / GET /
    service at the first question, running a program from the second same question)."""
    out = _offer(ctx, acc, x)
    if out["eligible"] or out["why_not"] in KEY_NEVER or str(out["why_not"] or "").startswith(KEY_NEVER_START):
        return out
    try:
        meta = json.loads(x["cmd_meta"]) if x["cmd_meta"] else None
        if "exec_json" in x.keys() and x["exec_json"] and '"written_run"' in x["exec_json"]:
            return out                                 # a file the agent wrote runs: never a key (law §3 p.4)
    except (TypeError, ValueError, IndexError, KeyError):
        return out
    if not isinstance(meta, dict) or x["status"] != "pending_approval":
        return out
    from app import klyuch
    return klyuch.offer(ctx, acc, x, meta, out)


def _offer(ctx, acc, x):
    out = {"eligible": False, "why_not": None, "commands": [], "project": None, "t": _now(), "days": list(DAYS), "default_days": DEFAULT_DAYS,
           "max_days": min(MAX_DAYS, ALLOWANCE_MAX_S // 86400), "typ": TYP, "text": TRUST_TEXT, "text_v": "tt-2", "max_per_project": MAX_PER_PROJECT}
    try:
        a = json.loads(x["action_json"]) if x["action_json"] else None
        meta = json.loads(x["cmd_meta"]) if x["cmd_meta"] else None
    except (TypeError, ValueError, IndexError, KeyError):
        a = meta = None
    if a is None or a.get("class") != "command" or x["status"] != "pending_approval":
        out["why_not"] = "only a pending shell command can be allowed for a project"
        return out
    if str(a.get("recipient") or "").startswith("defense:"):
        out["why_not"] = DEFENSE_WHY                   # r0305: an OS protection switched off (Н10; asked only as a strict doubt)
        return out
    if str(a.get("recipient") or "").startswith("autostart:") and "in an unknown directory" not in str(a.get("recipient")) \
            and not str(a.get("recipient")).startswith("autostart:copy into "):   # r0304 mass copy keeps its own words
        out["why_not"] = LATER_WHY                     # r0305 (W5): .envrc, .husky, CI ... run later by another program: once only
        return out
    if str(a.get("recipient") or "").startswith("autostart:"):
        # r0298 (decision of Deus 14.11): a file that starts commands by itself, in a folder Witness cannot tell: never "from now on" --
        # neither an allowance nor an amendment (checked before both; create() rebuilds this offer, so a forged request gets 409)
        out["why_not"] = AUTOSTART_COPY_WHY if str(a.get("recipient")).startswith("autostart:copy into ") else AUTOSTART_WHY
        return out
    am = meta.get("amend") if isinstance(meta, dict) else None
    if isinstance(am, list) and am:                    # 06.11 (r0260): an amendment of a KIND of act (app/amend.py), planned when asked
        return _amend_offer(ctx, acc, x, meta, am, out)
    if a.get("dangerous") is True and str(x["tool"] or "").split(".")[0] in ("Write", "Edit", "MultiEdit", "NotebookEdit") \
            and str(a.get("recipient") or "").startswith("(write outside the project) "):
        out["why_not"] = "a file in a shared temporary folder is asked each time: approve it once"     # r0261f (0.2.59)
        return out
    if x["reason"] == "ESCALATE_COMMAND_DANGER":
        from app.qwords import git_config_read
        if git_config_read(x):
            # 12.11 (r0264, L3 q-Z62DVF): a Low read of git settings said "a dangerous command is never allowed". The question is the
            # client lock's (0.2.61 needs an owner-approved receipt for every line with `git config`: an allowance would not let it run)
            out["why_not"] = ("your Witness client asks about every line that touches git settings, one call at a time: allow it once. "
                              "Client 0.2.62 and newer does not ask about a plain read")
            return out
    if a.get("dangerous") is True or x["reason"] == "ESCALATE_COMMAND_DANGER":
        out["why_not"] = "a dangerous command is never allowed for a project: it is asked every time"
        return out
    if x["reason"] != "ESCALATE_COMMAND":
        out["why_not"] = "this question is not about an unlisted command (%s)" % x["reason"]
        return out
    if "exec_json" in x.keys() and x["exec_json"] and '"written_run"' in x["exec_json"] and not _written_clean(x, meta):
        from app.repeat import written_run_words
        out["why_not"] = written_run_words(x["exec_json"])     # r25 (s8 P2); r0345: or a download place
        return out
    if team(ctx, acc["id"]):
        out["why_not"] = "a team's mandate is not widened by one signature: approve once (allowances are for a personal account)"
        return out
    if not meta:
        out["why_not"] = "the agent's hook does not report the project (deus-witness 0.2.10 or newer is needed)"
        return out
    m = ctx.db.one("SELECT * FROM mandates WHERE id=?", (x["mandate_id"],))
    if m is None or m["status"] != "active":
        out["why_not"] = "the mandate of this request is no longer active"
        return out
    L = ctx.hub.ledger(acc["id"])
    now = L.sync_now()
    base = {k: v for k, v in wire.cbor_form(a).items() if k not in ("allowance", "project")}
    want = []
    for h in meta["heads"]:
        v = L.S.decide_for(m["id"], cover(L, m["id"], dict(base, recipient=h), meta, now), now)[1:]
        if v[0] == "allow":
            continue
        if v != ("defer", "ESCALATE_COMMAND"):
            out["why_not"] = "the line also contains %s (%s): approve it once" % (h, v[1])
            return out
        if h in meta["outside"]:
            out["why_not"] = "%s runs outside the project or names a path outside it: approve it once" % h
            return out
        w = why_not(h)
        if w:
            out["why_not"] = w
            return out
        want.append(h)
    if not want or len(want) > 8:
        out["why_not"] = "nothing in this line can be allowed for a project" if not want else "too many different commands in one line"
        return out
    out.update(eligible=True, commands=want, project=meta["project"], mandate_id=m["id"])
    return _narrow(ctx, acc, x, meta, out)


def _narrow(ctx, acc, x, meta, out):
    """0.2.96: the branch the rule is bound to (shown on the page) and the per-project limit."""
    out["branch"] = meta.get("branch")
    n = live_count(ctx, acc["id"], x["agent_id"], meta["project"])
    out["live_in_project"] = n
    if n >= MAX_PER_PROJECT:
        out.update(eligible=False, why_not="this project already has %d \"from now on\" rules (the most a project may have): revoke one under "
                   "Settings -> Allowances, or approve this once" % n)
    return out


def _written_clean(x, meta):
    """r0271 (ISPYTANIE-0266 Н1): every written file this page shows is one a "from now on" rule for the project covers later
    (actions.clean_in_project: the witness read the whole text, no gate, no script findings, inside the project) -> the rule is offered:
    it would not be held after the next clean write either. Anything else (or unreadable) -> False (approve once, as before)."""
    from app.actions import clean_in_project
    try:
        wr = json.loads(x["exec_json"]).get("written_run")
    except (TypeError, ValueError, AttributeError):
        return False
    if not isinstance(wr, list) or not wr or not isinstance(meta, dict):
        return False
    return all(isinstance(w, dict) and clean_in_project(w, w.get("file"), meta.get("project")) for w in wr)


def _amend_offer(ctx, acc, x, meta, ids, out):
    """06.11 (r0260): the offer of an amendment (same signed object as a project allowance, kind identifiers as its `commands`)."""
    from app import amend
    if "exec_json" in x.keys() and x["exec_json"] and '"written_run"' in x["exec_json"]:
        from app.repeat import written_run_words
        out["why_not"] = written_run_words(x["exec_json"])
        return out
    if team(ctx, acc["id"]):
        out["why_not"] = "a team's mandate is not widened by one signature: approve once (allowances are for a personal account)"
        return out
    m = ctx.db.one("SELECT * FROM mandates WHERE id=?", (x["mandate_id"],))
    if m is None or m["status"] != "active":
        out["why_not"] = "the mandate of this request is no longer active"
        return out
    if not (isinstance(ids, list) and 0 < len(ids) <= amend.MAX_IDS and all(isinstance(i, str) and i.startswith(amend.KINDS) and 0 < len(i) <= 200
                                                                          and "*" not in i for i in ids)):
        out["why_not"] = "nothing in this call can be allowed from now on"
        return out
    out.update(eligible=True, commands=list(ids), project=meta["project"], mandate_id=m["id"], text=amend.TEXT, text_v="am-1", kind="amendment")
    return _narrow(ctx, acc, x, meta, out)


def create(ctx, acc, user_id, rid, env, view_fn=None):
    """POST /api/allowances: the owner signed the allowance map (wa-sig typ application/aar-allowance+cbor) on the approval page of `rid`.
    The server checks that the signed map is exactly what it would offer for that request (commands, project, the active mandate's hash,
    nbf ~ now, exp <= nbf + 90 days, a fresh id), records it in the ledger and marks the pending request as answered by it.
    pv2: the allowance map may carry `view` (bstr 32, the presentation hash of the approval page that offered it); the request then claims
    the same hash (view_sha256) and view_fn checks it against the rows under hub.lock. Signed without the claim, claimed without the
    signature, or another hash than the claim -> ALLOWANCE_MISMATCH; the claim is not the rows' view -> VIEW_CHANGED. Neither: as before
    (the permission is marked "view not signed").
    r0327 (law "Signed = shown"): a claimed view must be signed as allow_view(page, text_v, text) -- the page AND the offer's text of trust,
    whole; the page alone -> ALLOWANCE_TEXT_NOT_SIGNED, another text or version -> ALLOWANCE_MISMATCH. The object goes into shown_views
    (views/allowance-<id>.json of the pack), the version into allowances.trust_v (the list shows that text)."""
    if not looks_like_envelope(env) or wq.envelope_kind(env) != "wa":
        raise Err(409, "WA_MALFORMED")               # one owner's wa-sig (a team's quorum does not widen its mandate this way)
    try:
        e = cbor2.loads(env)
        g = cbor2.loads(e["payload"])
        if not isinstance(g, dict) or allowance_payload(g) != e["payload"]:
            raise ValueError
    except Exception:
        raise Err(409, "ALLOWANCE_MALFORMED")
    org.refuse_revoked(ctx, env)
    with ctx.hub.lock(acc["id"]):
        x = ctx.db.one("SELECT * FROM actions WHERE rid=? AND account_id=?", (rid, acc["id"])) if isinstance(rid, str) else None
        if x is None:
            raise Err(404, "NOT_FOUND")
        from app import actions as act
        x = act.refresh(ctx, rid)
        o = offer(ctx, acc, x)
        if not o["eligible"]:
            raise Err(409, "ALLOWANCE_NOT_ELIGIBLE", o["why_not"])
        from app import levels             # 0.2.13: the allowance answers a laptop-level question; with "everything on the phone" it needs a phone key
        levels.check_signers(ctx, acc["id"], levels.env_kids(env), json.loads(x["action_json"]), x["reason"], x["level_min"])
        m = ctx.db.one("SELECT * FROM mandates WHERE id=?", (o["mandate_id"],))
        M = wire.cbor_form(json.loads(m["mandate_json"]))
        now = _now()
        if validate_allowance(g) or not ID_RE.fullmatch(g["id"]):
            raise Err(409, "ALLOWANCE_MALFORMED")
        if g["mandate"] != mandate_hash(M) or g["commands"] != o["commands"] or g["project"] != o["project"]:
            raise Err(409, "ALLOWANCE_MISMATCH", "the signed allowance is not the one offered for this request; reload the page")
        view = view_fn() if view_fn is not None else None           # pv2: under hub.lock, atomic with the ledger entry below
        if ("view" in g) != (view_fn is not None):
            raise Err(409, "ALLOWANCE_MISMATCH", "the view the permission signs is not the view this request claims; reload the page")
        shown = None
        if "view" in g:
            shown = _allow_shown(ctx, acc["id"], view, o)       # r0327: (hash of page + text of trust, that object)
            if shown is None or g["view"] != shown[0]:
                if g["view"] == view:
                    raise Err(409, "ALLOWANCE_TEXT_NOT_SIGNED", "the permission signs the page but not the text of trust shown with it; "
                              "reload the page")
                raise Err(409, "ALLOWANCE_MISMATCH", "the view the permission signs is not the view this request claims; reload the page")
            shown = shown if shown[1] is not None else None
        if not now - NBF_SKEW_S <= g["nbf"] <= now + 5:          # the core counts it from nbf: no allowance that starts "later"
            raise Err(409, "ALLOWANCE_MALFORMED", "nbf must be the time of signing")
        if g["exp"] - g["nbf"] > MAX_DAYS * 86400:               # 0.2.96: the term is a ceiling of 30 days on this witness
            raise Err(409, "ALLOWANCE_TOO_LONG", "\"from now on\" lasts at most %d days; sign a shorter term" % MAX_DAYS)
        if o.get("kind") == "klyuch" and g["exp"] - g["nbf"] > int(o["max_days"]) * 86400:      # r0348: the term the text names
            raise Err(409, "ALLOWANCE_TOO_LONG", "this rule lasts at most %d day(s); sign a shorter term" % int(o["max_days"]))
        if ctx.db.one("SELECT 1 AS k FROM allowances WHERE id=?", (g["id"],)):
            raise Err(409, "ALLOWANCE_ID_TAKEN")
        org.check_sign_counts(ctx, env, "allowance", acc["id"])      # 0.2.20 (the counter is read only where the passkey's key signed it)
        L = ctx.hub.ledger(acc["id"])
        res = L.register_allowance(m["id"], g, cose_bytes=env)
        if res["result"] != "accept":
            raise Err(409, res["reason"])
        with ctx.db.tx():
            if shown is not None:          # r0327: the evidence pack carries the signed object (page + text) as views/allowance-<id>.json
                ctx.db.x("INSERT INTO shown_views(account_id, sha256, view_json, t) VALUES(?,?,?,?) ON CONFLICT(account_id, sha256) DO UPDATE "
                         "SET t=excluded.t", (acc["id"], shown[0].hex(), json.dumps(shown[1], ensure_ascii=False, sort_keys=True), now))
            ctx.db.x("INSERT INTO allowances(id,account_id,agent_id,mandate_id,commands,project,nbf,exp,envelope,ledger_seq,created_at,created_by,from_rid,"
                     "view_sha256,branch,trust_v) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (g["id"], acc["id"], x["agent_id"], m["id"], json.dumps(g["commands"]), g["project"], g["nbf"], g["exp"], env, res["seq"],
                      now, user_id, rid, g["view"].hex() if "view" in g else None, o.get("branch"), shown[1]["text_v"] if shown else None))
            # the pending request is answered by the allowance (status `covered`: it leaves every queue; a waiting hook sends the call again,
            # an older hook answers "ask" as for any unanswered question and the agent's next call runs under the allowance)
            ctx.db.x("UPDATE actions SET covered_by=?, status='covered', updated_at=? WHERE rid=? AND status='pending_approval'", (g["id"], now, rid))
            if o.get("kind") == "klyuch":         # r0348: one key rule answers every waiting question of this agent with the same key
                from app import klyuch
                ctx.db.x("UPDATE actions SET covered_by=?, status='covered', updated_at=? WHERE account_id=? AND agent_id=? AND "
                         "status='pending_approval' AND cmd_meta IS NOT NULL AND instr(cmd_meta, ?)>0",
                         (g["id"], now, acc["id"], x["agent_id"], '"klyuch_h": "%s"' % klyuch.key_hash(g["commands"])))
    return {"allowance_id": g["id"], "commands": g["commands"], "project": g["project"], "exp": g["exp"], "ledger_seq": res["seq"],
            "branch": o.get("branch")}


def _allow_shown(ctx, account_id, page_hash, o):
    """r0327: -> (hash, object) of the view a new rule must sign: the page view the server has just matched (stored under that hash by
    api_web._view_match) plus the text of trust of THIS offer, whole. None when the page view is not held (the page then cannot sign)."""
    if not isinstance(page_hash, bytes):
        return None
    r = ctx.db.one("SELECT view_json FROM shown_views WHERE account_id=? AND sha256=?", (account_id, page_hash.hex()))
    tv = text_version(o.get("text"))
    if o.get("kind") == "klyuch":                       # r0348: the text of a key rule is built from its keys (kl-1), not one fixed text
        from app import klyuch
        tv = klyuch.V if o.get("text_v") == klyuch.V and o.get("text") == klyuch.render(o["commands"], o["max_days"]) else None
    if r is None or tv is None or tv != o.get("text_v"):
        return None
    from app.signview import jcs
    obj = allow_view(json.loads(r["view_json"]), tv, o["text"])
    return hashlib.sha256(jcs(obj)).digest(), obj


def revoke(ctx, acc, aid):
    """One click (the owner's session; no passkey prompt: ending an allowance only narrows the mandate). Ledger entry ALLOWANCE_END."""
    with ctx.hub.lock(acc["id"]):
        g = ctx.db.one("SELECT * FROM allowances WHERE id=? AND account_id=?", (aid, acc["id"])) if isinstance(aid, str) else None
        if g is None:
            raise Err(404, "NOT_FOUND")
        if g["ended_at"] is not None:
            return {"allowance_id": aid, "status": "revoked", "ended_at": g["ended_at"]}
        L = ctx.hub.ledger(acc["id"])
        res = L.end_allowance(aid, "revoked")
        if res["result"] != "accept" and res.get("reason") != "ALLOWANCE_ENDED":
            raise Err(409, res["reason"])
        t = _now()
        ctx.db.x("UPDATE allowances SET ended_at=?, end_seq=?, end_reason='revoked' WHERE id=?", (t, res.get("seq"), aid))
    return {"allowance_id": aid, "status": "revoked", "ended_at": t}


def status_of(ctx, g, now=None):
    now = _now() if now is None else now
    if g["ended_at"] is not None:
        er = g["end_reason"] if "end_reason" in g.keys() else None
        return "branch_changed" if er == "branch" else "text_unsigned_renewed" if er == "text-unsigned-renewed" else "revoked"
    m = ctx.db.one("SELECT status FROM mandates WHERE id=?", (g["mandate_id"],))
    if m is None or m["status"] != "active":
        return "mandate_ended"
    if now > g["exp"]:
        return "expired"
    return "active"


def listing(ctx, acc):
    names = {a["id"]: a["name"] for a in ctx.db.q("SELECT id, name FROM agents WHERE account_id=?", (acc["id"],))}
    now = _now()
    out = []
    for g in ctx.db.q("SELECT * FROM allowances WHERE account_id=? ORDER BY created_at DESC, rowid DESC", (acc["id"],)):
        use = ctx.db.one("SELECT COUNT(*) AS n, MAX(created_at) AS last FROM actions WHERE account_id=? AND allowances IS NOT NULL"
                         " AND instr(allowances, ?) > 0", (acc["id"], '"%s"' % g["id"]))
        out.append({"id": g["id"], "agent_id": g["agent_id"], "agent": names.get(g["agent_id"], ""), "mandate_id": g["mandate_id"],
                    "commands": json.loads(g["commands"]), "project": g["project"], "nbf": g["nbf"], "exp": g["exp"],
                    "created_at": g["created_at"], "from_rid": g["from_rid"], "ended_at": g["ended_at"], "status": status_of(ctx, g, now),
                    "uses": use["n"], "last_used": use["last"], "ledger_seq": g["ledger_seq"], "branch": g["branch"],
                    # r0327: the text of trust of the version this rule signed (None: signed before the text was part of the signature)
                    "text_v": g["trust_v"], "text": _rule_text(g),
                    # r1611: no text_v = the text of trust is not part of this rule's signature: its first use is asked again
                    "text_signed": bool(g["trust_v"]), "note": None if g["trust_v"] else "text not signed"})
    return out


def _rule_text(g):
    """The text of trust a rule signed: a fixed version, or (r0348, kl-1) the key rule's text rebuilt from its keys."""
    if not g["trust_v"]:
        return None
    from app import klyuch
    if g["trust_v"] == klyuch.V:
        try:
            return klyuch.text_of_rule(json.loads(g["commands"]), g["nbf"], g["exp"])
        except (TypeError, ValueError, StopIteration):
            return None
    return texts().get(g["trust_v"])


def sandbox_cover(L, mid, a, meta, w, now, text=None):
    """V3 prototype: if the core would ask about this command (defer ESCALATE_COMMAND), the hook's facts say the line runs in a STRICT
    Claude Code sandbox (`_witness.sandbox.strict`, judged on the server: hookjudge/sandbox.py) and the command is a runner
    (hookjudge/sandbox.runner), the action is sent with `sandboxed: true`; the core allows it (OK_SANDBOXED) only when the signed mandate
    says command.sandboxed = "allow". Anything else: unchanged (asked as before). Never for a dangerous command, a variant, a command that
    left the project, or a file the agent changed that the command executes (exec_changed is checked by the core first)."""
    from app.hookjudge import sandbox as hsb
    sb = w.get("sandbox") if isinstance(w, dict) else None
    if meta is None or not isinstance(sb, dict) or sb.get("strict") is not True:
        return a
    if a.get("class") == "command" and "allowance" not in a and code_option(L, mid):
        b = code_cover(L, mid, a, meta, w, now, text)
        if b is not a:
            return b
    if a.get("class") != "command" or a.get("dangerous") is True or "allowance" in a:
        return a
    rc = a.get("recipient", "")
    if rc in meta["outside"] or not hsb.runner(rc):
        return a
    if L.S.decide_for(mid, a, now)[1:] != ("defer", "ESCALATE_COMMAND"):
        return a
    b = dict(a, sandboxed=True)
    return b if L.S.decide_for(mid, b, now)[1:] == ("allow", "OK_SANDBOXED") else a


# 0.2.82 (irreversibility gate, decision 01.11): the option "Code in Claude Code's strict sandbox: run without asking".
CODE_DEFERS = ("ESCALATE_COMMAND", "ESCALATE_COMMAND_DANGER", "ESCALATE_EXEC_CHANGED")
# a dangerous / changed-file action under `unlisted: allow` is still a defer of the core (dangerous and exec_changed come first)


def code_option(L, mid):
    """True when the signed mandate `mid` carries the option: the reserved entry in command.allow AND command.sandboxed = "allow"."""
    from app.hookjudge.mapping import SANDBOXED_CODE
    M = L.S.mandates.get(mid) if L is not None else None
    cp = ((M or {}).get("permissions") or {}).get("command")
    return isinstance(cp, dict) and cp.get("sandboxed") == "allow" and isinstance(cp.get("allow"), list) and SANDBOXED_CODE in cp["allow"]


def line_contained(L, mid, meta, w, text) -> bool:
    """v1 П3 (Р-0611-D8, 06.11): does this whole Bash line run inside a FRESH strict Claude Code sandbox under the signed code option, with
    nothing the sandbox does not hold (hookjudge/sandbox.code_line_ok: no exit, every danger contained, every visible write inside the
    project and outside .git / the agent's settings, no network in the text)? Used for a line the LIST allows (`python3 x.py` with python3
    listed): before 06.11 such a line was not marked sandboxed, so a file the agent wrote and it runs was held (ESCALATE_WRITTEN_RUN) even
    in the sandbox, while the same line unlisted ran OK_SANDBOXED. Anything missing or malformed -> False (the old rule applies)."""
    from app.hookjudge import sandbox as hsb
    if not in_strict_sandbox(L, mid, meta, w):
        return False
    return hsb.code_line_ok(w, meta["project"], text)[0] is True


def home_tmp_cover(L, mid, a, w, now, text):
    """11.11 (r0260, class (б)): a line of a session started in the home folder that the hook marked `home_tmp` (mapping: strict fact,
    empty allowedDomains, inert programs, every write / delete in the session's own temp folder on the resolved path). The marks of the
    line are checked again here (hookjudge/sandbox.home_tmp_line without the realpath); under the code option the core may then answer
    OK_SANDBOXED. Anything else: the action unchanged."""
    from app.hookjudge import sandbox as hsb
    ht = w.get("home_tmp") if isinstance(w, dict) else None
    if not isinstance(ht, dict) or a.get("class") != "command" or not code_option(L, mid) or w.get("project") is not None:
        return a
    if not hsb.home_tmp_line(w, text, ht.get("home"), ht.get("sid"))[0]:
        return a
    _, v0, why0 = L.S.decide_for(mid, a, now)
    if not (v0 == "defer" and why0 in CODE_DEFERS):
        return a
    b = dict(a, sandboxed=True, dangerous=False)
    b.pop("exec_changed", None)
    return b if L.S.decide_for(mid, b, now)[1:] in (("allow", "OK_SANDBOXED"), ("allow", "OK")) else a


def in_strict_sandbox(L, mid, meta, w) -> bool:
    """v1 П3: the hook's FRESH strict-sandbox fact holds for this line (judged on the server: hookjudge/sandbox.py, 0.2.88 fail-closed)
    and the signed mandate carries the code option. What the line itself visibly does is judged on its own; this says only that any
    code it runs (a file the agent wrote included) runs under the OS bounds: no network, no write outside the project and temp, no read
    of the secrets under ~."""
    sb = w.get("sandbox") if isinstance(w, dict) else None
    return meta is not None and isinstance(sb, dict) and sb.get("strict") is True and code_option(L, mid)


def code_cover(L, mid, a, meta, w, now, text):
    """The core would ask about this part of a Bash line (an unlisted command, a dangerous one, a changed executed file) and the line runs
    in a strict Claude Code sandbox (checked by the caller): if hookjudge/sandbox.code_line_ok says the whole line stays inside it (no
    exit, every danger contained, every visible write inside the project and outside .git / the agent's settings, no network in the text),
    the action goes to the core as `sandboxed: true` without the `dangerous` / `exec_changed` marks the sandbox makes moot; the core must
    then answer OK_SANDBOXED (else: the original action, asked as before). A deny of the core is never turned into an allow."""
    from app.hookjudge import sandbox as hsb
    _, v0, why0 = L.S.decide_for(mid, a, now)
    if not ((v0 == "defer" and why0 in CODE_DEFERS) or (v0, why0) == ("allow", "OK_UNSPECIFIED")):
        return a                                      # OK_UNSPECIFIED (unlisted: allow): recorded as sandboxed, so the holds below know
    from app import amend
    ok, _why = hsb.code_line_ok(w, meta["project"], text, skip=amend.covered_marks(L, mid, meta["project"], w, text, now))
    if not ok:
        return a
    b = dict(a, sandboxed=True, dangerous=False)
    b.pop("exec_changed", None)
    # 10.11 (r0260): a LISTED part of the same line (`npm test 2>&1 | tail -5`: tail; `python3 - <<EOF ...; head -3`) carries the line's
    # changed executed files too; without them the core allows it as listed ("OK"), not "OK_SANDBOXED" -- before, that part kept its
    # ESCALATE_EXEC_CHANGED and the whole line was asked although every part runs inside the sandbox (dev corpus: 4 lines, every day).
    return b if L.S.decide_for(mid, b, now)[1:] in (("allow", "OK_SANDBOXED"), ("allow", "OK")) else a


EXIT_PREFIX = "(network) "


FETCH_HEADS = {"curl", "wget", "http", "https", "xh", "xhs"}


def held_mark_cover(L, mid, a, tool, args, w, now):
    """10.11 (r0260, law 2): one danger mark of a Bash line (the part Bash.danger, recipient = the mark) that the strict sandbox holds by
    itself (amend._held: hookjudge/sandbox.contained / code_contained, the hook's held K1 word) is a sandboxed run of THAT part, whatever
    else the line does: every other part (a program that leaves, its host, a write outside the project) is judged on its own and asked
    on its own. Before, one asked part made the whole line's held marks questions too, and no "from now on" could be offered for the
    asked part (amend.line_ok). Never without the strict fact and the code option; a deny of the core stays a deny."""
    from app import amend
    if tool != "Bash.danger" or not isinstance(a, dict) or a.get("class") != "command" or "allowance" in a or a.get("sandboxed") is True:
        return a
    from app.hookjudge import sandbox as hsb
    meta = project_meta(args)
    if not in_strict_sandbox(L, mid, meta, w) or not amend._held(a.get("recipient"), dict(w, project=meta["project"])):
        return a
    # a line WITH danger marks has no part of its own for its programs (mapping: the part "Bash" only when there is no danger): the
    # danger part stands for them. So every program that leaves must be judged by another part: a fetcher whose host is a Bash.net part.
    net = w.get("net") if isinstance(w.get("net"), list) else []
    dz = w.get("danger") or []
    exits = [h for h in w.get("commands") or [] if hsb.code_exit(h) and ("exit:%s" % h) not in dz]   # an exit with its own mark: that part
    if any(not (isinstance(h, str) and h.split(" ")[0].rsplit("/", 1)[-1] in FETCH_HEADS and net) for h in exits):
        return a
    if exits:                                         # a fetcher's request is its Bash.net part only when the shell words are plain: every
        cm_ = hsb.code_only(w)[0]                     # danger mark of the line must come from interpreter code (or the held K1 word) --
        if any(d not in cm_ and d != w.get("harness_held") for d in w.get("danger") or []):    # a brace / variable / unparsable part
            return a                                  # of the line may hide another host
    if L.S.decide_for(mid, a, now)[1] != "defer":
        return a
    b = dict(a, sandboxed=True, dangerous=False)
    b.pop("exec_changed", None)
    return b if L.S.decide_for(mid, b, now)[1:] == ("allow", "OK_SANDBOXED") else a


def code_net_cover(L, mid, a, tool, args, w, now):
    """10.11 (r0260, law 2 / Р-1011 А): a host that ONLY interpreter code of the line names (`python3 -c "urlopen('https://h')"`, a python
    heredoc), on a line the strict sandbox contains (hookjudge/sandbox.code_line_ok, which already drops such hosts from its network test):
    the network part goes to the core as a sandboxed run (the kernel refuses the connection), OK_SANDBOXED or unchanged. 10.11 (decision
    Р-1011-сеть-в-строгой): the same for a host of the line's network READS (hookjudge/sandbox.net_read_line: curl / wget GET, git clone ...)
    -- outside allowedDomains the kernel refuses it, inside the person listed it. Never for a host of a program that is not a read (ssh,
    curl with a body, git push ...: asked), never without the strict fact and the code option. The core's DLP comes first (a credential
    in the call: DATA_FORBIDDEN, never turned)."""
    from app.hookjudge import sandbox as hsb
    if tool != "Bash.net" or not isinstance(a, dict) or a.get("class") != "command" or "allowance" in a:
        return a
    rc = a.get("recipient", "")
    if not isinstance(rc, str) or not rc.startswith(EXIT_PREFIX):
        return a
    meta = project_meta(args)
    if not in_strict_sandbox(L, mid, meta, w):
        return a
    host = hsb._rcpt_host(rc[len(EXIT_PREFIX):])
    nr = hsb.net_read_line(args.get("command"))
    if host not in hsb.code_only(w)[1] and (nr is None or host not in nr["hosts"]):
        return a
    if L.S.decide_for(mid, a, now)[1] != "defer" or not hsb.code_line_ok(w, meta["project"], args.get("command"))[0]:
        return a
    b = dict(a, sandboxed=True, dangerous=False)
    return b if L.S.decide_for(mid, b, now)[1:] == ("allow", "OK_SANDBOXED") else a


def exit_ask(L, mid, a, tool, now):
    """0.2.91 (friction 04.11: `curl https://witness.example/healthz`, a URL literal in interpreter code): a host of a SHELL line (Bash.net)
    outside the mandate's message domains was refused RECIPIENT, with no button, although the recommended mandate asks about every exit of
    a shell line (gate G2) and the owner may well want this one. Such a part goes to the core as what it is -- a dangerous command of the
    line, "(network) HOST" -- and is asked (defer ESCALATE_COMMAND_DANGER) when the mandate's command permission asks about dangerous
    commands; under `command.unlisted: "deny"`, protected data in the call, or anything else: unchanged (the core refuses it as before).
    WebFetch is not touched (its domains list is the rule of that tool)."""
    if tool != "Bash.net" or not isinstance(a, dict) or a.get("class") != "disclosure":
        return a
    if L.S.decide_for(mid, a, now)[1:] != ("deny", "RECIPIENT"):
        return a
    host = str(a.get("recipient", "")).split("@", 1)[-1]
    b = dict(a, **{"class": "command", "recipient": EXIT_PREFIX + host, "dangerous": True})
    return b if L.S.decide_for(mid, b, now)[1:] == ("defer", "ESCALATE_COMMAND_DANGER") else a
