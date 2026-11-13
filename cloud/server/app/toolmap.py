"""Tool map (ARHITEKTURA 4.3): raw MCP call (tool, args) -> action of -04; presets; DLP; masking of args for the panel."""
import collections
import contextvars
import copy
import functools
import hashlib
import json
import re
import threading

from app import _paths  # noqa: F401  (sys.path of the core)
from svidetel_v4.decide import _WS, _nfkc_cf

# 0.2 (§4.2): L1+L2 come from the DLP library of task 03 (`dw_dlp`, cloud/lib/dlp, on sys.path via _paths). No fallback: a server
# without the library must not start (0.2.0 merge: the stand-in dlp_stub of 02 is removed).
import dw_dlp as _dlp

CLASSES = ("message", "file", "disclosure", "purchase", "sale", "meeting", "refund", "delete", "publish", "pass", "command", "http")   # PROPOSAL-06: command; 0.2.43 PROPOSAL-08-http: http
PATH_RE = re.compile(r"\$(\.[A-Za-z0-9_]+)+")
SECRET_RE = [   # patterns of dogfood/ten.py (the shapes only; no values)
    ("telegram_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b")),
    ("api_key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|xox[abprs]-[A-Za-z0-9-]{10,})\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"))]
UNMAPPED = "UNMAPPED"
STRICT_CLASSES = ("message", "publish", "file", "disclosure", "command", "http")     # 0.2 §6: every top-level argument must be mapped; other classes: "strict": true

# Claude Code hook tools other than the shell command itself (the same in the -05 and the PROPOSAL-06 preset)
_CC_COMMON = {
    "Bash.write": {"class": "delete", "recipient": "$._witness.writes", "text": ["$.command"], "reversible": False, "strict": True, "l2_skip": ["$._witness"],
                   "extra_keys": ["description", "timeout", "run_in_background", "dangerouslyDisableSandbox"]},
    "Bash.net": {"class": "disclosure", "recipient": "$._witness.net", "text": ["$.command"], "strict": True, "l2_skip": ["$._witness"],                 # judged like WebFetch
                 "extra_keys": ["description", "timeout", "run_in_background", "dangerouslyDisableSandbox"]},
    "Write": {"class": "delete", "recipient": "$._witness.path", "text": ["$.content"], "reversible": False, "strict": True, "l2_skip": ["$._witness"],
              "extra_keys": ["file_path"]},
    "Edit": {"class": "delete", "recipient": "$._witness.path", "text": ["$.new_string"], "reversible": False, "strict": True, "l2_skip": ["$._witness"],
             "extra_keys": ["file_path", "old_string", "replace_all"]},
    "MultiEdit": {"class": "delete", "recipient": "$._witness.path", "text": ["$.edits"], "reversible": False, "strict": True, "l2_skip": ["$._witness"],
                  "extra_keys": ["file_path"]},
    "NotebookEdit": {"class": "delete", "recipient": "$._witness.path", "text": ["$.new_source"], "reversible": False, "strict": True, "l2_skip": ["$._witness"],
                     "extra_keys": ["notebook_path", "cell_id", "cell_type", "edit_mode"]},
    "Read": {"class": "pass"},
    "Read.secret": {"class": "publish", "recipient": "$._witness.danger", "strict": True, "l2_skip": ["$._witness"], "extra_keys": ["file_path", "offset", "limit", "pages"]},
    "WebFetch": {"class": "disclosure", "recipient": "$._witness.recipient", "text": ["$.url", "$.prompt"], "strict": True, "l2_skip": ["$._witness"]},
    # 0.2.12 (R7-06): the other built-in tools that read files or send data (recommended matcher). Grep of a credential file is asked like
    # Read.secret; WebSearch sends its query out (recipient websearch@api.anthropic.com: allowed only if the owner lists that domain).
    "Grep": {"class": "pass"},
    "Grep.secret": {"class": "publish", "recipient": "$._witness.danger", "strict": True, "l2_skip": ["$._witness"],
                    "extra_keys": ["pattern", "path", "glob", "output_mode", "-B", "-A", "-C", "-n", "-i", "type", "head_limit", "offset", "multiline"]},
    "Glob": {"class": "pass"},
    "LS": {"class": "pass"},
    "NotebookRead": {"class": "pass"},
    "NotebookRead.secret": {"class": "publish", "recipient": "$._witness.danger", "strict": True, "l2_skip": ["$._witness"], "extra_keys": ["notebook_path", "cell_id"]},
    "WebSearch": {"class": "disclosure", "recipient": "$._witness.recipient", "text": ["$.query"], "strict": True, "l2_skip": ["$._witness"],
                  "extra_keys": ["allowed_domains", "blocked_domains"]},
    "ReadMcpResourceTool": {"class": "pass"},
    "ListMcpResourcesTool": {"class": "pass"}}

# 0.2.9: read-only shell commands of the recommended Claude Code mandate (command.allow, unlisted: ask), modelled on Claude Code's own read-only set.
# The same list as mcp/deus_witness/hook/form.py and app/hookjudge/mapping.py DEFAULT_SAFE_COMMANDS and web/js/mandate_form.js READONLY_COMMANDS (tests keep them equal);
# why each entry is there and why find/xargs/sed/awk/env/printenv/make/interpreters/package managers/curl/wget are not: docs/internal/coverage.md 6.2.
# 0.2.53: the last 15 are local writes, allowed only in the form whose every path is inside the project (hookjudge/bashparse._local_write).
# 0.2.89: + 19 read-only diagnostics after jq, each only in its read-only form (hookjudge/bashparse._ro_tags / _ro_ident).
CC_READONLY_COMMANDS = ("ls", "pwd", "cd", "cat", "head", "tail", "wc", "echo", "grep", "rg", "which", "file", "stat", "du", "df",
                        "date", "uname", "git status", "git log", "git diff", "git show", "git branch", "diff", "tree", "sort",
                        "uniq", "cut", "tr", "nl", "column", "basename", "dirname", "realpath", "sha1sum", "sha256sum", "sha512sum",
                        "shasum", "cmp", "comm", "test", "sleep", "git blame", "git ls-files", "git rev-parse", "git describe",
                        "git shortlog", "git grep", "git reflog",
                        "mkdir", "touch", "cp", "mv", "ln", "chmod", "rm", "rmdir", "git add", "git commit", "git checkout",
                        "git switch", "git restore", "git mv", "git rm",
                        "find", "sed", "awk", "jq",
                        "ps", "lsof", "whoami", "id", "git remote", "git tag list", "git stash list", "git stash show", "git config get", "npm ls", "npm list",
                        "pip list", "pip3 list", "pip freeze", "pip3 freeze", "pip show", "pip3 show", "uv pip", "git check-ignore", "git ls-tree", "git rev-list", "git merge-base", "git show-ref",
                        "od", "hexdump", "strings", "xxd", "--version")
# 0.2.9: a Write/Edit/MultiEdit/NotebookEdit to git's configuration, hooks or a `.git` file is sent twice: as the file tool (delete targets) and as
# Write.danger (git runs what is written there on the next `git status`/`git diff`: judged like a dangerous command, the owner is asked each time)
_CC_WRITE_DANGER = {"recipient": "$._witness.danger", "text": ["$.content", "$.new_string", "$.edits", "$.new_source"], "strict": True, "l2_skip": ["$._witness"],
                    "extra_keys": ["file_path", "old_string", "replace_all", "notebook_path", "cell_id", "cell_type", "edit_mode"]}

PRESETS = {
    "demo": {"version": 1, "default": "deny", "tools": {
        "send_email": {"class": "message", "recipient": ["$.to", "$.cc", "$.bcc"], "text": ["$.subject", "$.body"]},
        "purchase": {"class": "purchase", "recipient": "$.vendor", "amount": "$.amount_cents", "currency": "USD", "strict": True},
        "delete_resource": {"class": "delete", "recipient": "$.resource", "reversible": {"cache-tmp": True}, "strict": True},
        "publish": {"class": "publish", "recipient": "$.channel", "text": ["$.text"], "strict": True},
        "read_file": {"class": "pass"}}},
    "filesystem": {"version": 1, "default": "deny", "tools": {
        # 0.1.3: a write is judged like an IRREVERSIBLE delete of the path: allowed only for paths matching the mandate's delete targets
        # AND only when the mandate sets allow_irreversible; without that it stays denied (IRREVERSIBLE_DELETE / RESOURCE).
        "write_file": {"class": "delete", "recipient": "$.path", "text": ["$.content"], "reversible": False, "strict": True},
        "edit_file": {"class": "delete", "recipient": "$.path", "text": ["$.content", "$.edits"], "extra_keys": ["dryRun"], "reversible": False, "strict": True},
        # 0.1.3: both ends of a move must match the delete targets
        "move_file": {"class": "delete", "recipient": ["$.source", "$.destination"], "reversible": True, "strict": True},
        "read_file": {"class": "pass"}, "read_text_file": {"class": "pass"}, "read_multiple_files": {"class": "pass"},
        "list_directory": {"class": "pass"}, "list_allowed_directories": {"class": "pass"},
        "search_files": {"class": "pass"}, "get_file_info": {"class": "pass"}, "directory_tree": {"class": "pass"}}},
    # Claude Code PreToolUse hook (deus-witness-hook, mcp/deus_witness/hook). The hook sends the tool_input plus `_witness`, which it computes
    # (realpath of the file, classified shell command, webfetch@host); recipients are read ONLY from `_witness`. One Bash line may be sent
    # as several parts (Bash.danger / Bash.write / Bash.net / Bash), all of which must be allowed.
    # Default rules = the recommended mandate (deus-witness-hook --print-form DIR): delete.targets = project/* and tmp/* with allow_irreversible,
    # command.allow = read-only commands (others: defer ESCALATE_COMMAND; dangerous: defer ESCALATE_COMMAND_DANGER), message.domains = WebFetch allow-list.
    # 0.2.0 merge (09 x 02 §6): every non-pass tool is strict; the other fields of Claude Code's tool_input are listed in extra_keys
    # (SDK types: BashInput, FileWriteInput, FileEditInput, NotebookEditInput, WebFetchInput, FileReadInput) -- a NEW field -> TOOL_ARGS_UNMAPPED.
    # PROPOSAL-06 (preset "claude-code" since 0.3): a shell command is class `command` (it was `pass`, and a dangerous one `publish`). An agent keeps the
    # map it was created with (agents.toolmap_json, bound to its mandate by hash): the -05 map stays as "claude-code-05" for reference and tests.
    "claude-code": {"version": 1, "default": "deny", "tools": dict(_CC_COMMON, **{
        "Bash": {"class": "command", "recipient": "$._witness.commands", "text": ["$.command", "$.description"], "strict": True, "l2_skip": ["$._witness"],
                 "extra_keys": ["timeout", "run_in_background", "dangerouslyDisableSandbox"]},
        "Bash.danger": {"class": "command", "dangerous": True, "recipient": "$._witness.danger", "text": ["$.command", "$.description"], "strict": True,
                        "l2_skip": ["$._witness"], "extra_keys": ["timeout", "run_in_background", "dangerouslyDisableSandbox"]},
        "Write.danger": dict(_CC_WRITE_DANGER, **{"class": "command", "dangerous": True}),
        # 0.2.90: a Write / Edit / NotebookEdit outside the project that the hook shadow-copied first: judged as the pseudo-command
        # "(write outside the project) <path>" of class command (the mandate's `unlisted` decides; a receipt either way)
        "Write.outside": dict(_CC_WRITE_DANGER, **{"class": "command", "recipient": "$._witness.commands"})})},
    "claude-code-05": {"version": 1, "default": "deny", "tools": dict(_CC_COMMON, **{
        "Bash": {"class": "pass"},                                                                   # nothing dangerous and no file written
        "Bash.danger": {"class": "publish", "recipient": "$._witness.danger", "text": ["$.command", "$.description"], "strict": True, "l2_skip": ["$._witness"],
                        "extra_keys": ["timeout", "run_in_background", "dangerouslyDisableSandbox"]},
        "Write.danger": dict(_CC_WRITE_DANGER, **{"class": "publish"})})},
    # 0.2.43 (spec/PROPOSAL-08-http.md): the Witness middleware for NVIDIA OpenShell (openshell-modul/witness_openshell/policy.py TOOLMAP, kept equal by
    # a test). One HTTP request of the sandbox = one action of class `http`: recipient = "<METHOD> <host>:<port><path>" built by the middleware from
    # what the proxy saw; the query and the body (as text when small) are DLP-scanned; body_sha256 / body_bytes / sandbox_id are bound by args_sha256.
    "openshell": {"version": 1, "default": "deny", "tools": {
        "openshell.http": {"class": "http", "recipient": "$.target", "text": ["$.body", "$.query"],
                           "extra_keys": ["body_sha256", "body_bytes", "sandbox_id"], "strict": True}}},
    "empty": {"version": 1, "default": "deny", "tools": {}},
}


class ToolmapInvalid(Exception):
    pass


def preset(name):
    return copy.deepcopy(PRESETS.get(name or "demo", PRESETS["demo"]))


def check_toolmap(tm):
    if not isinstance(tm, dict) or tm.get("version") != 1 or tm.get("default") not in ("deny", "pass") or not isinstance(tm.get("tools"), dict):
        raise ToolmapInvalid("version=1, default deny|pass, tools{}")
    for n, t in tm["tools"].items():
        if not isinstance(n, str) or not isinstance(t, dict) or t.get("class") not in CLASSES:
            raise ToolmapInvalid("bad class for " + str(n))
        if "recipient" in t:
            rc = t["recipient"]
            if not ((isinstance(rc, str) and PATH_RE.fullmatch(rc)) or
                    (isinstance(rc, list) and 0 < len(rc) <= 8 and all(isinstance(p, str) and PATH_RE.fullmatch(p) for p in rc))):
                raise ToolmapInvalid("recipient: a path or a list of up to 8 paths for " + str(n))
        if "amount" in t and isinstance(t["amount"], str) and not PATH_RE.fullmatch(t["amount"]):
            raise ToolmapInvalid("path amount")
        if "extra_keys" in t and not (isinstance(t["extra_keys"], list) and all(isinstance(k, str) for k in t["extra_keys"])):
            raise ToolmapInvalid("extra_keys for " + str(n))
        if "text" in t and not (isinstance(t["text"], list) and all(isinstance(p, str) and PATH_RE.fullmatch(p) for p in t["text"])):
            raise ToolmapInvalid("text paths for " + str(n))
        if "reversible" in t and not (isinstance(t["reversible"], bool) or (isinstance(t["reversible"], dict) and all(isinstance(v, bool) for v in t["reversible"].values()))):
            raise ToolmapInvalid("reversible for " + str(n))
        if "l2_skip" in t and not (isinstance(t["l2_skip"], list) and len(t["l2_skip"]) <= 8 and all(isinstance(p, str) and PATH_RE.fullmatch(p) for p in t["l2_skip"])):
            raise ToolmapInvalid("l2_skip: a list of up to 8 paths for " + str(n))
        if "dangerous" in t and not (isinstance(t["dangerous"], bool) and t["class"] == "command"):
            raise ToolmapInvalid("dangerous: a boolean, only for class command, for " + str(n))
        if "strict" in t and not isinstance(t["strict"], bool):
            raise ToolmapInvalid("strict must be boolean for " + str(n))
        if t["class"] in ("purchase", "sale", "refund") and "amount" not in t:
            raise ToolmapInvalid("amount missing for " + str(n))


def jpath(obj, path):
    cur = obj
    for p in path[2:].split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def dlp_tags(text, literals):
    """Literal match (case-insensitive) of the account's data_patterns + built-in secret shapes. A paraphrase evades it (stated in the docs)."""
    tags = {n for n, rx in SECRET_RE if rx.search(text)}
    low = _norm(text)            # N-03: same normalisation as the core uses for addresses (NFKC + casefold, no format characters, no white space)
    for cls, lits in literals.items():
        if any(l and _norm(l) and _norm(l) in low for l in lits):
            tags.add(cls)
    return sorted(tags)


def _norm(s):
    return _WS.sub("", _nfkc_cf(s))


LEAF_LIMIT = 262144      # N-02: DLP looks at every string leaf of the arguments (and the keys), up to this many characters in total


def string_leaves(args, budget=LEAF_LIMIT):
    """All string values (and dict keys) of the arguments, depth-first, up to `budget` characters; non-strings are skipped."""
    out, stack = [], [args]
    while stack and budget > 0:
        x = stack.pop()
        if isinstance(x, str):
            out.append(x[:budget]); budget -= len(x)
        elif isinstance(x, dict):
            for k, v in x.items():
                stack.append(v)
                if isinstance(k, str):
                    stack.append(k)
        elif isinstance(x, (list, tuple)):
            stack.extend(x)
    return out


PREVIEW_CHARS = 300
TEXT_PREVIEW_CHARS = 4096


@functools.lru_cache(maxsize=64)
def _lit_rx(lits):
    return re.compile("|".join(re.escape(l) for l in lits), re.I) if lits else None


def _lits_key(literals):
    return tuple(sorted({l for ls in literals.values() for l in ls if l}, key=lambda x: (-len(x), x)))


def mask_text(s, literals, limit):
    # N-09: cut to the limit PLUS the longest literal/secret first (so a literal on the edge is masked whole), mask, THEN cut to the limit
    longest = max([len(l) for ls in literals.values() for l in ls] + [0])
    s = s[:limit + longest + 512]
    for _, rx in SECRET_RE:
        s = rx.sub("[masked]", s)
    rx = _lit_rx(_lits_key(literals))
    if rx is not None:
        s = rx.sub("[masked]", s)
    return s[:limit]


# 0.2.24 (critique B): a secret in an assignment has no known shape (`DB_PASSWORD=hunter2`): its VALUE is masked in previews (only in previews:
# the DLP tags that decide are unchanged). The name stays, so the owner sees what kind of value was there.
# 29.10 (ReDoS, OTCHET-REDOS-AUDIT-2910 #1): `[A-Za-z0-9_]*KW[A-Za-z0-9_]*` with no left edge re-split the same name from every position
# ('PASS' x 1000: 0.7 s, x 1024: > 20 s, cubic). Now a name is tried ONCE, from its first character (the lookbehind), the keyword is looked
# for by a lookahead and the name is taken whole. Same matches as before (group 1 was always the whole name: it must be followed by \s or
# [=:]), checked on a 92 000-line corpus with 0 differences (server/tests/test_redos_2910.py). No atomic group: the client runs on 3.10.
# 29.10 MTYPE (cloud/OTCHET-MASKA-TIP-2910.md, RT-MASKA-UKRYTIE-2910): a bare [masked] hid exactly what the witness asked the person to decide
# (`AUTH_URL=https://host/x; curl "$AUTH_URL"`, `passthrough_cmd='curl ...'; eval ...`). A masked value that looks like a URL is now shown as
# `[masked URL host=<host>]` (never userinfo, port, path, query; a subdomain label not in MARK_SUB_OK is `*`: a secret can ride in a DNS
# label), one that looks like a command as `[masked command: <program>]` (the program only when it is in MARK_PROGRAMS, never its arguments),
# anything else `[masked]` as before. "Already masked" now means any of these markers (MASK_MARK). In the TEXT OF A SHELL COMMAND (shell=True:
# the Bash* tools) a bare value ends at an unquoted ; & | ) or a line end: `PASS=1;rm -rf build` -> `PASS=[masked];rm -rf build` (it ate `;rm`).
MASK_MARK = r"\[masked(?: URL host=[a-z0-9.*\-]+| command: [A-Za-z0-9._+\-]+)?\]"
ASSIGN_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]*(?:PASSWORD|PASSWD|PASS|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|AUTH))([A-Za-z0-9_]+)(\s*[=:]\s*)(?!" + MASK_MARK + r")((?:Bearer|Basic|Token)\s+\S+|\S+)")
# 29.10 QMASK (cloud/OTCHET-QMASK-2910.md): ASSIGN_RE never masked a name in QUOTES: `"password": "hunter2"` (JSON, a dict, YAML) left the
# machine open in a file preview, `password: "two words"` / `DB_PASSWORD="a b"` lost only the first word. Widening ASSIGN_RE itself made 142
# corpus cases softer, so this is a SECOND pass: its value spans are added to ASSIGN_RE's on the same string (a union: it only adds masks).
# Name: optionally in quotes (' " or the JSON-escaped \"), then `]` (d['token'] = ...), the same words as ASSIGN_RE (API_KEY/PRIVATE_KEY also
# with '-': X-Api-Key), also '-' and '.' inside; value: a quoted string (escapes inside, to the line end if unterminated), Bearer/Basic/Token
# + value, or a bare word. A value already [masked] is left. Linear: every quoted body has one tokenisation, a name is tried once (lookbehind).
QUOTED_ASSIGN_RE = re.compile(
    r"""(?i)(?P<kq>\\"|["'])?(?<![A-Za-z0-9_.\-])(?=[A-Za-z0-9_.\-]*(?:PASSWORD|PASSWD|PASS|SECRET|TOKEN|API[_\-]?KEY|PRIVATE[_\-]?KEY|AUTH))"""
    r"""(?P<k>[A-Za-z0-9_.\-]+)(?(kq)(?P=kq)\]?)\s*[=:]\s*(?!(?:\\"|["'])?""" + MASK_MARK + r""")"""
    r"""(?P<v>(?:Bearer|Basic|Token)\s+[^\s"'\\,;{}\[\]]+"""
    r"""|"(?:[^"\\\n]|\\.)*(?:"|(?=\\?[\r\n])|\\?\Z)"""
    r"""|'(?:[^'\\\n]|\\.)*(?:'|(?=\\?[\r\n])|\\?\Z)"""
    r"""|\\"(?:[^"\\\n]|\\\\(?:\\.|[^"\\\n])|\\[^"\\\n])*(?:\\"|(?=\\?[\r\n])|\\?\Z)"""
    r"""|[^\s"'\\,;{}\[\]]+)""")


# the same two shapes for shell text: the bare value (and the Bearer value) stops at ; & | ) (a quoted value is still taken whole)
ASSIGN_SH_RE = re.compile(ASSIGN_RE.pattern.replace(r"\s+\S+|\S+)", r"\s+[^\s;&|)]+|[^\s;&|)]+)"))
QUOTED_ASSIGN_SH_RE = re.compile(QUOTED_ASSIGN_RE.pattern.replace("\\,;{}\\[\\]]+", "\\,;{}\\[\\]&|)]+"))
assert ASSIGN_SH_RE.pattern.count("[^\\s;&|)]+") == 2 and QUOTED_ASSIGN_SH_RE.pattern.count("&|)]+") == 2
MARK_PROGRAMS = frozenset((
    "curl wget nc ncat netcat socat ssh scp sftp rsync ftp telnet bash sh zsh dash ksh fish eval exec source python python2 python3 node "
    "deno bun perl ruby php lua powershell pwsh osascript rm dd mkfs chmod chown sudo su doas git docker kubectl base64 openssl gpg xxd "
    "nslookup dig host ping env xargs sed awk tar zip unzip mv cp cat echo printf tee crontab launchctl systemctl npm npx pip pip3 make").split())
MARK_SUB_OK = frozenset((
    "www api apis docs doc raw cdn static files file upload uploads download downloads git gist gitlab github auth login oauth sso id app "
    "apps m mail smtp imap s3 storage objects registry pypi npm hooks hook webhook webhooks dev staging stage prod test beta api2 v1 v2 "
    "rpc ws wss ftp sftp cloud console admin dashboard portal pay checkout billing").split())
_MARK_URL = re.compile(r"(?i)[a-z][a-z0-9+.\-]{0,15}://(?:[^/?#\s'\"\\@]*@)?([a-z0-9.\-]{1,253})(?![a-z0-9.\-@])")
_MARK_CMD = re.compile(r"(?:(?:\$\(|`)\s*|(?=\S+\s+\S))(?:[A-Za-z0-9._\-]*/)*([A-Za-z0-9._+\-]{1,32})(?![A-Za-z0-9._+\-/])")
_MARK_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?")


def _mark_host(h):
    """the host as the marker shows it, or None: an IPv4 as is; a name: its last two labels (three under co/com/net/org/gov/edu/ac + a
    two-letter TLD) plus the subdomain labels found in MARK_SUB_OK, any other label as `*` (runs of them collapsed)."""
    h = h.lower().rstrip(".")
    labels = h.split(".")
    if len(labels) < 2 or not all(_MARK_LABEL.fullmatch(l) for l in labels):
        return None
    if all(l.isdigit() for l in labels):
        return h if len(labels) == 4 and all(int(l) < 256 for l in labels) else None
    if labels[-1].isdigit():
        return None
    n = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in ("co", "com", "net", "org", "gov", "edu", "ac") else 2
    sub = []
    for l in labels[:-n]:
        l = l if l in MARK_SUB_OK else "*"
        if not (l == "*" and sub and sub[-1] == "*"):
            sub.append(l)
    return ".".join(sub + labels[-n:])


def mask_marker(v):
    """The marker that replaces the masked value `v` (see MASK_MARK): URL -> host, command -> program, else [masked]."""
    t = v.strip()
    for q in ('\\"', '"', "'"):
        if t.startswith(q):
            t = t[len(q):]
            break
    m = _MARK_URL.match(t)
    if m:
        h = _mark_host(m.group(1))
        return "[masked URL host=%s]" % h if h else "[masked]"
    m = _MARK_CMD.match(t)
    if m and m.group(1) in MARK_PROGRAMS:
        return "[masked command: %s]" % m.group(1)
    return "[masked]"


_SH_SEP = ";&|)"


def _shell_stops(s):
    """stop[i]: the first j >= i where s[j] is whitespace or a separator OUTSIDE shell quotes (len(s) if none); nsep[i]: the first j >= i
    where s[j] is a separator outside quotes; quoted[i]: s[i] is inside quotes or escaped. Quotes: '...' (no escapes),
    "..." (backslash escapes), a backslash outside quotes escapes the next character; an unterminated quote runs to the end (masks more)."""
    n = len(s)
    stop = [n] * (n + 1)
    nsep = [n] * (n + 1)
    quoted = bytearray(n)
    st, i = 0, 0                     # 0 outside, 1 in '...', 2 in "..."
    while i < n:
        ch = s[i]
        if st == 0:
            if ch == "\\":
                quoted[i] = 1
                if i + 1 < n:
                    quoted[i + 1] = 1
                i += 2
                continue
            if ch == "'":
                st = 1
            elif ch == '"':
                st = 2
        elif st == 1:
            quoted[i] = 1
            if ch == "'":
                st = 0
        else:
            quoted[i] = 1
            if ch == "\\" and i + 1 < n:
                quoted[i + 1] = 1
                i += 2
                continue
            if ch == '"':
                st = 0
        i += 1
    for j in range(n - 1, -1, -1):
        c = s[j]
        sep = c in _SH_SEP and not quoted[j]
        nsep[j] = j if sep else nsep[j + 1]
        stop[j] = j if (sep or c.isspace()) else stop[j + 1]
    return stop, quoted, nsep


# 12.11 (L3 ISPYTANIE-L3-0260, repeat on 0.2.61): "Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>" (every commit of Claude Code)
# showed as "Co-Authored-By: [masked] Haiku 5.5": AUTH matched inside AUTHOR, and the person saw a word hidden and an address shown. A name
# whose only key word is AUTHOR (AUTHORED, GIT_AUTHOR_NAME, author:) names a person, not a secret. AUTHORIZATION / AUTHORITY / AUTHORISE and
# a name with another key word (AUTHOR_TOKEN) stay masked. A filter on the server's spans: the shared patterns (and the client 0.2.61 copy,
# which masks only exec previews, so it masks MORE there) are unchanged.
_AUTHOR_WORD = re.compile(r"(?i)AUTHOR(?!I[ZST])")


_NAME_KEY = re.compile(r"(?i)PASSWORD|PASSWD|PASS|SECRET|TOKEN|API[_\-]?KEY|PRIVATE[_\-]?KEY|AUTH")      # the key words of both patterns


def _secret_name(name):
    return bool(_NAME_KEY.search(_AUTHOR_WORD.sub("", name or "")))


def assign_spans(s, shell=False):
    """The spans masked in `s`: ASSIGN_RE's values united with QUOTED_ASSIGN_RE's (overlaps merged). shell=True (the text of a shell
    command): the _SH_ shapes, a bare value ending at a separator; one INSIDE shell quotes (`-H 'Authorization: Bearer a;b'`) is part of the
    value, so such a span runs on to the next whitespace or unquoted separator (_shell_stops). United with the plain spans each cut at its
    first unquoted separator: what the shell text shows more than the plain one always starts at an unquoted separator."""
    sp = sorted([m.span(3) for m in ASSIGN_RE.finditer(s) if _secret_name(m.group(1))]
                + [m.span("v") for m in QUOTED_ASSIGN_RE.finditer(s) if _secret_name(m.group("k"))])
    if shell and sp:
        stops = None
        for k, (a, b) in enumerate(sp):              # the plain spans, cut at their first unquoted separator
            if any(ch in _SH_SEP for ch in s[a:b]):
                if stops is None:
                    stops = _shell_stops(s)
                sp[k] = (a, min(b, stops[2][a]))
        for m, g in [(m, 3) for m in ASSIGN_SH_RE.finditer(s) if _secret_name(m.group(1))] + [(m, "v") for m in QUOTED_ASSIGN_SH_RE.finditer(s) if _secret_name(m.group("k"))]:
            a, b = m.span(g)                          # + the shell spans (a later NAME= after a separator), run on over quoted separators
            if b < len(s) and s[b] in _SH_SEP:
                if stops is None:
                    stops = _shell_stops(s)
                if stops[1][b]:
                    b = stops[0][b + 1]
            sp.append((a, b))
        sp = sorted(x for x in sp if x[1] > x[0])
    out = []
    for a, b in sp:
        if out and a < out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def mask_assign(s, shell=False):
    """Every span of assign_spans(s, shell) replaced by its marker (mask_marker; ASSIGN_RE.sub's output exactly when the quoted pass adds
    nothing and no value is a URL or a command)."""
    out, i = [], 0
    for a, b in assign_spans(s, shell):
        out += [s[i:a], mask_marker(s[a:b])]
        i = b
    out.append(s[i:])
    return "".join(out)
SECRET_KEY_RE = re.compile(r"(?i)(PASSWORD|PASSWD|PASS|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|AUTH)")
MASK_NODES = 2000            # leaves/containers walked for a preview; the rest is "..." (the preview is 300 characters anyway)
MASK_DEPTH = 32


def mask_value(s, literals, limit, shell=False):
    """mask_text + the value of every `NAME=value` / `NAME: value` whose name says password/secret/token/key/auth (shell=True: the text of a
    shell command, a bare value ends at ; & | ) - MTYPE 29.10)."""
    return mask_assign(mask_text(s, literals, limit), shell)


def shell_tool(tool):
    """MTYPE 29.10: the tools whose mapped text is a shell command line (Bash and its derived Bash.* rows)."""
    return isinstance(tool, str) and (tool == "Bash" or tool.startswith("Bash."))


def _masked_copy(args, literals, limit, shell=False):
    """0.2.24 (critique B, bug): every string leaf (and key) masked BEFORE json.dumps. Masking the serialised JSON missed `ghp_...` after a
    newline: the JSON escape `\\n` glued an `n` to the token and the leading \\b of the pattern never matched. A string under a key named like a
    secret (password, token, api_key ...) is masked whole. Iterative budget: deep or huge arguments become "..." past MASK_NODES / MASK_DEPTH."""
    budget = [MASK_NODES]

    def walk(x, depth, key_secret, path=()):
        budget[0] -= 1
        if budget[0] < 0 or depth > MASK_DEPTH:
            return "..."
        if isinstance(x, str):
            if key_secret and x:          # MTYPE 29.10: the whole string is the secret's value; its marker says URL host / program, if any
                return mask_marker(mask_text(x, literals, limit))
            return mask_value(x, literals, limit, shell and path == ("command",))
        if isinstance(x, dict):
            out = {}
            for k, v in x.items():
                if budget[0] < 0:
                    out["..."] = "..."
                    break
                ks = mask_value(k, literals, 200) if isinstance(k, str) else str(k)
                out[ks] = walk(v, depth + 1, isinstance(k, str) and bool(SECRET_KEY_RE.search(k)), path + (k,) if depth == 0 else None)
            return out
        if isinstance(x, (list, tuple)):
            out = []
            for v in x:
                if budget[0] < 0:
                    out.append("...")
                    break
                out.append(walk(v, depth + 1, key_secret))
            return out
        if x is None or isinstance(x, (bool, int, float)):
            return x
        return mask_value(str(x), literals, limit)
    return walk(args, 0, False)


def mask_args(args, literals, limit=PREVIEW_CHARS, shell=False):
    """args_preview: <= 300 chars, secrets, secret assignments and the account's literals replaced by [masked] (each string before serialising)."""
    try:
        s = json.dumps(_masked_copy(args, literals, limit, shell), ensure_ascii=False, default=str)
    except (ValueError, RecursionError, TypeError):
        s = "[unprintable]"
    return mask_value(s, literals, limit, shell)


DECIDED_EXCERPT = 80
DECIDED_PREFIX = "args sha256:"


def decided_preview(args_sha256, masked_preview):
    """0.2.24 (critique B, storage): what stays of the previews once the action is decided: the hash of the arguments (what the receipt binds)
    and a short masked excerpt (<= 80 characters). The full previews are kept only while the action waits for a person."""
    ex = (masked_preview or "")[:DECIDED_EXCERPT]
    return "%s%s %s" % (DECIDED_PREFIX, args_sha256 or "-", ex)


# r0269 (migration plan step 3): args_sha256 over RFC 8785 (JCS) with a domain prefix, rule "mr-args-2". The old rule (v1: Python
# json.dumps with sort_keys, code-point order, repr numbers; salted form "dw-args1") stays the default, so every deployed client that
# recomputes the hash keeps matching. A client opts in per request with the header X-DW-Args-V: 2 (api_agent sets ARGS_V for that
# request); the action then carries the label `args_v: 2`, and a reader picks the rule by that label (absent = v1, old receipts).
# Arguments JCS cannot encode (an integer beyond 2^53, a non-finite number) fall back to v1 WITHOUT the label: same rule on both sides.
ARGS_V = contextvars.ContextVar("dw_args_v", default=1)
ARGS_V2 = b"mr-args-2\0"


def args_digest_v(tool, args, salt=None, v=None):
    """-> (hex, rule version actually used: 1 or 2)."""
    v = ARGS_V.get() if v is None else v
    if v == 2:
        from app.signview import jcs
        try:
            raw = ARGS_V2 + jcs([tool, args])
        except (ValueError, TypeError, RecursionError):
            raw = None
        if raw is not None:
            if salt is None:
                return hashlib.sha256(raw).hexdigest(), 2
            import hmac
            return hmac.new(salt, raw, hashlib.sha256).hexdigest(), 2
    return _args_digest_v1(tool, args, salt), 1


def _args_digest_v1(tool, args, salt=None, **kw):
    """0.2.34: SHA-256 of the canonical [tool, args], or (salt given, DW_ARGS_SALT=on) HMAC-SHA-256(salt, "dw-args1\\0" + canonical)."""
    raw = json.dumps([tool, args], sort_keys=True, separators=(",", ":"), ensure_ascii=False, **kw).encode()
    if salt is None:
        return hashlib.sha256(raw).hexdigest()
    import hmac
    return hmac.new(salt, b"dw-args1\0" + raw, hashlib.sha256).hexdigest()


def _args_digest(tool, args, salt=None):
    return args_digest_v(tool, args, salt)[0]


def _bind_args(act, tool, args, salt):
    h, v = args_digest_v(tool, args, salt)
    act["args_sha256"] = h
    if v == 2:
        act["args_v"] = 2
    return h


def args_matches(action, tool, args, salt=None):
    """Reader side: does `action.args_sha256` bind exactly (tool, args)? The rule is chosen by the action's own label."""
    v = 2 if isinstance(action, dict) and action.get("args_v") == 2 else 1
    h, used = args_digest_v(tool, args, salt, v=v)
    return isinstance(action, dict) and used == v and action.get("args_sha256") == h


def args_hash(tool, args, salt=None):
    v = ARGS_V.get()
    if v == 2:
        return args_digest_v(tool, args, salt, v=2)[0]
    return _args_digest_v1(tool, args, salt, default=str)


def text_preview(toolmap, tool, args, literals):
    """R-05: masked text of the mapped `text` paths (<= 4 KB) for the approval page; "" when nothing is mapped."""
    t = toolmap["tools"].get(tool)
    if not t:
        return ""
    parts = [str(jpath(args, p)) for p in t.get("text", []) if jpath(args, p) is not None]
    return mask_value(" \n".join(parts), literals, TEXT_PREVIEW_CHARS, shell_tool(tool))


def toolmap_hash(toolmap):
    """R-03: SHA-256 of the canonical JSON of the tool map; stored with the passkey-signed mandate."""
    return hashlib.sha256(json.dumps(toolmap, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def reversible_of(t, recipient):
    """N-01: reversibility of the delete target `recipient` under tool entry `t`."""
    rv = t.get("reversible")
    return (rv is True) or (isinstance(rv, dict) and rv.get(recipient) is True)


def recipient_values(t, args):
    """R-02: every recipient the call addresses -> list of strings. The first path is required (missing -> "", which the core denies);
    further paths (cc, bcc) are skipped when absent/empty; a list value is expanded; anything not a string -> its str() (the core denies it)."""
    rc = t.get("recipient")
    if rc is None:
        return []
    paths = [rc] if isinstance(rc, str) else list(rc)
    out = []
    for i, p in enumerate(paths):
        v = jpath(args, p)
        if v is None or v == "" or v == []:
            if i == 0:
                out.append("")
            continue
        for x in (v if isinstance(v, list) else [v]):
            out.append(x if isinstance(x, str) else str(x))
    return out or [""]


def is_strict(t):
    return bool(t) and t["class"] != "pass" and (t["class"] in STRICT_CLASSES or t.get("strict") is True)


def unmapped_args(toolmap, tool, args):
    """R-02, 0.2 §6: for message/publish/file/disclosure (and any tool with "strict": true) every top-level argument must be mapped
    (recipient/text/amount path) or listed in `extra_keys`; -> list of unknown keys. A nested object under a mapped path is not inspected."""
    t = toolmap["tools"].get(tool)
    if not is_strict(t):
        return []
    known = set(t.get("extra_keys", []))
    rc = t.get("recipient")
    am = [t["amount"]] if isinstance(t.get("amount"), str) else []
    for p in ([rc] if isinstance(rc, str) else list(rc or [])) + list(t.get("text", [])) + am:
        known.add(p[2:].split(".")[0])
    return sorted(k for k in args if k not in known)


_TEXTS = collections.OrderedDict()      # args_sha256 -> scanned text, for the L3 advisor in flow.hooks.pre_authorize (its signature has no text)
_TEXTS_LOCK = threading.Lock()
_TEXTS_MAX = 64


def _remember_text(h, text):
    with _TEXTS_LOCK:
        _TEXTS[h] = text
        _TEXTS.move_to_end(h)
        while len(_TEXTS) > _TEXTS_MAX:
            _TEXTS.popitem(last=False)


def last_text(args_sha256):
    with _TEXTS_LOCK:
        return _TEXTS.get(args_sha256)


def dlp_scan(text, literals):
    """-> (tags, hits) of the DLP library (L1 literals/secrets + L2 checksummed formats). Pure."""
    r = _dlp.scan(text, literals)
    if isinstance(r, dict):
        return list(r["tags"]), list(r["hits"])
    return list(r[0]), list(r[1])


def dlp_ruleset():
    return _dlp.ruleset_id()


def _without_recipients(t, args):
    """Copy of the arguments with the values under the recipient paths (and `l2_skip` paths: metadata an integration computed, e.g. the
    Claude Code hook's `_witness` with synthetic `webfetch@host` addresses) removed (their keys stay). L1 still sees every string."""
    rc = t.get("recipient")
    paths = ([rc] if isinstance(rc, str) else list(rc or [])) + list(t.get("l2_skip", []))
    if not paths:
        return args
    out = dict(args)                     # shallow copies along each path only (arguments may be nested deeper than recursion allows)
    for p in paths:
        keys = p[2:].split(".")
        cur = out
        for k in keys[:-1]:
            nxt = cur.get(k)
            if not isinstance(nxt, dict):
                cur = None
                break
            cur[k] = nxt = dict(nxt)
            cur = nxt
        if isinstance(cur, dict) and keys[-1] in cur:
            cur[keys[-1]] = None
    return out


def _without_exec(args):
    """Arguments without `_witness.exec` (0.2.13: {root, files: {path: sha256}} computed by the hook; paths of the project, hex digests)."""
    w = args.get("_witness") if isinstance(args, dict) else None
    if not isinstance(w, dict) or "exec" not in w:
        return args
    return dict(args, _witness={k: v for k, v in w.items() if k != "exec"})


def pass_action(agent_id, tool, args, literals, salt=None):
    """0.2.4 (draft-deus-aar-05 8.6): a call the signed map marks `pass` is an action of class `pass`: recipient = the tool identifier, data = the data classes
    detected in ANY string of the arguments, amount 0. The witness decides it (OK_PASS or DATA_FORBIDDEN) and writes a RECEIPT."""
    act = {"agent": agent_id, "class": "pass", "recipient": "tool:" + tool[:200], "amount": 0}
    _bind_args(act, tool, args, salt)
    text = " \n".join(string_leaves(_without_exec(args)))
    tags, hits = dlp_scan(text, literals)
    act["data"] = sorted(set(tags) | set(dlp_tags(text, literals)))
    act["dlp_rs"] = dlp_ruleset()
    act["dlp_hits"] = sorted(hits)
    act["adv"] = ""
    _remember_text(act["args_sha256"], text)
    return act


def build_action(agent_id, toolmap, tool, args, literals, pass_receipt=False, salt=None):
    """-> None (pass), UNMAPPED, or the action map of -04 (strings/ints only; the amount is passed as given: non-integers are the witness' BAD_AMOUNT).
    pass_receipt (0.2.4, mandate with the map hash inside its signature): a `pass` call is returned as an action of class `pass`, not None."""
    t = toolmap["tools"].get(tool)
    if t is None:
        if toolmap["default"] == "pass":
            return pass_action(agent_id, tool, args, literals, salt) if pass_receipt else None
        return UNMAPPED
    if t["class"] == "pass":
        return pass_action(agent_id, tool, args, literals, salt) if pass_receipt else None
    act = {"agent": agent_id, "class": t["class"]}
    # Bind the decision (and any later approval) to the EXACT request: hash of the tool name and all arguments.
    # request_hash (-04 5.7) covers every member of the action, so an approval for one email cannot authorise another.
    _bind_args(act, tool, args, salt)
    if "recipient" in t:
        act["recipient"] = recipient_values(t, args)[0]
    text = " \n".join(str(jpath(args, p)) for p in t.get("text", []) if jpath(args, p) is not None)
    # N-02: closed data and secrets are looked for in EVERY string of the arguments, not only in the mapped text paths
    dargs = _without_exec(args)            # 0.2.13: the hook's file digests are not data; they must not eat the DLP budget of the real arguments
    text = " \n".join([text] + string_leaves(dargs))
    # 0.2 §4.2: tags of L1+L2 (dw_dlp.scan) -> action.data; which level fired and under which rule set goes into the action (no values).
    # The addressees themselves (values of the recipient paths) are judged by the recipient rules, not by L2 (else every e-mail is `email_address`).
    l2text = " \n".join([" \n".join(str(jpath(args, p)) for p in t.get("text", []) if jpath(args, p) is not None)]
                        + string_leaves(_without_recipients(t, dargs)))
    tags, hits = dlp_scan(l2text, literals)
    act["data"] = sorted(set(tags) | set(dlp_tags(text, literals)))
    act["dlp_rs"] = dlp_ruleset()
    act["dlp_hits"] = sorted(hits)
    act["adv"] = ""
    _remember_text(act["args_sha256"], text)
    inert_ = False
    if act["data"] and tool.startswith("Bash") and isinstance(args.get("command"), str):
        # 11.11 (r0260, class (в) of the dev hold-out): a token-shaped value only inside a quoted heredoc that `cat > f` / edit-only Python
        # puts into a LOCAL file, on a line with no network and no exit (hookjudge/inline.dlp_inert_text), was refused (DATA_*) -- a test
        # fixture edit. The data rule judges the line without that text; when that removes a tag, the line is ASKED as dangerous instead
        # (a refusal of harmless work is worse than a question). In the strict sandbox the gate may then contain it (the value stays on
        # the machine: no network on the line). Anything the text-less line still carries is refused as before.
        from app.hookjudge import inline as _inl
        cut_ = _inl.dlp_inert_text(args["command"], args.get("_witness"))
        if cut_ is not None:
            a2_ = dict(args, command=cut_)
            d2_ = _without_exec(a2_)
            tx2_ = " \n".join([" \n".join(str(jpath(a2_, p)) for p in t.get("text", []) if jpath(a2_, p) is not None)] + string_leaves(d2_))
            l2_ = " \n".join([" \n".join(str(jpath(a2_, p)) for p in t.get("text", []) if jpath(a2_, p) is not None)]
                              + string_leaves(_without_recipients(t, d2_)))
            tg2_, ht2_ = dlp_scan(l2_, literals)
            dt2_ = sorted(set(tg2_) | set(dlp_tags(tx2_, literals)))
            # 12.11 (r0263): a personal-data format alone (an address in a fixture) is not a reason to ask: hookjudge/datarule drops it
            # for a line that keeps its text on this computer; only a secret moved into a local file still makes the line dangerous
            from app.hookjudge.datarule import FORMATS as _FMT
            if set(dt2_) < set(act["data"]) and set(act["data"]) - set(dt2_) - set(_FMT):
                act["data"], act["dlp_hits"], inert_ = dt2_, sorted(ht2_), True
    if t["class"] in ("purchase", "sale", "refund"):
        act["amount"] = jpath(args, t["amount"]) if isinstance(t.get("amount"), str) else t.get("amount")
        cur = t.get("currency", "USD")
        act["currency"] = cur.upper() if isinstance(cur, str) and cur.isascii() else cur     # 0.2.84 (R5-P2): the case the mandate form writes
    if t["class"] == "delete":
        act["reversible"] = reversible_of(t, act.get("recipient"))
    if t["class"] == "command":
        act["dangerous"] = t.get("dangerous") is True or inert_   # PROPOSAL-06: set by the signed tool map (the hook's Bash.danger), never by the
        #                                                       arguments; 11.11: or a protected value moved into a local file (above): only tightens
    return act


def is_pass_class(toolmap, tool):
    t = toolmap["tools"].get(tool)
    return (t["class"] == "pass") if t else toolmap["default"] == "pass"
