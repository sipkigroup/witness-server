"""Claude Code tool call (PreToolUse event) -> the call shown to the witness: (wire tool name, args).

The wire args are the tool_input as Claude Code gave it PLUS one reserved key `_witness` that the hook computes
(absolute path, classified command, web recipient). The server's `claude-code` preset (server/app/toolmap.py) reads only
`_witness.*` for the recipient, so a model cannot steer the judged target through tool_input; a tool_input that already
carries `_witness` is refused before anything is sent.

  Claude Code tool        wire tool       witness class                judged on
                                          (preset 0.3 = PROPOSAL-06; -05 preset in brackets: an agent keeps the map it was created with)
  Bash (no danger)        Bash            command        [pass]        every command id "ls", "git status" (mandate command.allow;
                                                                       none listed -> defer ESCALATE_COMMAND; 0.2.10: or an owner-signed
                                                                       allowance for `_witness.project`, PROPOSAL-07)
  Bash (dangerous)        Bash.danger     command, dangerous [publish] "category:detail" -> defer ESCALATE_COMMAND_DANGER
                                                                       [-05: publish.channels; none -> defer ESCALATE_PUBLISH]
  Bash (writes files)     Bash.write      delete, irreversible        every written path   (mandate delete.targets)
  Bash (network)          Bash.net        disclosure                  "webfetch@<host>"    (mandate message.domains, like WebFetch)
  Write/Edit/MultiEdit    same name       delete, irreversible        realpath of file_path
  NotebookEdit            NotebookEdit    delete, irreversible        realpath of notebook_path
  (any of the four, to git's config / hooks / a `.git` file: plus the part Write.danger = command, dangerous [publish] "git-config:<path>", 0.2.9)
  Read (credential file)  Read.secret     publish                     "secrets:<path>"
  Read                    Read            pass                        -
  WebFetch                WebFetch        disclosure                  "webfetch@<host>"    (mandate message.domains)
  0.2.12 (R7-06): the other built-in tools that read files or send data, in the recommended matcher too
  Grep (a credential file Grep.secret     publish                     "secrets:<path or glob>"  (path or glob names a credential file)
    or glob)
  Grep / Glob / LS        same name       pass                        - (listed in the ledger; Claude Code's Read deny rules apply to them)
  NotebookRead            NotebookRead[.secret], like Read on notebook_path (older Claude Code)
  WebSearch               WebSearch       disclosure                  "websearch@api.anthropic.com" (the query leaves the machine: it is
                                                                       sent through the API to the search provider; message.domains)
  ReadMcpResourceTool /   same name       pass                        - (MCP resources are read by Claude Code itself, not through
    ListMcpResourcesTool                                                 deus-witness-mcp: at least the ledger shows them)
  mcp__server__tool       unchanged       whatever the owner maps     (unmapped -> deny TOOL_UNMAPPED)

0.2.13 (PROPOSAL-08): a Bash line in a project also carries `_witness.exec` = {root, files: {relative path: sha256}, truncated}: the files that
test runners, package managers, make, cargo, go, git ... execute (execfiles.py). The server compares them with the versions the owner last
confirmed; a changed one makes the next command that executes it a question (ESCALATE_EXEC_CHANGED) even when the command is listed or allowed.

One Bash line can be several of danger / write / network at once: map_event then returns one part per aspect (same args,
different wire tool) and the hook allows the line only when EVERY part is allowed. A line without danger always carries the
`Bash` part too (PROPOSAL-06: a redirection into the project must not turn an unlisted command into one nobody is asked about);
a dangerous line does not (the owner is asked about the whole line already).
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import tempfile
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import fs as _fs
from .bashparse import _abspath, temp_in, under_home, _in_project, classify, is_agent_config_path, is_git_exec_path, is_persist_path, is_secret_path
from . import samefile as _samefile

RESERVED = "_witness"
MAX_WRITES = 32
FILE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}

# Default WebFetch allow-list of the recommended mandate (message.domains): documentation and package indexes only.
# 0.2.24 (critique T3): no host where anyone can PUBLISH content (github.com, raw.githubusercontent.com, gists, pastebins): a GET with a query
# string to such a host is a channel out. The client's copy (mcp/deus_witness/hook/form.py) must drop them too (OTCHET-0.2.24.md).
DEFAULT_WEB_DOMAINS = ["localhost", "127.0.0.1", "docs.python.org", "pypi.org", "docs.github.com",
                       "developer.mozilla.org", "www.npmjs.com", "nodejs.org", "docs.anthropic.com", "code.claude.com"]


class Refuse(Exception):
    """The event cannot be shown to the witness in a well-formed shape -> deny without asking it."""


@dataclass
class Mapped:
    tool: str
    args: dict
    summary: str          # one line for logs and messages; never the arguments themselves


def web_recipient(url) -> str:
    """WebFetch target as a mailbox-shaped id the core can match on its domain: webfetch@<host>; "" if there is no host."""
    try:
        host = urlsplit(url).hostname if isinstance(url, str) else None
    except ValueError:
        host = None
    if not host:
        return ""
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    return "webfetch@" + host.lower().rstrip(".")


def project_of(cwd: str, env=None) -> str | None:
    """0.2.10: the project a Bash line runs in, for the owner's "allow this command in this project" (PROPOSAL-07). It is what Claude Code
    tells the hook, never what the model writes: CLAUDE_PROJECT_DIR (set by Claude Code for its hooks: the directory the session was
    started in), else the event's `cwd`; as a realpath (a symlinked path names its target). None when the session's cwd is outside it
    (the agent went elsewhere: no project allowance applies there)."""
    e = os.environ if env is None else env
    p = e.get("CLAUDE_PROJECT_DIR")
    p = p if isinstance(p, str) and os.path.isabs(p) else cwd
    try:
        p = _fs.current().realpath(p)
        c = _fs.current().realpath(cwd)
    except (OSError, ValueError):
        return None
    try:
        home = _fs.current().realpath(e.get("HOME") or _fs.current().home())
    except (OSError, ValueError):
        home = None
    if p == "/" or p == home or len(p) > 1024:
        return None                                   # the whole machine or the whole home directory is not a project
    return p if c == p or c.startswith(p.rstrip("/") + "/") else None


def _home_session(cwd, env, home) -> bool:
    """11.11 (r0260): Claude Code was started in the user's home folder (CLAUDE_PROJECT_DIR, else the event's cwd, IS the home)."""
    e = os.environ if env is None else env
    p = e.get("CLAUDE_PROJECT_DIR")
    p = p if isinstance(p, str) and os.path.isabs(p) else cwd
    try:
        return isinstance(home, str) and home.startswith("/") and home != "/" and _fs.current().realpath(p) == _fs.current().realpath(home)
    except (OSError, ValueError):
        return False


def _hooks_dirs(ex, root, home):
    """0.2.77 (red team R2-2): the core.hooksPath directories named by the exec report's git config keys (`gitcfg`, hook 0.2.46+;
    LocalFS: execfiles.git_config_programs) -> absolute directories (samefile.hooks_dirs), [] when none / no report."""
    g = ex.get("gitcfg") if isinstance(ex, dict) else None
    if not isinstance(g, dict):
        return []
    vals = [kv[1] for ent in g.values() if isinstance(ent, list) for kv in ent
            if isinstance(kv, list) and len(kv) == 2 and isinstance(kv[0], str) and kv[0].lower() == "core.hookspath"]
    gl = ex.get("hookspath")                        # 0.2.77c (round 2b): global / system / included core.hooksPath (hook 0.2.51c+)
    if isinstance(gl, list):
        vals += [v for v in gl[:_samefile.MAX_HOOKSPATH] if isinstance(v, str) and len(v) <= 1024]
    return _samefile.hooks_dirs(root, vals, home) if vals else []


def _hookspath_write(path, cwd, home, env):
    """0.2.77 (red team R2-2): a file tool's write into the repository's core.hooksPath directory -> the path judged (real path when the
    named one is a link), else None. Asked of the hook (its exec report of the project) only when the path could be one (hooks_gate)."""
    if not _samefile.hooks_gate(path):
        return None
    if (env if env is not None else os.environ).get("DEUS_WITNESS_EXEC_SCAN", "1") == "0":
        return None
    project = project_of(cwd, env)
    if project is None:
        return None
    hd = _hooks_dirs(_fs.current().scan(project), project, home)
    if not hd:
        return None
    if _samefile.hooks_path_hit(path, hd):
        return path
    try:
        real = _fs.current().realpath(path)
    except (OSError, ValueError):
        return None
    return real if isinstance(real, str) and _samefile.hooks_path_hit(real, hd) else None


def map_event(ev: dict, home: str | None = None, env=None) -> list:
    """-> [Mapped, ...] (one part; several for a Bash line with more than one aspect). Raises Refuse."""
    tok = None
    if isinstance(_fs.current(), _fs.LocalFS) and isinstance(ev, dict):
        # 0.2.73 (N13): LocalFS (tests, the fatigue harness) walks the project for hard links of credential files, as the hook does
        e = env if isinstance(env, dict) else os.environ
        r = e.get("CLAUDE_PROJECT_DIR") if isinstance(e.get("CLAUDE_PROJECT_DIR"), str) and os.path.isabs(e.get("CLAUDE_PROJECT_DIR")) else ev.get("cwd")
        tok = _fs.hint_root(os.path.realpath(r) if isinstance(r, str) and os.path.isabs(r) else None, home or e.get("HOME"))
    from . import bashparse as _bp
    ti_ = ev.get("tool_input") if isinstance(ev, dict) and isinstance(ev.get("tool_input"), dict) else {}
    ttok = _bp.TMPDIR_CTX.set(_bp.tmpdir_of(env if isinstance(env, dict) else {}, ti_.get("command")))   # 0.2.93 (r0263): $TMPDIR
    try:
        m = _map(ev, home, env)
        gh_ = getattr(_fs.current(), "git_head", lambda: None)()
    finally:
        _bp.TMPDIR_CTX.reset(ttok)
        if tok is not None:
            _fs.reset_root(tok)
    m = m if isinstance(m, list) else [m]
    if isinstance(gh_, str) and gh_:
        # 0.2.96 (client 0.2.65): the git branch of the project (the hook reads .git/HEAD). A "from now on" of this project ends when the
        # branch is another one (app/allowances.reset_stale). Absent (an older hook, no git, LocalFS without a test value): byte-equal
        for x in m:
            w_ = x.args.get(RESERVED) if isinstance(x.args, dict) else None
            if isinstance(w_, dict) and w_.get("project") is not None:
                w_["branch"] = gh_
    return m


def _map(ev, home, env=None):
    if not isinstance(ev, dict):
        raise Refuse("EVENT_MALFORMED")
    tool, inp = ev.get("tool_name"), ev.get("tool_input")
    inp = {} if inp is None else inp
    if not isinstance(tool, str) or not tool or len(tool) > 200 or not isinstance(inp, dict):
        raise Refuse("EVENT_MALFORMED")
    if RESERVED in inp:
        raise Refuse("RESERVED_KEY")
    cwd = ev.get("cwd") if isinstance(ev.get("cwd"), str) and os.path.isabs(ev.get("cwd")) else _fs.current().getcwd()
    home = home or _fs.current().home()
    args = json.loads(json.dumps(inp))              # a plain JSON copy: exactly what is hashed and sent
    if tool == "Bash":
        cmd = inp.get("command")
        if not isinstance(cmd, str):
            raise Refuse("EVENT_MALFORMED")
        project = project_of(cwd, env)
        c = classify(cmd, cwd, home, project=project)
        from . import envmask as _envmask
        if _envmask.masked_line(cmd):                # 06.11 (r0260): `env | grep -i node | <mask>`: no secret value reaches the agent
            c.danger = [d for d in c.danger if d != "secrets:whole environment"]
        if any(isinstance(h, str) and SANDBOXED_CODE in h for h in c.heads):
            c.add("opaque", "a command named like the mandate's reserved entry")     # 0.2.82: never matched as the list entry
        from . import sandbox as _sbx
        from .bashparse import FETCHERS, REMOTE_SHELLS
        for h in c.heads:
            if _sbx.standing_exit(h) and not (c.net and h.split(" ")[0].rsplit("/", 1)[-1] in FETCHERS | REMOTE_SHELLS):
                c.add("exit", h)                        # 0.2.90 (G2): sends / fetches / pays / acts as the user outside the session: asked
                                                        # (curl / ssh with a host the line shows: the mandate's domains judge it, Bash.net)
        if len(c.writes) > MAX_WRITES:
            c.add("opaque", "%d write targets" % len(c.writes))
            c.writes = c.writes[:MAX_WRITES]
        net = [web_recipient("http://" + h if ":" not in h else "http://[%s]" % h) or "webfetch@" + h for h in c.net[:MAX_WRITES]]
        outside_w, shadow = _outside_writes(c, project, home)      # 0.2.90: writes outside the project with a shadow copy -> pseudo-commands
        hz = _fs.current().harness() if hasattr(_fs.current(), "harness") else None
        if isinstance(hz, str) and hz:              # 0.2.91 (client 0.2.59): the hook's lock K1 found the agent's harness in the line: asked
            c.add("agent-config", HARNESS_MARK + hz[:200])
        args[RESERVED] = {"cwd": cwd, "danger": c.danger, "writes": c.writes, "net": net, "commands": c.heads}
        gs_ = getattr(_fs.current(), "git_self", lambda: None)() if "@" in cmd else None
        if gs_:                                     # 0.2.95 (ISPYTANIE-PERED-LYUDMI-1211 Н3): the person's own git address named in the line
            from . import datarule as _dr           # (its digest only; absent on every other line: byte-equal to before)
            own_ = _dr.own_addresses(cmd, gs_)
            if own_:
                args[RESERVED]["own_addr"] = own_
        if outside_w:
            args[RESERVED].update(outside_writes=outside_w, shadow=shadow)
        if (outside_w or any(isinstance(d, str) and d.startswith("agent-config:") for d in c.danger)
                or any(isinstance(d, str) and re.match(r"opaque:code injected through (?:PYTHONPATH|NODE_PATH)=", d) for d in c.danger)
                or ("GH_CONFIG_DIR=" in cmd and any(isinstance(h, str) and h.split(" ")[0] == "gh" for h in c.heads))) \
                and project is not None \
                and isinstance(home, str) and home.startswith("/"):
            args[RESERVED]["home"] = home           # 06.11 (r0260): app/amend.py judges a folder amendment against the user's home
        if c.deletes:
            args[RESERVED]["deletes"] = [d for d in c.deletes if d in c.writes]      # 0.2.90: deletions among the writes (not code written)
        rf = getattr(c, "repo_files", None)
        if rf and not getattr(c, "xforeign", None) and not getattr(c, "repo_files_bad", False) and not c.danger and not c.net \
                and not getattr(c, "opaque", False) and not getattr(c, "gtamper", False) \
                and len(c.heads) == 1 and str(c.heads[0]).split(" ", 1)[0].rsplit("/", 1)[-1] == "git" \
                and {os.path.normpath(w) for w in c.writes if isinstance(w, str)} == set(rf) and sum(len(v) for v in rf.values()) <= 256:
            # N6 0.2.71: the line is ONE `git stash pop|apply` of the latest stash, git named its files (bashparse._stash_files), nothing
            # else runs or writes on it; absent on every other line (byte-equal to before)
            args[RESERVED]["dirfiles"] = {d: list(v) for d, v in sorted(rf.items())}
        if project is not None:                     # 0.2.10 (PROPOSAL-07): the project and the commands that left it (no allowance for those)
            args[RESERVED].update(project=project, outside=c.outside)
            ex = _fs.current().scan(project) if (env if env is not None else os.environ).get("DEUS_WITNESS_EXEC_SCAN", "1") != "0" else None
            if ex is not None:                      # 0.2.13 (PROPOSAL-08): digests of the files commands execute (conftest.py, package.json ...)
                args[RESERVED]["exec"] = ex
                wh = _fs.current().which() if hasattr(_fs.current(), "which") else None
                if isinstance(wh, dict) and wh:    # 0.2.89: where the line's Python tools resolve (execguard: is the project's venv run?)
                    args[RESERVED]["which"] = {k: wh[k] for k in sorted(wh)}
                hd = _hooks_dirs(ex, project, home)
                for w in list(c.writes) if hd else ():
                    if _samefile.hooks_path_hit(w, hd):
                        c.add("git-config", w)      # 0.2.77 (R2-2): a write into core.hooksPath (husky, .githooks) is a git hook write
            sb = _fs.current().sandbox()
            if sb is not None:                      # V3: is this line contained by a strict Claude Code sandbox? (the gateway may then skip the question)
                from . import sandbox as _sandbox
                strict, _why = _sandbox.evaluate(sb, c.heads, home, project)
                if inp.get("allowed_domains") not in (None, False, "", [], {}):
                    strict = False                  # 0.2.58 (L2 series 3 p.7): a per-call network widening (allowed_domains) -> not strict, asked
                closed_ = False
                if strict and sb.get("domains"):
                    # 10.11 (r0260, after the L2 fact "the keychain is readable from the sandbox"): a WRITE host in allowedDomains
                    # (github.com, the npm registry ...) lets any code of the line publish in the person's name with a keychain credential:
                    # such a line is judged as outside the sandbox, and the question says why (qwords: cmd_meta.sbx_open)
                    # 11.11 (r0260): with every credential source of the person closed (sandbox.cred_closed: the keychain, the
                    # browsers, the editors' stores, CLI files in denyRead; no credential in a config file the sandbox must read), only
                    # a line that NAMES a write host or a publication loses the strict fact; the question then says so
                    closed_ = _sandbox.cred_closed(sb, home)[0]
                    op_ = _sandbox.write_open(sb["domains"], c.heads, c.danger, net, cmd, c.code_only_marks(), c.code_only_hosts(),
                                              closed=closed_)
                    if op_:
                        strict = False
                        args[RESERVED]["sbx_open"] = op_[:16]
                        if closed_:
                            args[RESERVED]["sbx_closed"] = True
                if strict:                          # only then: every other judged call stays byte-equal to before (receipts, 0.2.15 parity)
                    args[RESERVED]["sandbox"] = {"strict": True}
                    if sb.get("domains"):
                        args[RESERVED]["sbx_listed"] = True     # 10.11 (r0260, Р-1011-сеть): a narrow allowedDomains list: listed hosts are reachable
                        if closed_ and all(w_ in _sandbox.CRED_HOSTS for w_ in _sandbox.write_hosts(sb["domains"])):
                            args[RESERVED]["sbx_cred_closed"] = True     # 11.11 (r0260): no credential of the person reachable (code_line_ok)
                    if isinstance(home, str) and home.startswith("/"):
                        args[RESERVED]["sbx_home"] = home       # 06.11 (law 2): sandbox.in_temp never counts the home folder as temp
                    sid_ = getattr(_fs.current(), "session", lambda: None)()
                    if isinstance(sid_, str) and sid_:
                        args[RESERVED]["sbx_sid"] = sid_[:128]  # 06.11 (law 2): this session's own folder in Claude Code's shared temp
                    hm = "agent-config:" + HARNESS_MARK + hz[:200] if isinstance(hz, str) and hz else None
                    if hm in c.danger and getattr(_fs.current(), "harness_held", lambda: False)() is True \
                            and _held_claim_ok(cmd, c.heads):    # r0261c: the hook's claim checked on the text that runs
                        # 06.11 (law 2 of the Constitution): the hook's K1 lock found the agent's harness ONLY in text the strict sandbox
                        # holds by itself (a heredoc body, a quoted argument: code that would write .git/hooks, .git/config,
                        # .claude/settings*.json, .mcp.json gets EPERM from Seatbelt) -- and no place the sandbox does NOT hold
                        # (hook/heldwords.py). The mark stays; sandbox.code_line_ok counts THIS mark as contained (only while the
                        # strict fact stands: freshness.strip_strict removes both, and the line is asked as before). A write the
                        # parser SEES keeps its own mark (git-config, persist, agent-config with the path): never covered by this.
                        args[RESERVED]["harness_held"] = hm
                    # 10.11 (r0260, law 2 / Р-1011 А): the danger marks and hosts that come ONLY from interpreter code on the line (the code
                    # runs inside the sandbox: its network is refused by the kernel, its deletes outside the project get EPERM).
                    # 10.11 (decision Р-1011-сеть-в-строгой): the guard "no code hosts while allowedDomains is not empty" is gone: a
                    # host outside the list is refused by the kernel, a host in it is one the person listed, and the same code saved to a
                    # file already runs without a question. What the guard really kept out -- a secret or a credential sent to a listed
                    # host -- is refused on every host by Н1 (constitution) and the core's DLP (DATA_FORBIDDEN), which apply first.
                    cm_ = c.code_only_marks()
                    ch_ = c.code_only_hosts()
                    if cm_ or ch_:
                        args[RESERVED]["sbx_code"] = {"marks": cm_[:MAX_WRITES], "hosts": ch_[:MAX_WRITES]}
        if project is None and _home_session(cwd, env, home):
            # 11.11 (r0260, class (б)): a session started in the home folder (no project). Only a line of inert programs whose every
            # write / delete lands in THIS session's own temp folder (realpath checked by the hook) is marked, under the strict fact with
            # an empty allowedDomains (hookjudge/sandbox.home_tmp_line); allowances.home_tmp_cover may then let it run as sandboxed.
            sb = _fs.current().sandbox()
            sid_ = getattr(_fs.current(), "session", lambda: None)()
            if sb is not None and not sb.get("domains") and inp.get("allowed_domains") in (None, False, "", [], {}) \
                    and isinstance(sid_, str) and isinstance(home, str) and home.startswith("/"):
                from . import sandbox as _sandbox
                if _sandbox.evaluate(sb, c.heads, home, None)[0] and _sandbox.home_tmp_line(
                        {"commands": c.heads, "danger": c.danger, "writes": c.writes, "net": net}, cmd, home, sid_,
                        _fs.current().realpath)[0]:
                    args[RESERVED]["home_tmp"] = {"sid": sid_[:128], "home": home}
        parts = []
        if c.danger:
            parts.append(Mapped("Bash.danger", args, "Bash: " + ", ".join(sorted({d.split(":", 1)[0] for d in c.danger}))))
        if c.writes:
            parts.append(Mapped("Bash.write", args, "Bash: writes %d path(s)" % len(c.writes)))
        if net:
            parts.append(Mapped("Bash.net", args, "Bash: network to " + ", ".join(n.split("@", 1)[1] for n in net)))
        if not c.danger:
            parts.append(Mapped("Bash", args, "Bash: " + (", ".join(c.heads[:4]) + (" ..." if len(c.heads) > 4 else "") if c.heads else "(no command)")))
        return parts
    if tool in FILE_TOOLS:
        p = inp.get(FILE_TOOLS[tool])
        if not isinstance(p, str) or not p:
            raise Refuse("EVENT_MALFORMED")
        path = _abspath(p, cwd, home)
        if is_persist_path(path):                   # 0.2.90 (G4): shell rc, LaunchAgents, the agent's settings / hooks / plugins, the witness's key
            args[RESERVED] = {"path": path, "danger": ["persist:" + path]}
            return [Mapped("Write.danger", args, "%s: a place that runs at the next login / session (only by hand)" % tool), Mapped(tool, args, "%s %s" % (tool, path))]
        if is_git_exec_path(path):                  # 0.2.9: git runs what is written there (core.fsmonitor, hooks, a `.git` gitdir pointer)
            args[RESERVED] = {"path": path, "danger": ["git-config:" + path]}
            return [Mapped(tool, args, "%s %s" % (tool, path)), Mapped("Write.danger", args, "%s: git configuration or hook" % tool)]
        hz = _fs.current().harness() if hasattr(_fs.current(), "harness") else None
        dz = "agent-config:" + path if is_agent_config_path(path) else ("agent-config:" + HARNESS_MARK + hz[:200] if isinstance(hz, str) and hz else None)
        if dz is not None:                          # 0.2.24 (critique A): Claude Code settings/hooks, .mcp.json: always the owner; 0.2.91 (client
            #                                         0.2.59): or a place the hook's lock K1 guards (memory, tools, key files, its own install)
            project = project_of(cwd, env)
            if project is not None and not _inside_targets(path, project, home) and not is_secret_path(path) \
                    and under_home(path, home):
                # 0.2.91 (friction 04.11): outside the project the write part (class delete) was refused RESOURCE before the question
                # could be asked: ~/.claude/tools/x.sh, ~/.claude/projects/*/memory/x.md. Now: the question (Write.danger) and, when the
                # hook kept a shadow copy, the write as an outside write (undo); with no copy only the question
                sh = _fs.current().shadow(path)
                if sh is not None and _shadow_ok(sh):
                    args[RESERVED] = {"path": path, "danger": [dz], "commands": [OUTSIDE_WRITE + path], "shadow": {path: sh.get("sha256") or "absent"},
                                      "project": project, "home": home}         # 06.11 (r0260): app/amend.py (memory folder amendment)
                    return [Mapped("Write.danger", args, "%s: the agent's harness" % tool), Mapped("Write.outside", args, "%s outside the project: %s" % (tool, path))]
                if sh is not None:
                    args[RESERVED] = {"path": path, "danger": [dz]}
                    return Mapped("Write.danger", args, "%s: the agent's harness (no shadow copy): %s" % (tool, path))
            args[RESERVED] = {"path": path, "danger": [dz]}
            return [Mapped(tool, args, "%s %s" % (tool, path)), Mapped("Write.danger", args, "%s: agent hook or MCP configuration" % tool)]
        hp = _hookspath_write(path, cwd, home, env)
        if hp is not None:                          # 0.2.77 (red team R2-2): core.hooksPath (husky, .githooks): git runs it like .git/hooks
            args[RESERVED] = {"path": path, "danger": ["git-config:" + hp]}
            return [Mapped(tool, args, "%s %s" % (tool, path)), Mapped("Write.danger", args, "%s: git hook (core.hooksPath)" % tool)]
        project = project_of(cwd, env)
        if project is not None and not _inside_targets(path, project, home) and not is_secret_path(path) and not is_agent_config_path(path) \
                and under_home(path, home):
            sh = _fs.current().shadow(path)         # 0.2.90 (FABLE-NOL p.5.3, QA D6): a write outside the project is reversible when the hook
            if sh is None:                          # kept a shadow copy (or the file did not exist): judged as an unlisted command with a
                pass                                # receipt, not RESOURCE; no copy -> a question (dangerous part), never a silent run
            elif _shadow_ok(sh):
                args[RESERVED] = {"path": path, "commands": [OUTSIDE_WRITE + path], "shadow": {path: sh.get("sha256") or "absent"},
                                  "project": project, "home": home}             # 06.11 (r0260): app/amend.py (folder amendment)
                return Mapped("Write.outside", args, "%s outside the project: %s" % (tool, path))
            else:
                args[RESERVED] = {"path": path, "danger": ["write-outside:" + path]}
                return Mapped("Write.danger", args, "%s outside the project (no shadow copy): %s" % (tool, path))
        args[RESERVED] = {"path": path}
        if project is not None and (path == project or path.startswith(project.rstrip("/") + "/")):
            from .strict_policy import LATER_PATH
            if LATER_PATH.search(path):             # r0261b: a file run later outside the sandbox: the question's "from now on" is this
                args[RESERVED]["project"] = project  # path in THIS project (strict_policy.write_cover); every other write byte-equal
                sb_ = _fs.current().sandbox()       # r0261c (д): the hook's own strict fact on this call (tests, the fatigue stand); on
                if sb_ is not None:                 # the user's machine the session's mark (freshness.session_strict) brings it
                    from . import sandbox as _sandbox
                    if _sandbox.evaluate(sb_, [], home, project)[0] and inp.get("allowed_domains") in (None, False, "", [], {}):
                        args[RESERVED]["sbx_session"] = True
        return Mapped(tool, args, "%s %s" % (tool, path))
    if tool == "Read":
        return _read_like(tool, inp, args, cwd, home, "file_path")
    if tool == "NotebookRead":                      # older Claude Code; today Read reads notebooks
        return _read_like(tool, inp, args, cwd, home, "notebook_path")
    if tool == "Grep":
        return _grep(inp, args, cwd, home)
    if tool in ("Glob", "LS"):
        p = inp.get("path")
        args[RESERVED] = {"path": _abspath(p, cwd, home) if isinstance(p, str) and p else cwd}
        return Mapped(tool, args, tool)
    if tool == "WebSearch":
        args[RESERVED] = {"recipient": WEBSEARCH}
        return Mapped("WebSearch", args, "WebSearch")
    if tool == "WebFetch":
        r = web_recipient(inp.get("url"))
        args[RESERVED] = {"recipient": r}
        return Mapped("WebFetch", args, "WebFetch " + (r.split("@", 1)[1] if r else "(no host)"))
    return Mapped(tool, args, tool)                 # mcp__* and anything else: judged by the owner's tool map (default deny)


WEBSEARCH = "websearch@api.anthropic.com"
def _held_claim_ok(cmd, heads):
    from .strict_policy import held_claim_ok
    try:
        return held_claim_ok(cmd, heads)
    except Exception:      # noqa: BLE001  fail closed: the mark stays a question
        return False


HARNESS_MARK = "(hook) "                            # 0.2.91: an agent-config danger the hook's lock K1 reported (the fact `harness`)
# 0.2.90: a write outside the project (not a secret, not a place of persistence) that the hook shadow-copied first is judged as this
# pseudo-command of the line (class command: `unlisted` decides; an owner may list `(write outside the project) /Users/me/notes/*`).
OUTSIDE_WRITE = "(write outside the project) "


def _inside_targets(p, project, home) -> bool:
    """Inside the project, or a temp directory (the recommended mandate's delete targets); a temp path under the home directory is not temp."""
    return _in_project(p, project) or temp_in(p, home)     # r0274: firmlink-insensitive, at / above the home too (bashparse.temp_in)


def _shadow_ok(sh) -> bool:
    return isinstance(sh, dict) and (sh.get("absent") is True or (isinstance(sh.get("sha256"), str) and len(sh["sha256"]) == 64))


def _outside_writes(c, project, home):
    """0.2.90: -> (paths written outside the project that the hook shadow-copied, {path: sha256 | "absent"}). Those paths leave c.writes
    (the delete part would refuse them RESOURCE) and join the line's commands as OUTSIDE_WRITE pseudo-commands. A guarded path (secret,
    persistence, the agent's or git's configuration) stays a write (judged as before); a path the hook could not copy is the danger
    `write-outside` (asked). Without a project nothing changes."""
    if project is None or not c.writes:
        return [], {}
    out, shadow, keep = [], {}, []
    asked = {d.split(":", 1)[1] for d in c.danger if isinstance(d, str) and d.split(":", 1)[0] == "agent-config"}
    for w in c.writes:
        if isinstance(w, str) and not _inside_targets(w, project, home) and is_agent_config_path(w) and w in asked \
                and not is_secret_path(w) and not is_persist_path(w) and not is_git_exec_path(w):
            continue                                # 0.2.91 (friction 04.11): the agent's configuration outside the project is the
            #                                         danger the line already carries (asked, the owner can approve); kept as a write it was
            #                                         refused RESOURCE first, with no button (`sed -i ~/.claude/tools/x.sh`, `~/.claude/CLAUDE.md`)
        if not isinstance(w, str) or _inside_targets(w, project, home) or is_secret_path(w) or is_persist_path(w) or is_agent_config_path(w) or is_git_exec_path(w):
            keep.append(w)
            continue
        if not under_home(w, home):                 # r0274: firmlink-insensitive (a home under /tmp is /private/tmp/... here)
            c.add("write-outside", w)               # outside the home directory (/etc, /usr, /Volumes): no shadow, asked
            continue
        sh = _fs.current().shadow(w)
        if sh is None:
            keep.append(w)                          # a fact round is pending (FactsFS) -- judged again with the answer
        elif _shadow_ok(sh):
            out.append(w)
            shadow[w] = sh.get("sha256") or "absent"
            c.head(OUTSIDE_WRITE + w)
        else:
            c.add("write-outside", w)               # 0.2.91: no copy (a directory, a file the hook may not look at): asked, never RESOURCE
    c.writes = keep
    return out, shadow
# 0.2.12 (R7-06): names a glob of Grep is tried against: a glob that would pick a credential file is a read of a secret
SECRET_SAMPLES = (".env", ".env.local", ".env.production", ".envrc", ".netrc", ".npmrc", ".pypirc", ".pgpass", ".git-credentials", "credentials",
                  "credentials.json", ".vault-token", "id_rsa", "id_ed25519", "id_ecdsa", "server.pem", "server.key", "cert.p12", "store.jks",
                  "db.kdbx", "secrets.yaml", "secrets.yml", "secret.json", "secrets.toml", "secrets.env", ".terraformrc")


def _read_like(tool, inp, args, cwd, home, key):
    p = inp.get(key)
    if not isinstance(p, str) or not p:
        raise Refuse("EVENT_MALFORMED")
    path = _abspath(p, cwd, home)
    if is_secret_path(path):
        via = _fs.current().note(path) if hasattr(_fs.current(), "note") else None      # 0.2.73 (N13): a hard link of it, by the fact samefile
        if isinstance(via, str) and via != path and os.path.dirname(via) == os.path.dirname(path):
            via = os.path.basename(via)
        # the credential's full path stays first in the detail (its prefix is what the page and the target of the refusal block name)
        args[RESERVED] = {"path": path, "danger": ["secrets:" + (path if not isinstance(via, str) or via == path else
                                                                 "%s (read as %s: a hard link of it, the same file)" % (path, via))]}
        return Mapped(tool + ".secret", args, "%s credential file" % tool)
    args[RESERVED] = {"path": path}
    return Mapped(tool, args, tool)


def _glob_hits_secret(g: str) -> bool:
    alts = [g]
    m = re.search(r"\{([^{}]*)\}", g)
    if m:                                           # ripgrep globs take one level of {a,b}
        alts = [g[:m.start()] + a + g[m.end():] for a in m.group(1).split(",")]
    for a in alts:
        last = a.rstrip("/").rsplit("/", 1)[-1]
        if is_secret_path(a) or any(fnmatch.fnmatchcase(n, last) for n in SECRET_SAMPLES) or re.search(r"(^|/)(\.ssh|\.aws|\.gnupg|\.kube|\.docker)(/|$)", a):
            return True
    return False


def _grep(inp, args, cwd, home):
    """0.2.12 (R7-06): Grep prints the lines it finds: grepping a credential file (`pattern: "."`, path .env) is reading it. A path or a glob
    that names one -> Grep.secret (asked, like Read.secret / `cat .env`); a search of a directory is `Grep` (pass): ripgrep skips hidden and
    git-ignored files unless told otherwise, and Claude Code's `Read(...)` deny rules also bind Grep (docs/internal/coverage.md 6)."""
    p, g = inp.get("path"), inp.get("glob")
    if (p is not None and not isinstance(p, str)) or (g is not None and not isinstance(g, str)):
        raise Refuse("EVENT_MALFORMED")
    path = _abspath(p, cwd, home) if p else cwd
    danger = []
    if is_secret_path(path) or (p and is_secret_path(p)):
        danger.append("secrets:" + path)
    if g and _glob_hits_secret(g):
        danger.append("secrets:%s/%s" % (path, g))
    args[RESERVED] = {"path": path, "danger": danger} if danger else {"path": path}
    return Mapped("Grep.secret" if danger else "Grep", args, "Grep credential file" if danger else "Grep")


# Default read-only commands of the recommended mandate (command.allow, PROPOSAL-06), 0.2.9: modelled on Claude Code's own read-only set.
# Deliberately NOT listed: find (-exec, -delete), xargs, sed (-i, `e`), awk (system()), env/printenv (print secrets), make, interpreters,
# package managers, curl/wget: they run other programs or code, write files or send data, so listing them would allow whatever they run.
# A listed name covers only the plain form: `./ls`, `LD_PRELOAD=x ls`, `xargs grep`, `git -c k=v status`, `git log --output=f`, `git branch new`,
# `rg --pre cmd`, `date -s` get another identifier ("<id> [<why>]", bashparse._variants) and are asked. Same list: server/app/toolmap.py
# CC_READONLY_COMMANDS and web/js/mandate_form.js READONLY_COMMANDS (a test keeps the three equal). docs/internal/coverage.md 6.2 explains each entry.
# 0.2.53: + 15 local writes (mkdir ... git rm, bashparse.LW_LIST): a listed name covers only the form whose every path is inside the project or a
# temp directory and not protected (bashparse._local_write); any other form is "<id> [outside|unsure|protected|recursive|dir|force]", asked.
# 0.2.54: + find, sed, awk, jq (the 0.2.9 note above is superseded): a listed name covers only the form that reads and prints (bashparse._tx);
# find -exec/-delete/-fprint, sed -i/e/w/r, awk system()/pipes/print >, jq -f ... are "<id> [exec|write|delete|read|outside|follow|unsure]",
# asked; sed -f / awk -f are opaque; jq env / $ENV and awk ENVIRON are the danger `secrets` (like printenv).
# 0.2.89 (friction 03.11): + 19 read-only diagnostics after jq; each covers only its read-only form (server bashparse._ro_tags / _ro_ident):
# `git remote add`, `git tag v1`, `git stash` / `pop`, `git config k v`, `pip list --outdated`, `uv pip install`, `ps eww` (environments)
# are other identifiers, asked; "--version" = `python3 --version`, `node --version` ... (bashparse.VERSION_QUERIES).
DEFAULT_SAFE_COMMANDS = ["ls", "pwd", "cd", "cat", "head", "tail", "wc", "echo", "grep", "rg", "which", "file", "stat", "du", "df",
                         "date", "uname", "git status", "git log", "git diff", "git show", "git branch", "diff", "tree", "sort",
                         "uniq", "cut", "tr", "nl", "column", "basename", "dirname", "realpath", "sha1sum", "sha256sum", "sha512sum",
                         "shasum", "cmp", "comm", "test", "sleep", "git blame", "git ls-files", "git rev-parse", "git describe",
                         "git shortlog", "git grep", "git reflog",
                         "mkdir", "touch", "cp", "mv", "ln", "chmod", "rm", "rmdir", "git add", "git commit", "git checkout",
                         "git switch", "git restore", "git mv", "git rm",
                         "find", "sed", "awk", "jq",
                         "ps", "lsof", "whoami", "id", "git remote", "git tag list", "git stash list", "git stash show", "git config get", "npm ls", "npm list",
                         "pip list", "pip3 list", "pip freeze", "pip3 freeze", "pip show", "pip3 show", "uv pip", "git check-ignore", "git ls-tree", "git rev-list", "git merge-base", "git show-ref",
                         "od", "hexdump", "strings", "xxd", "--version"]


# 0.2.56 (V3): command.sandboxed = "allow" in the RECOMMENDED form: a test runner (pytest, npm test, make ...) runs without a question only
# while the hook reports that THIS call runs inside a strict Claude Code sandbox (macOS Seatbelt, no network, secrets unreadable, no retry
# outside it: server/app/hookjudge/sandbox.py); without that sandbox every runner is asked as before. A mandate signed WITHOUT this key is
# never widened: the core allows OK_SANDBOXED only when the signed mandate says "allow" (svidetel_v4/decide.py). Same value: the Mandate
# page's recommended section (web/js/mandate_form.js RECOMMENDED_SANDBOXED); a test keeps them equal.
DEFAULT_SANDBOXED = "allow"
# 0.2.90 (FABLE-NOL 03.11, "standing mandate"): the RECOMMENDED form says `unlisted: "allow"`: every command runs with a receipt, and the
# owner is asked only at the four gates the witness itself names (G1 irreversible delete outside the project, G2 any non-loopback exit,
# G3 secrets, G4 persistence / the watchdog itself), at a changed executed file, and for what the classifier cannot read (opaque) outside
# a strict sandbox. Same value: the client's form.py and web/js/mandate_form.js (a test keeps them equal). A mandate signed with "ask" keeps asking.
DEFAULT_UNLISTED = "ask"
# 0.2.90 (QA 03.11 на 0e4f6f9, закон: лексический разбор проигрывает адаптивному противнику, точка принуждения -- ОС): the recommended form
# keeps `unlisted: "ask"`. "Allowed by default" is bought by the strict OS sandbox only: under a FRESH strict fact (hookjudge/sandbox.py,
# 0.2.88 fail-closed) the code option of the same form (SANDBOXED_CODE + sandboxed "allow", 0.2.82 allowances.code_cover) turns an
# unlisted line the sandbox contains into OK_SANDBOXED; without the fact every unlisted line is a question, as in 0.2.57 -- with the
# 0.2.58 gates, shadow copies, no freeze cascade and the person's systemMessage kept.
# 0.2.82 (irreversibility gate, decision 01.11): the mandate option "Code in Claude Code's strict sandbox: run without asking". The core's
# CDDL has no member for it (command = {allow, unlisted, sandboxed}) and the core is shared with the client's offline checker, so the option
# is this reserved ENTRY of the signed command.allow list: the owner signs it like any list entry, the page shows it as the option, the core
# only ever sees it as a list entry that names no command (the gateway refuses a command of that name: actions.py). It widens nothing
# alone: OK_SANDBOXED still needs command.sandboxed = "allow" in the same signed mandate. A mandate signed without it is never widened.
SANDBOXED_CODE = "(code in the strict sandbox)"
DEFAULT_SANDBOXED_CODE = True


class ProjectRefused(ValueError):
    """29.10 (RT-BASHRC-2910): '/', the home directory or a folder above it is not a project (the client's hook/form.py has the same)."""


def _expand(p: str, home=None) -> str:
    """A leading ~ names `home` when given (the hook's own HOME), else this process' ~."""
    if home and (p == "~" or p.startswith("~/")):
        return home + p[1:]
    return os.path.expanduser(p)


def refuse_reason(project_dir: str, home=None) -> str | None:
    """-> None when `project_dir` may be a project; else why not. Same rule and text as the client's hook/form.py refuse_reason."""
    proj = os.path.realpath(_expand(project_dir, home))
    try:
        h = os.path.realpath(home or os.path.expanduser("~"))
    except (OSError, ValueError):
        h = None
    if os.path.dirname(proj) == proj:
        what = "the root of the file system"
    elif h and proj == h:
        what = "your home directory"
    elif h and (h + os.sep).startswith(proj.rstrip(os.sep) + os.sep):
        what = "a folder that contains your home directory"
    else:
        return None
    return ("%s is %s, not a project: the recommended mandate lets the agent write anywhere inside the project, so it could rewrite "
            "~/.bashrc, ~/.ssh or LaunchAgents without asking. Run this from the project's own folder or name that folder."
            % (proj, what))


def _scratch_targets() -> list:
    """0.2.58 / 0.2.90: Claude Code's own scratch directory of this user (/private/tmp/claude-<uid>, /tmp/claude-<uid>: session files,
    task outputs) is a delete target of the recommended form too: the agent writes there on every session; under the old form every such
    write was refused RESOURCE (66 of 1045 calls of the owner's corpus). Nothing else under /tmp (shared) is added."""
    try:
        uid = os.getuid()
    except AttributeError:
        return []
    return ["/private/tmp/claude-%d/*" % uid, "/tmp/claude-%d/*" % uid]


def default_form(project_dir: str, web_domains=None, safe_commands=None, home=None) -> dict:
    """Recommended mandate form for a Claude Code agent (the 'default rules'):
      - writes (Write/Edit/NotebookEdit/Bash redirections) only inside the project and the temp dir; elsewhere deny RESOURCE;
      - shell commands: the listed read-only commands run, any other is asked (ESCALATE_COMMAND), a dangerous one is always asked
        (ESCALATE_COMMAND_DANGER); Read.secret: no publish permission -> defer ESCALATE_PUBLISH (owner approves);
      - WebFetch only to the listed domains; elsewhere deny RECIPIENT;
      - no purchases.
    29.10: raises ProjectRefused for '/', the home directory or a folder above it (see refuse_reason)."""
    why = refuse_reason(project_dir, home)
    if why:
        raise ProjectRefused(why)
    proj = os.path.realpath(_expand(project_dir, home))
    tmp = os.path.realpath(tempfile.gettempdir())
    scratch = _scratch_targets()
    return {"currency": "USD", "valid_days": 30, "purchase": None,
            "message": {"domains": list(DEFAULT_WEB_DOMAINS if web_domains is None else web_domains), "to": []},
            "forbidden_data": [], "publish": None,
            "delete": {"targets": [proj + "/*", tmp + "/*"] + scratch, "allow_irreversible": True},
            "command": {"allow": list(DEFAULT_SAFE_COMMANDS if safe_commands is None else safe_commands)
                                 + ([SANDBOXED_CODE] if DEFAULT_SANDBOXED_CODE else []), "unlisted": DEFAULT_UNLISTED,
                        "sandboxed": DEFAULT_SANDBOXED}}
