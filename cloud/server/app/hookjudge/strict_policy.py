"""11.11 (r0261, поворот метода Деуса): the STRICT sandbox decides by a CLOSED LIST of reasons.

Why (internal decision log, 11.11): four rounds of "be silent when ..." rules tuned on 7 dev sessions gave <= 2 questions
a day on them and 7-14 a day plus refusals of harmless work on sessions the rules had not seen. A list of exceptions to asking does not
generalise. Turned around: under a FRESH strict fact (hookjudge/sandbox.evaluate: Seatbelt, every credential path of ~ in denyRead,
network locked to a narrow list, no retry outside the sandbox, no excluded commands; freshness.py) a Bash line is

  REFUSED (Н, no question)  -- an immutable article of the Constitution (app/constitution.py, Н1-Н8; Н9 = actions.refused_like),
                               judged on what the line RUNS: an article whose words appear only in text the line writes or quotes (a
                               heredoc body, a quoted argument of an inert program) is a doubt -> asked (DOUBT), never refused;
  ASKED (С, narrow "from now on") -- one of the reasons of TABLE below, found on what the parser SEES;
  SILENT (OK_SANDBOXED, a row in the day's summary) -- everything else: code, tests, builds, installs, edits by any means, network reads,
                               secrets seen, writes to temp of any session, any module search path, a program the parser cannot see.

The table is the ONE place of the strict decision (actions._do_action calls verdict() and cover(); nothing else turns a strict line into
a question). Outside the strict fact nothing here applies: the 0.2.x rules judge the line as before (a separate mode).

What makes the silence safe (law 2: what the kernel holds is not a question): no network but the person's narrow list (a host outside it
is refused by the kernel); no credential of the person readable (keychain, browsers, CLI stores: CRED_SOURCES / SECRETS in denyRead), so
nothing can act in the person's NAME; no write outside the project and Claude Code's temp root; no run outside the sandbox
(allowUnsandboxedCommands false, excludedCommands empty). What it does NOT hold, and so stays on the list: what leaves the machine by the
person's own allowed hosts (PUBLISH), programs that hand work to something outside the sandbox (OUTSIDE), files inside the project that
other programs run later outside it (LATER), a loader that pulls code from a place the agent did not write (INJECT), the guard's own key
(WITNESS).

11.11 (r0261b, decisions of Deus on the r0261 report): (1) every article AND the data rule act on what RUNS or LEAVES: a literal an
edit-only inline program writes is text (_text_article, inline.inert_cut); a body that cannot be read is a doubt (asked, never refused);
a protected value on a line with no way out is asked (soften_data), not refused; `$(...)` in an unquoted heredoc body is judged as what
runs (heredoc_subs). (2) С6 IRREV: irreversible inside the project (git reset --hard, clean -f, whole-tree checkout / restore, stash drop /
clear, branch -D, rm -rf .git, DROP by a database CLI) -- asked with the kind as "from now on"; one named file reverted stays silent.
(3) Write / Edit under the code option: the same С3 as a shell write (write_cover).
"""
from __future__ import annotations

import json
import posixpath
import re
import shlex

# ---- the reason codes (also the question's words: app/qwords.py STRICT_WORDS; the recipient prefix of the asked part) ----------------
PUBLISH = "(strict publish) "      # С1 data or a change leaves this computer by a program that writes somewhere else
OUTSIDE = "(strict outside) "      # С2 a program that makes something OUTSIDE the sandbox act (browser, other apps, root)
LATER = "(strict later run) "      # С3 a file other programs run later, outside the sandbox (direnv, git hooks via husky, CI, editors, agent)
INJECT = "(strict inject) "        # С4 a loader variable that pulls code from a place outside the project and temp
WITNESS = "(strict witness) "      # С5 the guard's own key / settings
DOUBT = "(strict doubt) "          # an immutable article matched only in text the line writes or quotes: asked, not refused
IRREV = "(strict irreversible) "   # С6 (r0261b) irreversible INSIDE the project: git history / uncommitted work / a database dropped
DATA = "(strict data) "            # (r0261b) a protected value on a line with no way out: asked, not refused (the data rule acts on what LEAVES)
PREFIXES = (PUBLISH, OUTSIDE, LATER, INJECT, WITNESS, DOUBT, IRREV, DATA)

# The table: (code, Н/С, plain words what, plain words why) -- the readable form of the decision; the tests below each row are in
# tests/test_1111_zakrytyy_spisok.py. Н rows are app/constitution.py (unchanged articles, judged on what runs).
TABLE = (
    ("Н1 FORBIDDEN_SECRET_READ", "Н", "read a private key / token store / keychain / browser cookies", "identity theft; the kernel holds it too"),
    ("Н3 FORBIDDEN_GIT_HOOKS", "Н", ".git/hooks, core.hooksPath", "git runs it later outside the sandbox: the agent changes its own bounds"),
    ("Н3 FORBIDDEN_WITNESS_OFF", "Н", "the witness uninstalled, stopped, killed, its files deleted / replaced outside the project",
     "after it nothing is checked: the agent removes its own guard (r0333)"),
    ("Н4 FORBIDDEN_AUTOSTART", "Н", "rc files, LaunchAgents, cron, the agent's settings / hooks, .mcp.json, the witness", "the agent stays for good"),
    ("Н5 FORBIDDEN_WIPE", "Н", "rm -rf of ~, / or a folder above the project", "irreversible"),
    ("Н6 FORBIDDEN_REMOTE_SHELL", "Н", "download | shell, reverse shell, listener", "capture of the machine"),
    ("Н7 FORBIDDEN_HIDDEN_CHARS", "Н", "bidi / zero-width characters in what runs", "what the person reads is not what runs"),
    ("Н8 FORBIDDEN_FORCE_PUSH", "Н", "force-push, deleting a remote branch", "history destroyed"),
    ("Н10 FORBIDDEN_DEFENSE_OFF", "Н", "Gatekeeper / quarantine, SIP, TCC, firewall, SELinux / AppArmor, Defender switched off",
     "the OS's own guard removed: what runs next is not checked (r0305)"),
    (PUBLISH, "С", "git push, npm/yarn/pnpm/uv/twine/cargo/gem publish, gh writes, deploy CLIs, cloud CLIs that write, ssh/scp/rsync to "
                   "another machine, curl/wget/http with a method or a body to a host outside loopback, mail, payments",
     "leaves the computer by a host the person allowed; cannot be taken back"),
    (OUTSIDE, "С", "open, osascript, sudo / su / doas / pkexec, security add/delete/import",
     "hands the work to a program outside the sandbox (a browser runs a page with no sandbox)"),
    (LATER, "С", "writes (shell or a quoted path in interpreter code) to .envrc, .husky/, .githooks/, .pre-commit-config.yaml, .devcontainer/, "
                 ".vscode/{tasks,launch,settings}.json, .claude/{hooks,skills,commands,agents,settings*}, .mcp.json, CI files",
     "another program runs it later OUTSIDE the sandbox (a commit by the person, direnv, the editor, CI after a push, the agent's next session)"),
    (INJECT, "С", "LD_* / DYLD_* / NODE_OPTIONS --require|--import|--loader with a path outside the project and temp",
     "the line no longer says what runs; the code comes from a place the agent did not write"),
    (WITNESS, "С", "the witness's key / settings files, $DEUS_WITNESS_* in the line", "the guard's own key; the kernel holds the files, not "
                                                                                       "a variable a process may inherit"),
    (IRREV, "С", "git reset --hard, git clean -f, checkout / restore / switch --discard-changes of the whole tree, git stash drop / clear, "
                 "git branch -D, rm -rf .git, DROP TABLE / DATABASE / SCHEMA by sqlite3 / psql / mysql",
     "inside the project, but nothing brings it back (uncommitted work, history, a database); one named file reverted is silent"),
    (DOUBT, "С", "an article above matched only inside a heredoc body / a quoted argument, or in a body that cannot be read",
     "text written is not text run: never refused"),
    (DATA, "С", "a protected value (a token, a card, the person's literals) on a line with no network, publication or program that leaves",
     "the value stays on this computer; with a way out the data rule refuses as before"),
)

# ---- С1 publication ---------------------------------------------------------------------------------------------------------------------
GIT_PUBLISH = {"push", "send-email", "send-pack", "http-push", "imap-send", "request-pull", "svn", "p4", "daemon", "http-backend",
               "receive-pack", "upload-pack"}
GIT_LOCAL_KNOWN = {"status", "log", "diff", "show", "add", "commit", "checkout", "switch", "restore", "reset", "branch", "tag", "merge",
                   "rebase", "cherry-pick", "revert", "stash", "rm", "mv", "init", "config", "rev-parse", "rev-list", "describe", "blame",
                   "grep", "ls-files", "ls-tree", "cat-file", "worktree", "clean", "apply", "am", "format-patch", "bisect", "notes",
                   "shortlog", "reflog", "gc", "fsck", "archive", "bundle", "fetch", "pull", "clone", "ls-remote", "remote", "submodule",
                   "lfs", "credential", "sparse-checkout", "update-index", "hash-object", "for-each-ref", "symbolic-ref", "merge-base",
                   "name-rev", "var", "version", "help", "count-objects", "check-ignore", "check-attr", "whatchanged", "range-diff",
                   "difftool", "mergetool", "maintenance", "prune", "repack", "verify-commit", "verify-tag", "show-ref", "update-ref",
                   "read-tree", "write-tree", "commit-tree", "diff-tree", "diff-index", "diff-files", "mktree", "column", "stripspace"}
PKG_PUBLISH = {"publish", "unpublish", "deploy", "release", "upload", "push", "owner", "dist-tag", "login", "logout", "adduser", "token",
               "register", "yank", "deprecate", "access", "team", "org", "hook", "star", "unstar"}
PKG_FAMILY = {"npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "pipenv", "cargo", "gem", "mvn", "gradle", "dotnet", "nuget",
              "composer", "flit", "hatch", "deno", "swift", "mix", "hex", "cabal", "stack", "opam", "conda", "mamba", "micromamba", "brew"}
FORGE_CLI = {"gh", "glab", "hub", "tea"}
FETCH_PROGS = {"curl", "wget", "http", "https", "xh", "xhs", "httpie", "aria2c"}
REMOTE_PROGS = {"ssh", "scp", "sftp", "mosh", "telnet", "ftp", "tftp", "lftp", "smbclient", "rclone", "s3cmd", "nc", "ncat", "netcat",
                "socat", "websocat", "grpcurl", "mosquitto_pub", "ngrok", "cloudflared", "tailscale", "wireguard", "wg", "wg-quick", "openvpn",
                "mail", "mailx", "sendmail", "mutt", "msmtp", "twine",
                "stripe", "paypal", "bitcoin-cli", "lightning-cli", "lncli", "elements-cli", "solana", "spl-token", "cast", "near", "aptos",
                "sui", "seth", "electrum", "monero-wallet-cli", "cardano-cli", "litecoin-cli", "dogecoin-cli"}     # r0319: wallets (Б4)
DB_PROGS = {"psql", "mysql", "mongosh", "mongo", "sqlcmd", "redis-cli"}
# programs that talk to a remote service: a READ verb (first words that are not options) keeps them silent; anything else is a publication
CLOUD_READ = {
    "kubectl": {"get", "describe", "logs", "explain", "version", "api-resources", "api-versions", "top", "cluster-info", "config", "auth",
                "diff", "kustomize", "completion", "wait", "events"},
    "oc": {"get", "describe", "logs", "explain", "version", "whoami", "status", "project", "projects", "config"},
    "helm": {"list", "ls", "status", "get", "show", "template", "lint", "version", "search", "history", "dependency", "repo", "env",
             "verify", "completion"},
    "terraform": {"plan", "validate", "fmt", "show", "output", "version", "init", "graph", "providers", "console", "get", "state",
                  "workspace", "test", "metadata", "modules"},
    "tofu": {"plan", "validate", "fmt", "show", "output", "version", "init", "graph", "providers", "console", "get", "state", "workspace",
             "test"},
    "pulumi": {"preview", "stack", "config", "about", "version", "whoami", "logs", "plugin", "schema", "convert"},
    "docker": {"build", "run", "ps", "images", "image", "inspect", "logs", "pull", "compose", "exec", "start", "stop", "rm", "rmi", "version",
               "info", "network", "volume", "system", "container", "buildx", "tag", "create", "cp", "top", "stats", "kill", "restart",
               "context", "events", "history", "save", "load", "search", "port", "diff", "wait", "attach", "pause", "unpause", "builder"},
    "aws": set(), "gcloud": set(), "gsutil": {"ls", "cat", "du", "stat", "hash", "version", "help"}, "bq": {"ls", "show", "head", "version",
                                                                                                             "help"},
    "az": set(),
    "vercel": {"whoami", "list", "ls", "logs", "inspect", "env", "dev", "build", "pull", "link", "help", "--version", "-v", "domains",
               "certs", "projects", "teams", "switch"},
    "netlify": {"status", "whoami", "logs", "dev", "build", "help", "--version", "functions:list", "sites:list", "env:list", "open"},
    "heroku": {"apps", "logs", "ps", "config", "info", "whoami", "status", "help", "--version", "releases"},
    "fly": {"status", "logs", "apps", "list", "info", "version", "help", "auth", "doctor", "ips", "regions", "machines", "dashboard"},
    "flyctl": {"status", "logs", "apps", "list", "info", "version", "help", "auth", "doctor", "ips", "regions", "machines"},
    "firebase": {"projects:list", "apps:list", "login:list", "help", "--version", "emulators:start", "serve", "use", "target"},
    "wrangler": {"dev", "whoami", "tail", "types", "help", "--version", "-v", "login", "init", "build", "generate"},
    "supabase": {"start", "stop", "status", "init", "help", "--version", "gen", "db", "functions", "projects", "migration", "test"},
    "railway": {"status", "logs", "whoami", "list", "help", "--version", "run", "shell", "link"},
}
CLOUD_PUBLISH_SUB = {   # a READ verb that still writes when followed by these words
    "docker": {"push", "login"}, "terraform": {"apply", "destroy", "import", "taint", "untaint", "force-unlock", "push"},
    "tofu": {"apply", "destroy", "import", "taint", "untaint", "force-unlock"},
    "helm": {"install", "upgrade", "uninstall", "delete", "rollback", "push", "registry"},
    "pulumi": {"up", "update", "destroy", "import", "refresh", "cancel", "rm", "watch"},
    "supabase": {"push", "deploy", "link"}, "kubectl": {"apply", "delete", "create", "patch", "replace", "edit", "set", "scale",
                                                         "rollout", "label", "annotate", "expose", "run", "cp", "exec", "drain", "cordon",
                                                         "taint", "port-forward", "proxy"},
}
AWS_READ_OP = re.compile(r"^(?:describe|list|get|head|batch-get|lookup|search|scan|query|filter|preview|estimate|simulate|validate|test|"
                         r"detect|check|view)(?:-|$)|^(?:wait|help|ls|whoami|get-caller-identity)$")
GCLOUD_READ = {"list", "describe", "get", "get-iam-policy", "info", "version", "help", "read", "logs", "print-access-token", "show",
               "get-value", "configurations", "components", "config"}
AZ_READ = re.compile(r"^(?:show|list|get|version|find|query|check-name|exists|wait|help|login|account)$|^(?:list|show|get)-")
OUTSIDE_PROGS = {"open", "osascript", "sudo", "su", "doas", "pkexec", "xdg-open", "gio", "osacompile", "shortcuts", "automator"}
_LOOPBACK_HOST = re.compile(r"^(?:localhost|127(?:\.\d{1,3}){3}|::1|\[::1\]|0\.0\.0\.0)$", re.I)
_DB_REMOTE = re.compile(r"(?:(?:^|\s)(?:-h\s*|--host[= ]\s*)['\"]?(?!localhost\b|127\.|\[?::1|/)|://(?:[^/\s@]*@)?(?!localhost\b|127\.|\[?::1))", re.I)
_WRAPPERS = {"sudo", "env", "time", "nohup", "command", "exec", "nice", "timeout", "xargs", "caffeinate", "stdbuf", "builtin", "then", "do",
             "else", "!", "{", "(", "if", "while", "until"}
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# ---- С3 later run -----------------------------------------------------------------------------------------------------------------------
LATER_PATH = re.compile(
    r"(?:^|/)(?:\.envrc|\.husky(?:/|$)|\.githooks(?:/|$)|\.pre-commit-config\.ya?ml$|\.pre-commit-hooks\.ya?ml$|\.devcontainer(?:/|$)|"
    r"\.vscode/(?:tasks|launch|settings)\.json$|\.claude/(?:hooks|skills|commands|agents)(?:/|$)|\.claude/settings[^/]*\.json$|"
    r"\.mcp\.json$|\.github/workflows(?:/|$)|\.github/actions(?:/|$)|\.gitlab-ci\.ya?ml$|\.circleci(?:/|$)|\.buildkite(?:/|$)|"
    r"azure-pipelines\.ya?ml$|bitbucket-pipelines\.ya?ml$|\.travis\.ya?ml$|Jenkinsfile$|\.git/hooks(?:/|$)|\.cursor/(?:mcp|hooks)\.json$)",
    re.I)
# a quoted literal that IS such a path (not a sentence that mentions it): interpreter code writing it; the literal alone is enough (a
# doubt is a question, never a refusal)
_LATER_LITERAL = re.compile(
    r"""(?:(['"])(?:\./)?(?:[\w.@-]+/)*(?:\.envrc|\.husky(?:/[\w.@-]+)*|\.githooks(?:/[\w.@-]+)*|\.pre-commit-config\.ya?ml|"""
    r"""\.devcontainer(?:/[\w.@-]+)*|\.vscode/(?:tasks|launch|settings)\.json|\.claude/(?:hooks|skills|commands|agents)(?:/[\w.@-]+)*|"""
    r"""\.github/workflows(?:/[\w.@-]+)*|\.gitlab-ci\.ya?ml)/?\1)""",
    re.I)
# not in the literal list: .git/hooks, .git/config, .claude/settings*.json, .mcp.json -- code that writes them gets EPERM from Seatbelt's
# mandatory write deny (law 2, test_0611_zakon2); a write the parser SEES there is an article (Н3 / Н4)
# the same places named anywhere in a TEXT the agent wrote (a script that, run in the sandbox, writes them): the written-run gate keeps
# such a file held under the strict fact (execguard's G4 covers only places OUTSIDE the project: rc files, LaunchAgents ...)
_LATER_WORD = re.compile(r"(?<![\w.-])(?:\.envrc|\.husky/|\.githooks/|\.pre-commit-config\.ya?ml|\.devcontainer/|\.vscode/(?:tasks|launch|settings)\.json|"
                         r"\.claude/(?:hooks|skills|commands|agents)/|\.github/workflows/|\.gitlab-ci\.ya?ml)", re.I)


# r0261c (class (в)): the places the strict sandbox does NOT hold, as the hook names them (mcp/deus_witness/hook/heldwords.UNHELD, the same
# words). The hook now claims "held" when they stand only inside text (a heredoc body, a quoted argument); the witness accepts the claim
# only when they are gone from the text that RUNS (inline.runs_text: the literals edit-only code only writes cut). Else the K1 mark stays
# a question (as before: an old hook never claims it).
HOOK_UNHELD = re.compile(
    r"(?i)\.git[. ]*[/\\]+(?:modules|worktrees|info)(?![\w-])|config\.worktree|\.husky(?![\w-])|\.githooks(?![\w-])|"
    r"pre-commit-config|lefthook|\.envrc(?![\w.-])|\.devcontainer|\.claude[/\\]+(?:hooks|skills)(?![\w-])|"
    r"core\.hookspath|hookspath")


def held_claim_ok(cmd, heads) -> bool:
    if not isinstance(cmd, str):
        return False
    if not HOOK_UNHELD.search(cmd):
        return True
    from .inline import runs_text
    rt = runs_text(cmd, list(heads or []), spaced=True)    # a literal with a blank is a sentence here ('.envrc and .husky are not')
    return rt != cmd and not HOOK_UNHELD.search(rt)


def later_text(text) -> bool:
    return isinstance(text, str) and _LATER_WORD.search(text) is not None


# the literal is an argument of a call that writes / creates there (`open('.envrc','w')`, `os.makedirs('.husky')`, `fs.writeFileSync(`,
# `shutil.copy(x, '.github/workflows/ci.yml')`), or a pathlib object written right after (`Path('.envrc').write_text(..)`)
_WRITE_CALL = re.compile(r"(?:\bopen|write_text|write_bytes|writeFileSync|appendFileSync|createWriteStream|copyFileSync|copyfile|copy2?|"
                         r"copytree|move|rename|replace|symlink(?:_to)?|makedirs|mkdir(?:Sync)?|File\.write|IO\.write)\s*\([^()]{0,120}$")
_PATH_WRITE = re.compile(r"^\s*\)\s*(?:/\s*['\"][^'\"]*['\"]\s*)*\.(?:write_text|write_bytes|open|touch|mkdir|symlink_to)\b")
_INTERP = re.compile(r"^(?:python[0-9.]*|node|nodejs|deno|bun|ruby|perl|php|lua|Rscript|osascript|swift|tsx|ts-node|pwsh|julia)$")

# ---- С4 injection -----------------------------------------------------------------------------------------------------------------------
_INJECT_MARK = re.compile(r"^opaque:code injected through ((?:LD_[A-Z0-9_]+|DYLD_[A-Z0-9_]+|NODE_OPTIONS))=(.*?)(?: \(.*\))?$")

# ---- С5 the witness ---------------------------------------------------------------------------------------------------------------------
_WITNESS_PATH = re.compile(r"(?:^|/)\.deus-witness(?:/|$)|/\.config/deus-witness(?:/|$)|/Library/Application Support/deus-witness(?:/|$)|"
                           r"/\.local/share/deus-witness(?:/|$)|(?:^|/)agent-key\.json$", re.I)
_WITNESS_VAR = re.compile(r"\$\{?DEUS_WITNESS_KEY\b|\bprintenv\s+DEUS_WITNESS_KEY\b|\bCLAUDE_CODE_DISABLE_HOOKS\b|\bdisableAllHooks\b")
# the key read, or the guard switched off (a URL / caller variable for a child process changes nothing of the hook: silent). Judged on
# the line's skeleton (quoted text blanked: `grep -n "DEUS_WITNESS_KEY" x.py` names it, it does not read it); an expansion
# `$DEUS_WITNESS_KEY` also inside double quotes (the shell expands it there)
# (proby #38: `export CLAUDE_CODE_DISABLE_HOOKS=1` -- the hooks run in Claude Code's own process, a shell variable does not reach them;
#  but the line says it wants the guard off: the person is asked, never silent)


def _witness(args):
    w = args.get("_witness") if isinstance(args, dict) else None
    return w if isinstance(w, dict) else {}


def skeleton(text):
    from .sandbox import skeleton as _sk
    return _sk(text)


def _bare(text):
    """The line without heredoc bodies (quotes kept): what the shell parses. Unreadable -> the text itself (fail closed)."""
    try:
        from .bashparse import _normalize
        one, _docs, balanced, unsure = _normalize(text)
    except Exception:      # noqa: BLE001
        return text
    return one if balanced and unsure is None and isinstance(one, str) else text


# r0346 (cost, test_0217 longest line: r0345's download_runs parses the line once more): a part with no quote, no backslash and no blank
# other than space / tab / CR / LF splits the same with str.split() as with shlex.split(posix) (shlex's specials are the quotes and "\\"
# only; str.split's extra blanks \v \f \x1c-\x1f \x85 and the Unicode spaces are excluded here, so they still go through shlex).
_SHLEX_PLAIN = re.compile(r"[^'\"\\\s]*(?:[ \t\r\n]+[^'\"\\\s]*)*")


def _segments(text):
    """Lenient argv of every simple command of the line (heredoc bodies cut, `$(` / backticks / `;|&` split), wrappers and leading
    assignments dropped. For VERB detection only: a segment that cannot be read is returned as its whitespace words (fail closed: an
    unknown verb is a publication)."""
    one = _bare(text) if isinstance(text, str) else ""
    out = []
    for part in _split_unquoted(one):
        part = part.strip()
        if not part:
            continue
        if _SHLEX_PLAIN.fullmatch(part):
            argv = part.split()                       # r0346 (cost): no quote, no backslash, only ' \t\r\n' as blanks -- shlex's own answer
        else:
            try:
                argv = shlex.split(part, posix=True)
            except ValueError:
                argv = part.split()
        k = 0
        while k < len(argv) and (argv[k] in _WRAPPERS or _ASSIGN.match(argv[k])):
            k += 1                                    # r0346 (cost): one slice, not one per word (`{ { { ...` was quadratic)
        if k < len(argv):
            out.append(argv[k:] if k else argv)
    return out


_SPLIT_PLAIN = re.compile(r"\$\(|[;|&\n()`]")


def _split_unquoted(one):
    """split on `;` `|` `&` newline `(` `)` `$(` and backticks OUTSIDE quotes (a `|` inside a quoted grep pattern is text)"""
    if "'" not in one and '"' not in one and "\\" not in one:
        return _SPLIT_PLAIN.split(one)                # r0346 (cost): no quote, no escape -- the walk below gives exactly this
    parts, cur, q, i = [], [], None, 0
    while i < len(one):
        ch = one[i]
        if q:
            cur.append(ch)
            if ch == "\\" and q == '"' and i + 1 < len(one):
                cur.append(one[i + 1])
                i += 2
                continue
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
            cur.append(ch)
        elif ch == "\\" and i + 1 < len(one):
            cur.append(one[i:i + 2])
            i += 2
            continue
        elif ch in ";|&\n()`" or (ch == "$" and one[i + 1:i + 2] == "("):
            parts.append("".join(cur))
            cur = []
            if ch == "$":
                i += 1
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def _base(word):
    return word.rsplit("/", 1)[-1].lower() if isinstance(word, str) else ""


def _verbs(argv, n=3):
    """the first n words after the program that are not options (and not an option's value we know takes one)."""
    out, skip = [], False
    for a in argv[1:]:
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            if a in ("-n", "--namespace", "-C", "--context", "--profile", "--region", "-p", "--project", "--chdir", "-R", "--repo",
                     "--output", "-o", "-f", "--file", "--config", "--app", "-a", "--subscription", "-g", "--resource-group"):
                skip = True
            continue
        out.append(a)
        if len(out) >= n:
            break
    return out


def _cloud_publishes(argv):
    prog = _base(argv[0])
    v = _verbs(argv)
    if prog == "aws":
        if len(v) >= 2 and v[0] == "s3":
            if v[1] in ("ls", "presign"):
                return False
            if v[1] in ("cp", "sync", "mv"):
                dests = [a for a in argv[3:] if not a.startswith("-")]
                return bool(dests) and dests[-1].startswith("s3://")
            return True
        return not (len(v) >= 2 and AWS_READ_OP.search(v[1]) or (v and v[0] in ("help", "--version", "configure") and
                                                                  (len(v) < 2 or v[1] in ("list", "get"))))
    if prog == "gcloud":
        return not any(x in GCLOUD_READ for x in v)
    if prog == "az":
        return not any(AZ_READ.search(x) for x in v)
    if prog == "gsutil":
        if v and v[0] in ("cp", "rsync", "mv"):
            dests = [a for a in argv[2:] if not a.startswith("-")]
            return bool(dests) and dests[-1].startswith("gs://")
        return not (v and v[0] in CLOUD_READ["gsutil"])
    reads = CLOUD_READ.get(prog)
    if reads is None:
        return True
    if not v:
        return prog in ("vercel", "netlify", "fly", "flyctl", "railway", "firebase")     # `vercel` alone deploys
    pub = CLOUD_PUBLISH_SUB.get(prog, set())
    if any(x in pub for x in v):
        if prog == "docker" and v[0] in ("buildx", "build") and "--push" not in argv and v[1:2] != ["push"]:
            pass
        else:
            return True
    if prog in ("docker", "podman", "nerdctl") and "--push" in argv:
        return True
    return v[0] not in reads


def publish_reasons(w, text):
    """-> [target] for every program of the line that the parser SEES and that writes outside this computer."""
    from . import sandbox as hsb
    heads = [h for h in (w.get("commands") or []) if isinstance(h, str)]
    nr = hsb.net_read_line(text) if isinstance(text, str) else None
    rheads = nr["heads"] if nr is not None else set()
    sk = skeleton(text) if isinstance(text, str) else ""
    segs = _segments(text)
    out = []
    by_prog = {}
    for a in segs:
        by_prog.setdefault(_base(a[0]), []).append(a)
    # a program the parser cannot see (`read C; $C push`, `f() { npm publish; }; f`) with a publication word on the line: asked
    # (sandbox.code_line_ok since d80633d); without the word it is code like any other (credentials closed, the kernel holds the network)
    cm_ = hsb.code_only(w)[0]
    hid = [d for d in (w.get("danger") or []) if isinstance(d, str) and d not in cm_ and hsb.HIDES_PROGRAM.match(d)
           and not hsb._interp_var(d, text)]
    if hid and hsb.PUBLISH_WORD.search(sk):
        out.append("a program hidden in the line, next to the word %r" % hsb.PUBLISH_WORD.search(sk).group(0))
    for h in heads:
        if h in rheads:
            continue
        ws = h.split(" ")
        base = _base(ws[0])
        sub = ws[1] if len(ws) > 1 and not ws[1].startswith("[") else None
        if base == "git":
            if sub in GIT_PUBLISH or (sub == "lfs" and re.search(r"\blfs\s+push\b", sk)) or \
                    (sub not in GIT_LOCAL_KNOWN and hsb.PUBLISH_TEXT.search(sk)):
                out.append(h)
            continue
        if base in PKG_FAMILY:
            if sub in PKG_PUBLISH:
                out.append(h)
            continue
        if re.fullmatch(r"python[0-9.]*", base) and len(ws) >= 3 and ws[1] == "-m" and ws[2].split("[")[0] in ("twine", "smtpd"):
            out.append(h)
            continue
        if base in FORGE_CLI:
            # a read of gh (net_read_line above, or each gh command of the line read one by one: `export GH_CONFIG_DIR=..; gh run list`)
            ga = by_prog.get(base) or []
            if base == "gh" and ga and all(hsb._gh_read(a) or (len(a) >= 2 and a[1] in ("--version", "version", "help", "--help")) or
                                           a[1:3] == ["auth", "status"] for a in ga):
                continue
            out.append(h)                                  # anything else writes in the forge
            continue
        if base in FETCH_PROGS:
            hosts = [n.rsplit("@", 1)[-1] for n in (w.get("net") or []) if isinstance(n, str)]
            if hosts and all(_LOOPBACK_HOST.match(x.strip("[]")) for x in hosts) and isinstance(text, str) and \
                    not any(hsb.FETCH_INDIRECT.search(x) for x in hsb.fetch_texts(text)):
                continue                                   # a loopback request: the kernel refuses it anyway, nothing leaves (unless a
                #                                            config file / --connect-to / --resolve / a proxy can bring another host)
            out.append(_with_hosts(h, w, by_prog.get(base)))
            continue
        if base == "rsync":
            if h != hsb.RSYNC_PLAIN_HEAD:
                out.append(h)
            continue
        if base in REMOTE_PROGS:
            if base == "twine" and any(_verbs(a)[:1] == ["check"] for a in by_prog.get("twine", [])):
                continue
            out.append(_with_hosts(h, w, by_prog.get(base)))
            continue
        if base in DB_PROGS:
            if _DB_REMOTE.search(text or ""):
                out.append(h)
            continue
        if base in CLOUD_READ or base in ("podman", "nerdctl"):
            argvs = by_prog.get(base) or by_prog.get("docker" if base in ("podman", "nerdctl") else base) or []
            if not argvs or any(_cloud_publishes(a if _base(a[0]) != base or base not in ("podman", "nerdctl") else ["docker"] + a[1:])
                                for a in argvs):
                out.append(h)
            continue
    # backstop on the TEXT that runs (heredoc bodies cut, `$(` / `;` / `|` split): a part of the line the parser could not read hides the
    # rest from its heads (friction stand real #970: `until s=$(gh run view ..); ...; ssh vps "docker exec .." < x.py`; #342: a token
    # from a file in a curl header). Every simple command whose program writes outside is asked, read or not by the parser.
    if not out:
        for a in segs:
            t = _seg_publishes(a, w)
            if t:
                out.append(t)
                break
    return out


_FETCH_WRITE = re.compile(r"^(?:-d|--data(?:-\w+)?|-F|--form(?:-string)?|-T|--upload-file|--post-data|--post-file|--body-data|--body-file|"
                          r"--method|-X(?!GET$|HEAD$)\S*|--request)(?:=|$)")


def _with_hosts(h, w, argvs=None):
    """a publication target names its hosts, so that "from now on" is this program to these hosts, not the program anywhere"""
    hs = _hosts_of(w, (argvs or [None])[0])
    return "%s -> %s" % (h, ",".join(hs[:4])) if hs else h


def _seg_publishes(a, w):
    """one lenient argv (_segments): the program it names, when it writes outside this computer; else None."""
    from . import sandbox as hsb
    base = _base(a[0])
    v = _verbs(a)
    if base == "git":
        return "git " + v[0] if v and v[0] in GIT_PUBLISH else None
    if base in PKG_FAMILY:
        return "%s %s" % (base, v[0]) if v and v[0] in PKG_PUBLISH else None
    if base in FORGE_CLI:
        return None if base == "gh" and (hsb._gh_read(a) or v[:1] in (["version"], ["help"]) or v[:2] == ["auth", "status"]) else base
    if base in FETCH_PROGS:
        x = a[1:]
        cred = any(t in ("-u", "--user", "-b", "--cookie", "--oauth2-bearer", "-E", "--cert", "-K", "--config") or
                   t.startswith(("--user=", "--cookie=", "--oauth2-bearer=", "-K", "--config=")) for t in x) or \
            any(x[k] in ("-H", "--header") and k + 1 < len(x) and re.search(r"[$@`]|authorization|token|cookie", x[k + 1], re.I)
                for k in range(len(x)))
        if cred or any(_FETCH_WRITE.match(t) for t in x) or (base in ("http", "https", "xh", "xhs") and v and v[0].upper() in
                                                            ("POST", "PUT", "PATCH", "DELETE")):
            urls = [t for t in x if "://" in t or re.match(r"^[\w.-]+(?::\d+)?/", t)]
            if urls and all(_LOOPBACK_HOST.match((hsb.url_host(u) or re.split(r"[:/]", u.split("://")[-1])[0]).strip("[]")) for u in urls):
                return None
            return _with_hosts(base, w, [a])
        return None
    if base in REMOTE_PROGS:
        return None if base == "twine" and v[:1] == ["check"] else _with_hosts(base, w, [a])
    if base == "rsync":
        return "rsync" if any(re.match(r"^(?:[\w.-]+@)?[\w.-]+:(?!/)|^(?:[\w.-]+@)?[\w.-]+:/", t) for t in a[1:] if not t.startswith("-")) \
            else None
    if base in OUTSIDE_PROGS:
        return None                                   # С2, judged by outside_reasons on the parser's heads
    if base in CLOUD_READ or base in ("podman", "nerdctl"):
        return base if _cloud_publishes(a if base not in ("podman", "nerdctl") else ["docker"] + a[1:]) else None
    return None


def outside_reasons(w, text):
    heads = [h for h in (w.get("commands") or []) if isinstance(h, str)]
    out = [h for h in heads if _base(h.split(" ")[0]) in OUTSIDE_PROGS]
    for a in _segments(text):
        if _base(a[0]) == "security" and len(a) > 1 and re.match(r"^(?:add|delete|import|set|create|unlock|default|login)-?", a[1]):
            out.append("security " + a[1])
    return out


def later_reasons(w, text, project):
    out = []
    for p in w.get("writes") or []:
        if isinstance(p, str) and LATER_PATH.search(p):
            out.append(p)
    for d in w.get("danger") or []:
        if isinstance(d, str) and d.startswith("agent-config:") and d != w.get("harness_held"):     # held: Seatbelt refuses the place
            p = d[len("agent-config:"):]
            hook_ = p.startswith("(hook) ")
            p = p[len("(hook) "):] if hook_ else p
            if hook_ and p not in out:
                # r0261c (в): the hook's K1 word that the witness does NOT count as held (no claim, or a claim the text that runs
                # disproves: strict_policy.held_claim_ok) -- the place may be one the sandbox does not hold: asked, never silent
                out.append(p)
            elif LATER_PATH.search(p) and p not in out and _writes_line(w, text):
                out.append(p)
    heads = [_base(h.split(" ")[0]) for h in (w.get("commands") or []) if isinstance(h, str)]
    if isinstance(text, str) and any(_INTERP.match(h) for h in heads):
        for m in _LATER_LITERAL.finditer(text):
            if not _WRITE_CALL.search(text[max(0, m.start() - 160):m.start()]) and \
                    not _PATH_WRITE.match(text[m.end():m.end() + 160]):
                continue                              # a literal in a test, a list, a message: text, not a write
            lit = m.group(0)[1:-1]
            ab = lit if lit.startswith("/") else posixpath.normpath(posixpath.join(project or "/", lit))
            if ab not in out:
                out.append(ab)
    return out


_READERS = {"cat", "head", "tail", "less", "more", "grep", "rg", "ls", "stat", "wc", "file", "jq", "diff", "bat", "find", "tree", "test", "["}


def _writes_line(w, text):
    """an agent-config mark of a line whose programs only READ (cat .claude/settings.json) is no write."""
    heads = {_base(h.split(" ")[0]) for h in (w.get("commands") or []) if isinstance(h, str)}
    return not (heads and heads <= _READERS and not (w.get("writes") or []))


def _in(p, root):
    return isinstance(root, str) and root.startswith("/") and (p == root or p.startswith(root.rstrip("/") + "/"))


def inject_reasons(w, project):
    out = []
    cwd = w.get("cwd") if isinstance(w.get("cwd"), str) and w.get("cwd").startswith("/") else project
    for d in w.get("danger") or []:
        m = _INJECT_MARK.match(d) if isinstance(d, str) else None
        if not m:
            continue
        var, val = m.group(1), m.group(2)
        paths = re.findall(r"(?:^|[\s=:])((?:~|\$HOME|\$\{HOME\}|/)[^\s:'\"]*)", val)
        # a relative path that climbs out (`--require ../n.js`): taken from the line's folder
        paths += [posixpath.normpath(posixpath.join(cwd or "/", r)) for r in re.findall(r"(?:^|[\s=:])(\.\.(?:/[^\s:'\"]*)?)", val)]
        if var == "NODE_OPTIONS" and not re.search(r"--(?:require|import|(?:experimental-)?loader)|(?:^|\s)-r\b", val):
            continue
        from .sandbox import CLAUDE_TMP
        bad = [p for p in paths if not ((_in(posixpath.normpath(p), project)) or
                                        (p.startswith("/") and CLAUDE_TMP.match(posixpath.normpath(p) + "/")))]   # Claude Code's temp root
        if bad or (not paths and re.search(r"[$`]", val)):
            out.append("%s=%s" % (var, val[:120]))
    return out


def witness_reasons(w, text):
    from app.constitution import _LOOK_ONLY
    out = []
    heads0 = {_base(h.split(" ")[0]) for h in (w.get("commands") or []) if isinstance(h, str)}
    look = bool(heads0) and heads0 <= _LOOK_ONLY      # `ls ~/.config/deus-witness/`: names in a folder, no key (as Н1's look-only rule)
    for d in ([] if look else (w.get("danger") or [])):
        if isinstance(d, str) and d.startswith("secrets:"):
            p = d[len("secrets:"):].split(" (read as ", 1)[0]
            if _WITNESS_PATH.search(p) and not re.search(r"deus-witness/?$", p):
                out.append(p)                         # a file of the witness (the folder itself: `ls` of names, no key)
    for p in w.get("writes") or []:
        if isinstance(p, str) and _WITNESS_PATH.search(p) and p not in out:
            out.append(p)
    if isinstance(text, str):
        m = _WITNESS_VAR.search(skeleton(text)) or re.search(r'"[^"]*(\$\{?DEUS_WITNESS_KEY)\b', _bare(text))
        if m:
            out.append(re.sub(r"^.*?((?:DEUS_WITNESS|CLAUDE_CODE_DISABLE_HOOKS|disableAllHooks)[A-Za-z_]*).*$", r"\1", m.group(0), flags=re.S))
    return out


# ---- С6 irreversible inside the project (r0261b) -----------------------------------------------------------------------------------------
_GIT_GLOBAL_VAL = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}
_WHOLE_TREE = re.compile(r"^(?:\.|\./|:/|:/\*|:\(top\).*|\*)$|/$|[*?\[]")
_DROP = re.compile(r"(?i)\bdrop\s+(table|database|schema)\b")
_DB_CLI = {"sqlite3", "sqlite", "psql", "mysql", "mariadb", "duckdb", "cockroach", "clickhouse-client", "pgcli", "mycli", "litecli"}


def _git_sub(a):
    """git argv -> (sub-command, its words) with git's own options skipped (`git -C dir -c k=v reset --hard`)."""
    i = 1
    while i < len(a):
        x = a[i]
        if x in _GIT_GLOBAL_VAL:
            i += 2
            continue
        if x.startswith("-"):
            i += 1
            continue
        return x, a[i + 1:]
    return None, []


def _short(rest, ch):
    """a short option letter in any combined form (`-fdx`, `-df`), before `--`"""
    for x in rest:
        if x == "--":
            return False
        if re.match(r"^-[A-Za-z]+$", x) and ch in x[1:]:
            return True
    return False


def _paths(rest):
    if "--" in rest:
        return rest[rest.index("--") + 1:]
    return [x for x in rest if not x.startswith("-")]


def _git_irrev(a):
    sub, rest = _git_sub(a)
    if sub == "reset" and "--hard" in rest:
        return "git reset --hard"
    if sub == "clean" and (_short(rest, "f") or "--force" in rest) and not (_short(rest, "n") or "--dry-run" in rest):
        return "git clean -f"
    if sub == "checkout":
        if "-f" in rest or "--force" in rest:
            return "git checkout ."
        if any(_WHOLE_TREE.search(x) for x in _paths(rest)):
            return "git checkout ."                   # `.`, `:/`, a folder `src/`, a glob: the whole tree (one named file: silent)
        return None
    if sub == "restore":
        staged = "--staged" in rest or _short(rest, "S")
        worktree = "--worktree" in rest or _short(rest, "W")
        if staged and not worktree:
            return None                               # only the index: the work is still in the files
        if any(_WHOLE_TREE.search(x) for x in _paths(rest)):
            return "git restore ."
        return None
    if sub == "switch" and ("--discard-changes" in rest or "-f" in rest or "--force" in rest):
        return "git switch --discard-changes"
    if sub == "stash" and rest[:1] in (["drop"], ["clear"]):
        return "git stash " + rest[0]
    if sub == "branch" and ("-D" in rest or (("--delete" in rest or _short(rest, "d")) and ("--force" in rest or _short(rest, "f")))):
        return "git branch -D"
    return None


def _dot_git(p):
    return isinstance(p, str) and posixpath.basename(posixpath.normpath(p)) == ".git"


def irreversible_reasons(w, text):
    """С6 (r0261b): -> [kind] for every act of the line that destroys what nothing brings back INSIDE the project (the kernel lets the
    project be written: uncommitted work, git's history, a local database). The kind is the narrow "from now on" (this project)."""
    out = []
    segs = _segments(text) if isinstance(text, str) else []
    for a in segs:
        base = _base(a[0])
        k = None
        if base == "git":
            k = _git_irrev(a)
        elif base == "rm" and any(_dot_git(x) for x in a[1:] if not x.startswith("-")):
            k = "rm -rf .git"
        if k and k not in out:
            out.append(k)
    for d in w.get("danger") or []:
        if isinstance(d, str) and d.startswith("rm-rf:"):
            t = d[len("rm-rf:"):].strip()
            m = re.match(r"^\w[\w.]*\((.*)\)$", t)
            if _dot_git(m.group(1) if m else t) and "rm -rf .git" not in out:
                out.append("rm -rf .git")
    if isinstance(text, str) and any(_base(a[0]) in _DB_CLI for a in segs):
        for m in _DROP.finditer(text):
            k = "DROP " + m.group(1).upper()
            if k not in out:
                out.append(k)
    return out


# ---- an unquoted heredoc body: the shell runs its $(...) / `...` before the program reads it (r0261b) ---------------------------------
def heredoc_subs(text):
    """-> the commands inside $(...) / `...` of every UNQUOTED heredoc body of the line ([] when none or the line cannot be read)."""
    if not isinstance(text, str) or ("$(" not in text and "`" not in text):
        return []
    try:
        from .bashparse import _normalize
        _one, docs, _bal, _uns = _normalize(text)
    except Exception:      # noqa: BLE001
        return []
    out = []
    for d in docs or []:
        if not (isinstance(d, (tuple, list)) and len(d) >= 3) or d[2] or not isinstance(d[1], str):
            continue
        body = d[1]
        i = 0
        while i < len(body):
            if body.startswith("$(", i) and not body.startswith("$((", i):
                depth, j = 1, i + 2
                while j < len(body) and depth:
                    depth += {"(": 1, ")": -1}.get(body[j], 0)
                    j += 1
                out.append(body[i + 2:j - 1] if not depth else body[i + 2:])
                i = j
            elif body[i] == "`":
                j = body.find("`", i + 1)
                out.append(body[i + 1:] if j < 0 else body[i + 1:j])
                i = len(body) if j < 0 else j + 1
            else:
                i += 1
    return [x for x in out if x.strip()][:16]


def _reparse(tool, args, t):
    """The immutable article of the line text `t` judged by THIS server's parser with the witness's place (cwd, home, project): a mark the
    hook's witness carries and the parser makes again. -> (code, detail) | None; raises on any doubt (the caller keeps what it had)."""
    from app import constitution
    from . import bashparse
    w = _witness(args)
    project = w.get("project") if isinstance(w.get("project"), str) and w.get("project").startswith("/") else None
    cwd = w.get("cwd") if isinstance(w.get("cwd"), str) and w.get("cwd").startswith("/") else project
    home = next((h for h in (w.get("sbx_home"), w.get("home")) if isinstance(h, str) and h.startswith("/")), None)
    if cwd is None or home is None:
        raise ValueError("no place")
    c = bashparse.classify(t, cwd, home, project=project)
    keep = [d for d in (w.get("danger") or []) if isinstance(d, str) and d.startswith("agent-config:")]
    w2 = dict(w, danger=list(c.danger) + [d for d in keep if d not in c.danger], writes=list(c.writes), commands=list(c.heads),
              deletes=[d for d in c.deletes if d in c.writes])
    a2 = dict(args, command=t, _witness=w2)
    nz = constitution.check(tool, a2)
    if nz is None:
        wp = _wipe_of_project(w2, t)
        if wp is not None:
            nz = (constitution.WIPE, wp)
    return nz


def _text_article(tool, args, nz):
    """r0261b: an immutable article found only in TEXT an edit-only inline program writes (a quoted heredoc fed to python3 / cat / tee,
    `python3 -c` with no exec / system / subprocess) is no act: None. Found only in a body that cannot be read (cut, broken), or on a
    line where another program may run what was written: a doubt (asked). Anything else (the article on what runs, a mark this
    parser does not make again, a line it cannot cut): the article, unchanged."""
    from . import inline
    text = args.get("command")
    ic = inline.inert_cut(text, _witness(args))
    if ic is None:
        return nz
    cut, unread, other = ic
    try:
        full = _reparse(tool, args, text)
        part = _reparse(tool, args, cut)
    except Exception:      # noqa: BLE001
        return nz
    if full is None or full[0] != nz[0] or (part is not None and part[0] == nz[0]):
        return nz
    return ("DOUBT", nz[1]) if (unread or other) else None


TEXT_ARTICLES = ("FORBIDDEN_REMOTE_SHELL", "FORBIDDEN_HIDDEN_CHARS", "FORBIDDEN_GIT_HOOKS")


def written_run_texts(args):
    """r0261c (class (г), decision of Deus): the TEXT this line writes into a file (a `cat > f` / `tee f` heredoc body, the strings of
    edit-only inline Python) when a program of the SAME line runs a file it writes (`bash x.sh`, `./x.sh`, `python3 x.py`). That text
    runs: Н5 in it is refused, С6 asked, as if it stood on the line. [] otherwise (text written and not run stays text)."""
    from . import inline
    text = args.get("command") if isinstance(args, dict) else None
    if not isinstance(text, str):
        return []
    texts, targets = inline.written_texts(text)
    if not texts or not inline.runs_written(text, [p for p in (_witness(args).get("writes") or []) if isinstance(p, str)] + targets):
        return []
    return texts


def _cds(text):
    return ["cd " + shlex.quote(a[1]) for a in _segments(text) if a[0] == "cd" and len(a) >= 2]


def _written_run_wipe(tool, args):
    from app import constitution
    texts = written_run_texts(args)
    if not texts:
        return None
    cds = _cds(args["command"])
    for t in texts:
        for synth in ([" && ".join(cds + [t])] if cds else []) + [t]:
            try:
                ns = _reparse(tool, args, synth)
            except Exception:      # noqa: BLE001
                return ("DOUBT", "a file written and run on this line: " + t[:120])
            if ns is not None and ns[0] == constitution.WIPE:
                return ns
    return None


def article(tool, args):
    """r0261c (г): what _article finds, and when that is nothing or a doubt, a wipe in the text of a file written and run on this line."""
    nz = _article(tool, args)
    if (nz is None or nz[0] == "DOUBT") and isinstance(args, dict) and isinstance(args.get("command"), str):
        wp = _written_run_wipe(tool, args)
        if wp is not None:
            return wp
    return nz


def _article(tool, args):
    """Н under the strict fact: app/constitution.check, judged on what the line RUNS. -> (code, detail) | ("DOUBT", detail) | None.
    An article whose regex matched the raw text but not the line with heredoc bodies cut and quoted text blanked (and no write target /
    mark of the witness carries it) is a doubt: asked, never refused (text the code writes is no act)."""
    from app import constitution
    nz = constitution.check(tool, args)
    if nz is None:
        wp = _wipe_of_project(_witness(args), args.get("command"))
        if wp is not None:
            nz = (constitution.WIPE, wp)
    if nz is None and isinstance(args.get("command"), str):
        for sub in heredoc_subs(args["command"]):      # r0261b: `<<EOF ... $(rm -rf ..) ...`: the shell runs it before the program reads
            try:
                ns = _reparse(tool, args, sub)
            except Exception:      # noqa: BLE001
                return ("DOUBT", "a command substitution in a heredoc body: " + sub[:120])
            if ns is not None:
                return ns
    if nz is not None and nz[0] not in TEXT_ARTICLES and isinstance(args.get("command"), str):
        return _text_article(tool, args, nz)          # r0261b: every article judged on what runs, not on text written
    if nz is None or nz[0] not in TEXT_ARTICLES or not isinstance(args.get("command"), str):
        return nz
    w = _witness(args)
    if nz[0] == "FORBIDDEN_GIT_HOOKS" and (any(isinstance(p, str) and constitution._GIT_HOOKS.search(p) for p in w.get("writes") or [])
                                          or any(isinstance(d, str) and d.startswith("git-config:") for d in w.get("danger") or [])):
        return nz                                     # a write / a git config the parser SEES
    sk = skeleton(args["command"])
    if sk == args["command"]:
        return nz                                     # nothing quoted / no heredoc: the article is on what runs
    a2 = dict(args, command=sk)
    nz2 = constitution.check(tool, a2)
    if nz2 is not None and nz2[0] == nz[0]:
        return nz
    from .sandbox import INERT_HEADS
    heads = [_base(h.split(" ")[0]) for h in (w.get("commands") or []) if isinstance(h, str)]
    if heads and all(h in INERT_HEADS and h not in ("sed", "awk", "find") for h in heads) and \
            not any(re.search(r"\[(?:exec|via|eval|-c)", h) for h in (w.get("commands") or []) if isinstance(h, str)):
        return None                                   # `echo '...' > notes.md`, `cat > doc.md <<EOF`: only text is written
    return ("DOUBT", nz[1])                           # code may run it (python -c, bash -c): the kernel holds it, the person decides


def _wipe_of_project(w, text=None):
    """Н5 on what the parser resolved: a recursive delete whose target, taken from the line's cwd, is the project, a folder that contains
    it, or the project's whole content (`./*`, `<project>/*`). constitution._wipe_target reads only an absolute mark; under the strict
    fact everything else of the project is silent, so a relative `rm -rf ..` / `rm -rf ./*` must be caught here (in temp too: a project
    that lives in Claude Code's temp root is still the person's project)."""
    project = w.get("project") if isinstance(w.get("project"), str) and w.get("project").startswith("/") else None
    cwd = w.get("cwd") if isinstance(w.get("cwd"), str) and w.get("cwd").startswith("/") else project
    if project is None:
        return None
    heads = {_base(h.split(" ")[0]) for h in (w.get("commands") or []) if isinstance(h, str)}
    # the parser's delete targets: an `rm` names them; a `find` lists the ROOT it may empty there -- counted only when that root is the
    # project itself (`find <project> -name '*' -delete`; a filtered find of a folder above the project keeps its mark, judged below)
    pr0 = posixpath.normpath(project)
    cands = [p for p in (w.get("deletes") or []) if isinstance(p, str) and ("find" not in heads or posixpath.normpath(p) == pr0)]
    for d in w.get("danger") or []:
        if isinstance(d, str) and d.startswith("rm-rf:"):
            t = d[len("rm-rf:"):].strip()
            mf = re.match(r"^find (\S+)$", t)          # `find <root> -delete` with no filter: the whole root
            mc = re.match(r"^(?:shutil\.rmtree|os\.removedirs|rmtree|fs\.rmSync|fs\.rmdirSync|FileUtils\.rm_rf|rimraf)\((.+)\)$", t)
            if mf and isinstance(text, str) and re.search(r"(?:^|[;&|(\s])find\s+['\"]?[^\s'\"]+['\"]?\s+-delete\b", text):
                cands.append(mf.group(1))
            elif mc:
                cands.append(mc.group(1))              # r0261b: code that removes a tree (`shutil.rmtree('..')` from a subfolder)
            elif t and not re.match(r"^(?:rm|find|chmod|shutil|unlink|git)\b", t):
                cands.append(t)
    pr = posixpath.normpath(project)
    for t in cands:
        if t.startswith("~") or "$" in t:
            continue
        p = posixpath.normpath(t if t.startswith("/") else posixpath.join(cwd, t))
        whole = False
        if p.endswith("/*") or p == "*":
            p, whole = posixpath.dirname(p) if p != "*" else cwd, True
        if p == pr or pr.startswith(p.rstrip("/") + "/") or (whole and p == pr):
            return t[:200]
        if _TEMP_ROOTS.match(p):
            return t[:200]                            # the temp root itself: every session's work (and a project kept there)
        home = w.get("sbx_home") if isinstance(w.get("sbx_home"), str) and w.get("sbx_home").startswith("/") else None
        from .bashparse import canon_path
        if home and canon_path(posixpath.dirname(p)) == canon_path(home) and not _in(pr, p):   # r0274: a home under /tmp (firmlink)
            return t[:200]                            # a whole top folder of the home (~/Documents, ~/Library): the kernel refuses it
            #                                           too -- refused here at once (defense in depth, no question, nobody notified)
    return None


_TEMP_ROOTS = re.compile(r"^(?:/private)?(?:/var)?/tmp(?:/claude-\d+)?/?$")


class Verdict:
    """the strict decision of one Bash call: `refuse` (code, detail) | None, `ask` [(prefix, target)], `silent` bool."""
    __slots__ = ("refuse", "ask")

    def __init__(self, refuse, ask):
        self.refuse, self.ask = refuse, ask

    @property
    def silent(self):
        return self.refuse is None and not self.ask

    def ids(self):
        return [p + t for p, t in self.ask]


def verdict(tool, args):
    """The closed list over one Bash call (any part: the witness is the line's). Pure, no I/O."""
    w = _witness(args)
    text = args.get("command") if isinstance(args, dict) else None
    project = w.get("project") if isinstance(w.get("project"), str) else None
    nz = article(tool, args)
    if nz is None and any(isinstance(d, str) and d.startswith("witness:(quiet mode on) ") for d in w.get("danger") or []):
        # r0262: the agent's quiet-mode line under the strict fact: the sandbox is on already and the kernel would refuse the write of
        # ~/.claude/settings.json; refused as before r0262 (the danger `persist` then), never silent: changing it is the person's, by hand
        nz = ("FORBIDDEN_AUTOSTART", "the strict sandbox is on: change Claude Code's settings in your own terminal (deus-witness-hook --setup-strict)")
    ask = []
    if nz is not None and nz[0] == "DOUBT":
        ask.append((DOUBT, str(nz[1])[:200]))
        nz = None
    if nz is not None:
        return Verdict(nz, [])
    if tool in FILE_TOOLS:
        # r0261b: Write / Edit -- the same С3 as a shell write (the path the hook resolved); nothing else of the list applies to a file tool
        pth = w.get("path")
        return Verdict(None, ask + ([(LATER, pth[:180])] if isinstance(pth, str) and LATER_PATH.search(pth) else []))
    for pfx, fn in ((PUBLISH, lambda: publish_reasons(w, text) + _subs_publish(w, text)), (OUTSIDE, lambda: outside_reasons(w, text)),
                    (LATER, lambda: later_reasons(w, text, project)), (INJECT, lambda: inject_reasons(w, project)),
                    (WITNESS, lambda: witness_reasons(w, text)), (IRREV, lambda: irreversible_reasons(w, text)),
                    (IRREV, lambda: [k for t in written_run_texts(args) for k in irreversible_reasons({}, t)])):   # r0261c (г)
        for t in fn():
            if (pfx, t) not in ask:
                ask.append((pfx, str(t)[:180]))       # an amendment id is <= 200 characters (allowances._amend_offer)
    return Verdict(None, ask[:8])


FILE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")


def _subs_publish(w, text):
    """r0261b: a publication inside $(...) of an unquoted heredoc body (the shell runs it; the parser's heads do not show it)."""
    out = []
    for sub in heredoc_subs(text):
        for a in _segments(sub):
            t = _seg_publishes(a, w)
            if t and t not in out:
                out.append(t)
    return out


def no_way_out(w, text, v):
    """r0261b: nothing on this line can carry a value off the computer: no publication / outside program of the list, no network part,
    no program that leaves (sandbox.code_exit), no network word outside quotes and heredoc bodies."""
    from . import sandbox as hsb
    if any(p in (PUBLISH, OUTSIDE) for p, _ in v.ask) or w.get("net"):
        return False
    if any(hsb.code_exit(h) for h in (w.get("commands") or []) if isinstance(h, str)):
        return False
    return not (isinstance(text, str) and hsb.NET_TEXT.search(skeleton(text)))


def soften_data(L, mid, a, tool, args, v, now):
    """r0261b: the data rule acts on what LEAVES. Under the strict fact, a part the core refuses only for its data (DATA_*) on a line with
    no way out (no_way_out) is asked instead: the data members cleared, `dangerous` set, and the reason "(strict data) <tags>" put FIRST
    in the verdict (the question's recipient, so "from now on" can list it). With a way out, or a refusal for another reason: unchanged.
    -> (action, verdict)."""
    if not isinstance(a, dict) or not a.get("data") or v.refuse is not None or tool not in ("Bash", "Bash.danger", "Bash.write"):
        return a, v
    _, v0, why0 = L.S.decide_for(mid, a, now)
    if v0 != "deny" or not str(why0).startswith("DATA_"):
        return a, v
    w = _witness(args)
    if not no_way_out(w, args.get("command"), v):
        return a, v
    b = dict(a, data=[], dlp_hits=[], dangerous=True)
    if L.S.decide_for(mid, b, now)[1] == "deny":
        return a, v
    rid = (DATA, ",".join(sorted(str(x) for x in a["data"]))[:120])
    return b, Verdict(None, [rid] + [x for x in v.ask if x != rid][:7])


def write_cover(L, mid, a, tool, args, now, project):
    """r0261b: Write / Edit under the code option -- a file another program runs later outside the sandbox (С3, the path the hook
    resolved) is asked with the narrow "from now on" (this path, this project), as a shell write is. Any other file: unchanged."""
    if not isinstance(a, dict) or tool not in FILE_TOOLS or "allowance" in a:
        return a
    if _witness(args).get("danger"):
        return a                                      # .vscode/tasks.json, .claude/..., a git hook: its Write.danger part is the question
    v = verdict(tool, args)
    if v.refuse is not None:
        return a
    # r0261c (д, decision of Deus): С3 for a file tool only under a fresh strict fact of the session (`sbx_session`); without it П2 --
    # a CI / build file changes silently, its run outside is judged when it runs
    ids = v.ids() if _witness(args).get("sbx_session") is True else []
    _, v0, why0 = L.S.decide_for(mid, a, now)
    if v0 == "deny" and str(why0).startswith("DATA_") and a.get("data"):
        # a protected value written into a file the mandate lets the agent write (the project, temp): it stays on this computer --
        # asked, not refused (no "from now on": a file tool carries no project unless the path is on the list)
        a0 = dict(a, data=[], dlp_hits=[])
        if L.S.decide_for(mid, a0, now)[1] != "allow":
            return a
        ids = [DATA + ",".join(sorted(str(x) for x in a["data"]))[:120]] + ids
        a, v0 = a0, "allow"
    if not ids or v0 == "deny":
        return a
    b = dict(a, **{"class": "command"}, recipient=ids[0], dangerous=True)
    b.pop("reversible", None)
    b.pop("sandboxed", None)
    if isinstance(project, str):
        for gid, g in sorted(L.S.allowances.items(), key=lambda kv: -kv[1]["seq"]):
            if g["mandate"] == mid and not g["ended"] and g["nbf"] <= now <= g["exp"] and g["project"] == project \
                    and all(i in g["commands"] for i in ids):
                c = dict(b, dangerous=False, allowance=gid, project=project)
                if L.S.decide_for(mid, c, now)[1:] == ("allow", "OK_ALLOWANCE"):
                    return c
    return b if L.S.decide_for(mid, b, now)[1] == "defer" else a


_SHARED_TEMP = re.compile(r"^(?:/private)?/(?:tmp|var/tmp)/.|^(?:/private)?/var/folders/[^/]+/[^/]+/T/.")


def temp_write_ask(L, mid, a, tool, args, now):
    """r0261f (release 0.2.59; the last refusal of harmless work on the blind corpus, `Write /tmp/readme-check/x.mjs`): a Write / Edit
    of a file in the shared temp of this computer that the mandate's targets do not name (the core refuses it RESOURCE, with no button) is
    a question, asked ONCE: the pseudo-command "(write outside the project) <path>", dangerous (never `unlisted: allow`, never a
    project allowance or a folder amendment: amend.folder_id names no folder outside the home). With or without the strict fact.
    Unchanged: a place of an article (rc files, LaunchAgents, /etc, ~/.ssh: the mapping makes it Write.danger, refused), a temp folder
    under the home, any other place outside the targets (/opt, /usr/local, another user's home, /Volumes: RESOURCE), a refusal for
    another reason (data, the agent's harness)."""
    if not isinstance(a, dict) or tool not in FILE_TOOLS or "allowance" in a:
        return a
    w = _witness(args)
    pth = w.get("path")
    if w.get("danger") or not isinstance(pth, str) or not _SHARED_TEMP.match(pth) or posixpath.normpath(pth) != pth:
        return a
    from .bashparse import is_agent_config_path, is_git_exec_path, is_persist_path, is_secret_path
    from .mapping import OUTSIDE_WRITE
    if is_secret_path(pth) or is_persist_path(pth) or is_agent_config_path(pth) or is_git_exec_path(pth):
        return a
    home = w.get("home")
    from .bashparse import around_home
    if around_home(pth, home):                      # r0274: at / under / above the home, firmlink-insensitive
        return a
    _, v0, why0 = L.S.decide_for(mid, a, now)
    if (v0, why0) != ("deny", "RESOURCE"):
        return a
    b = dict(a, **{"class": "command"}, recipient=(OUTSIDE_WRITE + pth)[:1000], dangerous=True)
    for k in ("reversible", "sandboxed", "project"):
        b.pop(k, None)
    return b if L.S.decide_for(mid, b, now)[1] == "defer" else a


def _net_read_or_code(w, args):
    """a host of the line's network part that the 0.2.x rules let run silently (a read, a host only code names): then the network part
    may not ask, and the command part must."""
    from . import sandbox as hsb
    nr = hsb.net_read_line(args.get("command")) if isinstance(args.get("command"), str) else None
    quiet = set(hsb.code_only(w)[1]) | (nr["hosts"] if nr is not None else set())
    return any(hsb._rcpt_host(n) in quiet for n in (w.get("net") or []) if isinstance(n, str))


def _hosts_of(w, argv=None):
    hs = [n.rsplit("@", 1)[-1].strip("[]") for n in (w.get("net") or []) if isinstance(n, str)]
    if argv:
        from . import sandbox as hsb
        hs += [h for h in (hsb.url_host(t) for t in argv[1:]) if h]
        hs += [m.group(1) for t in argv[1:] for m in [re.match(r"^(?:[\w.-]+@)?([\w.-]+):", t)] if m and not t.startswith("-")]
    out = sorted({h.lower() for h in hs if h and not _LOOPBACK_HOST.match(h)})
    return out


def strict_fact(args) -> bool:
    w = _witness(args)
    return w.get("sandbox") == {"strict": True}


SILENT_PREFIX = "(sandboxed) "      # a part that was not a command (a write, a request) run as a sandboxed command: the receipt says so


def cover(L, mid, a, tool, args, v, now, amend_meta=None):
    """The gateway step for one part of a strict line (the caller checked the strict fact and the code option).
    silent: a part the core would ASK about goes to the core as a sandboxed command -> OK_SANDBOXED (a core deny stays a deny).
    asked:  the line's command part (Bash / Bash.danger) is asked about the FIRST reason of the table (its recipient = that reason's id, so
            "from now on" can list it), unless an amendment of this project lists every reason of the line, or the core already asks /
            refuses this part, or the person LISTED the publishing command itself. Other parts: as the 0.2.x rules judged them."""
    if not isinstance(a, dict) or "allowance" in a or v.refuse is not None:
        return a                                      # an article: refused by the gateway (constitution), unchanged here
    _, v0, why0 = L.S.decide_for(mid, a, now)
    if v.silent:
        if v0 != "defer":
            return a
        b = dict(a, sandboxed=True, dangerous=False)
        b.pop("exec_changed", None)
        if b.get("class") != "command":
            b["class"] = "command"
            b["recipient"] = SILENT_PREFIX + str(a.get("recipient") or "")[:900]
            b.pop("reversible", None)
        # r0261d: a listed head (`cd`) whose only mark was the protected value moved into a local file (toolmap: dangerous) is plain OK
        return b if L.S.decide_for(mid, b, now)[1:] in (("allow", "OK_SANDBOXED"), ("allow", "OK")) else a
    if tool not in ("Bash", "Bash.danger") or a.get("class") != "command" or v0 == "deny":
        return a
    if v0 == "allow" and why0 == "OK_ALLOWANCE":
        return a
    if v0 == "allow" and why0 == "OK" and all(p == PUBLISH for p, _ in v.ask):
        return a                                      # the person listed this publishing command in the mandate
    ids = v.ids()
    as_ = any(isinstance(d, str) and (d.startswith("defense:") or (d.startswith("autostart:") and "in an unknown directory" in d))
              for d in _witness(args).get("danger") or [])   # r0305: + defense; a W5 mark is С3 here (its narrow amendment stays)
    if amend_meta is not None and not as_:            # r0298: autostart in an unknown folder is never covered "from now on"
        for gid, g in sorted(L.S.allowances.items(), key=lambda kv: -kv[1]["seq"]):
            if g["mandate"] == mid and not g["ended"] and g["nbf"] <= now <= g["exp"] and g["project"] == amend_meta["project"] \
                    and all(i in g["commands"] for i in ids):
                b = dict(a, recipient=ids[0], dangerous=False, allowance=gid, project=amend_meta["project"])
                b.pop("sandboxed", None)
                if L.S.decide_for(mid, b, now)[1:] == ("allow", "OK_ALLOWANCE"):
                    return b
    if v0 == "defer" and all(p == PUBLISH for p, _ in v.ask):
        return a                                      # the 0.2.x question of a publication (its own "from now on": amend.publish_id)
    w = _witness(args)
    if all(p == PUBLISH for p, _ in v.ask) and w.get("net") and \
            all(_base(t.split(" ")[0]) in FETCH_PROGS | REMOTE_PROGS | {"rsync"} for _, t in v.ask) and not _net_read_or_code(w, args):
        return a                                      # a request / a remote copy: its network part (Bash.net) is the question, with its
        #                                               own narrow "from now on" ("(network send) host", "(remote) ssh host cmd")
    b = dict(a, recipient=ids[0], dangerous=True)
    b.pop("sandboxed", None)
    b.pop("allowance", None)
    return b if L.S.decide_for(mid, b, now)[1] == "defer" else a


# ---- r0262 (П3 rest of RT-0259): a file the agent WROTE, run by a LATER call ---------------------------------------------------------
# r0261c judged the text of a file written and run on the SAME line. A file written by Write / Edit (or a shell heredoc) and run by a
# separate call (`bash scripts/p.sh`, `python3 x.py`, `node x.js`, `./x`) ran silently whatever it held: the witness saw the text when it
# was written, not when it ran. Now, when the write is allowed, the witness judges the text as if it stood on a line (script_findings:
# the same closed list -- Н5 wipe refused, С1 publish / С6 irreversible / the rest of the list asked; another article only in text: a
# doubt) and keeps ONLY those findings on the write's mark (actions: wrun[path]["sf"]), never the text for this. A later strict line that
# RUNS that path (run_targets) carries them (with_scripts). A file the witness never saw written (the person's own script, a file code
# made) is NOT asked for: its run is what the kernel holds, as before (asking on every `python x.py` is the friction the list removed).
import contextvars  # noqa: E402
PLACE = contextvars.ContextVar("dw_strict_place", default=None)   # r0262: {project, home, cwd} of the hook event being judged (judge.py)
SCRIPT_MAX = 200_000                  # characters judged; a longer text is a doubt when it runs (asked), never silently cut
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "source", "."}
_SCRIPT_INTERP = {"node", "perl", "ruby", "tsx", "ts-node", "bun", "deno"}
_RUNNERS = {"uv", "poetry", "pipenv", "pdm", "hatch", "rye", "npx", "bunx", "pnpx"}
_PY = re.compile(r"python(?:[23](?:\.\d{1,2})?)?")
REFUSE_MARK = "!"


def script_kind(path, text):
    """'sh' | 'py' | 'js' | 'pkg' | 'make' | None: how the text runs (the shebang, else the extension; an extensionless file runs in a
    shell). r0263: package.json (its scripts run by npm / yarn / pnpm / bun), a Makefile (its recipes run by make), .ts (tsx / ts-node)."""
    base0 = posixpath.basename(path or "")
    if base0 == "package.json":
        return "pkg"
    if base0 in ("Makefile", "makefile", "GNUmakefile") or base0.endswith(".mk"):
        return "make"
    first = text.split("\n", 1)[0] if isinstance(text, str) else ""
    if first.startswith("#!"):
        if re.search(r"python", first):
            return "py"
        if re.search(r"\b(?:node|bun|deno|tsx)\b", first):
            return "js"
        if re.search(r"\b(?:ba|z|da|k)?sh\b", first):
            return "sh"
        return None
    base = posixpath.basename(path or "")
    ext = base.rsplit(".", 1)[-1].lower() if "." in base.lstrip(".") else ""
    if ext in ("sh", "bash", "zsh", "ksh", ""):
        return "sh"
    if ext in ("py", "pyw"):
        return "py"
    if ext in ("js", "mjs", "cjs", "ts", "mts", "cts"):
        return "js"
    return None


# ---- r0263 (П3 rest): what a written file runs through a TOOL rather than an interpreter ------------------------------------------------
# package.json scripts (npm run X / npm test / npm install's lifecycle / yarn X / pnpm X / bun run X), Makefile recipes (make [target]),
# and the commands a .js / .py file hands to a shell (child_process.execSync('npm publish'), subprocess.run(["git", "push"]), os.system).
# Findings of a package.json / a Makefile carry a TAG (the third element: "npm:<script>" / "make:<target>"; "make:" = the default target),
# so `npm test` is not asked about the `release` script beside it. A script / target's findings include those of the scripts / targets
# it runs itself (npm run Y inside, make prerequisites), computed when the file is written (the whole text is known then).
NPM_LIFECYCLE = {"install": ("preinstall", "install", "postinstall", "prepare"), "ci": ("preinstall", "install", "postinstall", "prepare"),
                 "pack": ("prepack", "prepare", "postpack"), "publish": ("prepublishOnly", "prepack", "prepare", "postpack", "publish",
                                                                          "postpublish")}
_PKG_META = {"name", "version", "description", "main", "module", "types", "typings", "license", "author", "homepage", "url", "type",
             "email", "private", "packageManager", "browser", "bin", "directory"}
_PKG_PAIR = re.compile(r'"((?:[^"\\]|\\.){1,128})"\s*:\s*"((?:[^"\\]|\\.){1,4000})"')
_NPM_RUN = re.compile(r"\b(?:npm|pnpm|yarn|bun)\s+(?:run(?:-script)?\s+)?([A-Za-z0-9:_.@/-]+)")


def _pkg_scripts(text):
    """-> {name: command} of a package.json text: its "scripts" when the text is JSON; for a fragment (an Edit) every "key": "value"
    pair that is not package metadata (fail toward judging)."""
    try:
        d = json.loads(text)
        sc = d.get("scripts") if isinstance(d, dict) else None
        return {k: v for k, v in sc.items() if isinstance(k, str) and isinstance(v, str)} if isinstance(sc, dict) else {}
    except ValueError:
        out = {}
        if not _PKG_PAIR.search(text):               # the witness's own form of a written package.json (execguard._written_text):
            for ln in text.split("\n"):              # one `name: command` per line
                m = re.match(r"^([^\s\"]{1,128}?): (.+)$", ln)
                if m:
                    out[m.group(1)] = m.group(2)
            return out
        for m in _PKG_PAIR.finditer(text):
            k, v = m.group(1), m.group(2)
            if k not in _PKG_META and not v.startswith(("http://", "https://", "^", "~", ">=", "git+")) and not re.fullmatch(r"[\d.x*]+", v):
                try:
                    out[k] = json.loads('"%s"' % v)
                except ValueError:
                    out[k] = v
        return out


def _make_rules(text):
    """-> ([targets in order], {target: (prerequisites, [recipe lines])}) of a Makefile (plain rules; variables are left as text)."""
    order, rules, cur = [], {}, []
    for raw in re.sub(r"\\\n", " ", text).split("\n"):
        if raw.startswith("\t"):
            line = raw[1:].lstrip("@-+ ")
            for t in cur:
                rules[t][1].append(line)
            continue
        m = re.match(r"^([A-Za-z0-9_./%-][A-Za-z0-9_./% -]*)\s*::?(?!=)\s*([^;#=]*)(?:;\s*(.*))?$", raw)
        if m and not raw.lstrip().startswith("#"):
            cur = [t for t in m.group(1).split() if t]
            for t in cur:
                if t not in rules:
                    rules[t] = ([], [])
                    if not t.startswith(".") and "%" not in t:
                        order.append(t)
                rules[t][0].extend(x for x in m.group(2).split() if x)
                if m.group(3):
                    rules[t][1].append(m.group(3))
        elif raw.strip() and not raw.startswith(" "):
            cur = []
    return order, rules


def _closure(start, edges):
    seen, todo = [], [start]
    while todo and len(seen) < 64:
        x = todo.pop()
        if x in seen:
            continue
        seen.append(x)
        todo.extend(edges.get(x, ()))
    return seen


_JS_EXEC = re.compile(r"(?<!/\.)\b(?:execSync|exec|execFileSync|execFile|spawnSync|spawn|execa|execaSync)\s*\(\s*(['\"`])((?:(?!\1)[^\\]|\\.){1,2000})\1"
                      r"(?:\s*,\s*\[([^\]]{0,2000})\])?")
_PY_EXEC = re.compile(r"\b(?:os\.system|os\.popen|os\.exec\w*|subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)"
                      r"|sh\.\w+|run|call|check_call|check_output|Popen)\s*\(\s*(?:(['\"])((?:(?!\1)[^\\]|\\.){1,2000})\1|\[([^\]]{0,2000})\])")
_LIT = re.compile(r"(['\"])((?:(?!\1)[^\\]|\\.){0,500})\1")


def code_commands(kind, text):
    """-> [command lines] a .js / .py text hands to a shell or a process (string literals only: a command built at run time is not
    seen, as when typed on a line)."""
    out = []
    if kind == "js":
        for m in _JS_EXEC.finditer(text):
            words = [m.group(2)] + [x.group(2) for x in _LIT.finditer(m.group(3) or "")]
            out.append(" ".join(shlex.quote(w) if i else w for i, w in enumerate(words)))
    elif kind == "py":
        for m in _PY_EXEC.finditer(text):
            if m.group(2) is not None:
                out.append(m.group(2))
            else:
                words = [x.group(2) for x in _LIT.finditer(m.group(3) or "")]
                if words:
                    out.append(" ".join(shlex.quote(w) for w in words))
    return out[:32]


def _tagged(fs, tag):
    return [f + [tag] for f in fs if isinstance(f, list)]


def script_findings(place, path, text):
    """r0263: package.json / Makefile per script / target (tagged); a .js / .py file also by the commands it hands to a shell."""
    kind = script_kind(path, text)
    if kind not in ("pkg", "make") or not isinstance(text, str) or not text.strip():
        out = _script_findings(place, path, text)
        if kind in ("js", "py") and isinstance(text, str) and len(text) <= SCRIPT_MAX:
            for c in code_commands(kind, text):
                for f in _script_findings(place, (path or "x") + ".sh", c):
                    if f not in out:
                        out.append(f)
        return out[:8]
    if len(text) > SCRIPT_MAX:
        return [[DOUBT, "a file too long to read: %s" % posixpath.basename(path or "")]]
    own, edges, extra = {}, {}, []
    if kind == "pkg":
        sc = _pkg_scripts(text)
        for k, v in list(sc.items())[:64]:
            own[k] = _script_findings(place, (path or "x") + ".sh", v)
            edges[k] = [n for n in _NPM_RUN.findall(v) if n in sc and n != k]
            # npm runs preX / postX around X
            edges[k] += [n for n in ("pre" + k, "post" + k) if n in sc]
        tags = {k: "npm:" + k for k in sc}
    else:
        order, rules = _make_rules(text)
        for t, (deps, lines) in list(rules.items())[:128]:
            own[t] = _script_findings(place, (path or "x") + ".sh", "\n".join(lines)) if lines else []
            edges[t] = [d for d in deps if d in rules]
        tags = {t: "make:" + t for t in rules}
        if order:
            extra = [order[0]]                        # `make` with no target runs the first one
    out = []
    for k in own:
        fs = []
        for n in _closure(k, edges):
            fs += [f for f in own.get(n, []) if f not in fs]
        out += _tagged(fs, tags[k])
        if k in extra:
            out += _tagged(fs, "make:")
    return out[:48]


def _script_findings(place, path, text):
    """-> [[prefix, target]] (asked) and [REFUSE_MARK, code, detail] (Н5: refused) for the TEXT of a file, judged as a line in the
    write's place (project, home). [] when nothing of the list is in it or the file is no script the list can read. Never raises."""
    kind = script_kind(path, text)
    if kind is None or not isinstance(text, str) or not text.strip():
        return []
    name = posixpath.basename(path or "") or "the file"
    if len(text) > SCRIPT_MAX:
        return [[DOUBT, "a file too long to read: %s" % name]]
    line = _script_self(text, path) if kind == "sh" else ("python3 -c " if kind == "py" else "node -e ") + shlex.quote(text)
    try:
        from app import constitution
        from . import bashparse
        w0 = place if isinstance(place, dict) else {}
        project = w0.get("project") if isinstance(w0.get("project"), str) and w0.get("project").startswith("/") else None
        cwd = project or (w0.get("cwd") if isinstance(w0.get("cwd"), str) and w0.get("cwd").startswith("/") else None)
        home = next((h for h in (w0.get("sbx_home"), w0.get("home")) if isinstance(h, str) and h.startswith("/")), None)
        if cwd is None or home is None:
            return []
        c = bashparse.classify(line, cwd, home, project=project)
        # no `sbx_home`: a whole top folder of the home OUTSIDE the project (`rm -rf ~/Documents` in a file) is what the kernel refuses
        # (no write outside the project); refused here is only what the kernel lets through: the project, a folder above it, temp roots
        w2 = {"project": project, "cwd": cwd, "home": home, "danger": list(c.danger), "writes": list(c.writes),
              "commands": list(c.heads), "deletes": [d for d in c.deletes if d in c.writes], "net": list(c.net)}
        v = verdict("Bash", {"command": line, "_witness": w2})
    except Exception:      # noqa: BLE001  a text the parser cannot read: a doubt when it runs
        return [[DOUBT, "a file the witness could not read: %s" % name]]
    out = []
    if v.refuse is not None:
        # Н5 (a wipe of the project or above) refuses the run. A force-push is a publication (asked); a download into a shell / a
        # listener is a doubt (asked). The other articles in a written text are what the kernel holds (a secret store under denyRead,
        # no write outside the project) or what the hold of a written file already asks about (autostart, git hooks: G4 / later_text)
        if v.refuse[0] == constitution.WIPE:
            out.append([REFUSE_MARK, v.refuse[0], str(v.refuse[1])[:160]])
        elif v.refuse[0] == "FORBIDDEN_FORCE_PUSH":
            out.append([PUBLISH, "git push --force"])
        elif v.refuse[0] == "FORBIDDEN_REMOTE_SHELL":
            out.append([DOUBT, ("%s in %s" % (v.refuse[0], name))[:180]])
    segs = _segments(line) if kind == "sh" else []
    for p, t in v.ask:
        b = _base(t.split(" ")[0])
        if p == PUBLISH and b in FETCH_PROGS and kind == "sh" and not any(_base(a[0]) == b and _seg_publishes(a, w2) for a in segs):
            continue                                  # a plain request (GET): on a line its network part is the question (cover); in a
            #                                           script the kernel holds the host list -- only a send / upload / credential is asked
        out.append([p, t])
    return out[:8]


_SELF_DIR = re.compile(r'\$\(\s*dirname\s+"?(?:\$0|\$\{0\}|\$\{BASH_SOURCE(?:\[0\])?\}|\$BASH_SOURCE)"?\s*\)|\$\{(?:0|BASH_SOURCE(?:\[0\])?)%/\*\}')
_CD_PWD = re.compile(r'\$\(\s*cd\s+"?([^"$`()\s;&|]+)"?\s*(?:&&|;)\s*pwd(?:\s+-P)?\s*\)')
_PLAIN_PATH = re.compile(r"[\w./@+-]+")


def _script_self(text, path):
    """A script that names its own folder (`$(dirname "$0")`, `${BASH_SOURCE%/*}`, `$(cd "$(dirname "$0")/.." && pwd)`): the folder the
    file was written in is put in, so that `rm -rf "$ROOT"` is judged on the place it names (a plain path only; quotes kept)."""
    if not isinstance(path, str) or not path.startswith("/") or "$" not in text:
        return text
    d = posixpath.dirname(posixpath.normpath(path))
    if not _PLAIN_PATH.fullmatch(d):
        return text
    t = _SELF_DIR.sub(lambda m: d, text)
    for _ in range(3):
        t2 = _CD_PWD.sub(lambda m: posixpath.normpath(m.group(1)) if m.group(1).startswith("/") else m.group(0), t)
        if t2 == t:
            break
        t = t2
    return t


_DUR = re.compile(r"[\d.]+[smhd]?")
_LVAR = re.compile(r"\$\{?([A-Za-z_]\w*)\}?")


def run_targets(text, cwd):
    """-> set of absolute paths a line RUNS as a script: `bash x.sh`, `sh < x.sh`, `source x`, `python3 x.py`, `node x.js`, `./x`,
    `scripts/x`, `uv run x.py`, `cat x.sh | bash`. Relative paths from cwd and from each `cd DIR` of the line."""
    if not isinstance(text, str):
        return set()
    names = []
    segs = _segments(text)
    bare_runner = False
    cats = []
    lvars = {}
    for m in re.finditer(r"(?:^|[;&|(\s])([A-Za-z_]\w*)=('[^']*'|\"[^\"$`]*\"|[^\s;&|()$`'\"]+)", text):
        lvars[m.group(1)] = m.group(2).strip("'\"")          # a literal the line sets (`X=scripts/p.sh; bash $X`)
    for a in segs:
        while a and (a[0].startswith("-") or _DUR.fullmatch(a[0])):
            a = a[1:]                                 # what a dropped wrapper left (`timeout 10`, `nice -n 5`)
        while a and (_base(a[0]) in _RUNNERS or _base(a[0]) in ("timeout", "nice", "nohup", "time", "exec", "command", "caffeinate")):
            if _base(a[0]) in _RUNNERS:
                a = a[2:] if len(a) > 1 and a[1] in ("run", "exec") else a[1:]
            else:
                a = a[1:]
                while a and (a[0].startswith("-") or _DUR.fullmatch(a[0])):
                    a = a[1:]
        if not a:
            continue
        if lvars:                                     # r0346 (cost): no literal set on the line / no "$" in a word -> the word as it is
            a = [_LVAR.sub(lambda m: lvars.get(m.group(1), m.group(0)), x) if "$" in x else x for x in a]
        if _base(a[0]) in _SHELLS and "-c" in a[1:]:
            k = a.index("-c", 1)
            if k + 1 < len(a):
                inner = run_targets(a[k + 1], cwd)
                names += list(inner)
            continue
        h = _base(a[0])
        ops = [x for x in a[1:]]
        if h in ("make", "gmake"):                    # r0263: the recipes of a Makefile (tagged by target; "" = the default one)
            mf, md, tg = None, None, []
            k = 0
            while k < len(ops):
                x = ops[k]
                if x in ("-f", "--file", "--makefile") and k + 1 < len(ops):
                    mf, k = ops[k + 1], k + 2
                    continue
                if x in ("-C", "--directory") and k + 1 < len(ops):
                    md, k = ops[k + 1], k + 2
                    continue
                if x.startswith("-f") and len(x) > 2:
                    mf = x[2:]
                elif x.startswith("-C") and len(x) > 2:
                    md = x[2:]
                elif not x.startswith("-") and "=" not in x:
                    tg.append(x)
                k += 1
            for f_ in ([mf] if mf else ["Makefile", "makefile", "GNUmakefile"]):
                for t_ in (tg or [""]):
                    names.append(posixpath.join(md, f_) + "#make:" + t_ if md else f_ + "#make:" + t_)
            continue
        if h in ("npm", "pnpm", "yarn", "bun"):       # r0263: package.json scripts (tagged by script name)
            pre = None
            rest = []
            k = 0
            while k < len(ops):
                if ops[k] in ("--prefix", "-C", "--cwd", "--dir") and k + 1 < len(ops):
                    pre, k = ops[k + 1], k + 2
                    continue
                if not ops[k].startswith("-"):
                    rest.append(ops[k])
                k += 1
            sub = rest[0] if rest else ("install" if h in ("yarn", "pnpm", "bun") or not ops else "")
            scr = []
            if sub in ("run", "run-script", "rum", "urn") and len(rest) > 1:
                scr = [rest[1]]
            elif h == "bun" and sub == "test":
                scr = []                              # bun's own test runner, not a script
            elif sub in ("test", "t", "tst", "start", "stop", "restart"):
                scr = [{"t": "test", "tst": "test"}.get(sub, sub)]
            elif sub in ("install", "i", "isntall", "ci", "add") or (h == "yarn" and not rest):
                scr = list(NPM_LIFECYCLE["install"])
            elif sub in ("publish", "pack"):
                scr = list(NPM_LIFECYCLE[sub])
            elif h in ("yarn", "pnpm", "bun") and sub and sub not in ("exec", "dlx", "x", "create", "init", "remove", "rm", "why",
                                                                       "list", "ls", "info", "view", "outdated", "upgrade", "update", "up"):
                scr = [sub]                           # `yarn build` / `pnpm lint` / `bun dev`: a script of that name
            for n_ in scr:
                names.append((posixpath.join(pre, "package.json") if pre else "package.json") + "#npm:" + n_)
            continue
        if "/" in a[0] and h not in _SHELLS and not _PY.fullmatch(h) and h not in _SCRIPT_INTERP:
            names.append(a[0])
            continue
        if h in _SHELLS or _PY.fullmatch(h) or h in _SCRIPT_INTERP:
            inline_ = ("-c",) if h in _SHELLS else ("-c", "-m") if _PY.fullmatch(h) else ("-e", "-p", "--eval", "--print", "-c")
            if any(x in inline_ for x in ops):
                continue                              # code given on the line: judged as the line
            if h in ("bun", "deno") and ops[:1] == ["run"]:
                ops = ops[1:]
            k = 0
            while k < len(ops) and ops[k].startswith("-") and ops[k] != "-":
                k += 1
            if k < len(ops) and ops[k] == "<" and k + 1 < len(ops):
                names.append(ops[k + 1])
            elif k < len(ops) and ops[k] not in ("-", "<"):
                names.append(ops[k])
            elif k < len(ops) and ops[k] == "-" and any(x in ("<<", "<<-", "<<<") or x.startswith("<<") for x in ops[k + 1:]):
                continue                              # r0349: `python3 - ARG <<'EOF'`: the program is the heredoc (judged as the line)
            elif k < len(ops) and ops[k] == "-" and "<" in ops[k + 1:] and ops.index("<", k + 1) + 1 < len(ops):
                names.append(ops[ops.index("<", k + 1) + 1])     # `python3 - ARG < f.py`: f.py runs
            else:
                bare_runner = True
        elif h == "cat":
            cats += [x for x in ops if not x.startswith("-")]
    if bare_runner:
        names += cats
    cwds = [cwd] if isinstance(cwd, str) and cwd.startswith("/") else []
    for d in re.findall(r"(?:^|[;&|(]\s*)cd\s+([^\s;&|)]+)", text):
        if cwds:
            cwds.append(posixpath.normpath(posixpath.join(cwds[-1], d.strip("'\""))))
    out = set()
    for n in names:
        n = n.strip("'\"")
        n, tag = (n.split("#", 1) + [""])[:2] if "#npm:" in n or "#make:" in n else (n, "")
        tag = "#" + tag if tag else ""
        if not n or "$" in n or n.startswith("~"):
            continue
        if n.startswith("/"):
            out.add(posixpath.normpath(n) + tag)
        else:
            for c in cwds:
                out.add(posixpath.normpath(posixpath.join(c, n)) + tag)
    return out


def split_target(t):
    """r0263: 'path#npm:x' -> ('path', 'npm:x'); a plain path -> (path, None)."""
    if isinstance(t, str) and ("#npm:" in t or "#make:" in t):
        p, tag = t.rsplit("#", 1)
        return p, tag
    return t, None


def for_tags(sf, tags):
    """r0263: the findings of a file for the run: untagged ones always; a tagged one (package.json script, Makefile target) only when this
    line runs that script / target. The tag is dropped from what is returned."""
    out = []
    for f in sf if isinstance(sf, list) else []:
        if not isinstance(f, list) or not f:
            continue
        n = 4 if f[0] == REFUSE_MARK else 3
        if len(f) == n:
            if f[-1] in tags:
                g = f[:-1]
                if g not in out:
                    out.append(g)
        elif f not in out:
            out.append(f)
    return out


def _same_path(a, b):
    def n(p):
        p = posixpath.normpath(p)
        return p[len("/private"):] if p.startswith("/private/") else p
    return n(a) == n(b)


def with_scripts(v, found):
    """found = [(path, findings)] of the files this line runs whose text the witness judged when the agent wrote them. -> the verdict
    with their findings: a wipe refuses the line (Н5), every other finding is asked as if it stood on the line."""
    if v is None or v.refuse is not None or not found:
        return v
    ask = list(v.ask)
    for path, sf in found:
        for f in sf if isinstance(sf, list) else []:
            if not isinstance(f, list) or not f:
                continue
            if f[0] == REFUSE_MARK and len(f) == 3:
                return Verdict((str(f[1]), "%s (in %s, written by the agent)" % (f[2], posixpath.basename(path))), [])
            if len(f) == 2 and f[0] in PREFIXES and isinstance(f[1], str) and (f[0], f[1]) not in ask:
                ask.append((f[0], f[1][:180]))
    return Verdict(None, ask[:8])
