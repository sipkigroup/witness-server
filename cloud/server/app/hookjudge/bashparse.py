"""Witness class `command`: what a shell command line (Claude Code `Bash` tool) is about to do. Pure functions, no I/O except realpath.

classify(cmd, cwd, home) -> Command(danger=[...], writes=[...], opaque=bool)
  danger  "category:detail" strings, category one of DANGER_CATEGORIES; the detail is the target (path, remote, SQL verb ...)
  writes  absolute, normalised paths the line writes through redirections, tee, cp/mv/install, sed -i, dd of=, touch, mkdir
  net     hosts the line talks to over the network (curl/wget/http URLs, ssh/scp/rsync/sftp/nc/telnet targets, git clone/fetch/pull URLs)
  opaque  the line could not be read reliably (unbalanced quotes, eval, `$(...)` around a command name, too deep nesting)
  heads   command identifiers of every simple command (PROPOSAL-06 class `command`, action.recipient): the program's base name, plus the
          sub-command for the tools in SUBCOMMAND_TOOLS ("git status", "npm test"); also for $(...), backticks, `sh -c`, code heredocs.
          0.2.9: an identifier names exactly what runs, so that a read-only entry of the owner's list cannot be used to run something else:
          a program called by path keeps the path ("./ls"), and a form that runs other code or writes gets a variant suffix
          "<id> [<why>]" ("ls [env LD_PRELOAD]", "grep [via xargs]", "git status [-c]", "rg [--pre]", "git branch [write]"), see _variants()
0.2.11 (review 6): every redirection operator of bash and zsh is cut out of shlex's punctuation runs and named explicitly (_relex,
_redirects: `>|` writes its word, it is not a file called "|"); a redirection without a word or an operator we do not know is opaque.
A path the hook cannot know -- an expansion other than $HOME / $PWD, ~user, a substitution, a glob or brace in a write target -- is
opaque (asked as dangerous); `${...}` stays one word, so `cat ${HOME}/.ssh/id_rsa` is still a read of a secret. Substitutions are
classified at any depth (_substitute) within one budget per line (MAX_NESTED). Interpreters given code on the line are "<id> [eval]".

This is a TRIPWIRE, not a sandbox: an agent that writes a script and runs it, or uses an interpreter
(`python -c "import shutil; shutil.rmtree(...)"`), is caught only where a raw-text pattern below matches.
"""
from __future__ import annotations

import bisect
import json
import os
import re
import shlex
from dataclasses import dataclass, field

from . import fs as _fs
from . import runners as _runners

# tools whose first operand is a sub-command that changes what they do: the command identifier is "<tool> <sub-command>"
SUBCOMMAND_TOOLS = {"git", "npm", "pnpm", "yarn", "npx", "cargo", "go", "docker", "podman", "kubectl", "helm", "pip", "pip3", "uv", "poetry",
                    "brew", "apt", "apt-get", "systemctl", "launchctl", "make", "gh"}
SUBCOMMAND_RE = re.compile(r"[A-Za-z][A-Za-z0-9._:-]{0,63}")
MAX_HEADS = 32
DANGER_CATEGORIES = ("rm-rf", "sql-drop", "git-force-push", "git-destroy", "git-config", "agent-config", "pipe-to-shell", "secrets", "disk", "opaque",
                     "persist", "witness", "exit", "write-outside", "net-out", "loopback-write")    # 0.2.90 / 0.2.91: gates G2 / G4 (witness: a run the witness may not watch, asked)
DETAIL_MAX = 160
MAX_DEPTH = 4
MAX_NESTED = 128           # 0.2.11: substitutions, `sh -c`, eval, code heredocs of one line: more -> opaque (and no quadratic time)

SEPARATORS = {";", ";;", ";&", ";;&", "&&", "||", "|", "&", "|&", "\n", "(", ")", "{", "}"}
# 0.2.11 (R6-01): the shell's redirection operators, each named explicitly. shlex glues a run of punctuation into ONE token (">|", "&>>", ";>",
# "}>"); _relex cuts such a run into these operators, longest first, and _redirects judges each one. A run it cannot cut (none: every single
# character is an operator) or an operator without a word after it makes the line opaque: never "a write to a file named '|' in the project".
WRITE_OPS = {">", ">>", ">|", ">>|", "&>", "&>>", "&>|", "<>", ">&|"}       # the zsh forms (>>|, &>|, >&|) write too; bash rejects them
DUP_OPS = {">&", "<&"}                  # 2>&1, >&-, <&3 duplicate or close a descriptor; `>&file` / `>& file` writes the file (bash and zsh)
READ_OPS = {"<"}
WORD_OPS = {"<<", "<<<"}                # heredoc delimiter / here-string: the next word is data, not a path
REDIR_OPS = WRITE_OPS | DUP_OPS | READ_OPS | WORD_OPS
PUNCT = set(";&|<>(){}")
OPS = sorted(SEPARATORS - {"\n"} | REDIR_OPS, key=len, reverse=True)
REDIRECTS = WRITE_OPS
# 0.2.12: reserved words that start or continue a compound command: the simple command is the rest of the words (`if true; then cd /etc; fi`,
# `while x; do touch ~/f; done`, `! git push -f`, `coproc touch /etc/x`). Before, the hook took `then` / `do` / `!` for the program and did not
# see the command, its writes or a `cd` after them (found while fixing review 7).
KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "coproc"}
# 0.2.52: the wrappers are WRAP_SYNTAX (read with their own options) and ALWAYS_ASK (below _split); this set is what they were
WRAPPERS = {"sudo", "doas", "nohup", "time", "command", "exec", "nice", "ionice", "stdbuf", "builtin", "chronic", "unbuffer",
            "setsid", "watch", "caffeinate", "proxychains", "proxychains4", "torsocks", "strace", "ltrace", "parallel", "taskset", "chrt"}
# CLIs whose job is talking to a remote service / publishing: the line is `opaque` (the owner decides), their sub-commands are not enumerated
CLOUD_CLIS = {"gh", "aws", "gcloud", "az", "gsutil", "rclone", "doctl", "heroku", "flyctl", "vercel", "netlify", "wrangler", "firebase", "terraform", "pulumi"}
PUBLISH = {("npm", "publish"), ("yarn", "publish"), ("pnpm", "publish"), ("cargo", "publish"), ("docker", "push"), ("podman", "push"),
           ("twine", "upload"), ("gem", "push"), ("helm", "push")}
# RT6 (28.10): the runner tables come from ONE registry (app/hookjudge/runners.py); five disagreeing tables let 104 runners pass
SHELLS = _runners.POSIX_SHELLS
INTERPRETERS = _runners.EVAL_INTERPRETERS
FETCHERS = {"curl", "wget", "fetch", "http", "https", "iwr", "aria2c", "xh", "httpie"}
# RT-0.2.54: readers that print FILE CONTENT while walking a directory tree. Rooted outside the project they reach into .ssh / .aws / *.pem
# WITHOUT naming them (the per-operand secret check only fires on a secret-named operand), so the owner is never asked and the secret read
# is never seen (no ESCALATE_SECRET_SEEN). A traversal root outside the project (and not a temp dir) -> asked.
RECURSIVE_CONTENT_READERS = {"grep", "egrep", "fgrep", "rgrep", "rg", "ripgrep"}
# 0.2.55: readers that print file NAMES while walking a tree (`ls -R ~`, `du -a ~`, `tree /Users`): the names of keys and tokens outside the
# project (id_rsa, *.pem, .env) are reconnaissance before a read. Same rule as the content readers: a recursive walk whose root is outside
# the project and not a temp directory -> asked. A one-level listing (`ls ~`, `ls /etc`, `du -sh ~`, `du -d 1 ~`) stays allowed.
RECURSIVE_NAME_READERS = {"ls", "du", "tree"}
REMOTE_SHELLS = {"ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "telnet", "ftp", "mosh", "socat"}
CURL_VALUE_LONG = {"--output", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--header", "--user", "--request", "--upload-file",
                   "--form", "--cookie", "--cookie-jar", "--config", "--max-time", "--write-out", "--proxy", "--user-agent", "--referer",
                   "--output-document", "--post-data", "--post-file", "--resolve", "--connect-to"}
URL_RE = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]{0,15})://(?:[^/@\s]*@)?(\[[0-9a-fA-F:.]+\]|[^/:?#\s\\\"'`]+)")
# 0.2.12 (R7-02): commands after which the hook no longer knows what the rest of the line does or where it runs: they run code from a
# string or a file (eval, source / ., trap's handler, a completion or mapfile callback), or change what a later word means (alias, hash -p,
# enable -f, shopt expand_aliases; zsh setopt / autoload / zmodload / emulate). The line is opaque, and a relative path after them is in an
# unknown directory (LOST_CWD), never "in the project".
EVALISH = {"eval", "source", ".", "alias", "unalias", "trap", "hash", "enable", "shopt", "setopt", "unsetopt", "fc", "bind", "complete",
           "compgen", "compdef", "function", "autoload", "zmodload", "emulate", "unfunction", "disable", "unhash", "functions"}
LOST_CWD = "/(unknown directory)"
DELETERS = {"rm", "unlink", "shred", "rmdir", "srm", "wipe"}
SAFE_SINKS = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"}
# 0.2.11 (R6-02): commands whose operands are files they read, copy or send: an operand the hook cannot resolve (`cat ${KEY}`) is opaque.
# The number is how many leading operands are not files (the pattern of grep / rg / sed / awk).
FILE_READERS = dict({n: 0 for n in ("cat", "head", "tail", "less", "more", "bat", "batcat", "nl", "tac", "rev", "base64", "base32", "xxd", "od",
                                    "hexdump", "strings", "wc", "file", "stat", "cp", "mv", "ln", "install", "tee", "source", ".", "scp", "rsync",
                                    "du", "ls", "diff", "cmp", "comm", "paste", "join", "cut", "sort", "uniq", "fold", "fmt", "pr", "split",
                                    "sha1sum", "sha256sum", "sha512sum", "md5sum", "shasum", "cksum", "gzip", "gunzip", "zcat", "bzip2", "xz",
                                    "zstd", "tar", "zip", "unzip", "7z", "gpg", "jq", "yq", "iconv", "dos2unix", "truncate", "touch", "mkdir",
                                    "rm", "rmdir", "unlink", "shred", "chmod", "chown", "dd", "open", "xdg-open", "pbcopy", "xclip",
                                    "column", "tree")},   # 0.2.51: column / tree (--fromfile) read the files they name
                    grep=1, egrep=1, fgrep=1, rg=1, ag=1, ack=1, sed=1, awk=1, gawk=1)
# 0.2.73 (N13, polygon series 9): readers whose plain-name operand (`cat h3.txt`, `curl -d @h3.txt`) is resolved too: a hard link of .env (the
# hook's fact samefile) or a symlink to it has a plain name. Not these: they show only names / sizes / types or change metadata, no content.
# N16 0.2.74 (series 10): commands that only look at a file's metadata (its name, size, mode, times, whether it exists) and never print a byte
# of it: `ls -la .env`, `stat .env`, `test -f .env`, `[ -f .env ]` name a credential file without reading it, so the name alone is not a
# secret read. Not here: du / wc (--files0-from=F reads F and prints its text in errors), file (prints what it finds inside), rm / chmod /
# truncate (they change the file), anything that reads; nor a credential DIRECTORY (`ls ~/.ssh` lists the keys: asked as before).
STAT_ONLY = frozenset({"ls", "stat", "test", "["})
META_ONLY = frozenset({"ls", "stat", "du", "file", "wc", "touch", "mkdir", "rm", "rmdir", "unlink", "shred", "chmod", "chown", "truncate", "tree"})

# 0.2.9: what makes a listed read-only command run something else (an entry of command.allow must not be a way to run other code).
# Environment assignments before a command (`LD_PRELOAD=./x.so ls`, `GIT_EXTERNAL_DIFF=./x git diff`, `PAGER=./x git log`): every variable
# except these display ones turns the identifier into "<id> [env VAR]".
SAFE_ENV = re.compile(r"(LANG|LANGUAGE|LC_[A-Z]+|TZ|NO_COLOR|FORCE_COLOR|CLICOLOR(_FORCE)?|TERM|COLUMNS|LINES|CI)")
SAFE_PAGER = {"GIT_PAGER", "PAGER"}                 # only with the value "cat" or empty
# wrappers that build a shell command line out of their arguments or of stdin: what runs is not what the list names
COMPOSING_WRAPPERS = {"xargs", "parallel", "watch"}
# git global options that do not change which code git runs; any other (-c, --config-env, --exec-path, --git-dir, --work-tree, -p ...) is a variant
GIT_SAFE_GLOBAL = {"-C", "--no-pager", "-P", "--no-optional-locks", "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs",
                   "--icase-pathspecs", "--no-replace-objects"}
# `git branch` options that only list (with them, operands are patterns or commits, nothing is created)
GIT_BRANCH_LIST = {"-l", "--list", "-a", "--all", "-r", "--remotes", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at",
                   "--show-current", "-v", "-vv", "--verbose", "--sort", "--format", "--color", "--no-color", "--column", "--no-column",
                   "--abbrev", "--no-abbrev", "-i", "--ignore-case", "--omit-empty"}
# git configuration keys whose value is a program or code git runs later (`git config core.fsmonitor ./x` then `git status` runs ./x)
GIT_EXEC_KEY = re.compile(r"(core\.(fsmonitor|pager|editor|sshcommand|hookspath|gitproxy|askpass|alternaterefscommand)|diff\.external|"
                          r"(diff|merge|filter)\..+|alias\..+|credential\..*|sequence\.editor|gpg\..*program|pager\..+|"
                          r"include\.path|includeif\..+|uploadpack\..+|receivepack\..+|remote\..+\.(uploadpack|receivepack|proxy)|"
                          r"protocol\..+|url\..+|http\..*(proxy|curloptresolve)|instaweb\..+|web\.browser|browser\..+|man\..+)", re.I)
# files git reads its configuration and hooks from: a write there is a way to make a later `git status`/`git diff` run a program
# 0.2.77 (red team R2-6): case-insensitive (APFS / NTFS open `.GIT/hooks` as .git/hooks) and `.git.` / `.git ` (NTFS drops trailing dots
# and blanks), as the hook's K1 guard (_in_git_dir); samefile.GIT_EXEC is a byte copy (test_0277_redteam)
GIT_EXEC_PATH = re.compile(r"(/\.gitattributes$|/\.gitmodules$|/\.git[. ]*$|/\.git[. ]*/(.+/)?(config|config\.worktree)$|/\.git[. ]*/(.+/)?hooks(/|$)|/\.gitconfig$|/\.config/git/config$)", re.I)


# 0.2.10: per runner, options that change which code or configuration it loads, or what it deletes (see _variants)
RUNNER_OPTS = {
    "pytest": {"-p", "-c", "--config-file", "--rootdir", "--confcutdir", "-o", "--override-ini", "--basetemp", "--pyargs"},
    "py.test": {"-p", "-c", "--config-file", "--rootdir", "--confcutdir", "-o", "--override-ini", "--basetemp", "--pyargs"},
    "npm": {"--script-shell", "--node-options", "--userconfig", "--globalconfig"},
    "pnpm": {"--script-shell", "--node-options"},
    "yarn": {"--script-shell"},
    "make": {"-f", "--file", "--makefile", "-I", "--include-dir", "--eval", "-E"},     # RT-0.2.55c: GNU make 4.4 `-E <text>` = --eval
    "cargo": {"--config", "-Z"},
    "go": {"-exec", "-toolexec", "-overlay", "-modfile"},
    "npx": {"-p", "--package", "-c", "--call"},
    "mypy": {"--config-file", "--python-executable"},
    # 0.2.11 (R6-03): the runners a project allowance may now cover; options that load code, plugins or configuration from elsewhere
    "jest": {"-c", "--config", "--setupFiles", "--setupFilesAfterEnv", "--testRunner", "--transform", "--globalSetup", "--globalTeardown",
             "--testEnvironment", "--resolver", "--reporters", "--preset", "--rootDir", "--roots", "--moduleDirectories", "--modulePaths",
             "--watchPlugins", "--testSequencer", "--snapshotResolver", "--runner", "--projects"},
    "vitest": {"-c", "--config", "-r", "--root", "--dir", "--environment", "--globalSetup", "--setupFiles", "--reporter", "--pool", "--workspace"},
    "mocha": {"-r", "--require", "--config", "--package", "--file", "--ui", "-u", "--reporter", "-R", "--loader", "--node-option", "-n"},
    "eslint": {"-c", "--config", "--rulesdir", "--plugin", "--resolve-plugins-relative-to", "--parser", "-f", "--format"},
    "prettier": {"--plugin", "--config", "--plugin-search-dir"},
    "pylint": {"--load-plugins", "--init-hook", "--rcfile"},
    "tox": {"-c", "-x", "--override", "--conf"},
    "nox": {"-f", "--noxfile"},
    "ruff": {"--config"},
}
# RT-0.2.55c: runners whose option parser takes a unique PREFIX of a long option (GNU getopt_long: make; nopt: npm/pnpm, `_` = `-`;
# argparse with abbreviations: pylint, tox, nox, mypy): `make --ev=<code>`, `npm test --node-opt=--import=data:...`, `pylint --init-h=<code>`
# are the listed options. And yargs (jest/vitest/mocha) reads `--setup-files` as `--setupFiles`: options are compared without `-`/`_`/case.
PREFIX_PARSERS = {"make", "npm", "pnpm", "pylint", "tox", "nox", "mypy"}


def _runner_opt(name, o, opts):
    """-> the listed long option that `o` (an option word without its `=value`) stands for, else None."""
    if not o.startswith("--") or len(o) < 4:
        return None
    canon = lambda x: x[2:].replace("-", "").replace("_", "").lower()    # noqa: E731
    c = canon(o)
    for x in sorted(opts):
        if x.startswith("--") and (canon(x) == c or (name in PREFIX_PARSERS and canon(x).startswith(c))):
            return x
    return None


# 0.2.11 (R6-03): interpreters and runners given code on the command line (`node -e`, `tsx -e`, `python -c`, `ruby -e` ...): "<id> [eval]".
# Whatever an owner listed for `node build.js` / `python x.py` then does not cover code written into the line itself.
EVAL_OPTS = {"node": {"-e", "--eval", "-p", "--print", "-r", "--require", "--import", "--loader", "--experimental-loader"},
             "python": {"-c"}, "ruby": {"-e", "-r"}, "perl": {"-e", "-E", "-M", "-m"}, "php": {"-r", "-B", "-R", "-E", "-F"},
             "lua": {"-e", "-l"}, "Rscript": {"-e"}, "osascript": {"-e"}, "julia": {"-e", "-E"}, "deno": {"eval"}, "bun": {"-e", "--eval", "-p", "--print"}}
for _n in ("nodejs", "tsx", "ts-node", "ts-node-dev", "esno", "tsm", "swc-node", "babel-node", "vite-node", "nodemon"):
    EVAL_OPTS[_n] = EVAL_OPTS["node"]


def is_git_exec_path(p: str) -> bool:
    """0.2.9: git's configuration, hooks, or a `.git` file (`gitdir:` pointer). Writing it is judged as dangerous (category git-config)."""
    return bool(GIT_EXEC_PATH.search(p))


# 0.2.24 (critique A): the agent's OWN harness: Claude Code settings / hooks / commands / agents (`.claude/**`, project or ~), and the MCP client
# configuration files (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, Claude Desktop's config). A write there can switch the witness off for
# the next session (remove the hook, add an unproxied MCP server): it is dangerous, always asked (category agent-config), like git-config.
# 0.2.77 (red team R2-3): other agents' harness in the same project or home -- files whose program those tools start by themselves (hooks,
# MCP servers, tasks run on folder open): .cursor/hooks.json, .gemini/settings.json, .vscode/tasks.json, .windsurf/*.json (hooks, MCP),
# Windsurf's MCP config, .roo/mcp.json, .kiro/settings|hooks, .amazonq/mcp.json and its agents, opencode.json. Instruction files (CLAUDE.md,
# AGENTS.md, rules/steering folders) and .vscode/settings.json are NOT here: edited all the time (fatigue), named as a known limit.
AGENT_CONFIG_PATH = re.compile(r"(/\.claude(/(?!projects/[^/]+/memory/)|$)|/\.claude\.json$|/\.mcp\.json$|/\.cursor/(mcp|hooks)\.json$|/\.vscode/(mcp|tasks)\.json$|/claude_desktop_config\.json$|"
                               r"/\.config/claude(/|$)|/Library/Application Support/Claude/|/\.gemini/settings\.json$|/\.windsurf/[^/]+\.json$|"
                               r"/\.codeium/windsurf/mcp_config\.json$|/\.roo/mcp\.json$|/\.kiro/(settings|hooks)/|/\.amazonq/(mcp\.json$|(cli-)?agents/)|"
                               r"/opencode\.jsonc?$)", re.I)


def is_agent_config_path(p: str) -> bool:
    return bool(AGENT_CONFIG_PATH.search(p))

# Secrets: file names / directories whose CONTENT is a credential. Matched on path segments, not on substrings of words.
SECRET_NAME = re.compile(r"(^|/)(\.env(\.[\w.-]+)?|\.envrc|\.netrc|\.npmrc|\.pypirc|\.pgpass|\.git-credentials|\.?credentials(\.json)?|"
                         r"\.vault-token|\.terraformrc|credentials\.tfrc\.json|\.s3cfg|\.boto|\.my\.cnf|\.authinfo(\.gpg)?|rclone\.conf|\.(zsh|bash)_history|[\w.-]+\.ovpn|"   # RT-0.2.55 (+history/ovpn by Deus): common plaintext cred files missing before
                         r"id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|ssh_host_[\w-]+_key|[\w.-]+\.(pem|key|p12|pfx|jks|keystore|kdbx|ppk|p8)|secrets?\.(ya?ml|json|toml|env)|"
                         r"Login Data|Cookies|Web Data|logins\.json|key4\.db|cookies\.sqlite|Cookies\.binarycookies|[\w .-]*passwords[\w .-]*\.csv|[\w.-]+\.1pux|"   # r0293: browser stores, password exports
                         r"(bitwarden|lastpass|1password|keepass|dashlane|nordpass)[\w .-]*\.(csv|json|xml|txt))$", re.I)
SECRET_DIR = re.compile(r"(^|/)(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config/(gcloud|gh|op|hub|doctl|fly|rclone|containers|sops|deus-witness)|\.azure|Library/Keychains|Library/(Mail|Messages|Cookies)|\.thunderbird|Library/Thunderbird|[\w .-]+\.mbox)(/|$)", re.I)   # RT-0.2.55: more ~/.config service cred dirs
SECRET_DIR_ITSELF = re.compile(r"(^|/)(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config/(gcloud|gh|op|hub|doctl|fly|rclone|containers|sops)|\.azure)$", re.I)   # 0.2.91
SECRET_ENV = re.compile(r"\$\{?(\w*(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY)\w*)\}?", re.I)
# 0.2.90 (gate G4 "persistence / watchdog", FABLE-NOL 03.11 p.2.1): places whose text runs at the next login / shell / session or switches
# the witness off. A write there is the danger `persist` (the hook refuses it outright: "only by hand at your terminal"), whatever the
# mandate's `unlisted` says. Agent config elsewhere in ~/.claude (memory, tools, projects) stays `agent-config` (asked, approvable).
PERSIST_PATH = re.compile(r"(^|/)(\.(zshrc|zprofile|zshenv|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|profile|login|cshrc|tcshrc|kshrc|mkshrc|"
                          r"xinitrc|xprofile|xsession|pam_environment|hushlogin)|\.config/fish/[^/]+\.fish|\.config/fish/conf\.d/.*|"
                          r"Library/LaunchAgents(/.*)?|Library/LaunchDaemons(/.*)?|Library/StartupItems(/.*)?|\.config/autostart/.*|\.config/systemd/user/.*|"
                          r"\.claude/settings(\.local)?\.json|\.claude/hooks(/.*)?|\.claude/plugins(/.*)?|\.claude\.json|\.mcp\.json|"
                          r"\.config/deus-witness(/.*)?|\.deus-witness(/.*)?|Library/Application Support/deus-witness(/.*)?|\.local/share/deus-witness(/.*)?|deus-witness/shadow(/.*)?|"
                          r"\.ssh/(authorized_keys2?|config|rc|environment)|\.config/git/hooks(/.*)?|\.gitconfig|\.config/git/config)$|"
                          r"^/(private/)?etc/(cron\.[^/]+/.*|crontab|cron\.d/.*|profile(\.d/.*)?|bashrc|zshrc|zprofile|zshenv|sudoers(\.d/.*)?|hosts|paths(\.d/.*)?|"
                          r"launchd\.conf|rc\.[^/]+|environment|ld\.so\.[^/]+|pam\.d/.*)$|^/(private/)?var/(at|cron|spool/cron)/.*|"
                          r"^/Library/(LaunchAgents|LaunchDaemons|StartupItems)/.*", re.I)


def is_persist_path(p: str) -> bool:
    return bool(PERSIST_PATH.search(p))


# r0298 (decision of Deus 14.11, KLIENT-0.2.76-AUTO.md p.4): a RELATIVE write in an unknown directory (LOST_CWD: `false && cd x` + a line
# feed, eval, source ...) whose tail names a place that starts programs by itself -- PERSIST_PATH (shell rc, LaunchAgents, Claude Code's
# settings / hooks / plugins, .mcp.json, the witness, ~/.gitconfig ...) or git's own hooks / config -- carries the danger `autostart`
# next to the opaque mark. Not a refusal (`persist`, Н4): which folder the file lands in is not known, so the article is not certain
# (constitution: "a refusal is only for what is certain"). It is a question that says the truth: the words of qwords SCREEN
# "autostart_*" (mr-vocab-4), "Allow once" / "No" only -- never "from now on" (allowances.offer, repeat.eligible: a dangerous command).
# The mark stands FIRST in the line's danger list: the question's recipient is the first mark (toolmap.recipient_values).
AUTOSTART = "autostart"
AUTOSTART_GIT = re.compile(r"(^|/)\.git[. ]*/(.+/)?(hooks(/|$)|config(\.worktree)?$)", re.I)


def is_autostart_tail(t) -> bool:
    """r0298: a relative path whose tail is a place that starts programs by itself, wherever the unknown directory is."""
    return isinstance(t, str) and bool(t) and (is_persist_path(t) or bool(AUTOSTART_GIT.search(t)))


# 0.2.90: variables and aliases a line sets ONCE with a literal value (`D=/x; cat $D/f`, `alias ll='ls -la'; ll`) are read as bash would
# substitute them: the path / command is then judged, not "unknown" (the fatigue of 03.11: 60+ `path from expansion: $f` on the owner's own
# notes). One frame per command line (a nested `bash -c` / `$(..)` starts empty); a name set twice, read, unset or looped over is unknown
# again (None). Never a value with `$`, a backquote, a glob or `~user` (bash would build it), and never HOME / PWD (REASSIGN: opaque).
_FRAMES = []
_VAR_REF = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_LIT_VALUE = re.compile(r"[^$`*?\[\]\\]*")


def _frame():
    return _FRAMES[-1] if _FRAMES else None


# r0299 (AVTOZAPUSK-NEIZVESTNAYA-PAPKA.md, "what is left"): an unknown DIRECTORY makes only RELATIVE paths unknown. After `false && cd X` +
# a line feed (a cd that may or may not have run, a cd in a pipeline) $HOME is still the hook's $HOME: `echo x > ~/.bashrc` writes the same
# file in any directory, and is refused (Н4) exactly as without the prefix. Only what can change the meaning of HOME itself -- eval, source,
# alias, trap ... (EVALISH) or a function defined in the line -- makes ~ / $HOME unknown as well ("home lost", sticky for the rest of the
# line and inherited by its nested command lines); then such a write stays a question (autostart / opaque) as in r0298.
def _lose_home():
    f = _frame()
    if f is not None:
        f["home_lost"] = True


def _home_lost() -> bool:
    f = _frame()
    return bool(f and f.get("home_lost"))


def _known_without_cwd(t, cwd, home):
    """r0299: -> True when the path word `t` names the same file in any directory: absolute after expansion ($HOME, $TMPDIR, a literal line
    variable), or `~` / `~/...`, and $HOME has not been lost (_home_lost). `$PWD/...` and anything under the unknown directory are not."""
    if _home_lost():
        return False
    e = _expand(t, cwd, home)
    if e is None or not e:
        return False
    if e == "~" or e.startswith("~/"):
        return True
    return e.startswith("/") and not _in_project(os.path.normpath(e), LOST_CWD)


def _set_var(name, value):
    f = _frame()
    if f is None:
        return
    v = f["vars"]
    v[name] = None if name in v else value          # set twice in one line: which one holds at a later word is not known


def _var_value(name):
    f = _frame()
    v = (f or {}).get("vars", {}).get(name) if f else None
    return v if isinstance(v, str) else None


def _subst_vars(w: str):
    """`$NAME` / `${NAME}` of a variable this line set once, outside single quotes (the masked token keeps quote marks) -> its value."""
    if "$" not in w or not _FRAMES or not _frame()["vars"]:
        return w
    out, i, n, sq = [], 0, len(w), False
    while i < n:
        ch = w[i]
        if ch == "'":
            sq = not sq
            out.append(ch)
            i += 1
            continue
        if ch == "$" and not sq:
            m = _VAR_REF.match(w, i)
            if m:
                val = _var_value(m.group(1) or m.group(2))
                if val is not None:
                    out.append(val)
                    i = m.end()
                    continue
        out.append(ch)
        i += 1
    return "".join(out)


def _claude_env(c, name: str, tok: str, home: str, detail: str) -> None:
    """0.2.91 (friction 04.11): a CLAUDE_* variable set in the line (`CLAUDE_CONFIG_DIR=/tmp/cfg claude -p ..`, `export CLAUDE_CODE_..`)
    lives only in this shell: Claude Code starts every Bash call in a fresh shell. It is the danger `witness` (a Claude Code run the
    witness may not watch: ASKED, the owner can approve it), not `persist` (a place that runs at the next login, refused with no button).
    CLAUDE_CONFIG_DIR with a literal value other than ~/.claude marks the line: `claude plugin|mcp|config ..` then changes that other
    configuration, not the agent's own (see _gates)."""
    c.add("witness", detail)
    if name.upper() != "CLAUDE_CONFIG_DIR" or "=" not in tok:
        return
    v = str(_unmask(tok.split("=", 1)[1]))
    if not v or re.search(r"[$`*?\[]", v):
        return
    if v == "~" or v.startswith("~/"):
        v = (home or "~") + v[1:]
    if not v.startswith("/"):
        return
    real = [os.path.normpath(os.path.join(h, ".claude")) for h in (home,) if h]
    fr = _frame()
    if fr is not None and os.path.normpath(v) not in real:
        fr["alt_cfg"] = True


def _record_assignment(tok: str, home: str) -> str | None:
    """A masked token `NAME=value` as a bare assignment of the line -> the name recorded (its value known or not), else None."""
    m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)(\+?=)(.*)", tok, re.S)
    if not m:
        return None
    name, op, raw = m.group(1), m.group(2), m.group(3)
    val = _unmask(raw)
    quoted = raw != val or isinstance(val, _Lit)
    if op == "+=" or (not isinstance(val, _Lit) and (re.search(r"[$`]", val) or re.search(r"[*?\[]", val))) or re.match(r"~[^/]", val):
        _set_var(name, None)
    else:
        v = str(val)
        if not quoted and (v == "~" or v.startswith("~/")):
            v = home + v[1:]                      # bash expands a bare ~ in an assignment, not a quoted one
        _set_var(name, v)
    return name


def _set_alias(args) -> bool:
    """`alias NAME='words'` with literal words only -> recorded; -> False when any part cannot be read (the line stays opaque)."""
    f = _frame()
    if f is None or not args:
        return False
    for a in args:
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_.-]*)=(.*)", a, re.S)
        if not m:
            return False
        val = _unmask(m.group(2))
        if (not isinstance(val, _Lit) and re.search(r"[$`]", val)) or re.search(r"[;&|<>(){}\n]", str(val)) or not str(val).strip():
            return False
        try:
            words = shlex.split(str(val))
        except ValueError:
            return False
        if not words or any(re.search(r"[$`*?\[]", w) for w in words):
            return False
        f["aliases"][m.group(1)] = words
    return True

# Raw-text backstops (they also see inside quoted strings, heredocs and interpreter one-liners)
SQL_DROP = re.compile(r"\b(DROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|USER|ROLE)|TRUNCATE\s+(TABLE\s+)?\w|DELETE\s+FROM\s+[\w.\"`]+\s*(;|$|\"|'))", re.I)
RAW_RM = re.compile(r"\b(shutil\.rmtree|fs\.rm(Sync)?\s*\([^)]{0,200}recursive|rimraf|os\.removedirs|FileUtils\.rm_r|rm\s+-[a-zA-Z]*[rR])", re.S)
RM_R_WORD = re.compile(r"\brm\s+-[a-zA-Z]*[rR]")
RAW_PIPE_SHELL = re.compile(r"<\s*\(\s*(curl|wget)\b|\b(ba|z|da)?sh\s+-c\s+[\"']?\$\(\s*(curl|wget)\b|\beval\s+[\"']?\$\(\s*(curl|wget)\b", re.I)
PIPE_FROM = re.compile(r"\b(curl|wget|fetch|iwr)\b", re.I)
PIPE_INTO = re.compile(r"\s*(sudo\s+)?(\S*/)?((ba|z|da|k)?sh|python[0-9.]*|perl|ruby|node|php)\b", re.I)
MAX_CMD = 256 * 1024                       # a longer line is not parsed: `opaque` (the owner decides)
HEREDOC_READER = re.compile(r"(^|[;&|(]\s*)(sudo\s+)?(\S*/)?(sh|bash|zsh|dash|ksh|(?:python|pypy)[0-9.]*|node|perl|ruby|php|ssh|eval|source|\.(?=\s))(\b|(?<=\.))")
# 29.10 (ReDoS, OTCHET-REDOS-AUDIT-2910 #2): HEREDOC_READER.search re-scanned `(\S*/)?` to the end of the word from EVERY `;&|(` inside it
# (';' x 32 000 + 'X': 1.3 s, quadratic). heredoc_reader() gives exactly HEREDOC_READER.search(s).group(4) (same start order, same greedy
# rightmost '/', sudo first), but each word's rightmost "/<reader>" is found once. The regex stays as the reference (tests compare the two).
_HR_CMD = re.compile(r"(sh|bash|zsh|dash|ksh|(?:python|pypy)[0-9.]*|node|perl|ruby|php|ssh|eval|source|\.(?=\s))(\b|(?<=\.))")
_HR_SUDO = re.compile(r"sudo\s+")
_HR_WS = re.compile(r"\s*")
_HR_WORD = re.compile(r"\S+")


def heredoc_reader(s):
    """-> the reader of a heredoc head (group 4 of HEREDOC_READER.search(s)) or None. Linear."""
    n = len(s)
    words = [m.span() for m in _HR_WORD.finditer(s)]
    starts = [a for a, _ in words]
    best = {}                                              # word index -> reader after its rightmost '/' that has one (or None)

    def after_slash(q):                                    # `(\S*/)(reader)` at q: the rightmost '/' at or after q in q's word
        if q >= n or not starts:
            return None
        k = bisect.bisect_right(starts, q) - 1
        if k < 0 or not (words[k][0] <= q < words[k][1]):
            return None                                    # q is on whitespace: `\S*/` needs a '/' right here
        if k not in best:
            a, b = words[k]
            best[k] = None
            j = s.rfind("/", a, b)
            while j >= 0:
                m = _HR_CMD.match(s, j + 1)
                if m:
                    best[k] = (j, m.group(1))
                    break
                j = s.rfind("/", a, j)
        r = best[k]
        return r[1] if r and r[0] >= q else None

    def at(q):                                             # (reader) right at q
        m = _HR_CMD.match(s, q)
        return m.group(1) if m else None

    def attempt(q):
        m = _HR_SUDO.match(s, q)
        if m:
            r = after_slash(m.end()) or at(m.end())
            if r:
                return r
        return after_slash(q) or at(q)

    r = attempt(0)
    if r:
        return r
    for i in range(n):
        if s[i] in ";&|(":
            r = attempt(_HR_WS.match(s, i + 1).end())
            if r:
                return r
    return None
# s7 (polygon series 7, O1, 28.10): the network of CODE an interpreter is given on the line (`python3 -c`, `node -e`, `perl -e`, `osascript -e`,
# `python3 - <<EOF`, `echo code | node`, a git alias `!...`). Before, such code was only "<id> [eval]": the owner saw "python3 [eval]",
# Dangerous false, and one tap sent data to a host outside the mandate. Now a URL literal in the code is a host of the line (Bash.net, judged
# like curl: outside message.domains -> deny RECIPIENT); a network API or program with no literal host, or a URL whose host is built at run
# time ("https://" + h, f"https://{h}", `https://${h}`), is the danger "opaque:network ..." (asked as dangerous, the page shows the code).
# A tripwire like the rest of this file: code that hides both the API and the URL (getattr + string building, base64) is not seen.
CODE_URL_RE = re.compile(r"\b(https?|wss?|ftps?|sftp|ssh|git|telnet|gopher|dict|ldaps?|smtps?|imaps?|pop3s?|tftp|mqtts?|amqps?|redis)://"
                         r"(?:[^/@\s'\"`]*@)?(\[[0-9a-fA-F:.]+\]|[^/:?#\s\\\"'`]*)", re.I)
# 29.10 (hang): each label is ATOMIC. `(?:label\.?)+` split a dotless run of n characters in 2^n ways before a fullmatch failed on a
# character no host has (`https://aaaa...a;`): one curl line held a server thread for minutes. A label now takes its longest form once
# (<= 64 characters, no backtracking into it); a host the old pattern took only by re-splitting a run is not a literal host now (fail closed).
HOST_OK = re.compile(r"(?>[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?\.?)+|\[[0-9a-fA-F:.]+\]")
CODE_NET_API = re.compile(
    r"\b(?:urlopen|urlretrieve|urllib[0-9]?|requests\s*\.\s*(?:get|post|put|patch|delete|head|request|Session)|httpx|aiohttp|http\.client|"
    r"(?:import|from)\s+[\w.]*requests|httplib2?|pycurl|paramiko|"
    r"HTTPS?Connection|socket|ftplib|smtplib|telnetlib|xmlrpc|websockets?|XMLHttpRequest|WebSocket|EventSource|sendBeacon|axios|undici|"
    r"node-fetch|superagent|https?\s*\.\s*(?:get|request)|net\s*\.\s*(?:connect|createConnection|Socket)|tls\s*\.\s*connect|dgram|http2|"
    r"LWP|HTTP::Tiny|IO::Socket|Net::\w+|open-uri|URI\s*\.\s*open|TCPSocket|UDPSocket|Faraday|HTTParty|RestClient|"
    r"file_get_contents|curl_init|curl_exec|fsockopen|stream_socket_client|NSURL\w*|"
    r"Deno\s*\.\s*connect|Bun\s*\.\s*connect|Invoke-WebRequest|Invoke-RestMethod)\b|"
    r"(?<![./\w-])(?:curl|wget|ncat|netcat|socat|ssh|scp|sftp|rsync|telnet|ftp|aria2c)\b(?![./-])|\bfetch\s*\(|\bdo\s+shell\s+script\b|"
    r"(?<![./\w-])nc\s+-?\w", re.I)


# rt2810 (RT-CODE-NET, false RECIPIENT): a URL literal in code with no network API is a host of the line unless it is plainly inert: inside
# the first string argument of a printing call (`print('visit https://x')`, `console.log("https://x")`, `puts "https://x"`) or in a line
# comment with no quote before it on its line (`// https://x`, `# https://x`). Any other place keeps the host (fail closed): the URL may be
# handed to a function that fetches it and is not in CODE_NET_API (pandas read_csv, R url(), PHP fopen, webbrowser.open ...).
PRINT_LIKE = (r"print|println|printf|puts|say|echo|warn|pprint|console\s*\.\s*(?:log|error|info|warn|debug)|"
              r"(?:sys|process)\s*\.\s*std(?:out|err)\s*\.\s*write|System\s*\.\s*out\s*\.\s*print(?:ln)?")
INERT_PRINT = re.compile(r"(?:^|[^\w.$])(?:%s)\s*(?:\(\s*)?[fFbBrRuU]{0,2}(['\"])[^'\"\n\r{}]*$" % PRINT_LIKE)
INERT_COMMENT = re.compile(r"^[^'\"`\n]*?(?:^|\s|;)(?:#|//)")


def _inert_url(text: str, pos: int) -> bool:
    start = max(text.rfind(x, 0, pos) for x in ("\n", "\r", "\u2028", "\u2029")) + 1    # python / js line ends (a \r ends a comment)
    line = text[max(start, pos - 400):pos]
    return bool(INERT_PRINT.search(line) or INERT_COMMENT.search(line))


# rt2810 (RT-CODE-NET, obfuscation): code that builds what it runs or imports at run time hides both the network API and the host from a
# text scan (`getattr(__import__('urll'+'ib.request'),'url'+'open')`, `exec(base64.b64decode(..))`, `exec(bytes([..]).decode())`,
# `importlib.import_module('req'+'uests')`, `require('ht'+'tp')`, `new Function(..)`, PHP `eval(base64_decode(..))`, `$f(..)`). Such code is
# the danger "opaque:obfuscated code" (fail closed: asked as dangerous), without trying to prove network. Not matched: print / json / plain
# imports, `re.compile`, `ast.literal_eval`, `/re/.exec(s)`, `require('fs')` with a literal module, a perl `eval { }` block.
CODE_OBFUSCATED = re.compile(
    r"(?<![.\w$-])(?:exec|eval|execfile|compile)\s*\(|"                      # python / js / php / ruby dynamic code
    r"__import__|\bimportlib\b|__(?:class|base|bases|mro|globals|code|loader|spec|reduce(?:_ex)?)__|\bsys\s*\.\s*modules\b|"
    r"\bprocess\s*\[|(?<![.\w])getattr\s*\(|(?<![.\w])setattr\s*\(|__builtins__|__dict__|__getattribute__|__subclasses__|"
    r"\b(?:globals|locals|vars)\s*\(\s*\)\s*\[|\b(?:attrgetter|methodcaller)\b|\bctypes\b|\b(?:marshal|pickle|dill)\s*\.\s*loads?\b|"
    r"\b(?:b64|b32|b16|b85|a85|urlsafe_b64)decode\b|\bdecodebytes\b|\bdecodestring\b|\bcodecs\s*\.\s*decode\b|\brot_?13\b|"
    r"\bzlib\s*\.\s*decompress\b|\b(?:lzma|bz2|gzip)\s*\.\s*decompress\b|\bbytes(?:array)?\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*\.\s*decode\b|"
    r"\.\s*fromhex\s*\(|\bbinascii\b|"
    r"(?<![.\w])Function\s*\(|\bnew\s+Function\b|\bconstructor\s*\(|\[\s*['\"]constructor['\"]\s*\]|\bString\s*\.\s*fromCharCode\b|"
    r"\batob\s*\(|\bBuffer\s*\.\s*from\s*\([^)]*['\"](?:base64|hex|base64url)['\"]|\brequire\s*\(\s*(?![\"'][^\"'+]*[\"']\s*\))|"
    r"(?<![.\w])import\s*\(\s*(?![\"'][^\"'+]*[\"']\s*\))|\bvm\s*\.\s*(?:run\w*|Script|compile\w*)|\brequire\s*\(\s*['\"](?:node:)?vm['\"]|"
    r"\bprocess\s*\.\s*(?:binding|dlopen|mainModule)\b|\bmodule\s*\.\s*constructor\b|\b(?:globalThis|global|window|self)\s*\[|"
    r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]|"
    r"\b(?:instance_eval|class_eval|module_eval|instance_exec|public_send|__send__|const_get|define_method)\b|\.\s*send\s*\(?\s*[:'\"]|"
    r"\bunpack1?\s*\(\s*['\"]m|\bBase64\s*\.\s*\w*decode|\bdecode_base64\b|\bMIME::Base64\b|(?<![.\w$-])eval\b(?!\s*\{)|"
    r"\b(?:base64_decode|str_rot13|gzinflate|gzuncompress|gzdecode|create_function|call_user_func(?:_array)?|assert)\s*\(|"
    r"\bpreg_replace\s*\(\s*['\"](.).*\1[a-zA-Z]*e[a-zA-Z]*['\"]|(?<![\w\\])\$\w+\s*\(|\$\{\s*['\"]|"
    r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]+\}|\\[0-7]{3}){2,}|"
    # adaptive RT 28.10: perl do / require of a file or a variable, ruby load / require_relative / require of a variable or a path,
    # a URL scheme split by a concatenation ('ht'+'tp://'), /dev/tcp split by awk's string juxtaposition ("/dev/" "tcp/...")
    r"(?<![\w$>-])do\s+(?:['\"]|\$)|(?<![\w$>.-])require\s+(?:\$|['\"][^'\"]*[/.][^'\"]*['\"])|"
    r"(?<![\w.])(?:load|require_relative)\s*\(?\s*(?:['\"]|[a-z_$@])|"
    r"['\"](?:h|ht|htt|https?|https?:|https?:/|wss?|ftp)['\"]\s*[+.]|['\"][^'\"]{0,3}['\"]\s*[+.]\s*['\"](?:tps?|ps?|s?:)?:?//|"
    r"/dev/['\"]\s*[+.]?\s*['\"]\s*(?:tcp|udp)\b", re.S)


# a program run by the code whose name is built from pieces: `subprocess.run(['cu'+'rl', h])`, `system("cu"."rl")`, `''.join(..)`, `[::-1]`
CODE_PROC = re.compile(r"\bsubprocess\b|\bos\s*\.\s*(?:system|popen|exec\w*|spawn\w*|posix_spawn\w*)|\bpty\s*\.\s*spawn|\bchild_process\b|"
                       r"\b(?:execSync|spawnSync|execFile\w*|shell_exec|passthru|proc_open|popen|IO\s*\.\s*popen|Open3|Process\s*\.\s*spawn)\b|"
                       r"(?<![.\w$-])(?:system|exec|spawn)\s*\(|\bqx\b|`")
CODE_BUILT = re.compile(r"['\"]\s*[+.]\s*['\"]|['\"]\s+['\"]|\.\s*join\s*\(|\[\s*:\s*:\s*-|\breversed\s*\(|\bchr\s*\(|\bord\s*\(|\bfromCharCode\b|"
                        r"\.\s*(?:replace|translate|reverse)\s*\(|"
                        r"['\"]\s*%\s*[\w('\"]|\.\s*format\s*\(|\bf['\"][^'\"]*\{|\w\]\s*\+\s*\w")   # adaptive RT 28.10: % / .format / f-string / p[0]+p[1]


def code_obfuscated(text: str):
    """rt2810: -> the matched primitive of dynamic code / import / decoding in a piece of interpreter code, else None."""
    if not isinstance(text, str):
        return None
    m = CODE_OBFUSCATED.search(text)
    if m:
        return " ".join(m.group(0).split())[:40]
    p = CODE_PROC.search(text)
    b = CODE_BUILT.search(text) if p else None
    return ("%s with a built name (%s)" % (" ".join(p.group(0).split()), " ".join(b.group(0).split())))[:60] if b else None


def code_net(text: str):
    """s7: -> (hosts, unseen). hosts: the literal network hosts in a piece of code; unseen: why the code may talk to a host that is not a
    literal (a network API or program without any literal host, or a URL whose host is built at run time), else None.
    rt2810: with no network API in the code, a URL literal in a print argument or a line comment is not a host (_inert_url)."""
    hosts, runtime = [], None
    if not isinstance(text, str):
        return hosts, None
    api = CODE_NET_API.search(text)
    for m in CODE_URL_RE.finditer(text):
        h = m.group(2)
        if h and HOST_OK.fullmatch(h):
            if not api and _inert_url(text, m.start()):
                continue
            h = h.strip("[]").lower().rstrip(".")
            if h and h not in hosts:
                hosts.append(h)
        elif runtime is None:
            runtime = "host built at run time (%s)" % m.group(0)[:60]
    if runtime:
        return hosts, runtime
    if api and not hosts:
        return hosts, "%s without a literal host" % " ".join(api.group(0).split())[:40]
    return hosts, None


_CODE = [0]          # 10.11 (r0260): > 0 while interpreter code is scanned (Command.add / host record the origin of a mark)


def _code_scan(code, c, who, obfuscation=True) -> None:
    """s7: the hosts of interpreter code go to the line's network (Bash.net); a host it cannot show makes the line dangerous.
    rt2810: code that builds what it runs / imports at run time is the danger "opaque:obfuscated code" (obfuscation=False: awk programs,
    whose `system()` / sockets are tagged [exec] already)."""
    _CODE[0] += 1
    try:
        if isinstance(code, str) and code not in c.code_texts:
            c.code_texts.append(code)
        _code_scan1(code, c, who, obfuscation)
    finally:
        _CODE[0] -= 1


def _text_view(code, who):
    """11.11 (r0261c, class (а)): edit-only inline Python (inline.edit_only: no network module, no exec / subprocess / import machinery)
    cannot reach a host; a host inside one of its TEXT literals (a test line `"curl -s https://evil.example/x"` the code writes into a
    file) is text, not network: the literals are blanked before the host scan (a bare URL / path literal stays). Any other code: as is."""
    if not (isinstance(who, str) and isinstance(code, str) and PY_MODULE.fullmatch(who.rsplit("/", 1)[-1])):
        return code
    from .inline import _blank_text_literals, edit_only
    if edit_only(code, ext=True) is None:          # r0261d: the project's own modules too (inline.edit_only ext)
        return code
    nb = _blank_text_literals(code)
    return nb if nb is not None else code


def _code_scan1(code, c, who, obfuscation=True) -> None:
    hosts, unseen = code_net(_text_view(code, who))
    for h in hosts:
        c.host(h)
    if unseen:
        c.add("opaque", "network from %s code: %s" % (who, unseen))
    ob = code_obfuscated(code) if obfuscation else None
    if ob:
        c.add("opaque", "obfuscated code (%s): %s" % (who, ob))


# rt2810 (RT-CODE-NET, critical): bash / zsh / ksh open a TCP / UDP socket for a redirection to /dev/tcp/HOST/PORT or /dev/udp/HOST/PORT
# (`cat < /dev/tcp/h/80`, `exec 3<>/dev/tcp/h/80`), gawk for "/inet/tcp/LPORT/HOST/RPORT" and "/dev/tcp/..." with `|&`. Anywhere on the line
# -- an operand (`cat /dev/tcp/h/80`), a redirection target, `bash -c` text, awk / interpreter code -- HOST is a host of the line (Bash.net,
# like `curl HOST`), and the simple command naming it gets the tag [net] (`cat [net]` is not the `cat` of the default list). A host the line
# does not show (`/dev/tcp/$H/80`) or a listening gawk socket is opaque:network.
DEV_NET = re.compile(r"/+dev/+(?:\./+)*(?:tcp|udp)/+([^/\s'\"`;|&<>()]*)/")
DEV_SPLIT = re.compile(r"/+dev/*['\"]\s*[+.]?\s*['\"]\s*/*(?:tcp|udp)\b|/inet[46]?/*['\"]\s*[+.]?\s*['\"]")
INET_NET = re.compile(r"/inet[46]?/(?:tcp|udp)/[^/\s'\"`]*/([^/\s'\"`]*)/")


def _dev_net(text, c) -> bool:
    """rt2810: the socket paths in a piece of text -> their hosts on the line; True when there is one."""
    if not isinstance(text, str) or ("/dev" not in text and "/inet" not in text):
        return False
    seen = False
    if DEV_SPLIT.search(text):          # adaptive RT 28.10: "/dev/" "tcp/h/80" (awk juxtaposition), '/dev/'+'tcp/...': the host is built
        c.add("opaque", "network: a /dev/tcp path built from pieces")
        seen = True
    for rx, kind in ((DEV_NET, "/dev/tcp"), (INET_NET, "/inet")):
        for m in rx.finditer(text):
            seen = True
            h = m.group(1).strip("[]")
            if kind == "/inet" and h in ("", "0"):
                c.add("opaque", "network: listening socket %s" % m.group(0)[:60])
            elif h and not re.search(r"[$`]", h) and HOST_OK.fullmatch(h):
                c.host(h)
            else:
                c.add("opaque", "network: %s to a host the line does not show (%s)" % (kind, m.group(0)[:60]))
    return seen


# rt2810 (RT-CODE-NET, medium): environment variables that make a program load code the line does not show. `PYTHONSTARTUP=/tmp/x.py python3`,
# `NODE_OPTIONS=--require=/tmp/x.js node app.js`, `PERL5OPT=-Murllib perl s.pl`, `RUBYOPT=-r/tmp/x ruby s.rb`, `BASH_ENV=./x bash s.sh`
# -- as a prefix, through `env`, `export` or a bare assignment -> the danger "opaque:code injected through VAR".
# Options that load nothing stay the old "[env VAR]" question (`NODE_OPTIONS=--max-old-space-size=4096 npm run build`).
ENV_INJECT_ALWAYS = {"PYTHONSTARTUP", "BASH_ENV", "PERL5DB"}
# 0.2.43b (OTCHET-RT2810-PRAVKI, proposal 1): the dynamic loader loads a library the line does not show into EVERY program it starts
# (`LD_PRELOAD=./x.so ls`, `DYLD_INSERT_LIBRARIES=...`, a library path that puts the agent's .so first). Was "[env VAR]" (an ordinary
# question, 0.2.9); now the danger "opaque:code injected through VAR" as well (asked as dangerous). The head keeps its "[env VAR]" tag.
ENV_INJECT_LOADER = re.compile(r"LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|DYLD_[A-Z0-9_]+")
ENV_INJECT_OPT = {
    "NODE_OPTIONS": re.compile(r"(?:^|\s)(?:-r|--require|--import|--(?:experimental-)?loader|--experimental-policy|--inspect\S*)(?:[=\s]|$)"),
    "PERL5OPT": re.compile(r"(?:^|\s)-[A-Za-z]*[MmdI]"),
    "RUBYOPT": re.compile(r"(?:^|\s)-[A-Za-z]*[rI]"),
    "JAVA_TOOL_OPTIONS": re.compile(r"-(?:javaagent|agentpath|agentlib)|OnOutOfMemoryError|OnError"),
    "_JAVA_OPTIONS": re.compile(r"-(?:javaagent|agentpath|agentlib)|OnOutOfMemoryError|OnError"),
    "JDK_JAVA_OPTIONS": re.compile(r"-(?:javaagent|agentpath|agentlib)|OnOutOfMemoryError|OnError"),
}


def _env_inject(words, c) -> None:
    for a in words:
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\+?=(.*)", a, re.S) if isinstance(a, str) else None
        if not m:
            continue
        k, v = m.group(1), m.group(2)
        rx = ENV_INJECT_OPT.get(k)
        if (k in ENV_INJECT_ALWAYS or ENV_INJECT_LOADER.fullmatch(k)) and v or (rx and (rx.search(v) or re.search(r"[$`]", v))):
            c.add("opaque", "code injected through %s=%s" % (k, v[:60]))


# 10.11 (r0260): variables before a command. An ordinary one (UV_CACHE_DIR, SOURCE_DATE_EPOCH, TR_CLOUD, PYTHONPATH=server) changes
# nothing about WHAT runs: no mark (the head keeps its "[env X]" tag, as since 0.2.9). Marked "opaque:code injected through X=..." (asked,
# also in the strict sandbox: sandbox.ASK_OPAQUE) -- a variable that makes the program run OTHER code than the line shows:
#   a program the tool starts: pagers / editors / askpass / ssh / diff / proxy commands of git, less, sudo, ssh (a harmless value -- cat,
#     less, true, vim ... -- is not marked: `GIT_PAGER=cat git log`, `GIT_EDITOR=true git rebase --continue`);
#   git's own configuration and repository: GIT_CONFIG_GLOBAL / SYSTEM / GIT_CONFIG (except /dev/null), GIT_CONFIG_PARAMETERS and
#     GIT_CONFIG_KEY_n (except user.* / commit|tag.gpgsign / init.defaultBranch / color.* / advice.*), GIT_EXEC_PATH, GIT_TEMPLATE_DIR,
#     GIT_DIR / GIT_WORK_TREE outside the project;
#   a search path that leaves the project: PATH (system bin folders and $PATH itself are fine), PYTHONPATH, NODE_PATH, PERL5LIB,
#     RUBYLIB, CLASSPATH, PYTHONHOME (any value); a value the line cannot show ($X, `...`): marked;
#   shell start files and traps: ZDOTDIR, PROMPT_COMMAND, PS4 with $( or `, LESSOPEN / LESSCLOSE, BASH_FUNC_*;
#   build tools: CC / CXX / LD / AR / RUSTC / RUSTC_WRAPPER / RUSTC_WORKSPACE_WRAPPER / CARGO_*_RUNNER / CARGO_BUILD_RUSTC*, GOFLAGS
#     with -toolexec / -exec, npm_config_{script_shell,node_options,git,editor,shell,onload_script,init_module,userconfig,globalconfig,
#     prefix}, DOTNET_STARTUP_HOOKS, NODE_REPL_EXTERNAL_MODULE, PYTHONBREAKPOINT (other than 0);
#   the network's route or trust: HTTP(S)_PROXY / ALL_PROXY (any case), NODE_TLS_REJECT_UNAUTHORIZED=0, SSL_CERT_FILE, SSL_CERT_DIR,
#     REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, NODE_EXTRA_CA_CERTS, GIT_SSL_NO_VERIFY ("network" in the detail: asked).
# Not marked: ENV (sh reads it only when interactive; ENV=production is an application's variable). Already marked before: LD_* / DYLD_*, PYTHONSTARTUP, BASH_ENV, PERL5DB, NODE_OPTIONS / PERL5OPT / RUBYOPT / JAVA options (ENV_INJECT_*),
# HOME / PWD / CDPATH (REASSIGN), CLAUDE_* (witness), registry / index variables of npm / pip (net-out).
ENV_PROGRAM = {"GIT_PAGER", "PAGER", "MANPAGER", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "EDITOR", "VISUAL", "GIT_SSH", "GIT_SSH_COMMAND",
               "GIT_ASKPASS", "SSH_ASKPASS", "SUDO_ASKPASS", "GIT_EXTERNAL_DIFF", "GIT_PROXY_COMMAND", "BROWSER", "SHELL", "DIFF", "MERGE"}
ENV_PROGRAM_OK = {"", "cat", "less", "less -R", "less -r", "less -FRX", "less -FX", "more", "true", "false", ":", "head", "tail", "vi", "vim",
                  "nvim", "nano", "/bin/cat", "/usr/bin/less", "/usr/bin/true", "/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/vim"}
ENV_ALWAYS_MORE = {"ZDOTDIR", "PROMPT_COMMAND", "LESSOPEN", "LESSCLOSE", "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR", "PYTHONHOME",
                   "DOTNET_STARTUP_HOOKS", "NODE_REPL_EXTERNAL_MODULE", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"}
ENV_SEARCH = {"PATH", "PYTHONPATH", "NODE_PATH", "PERL5LIB", "PERLLIB", "RUBYLIB", "CLASSPATH"}
ENV_SYS_BIN = ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/sbin")
ENV_GIT_CFG_OK = re.compile(r"(?i)(?:user\.(?:name|email)|(?:commit|tag)\.gpgsign|init\.defaultbranch|color\.[\w.]+|advice\.[\w.]+|"
                            r"core\.quotepath|i18n\.[\w.]+|log\.[\w.]+|safe\.directory)")
ENV_NPM_BAD = {"script_shell", "script-shell", "node_options", "node-options", "git", "editor", "shell", "onload_script", "onload-script",
               "init_module", "init-module", "userconfig", "globalconfig", "prefix", "browser", "viewer"}
ENV_COMPILER_OK = re.compile(r"(?:/usr/bin/)?(?:cc|c\+\+|gcc|g\+\+|clang|clang\+\+|ld|ar|rustc|ld\.lld|lld)(?:-\d+(?:\.\d+)*)?")
ENV_NET = re.compile(r"(?i)(?:https?|all|ftp)_proxy|ssl_cert_file|ssl_cert_dir|requests_ca_bundle|curl_ca_bundle|node_extra_ca_certs")


def _env_more(words, here, home, project, c) -> None:
    """10.11 (r0260): see the table above. `words` = the command's words (assignments first, or `export A=1 B=2`)."""
    for a in words:
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_%]*)\+?=(.*)", a, re.S) if isinstance(a, str) else None
        if not m:
            continue
        k, v = m.group(1), str(_unmask(m.group(2)))
        ku = k.upper()
        why = None
        if ku in ENV_PROGRAM:
            why = None if v.strip() in ENV_PROGRAM_OK else "program"
        elif ku in ENV_ALWAYS_MORE or k.startswith("BASH_FUNC_"):
            why = "start code" if v else None
        elif ku == "PS4":
            why = "start code" if re.search(r"\$\(|`", v) else None
        elif ku in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG"):
            why = None if v in ("/dev/null", "") else "git configuration"
        elif ku == "GIT_CONFIG_PARAMETERS":
            keys = re.findall(r"'([^'=]+)(?:=|')", v) or [v]
            why = None if all(ENV_GIT_CFG_OK.fullmatch(x.strip()) for x in keys) else "git configuration"
        elif re.fullmatch(r"GIT_CONFIG_KEY_\d+", ku):
            why = None if ENV_GIT_CFG_OK.fullmatch(v.strip()) else "git configuration"
        elif ku in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
            why = None if _env_inside(v, here, home, project, self_=None) else "git repository elsewhere"
        elif ku in ENV_SEARCH:
            why = None if all(_env_inside(e, here, home, project, self_=ku, sysbin=ku == "PATH") for e in v.split(":")) else "search path"
        elif ku in ("CC", "CXX", "LD", "AR"):
            why = None if not v or ENV_COMPILER_OK.fullmatch(v.strip()) else "build tool"
        elif re.fullmatch(r"CARGO_(?:TARGET_[A-Z0-9_]+_RUNNER|BUILD_RUSTC(?:_WRAPPER|_WORKSPACE_WRAPPER)?|BUILD_RUSTFLAGS)", ku):
            why = "build tool"
        elif ku == "GOFLAGS":
            why = "build tool" if re.search(r"-(?:toolexec|exec|overlay)", v) else None
        elif ku.startswith("NPM_CONFIG_"):
            why = "npm configuration" if k[len("npm_config_"):].lower() in ENV_NPM_BAD else None
        elif ku == "PYTHONBREAKPOINT":
            why = None if v in ("", "0") else "start code"
        elif ENV_NET.fullmatch(k) or (ku == "NODE_TLS_REJECT_UNAUTHORIZED" and v.strip() == "0") or (ku == "GIT_SSL_NO_VERIFY" and v):
            c.add("opaque", "network route or trust changed through %s=%s" % (k, v[:60]))
            continue
        if why is not None:
            c.add("opaque", "code injected through %s=%s (%s)" % (k, v[:60], why))


def _env_inside(e, here, home, project, self_=None, sysbin=False) -> bool:
    """one element of a search path / a git directory: inside the project (relative to the line's folder too), a system bin folder (PATH),
    or the variable's own old value ($PATH / ${PATH}). Anything the line cannot show ($X, `...`, ~user) is not."""
    if self_ and e in ("$" + self_, "${%s}" % self_):
        return True
    if e == "":
        return self_ is not None and self_ != "PATH"         # PYTHONPATH= (empty): nothing added; an empty PATH element is the cwd
    if re.search(r"[$`*?\[]", e) or (e.startswith("~") and not (e == "~" or e.startswith("~/"))):
        return False
    if sysbin and os.path.normpath(e) in ENV_SYS_BIN:
        return True
    if not isinstance(project, str) or not project.startswith("/") or here == LOST_CWD:
        # no project known (the line runs elsewhere, asked anyway): a plain relative folder of the cwd is not marked by itself
        return not e.startswith(("/", "~")) and ".." not in e.split("/") and here != LOST_CWD
    x = _expand(e, here, home)
    if x is None:
        return False
    x = os.path.normpath(_abspath(x, here, home))
    for pr in {os.path.normpath(project), os.path.normpath(_abspath(project, here, home))}:   # /tmp -> /private/tmp on macOS
        if x == pr or x.startswith(pr.rstrip("/") + "/"):
            return True
    from . import sandbox as _sbx                      # the project's own folders in Claude Code's temp root count as the project's
    return _sbx.in_temp(x, project, home) and _sbx.CLAUDE_TMP.match(x) is not None


def _is_interp(name: str) -> bool:
    return bool(name) and (name in INTERPRETERS or name in EVAL_OPTS or bool(PY_MODULE.fullmatch(name)))


PRINTERS = {"echo", "printf"}


def _piped_net(name, args, via_xargs, prev, c) -> None:
    """s7 (O1): what a pipe feeds. `echo https://evil | xargs curl`: the URL is an argument of curl that the line does not show where curl
    is; `echo "fetch('https://evil')" | node`: the code an interpreter reads from stdin. From echo / printf the words are read as the URLs
    or the code they are; from anything else (a file, a command) a network program fed by xargs cannot show its host -> opaque:network."""
    pname, pargs = prev if prev else (None, [])
    shown = pname in PRINTERS and not any(re.search(r"[$`]", a) for a in pargs)
    if via_xargs and (name in FETCHERS or name in REMOTE_SHELLS or name in CLOUD_CLIS):
        hosts = []
        if shown:
            for a in pargs:
                hosts += [m.group(2).strip("[]") for m in URL_RE.finditer(a)]
                hosts += [re.split(r"[:/]", w, maxsplit=1)[0] for w in re.sub(r"\\[ntr0]|%s", " ", a).split()
                          if not URL_RE.search(w) and re.fullmatch(r"(?:[\w-]+@)?[\w.-]+\.[a-zA-Z]{2,}(:\d+)?(/\S*)?", w)]
        for h in hosts:
            c.host(h.rsplit("@", 1)[-1])
        if not hosts:
            c.add("opaque", "network: %s via xargs, the host comes from its input" % name)
    elif _is_interp(name) and pname in PRINTERS and not [a for a in args if not a.startswith("-") and a != "-"]:
        _code_scan(" ".join(pargs), c, name)


# 0.2.43b (RT-CODE-NET residual risk, OTCHET-RT2810-PRAVKI proposal 2): a file the line WRITES and then RUNS. `echo "import urllib..." > m.py
# && python3 m.py`, `cat > x.sh <<EOF ... EOF; bash x.sh`, `printf ... | tee Makefile && make`: the code that runs is the text written a moment
# before, which the classifier saw only as data. Now the text a simple command writes is kept per path for the rest of the line when the
# line shows it (echo / printf with literal words, `cat` reading a heredoc or a here-string, `tee` fed by one of those); a later command of
# the same line that runs that path (an interpreter or shell with it as its script, `./f` / `/abs/f`, make with that Makefile, a command
# whose executed files include it: npm + package.json, pytest + conftest.py) has that text judged as the code it is: shell text and
# Makefile recipes as command lines (classify), any text by code_net / code_obfuscated (_code_scan). A file of the line whose text the
# line does not show (`curl -o x.sh ...; bash x.sh`, `cp a m.py && python3 m.py`, `echo "$X" > f; sh f`) -> "opaque:runs FILE written in
# this line (content not shown)". A file written by an earlier Bash call is execguard's (O2), not this.
RUN_CODE = _runners.SCRIPT_INTERPRETERS                  # RT6: from the registry (python2 / pypy / irb / java ... included)
MAKE_RUNNERS = _runners.MAKE_RUNNERS
MAKEFILES = ("GNUmakefile", "makefile", "Makefile")


def _out_text(name, args, heredoc, herestr, fed):
    """0.2.43b: the text a simple command writes to its stdout when the line shows it, else None."""
    if name in PRINTERS:
        if any(re.search(r"[$`]", a) for a in args):
            return None
        ws = list(args)
        if name == "echo":
            while ws and re.fullmatch(r"-[neE]+", ws[0]):
                ws.pop(0)
            t = " ".join(ws)
        else:
            t = "\n".join(ws)
        t2 = t.replace("\\n", "\n").replace("\\t", "\t")
        return t if t2 == t else t + "\n" + t2       # as written, and with \\n / \\t read as echo -e / printf do
    if name == "cat" and not [a for a in args if a != "-"]:
        return heredoc if heredoc is not None else herestr
    if name == "tee":
        return fed
    return None


def _first_operand(args, skip_with_value=()):
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return args[i + 1] if i + 1 < len(args) else None
        if a.startswith("-") and a != "-":
            i += 2 if a in skip_with_value else 1
            continue
        return a
    return None


def _run_targets(name, argv0, args, here, home):
    """0.2.43b: -> [(absolute path, kind)] of the files this simple command runs as code; kind "shell" | "make" | "code" | "family"."""
    def ab(w):
        e = _expand(w, here, home)
        return _abspath(e, here, home) if e is not None and not re.search(r"[*?[]", e) else None
    out = []
    if "/" in argv0:
        p = ab(argv0)
        if p:
            out.append((p, "shell"))                         # `./f`, `/p/f`: a script of any kind (scanned as shell AND as code)
    elif name in SHELLS:
        if not any(a == "-c" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:]) for a in args):
            f = _first_operand(args, {"-o", "+o", "-O", "+O"})
            if f and f != "-" and ab(f):
                out.append((ab(f), "shell"))
    elif _is_interp(name) or name in RUN_CODE:
        ev = EVAL_OPTS.get("python" if PY_MODULE.fullmatch(name) else name, set()) | {"-c", "-m"}
        if not any(a in ev or (name.startswith("python") and re.fullmatch(r"-[A-Za-z]*[cm]\S*", a)) for a in args):
            f = _first_operand([a for a in args if a not in ("run",)] if name in ("deno", "bun") else args, {"-W", "-X", "-Q"})
            if f and f != "-" and ab(f):
                out.append((ab(f), "code"))
    elif name in MAKE_RUNNERS:
        d, files, i = here, [], 0
        while i < len(args):
            a = args[i]
            if a in ("-f", "--file", "--makefile") and i + 1 < len(args):
                files.append(args[i + 1]); i += 2; continue
            if a.startswith(("--file=", "--makefile=")):
                files.append(a.split("=", 1)[1])
            elif a.startswith("-f") and len(a) > 2:
                files.append(a[2:])
            elif a == "-C" and i + 1 < len(args):
                d = ab(args[i + 1]) or d; i += 2; continue
            i += 1
        for f in files or MAKEFILES:
            p = _abspath(f, d, home) if (files and _expand(f, d, home) is not None) or not files else None
            if p:
                out.append((p, "make"))
        out.append((_fs.current().realpath(d).rstrip("/") + "/*.mk", "make"))       # an included .mk written in the line
    out.append(("", "family"))                              # npm + package.json, pytest + conftest.py ...: matched against the written paths
    return out


def _written_runs(name, argv0, args, here, home, project, written, before, c, depth):
    """0.2.43b: judge the text of every file of `written` / `before` (paths this line wrote before this command) that this command runs."""
    if not written and not before:
        return
    try:
        from app.execguard import families_of_command, families_of_path, fold
    except ImportError:                                     # the classifier without the server tables (never in the witness)
        families_of_command = families_of_path = None
    hits = []
    under = tuple({here.rstrip("/") + "/", _fs.current().realpath(here).rstrip("/") + "/"})    # written paths are real paths (_abspath)
    for p, kind in _run_targets(name, argv0, args, here, home):
        if kind == "family":
            fams = set(families_of_command(" ".join([name] + list(args[:1])))) if families_of_command else set()
            if fams:
                hits += [(q, "family") for q in list(written) + [w for w in before if w not in written]
                         if set(families_of_path(q)) & fams and q.startswith(under)
                         and (q, "family") not in hits and not any(q == h for h, _ in hits)]
        elif p.endswith("/*.mk"):
            hits += [(q, "make") for q in list(written) + list(before) if q.endswith(".mk") and q.startswith(p[:-4]) and not any(q == h for h, _ in hits)]
        elif p in written or p in before:
            hits.append((p, kind))
    for p, kind in hits:
        text = written.get(p) if p in written else None
        who = os.path.basename(p)
        if text is None:
            c.add("opaque", "runs %s written in this line (content not shown)" % p[-120:])
            continue
        if kind == "family" and families_of_command and fold(who) == "package.json":
            try:
                sc = json.loads(text).get("scripts")
                if isinstance(sc, dict):
                    text = "\n".join(str(v) for v in sc.values())
            except (ValueError, AttributeError):
                pass
        if kind in ("shell", "make"):
            sh = text
            if kind == "make" or fold(who) in ("makefile", "gnumakefile") or who.endswith(".mk"):
                sh = "\n".join(re.sub(r"^\t[@+\-]*", "", ln) for ln in text.splitlines() if ln.startswith("\t"))
            _merge(c, classify(sh, here, home, depth + 1, project, _budget=c.budget))
        _code_scan(text, c, "%s written in this line" % who[-60:])


@dataclass
class Command:
    danger: list = field(default_factory=list)
    writes: list = field(default_factory=list)
    net: list = field(default_factory=list)
    heads: list = field(default_factory=list)
    opaque: bool = False
    outside: list = field(default_factory=list)   # 0.2.10: heads that ran outside the project or name a path outside it (no project allowance)
    extract: list = field(default_factory=list)   # RT-0269 p.4: written paths whose text comes from an archive / a patch / git objects, not the line
    xdirs: list = field(default_factory=list)     # RT-0269 p.4: ... of them, written as a whole directory (members unknown)
    # N15 29.10 (noise of set-up E): extract paths whose text comes ONLY from the repository's own objects (stash, pull, merge, switch,
    # checkout / restore from the index, HEAD or a branch) -- still writes (FILE_CHANGED, the page), not "risky writes" for a later run;
    # xforeign: extract paths from anything else (a patch / archive / mbox file, `git apply`, `git am`, a checkout of paths from a named ref)
    repo_extract: list = field(default_factory=list)
    xforeign: list = field(default_factory=list)
    # RT-0270 29.10: the line changes what git's own objects / index / refs / remotes hold (update-index, hash-object, notes, read-tree,
    # config, remote add|set-url, worktree, a fetch / pull of a path, URL or refspec, a branch / tag at a start point, reset to a ref,
    # apply --cached ...): a later restore "from the index / HEAD / a branch" may then write a text the witness never saw
    gtamper: bool = False
    # N6 0.2.71 (series 8c): {directory: [absolute paths]} -- the files a whole-directory restore from the repository's own objects really
    # rewrites, by git's own object hashes (the hook's fact `gitref`: `git diff-tree HEAD stash`). Absent = unknown: the whole directory.
    repo_files: dict = field(default_factory=dict)
    repo_files_bad: bool = False
    rm_data: int = 0                              # 10.11 (r0260): `rm -r..` words that are a search pattern of grep / rg / git grep (data)
    rm_plain: int = 0                             # 0.2.89: plain recursive deletes inside the project on this line (rm -rf build)
    # RT-0271 0.2.72: repository tops into which the line puts the WORK TREE's text (`git stash` / push / save / create, `git add`,
    # `git commit`): what an unseen risky write left there comes back later through an "own" restore (stash pop, restore, checkout -- f)
    gstore: list = field(default_factory=list)
    rm_judged: int = 0                            # 0.2.90: deletion calls of interpreter code resolved to a literal path (_code_fs_scan)
    deletes: list = field(default_factory=list)   # 0.2.90: of the writes, the paths the line DELETES (rm -rf build, find -delete, rmtree): no code is written there
    # 10.11 (r0260, law 2 / Р-1011 А): where each danger mark and host came from -- interpreter code (`python3 -c`, `perl -e`, a heredoc
    # read by an interpreter, a here-string, a file written and run in the line: _code_scan / _code_fs_scan) or the shell line itself.
    # A mark or host seen in BOTH counts as the line's own (code_only_*). Only the strict-sandbox gate reads it (sandbox.code_line_ok).
    code_d: list = field(default_factory=list)
    plain_d: list = field(default_factory=list)
    code_h: list = field(default_factory=list)
    plain_h: list = field(default_factory=list)
    code_texts: list = field(default_factory=list)

    def code_only_marks(self):
        return [d for d in self.danger if d in self.code_d and d not in self.plain_d]

    def code_only_hosts(self):
        return [h for h in self.net if h in self.code_h and h not in self.plain_h]

    def head(self, h: str) -> None:
        if not h or h in self.heads:
            return
        if len(self.heads) >= MAX_HEADS:            # never drop a command silently: a line too long to list is judged as dangerous
            self.opaque = True
            self.add("opaque", "more than %d commands" % MAX_HEADS)
            return
        self.heads.append(h)

    def add(self, cat: str, detail: str = "") -> None:
        d = "%s:%s" % (cat, " ".join(str(detail).split())[:DETAIL_MAX]) if detail else cat
        if d not in self.danger:
            if cat == AUTOSTART:                    # r0298: first, after earlier autostart marks (the question's recipient)
                k = 0
                while k < len(self.danger) and self.danger[k].startswith(AUTOSTART + ":"):
                    k += 1
                self.danger.insert(k, d)
            else:
                self.danger.append(d)
        o = self.code_d if _CODE[0] > 0 else self.plain_d
        if d not in o:
            o.append(d)

    def delete(self, path: str) -> None:
        if isinstance(path, str) and path.startswith(LOST_CWD + "/"):
            if path not in self.writes:             # r0298: a deletion starts nothing: no `autostart` mark (the opaque one stays)
                self.writes.append(path)
        else:
            self.write(path)
        if path not in self.deletes:
            self.deletes.append(path)

    def out(self, h: str) -> None:
        if h and h not in self.outside:
            self.outside.append(h)

    def write(self, path: str) -> None:
        if path not in self.writes:
            self.writes.append(path)
        if isinstance(path, str) and path.startswith(LOST_CWD + "/"):
            t_ = path[len(LOST_CWD) + 1:]           # r0298: under the unknown directory the place is not certain: asked (autostart), never Н4
            if is_autostart_tail(t_):
                self.add(AUTOSTART, "write to %s in an unknown directory" % t_)
        elif is_persist_path(path):
            self.add("persist", path)               # 0.2.90: shell rc, LaunchAgents, crontab, the agent's settings / hooks, the witness's key

    def host(self, h: str) -> None:
        h = h.lower().rstrip(".")
        if h not in self.net:
            self.net.append(h)
        o = self.code_h if _CODE[0] > 0 else self.plain_h
        if h not in o:
            o.append(h)


def _abspath(p: str, cwd: str, home: str) -> str:
    if p == "~" or p.startswith("~/"):
        p = home + p[1:]
    if not os.path.isabs(p):
        p = os.path.join(cwd, p)
    r = _fs.current().realpath(p)         # symlinks are followed: a link inside the project that points outside is judged by its target
    f = _frame()
    if f and f.get("links"):              # 0.2.90 (QA G, Н4): `ln -s ~/Documents ./docs && rm -rf ./docs/`: a link this LINE makes is followed too
        n = os.path.normpath(r)
        for link, target in f["links"].items():
            if n == link or n.startswith(link.rstrip("/") + "/"):
                return os.path.normpath(target + n[len(link):])
    return r


def is_secret_path(p: str) -> bool:
    return bool(SECRET_NAME.search(p) or SECRET_DIR.search(p))


KNOWN_VAR = re.compile(r"\$(?:\{(HOME|PWD)\}|(HOME|PWD)(?![A-Za-z0-9_]))")
# 0.2.93 (r0263, L3 12.11 Б2): `npm test > $TMPDIR/test-out.txt; tail $TMPDIR/test-out.txt` was "opaque: write to $TMPDIR/..." -- a
# DANGEROUS question for a write into temp. The hook (client 0.2.61) sends its TMPDIR; mapping.map_event puts it here when it is an absolute
# folder of a temp root and the line does not set TMPDIR itself. Only `$TMPDIR` / `${TMPDIR}` at the START of a word, followed by nothing
# or by a path with no `..` (the real TMPDIR of the command may be another temp folder: a `..` walk could then lead elsewhere).
import contextvars as _cv  # noqa: E402
TMPDIR_CTX = _cv.ContextVar("dw_tmpdir", default=None)
TMP_VAR = re.compile(r"^\$(?:\{TMPDIR\}|TMPDIR(?![A-Za-z0-9_]))(?=/|$)")
TMP_ROOT = re.compile(r"^(?:/private)?/(?:tmp|var/tmp)(?:/|$)|^(?:/private)?/var/folders/[^/]+/[^/]+/T(?:/|$)")
TMP_SET = re.compile(r"(?:^|[\s;&|(`])(?:export\s+|local\s+|declare\s+(?:-\w+\s+)*|readonly\s+)?TMPDIR\+?=|\b(?:unset|read|for|mapfile|readarray|printf\s+-v)\b[^;&|]*\bTMPDIR\b")


def tmpdir_of(env, line):
    """-> the hook's TMPDIR (no trailing slash) when it may stand for $TMPDIR in this line, else None."""
    t = env.get("TMPDIR") if isinstance(env, dict) else None
    if not isinstance(t, str) or not t.startswith("/") or not TMP_ROOT.search(t) or "/../" in t + "/" or "/./" in t + "/":
        return None
    if isinstance(line, str) and TMP_SET.search(line):
        return None
    return t.rstrip("/") or None


def _tmp_sub(w):
    t = TMPDIR_CTX.get()
    if not t or not TMP_VAR.match(w):
        return w
    rest = TMP_VAR.sub("", w, count=1)
    if ".." in rest.split("/") or re.search(r"[$`]", rest):
        return w
    return t + rest
# 0.2.11 (R6-02): a line that changes what $HOME / $PWD / ~ / a relative `cd` mean cannot have its paths resolved by the hook
REASSIGN = re.compile(r"(^|[\s;&|(])((export|local|declare|typeset|readonly)(\s+-\w+)*\s+)?(HOME|PWD|OLDPWD|CDPATH)\+?=|"
                      r"\b(read|unset|for|select|printf\s+-v|mapfile|readarray|getopts)\b[^;&|]*\b(HOME|PWD|OLDPWD|CDPATH)\b")


def _expand(w: str, cwd: str, home: str):
    """0.2.11 (R6-02): a word as the shell would see it as a path. $HOME/${HOME} and $PWD/${PWD} are what the hook knows; any other expansion
    ($VAR, ${...}, $(...), backticks, ~user, ~+, ~-) leaves the path unknown -> None (the caller fails closed)."""
    w = KNOWN_VAR.sub(lambda m: home if (m.group(1) or m.group(2)) == "HOME" else cwd, w)
    w = _tmp_sub(w)                                      # 0.2.93 (r0263): $TMPDIR the hook knows
    w = _subst_vars(w)                                   # 0.2.90: `D=/x; cat $D/f`
    if re.search(r"[$`]", w) or re.match(r"~[^/]", w):
        return None
    return w


HD_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")      # 0.2.12: a delimiter we accept; any other (empty, `$x`, `$'..'`, spaces ...) -> opaque
HD_META = set(" \t\n;&|<>()")


def _heredoc_word(cmd: str, k: int):
    """0.2.12 (R7-01): the delimiter after `<<` / `<<-` read as bash reads it: the WHOLE shell word up to an unquoted metacharacter, quotes
    removed (`E\\OF`, `E'O'F`, `"E"OF`, `EOF''` are all EOF, and quoted: the body is data). -> (delimiter, quoted, end) or None when the
    word is not one we can be sure of (no word, `$` or a backtick in it, a line continuation, an unclosed quote, a name outside HD_WORD)."""
    n = len(cmd)
    while k < n and cmd[k] in " \t":
        k += 1
    val, quoted, start = [], False, k
    while k < n and cmd[k] not in HD_META:
        ch = cmd[k]
        if ch == "\\":
            if k + 1 >= n or cmd[k + 1] == "\n":
                return None
            val.append(cmd[k + 1])
            quoted, k = True, k + 2
        elif ch == "'":
            j = cmd.find("'", k + 1)
            if j < 0:
                return None
            val.append(cmd[k + 1:j])
            quoted, k = True, j + 1
        elif ch == '"':
            j = k + 1
            while j < n and cmd[j] != '"':
                if cmd[j] in "$`" or cmd[j:j + 2] == "\\\n":
                    return None
                if cmd[j] == "\\" and j + 1 < n and cmd[j + 1] in '"\\':
                    j += 1
                val.append(cmd[j])
                j += 1
            if j >= n:
                return None
            quoted, k = True, j + 1
        elif ch in "$`":
            return None
        else:
            val.append(ch)
            k += 1
    d = "".join(val)
    if k == start or not HD_WORD.fullmatch(d):
        return None
    return d, quoted, k


class _Unsure(str):
    """04.11 (Hypothesis I3): why _normalize is unsure, and where the construct it could not read starts (`at`: the index of its `<<`).
    bash runs the commands before it whatever it makes of the rest: _classify judges cmd[:at] as usual, so opacity only adds a question."""
    def __new__(cls, why, at=None):
        o = str.__new__(cls, why)
        o.at = at
        return o


def _normalize(cmd: str):
    """Quote-aware pass: an unquoted newline becomes ";", unquoted comments are dropped, heredoc bodies are cut out.
    -> (one-line command, [(line that opened the heredoc, body, delimiter quoted?)], balanced quotes?, why unsure or None)
    0.2.12 (R7-01): heredocs are found as bash finds them. The delimiter is the whole word with quotes removed (_heredoc_word); the body ends
    at the first line EQUAL to it (`<<-`: after leading tabs), not at a stripped line. `<<` inside `$((..))`, `((..))`, `$[..]` or `${..}` is
    not a heredoc (a shift, or text). Fail closed (-> the line is opaque) on anything we might read differently from bash: a delimiter we do
    not accept, a body that never ends, a line continuation in a body with an unquoted delimiter (bash joins it before comparing), a body
    that would start inside another construct than the one that opened it, an arithmetic `((` that turns out not to be one, a body inside
    backticks with a backtick in it (bash finds the end of `..` before it reads a heredoc in it)."""
    out, docs, q, i, n = [], [], None, 0, len(cmd)
    line_start = 0
    pending = []                           # heredocs opened on the current line: (delimiter, quoted, strip tabs, contexts when opened)
    # unquoted contexts, innermost last: [kind, saw "<<", plain "(" inside]; R = the line, C = $( <( >(, A + a = $(( / ((, B = ${ {, S = $[ [,
    # K = `...`
    stack = [["R", False, 0]]
    while i < n:
        ch = cmd[i]
        if q is None:
            top = stack[-1]
            kind, k = top[0], 0
            if ch == "\\" and i + 1 < n:
                out.append(cmd[i:i + 2]) if cmd[i + 1] != "\n" else None
                i += 2
                continue
            if ch in "'\"":
                q = ch
            elif ch == "#" and (i == 0 or cmd[i - 1] in " \t\n;&|("):
                while i < n and cmd[i] != "\n":
                    i += 1
                continue
            elif cmd.startswith("<<<", i):
                out.append("<<<")                  # here-string: the word is data (judged in classify), not a heredoc delimiter
                i += 3
                continue
            elif cmd.startswith("<<", i):
                if kind in ("A", "a", "B", "S"):
                    top[1] = True                  # a shift (or text in ${..}), as long as this really is arithmetic (checked at its end)
                    out.append("<<")
                    i += 2
                    continue
                strip = cmd.startswith("<<-", i)
                w = _heredoc_word(cmd, i + 2 + strip)
                if w is None:
                    return "".join(out), docs, q is None, _Unsure("heredoc delimiter not understood", i)
                pending.append((w[0], w[1], strip, [(e[0], e[2]) for e in stack], i))
                out.append(" << __HEREDOC__ ")
                i = w[2]
                continue
            elif kind not in ("B", "S") and (cmd.startswith("$((", i) or cmd.startswith("((", i)):
                stack += [["A", False, 0], ["a", False, 0]]
                k = 3 if ch == "$" else 2
            elif cmd.startswith(("$(", "<(", ">("), i):
                stack.append(["C", False, 0])
                k = 2
            elif cmd.startswith("${", i) or (ch == "{" and kind == "B"):
                stack.append(["B", False, 0])
                k = 2 if ch == "$" else 1
            elif cmd.startswith("$[", i) or (ch == "[" and kind == "S"):
                stack.append(["S", False, 0])
                k = 2 if ch == "$" else 1
            elif ch == "`":
                if kind == "K":
                    stack.pop()                    # a backtick substitution: a heredoc may live inside it, one opened outside may not start in it
                else:
                    stack.append(["K", False, 0])
                k = 1
            elif (ch == "}" and kind == "B") or (ch == "]" and kind == "S"):
                stack.pop()
                k = 1
            elif ch == "(" and kind not in ("B", "S"):
                top[2] += 1
                k = 1
            elif ch == ")" and kind not in ("B", "S"):
                k = 1
                if top[2]:
                    top[2] -= 1
                elif kind == "a":
                    stack.pop()
                    if cmd.startswith(")", i + 1):
                        stack.pop()                # `))`: the arithmetic really ends here
                        k = 2
                    elif top[1]:
                        return "".join(out), docs, q is None, "<< in an arithmetic that is not one"
                    else:
                        stack[-1][0] = "C"         # `$((1) + (2))`: bash reads a command substitution of a subshell after all
                elif kind != "R":
                    stack.pop()
            if k:
                out.append(cmd[i:i + k])
                i += k
                continue
            elif ch == "\n":
                out.append(" ; ")
                head = cmd[line_start:i]           # the whole line that opened the heredoc(s): `cat <<EOF | sh` reads it as code
                i += 1
                for delim, quoted, strip, ctx, at in pending:
                    if ctx != [(e[0], e[2]) for e in stack]:
                        return "".join(out), docs, q is None, _Unsure("heredoc body inside another construct", at)
                    body, closed = [], False
                    while i < n:
                        j = cmd.find("\n", i)
                        j = n if j < 0 else j
                        ln = cmd[i:j]
                        i = j + 1
                        if (ln.lstrip("\t") if strip else ln) == delim:
                            closed = True
                            break
                        if "`" in ln and any(kd == "K" for kd, _ in ctx):
                            return "".join(out), docs, q is None, _Unsure("heredoc inside backticks", at)   # bash ends `..` first, at any backtick
                        if not quoted and (len(ln) - len(ln.rstrip("\\"))) % 2 == 1:
                            return "".join(out), docs, q is None, _Unsure("line continuation in a heredoc body", at)
                        body.append(ln)
                    if not closed and body:
                        return "".join(out), docs, q is None, _Unsure("heredoc %s never ends" % delim, at)
                    docs.append((head, "\n".join(body), quoted))
                pending = []
                line_start = i
                continue
        elif ch == q:
            q = None
        elif q == '"' and ch == "\\" and i + 1 < n:
            out.append(cmd[i:i + 2])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out), docs, q is None, None


# 0.2.54: a quoted or backslash-escaped operator character is a word, not an operator (`find . \( -name a \) -exec cat {} \;`, `grep '|' f`):
# before shlex it is replaced by a private-use character (shlex cannot tell `\;` from `;`); _redirects turns the words back (_unmask)
_MASK = {ch: chr(0xE000 + k) for k, ch in enumerate(";&|<>(){}$`")}     # `$` / backquote: masked inside single quotes only (_Lit)
_UNMASK = {ord(v): k for k, v in _MASK.items()}
_UNMASK[0xE00B] = None          # an empty quoted pair: `sed -i '' ...`, `awk -F '' prog` (shlex's empty word was dropped by _split)


def _unmask(w: str) -> str:
    """-> the word as bash passes it; a _Lit when it had a `$` / backquote and every one of them was single-quoted (0.2.54)."""
    u = w.translate(_UNMASK)
    if ("\ue009" in w or "\ue00a" in w) and not re.search(r"[$`]", w):
        return _Lit(u)
    return u


def _mask(line: str) -> str:
    out, q, i, n = [], None, 0, len(line)
    while i < n:
        ch = line[i]
        if q is None:
            if ch == "\\" and i + 1 < n:
                out.append(_MASK.get(line[i + 1]) if line[i + 1] in PUNCT else line[i:i + 2])
                i += 2
                continue
            if ch in "'\"" and line[i + 1:i + 2] == ch:
                out.append(ch + "\ue00b" + ch)
                i += 2
                continue
            if ch in "'\"":
                q = ch
            out.append(ch)
        elif ch == q:
            q = None
            out.append(ch)
        elif q == '"' and ch == "\\" and i + 1 < n:
            out.append(line[i:i + 2])        # `"\;"` is a backslash and a `;` in bash: one word, never an operator either way
            i += 2
            continue
        elif q == '"' and ch in "$`":
            out.append(ch)                   # expanded inside double quotes
        else:
            out.append(_MASK.get(ch, ch))
        i += 1
    return "".join(out)


def _tokens(cmd: str):
    if any(ch in _UNMASK for ch in map(ord, cmd)):
        raise ValueError("a private-use character U+E000..U+E00B")      # it would read as an operator character after _unmask
    lx = shlex.shlex(_mask(cmd), posix=True, punctuation_chars=";&|<>(){}")
    lx.whitespace_split = True
    lx.commenters = ""
    return _relex(list(lx))


def _relex(toks):
    """0.2.11 (R6-01): shlex returns a run of punctuation as one token (">|", "2>&1" -> ">&", ";>", "}>"); cut it into shell operators,
    longest first (">|" is ">|", not ">" followed by a word "|")."""
    out = []
    for t in toks:
        if t and set(t) <= PUNCT:
            k = 0
            while k < len(t):
                op = next(o for o in OPS if t.startswith(o, k))
                out.append(op)
                k += len(op)
        else:
            out.append(t)
    return out


FD_VAR = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}(?=[<>])")


def _close(s: str, k: int):
    """Index of the ")" that closes the "(" at s[k], quote-aware; None when there is none."""
    depth, q, i = 0, None, k
    while i < len(s):
        ch = s[i]
        if q == "'":
            q = None if ch == "'" else q
        elif ch == "\\":
            i += 1
        elif q == '"':
            q = None if ch == '"' else q
        elif ch in "'\"":
            q = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _substitute(line, c, cwd, home, depth, project, data=False):
    """0.2.11: quote-aware pass over the one-line command. Every command substitution `$(...)`, backtick and process substitution `<(...)` /
    `>(...)`, at any nesting depth, is classified as a command line of its own and replaced by one word: "$__SUB__" (a value the hook cannot
    know: a path made of it is unknown) or "/dev/fd/63" (process substitution); `$((...))` -> "$__ARITH__" (substitutions inside it are
    classified); `${...}` stays one word (the tokenizer no longer cuts `${HOME}/.ssh/id_rsa` at the braces, R6-02); `{fd}` before a
    redirection is dropped (`exec {fd}>f` writes f). -> the new line, or None when it cannot be read (unclosed, nested `${..$(..)}`, a "("
    glued to a word: extglob `@(..)` / zsh glob qualifiers `*(e:..:)` run code or build names we cannot see, unbalanced parentheses).
    data=True: the body of a heredoc whose delimiter is not quoted -- quotes are text and only `$(...)`, `$((...))` and backticks run."""
    out, i, n, q, parens = [], 0, len(line), None, 0
    while i < n:
        ch = line[i]
        if q == "'":
            out.append(ch)
            q = None if ch == "'" else q
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(line[i:i + 2])
            i += 2
            continue
        if data and ch not in "$`":
            out.append(ch)
            i += 1
            continue
        if ch == "'" and q is None or ch == '"':
            q = ch if q is None else None
            out.append(ch)
            i += 1
            continue
        if ch == "`":
            j = i + 1
            while j < n and line[j] != "`":
                j += 2 if line[j] == "\\" else 1
            if j >= n:
                return None
            _merge(c, classify(line[i + 1:j].replace("\\`", "`"), cwd, home, depth + 1, project, _budget=c.budget))
            if c.budget[0] < 0:
                return None
            out.append("$__SUB__")
            i = j + 1
            continue
        if ch == "$" and line.startswith("$((", i):
            j = _close(line, i + 1)
            c.budget[0] -= 1
            if j is None or c.budget[0] < 0 or _substitute(line[i + 3:j - 1], c, cwd, home, depth + 1, project) is None:
                return None
            out.append("$__ARITH__")
            i = j + 1
            continue
        if (ch == "$" or (ch in "<>" and q is None)) and line.startswith("(", i + 1):
            j = _close(line, i + 1)
            if j is None:
                return None
            _merge(c, classify(line[i + 2:j], cwd, home, depth + 1, project, _budget=c.budget))
            if c.budget[0] < 0:
                return None
            out.append("$__SUB__" if ch == "$" else " /dev/fd/63")
            i = j + 1
            continue
        if ch == "$" and line.startswith("${", i) and not data:
            j = line.find("}", i + 2)
            if j < 0 or not re.fullmatch(r"[^\"'`{}\\$()\s]*", line[i + 2:j]):
                return None
            out.append(line[i:j + 1] if q == '"' else '"%s"' % line[i:j + 1])
            i = j + 1
            continue
        if q is None and not data:
            m = FD_VAR.match(line, i)
            if m and (i == 0 or line[i - 1] in " \t;&|("):
                out.append(" ")
                i = m.end()
                continue
            if ch == "(":
                if i > 0 and line[i - 1] not in " \t;&|(=" and not line.startswith("()", i):
                    return None
                parens += 1
            elif ch == ")":
                parens -= 1
                if parens < 0:
                    return None
        out.append(ch)
        i += 1
    return "".join(out) if parens == 0 else None


def _brace_pairs(tokens):
    """0.2.52: `{` `}` right after each other, after the first word of a command, are the word `{}` (`xargs -I{} cat {}`, `find -exec cat {}`;
    `{` / `}` are reserved words only where a command starts). Before, the line was cut there and `cat {}` was judged as a plain `cat`, not
    `cat [via xargs]`. Any other `{` / `}` is cut as before (brace expansion is opaque on its own)."""
    out, start, k = [], True, 0
    while k < len(tokens):
        p = tokens[k]
        if p == "{" and k + 1 < len(tokens) and tokens[k + 1] == "}" and not start:
            out.append("{}")
            k += 2
            continue
        out.append(p)
        start = p in SEPARATORS or (start and p in KEYWORDS)
        k += 1
    return out


def _split_ctx(tokens):
    """0.2.12: -> [(argv, separator before, separator after, subshell depth)] for every simple command (`(` .. `)` is a subshell)."""
    out, cur, before, depth = [], [], None, 0
    for p in _brace_pairs(tokens):
        if p in SEPARATORS:
            if cur:
                out.append((cur, before, p, depth))
                cur = []
            before = p
            depth += (p == "(") - (p == ")")
            depth = max(depth, 0)
        elif p != "":
            cur.append(p)
    if cur:
        out.append((cur, before, None, depth))
    return out


def _split(tokens):
    """-> list of simple commands, each a list of tokens."""
    cmds, cur = [], []
    for p in _brace_pairs(tokens):
        if p in SEPARATORS:
            if cur:
                cmds.append(cur)
            cur = []
        elif p != "":
            cur.append(p)
    if cur:
        cmds.append(cur)
    return cmds


# 0.2.52: wrapper option syntax, read as getopt reads it (union of the GNU coreutils / util-linux / procps / BSD man pages; bash for the
# builtins). Each: short flags, short options taking a value (`-o F`, `-oF`), short options with an OPTIONAL value (only glued: `-iR`),
# long flags, long options with a value (`--output F`, `--output=F`, unambiguous prefixes `--out=F`), long options with an optional value
# (`--eof[=E]`), operands taken before the command. Before, every word starting with '-' was dropped and the value of an option was taken for
# the command (`time -o ls rm a` ran rm and was judged as `ls`). An option not in the table, an ambiguous prefix, a missing value or an operand
# of an unexpected shape is "not sure what runs": the line is opaque (asked every time), never allowed by a guess.
WRAP_SYNTAX = {
    "time": ("alhpvqV", "of", "", {"--append", "--portability", "--verbose", "--quiet", "--help", "--version"}, {"--output", "--format"}, set(), 0),
    "nohup": ("", "", "", {"--help", "--version"}, set(), set(), 0),
    "nice": ("", "n", "", {"--help", "--version"}, {"--adjustment"}, set(), 0),
    "timeout": ("fpv", "ks", "", {"--foreground", "--preserve-status", "--verbose", "--help", "--version"}, {"--kill-after", "--signal"}, set(), 1),
    "stdbuf": ("", "ioe", "", {"--help", "--version"}, {"--input", "--output", "--error"}, set(), 0),
    "env": ("i0v", "uCPS", "", {"--ignore-environment", "--null", "--debug", "--list-signal-handling", "--help", "--version"},
            {"--unset", "--chdir", "--split-string", "--argv0"}, {"--block-signal", "--default-signal", "--ignore-signal"}, 0),
    "command": ("pvV", "", "", set(), set(), set(), 0),
    "exec": ("cl", "a", "", set(), set(), set(), 0),
    "builtin": ("", "", "", set(), set(), set(), 0),
    "chronic": ("ev", "", "", set(), set(), set(), 0),
    "unbuffer": ("p", "", "", set(), set(), set(), 0),
    "setsid": ("cfw", "", "", {"--ctty", "--fork", "--wait", "--help", "--version"}, set(), set(), 0),
    "caffeinate": ("dimsu", "tw", "", set(), set(), set(), 0),
    "xargs": ("0oprtx", "EIJLnPsadRS", "iel", {"--null", "--interactive", "--no-run-if-empty", "--verbose", "--exit", "--open-tty", "--show-limits"},
              {"--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-chars", "--process-slot-var"}, {"--eof", "--replace", "--max-lines"}, 0),
    "flock": ("sxenoFu", "wEc", "", {"--shared", "--exclusive", "--unlock", "--nonblock", "--nb", "--close", "--no-fork", "--verbose"},
              {"--timeout", "--wait", "--conflict-exit-code", "--command"}, set(), 1),
    "ionice": ("t", "cnpPu", "", {"--ignore", "--help", "--version"}, {"--class", "--classdata", "--pid", "--pgid", "--uid"}, set(), 0),
    "taskset": ("acp", "", "", {"--all-tasks", "--cpu-list", "--pid", "--help", "--version"}, set(), set(), 1),
    "chrt": ("abdfiomrRv", "TPD", "", {"--all-tasks", "--batch", "--deadline", "--fifo", "--idle", "--other", "--max", "--rr", "--reset-on-fork",
                                       "--verbose", "--help", "--version"}, {"--sched-runtime", "--sched-period", "--sched-deadline"}, set(), 1),
    "watch": ("bcCegprtwx", "nqs", "d", {"--beep", "--color", "--no-color", "--errexit", "--chgexit", "--precise", "--no-rerun", "--no-title",
                                         "--no-wrap", "--exec"}, {"--interval", "--equexit", "--shotsdir"}, {"--differences"}, 0),
    "sudo": ("ABbEHnPSilsKkVN", "CDghpRTUu", "", {"--askpass", "--bell", "--background", "--preserve-env", "--set-home", "--non-interactive",
             "--preserve-groups", "--stdin", "--login", "--list", "--shell", "--remove-timestamp", "--reset-timestamp", "--validate"},
             {"--close-from", "--chdir", "--group", "--host", "--prompt", "--chroot", "--command-timeout", "--other-user", "--user", "--role", "--type"},
             set(), 0),
    "doas": ("Lns", "uC", "", set(), set(), set(), 0),
}
# options after which the paths of the command no longer mean what the hook resolved, or the command runs code it did not parse
WRAP_RISKY = {
    ("env", "-C"): "env -C: the command runs in another directory", ("env", "--chdir"): "env -C: the command runs in another directory",
    ("env", "-S"): "env -S", ("env", "--split-string"): "env -S",
    ("env", "-P"): "env -P: the command is looked up in another PATH", ("env", "--argv0"): "env --argv0",
    ("flock", "-c"): "flock -c: a command string run by a shell", ("flock", "--command"): "flock -c: a command string run by a shell",
    ("ionice", "-p"): "ionice -p: changes other processes", ("ionice", "--pid"): "ionice -p: changes other processes",
    ("ionice", "-P"): "ionice -P: changes other processes", ("ionice", "--pgid"): "ionice -P: changes other processes",
    ("ionice", "-u"): "ionice -u: changes other processes", ("ionice", "--uid"): "ionice -u: changes other processes",
    ("taskset", "-p"): "taskset -p: changes another process", ("taskset", "--pid"): "taskset -p: changes another process",
    ("chrt", "-p"): "chrt -p: changes another process", ("chrt", "--pid"): "chrt -p: changes another process",
    ("watch", "-s"): "watch --shotsdir: writes screenshots", ("watch", "--shotsdir"): "watch --shotsdir: writes screenshots",
    ("sudo", "-D"): "sudo -D: the command runs in another directory", ("sudo", "--chdir"): "sudo -D: the command runs in another directory",
    ("sudo", "-R"): "sudo -R: the command runs in another root", ("sudo", "--chroot"): "sudo -R: the command runs in another root",
    ("sudo", "-e"): "sudo -e: edits files", ("doas", "-C"): "doas -C",
}
# options whose value is a file the wrapper writes (judged as a write) and makes the command a variant ("<id> [via time -o]")
WRAP_OUT = {("time", "-o"): "via time -o", ("time", "--output"): "via time -o"}
WRAP_OPERAND = {"timeout": re.compile(r"(\d+(\.\d*)?|\.\d+)[smhd]?"), "taskset": re.compile(r"(0x)?[0-9a-fA-F,-]+"), "chrt": re.compile(r"\d+"),
                "flock": re.compile(r".+")}
# 0.2.52: tracers and proxies are not stripped: what they run, trace, log or route is theirs (strace -o F, -e inject=..., proxychains -f conf):
# the line is opaque (asked every time, never covered by a list or an allowance). sudo / doas are stripped with their own options (WRAP_SYNTAX)
# so that the command is still judged; their head is "sudo <id>", which no default list holds and no allowance covers (allowances.why_not).
ALWAYS_ASK = {"strace": "strace", "ltrace": "ltrace", "proxychains": "proxychains", "proxychains4": "proxychains", "torsocks": "torsocks"}


def _wrap_long(name, a, spec):
    """-> (canonical long option, 'flag' | 'value' | 'optional') for `a` (`--out=F` -> `--output`), or None (unknown or ambiguous prefix)."""
    o = a.split("=", 1)[0]
    kinds = [(x, "flag") for x in spec[3]] + [(x, "value") for x in spec[4]] + [(x, "optional") for x in spec[5]]
    exact = [k for k in kinds if k[0] == o]
    if exact:
        return exact[0]
    hits = [k for k in kinds if k[0].startswith(o) and len(o) > 2]
    return hits[0] if len(hits) == 1 else None


def _unwrap_one(name, argv, i):
    """Options and operands of the wrapper at argv[i] -> (index of its command, issues, out-values, tags, opts seen)."""
    spec = WRAP_SYNTAX[name]
    issues, outs, seen = [], [], []
    i += 1
    while i < len(argv):
        a = argv[i]
        if a == "--":
            i += 1
            break
        if name == "env" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", a):
            i += 1                                       # env NAME=value
            continue
        if name == "env" and a == "-":
            seen.append("-i")
            i += 1
            continue
        if name == "nice" and re.fullmatch(r"--?\d+", a):
            i += 1                                       # obsolete `nice -5` / `nice --5`
            continue
        if not a.startswith("-") or a == "-":
            break
        if a.startswith("--"):
            k = _wrap_long(name, a, spec)
            if k is None:
                issues.append("%s %s: an option this version does not know" % (name, a.split("=", 1)[0]))
                return i + 1, issues, outs, seen
            opt, kind = k
            seen.append(opt)
            if kind == "value":
                if "=" in a:
                    val = a.split("=", 1)[1]
                elif i + 1 < len(argv):
                    i += 1
                    val = argv[i]
                else:
                    issues.append("%s %s: no value" % (name, opt))
                    return i + 1, issues, outs, seen
                if (name, opt) in WRAP_OUT:
                    outs.append((opt, val))
            elif kind == "flag" and "=" in a:
                issues.append("%s %s takes no value" % (name, opt))
                return i + 1, issues, outs, seen
            i += 1
            continue
        k = 1                                            # a short cluster: -pv, -oFILE, -po FILE, -iR
        while k < len(a):
            ch = a[k]
            if ch in spec[0]:
                seen.append("-" + ch)
                k += 1
                continue
            if ch in spec[2]:
                seen.append("-" + ch)                    # optional value: only glued, the rest of the word
                break
            if ch in spec[1]:
                seen.append("-" + ch)
                if k + 1 < len(a):
                    val = a[k + 1:]
                elif i + 1 < len(argv):
                    i += 1
                    val = argv[i]
                else:
                    issues.append("%s -%s: no value" % (name, ch))
                    return i + 1, issues, outs, seen
                if (name, "-" + ch) in WRAP_OUT:
                    outs.append(("-" + ch, val))
                break
            issues.append("%s -%s: an option this version does not know" % (name, ch))
            return i + 1, issues, outs, seen
        i += 1
    for _ in range(spec[6] if not (name == "taskset" and ("-p" in seen or "--pid" in seen)) else 0):
        if i >= len(argv) or not WRAP_OPERAND[name].fullmatch(argv[i]):
            issues.append("%s: not the operand expected before the command" % name)
            return min(i + 1, len(argv)), issues, outs, seen
        if name == "flock":
            outs.append(("lock", argv[i]))               # flock opens (and creates) the lock file
        i += 1
    if name == "flock" and i < len(argv) and argv[i].startswith("-"):
        seen.append("-c")                                # `flock FILE -c CMD`: a command string run by a shell
    return i, issues, outs, seen


def _unwrap(argv):
    """Drop VAR=value assignments, reserved words and wrappers (env, timeout 5, nice -n 5, time -o F, xargs ...), each read with its own
    option syntax (WRAP_SYNTAX). -> (argv of the command, info): info = {"xargs": bool, "issues": [why the line is opaque],
    "outs": [files a wrapper writes], "tags": [variant tags], "env": an env wrapper}."""
    info = {"xargs": False, "issues": [], "outs": [], "tags": [], "env": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        base = os.path.basename(a)
        if _runners.canon(base) in WRAP_SYNTAX:
            base = _runners.canon(base)              # RT7: gtimeout / gnice / genv / gxargs (Homebrew coreutils) are the same wrappers
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", a):
            i += 1
        elif a in KEYWORDS:
            i += 1                                   # 0.2.12: `then touch ~/.bashrc`, `do git push -f`, `! cd /etc`: the command is what follows
        elif base in ALWAYS_ASK:
            info["issues"].append("%s: runs another program as it decides (asked every time)" % ALWAYS_ASK[base])
            break                                    # 0.2.52: strace / ltrace / proxychains / torsocks: not stripped, the head is the tracer
        elif base in WRAP_SYNTAX:
            if base == "xargs":
                info["xargs"] = True
            if base == "env":
                info["env"] = True
            i, iss, outs, seen = _unwrap_one(base, argv, i)
            info["issues"] += iss
            for o in seen:
                if (base, o) in WRAP_RISKY and WRAP_RISKY[(base, o)] not in info["issues"]:
                    info["issues"].append(WRAP_RISKY[(base, o)])
            for opt, val in outs:
                info["outs"].append(val)
                if (base, opt) in WRAP_OUT and WRAP_OUT[(base, opt)] not in info["tags"]:
                    info["tags"].append(WRAP_OUT[(base, opt)])
        elif base == "parallel":
                                                     # composing wrapper: tagged "via parallel" from the prefix (_variants)
            if i + 1 < len(argv) and argv[i + 1].startswith("-"):
                info["issues"].append("parallel %s: options of GNU parallel are not parsed" % argv[i + 1])
            i += 1
        elif base == "busybox" and i + 1 < len(argv) and not argv[i + 1].startswith("-"):
            i += 1                                   # `busybox wget URL` is `wget URL`
        else:
            break
        if base == "watch" and i < len(argv) and not any(x in ("-x", "--exec") for x in argv[:i]):
            if any(re.search(r"[\s;&|<>()`$\\]", w) for w in argv[i:]):
                info["issues"].append("watch: a command string run by a shell")
    return argv[i:], info


def _strip_prefix(argv):
    """-> (argv of the command, via xargs) (see _unwrap)."""
    rest, info = _unwrap(argv)
    return rest, info["xargs"]


# ---------------------------------------------------------------- 0.2.53: local writes in the default mandate, every path checked
# mkdir, touch, cp, mv, ln, chmod, rm, rmdir and git add / commit / checkout / switch / restore / mv / rm are in the default mandate. The listed
# name covers ONLY a form whose every path -- what the command reads and what it writes -- was read for sure and lies inside the project or a temp
# directory, and touches no protected path. Any other form gets a variant tag ("cp [outside]", "rm [recursive]" ...), which no entry of the list
# matches and no project allowance covers: the owner is asked. Writes are also judged as writes (Bash.write: outside the mandate's targets ->
# deny RESOURCE), the harness and git's files as danger (always asked). Options are read with an explicit table per command: the options that
# mean the same in GNU coreutils 9 and in the BSD / macOS tools (man cp, mv, ln, rm, rmdir, mkdir, touch, chmod on Darwin; `info coreutils`)
# and git 2.54 (git help <sub>). An option outside the table, a long option written as a prefix, an option after an operand (GNU permutes,
# BSD stops) -> "unsure". Tags:
#   outside    a path is neither strictly inside the project nor inside a temp directory (also: no project; a symlink target outside the
#              project; a git repository whose top is not inside the project, or whose .git is a file pointing elsewhere)
#   unsure     an option not in the table, an expansion ($VAR, `..`, ~user), a glob, "-", an unknown directory, a chmod mode it cannot read,
#              a directory from outside the project (a temp one) copied or moved in whole, `cp -R dir/ dst` (contents merged),
#              a git pathspec with magic (":..."), interactive git forms (-p, -i, -e), pathspecs from a file
#   protected  a path is the agent's harness (.claude, .mcp.json ...), anything in or named `.git`, a credential file, the Deus Witness keys
#   recursive  rm -r / -R, git rm -r, chmod -R; dir: rm -f of a directory, git checkout/restore of a directory (many files' changes discarded)
#   force      git add -f (ignored files, often secrets), git checkout -f, git switch -f / --discard-changes / -C, git rm -f
#   branch     a ref switch (git checkout <ref> / -, git switch <ref> / -c N <start> / --detach <ref>, checkout -b N <start>) that
#              rewrites more than ordinary project files: the hook's fact (gitref.py: git diff-tree HEAD <ref>) names a protected path,
#              a .gitattributes / .gitmodules, a submodule, a post-checkout hook or hooks in the tree, or more paths than it lists; or there is
#              no fact (an older hook, git could not answer): asked. A switch that changes only ordinary files is the plain form (RT-0.2.53).
LW_CMDS = ("mkdir", "touch", "cp", "mv", "ln", "chmod", "rm", "rmdir")
LW_GIT = ("add", "commit", "checkout", "switch", "restore", "mv", "rm")
LW_LIST = list(LW_CMDS) + ["git " + s for s in LW_GIT]
F, V, O = "flag", "value", "optional"
# short flags (no value), short options with a value, long options {name: kind}; only what GNU and BSD read alike
LW_SPECS = {
    "mkdir": ("pv", "m", {"--parents": F, "--verbose": F, "--mode": V}),
    "touch": ("acmfh", "rtd", {"--no-create": F, "--no-dereference": F, "--reference": V, "--date": V, "--time": V}),
    "cp": ("finvpRPax", "t", {          # not -r: BSD / macOS cp -r is -RL (follows every link in the tree), GNU -r is -R"--force": F, "--interactive": F, "--no-clobber": F, "--verbose": F, "--recursive": F, "--archive": F,
                               "--no-dereference": F, "--one-file-system": F, "--target-directory": V, "--preserve": O}),
    "mv": ("finv", "t", {"--force": F, "--interactive": F, "--no-clobber": F, "--verbose": F, "--target-directory": V}),
    "ln": ("sfnvih", "t", {"--symbolic": F, "--force": F, "--no-dereference": F, "--verbose": F, "--interactive": F, "--target-directory": V}),
    "chmod": ("fvR", "", {"--silent": F, "--quiet": F, "--verbose": F, "--changes": F, "--recursive": F, "--reference": V}),
    "rm": ("fivdIrR", "", {"--force": F, "--verbose": F, "--dir": F, "--interactive": O, "--recursive": F}),
    "rmdir": ("pv", "", {"--parents": F, "--verbose": F, "--ignore-fail-on-non-empty": F}),
}
_GQ = {"--quiet": F, "--progress": F, "--no-progress": F}
LW_GIT_SPECS = {
    "add": ("nvuANfipe", "", "", dict(_GQ, **{"--dry-run": F, "--verbose": F, "--update": F, "--all": F, "--no-all": F, "--intent-to-add": F,
            "--refresh": F, "--ignore-errors": F, "--ignore-missing": F, "--renormalize": F, "--no-ignore-removal": F, "--ignore-removal": F,
            "--sparse": F, "--chmod": V, "--force": F, "--interactive": F, "--patch": F, "--edit": F, "--pathspec-from-file": V})),
    "commit": ("aqvnsze", "mFCct", "uS", dict(_GQ, **{"--all": F, "--verbose": F, "--no-verify": F, "--verify": F, "--signoff": F,
               "--allow-empty": F, "--allow-empty-message": F, "--amend": F, "--no-edit": F, "--edit": F, "--dry-run": F, "--short": F,
               "--branch": F, "--porcelain": F, "--long": F, "--null": F, "--reset-author": F, "--include": F, "--only": F, "--no-post-rewrite": F,
               "--status": F, "--no-status": F, "--message": V, "--file": V, "--reuse-message": V, "--reedit-message": V, "--fixup": V,
               "--squash": V, "--author": V, "--date": V, "--template": V, "--cleanup": V, "--trailer": V, "--untracked-files": O,
               "--gpg-sign": O, "--no-gpg-sign": F, "--patch": F, "--interactive": F, "--pathspec-from-file": V})),
    "checkout": ("qfmtlp", "bB", "", dict(_GQ, **{"--force": F, "--merge": F, "--detach": F, "--ours": F, "--theirs": F, "--overlay": F,
                 "--no-overlay": F, "--guess": F, "--no-guess": F, "--track": O, "--no-track": F, "--orphan": V, "--conflict": V,
                 "--ignore-skip-worktree-bits": F, "--patch": F, "--pathspec-from-file": V})),
    "switch": ("qfmdt", "cC", "", dict(_GQ, **{"--force": F, "--discard-changes": F, "--merge": F, "--detach": F, "--guess": F,
               "--no-guess": F, "--track": O, "--no-track": F, "--create": V, "--force-create": V, "--orphan": V, "--conflict": V})),
    "restore": ("SWqmp", "s", "", dict(_GQ, **{"--staged": F, "--worktree": F, "--ours": F, "--theirs": F, "--merge": F, "--overlay": F,
                "--no-overlay": F, "--ignore-unmerged": F, "--ignore-skip-worktree-bits": F, "--source": V, "--conflict": V, "--patch": F,
                "--pathspec-from-file": V})),
    "mv": ("vnfk", "", "", dict(_GQ, **{"--verbose": F, "--dry-run": F, "--force": F, "--sparse": F})),
    "rm": ("qnrf", "", "", dict(_GQ, **{"--cached": F, "--dry-run": F, "--ignore-unmatch": F, "--sparse": F, "--force": F, "--recursive": F,
           "--pathspec-from-file": V})),
}
LW_GIT_UNSURE = {"-i", "-p", "-e", "--interactive", "--patch", "--edit", "--pathspec-from-file"}
TEMP_IN = re.compile(r"^(/private)?/(tmp|var/tmp)/.|^(/private)?/var/folders/[^/]+/[^/]+/T/.")
# 13.11 (r0274, red team): a HOME kept inside a temp directory (containers, CI, some sandboxes: HOME=/tmp/u, /var/folders/../T/u) made
# every `~/...` a "temp path" for the gates that excuse temp (grep -r KEY ~ ran unasked, a write / delete in ~/Documents fell under the
# mandate's `<tmp>/*` target). Law: the home folder is the person's wherever the file system keeps it -- a path AT, UNDER or ABOVE the home
# is never temp. Compared lexically on the macOS firmlink form (/private/tmp = /tmp, /private/var = /var): the hook's HOME is often the
# unresolved spelling while operands are realpaths, and a realpath of the home would cost the remote fs a round trip.
_FIRMLINK = re.compile(r"^/private(?=/(?:tmp|var|etc)(?:/|$))")


def canon_path(p):
    """-> `p` normalized, with macOS's /private prefix of /tmp, /var, /etc dropped ("" for a non-absolute / non-string)."""
    if not isinstance(p, str) or not p.startswith("/"):
        return ""
    return _FIRMLINK.sub("", os.path.normpath(p))


def around_home(p, home) -> bool:
    """-> True when `p` is the home folder, inside it or above it (an absolute home other than "/" only)."""
    h, q = canon_path(home), canon_path(p)
    if not h or h == "/" or not q:
        return False
    return q == h or q.startswith(h.rstrip("/") + "/") or h.startswith(q.rstrip("/") + "/")


def under_home(p, home) -> bool:
    """-> True when `p` lies strictly inside the home folder (firmlink-insensitive, see around_home)."""
    h, q = canon_path(home), canon_path(p)
    return bool(h) and h != "/" and bool(q) and q.startswith(h.rstrip("/") + "/")


def temp_in(p, home) -> bool:
    """-> True for a path inside a temp directory that is not around the home folder (TEMP_IN minus the home, r0274)."""
    return isinstance(p, str) and bool(TEMP_IN.match(p)) and not around_home(p, home)


DW_KEYS = re.compile(r"(^|/)\.deus-witness(/|$)|/\.config/deus-witness(/|$)|(^|/)agent-key\.json$")
CHMOD_MODE = re.compile(r"[0-7]{1,4}|[ugoa]*([-+=]([rwxXst]*|[ugo]))+(,[ugoa]*([-+=]([rwxXst]*|[ugo]))+)*")


def _lw_opts(args, short_f, short_v, long_, permute=False, short_o=""):
    """getopt by an explicit table -> (options [(opt, value)], operands, why unsure or None). Exact long names only (a prefix is unsure: GNU and
    git take prefixes, BSD has no long options); a cluster `-pv`, a glued value `-m755` / `-mmsg`, `--opt=value`; `--` ends options. Without
    permute, an option after an operand is unsure (GNU reads it as an option, BSD as a file)."""
    opts, ops, k, end = [], [], 0, False
    while k < len(args):
        a = args[k]
        k += 1
        if end or a == "-" or not a.startswith("-"):
            ops.append(a)
            continue
        if a == "--":
            end = True
            continue
        if ops and not permute:
            return opts, ops, "option %s after an operand" % a
        if a.startswith("--"):
            o, eq, val = a.partition("=")
            kind = long_.get(o)
            if kind is None:
                return opts, ops, "option %s" % o
            if kind == F and eq:
                return opts, ops, "option %s takes no value" % o
            if kind == V and not eq:
                if k >= len(args):
                    return opts, ops, "option %s without a value" % o
                val, k = args[k], k + 1
            opts.append((o, val if (eq or kind == V) else None))
            continue
        j = 1
        while j < len(a):
            ch = a[j]
            if ch in short_f:
                opts.append(("-" + ch, None))
                j += 1
                continue
            if ch in short_o:
                opts.append(("-" + ch, a[j + 1:] or None))
                break
            if ch in short_v:
                if j + 1 < len(a):
                    val = a[j + 1:]
                elif k < len(args):
                    val, k = args[k], k + 1
                else:
                    return opts, ops, "option -%s without a value" % ch
                opts.append(("-" + ch, val))
                break
            return opts, ops, "option -%s" % ch
    return opts, ops, None


def _lw_protected(p: str) -> bool:
    return bool(is_agent_config_path(p) or re.search(r"/\.git(/|$)", p) or is_secret_path(p) or is_git_exec_path(p) or DW_KEYS.search(p))


class _LW:
    """The paths of one simple command of the list, checked one by one; tags collect why it is not the plain listed form."""

    def __init__(self, here, home, project, c):
        self.here, self.home, self.project, self.c, self.tags, self.writes = here, home, project, c, [], []

    def tag(self, t):
        if t not in self.tags:
            self.tags.append(t)

    def where(self, real) -> str:
        pr = self.project
        if pr is not None and real != pr and _in_project(real, pr):
            return "project"
        if pr is not None and real == pr:
            return "root"
        return "temp" if temp_in(real, self.home) else "outside"

    def path(self, o, here=None, role="read"):
        """-> the realpath of operand `o` (None when it cannot be known), tagging what it is. role: read (project, its root or temp), write
        (strictly inside the project or temp), link (a symlink / hard link target: inside the project only)."""
        here = self.here if here is None else here
        e = _expand(o, here, self.home) if o != "-" else None
        if e is None or not e or re.search(r"[*?[]", e) or "\0" in e:
            self.tag("unsure")
            return None
        if here == LOST_CWD and not e.startswith("/") and not e.startswith("~"):
            self.tag("unsure")
            return None
        lex = os.path.normpath(os.path.join(here, self.home + e[1:] if e == "~" or e.startswith("~/") else e))
        real = _abspath(e, here, self.home)
        if _in_project(real, LOST_CWD) or _in_project(lex, LOST_CWD):
            self.tag("unsure")
            return None
        if _lw_protected(lex) or _lw_protected(real):
            self.tag("protected")
        w = self.where(real)
        ok = {"read": ("project", "root", "temp"), "write": ("project", "temp"), "link": ("project", "root")}[role]
        if w not in ok:
            self.tag("outside")
        return real

    def write(self, real):
        """A path the command changes. Kept only for the plain form (no tag): then these are its writes, exactly (judged by the mandate's
        delete targets); a tagged form is asked anyway and keeps the coarse writes of _one (a directory destination, an option's value)."""
        if real is not None and real not in self.writes:
            self.writes.append(real)

    def into(self, dest_real, dest_word, src_word, here=None):
        """Where an entry named after `src_word` lands under the destination: dest/basename(src) when the destination is a directory."""
        b = os.path.basename(src_word.rstrip("/")) or src_word
        if b in (".", ".."):
            self.tag("unsure")                       # `cp -R dir/. dst`: the contents are merged into dst
            return None
        return self.path(os.path.join(dest_word, b), here=here, role="write")


def _local_write(name, args, here, home, project, c):
    """0.2.53: -> variant tags of a simple command of LW_LIST (see above); [] for the plain form, whose exact writes are then added to c."""
    lw = _LW(here, home, project, c)
    tags = _lw_tags(name, args, lw)
    if not tags:
        for p in lw.writes:
            c.write(p)
    return tags


ARTIFACT_DIRS = frozenset({"build", "dist", "out", "target", "node_modules", ".cache", "cache", "__pycache__", ".pytest_cache", ".mypy_cache",
                           ".ruff_cache", ".hypothesis", ".tox", ".nox", "htmlcov", "coverage", ".coverage_html", ".next", ".nuxt", ".svelte-kit",
                           ".turbo", ".parcel-cache", ".vite", ".angular", ".gradle", ".eggs", "_build", ".docusaurus", ".expo", "DerivedData",
                           ".dart_tool", "bazel-out", "cmake-build-debug", "cmake-build-release", ".nyc_output", ".webpack", "storybook-static"})


def _artifact(real, project) -> bool:
    """0.2.89: `real` (strictly inside `project`) lies in a folder a build or a tool regenerates (by a component name, or *.egg-info)."""
    rel = real[len(project.rstrip("/")) + 1:].split("/")
    return any(x in ARTIFACT_DIRS or (x.endswith(".egg-info") and len(x) > 9) for x in rel if x)


def _lw_tags(name, args, lw):
    here, project = lw.here, lw.project
    if project is None:
        lw.tag("outside")                            # no project (the session left it): nothing can be checked against it
    if name == "git":
        _lw_git(args, lw)
        return lw.tags
    sf, sv, lo = LW_SPECS[name]
    if name == "chmod":                              # `chmod -w f`, `chmod -x,o-r f`: a mode that starts with '-' is the mode, not options
        k = next((i for i, a in enumerate(args) if not re.fullmatch(r"-[fvR]+|--[a-z-]+(=.*)?", a)), len(args))
        if k < len(args) and args[k].startswith("-") and args[k] != "--" and CHMOD_MODE.fullmatch(args[k]):
            args = args[:k] + ["--", args[k]] + args[k + 1:]
    opts, ops, why = _lw_opts(args, sf, sv, lo)
    if why:
        lw.tag("unsure")
        return lw.tags
    o = {k for k, _ in opts}
    val = {k: v for k, v in opts}
    tgt = val.get("-t") or val.get("--target-directory")
    if name == "mkdir":
        if not ops:
            lw.tag("unsure")
        for p in ops:
            lw.write(lw.path(p, role="write"))
    elif name == "touch":
        ref = val.get("-r") or val.get("--reference")
        if ref is not None:
            lw.path(ref)
        if not ops:
            lw.tag("unsure")
        for p in ops:
            lw.write(lw.path(p, role="write"))
    elif name == "chmod":
        ref = val.get("--reference")
        if ref is not None:
            lw.path(ref)
        elif not ops or not CHMOD_MODE.fullmatch(ops[0]):
            lw.tag("unsure")                         # BSD ACL forms (+a, =a, -E, -C, -N ...) or no mode
            return lw.tags
        else:
            ops = ops[1:]
        if o & {"-R", "--recursive"}:
            lw.tag("recursive")
        if not ops:
            lw.tag("unsure")
        for p in ops:
            lw.write(lw.path(p, role="write"))
    elif name == "rm":
        rec = bool(o & {"-r", "-R", "--recursive"})
        if not ops:
            lw.tag("unsure")
        # 0.2.89 (friction 03.11): `rm -rf build`, `rm -rf node_modules/.cache`: a recursive delete of a literal path strictly inside the
        # project -- the mandate's own delete targets -- under a folder that a build regenerates (ARTIFACT_DIRS: build, dist, node_modules,
        # caches ...) is the plain form. `rm -rf src`, `rm -rf docs`, a temp directory: as before (rm-rf, asked). Not: the project's root or a folder above
        # it, a .git directory (history) or any protected path (lw.path tags those), a glob / $VAR (unsure), a path the session cannot see.
        for p in ops:
            r = lw.path(p, role="write")
            if rec and (r is None or project is None or not _in_project(r, project) or _in_project(project, r) or re.search(r"(^|/)\.git(/|$)", r)
                        or p.rstrip("/") in ("", ".", "..", "~") or p.startswith("-") or not _artifact(r, project)):
                lw.tag("recursive")
            if r is not None and not rec and o & {"-f", "--force"} and _fs.current().isdir(r):
                lw.tag("dir")
            lw.write(r)
        if rec and lw.tags:
            lw.tag("recursive")
    elif name == "rmdir":
        if not ops:
            lw.tag("unsure")
        for p in ops:
            words = [p.rstrip("/") or p]
            if o & {"-p", "--parents"}:              # `rmdir -p a/b/c` removes a/b/c, a/b, a (as written)
                d = os.path.dirname(words[0])
                while d and d not in ("/", ".", ".."):
                    words.append(d)
                    d = os.path.dirname(d)
            for w in words:
                lw.write(lw.path(w, role="write"))
    elif name in ("cp", "mv"):
        if o & {"-T"}:
            lw.tag("unsure")
        srcs, dest = (ops, tgt) if tgt is not None else (ops[:-1], ops[-1] if ops else None)
        if dest is None or not srcs:
            lw.tag("unsure")
            return lw.tags
        dreal = lw.path(dest, role="read")          # a directory destination may be the project's root: what lands in it is checked
        dir_dest = tgt is not None or (dreal is not None and _fs.current().isdir(dreal))
        if dreal is not None and not dir_dest and lw.where(dreal) not in ("project", "temp"):
            lw.tag("outside")
        if not dir_dest and len(srcs) > 1:
            lw.tag("unsure")
        recursive = name == "mv" or bool(o & {"-R", "-a", "--recursive", "--archive"})
        for s in srcs:
            sreal = lw.path(s, role="write" if name == "mv" else "read")
            if name == "mv":
                lw.write(sreal)                      # the source's entry goes away
            lands = dreal is not None and lw.where(dreal) in ("project", "root")
            if sreal is not None and recursive and _fs.current().isdir(sreal):
                if lands and lw.where(sreal) != "project":
                    lw.tag("unsure")                 # a directory from elsewhere lands whole: a .git, .claude or .mcp.json in it is unseen
                                                     # (the hook answers only about the paths of its call, not about their contents)
                if name == "cp" and (s.endswith("/") or s.endswith("/.")):
                    lw.tag("unsure")                 # BSD `cp -R dir/ dst` merges the contents into dst
            if dir_dest:
                lw.write(lw.into(dreal, dest, s))
        if not dir_dest:
            lw.write(dreal)
        elif dreal is not None and tgt is not None and not _fs.current().isdir(dreal):
            lw.tag("unsure")
    elif name == "ln":
        sym = bool(o & {"-s", "--symbolic"})
        if o & {"-n", "-h", "--no-dereference"} and len(ops) >= 2 and tgt is None:
            lw.tag("unsure")                         # with a symlink to a directory as the link name, GNU / BSD replace or descend differently
        if tgt is not None:
            targets, links = ops, [(tgt, t) for t in ops]
        elif len(ops) == 1:
            targets, links = ops, [(".", ops[0])]
        elif len(ops) >= 2:
            targets = ops[:-1]
            dreal = lw.path(ops[-1], role="read")
            if dreal is not None and _fs.current().isdir(dreal):
                links = [(ops[-1], t) for t in targets]
            elif len(targets) == 1:
                links = [(None, targets[0])]
            else:
                lw.tag("unsure")
                return lw.tags
        else:
            lw.tag("unsure")
            return lw.tags
        for d, t in links:
            if d is None:
                link_word = ops[-1]
            else:
                link_word = os.path.join(d, os.path.basename(t.rstrip("/")) or t)
            lreal = lw.path(link_word, role="write")
            lw.write(lreal)
            if lreal is None:
                continue
            if sym and not t.startswith("/") and not t.startswith("~") and not t.startswith("$"):
                lex = os.path.normpath(os.path.join(here, link_word))
                base = _fs.current().realpath(os.path.dirname(lex))       # a relative symlink is read from the link's directory
                lw.path(t, here=base, role="link")
            else:
                lw.path(t, role="link")
    return lw.tags


def _lw_git(args, lw):
    here, i = lw.here, 0
    while i < len(args) and args[i].startswith("-"):
        a = args[i]
        if a == "-C" and i + 1 < len(args):
            r = lw.path(args[i + 1], here=here, role="read")
            if r is None:
                return
            here, i = r, i + 2
            continue
        if a in ("--no-pager", "-P", "--no-optional-locks", "--literal-pathspecs"):
            i += 1
            continue
        lw.tag("unsure")                             # -c, --git-dir, --work-tree, --exec-path ...: also tagged by _variants
        return
    if i >= len(args):
        return
    sub, rest = args[i], args[i + 1:]
    top = _lw_repo(here, lw)
    sf, sv, so, lo = LW_GIT_SPECS[sub]
    dd = "--" in rest
    opts, before, why = _lw_opts(rest[:rest.index("--")] if dd else rest, sf, sv, lo, permute=True, short_o=so)
    after = rest[rest.index("--") + 1:] if dd else []
    ops = before + after
    if why:
        lw.tag("unsure")
        return
    o = {k for k, _ in opts}
    val = {k: v for k, v in opts}
    if o & LW_GIT_UNSURE:
        lw.tag("unsure")                             # interactive, an editor of the patch, pathspecs from a file
    if sub == "add" and o & {"-f", "--force"}:
        lw.tag("force")
    if sub == "commit":
        for k in ("-F", "--file", "-t", "--template"):
            if val.get(k) not in (None, "-"):
                lw.path(val[k], here=here)
    if sub in ("checkout", "switch") and o & {"-f", "--force", "--discard-changes", "-C", "--force-create", "-B", "-m", "--merge"}:
        lw.tag("force")
    paths = []
    if sub in ("add", "commit", "rm"):
        paths = ops
    elif sub == "restore":
        paths = ops
        if not paths:
            lw.tag("unsure")
    elif sub == "checkout":
        new = val.get("-b") or val.get("-B") or val.get("--orphan")
        if dd:
            paths = after
            if len(before) > 1 or new is not None:
                lw.tag("unsure")
        else:
            for x in ops:                            # `git checkout X`: a branch, a commit or a path (git decides): as a path it must be ours
                if x == "-":                         # `git checkout -`: the previous branch (@{-1})
                    if _lw_ref(lw, top, x) is not True:
                        lw.tag("branch")
                    continue
                r = lw.path(x, here=here, role="write")
                if x.startswith(":") or r is None:
                    lw.tag("unsure")
                    continue
                k = _lw_ref(lw, top, x)              # a commit -> git switches to it (even when a file X exists: `touch main; git checkout main`)
                if k is None or (k is False and not _fs.current().exists(r)):
                    lw.tag("branch")                 # unknown, or no commit and no path: git guesses a remote branch (or fails)

    elif sub == "switch":
        if o & {"--orphan"}:
            lw.tag("force")                          # `git switch --orphan`: the tracked files leave the working tree
        for x in ops:                                # `git switch <ref>` / `-c N <start>` / `--detach <ref>`; bare `-c N` stays at HEAD
            if _lw_ref(lw, top, x) is not True:
                lw.tag("branch")
    elif sub == "mv":
        if len(ops) < 2:
            lw.tag("unsure")
    for p in paths:
        if p.startswith(":"):
            lw.tag("unsure")                         # pathspec magic (:/, :(top), :!x)
            continue
        worktree = sub in ("checkout", "restore") and not (sub == "restore" and o & {"-S", "--staged"} and not o & {"-W", "--worktree"})
        changes = worktree or (sub == "rm" and not o & {"--cached"})
        r = lw.path(p, here=here, role="write" if changes else "read")     # only the index changes: a read of the path
        if r is None:
            continue
        if changes:
            if _fs.current().isdir(r):
                lw.tag("dir" if sub != "rm" else "recursive")
            lw.write(r)
    if sub == "rm":
        if o & {"-r", "--recursive"}:
            lw.tag("recursive")
        if o & {"-f", "--force"}:
            lw.tag("force")
        if not ops:
            lw.tag("unsure")
    if sub == "mv" and len(ops) >= 2:
        dreal = lw.path(ops[-1], here=here, role="read")
        dir_dest = dreal is not None and _fs.current().isdir(dreal)
        if dreal is not None and not dir_dest and lw.where(dreal) not in ("project", "temp"):
            lw.tag("outside")
        if not dir_dest and len(ops) > 2:
            lw.tag("unsure")
        for s in ops[:-1]:
            sreal = lw.path(s, here=here, role="write")
            lw.write(sreal)
            if dir_dest:
                lw.write(lw.into(dreal, ops[-1], s, here=here))
        if not dir_dest:
            lw.write(dreal)


def _lw_repo(here, lw):
    """The repository git works on must have its top inside the project, with `.git` a directory there (a `.git` file points to a git directory
    elsewhere: a worktree or a submodule, where git writes outside the project). -> that top, or None (tagged)."""
    pr = lw.project
    if pr is None or here == LOST_CWD:
        lw.tag("outside")
        return None
    d = here
    while _in_project(d, pr):
        g = os.path.join(d, ".git")
        if _fs.current().exists(g):
            if not _fs.current().isdir(g):
                lw.tag("outside")
                return None
            return d
        if d == pr:
            break
        d = os.path.dirname(d)
    lw.tag("outside")
    return None


REF_FILES = (".gitattributes", ".gitmodules")      # how git checks files out (filters, eol) and where submodules come from


def _lw_ref(lw, top, ref):
    """0.2.53 (red team): a ref switch of the repository at `top`, judged by the hook's fact (fs gitref, gitref.py). -> True: `ref` is a commit
    and the switch was judged (tagged `branch` unless every changed path is an ordinary project file); False: no commit; None: no answer."""
    v = _fs.current().gitref(top, ref) if top is not None else None
    if not isinstance(v, dict):
        return None
    if not v.get("commit"):
        return False
    if v.get("more") or v.get("special") or any(_lw_ref_protected(top, p) for p in v.get("paths") or ()):
        lw.tag("branch")
    return True


def _lw_ref_protected(top, p) -> bool:
    if not isinstance(p, str) or not p or p.startswith("/") or "\0" in p or ".." in p.split("/"):
        return True
    full = top.rstrip("/") + "/" + p
    return (_lw_protected(full) or _lw_protected(full.lower()) or p.rsplit("/", 1)[-1].lower() in REF_FILES
            or bool(re.search(r"(^|/)\.git(/|$)", p, re.I)))


# 0.2.54: find, sed, awk, jq. The plain form of each only reads (inside the project for find; files named on the line, as cat does, for the
# others) and prints to stdout; any form that runs a program, writes or deletes a file, reads a file the line does not show as an operand, or
# that the parser cannot read for sure gets a variant tag and is asked: [exec] (find -exec/-execdir/-ok/-okdir; sed e, s///e; awk system(),
# pipes, @load / @include, extension()), [write] (find -fprint/-fprint0/-fprintf/-fls; sed -i / -I / --in-place, w / W, s///w; awk print >
# / >>), [delete] (find -delete), [read] (sed r / R, awk getline < file, jq import / include), [outside] (a find start point or a reference
# file, a sed r file, a jq --rawfile / --slurpfile / -L / -f path outside the project or temp), [follow] (find -L / -follow: symlinks lead
# anywhere), [unsure] (an option or a primary not in the table, a script the parser cannot read, a `$` or backquote that is not single-quoted:
# the shell expands it, splits it into words, and may add options), [protected]. sed -f / awk -f (a program in a file) -> opaque.
# jq: `env` / `$ENV` print the environment, as `printenv` does -> danger `secrets` (and so the class "the agent saw a secret").
TX_SED = ("sed", "gsed")
TX_AWK = ("awk", "gawk", "mawk", "nawk")
TX_FIND = ("find", "gfind")
TX_JQ = ("jq",)
TX_NAMES = TX_SED + TX_AWK + TX_FIND + TX_JQ
TX_TAG_ORDER = ("exec", "write", "delete", "read", "outside", "follow", "protected", "unsure")


class _Lit(str):
    """0.2.54: a word whose every `$` and backquote was inside single quotes: literal text, the shell expands nothing in it."""


def _lit_ok(w: str) -> bool:
    """A word the shell passes as written: no expansion left in it (a single-quoted `$1` of an awk program is fine, `"$X"` / `$X` is not)."""
    return isinstance(w, _Lit) or not re.search(r"[$`]", w)


FIND_PRE = set("HLPEXdsx")                              # BSD and GNU options before the start points (-f PATH, -D, -O apart)
FIND_NOARG = {"-print", "-print0", "-ls", "-prune", "-quit", "-true", "-false", "-empty", "-executable", "-readable", "-writable", "-nouser",
              "-nogroup", "-depth", "-d", "-xdev", "-x", "-mount", "-noleaf", "-daystart", "-ignore_readdir_race", "-noignore_readdir_race",
              "-nowarn", "-warn", "-acl", "-xattr", "-not", "!", "-a", "-and", "-o", "-or", "(", ")", ","}
FIND_ARG = {"-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-lname", "-ilname", "-type", "-xtype",
            "-maxdepth", "-mindepth", "-size", "-perm", "-user", "-group", "-uid", "-gid", "-links", "-inum", "-mtime", "-atime", "-ctime",
            "-mmin", "-amin", "-cmin", "-Btime", "-Bmin", "-used", "-fstype", "-regextype", "-printf", "-flags", "-xattrname"}
FIND_FILE = {"-newer", "-anewer", "-cnewer", "-Bnewer", "-samefile"}
FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir"}
FIND_OUT = {"-fprint": 1, "-fprint0": 1, "-fls": 1, "-fprintf": 2}


def _tx(name, args, here, home, project, c, depth=0):
    """0.2.54 -> (variant tags, words that are a program / script / pattern, not files). The plain form has no tag."""
    lw = _LW(here, home, project, c)
    nonfile = set()
    if name in TX_FIND:
        _tx_find(args, lw, c, here, home, project, depth, nonfile)
    elif name in TX_SED:
        _tx_sed(args, lw, c, nonfile)
    elif name in TX_AWK:
        _tx_awk(args, lw, c, nonfile)
    else:
        _tx_jq(args, lw, c, nonfile)
    return [t for t in TX_TAG_ORDER if t in lw.tags], nonfile


def _tx_read(lw, c, o):
    """A file the command reads that is not an operand (a find reference file, sed r, a jq --rawfile ...): inside the project or temp."""
    if not _lit_ok(o):
        lw.tag("unsure")
        return
    e = _expand(o, lw.here, lw.home)
    if e and lw.here != LOST_CWD and (is_secret_path(o) or is_secret_path(_abspath(e, lw.here, lw.home))):
        c.add("secrets", _abspath(e, lw.here, lw.home))
    lw.path(o, role="read")


def _tx_write(lw, c, o):
    if o in ("/dev/stdout", "/dev/stderr", "/dev/null"):
        return                                            # `print > "/dev/stderr"`, `w /dev/stdout`: no file
    lw.tag("write")
    if not _lit_ok(o):
        lw.tag("unsure")
        c.opaque = True
        c.add("opaque", "write to " + o)
        return
    _write_target(o, lw.here, lw.home, c, c.writes)


def _tx_find(args, lw, c, here, home, project, depth, nonfile):
    k, starts = 0, []
    while k < len(args) and args[k].startswith("-") and len(args[k]) > 1 and args[k] not in FIND_NOARG and args[k] not in FIND_ARG \
            and args[k] not in FIND_FILE and args[k] not in FIND_EXEC and args[k] not in FIND_OUT and args[k] != "-delete" and args[k] != "-follow":
        a = args[k]
        if a == "-f" and k + 1 < len(args):              # BSD: `-f path` names a start point
            starts.append(args[k + 1])
            k += 2
            continue
        if re.fullmatch(r"-O[0-3]", a):
            k += 1
            continue
        if not set(a[1:]) <= FIND_PRE:
            lw.tag("unsure")                              # -D (GNU debug options), `--`, anything else
        if "L" in a[1:]:
            lw.tag("follow")
        k += 1
    while k < len(args) and not (args[k].startswith("-") and len(args[k]) > 1) and args[k] not in ("(", ")", "!", ","):
        starts.append(args[k])
        k += 1
    for s in starts or ["."]:
        if not _lit_ok(s):
            lw.tag("unsure")
        else:
            lw.path(s, role="read")
    while k < len(args):
        a = args[k]
        k += 1
        if not _lit_ok(a):
            lw.tag("unsure")                              # `find . -name $X`: the shell splits $X into words, `-exec` among them
            continue
        if a in FIND_NOARG:
            if a == "-depth" and k < len(args) and re.fullmatch(r"[+-]?\d+", args[k]):
                k += 1                                    # BSD `-depth n`
            continue
        if a == "-follow":
            lw.tag("follow")
            continue
        if a == "-delete":
            lw.tag("delete")
            continue
        if a in FIND_ARG or re.fullmatch(r"-newer[aBcm]t", a):
            if k >= len(args):
                lw.tag("unsure")
                break
            if not _lit_ok(args[k]):
                lw.tag("unsure")
            nonfile.add(args[k])
            k += 1
            continue
        if a in FIND_FILE or re.fullmatch(r"-newer[aBcm][aBcm]", a):
            if k >= len(args):
                lw.tag("unsure")
                break
            _tx_read(lw, c, args[k])
            k += 1
            continue
        if a in FIND_OUT:
            if k + FIND_OUT[a] > len(args):
                lw.tag("unsure")
                break
            _tx_write(lw, c, args[k])
            nonfile.update(args[k + 1:k + FIND_OUT[a]])
            k += FIND_OUT[a]
            continue
        if a in FIND_EXEC:
            lw.tag("exec")
            j = k
            while j < len(args) and not (args[j] == ";" or (args[j] == "+" and j > k and args[j - 1] == "{}")):
                j += 1
            if j >= len(args) or j == k:
                lw.tag("unsure")                          # no command, or no `;` / `{} +` that ends it
                break
            inner = args[k:j]
            nonfile.update(inner)
            if all(_lit_ok(x) for x in inner):            # what it runs: its dangers, writes and hosts count (the head stays `find [exec]`)
                d = classify(shlex.join(inner), here if a in ("-exec", "-ok") else LOST_CWD, home, depth + 1, project, _budget=c.budget)
                for x in d.danger:
                    c.add(*x.split(":", 1)) if ":" in x else c.add(x)
                for p in d.writes:
                    c.write(p)
                for h in d.net:
                    c.host(h)
                for p in d.extract:                       # RT-0270: what it extracts (git checkout {} ...) is foreign: its operands are unknown
                    if p not in c.extract:
                        c.extract.append(p)
                    if p not in c.xforeign:
                        c.xforeign.append(p)
                for p in d.xdirs:
                    if p not in c.xdirs:
                        c.xdirs.append(p)
                c.gtamper = c.gtamper or d.gtamper or bool(d.extract and "git" in [str(h).split(" ", 1)[0] for h in d.heads])
                for p in d.gstore:
                    if p not in c.gstore:
                        c.gstore.append(p)
                c.opaque = c.opaque or d.opaque
            else:
                lw.tag("unsure")
            k = j + 1
            continue
        lw.tag("unsure")                                  # a primary not in the table (GNU / BSD extensions we did not read): asked


def _sed_delim(s, i, d):
    """-> index of the delimiter `d` that ends a regex / replacement starting at s[i], or None. Two readings: GNU (no bracket rule) and BSD
    (a delimiter inside [...] is literal, checked on this machine: `s/[/]/X/`); when they end in different places the script is unsure."""
    def scan(brackets):
        j = i
        while j < len(s):
            ch = s[j]
            if ch == "\\":
                j += 2
                continue
            if ch == "\n" and d != "\n":
                return None
            if brackets and ch == "[":
                m = j + 1
                if m < len(s) and s[m] == "^":
                    m += 1
                if m < len(s) and s[m] == "]":
                    m += 1
                while m < len(s) and s[m] != "]":
                    if s.startswith(("[:", "[.", "[="), m):
                        e = s.find(s[m + 1] + "]", m + 2)
                        if e < 0:
                            return None
                        m = e + 2
                        continue
                    m += 1
                if m >= len(s):
                    return None
                j = m + 1
                continue
            if ch == d:
                return j
            j += 1
        return None
    a, b = scan(False), scan(True)
    return a if a == b else -1


def _sed_script(s):
    """0.2.54: a sed script -> [(kind, arg)]: ("exec", cmd), ("write", file), ("read", file), ("unsure", why). Commands of POSIX, GNU and BSD
    sed; anything else, or a script that does not end where a command must, is unsure (fail closed)."""
    out, i, n = [], 0, len(s)

    def rest_of_line(j):
        e = s.find("\n", j)
        e = n if e < 0 else e
        return s[j:e].strip(" \t"), e

    def addr(j):
        if j < n and s[j].isdigit():
            while j < n and s[j].isdigit():
                j += 1
            if j < n and s[j] == "~":
                j += 1
                while j < n and s[j].isdigit():
                    j += 1
            return j
        if j < n and s[j] == "$":
            return j + 1
        if j < n and s[j] in "/\\":
            d = "/"
            if s[j] == "\\":
                if j + 1 >= n or s[j + 1] in "\n\\":
                    return None
                d, j = s[j + 1], j + 1
            e = _sed_delim(s, j + 1, d)
            if e is None or e < 0:
                return None
            j = e + 1
            while j < n and s[j] in "IM":
                j += 1
            return j
        return j
    while i < n:
        while i < n and s[i] in " \t\n;":
            i += 1
        if i >= n:
            break
        if s[i] == "#":
            _, i = rest_of_line(i)
            continue
        j = addr(i)
        if j is None:
            return out + [("unsure", "address")]
        if j > i and j < n and s[j] == ",":
            j += 1
            if j < n and s[j] in "+~":
                j += 1
                while j < n and s[j].isdigit():
                    j += 1
            else:
                j2 = addr(j)
                if j2 is None or j2 == j:
                    return out + [("unsure", "address")]
                j = j2
        while j < n and s[j] in " \t!":
            j += 1
        if j >= n:
            return out + [("unsure", "address without a command")]
        cmd, i = s[j], j + 1
        if cmd == "{":
            continue                                      # a block: its first command follows directly
        if cmd in "}=dDgGhHnNpPxzF":
            pass
        elif cmd in "qQlL":
            while i < n and s[i] in " \t":
                i += 1
            while i < n and s[i].isdigit():
                i += 1
        elif cmd in "aic":
            while True:                                   # the text: to the end of the line, and on while a line ends with a backslash
                e = s.find("\n", i)
                if e < 0:
                    i = n
                    break
                line = s[i:e]
                i = e + 1
                if (len(line) - len(line.rstrip("\\"))) % 2 == 0:
                    break
            continue
        elif cmd in "btT:v":
            while i < n and s[i] not in "\n;":           # a label ends at `;` for GNU, at the newline for BSD: the shorter reading is
                i += 1                                    # taken (what follows a `;` is parsed as commands: more is checked, not less)
            continue
        elif cmd in "rRwW":
            f, i = rest_of_line(i)
            out.append(("read" if cmd in "rR" else "write", f))
            continue
        elif cmd == "e":
            f, i = rest_of_line(i)
            out.append(("exec", f or "(pattern space)"))
            continue
        elif cmd in "sy":
            if i >= n or s[i] in "\\\n":
                return out + [("unsure", "%s delimiter" % cmd)]
            d = s[i]
            e1 = _sed_delim(s, i + 1, d)
            e2 = _sed_delim(s, e1 + 1, d) if e1 is not None and e1 >= 0 else None
            if e2 is None or e2 < 0:
                return out + [("unsure", "%s command" % cmd)]
            i = e2 + 1
            if cmd == "s":
                while i < n and s[i] not in " \t\n;}#":
                    f = s[i]
                    if f == "w":
                        fn, i = rest_of_line(i + 1)
                        out.append(("write", fn))
                        break
                    if f == "e":
                        out.append(("exec", "s///e"))
                    elif f not in "gpiImM0123456789":
                        return out + [("unsure", "s flag %s" % f)]
                    i += 1
        else:
            return out + [("unsure", "command %s" % cmd)]
        while i < n and s[i] in " \t":
            i += 1
        if i < n and s[i] not in "\n;}#":
            if cmd == "}" or s[i] == "}":
                continue
            return out + [("unsure", "after command %s" % cmd)]
    return out


SED_FLAGS = set("nrEsuza")
SED_LONG_F = {"--quiet", "--silent", "--regexp-extended", "--separate", "--unbuffered", "--null-data", "--zero-terminated", "--posix",
              "--debug", "--sandbox", "--follow-symlinks"}


def _tx_sed(args, lw, c, nonfile):
    scripts, ops, inplace, bare_i, k, end, from_file = [], [], False, False, 0, False, False
    while k < len(args):
        a = args[k]
        k += 1
        if end or a == "-" or not a.startswith("-"):
            ops.append(a)
            continue
        if a == "--":
            end = True
            continue
        if a.startswith("--"):
            o, eq, v = a.partition("=")
            if o in SED_LONG_F and not eq:
                continue
            if o == "--in-place":
                inplace = True
                continue
            if o in ("--expression", "--file", "--line-length"):
                if not eq:
                    if k >= len(args):
                        lw.tag("unsure")
                        break
                    v, k = args[k], k + 1
                if o == "--expression":
                    scripts.append(v)
                    nonfile.add(v)
                    nonfile.add(a)
                elif o == "--file":
                    from_file = True
                continue
            lw.tag("unsure")
            continue
        j = 1
        while j < len(a):
            ch = a[j]
            if ch in SED_FLAGS:
                j += 1
                continue
            if ch in "iI":
                inplace = True
                if j + 1 == len(a):                       # bare -i: GNU no suffix; BSD takes the next word as the suffix (`-i ''`)
                    if k < len(args) and args[k] == "":
                        k += 1
                    else:
                        bare_i = True
                break
            if ch in "ef":
                v = a[j + 1:]
                if not v:
                    if k >= len(args):
                        lw.tag("unsure")
                        break
                    v, k = args[k], k + 1
                if ch == "e":
                    scripts.append(v)
                    nonfile.add(v)
                else:
                    from_file = True
                break
            lw.tag("unsure")                              # -l (GNU: a value, BSD: a flag), -b, anything else
            break
    if from_file:
        c.opaque = True
        c.add("opaque", "sed -f: the script is in a file")
    if not scripts and not from_file:
        if not ops:
            lw.tag("unsure")
            return
        scripts.append(ops[0])
        nonfile.add(ops[0])
        if bare_i and len(ops) > 1:
            scripts.append(ops[1])                        # BSD reads `sed -i X script f` (X the suffix): the second word may be the script
        files = ops[1:]
    else:
        files = ops
    for sc in scripts:
        if not _lit_ok(sc):
            lw.tag("unsure")
            continue
        for kind, arg in _sed_script(sc):
            if kind == "exec":
                lw.tag("exec")
            elif kind == "write":
                _tx_write(lw, c, arg)
            elif kind == "read":
                lw.tag("read")
                _tx_read(lw, c, arg)
            else:
                lw.tag("unsure")
    for f in files:
        if not _lit_ok(f):
            lw.tag("unsure")
    if inplace:
        lw.tag("write")
        for f in files:
            if f != "-":
                _tx_write(lw, c, f)


# where a `/` can only start a regex (an operand is expected and `/` cannot be a division); elsewhere it is read as a division. A regex read as
# a division only exposes more to the checks below (fail closed); the other way round (`getline / 1; print | "sh"; x = 1 / 1`) would hide code
AWK_REGEX_BEFORE = {None, "(", ",", "{", "}", ";", "\n", "!", "~", "!~", "&&", "||", "?", ":", "=", "==", "!=", "print", "printf", "return",
                    "do", "else"}


def _awk_tokens(p):
    """0.2.54: awk program -> [(kind, text)], kind one of str, re, id, num, op; None when a string or a regex never ends."""
    out, i, n = [], 0, len(p)
    while i < n:
        ch = p[i]
        if ch in " \t\r":
            i += 1
            continue
        if ch == "\\" and i + 1 < n and p[i + 1] == "\n":
            i += 2
            continue
        if ch == "#":
            while i < n and p[i] != "\n":
                i += 1
            continue
        if ch == '"':
            j, buf = i + 1, []
            while j < n and p[j] != '"':
                if p[j] == "\\" and j + 1 < n:
                    buf.append(p[j:j + 2])
                    j += 2
                    continue
                if p[j] == "\n":
                    return None
                buf.append(p[j])
                j += 1
            if j >= n:
                return None
            out.append(("str", "".join(buf)))
            i = j + 1
            continue
        prev = out[-1][1] if out and out[-1][0] in ("op", "id") else (None if not out else "#value")
        if ch == "\n":
            out.append(("op", "\n"))
            i += 1
            continue
        if ch == "/" and prev in AWK_REGEX_BEFORE:
            j = i + 1
            in_br = False
            while j < n and (p[j] != "/" or in_br):
                if p[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if p[j] == "\n":
                    return None
                if p[j] == "[":
                    in_br = True
                elif p[j] == "]":
                    in_br = False
                j += 1
            if j >= n:
                return None
            out.append(("re", p[i + 1:j]))
            i = j + 1
            continue
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", p[i:])
        if m:
            out.append(("id", m.group(0)))
            i += len(m.group(0))
            continue
        m = re.match(r"(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?", p[i:])
        if m:
            out.append(("num", m.group(0)))
            i += len(m.group(0))
            continue
        for op in ("|&", "||", "&&", ">>", ">=", "<=", "==", "!=", "!~", "+=", "-=", "*=", "/=", "%=", "^=", "++", "--", "**"):
            if p.startswith(op, i):
                out.append(("op", op))
                i += len(op)
                break
        else:
            out.append(("op", ch))
            i += 1
    return out


def _tx_awk(args, lw, c, nonfile):
    prog, ops, k, end = None, [], 0, False
    while k < len(args):
        a = args[k]
        k += 1
        if end or a == "-" or not a.startswith("-"):
            ops.append(a)
            continue
        if a == "--":
            end = True
            continue
        if a[:2] in ("-F", "-v") or a in ("--field-separator", "--assign") or a.startswith(("--field-separator=", "--assign=")):
            v = a.partition("=")[2] if a.startswith("--") else a[2:]
            if not v and not (a.startswith("--") and "=" in a):
                if k >= len(args):
                    lw.tag("unsure")
                    break
                v, k = args[k], k + 1
            if not _lit_ok(v):
                lw.tag("unsure")
            nonfile.add(v)
            nonfile.add(a)
            continue
        if a[:2] == "-f" or a.startswith("--file"):
            c.opaque = True
            c.add("opaque", "awk -f: the program is in a file")
            if a in ("-f", "--file") and k < len(args):
                k += 1
            continue
        lw.tag("unsure")                                  # gawk -e/-i/-l/-o/-p/-d/-E, -safe ... and anything else
    if prog is None:
        if not ops:
            lw.tag("unsure")
            return
        prog, ops = ops[0], ops[1:]
    nonfile.add(prog)
    for f in ops:
        if not _lit_ok(f):
            lw.tag("unsure")
    if not _lit_ok(prog):
        lw.tag("unsure")
        return
    toks = _awk_tokens(prog)
    if toks is None:
        lw.tag("unsure")
        return
    depth, print_at = 0, None
    for x, (kind, t) in enumerate(toks):
        nxt = toks[x + 1] if x + 1 < len(toks) else (None, None)
        if kind == "op" and t in "([":
            depth += 1
        elif kind == "op" and t in ")]":
            depth -= 1
        elif kind == "op" and t in (";", "\n", "{", "}"):
            print_at = None
        if kind == "id" and t in ("print", "printf"):
            print_at = depth
        elif kind == "id" and t in ("system", "extension"):
            lw.tag("exec")
        elif kind == "id" and t == "ENVIRON":
            c.add("secrets", "awk ENVIRON")              # the environment, printed: like `printenv`
        elif kind == "id" and t in ("close", "fflush") and nxt == ("op", "("):
            lw.tag("unsure")
        elif kind == "id" and t == "getline":
            y = x + 1
            if y < len(toks) and toks[y][0] == "id" or (y < len(toks) and toks[y] == ("op", "$")):
                y += 2 if toks[y] == ("op", "$") else 1
            if y < len(toks) and toks[y] == ("op", "<"):
                lw.tag("read")
                f = toks[y + 1] if y + 1 < len(toks) else (None, None)
                if f[0] == "str" and "\\" not in f[1]:
                    _tx_read(lw, c, f[1])
                elif f != ("str", "-"):
                    lw.tag("unsure")
        elif kind == "op" and t in ("|", "|&"):
            lw.tag("exec")                                # print | "cmd", "cmd" | getline, |& (gawk coprocess, /inet)
        elif kind == "op" and t == "@":
            lw.tag("exec")                                # gawk @load (a shared library), @include, indirect calls @f()
        elif kind == "op" and t in (">", ">>") and print_at is not None and depth == print_at:
            f = nxt
            if f[0] == "str" and "\\" not in f[1]:
                _tx_write(lw, c, f[1])
            else:
                lw.tag("write")
                lw.tag("unsure")
    if depth != 0 or sum(t == ("op", "{") for t in toks) != sum(t == ("op", "}") for t in toks):
        lw.tag("unsure")


JQ_FLAGS = set("nrjasSCMceRhVb")
JQ_LONG_F = {"--tab", "--seq", "--stream", "--stream-errors", "--ascii-output", "--raw-output", "--raw-output0", "--join-output",
             "--null-input", "--raw-input", "--slurp", "--compact-output", "--color-output", "--monochrome-output", "--sort-keys",
             "--exit-status", "--unbuffered", "--help", "--version", "--build-configuration", "--debug-dump-disasm", "--debug-trace", "--binary"}


def _jq_code(p):
    """0.2.54: the code of a jq program (string literals cut out, the code of their \\( ) interpolations kept, comments dropped); None when
    a string never ends."""
    out, i, n, stack = [], 0, len(p), []          # stack: paren depth at which each open interpolation returns to its string
    in_str, depth = False, 0
    while i < n:
        ch = p[i]
        if in_str:
            if ch == "\\" and p.startswith("\\(", i):
                stack.append(depth)
                depth += 1
                in_str = False
                out.append(" (")
                i += 2
                continue
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_str = False
                out.append(' "" ')
            i += 1
            continue
        if ch == '"':
            in_str = True
        elif ch == "#":
            while i < n and p[i] != "\n":
                i += 1
            continue
        elif ch == "(":
            depth += 1
            out.append(ch)
        elif ch == ")":
            depth -= 1
            out.append(ch)
            if stack and depth == stack[-1]:
                stack.pop()
                in_str = True
        else:
            out.append(ch)
        i += 1
    return None if in_str or stack else "".join(out)


def _tx_jq(args, lw, c, nonfile):
    prog, ops, k, end, from_file, strings = None, [], 0, False, False, False
    while k < len(args):
        a = args[k]
        k += 1
        if end or a == "-" or not a.startswith("-"):
            ops.append(a)
            continue
        if a == "--":
            end = True
            continue
        if a in JQ_LONG_F:
            continue
        if a in ("--args", "--jsonargs"):
            strings = True                                 # the positional words after the program are values, not files
            continue
        if a == "--indent":
            k += 1
            continue
        if a in ("--arg", "--argjson"):
            nonfile.update(args[k:k + 2])
            for v in args[k:k + 2]:
                if not _lit_ok(v):
                    lw.tag("unsure")
            k += 2
            continue
        if a in ("--slurpfile", "--rawfile"):
            if k + 2 > len(args):
                lw.tag("unsure")
                break
            nonfile.add(args[k])
            _tx_read(lw, c, args[k + 1])
            k += 2
            continue
        if a in ("-f", "--from-file") or a == "-L" or (a.startswith("-L") and len(a) > 2):
            v = a[2:] if a.startswith("-L") and len(a) > 2 else (args[k] if k < len(args) else None)
            if v is None:
                lw.tag("unsure")
                break
            if not (a.startswith("-L") and len(a) > 2):
                k += 1
            _tx_read(lw, c, v)
            if a in ("-f", "--from-file"):
                from_file = True
                lw.tag("unsure")                          # the program is in a file the owner does not see: it may print env / $ENV
            else:
                lw.tag("read")                            # modules and data files from that directory (import / include)
            continue
        if not a.startswith("--") and set(a[1:]) <= JQ_FLAGS:
            continue
        lw.tag("unsure")
    if not from_file:
        if not ops:
            return
        prog, ops = ops[0], ops[1:]
        nonfile.add(prog)
    if strings:
        nonfile.update(ops)
    for f in ops:
        if not _lit_ok(f):
            lw.tag("unsure")
    if prog is None:
        return
    if not _lit_ok(prog):
        lw.tag("unsure")
        return
    code = _jq_code(prog)
    if code is None:
        lw.tag("unsure")
        return
    if re.search(r"\$ENV\b|\$__prog_args\b", code) or re.search(r"(?<![.$@\w])env\b(?!\s*:)", code):
        c.add("secrets", "jq env")                         # the environment, printed: like `printenv`
    if re.search(r"(?<![.$@\w])(import|include)\b", code):
        lw.tag("read")


def _flags(args):
    """Short flags joined ("-rf" -> {"r","f"}) and long flags ("--force"). Stops at "--"."""
    short, long_ = set(), set()
    for a in args:
        if a == "--":
            break
        if a.startswith("--"):
            long_.add(a.split("=", 1)[0])
        elif a.startswith("-") and len(a) > 1:
            short |= set(a[1:])
    return short, long_


def _operands(args):
    out, end = [], False
    for a in args:
        if end or not a.startswith("-") or a == "-":
            out.append(a)
        elif a == "--":
            end = True
    return out


def _npx_local(pkg: str, here: str) -> bool:
    """0.2.10: `npx jest` runs the project's own node_modules/.bin/jest when there is one (searched upwards, as npx does), else it downloads."""
    d = here
    while True:
        if _fs.current().exists(os.path.join(d, "node_modules", ".bin", pkg)):
            return True
        up = os.path.dirname(d)
        if up == d:
            return False
        d = up


def _in_project(p: str, project: str) -> bool:
    return p == project or p.startswith(project.rstrip("/") + "/")


PATHLIKE = re.compile(r"(/|~|\.\.?(/|$))")


def _outside(args, here, home, project) -> bool:
    """0.2.10: does this simple command run outside the project, or name a path outside it (`pytest /tmp/t.py`, `make -C ..`,
    `--rootdir=/x`)? A path from an expansion cannot be judged: outside. Used only to refuse a project allowance, never to allow."""
    if not _in_project(here, project):
        return True
    for a in args:
        v = a.split("=", 1)[1] if a.startswith("-") and "=" in a else a
        if not v or not (PATHLIKE.match(v) or "/" in v):
            continue
        e = _expand(v, here, home)
        if e is None or not _in_project(_abspath(e, here, home), project):
            return True
    return False


def classify(cmd: str, cwd: str, home: str | None = None, _depth: int = 0, project: str | None = None, _budget=None) -> Command:
    """0.2.90: one frame of line variables / aliases per command line (see _FRAMES); the rest is _classify."""
    # r0299: a nested command line (`bash -c`, `$(..)`, a runner's child) keeps "$HOME is not known" of the line that runs it
    _FRAMES.append({"vars": {}, "aliases": {}, "links": {}, "home_lost": bool(_FRAMES and _FRAMES[-1].get("home_lost"))})
    try:
        return _classify(cmd, cwd, home, _depth, project, _budget)
    finally:
        _FRAMES.pop()


def _classify(cmd: str, cwd: str, home: str | None = None, _depth: int = 0, project: str | None = None, _budget=None) -> Command:
    """project (0.2.10): the realpath of the project root; given, `outside` lists the heads that ran outside it (see _outside).
    _budget (0.2.11): command lines left to classify for the whole line ([n], shared by every nested call, MAX_NESTED)."""
    home = home or _fs.current().home()
    c = Command()
    c.budget = _budget if _budget is not None else [MAX_NESTED]
    c.budget[0] -= 1
    if c.budget[0] < 0:
        c.opaque = True
        c.add("opaque", "more than %d nested command lines" % MAX_NESTED)
        return c
    if not isinstance(cmd, str):
        c.opaque = True
        c.add("opaque", "not a string")
        return c
    if len(cmd) > MAX_CMD:
        c.opaque = True
        c.add("opaque", "command of %d characters" % len(cmd))
        return c
    _raw_scan(cmd, c)
    _dev_net(cmd, c)                                       # rt2810: /dev/tcp/HOST/PORT, gawk /inet/... anywhere in the raw text
    if _depth > MAX_DEPTH:
        c.opaque = True
        c.add("opaque", "nesting deeper than %d" % MAX_DEPTH)
        return c
    line, docs, balanced, unsure = _normalize(cmd)
    if unsure:
        c.opaque = True                                    # 0.2.12 (R7-01): we might not cut the line where bash does
        c.add("opaque", unsure)
        at = getattr(unsure, "at", None)
        if isinstance(at, int) and 0 < at < len(cmd):
            # 04.11 (Hypothesis I3, monotone): bash runs what comes before the heredoc it reads differently from us (`echo hi >> ~/.zshrc ;
            # cat <<EOF` with no end line): that prefix is judged as usual, so opacity adds a question and never hides a refusal
            _merge(c, classify(cmd[:at], cwd, home, _depth, project, _budget=c.budget))
        return c
    if re.search(r"(?<!\$)\{[^{}\s]*(,|\.\.)[^{}\s]*\}", re.sub(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"", "", line)):
        c.opaque = True                                    # `{rm,-rf,/x}`, `> .git/hook{s..s}/x`: the shell builds the words after we parsed them
        c.add("opaque", "brace expansion")
    if REASSIGN.search(line):
        c.opaque = True                                    # 0.2.11: `HOME=/etc; echo x > ~/f`: the hook's $HOME / ~ / cwd no longer hold
        c.add("opaque", "HOME / PWD / CDPATH changed in the line")
    raw_rm = RAW_RM.search(line)                           # heredoc DATA is not code; code heredocs are classified below
    for head, body, quoted in docs:
        hr = heredoc_reader(head.strip())              # 29.10: == HEREDOC_READER.search(...).group(4), linear
        if hr and hr in SHELLS | {"ssh", "eval", "source", "."}:   # `bash <<EOF`, `ssh host <<EOF`: the body is a shell line
            _merge(c, classify(body, cwd, home, _depth + 1, project, _budget=c.budget))
        elif hr:                                           # `python - <<EOF`: interpreter code (0.2.90: it was parsed as a shell line
            _code_scan(body, c, hr)                        # before -> "unparsable" on nearly every python heredoc of the owner); its file
                                                           # consequences are scanned in the loop below, with the command's operands
        elif not quoted and _substitute(body, c, cwd, home, _depth, project, data=True) is None:
            c.opaque = True                                # 0.2.11: `cat <<EOF` (delimiter not quoted) runs the $(...) / `...` of its body
            c.add("opaque", "heredoc body with an unreadable substitution")
    # 0.2.11: command, process and arithmetic substitutions at any depth are classified as command lines of their own and replaced by one word
    sub = _substitute(line, c, cwd, home, _depth, project)
    if sub is None:
        c.opaque = True
        c.add("opaque", "unparsable substitution or parenthesis")
        return c
    line = sub
    try:
        if not balanced:
            raise ValueError("No closing quotation")
        toks = _tokens(line)
    except ValueError as e:                     # unbalanced quotes: cannot know where words end
        c.opaque = True
        c.add("opaque", "unparsable (%s)" % e)
        return c
    here = cwd
    if _defines_function(toks):
        c.opaque = True                                    # 0.2.12 (R7-02): any later word may run the function: its effect is unknown
        c.add("opaque", "function defined in the line")
        here = LOST_CWD
        _lose_home()                                       # r0299: a function may set HOME when it runs: ~ / $HOME unknown too
    # 0.2.12: where each simple command runs. A `cd` changes the directory for sure only when it runs in this shell (not in a pipeline, in the
    # background or in a `( )` subshell, which ends at its `)`), unconditionally (not after && / || / then / do ...) and into a directory that
    # exists (bash stays where it was when `cd` fails). Otherwise the commands after it in the same && chain run there, and the commands after
    # the chain run in one of two directories: unless both are the same, the directory is unknown (LOST_CWD) -- never "the project" by guess.
    depth_here, last_depth, fallback = {0: here}, 0, None
    prev_simple = None                                     # s7 (O1): the simple command before a `|` (what feeds xargs / an interpreter)
    written, prev_out, hd_i = {}, None, 0                  # 0.2.43b: text written to a path earlier in this line (None: not shown)
    hd_ok = sum(1 for t in toks if t == "<<") == len(docs)  # each `<<` of the line owns the next heredoc body (else: bodies unknown)
    for argv, before, after, depth in _split_ctx(toks):
        pipe_prev, prev_simple = (prev_simple if before in ("|", "|&") else None), None
        fed, prev_out = (prev_out if before in ("|", "|&") else None), None
        writes_before = list(c.writes)
        hd_body = herestr = None
        appended = set()
        for k, t in enumerate(argv):
            if t == "<<":
                d = docs[hd_i] if hd_ok and hd_i < len(docs) else None
                hd_body = d[1] if d is not None and (d[2] or not re.search(r"\$\(|`", d[1])) else None
                hd_i += 1
            elif t == "<<<" and k + 1 < len(argv):
                hs = _unmask(argv[k + 1])
                herestr = hs[1:-1] if len(hs) > 1 and hs[0] == hs[-1] and hs[0] in "'\"" else (None if re.search(r"[$`]", hs) else hs)
            elif t in (">>", ">>|", "&>>") and k + 1 < len(argv):
                e = _expand(_unmask(argv[k + 1]), here, home)
                if e is not None:
                    appended.add(_abspath(e, here, home))
        if depth != last_depth or (fallback is not None and before != "&&"):
            if fallback is not None and fallback != here:
                here = LOST_CWD
            fallback = None
            depth_here[last_depth] = here
            if depth > last_depth:
                for d in range(last_depth + 1, depth + 1):
                    depth_here[d] = depth_here[d - 1]
            here, last_depth = depth_here[depth], depth
        if len(argv) == 1 and os.path.basename(argv[0]) == "env":
            c.add("secrets", "whole environment")
        if "<<<" in argv:                                      # here-string into a shell / interpreter is code
            k = argv.index("<<<")
            pre, _ = _strip_prefix(argv[:k])
            if pre and (os.path.basename(pre[0]) in SHELLS | INTERPRETERS | {"eval", "source", "."}) and k + 1 < len(argv):
                _merge(c, classify(_unmask(argv[k + 1]), cwd, home, _depth + 1, project, _budget=c.budget))
                if _is_interp(os.path.basename(pre[0])):
                    _code_scan(_unmask(argv[k + 1]), c, os.path.basename(pre[0]))     # s7 (O1): `python3 <<< "urlopen(...)"`
        argv = [_subst_vars(t) for t in argv]                 # 0.2.90: `$D` of a variable this line set once (outside single quotes)
        fr = _frame()
        if fr is not None and argv and argv[0] in fr["aliases"]:
            argv = list(fr["aliases"][argv[0]]) + argv[1:]    # 0.2.90: `alias x='rm -rf'; x /y` is judged as `rm -rf /y`
        if fr is not None:
            lead = [t for t in argv if t not in ("<<",)]
            k0 = 0
            while k0 < len(lead) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\+?=.*", lead[k0], re.S):
                k0 += 1
            rest0 = lead[k0:]
            bare = k0 > 0 and (not rest0 or rest0[0] in SEPARATORS)
            for t in lead[:k0]:                               # a bare `D=/x` (no command after it) sets D for the rest of the line
                nm = _record_assignment(t, home) if bare else re.match(r"[A-Za-z_][A-Za-z0-9_]*", t).group(0)
                if nm is not None and nm.upper().startswith("CLAUDE_"):
                    _claude_env(c, nm, t, home, "%s=" % nm)   # 0.2.90 (G4, spec v0.1 per-9): CLAUDE_CODE_DISABLE_HOOKS=1, CLAUDE_CONFIG_DIR=...
            if rest0 and os.path.basename(rest0[0]) in ("export", "declare", "typeset", "local", "readonly") and not bare:
                for t in rest0[1:]:
                    if t.startswith("-"):
                        continue
                    nm = _record_assignment(t, home) or (re.match(r"[A-Za-z_][A-Za-z0-9_]*$", t) and t)
                    if nm and nm.upper().startswith("CLAUDE_"):
                        _claude_env(c, nm, t, home, "export %s" % nm)
            elif rest0 and os.path.basename(rest0[0]) == "for" and len(rest0) >= 4 and rest0[2] == "in" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", rest0[1]) \
                    and all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", t) and not is_secret_path(t) for t in rest0[3:]):
                _set_var(rest0[1], rest0[3])                  # `for d in a b c`: plain names under the directory (no /, ~, dot-files): the
                                                              # first one stands for all (same directory, same kind of path)
            elif rest0 and os.path.basename(rest0[0]) in ("unset", "read", "mapfile", "readarray", "getopts", "for", "select", "let", "printf") and not bare:
                for t in rest0[1:]:
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", t):
                        _set_var(t, None)                     # read / unset / a loop variable: its value is not in the line
            if rest0 and os.path.basename(rest0[0]) == "env":
                for t in rest0[1:]:
                    if re.match(r"CLAUDE_\w*=", t, re.I):
                        _claude_env(c, t.split("=", 1)[0], t, home, "env %s" % t.split("=", 1)[0])
        devnet = [a for a in argv if _dev_net(_unmask(a), c)]     # rt2810: after quote removal (`"/dev/t"cp/h/80`)
        argv, redirect_writes = _redirects(argv, here, home, c)
        for p in redirect_writes:
            c.write(p)
        full = argv
        _env_inject(full, c)                               # rt2810: PYTHONSTARTUP / NODE_OPTIONS=--require / PERL5OPT=-M ... (also `export`)
        _env_more(full, here, home, project, c)            # 10.11 (r0260): pagers, git config, search paths outside the project, proxies ...
        argv, winfo = _unwrap(argv)
        via_xargs = winfo["xargs"]
        for why in winfo["issues"]:                        # 0.2.52: a wrapper read with doubt, or one that moves the command elsewhere
            c.opaque = True
            c.add("opaque", why)
        for t in winfo["outs"]:                            # 0.2.52: `time -o F`, flock's lock file: files the wrapper itself writes
            ws = []
            _write_target(t, here, home, c, ws)
            for p in ws:
                c.write(p)
        if not argv:
            if devnet:
                c.head("exec [net]")                       # rt2810: `exec 3<>/dev/tcp/h/80`, a bare `<>/dev/tcp/h/80`: a socket opened
            if winfo["env"] and not winfo["issues"]:
                c.add("secrets", "whole environment")      # `env -u X` / `env -0` with no command prints the environment
            continue
        name = os.path.basename(argv[0])
        args = argv[1:]
        prev_simple = (name, args)
        if argv[0] == "":
            c.opaque = True                                # 0.2.54: `"" ls` (bash: command not found); kept rather than read as `ls`
            c.add("opaque", "empty command name")
            continue
        if len(argv) == 1 and argv[0] in ("fi", "done", "esac"):
            continue                                       # 0.2.12: the end of a compound command runs nothing (its redirections are judged above)
        _written_runs(name, argv[0], args, here, home, project, written, writes_before, c, _depth)     # 0.2.43b: write, then run
        out_t = _out_text(name, args, hd_body, herestr, fed)
        if hd_body is not None and _is_interp(name) and ("-" in args or not [a for a in args if not a.startswith("-")]):
            _code_fs_scan(hd_body, c, name, here, home, project, _depth, operands=[_unmask(a) for a in args if a != "-" and not a.startswith("-") and _lit_ok(_unmask(a))])
        if name in ("base64", "base32") and isinstance(fed, str) and any(a in ("-d", "-D", "--decode") or re.fullmatch(r"-[a-zA-Z]*[dD][a-zA-Z]*", a) for a in args) \
                and not [a for a in args if not a.startswith("-")]:
            out_t = _decoded(name, fed)                    # 0.2.90: `echo <base64> | base64 -d | sh`: the decoded text is what runs
        if isinstance(fed, str) and before in ("|", "|&") and name in SHELLS and not [a for a in args if not a.startswith("-")] \
                and not any(a.startswith("-c") for a in args) and fed.strip():
            _merge(c, classify(fed, here, home, _depth + 1, project, _budget=c.budget))     # 0.2.90: the shell runs the text the line shows
            c.danger[:] = [d for d in c.danger if d != "pipe-to-shell:decoded data | sh"]   # ... judged as a line of its own, not "decoded data"
        elif isinstance(fed, str) and before in ("|", "|&") and _is_interp(name) and not [a for a in args if not a.startswith("-") and a != "-"] and fed.strip():
            _code_fs_scan(fed, c, name, here, home, project, _depth)        # 0.2.90: `echo <b64> | base64 -d | python3`
        prev_out = out_t
        targets = list(redirect_writes)
        if name == "tee":
            for a in args:
                e = _expand(a, here, home) if not a.startswith("-") else None
                if e is not None:
                    targets.append(_abspath(e, here, home))
                    if "-a" in args or "--append" in args:
                        appended.add(_abspath(e, here, home))
        for p in targets:
            if out_t is None or (p in appended and p not in written) or (p in written and written[p] is None):
                written[p] = None
            else:
                written[p] = (written[p] + "\n" + out_t) if p in written and p in appended else out_t
        lw_plain, nonfile = False, set()
        if not re.search(r"[$`]", argv[0]):
            prefix = full[:len(full) - len(argv)]
            elevated = any(os.path.basename(x) in ("sudo", "doas") for x in prefix)
            ident = command_id(argv[0] if "/" in argv[0] else name, args)       # `./ls` / `/tmp/x/cat` is not the `ls` / `cat` of the list
            if "/" not in argv[0]:
                ident = _ro_ident(name, ident, args)        # 0.2.89: "git stash list", "git tag list"
            tags = _variants(name, args, prefix) + [t for t in winfo["tags"]]
            if devnet:
                tags.append("net")                         # rt2810: `cat /dev/tcp/h/80`, `cat < /dev/tcp/h/80`
            if "/" not in argv[0] and (name in LW_CMDS or (name == "git" and ident in LW_LIST)):
                n0_ = len(c.writes)
                lw_tags = _local_write(name, args, here, home, project, c)          # 0.2.53: every path checked
                if name in DELETERS:
                    for p_ in c.writes[n0_:]:
                        if p_ not in c.deletes:
                            c.deletes.append(p_)                                    # 0.2.90: rm / rmdir write no code (execguard D8)
                lw_plain = name in LW_CMDS and not lw_tags
                tags += [t for t in lw_tags if t not in tags]
            if name in TX_NAMES:
                tx_tags, nonfile = _tx(name, args, here, home, project, c, _depth)     # 0.2.54: find, sed, awk, jq
                tags += [t for t in tx_tags if t not in tags]
            if name == "npx" and ident != "npx" and not _npx_local(ident.split(" ", 1)[1], here):
                tags.append("fetch")                          # 0.2.10: not installed in the project: npx would download it from the registry
            hid = ("sudo " if elevated else "") + ident + (" [%s]" % ", ".join(tags) if tags else "")
            if argv[0].startswith("--") or re.search(r"\s", argv[0]):
                c.opaque = True                            # 0.2.89: a program named `--version` would be the version entry below
                c.add("opaque", "command name starting with '--' or with blanks")
            if not elevated and "/" not in argv[0] and args == ["--version"] and name in VERSION_QUERIES and not prefix:
                hid = VERSION_HEAD                         # 0.2.89: `python3 --version` prints a version and exits before it reads anything
            c.head(hid)   # `sudo ls` is not `ls` for the owner's list
            if project is not None and _outside([a for a in args if a not in nonfile], here, home, project):
                c.out(hid)
            # RT6 (28.10): the command a program carries (`arch -arm64 python3 f.py`, `hyperfine 'python3 f.py'`, `fd -x python3`,
            # `git submodule foreach 'cmd'`, `tmux new -d 'cmd'`) is judged as a command of its own: its head joins the line's heads, so the
            # owner's permission for the carrier never covers the child (23 of 24 carriers hid an interpreter from the mandate).
            for ch in dict.fromkeys(_runners.children(name, args)):
                _merge(c, classify(ch, here, home, _depth + 1, project, _budget=c.budget))
        if name == "alias" and _set_alias(args):
            continue                                       # 0.2.90: `alias ll='ls -la'`: known for the rest of the line
        new_link = None
        if name == "ln" and fr is not None and any(a.startswith("-") and "s" in a[1:] for a in args):
            ops_ = [a for a in args if not a.startswith("-")]
            if len(ops_) == 2 and all(_lit_ok(o) for o in ops_):      # 0.2.90 (Н4): remember `ln -s TARGET LINK` for the paths after it
                e_t, e_l = _expand(ops_[0], here, home), _expand(ops_[1], here, home)
                if e_t is not None and e_l is not None:
                    tgt = e_t if os.path.isabs(e_t) or e_t.startswith("~") else os.path.join(os.path.dirname(_abspath(e_l, here, home)), e_t)
                    # r0300: kept aside until `ln` itself is judged: `ln -s /tmp/evil ~/.bashrc` writes ~/.bashrc (the link), not
                    # /tmp/evil (before r0300 the link was followed by its own command: "write /tmp/evil", no persist, a question)
                    new_link = (os.path.normpath(_abspath(e_l, here, home)), os.path.normpath(_abspath(tgt, here, home)))
        if name in EVALISH or (name in ("mapfile", "readarray") and any(a.startswith("-") and "C" in a for a in args)):
            c.opaque = True                                # 0.2.12 (R7-02): what the rest of the line means (its directory, its commands)
            c.add("opaque", "%s: the rest of the line cannot be judged" % name)     # is not known after eval / source / alias / trap ...
            here = LOST_CWD
            _lose_home()                                   # r0299: eval / source may set HOME: ~ / $HOME unknown too (not after a lost `cd`)
        if name in ("cd", "pushd", "popd") and here == LOST_CWD:
            continue                                       # `cd` itself may be a function or alias by now: the directory stays unknown
        if name in ("cd", "pushd", "popd"):
            ops = _operands(args)
            new = None
            if name == "popd" or ops[:1] == ["-"] or any(re.fullmatch(r"[+-]\d+", o) for o in ops):
                c.opaque = True                                # 0.2.11: the directory stack / OLDPWD: the hook does not know where that is
                c.add("opaque", name + " " + " ".join(ops))
            elif ops and _expand(ops[0], here, home) is not None and not re.search(r"[*?[]", ops[0]):
                new = _abspath(_expand(ops[0], here, home), here, home)
            elif ops:
                c.opaque = True
                c.add("opaque", "cd " + ops[0])
            elif name == "cd":
                new = home
            else:
                c.opaque = True
                c.add("opaque", "pushd")
            if new is not None and new != here:
                kw = any(x in KEYWORDS for x in full[:len(full) - len(argv)])
                if before in ("|", "|&") or after in ("|", "|&", "&"):
                    here = LOST_CWD                            # zsh runs the last part of a pipeline in this shell, bash does not
                elif _fs.current().isdir(new) and before not in ("&&", "||") and not kw and not any(new == w or _in_project(new, w) for w in c.writes) \
                        and not any(d.startswith("rm-rf") for d in c.danger):
                    here = new                                 # runs, and succeeds: it exists, and nothing before wrote, moved or deleted it
                else:
                    fallback = here if fallback is None else fallback
                    here = new                                 # true for the rest of this && chain only
            continue
        if re.search(r"[$`]", argv[0]):
            c.opaque = True
            c.add("opaque", "command name from expansion: " + argv[0])
            continue
        _piped_net(name, args, via_xargs, pipe_prev, c)
        if not via_xargs and _grep_data(name, args, line):
            c.rm_data += len(RAW_RM.findall(" ".join(_unmask(a) for a in args)))
        _one(name, args, here, home, c, via_xargs, _depth, project, lw_plain=lw_plain, nonfile=nonfile)
        if new_link is not None:
            fr["links"][new_link[0]] = new_link[1]           # the paths AFTER `ln -s` follow the new link (0.2.90, QA G)
    if raw_rm and c.rm_plain and len(RAW_RM.findall(line)) == len(RM_R_WORD.findall(line)) <= c.rm_plain:
        raw_rm = None                             # 0.2.89: every `rm -r..` of the line is a plain delete inside the project, judged above
    if raw_rm and not any(d.startswith("rm-rf") for d in c.danger) and c.rm_judged + c.rm_data < len(RAW_RM.findall(line)):
        # inside a quoted string / interpreter one-liner / heredoc data (0.2.90: unless the code scan resolved every deletion call of the
        # line to a path, judged by that path). 10.11 (r0260): when every unexplained `rm -r..` word of the line stands in the code given
        # to an interpreter on it (each code text counted once), the mark is the code's (sandbox.code_line_ok: held by the strict sandbox)
        unexplained = len(RAW_RM.findall(line)) - c.rm_judged - c.rm_data
        ts_ = [t for t in c.code_texts if isinstance(t, str)]
        ts_ = [t for k_, t in enumerate(ts_) if not any(t in u for j_, u in enumerate(ts_) if j_ != k_ and (u != t or j_ < k_))]
        in_code = sum(len(RAW_RM.findall(t)) for t in ts_)      # one code text seen by two scans (`-c CODE` and CODE) counts once
        if 0 < unexplained <= in_code:
            _CODE[0] += 1
            try:
                c.add("rm-rf", raw_rm.group(0))
            finally:
                _CODE[0] -= 1
        else:
            c.add("rm-rf", raw_rm.group(0))
    lost = [w for w in c.writes if _in_project(w, LOST_CWD)]
    if lost:                                      # 0.2.12 (R7-02): a relative write after the directory became unknown is not "in the project"
        c.writes = [w for w in c.writes if w not in lost]
        c.opaque = True
        c.add("opaque", "write to a relative path in an unknown directory")
    return c


# 10.11 (r0260): programs whose arguments are search patterns and paths, never code: `grep -rn 'rm -rf' src` searches for the words, it
# runs nothing (the text backstop RAW_RM asked about it: 16 questions in the developer corpus). Not here: rg --pre / --pre-glob (runs a
# command per file), git grep -O / --open-files-in-pager (runs a pager command), any of them via xargs / find -exec (judged as before),
# ack / ag (--pager), sed / awk / perl (scripts that can run commands). What grep PRINTS piped into a shell is judged by that pipe.
GREP_DATA = {"grep", "egrep", "fgrep", "rg"}


def _grep_data(name, args, line="") -> bool:
    a = [_unmask(x) for x in args]
    if name == "git":                                 # -O may come bundled with other short options (-nO): any short bundle with O
        return a[:1] == ["grep"] and not any(x.startswith("--open-files-in-pager") or (x.startswith("-") and not x.startswith("--")
                                                                                         and "O" in x) for x in a[1:])
    if name not in GREP_DATA:
        return False
    return not (name == "rg" and (any(x.startswith("--pre") for x in a) or "RIPGREP_CONFIG_PATH" in line))


def _defines_function(toks) -> bool:
    """0.2.12 (R7-02): `f(){ ...; }`, `f () ...`, `function f`, zsh's anonymous `() { ...; }`."""
    for k, t in enumerate(toks):
        if t == "(" and toks[k + 1:k + 2] == [")"] and (k == 0 or toks[k - 1] not in SEPARATORS or toks[k + 2:k + 3] == ["{"]):
            return True
        if t == "function" and (k == 0 or toks[k - 1] in SEPARATORS):
            return True
    return False


PY_MODULE = _runners.PY_RE                                # RT6: python2, pypy3 ... (execguard._PY_RE is the same object)
MODULE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")


def command_id(name: str, args) -> str:
    """PROPOSAL-06: the identifier the owner's `command.allow` list is matched against (byte-exact or a trailing-* prefix).
    0.2.10: `python -m pytest` is "python -m pytest" (it runs that module, not code given on the line), not "python"."""
    if PY_MODULE.fullmatch(name) and args[:1] == ["-m"] and len(args) > 1 and MODULE_RE.fullmatch(args[1]):
        return "%s -m %s" % (name, args[1])
    if name not in SUBCOMMAND_TOOLS:
        return name
    i = 0
    while i < len(args) and args[i].startswith("-"):           # global options: git -C dir, -c k=v, --no-pager; npm --prefix x
        i += 1 + (args[i] in ("-C", "-c", "--git-dir", "--work-tree", "--prefix", "--manifest-path", "-f", "--file", "-n", "--namespace", "--context"))
    if i < len(args) and SUBCOMMAND_RE.fullmatch(args[i]):
        return name + " " + args[i]
    return name


def _eval_form(name: str, args) -> bool:
    """0.2.11: code given on the command line of an interpreter (EVAL_OPTS), before its script operand."""
    opts = EVAL_OPTS.get("python" if PY_MODULE.fullmatch(name) else name)
    if not opts:
        return False
    if name == "deno":
        return args[:1] == ["eval"]
    for a in args:
        if not a.startswith("-") or a == "--":
            return False                                     # the script: what follows are its own arguments
        o = a.split("=", 1)[0]
        if o in opts or (not a.startswith("--") and any(len(x) == 2 and x[1] in a[1:] for x in opts)):
            return True
    return False


# 0.2.89 (friction 03.11): `<tool> --version` of these runs nothing of the project: the version is printed while the options are read,
# before any startup code (checked: `python3 --version` runs no sitecustomize / .pth; `node --version` ignores NODE_OPTIONS). Such a simple
# command is "--version" (VERSION_HEAD, one entry of the recommended list for all of them; a program named "-..." is opaque; no executor
# family: nothing for EXEC_CHANGED; the page shows the line itself). Exactly the one argument `--version`, a bare
# name (no path), nothing before it on the line (no env, no wrapper). pip, pytest, npm scripts ... are NOT here: they
# import their environment (pip runs the .pth files of its venv) or read project configuration first.
VERSION_HEAD = "--version"
VERSION_QUERIES = frozenset({"python", "python2", "python3"} | {"python3.%d" % k for k in range(6, 20)} |
                            {"node", "nodejs", "git", "uv", "cargo", "rustc", "make", "gmake", "gcc", "g++", "clang", "clang++", "cc",
                             "deno", "bun", "java", "ruby", "perl", "jq", "rg"})
# 0.2.89: read-only forms of commands added to the recommended list (git remote / tag / stash / config, pip list / freeze / show, uv pip, ps).
# The listed name covers only its read-only form; every other form gets a tag ("git tag [write]", "uv pip [install]", "ps [env]") and is asked.
_GIT_TAG_WRITE = {"-d", "--delete", "-a", "--annotate", "-s", "--sign", "-u", "--local-user", "-f", "--force", "-m", "--message", "-F", "--file",
                  "-e", "--edit", "--cleanup", "--create-reflog", "--trailer"}
_GIT_CONFIG_READ = {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l", "--list", "--get-color", "--get-colorbool", "--show-origin",
                    "--show-scope", "--name-only", "--null", "-z", "--global", "--system", "--local", "--worktree", "--includes", "--no-includes",
                    "--type", "--bool", "--int", "--path", "--bool-or-int", "--expiry-date", "--default"}


_GIT_CONFIG_RUN_KEY = re.compile(r"(core|diff|filter|merge|sequence|credential|gpg|include|includeif|http|url|ssh|alias|uploadpack|"
                                 r"receivepack|protocol|submodule|pager|interactive|instaweb|sendemail|difftool|mergetool|gc|fsmonitor)\.", re.I)


def _ro_ident(name, ident, args) -> str:
    """0.2.89: `git stash list` / `git stash show` -> "git stash list" / "git stash show", a listing `git tag` / `git tag -l v*` -> "git tag list",
    a read of git's configuration -> "git config get"
    (entries of the recommended list). Every other form keeps "git stash" / "git tag" exactly as before (an owner's project allowance for
    "git stash" still covers `git stash pop`)."""
    if name != "git" or ident not in ("git stash", "git tag", "git config"):
        return ident
    sub = ident.split(" ", 1)[1]
    k = next((i for i, a in enumerate(args) if a == sub), None)
    rest = args[k + 1:] if k is not None else []
    ops = [a for a in rest if not a.startswith("-")]
    fl = {a.split("=", 1)[0] for a in rest if a.startswith("-")}
    if sub == "config":
        # `git config user.name`, `git config --get k`, `git config --list`, `git config get k` -> "git config get". Not: a value, -f / --blob
        # (another file read as configuration), --get-regexp, a key git runs (core.*, diff.*, alias.*, filter.* ...: the client's harness rule)
        if fl & {"-f", "--file", "--blob", "--get-regexp"} or not fl <= _GIT_CONFIG_READ or any(_GIT_CONFIG_RUN_KEY.match(o) for o in ops):
            return ident
        if ops[:1] in (["get"], ["list"]):
            return "git config get" if len(ops) <= 2 else ident
        if fl & {"-l", "--list"}:
            return "git config get" if not ops else ident
        return "git config get" if len(ops) == 1 or (len(ops) == 2 and "--get-urlmatch" in fl) else ident
    if sub == "stash":
        return "git stash " + ops[0] if ops[:1] in (["list"], ["show"]) else ident
    if fl & _GIT_TAG_WRITE:
        return ident
    listing = bool(fl & {"-l", "--list"}) or any(f.startswith("-n") for f in fl)
    return "git tag list" if (not ops or listing) else ident


def _ro_tags(name, ident, args) -> list:
    """0.2.89: [] for the read-only form of an entry added in 0.2.89, else the tag that makes it another identifier (asked)."""
    if name == "git":
        sub = ident.split(" ", 1)[1] if " " in ident else ""
        k = next((i for i, a in enumerate(args) if a == sub), None)
        rest = args[k + 1:] if k is not None else []
        ops = [a for a in rest if not a.startswith("-")]
        fl = {a.split("=", 1)[0] for a in rest if a.startswith("-")}
        if sub == "remote":
            if ops[:1] == ["get-url"] and len(ops) <= 2 and fl <= {"--push", "--all"}:
                return []
            return [] if not ops and fl <= {"-v", "--verbose"} else ["write" if ops[:1] != ["show"] else "net"]
        if sub in ("tag", "stash"):
            return []                                  # their read-only forms get their own identifier instead (_ro_ident)
        return []                                      # git tag / stash / config: their read-only forms get their own identifier (_ro_ident)
    if name in ("pip", "pip3") and ident.split(" ", 1)[-1] in ("list", "freeze", "show"):
        lg = {a.split("=", 1)[0] for a in args if a.startswith("--")}
        sh = {a for a in args if a.startswith("-") and not a.startswith("--")}
        return ["net"] if (lg & {"--outdated", "--uptodate", "--index-url", "--extra-index-url", "--find-links", "--proxy"} or sh & {"-o", "-u", "-i", "-f"}) else []
    if name == "uv" and ident == "uv pip":
        k = next((i for i, a in enumerate(args) if a == "pip"), None)
        rest = args[k + 1:] if k is not None else []
        sub = next((a for a in rest if not a.startswith("-")), "")
        if sub in ("list", "freeze", "show", "tree") and not any(a.split("=", 1)[0] in ("--outdated", "--index-url", "--extra-index-url", "--find-links")
                                                                for a in rest):
            return []
        return [sub or "unsure"] if re.fullmatch(r"[a-z-]{1,24}", sub or "x") else ["unsure"]
    if name == "ps":
        for a in args:
            if a.startswith("-") and "E" in a[1:]:
                return ["env"]                         # prints every process' environment (tokens, keys)
            if not a.startswith("-") and re.fullmatch(r"[A-Za-z]+", a) and "e" in a:
                return ["env"]                         # BSD form `ps eww` / `ps auxe`; a word with e in a format list is asked too (safe side)
        return []
    return []


# 0611 (friction, real corpus: `rsync -a --exclude __pycache__ ~/src/ $SCRATCH/snap/`): rsync between two local paths is a copy, like
# `cp -R`: its last operand is judged as a write (_one), every source as a read (FILE_READERS: a credential source is `secrets`). It was
# the danger `exit` for every form. Plain = every operand a literal local path (no `host:`, `host::`, `rsync://`, no variable left) and
# every option on this list; anything else keeps the name "rsync [remote]" / "rsync [option]" (exit, asked as before). Not plain, among
# others: -e / --rsh / --rsync-path (a program), --remove-source-files (deletes the sources), --delete* / -b / --backup-dir / -T /
# --temp-dir / --partial-dir / --log-file / --write-batch / --read-batch (writes or deletes elsewhere), -L / -k / -K (follow links out
# of the tree), --files-from / --exclude-from / --filter (a rule file), --daemon / --config / --password-file / --port.
RSYNC_PLAIN_SHORT = frozenset("arvzhnqlptgoDucPixRWSHEAXOJmC")
RSYNC_PLAIN_LONG = frozenset({"--archive", "--recursive", "--verbose", "--compress", "--human-readable", "--dry-run", "--quiet", "--links",
                              "--perms", "--times", "--group", "--owner", "--devices", "--specials", "--update", "--checksum", "--partial",
                              "--progress", "--itemize-changes", "--one-file-system", "--relative", "--whole-file", "--sparse",
                              "--hard-links", "--executability", "--acls", "--xattrs", "--omit-dir-times", "--omit-link-times",
                              "--prune-empty-dirs", "--cvs-exclude", "--stats", "--no-motd", "--size-only", "--ignore-existing",
                              "--existing", "--mkpath", "--no-owner", "--no-group", "--no-perms", "--no-times"})
RSYNC_PLAIN_VALUE = frozenset({"--exclude", "--include", "--info"})     # `--exclude=X` or `--exclude X`: a pattern / a verbosity, no file


def rsync_plain(args):
    """-> True for a plain local rsync (see RSYNC_PLAIN_SHORT), else the variant tag "remote" or "option"."""
    ops, i, remote = [], 0, False
    while i < len(args):
        a = args[i]
        if a == "--":
            ops += args[i + 1:]
            break
        if a.startswith("--"):
            o = a.split("=", 1)[0]
            if o in RSYNC_PLAIN_VALUE:
                if "=" in a:
                    v = a.split("=", 1)[1]
                else:
                    if i + 1 >= len(args):
                        return "option"
                    v = args[i + 1]
                    i += 1
                if re.search(r"[$`]", v):
                    return "option"
            elif "=" in a or o not in RSYNC_PLAIN_LONG:
                return "option"
        elif a.startswith("-") and len(a) > 1:
            if not set(a[1:]) <= RSYNC_PLAIN_SHORT:
                return "option"
        else:
            ops.append(a)
        i += 1
    if len(ops) < 2:
        return "option"                                     # `rsync host::` / one operand lists a remote module or a directory
    for o in ops:
        if re.match(r"[^/]*:", o) or "::" in o or o.lower().startswith("rsync:"):
            remote = True
        elif re.search(r"[$`]", o) or not o.strip():
            return "option"
    return "remote" if remote else True


def _variants(name: str, args, prefix) -> list:
    """0.2.9: why this simple command is not the plain read-only command its name says -> ["env LD_PRELOAD", "via xargs", "-c", ...].
    A non-empty list makes the identifier "<id> [<tags>]", which no plain entry of the owner's list matches (the owner is asked)."""
    tags = []
    env = sorted({a.split("=", 1)[0] for a in prefix if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", a)
                  and not SAFE_ENV.fullmatch(a.split("=", 1)[0])
                  and not (a.split("=", 1)[0] in SAFE_PAGER and a.split("=", 1)[1] in ("", "cat"))})
    if env:
        tags.append("env " + ",".join(env)[:64])
    for w in sorted({os.path.basename(a) for a in prefix} & COMPOSING_WRAPPERS):
        tags.append("via " + w)
    short, long_ = _flags(args)
    ro = _ro_tags(name, command_id(name, args), args) if name in ("git", "pip", "pip3", "uv", "ps") else []
    tags += [t for t in ro if t not in tags]
    if name == "git":
        i = 0
        while i < len(args) and args[i].startswith("-"):
            o = args[i].split("=", 1)[0]
            if o not in GIT_SAFE_GLOBAL:
                tags.append(o)
            i += 1 + (args[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--exec-path") and "=" not in args[i])
        sub, rest = (args[i], args[i + 1:]) if i < len(args) else ("", [])
        if sub == "grep" and _git_grep_pager(rest):
            tags.append("-O")                                # 0.2.51: `git grep -O<cmd>` / `--open-files-in-pager=<cmd>` (or `--open=`) runs <cmd>
        if sub == "reflog":
            r_ops = _operands(rest)
            if r_ops and r_ops[0] not in ("show", "list", "exists") and re.fullmatch(r"[a-z][a-z-]*", r_ops[0]) and r_ops[0] != "--":
                tags.append("write")                         # 0.2.51: `git reflog write|delete|drop|expire` (and any later sub-command) change refs
        if any(a == "--output" or a.startswith("--output=") or a == "--output-directory" or a.startswith("--output-directory=") for a in rest):
            tags.append("--output")
        for o in sorted({a.split("=", 1)[0] for a in rest} & {"--upload-pack", "--receive-pack", "--exec", "--extcmd", "--tool"}):
            tags.append(o)                                   # 0.2.11: `git fetch --upload-pack=<cmd>` / `rebase --exec` run that command
        if sub == "branch":
            rs, rl = _flags(rest)
            modify = (rs & set("dDmMcCfu") or rl & {"--delete", "--move", "--copy", "--force", "--set-upstream-to", "--unset-upstream",
                                                     "--edit-description", "--track", "--no-track", "--create-reflog", "--recurse-submodules"})
            listing = {a.split("=", 1)[0] for a in rest if a.startswith("-")} & GIT_BRANCH_LIST
            if modify or (_operands(rest) and not listing):
                tags.append("write")
    elif name == "rsync" and rsync_plain(args) is not True:
        tags.append(rsync_plain(args))                       # 0611: "rsync [remote]" / "rsync [option]": not the plain local copy
    elif name == "rg" and any(a.split("=", 1)[0] in ("--pre", "--hostname-bin") for a in args):
        tags.append("--pre" if any(a.split("=", 1)[0] == "--pre" for a in args) else "--hostname-bin")     # ripgrep runs that program
    elif name == "date" and ("s" in short or "--set" in long_):
        tags.append("--set")                                 # sets the system clock
    elif name == "file" and ("C" in short or "--compile" in long_):
        tags.append("--compile")                             # writes a .mgc file
    elif name == "xxd" and len(_xxd_ops(args)) >= 2 and _xxd_ops(args)[1] != "-":
        tags.append("write")                                 # 0.2.95: `xxd IN OUT` writes OUT ("xxd [write]", asked; the write is judged too)
    elif name in ("sort", "tree", "uniq"):
        # 0.2.51: read-only commands of the default list that write a file or run a program in some form: "<id> [write]" /
        # "<id> [--compress-program]" (asked), whatever the path; the write itself is also judged as a write (_one, _out_file_args)
        out, tmpdir, prog = _out_file_args(name, args)
        if prog:
            tags.append("--compress-program")                # sort runs that program (also `--co=`, `--compress-prog`: getopt prefixes)
        if out or tmpdir:
            tags.append("write")
    elif _install_sub(name, args) is not None:
        tags += _install_tags(name, _install_sub(name, args))
    elif _eval_form(name, args):
        tags.append("eval")
    elif PY_MODULE.fullmatch(name) and args[:1] == ["-m"] and len(args) > 1 and args[1] in RUNNER_OPTS:
        tags += _variants(args[1], args[2:], [])                 # 0.2.10: `python -m pytest -p x` is `python -m pytest [-p]`
    elif name in RUNNER_OPTS:
        # 0.2.10: options of test runners / build tools that load code or configuration from elsewhere, or delete a directory they name:
        # with them it is not the plain `pytest` / `make` / `cargo test` an owner allowed for the project ("<id> [<option>]", asked)
        opts = RUNNER_OPTS[name]
        for k, a in enumerate(args):
            if a == "--":
                break
            o = a.split("=", 1)[0]
            if o in opts:
                hit = o
            elif _runner_opt(name, o, opts):
                hit = _runner_opt(name, o, opts)
            elif re.fullmatch(r"-[A-Za-z]+.*", a) and not a.startswith("--"):       # a short cluster `-vp x`, `-pplugin`, `-sfOther.mk`
                hit = next((x for x in sorted(opts) if len(x) == 2 and x[1] in re.match(r"-([A-Za-z]+)", a).group(1)), None)
            else:
                hit = None
            if hit == "-p" and (a[2:] if a.startswith("-p") and len(a) > 2 else (args[k + 1] if k + 1 < len(args) else "")).startswith("no:"):
                hit = None                                   # `-p no:cacheprovider` only switches a plugin off
            if hit and hit not in tags:
                tags.append(hit)
        if name == "make" and any(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*=.*", a) for a in _operands(args)):
            tags.append("vars")                              # `make SHELL=./x CC=./y`: overrides decide what make runs
        if name == "npx":                                    # 0.2.11: `npx jest --config x` is judged by jest's own options too
            k = next((k for k, x in enumerate(args) if not x.startswith("-")), None)
            if k is not None and args[k] in RUNNER_OPTS and args[k] != "npx":
                tags += [t for t in _variants(args[k], args[k + 1:], []) if t not in tags]
    return tags


# 0.2.10: installers. `npm install` / `npm ci` / `pip install -e .` / `pip install -r requirements.txt` install what the PROJECT declares
# (package.json + lockfile, its own requirements); naming a package (`npm install left-pad`, `pip install requests`, `pip install -e git+https://...`)
# or another index (`--registry`, `--index-url`, `--find-links` ...) installs code the project does not declare: "<id> [packages]" / "<id> [--index-url]".
NPM_INSTALL = {"install", "i", "ci", "add", "isntall", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal"}
PIP_VALUE = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target", "--prefix", "--root", "--src", "-b", "--build",
             "--python-version", "--platform", "--implementation", "--abi", "--progress-bar", "--log", "--cache-dir", "--report", "--upgrade-strategy",
             "--config-settings", "-C", "--global-option", "--install-option", "--only-binary", "--no-binary"}
PIP_REMOTE = {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host", "--proxy", "--cert", "--client-cert"}
NPM_REMOTE = {"--registry", "--userconfig", "--globalconfig"}
PATHY = re.compile(r"(\.|\.\.|[.~]?/.*|[^:]*\.(txt|in|cfg|toml))$")


def _install_sub(name, args):
    """-> the arguments after the install sub-command of npm / pnpm / yarn / pip / pip3 / python -m pip, or None."""
    if PY_MODULE.fullmatch(name) and args[:2] == ["-m", "pip"]:
        name, args = "pip", args[2:]
    if name in ("pip", "pip3"):
        ops = [i for i, a in enumerate(args) if not a.startswith("-")]
        return args[ops[0] + 1:] if ops and args[ops[0]] == "install" else None
    if name in ("npm", "pnpm", "yarn"):
        ops = [i for i, a in enumerate(args) if not a.startswith("-")]
        return args[ops[0] + 1:] if ops and args[ops[0]] in NPM_INSTALL else None
    return None


def _install_tags(name, rest):
    tags = []
    pip = name in ("pip", "pip3") or PY_MODULE.fullmatch(name)
    remote = PIP_REMOTE if pip else NPM_REMOTE
    for o in sorted({a.split("=", 1)[0] for a in rest if a.startswith("-")} & remote):
        tags.append(o)
    pkgs, k = False, 0
    while k < len(rest):
        a = rest[k]
        if a == "--":
            pkgs = pkgs or k + 1 < len(rest)
            break
        if pip and a.split("=", 1)[0] in PIP_VALUE:
            v = a.split("=", 1)[1] if "=" in a else (rest[k + 1] if k + 1 < len(rest) else "")
            if a.split("=", 1)[0] in ("-e", "--editable") and not PATHY.fullmatch(v):
                pkgs = True                                  # `-e git+https://...`: not the project's own folder
            k += 1 if "=" in a else 2
            continue
        if not a.startswith("-"):
            pkgs = pkgs or not (pip and PATHY.fullmatch(a))  # `pip install .` is the project itself; a name is a package from the index
        k += 1
    if pkgs:
        tags.append("packages")
    return tags


# 04.11 (Hypothesis I2, "signed != shown"): the approval page shows the text of a shell line only up to 4 KB; a command after a long echo
# was in no field of the page. line_texts() gives every simple command of the line in its RAW text (nested $(..), `..`, ( ), { } stay in
# the command that holds them; a heredoc body follows its command), so the page lists each one whole. A command may be folded on the page
# only when it is a long `echo` of plain words (no $, backquote, redirection, parenthesis, brace, backslash) whose output goes to no pipe.
LINE_FOLD_MIN = 256
_FOLD_ECHO = re.compile(r"echo(?:[ \t][^$`<>(){}\\|;&]*)?", re.S)


def line_texts(cmd):
    """-> [(text, foldable), ...]: every simple command of the shell line `cmd` as written (comments dropped). A line we cannot cut as bash
    does (an unsure heredoc, unbalanced quotes, longer than MAX_CMD) -> [(cmd, False)]: the whole line, never folded."""
    if not isinstance(cmd, str) or not cmd.strip():
        return []
    if len(cmd) > MAX_CMD:
        return [(cmd, False)]
    line, docs, balanced, unsure = _normalize(cmd)
    if unsure or not balanced:
        return [(cmd, False)]
    segs, cur, q, depth, bt, i, n = [], [], None, 0, False, 0, len(line)

    def flush(sep):
        t = "".join(cur).strip()
        if t and t != ";":
            segs.append([t, sep])
        elif segs and sep:
            segs[-1][1] = segs[-1][1] or sep
        cur.clear()
    while i < n:
        ch = line[i]
        if q is not None:
            cur.append(ch)
            if ch == q:
                q = None
            elif q == '"' and ch == "\\" and i + 1 < n:
                cur.append(line[i + 1])
                i += 1
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            cur.append(line[i:i + 2])
            i += 2
            continue
        if ch in "'\"":
            q = ch
        elif ch == "`":
            bt = not bt
        elif ch in "({":
            depth += 1
        elif ch in ")}":
            depth = max(0, depth - 1)
        elif depth == 0 and not bt:
            sep = None
            if line.startswith(("&&", "||", "|&"), i):
                sep = line[i:i + 2]
            elif ch == ";":
                sep = ";"
            elif ch == "|" and (i == 0 or line[i - 1] != ">"):
                sep = "|"
            elif ch == "&" and (i == 0 or line[i - 1] not in "<>") and not line.startswith("&>", i):
                sep = "&"
            if sep:
                flush(sep)
                i += len(sep)
                continue
        cur.append(ch)
        i += 1
    flush(None)
    out, k, mark = [], 0, "<< __HEREDOC__"
    for t, sep in segs:
        hd = mark in t
        while mark in t:
            body = docs[k][1] if k < len(docs) else None
            k += 1
            t = t.replace(mark, "<<" if body is None else "<< (heredoc)\n" + body + "\n(end of heredoc)", 1)
        fold = (not hd and len(t) > LINE_FOLD_MIN and sep not in ("|", "|&") and bool(_FOLD_ECHO.fullmatch(t)))
        out.append((t, fold))
    for d in docs[k:]:
        out.append(("(heredoc)\n" + d[1], False))     # a body the marks did not take (never expected): shown, never folded
    return out


FIND_GLOB_PAT = re.compile(r"[^/\x00]{1,200}")


def _find_root_glob(expr):
    """10.11 (r0260): the expression of `find ROOT <expr>` -> the -name / -iname patterns when <expr> only narrows by name: `-name P`
    joined by `-a` (with `-type f|d|l`, `-maxdepth N`, `-mindepth N`), or `-name P1 -o -name P2 ...` (nothing else, in optional
    parentheses), ending with `-delete`. Anything else (`!` / `-not`, `-path`, `-regex`, `-newer`, `-exec`, `-o` next to -type, a pattern
    that is only wildcards or has a `/`) -> None: judged as before."""
    if not expr or expr[-1] != "-delete":
        return None
    t = [x for x in expr[:-1] if x not in ("(", ")")]
    pats, k, has_or, other = [], 0, False, False
    while k < len(t):
        a = t[k]
        if a in ("-name", "-iname") and k + 1 < len(t):
            pats.append(t[k + 1])
            k += 2
        elif a in ("-o", "-or"):
            has_or = True
            k += 1
        elif a in ("-a", "-and"):
            k += 1
        elif a == "-type" and k + 1 < len(t) and t[k + 1] in ("f", "d", "l"):
            other = True
            k += 2
        elif a in ("-maxdepth", "-mindepth") and k + 1 < len(t) and re.fullmatch(r"\d{1,3}", t[k + 1]):
            other = True
            k += 2
        else:
            return None
    if not pats or (has_or and other) or (has_or and len(pats) != t.count("-o") + t.count("-or") + 1):
        return None
    for p in pats:
        if not FIND_GLOB_PAT.fullmatch(p) or not re.search(r"[^*?\[\]]", p) or p in (".", "..") or re.search(r"[$`]", p):
            return None
    return pats


def _merge(c: Command, d: Command) -> None:
    for x in d.danger:
        if x not in c.danger:
            c.danger.append(x)
    for p in d.writes:
        c.write(p)
    for h in d.net:
        if h not in c.net:
            c.net.append(h)
    for src, dst in ((d.code_d, c.code_d), (d.plain_d, c.plain_d), (d.code_h, c.code_h), (d.plain_h, c.plain_h)):
        for x in src:                                 # 10.11 (r0260): the origin of each mark / host travels with it
            if x not in dst:
                dst.append(x)
    if _CODE[0] > 0:                                  # a nested line classified while scanning code (os.system("...")): its marks are code
        for x in d.danger:
            if x not in c.code_d:
                c.code_d.append(x)
        for h in d.net:
            if h not in c.code_h:
                c.code_h.append(h)
    for h in d.heads:
        c.head(h)
    for h in d.outside:
        c.out(h)
    for p in d.extract:
        if p not in c.extract:
            c.extract.append(p)
    for p in d.xdirs:
        if p not in c.xdirs:
            c.xdirs.append(p)
    for p in d.repo_extract:
        if p not in c.repo_extract:
            c.repo_extract.append(p)
    for p in d.xforeign:
        if p not in c.xforeign:
            c.xforeign.append(p)
    c.gtamper = c.gtamper or d.gtamper
    for p in d.gstore:
        if p not in c.gstore:
            c.gstore.append(p)
    for p in d.deletes:
        if p not in c.deletes:
            c.deletes.append(p)
    c.rm_judged += d.rm_judged
    c.rm_data += d.rm_data
    c.opaque = c.opaque or d.opaque


def _redirects(argv, cwd, home, c):
    """Remove redirections from argv; -> (argv, [written paths]). Every operator of REDIR_OPS takes the next word (`>file` and `> file` are
    the same tokens). 0.2.11 (R6-01): `>|`, `>>|`, `&>|`, `>&file`, `<>` write their word; a redirection without a word, a punctuation token
    that is not an operator, or a zsh `>!` makes the line opaque (fail closed), never a write to a made-up file in the project."""
    out, writes, i = [], [], 0
    while i < len(argv):
        a = argv[i]
        if a in REDIR_OPS:
            t = argv[i + 1] if i + 1 < len(argv) else None
            i += 2
            if t is None or (set(t) <= PUNCT):
                c.opaque = True
                c.add("opaque", "redirection %s without a target" % a)
                continue
            t = _unmask(t)
            if a in WORD_OPS or (a in DUP_OPS and re.fullmatch(r"\d*-?", t)):
                continue                        # heredoc delimiter / here-string / 2>&1, >&-: no file
            if t.startswith("!"):               # zsh `>! file` / `>!file` writes `file` (clobber); bash writes a file named "!..."
                c.opaque = True
                c.add("opaque", "redirection %s%s" % (a, t))
                continue
            if DEV_NET.match(t):
                _dev_net(t, c)                  # rt2810: a socket, not a file (its host is a host of the line)
                continue
            if a in READ_OPS or a == "<&":
                _read_target(t, cwd, home, c)
            else:
                _write_target(t, cwd, home, c, writes)
        elif a.isdigit() and i + 1 < len(argv) and argv[i + 1] in REDIR_OPS:
            i += 1                              # "2" before a split ">" token (shlex splits "2>" into "2", ">")
        elif a and set(a) <= PUNCT and a not in ("{", "}", "{}"):     # 0.2.52: `{` / `}` after a command's first word are words
            c.opaque = True                     # not an operator we know (cannot happen after _relex; kept fail-closed)
            c.add("opaque", "operator " + a)
            i += 1
        else:
            out.append(_unmask(a))
            i += 1
    return out, writes


def _read_target(t, cwd, home, c):
    """0.2.11 (R6-02): `< file`: a credential file is the danger `secrets`; a path the hook cannot know (`< $F`, `< ~user/x`) is opaque."""
    e = _expand(t, cwd, home)
    if is_secret_path(t) or (e is not None and is_secret_path(_abspath(e, cwd, home))):
        c.add("secrets", _secret_detail("<", [], [], t, _abspath(e, cwd, home), cwd, home) if e is not None else t)
    elif e is None:
        c.opaque = True
        c.add("opaque", "read from " + t)


def _write_target(t, cwd, home, c, writes, deleting=False):
    if t in SAFE_SINKS or t.startswith("/dev/fd/"):
        return
    if cwd == LOST_CWD and not t.startswith("/") and not _known_without_cwd(t, cwd, home):
        c.opaque = True                         # 0.2.12 (R7-02): after eval / source / a function neither the directory nor $HOME is known
        if not deleting and is_autostart_tail(t):
            c.add(AUTOSTART, "write to %s in an unknown directory" % t)     # r0298: a place that starts programs by itself (asked, once)
        c.add("opaque", "write to %s in an unknown directory" % t)
        return
    e = _expand(t, cwd, home)                   # 0.2.11 (R6-02): $HOME / $PWD resolved; any other expansion, ~user, a glob: unknown target
    if e is None or re.search(r"[*?[]", e):
        if is_secret_path(t):
            c.add("secrets", t)
        c.opaque = True
        c.add("opaque", "write to " + t)
        return
    p = _abspath(e, cwd, home)
    writes.append(p)
    if is_secret_path(p):
        c.add("secrets", p)
    if is_persist_path(p):
        c.add("persist", p)                     # 0.2.90 (G4): shell rc, LaunchAgents, crontab, the agent's settings / hooks, the witness's key
    if is_git_exec_path(p):
        c.add("git-config", p)                  # 0.2.9: git would run what is written there on the next `git status` / `git diff`
    if is_agent_config_path(p):
        c.add("agent-config", p)                # 0.2.24 (critique A): the hook / MCP configuration of the agent itself


def _delete_targets(ops, cwd, home, c):
    """Deleting a file is writing to its path: it is judged like any other write (outside the project -> RESOURCE)."""
    for o in ops:
        d = _expand(os.path.dirname(o) or ".", cwd, home)
        n0 = len(c.writes)
        if re.search(r"[*?[]", os.path.basename(o)) and d is not None and not re.search(r"[*?[]", d):
            c.write(_abspath(d, cwd, home))                               # glob: the directory it expands in
        else:
            _write_target(o, cwd, home, c, c.writes, deleting=True)       # r0298: a deletion starts nothing (no `autostart` mark)
        for p_ in c.writes[n0:]:
            if p_ not in c.deletes:
                c.deletes.append(p_)                                      # 0.2.90: a deletion writes no code (execguard D8 marks)


def _walks(name, args) -> bool:
    """0.2.55: does this reader walk a directory tree (and print what it finds below the first level)? Flags are read wherever they stand
    (GNU permutes `ls ~ -R`; BSD would take -R for a file: asking is the safe reading), up to `--`."""
    sh, lg = _flags(args)
    if name in ("rg", "ripgrep", "rgrep", "tree"):
        return True                                   # recursive by default (tree -L 1 is rare outside a project: not worth a branch)
    if name in ("grep", "egrep", "fgrep"):
        if bool(sh & {"r", "R"}) or any(len(l) >= 5 and ("--recursive".startswith(l) or "--dereference-recursive".startswith(l))
                                        for l in lg):
            return True
        for k, a in enumerate(args):                  # -d ACTION / --directories=ACTION: ACTION recurse (GNU takes a unique prefix: rec..)
            if a == "--":
                break
            val = None
            if a.startswith("--"):
                key, eq, v = a.partition("=")
                if len(key) >= 4 and "--directories".startswith(key):
                    val = v if eq else (args[k + 1] if k + 1 < len(args) else "")
            elif a.startswith("-") and "d" in a[1:]:
                m = a.index("d", 1)
                val = a[m + 1:] or (args[k + 1] if k + 1 < len(args) else "")
            if val is not None and len(val) >= 3 and "recurse".startswith(val):
                return True
        return False
    if name == "ls":
        return "R" in sh or any(len(l) >= 5 and "--recursive".startswith(l) for l in lg)    # --rec.. (--re is ambiguous with --reverse)
    if name == "du":                                  # recursive unless the depth printed is 0 or 1: -s / --summarize / -d N / --max-depth=N
        depth, all_, k = None, False, 0
        while k < len(args):
            a = args[k]
            if a == "--":
                break
            if a.startswith("--"):
                key, eq, val = a.partition("=")
                if len(key) >= 4 and "--summarize".startswith(key):
                    depth = 0 if depth in (None, 0) else 99
                elif len(key) >= 4 and "--max-depth".startswith(key):
                    if not eq:
                        k += 1
                        val = args[k] if k < len(args) else ""
                    depth = int(val) if re.fullmatch(r"\d+", val) else 99
                elif len(key) >= 4 and "--all".startswith(key):
                    all_ = True
            elif a.startswith("-") and len(a) > 1:
                m = 1
                while m < len(a):
                    ch = a[m]
                    if ch == "s":
                        depth = 0 if depth in (None, 0) else 99
                    elif ch == "a":
                        all_ = True
                    elif ch == "d":
                        val = a[m + 1:]
                        if not val:
                            k += 1
                            val = args[k] if k < len(args) else ""
                        depth = int(val) if re.fullmatch(r"\d+", val) else 99
                        break
                    elif ch in "BIt":                 # BSD -B blocksize, -I mask, -t threshold: a value follows
                        if m + 1 == len(a):
                            k += 1
                        break
                    m += 1
            k += 1
        return depth is None or depth > 1
    return False


def _roots(o: str) -> list:
    """0.2.55: the directories a traversal operand may start at. A glob component starting with a dot (`.*`, `src/.?`) also matches `..` in
    bash 3.2 (macOS /bin/bash) and before globskipdots: the parent is a root too."""
    out = [o]
    parts = o.split("/")
    for n, comp in enumerate(parts):
        if comp.startswith(".") and re.search(r"[*?[]", comp):
            out.append("/".join(parts[:n] + [".."]) or "/")
    return out


# 0.2.89 (friction 03.11): a recursive read outside the project is DANGER only where credentials live or when the walk follows links.
# A root strictly inside the home directory that is not a credential place and has none below it by name (~/.ssh, ~/.aws, ~/.config/*,
# ~/Library/*, the top of any hidden directory of the home: ~/.claude holds .credentials.json, ~/.config gh / gcloud ...) is:
#   - a listing (ls -R, du, tree) or a content search that prints only names / counts (grep -rl / -L / -c / -q, rg -l / -c / --files): let through
#     (the Read tool reads such files without a question already; names are not contents);
#   - a content search that prints lines (grep -rn, rg PATTERN): an ordinary question ("<name> [outside]", ESCALATE_COMMAND), not DANGER.
# Outside the home (/, /etc, /Users, another user), the home itself, a credential place, a root that cannot be resolved, or a walk that
# follows symlinks (grep -R / -S / -O / --dereference-recursive, rg -L / --follow, tree -l, ls -L, du -L) -> as before (opaque, DANGER).
_FOLLOW_SHORT = {"grep": set("RSO"), "egrep": set("RSO"), "fgrep": set("RSO"), "rgrep": set("RSO"), "rg": set("L"), "ripgrep": set("L"),
                 "tree": set("l"), "ls": set("LH"), "du": set("LH")}
_FOLLOW_LONG = ("--dereference-recursive", "--follow", "--dereference", "--dereference-args")
_NAMES_SHORT = {"grep": set("lLcq"), "egrep": set("lLcq"), "fgrep": set("lLcq"), "rgrep": set("lLcq"), "rg": set("lcq"), "ripgrep": set("lcq")}
_NAMES_LONG = ("--files-with-matches", "--files-without-match", "--count", "--count-matches", "--quiet", "--silent", "--files")
_HOME_CRED_TOPS = ("Library", ".config", ".local", ".password-store", ".mozilla", ".thunderbird", ".pki", ".terraform.d")


def _follows(name, args) -> bool:
    sh, lg = _flags(args)
    return bool(sh & _FOLLOW_SHORT.get(name, set())) or any(len(l) >= 5 and any(f.startswith(l) for f in _FOLLOW_LONG) for l in lg)


def _names_only(name, args) -> bool:
    sh, lg = _flags(args)
    return bool(sh & _NAMES_SHORT.get(name, set())) or any(l in _NAMES_LONG for l in lg)


def _quiet_root(real, home) -> bool:
    """0.2.89: may a recursive read start at `real` (a realpath) without DANGER? Strictly inside the home, not a credential place by name, and
    not the top of / inside a place that holds credentials stores (see above)."""
    h = canon_path(home).rstrip("/")
    q = canon_path(real)
    if not h or not q.startswith(h + "/") or is_secret_path(real) or DW_KEYS.search(real):
        return False
    rel = q[len(h) + 1:].strip("/").split("/")
    if not rel or not rel[0]:
        return False
    if rel[0] in _HOME_CRED_TOPS:
        return False
    if rel[0].startswith(".") and len(rel) == 1:
        return False                                  # ~/.claude (.credentials.json), ~/.cache, ~/.npm ...: the top of a hidden directory
    return True


def _recursive_outside(name, args, ops, cwd, home, project, c):
    """RT-0.2.54 / 0.2.55: a recursive reader (content: grep -r, rg; names: ls -R, du, tree) whose traversal root is outside the project and
    not a temp directory -> opaque (asked): it reaches .ssh / .aws / *.pem without naming them. No operand = the working directory; a root the
    hook cannot resolve ($VAR, ~user, $(..)) -> asked."""
    if not _walks(name, args):
        return
    if name in RECURSIVE_CONTENT_READERS:
        has_e = any(a.split("=", 1)[0] in ("--regexp", "--file") for a in args) or \
            any(re.fullmatch(r"-[A-Za-z]*[ef]", a) for a in args if a.startswith("-") and not a.startswith("--"))
        ops = ops if has_e else ops[1:]               # grep / rg: the first operand is the pattern unless -e / -f gave it
    kind = "read" if name in RECURSIVE_CONTENT_READERS else "listing"
    for o in (ops or ["."]):
        if o == "-":
            continue                                  # standard input
        for r in _roots(o):
            e = _expand(r, cwd, home)
            real = None if e is None else _abspath(e, cwd, home)
            if real is None and any(d.startswith("opaque:path from expansion: %s " % name) for d in c.danger):
                c.opaque = True                       # already asked for the same reason (one detail, as before)
                return
            if real is None or (not _in_project(real, project) and not temp_in(real, home)):
                if real is not None and _quiet_root(real, home) and not _follows(name, args):
                    if kind == "read" and not _names_only(name, args):
                        c.head(name + " [outside]")       # 0.2.89: lines of files outside the project: an ordinary question, not DANGER
                    continue
                c.opaque = True                       # reaches outside: may read (or list) a credential file without naming it
                c.add("opaque", "recursive %s outside the project: %s %s" % (kind, name, o))
                return


def _git_grep_outside(args, cwd, home, project, c):
    """0.2.55: `git grep` reads file CONTENT of the tree it runs in: `git -C ~ grep --no-index KEY` (or `cd ~ && git grep --no-index`) prints
    ~/.ssh/id_rsa (checked with git 2.54). The directory git runs in (cwd, then every -C), --git-dir / --work-tree / -c core.worktree, and
    every path operand must be in the project or a temp directory, else -> opaque (asked)."""
    here, i, where = cwd, 0, []
    while i < len(args) and args[i].startswith("-") and args[i] != "--":
        a = args[i]
        key, eq, v = a.partition("=")
        if a in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--super-prefix", "--exec-path") and not eq:
            v = args[i + 1] if i + 1 < len(args) else ""
            i += 1
        if a == "-C" or a.startswith("-C"):
            v = v if a == "-C" else a[2:]
            e = _expand(v, here, home)
            here = LOST_CWD if e is None else (_abspath(e, here, home) if v else here)
        elif key in ("--git-dir", "--work-tree"):
            where.append(v)
        elif a == "-c" or a.startswith("-c"):
            kv = v if a == "-c" else a[2:]
            if re.match(r"(?i)core\.(worktree|bare)|include|safe\.", kv):
                where.append(None)
        elif key == "--config-env":
            where.append(None)
        i += 1
    if i >= len(args) or args[i] != "grep":
        return
    rest = args[i + 1:]
    ops = _operands(rest)
    has_e = any(a.split("=", 1)[0] in ("--regexp", "--file") for a in rest) or \
        any(re.fullmatch(r"-[A-Za-z]*[ef]", a) for a in rest if a.startswith("-") and not a.startswith("--"))
    roots = [here] + where + [o for o in (ops if has_e else ops[1:])]
    for r in roots:
        e = None if r is None else _expand(r, here, home)
        real = None if e is None else _abspath(e, here, home)
        if real is None or (not _in_project(real, project) and not temp_in(real, home)):
            c.opaque = True
            c.add("opaque", "git grep outside the project: %s" % (r if r is not None else "-c"))
            return


# RT-0269 p.4: commands that write project files with a text that is not in the line (an archive, a patch, git objects). Before, none of
# them made a write: no Bash.write row, so a risky-write mark, a "written since" check (late release, the page of a question) never saw
# them. Each written path is a write (c.writes) AND an "extract" (execguard.written_run: the text is unseen -> risky); members unknown ->
# the directory as a whole (xdirs).
_PATCH_V_SHORT = set("BdDFiopPrVYz")
_PATCH_V_LONG = ("--directory", "--input", "--output", "--strip", "--reject-file", "--fuzz", "--ifdef", "--prefix", "--basename-prefix",
                 "--suffix", "--version-control", "--quoting-style", "--get", "--backup-if-mismatch")
_TAR_V_SHORT = set("bCfFgHIKLNTVX")
_GIT_TREE_SUBS = ("pull", "merge", "am", "cherry-pick", "rebase", "revert")
_GIT_STASH_WRITES = ("pop", "apply", "branch", "push", "save", "")
_GIT_STASH_NO_STORE = ("list", "show", "drop", "clear", "pop", "apply", "branch", "store")   # RT-0271: store is gtamper by itself
# RT-0270 29.10: git subcommands that change what the repository's objects / index / refs / remotes / config hold
_GIT_TAMPER = ("update-index", "hash-object", "notes", "read-tree", "commit-tree", "mktree", "mktag", "update-ref", "symbolic-ref", "replace",
               "unpack-objects", "fast-import", "index-pack", "bundle", "worktree", "config", "remote", "filter-branch", "filter-repo",
               "submodule", "subtree", "sparse-checkout", "merge-file", "merge-tree", "rerere", "pack-objects", "receive-pack")
_GIT_QUIET_FL = {"-q", "--quiet", "-f", "--force", "--progress", "--no-progress"}
_GIT_REF_NAMES = {"HEAD", "FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REBASE_HEAD", "REVERT_HEAD", "AUTO_MERGE",
                  "BISECT_HEAD", "stash"}


def _git_local_branch(n):
    """RT-0270: a plain local branch name (`main`, `wip`, `fix-1`): no `/` (origin/x), no ref syntax (@ ~ ^ : { }), not a sha, not a
    special ref (FETCH_HEAD ...), not `-`. Fail closed: `feature/x` is taken as not local (a remote-tracking spelling)."""
    return bool(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,99}", n)) and n not in _GIT_REF_NAMES and \
        not re.fullmatch(r"[0-9a-fA-F]{4,64}", n) and not n.endswith((".lock", "."))


def _git_tamper_read_only(sub, rest):
    """RT-0270: the read-only forms of a tamper subcommand (no change): `config --get / --list`, `remote [-v] / show / get-url`,
    `worktree list`, `notes list / show`, `submodule status`. Anything else (or unsure) changes git's state."""
    ops = [a for a in rest if not a.startswith("-")]
    fl = {a.split("=", 1)[0] for a in rest if a.startswith("-")}
    if sub == "config":
        if fl & {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l", "--get-color", "--get-colorbool"}:
            return True
        if ops[:1] in (["get"], ["list"]):
            return True
        return len(ops) == 1 and not fl & {"--unset", "--unset-all", "--add", "--replace-all", "--rename-section", "--remove-section",
                                             "-e", "--edit"}
    if sub == "remote":
        return not ops or ops[0] in ("show", "get-url") or (ops == [] and fl <= {"-v", "--verbose"})
    if sub == "worktree":
        return ops[:1] == ["list"]
    if sub == "notes":
        return ops[:1] in (["list"], ["show"])
    if sub == "submodule":
        return ops[:1] == ["status"]
    if sub == "rerere":
        return ops[:1] in (["status"], ["diff"])
    return False


def _stash_files(top, c):
    """N6 0.2.71 (series 8c): `git stash pop|apply` (the latest stash) writes only the paths where the stash's tree differs from HEAD (the
    untracked part never overwrites an existing file: git refuses). The hook's fact (gitref.py, `git diff-tree HEAD stash`: object hashes)
    names them; the word `stash` is in the line, so a 0.2.37+ hook answers. Only a full, plain answer counts (a commit, no `more`, no
    submodule / hook, ordinary relative paths); anything else leaves the directory whole (fail closed: page_files_changed)."""
    if not isinstance(top, str) or not top.startswith("/"):
        return
    v = _fs.current().gitref(top, "stash")
    if not isinstance(v, dict):
        return
    if not v.get("commit"):
        c.repo_files[os.path.normpath(top)] = []      # no stash: `pop` fails, nothing is written
        return
    ps = v.get("paths")
    if v.get("more") or v.get("special") or not isinstance(ps, list):
        return
    out = []
    for p in ps:
        if not isinstance(p, str) or not p or p.startswith("/") or "\0" in p or ".." in p.split("/"):
            return
        out.append(os.path.normpath(os.path.join(top, p)))
    c.repo_files[os.path.normpath(top)] = sorted(set(out))


def _cw_add(t, cwd, home, c, whole=False, repo=False):
    n = len(c.writes)
    _write_target(t, cwd, home, c, c.writes)
    p = c.writes[-1] if len(c.writes) > n else (_abspath(t, cwd, home) if not re.search(r"[$`*?[]", t) else None)
    if p is not None:
        if p not in c.extract:
            c.extract.append(p)
        lst = c.repo_extract if repo else c.xforeign
        if p not in lst:
            lst.append(p)
        if whole and p not in c.xdirs:
            c.xdirs.append(p)
        elif whole:
            c.repo_files_bad = True                    # N6: a second whole-directory write of the line (`git stash && git stash pop`)


def _cw_opts(args, v_short, v_long):
    """-> ([(option, value)], operands): a getopt-like pass (short clusters with a value letter take the rest or the next word)."""
    opts, ops, k = [], [], 0
    while k < len(args):
        a = args[k]
        if a == "--":
            ops += args[k + 1:]
            break
        if a.startswith("--"):
            o = a.split("=", 1)[0]
            if "=" in a:
                opts.append((o, a.split("=", 1)[1]))
            elif o in v_long and k + 1 < len(args):
                opts.append((o, args[k + 1]))
                k += 1
            else:
                opts.append((o, None))
        elif a.startswith("-") and len(a) > 1:
            j = 1
            while j < len(a):
                ch = a[j]
                if ch in v_short:
                    if a[j + 1:]:
                        opts.append(("-" + ch, a[j + 1:]))
                    elif k + 1 < len(args):
                        opts.append(("-" + ch, args[k + 1]))
                        k += 1
                    break
                opts.append(("-" + ch, None))
                j += 1
        else:
            ops.append(a)
        k += 1
    return opts, ops


def _git_base(args, cwd, home):
    """-> (directory git runs in (`-C dir`), index of the subcommand)."""
    i, base = 0, cwd
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "-C" and i + 1 < len(args):
            base = _abspath(args[i + 1], base, home) if not re.search(r"[$`]", args[i + 1]) else base
        i += 1 + (args[i] in ("-C", "-c", "--git-dir", "--work-tree"))
    return base, i


_GIT_COMMIT_V = {"-m", "--message", "-F", "--file", "-C", "--reuse-message", "-c", "--reedit-message", "-t", "--template", "--author",
                 "--date", "--fixup", "--squash", "--cleanup", "--trailer", "--pathspec-from-file"}
_GIT_ADD_PLAIN = {"-n", "--dry-run", "-v", "--verbose", "-f", "--force", "-u", "--update", "-A", "--all", "--no-all", "--ignore-removal",
                  "--no-ignore-removal", "-N", "--intent-to-add", "--refresh", "--ignore-errors", "--ignore-missing", "--sparse",
                  "--renormalize", "--no-warn-embedded-repo", "-q", "--quiet", "--chmod"}


def _git_stored(sub, pre, before, after, bops, bfl, base, top, home, via_xargs):
    """RT-0271 0.2.72 (cloud/OTCHET-DEGRADACIYA-STASH-0272.md): the paths whose WORK-TREE text this git line puts into git's objects / index:
    `git stash` (push / save / create / any form not known to only list / restore: the whole tree), `git add PATHS`, `git commit -a` (the
    whole tree) or `git commit PATHS`. "*" = unknown (xargs, --work-tree / --git-dir, a pathspec git expands, an option this list does not
    know): any path. A plain `git commit` stores the index only (what an add put there was judged at the add)."""
    if sub == "stash":
        return [top] if (bops[0] if bops else "") not in _GIT_STASH_NO_STORE else []
    if sub not in ("add", "commit"):
        return []
    if via_xargs or any(a.split("=", 1)[0] in ("--work-tree", "--git-dir") for a in pre):
        return ["*"]
    words, k, flags = [], 0, set()
    while k < len(before):
        a = before[k]
        f = a.split("=", 1)[0]
        if a.startswith("-") and len(a) > 1:
            if sub == "commit" and f in _GIT_COMMIT_V:
                if f == "--pathspec-from-file":
                    return ["*"]
                k += 1 if "=" in a else 2
                continue
            if sub == "commit" and re.fullmatch(r"-[A-Za-z]+", a) and a[-1] in "mFCct" and len(a) > 2:
                flags |= set(a[1:-1])
                k += 2                                     # `-am MSG`: the value of the last letter follows
                continue
            if sub == "add" and f == "--pathspec-from-file":
                return ["*"]
            if sub == "add" and f not in _GIT_ADD_PLAIN and not re.fullmatch(r"-[nvfuAN]+", a):
                return ["*"]
            flags |= set(a[1:]) if re.fullmatch(r"-[A-Za-z]+", a) else {f}
            k += 1
            continue
        words.append(a)
        k += 1
    words += after
    if any(re.search(r"[*?\[]", w) or w.startswith(":") for w in words):
        return ["*"]                                       # a pathspec git expands itself (`*.py`, `:/`, `:(glob)`)
    if sub == "commit" and ("a" in flags or "--all" in flags):
        return [top]
    if sub == "add" and not words:
        return [top] if flags & {"A", "u", "--all", "--update"} else []
    if sub == "commit" and not words:
        return []
    out = []
    for w in words:
        if re.search(r"[$`]", w):
            return ["*"]
        out.append(_abspath(w, base, home))
    return out


def _archive_links(arch, dest, cwd, home, c):
    """0.2.73 (N13, polygon series 9): `tar xf ln.tar` whose entry h3.txt is a hard link to .env puts a second name of the secret into
    the project (`cat h3.txt` then reads it). The hook reads the archive's headers (fact `archive`, archlinks.py): a link entry whose target
    is a credential file is the danger `secrets`, named on the page; a hard link out of the extraction directory, or an archive with more
    links than the hook lists, is `opaque`. No fact (an older hook, not a tar / zip it reads, `-f -`): the extraction stays the question
    it was (unseen_write)."""
    if not isinstance(arch, str) or not arch or arch == "-" or re.search(r"[$`*?\[]", arch):
        return
    e = _expand(arch, cwd, home)
    if e is None or ":" in e.split("/", 1)[0]:
        return                                         # `host:file` is a remote archive (GNU tar --force-local aside): nothing to read here
    ap = _abspath(e, cwd, home)
    info = _fs.current().archive(ap)
    if not isinstance(info, dict):
        return
    de = _expand(dest, cwd, home) if isinstance(dest, str) else cwd
    base = os.path.normpath(os.path.join(cwd, de)) if de is not None else cwd
    for kind, nm, tgt in info.get("links") or []:
        if not isinstance(tgt, str) or not isinstance(nm, str):
            continue
        t = tgt if tgt.startswith("/") else os.path.join(base, tgt) if kind == "hard" else os.path.join(base, os.path.dirname(nm), tgt)
        t = os.path.normpath(t)
        if is_secret_path(tgt) or is_secret_path(t):
            c.add("secrets", ("%s: %s becomes a hard link of %s (the same file under another name)" if kind == "hard" else
                              "%s: %s becomes a symbolic link to %s") % (arch, nm, _shown(t, cwd)))
        elif kind == "hard" and not (t == base or t.startswith(base.rstrip("/") + "/")):
            c.add("opaque", "%s: %s is a hard link to %s, outside the extraction" % (arch, nm, t))
    if info.get("more") is True:
        c.add("opaque", "%s: more links than the hook lists" % arch)


def _content_writes(name, args, cwd, home, c, project=None, via_xargs=False):
    if name == "patch":
        opts, ops = _cw_opts(args, _PATCH_V_SHORT, _PATCH_V_LONG)
        ov = dict(opts)
        if "--dry-run" in ov or "-C" in ov or "--check" in ov:
            return
        here = cwd
        d = ov.get("-d") or ov.get("--directory")
        if isinstance(d, str):
            here = _abspath(d, cwd, home) if not re.search(r"[$`]", d) else cwd
        out = ov.get("-o") or ov.get("--output")
        if isinstance(out, str) and out != "-":
            _cw_add(out, here, home, c)
        elif ops:
            _cw_add(ops[0], here, home, c)             # `patch FILE [PATCH]`
        else:
            _cw_add(here, here, home, c, whole=True)   # `patch -p1 < x.diff`: the files are named inside the patch
        return
    if name in ("tar", "bsdtar", "gtar"):
        first = args[0] if args else ""
        old_style = bool(first) and not first.startswith("-")
        letters = set(first) if old_style else set()
        opts, _ops = _cw_opts(args[1:] if old_style else args, _TAR_V_SHORT, ("--directory", "--file", "--files-from", "--exclude-from"))
        letters |= {o[1:] for o, _ in opts if len(o) == 2}
        longs = {o for o, _ in opts if o.startswith("--")}
        if not ("x" in letters or longs & {"--extract", "--get"}):
            return
        if "O" in letters or longs & {"--to-stdout", "--to-command", "--list"} or "t" in letters:
            return                                     # to stdout / to a program (`--to-command`: judged as a runner) / a listing
        ov = dict(opts)
        d = ov.get("-C") or ov.get("--directory")
        _cw_add(d if isinstance(d, str) else cwd, cwd, home, c, whole=True)
        arch = ov.get("-f") or ov.get("--file")
        if old_style and "f" in first:                 # `tar xf a.tar`, `tar xCf dir a.tar`: the values follow in the order of their letters
            vl = [ch for ch in first if ch in _TAR_V_SHORT]
            rest = args[1:]
            arch = rest[vl.index("f")] if vl.index("f") < len(rest) else None
        _archive_links(arch, d if isinstance(d, str) else None, cwd, home, c)
        return
    if name == "unzip":
        opts, ops = _cw_opts(args, set("d"), ())
        letters = {o[1:] for o, _ in opts if len(o) == 2}
        if letters & set("lptcvZz"):
            return                                     # list / pipe / test / to stdout: nothing written
        d = dict(opts).get("-d")
        _cw_add(d if isinstance(d, str) else cwd, cwd, home, c, whole=True)
        _archive_links(ops[0] if ops else None, d if isinstance(d, str) else None, cwd, home, c)
        return
    if name in ("perl", "ruby") and any(re.fullmatch(r"-[A-Za-z]*i\S*", a) for a in args if not a.startswith("--")):
        k, files = 0, []
        while k < len(args):
            a = args[k]
            if a in ("-e", "-E"):
                k += 2
                continue
            if not a.startswith("-"):
                files.append(a)
            k += 1
        if not any(a in ("-e", "-E") or re.fullmatch(r"-[A-Za-z]*[eE]", a) for a in args):
            files = files[1:]                          # the first operand is the script
        for f in files:
            _cw_add(f, cwd, home, c)
        return
    if name != "git":
        return
    base, i = _git_base(args, cwd, home)
    if i >= len(args):
        return
    sub, rest = args[i], args[i + 1:]
    top = project if project and (base == project or base.startswith(project.rstrip("/") + "/")) else base
    dd = "--" in rest
    before = rest[:rest.index("--")] if dd else rest
    after = rest[rest.index("--") + 1:] if dd else []
    bops = [a for a in before if not a.startswith("-")]
    bfl = {a.split("=", 1)[0] for a in before if a.startswith("-")}
    # RT-0271 0.2.72: the line stores the work tree's text into git (fail closed: a stash form not known to only read / restore stores)
    for g in _git_stored(sub, args[:i], before, after, bops, bfl, base, top, home, via_xargs):
        if g not in c.gstore:
            c.gstore.append(g)
    # RT-0270 29.10: quiet ("own") only for restoring the agent's own, seen work: from the index / HEAD, a stash with no argument, a switch
    # to a plain local branch name. Anything else git writes (pull, merge, a ref, a sha, a stash@{n}, -p, an argument list from xargs) is
    # foreign; a line that changes git's objects / index / refs / remotes is tamper (execguard / actions then take no restore as own).
    if via_xargs or any(re.search(r"[$`*?]", a) for a in rest):
        if sub in _GIT_TAMPER or sub in ("checkout", "restore", "switch", "stash", "reset", "checkout-index", "fetch", "pull", "merge",
                                          "branch", "tag", "apply", "am", "rebase", "cherry-pick", "revert"):
            c.gtamper = True
            if sub not in ("fetch", "branch", "tag") and sub not in _GIT_TAMPER:
                _cw_add(top, top, home, c, whole=True)   # what it writes depends on words the line does not show: foreign
        return
    if sub in _GIT_TAMPER:
        if not _git_tamper_read_only(sub, rest):
            c.gtamper = True
        return
    if sub == "checkout-index":
        own = not (bfl - _GIT_QUIET_FL - {"-a", "--all", "-u", "--index", "-n", "--no-create"})
        ps_ = [a for a in rest if not a.startswith("-")]
        for p in ps_:
            _cw_add(p, base, home, c, repo=own)
        if not ps_:
            _cw_add(top, top, home, c, whole=True, repo=own)
        return
    if sub == "checkout":
        if dd:
            # N15 / RT-0270: `checkout -- f` / `checkout HEAD -- f` (the index / HEAD), no -p / --ours / --theirs / --merge
            own = (not bops or bops == ["HEAD"]) and not (bfl - _GIT_QUIET_FL)
            if bfl & {"-b", "-B", "--orphan"}:
                c.gtamper = True
                own = False
            for p in after:
                _cw_add(p, base, home, c, repo=own)
            return
        if bfl & {"-b", "-B", "--orphan"}:
            if len(bops) <= 1:
                return                                 # a new branch at HEAD: no file changes
            c.gtamper = True                           # a new branch at a start point the witness never saw
            _cw_add(top, top, home, c, whole=True)
            return
        own = len(bops) == 1 and _git_local_branch(bops[0]) and not (bfl - _GIT_QUIET_FL)
        _cw_add(top, top, home, c, whole=True, repo=own)   # a branch (own), or a commit / ref / paths / -p (git decides): foreign
        return
    if sub == "restore":
        vals = {"-s", "--source"}
        ops, k = [], 0
        while k < len(rest):
            a = rest[k]
            if a == "--":
                ops += rest[k + 1:]
                break
            if a in vals:
                k += 2
                continue
            if not a.startswith("-"):
                ops.append(a)
            k += 1
        src_ = None
        for k_, a_ in enumerate(rest):
            if a_ == "--":
                break
            if a_ in vals and k_ + 1 < len(rest):
                src_ = rest[k_ + 1]
            elif a_.startswith(("--source=", "-s")) and a_ not in vals and not a_.startswith("--staged"):
                src_ = a_.split("=", 1)[1] if "=" in a_ else a_[2:]
        if bfl & {"--staged", "-S"} and not bfl & {"--worktree", "-W"}:
            if src_ not in (None, "HEAD"):
                c.gtamper = True                       # RT-0270: the index from a ref: a later `checkout -- f` writes it
            return                                     # only the index
        # N15 / RT-0270: from the index / HEAD only; `--source=evil`, -p, --ours / --theirs / --merge stay foreign
        own = src_ in (None, "HEAD") and not (bfl - _GIT_QUIET_FL - {"-s", "--source", "-S", "--staged", "-W", "--worktree"})
        for p in ops:
            _cw_add(p, base, home, c, repo=own)
        if not ops:
            _cw_add(top, top, home, c, whole=True, repo=own)
        return
    if sub == "switch":
        if bfl & {"-c", "-C", "--create", "--force-create", "--orphan"} and len(bops) <= 1:
            return
        own = len(bops) == 1 and _git_local_branch(bops[0]) and not (bfl - _GIT_QUIET_FL)
        if bfl & {"-c", "-C", "--create", "--force-create"}:
            c.gtamper = True                           # a new branch at a start point
            own = False
        _cw_add(top, top, home, c, whole=True, repo=own)
        return
    if sub == "stash":
        op = bops[0] if bops else ""
        if op in ("store",):
            c.gtamper = True                           # any commit becomes a stash
            return
        if op in _GIT_STASH_WRITES:
            # RT-0270: `stash pop` / `stash apply` with no stash argument (the agent's latest stash); `stash@{n}`, a sha, `stash branch`
            # are foreign; push / save write HEAD's text back (own)
            if op in ("pop", "apply"):
                own = len(bops) == 1 and not after and not (bfl - _GIT_QUIET_FL - {"--index"})
            elif op == "branch":
                own = False
            else:
                own = True
            _cw_add(top, top, home, c, whole=True, repo=own)
            if own and op in ("pop", "apply"):
                _stash_files(top, c)
        return
    if sub == "apply":
        if bfl & {"--check", "--stat", "--numstat", "--summary"} and "--apply" not in bfl:
            return
        if bfl & {"--cached"} and not bfl & {"--index"}:
            c.gtamper = True                           # RT-0270: only the index, a later `checkout -- f` writes the patched text
            return
        c.gtamper = c.gtamper or bool(bfl & {"--index"})
        _cw_add(top, top, home, c, whole=True)
        return
    if sub in ("fetch", "pull"):
        # RT-0270: a fetch / pull of a path, a URL or a refspec with a local destination (`../stage`, `https://...`, `a:b`) brings objects
        # the witness never saw under names a later switch takes as "own"; `git fetch origin` (the configured remote) does not
        if any(("/" in a or ":" in a or a.startswith(".")) for a in bops) or bfl & {"--upload-pack", "--refmap", "--update-head-ok"}:
            c.gtamper = True
        if sub == "pull":
            _cw_add(top, top, home, c, whole=True)    # RT-0270: pull writes the remote's text: foreign (as before N15)
        return
    if sub in ("branch", "tag"):
        # RT-0270: a branch / tag at a start point, forced, renamed or copied: a later switch to it is a ref the witness never saw
        if bfl & {"-f", "--force", "-m", "-M", "-c", "-C", "--move", "--copy", "--set-upstream-to", "-u"} or \
                (len(bops) >= 2 and not bfl & {"-d", "-D", "--delete", "-l", "--list", "-v", "-n", "--contains", "--merged",
                                                  "--no-merged", "--points-at"}):
            c.gtamper = True
        return
    if sub in _GIT_TREE_SUBS:
        # RT-0270: merge / rebase / cherry-pick / am / revert: foreign (as before N15), text the witness never saw. Not tamper: what a
        # later restore from HEAD gives back is the text this write already put there (marked risky with it)
        _cw_add(top, top, home, c, whole=True)
        return
    if sub == "reset":
        if bfl & {"--hard", "--merge", "--keep"}:
            c.gtamper = True
            _cw_add(top, top, home, c, whole=True)
            return
        if bops and not (bops == ["HEAD"]) and not (dd and not bops):
            c.gtamper = True                           # RT-0270: HEAD / the index moved to a ref (`reset origin/evil`, `reset evil -- f`)
        return
    if sub == "mv" and len(bops + after) >= 2:
        for p in bops + after:
            _cw_add(p, base, home, c)
        return



def _shown(p, cwd):
    """0.2.73: a path as the page names it in a detail (DETAIL_MAX characters): relative to the call's directory when it lies under it."""
    if isinstance(cwd, str) and cwd and cwd != LOST_CWD and p.startswith(cwd.rstrip("/") + "/"):
        return p[len(cwd.rstrip("/")) + 1:]
    return p


def _secret_detail(name, args, ops, o, p, cwd, home):
    """0.2.73 (N13): what the page says of a credential file a command names. `ln .env x` (no -s): x becomes the same file under another
    name (reading x reads .env); `cat h3.txt` where h3.txt is a hard link of .env (the hook's fact samefile): which name the call used."""
    via = _fs.current().note(p) if hasattr(_fs.current(), "note") else None
    if isinstance(via, str) and via != p:
        return "%s is a hard link of %s (the same file under another name)" % (_shown(via, cwd), _shown(p, cwd))
    if name == "ln" and len(ops) >= 2 and o in ops[:-1] and not ({"-s", "--symbolic"} & set(args) or any(re.fullmatch(r"-[A-Za-z]*s[A-Za-z]*", a) for a in args)):
        return "ln makes %s a hard link of %s (the same file under another name)" % (ops[-1], _shown(p, cwd))
    return p


def _one(name, args, cwd, home, c, via_xargs, depth, project=None, lw_plain=False, nonfile=frozenset()):
    """lw_plain (0.2.53): a command of LW_CMDS whose every path _local_write read for sure; its writes are already judged (exactly: a
    directory destination is not itself written, an option's value is not a file), so the coarse extraction below is skipped for it."""
    short, long_ = _flags(args)
    ops = _operands(args)
    paths = [o for o in ops if not re.search(r"[$`]", o)]
    uploads = [m.group(1) for a in args for m in [re.search(r"(?:^|=)@([^@\s]+)$", a)] if m]     # curl -d @file, -F f=@file
    if name == "dd":
        uploads += [a[3:] for a in args if a.startswith("if=") and len(a) > 3]    # r0275: `dd if=~/.ssh/id_rsa of=x` reads that file
    values = [a.split("=", 1)[1] for a in args if a.startswith("-") and "=" in a]
    code_args = _eval_code_args(name, args) if _eval_form(name, args) else set()
    for o in ops + uploads + values:                      # reading, copying or uploading a credential file
        if o in nonfile and _lit_ok(o):
            continue                                      # 0.2.54: a sed script, an awk / jq program, a find pattern: not a path
        if o in code_args:
            # 10.11 (r0260, dev #483): the CODE of `python -c CODE` / `node -e CODE` is not a file operand. Before, a secret path written
            # anywhere in it (`['git config -f ~/.ssh/x --list']`, a test table) made `secrets:<cwd>/<the whole code>` a mark of the SHELL
            # line. Now each secret path the code writes is a mark of the code (_CODE), with that path: still asked outside the strict
            # sandbox (the same backstop); inside it sandbox.code_contained holds a path under the denyRead the strict fact requires.
            o_ = o
            if re.fullmatch(r"python(?:[23](?:\.\d{1,2})?)?", name):
                from .inline import blank_text
                o_ = blank_text(o)                     # 11.11 (r0260, class (в)): a secret path only inside text the code writes: no mark
            if is_secret_path(o_):
                _CODE[0] += 1
                try:
                    toks = [t for t in _CODE_PATH_TOK.findall(o_) if is_secret_path(t)]
                    for t in toks or [o]:
                        e = _expand(t, cwd, home) if toks else None
                        c.add("secrets", _abspath(e, cwd, home) if e is not None else t[:200])
                finally:
                    _CODE[0] -= 1
            continue
        e = _expand(o, cwd, home)                         # 0.2.11: also through $HOME/${HOME}, and a symlink in the project to a key
        if name in STAT_ONLY and o in ops and o not in uploads and _lit_ok(o) and e is not None and \
                not SECRET_DIR.search(o) and not SECRET_DIR.search(_abspath(e, cwd, home)):
            continue                                      # N16 0.2.74: `ls -la .env` / `stat .env` / `test -f .env`: metadata, not the text
        if name == "ls" and o in ops and _lit_ok(o) and e is not None and not short & {"R"} and "--recursive" not in long_ \
                and SECRET_DIR_ITSELF.search(_abspath(e, cwd, home).rstrip("/")):
            continue                                      # 0.2.91 (friction 04.11): `ls -la ~/.config/gh/` lists the names in the directory, never
            #                                               a file's text (a file inside it, `ls -R`, `cat`, `stat ~/.ssh/id_rsa` stay questions)
        plain = e is not None and (PATHLIKE.match(e) or "/" in e or (o in uploads or (name in FILE_READERS and name not in META_ONLY and
                                                                      o in ops[FILE_READERS[name]:] and _lit_ok(o))))
        if is_secret_path(o) or (plain and is_secret_path(_abspath(e, cwd, home))):
            c.add("secrets", _secret_detail(name, args, ops, o, _abspath(e, cwd, home) if e is not None else o, cwd, home))
        elif e is None and (o.startswith("~") or "/" in o or o in uploads or (name in FILE_READERS and o not in ops[:FILE_READERS[name]])):
            c.opaque = True                               # 0.2.11 (R6-02): `cat ${KEY}`, `cp $(..) x`, `less ~user/x`: a path the hook cannot
            c.add("opaque", "path from expansion: %s %s" % (name, o))   # know may be a credential -> asked as dangerous, whatever unlisted says
    for m in SECRET_ENV.finditer(" ".join(a for a in args if not (name in TX_NAMES and isinstance(a, _Lit)))):
        if name in ("echo", "printf", "env", "printenv", "export", "set", "declare") or name in FETCHERS or name in TX_NAMES:
            c.add("secrets", "$" + m.group(1))
    if name == "printenv" and not ops:
        c.add("secrets", "whole environment")
    if (name in RECURSIVE_CONTENT_READERS or name in RECURSIVE_NAME_READERS) and project is not None and not via_xargs:
        _recursive_outside(name, args, ops, cwd, home, project, c)
    if name == "git" and project is not None:
        _git_grep_outside(args, cwd, home, project, c)
    _network(name, args, ops, c)
    if name in TX_AWK:
        for a in sorted(nonfile):
            _code_scan(a, c, name, obfuscation=False)     # rt2810: `awk 'BEGIN{system("curl https://h")}'` shows its host
    if _eval_form(name, args):
        _sa = " ".join(args[1:] if name == "deno" else args)
        if PY_MODULE.fullmatch(name):                     # r0261c (а): the code of `python3 -c` seen as text where it only writes text
            _ec = _eval_code(name, args)
            _tv = _text_view(_ec, name) if _ec else _ec
            if _ec and _tv != _ec and _ec in _sa:
                _sa = _sa.replace(_ec, _tv, 1)
        _code_scan(_sa, c, name)                          # s7 (O1): `python3 -c "...urlopen('https://evil')"`, `node -e "fetch(...)"`
        _code_fs_scan(_eval_code(name, args), c, name, cwd, home, project, depth, operands=[o for o in ops if _lit_ok(o)])   # 0.2.90
    _gates(name, args, ops, short, long_, cwd, home, c)                                  # 0.2.90: G2 egress, G3 keychain, G4 persistence
    if name == "git":
        _git_global(args, cwd, home, c, depth, project)  # s7 (O1): `git -c alias.x='!curl https://evil' x`
        _git_config_set(args, cwd, home, c, depth, project)     # rt2810: `git config core.sshCommand "curl https://evil"`
    if name in CLOUD_CLIS or (name, ops[0] if ops else "") in PUBLISH:
        c.opaque = True
        c.add("opaque", "remote service CLI: " + name)
    if name in ("ditto", "install", "truncate", "rsync") and ops:    # 0.2.90 (QA Н6, spec del-7/8): copy / truncate tools write their last operand
        last = ops[-1]
        if not (name == "rsync" and re.match(r"[^/]*:", last)):      # a remote rsync destination is a host (REMOTE_SHELLS), not a path
            e_ = _expand(last, cwd, home)
            if e_ is not None and not re.search(r"[*?[]", e_):
                _write_target(e_, cwd, home, c, c.writes)
    if name in FETCHERS:                                  # curl -o FILE / --output FILE, wget -O FILE / --output-document=FILE
        flags = {"curl": ("-o", "--output"), "wget": ("-O", "--output-document")}.get(name, ())
        for k, a in enumerate(args):
            if flags and k + 1 < len(args) and (a in flags or (re.fullmatch(r"-[A-Za-z]+", a) and a.endswith(flags[0][1]))):
                if args[k + 1] != "-":                    # "-" = stdout
                    _write_target(args[k + 1], cwd, home, c, c.writes)
            elif "=" in a and a.split("=", 1)[0] in flags and a.split("=", 1)[1] != "-":
                _write_target(a.split("=", 1)[1], cwd, home, c, c.writes)
            elif len(a) > 2 and a[:2] in flags and not a.startswith("--") and a[2:] != "-":
                _write_target(a[2:], cwd, home, c, c.writes)
    _content_writes(name, args, cwd, home, c, project, via_xargs=via_xargs)   # RT-0269 p.4: patch, tar x, unzip, git checkout / restore / pull ... write files
    if lw_plain and not via_xargs:
        if name == "rm" and (short & {"r", "R"} or "--recursive" in long_):
            c.rm_plain += 1                               # 0.2.89: judged path by path (_lw_tags); the raw scan of the line does not count it
        return
    if name == "rm":
        rec = bool(short & {"r", "R"}) or "--recursive" in long_
        force = "f" in short or "--force" in long_
        if rec or (force and (via_xargs or any(re.search(r"[*?]", o) for o in ops))):
            for o in (ops or ["(stdin)" if via_xargs else "(none)"]):
                if re.search(r"[$`*?]", o) or o.startswith("("):
                    c.add("rm-rf", o)
                    continue
                p_ = _abspath(o, cwd, home)
                if _deep_inside(p_, project, home):
                    c.delete(p_)                      # 0.2.90 (FABLE-NOL p.5.2): `rm -rf build` inside the project: the mandate's own targets
                    c.rm_judged += 1
                else:
                    c.add("rm-rf", p_)
        else:
            _delete_targets(ops, cwd, home, c)          # a plain delete is a write to its path (rm -rf is judged as danger already)
        return
    if name in ("rmdir", "unlink", "shred", "srm", "wipe"):
        if name == "shred" or via_xargs:
            c.add("rm-rf", " ".join(ops) or name)
        _delete_targets(ops, cwd, home, c)
        return
    if name == "find" and ("-delete" in args or any(os.path.basename(a) in DELETERS for a in args)):
        roots = []
        for a in args:                                    # the start points: the words before the first expression / option
            if a.startswith("-") or a in ("(", "!"):
                break
            roots.append(a)
        roots = roots or ["."]
        for r_ in roots:                                  # 0.2.90: `find build -delete` inside the project is a delete of the mandate's targets
            e_ = _expand(r_, cwd, home)
            p_ = _abspath(e_, cwd, home) if e_ is not None and not re.search(r"[*?[]", e_) else None
            filtered = any(a in ("-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-wholename") for a in args)
            pats = _find_root_glob(args[len(roots):]) if "-delete" in args else None
            if p_ is not None and pats and project and p_.rstrip("/") == project.rstrip("/"):
                for pat in pats:                          # 10.11 (r0260): the files it deletes, "<project>/**/<pattern>": a delete of the
                    c.delete(p_.rstrip("/") + "/**/" + pat)   # mandate's target "<project>/*" (the root itself was RESOURCE: proby #24)
            elif p_ is not None and (_deep_inside(p_, project, home) or (filtered and project and p_.rstrip("/") == project.rstrip("/"))):
                c.delete(p_)                              # `find . -name '*.pyc' -delete` at the project root: a filtered delete inside it
            else:
                c.add("rm-rf", "find " + r_)
        return
    if name == "find" and any(a in ("-exec", "-execdir", "-ok", "-okdir") and k + 1 < len(args) and os.path.basename(args[k + 1]) in FIND_WRITERS
                              for k, a in enumerate(args)):
        roots = []
        for a in args:
            if a.startswith("-") or a in ("(", "!"):
                break
            roots.append(a)
        for r_ in (roots or ["."]):                       # 0.2.90 (G4): `find ~/Library/LaunchAgents -exec sed -i ...` writes under its root
            e_ = _expand(r_, cwd, home)
            if e_ is not None and not re.search(r"[*?[]", e_):
                _write_target(e_, cwd, home, c, c.writes)
    if name == "git":
        _git(args, cwd, home, c)
        return
    if name in ("dd",):
        for a in args:
            if a.startswith("of="):
                tgt = a[3:]
                if tgt.startswith("/dev/") and tgt not in SAFE_SINKS:
                    c.add("disk", tgt)
                else:
                    _write_target(tgt, cwd, home, c, c.writes)
        return
    if name.startswith("mkfs") or name in ("fdisk", "parted", "wipefs", "sgdisk"):
        c.add("disk", " ".join(ops) or name)
        return
    if name in ("chmod", "chown") and ("R" in short or "--recursive" in long_) and any(_abspath(p, cwd, home) in ("/", home) for p in paths):
        c.add("rm-rf", "%s -R %s" % (name, " ".join(paths)))
        return
    if name in SHELLS:
        if "c" in short:
            i = next((k for k, a in enumerate(args) if a.startswith("-") and "c" in a[1:] and not a.startswith("--")), None)
            if i is not None and i + 1 < len(args):
                _merge(c, classify(args[i + 1], cwd, home, depth + 1, project, _budget=c.budget))
        elif via_xargs:
            c.add("opaque", name + " via xargs")
            c.opaque = True
        return
    if name == "eval" or name == "source" or name == ".":
        if name == "eval":
            _merge(c, classify(" ".join(args), cwd, home, depth + 1, project, _budget=c.budget))
        return
    if name in ("tee",):
        for p in ops:
            _write_target(p, cwd, home, c, c.writes)
        return
    if name in ("cp", "mv", "install", "ln", "rsync", "scp") and len(ops) >= 2:
        t = next((args[k + 1] for k, a in enumerate(args) if a in ("-t", "--target-directory") and k + 1 < len(args)), None)
        dest = t or ops[-1]
        if ":" not in dest or name not in ("rsync", "scp"):
            _write_target(dest, cwd, home, c, c.writes)
            if not (name == "install" and ("d" in short or "--directory" in long_)):
                tree = name == "mv" or bool(set(short) & {"r", "R", "a"}) or bool({"--recursive", "--archive"} & set(long_))
                _into_persist(name, [o for o in ops if o != dest] if t else ops[:-1], dest, bool(t), cwd, home, c, tree=tree)
        if name == "mv":
            for p in ops[:-1]:
                _write_target(p, cwd, home, c, c.writes)    # moving a file away changes the source path too
        return
    if name in ("sort", "tree", "uniq"):                     # PROPOSAL-06: read-only commands of the default list that can still write a file
        out, tmpdir, _ = _out_file_args(name, args)          # 0.2.51: parsed as getopt does (clusters `-ro F`, prefixes `--outp=F`)
        for p in out:
            _write_target(p, cwd, home, c, c.writes)
        return
    if name == "xxd":                                        # 0.2.95: `xxd [opts] IN OUT` writes OUT (a dump, or with -r the bytes)
        ops = _xxd_ops(args)
        if len(ops) >= 2 and ops[1] != "-":
            _write_target(ops[1], cwd, home, c, c.writes)
        return
    if name in ("touch", "mkdir", "truncate"):
        for p in ops:
            if name != "truncate" or not p.isdigit():
                _write_target(p, cwd, home, c, c.writes)
        return
    if name in ("psql", "mysql", "sqlite3", "mongo", "mongosh", "redis-cli") and any(a.upper() in ("FLUSHALL", "FLUSHDB") for a in args):
        c.add("sql-drop", " ".join(args)[:DETAIL_MAX])


# r0300: names that start programs only in the HOME folder (a shell reads ~/.zshrc, git ~/.gitconfig, Claude Code ~/.claude.json).
# A copy into another folder (`cp ~/.bashrc /tmp/`, a backup) is not taken as a write to an autostart place by _into_persist.
HOME_ONLY_NAME = re.compile(r"^\.(zshrc|zprofile|zshenv|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|profile|login|cshrc|tcshrc|kshrc|"
                            r"mkshrc|xinitrc|xprofile|xsession|pam_environment|hushlogin|gitconfig|claude\.json)$", re.I)


def _into_persist(name, srcs, dest, by_t, cwd, home, c, tree=False):
    """r0300 (Н4): `cp a.service ~/.config/systemd/user/`, `cp .bashrc ~`, `cp settings.json ~/.claude/`, `ln -s /tmp/e ~/.config/autostart/`:
    into a DIRECTORY the file lands as DIR/<its name>. When that path is a place that starts programs by itself (PERSIST_PATH) and the
    directory itself is not one, it is the same write as naming the file: `persist` (refused), not a question about the directory.
    The destination is a directory when: -t / --target-directory, a trailing '/', more than one source, it is the home folder, every
    name in it is an autostart place (LaunchAgents, systemd/user, autostart, conf.d, cron.d ...), or the file system says so (isdir is
    asked only when the landing path would be persist). Remote sources / destinations (`host:path`) are not ours to judge here."""
    if not srcs or ":" in dest and name in ("rsync", "scp") or (cwd == LOST_CWD and not dest.startswith("/") and not _known_without_cwd(dest, cwd, home)):
        return
    e = _expand(dest, cwd, home)
    if e is None or re.search(r"[*?[]", e):
        return
    d = _abspath(e, cwd, home)
    if is_persist_path(d):
        return                                      # the directory itself is refused already (`cp a ~/Library/LaunchAgents/`)
    every = is_persist_path(d.rstrip("/") + "/x")   # a directory whose every entry starts programs (systemd/user, autostart, cron.d ...)
    for s_ in srcs:
        if ":" in s_ and name in ("rsync", "scp"):
            base = os.path.basename(s_.split(":", 1)[1].rstrip("/")) or "x"
        else:
            base = os.path.basename(s_.rstrip("/"))
        if not base or base in (".", ".."):
            if every:
                c.add("persist", d.rstrip("/") + "/")
            continue
        cand = os.path.join(d, base)
        whole = tree and is_persist_path(cand + "/x")  # `cp -R autostart ~/.config/`: a whole folder lands as an autostart folder
        if not (is_persist_path(cand) or every or whole):
            continue
        if HOME_ONLY_NAME.match(base) and d != home and not every:
            continue                                # `cp ~/.bashrc /tmp/`, `cp ~/.gitconfig backup/`: a copy OF the place, read only
        dir_dest = by_t or dest.endswith("/") or len(srcs) > 1 or d == home or every or _fs.current().isdir(d)
        if dir_dest:
            c.add("persist", cand if is_persist_path(cand) else cand + "/")


# 0.2.51: short options that take a value (the rest of the cluster or the next word), per command; long options are matched by getopt prefix
_OUT_SHORT_VALUE = {"sort": set("kotST"), "tree": set("LPIoHT"), "uniq": set("fsw")}
_OUT_LONG_VALUE = {"sort": ("--key", "--output", "--buffer-size", "--field-separator", "--temporary-directory", "--compress-program",
                            "--batch-size", "--parallel", "--random-source", "--files0-from", "--sort"),
                   "tree": ("--filelimit", "--timefmt", "--charset", "--sort", "--hintro", "--houtro", "--infofile", "--gitfile"),
                   "uniq": ("--skip-fields", "--skip-chars", "--check-chars")}


# 0.2.95 (ISPYTANIE-PERED-LYUDMI-1211 Н4): xxd's options that take a value (`-c 16`, `-l 64`, `-s +8`, `-n name`, `-o off`, `-g 2`, `-R when`)
_XXD_VALUE = ("-c", "-cols", "-g", "-groupsize", "-l", "-len", "-n", "-name", "-o", "-s", "-seek", "-R")


def _xxd_ops(args):
    """xxd's operands (infile, outfile), read as xxd reads them: a value of a listed option is no operand; `-c16` carries its own."""
    ops, k = [], 0
    while k < len(args):
        a = args[k]
        if a == "--":
            ops += args[k + 1:]
            break
        if a.startswith("-") and len(a) > 1:
            k += 2 if a in _XXD_VALUE else 1
            continue
        ops.append(a)
        k += 1
    return ops


def _long_is(a: str, full: str, least: int) -> bool:
    """getopt_long takes any unambiguous prefix (`--outp=F` is `--output=F`): `a` (before '=') is a prefix of `full`, at least `least` long."""
    o = a.split("=", 1)[0]
    return len(o) >= least and full.startswith(o)


def _out_file_args(name, args):
    """0.2.51: sort / tree / uniq -> ([files written], wrote temp files into a directory?, runs a program?), read as getopt reads them:
    `sort -o F`, `-roF`, `-ro F`, `--output F`, `--outp=F`, `-T DIR`, `--compress-prog=P`; `tree -o F`, `-ao F`, `-R` (writes 00Tree.html in
    every directory); `uniq [opts] IN OUT` (values of -f/-s/-w are not operands)."""
    out, tmpdir, prog, ops, k = [], False, False, [], 0
    short_v, long_v = _OUT_SHORT_VALUE[name], _OUT_LONG_VALUE[name]
    while k < len(args):
        a = args[k]
        if a == "--":
            ops += args[k + 1:]
            break
        if a.startswith("--"):
            val = a.split("=", 1)[1] if "=" in a else (args[k + 1] if k + 1 < len(args) else None)
            takes = "=" not in a and any(_long_is(a, f, 3) for f in long_v)
            if name == "sort" and _long_is(a, "--output", 3) and val is not None:
                out.append(val)
            elif name == "sort" and _long_is(a, "--temporary-directory", 4):
                tmpdir = True
            elif name == "sort" and _long_is(a, "--compress-program", 4):
                prog = True
            k += 2 if takes else 1
            continue
        if a.startswith("-") and len(a) > 1:
            j, skip = 1, 0
            while j < len(a):
                ch = a[j]
                if name == "tree" and ch == "R":
                    tmpdir = True                    # `tree -R`: runs itself again in every directory with `-o 00Tree.html`
                if ch in short_v:
                    val = a[j + 1:] or (args[k + 1] if k + 1 < len(args) else None)
                    skip = 0 if a[j + 1:] else 1
                    if ch == "o" and name in ("sort", "tree") and val is not None:
                        out.append(val)
                    elif ch == "T" and name == "sort":
                        tmpdir = True
                    break
                j += 1
            k += 1 + skip
            continue
        ops.append(a)
        k += 1
    if name == "uniq" and len(ops) >= 2 and ops[1] != "-":
        out.append(ops[1])
    return out, tmpdir, prog


def _git_grep_pager(rest) -> bool:
    """0.2.51: `git grep -O[<pager>]`, `-iO<cmd>`, `--open-files-in-pager[=<cmd>]` and its prefixes (`--open=<cmd>`, parse-options takes
    them; checked with git 2.54): git runs that program on the matching files."""
    for a in rest:
        if a == "--":
            break
        if a.startswith("--"):
            if _long_is(a, "--open-files-in-pager", 4):
                return True
        elif a.startswith("-") and "O" in a[1:]:
            return True
    return False


# s7 (O1): git configuration keys given with `-c` whose value is a shell command git runs (an alias `!...`, a pager, an editor, ssh, a diff
# or merge driver, a filter, a credential helper `!...`): the value is classified as a command line of its own (its hosts, its danger)
GIT_SHELL_KEY = re.compile(r"(core\.(pager|editor|sshcommand|fsmonitor|askpass|gitproxy|alternaterefscommand)|diff\.external|sequence\.editor|"
                           r"pager\..+|(diff|merge)\..+\.(command|textconv|driver)|filter\..+\.(clean|smudge|process)|gpg(\..+)?\.program|"
                           r"uploadpack\.packobjectshook)", re.I)


def _git_global(args, cwd, home, c, depth, project):
    """s7: `git -c k=v` / `-ck=v` / `--config-env=k=ENV` before the sub-command: a URL in the key or value is a host the line talks to
    (`url.<base>.insteadOf`, `http.proxy`); a value git runs as a shell command is classified; one taken from the environment is opaque."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        a, kv = args[i], None
        if a == "-c" and i + 1 < len(args):
            kv, i = args[i + 1], i + 2
        elif a.startswith("-c") and len(a) > 2:
            kv, i = a[2:], i + 1
        elif a.startswith("--config-env"):
            k = (a.split("=", 1)[1] if "=" in a else (args[i + 1] if i + 1 < len(args) else "")).split("=", 1)[0]
            i += 1 if "=" in a else 2
            if k.lower().startswith("alias.") or GIT_SHELL_KEY.fullmatch(k) or k.lower().startswith(("url.", "http.", "remote.")):
                c.add("opaque", "git --config-env " + k)
            continue
        else:
            i += 1 + (a in ("-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--exec-path") and "=" not in a)
            continue
        if not isinstance(kv, str):
            continue
        _git_kv(kv, cwd, home, c, depth, project)


def _git_kv(kv, cwd, home, c, depth, project, urls_any=True):
    """s7 / rt2810: one git setting `key=value` (`git -c`, and `git config key value`): a URL in it is a host; a value git runs is classified.
    urls_any=False (`git config`, a lasting setting that runs later): URLs only of url.* / http(s).*proxy keys and of the values git runs,
    and of an alias / credential helper only its hosts and danger (its commands do not run now)."""
    k, _, v = kv.partition("=")
    if urls_any or k.lower().startswith("url.") or re.fullmatch(r"https?\..*proxy", k, re.I):
        for m in URL_RE.finditer(kv):
            c.host(m.group(2).strip("[]"))
    bang = k.lower().startswith(("alias.", "credential.")) and v.startswith("!")
    if bang and urls_any:
        _merge(c, classify(v[1:], cwd, home, depth + 1, project, _budget=c.budget))
    elif bang or (GIT_SHELL_KEY.fullmatch(k) and v):
        sub = classify(v[1:] if bang else v, cwd, home, depth + 1, project, _budget=c.budget)   # its hosts and its danger; the line is
        for h in sub.net:                                                                        # "<git> [-c]" / git-config already
            c.host(h)
        for d_ in sub.danger:
            c.add(*d_.split(":", 1)) if ":" in d_ else c.add(d_)


def _git_config_set(args, cwd, home, c, depth, project):
    """rt2810 (RT-CODE-NET): `git config [--global ...] core.sshCommand "curl https://h"` / `url.<base>.insteadOf` / `alias.x '!..'`:
    the value is scanned like the one of `git -c` (the setting itself is the danger git-config already, see _git)."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 1 + (args[i] in ("-C", "-c", "--git-dir", "--work-tree"))
    if i >= len(args) or args[i] != "config":
        return
    rest = args[i + 1:]
    ops, j = [], 0
    while j < len(rest):
        a = rest[j]
        if a in ("-f", "--file", "--blob", "--type", "--default", "--comment", "--value", "--fixed-value") and j + 1 < len(rest):
            j += 2
            continue
        if a.startswith("-"):
            if a in ("--get", "--get-all", "--get-regexp", "--get-urlmatch", "--unset", "--unset-all", "-l", "--list", "--remove-section",
                     "--rename-section", "--show-origin", "--show-scope", "-e", "--edit"):
                return
            j += 1
            continue
        ops.append(a)
        j += 1
    if ops[:1] == ["set"]:
        ops = ops[1:]
    elif ops[:1] in (["get"], ["list"], ["unset"], ["edit"], ["rename-section"], ["remove-section"]):
        return
    if len(ops) >= 2:
        _git_kv("%s=%s" % (ops[0], ops[1]), cwd, home, c, depth, project, urls_any=False)


def _git(args, cwd, home, c):
    i = 0
    while i < len(args) and args[i].startswith("-"):        # git -C dir, -c k=v
        i += 1 + (args[i] in ("-C", "-c", "--git-dir", "--work-tree"))
    if i >= len(args):
        return
    sub, rest = args[i], args[i + 1:]
    short, long_ = _flags(rest)
    ops = _operands(rest)
    for k, a in enumerate(rest):                             # git diff/log/show/format-patch --output=FILE, -o DIR: a write
        if a.startswith("--output=") or a.startswith("--output-directory="):
            _write_target(a.split("=", 1)[1], cwd, home, c, c.writes)
        elif a in ("--output", "--output-directory") or (a == "-o" and sub == "format-patch"):
            if k + 1 < len(rest):
                _write_target(rest[k + 1], cwd, home, c, c.writes)
    if sub == "config":                                  # 0.2.9: sets a program git runs later (core.fsmonitor, diff.*.textconv, alias.*, ...)
        key = ops[1] if ops[:1] == ["set"] and len(ops) > 1 else (ops[0] if ops else "")
        reading = short & {"l"} or long_ & {"--list", "--get", "--get-all", "--get-regexp", "--get-urlmatch", "--show-origin", "--show-scope",
                                             "--unset", "--unset-all"} or ops[:1] in (["get"], ["list"], ["unset"])
        if ops[:1] == ["edit"] or short & {"e"} or "--edit" in long_:
            c.add("git-config", "config --edit")
        elif not reading and GIT_EXEC_KEY.fullmatch(key):
            c.add("git-config", "config " + key)
    if sub in ("push", "pull", "fetch", "clone", "ls-remote") or (sub == "remote" and ops[:1] == ["update"]) or (sub == "submodule" and ops[:1] == ["update"]):
        c.add("net-out", "git %s %s" % (sub, " ".join(ops)[:80]))
    elif sub == "archive" and any(a.startswith("--remote") or a.startswith("--exec") for a in rest):
        c.add("net-out", "git archive " + " ".join(rest)[:80])       # 10.11 (r0260): --remote fetches (and --exec runs) on another host         # 0.2.90 (G2, spec v0.1 out-3): every non-loopback exit is a gate
    if sub == "push":
        if "f" in short or long_ & {"--force", "--force-with-lease", "--force-if-includes", "--mirror", "--delete", "--prune"} or "d" in short \
                or any(o.startswith("+") or o.startswith(":") for o in ops[1:]):
            c.add("git-force-push", " ".join(ops) or "(default remote)")      # 0.2.88: + --prune (deletes remote refs not here)
    elif sub == "reset" and "--hard" in long_:
        c.add("git-destroy", "reset --hard " + " ".join(ops))
    else:
        d = _git_destroy(sub, rest, short, long_, ops)
        if d:
            c.add("git-destroy", d)


def _git_destroy(sub, rest, short, long_, ops):
    """0.2.88 (git-scm.com/docs): a git command that loses state for good -> a short detail, else None. Lost for good = what no reflog
    keeps: uncommitted changes of the whole work tree / the index, untracked files, the stash, a ref deleted together with its own reflog,
    the reflog itself, unreachable objects pruned now. Not here (reflog keeps the old tip for gc.reflogExpire, 90 days; the work tree is untouched or git
    refuses to overwrite local changes): reset --soft / --mixed / --keep, rebase (also -i with dropped commits, --skip, --abort), commit
    --amend, branch -d / -f / -m, switch -c / -C, checkout -b / -B / <branch>, cherry-pick, revert, merge, stash push / pop / apply,
    restore --staged alone, rm (refuses modified files) / rm --cached, update-ref <ref> <new>, gc without --prune=now, worktree remove (refuses
    a dirty worktree). git push is remote (asked anyway in the strict sandbox); its force forms are git-force-push."""
    dd = rest[rest.index("--") + 1:] if "--" in rest else []
    if sub == "reset" and "--merge" in long_:
        return "reset --merge " + " ".join(ops)                     # resets the index and the files that differ: staged changes are lost
    if sub == "clean" and not ("n" in short or "--dry-run" in long_):
        return "clean " + " ".join(rest)                             # -f (or clean.requireForce=false): untracked files are deleted
    # Per-file `git checkout -- <file>` / `git checkout <file>` / `git restore <file>` are NOT here: the 0.2.53 light-write forms the owner's
    # mandate lists ("git checkout", "git restore"), judged path by path (_lw_git) like `rm <file>` or an overwrite of it; a directory, a
    # glob, pathspec magic, -f, --source with paths outside the project are variants there and asked anyway. Here: the whole tree at once.
    whole = [o for o in (ops + dd) if o in (".", "./", ":/", ":/.", "*")]
    if sub == "checkout":
        if whole:
            return "checkout ."
        if "f" in short or "--force" in long_:
            return "checkout --force"                                # throws away every local change when switching
        return None
    if sub == "restore":
        staged_only = (("S" in short or "--staged" in long_) and not ("W" in short or "--worktree" in long_))
        if whole and not staged_only:
            return "restore ."                                       # every uncommitted change of the work tree
        return None
    if sub == "switch" and ("f" in short or long_ & {"--force", "--discard-changes"}):
        return "switch --discard-changes"
    if sub == "branch" and ("D" in short or ("d" in short or "--delete" in long_) and ("f" in short or "--force" in long_)):
        return "branch -D " + " ".join(ops)                          # an unmerged branch: its reflog goes with it
    if sub == "branch" and ("M" in short or "C" in short or (long_ & {"--move", "--copy"} or short & {"m", "c"})
                            and ("f" in short or "--force" in long_)):
        return "branch -M " + " ".join(ops)                          # overwrites an existing branch (and drops its reflog)
    if sub == "tag" and ("d" in short or "--delete" in long_ or "f" in short or "--force" in long_):
        return "tag -d/-f " + " ".join(ops)                          # tags have no reflog
    if sub in ("filter-branch", "filter-repo"):
        return sub
    if sub == "reflog" and ops[:1] in (["expire"], ["delete"]):
        return "reflog " + ops[0]
    if sub == "stash" and ops[:1] in (["drop"], ["clear"]):
        return "stash " + ops[0]
    if sub == "gc" and any(a.startswith("--prune=") and a.split("=", 1)[1] in ("now", "all") for a in rest):
        return "gc --prune=now"                                      # unreachable objects (what the reflog could still reach) go now
    if sub == "prune" and not ("n" in short or "--dry-run" in long_):
        return "prune"
    if sub == "repack" and "d" in short and "a" in short and "A" not in short and "--keep-unreachable" not in long_:
        return "repack -a -d"                                        # unreachable packed objects are dropped
    if sub == "update-ref" and ("d" in short or "--stdin" in long_):
        return "update-ref -d"                                       # the ref and its reflog (--stdin: the commands are not visible)
    if sub == "symbolic-ref" and ("d" in short or "--delete" in long_):
        return "symbolic-ref -d"
    if sub == "worktree" and ops[:1] == ["remove"] and ("f" in short or "--force" in long_):
        return "worktree remove --force"                             # a dirty worktree with untracked files is deleted
    if sub == "merge" and "--abort" in long_:
        return "merge --abort"                                       # docs: may be unable to reconstruct the pre-merge local changes
    if sub == "rm" and ("f" in short or "--force" in long_) and "--cached" not in long_:
        return "rm --force " + " ".join(ops)                         # removes files with uncommitted changes
    if sub == "mv" and ("f" in short or "--force" in long_):
        return "mv --force " + " ".join(ops)                         # overwrites the destination
    if sub == "checkout-index" and ("f" in short or "--force" in long_):
        return "checkout-index --force"
    if sub == "read-tree" and "--reset" in long_ and "u" in short:
        return "read-tree --reset -u"
    return None


def _raw_scan(cmd: str, c: Command) -> None:
    m = SQL_DROP.search(cmd)
    if m:
        c.add("sql-drop", m.group(0).strip(" ;\"'"))
    m = RAW_PIPE_SHELL.search(cmd)
    if m:
        c.add("pipe-to-shell", m.group(0))
    for seg in re.split(r"[;&\n]", cmd):                 # `curl ... | sh`: a fetch piped straight into an interpreter (linear time)
        parts = seg.split("|")
        for a, b in zip(parts, parts[1:]):
            if b and PIPE_INTO.match(b) and PIPE_FROM.search(a):
                c.add("pipe-to-shell", (a.strip() + " | " + b.strip())[:DETAIL_MAX])
                break
    if re.search(r"\b(base64|openssl\s+(enc|base64)|xxd|uudecode|gunzip|zcat|gzip\s+-\w*d)\b[^|]*\|\s*(sudo\s+)?(\S*/)?(ba|z|da|k)?sh\b", cmd, re.I):
        c.add("pipe-to-shell", "decoded data | sh")


def _network(name, args, ops, c):
    """Hosts a command talks to. A host hidden in a variable makes the line opaque (cannot be judged by domain)."""
    if name in FETCHERS or (name == "git" and ops[:1] and ops[0] in ("clone", "fetch", "pull", "push", "ls-remote", "remote", "submodule")) \
            or name in ("pip", "pip3", "npm", "npx", "yarn", "pnpm", "uv", "go", "cargo", "docker", "podman", "kubectl", "helm"):
        for a in args:
            for m in URL_RE.finditer(a):
                c.host(m.group(2).strip("[]"))
        if name in FETCHERS and not c.net:
            vals, skip = [], False                       # operands that are not values of an option (-o FILE, -H HDR, -d DATA ...)
            for a in args:
                if skip:
                    skip = False
                    continue
                if re.fullmatch(r"-[A-Za-z]*[oOdHuXTFAebcKmwxEr]", a) or a in CURL_VALUE_LONG:
                    skip = True
                    continue
                if not a.startswith("-"):
                    vals.append(a)
            bare = [o for o in vals if not URL_RE.search(o) and re.fullmatch(r"([\w.-]+\.[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3}|localhost)(:\d+)?(/\S*)?", o)]   # 0.2.90: + IPv4, localhost
            for o in bare:                                   # curl example.com/path (no scheme)
                c.host(re.split(r"[:/]", o, maxsplit=1)[0])
            if any(re.search(r"\$|`", o) for o in ops) and not c.net:
                c.opaque = True
                c.add("opaque", "%s to a host from a variable" % name)
    elif name in REMOTE_SHELLS:
        tgt = []
        if name in ("ssh", "mosh", "sftp", "telnet", "ftp", "nc", "ncat", "netcat"):
            skip_next = set("bcDEeFIiJLlmOopQRSWw") if name in ("ssh", "sftp") else set("pswiq")
            i = 0
            while i < len(args):
                a = args[i]
                if a.startswith("-") and len(a) > 1:
                    i += 1 + (len(a) == 2 and a[1] in skip_next)
                    continue
                tgt.append(a)
                break
        else:                                                    # scp / rsync: [user@]host:path operands
            tgt = [o.split(":", 1)[0] for o in ops if re.match(r"[^/]*:", o) and not o.startswith("/")]
        for t in tgt:
            h = t.rsplit("@", 1)[-1]
            if re.search(r"[$`]", h):
                c.opaque = True
                c.add("opaque", "%s to a host from a variable" % name)
            elif h:
                c.host(h)


# ---- 0.2.90: gates G1-G4 of a standing mandate (`unlisted: "allow"`; spec mandate-receipt-v0.1 6.5) ----------------------------------
def _deep_inside(p: str, project, home=None) -> bool:
    """A literal path strictly inside the project (not its root, not its .git) or inside a temp directory: the mandate's own delete targets."""
    if not isinstance(p, str):
        return False
    if temp_in(p, home):
        return True
    if not project or not _in_project(p, project) or p.rstrip("/") == project.rstrip("/"):
        return False
    return not re.search(r"(^|/)\.git(/|$)", p[len(project.rstrip("/")):])


def _decoded(name, text):
    """`base64 -d` of a literal the line shows -> the text, or None."""
    import base64
    import binascii
    try:
        raw = re.sub(r"\s+", "", text)
        b = base64.b32decode(raw + "=" * (-len(raw) % 8)) if name == "base32" else base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False)
        t = b.decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    return t if "\x00" not in t else None


QUIET_ON = "(quiet mode on) "      # 0.2.92 (r0262): the danger detail of the agent's `--setup-strict --yes` (qwords: plain words)
WITNESS_STATE_FLAGS = frozenset({"--trust", "--undo", "--undo-strict", "--setup-strict", "--force", "--reset", "--uninstall"})   # 0.2.91
WITNESS_READ_ONLY = frozenset({"--quiet-offer", "--quiet-no", "--doctor", "--help", "-h"})   # r0263: deus-witness-hook alone with one of these
CRON_LIKE = {"crontab"}          # `at now -f f.sh` runs a job now (a listed carrier in rt6); the 0.2.82 sandbox gate keeps `at` as an exit
FIND_WRITERS = {"rm", "rmdir", "unlink", "shred", "mv", "cp", "tee", "chmod", "chown", "truncate", "install", "ln", "touch", "dd", "sed", "perl", "sh", "bash", "zsh", "python3", "python", "node"}
LAUNCH_SUBS = {"load", "unload", "bootstrap", "bootout", "enable", "disable", "submit", "kickstart", "setenv", "unsetenv", "remove", "start", "stop", "attach"}
INSTALLERS = {"pip": {"install", "download"}, "pip3": {"install", "download"}, "pipx": {"install", "upgrade", "run"}, "uv": {"add", "sync", "lock", "tool"},
              "npm": {"install", "i", "add", "ci", "update", "up", "upgrade", "exec"}, "pnpm": {"install", "i", "add", "update", "up", "dlx"},
              "yarn": {"add", "install", "up", "upgrade", "dlx"}, "cargo": {"add", "install", "update", "fetch"}, "go": {"get", "install", "mod"},
              "gem": {"install", "update"}, "bundle": {"install", "update"}, "brew": {"install", "upgrade", "tap", "update", "cask"},
              "composer": {"install", "require", "update"}, "poetry": {"add", "install", "update", "lock"}, "conda": {"install", "update", "create"},
              "mamba": {"install", "update", "create"}, "apt": {"install", "update", "upgrade"}, "apt-get": {"install", "update", "upgrade"},
              "nix": {"profile", "shell", "run"}, "deno": {"install", "add"}, "bun": {"add", "install", "x"}}
KEYCHAIN_OPS = {"find-generic-password", "find-internet-password", "find-key", "find-identity", "dump-keychain", "export", "unlock-keychain",
                "add-generic-password", "add-internet-password", "set-generic-password-partition-list"}
LOOPBACK = re.compile(r"^(localhost|127(\.\d{1,3}){3}|::1|\[::1\]|0\.0\.0\.0)$", re.I)
CURL_WRITING = re.compile(r"^(-[a-zA-Z]*[dTF][a-zA-Z]*|--data(-\w+)?|--data(-\w+)?=.*|--upload-file(=.*)?|--form(-string)?(=.*)?|--json(=.*)?|-X|--request(=.*)?)$")

# 06.11 (r0260, friction: `curl -s localhost:8000/health` asked 4 times a day). Local services that even a GET can harm, or that hand out
# secrets / files to a GET: such a loopback URL is the danger `loopback-write` (asked) whatever the list says -- a listed curl too. Every
# other loopback GET is judged as before (and may run in the strict sandbox: hookjudge/sandbox.loopback_get_line).
LOCAL_DANGER_PORTS = {
    9222: "a browser's debugging port (CDP)", 9223: "a browser's debugging port (CDP)", 9224: "a browser's debugging port (CDP)",
    9333: "a browser's debugging port (CDP)", 9229: "the Node.js inspector", 9230: "the Node.js inspector",
    2375: "the Docker API", 2376: "the Docker API", 2379: "etcd (keys)", 2380: "etcd", 4001: "etcd (keys)", 8500: "Consul (keys)",
    8200: "Vault (secrets)", 6443: "the Kubernetes API", 8001: "kubectl proxy (the cluster's secrets)", 10250: "the kubelet", 10255: "the kubelet",
    6379: "Redis", 11211: "memcached", 8888: "Jupyter (files and terminals)", 8889: "Jupyter (files and terminals)"}
LOCAL_DANGER_PATH = re.compile(r"(?i)^/+(?:json(?:[/?#]|$)|devtools(?:[/?#]|$)|api/(?:contents|terminals|kernels|sessions)(?:[/?#]|$)|"
                               r"v1/(?:kv|secret|acl|agent)(?:[/?#]|$)|v2/keys(?:[/?#]|$)|api/v1/(?:namespaces|secrets)(?:[/?#]|$)|actuator(?:[/?#]|$))")
LOCAL_SECRET_PATH = re.compile(r"(?i)(?:^|/)\.(?:ssh|aws|gnupg|kube|docker|netrc|npmrc|pypirc|git-credentials|env|claude\.json|credentials)"
                               r"(?:[/?#.]|$)|id_(?:rsa|ed25519|ecdsa|dsa)|credentials|cookies|login[ _]data|keychain")
LOOPBACK_URL = re.compile(r"^(?:(https?)://)?(?:([^@/\s]*)@)?(localhost|127(?:\.\d{1,3}){3}|\[::1\]|0\.0\.0\.0)(?::(\d{1,5}))?([/?#].*)?$", re.I)


def loopback_url(arg):
    """-> (scheme, userinfo, host, port, path) when `arg` is a URL of this machine (`http://localhost:8000/x`, `127.0.0.1:3000`), else None."""
    m = LOOPBACK_URL.match(arg) if isinstance(arg, str) else None
    if not m:
        return None
    sch = (m.group(1) or "http").lower()
    port = int(m.group(4)) if m.group(4) else (443 if sch == "https" else 80)
    return sch, m.group(2), m.group(3).lower(), port, m.group(5) or "/"


def loopback_harm(u):
    """-> why a GET to this local URL (loopback_url) is not harmless, or None."""
    from urllib.parse import unquote
    _, _, _, port, path = u
    if port in LOCAL_DANGER_PORTS:
        return LOCAL_DANGER_PORTS[port]
    p = path
    for _ in range(3):                                   # %2e%73%73%68 is .ssh
        p = unquote(p)
    if LOCAL_DANGER_PATH.search(p.split("?", 1)[0].split("#", 1)[0]) or LOCAL_DANGER_PATH.search(p):
        return "a debugging / admin endpoint (%s)" % p.split("?", 1)[0][:40]
    if LOCAL_SECRET_PATH.search(p):
        return "a path that names a secret"
    return None


def _gates(name, args, ops, short, long_, cwd, home, c):
    """G2 (egress) / G3 (secrets) / G4 (persistence) for the commands the 0.2.88 classifier let through under `unlisted: allow`
    (spec v0.1 6.5: `pip install`, `security find-generic-password`, `crontab -`, `launchctl load`, `claude plugin disable`)."""
    if name in CRON_LIKE:
        if not (name == "crontab" and (short & {"l"} and not short & {"r", "e"} and not ops)):
            c.add("persist", "%s %s" % (name, " ".join(args)[:60]))         # crontab -l (list) is a read; -, -e, -r, FILE change the table
        return
    if name == "launchctl":
        if ops and ops[0] in LAUNCH_SUBS:
            c.add("persist", "launchctl " + " ".join(ops)[:60])
        return
    if name == "claude":
        # 0.2.91: with CLAUDE_CONFIG_DIR set in the line to another directory (a test configuration), the change is to THAT one: asked
        kind = "witness" if (_frame() or {}).get("alt_cfg") else "persist"
        if ops[:1] == ["plugin"] and ops[1:2] and ops[1] in ("disable", "enable", "install", "uninstall", "remove", "update", "add", "marketplace"):
            c.add(kind, "claude " + " ".join(ops[:3]))
        elif ops[:1] == ["mcp"] and ops[1:2] and ops[1] in ("add", "remove", "add-json", "add-from-claude-desktop"):
            c.add(kind, "claude " + " ".join(ops[:3]))
        elif ops[:1] == ["config"] and ops[1:2] and ops[1] in ("set", "add", "remove", "rm"):
            c.add(kind, "claude " + " ".join(ops[:3]))
        return
    if name in ("deus-witness", "deus-witness-hook", "deus-witness-mcp") or (name in ("uvx", "pipx") and any(re.match(r"(--from=)?deus-witness\b", a) or a == "deus-witness" for a in args)) \
            or (re.fullmatch(r"python[0-9.]*", name) and any(a == "-m" and k + 1 < len(args) and args[k + 1].startswith("deus_witness") for k, a in enumerate(args))):
        # 0.2.90 (QA Н10): the witness's own client run by the agent. 0.2.91 (friction 04.11): what rewrites the witness's own state on
        # this machine (pins, shadow copies, the strict sandbox in settings.json) stays `persist` (refused, by hand only); any other run
        # (`uvx --from deus-witness==X python -c ..` in a fresh cache, `deus-witness try` under a temporary HOME, `python -m
        # deus_witness.verify_pack`) is the danger `witness`: asked, the owner can approve it
        # 0.2.92 (r0262): `--setup-strict --yes` is the agent's fixed line for quiet mode (client 0.2.60 /deus-witness:try): the danger
        # `witness` too -- asked, the owner approves it once with the passkey (dangerous: no "from now on", no repeat), and the client's
        # lock (hook main.STRICT_SWITCH) lets it run only with that approval. --undo-strict, --trust, --undo ... stay `persist`.
        # r0263 (L3 of /deus-witness:quiet): the client's read-only lines -- the offer (`--quiet-offer`, `--setup-strict --dry-run`), the
        # doctor, the help -- and `--quiet-no` (it only stops the quiet-mode reminder: a date in a file next to the key) are no question:
        # asking the owner before SHOWING the offer, or to say "no" to it, was friction with nothing behind it.
        tail_ = args[args.index("deus-witness-hook") + 1:] if name != "deus-witness-hook" and "deus-witness-hook" in args else \
            (args if name == "deus-witness-hook" else None)
        if tail_ is not None and (tail_ in (["--setup-strict", "--dry-run"], ["--dry-run", "--setup-strict"], ["--quiet-offer", "--full"]) or
                                  (len(tail_) == 1 and tail_[0] in WITNESS_READ_ONLY)):
            return
        sflags = {a.split("=", 1)[0] for a in args} & WITNESS_STATE_FLAGS
        own = bool(sflags) and not (sflags == {"--setup-strict"} and ("--dry-run" in args or "--yes" in args))
        c.add("persist" if own else "witness", ("%s %s" % (name, " ".join(args)[:60])) if not (sflags == {"--setup-strict"} and "--yes" in args
                                                and "--dry-run" not in args) else QUIET_ON + "%s %s" % (name, " ".join(args)[:60]))
        return
    if name == "uvx" and any(a.startswith("--from") for a in args):
        pass
    if name == "security":
        if any(o in KEYCHAIN_OPS for o in ops[:1]):
            c.add("secrets", "security " + ops[0])                          # G3 (spec v0.1 sec-3): the login keychain's passwords
        return
    if name == "defaults" and ops[:1] == ["write"] and any(re.search(r"loginwindow|loginitems|LaunchAgents|com\.apple\.(dock|SystemEvents)", o, re.I) for o in ops[1:]):
        c.add("persist", "defaults write " + " ".join(ops[1:3]))
        return
    if name == "osascript" and re.search(r"login\s+item", " ".join(args), re.I):
        c.add("persist", "osascript: login item")
        return
    if name in INSTALLERS:
        sub = ops[0] if ops else ""
        if name == "uv" and ops[:2] == ["pip", "install"]:
            sub = "add"
        if name == "go" and ops[:2] == ["mod", "download"]:
            sub = "get"
        if name == "nix" and ops[:2] == ["profile", "install"]:
            sub = "profile"
        if sub in INSTALLERS[name] and not (long_ & {"--no-index", "--offline", "--no-fetch"}) and not (name in ("pip", "pip3") and any(o in (".", "-e") or o.startswith("./") for o in ops[1:]) and len(ops) <= 3):
            c.add("net-out", "%s %s" % (name, " ".join(ops[:3])[:60]))       # G2 (spec v0.1 out-5): code from the network comes in
        return
    if name in ("nslookup", "dig", "host", "ping", "ping6", "traceroute", "mtr", "whois"):
        for o in ops:
            if re.fullmatch(r"[\w.-]+\.[a-zA-Z]{2,}", o):
                c.host(o)
            elif re.search(r"[$`]", o):
                c.add("opaque", "%s to a host from a variable" % name)
        return
    if name in FETCHERS:
        for k, a in enumerate(args):                     # 06.11 (r0260): a browser's debugging port, Docker, Jupyter, a secret path ...
            v = a.split("=", 1)[1] if a.startswith("--url=") else a
            u = loopback_url(v)
            h = loopback_harm(u) if u is not None else None
            if h is not None:
                c.add("loopback-write", "%s %s:%d%s (%s)" % (name, u[2], u[3], u[4][:60], h))
    if name in FETCHERS and c.net and all(LOOPBACK.match(h) for h in c.net) and any(CURL_WRITING.match(a) and not re.fullmatch(r"-[a-zA-Z]*[sSLkvo][a-zA-Z]*", a) for a in args):
        xm = [a for k, a in enumerate(args) if k and args[k - 1] in ("-X", "--request")]
        if not xm or any(x.upper() not in ("GET", "HEAD") for x in xm):
            c.add("loopback-write", "%s %s" % (name, ", ".join(c.net)))    # FABLE-NOL p.2.6: a POST / upload to a local service (CDP, Docker ...) is asked, a GET is not


_CODE_PATH_TOK = re.compile(r"[^\s'\"`,;()\[\]{}<>|&=]+")


def _eval_code_args(name, args) -> set:
    """10.11 (r0260): the arguments of an interpreter that ARE code (`-c CODE`, `-e CODE`, `--eval=CODE`; deno: everything after `eval`),
    never a module / file option's value (`node -r ./x.js`, `perl -M`, `ruby -r`, `lua -l`: paths or names, judged as before)."""
    if name == "deno":
        return set(args[1:]) if args[:1] == ["eval"] else set()
    py = PY_MODULE.fullmatch(name) is not None
    opts = {"-c"} if py else {"-e", "-E", "--eval", "-p", "--print"} | ({"-r", "-B", "-R", "-F"} if name == "php" else set())
    bundle = re.compile(r"-[A-Za-z]*c" if py else r"-[A-Za-z]*[eE]")            # `python3 -Bc CODE`, `perl -ne CODE`
    out = set()
    for k, a in enumerate(args):
        if k and (args[k - 1] in opts or bundle.fullmatch(args[k - 1])):
            out.add(a)
        elif not py and (a.startswith("--eval=") or a.startswith("--print=")):
            out.add(a.split("=", 1)[1])                   # _one sees the option's value
    return out


def _eval_code(name, args) -> str:
    """The code string an interpreter is given on the line (`python3 -c CODE`, `node -e CODE`, `perl -e`, `ruby -e`, `deno eval CODE`)."""
    if name == "deno":
        return " ".join(args[1:])
    out = []
    for k, a in enumerate(args):
        if k and args[k - 1] in ("-c", "-e", "-E", "--eval", "-p", "--print", "-r", "-l", "-x"):
            out.append(a)
        elif a.startswith("--eval=") or a.startswith("--print="):
            out.append(a.split("=", 1)[1])
    return " ".join(out) if out else " ".join(args)


# consequence scan of interpreter code: file APIs with the path they name (literal, HOME-built, a variable the code set once, an operand)
_FS_API = re.compile(r"(?P<fn>shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir|os\.removedirs|(?<![\w.])rmtree|fs\.rmSync|fs\.rm|fs\.unlinkSync|fs\.unlink|fs\.rmdirSync|fs\.rmdir|fs\.promises\.rm|fs\.promises\.unlink|"
                     r"(?<![\w.])rimraf(?:\.sync)?|FileUtils\.rm_rf|FileUtils\.rm_r|FileUtils\.rm|File\.delete|File\.unlink|(?<![\w.])unlink|"
                     r"fs\.writeFileSync|fs\.writeFile|fs\.appendFileSync|fs\.appendFile|fs\.createWriteStream|fs\.promises\.writeFile|fs\.promises\.appendFile|fs\.copyFileSync|fs\.copyFile|fs\.renameSync|fs\.rename|"
                     r"fs\.readFileSync|fs\.readFile|fs\.createReadStream|fs\.promises\.readFile|"
                     r"shutil\.copy2?|shutil\.copyfile|shutil\.move|os\.rename|os\.replace|os\.chmod|os\.chown|os\.symlink|os\.link|"
                     r"(?<![\w.])open|io\.open|codecs\.open|File\.open|File\.write|File\.read|IO\.read|IO\.write|File\.binread|File\.binwrite|(?<![\w.])Path)\s*\(")
_PY_VAR = re.compile(r"^[ \t]*(?:const|let|var|my|our)?[ \t]*\$?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=(?!=)[ \t]*([^;\n]+?)[ \t]*;?[ \t]*$", re.M)
_RUN_API = re.compile(r"(os\.system|os\.popen|subprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)|child_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)|"
                      r"(?<![\w.])(?:execSync|spawnSync|exec|spawn|system|popen|IO\.popen|Open3\.\w+|commands\.getoutput|pty\.spawn|os\.exec[lv]p?e?|os\.spawn[lv]p?e?))\s*\(")
_DEL_FN = {"shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "os.removedirs", "rmtree", "fs.rmSync", "fs.rm", "fs.unlinkSync", "fs.unlink", "fs.rmdirSync",
           "fs.rmdir", "fs.promises.rm", "fs.promises.unlink", "rimraf", "rimraf.sync", "FileUtils.rm_rf", "FileUtils.rm_r", "FileUtils.rm", "File.delete", "File.unlink", "unlink"}
_READ_FN = {"fs.readFileSync", "fs.readFile", "fs.createReadStream", "fs.promises.readFile", "File.read", "IO.read", "File.binread"}
MAX_CODE_SCAN = 64 * 1024


def _arg_expr(code, k):
    """The first argument expression of the call whose "(" is at code[k-1] -> (text, end index) at depth 0 up to "," or ")"."""
    depth, i, q, n = 0, k, None, len(code)
    while i < n:
        ch = code[i]
        if q:
            if ch == "\\":
                i += 2
                continue
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return code[k:i].strip(), i
            depth -= 1
        elif ch == "," and depth == 0:
            return code[k:i].strip(), i
        i += 1
    return None, n


def _code_path(expr, pyvars, home, operands):
    """-> the path an argument expression names, or None (not shown: a variable, an f-string, a call, process.env.X of an unknown X)."""
    e = expr.strip()
    m = re.fullmatch(r"[rRbBuU]?(['\"])((?:(?!\1).)*)\1", e)
    if m:
        return m.group(2)
    if re.fullmatch(r"(?:os\.environ(?:\[['\"]HOME['\"]\]|\.get\(['\"]HOME['\"]\))|os\.getenv\(['\"]HOME['\"]\)|process\.env\.HOME|os\.homedir\(\)|homedir\(\)|ENV\[['\"]HOME['\"]\]|Dir\.home|Path\.home\(\)|pathlib\.Path\.home\(\))", e):
        return home
    m = re.fullmatch(r"(?:os\.path\.expanduser|expanduser|path\.expanduser)\s*\(\s*(['\"])((?:(?!\1).)*)\1\s*\)", e)
    if m:
        v = m.group(2)
        return home + v[1:] if v == "~" or v.startswith("~/") else v
    m = re.fullmatch(r"(?:os\.environ(?:\[['\"]HOME['\"]\]|\.get\(['\"]HOME['\"]\))|os\.getenv\(['\"]HOME['\"]\)|process\.env\.HOME|os\.homedir\(\)|homedir\(\)|ENV\[['\"]HOME['\"]\]|Dir\.home)"
                     r"\s*\+\s*(['\"])((?:(?!\1).)*)\1", e)
    if m:
        return home + m.group(2)
    m = re.fullmatch(r"(?:Path\.home\(\)|pathlib\.Path\.home\(\))\s*/\s*(['\"])((?:(?!\1).)*)\1", e)
    if m:
        return home + "/" + m.group(2)
    m = re.fullmatch(r"(?:os\.path\.join|path\.join)\s*\(\s*(.*)\)", e)
    if m:
        parts = [_code_path(x, pyvars, home, operands) for x in m.group(1).split(",")]
        return "/".join(p.rstrip("/") for p in parts) if parts and all(isinstance(p, str) for p in parts) else None
    m = re.fullmatch(r"(?:os\.environ(?:\[['\"](\w+)['\"]\]|\.get\(['\"](\w+)['\"]\))|os\.getenv\(['\"](\w+)['\"]\)|process\.env\.(\w+)|ENV\[['\"](\w+)['\"]\])(?:\s*\+\s*(['\"])((?:(?!\6).)*)\6)?", e)
    if m:
        v = _var_value(next(g for g in m.groups()[:5] if g))
        return (v + (m.group(7) or "")) if isinstance(v, str) else None
    m = re.fullmatch(r"(?:sys\.argv|process\.argv|ARGV)\s*\[\s*(\d+)\s*\]", e)
    if m:
        k = int(m.group(1)) - (1 if "sys" in e or "ARGV" in e else 2)
        return operands[k] if 0 <= k < len(operands) else None
    m = re.fullmatch(r"\$?([A-Za-z_][A-Za-z0-9_]*)", e)
    if m and m.group(1) in pyvars:
        rhs = pyvars[m.group(1)]
        return _code_path(rhs, {k: v for k, v in pyvars.items() if k != m.group(1)}, home, operands) if len(pyvars) < 64 else None
    parts = _split_plus(e)
    if len(parts) > 1:                                   # a + b + c: every piece must be shown
        vals = [_code_path(x, pyvars, home, operands) for x in parts]
        return "".join(vals) if all(isinstance(v, str) for v in vals) else None
    return None


def _split_plus(e):
    out, depth, q, k, i = [], 0, None, 0, 0
    while i < len(e):
        ch = e[i]
        if q:
            if ch == "\\":
                i += 1
            elif ch == q:
                q = None
        elif ch in "'\"":
            q = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "+" and depth == 0:
            out.append(e[k:i])
            k = i + 1
        i += 1
    out.append(e[k:])
    return [x.strip() for x in out]


def _code_fs_scan(code, c, who, cwd, home, project, depth, operands=()):
    """0.2.90 ("consequences, not commands"): the file system calls of interpreter code, judged by the path each names. A deletion:
    outside the project -> rm-rf (G1), inside -> a write of the mandate's targets; a write: judged like a shell redirection (secrets,
    persistence, outside); a read: a credential file -> secrets. A path the code does not show -> opaque (asked without a sandbox).
    A command the code runs (os.system, subprocess, child_process) with a literal string -> a command line of its own; else opaque."""
    _CODE[0] += 1
    try:
        if isinstance(code, str) and code not in c.code_texts:
            c.code_texts.append(code)
        _code_fs_scan1(code, c, who, cwd, home, project, depth, operands)
    finally:
        _CODE[0] -= 1


def _code_fs_scan1(code, c, who, cwd, home, project, depth, operands=()):
    if not isinstance(code, str) or not code.strip():
        return
    if isinstance(who, str) and re.fullmatch(r"python(?:[23](?:\.\d{1,2})?)?", who.rsplit("/", 1)[-1]):
        from .inline import blank_text
        code = blank_text(code)                        # 11.11 (r0260, class (в)): text literals the code WRITES are not file calls
    if len(code) > MAX_CODE_SCAN:
        c.add("opaque", "%s code of %d characters" % (who, len(code)))
        return
    code = re.sub(r"require\s*\(\s*['\"](?:node:)?fs(?:/promises)?['\"]\s*\)", "fs", code)     # require('fs').rmSync(...) -> fs.rmSync(...)
    pyvars = {}
    for m in _PY_VAR.finditer(re.sub(r";[ \t]*(?=[A-Za-z_$])", "\n", code)):          # `import sys;p=sys.argv[1];s=...`: one statement per line
        pyvars[m.group(1)] = None if m.group(1) in pyvars else m.group(2)      # the right-hand side, read by _code_path when used
    pyvars = {k: v for k, v in pyvars.items() if isinstance(v, str)}
    ops = list(operands)
    for m in _FS_API.finditer(code):
        fn = m.group("fn")
        expr, a_end = _arg_expr(code, m.end())
        if expr is None:
            c.add("opaque", "%s code: %s( not closed" % (who, fn))
            continue
        kind = "delete" if fn in _DEL_FN else "read" if fn in _READ_FN else "write" if fn not in ("open", "io.open", "codecs.open", "File.open", "Path") else None
        if kind is None:                               # open(path, mode): the mode decides; Path(x).unlink() / .write_text() / .read_text()
            tail = code[m.end():m.end() + 400]
            # RT-0259 (release 0.2.59): the mode is read AFTER the whole first argument (`open(os.path.expanduser('~/x'), 'w')`: a path
            # expression with its own parentheses hid the mode, and the write was taken for a read)
            tail = "x" + code[a_end:a_end + 400] if fn != "Path" and a_end < len(code) and code[a_end] == "," else tail
            mode = re.match(r"[^,)]*,\s*(?:mode\s*=\s*)?(['\"])([rwaxb+t]*)\1", tail)
            if fn == "Path":
                after = re.match(r"[^)]*\)\s*\.\s*(unlink|rmdir|write_text|write_bytes|read_text|read_bytes|open|touch|mkdir|rename|replace|chmod)\b", tail)
                if not after:
                    continue
                kind = {"unlink": "delete", "rmdir": "delete", "write_text": "write", "write_bytes": "write", "touch": "write", "mkdir": "write",
                        "rename": "write", "replace": "write", "chmod": "write", "read_text": "read", "read_bytes": "read"}.get(after.group(1))
                if after.group(1) == "open":
                    md = re.search(r"open\s*\(\s*(?:mode\s*=\s*)?(['\"])([rwaxb+t]*)\1", tail)
                    kind = "write" if md and re.search(r"[wax+]", md.group(2)) else "read"
            elif mode is not None:
                kind = "write" if re.search(r"[wax+]", mode.group(2)) else "read"
            elif re.match(r"[^,)]*,\s*['\"]", tail) or re.match(r"[^,)]*,\s*(?:mode|flags)\s*=", tail):
                kind = "write"                         # a mode we cannot read: fail closed
            elif fn == "File.open":
                kind = "read"
            else:
                kind = "read"
        if kind is None:
            continue
        path = _code_path(expr, pyvars, home, ops)
        if path is None:
            if kind == "delete":
                c.add("opaque", "%s code: %s with a path not shown (%s)" % (who, fn, expr[:40]))
            elif kind == "write":
                c.add("opaque", "%s code: write to a path not shown (%s)" % (who, expr[:40]))
            else:
                c.add("opaque", "%s code: read of a path not shown (%s)" % (who, expr[:40]))
            continue
        if path == "~" or path.startswith("~/"):
            path = home + path[1:]
        if kind == "delete":
            c.rm_judged += 1
            p_ = _abspath(path, cwd, home)
            if _deep_inside(p_, project, home):
                c.delete(p_)
            else:
                c.add("rm-rf", "%s(%s)" % (fn, p_))
        elif kind == "write":
            _write_target(path, cwd, home, c, c.writes)
        else:
            p_ = _abspath(path, cwd, home)
            if is_secret_path(path) or is_secret_path(p_):
                c.add("secrets", p_)
    for m in _RUN_API.finditer(code):
        expr, _ = _arg_expr(code, m.end())
        lit = re.fullmatch(r"[rRbBuUf]?(['\"])((?:(?!\1).)*)\1", expr or "")
        if lit and not expr.startswith("f"):
            _merge(c, classify(lit.group(2), cwd, home, depth + 1, project, _budget=c.budget))
            continue
        if expr is not None and expr.startswith("["):
            words = re.findall(r"(['\"])((?:(?!\1).)*)\1", expr)
            if words and len(words) == len([x for x in expr.strip("[]").split(",") if x.strip()]):
                _merge(c, classify(" ".join(shlex.quote(w[1]) for w in words), cwd, home, depth + 1, project, _budget=c.budget))
                continue
        c.add("opaque", "%s code runs a command not shown (%s)" % (who, (expr or "")[:40]))
