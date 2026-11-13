"""RT6 (28.10): ONE registry of "what runs code". Before, five tables disagreed (actions.CODE_RUNNERS / RUNNERS, bashparse SHELLS /
INTERPRETERS / RUN_CODE / MAKE_RUNNERS, execguard.EXECUTORS): the written-run rule looked at two of them and let 104 of 126 runners pass
after a risky write (cloud/RT-6-RANNERY-2810.md). Every table is built from here now.

Three questions this module answers:
  * is_python(name)       -- python, python3.12, python2, pypy3 ... (one expression, execguard's _PY_RE)
  * runs_code(head, line) -- after a risky write: does this command head run code? INVERTED (RT6): any head runs code EXCEPT the explicit
                             list of heads that do not (NOT_RUNNERS: the default read-only list, the local writes, static analysers, readers
                             whose exec flags are checked). An unknown program is a run: the list of runners can never be complete (m4,
                             erb, gnuplot, sqlite3, ed are languages too), the list of non-runners can.
  * children(name, args)  -- the command lines a program carries and runs (`arch -arm64 python3 f.py`, `hyperfine 'python3 f.py'`,
                             `fd -x python3`, `git submodule foreach 'cmd'`): the parser judges each as a command of its own, so the owner's
                             permission for the carrier never covers the child.
"""
import re

PY_RE = re.compile(r"(python|pypy)[0-9.]*")             # execguard._PY_RE is this object

# ---------------------------------------------------------------- interpreters and shells
# shells whose `-c STRING` is a shell line the parser reads (bashparse SHELLS)
POSIX_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "busybox", "ash", "mksh", "yash"})
OTHER_SHELLS = frozenset({"csh", "tcsh", "pwsh", "powershell", "nu", "xonsh", "elvish", "rc", "es", "cmd"})
SHELLS = POSIX_SHELLS | OTHER_SHELLS
# interpreters with code given on the line (bashparse INTERPRETERS: their -e / -c code is scanned)
EVAL_INTERPRETERS = frozenset({"python", "python3", "node", "nodejs", "perl", "ruby", "php", "deno", "bun"})
# interpreters whose first operand is a script file (bashparse RUN_CODE)
SCRIPT_INTERPRETERS = frozenset({
    "tsx", "ts-node", "ts-node-dev", "esno", "babel-node", "vite-node", "Rscript", "R", "lua", "luajit", "tclsh", "wish", "expect",
    "osascript", "pwsh", "powershell", "julia", "groovy", "elixir", "escript", "erl", "swift", "kotlin", "kotlinc", "scala", "nodejs",
    "irb", "jshell", "java", "jruby", "jython", "ipython", "racket", "guile", "sbcl", "clisp", "ghc", "runghc", "runhaskell", "stack",
    "ocaml", "crystal", "nim", "dart", "zig", "perl6", "raku", "php-cgi", "hhvm", "cscript", "wscript", "csi",
    "dotnet-script", "pypy", "pypy3", "python2", "m4", "erb", "gnuplot", "octave", "matlab", "maxima", "sage"})
INTERPRETERS = EVAL_INTERPRETERS | SCRIPT_INTERPRETERS
MAKE_RUNNERS = frozenset({"make", "gmake", "bmake", "pmake"})
# build / test / task / package runners and servers: they run the project's code or code named in its files
TASK_RUNNERS = frozenset({
    "pytest", "py.test", "tox", "nox", "npm", "npx", "yarn", "pnpm", "pnpx", "bun", "bunx", "corepack", "cmake", "ninja", "cargo", "go",
    "mvn", "mvnw", "gradle", "gradlew", "ant", "poetry", "pipenv", "hatch", "pdm", "uv", "uvx", "pipx", "rake", "bundle", "just", "task",
    "jest", "vitest", "mocha", "ava", "karma", "cypress", "playwright", "xargs", "parallel", "watch", "eval", "pushd", "popd", "bazel",
    "bazelisk", "buck", "buck2", "pants", "meson", "scons", "waf", "xcodebuild", "xcrun", "sbt", "mill", "lein", "mix", "rebar3", "dotnet",
    "msbuild", "snakemake", "invoke", "inv", "doit", "fab", "turbo", "nx", "lerna", "rush", "vite", "webpack", "rollup", "esbuild", "parcel",
    "next", "nuxt", "astro", "gatsby", "remix", "sphinx-build", "mkdocs", "latexmk", "pdflatex", "xelatex", "lualatex", "latex", "tex",
    "eslint", "prettier", "stylelint", "pre-commit", "coverage", "uvicorn", "gunicorn", "hypercorn", "daphne", "flask", "django-admin",
    "streamlit", "gradio", "nodemon", "jupyter", "ipython", "papermill", "nbconvert", "conda", "mamba", "micromamba", "pixi", "cabal", "stack",
    "composer", "gem", "pod", "fastlane", "vagrant", "nix", "nix-shell", "nix-build", "direnv", "ansible", "ansible-playbook", "terraform",
    "pulumi", "docker", "docker-compose", "podman", "act", "rustup", "husky", "lint-staged", "pandoc", "sqlite3", "psql", "mysql",
    "vim", "vi", "nvim", "view", "ex", "emacs", "ed", "gdb", "lldb", "valgrind", "perf", "dtruss", "dtrace", "strace", "ltrace",
    # RT7: static analysers that IMPORT project code named in their config (mypy plugins, pylint load-plugins / init-hook, flake8
    # local-plugins / --append-config, pyright's venv interpreter, markdownlint custom rules): runs, not NOT_RUNNERS (see below)
    "mypy", "dmypy", "pylint", "flake8", "pyright", "basedpyright", "markdownlint", "markdownlint-cli2", "lefthook", "commitlint", "overcommit",
    # execguard.EXECUTORS names (a test keeps every executor known here)
    "brew", "bundler", "code", "cpack", "ctest", "devcontainer", "devenv", "gitlab-runner", "grunt", "gulp", "iex", "muon", "nix-env",
    "nuxi", "pip", "pip3", "postcss", "rails", "rspec", "sphinx-autobuild", "svelte-kit", "tailwindcss", "nuxt", "esbuild", "parcel",
    "stylelint", "cypress", "karma", "lerna", "gatsby", "remix", "zig", "msbuild", "bazelisk", "rustup", "husky", "lint-staged", "act"})
# programs that run a command they are given: the child is judged on its own (children() below)
CARRIERS = frozenset({
    "arch", "xcrun", "sandbox-exec", "rlwrap", "script", "tmux", "screen", "at", "batch", "hyperfine", "watchexec", "entr", "gdb", "lldb",
    "valgrind", "perf", "dtruss", "conda", "mamba", "micromamba", "pixi", "nix-shell", "direnv", "fd", "fdfind", "tar", "zip", "man",
    "firejail", "bwrap", "systemd-run", "unshare", "chroot", "nsenter", "flatpak-spawn", "su", "runuser", "time", "hyperfine", "poetry",
    "pipenv", "pdm", "hatch", "uv", "bundle", "npx", "pnpm", "yarn", "bunx", "pnpx", "uvx", "pipx", "mise", "asdf", "rtx", "dotenv",
    "op", "doppler", "infisical", "chamber", "aws-vault", "with-contenv", "catchsegv", "faketime", "torify", "tsp", "ts", "parallel",
    "nohup", "setsid", "nice", "timeout"})
# the old wrapper words of actions.RUNNERS (they carry a command: the line is a run)
WRAPPER_WORDS = frozenset({"source", ".", "exec", "env", "nohup", "nice", "timeout", "time", "sudo", "doas"})

ALL_RUNNERS = SHELLS | INTERPRETERS | MAKE_RUNNERS | TASK_RUNNERS | CARRIERS - {"tar", "zip", "man", "time"}


def is_python(name):
    return bool(PY_RE.fullmatch(name or ""))


def is_interpreter(name):
    """A shell or an interpreter of code / a script (python2, pypy3, nodejs, julia ...)."""
    return name in SHELLS or name in INTERPRETERS or is_python(name)


def is_runner(name):
    """Any program the registry knows to run code (interpreters, shells, build / test / task runners, carriers)."""
    return is_interpreter(name) or name in ALL_RUNNERS


# ---------------------------------------------------------------- the inverted written-run rule: what does NOT run code
# The default read-only list (mapping.DEFAULT_SAFE_COMMANDS, single words), the local writes (bashparse LW_CMDS) and static analysers that
# parse and do not import (ruff, black, isort, flake8, mypy, pylint, tsc ...: RT5 decision). `find` runs code only with -exec (checked);
# sed / awk / jq: their code-running forms (-f script, system(), e command) are asked by the parser's own tags (TX), not by this rule.
NOT_RUNNERS = frozenset({
    "ls", "pwd", "cd", "cat", "head", "tail", "wc", "echo", "printf", "grep", "egrep", "fgrep", "rg", "which", "type", "whereis", "file",
    "stat", "du", "df", "date", "uname", "diff", "tree", "sort", "uniq", "cut", "tr", "nl", "column", "basename", "dirname", "realpath",
    "readlink", "sha1sum", "sha256sum", "sha512sum", "shasum", "md5sum", "md5", "cksum", "cmp", "comm", "test", "[", "true", "false",
    "sleep", "find", "sed", "awk", "jq", "yq", "less", "more", "bat", "batcat", "tac", "rev", "xxd", "od", "hexdump", "strings", "base64",
    "base32", "paste", "join", "fold", "fmt", "pr", "split", "expand", "unexpand", "iconv", "wait", "export", "unset", "set", "read",
    "printenv", "id", "whoami", "hostname", "uptime", "ps", "pgrep", "lsof", "free", "vm_stat", "sw_vers", "locale", "tput", "clear",
    "mkdir", "touch", "cp", "mv", "ln", "chmod", "rm", "rmdir", "tee", "gzip", "gunzip", "zcat", "bzip2", "bunzip2", "xz", "unxz", "zstd",
    "unzip", "tar", "zip", "man", "curl", "wget", "rsync", "install", "dd", "truncate", "cmp", "patch",
    "ruff", "black", "isort", "tsc", "shellcheck", "gofmt", "rustfmt", "clang-format", "yamllint", "codespell", "git",
    # 29.10 (OTCHET-SHUM-ZHIVYE-2910 §5.1, 27 of 88 new questions): shell keywords the parser reports as heads. The commands of a loop /
    # if / group body are reported as heads of their own (`for i in 1; do python3 f.py; done` -> for, python3), `time` and `!` are
    # stripped before the command they prefix. seq / kill run no code. NOT here: eval, exec, source, ., coproc, trap (they run code).
    "for", "while", "until", "do", "done", "if", "then", "else", "elif", "fi", "case", "esac", "break", "continue", "function",
    "{", "}", "[[", "]]", "!", "time", "seq", "kill"})
# RT7 (28.10): mypy / pylint / flake8 / pyright / markdownlint LEFT this list. Each imports code its configuration names (mypy.ini plugins,
# .pylintrc load-plugins / init-hook, setup.cfg [flake8:local-plugins], pyrightconfig.json venv -> runs that python, --rules ./r.js). The
# server sees a config's digest, never its text, so "does the config name a plugin" cannot be decided here without a client release; and a
# rule "a config of the tool exists" is the same as removal (pyproject.toml / setup.cfg are in nearly every project). Cost: one question per
# risky write when one of them runs next (the "once" rule). ruff / black / isort / tsc do not import project code: they stay.

# RT7: GNU tools installed with a g prefix (Homebrew coreutils / findutils / gnu-tar / gnu-sed / gnu-time): `gtimeout 5 make` is `timeout`
G_PREFIXED = frozenset({
    "timeout", "nice", "nohup", "stdbuf", "env", "xargs", "time", "chroot", "split", "csplit", "install", "tar", "sort", "find", "sed", "ls",
    "cat", "head", "tail", "wc", "cut", "tr", "uniq", "readlink", "realpath", "stat", "du", "df", "date", "dd", "cp", "mv", "ln", "rm",
    "mkdir", "rmdir", "chmod", "touch", "tee", "basename", "dirname", "sha1sum", "sha256sum", "sha512sum", "md5sum", "base64", "base32",
    "echo", "printf", "test", "nl", "od", "paste", "join", "fold", "fmt", "pr", "tac", "comm", "cmp", "diff", "expand", "unexpand",
    "truncate", "whoami", "id", "uname", "pwd", "sleep", "true", "false"})


def canon(name):
    """`gtimeout` -> `timeout`, `gsplit` -> `split` (only the GNU tools above; `gawk`, `gdb`, `git` stay)."""
    n = name or ""
    return n[1:] if n[:1] == "g" and n[1:] in G_PREFIXED else n
# the git sub-commands that run a program they are given (`git bisect run CMD`, `git submodule foreach CMD`, `git difftool -x CMD`,
# `git rebase --exec CMD`, `git filter-branch --tree-filter CMD`); every other git sub-command is a read or a write of the repository
# (git runs only the programs its config names: gitcfg / execguard cover those)
GIT_RUN_SUBS = frozenset({"bisect", "submodule", "difftool", "mergetool", "filter-branch", "filter-repo", "rebase", "instaweb", "web--browse"})
# readers whose options can name a program: such a form is a run.
# RT7: a long option is matched as GNU getopt_long reads it -- any prefix at least as long as the shortest UNAMBIGUOUS one
# (`tar --to-comm=CMD` is --to-command). The minimum is taken on the short side (a shorter prefix only asks more, never lets one pass).
# {program: {long option without "--": minimum prefix length}}
READER_LONG = {
    "tar": {"to-command": 4, "use-compress-program": 2, "checkpoint-action": 11, "info-script": 3, "new-volume-script": 4,
            "rsh-command": 2, "rmt-command": 2},
    "zip": {"unzip-command": 3},
    "man": {"pager": 3, "html": 2, "config-file": 2},
    "sort": {"compress-program": 2},
    "less": {"lesskey-file": 3, "lesskey-src": 3, "lesskey-content": 3},   # 2910: less 668 (--lesskey was the pre-668 name)
    "curl": {"config": 6},
    "wget": {"execute": 3, "use-askpass": 5},
    "rsync": {"rsh": 2, "rsync-path": 2},
    "bat": {"pager": 4},
    "split": {"filter": 1},
    "install": {"strip-program": 6},
}
READER_SHORT = {
    "tar": r"^-[A-Za-z]*[IF]",
    "zip": r"^-TT",
    "man": r"^-[A-Za-z]*[PHC]",
    "less": r"^-k|^\+.*[!|]",                       # less '+!cmd' / '+|cmd': a start-up command that runs a shell
    "curl": r"^-K",
    "wget": r"^-e",
    "rsync": r"^-[A-Za-z]*e",
    "find": r"^-(exec|execdir|ok|okdir)$",
    "rg": r"^--pre(=|$)",
}


def _long_rx(opt, mn):
    """`--` + any prefix of `opt` at least `mn` characters long, then `=` or the end of the word."""
    frag = ""
    for ch in reversed(opt[mn:]):
        frag = "(?:" + re.escape(ch) + frag + ")?"
    return "^--" + re.escape(opt[:mn]) + frag + "(?:=|$)"


def long_hit(word, opt, mn=None):
    """Does `word` (`--to-comm=x`, `--to-command`) name the long option `opt` (`--to-command`) as getopt_long would read it?"""
    if not (isinstance(word, str) and word.startswith("--") and opt.startswith("--")):
        return False
    w = word.split("=", 1)[0][2:]
    o = opt[2:]
    return bool(w) and o.startswith(w) and len(w) >= (len(o) if mn is None else mn)


READER_EXEC = {n: re.compile("|".join([_long_rx(o, m) for o, m in READER_LONG.get(n, {}).items()]
                                      + ([READER_SHORT[n]] if n in READER_SHORT else [])))
               for n in sorted(set(READER_LONG) | set(READER_SHORT))}
_OLD_TAR = re.compile(r"[A-Za-z]*[IF][A-Za-z]*")      # `tar xIf CMD a.tar`: the old key (first operand, no dash) with I / F


def _reader_exec(first, words):
    rx = READER_EXEC.get(first)
    ws = [w for w in words if isinstance(w, str)]
    if rx and any(rx.search(w) for w in ws):
        return True
    if first == "tar":
        for k, w in enumerate(ws[:-1]):
            if canon(w.rsplit("/", 1)[-1]) == "tar" and _OLD_TAR.fullmatch(ws[k + 1]):
                return True
    return False


# RT7 (28.10): git runs the hooks of the repository. After a risky write, a git sub-command is a run when the exec report shows a hook it
# fires (a hook may call the file the agent just rewrote: `.git/hooks/pre-commit: python3 f.py`). {hook name: sub-commands that fire it}
_COMMIT_SUBS = ("commit", "merge", "pull", "cherry-pick", "revert", "am", "rebase")
_REF_SUBS = _COMMIT_SUBS + ("fetch", "checkout", "switch", "branch", "tag", "reset", "stash", "update-ref", "push", "worktree", "clone",
                            "remote", "replace", "notes", "symbolic-ref", "restore")
GIT_HOOK_SUBS = {
    "pre-commit": _COMMIT_SUBS, "prepare-commit-msg": _COMMIT_SUBS, "commit-msg": _COMMIT_SUBS, "post-commit": _COMMIT_SUBS,
    "pre-merge-commit": ("merge", "pull"), "post-rewrite": ("commit", "rebase", "pull", "am"),
    "applypatch-msg": ("am",), "pre-applypatch": ("am",), "post-applypatch": ("am",),
    "pre-rebase": ("rebase", "pull"), "post-checkout": ("checkout", "switch", "clone", "worktree", "rebase", "pull"),
    "post-merge": ("merge", "pull"), "pre-push": ("push",), "pre-auto-gc": ("gc",) + _COMMIT_SUBS + ("fetch",),
    "reference-transaction": _REF_SUBS,
    "post-index-change": ("add", "status", "commit", "checkout", "switch", "reset", "restore", "rm", "mv", "stash", "merge", "pull",
                          "rebase", "cherry-pick", "revert", "am", "update-index", "read-tree", "apply"),
    "sendemail-validate": ("send-email",), "push-to-checkout": ("push",), "pre-receive": ("push",), "update": ("push",),
    "post-receive": ("push",), "post-update": ("push",), "proc-receive": ("push",),
}
# project files of hook managers: when present, their hooks are taken as installed (pre-commit, lint-staged, lefthook, husky ...)
HOOK_MANAGER_HOOKS = ("pre-commit", "commit-msg", "pre-push", "post-checkout", "post-merge")
SYS_BIN = ("/bin/", "/usr/bin/", "/usr/local/bin/", "/opt/homebrew/bin/", "/usr/sbin/", "/sbin/")


def head_runs_code(head, words=(), git_hooks=None):
    """RT6: a command head of the line (the parser's identifier: "git status", "cat [env X]", "./x", "sudo ls") runs code? `words`: the
    words of its simple command when known (checked for the exec flags of readers). Everything not on NOT_RUNNERS runs code.
    RT7: `git_hooks` = the names of the hooks the exec report shows (None: no report): a git sub-command that fires one is a run."""
    h = head.split(" [", 1)[0].strip("'\"\\")
    if not h:
        return False
    first = canon(h.split(" ", 1)[0])
    if first.startswith("-") or "=" in first.split("/", 1)[0]:
        return False
    if " [" in head:                                 # a variant ("cat [env LD_PRELOAD]", "sed [exec]", "rg [pre]"): not the plain reader
        tags = head.split(" [", 1)[1]
        if re.search(r"\b(env|exec|eval|pre|via|-c|fetch|net)\b", tags):
            return True
    if "/" in first:
        b = first.rsplit("/", 1)[-1]
        return not (first.startswith(SYS_BIN) and first.count("/") <= 4 and b in NOT_RUNNERS and b != "git")
    if first == "git":
        sub = h.split(" ", 2)[1] if " " in h else ""
        if sub in GIT_RUN_SUBS:
            return True
        return any(sub in GIT_HOOK_SUBS.get(k, ()) for k in (git_hooks or ()))
    if first not in NOT_RUNNERS:
        return True
    return _reader_exec(first, words)


# ---------------------------------------------------------------- children: the command a program carries
# options with a value, per carrier (skipped before the child); options that take a COMMAND STRING; sub-commands after which the child starts
_OPTV = {
    "arch": {"-arch", "-e", "-d"}, "xcrun": {"-sdk", "--sdk", "-toolchain", "--toolchain"}, "sandbox-exec": {"-f", "-n", "-p", "-D"},
    "rlwrap": {"-a", "-b", "-C", "-D", "-e", "-f", "-g", "-H", "-l", "-M", "-N", "-O", "-p", "-P", "-q", "-s", "-S", "-t", "-w", "-z"},
    "screen": {"-S", "-c", "-e", "-h", "-L", "-Logfile", "-p", "-s", "-T", "-t", "-X"}, "script": {"-F", "-T", "-t", "-c", "--command", "-E", "--echo", "-I", "-O", "-B", "--log-in", "--log-out", "--log-io"},
    "valgrind": set(), "perf": {"-e", "-o", "-p", "-t", "-C", "-r", "-G", "-x", "-I", "-c", "-F", "--event", "--output"},
    "dtruss": {"-p", "-n", "-t", "-W"}, "entr": set(), "watchexec": {"-w", "--watch", "-e", "--exts", "-f", "--filter", "-i", "--ignore",
    "-d", "--debounce", "-s", "--signal", "--stop-signal", "--stop-timeout", "--delay-run", "--project-origin", "--workdir", "-E", "--env",
    "--on-busy-update", "--emit-events-to", "--shell", "--filter-file", "--ignore-file", "-W", "--watch-non-recursive"},
    "conda": {"-n", "--name", "-p", "--prefix", "--cwd"}, "mamba": {"-n", "--name", "-p", "--prefix", "--cwd"},
    "micromamba": {"-n", "--name", "-p", "--prefix", "--cwd"}, "pixi": {"-e", "--environment", "--manifest-path"},
    "firejail": set(), "bwrap": {"--bind", "--ro-bind", "--dev-bind", "--proc", "--dev", "--tmpfs", "--chdir", "--setenv", "--unsetenv",
    "--symlink", "--dir", "--file", "--uid", "--gid", "--hostname"}, "systemd-run": {"-u", "--unit", "-p", "--property", "-E",
    "--setenv", "--working-directory", "--uid", "--gid", "--slice", "-M", "--machine", "-H", "--host"},
    "unshare": {"--map-user", "--map-group", "--setuid", "--setgid", "--wd", "--root"}, "nsenter": {"-t", "--target", "-S", "-G", "-w", "-r"},
    "chroot": {"--userspec", "--groups"}, "su": {"-s", "--shell", "-g", "--group"}, "runuser": {"-u", "--user", "-g", "--group", "-s"},
    "flatpak-spawn": {"--env", "--directory"}, "faketime": {"-m", "-f"}, "catchsegv": set(), "with-contenv": set(),
    "aws-vault": {"--duration", "--region"}, "doppler": {"-p", "--project", "-c", "--config"}, "op": {"--env-file", "--account"},
    "infisical": {"--env", "--projectId", "--path"}, "chamber": set(), "dotenv": {"-f", "-e", "-v"}, "torify": set(), "tsp": set(),
    "mise": {"-C", "--cd", "-E", "--env"}, "asdf": set(), "rtx": set(), "at": {"-q", "-f", "-t"}, "batch": {"-q", "-f"},
}
# option -> takes a COMMAND STRING (run by a shell) or starts a child argv ("argv": the rest of the line after it is the child)
_CMD_OPTS = {
    "fd": {"-x": "argv", "--exec": "argv", "-X": "argv", "--exec-batch": "argv"}, "fdfind": {"-x": "argv", "--exec": "argv", "-X": "argv",
    "--exec-batch": "argv"},
    "nix-shell": {"--run": "str", "--command": "str"}, "tar": {"--to-command": "str", "--use-compress-program": "str", "-I": "str",
    "--info-script": "str", "--new-volume-script": "str", "-F": "str", "--rsh-command": "str"},
    "zip": {"-TT": "str", "--unzip-command": "str"}, "man": {"-P": "str", "--pager": "str", "-H": "str", "--html": "str"},
    "hyperfine": {"-p": "str", "--prepare": "str", "-s": "str", "--setup": "str", "-c": "str", "--cleanup": "str", "--conclude": "str",
                  "-S": "str", "--shell": "str"},
    "gdb": {"--args": "argv", "-ex": "gdbcmd", "-eval-command": "gdbcmd", "--eval-command": "gdbcmd", "-iex": "gdbcmd"},
    "lldb": {"--": "argv", "-o": "gdbcmd", "--one-line": "gdbcmd", "-O": "gdbcmd", "--one-line-before-file": "gdbcmd", "-k": "gdbcmd"},
    "script": {"-c": "str", "--command": "str"}, "su": {"-c": "str", "--command": "str"}, "runuser": {"-c": "str", "--command": "str"},
    "watchexec": {"--": "argv", "--shell": "str"}, "screen": {"-X": "str"}, "flock": {"-c": "str"}, "systemd-run": {"--": "argv"},
    # RT7: readers' options that name a program (bat --pager, split --filter, install --strip-program, tar --rmt-command ...)
    "bat": {"--pager": "str"}, "batcat": {"--pager": "str"}, "split": {"--filter": "str"}, "install": {"--strip-program": "str"},
    "doppler": {"--command": "str"}, "nodemon": {"--exec": "str", "-x": "str"},
}
_CMD_OPTS["tar"]["--rmt-command"] = "str"
_CMD_OPTS["tar"]["--checkpoint-action"] = "str"
# RT7: the shortest prefix getopt_long accepts for a long option of _CMD_OPTS (READER_LONG; default: the whole name)
_LONG_MIN = {(n, "--" + o): m for n, d in READER_LONG.items() for o, m in d.items()}
# RT7: options whose value is a command (`nodemon --exec=CMD`, `doppler run --command CMD`, `watch --on-change=CMD`) on ANY program
_CMDISH_OPT = re.compile(r"--?(exec|execute|command|cmd|call|run-command|script|hook|on-[a-z-]+|pre-command|post-command|before|after|setup|"
                         r"cleanup|teardown|prepare|conclude|watch-command|shell-command|program|prog|pager|editor|filter|signal-command)")
# RT7: the first operand of an unknown program is its child when it is a runner (`dbus-run-session make`); not for these (they name a
# program as data: `info make`, `pkill make`, `brew install make`)
_NAMES_PROGRAMS = frozenset({"info", "whatis", "apropos", "tldr", "help", "port", "apt", "apt-get", "apt-cache", "dnf", "yum", "pacman",
                             "zypper", "apk", "choco", "winget", "scoop", "kill", "pkill", "killall", "pidof", "complete", "compdef",
                             "alias", "unalias", "hash", "open", "xdg-open", "brew", "mas", "snap", "flatpak", "asdf", "mise", "rtx"})
_DURATION = re.compile(r"[0-9][0-9.]*[smhd]?|0x[0-9a-fA-F]+")
# gdb / lldb commands (-ex / -o values): they take any unambiguous PREFIX (`she make` is `shell make`, `pla sh` is `platform shell`), so a
# name regex is not enough. A value is safe only when its first word is on this list and nothing in it can reach a shell or an
# interpreter ($_shell(), python, pipes, sub-command lists); any other value is judged as a command line of its own (asked).
_GDB_SAFE = frozenset({"run", "r", "start", "starti", "continue", "c", "next", "n", "step", "s", "stepi", "si", "nexti", "ni", "finish",
                       "bt", "backtrace", "where", "info", "i", "frame", "f", "up", "down", "list", "l", "break", "b", "tbreak", "delete",
                       "d", "disable", "enable", "watch", "thread", "set", "show", "quit", "q", "kill", "k", "detach", "file", "core-file",
                       "handle", "ptype", "whatis", "disassemble", "help", "h", "until", "p", "print", "x", "display",
                       "image", "breakpoint", "br", "register", "memory", "di", "exit", "version", "settings", "process", "fr"})
_DBG_DANGER = re.compile(r"[$|`!(;]|\b(sh|she|shel|shell|pi|py|pyt|pyth|pytho|python|python-interactive|guile|gu|script|scr|scri|scrip|"
                         r"command|com|comm|comma|comman|commands|platform|pla|plat|platf|platfo|platfor|pipe|source|so|sou|make|eval|"
                         r"define|alias|launch-shell|stop-hook|add-symbol-file|target)\b", re.I)
_DBG_SHELLISH = ("shell", "platform", "pipe", "python", "python-interactive", "pi", "script", "!", "|")


def _dbg_child(val):
    """A gdb / lldb command -> the command line it may run, or None (a safe command)."""
    w = val.split()
    if not w:
        return None
    if w[0] in _GDB_SAFE and not _DBG_DANGER.search(val):
        return None
    i = 0
    while i < len(w) and any(x.startswith(w[i].lower()) and (len(w[i]) >= 2 or w[i] in "!|") for x in _DBG_SHELLISH):
        i += 1                                             # `she make`, `pla sh make`, `pi import os`: the rest is what runs
    if i == 0:
        return val                                         # an unknown / unsafe command: the whole value is judged (asked)
    return " ".join(w[i:]) or "sh"
# (rg --pre, sort --compress-program, git grep -O: the parser tags them already, "rg [--pre]" is asked; no child needed)
# a sub-command after which the rest is the child argv / a command string
_SUBS = {
    ("conda", "run"): "argv", ("mamba", "run"): "argv", ("micromamba", "run"): "argv", ("pixi", "run"): "argv", ("pixi", "exec"): "argv",
    ("direnv", "exec"): "dir+argv", ("perf", "stat"): "argv", ("perf", "record"): "argv", ("perf", "trace"): "argv", ("poetry", "run"): "argv",
    ("pipenv", "run"): "argv", ("pdm", "run"): "argv", ("hatch", "run"): "argv", ("uv", "run"): "argv", ("bundle", "exec"): "argv",
    ("mise", "exec"): "argv", ("mise", "x"): "argv", ("asdf", "exec"): "argv", ("rtx", "exec"): "argv", ("op", "run"): "argv",
    ("doppler", "run"): "argv", ("infisical", "run"): "argv", ("chamber", "exec"): "argv", ("aws-vault", "exec"): "prof+argv",
    ("tmux", "new-session"): "tmux", ("tmux", "new"): "tmux", ("tmux", "new-window"): "tmux", ("tmux", "neww"): "tmux",
    ("tmux", "split-window"): "tmux", ("tmux", "splitw"): "tmux", ("tmux", "run-shell"): "tmux", ("tmux", "run"): "tmux",
    ("tmux", "send-keys"): "tmux", ("tmux", "send"): "tmux", ("tmux", "respawn-pane"): "tmux", ("tmux", "respawn-window"): "tmux",
    ("tmux", "display-popup"): "tmux", ("tmux", "popup"): "tmux", ("tmux", "pipe-pane"): "tmux", ("tmux", "if-shell"): "tmux",
    ("tmux", "if"): "tmux",
    ("nix", "develop"): "nixc", ("nix", "shell"): "nixc", ("nix", "print-dev-env"): "nixc",     # RT7: `nix develop -c CMD`
}
_TMUX_OPTV = {"-t", "-s", "-n", "-c", "-e", "-F", "-x", "-y", "-l", "-p", "-w", "-h", "-d", "-E", "-b", "-T", "-N", "-X", "-H"}
_TMUX_FLAGS = {"-d", "-P", "-h", "-v", "-b", "-f", "-l", "-R", "-k", "-a", "-A", "-D", "-E", "-X", "-M", "-H", "-Z", "-o", "-I", "-K"}
# whole remaining argv is the child (after the carrier's own options)
_ARGV_CARRIERS = {"arch", "xcrun", "sandbox-exec", "rlwrap", "valgrind", "dtruss", "entr", "screen", "firejail", "bwrap", "unshare", "nsenter",
                  "chroot", "flatpak-spawn", "faketime", "catchsegv", "with-contenv", "torify", "tsp", "ts", "chamber", "dotenv", "systemd-run"}
_GIT_CHILD = {"bisect": ("run", "argv"), "submodule": ("foreach", "str"), "rebase": (("-x", "--exec"), "str"),
              "difftool": (("-x", "--extcmd", "-t", "--tool"), "str"), "mergetool": (("-t", "--tool"), "str"),
              "filter-branch": (("--tree-filter", "--index-filter", "--env-filter", "--msg-filter", "--commit-filter", "--parent-filter",
                                 "--tag-name-filter", "--subdirectory-filter"), "str")}
_WS = re.compile(r"\s")
# hyperfine options -> how many values follow (every operand is a benchmarked command line)
_HYPERFINE_V = {o: 1 for o in ("-w", "--warmup", "-m", "--min-runs", "-M", "--max-runs", "-r", "--runs", "-p", "--prepare", "-s", "--setup",
                               "-c", "--cleanup", "--conclude", "-S", "--shell", "-u", "--time-unit", "--export-asciidoc", "--export-csv",
                               "--export-json", "--export-markdown", "--export-orgmode", "--style", "-n", "--command-name", "--sort",
                               "-D", "--parameter-step-size", "--output", "--input", "--reference")}
_HYPERFINE_V.update({"-L": 2, "--parameter-list": 2, "-P": 3, "--parameter-scan": 3})


def _q(w):
    return w if re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", w) else "'" + w.replace("'", "'\"'\"'") + "'"


def _argv_line(ws):
    if len(ws) == 1 and _WS.search(ws[0]):
        return ws[0]                                     # `entr -s 'cmd'`, `screen -dm 'cmd'`: one word that is a command line
    return " ".join(_q(w) for w in ws)


def _skip_opts(args, optv, i=0):
    """Index of the first operand: options of the carrier (with their values) skipped; `--` ends them."""
    while i < len(args):
        a = args[i]
        if a == "--":
            return i + 1
        if not a.startswith("-") or a == "-":
            return i
        if a in optv and "=" not in a:
            i += 2
            continue
        i += 1
    return i


def _looks_like_command(s):
    """A string argument that is a command line: its first word is a known runner / shell / interpreter or a program by path."""
    w = s.strip().split()
    if not w:
        return False
    h = w[0].rsplit("/", 1)[-1]
    return is_runner(h) or "/" in w[0] and not w[0].startswith(("http:", "https:")) or h in ("eval", "source", ".", "exec", "env", "sudo")


def children(name, args):
    """-> [command line] the program `name` (with `args`) runs as a child. Explicit carriers are read with their syntax; any other program
    is scanned generically: a word that is a known interpreter / shell / runner (`foo --x python3 f.py`) starts a child argv, and an argument
    that is a command line (`foo 'python3 f.py'`) is a child. Data commands (NOT_RUNNERS except the readers' exec flags) carry nothing."""
    args = [a for a in args if isinstance(a, str)]
    name = canon(name)                                    # RT7: gtimeout / gsplit / gtar are the GNU tools
    out = []
    if name == "git":
        i = 0
        while i < len(args) and args[i].startswith("-"):
            i += 1 + (args[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"))
        if i >= len(args) or args[i] not in _GIT_CHILD:
            return []
        sub, rest = args[i], args[i + 1:]
        key, kind = _GIT_CHILD[sub]
        if isinstance(key, str):
            if key in rest:
                k = rest.index(key) + 1
                while k < len(rest) and rest[k].startswith("-"):
                    k += 1                                 # git submodule foreach --recursive 'cmd'
                tail = rest[k:]
                if tail:
                    out.append(" ".join(tail) if kind == "str" else _argv_line(tail))
            return out
        for k, a in enumerate(rest):
            for o in key:
                if a == o and k + 1 < len(rest):
                    out.append(rest[k + 1])
                elif a.startswith(o + "=") and o.startswith("--"):
                    out.append(a.split("=", 1)[1])
                elif not o.startswith("--") and a.startswith(o) and len(a) > len(o):
                    out.append(a[len(o):])
        return out
    if name in NOT_RUNNERS:
        opts = _CMD_OPTS.get(name)
        if opts:
            out += _opt_children(name, args, opts)
        if name == "tar" and args and _OLD_TAR.fullmatch(args[0]):
            out += _old_tar(args)
        if name == "less":
            out += [a[2:] or "sh" for a in args if re.match(r"\+[!|]", a)]   # less '+!cmd'
        return list(dict.fromkeys(out))
    if is_interpreter(name) or name in WRAPPER_WORDS:
        return []                                         # their operands are scripts / their own syntax (the parser reads them)
    opts = _CMD_OPTS.get(name, {})
    out += _opt_children(name, args, opts)
    if name not in TASK_RUNNERS:
        out += _cmdish_children(args, opts)               # RT7: `--exec=CMD`, `--command CMD` of an unknown program (the parser tags go -exec ...)
    first = 0
    if name == "tmux":                                    # RT7: tmux's own options before the sub-command (`tmux -c CMD`, `tmux -L s new`)
        while first < len(args) and args[first].startswith("-") and args[first] != "--":
            a = args[first]
            if a == "-c" and first + 1 < len(args):
                out.append(args[first + 1])
                first += 2
            elif a.startswith("-c") and len(a) > 2:
                out.append(a[2:])
                first += 1
            elif a in ("-L", "-S", "-f", "-T"):
                first += 2
            else:
                first += 1
    sub = next((a for a in args[first:] if not a.startswith("-")), None)
    mode = _SUBS.get((name, sub))
    if mode:
        k = args.index(sub, first) + 1
        if mode == "tmux":
            out += _tmux(args[k:])
        elif mode == "nixc":
            for j in range(k, len(args)):
                if args[j] in ("-c", "--command"):
                    if j + 1 < len(args):
                        out.append(_argv_line(args[j + 1:]))
                    break
        else:
            k = _skip_opts(args, _OPTV.get(name, set()), k)
            if mode in ("dir+argv", "prof+argv"):
                k += 1
            if k < len(args):
                out.append(_argv_line(args[k:]))
        return out
    if name == "xcrun" and any(a in ("-f", "--find", "--show-sdk-path", "--show-sdk-version", "--show-sdk-platform-path",
                                      "--show-sdk-build-version", "--show-toolchain-path", "--version", "-h", "--help") for a in args):
        return out                                        # xcrun -f clang: prints the path, runs nothing
    if name in _ARGV_CARRIERS:
        k = _skip_opts(args, _OPTV.get(name, set()))
        if k < len(args):
            out.append(_argv_line(args[k:]))
        return out
    if name == "script":
        k = _skip_opts(args, _OPTV["script"])
        if k + 1 < len(args):
            out.append(_argv_line(args[k + 1:]))           # macOS: script [-q] FILE CMD ...
        return out
    if name == "hyperfine":
        k, ops = 0, []
        while k < len(args):
            a = args[k]
            if a in _HYPERFINE_V:
                k += 1 + _HYPERFINE_V[a]
                continue
            if not a.startswith("-"):
                ops.append(a)
            k += 1
        return out + ops
    if name == "watchexec" and "--" not in args:
        k = _skip_opts(args, _OPTV["watchexec"])
        if k < len(args):
            out.append(_argv_line(args[k:]) if len(args) - k > 1 or not _WS.search(args[k]) else args[k])
        return out
    if name in ("at", "batch"):
        return out
    if "--" in args and name not in TASK_RUNNERS:
        k = args.index("--") + 1
        if k < len(args) and (is_runner(args[k].rsplit("/", 1)[-1]) or "/" in args[k]):
            out.append(_argv_line(args[k:]))
            return out
    # RT7: the first operand of an unknown program that is a runner starts its child (`dbus-run-session make`, `foo 5 make`)
    if name not in TASK_RUNNERS and name not in _NAMES_PROGRAMS and name not in CARRIERS:
        k = 0
        while k < len(args) and (args[k].startswith("-") or _DURATION.fullmatch(args[k])):
            k += 1
        if k < len(args) and not re.search(r"[\s/]", args[k]) and is_runner(canon(args[k])) and not is_interpreter(args[k]):
            out.append(_argv_line(args[k:]))
            return list(dict.fromkeys(out))
    # generic: a known runner word starts a child argv; a command-line string argument is a child
    for k, a in enumerate(args):
        if a.startswith("-"):
            continue
        b = a.rsplit("/", 1)[-1]
        if _WS.search(a) and _looks_like_command(a):
            out.append(a)
        elif is_interpreter(b) and k + 0 < len(args):
            out.append(_argv_line(args[k:]))
            break
    return out


def _old_tar(args):
    """`tar xIf CMD a.tar` / `tar cFf CMD a.tar x`: the old key's letters take their values in order from the next words."""
    takes = set("fbCFgIKLNTVXH")
    out, j = [], 1
    for ch in args[0]:
        if ch in takes:
            if j < len(args) and ch in "IF":
                out.append(args[j])
            j += 1
    return out


def _cmdish_children(args, known):
    """RT7: `--exec=CMD` / `--command CMD` (an option named like a command) of any program: the value is a child when it is a command line,
    a runner or a program by path. Options of the program's own table (`known`) are read there."""
    out = []
    for k, a in enumerate(args):
        if not a.startswith("-"):
            continue
        o, eq, v = a.partition("=")
        if o in known or not _CMDISH_OPT.fullmatch(o):
            continue
        if not eq:
            if k + 1 >= len(args) or args[k + 1].startswith("-"):
                continue
            v = args[k + 1]
        w = v.strip().split()
        if w and (_looks_like_command(v) or is_runner(canon(w[0].rsplit("/", 1)[-1])) or "/" in w[0]):
            out.append(v)
    return out


def _opt_children(name, args, opts):
    out = []
    k = 0
    while k < len(args):
        a = args[k]
        for o, kind in opts.items():
            val = None
            if a == o or (o.startswith("--") and "=" not in a and long_hit(a, o, _LONG_MIN.get((name, o)))):
                if kind == "argv":
                    rest = args[k + 1:]
                    if name in ("fd", "fdfind") and ";" in rest:
                        rest = rest[:rest.index(";")]
                    if rest:
                        out.append(_argv_line(rest))
                    return out
                if k + 1 < len(args):
                    val = args[k + 1]
            elif o.startswith("--") and "=" in a and long_hit(a, o, _LONG_MIN.get((name, o))):
                val = a.split("=", 1)[1]
            elif not o.startswith("--") and len(o) == 2 and a.startswith(o) and len(a) > 2 and a[:2] != "--":
                val = a[2:]
            if val is not None:
                if kind == "gdbcmd":
                    ch = _dbg_child(val)
                    if ch is not None:
                        out.append(ch)
                elif name == "tar" and o == "--checkpoint-action":
                    if val.startswith("exec="):
                        out.append(val[5:])
                else:
                    out.append(val)
                break
        k += 1
    return out


def _tmux(rest):
    """tmux new-session / split-window / run-shell / send-keys ...: the shell command is the operands after the options."""
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--":
            i += 1
            break
        if not a.startswith("-") or a == "-":
            break
        if a in _TMUX_OPTV and a not in _TMUX_FLAGS and i + 1 < len(rest):
            i += 2
            continue
        if len(a) > 2 and a[:2] in _TMUX_OPTV and a[:2] not in _TMUX_FLAGS:
            i += 1
            continue
        i += 1
    ops = [w for w in rest[i:] if w not in ("Enter", "C-m", "KPEnter")]
    if not ops:
        return []
    return [" ".join(ops)]
