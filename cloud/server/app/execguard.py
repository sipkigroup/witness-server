"""0.2.13 (PROPOSAL-08): escalation after a change of a file that commands EXECUTE (conftest.py, package.json, Makefile, build.rs, .git/hooks ...).

The problem (external review 2026-10-19): the owner's list or "allow in this project" lets `pytest`, `npm test`, `make` run without a question;
they run code from the project's own files, and the agent can edit those files. After such a file changes, the next command that executes it
is asked again, whatever the list or an allowance say: the gateway puts `exec_changed` (the changed files) into the action, and the core
decides defer ESCALATE_EXEC_CHANGED (svidetel_v4/decide.py, spec/PROPOSAL-08-exec.md). The receipt and the approval page name the files.

State per agent (tables exec_files, exec_roots):
  - "dirty": every write the witness ALLOWED (or the owner approved) to such a path: Write / Edit / MultiEdit / NotebookEdit / Bash.write /
    Write.danger. This needs nothing from the hook beyond the paths it already sends;
  - "ok" + digest: the version the owner confirmed. The hook (0.2.13) reports `_witness.exec` = {root, files: {relative path: sha256}, truncated}
    before each shell command in a project; a digest that differs from the confirmed one, or a file that was not there, is a change. This catches
    what the witness did not see as a write (an interpreter, `git checkout`, a test that rewrites conftest.py, a human edit).
  - the first report of a project (root) is taken as confirmed (trust on first use), except files already marked dirty, and except git's
    configuration when it names a program git runs (0.2.46: `gitcfg`, GITCFG below): that is asked before the first git command.
Confirmation: when an action that carried `exec_changed` is CONSUMED (the owner approved it and the agent ran it), the reported digests of those
files become the confirmed ones (a file no longer reported is forgotten).
0.2.16: the tables below exist only on the server (app/hookjudge/execfiles.py uses them; the hook gets a signed list of file shapes, scan_list())."""
import hashlib
import json
import os
import re
import time
import unicodedata

from app.hookjudge import runners as _runners

# ---------------------------------------------------------------- which file belongs to which family (what executes it)
# 0.2.14 (R8-01): every name and directory is compared after NFC + casefold (macOS APFS and Windows NTFS open PACKAGE.JSON as package.json),
# trailing dots/spaces dropped (Windows); the tables hold the folded forms. (R8-02): more files of the declared ecosystems; a DIRS rule with
# "**" takes every file below that directory at any depth, "*" only its direct children.
NAMES = {
    # Python: pytest / tox / nox / pip / linters with plugins / the interpreter itself
    "conftest.py": ("py",), "pytest.ini": ("py",), ".pytest.ini": ("py",), "pytest.toml": ("py",), ".pytest.toml": ("py",), "tox.ini": ("py",),
    "tox.toml": ("py",), "setup.cfg": ("py",), "pyproject.toml": ("py",), "setup.py": ("py",), "noxfile.py": ("py",), "sitecustomize.py": ("py",),
    "usercustomize.py": ("py",), "pylintrc": ("py",), ".pylintrc": ("py",), "mypy.ini": ("py",), ".mypy.ini": ("py",), ".flake8": ("py",),
    ".coveragerc": ("py",), "tasks.py": ("py",), "hatch.toml": ("py",),
    # JavaScript: npm / pnpm / yarn lifecycle scripts and settings
    "package.json": ("js",), ".npmrc": ("js",), ".yarnrc": ("js",), ".yarnrc.yml": ("js",), ".pnpmfile.cjs": ("js",), ".pnp.cjs": ("js",),
    ".pnp.loader.mjs": ("js",), "pnpm-workspace.yaml": ("js",),
    # make / just / task
    "makefile": ("make",), "gnumakefile": ("make",), "justfile": ("make",), ".justfile": ("make",),
    # Rust / Go
    "build.rs": ("cargo",), "cargo.toml": ("cargo",), "rust-toolchain": ("cargo",), "rust-toolchain.toml": ("cargo",), "go.mod": ("go",), "go.work": ("go",),
    # JVM: the wrapper scripts execute THEMSELVES (./gradlew, ./mvnw)
    "build.gradle": ("gradle",), "build.gradle.kts": ("gradle",), "settings.gradle": ("gradle",), "settings.gradle.kts": ("gradle",),
    "gradle.properties": ("gradle",), "gradle-wrapper.properties": ("gradle",), "gradlew": ("gradle",), "gradlew.bat": ("gradle",),
    "pom.xml": ("maven",), "mvnw": ("maven",), "mvnw.cmd": ("maven",),
    # git: attributes name filters / diff drivers; pre-commit runs from a git hook
    ".gitattributes": ("git",), ".pre-commit-config.yaml": ("git", "py"),
    # containers, CI, editor tasks
    "dockerfile": ("docker",), "containerfile": ("docker",), "compose.yaml": ("docker",), "compose.yml": ("docker",),
    "devcontainer.json": ("docker", "editor"), ".devcontainer.json": ("docker", "editor"), ".gitlab-ci.yml": ("ci",),
    # RT6 (28.10): configuration files that ARE code (evaluated by the tool that reads them; audit RT-6 §3.4: families_of_path() was empty)
    "package.swift": ("swift",), "gemfile": ("bundler",), "gems.rb": ("bundler",), "rakefile": ("rake",), "rakefile.rb": ("rake",),
    "vagrantfile": ("vagrant",), "brewfile": ("brew",), "podfile": ("pod",), "fastfile": ("fastlane",), "appfile": ("fastlane",),
    "mix.exs": ("mix",), "build.sbt": ("sbt",), "directory.build.props": ("dotnet",), "directory.build.targets": ("dotnet",),
    "build.bazel": ("bazel",), "workspace": ("bazel",), "workspace.bazel": ("bazel",), "module.bazel": ("bazel",),
    ".bazelrc": ("bazel",), "meson.build": ("meson",), "meson_options.txt": ("meson",), "meson.options": ("meson",),
    "sconstruct": ("scons",), "sconscript": ("scons",), "snakefile": ("snakemake",), "dodo.py": ("doit", "py"), "fabfile.py": ("fab", "py"),
    # Sphinx's docs/conf.py (by name, not as a DIRS rule: execfiles._prio ranks every file under a DIRS directory first, and the agent's
    # junk in docs/ would push named files out of the bounded report); gunicorn's conf.py is code too
    "conf.py": ("sphinx", "py"), "gunicorn.conf.py": ("py",),
    "mkdocs.yml": ("mkdocs",), "mkdocs.yaml": ("mkdocs",), ".latexmkrc": ("latex",), "latexmkrc": ("latex",),
    ".envrc": ("direnv", "shell"), "shell.nix": ("nix",), "default.nix": ("nix",), "flake.nix": ("nix",), "devenv.nix": ("nix",),
    "pixi.toml": ("pixi",), ".gdbinit": ("gdb",), "gdbinit": ("gdb",), ".lldbinit": ("lldb",), ".exrc": ("vim",), ".nvimrc": ("vim",),
    ".nvim.lua": ("vim",), "cmakelists.txt": ("cmake",), "cmakepresets.json": ("cmake",), "build.zig": ("zig",), "composer.json": ("php",),
    "deno.json": ("js",), "deno.jsonc": ("js",), "bunfig.toml": ("js",), "turbo.json": ("js",), "nx.json": ("js",), "pipfile": ("py",),
    "mise.toml": ("mise",), ".mise.toml": ("mise",), "noxfile.toml": ("py",),
    # RT7 (28.10): configs of static analysers that import code (pylint init-hook / load-plugins, pyright's venv interpreter), man's
    # config (DEFINE pager), tmux's config (run-shell), git hook managers (lefthook, overcommit)
    "pylintrc.toml": ("py",), ".pylintrc.toml": ("py",), "pyrightconfig.json": ("py",), "man.conf": ("man",), "man_db.conf": ("man",),
    "manpath.config": ("man",), ".tmux.conf": ("tmux",), "tmux.conf": ("tmux",), ".overcommit.yml": ("git",),
}
PREFIXES = (("taskfile", ("make",)), ("docker-compose", ("docker",)), ("dockerfile.", ("docker",)), (".yarnrc", ("js",)),
            ("jest.config.", ("js",)), ("vitest.config.", ("js",)), ("vite.config.", ("js",)), (".mocharc", ("js",)),
            ("eslint.config.", ("js",)), (".eslintrc", ("js",)), ("babel.config.", ("js",)), (".babelrc", ("js",)),
            ("playwright.config.", ("js",)), ("webpack.config.", ("js",)), ("prettier.config.", ("js",)), (".prettierrc", ("js",)),
            # RT6: more JS tools whose config is a module they import
            ("next.config.", ("js",)), ("rollup.config.", ("js",)), ("nuxt.config.", ("js",)), ("astro.config.", ("js",)),
            ("svelte.config.", ("js",)), ("postcss.config.", ("js",)), ("tailwind.config.", ("js",)), ("esbuild.config.", ("js",)),
            ("stylelint.config.", ("js",)), (".stylelintrc", ("js",)), ("cypress.config.", ("js",)), ("karma.conf.", ("js",)),
            ("gulpfile.", ("js",)), ("gruntfile.", ("js",)), ("remix.config.", ("js",)), ("gatsby-", ("js",)),
            # RT7: hook managers whose config names commands / is a module (run from a git hook), markdownlint (custom rules, *.cjs config)
            (".lintstagedrc", ("git", "js")), ("lint-staged.config.", ("git", "js")), ("lefthook", ("git",)), (".lefthook", ("git",)),
            (".simple-git-hooks", ("git", "js")), ("simple-git-hooks.", ("git", "js")), ("commitlint.config.", ("git", "js")),
            (".commitlintrc", ("git", "js")), (".markdownlint", ("mdlint",)))
SUFFIXES = ((".pth", ("py",)), (".mk", ("make",)),
            # RT6: project files evaluated by their tools (MSBuild targets run tasks / Exec, a gemspec is Ruby, *.bzl Starlark, *.cmake CMake)
            (".csproj", ("dotnet",)), (".fsproj", ("dotnet",)), (".vbproj", ("dotnet",)), (".sln", ("dotnet",)), (".gemspec", ("bundler",)),
            (".bzl", ("bazel",)), (".cmake", ("cmake",)), (".sbt", ("sbt",)), (".smk", ("snakemake",)))
# by a directory in the path: (directory components, file test, families)
DIRS = ((".git", "config", ("git",)), (".git", "config.worktree", ("git",)), (".git/info", "attributes", ("git",)), (".git/hooks", "*", ("git",)),
        (".husky", "**", ("git",)), (".githooks", "**", ("git",)),
        (".github/workflows", "*", ("ci",)), (".cargo", "config", ("cargo",)), (".cargo", "config.toml", ("cargo",)), (".mvn", "**", ("maven",)),
        ("gradle/wrapper", "*", ("gradle",)), (".vscode", "tasks.json", ("editor",)), ("init.d", "*.gradle", ("gradle",)),
        ("init.d", "*.gradle.kts", ("gradle",)), (".yarn/releases", "*", ("js",)), (".yarn/plugins", "**", ("js",)),
        # the executables of the commands themselves inside the project (an activated virtual environment, npm's .bin) and what they import
        ("node_modules", "**", ("js",)), ("site-packages", "**", ("py",)), (".venv/bin", "*", ("py",)), ("venv/bin", "*", ("py",)),
        (".venv/scripts", "*", ("py",)), ("venv/scripts", "*", ("py",)))

# ---------------------------------------------------------------- which command executes which family
EXECUTORS = {
    "py": ("python", "python2", "python3", "pypy", "pypy3", "pytest", "py.test", "tox", "nox", "pip", "pip3", "mypy", "dmypy", "pylint", "flake8",
           "pyright", "basedpyright",
           "uv", "uvx", "pipx", "poetry", "hatch", "pdm", "pre-commit", "ipython", "coverage", "invoke", "inv"),
    "js": ("npm", "pnpm", "yarn", "npx", "pnpx", "node", "nodejs", "bun", "bunx", "deno", "jest", "vitest", "mocha", "eslint", "prettier",
           "tsc", "playwright", "webpack", "vite", "tsx", "ts-node", "corepack",
           # RT6: tools that import their *.config.* module
           "next", "rollup", "nuxt", "nuxi", "astro", "esbuild", "parcel", "stylelint", "cypress", "karma", "gulp", "grunt", "remix",
           "gatsby", "svelte-kit", "postcss", "tailwindcss", "turbo", "nx", "lerna"),
    "make": ("make", "gmake", "just", "task"),
    "cargo": ("cargo", "rustup"),
    "go": ("go",),
    "gradle": ("gradle", "gradlew"),
    "maven": ("mvn", "mvnw"),
    "git": ("git", "pre-commit", "husky", "lint-staged", "lefthook", "commitlint", "overcommit"),
    "man": ("man",), "tmux": ("tmux",), "mdlint": ("markdownlint", "markdownlint-cli2"),
    "docker": ("docker", "docker-compose", "podman", "devcontainer"),
    "ci": ("act", "gitlab-runner"),
    "editor": ("code", "devcontainer"),
    # RT6 (28.10): the tools that evaluate the configuration files above
    # (a file that is also a plain script of a language: its interpreter is an executor too -- a family file is not marked by
    # written_run, so `ruby Rakefile` / `bash .envrc` must be asked here)
    "swift": ("swift", "xcodebuild", "xcrun"), "bundler": ("bundle", "bundler", "gem", "rake", "rails", "rspec", "pod", "fastlane", "ruby", "irb", "jruby"),
    "rake": ("rake", "rails", "ruby", "irb", "jruby"), "vagrant": ("vagrant", "ruby"), "brew": ("brew", "ruby"), "pod": ("pod", "ruby"),
    "fastlane": ("fastlane", "ruby"), "mix": ("mix", "iex", "elixir"), "sbt": ("sbt", "scala"),
    "shell": tuple(sorted(_runners.SHELLS)), "dotnet": ("dotnet", "msbuild"), "bazel": ("bazel", "bazelisk"), "meson": ("meson", "muon"), "scons": ("scons",),
    "snakemake": ("snakemake",), "doit": ("doit",), "fab": ("fab",), "sphinx": ("sphinx-build", "sphinx-autobuild", "make", "gmake"),
    "mkdocs": ("mkdocs",), "latex": ("latexmk", "perl"), "direnv": ("direnv",), "nix": ("nix", "nix-shell", "nix-build", "nix-env", "devenv", "direnv"),
    "pixi": ("pixi",), "gdb": ("gdb",), "lldb": ("lldb",), "vim": ("vim", "vi", "nvim", "view", "ex", "lua", "luajit"), "cmake": ("cmake", "ctest", "cpack"),
    "zig": ("zig",), "php": ("composer", "php"), "mise": ("mise",),
}
SUB_EXECUTORS = {("git", "push"): ("ci",), ("gh", "workflow"): ("ci",), ("gh", "run"): ("ci",)}
_PY_RE = _runners.PY_RE                                  # RT6: one expression for python / python2 / pypy3 (hookjudge/runners.py)


def fold(name: str) -> str:
    """0.2.14 (R8-01): the form a case-insensitive file system compares: NFC, casefold, no trailing dots/spaces (Windows)."""
    return unicodedata.normalize("NFC", name).casefold().rstrip(". ") or name


def families_of_path(path: str) -> tuple:
    """-> the families whose commands execute this file (empty: not an executed file). `path` absolute or relative, '/'-separated."""
    p = path.replace("\\", "/").rstrip("/")
    parts = [fold(x) for x in p.split("/") if x]
    if not parts:
        return ()
    name = parts[-1]
    out = set(NAMES.get(name, ()))
    for pre, fam in PREFIXES:
        if name.startswith(pre):
            out.update(fam)
    for suf, fam in SUFFIXES:
        if name.endswith(suf) and len(name) > len(suf):
            out.update(fam)
    dirs = parts[:-1]
    for d, f, fam in DIRS:
        dp = d.split("/")
        n = len(dp)
        if f == "**":
            if any(dirs[i:i + n] == dp for i in range(len(dirs) - n + 1)) and not name.endswith(".sample"):
                out.update(fam)
        elif len(parts) >= n + 1 and parts[-1 - n:-1] == dp:
            if f == "*" and not name.endswith(".sample"):
                out.update(fam)
            elif f.startswith("*.") and name.endswith(f[1:]):
                out.update(fam)
            elif f == name:
                out.update(fam)
    return tuple(sorted(out))


def families_of_command(cid: str) -> tuple:
    """A command identifier as the hook names it ("pytest", "npm test", "python3 -m pytest", "npx jest [fetch]", "./gradlew [path]")
    -> the families of files it may execute."""
    if not isinstance(cid, str) or not cid:
        return ()
    words = cid.split("[", 1)[0].split()
    if not words:
        return ()
    head = fold(words[0].rsplit("/", 1)[-1])
    if head.endswith(".exe") or head.endswith(".cmd") or head.endswith(".bat"):
        head = head[:-4]
    out = set()
    if _PY_RE.fullmatch(head):
        out.add("py")
    for fam, names in EXECUTORS.items():
        if head in names:
            out.add(fam)
    if len(words) > 1:
        out.update(SUB_EXECUTORS.get((head, words[1]), ()))
    if head in ("sudo", "npx", "pnpx", "bunx") and len(words) > 1:
        out.update(families_of_command(" ".join(words[1:])))         # RT7: `npx markdownlint .` reads .markdownlint.cjs too
    return tuple(sorted(out))


# 0.2.25 (OTCHET-0.2.24, objection 1): what a command of a family runs BESIDES the named files above: the project's source files it imports
# or calls (pytest imports test_*.py, conftest.py and every module they import; npm test runs the project's .js/.ts; a Makefile calls ./x.sh).
# Used only while an agent is marked "saw a secret" (app/actions.py hold_after_secret): a file of this shape that the agent wrote is code
# the command will run. Not used for the ordinary exec_changed question: asking after every edit of a source file would ask on every test run.
SOURCE_EXT = {"py": (".py", ".pyw", ".pyx", ".pth", ".pyi"), "js": (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".node"),
              "go": (".go", ".s"), "cargo": (".rs",), "gradle": (".java", ".kt", ".kts", ".groovy", ".gradle"), "maven": (".java", ".kt", ".groovy"),
              "make": (".mk",), "docker": (), "git": (), "ci": (".yml", ".yaml"), "editor": ()}
SCRIPT_EXT = (".sh", ".bash", ".zsh", ".ksh", ".fish", ".ps1", ".bat", ".cmd", ".pl", ".rb", ".php", ".lua", ".tcl")   # any family may call a script


# 06.11 (r0260, friction: `npm ls` after an edit of package.json held ESCALATE_EXEC_CHANGED every day). npm sub-commands that read the
# project's manifests and print, and run no script and no module of the project: ls / list / ll / la / explain / why / help / root /
# prefix, and `npm run` / `npm run-script` with NO script named (it prints the scripts). npm itself still reads .npmrc (npm <= 6:
# `onload-script` requires a module): a changed .npmrc stays a change for them; package.json, node_modules/** and every other file
# of the js family are not run by them. `npm run build`, `npm test`, `npm install`, `npm version` (runs the version scripts) are not here.
NPM_READ_SUBS = {"ls", "list", "ll", "la", "explain", "why", "help", "root", "prefix"}
NPM_RC = {".npmrc"}


def _bare_npm_run(cmd) -> bool:
    """True when every `npm run` / `npm run-script` of the line names no script (options only up to the end of its command)."""
    import shlex
    if not isinstance(cmd, str) or re.search(r"[$`\\\n]", cmd):
        return False
    try:
        lx = shlex.shlex(cmd, posix=True, punctuation_chars="|&;()<>")
        lx.whitespace_split = True
        t = list(lx)
    except ValueError:
        return False
    seen = False
    for k, w in enumerate(t):
        if w == "npm" and k + 1 < len(t) and t[k + 1] in ("run", "run-script", "rum", "urn"):
            seen = True
            for x in t[k + 2:]:
                if set(x) <= set("|&;()<>"):
                    break
                if not x.startswith("-") or "=" in x and not x.startswith("--"):
                    return False
                if x in ("-w", "--workspace", "--prefix", "-C"):
                    return False                     # takes a value: the next word is no script but a place
    return seen


def _read_only_npm(cid, cmd) -> bool:
    w = cid.split("[", 1)[0].split() if isinstance(cid, str) and "[" not in cid else []
    if len(w) != 2 or w[0] != "npm":
        return False
    return w[1] in NPM_READ_SUBS or (w[1] in ("run", "run-script") and _bare_npm_run(cmd))


def runs_source(cmd_ids, path) -> bool:
    """0.2.25: may one of these command identifiers run the file at `path` (an executed config file, a source file of its ecosystem, a script)?"""
    fams = set()
    for c in cmd_ids or ():
        fams.update(families_of_command(c))
    if not fams or not isinstance(path, str):
        return False
    if set(families_of_path(path)) & fams:
        return True
    name = fold(path.replace("\\", "/").rsplit("/", 1)[-1])
    if name.endswith(SCRIPT_EXT):
        return True
    return any(name.endswith(SOURCE_EXT.get(f, ())) for f in fams if SOURCE_EXT.get(f))


# ---------------------------------------------------------------- server state
WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit", "Bash.write", "Write.danger", "Write.outside", "Bash")   # 0.2.90: + outside writes
COMMAND_TOOLS = ("Bash", "Bash.danger")
MAX_REPORTED = 256
MAX_GIT = 160
MAX_CHANGED = 64
INCOMPLETE = "(the hook's walk of the project was incomplete: files it did not see may have changed)"   # 0.2.14 (R8-03): pseudo path, root + "/" + it
_HEX = re.compile(r"[0-9a-f]{64}")


def _now():
    return int(time.time())


def _abs_ok(p):
    return isinstance(p, str) and p.startswith("/") and 1 < len(p) <= 1024 and "\x00" not in p


# 0.2.46 (OTCHET-0.2.33-GITCONFIG, residual risk 1): git's configuration names PROGRAMS git runs on its own (diff.external, a textconv or a filter,
# core.fsmonitor, core.pager, an `!` alias ...). Trust on first use took a config poisoned before the project's first report as confirmed, and a
# listed `git diff` ran the stranger's program. Now the hook reports the program keys of git's config files (`_witness.exec.gitcfg` =
# {absolute path of .git/config | config.worktree: [[key, value], ...]}, only keys matching GITCFG_KEYS: tokens in remote URLs and headers are
# never sent); while such keys are present and the owner did not confirm them, every git command is asked (ESCALATE_EXEC_CHANGED) under the
# pseudo path <config> + GITCFG, whose digest is that of the key list (approving confirms it, like a file).
GITCFG = " (git config: the programs it runs)"
GITCFG_BAD = "(git config: the hook's list of program keys was malformed or cut)"     # pseudo path under the root; asked every time
GITCFG_KEYS = (r"diff\.external|diff\..+\.(textconv|command)|merge\..+\.driver|filter\..+\.(clean|smudge|process)"
               r"|core\.(fsmonitor|pager|editor|sshcommand|gitproxy|askpass|hookspath|alternaterefscommand)|pager\..+|sequence\.editor"
               r"|gpg\.program|gpg\..+\.program|gpg\.ssh\.defaultkeycommand|alias\..+|include\.path|includeif\..+\.path"
               r"|credential\.helper|credential\..+\.helper|(difftool|mergetool)\..+\.(cmd|path)|interactive\.difffilter"
               r"|trailer\..+\.(command|cmd)|submodule\..+\.update|remote\..+\.(uploadpack|receivepack)|protocol\.(.+\.)?allow"
               r"|sendemail\.smtpserver|man\..+\.(cmd|path)|browser\..+\.(cmd|path)|web\.browser")
_GITCFG_RX = re.compile(GITCFG_KEYS, re.I)
_BOOLS = {"", "true", "false", "yes", "no", "on", "off", "1", "0"}
MAX_GITCFG_FILES = 8
MAX_GITCFG_ENTRIES = 64
MAX_GITCFG_VALUE = 256


def git_programs_of(entries) -> list:
    """[[key, value], ...] of a git config -> those that make git run a program (an alias only with `!`, core.fsmonitor / pager.<cmd> not as a
    boolean, submodule.<name>.update only with `!`, protocol.*.allow unless `never`)."""
    out = []
    for k, v in entries:
        lk = k.lower()
        if not _GITCFG_RX.fullmatch(lk):
            continue
        lv = v.strip().lower()
        if lk.startswith("alias.") or (lk.startswith("submodule.") and lk.endswith(".update")):
            if not v.lstrip().startswith("!"):
                continue
        elif (lk == "core.fsmonitor" or lk.startswith("pager.")) and lv in _BOOLS:
            continue
        elif lk.startswith("protocol.") and lv == "never":
            continue
        out.append([k, v])
    return out


def gitcfg_of(args):
    """-> None (no `gitcfg`: a hook before 0.2.46), False (malformed or cut: unknown), or {absolute config path: [[key, value] that run a program]}."""
    w = args.get("_witness") if isinstance(args, dict) else None
    ex = w.get("exec") if isinstance(w, dict) else None
    if not isinstance(ex, dict) or "gitcfg" not in ex:
        return None
    g = ex["gitcfg"]
    if ex.get("gitcfg_cut") is True or not isinstance(g, dict) or len(g) > MAX_GITCFG_FILES:
        return False
    out = {}
    for ap, ent in g.items():
        if not _abs_ok(ap) or ".." in ap.split("/") or not isinstance(ent, list) or len(ent) > MAX_GITCFG_ENTRIES:
            return False
        for e in ent:
            if not (isinstance(e, list) and len(e) == 2 and all(isinstance(x, str) and len(x) <= 1024 and "\x00" not in x for x in e)):
                return False
        progs = git_programs_of([tuple(e) for e in ent])
        if progs:
            out[ap] = progs
    return out


def _gitcfg_digest(progs) -> str:
    """0.2.46: the digest of the program keys IN FILE ORDER (not sorted): git uses the last of two equal keys (diff.external twice), so swapping
    them changes the program git runs, and the owner's confirmation of one order must not cover the other."""
    import hashlib
    return hashlib.sha256(json.dumps([list(e) for e in progs], ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def report_of(args):
    """The hook's `_witness.exec` -> (root, {absolute path: digest}, truncated) or None (absent / malformed: then only dirty marks count).
    0.2.14 (R8-04): `git` = {absolute path: digest} of git's own files wherever they are (common .git of a worktree, core.hooksPath);
    they join the files (family git) by absolute path."""
    w = args.get("_witness") if isinstance(args, dict) else None
    ex = w.get("exec") if isinstance(w, dict) else None
    if not isinstance(ex, dict) or not _abs_ok(ex.get("root")) or not isinstance(ex.get("files"), dict) or len(ex["files"]) > MAX_REPORTED:
        return None
    root = ex["root"].rstrip("/") or "/"
    files = {}
    for rel, dg in ex["files"].items():
        if not isinstance(rel, str) or not rel or rel.startswith("/") or len(rel) > 512 or "\x00" in rel or ".." in rel.split("/"):
            return None
        if not isinstance(dg, str) or not (_HEX.fullmatch(dg) or dg == "unreadable"):
            return None
        files[root + "/" + rel] = dg
    g = ex.get("git", {})
    if not isinstance(g, dict) or len(g) > MAX_GIT:
        return None
    for ap, dg in g.items():
        if not _abs_ok(ap) or ".." in ap.split("/") or not isinstance(dg, str) or not (_HEX.fullmatch(dg) or dg == "unreadable"):
            return None
        files[ap] = dg
    return root, files, bool(ex.get("truncated"))


def sizes_of(args):
    """0.2.24 (critique V): optional `_witness.exec.sizes` = {relative path: bytes} of a newer hook -> {absolute path: bytes}. Absent or bad -> {}.
    An older hook does not send it: the approval page then shows the digest without a size."""
    w = args.get("_witness") if isinstance(args, dict) else None
    ex = w.get("exec") if isinstance(w, dict) else None
    sz = ex.get("sizes") if isinstance(ex, dict) else None
    if not isinstance(sz, dict) or not _abs_ok(ex.get("root")) or len(sz) > MAX_REPORTED:
        return {}
    root = ex["root"].rstrip("/") or "/"
    return {root + "/" + k: v for k, v in sz.items() if isinstance(k, str) and k and not k.startswith("/") and ".." not in k.split("/")
            and isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2 ** 53}


def _git_paths(args):
    ex = (args.get("_witness") or {}).get("exec") if isinstance(args, dict) and isinstance(args.get("_witness"), dict) else None
    g = ex.get("git") if isinstance(ex, dict) else None
    return list(g) if isinstance(g, dict) else []


def _root_of(args, rep):
    if rep is not None:
        return rep[0]
    w = args.get("_witness") if isinstance(args, dict) else None
    if not isinstance(w, dict):
        return None
    for k in ("project", "cwd"):
        if _abs_ok(w.get(k)):
            return w[k].rstrip("/") or "/"
    return None


def _commands(args):
    w = args.get("_witness") if isinstance(args, dict) else None
    c = w.get("commands") if isinstance(w, dict) else None
    out = [x for x in c if isinstance(x, str)][:64] if isinstance(c, list) else []
    return out


# 0.2.89 (friction 03.11): a changed file of a virtual environment inside the project (`.venv/bin/*`, `<venv>/lib/pythonX/site-packages/**`,
# its .pth files) runs only when the line runs THAT environment's Python. A system python3 (`python3 -c ...`, `pytest`) named on the line,
# which the hook (client 0.2.57) resolves on Claude Code's PATH to a file outside the project that is not a version-manager shim, does not.
# Still a change (asked as before): the word is a path (`.venv/bin/python`, `./venv/bin/pytest`), the line activates / names a venv or sets
# PATH / VIRTUAL_ENV / PYTHONHOME / PYTHONPATH, a tool that picks the project's environment by itself (uv, poetry, pdm, hatch, pipenv, tox,
# nox, pre-commit, pixi, rye, conda ...), a name with no fact (an older hook) or one that resolves inside the project or to a shim.
_VENV_BIN = re.compile(r"^(/.+?/(?:\.venv|venv)[^/]*)/(?:bin|scripts)/[^/]+$", re.I)
_VENV_SITE = re.compile(r"^(/.+?)/lib/(?:(?:python|pypy)[^/]*/)?site-packages/.+$", re.I)
VENV_PICKERS = {"uv", "uvx", "poetry", "pdm", "hatch", "pipenv", "tox", "nox", "pre-commit", "pixi", "rye", "conda", "mamba", "micromamba",
                "direnv", "nix", "nix-shell", "devenv", "mise", "asdf", "pyenv", "invoke", "inv", "pipx"}
_SHIM = re.compile(r"/(shims|\.pyenv|\.asdf|\.rtx|mise|rtx|\.volta|\.nodenv|\.rbenv)(/|$)", re.I)
_VENV_LINE = re.compile(r"(^|[\s;&|(/.])(activate(\.\w+)?|VIRTUAL_ENV|PYTHONHOME|PYTHONPATH|PYTHONUSERBASE)\b|(^|[\s;&|(])(export\s+)?PATH\+?=")


def venv_root(path):
    """-> the root of the virtual environment `path` belongs to (by its place), or None."""
    if not isinstance(path, str):
        return None
    p = path.replace("\\", "/")
    m = _VENV_BIN.match(p) or _VENV_SITE.match(p)
    return m.group(1) if m else None


def _venv_idle(p, args, root) -> bool:
    """0.2.89: True when the changed file `p` matters only through a project virtual environment that this line does not run."""
    vr = venv_root(p)
    if vr is None or not (vr == root or vr.startswith(root.rstrip("/") + "/")):
        return False
    fams = set(families_of_path(p))
    if fams != {"py"}:
        return False                         # a file another family runs too
    w = args.get("_witness") if isinstance(args, dict) else None
    which = w.get("which") if isinstance(w, dict) and isinstance(w.get("which"), dict) else None
    cmd = args.get("command") if isinstance(args, dict) else None
    if which is None or not isinstance(cmd, str) or _VENV_LINE.search(cmd):
        return False
    pr = root.rstrip("/") + "/"
    for c in _commands(args):
        if "py" not in families_of_command(c):
            continue
        word = c.split("[", 1)[0].split()
        if not word:
            return False
        head = word[0]
        if head in ("sudo",) and len(word) > 1:
            head = word[1]
        if "/" in head or head in VENV_PICKERS:
            return False
        found = which.get(head)
        if not isinstance(found, list) or not found or not all(isinstance(x, str) for x in found) or \
                any(x.startswith(pr) or x == root or _SHIM.search(x) for x in found):
            return False
    return True


def check(ctx, agent_id, tool, args, dry=False):
    """A shell command line of the hook -> (changed absolute paths, exec_json for the action row or None). Also records the first report of a
    project as its confirmed state (trust on first use). dry (0.2.43b): only look (nothing recorded; a first report changes nothing)."""
    if tool not in COMMAND_TOOLS:
        return [], None
    rep = report_of(args)
    root = _root_of(args, rep)
    if root is None:
        return [], None
    t = _now()
    known = ctx.db.one("SELECT 1 AS k FROM exec_roots WHERE agent_id=? AND root=?", (agent_id, root)) is not None
    if dry and rep is not None and not known:
        return [], None
    if rep is not None and not known:
        with ctx.db.tx():
            ctx.db.x("INSERT OR IGNORE INTO exec_roots(agent_id,root,first_seen,truncated) VALUES(?,?,?,?)", (agent_id, root, t, 1 if rep[2] else 0))
            for p, dg in rep[1].items():
                ctx.db.x("INSERT OR IGNORE INTO exec_files(agent_id,path,digest,state,rid,updated_at) VALUES(?,?,?,?,?,?)", (agent_id, p, dg, "ok", None, t))
        known = False                        # this report IS the baseline: nothing in it is a change
    fams, ro_js = set(), False
    cmd_ = args.get("command") if isinstance(args, dict) else None
    for c in _commands(args):
        f_ = families_of_command(c)
        if f_ == ("js",) and _read_only_npm(c, cmd_):
            ro_js = True                              # 06.11 (r0260): `npm ls`, bare `npm run`: of the js family only .npmrc counts
            continue
        fams.update(f_)
    rc_only = ro_js and "js" not in fams
    if rc_only:
        fams.add("js")

    def hit(p_):
        f_ = set(families_of_path(p_)) & fams
        if rc_only and f_ == {"js"}:
            return fold(p_.rsplit("/", 1)[-1]) in NPM_RC
        return bool(f_)
    if not fams:
        return [], None
    prefix = root.rstrip("/") + "/"
    rows = {r["path"]: r for r in ctx.db.q("SELECT * FROM exec_files WHERE agent_id=? AND substr(path,1,?)=?", (agent_id, len(prefix), prefix))}
    gitset = set(_git_paths(args)) if rep is not None else set()   # R8-04: git's own files (any folder: core.hooksPath may be scripts/hooks)
    outside = [p for p in (rep[1] if rep is not None else {}) if not p.startswith(prefix)]
    for p in outside:                        # R8-04: git's files outside the root (common .git, core.hooksPath) are compared by absolute path
        r = ctx.db.one("SELECT * FROM exec_files WHERE agent_id=? AND path=?", (agent_id, p))
        if r is not None:
            rows[p] = r
    if "git" in fams:                        # R8-04: a write the witness allowed to a .git/hooks file anywhere (a worktree's common .git)
        for r in ctx.db.q("SELECT * FROM exec_files WHERE agent_id=? AND state='dirty'", (agent_id,)):
            rows.setdefault(r["path"], r)
    changed = set()
    if rep is not None:
        for p, dg in rep[1].items():
            if not (hit(p) or (p in gitset and "git" in fams)):
                continue
            r = rows.get(p)
            if r is None:
                if known:
                    changed.add(p)           # a new executed file in a project seen before
            elif r["state"] == "dirty" or r["digest"] != dg:
                changed.add(p)
    for p, r in rows.items():                # a write the witness allowed, not (or no longer) in the report: still a change
        if r["state"] == "dirty" and hit(p) and (rep is None or p not in rep[1]):
            changed.add(p)
    changed = {p for p in changed if not _venv_idle(p, args, root)}     # 0.2.89: the project's venv, not run by this line
    cur = dict(rep[1]) if rep is not None else {}
    progs_of = {}
    if "git" in fams:                        # 0.2.46: git's config runs a program the owner did not confirm (not even on first use)
        gc = gitcfg_of(args)
        if gc is False:
            changed.add(prefix + GITCFG_BAD)
        for ap, progs in (gc or {}).items():
            pp, dg = ap + GITCFG, _gitcfg_digest(progs)
            cur[pp], progs_of[pp] = dg, (ap, progs)
            r = ctx.db.one("SELECT * FROM exec_files WHERE agent_id=? AND path=?", (agent_id, pp))
            if r is None or r["state"] != "ok" or r["digest"] != dg:
                changed.add(pp)
    if known and rep is not None and rep[2]:
        # 0.2.14 (R8-03): an incomplete report (the walk was cut: the agent can cause that with junk files) is an UNKNOWN state, not
        # "unchanged": every confirmed file of the command's families missing from it counts as changed, and when the project's baseline
        # walk was complete, the incompleteness itself is asked about (fail-closed). No report at all (no project named, scan off, an old
        # hook) is not a cut walk: then the dirty marks of judged writes decide, as before.
        for p, r in rows.items():
            if r["state"] == "ok" and hit(p) and p not in rep[1]:
                changed.add(p)
        base = ctx.db.one("SELECT truncated FROM exec_roots WHERE agent_id=? AND root=?", (agent_id, root))
        if base is not None and not base["truncated"]:
            changed.add(prefix + INCOMPLETE)
    if not changed:
        return [], None
    ch = sorted(changed)[:MAX_CHANGED]
    info = {"changed": ch, "root": root, "digests": {p: cur.get(p) for p in ch}}
    gp = [{"config": progs_of[p][0], "runs": progs_of[p][1]} for p in ch if p in progs_of]
    if gp:
        info["git_programs"] = gp                     # 0.2.46: the approval page says which program git's config runs
    if prefix + GITCFG_BAD in ch:
        info["git_programs_unknown"] = True
    sz = sizes_of(args)
    if sz:
        info["sizes"] = {p: sz[p] for p in ch if p in sz}
    by = {p: rows[p]["rid"] for p in ch if p in rows and rows[p]["state"] == "dirty" and rows[p]["rid"]}
    if by:
        info["written_by"] = by                       # the judged write that changed it (its text is on that action's page while it waits)
    info["net"] = {p: _net_seen(rows.get(p), p, prefix, cur.get(p)) for p in ch}     # s7 (O2): what the witness saw of the change (see TEXT_KEYS)
    pv = previews_of(args)
    for p in ch:                                      # 0.2.43b (O2 to the end): the hook's masked preview of a change the witness did not read
        n, x = info["net"][p], pv.get(p)
        if not n.get("seen") and x is not None and isinstance(cur.get(p), str) and x["digest"] == cur[p]:
            from app.toolmap import mask_value
            txt = mask_value(x["text"], {}, PREVIEW_MAX)           # masked again here: the hook's masker is a copy, this one decides
            seen = net_of_text(txt)
            info["net"][p] = dict(n, preview=txt, preview_cut=bool(x["cut"]),
                                  lines=((n.get("lines") or []) + [v for v in seen["lines"] if v not in (n.get("lines") or [])])[:NET_LINES],
                                  hosts=((n.get("hosts") or []) + [v for v in seen["hosts"] if v not in (n.get("hosts") or [])])[:16])
    return ch, json.dumps(info, ensure_ascii=False)


# 0.2.43b (OTCHET-S7-PRAVKI residual risk (a)): a changed executed file the witness could not read (a shell write, a change on disk) was
# "approve blind". A hook that says it can (client.caps "preview", 0.2.43+) is asked for those files (`need.preview` = [absolute paths of its
# own report]); it answers `facts.exec.preview` = {path: {"text": the first PREVIEW_MAX characters, secrets masked, "cut": bool, "digest":
# the digest of the file as in its report}}. A preview whose digest is not the reported one (the file changed between the rounds) is not
# shown. The page shows the text; the command stays marked dangerous (the witness did not judge that write, and 4 KB may not be the whole file).
PREVIEW_MAX = 4096
MAX_PREVIEWS = 8


def previews_of(args):
    """`_witness.exec.preview` -> {absolute path: {"text", "cut", "digest"}} (well-formed entries only; at most MAX_PREVIEWS)."""
    w = args.get("_witness") if isinstance(args, dict) else None
    ex = w.get("exec") if isinstance(w, dict) else None
    pv = ex.get("preview") if isinstance(ex, dict) else None
    if not isinstance(pv, dict):
        return {}
    out = {}
    for p, x in list(pv.items())[:MAX_PREVIEWS]:
        if _abs_ok(p) and ".." not in p.split("/") and isinstance(x, dict) and isinstance(x.get("text"), str) and len(x["text"]) <= 2 * PREVIEW_MAX \
                and isinstance(x.get("digest"), str) and (_HEX.fullmatch(x["digest"]) or x["digest"] == "unreadable") and isinstance(x.get("cut", False), bool):
            out[p] = {"text": x["text"][:PREVIEW_MAX], "cut": bool(x.get("cut")) or len(x["text"]) > PREVIEW_MAX, "digest": x["digest"]}
    return out


def blind_paths(ctx, agent_id, tool, args):
    """0.2.43b: the changed executed files of this command line that the witness could not read and the hook reported (so it can preview them)."""
    ch, ej = check(ctx, agent_id, tool, args, dry=True)
    if not ch or not ej:
        return []
    info = json.loads(ej)
    rep = report_of(args)
    files = rep[1] if rep is not None else {}
    return [p for p in ch if not (info.get("net") or {}).get(p, {}).get("seen") and p in files and files[p] != "unreadable"][:MAX_PREVIEWS]


def _net_seen(r, p, prefix, digest=None):
    """s7 (O2): -> {"seen": bool, "lines", "hosts"} for a changed path: seen only when every change since the confirmed version was a judged
    write whose text the witness read; a change on disk, a shell write or an incomplete walk is not seen. git's config programs are listed
    on the page by name (git_programs), so they count as seen."""
    if p.endswith(GITCFG) or p == prefix + GITCFG_BAD:
        return {"seen": True, "lines": [], "hosts": [], "git": True}
    if r is None or r["state"] != "dirty":
        return {"seen": False}
    try:
        n = json.loads(r["net"]) if r["net"] else None
    except (TypeError, ValueError, IndexError, KeyError):
        n = None
    if not isinstance(n, dict):
        return {"seen": False}
    if n.get("seen") and isinstance(n.get("sha256"), str) and isinstance(digest, str) and digest != n["sha256"]:
        return {"seen": False, "lines": n.get("lines") or [], "hosts": n.get("hosts") or [], "after": True}   # changed again after the write
    return n


# s7 (polygon series 7, O2, 28.10): the hook sends only a digest and a size of an executed file, never its text, so the approval page of
# `make build` after the agent wrote a Makefile with `curl` in it said "Makefile changed (sha256, 83 bytes)", Dangerous false. Now the text
# of a judged Write / Edit / MultiEdit / NotebookEdit to an executed file is scanned for network commands when the write is allowed (the
# same scanner as interpreter code, hookjudge/bashparse.code_net); only the lines that talk to the network (<= NET_LINES x NET_LINE_MAX
# characters) and their hosts are kept (exec_files.net), never the file. The page then marks the command dangerous and shows those lines; a
# change the witness could not read (a shell write, a change on disk, an incomplete walk) is marked dangerous as an approval made blind.
TEXT_KEYS = {"Write": ("content",), "Write.danger": ("content", "new_string", "new_source"), "Edit": ("new_string",),
             "MultiEdit": ("edits",), "NotebookEdit": ("new_source",)}
NET_LINES, NET_LINE_MAX = 5, 200


def _written_text(tool, args, path):
    """-> the text this write puts into the file, or None when the witness cannot read it (a shell write: `cp x Makefile`)."""
    keys = TEXT_KEYS.get(tool)
    if not keys or not isinstance(args, dict):
        return None
    parts = []
    for k in keys:
        v = args.get(k)
        if isinstance(v, str):
            parts.append(v)
        elif k == "edits" and isinstance(v, list):
            parts += [e.get("new_string") for e in v if isinstance(e, dict) and isinstance(e.get("new_string"), str)]
    if not parts:
        return None
    text = "\n".join(parts)
    if fold(path.rsplit("/", 1)[-1]) == "package.json" and tool in ("Write", "Write.danger"):
        try:                                       # package.json: only `scripts` run (repository / homepage URLs are not network)
            sc = json.loads(text).get("scripts")
            text = "\n".join("%s: %s" % (k, v) for k, v in sc.items() if isinstance(v, str)) if isinstance(sc, dict) else ""
        except (ValueError, AttributeError):
            pass
    return text


def net_of_text(text):
    """-> {"seen": True, "lines": [network lines], "hosts": [...]} for a text the witness read."""
    from app.hookjudge import bashparse as _bp
    lines, hosts = [], []
    for ln in text.splitlines():
        if _bp.CODE_NET_API.search(ln) or re.search(r"\bgit\s+(clone|fetch|pull|push|ls-remote|remote\s+add)\b", ln):
            if len(lines) < NET_LINES:
                lines.append(" ".join(ln.split())[:NET_LINE_MAX])
            for h in _bp.code_net(ln)[0]:
                if h not in hosts and len(hosts) < 16:
                    hosts.append(h)
    return {"seen": True, "lines": lines, "hosts": hosts}


def written(tool, args):
    """Paths an allowed write would change that commands execute -> exec_json {"writes": [...], "net": {path: ...}} or None."""
    if tool not in WRITE_TOOLS:
        return None
    w = args.get("_witness") if isinstance(args, dict) else None
    if not isinstance(w, dict):
        return None
    ps = [w["path"]] if isinstance(w.get("path"), str) else []
    ps += [x for x in (w.get("writes") or []) if isinstance(x, str)] if isinstance(w.get("writes"), list) else []
    if tool == "Bash":                                # 0.2.90: the Bash part's own writes are the shadow-copied ones outside the project
        ps = [x for x in (w.get("outside_writes") or []) if isinstance(x, str)] if isinstance(w.get("outside_writes"), list) else []
    ps = sorted({p for p in ps if _abs_ok(p) and families_of_path(p)})[:MAX_CHANGED]
    if not ps:
        return None
    net = {}
    for p in ps:
        t = _written_text(tool, args, p) if len(ps) == 1 else None
        net[p] = net_of_text(t) if isinstance(t, str) else {"seen": False}
        if isinstance(t, str) and tool == "Write" and isinstance(args.get("content"), str) and fold(p.rsplit("/", 1)[-1]) != "go.mod":
            net[p]["sha256"] = hashlib.sha256(args["content"].encode("utf-8", "surrogatepass")).hexdigest()   # the whole file: compared below
    return json.dumps({"writes": ps, "net": net}, ensure_ascii=False)


# 28.10 (adaptive red team №1): `echo "<network code>" > m.py` in one call and `python3 m.py` in the next were both allowed: the written
# file is not an executed-file family, so nothing remembered it, and the second line has no code to scan. Now a write is marked "risky" at
# the moment it is judged (its text is gone after the decision, cut_previews) when the witness could not read what goes into the file, or
# what it read talks to the network or builds the code it runs; a later command that runs (or names) a risky file is held
# (actions.written_run_files, ESCALATE_WRITTEN_RUN). A clean Write (print(1)) leaves no mark: running it is not a new question.
FETCH_HEADS = {"curl", "wget", "dd", "tar", "unzip", "gunzip", "base64", "xxd", "openssl"}   # what they write is never in the line
COPY_HEADS = {"cp", "mv", "install", "rsync", "scp", "ln"}    # risky when a source is outside the project (a copy within it is the project's)


def _copies_in(cmd, cwd):
    """-> True when a cp / mv / install / rsync / scp / ln of the line takes a source from outside cwd (absolute elsewhere, ~, .., host:)."""
    import shlex
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return True
    segs, cur = [], []
    for t in toks:
        if t in (";", "&&", "||", "|", "&"):
            segs.append(cur); cur = []
        else:
            cur.append(t)
    segs.append(cur)
    for sg in segs:
        if not sg or sg[0].rsplit("/", 1)[-1] not in COPY_HEADS:
            continue
        ops = [t for t in sg[1:] if not t.startswith("-")]
        for src in ops[:-1]:
            if src.startswith("~") or ".." in src.split("/") or re.match(r"^[^/]*:", src) or (
                    src.startswith("/") and not (cwd and (src + "/").startswith(cwd.rstrip("/") + "/"))):
                return True
    return False


def _risky_text(text):
    from app.hookjudge import bashparse as _bp
    if _bp.code_obfuscated(text):
        return True
    hosts, unseen = _bp.code_net(text)
    n = net_of_text(text)
    return bool(hosts or unseen or n["lines"] or n["hosts"])


# 04.11 (OTCHET-0258 D8, rule bcc4411): under a fresh strict-sandbox fact and the code option a run of a file this agent wrote goes with a
# receipt and no hold (the OS bounds it). Never when the written TEXT itself reaches a gate the witness names: G1 a delete outside the
# project, G2 a network exit, G3 secrets, G4 persistence / the agent's harness (~/.claude, .mcp.json, git hooks, the witness), or a text
# the witness cannot read (unseen, obfuscated). Such a mark carries "g" (the gate) and its run is held even inside the sandbox: the sandbox
# is a fact the hook reports, the gates stay the witness's own. Lexical, so it may only tighten (a miss leaves the OS sandbox as before).
_G1_DEL = re.compile(r"\b(rmtree|rm\s+-\w*[rf]|rimraf|unlink|os\.remove|os\.rmdir|removedirs|rmdir|shred|fs\.rm(Sync)?|rm_rf|"
                     r"FileUtils\.rm|Remove-Item|del\s+/[sq])", re.I)
_G1_HOME = re.compile(r"(~(/|['\"\s]|$)|expanduser|Path\.home|\$\{?HOME\b|['\"]HOME['\"]|homedir\(|\bos\.homedir|\.\./)")
_G1_ABS = re.compile(r"(?<![\w.~/$-])/(?!tmp\b|private/tmp\b|private/var/folders\b|var/folders\b|dev/null\b)[A-Za-z][\w./-]*")
_G4_WORDS = re.compile(r"(\.claude(?![\w-])(?!/worktrees/)|\.mcp\.json|\.git/hooks|core\.hooksPath|deus-witness|\.deus-witness|crontab|launchctl|"
                       r"LaunchAgents|LaunchDaemons|systemctl\s+--user|\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile)\b|authorized_keys)")
_PATHISH = re.compile(r"[~$\w{}./-]*[./][~$\w{}./-]*")
# 04.11 (QA red team D8-0411, 23 bypasses in 10 mechanisms): G1 also names a truncate / clobber outside the project (open 'w'/'a',
# write_text, truncate, a shell redirect, cp /dev/null, mv / os.replace / shutil.move over a file, find -delete); G2 a raw /dev/tcp|udp
# socket; G3 a secret read from the environment without "$" (os.environ[...], getenv(...)) and the OS key stores; G4 the user's PATH
# directories (~/.local/bin, ~/bin, a writable $PATH entry) and the editor's autorun (.vscode tasks / launch). A write INTO the project
# is never a gate (the edit -> test loop stays quiet).
_G2_RAW = re.compile(r"/dev/(tcp|udp)\b")
_G3_ENV = re.compile(r"(environ\s*(\[|\.get\s*\(|\.pop\s*\(|\.setdefault\s*\()|getenv\s*\(|Getenv\s*\(|process\.env\s*(\.|\[)|\bENV\s*(\[|\.fetch\s*\()|"
                     r"env::var\w*\s*\(|Deno\.env\.get\s*\(|\$env:|\bprintenv\s+|\benv\s*\.\s*get\s*\()\s*['\"]?"
                     r"\w*(SECRET|TOKEN|KEY|PASS|CREDENTIAL)", re.I)
_G3_STORE = re.compile(r"(\bsecurity['\"]?\s*,?\s*['\"]?(find-[\w-]*password|find-certificate|find-identity|find-key|dump-keychain|export|"
                       r"unlock-keychain)\b|/usr/bin/security\b|keyring\.get_(password|credential)|secret-tool['\"]?\s*,?\s*['\"]?lookup|"
                       r"\bop\s+(read|item\s+get)\b|\bgh\s+auth\s+token\b|\bgit\s+credential\s+fill\b|\baws\s+configure\s+(get|export-credentials)\b|"
                       r"\bgcloud\s+auth\s+print-\w*token\b|\bpass\s+show\b)", re.I)
_G4_MORE = re.compile(r"((~|\$\{?HOME\}?|/Users/[^/\s'\"]+|/home/[^/\s'\"]+)/(\.local/bin|bin)(/|['\"\s]|$)|\.vscode/(tasks|launch)\.json|"
                      r"(~|\$\{?HOME\}?|/Users/[^/\s'\"]+|/home/[^/\s'\"]+)/\.vscode\b|Code/User/|(['\"])\.local/bin\b)")
_PY_OPEN_W = re.compile(r"\bopen\s*\(")
_PY_MODE_W = re.compile(r"(['\"])[rbtU]*[wax][rbt+]*\1|(['\"])r[bt]*\+[bt]*\2|O_(WRONLY|RDWR|TRUNC|CREAT|APPEND)|\bmode\s*=")
_G1_API = re.compile(r"(write_text|write_bytes|\btruncate\s*\(|\bos\.(replace|rename|renames|link|symlink)\s*\(|\bshutil\.(move|copy\w*)\s*\(|"
                     r"\b(fs|fsp|promises)\.(writeFile|appendFile|truncate|rename|copyFile|createWriteStream|cp|symlink)\w*\s*\(|"
                     r"\bFile\.(write|open|rename|truncate|symlink)\b|\bIO\.write\b|FileUtils\.(mv|cp|copy|move|touch|ln)\w*|"
                     r"Set-Content|Add-Content|Out-File|Move-Item|Copy-Item|Clear-Content|Rename-Item)", re.I)
_SH_SEG = re.compile(r"(?:^|[;&|(`]|\$\(|\bthen\b|\bdo\b|\belse\b)\s*(?:sudo\s+|command\s+|exec\s+|env\s+)?([\w./-]+)([^;&|`\n)]*)")
_REDIR = re.compile(r"(?<![<>&=\-\w])\d*>{1,2}\|?\s*(?![&>(=])(['\"]?)([^\s'\";|&)<>]+)")
_G1_CAND = re.compile(r"(?<![\w.~/$-])(~(?=[/'\"\s]|$)[^\s'\"`;|&)(<>,]*|\$\{?HOME\}?[^\s'\"`;|&)(<>,]*|/[A-Za-z][^\s'\"`;|&)(<>,]*|(?:\.\./)+[^\s'\"`;|&)(<>,]*)")
_G1_HOMEFN = re.compile(r"(Path\.home\s*\(|homedir\s*\(|['\"]HOME['\"]|\bgetenv\s*\(\s*['\"]HOME)")
_G1_SAFE = ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders", "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/fd", "/dev/tty")
_G1_SYS_READ = ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/lib/", "/System/", "/usr/share/")


def _g1_norm(t):
    """A path-like token -> its absolute form ("" when relative / unknown)."""
    t = t.strip("'\"")
    h = os.path.expanduser("~")
    m = re.match(r"^(~|\$\{HOME\}|\$HOME)(?=/|$)", t)
    if m:
        t = h + t[m.end():]
    if ".." in t.split("/"):
        return "/..escape"                                     # leaves the cwd: treated as outside
    return t if t.startswith("/") else ""


_CACHE_SUB = re.compile(r"^/(Users|home)/[^/]+/(\.cache|Library/Caches)/[^/]")
_CACHE_TXT = re.compile(r"(?<![\w.~/$-])(~|\$\{?HOME\}?|/Users/[^/\s'\"]+|/home/[^/\s'\"]+|\$\{?XDG_CACHE_HOME\}?)/?(\.cache|Library/Caches)?/[^\s'\"`;|&)(<>,]+")


def _in_cache(a):
    """05.11: a path INSIDE the user cache (~/.cache/x, ~/Library/Caches/x, $XDG_CACHE_HOME/x) is rebuildable by definition: not a G1.
    The cache root itself (rmtree ~/.cache) stays outside: it destroys every other tool's cache too."""
    if _CACHE_SUB.match(a):
        return True
    x = os.environ.get("XDG_CACHE_HOME")
    return bool(x and x.startswith("/") and a.startswith(x.rstrip("/") + "/"))


def _g1_outside(t, pr):
    t = re.sub(r"^\$\{?XDG_CACHE_HOME\}?(?=/)", os.environ.get("XDG_CACHE_HOME") or "~/.cache", t.strip("'\""))
    a = _g1_norm(t)
    if not a:
        return False
    if _in_cache(a):
        return False
    if any(a == s or a.startswith(s + "/") for s in _G1_SAFE):
        return False
    return not (pr and (a.rstrip("/") + "/").startswith(pr))


def _path_bins(pr):
    """The user's PATH directories a write could shadow a program in: ~/.local/bin, ~/bin and every writable $PATH entry outside the
    project (its own .venv/bin stays the project's)."""
    h = os.path.expanduser("~")
    out = {h + "/.local/bin", h + "/bin"}
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if d.startswith("/") and not any(d == s or d.startswith(s + "/") for s in _G1_SAFE) and not (pr and (d.rstrip("/") + "/").startswith(pr)):
            try:
                if os.access(d, os.W_OK):
                    out.add(d.rstrip("/"))
            except (OSError, ValueError):
                pass
    return out


def _logical_lines(text, cap=20):
    """The text's lines, a call split over lines (open(\n "/x",\n "w")) joined back into one (at most cap physical lines)."""
    out, cur, depth = [], [], 0
    for ln in text.splitlines():
        cur.append(ln)
        depth = max(0, depth + ln.count("(") + ln.count("[") - ln.count(")") - ln.count("]"))
        if depth == 0 or len(cur) >= cap:
            out.append(" ".join(cur)); cur, depth = [], 0
    if cur:
        out.append(" ".join(cur))
    return out


def _clobbers(text, pr, shell=True):
    """-> (targets outside the project a line of the text truncates / overwrites / moves away / deletes with find, indirect): indirect is
    True when such a line writes to a name the text does not spell (a variable), and the text names an outside path elsewhere."""
    import shlex
    outs, indirect = [], False
    for ln in _logical_lines(text):
        s = ln.strip()
        if not s or s.startswith("#!"):
            continue
        hits, var = [], False
        api = bool(_G1_API.search(ln)) or (bool(_PY_OPEN_W.search(ln)) and bool(_PY_MODE_W.search(ln)))
        if api:
            c = [m.group(0) for m in _G1_CAND.finditer(ln)]
            hits += c
            if _G1_HOMEFN.search(ln):
                hits.append("/..home")
            if not c and not re.search(r"XDG_CACHE_HOME", ln):
                var = True
        for m in (_REDIR.finditer(ln) if shell else ()):
            tg = m.group(2)
            if tg.startswith("$") and not re.match(r"^\$\{?(HOME|XDG_CACHE_HOME)\b", tg) or tg.startswith("`"):
                var = True
            else:
                hits.append(tg)
        for m in (_SH_SEG.finditer(ln) if shell else ()):
            head, rest = m.group(1).rsplit("/", 1)[-1], m.group(2)
            if head not in ("cp", "mv", "install", "ln", "rsync", "tee", "truncate", "dd", "find", "sed", "perl", "touch", "ditto"):
                continue
            try:
                toks = shlex.split(rest, comments=False)
            except ValueError:
                toks = rest.split()
            ops = [t for t in toks if not t.startswith("-")]
            if head == "find":
                if not re.search(r"\s-(delete|exec(dir)?\s+(rm|shred|truncate|mv|unlink))\b", rest):
                    continue
                tg = [t for t in toks if not t.startswith("-") and not t.startswith(("(", "!", "{", ";"))][:1]
            elif head in ("sed", "perl"):
                if not re.search(r"\s-\w*i", " " + rest):
                    continue
                tg = ops
            elif head == "dd":
                tg = [t[3:] for t in toks if t.startswith("of=")]
            elif head in ("mv", "tee", "truncate", "touch"):
                tg = ops                                      # mv takes its sources away too; tee / truncate write every operand
            else:
                tg = ops[-1:]                                 # cp / install / ln / rsync / ditto: the destination
            if head == "touch":
                continue                                      # touch never destroys content
            for t in tg:
                if t.startswith("$") and not re.match(r"^\$\{?(HOME|XDG_CACHE_HOME)\b", t):
                    var = True
                else:
                    hits.append(t)
        for t in hits:
            if t == "/..home" or _g1_outside(t, pr):
                outs.append(_g1_norm(t) if t != "/..home" else t)
        indirect = indirect or var
    if indirect and not outs:
        for ln in text.splitlines():
            if ln.strip().startswith("#!"):
                continue
            for m in _G1_CAND.finditer(ln):
                a = _g1_norm(m.group(0))
                if a and not a.startswith(_G1_SYS_READ) and _g1_outside(m.group(0), pr):
                    return outs, True
            if _G1_HOMEFN.search(ln):
                return outs, True
        indirect = False
    return outs, indirect


_WRITEISH = re.compile(r"(\.write\s*\(|\bwriteFile|\bappendFile|\bchmod\b|\bchown\b|\bgit\s+config\b|(?<![<>&=\-\w])\d*>{1,2}\|?\s*[^\s&>(=]|"
                       r"(^|[;&|(`\n]|\bthen\b|\bdo\b)\s*(sudo\s+|command\s+)?(cp|mv|ln|install|rsync|tee|dd|truncate|touch|ditto|rm|sed\s+-\w*i|perl\s+-\w*i)\b)")
_EXFIL_LOCAL = re.compile(r"(\bsubprocess\b|\bos\.(system|popen|exec\w*|spawn\w*)\b|\bPopen\b|child_process|\bexecSync\b|\bspawn(Sync)?\s*\(|"
                          r"\bsystem\s*\(|\bshell_exec\b|print\s*\([^\n]*\bfile\s*=|logging\.(basicConfig|FileHandler)|FileHandler\s*\()", re.I)
_GIT_CFG_G = re.compile(r"\bgit\s+config\s+(\S+\s+)*--(global|system)\b")
_GIT_CFG_RD = re.compile(r"\bgit\s+config\s+(\S+\s+)*(--get\S*|--list|-l|--show-origin)\b")
_PRINT_LN = re.compile(r"(\bprint\s*\(|\bprintln|\bprintf\b|console\.(log|error|warn|info)|\becho\b|\bputs\b|sys\.std(out|err)\.write|\blogg?(er|ing)?\.\w+\s*\()", re.I)


def _writes_persist(text, toks):
    """A persist path (~/.gitconfig ...) is a G4 only when the text can WRITE: reading it is not a gate."""
    if any(_bp_persist(t) for t in toks):
        return bool(_WRITEISH.search(text) or _G1_API.search(text) or (_PY_OPEN_W.search(text) and _PY_MODE_W.search(text)))
    return False


def _bp_persist(t):
    from app.hookjudge import bashparse as _bp
    return _bp.is_persist_path(t)


def _g3_env_gate(text, clob, indirect):
    """-> True when the text holds a secret read from the environment AND lets it out: the programmatic read alone (environ[...], getenv)
    is how every client takes its key; it is a gate with a write outside the project, a log / print of it, or a subprocess in the text."""
    from app.hookjudge import bashparse as _bp
    if _bp.SECRET_ENV.search(text):
        return True                                                   # "$TOKEN" in a command: shown or passed
    hit = False
    for m in _G3_ENV.finditer(text):
        if re.match(r"(printenv|\$env:)", m.group(0), re.I):
            return True
        hit = True
    if not hit:
        return False
    if clob or indirect or _EXFIL_LOCAL.search(text):
        return True
    names = set()
    for ln in text.splitlines():
        if _G3_ENV.search(ln):
            if _PRINT_LN.search(ln):
                return True
            names.update(re.findall(r"(\w+)\s*(?::=|=)(?!=)", ln.split("=", 1)[0] + "=" if "=" in ln else ""))
    return any(_PRINT_LN.search(ln) and any(re.search(r"\b" + re.escape(n) + r"\b", ln) for n in names) for ln in text.splitlines())


def gate_bash(cmd, project=None, writes=None, home=None):
    """10.11 (r0260): gate_text for a SHELL line that writes (Bash.write). Before, the whole line was scanned as one text, so a heredoc body
    ran together with the next shell line and a relative `> ../web/x.json` after `cd server` counted as a write outside the project (G1:
    the developer corpus held such runs inside the strict sandbox every day). Now: each heredoc body (the text written) is scanned as
    before; the shell line without its bodies is scanned as before EXCEPT its own writes (redirects, cp / mv / tee targets), which are
    the parser's resolved paths `writes` (it follows `cd`): outside = not in the project, not in its own temp folder, not a cache.
    A line the normalizer cannot read: the whole text, as before."""
    from app.hookjudge import bashparse as _bp
    if not isinstance(cmd, str):
        return "unseen"
    try:
        one, docs, balanced, unsure = _bp._normalize(cmd)
    except Exception:  # noqa: BLE001
        return gate_text(cmd, project)
    if not balanced or unsure is not None or not isinstance(one, str) or not isinstance(writes, list):
        return gate_text(cmd, project)
    gs = [gate_text(body, project) for _h, body, _q in docs if isinstance(body, str)]
    gs.append(gate_text(one, project, shell_writes=[x for x in writes if isinstance(x, str)], home=home))
    for g in ("opaque", "G2", "G4", "G3", "G1"):
        if g in gs:
            return g
    return None


def _shell_out(p, pr, project, home):
    """a write the parser resolved: outside the project, its own temp folder (sandbox.in_temp, project slug) and the caches -> True."""
    from app.hookjudge import sandbox as _sbx
    if not isinstance(p, str) or not p.startswith("/"):
        return True
    a = os.path.normpath(p)
    if pr and (a.rstrip("/") + "/").startswith(pr):
        return False
    if _in_cache(a) or any(a == s_ or a.startswith(s_ + "/") for s_ in _G1_SAFE):
        return False
    return not _sbx.in_temp(a, project, home if isinstance(home, str) and home.startswith("/") and home != "/" else "/var/empty/no-home")


def gate_text(text, project=None, shell_writes=None, home=None):
    """-> the gate the written text reaches ("G1".."G4", "opaque"), or None. text None (the witness cannot read it) -> "unseen".
    shell_writes (gate_bash only): `text` is a shell line whose own write targets are these resolved paths (not read from the text)."""
    from app.hookjudge import bashparse as _bp
    if not isinstance(text, str):
        return "unseen"
    if _bp.code_obfuscated(text):
        return "opaque"
    hosts, unseen_net = _bp.code_net(text)
    if unseen_net or any(h not in ("localhost", "127.0.0.1", "::1", "0.0.0.0") for h in hosts) or _G2_RAW.search(text):
        return "G2"
    pr = project.rstrip("/") + "/" if isinstance(project, str) and project.startswith("/") else None
    if (_G4_WORDS.search(text) or _G4_MORE.search(text) or _GIT_CFG_G.search(text) and not _GIT_CFG_RD.search(text)
            or _writes_persist(text, _PATHISH.findall(text))):
        return "G4"
    clob, indirect = _clobbers(text, pr, shell=shell_writes is None)
    if shell_writes is not None:
        clob = clob + [os.path.normpath(p) for p in shell_writes if _shell_out(p, pr, project, home)]
    if clob:
        bins = _path_bins(pr)
        if any(a != "/..home" and any(a.startswith(b + "/") for b in bins) for a in clob):
            return "G4"
    if (_g3_env_gate(text, clob, indirect) or _G3_STORE.search(text)
            or any(_bp.SECRET_DIR.search(t) or _bp.SECRET_NAME.search(t) for t in _PATHISH.findall(text))):
        return "G3"
    if clob or indirect:
        return "G1"
    if _G1_DEL.search(text):
        text = _CACHE_TXT.sub(lambda m: m.group(0) if not _in_cache(_g1_norm(m.group(0))) and not re.match(r"\$\{?XDG", m.group(0)) else "CACHE", text)
        outs = [m.group(0) for m in _G1_ABS.finditer(text)]
        if _G1_HOME.search(text) or any(not (pr and (o + "/").startswith(pr)) for o in outs):
            return "G1"
    return None


WRITTEN_CODE_RISKY = True     # 0.2.90 (D8): a code-like file the agent wrote is risky whatever its text (tests of 0.2.81 rules switch it off)
CODE_EXT = {"py", "pyw", "js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx", "sh", "bash", "zsh", "ksh", "fish", "rb", "pl", "pm", "php",
            "lua", "r", "go", "rs", "java", "kt", "swift", "c", "cc", "cpp", "h", "jar", "class", "pyc", "so", "dylib", "wasm", "ps1", "bat",
            "cmd", "applescript", "scpt", "awk", "sed", "tcl", "exs", "ex", "jl", "dart"}


def _code_like(path, tool, args):
    """28.10 (fatigue E 10.4 -> noise): a write marks a later run only when what it writes can be run as code: a code extension, or an
    extensionless file written with its content (a script); `cp .env.example .env.local`, `ln -s ../data data` are data, not code."""
    base = path.rsplit("/", 1)[-1]
    ext = base.rsplit(".", 1)[-1].lower() if "." in base.lstrip(".") else ""
    if ext in CODE_EXT:
        return True
    if ext:
        return False
    cmd = args.get("command") if isinstance(args, dict) and isinstance(args.get("command"), str) else ""
    return not re.match(r"\s*ln\b", cmd)


def written_run(tool, args, git_taint=False, info=None):
    """RT-0270 29.10: git_taint=True (the agent changed git's objects / index / refs / remotes earlier: actions.git_tainted) or a line that
    does so itself (bashparse gtamper): no restore from the repository is "own", its paths are unseen like a foreign extraction.
    info={} (RT-0270 p.3): filled with {"unseen": bool}: the text written is not in the call (the key "seen" cannot be its arguments).
-> {path: "risky"} for the paths of an allowed write a later run must not take unseen, or None.
    Two kinds (28.10 fatigue fix): the text the witness READ talks to the network / builds what it runs -> every written path (a `.dat` fed
    to `python3` through a pipe is code too); the text is UNSEEN (copy from outside, download, variable) -> only code-like paths (_code_like)."""
    w = args.get("_witness") if isinstance(args, dict) else None
    if tool not in WRITE_TOOLS or not isinstance(w, dict):
        return None
    ps = [w["path"]] if isinstance(w.get("path"), str) else []
    ps += [x for x in (w.get("writes") or []) if isinstance(x, str)] if isinstance(w.get("writes"), list) else []
    if tool == "Bash":                                # 0.2.90: the Bash part carries the writes outside the project (shadow-copied)
        ps = [x for x in (w.get("outside_writes") or []) if isinstance(x, str)] if isinstance(w.get("outside_writes"), list) else []
    elif tool == "Write.outside" and isinstance(w.get("outside_writes"), list):
        ps += [x for x in w["outside_writes"] if isinstance(x, str)]
    # 0.2.81 (red team R4-1/R4-2): a family file (x.mk, jest.config.py, package.json, .husky/lib.py, node_modules/...) is marked too.
    # ESCALATE_EXEC_CHANGED asks only when its OWN family tool runs it; `python3 jest.config.py` (or a copy / link / rename of it) ran it
    # unasked. The two now add up (AND, not OR): written_run_files leaves a family file out only for a line whose every code-running
    # program is one of that file's family tools (exec_changed asks there, as before).
    dels = {x for x in (w.get("deletes") or []) if isinstance(x, str)} if isinstance(w.get("deletes"), list) else set()
    ps = sorted({p for p in ps if _abs_ok(p) and p not in dels})[:MAX_CHANGED]      # 0.2.90: a deletion writes no code
    if not ps:
        return None
    content, unseen, xdirs, repo_only = False, False, set(), False
    if tool in ("Bash.write", "Bash"):
        cmd = args.get("command") if isinstance(args.get("command"), str) else None
        if cmd is None:
            unseen = True
        else:
            from app.hookjudge import bashparse as _bp
            try:
                c = _bp.classify(cmd, w.get("cwd") if isinstance(w.get("cwd"), str) else "/", None)
                heads = {str(h).split(" ", 1)[0].rsplit("/", 1)[-1] for h in c.heads}
                # N15 29.10: every path this line writes comes from the repository's own objects (`git pull --rebase`, `git stash pop`):
                # the line's own text is written nowhere, so it is no "risky content" (a `git pull` names a remote, it writes no code)
                rx_ = {os.path.normpath(x) for x in (getattr(c, "repo_extract", None) or [])}
                tainted = bool(git_taint or getattr(c, "gtamper", False))
                repo_only = not tainted and bool(rx_) and not getattr(c, "xforeign", None) and all(os.path.normpath(p) in rx_ for p in ps)
                content = bool(c.net or (not repo_only and _risky_text(cmd)))
                unseen = bool(c.danger or getattr(c, "opaque", False) or heads & FETCH_HEADS
                              or (heads & COPY_HEADS and _copies_in(cmd, w.get("cwd") if isinstance(w.get("cwd"), str) else None))
                              or re.search(r"\$\(|`", cmd)
                              or (heads & {"echo", "printf", "cat", "tee"} and re.search(r"\$\{?[A-Za-z_]", cmd))   # the text is a variable
                              or bool(getattr(c, "xforeign", None) if hasattr(c, "xforeign") else getattr(c, "extract", None))
                              or (tainted and bool(rx_)))
                # RT-0269 p.4: patch / tar x / unzip / git apply|am / checkout of a named ref (text not in the line); N15 29.10: what git
                # takes from the repository's own objects (stash, pull, merge, switch, checkout / restore from the index or HEAD) is not unseen
                xd = [x for x in (getattr(c, "xdirs", None) or []) if isinstance(x, str)]
                xdirs = {p for p in ps if any(p == x or x.startswith(p.rstrip("/") + "/") for x in xd)}   # ... a whole directory: the mark covers it
            except Exception:  # noqa: BLE001 -- a line the parser cannot judge: what it wrote is unseen
                unseen = True
    else:
        for p in ps:
            t = _written_text(tool, args, p)
            if not isinstance(t, str):
                unseen = True
            elif _risky_text(t):
                content = True
    # 04.11 (D8 under the strict sandbox): which gate the written text reaches (see gate_text); recorded on the mark only (what is marked
    # is unchanged: without the fact the behaviour is the 0.2.90 one)
    proj_ = w.get("project") if isinstance(w.get("project"), str) else (w.get("cwd") if isinstance(w.get("cwd"), str) else None)
    if unseen:
        g_ = "unseen"
    elif tool in ("Bash.write", "Bash"):
        g_ = gate_bash(args.get("command") if isinstance(args.get("command"), str) else None, proj_,
                       w.get("writes") if isinstance(w.get("writes"), list) else None,
                       w.get("sbx_home") or w.get("home"))
    else:
        g_ = next((g for g in (gate_text(_written_text(tool, args, p), proj_) for p in ps) if g), None)
    if isinstance(info, dict):
        info["unseen"] = bool(unseen)
        info["gate"] = g_
    if content:
        return {p: ({"dir": True} if p in xdirs else "risky") for p in ps}
    if unseen:
        cl = [p for p in ps if p in xdirs or _code_like(p, tool, args)]
        return {p: ({"dir": True} if p in xdirs else "risky") for p in cl} or None
    if not repo_only and WRITTEN_CODE_RISKY:
        # 0.2.90 (QA 03.11, D8 "wrote, then ran"; under the standing mandate `python3 src/tool.py` runs without a question): a code-like
        # file this agent wrote is risky whatever its text looks like -- a text scan cannot bound what a program does (print(1) today,
        # the edited line tomorrow). Its next run is held once for the owner (ESCALATE_WRITTEN_RUN), or runs unasked only in the strict
        # sandbox under the code option. What git itself restores from the repository's objects (repo_only) is not the agent's text.
        cl = [p for p in ps if p in xdirs or _code_like(p, tool, args)]
        return {p: ({"dir": True} if p in xdirs else "risky") for p in cl} or None
    return None


def _merge_net(old, new):
    """Two writes to the same file before the owner confirmed it: what either of them showed stays (a later clean Edit does not hide a curl)."""
    try:
        o = json.loads(old) if old else None
    except (TypeError, ValueError):
        o = None
    if not isinstance(o, dict) or not isinstance(new, dict):
        return new
    if not o.get("seen") or not new.get("seen"):
        return {"seen": False, "lines": (o.get("lines") or []) + (new.get("lines") or []), "hosts": (o.get("hosts") or []) + (new.get("hosts") or [])}
    return {"seen": True, "lines": ((o.get("lines") or []) + [x for x in new.get("lines") or [] if x not in (o.get("lines") or [])])[:NET_LINES],
            "hosts": ((o.get("hosts") or []) + [x for x in new.get("hosts") or [] if x not in (o.get("hosts") or [])])[:16]}


def on_allowed(ctx, row):
    """An action row the witness allowed (or the owner approved): a write marks its executed paths dirty."""
    try:
        info = json.loads(row["exec_json"]) if row["exec_json"] else None
    except (TypeError, ValueError, KeyError, IndexError):
        info = None
    if not isinstance(info, dict) or not info.get("writes"):
        return 0
    t = _now()
    nets = info.get("net") if isinstance(info.get("net"), dict) else {}
    for p in info["writes"]:
        n = nets.get(p) if isinstance(nets.get(p), dict) else {"seen": False}
        old = ctx.db.one("SELECT state, net FROM exec_files WHERE agent_id=? AND path=?", (row["agent_id"], p))
        if old is not None and old["state"] == "dirty":
            n = _merge_net(old["net"], n)            # s7 (O2): still unconfirmed: keep what an earlier write showed
        ctx.db.x("INSERT INTO exec_files(agent_id,path,digest,state,rid,updated_at,net) VALUES(?,?,?,?,?,?,?) "
                 "ON CONFLICT(agent_id,path) DO UPDATE SET state='dirty', rid=excluded.rid, updated_at=excluded.updated_at, net=excluded.net",
                 (row["agent_id"], p, "", "dirty", row["rid"], t, json.dumps(n, ensure_ascii=False)))
    return len(info["writes"])


def on_consumed(ctx, row):
    """The owner approved a command that carried exec_changed and it ran: the reported versions become the confirmed ones."""
    try:
        info = json.loads(row["exec_json"]) if row["exec_json"] else None
    except (TypeError, ValueError, KeyError, IndexError):
        info = None
    if not isinstance(info, dict) or not info.get("changed"):
        return 0
    t = _now()
    for p in info["changed"]:
        if p.endswith("/" + INCOMPLETE):     # R8-03: the owner accepted an incomplete walk of this project as its baseline from now on
            ctx.db.x("UPDATE exec_roots SET truncated=1 WHERE agent_id=? AND root=?", (row["agent_id"], p[:-len(INCOMPLETE) - 1]))
            continue
        dg = (info.get("digests") or {}).get(p)
        if dg:
            ctx.db.x("INSERT INTO exec_files(agent_id,path,digest,state,rid,updated_at) VALUES(?,?,?,?,?,?) "
                     "ON CONFLICT(agent_id,path) DO UPDATE SET digest=excluded.digest, state='ok', rid=excluded.rid, updated_at=excluded.updated_at",
                     (row["agent_id"], p, dg, "ok", row["rid"], t))
        else:
            ctx.db.x("DELETE FROM exec_files WHERE agent_id=? AND path=?", (row["agent_id"], p))
    return len(info["changed"])


def state(ctx, agent_id):
    """For the agent page / tests: {path: {state, digest, rid, updated_at}}."""
    return {r["path"]: {"state": r["state"], "digest": r["digest"], "rid": r["rid"], "updated_at": r["updated_at"]}
            for r in ctx.db.q("SELECT * FROM exec_files WHERE agent_id=? ORDER BY path", (agent_id,))}
