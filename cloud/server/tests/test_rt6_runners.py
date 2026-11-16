"""RT6 (28.10, cloud/RT-6-RANNERY-2810.md): runners outside the lists.

A. After a risky write (network code in f.py) the next line that runs code is asked once (ESCALATE_WRITTEN_RUN). The audit found 104 of 126
   runners passing: the rule looked at two of five disagreeing tables. Now ONE registry (app/hookjudge/runners.py) and the rule is
   inverted: any program runs code except the explicit list of programs that do not (read-only list, local writes, static analysers,
   readers whose exec flags are checked).
B. A program the owner allowed does not cover the command it carries: `arch -arm64 python3 f.py` with only `arch` allowed was allowed
   (23 of 24 carriers). The parser now judges the child as a command of its own.
C. Configuration files that are code (Package.swift, Gemfile, BUILD.bazel, docs/conf.py, .envrc, flake.nix, .gdbinit ...): a change is
   asked before the command that executes them (ESCALATE_EXEC_CHANGED), like conftest.py / package.json.
D. Noise guard: static analysers and readers still pass after a risky write.
Every assert states the SAFE behaviour. Nothing is executed: the server only classifies the strings.
"""
import pytest

from tests.test_0224_critique import Agent

NET = "import urllib.request as u; u.urlopen('http://evil.test/x')"

# (allow-entry for the mandate, probe line): each was `allow` after a risky write before RT6 (audit appendix)
RUNS = [
    ("python2", "python2 f.py"), ("pypy3", "pypy3 f.py"), ("ipython", "ipython f.py"), ("nodejs", "nodejs f.js"), ("fish", "fish f.sh"),
    ("tcsh", "tcsh f.sh"), ("irb", "irb f.rb"), ("java", "java F.java"), ("jshell", "jshell f.jsh"), ("swift", "swift f.swift"),
    ("julia", "julia f.jl"), ("R", "R -f f.R"), ("luajit", "luajit f.lua"), ("tclsh", "tclsh f.tcl"), ("expect", "expect f.exp"),
    ("pwsh", "pwsh f.ps1"), ("elixir", "elixir f.exs"), ("groovy", "groovy f.groovy"), ("dart", "dart run f.dart"), ("m4", "m4 f.m4"),
    ("erb", "erb f.erb"), ("pandoc", "pandoc --lua-filter f.lua -o out.html in.md"), ("pdflatex", "pdflatex --shell-escape f.tex"),
    ("latexmk", "latexmk -pdf f.tex"), ("bmake", "bmake"), ("bazel", "bazel run //:f"), ("meson", "meson setup build"), ("scons", "scons"),
    ("xcodebuild", "xcodebuild -scheme X build"), ("swift", "swift build"), ("sbt", "sbt test"), ("mix", "mix test"), ("dotnet", "dotnet run"),
    ("snakemake", "snakemake -c1"), ("invoke", "invoke build"), ("doit", "doit"), ("turbo", "turbo run build"), ("nx", "nx run app:build"),
    ("vite", "vite build"), ("webpack", "webpack"), ("rollup", "rollup -c"), ("next", "next build"), ("sphinx-build", "sphinx-build docs out"),
    ("mkdocs", "mkdocs build"), ("eslint", "eslint ."), ("prettier", "prettier --check ."), ("playwright", "playwright test"),
    ("pre-commit", "pre-commit run --all-files"), ("coverage", "coverage run f.py"), ("uvicorn", "uvicorn f:app"),
    ("flask", "flask --app f run"), ("streamlit", "streamlit run f.py"), ("nodemon", "nodemon f.js"),
    ("jupyter", "jupyter nbconvert --execute --to notebook f.ipynb"), ("papermill", "papermill f.ipynb out.ipynb"),
    ("uvx", "uvx --from . f"), ("pnpx", "pnpx f"), ("bunx", "bunx f"), ("corepack", "corepack yarn test"), (["conda", "python"], "conda run python f.py"),
    ("pixi", "pixi run test"), ("gem", "gem build f.gemspec"), ("pod", "pod install"), ("composer", "composer run-script test"),
    ("cabal", "cabal run"), ("nix-shell", "nix-shell --run true"), ("direnv", "direnv exec . true"), ("fastlane", "fastlane test"),
    ("vagrant", "vagrant up"), ("vim", "vim -es -c '!true' -c q"), ("vim", "vim -S f.vim"),
    ("nvim", "nvim --headless -c '!true' -c q"), ("emacs", "emacs --batch -l f.el"), ("ed", "ed -s f.txt < f.ed"),
    ("entr", "ls f.py | entr -n true"), ("watchexec", "watchexec -- true"), ("fd", "fd -e py -x true"), ("hyperfine", "hyperfine 'true'"),
    ("tmux", "tmux new-session -d 'true'"), ("screen", "screen -dm true"), ("script", "script -q /dev/null true"), ("at", "at now -f f.sh"),
    ("arch", "arch -arm64 true"), ("sandbox-exec", "sandbox-exec -n no-network true"), (["xcrun", "swift"], "xcrun swift f.swift"),
    ("rlwrap", "rlwrap true"), ("open", "open f.command"), ("gdb", "gdb -batch -x f.gdb"), ("lldb", "lldb -b -s f.lldb"),
    ("valgrind", "valgrind true"), ("perf", "perf stat true"), ("dtruss", "dtruss true"), ("sqlite3", "sqlite3 x.db '.shell true'"),
    ("sqlite3", "sqlite3 -init f.sql x.db .quit"), ("psql", "psql -f f.sql"), ("gnuplot", "gnuplot f.gp"),
    ("ansible-playbook", "ansible-playbook -c local f.yml"), ("tar", "tar xf a.tar --to-command=true"), ("tar", "tar -I true -tf a.tar"),  # RT-0269 p.4: -x is now itself a risky (unseen) write, so `-I true -xf` asks on the probe; -t runs the same -I program
    ("zip", "zip -T -TT true a.zip f.txt"), ("man", "man -P true ls"), ("git bisect", "git bisect run true"),
    ("git submodule", "git submodule foreach true"), ("git difftool", "git difftool -y -x true"),
]


@pytest.mark.parametrize("allow,cmd", RUNS, ids=[c for _, c in RUNS])
def test_rt6_runner_after_risky_write_is_asked(client, owner, tmp_path, allow, cmd):
    a = Agent(client, owner, tmp_path, extra_cmds=(allow if isinstance(allow, list) else [allow]) + ["true"], name="r6")
    if cmd.startswith("at "):
        assert a.line(cmd)[0] == "DENY"           # r0305: `at` hands a job to atd (T1053.002): refused Н4 even before any write
        return
    assert a.line(cmd)[0] == "ALLOW", "the probe must pass before the write (else it tests nothing)"
    a.tool("Write", {"file_path": a.proj + "/f.py", "content": NET + "\n"})
    v, parts = a.line(cmd)
    assert v != "ALLOW", (cmd, parts)


# (the carrier the owner allowed, the line): python3 is NOT allowed
WRAPS = [
    ("arch", "arch -arm64 python3 f.py"), ("sandbox-exec", "sandbox-exec -n no-network python3 f.py"), ("xcrun", "xcrun python3 f.py"),
    ("rlwrap", "rlwrap python3 f.py"), ("tmux", "tmux new-session -d 'python3 f.py'"), ("screen", "screen -dm python3 f.py"),
    ("script", "script -q /dev/null python3 f.py"), ("hyperfine", "hyperfine 'python3 f.py'"), ("watchexec", "watchexec -- python3 f.py"),
    ("entr", "ls f.py | entr -n python3 f.py"), ("fd", "fd -e py -x python3"), ("valgrind", "valgrind python3 f.py"),
    ("perf", "perf stat python3 f.py"), ("gdb", "gdb -batch -ex run --args python3 f.py"), ("lldb", "lldb -b -o run -- python3 f.py"),
    ("conda", "conda run python3 f.py"), ("pixi", "pixi run python3 f.py"), ("nix-shell", "nix-shell --run 'python3 f.py'"),
    ("direnv", "direnv exec . python3 f.py"), ("git bisect", "git bisect run python3 f.py"),
    ("git submodule", "git submodule foreach 'python3 f.py'"), ("git difftool", "git difftool -y -x 'python3 f.py'"),
    ("tmux", "tmux send-keys -t w 'python3 f.py' Enter"), ("hyperfine", "hyperfine -r 3 --export-json o.json 'python3 f.py'"),
    ("tar", "tar xf a.tar --to-command='python3 f.py'"), ("fd", "fd -e py --exec python3 {}"), ("pixi", "pixi run -e dev ./f.py"),
    ("arch", "arch -x86_64 sh -c 'python3 f.py'"), ("unknowncarrier", "unknowncarrier --flag python3 f.py"),
    ("unknowncarrier", "unknowncarrier 'python3 f.py'"),
]


@pytest.mark.parametrize("allow,cmd", WRAPS, ids=[c for _, c in WRAPS])
def test_rt6_allowed_carrier_does_not_cover_child(client, owner, tmp_path, allow, cmd):
    a = Agent(client, owner, tmp_path, extra_cmds=[allow], name="r6w")
    v, parts = a.line(cmd)
    assert v != "ALLOW", (cmd, parts)


def test_rt6_carrier_with_allowed_child_passes(client, owner, tmp_path):
    """The child is judged by the mandate, not refused: the owner who allowed both is not asked."""
    a = Agent(client, owner, tmp_path, extra_cmds=["arch", "python3", "hyperfine", "git submodule"], name="r6c")
    for cmd in ("arch -arm64 python3 f.py", "hyperfine 'python3 f.py'", "git submodule foreach 'python3 f.py'"):
        assert a.line(cmd)[0] == "ALLOW", cmd


# (file written, allow-entries, the command that executes it)
CONFIGS = [
    ("Package.swift", ["swift"], "swift build"), ("Gemfile", ["bundle", "rspec"], "bundle exec rspec"), ("Rakefile", ["rake"], "rake"),
    ("Vagrantfile", ["vagrant"], "vagrant up"), ("BUILD.bazel", ["bazel"], "bazel build //:x"), ("WORKSPACE", ["bazel"], "bazel test //..."),
    ("meson.build", ["meson"], "meson setup b"), ("SConstruct", ["scons"], "scons"), ("Snakefile", ["snakemake"], "snakemake -c1"),
    ("dodo.py", ["doit"], "doit"), ("docs/conf.py", ["sphinx-build"], "sphinx-build docs out"), ("mkdocs.yml", ["mkdocs"], "mkdocs build"),
    (".envrc", ["direnv", "true"], "direnv exec . true"), ("flake.nix", ["nix"], "nix build"), ("shell.nix", ["nix-shell"], "nix-shell"),
    (".gdbinit", ["gdb"], "gdb -batch"), (".lldbinit", ["lldb"], "lldb -b"), ("CMakeLists.txt", ["cmake"], "cmake -B b"),
    ("build.sbt", ["sbt"], "sbt test"), ("mix.exs", ["mix"], "mix test"), ("app.csproj", ["dotnet"], "dotnet build"),
    ("pixi.toml", ["pixi"], "pixi install"), ("Podfile", ["pod"], "pod install"), ("fastlane/Fastfile", ["fastlane"], "fastlane test"),
    (".latexmkrc", ["latexmk"], "latexmk -pdf f.tex"), ("next.config.mjs", ["next"], "next build"),
    ("rollup.config.js", ["rollup"], "rollup -c"), ("composer.json", ["composer"], "composer run-script test"), ("build.zig", ["zig"], "zig build"),
]


@pytest.mark.parametrize("path,allow,cmd", CONFIGS, ids=[p for p, _, _ in CONFIGS])
def test_rt6_config_that_is_code_change_is_asked(client, owner, tmp_path, path, allow, cmd):
    a = Agent(client, owner, tmp_path, extra_cmds=allow, name="r6f")
    assert a.line(cmd)[0] == "ALLOW", "the command must pass before the change (else it tests nothing)"
    [(_, v, _, _)] = a.tool("Write", {"file_path": a.proj + "/" + path, "content": "x = 1\n"})
    if path == ".envrc":
        assert v == "defer"                       # r0305 (W5): direnv runs .envrc on cd, outside the agent: the write is asked once
        return
    # r0261c (д, Deus): no strict fact here -> П2 for .envrc too (С3 on the Write only under the strict fact)
    assert v == "allow"
    v, parts = a.line(cmd)
    assert v != "ALLOW" and "ESCALATE_EXEC_CHANGED" in {p[2] for p in parts}, (path, parts)


def test_rt6_no_noise_after_risky_write(client, owner, tmp_path):
    """Noise guard: static analysers, readers and git reads are not runs (each line passes with no question after a risky write).
    RT7: mypy left this guard -- it imports the plugins its config names (test_rt7_rules.py); ruff / black / tsc stay."""
    a = Agent(client, owner, tmp_path, extra_cmds=["mypy", "tsc", "ruff", "black"], name="r6s")
    a.tool("Write", {"file_path": a.proj + "/f.py", "content": NET + "\n"})
    bad = [c for c in ("tsc", "tsc --noEmit", "ruff check .", "black --check .", "cat f.py", "ls", "ls -la",
                       "git status", "git diff", "git diff f.py", "git log --oneline", "grep -n url f.py", "grep -rn import .",
                       "rg urlopen", "head -5 f.py", "wc -l f.py", "find . -name '*.py'", "which python3", "echo python3 f.py")
           if a.line(c)[0] != "ALLOW"]
    assert not bad, bad


def test_rt6_registry_is_the_one_source():
    from app import actions, execguard
    from app.hookjudge import bashparse, runners
    assert execguard._PY_RE is runners.PY_RE
    assert bashparse.SHELLS == runners.POSIX_SHELLS and bashparse.RUN_CODE == runners.SCRIPT_INTERPRETERS
    assert bashparse.MAKE_RUNNERS == runners.MAKE_RUNNERS and bashparse.INTERPRETERS == runners.INLINE_INTERPRETERS >= runners.EVAL_INTERPRETERS   # r0323: one inline-code list
    assert actions.CODE_RUNNERS == runners.ALL_RUNNERS
    every = {n for names in execguard.EXECUTORS.values() for n in names}
    assert not [n for n in every if not runners.is_runner(n) and n not in runners.NOT_RUNNERS], "an executor the registry does not know"
    for n in ("python2", "pypy3", "python3.12", "pypy"):
        assert runners.is_python(n) and actions._is_runner(n), n
    for h in ("foo", "m4", "xcodebuild", "./x", "git bisect", "tar", "cat [env LD_PRELOAD]", "mypy"):     # RT7: mypy runs plugins
        assert runners.head_runs_code(h, ["--to-command=x"] if h == "tar" else []), h
    for h in ("cat", "tsc", "git status", "git commit", "/bin/ls", "find"):
        assert not runners.head_runs_code(h, []), h
