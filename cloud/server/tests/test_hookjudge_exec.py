"""0.2.13 (PROPOSAL-08): the hook reports the digests of the files commands execute (`_witness.exec`), bounded, without following
directory links; the families of files and commands; the reason texts."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "mcp"))

from app.hookjudge import execfiles as ef
from app.hookjudge.mapping import map_event
from app.hookjudge.reasons import REASONS, explain


def _proj(tmp_path):
    p = (tmp_path / "proj").resolve()
    (p / "src" / "pkg").mkdir(parents=True)
    (p / "conftest.py").write_text("a = 1\n")
    (p / "src" / "pkg" / "conftest.py").write_text("b = 1\n")
    (p / "src" / "pkg" / "mod.py").write_text("c = 1\n")
    (p / "package.json").write_text("{}\n")
    (p / "node_modules" / "x").mkdir(parents=True)
    (p / "node_modules" / "x" / "package.json").write_text("{}\n")          # skipped: pytest / npm do not run a dependency's manifest this way
    (p / ".git" / "hooks").mkdir(parents=True)
    (p / ".git" / "config").write_text("[core]\n")
    (p / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n")
    (p / ".git" / "hooks" / "pre-push.sample").write_text("#!/bin/sh\n")
    (p / ".github" / "workflows").mkdir(parents=True)
    (p / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
    return p


def test_scan_reports_executed_files_only(tmp_path):
    p = _proj(tmp_path)
    r = ef.scan(str(p))
    assert r["root"] == str(p) and r["truncated"] is False
    assert sorted(r["files"]) == [".github/workflows/ci.yml", "conftest.py", "package.json", "src/pkg/conftest.py"]
    # 0.2.14 (R8-04): git's own files are reported by absolute path (they may live outside the root: worktree, core.hooksPath)
    assert sorted(r["git"]) == [str(p / ".git" / "config"), str(p / ".git" / "hooks" / "pre-commit")]
    assert all(len(v) == 64 for v in list(r["files"].values()) + list(r["git"].values()))
    # a change changes the digest; the same content gives the same digest
    d0 = r["files"]["conftest.py"]
    (p / "conftest.py").write_text("a = 2\n")
    assert ef.scan(str(p))["files"]["conftest.py"] != d0
    (p / "conftest.py").write_text("a = 1\n")
    assert ef.scan(str(p))["files"]["conftest.py"] == d0


def test_symlinks_and_venv_and_gomod(tmp_path):
    p = _proj(tmp_path)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "conftest.py").write_text("evil\n")
    (p / "linked").symlink_to(outside, target_is_directory=True)               # a directory link is not followed
    assert "linked/conftest.py" not in ef.scan(str(p))["files"]
    (p / "setup.py").symlink_to(outside / "conftest.py")                       # a file link: the digest binds the target's path too
    d1 = ef.scan(str(p))["files"]["setup.py"]
    (outside / "c2.py").write_text("evil\n")
    os.unlink(p / "setup.py")
    (p / "setup.py").symlink_to(outside / "c2.py")
    assert ef.scan(str(p))["files"]["setup.py"] != d1                          # same content, another target: a change
    v = p / ".venv"
    (v / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (v / "pyvenv.cfg").write_text("home = /usr\n")
    (v / "lib" / "python3.12" / "site-packages" / "evil.pth").write_text("import os\n")
    (v / "lib" / "python3.12" / "site-packages" / "big_module.py").write_text("x\n")
    files = ef.scan(str(p))["files"]
    assert ".venv/lib/python3.12/site-packages/evil.pth" in files and not any("big_module" in f for f in files)
    (p / "go.mod").write_text("module x\n\ngo 1.22\n\nrequire a v1.0.0\n")
    g0 = ef.scan(str(p))["files"]["go.mod"]
    (p / "go.mod").write_text("module x\n\ngo 1.22\n\nrequire a v1.0.1\nrequire b v2.0.0\n")   # dependency bookkeeping: not a change
    assert ef.scan(str(p))["files"]["go.mod"] == g0
    (p / "go.mod").write_text("module x\n\ngo 1.22\ntoolchain go1.23.0\nrequire a v1.0.1\n")    # toolchain / replace: a change
    assert ef.scan(str(p))["files"]["go.mod"] != g0


def test_bounds(tmp_path, monkeypatch):
    p = _proj(tmp_path)
    for i in range(30):
        (p / ("d%d" % i)).mkdir()
        (p / ("d%d" % i) / "conftest.py").write_text("x\n")
    monkeypatch.setattr(ef, "MAX_FILES", 10)
    r = ef.scan(str(p))
    assert r["truncated"] is True and len(r["files"]) <= 10
    assert ef.scan("relative/path") is None and ef.scan(str(tmp_path / "missing")) is None


def test_map_event_carries_exec_for_a_project_line(tmp_path):
    p = _proj(tmp_path)
    env = {"CLAUDE_PROJECT_DIR": str(p), "HOME": "/nonexistent"}
    parts = map_event({"tool_name": "Bash", "tool_input": {"command": "pytest -q"}, "cwd": str(p)}, env=env)
    w = parts[-1].args["_witness"]
    assert w["exec"]["root"] == str(p) and "conftest.py" in w["exec"]["files"]
    # off switch (for a huge tree): no report; the server still counts the writes it judged
    parts = map_event({"tool_name": "Bash", "tool_input": {"command": "pytest -q"}, "cwd": str(p)}, env=dict(env, DEUS_WITNESS_EXEC_SCAN="0"))
    assert "exec" not in parts[-1].args["_witness"]
    # outside the project: no project, no report
    parts = map_event({"tool_name": "Bash", "tool_input": {"command": "pytest"}, "cwd": str(tmp_path)}, env=env)
    assert "exec" not in parts[-1].args["_witness"]
    # a model cannot inject its own report: `_witness` in tool_input is refused before anything is sent
    import pytest
    from app.hookjudge.mapping import Refuse
    with pytest.raises(Refuse):
        map_event({"tool_name": "Bash", "tool_input": {"command": "pytest", "_witness": {"exec": {}}}, "cwd": str(p)}, env=env)


def test_families():
    assert ef.families_of_path("a/b/conftest.py") == ("py",)
    assert ef.families_of_path(".git/hooks/pre-commit") == ("git",) and ef.families_of_path(".git/hooks/pre-commit.sample") == ()
    assert ef.families_of_path(".pre-commit-config.yaml") == ("git", "py")
    assert ef.families_of_path("Dockerfile.dev") == ("docker",) and ef.families_of_path("docker-compose.override.yml") == ("docker",)
    assert ef.families_of_path("gradle/init.d/x.gradle") == ("gradle",) and ef.families_of_path(".mvn/extensions.xml") == ("maven",)
    assert ef.families_of_path("lib/x.mk") == ("make",) and ef.families_of_path(".pth") == ()
    assert ef.families_of_path("pnpm-lock.yaml") == () and ef.families_of_path("package-lock.json") == ()     # lockfiles: bookkeeping, see coverage 8
    for cid, fam in (("pytest", ("py",)), ("python3.12 -m pytest", ("py",)), ("npm test", ("js",)), ("npx jest [fetch]", ("js",)),
                     ("make build", ("make", "sphinx")), ("./gradlew [path]", ("gradle",)), ("cargo test", ("cargo",)), ("go test", ("go",)),
                     ("git status", ("git",)), ("git push", ("ci", "git")), ("sudo make", ("make", "sphinx")), ("ls", ()), ("", ())):
        assert ef.families_of_command(cid) == fam, cid


def test_reason_texts():
    assert REASONS["ESCALATE_EXEC_CHANGED"][0] == "ask" and "conftest.py" in explain("ESCALATE_EXEC_CHANGED", "Bash")
    assert REASONS["APPROVER_NONE"][0] == "deny" and "blocked" in REASONS["APPROVER_NONE"][1]
