"""12.11 (r0263): the rest of П3 -- a file the agent wrote that a TOOL runs: package.json scripts (npm run / npm test / npm install's
lifecycle / yarn / pnpm / bun), Makefile recipes (make [target], prerequisites), .ts through npx tsx, and the commands a .js / .py file
hands to a shell (execSync, spawn, subprocess, os.system). Per script / target: `npm test` is not asked about the `release` script beside
it. PRED is written before each check; the outcome on 3bda0a4 (r0262) is in the comment."""
import json

import pytest

from app.hookjudge import strict_policy as sp
from tests.test_0611_popravki import _v
from tests.test_1111_zakrytyy_spisok import _d
from tests.test_1211_r0262 import W, outcome

pytestmark = pytest.mark.standing

PKG = json.dumps({"name": "x", "version": "1.0.0", "description": "run npm publish by hand",
                  "scripts": {"test": "pytest -q && node t.js", "build": "tsc -p .", "release": "npm run build && npm publish",
                              "ship": "npm run release", "postinstall": "node setup.js", "prelint": "git push origin main", "lint": "eslint ."}},
                 indent=2)
MK = "all: build\n\nbuild:\n\tgo build ./...\n\ntest: build\n\tgo test ./...\n\nrelease: test\n\t@git push origin main\n\ndeploy: release\n\nclean:\n\trm -rf ./bin\n"


@pytest.mark.parametrize("run,pred", [
    ("npm run release", "asked"), ("npm run ship", "asked"),                # r0262: silent (npm run was not a run of the file)
    ("npm run lint", "asked"),                                              # prelint runs before lint
    ("yarn release", "asked"), ("pnpm run release", "asked"), ("bun run release", "asked"), ("npm --prefix . run release", "asked"),
    ("npm test", "silent"), ("npm run build", "silent"), ("npm install", "silent"), ("yarn", "silent"), ("pnpm install", "silent"),
    ("npm run", "silent"),
])
def test_package_json_scripts(client, owner, tmp_path, monkeypatch, run, pred):
    d = _d(client, owner, tmp_path, monkeypatch, "n")
    W(d, "package.json", PKG)
    got = d.send(run)
    PRED = pred
    assert outcome(got) == PRED, _v(got)


def test_install_runs_a_written_lifecycle_script(client, owner, tmp_path, monkeypatch):
    d = _d(client, owner, tmp_path, monkeypatch, "l")
    W(d, "package.json", json.dumps({"name": "x", "scripts": {"postinstall": "git push -f origin main", "test": "jest"}}))
    PRED = ("asked", "silent")                                              # r0262: (silent, silent)
    assert (outcome(d.send("npm install")), outcome(d.send("npm test"))) == PRED


def test_an_edit_of_package_json_adds_a_script(client, owner, tmp_path, monkeypatch):
    d = _d(client, owner, tmp_path, monkeypatch, "pe")
    W(d, "package.json", json.dumps({"name": "x", "scripts": {"test": "jest"}}, indent=2))
    assert outcome(d.send("npm run deploy")) == "silent"
    W(d, "package.json", '"deploy": "npm publish --access public",', tool="Edit")
    PRED = "asked"                                                          # r0262: silent
    assert outcome(d.send("npm run deploy")) == PRED


@pytest.mark.parametrize("run,pred", [
    ("make release", "asked"), ("make deploy", "asked"),                    # r0262: silent; deploy -> release (prerequisite)
    ("make -C . release", "asked"), ("make -f Makefile release", "asked"),
    ("make", "silent"), ("make test", "silent"), ("make build", "silent"), ("make clean", "silent"),   # the default target is `all`
])
def test_makefile_targets(client, owner, tmp_path, monkeypatch, run, pred):
    d = _d(client, owner, tmp_path, monkeypatch, "m")
    W(d, "Makefile", MK)
    got = d.send(run)
    PRED = pred
    assert outcome(got) == PRED, _v(got)


def test_makefile_default_target_with_a_push(client, owner, tmp_path, monkeypatch):
    d = _d(client, owner, tmp_path, monkeypatch, "md")
    W(d, "Makefile", "ship:\n\tgit push origin HEAD\n\ntest:\n\tpytest\n")
    PRED = ("asked", "silent")                                              # r0262: (silent, silent)
    assert (outcome(d.send("make")), outcome(d.send("make test"))) == PRED


@pytest.mark.parametrize("path,text,run,pred", [
    ("rel.ts", "import { execSync } from 'child_process'\nexecSync('npm publish')\n", "npx tsx rel.ts", "asked"),     # r0262: silent
    ("s.js", "const cp = require('child_process')\ncp.spawnSync('git', ['push', 'origin', 'main'])\n", "node s.js", "asked"),
    ("s2.js", "const {exec} = require('child_process'); exec(`gh release create v1`)\n", "node s2.js", "asked"),
    ("p.py", "import subprocess\nsubprocess.check_call('twine upload dist/*', shell=True)\n", "python3 p.py", "asked"),
    ("w.js", "require('child_process').execSync('rm -rf ..')\n", "node w.js", "refused"),
    # harmless twins
    ("ok.js", "require('child_process').execSync('npm test', {stdio: 'inherit'})\n", "node ok.js", "silent"),
    ("ok2.js", "const m = /a/.exec('git push'); console.log('npm publish')\n", "node ok2.js", "silent"),
    ("ok.py", "import subprocess\nsubprocess.run(['pytest', '-q'])\n", "python3 ok.py", "silent"),
    ("ok.ts", "console.log('hello')\n", "npx tsx ok.ts", "silent"),
])
def test_code_hands_a_command_to_a_shell(client, owner, tmp_path, monkeypatch, path, text, run, pred):
    d = _d(client, owner, tmp_path, monkeypatch, "c")
    W(d, path, text)
    got = d.send(run)
    PRED = pred
    assert outcome(got) == PRED, _v(got)


def test_a_package_json_the_agent_never_wrote_is_not_asked(client, owner, tmp_path, monkeypatch):
    d = _d(client, owner, tmp_path, monkeypatch, "o")
    open(str(d.proj) + "/package.json", "w").write(PKG)                     # the person's own file
    PRED = "silent"                                                         # the rule of r0262: no question on what the witness never saw
    assert outcome(d.send("npm run release")) == PRED


@pytest.mark.parametrize("text,cwd,pred", [
    ("make release", "/p", {"/p/Makefile#make:release", "/p/makefile#make:release", "/p/GNUmakefile#make:release"}),
    ("make -C sub -f build.mk", "/p", {"/p/sub/build.mk#make:"}),
    ("cd web && npm run build", "/p", {"/p/package.json#npm:build", "/p/web/package.json#npm:build"}),
    ("npm ci", "/p", {"/p/package.json#npm:" + n for n in sp.NPM_LIFECYCLE["ci"]}),
    ("npm view x", "/p", set()), ("bun test", "/p", set()), ("npx eslint .", "/p", set()),
])
def test_run_targets(text, cwd, pred):
    PRED = pred
    assert sp.run_targets(text, cwd) == PRED
