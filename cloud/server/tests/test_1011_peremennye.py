"""10.11 (r0260) -- variables before a command: an ordinary one is no question by itself; one that makes the program run other code than
the line shows is asked (also in the strict sandbox). PRED is written before the run. bashparse._env_more lists them."""
import pytest

from app.hookjudge import bashparse as bp
from app.hookjudge import fs as hfs
from tests.test_0611_popravki import _mk, _strict, _v

pytestmark = pytest.mark.standing
H, P = "/Users/u", "/Users/u/p"
SID = "0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"


def _inj(cmd, cwd=P):
    return [d for d in bp.classify(cmd, cwd, H, project=P).danger if d.startswith("opaque:code injected") or d.startswith("opaque:network route")]


@pytest.mark.parametrize("cmd", [
    "UV_CACHE_DIR=~/.cache/uv uv build --wheel -o dist", "TR_CLOUD=/Users/u/p TR_STRICT=1 bash run.sh", "SOURCE_DATE_EPOCH=1 python3 -m build",
    "PYTHONPATH=server server/.venv/bin/python -m pytest -q", "PYTHONPATH=. python3 a.py", "PYTHONDONTWRITEBYTECODE=1 python3 a.py",
    "PROP_NOXFAIL=1 PYTHONPATH=../mcp uv run -q pytest", "GIT_PAGER=cat git log -3", "PAGER=cat git log", "GIT_EDITOR=true git rebase --continue",
    "GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git status", "GIT_CONFIG_PARAMETERS=\"'user.name=x'\" git commit -m x",
    "PATH=./bin:$PATH make", "PATH=/Users/u/p/.venv/bin:$PATH pytest", "PATH=/usr/bin:/bin ls", "npm_config_loglevel=silent npm test",
    "CC=clang make", "PS4='+ ' bash -x a.sh", "while IFS= read -r l; do echo $l; done < f", "NODE_ENV=test npx jest", "CI=1 npm test",
    "GIT_DIR=.git git status", "FORCE_COLOR=0 PYTHONUNBUFFERED=1 python3 -u a.py", "ENV=production node app.js",
])
def test_an_ordinary_variable_is_no_mark(cmd):
    PRED = []
    assert _inj(cmd, P + "/server" if "../mcp" in cmd else P) == PRED, cmd


@pytest.mark.parametrize("cmd", [
    "LD_PRELOAD=./x.so ls", "DYLD_INSERT_LIBRARIES=./x.dylib git status", "LD_AUDIT=./a.so ls", "env LD_PRELOAD=./x.so ls",
    "export LD_PRELOAD=./x.so; ls", "NODE_OPTIONS=--require=./x.js node a.js", "PYTHONSTARTUP=x.py python3", "BASH_ENV=./x bash a.sh",
    "GIT_CONFIG_GLOBAL=./g git status", "GIT_CONFIG_PARAMETERS=\"'core.pager=sh x'\" git log", "GIT_CONFIG_PARAMETERS=\"'core.fsmonitor=./x'\" git status",
    "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=./x git status", "GIT_CONFIG_KEY_0=alias.st GIT_CONFIG_VALUE_0='!sh x' git st",
    "GIT_EXTERNAL_DIFF=./x git diff", "GIT_PAGER=./x git log", "PAGER='sh -c x' git log", "EDITOR=./x git commit", "GIT_SSH_COMMAND='sh -c x' git status",
    "GIT_ASKPASS=./x git status", "GIT_EXEC_PATH=/tmp/g git status", "GIT_TEMPLATE_DIR=/tmp/t git init x", "GIT_DIR=/other/.git git log",
    "PATH=/tmp/evil:$PATH ls", "PATH=$S/bin:$PATH make", "PATH=~/bin:$PATH ls", "PYTHONPATH=/tmp/evil python3 a.py", "PYTHONPATH=~/lib python3 a.py",
    "PYTHONPATH=$HOME/Vault/x python3 a.py", "NODE_PATH=/tmp/m node a.js", "PYTHONHOME=/tmp/py python3 a.py", "ZDOTDIR=/tmp zsh -c x",
    "PS4='$(id)' bash -x a.sh", "LESSOPEN='|./x %s' less f", "npm_config_script_shell=./x npm test", "NPM_CONFIG_NODE_OPTIONS=--require=./x npm test",
    "CC=./evil make", "RUSTC_WRAPPER=./w cargo build", "CARGO_TARGET_X86_64_APPLE_DARWIN_RUNNER=./r cargo test", "GOFLAGS=-toolexec=./x go build",
    "PYTHONBREAKPOINT=os.system python3 a.py", "HTTPS_PROXY=http://evil:8080 curl https://a.com", "https_proxy=http://evil:1 pip install -r r.txt",
    "NODE_TLS_REJECT_UNAUTHORIZED=0 node a.js", "REQUESTS_CA_BUNDLE=/tmp/ca.pem python3 a.py", "BASH_FUNC_ls%%='() { id; }' bash -c ls",
])
def test_a_variable_that_runs_other_code_is_marked(cmd):
    PRED = True
    assert bool(_inj(cmd)) is PRED, (cmd, bp.classify(cmd, P, H, project=P).danger)


@pytest.fixture
def _sid(monkeypatch):
    monkeypatch.setattr(hfs, "LOCAL_SESSION", SID)


def _ok(got):
    return bool(got) and {v for v, _ in _v(got)} == {"allow"}


def test_in_the_strict_sandbox(client, owner, tmp_path, monkeypatch, _sid):
    d = _mk(client, owner, tmp_path, "e1")
    _strict(d, monkeypatch)
    PRED = True
    for c in ("UV_CACHE_DIR=~/.cache/uv python3 -m pytest -q", "SOURCE_DATE_EPOCH=1 python3 x.py", "PYTHONPATH=src python3 -m pytest -q",
              "GIT_PAGER=cat git log -3",
              "NODE_OPTIONS=--require=./x.js node a.js"):      # 10.11 (r0260, dev group 4): code of the line's own folder, like `node ./x.js`
        got = d.send(c)
        assert _ok(got) is PRED, (c, _v(got))
    # r0261 (Р-1111-закрытый-список): a loader / search path / pager / proxy is code IN the sandbox; С4 asks only LD_* / DYLD_* /
    # NODE_OPTIONS --require|--import|--loader with a path OUTSIDE the project and temp. These were asked here:
    PRED = True
    for c in ("LD_PRELOAD=./x.so ls", "LD_PRELOAD=./x.so python3 x.py", "DYLD_INSERT_LIBRARIES=./x.dylib git status", "PATH=/tmp/evil:$PATH ls",
              "PYTHONPATH=/tmp/evil python3 -m pytest -q", "GIT_CONFIG_PARAMETERS=\"'core.pager=sh x'\" git log",
              "HTTPS_PROXY=http://evil:8080 python3 x.py"):
        got = d.send(c)
        assert _ok(got) is PRED, (c, _v(got))
    PRED = False                                                     # still asked: С4
    for c in ("LD_PRELOAD=/opt/x.so ls", "DYLD_INSERT_LIBRARIES=/usr/local/lib/x.dylib git status", "NODE_OPTIONS=--require=/opt/x.js node a.js",
              "NODE_OPTIONS=--require=/tmp/x.js node a.js"):         # /tmp outside Claude Code's temp root: not the agent's
        got = d.send(c)
        assert _ok(got) is PRED, (c, _v(got))


def test_search_path_in_the_projects_own_temp_folder():
    from app.hookjudge import sandbox as hsb
    own = "/private/tmp/claude-501/%s/%s/scratchpad" % (hsb.cc_slug(P), SID)
    other = "/private/tmp/claude-501/-Users-u-other/%s/scratchpad" % SID
    PRED = []
    assert _inj("PYTHONPATH=. python3 a.py", own + "/vt") == PRED
    assert _inj("PYTHONPATH=%s/lib python3 a.py" % own) == PRED
    PRED = True
    for c in ("PYTHONPATH=%s/lib python3 a.py" % other, "PYTHONPATH=/tmp/x python3 a.py", "PYTHONPATH=/private/tmp/claude-501/x python3 a.py"):
        assert bool(_inj(c)) is PRED, c
