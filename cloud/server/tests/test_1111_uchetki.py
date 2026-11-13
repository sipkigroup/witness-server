"""11.11 (r0260) -- the strict fact with the person's CREDENTIAL SOURCES closed (L2, Deus 10.11: with sandbox.filesystem.denyRead
["~/Library/Keychains"] `security find-generic-password` from the strict sandbox gets nothing -- KEYCHAIN_BLOCKED rc=44; without it the
dummy item was read).

Law: code can publish IN THE PERSON'S NAME only with a credential of the person. Where code in the sandbox could find one: the login
keychain (git credential-osxkeychain, gh, twine's keyring), the browsers' cookie stores (a github.com / pypi.org session), the editors'
token stores, the CLI config files (SECRETS + CRED_SOURCES), a URL with a password / an extra header / a credential helper in a git
config file the sandbox must keep readable, an auth token in the project's .npmrc / .yarnrc.yml / .pypirc or in ~/.yarnrc.yml (the client
reports these as `cred_files`, names only). When EVERY source is closed (cred_closed), a write host of the list (github.com, the npm
registry ...) no longer takes the strict fact from every line that runs code (87facd5): a line is asked only when it NAMES a write host or
a publication (git push, gh writes, npm / yarn / pnpm publish, twine, uv publish ...) -- the "from now on" amendments of c1e508b remain.
Not closed (a client before 11.11 sends no `cred_files`; a source missing from denyRead; a credential in a config file) -- 87facd5 as is.
Only hosts whose credentials are known to live in those sources (CRED_HOSTS) get the new silence; any other write host -- 87facd5.

Accepted residual (written down, not hidden): code may still SEND data to a listed write host with a credential it brings itself (an
attacker's token in the code); what it can read is what denyRead leaves (secrets are closed) -- Р-1011-сеть-в-строгой already accepts
that for every listed host. Every PRED is written before the check.
"""
import copy
import json
import posixpath

import pytest

from app.hookjudge import fs as hfs
from app.hookjudge import sandbox as hsb
from tests.test_0290_standing import STRICT
from tests.test_0611_popravki import _mk, _v, _pending

pytestmark = pytest.mark.standing
TYPICAL = ["github.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com",
           "registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]


def _fact(home, domains, deny=None, cred_files=(), **kw):
    f = copy.deepcopy(STRICT)
    f["deny_read"] = list(deny) if deny is not None else [home, "/nonexistent-home"]
    f["domains"] = list(domains)
    f["domains_user"] = list(domains)
    f["env_tokens"] = []
    if cred_files is not None:
        f["cred_files"] = list(cred_files)
    f.update(kw)
    return f


def _quiet(got):
    return bool(got) and all(r["verdict"] == "allow" for _, r in got)


H = "/Users/u"
EXACT = [posixpath.join(H, s) for s in hsb.SECRETS + hsb.CRED_SOURCES]


# ================================================================================================ units: is every source closed?
@pytest.mark.parametrize("deny,allow,cred_files,pred", [
    ([H], [], [], True),                                              # denyRead ~/ (a parent) -- L2 check listed for Deus
    (EXACT, [], [], True),                                            # what --setup-strict writes
    ([posixpath.join(H, s) for s in hsb.SECRETS], [], [], False),     # the 0.2.58 set: the keychain and the browsers are open
    ([H], [], None, False),                                           # a client before 11.11: no cred_files -> not known (87facd5)
    ([H], [], ["~/.gitconfig: a URL with a password"], False),        # a credential in a file the sandbox must keep readable
    ([x for x in EXACT if not x.endswith("Keychains")] + [H + "/Library/Keychains/"], [], [], True),     # a trailing slash: same path
    ([x for x in EXACT if not x.endswith("Keychains")] + [H + "/library/keychains"], [], [], False),     # other case: Seatbelt matches
    #                                                                   the path as the file system spells it (fail closed, L2 check)
    ([x for x in EXACT if not x.endswith("Keychains")] + [H + "/Library/Keychain"], [], [], False),      # a typo
    ([x for x in EXACT if not x.endswith("Keychains")] + ["$HOME/Library/Keychains"], [], [], False),    # not an absolute path
    ([x for x in EXACT if not x.endswith("Keychains")] + [H + "/Library/Keychains/*"], [], [], False),   # a glob the client did not cut
    ([H], [H + "/Library/Keychains/login.keychain-db"], [], False),  # allowRead re-opens a file inside
    ([H], [H + "/Library"], [], False),                               # PRED was True: allowRead ~/Library is MORE specific than deny ~/
    #                                                                   (the more specific entry wins, L2 OTCHET-V3-L2): it re-opens
    (EXACT, [H + "/Library"], [], True),                              # with the exact entries it is less specific: still closed
])
def test_cred_closed(deny, allow, cred_files, pred):
    f = _fact(H, TYPICAL, deny=deny, cred_files=cred_files, allow_read=allow)
    if cred_files is None:
        f.pop("cred_files", None)
    PRED = pred
    assert hsb.cred_closed(f, H)[0] is PRED, hsb.cred_closed(f, H)


def test_secrets_deny_is_case_exact_too():
    """The same Seatbelt law for the 0.2.58 SECRETS: a deny entry `~/.SSH` does not deny `~/.ssh` (fail closed); allowRead `~/.SSH` still
    re-opens it (fail closed the other way)."""
    f = _fact(H, [], deny=[x if not x.endswith("/.ssh") else H + "/.SSH" for x in EXACT])
    PRED = False
    assert hsb.evaluate(f, ["pytest"], H, H + "/p")[0] is PRED
    f = _fact(H, [], deny=EXACT, allow_read=[H + "/.SSH"])
    assert hsb.evaluate(f, ["pytest"], H, H + "/p")[0] is PRED


def test_cred_files_is_never_malformed():
    f = _fact(H, TYPICAL, cred_files=[""])
    PRED = False
    assert hsb.well_formed(f) is PRED
    f = _fact(H, TYPICAL, cred_files=["x"] * 65)
    assert hsb.well_formed(f) is PRED


# ================================================================================================ back to silence: code without a named write host
QUIET_CLOSED = [
    "pytest -q",
    "npm run release",                                                # no credential reachable: cannot publish in the person's name
    "python3 tools/release.py",
    "make gist",
    "bash scripts/ship.sh",
    # "git commit -m wip": PRED was quiet -- asked with an empty list too (git commit is not a runner; not this rule)
    "git fetch origin",                                               # a read (the keychain helper finds nothing)
    "python3 -c \"import urllib.request as u; print(u.urlopen('https://pypi.org/pypi/x/json').status)\"",
    # residual, accepted (Р-1011): a host the line does not show; without a credential of the person it is not "in your name"
    "python3 -c \"import base64,urllib.request as u; u.urlopen(base64.b64decode('aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9naXN0cw==').decode())\"",
]
ASKED_CLOSED = [
    "git push origin main",
    "git -C . push",
    "python3 -c \"import subprocess; subprocess.run(['git', 'push', 'origin', 'main'])\"",
    "npm publish",
    "yarn npm publish",
    "pnpm publish --access public",
    "twine upload dist/*",
    "uv publish",
    "gh gist create notes.md",
    "gh api -X POST repos/a/b/issues -f title=x",
    "gh release create v1 dist/x.tgz",
    "curl -s https://api.github.com/repos/a/b",                       # a write host named (a GET too: the owner's rule "named = asked")
    "curl -s https://API.GitHub.com/repos/a/b",
    "curl -s -X POST https://api.github.com/gists -d @notes.json",
    "U=https://api.github.com/gists; curl -X POST $U -d x",           # the host in a variable: still written in the line
    "H=api.github.com; python3 -c \"import os,urllib.request as u; u.urlopen('https://'+os.environ.get('H',''))\"",
    "node -e \"fetch('https://api.github.com/gists', {method: 'POST', body: '{}'})\"",
    "curl -s https://uploads.github.com/x",                           # below a listed write host
    "curl -X POST \"$(echo aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9naXN0cw== | base64 -d)\" -d @README.md",   # a host the parser cannot see
    "C=git; $C push",                                                 # a program the parser cannot see
]


@pytest.mark.parametrize("cmd", QUIET_CLOSED)
def test_code_is_quiet_when_credentials_are_closed(client, owner, tmp_path, monkeypatch, cmd):
    d = _mk(client, owner, tmp_path, "q")
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", _fact(d.home, TYPICAL))
    PRED = True
    assert _quiet(d.send(cmd)) is PRED, (cmd, _v(d.send(cmd + " ")))


@pytest.mark.parametrize("cmd", ASKED_CLOSED)
def test_named_write_hosts_and_publication_are_asked(client, owner, tmp_path, monkeypatch, cmd):
    d = _mk(client, owner, tmp_path, "a")
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", _fact(d.home, TYPICAL))
    PRED = False
    assert _quiet(d.send(cmd)) is PRED, (cmd, _v(d.send(cmd + " ")))


@pytest.mark.parametrize("name,kw", [
    ("old-client", {"cred_files": None}),                                             # no field: 87facd5
    ("keychain-open", {"deny": "SECRETS"}),                                           # the 0.2.58 set only
    ("project-cred", {"cred_files": [".git/config: a URL with a password"]}),
    ("unknown-host", {"domains": ["example.com", "pypi.org"]}),                       # a write host whose credentials we do not know
    ("wildcard", {"domains": ["*.github.com"]}),
    ("gitlab-self", {"domains": ["git.corp-example.com"]}),
])
def test_87facd5_stays_when_not_closed(client, owner, tmp_path, monkeypatch, name, kw):
    d = _mk(client, owner, tmp_path, "n" + name[:4])
    deny = [posixpath.join(d.home, s) for s in hsb.SECRETS] if kw.get("deny") == "SECRETS" else None
    f = _fact(d.home, kw.get("domains", TYPICAL), deny=deny, cred_files=kw.get("cred_files", ()))
    if "cred_files" in kw and kw["cred_files"] is None:
        f.pop("cred_files", None)
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", f)
    PRED = False
    assert _quiet(d.send("pytest -q")) is PRED, (name, _v(d.send("pytest -q ")))


def test_empty_list_unchanged(client, owner, tmp_path, monkeypatch):
    d = _mk(client, owner, tmp_path, "e")
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", _fact(d.home, []))
    PRED = True
    assert _quiet(d.send("pytest -q")) is PRED
    PRED = False                                                      # a push with no list: the network is refused, but named: as before
    assert _quiet(d.send("git push origin main")) is PRED


# ================================================================================================ the question
def test_the_question_says_in_your_name_and_does_not_claim_the_keychain(client, owner, tmp_path, monkeypatch):
    d = _mk(client, owner, tmp_path, "w")
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", _fact(d.home, TYPICAL))
    got = d.send("python3 -c \"import subprocess; subprocess.run(['git', 'push', 'origin', 'main'])\"")
    rids = _pending(got)
    assert rids, _v(got)
    w = d.c.get("/api/approvals/" + rids[0]).json()
    PRED = True
    assert ("github.com" in w["harm"] and "your name" in w["harm"]) is PRED, w["harm"]
    assert ("can read your login keychain" in w["details"]) is (not PRED), w["details"]
    assert ("closed" in w["details"] and "github.com" in w["details"]) is PRED, w["details"]
    assert len(w["harm"].split()) <= 12
    e = _mk(client, owner, tmp_path, "w2")                            # not closed: the 87facd5 words
    f = _fact(e.home, TYPICAL)
    f.pop("cred_files")
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", f)
    w = e.c.get("/api/approvals/" + _pending(e.send("npm run release"))[0]).json()
    assert ("can read your login keychain" in w["details"]) is PRED, w["details"]


def test_write_open_unit():
    PRED = []
    assert hsb.write_open(TYPICAL, ["pytest"], [], [], "pytest -q", closed=True) == PRED
    PRED = hsb.write_hosts(TYPICAL)
    assert hsb.write_open(TYPICAL, ["pytest"], [], [], "pytest -q", closed=False) == PRED
    assert hsb.write_open(TYPICAL, ["git push"], [], [], "git push origin main", closed=True) == PRED
    assert hsb.write_open(["example.com"] + TYPICAL, ["pytest"], [], [], "pytest -q", closed=True) == hsb.write_hosts(["example.com"] + TYPICAL)


# ================================================================================================ a program the parser cannot see (c1e508b)
# With a list, c1e508b asks every line that hides a program (`$(which ...)`, `for d in $(find ...)`, a function): it could publish to a
# listed host. With every credential source closed and only CRED_HOSTS write hosts, a hidden program is code like any other: it is asked
# only when the line carries a publication word (push / publish / upload / gist / release / deploy) -- `C=git; $C push` stays asked.
@pytest.mark.parametrize("cmd,pred", [
    ("for p in $(which -a python3 pytest 2>/dev/null); do echo \"$p: $($p -c 'import sys;print(1)' 2>&1 | tail -1)\"; done", True),
    ("for d in $(find build -maxdepth 2 -type d -name x); do echo \"$d $(grep version $d/package.json)\"; done", True),
    ("C=git; $C push", False),
    ("C=npm; $C publish", False),
    ("f() { git status; }; f", True),
    ("f() { git push; }; f", False),
])
def test_hidden_programs_when_credentials_are_closed(client, owner, tmp_path, monkeypatch, cmd, pred):
    d = _mk(client, owner, tmp_path, "hp")
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", _fact(d.home, TYPICAL))
    PRED = pred
    assert _quiet(d.send(cmd)) is PRED, (cmd, _v(d.send(cmd + " ")))
    e = _mk(client, owner, tmp_path, "hq")                            # not closed: c1e508b / 87facd5 as before
    f = _fact(e.home, TYPICAL)
    f.pop("cred_files")
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", f)
    PRED = False
    assert _quiet(e.send(cmd)) is PRED


# ================================================================================================ real #752: a note that mentions github.com
# `cat >> notes.md <<'EOF' ... github.com/iProov/HAPS ... EOF` -- every program of the line is inert (no network, runs nothing): with the
# credential sources closed a host written in its text cannot be reached by it. Asked as before when a program could reach it.
@pytest.mark.parametrize("cmd,pred", [
    ("cat >> notes/R.md <<'EOF'\n## R-HAPS: spec at github.com/iProov/HAPS (Apache-2.0)\nEOF", True),
    ("echo 'see https://api.github.com/repos/a/b' >> notes/x.md", True),
    ("grep -rn 'registry.npmjs.org' package-lock.json | head -3", True),
    ("curl -s https://api.github.com/repos/a/b", False),
    ("echo https://api.github.com/gists | xargs curl -X POST -d @notes.md", False),
    ("cat >> notes/R.md <<'EOF'\ngithub.com\nEOF\npython3 tools/x.py", False),
])
def test_inert_lines_may_name_a_write_host_when_closed(client, owner, tmp_path, monkeypatch, cmd, pred):
    d = _mk(client, owner, tmp_path, "in")
    monkeypatch.setattr(hfs, "LOCAL_SANDBOX", _fact(d.home, TYPICAL))
    PRED = pred
    assert _quiet(d.send(cmd)) is PRED, (cmd, _v(d.send(cmd + " ")))
