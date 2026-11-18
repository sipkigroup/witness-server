"""0.2.51 (MANDAT-PO-UMOLCHANIYU-2026-10-25, class (a) only): the default mandate lists 26 more read-only commands. Each runs without a question
in its plain form; every form of them that writes a file or runs a program is asked (or refused), judged by the real server under the
claude-code preset with the hook's own map_event."""
import os
import sys

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))

from app.hookjudge.bashparse import classify  # noqa: E402
from app.hookjudge.mapping import DEFAULT_SAFE_COMMANDS, default_form, map_event  # noqa: E402
from app.toolmap import CC_READONLY_COMMANDS  # noqa: E402
from app.flow.suggest import W6_READONLY_COMMANDS  # noqa: E402
from deus_witness.hook.form import DEFAULT_SAFE_COMMANDS as HOOK_LIST  # noqa: E402
from tests.helpers import act  # noqa: E402

ADDED = ["diff", "tree", "sort", "uniq", "cut", "tr", "nl", "column", "basename", "dirname", "realpath", "sha1sum", "sha256sum", "sha512sum",
         "shasum", "cmp", "comm", "test", "sleep", "git blame", "git ls-files", "git rev-parse", "git describe", "git shortlog", "git grep", "git reflog"]

PLAIN = ["diff -u a.txt b.txt", "tree -L 2 src", "sort -k2 -t, a.txt", "sort -to a.txt", "uniq -c a.txt", "uniq -f 1 a.txt", "cut -d, -f1 a.txt",
         "tr a-z A-Z < a.txt", "nl a.txt", "column -t a.txt", "basename src/a.py", "dirname src/a.py", "realpath src", "sha1sum a.txt",
         "sha256sum a.txt", "sha512sum a.txt", "shasum -a 256 a.txt", "cmp a.txt b.txt", "comm a.txt b.txt", "test -f a.txt", "sleep 1",
         "git blame a.txt", "git ls-files", "git rev-parse HEAD", "git describe --tags --always", "git shortlog -sn", "git grep -n foo -- src",
         "git grep --or -e a -e b", "git reflog", "git reflog show main", "git reflog exists main", "sort a.txt | uniq -c | sort -rn | head"]

# forms that write a file or run a program: never allowed without the owner (asked, or refused when they write outside the project)
RISKY = ["sort -o out.txt a.txt", "sort -ro out.txt a.txt", "sort -roout.txt a.txt", "sort --output out.txt a.txt", "sort --outp=out.txt a.txt",
         "sort --out=/etc/x a.txt", "sort -T /tmp a.txt", "sort --compress-program=./x a.txt", "sort --co=./x a.txt", "sort --compress-prog ./x a.txt",
         "uniq a.txt out.txt", "uniq -f 1 a.txt out.txt", "uniq -c a.txt /etc/u", "tree -o out.txt", "tree -ao out.txt", "tree -R -H . src",
         "git grep -O foo", "git grep -Ovim foo", "git grep -iOtouch foo", "git grep --open-files-in-pager=./x foo", "git grep --open=./x foo",
         "git reflog delete HEAD@{0}", "git reflog drop main", "git reflog write main a b c", "git reflog expire --all", "git reflog show --output=o.txt",
         "git -c core.pager=./x blame a.txt", "GIT_PAGER=./x git shortlog", "PAGER=./x git grep foo", "git --exec-path=/tmp describe",
         "diff a.txt <(./evil)", "xargs sha256sum < list", "column $F", "tree $D", "sha256sum ~/.ssh/id_rsa", "diff ~/.aws/credentials a.txt",
         "git describe --dirty; ./x"]


def test_four_copies_one_list_and_w6_narrow():
    assert list(CC_READONLY_COMMANDS) == DEFAULT_SAFE_COMMANDS == HOOK_LIST
    assert DEFAULT_SAFE_COMMANDS[22:48] == ADDED and len(set(DEFAULT_SAFE_COMMANDS)) == 112     # r0341: + 6 closed forms (test_1711_r0341); 0.2.53: + 15 local writes (test_0253); 0.2.54: + 4 (test_0254); r0325: + git init, xattr; r0335: + 9 state readers (test_1711_r0335)
    assert list(W6_READONLY_COMMANDS) == DEFAULT_SAFE_COMMANDS[:22]
    for not_a in ("gawk", "gsed", "less", "tac", "git stash", "git tag", "pytest", "tee", "git push", "git reset", "git clean"):
        assert not_a not in DEFAULT_SAFE_COMMANDS                    # class (c) stays out (find/sed/awk/jq: 0.2.54, test_0254)


@pytest.mark.parametrize("cmd", PLAIN)
def test_plain_form_is_the_listed_id(cmd):
    c = classify(cmd, "/proj", "/home/u")
    assert set(c.heads) <= set(DEFAULT_SAFE_COMMANDS) and not c.danger and not c.writes, (c.heads, c.danger, c.writes)


@pytest.mark.parametrize("cmd,heads", [
    ("sort -ro o a", ["sort [write]"]), ("sort --outp=o a", ["sort [write]"]), ("sort --co=./x a", ["sort [--compress-program]"]),
    ("sort -T /tmp a", ["sort [write]"]), ("uniq -f 1 a o", ["uniq [write]"]), ("tree -ao o", ["tree [write]"]), ("tree -R -H . s", ["tree [write]"]),
    ("git grep -iOx foo", ["git grep [-O]"]), ("git grep --open=x foo", ["git grep [-O]"]), ("git reflog drop", ["git reflog [write]"]),
    ("git reflog delete 'HEAD@{0}'", ["git reflog [write]"]),
])
def test_risky_forms_get_a_variant(cmd, heads):
    assert classify(cmd, "/proj", "/home/u").heads == heads


@pytest.mark.parametrize("cmd,w", [("sort -ro /etc/x a", "/etc/x"), ("sort --outp=/etc/y a", "/etc/y"), ("tree -ao /etc/t", "/etc/t"),
                                   ("uniq -f 1 a /etc/u", "/etc/u"), ("sort -bo/etc/z a", "/etc/z")])
def test_risky_writes_are_writes(cmd, w):
    assert classify(cmd, "/proj", "/home/u").writes == [os.path.realpath(w)]


def _send(client, hdr, cmd, proj, owner=None):
    out = []
    for m in map_event({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(proj)}):
        r = act(client, hdr, m.tool, m.args).json()
        out.append((m.tool, r["verdict"], r["reason"]))
        if owner is not None and r["verdict"] == "defer":
            assert owner.approve(r["rid"]).status_code == 200     # clears the pending queue: every line is judged on its own (no APPROVAL_RATE)
    return out


def test_on_the_server_plain_forms_run_risky_forms_do_not(client, owner, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.txt").write_text("b\na\n")
    ag, hdr = owner.new_agent("claude-code", "cc")
    owner.mandate(ag["id"], default_form(str(proj)))
    for cmd in PLAIN:
        assert _send(client, hdr, cmd, proj) == [("Bash", "allow", "OK")], cmd
    asked = {"ESCALATE_COMMAND", "ESCALATE_COMMAND_DANGER", "RESOURCE", "FORBIDDEN_SECRET_READ"}     # 06.11: or refused by an article
    for cmd in RISKY:
        r = _send(client, hdr, cmd, proj, owner)
        assert any(v in ("defer", "deny") and why in asked for _, v, why in r), (cmd, r)   # asked (defer) or refused (deny), never unasked
        assert not any(why in ("AGENT_FROZEN", "APPROVAL_RATE") for _, _, why in r), (cmd, r)
