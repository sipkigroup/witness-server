"""0.2.52: wrappers (time, env, nice, timeout, stdbuf, xargs, flock, ...) are read with their own option syntax (bashparse.WRAP_SYNTAX).
Before, every word starting with '-' was dropped and an option's value was taken for the command: `/usr/bin/time -o file echo x` was the
listed `file`, `time -o ls rm a` (runs rm) was the listed `ls`, `env -C /tmp ls` ran elsewhere and was judged in the project.
A plain read through a wrapper read for sure stays allowed; anything else is asked: an unknown option, a missing value or operand, an option
that moves the command elsewhere (env -C / --chdir / -P / -S, sudo -D), a file the wrapper writes (time -o), tracers and proxies."""
import os
import sys

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))

from app.hookjudge.bashparse import classify  # noqa: E402
from app.hookjudge.mapping import DEFAULT_SAFE_COMMANDS, default_form  # noqa: E402
from tests.test_0251_readonly import _send  # noqa: E402

P, H = "/proj", "/home/u"

PLAIN = ["nice -n 5 ls", "nice -5 ls", "nice --adjustment=3 ls", "timeout -s KILL 5 ls", "timeout 5 ls", "timeout --sig=KILL 5s ls",
         "timeout -k 1 2.5 ls", "stdbuf -oL ls", "stdbuf -o L ls", "stdbuf --output=0 -eL ls", "nohup ls", "nohup -- ls", "time ls",
         "time -p ls", "env -u X ls", "env LANG=C ls", "command ls", "exec ls", "ionice -c 2 -n 7 ls", "caffeinate -i ls",
         "timeout 5 nice -n 1 stdbuf -oL cat a.txt"]

ASKED = ["/usr/bin/time -o file echo x", "time -o ls rm a", "time -f %e -o out make", "time -ao out ls", "time --output=o.txt ls",
         "env -C /tmp ls", "env --chdir=/Users ls", "env --ch=/Users ls", "env -C/tmp ls", "env -S 'rm -rf x'", "env -P /tmp ls",
         "env -i PATH=/tmp ls", "strace ls", "strace -o out ls", "ltrace ls", "proxychains ls", "proxychains4 -q ls", "torsocks ls",
         "sudo ls", "sudo -D /tmp ls", "sudo -u root -- ls", "doas ls", "time --bogus ls", "timeout ls", "timeout -x 5 ls", "nice -n",
         "stdbuf -q ls", "nohup -x ls", "xargs -I{} cat {}", "ls | xargs -I {} cat {}", "xargs -0 cat", "watch 'ls; touch y'",
         "flock l -c 'rm x'", "flock -c 'rm x' l", "timeout --frob 5 ls", "env --chd /tmp ls", "time -o ~/.bashrc ls"]


@pytest.mark.parametrize("cmd", PLAIN)
def test_plain_read_through_a_wrapper_is_the_listed_id(cmd):
    c = classify(cmd, P, H, project=P)
    assert c.heads and set(c.heads) <= set(DEFAULT_SAFE_COMMANDS) and not c.danger and not c.writes and not c.opaque, (c.heads, c.danger, c.writes)


@pytest.mark.parametrize("cmd", ASKED)
def test_anything_else_is_not_a_plain_listed_command(cmd):
    c = classify(cmd, P, H, project=P)
    assert c.danger or c.writes or not set(c.heads) <= set(DEFAULT_SAFE_COMMANDS), (c.heads, c.danger, c.writes)


@pytest.mark.parametrize("cmd,heads,writes", [
    ("/usr/bin/time -o file echo x", ["echo [via time -o]"], ["/proj/file"]),       # was ['file']: the listed `file`, allowed unasked
    ("time -o ls rm a", ["rm [via time -o]"], ["/proj/ls", "/proj/a"]),              # was ['ls']: rm ran
    ("time -f %e -o out make", ["make [via time -o]"], ["/proj/out"]),                # was ['%e']
    ("timeout -s KILL 5 ls", ["ls"], []),                                              # was ['5']
    ("stdbuf -o L ls", ["ls"], []),                                                    # was ['L']
    ("env -u X ls", ["ls"], []),                                                       # was ['X']
    ("xargs -I{} cat {}", ["cat [via xargs]"], []),                                    # was ['cat']: the line was cut at `{`
    ("flock /proj/l ls", ["ls"], ["/proj/l"]),                                         # flock creates its lock file
])
def test_the_head_is_the_word_after_the_wrapper_options(cmd, heads, writes):
    c = classify(cmd, P, H, project=P)
    assert (c.heads, c.writes) == (heads, [os.path.realpath(w) for w in writes])


@pytest.mark.parametrize("cmd,why", [
    ("env -C /tmp ls", "env -C"), ("env --chdir=/Users ls", "env -C"), ("env --ch=/Users ls", "env -C"), ("env -S 'rm -rf x'", "env -S"),
    ("env -P /tmp ls", "env -P"), ("sudo -D /tmp ls", "sudo -D"), ("strace ls", "strace"), ("time --bogus ls", "time --bogus"),
    ("timeout ls", "timeout"), ("watch 'ls; touch y'", "watch"), ("flock l -c 'rm x'", "flock -c"), ("nohup -x ls", "nohup -x"),
])
def test_doubt_or_another_directory_is_opaque(cmd, why):
    c = classify(cmd, P, H, project=P)
    assert c.opaque and any(d.startswith("opaque:" + why) for d in c.danger), c.danger


def test_braces_still_cut_a_group():
    assert [h.split(" [")[0] for h in classify("if true; then { rm -rf y; }; fi", P, H).heads] == ["true", "rm"]     # 0.2.53: "rm [recursive ...]"
    assert classify("ls && { cat a; }", P, H).heads == ["ls", "cat"]
    assert classify("echo x > .git/hook{s..s}/pre-commit", P, H).opaque


def test_on_the_server_wrapped_reads_run_the_rest_is_asked(client, owner, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.txt").write_text("b\na\n")
    ag, hdr = owner.new_agent("claude-code", "cc")
    owner.mandate(ag["id"], default_form(str(proj)))
    for cmd in PLAIN:
        assert _send(client, hdr, cmd, proj) == [("Bash", "allow", "OK")], cmd
    asked = {"ESCALATE_COMMAND", "ESCALATE_COMMAND_DANGER", "RESOURCE"}
    for cmd in ASKED:
        r = _send(client, hdr, cmd, proj, owner)
        assert not all(v == "allow" for _, v, _ in r), (cmd, r)                         # never allowed unasked
        assert any(v in ("defer", "deny") and why in asked for _, v, why in r), (cmd, r)
        assert not any(why in ("AGENT_FROZEN", "APPROVAL_RATE") for _, _, why in r), (cmd, r)
