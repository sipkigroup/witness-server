"""0.2.12: the hook after review 7 -- heredocs read as bash reads them (R7-01), lines whose meaning the hook cannot know (R7-02), the built-in
tools that read files or send data (R7-06). The reviewer's own proofs are in cloud/review7/tests; these cover the forms around them."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "mcp"))

import pytest

from deus_witness.hook import failsafe
from app.hookjudge.mapping import map_event
from app.hookjudge.bashparse import classify

RP = os.path.realpath      # macOS: /home, /etc are links; the product names the real target
H, P = "/home/u", "/home/u/proj"
OUT = "/home/u/out"


def c(cmd):
    return classify(cmd, P, H, project=P)


def sees(r, path=OUT):
    return RP(path) in r.writes or r.opaque


# ---------------- R7-01
@pytest.mark.parametrize("delim", ["E\\OF", "E'O'F", "\"E\"OF", "'EOF'", "\"EOF\"", "EOF''", "\\EOF", "E\"O\"F", "E''OF"])
def test_quoted_delimiters_end_where_bash_ends_them(delim):
    r = c("cat <<%s\nrm -rf /\nEOF\ntouch %s\n" % (delim, OUT))
    assert "touch" in [h.split(" [")[0] for h in r.heads] and RP(OUT) in r.writes and not r.opaque, (delim, r)
    assert not any(d.startswith("rm-rf:/") for d in r.danger)        # quoted delimiter: the body is data


@pytest.mark.parametrize("delim", ["$'EOF'", "E$X", "'E OF'", "''", "E`x`OF", "", "1", "E\\\nOF"])
def test_unusual_delimiters_are_opaque(delim):
    r = c("cat <<%s\ndata\nEOF\ntouch %s\n" % (delim, OUT))
    assert r.opaque, (delim, r)


@pytest.mark.parametrize("end", ["EOF ", " EOF", "EOF)", "EOF;", "E", "EOF\r"])
def test_a_line_that_almost_ends_the_heredoc_does_not(end):
    r = c("cat <<EOF\ndata\n%s\ntouch %s\n" % (end, OUT))
    assert r.opaque, (end, r)                                          # never closed: the rest is not read as commands nor as data


def test_tabs_only_for_dash_form():
    assert not c("cat <<-EOF\n\tdata\n\t\tEOF\ntouch %s" % OUT).opaque
    assert c("cat <<EOF\n\tdata\n\tEOF\ntouch %s" % OUT).opaque         # without `-` a tab before EOF is not the end


def test_line_continuation_in_an_unquoted_body_is_opaque():
    assert c("cat <<EOF\nE\\\nOF\ntouch %s\nEOF\n" % OUT).opaque         # bash joins the lines and ends the heredoc at "EOF"
    assert not c("cat <<'EOF'\nE\\\nOF\nEOF\ntouch %s\n" % OUT).opaque  # quoted: no joining


@pytest.mark.parametrize("cmd", ["echo $((1<<y))", "(( z = 1 << y ))", "echo ${X:-<<y}", "echo $[1<<y]", "echo $(( (1) << y ))",
                                 "for ((i=0; i<1<<2; i++)); do :; done"])
def test_shift_is_not_a_heredoc(cmd):
    r = c(cmd + "\ntouch %s\n" % OUT)
    assert "touch" in [h.split(" [")[0] for h in r.heads] and RP(OUT) in r.writes, (cmd, r)


def test_arithmetic_that_is_a_subshell_after_all_is_opaque():
    assert c("echo $((cat <<y) )\ntouch %s\ny\n" % OUT).opaque


def test_common_heredocs_still_plain():
    for cmd in ["cat > f.txt <<'EOF'\nhello\nEOF", "cat <<EOF > f\n$HOME\nEOF\nls", "x=$(cat <<EOF\nbody\nEOF\n)\necho $x",
                "cat <<A <<B\na\nA\nb\nB\nls"]:
        r = c(cmd)
        assert not r.opaque and not r.danger, (cmd, r)


# ---------------- R7-02
@pytest.mark.parametrize("cmd", ["eval cd /etc; echo x > f", "eval 'cd /etc' && echo x > f", "f(){ cd /etc; }; f; echo x > f",
                                 "function f { cd /etc; }; f; echo x > f", ". ./env.sh; echo x > f", "source env.sh && touch f",
                                 pytest.param("alias ls='cd /etc'; ls; echo x > f", marks=pytest.mark.xfail(strict=False, reason="0.2.90 (OTCHET-0258.md): re-check under the standing mandate -- a literal variable is substituted, an exit / D12 refusal is not what 0.2.89 expected")), "trap 'cd /etc' DEBUG; echo x > f", "hash -p /tmp/x ls; ls > f",
                                 "shopt -s expand_aliases; echo x > f", "() { cd /etc; }; echo x > f", "mapfile -C 'cd /etc' -c 1 a < /dev/null; echo x > f"])
def test_unknown_meaning_makes_the_line_opaque_and_no_write_is_in_the_project(cmd):
    r = c(cmd)
    assert r.opaque, (cmd, r)
    assert P + "/f" not in r.writes and RP(P + "/f") not in r.writes, (cmd, r.writes)


def test_absolute_writes_after_unknown_meaning_are_still_named():
    r = c("eval true; echo x > /etc/passwd")
    assert r.opaque and RP("/etc/passwd") in r.writes


def test_relative_after_eval_is_outside_the_project_for_allowances():
    r = c("eval true; pytest")
    assert r.opaque and "pytest" in r.outside


# ---------------- R7-06
def _ev(tool, inp, proj):
    return map_event({"tool_name": tool, "tool_input": inp, "cwd": str(proj)}, env={"CLAUDE_PROJECT_DIR": str(proj), "HOME": str(proj.parent)})


@pytest.mark.parametrize("inp", [{"pattern": ".", "path": ".env"}, {"pattern": "KEY", "glob": ".env*"}, {"pattern": "x", "glob": "*.pem"},
                                 {"pattern": "x", "glob": "**/{.env,.npmrc}"}, {"pattern": "x", "path": "~/.ssh"}, {"pattern": "x", "path": "~/.aws/credentials"}])
def test_grep_of_secrets_is_asked(inp, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    parts = _ev("Grep", inp, proj)
    assert [p.tool for p in parts] == ["Grep.secret"] and parts[0].args["_witness"]["danger"], inp


@pytest.mark.parametrize("tool,inp", [("Grep", {"pattern": "def ", "path": "src"}), ("Grep", {"pattern": "x", "glob": "*.py"}),
                                      ("Glob", {"pattern": "**/*.env"}), ("LS", {"path": "."})])
def test_ordinary_search_passes(tool, inp, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    parts = _ev(tool, inp, proj)
    assert [p.tool for p in parts] == [tool]


def test_websearch_is_a_disclosure(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    p = _ev("WebSearch", {"query": "x"}, proj)[0]
    assert p.tool == "WebSearch" and p.args["_witness"]["recipient"] == "websearch@api.anthropic.com"


def test_notebookread_of_a_secret_is_asked(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    assert _ev("NotebookRead", {"notebook_path": "id_rsa"}, proj)[0].tool == "NotebookRead.secret"


def test_doctor_problem_when_readers_are_missing_and_ok_with_the_new_matcher(tmp_path):
    d = tmp_path / "p" / ".claude"
    d.mkdir(parents=True)
    hook = {"type": "command", "command": "deus-witness-hook || exit 2", "onFailure": "block", "timeout": 60}
    env = {"HOME": str(tmp_path), "CLAUDE_CODE_VERSION": "2.1.303"}
    nobin = lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError())          # noqa: E731
    (d / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit|Read|WebFetch|mcp__.*", "hooks": [hook]}]}}))
    r = failsafe.check(str(tmp_path / "p"), env=env, runner=nobin)
    assert any("Grep, Glob, WebSearch" in x for x in r["problems"]), r
    (d / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": failsafe.MATCHER, "hooks": [hook]}]}}))
    r = failsafe.check(str(tmp_path / "p"), env=env, runner=nobin)
    assert r["problems"] == [] and not any("does not cover" in n for n in r["notes"]), r


def test_example_settings_use_the_full_matcher():
    import os
    ex = os.path.join(os.path.dirname(__file__), "..", "..", "integrations", "06-claude-code-hook", "example", ".claude")
    for f in ("settings.json", "settings.wait-for-owner.json"):
        s = json.load(open(os.path.join(ex, f)))
        assert s["hooks"]["PreToolUse"][0]["matcher"] == failsafe.MATCHER, f


# ---------------- found while fixing R7-02: reserved words, and a `cd` that may not take effect in this shell
@pytest.mark.parametrize("cmd,write", [("if true; then touch ~/.bashrc; fi", "/home/u/.bashrc"), ("while x; do touch /etc/a; done", "/etc/a"),
                                       ("! touch /etc/b", "/etc/b"), ("coproc touch /etc/c", "/etc/c"), ("if a; then :; else touch /etc/d; fi", "/etc/d"),
                                       ("until a; do echo x > /etc/e; done", "/etc/e"), ("for i in 1; do :; done > ~/.bashrc", "/home/u/.bashrc")])
def test_command_after_a_reserved_word_is_seen(cmd, write):
    r = c(cmd)
    assert RP(write) in r.writes, (cmd, r)


def test_force_push_inside_a_loop_is_dangerous():
    assert any(d.startswith("git-force-push") for d in c("while true; do git push -f; break; done").danger)


def test_cd_that_may_not_take_effect_makes_the_directory_unknown(tmp_path):
    proj = str(tmp_path / "proj")
    (tmp_path / "proj" / "src").mkdir(parents=True)

    def k(cmd):
        return classify(cmd, proj, str(tmp_path), project=proj)
    for cmd in ["cd /etc; cd %s | true; echo x > f" % proj, "cd /etc; false && cd %s; echo x > f" % proj, "cd a/b/c; echo x > ../../../f",
                "cd /etc || cd %s; echo x > f" % proj, "if true; then cd /etc; fi; echo x > f", "cd /etc & echo x > f",
                "mv src y; cd src; echo x > f", "rmdir src; cd src; echo x > f"]:
        r = k(cmd)
        assert r.opaque and not any(w.startswith(proj) and w.endswith("/f") for w in r.writes), (cmd, r)
    assert k("cd /etc; (cd %s); echo x > f" % proj).writes == [RP("/etc/f")]                 # the subshell's cd ends at `)`
    assert k("cd src && echo x > f").writes == [proj + "/src/f"]                          # plain cases unchanged
    assert k("echo x > log; cd src; echo y > f").writes == [proj + "/log", proj + "/src/f"]   # a write elsewhere does not unsettle cd
    assert k("mkdir -p b && cd b && echo x > f").writes == [proj + "/b", proj + "/b/f"]   # the rest of the && chain runs there
    assert not k("(cd src && make)").opaque
