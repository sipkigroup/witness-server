"""0.2.46 (OTCHET-0.2.33-GITCONFIG, residual risk 1): trust on first use of git's configuration.

Before: the first report of a project was taken as confirmed. A `.git/config` poisoned BEFORE that report (diff.external, a filter, core.fsmonitor,
core.pager, an `!` alias ...) made a listed `git diff` / `git status` an allow, and git ran the stranger's program.
Now: the report carries the program-running keys of git's config (`_witness.exec.gitcfg`), and a git command asks the owner while such keys are
present and not confirmed by the owner (ESCALATE_EXEC_CHANGED, the page says "this repo's git config runs a program: ...")."""
import os
import sys

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))

from app import execguard  # noqa: E402
from app.hookjudge import execfiles  # noqa: E402
from app.hookjudge.mapping import map_event  # noqa: E402
from tests.helpers import act  # noqa: E402
from tests.org_helpers import ctx_of  # noqa: E402
from tests.test_0213 import CC, one, project  # noqa: E402

TEXT = "this repo's git config runs a program"


def poisoned(tmp_path, cfg):
    p = project(tmp_path)
    (p / ".git" / "config").write_text(cfg)
    return p


# ---------------------------------------------------------------- the red-team chain: poisoned before the first report
def test_poisoned_before_first_report_asks_and_the_owner_confirms_once(client, owner, tmp_path):
    p = poisoned(tmp_path, '[core]\n\tbare = false\n[diff]\n\texternal = "/tmp/evil.sh"\n')
    d = CC(client, owner, p)
    r = one(d, "git diff")
    assert (r["verdict"], r["reason"]) == ("defer", "ESCALATE_EXEC_CHANGED"), r                 # was allow OK: TOFU took the poison as the baseline
    pseudo = str(p / ".git" / "config") + execguard.GITCFG
    assert r["action"]["exec_changed"] == [pseudo]                                               # the receipt names it
    g = client.get("/api/approvals/" + r["rid"]).json()
    gp = g["exec_changed"]["git_programs"]
    assert gp[0]["config"] == str(p / ".git" / "config") and ["diff.external", "/tmp/evil.sh"] in gp[0]["runs"]
    assert TEXT in g["exec_changed"]["note"].lower() and "diff.external = /tmp/evil.sh" in g["exec_changed"]["note"]
    # other families are not affected; a command that is not git is not either
    assert one(d, "pytest -q")["reason"] == "OK"
    assert one(d, "ls")["verdict"] == "allow"
    # the owner approves once; the agent runs it; this config is now confirmed and git is free again
    assert owner.approve(r["rid"]).json()["verdict"] == "allow"
    r2 = one(d, "git diff")
    assert r2["rid"] == r["rid"] and d.present(r2["rid"])["result"] == "accept"
    assert execguard.state(ctx_of(client.app), d.ag["id"])[pseudo]["state"] == "ok"
    assert one(d, "git status")["reason"] == "OK"
    # a further program-running key changes the config: asked again (the config digest AND the program list)
    with open(p / ".git" / "config", "a") as f:
        f.write('[filter "x"]\n\tsmudge = /tmp/evil2\n')
    r3 = one(d, "git status")
    assert r3["reason"] == "ESCALATE_EXEC_CHANGED" and pseudo in r3["action"]["exec_changed"]


def test_clean_config_costs_nothing(client, owner, tmp_path):
    p = poisoned(tmp_path, '[core]\n\trepositoryformatversion = 0\n\tfsmonitor = false\n[remote "origin"]\n\turl = https://x/y.git\n'
                           '[alias]\n\tst = status\n[pager]\n\tlog = false\n[filter "lfs"]\n\trequired = true\n')
    d = CC(client, owner, p)
    assert one(d, "git status")["reason"] == "OK"
    assert one(d, "git diff")["reason"] == "OK"


@pytest.mark.parametrize("conf,key", [
    ('[diff "pdf"]\n\ttextconv = /tmp/e\n', 'diff.pdf.textconv'),
    ('[diff "x"]\n\tcommand = /tmp/e\n', 'diff.x.command'),
    ('[core]\n\tfsmonitor = /tmp/e\n', 'core.fsmonitor'),
    ('[core]\n\tpager = /tmp/e\n', 'core.pager'),
    ('[pager]\n\tdiff = /tmp/e\n', 'pager.diff'),
    ('[core]\n\tsshCommand = /tmp/e\n', 'core.sshcommand'),
    ('[gpg]\n\tprogram = /tmp/e\n', 'gpg.program'),
    ('[gpg "ssh"]\n\tprogram = /tmp/e\n', 'gpg.ssh.program'),
    ('[filter "x"]\n\tclean = /tmp/e\n', 'filter.x.clean'),
    ('[filter "x"]\n\tsmudge = /tmp/e\n', 'filter.x.smudge'),
    ('[filter "x"]\n\tprocess = /tmp/e\n', 'filter.x.process'),
    ('[alias]\n\td = "!/tmp/e"\n', 'alias.d'),
    ('[include]\n\tpath = ../evil.cfg\n', 'include.path'),
    ('[includeIf "gitdir:/"]\n\tpath = /tmp/x.cfg\n', 'includeif.gitdir:/.path'),
    ('[core]\n\thooksPath = /tmp/hooks\n', 'core.hookspath'),
    ('[credential]\n\thelper = !/tmp/e\n', 'credential.helper'),
    ('[merge "m"]\n\tdriver = /tmp/e %A\n', 'merge.m.driver'),
    ('[core]\n\teditor = /tmp/e\n', 'core.editor'),
    ('[DIFF]\n\tEXTERNAL = /tmp/e\n', 'diff.external'),                    # git keys are case-insensitive
    ('[diff.x]\n\ttextconv = /tmp/e\n', 'diff.x.textconv'),                # the old [section.subsection] spelling
])
def test_each_program_key_asks(client, owner, tmp_path, conf, key):
    p = poisoned(tmp_path, conf)
    d = CC(client, owner, p)
    r = one(d, "git status")
    assert r["reason"] == "ESCALATE_EXEC_CHANGED", (key, r)
    g = client.get("/api/approvals/" + r["rid"]).json()
    assert key in [k for k, v in g["exec_changed"]["git_programs"][0]["runs"]], g["exec_changed"]


def test_parser():
    ent = execfiles.parse_git_config('# c\n[core]\n\tpager = "less -R" ; comment\n\tfsmonitor\n[alias]\n\tx = "!f() { \\\n echo; }; f"\n'
                                     '\ty = log\n[url "ext::sh -c evil"]\n\tinsteadOf = https://\n')
    assert ["core.pager", "less -R"] in ent and ["core.fsmonitor", "true"] in ent
    assert ["alias.x", "!f() {  echo; }; f"] in ent and ["alias.y", "log"] in ent
    progs = execguard.git_programs_of(ent)
    assert ["core.pager", "less -R"] in progs and ["alias.x", "!f() {  echo; }; f"] in progs
    assert ["alias.y", "log"] not in progs and ["core.fsmonitor", "true"] not in progs


# ---------------------------------------------------------------- the protocol: an older hook, a bad report, the thin path
def _args(d, cmd):
    [m] = map_event({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": d.proj}, env={"CLAUDE_PROJECT_DIR": d.proj, "HOME": "/nonexistent-home"})
    return m


def test_older_hook_without_gitcfg_keeps_the_old_behaviour(client, owner, tmp_path):
    """A hook before 0.2.46 does not send `gitcfg`: the server cannot see the keys (fail-open, as 0.2.45; documented residual risk)."""
    p = poisoned(tmp_path, '[diff]\n\texternal = /tmp/evil.sh\n')
    d = CC(client, owner, p)
    m = _args(d, "git diff")
    assert "gitcfg" in m.args["_witness"]["exec"]
    del m.args["_witness"]["exec"]["gitcfg"]
    assert act(d.c, d.hdr, m.tool, m.args).json()["reason"] == "OK"


@pytest.mark.parametrize("bad", ["x", {"/rel/config": "x"}, {"rel": []}, {"/a/config": [["k"]]}, {"/a/config": [[1, "v"]]}])
def test_malformed_gitcfg_asks(client, owner, tmp_path, bad):
    p = project(tmp_path)
    d = CC(client, owner, p)
    m = _args(d, "git diff")
    m.args["_witness"]["exec"]["gitcfg"] = bad
    r = act(d.c, d.hdr, m.tool, m.args).json()
    assert r["reason"] == "ESCALATE_EXEC_CHANGED", (bad, r)


def test_cut_list_asks(client, owner, tmp_path):
    p = project(tmp_path)
    d = CC(client, owner, p)
    m = _args(d, "git diff")
    m.args["_witness"]["exec"]["gitcfg_cut"] = True
    assert act(d.c, d.hdr, m.tool, m.args).json()["reason"] == "ESCALATE_EXEC_CHANGED"


def test_thin_judge_keeps_gitcfg_and_the_list_names_the_keys():
    from app.hookjudge import judge as hj
    lst = hj.scan_list()
    gc = lst["git_config"]
    assert gc["files"] == ["config", "config.worktree"] and gc["max_entries"] >= 32 and gc["max_value"] >= 128
    import re
    rx = re.compile(gc["keys"], re.I)
    for k in ("diff.external", "filter.lfs.smudge", "core.fsmonitor", "alias.x", "includeif.gitdir:/x.path", "core.sshcommand"):
        assert rx.fullmatch(k), k
    for k in ("remote.origin.url", "user.email", "core.bare", "http.extraheader"):
        assert not rx.fullmatch(k), k                          # secrets of the config (tokens in URLs, headers) are not sent
    rep = {"root": "/p", "files": {}, "truncated": False, "rev": lst["rev"], "gitcfg": {"/p/.git/config": [["diff.external", "x"]]}, "gitcfg_cut": False}
    fx = hj._Facts({"fs": {}, "exec": rep, "home": "/h", "proc_cwd": "/p"}, lst["rev"])
    assert fx.report["gitcfg"] == rep["gitcfg"] and fx.report["gitcfg_cut"] is False


def test_masked_values_keep_the_program_shape():
    """0.2.52: the hook masks secrets inside values; the leading `!` and the digest logic still work on the masked text."""
    args = {"_witness": {"exec": {"gitcfg": {"/p/.git/config": [["credential.helper", "!f() { echo password=***; }; f"], ["alias.x", "echo ***"],
                                                                 ["core.sshCommand", "ssh -i /k"]]}}}}
    got = execguard.gitcfg_of(args)
    assert [k for k, _ in got["/p/.git/config"]] == ["credential.helper", "core.sshCommand"]       # a plain alias is no program
    assert execguard._gitcfg_digest(got["/p/.git/config"]) == execguard._gitcfg_digest(got["/p/.git/config"])
