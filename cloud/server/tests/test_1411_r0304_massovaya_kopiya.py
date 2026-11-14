"""r0304 (prepared, not released; deploy/VERSION stays 0.2.126): a MASS copy into the home folder or a parent of autostart places.

Found in r0300 (Vault/layer1/R0300-LN-U28-VOROTA.md p.6): `cp -r dotfiles/. ~`, `rsync -a dotfiles/ ~`, `cp -a cfg/. ~/.config/` put files
whose names the line does not say into places where a file starts programs by itself. The parser could not see inside: nothing was said
(an ordinary write, "from now on" offered).

Now (bashparse._mass_copy):
  1. contents unknown -> the question `autostart` "copy into <folder>: which files land there is not known": "Allow once" / "No", never
     "from now on", never a refusal (the article is not certain);
  2. the source is a folder of the project that exists, nothing earlier in the line changed it, the hook answers exists / realpath of
     SRC/<place> -> judged exactly: a place found is `persist` (Н4, refused, as `cp .bashrc ~`); none found, nothing is added;
  3. the strict sandbox holds a copy into a folder outside the project and the temp folders (sandbox.contained); into the project, or
     into a folder above it, it stays asked.

PRED (written before the run): vorota/predskazanie-2026-11-14-M-r0304.md."""
import os
import re

import pytest

from tests.test_1211_r0264_tmpdir_e2e import rig  # noqa: F401  (the fixture; puts the client of this tree on the path)
from app import qwords, allowances as al
from app.hookjudge import sandbox
from app.hookjudge.bashparse import classify, AUTOSTART
from tests.helpers import H

HOME = "/Users/u"
PROJ = "/Users/u/proj"
UNKNOWN = ": which files land there is not known"


def _marks(cmd, home=HOME, proj=PROJ):
    return classify(cmd, proj, home, project=proj).danger


# ---- 1. contents unknown: the question, first mark, no refusal ---------------------------------------------------------------------
@pytest.mark.parametrize("cmd,land", [
    ("cp -r dotfiles/. ~", HOME),                       # the finding of r0300, word for word
    ("rsync -a dotfiles/ ~", HOME),
    ("cp -a cfg/. ~/.config/", HOME + "/.config"),
    ("cp -R dotfiles/ ~/", HOME),                        # BSD cp: a trailing '/' copies the contents
    ("cp -r ~/dots/. ~", HOME),                          # the source is outside the project: not asked of the hook
    ("cp -r $D/. ~", HOME),                              # a variable
    ("rsync -a host:dots/ ~", HOME),                     # a remote source
    ("cp dots/.* ~", HOME),                              # a glob names files too (no -r needed)
    ("mv dots/* ~", HOME),
    ("cp -rT dots ~", HOME),                             # GNU cp -T: the contents of dots ARE ~
    ("cp -r .claude ~", HOME + "/.claude"),              # a whole folder lands as ~/.claude (settings.json, hooks)
    ("cp -r Library ~", HOME + "/Library"),
    ("ln -s ~/dots/.config ~", HOME + "/.config"),       # a link of a whole folder
    ("cp -r dots ~/.config", HOME + "/.config"),         # no ~/.config yet: dots becomes it
    ("rsync -a --exclude .git dots/ ~", HOME),           # an option's value is no source
    ("cp -r a/. /etc/", os.path.realpath("/etc")),       # /private/etc on macOS, /etc on Linux (CI)
    ("cp -r tpl/. .", PROJ),                             # the project root: .claude/settings.json, hooks, .mcp.json, .git
])
def test_contents_unknown_is_asked_once(cmd, land):
    d = _marks(cmd)
    PRED = ("autostart:copy into %s%s" % (land, UNKNOWN), False)    # before r0304: no autostart mark (nothing said)
    assert (d[0] if d else None, any(x.startswith("persist:") for x in d)) == PRED, (cmd, d)


@pytest.mark.parametrize("cmd", [
    "cp -r src ~/x", "cp -r src/. build/", "cp ~/.bashrc /tmp/", "cp -r node_modules/. /tmp/x/", "rsync -a --exclude X src/ /tmp/out/",
    "cp -r dots ~/proj2/", "cp -r tpl/. sub/", "cp a.txt ~", "mv notes ~",
    # brace expansion: the shell builds the words (the line is asked as opaque already; its words are not ours to read)
    "rsync -a --exclude __pycache__ ~/proj/{server,mcp,web} /tmp/out/",
])
def test_twins_without_the_mark(cmd):
    d = _marks(cmd)
    PRED = False
    assert any(x.startswith(AUTOSTART + ":copy into ") for x in d) is PRED, (cmd, d)


def test_into_an_autostart_folder_stays_refused_as_in_r0300():
    PRED = ["persist:%s/.config/autostart/" % HOME]       # every name there starts programs: refused, unchanged
    assert _marks("cp -r x/. ~/.config/autostart/") == PRED


# ---- 2. the source is a readable folder of the project: judged exactly -------------------------------------------------------------
@pytest.fixture
def tree(tmp_path):
    home = os.path.realpath(str(tmp_path / "home"))
    proj = os.path.join(home, "proj")
    os.makedirs(os.path.join(proj, "clean", "sub"))
    open(os.path.join(proj, "clean", "notes.txt"), "w").close()
    return home, proj


def _put(proj, rel, link=None):
    p = os.path.join(proj, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    if link:
        os.symlink(link, p)
    else:
        open(p, "w").close()


@pytest.mark.parametrize("rel,cmd,mark", [
    ("dots/.bashrc", "cp -r dots/. ~", "persist:{H}/.bashrc"),
    ("dots/.zshrc", "rsync -a dots/ ~", "persist:{H}/.zshrc"),
    ("dots/Library/LaunchAgents/x.plist", "cp -R dots/. ~", "persist:{H}/Library/LaunchAgents"),
    ("dots/.config/fish/config.fish", "cp -r dots/. ~", "persist:{H}/.config/fish"),
    ("dots/systemd/user/x.service", "cp -a dots/. ~/.config/", "persist:{H}/.config/systemd/user"),
    ("dots/.claude/settings.json", "cp -r dots/. .", "persist:{P}/.claude/settings.json"),
    ("dots/.mcp.json", "cp -r dots/. .", "persist:{P}/.mcp.json"),
    ("dots/.git/hooks/pre-commit", "cp -r dots/. .", "autostart:copy into {P} brings .git"),
    ("dots/settings.json", "cp -r dots ~/.claude", "persist:{H}/.claude/settings.json"),
])
def test_found_in_a_project_folder_is_judged_exactly(tree, rel, cmd, mark):
    home, proj = tree
    _put(proj, rel)
    d = _marks(cmd, home, proj)
    PRED = mark.format(H=home, P=proj)                    # before r0304: [] (nothing said)
    assert PRED in d and not any(x.endswith(UNKNOWN) for x in d), d


def test_a_broken_link_of_that_name_lands_too(tree):
    home, proj = tree
    _put(proj, "dots/.zshrc", link="/nonexistent/evil")
    PRED = "persist:%s/.zshrc" % home                     # exists() is False for a broken link; realpath tells it is a link
    assert PRED in _marks("cp -r dots/. ~", home, proj)


@pytest.mark.parametrize("cmd", ["cp -r clean/. ~", "rsync -a clean/ ~", "cd clean && cp -r . ~", "cp -r clean/sub/. ~/.config",
                                 "mkdir -p x && cp -r clean/. ~", "cp -r clean ~/.claude"])
def test_nothing_found_adds_nothing(tree, cmd):
    home, proj = tree
    PRED = []                                             # exact: no autostart place in the folder
    assert [x for x in _marks(cmd, home, proj) if x.startswith(("autostart:", "persist:"))] == PRED


@pytest.mark.parametrize("cmd", [
    "git pull && cp -r clean/. ~",                        # the line may change the folder before the copy
    "curl -s https://x.example/a -o clean/b && cp -r clean/. ~",
    "python3 gen.py && cp -r clean/. ~",
    "cp -r nonexist/. ~",                                 # not there now (a clone earlier in the line, a typo): not readable
])
def test_not_readable_now_is_asked(tree, cmd):
    home, proj = tree
    d = _marks(cmd, home, proj)
    PRED = "autostart:copy into %s: which" % home         # (the detail is cut at 160 characters: a long temp path)
    assert any(x.startswith(PRED) for x in d) and not any(x.startswith("persist:") for x in d), d


# ---- 3. the strict sandbox -------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("det,held", [
    ("copy into /Users/u/.config" + UNKNOWN, True),       # outside the project: the sandbox refuses the write (the copy fails)
    ("copy into /Users/u/.claude" + UNKNOWN, True),
    ("copy into /private/etc" + UNKNOWN, True),
    ("copy into /Users/u" + UNKNOWN, False),              # above the project: proj/... could be written through it
    ("copy into /Users/u/proj" + UNKNOWN, False),         # the project root: .claude/hooks is not held by the sandbox
    ("copy into /Users/u/proj brings .git", False),
    ("copy into /Users/u/.conf", False),                  # a detail cut short: not certain, asked
])
def test_sandbox_holds_only_a_copy_outside_the_project(det, held):
    assert sandbox.contained("autostart:" + det, PROJ, HOME) is held


# ---- end to end: the real hook (this tree's client) against the in-process witness -------------------------------------------------
def _page(rig, rid):  # noqa: F811
    return rig.c.get("/api/approvals/" + rid, headers=H).json()


def test_question_says_the_truth_and_offers_once_only(rig):  # noqa: F811
    d, why = rig("cp -r nonexist/. ~")
    m = re.search(r"receipt (r_[A-Z2-7]{26})", why)
    assert d == "deny" and m and "ESCALATE_COMMAND_DANGER" in why and "FORBIDDEN" not in why, (d, why)
    x = _page(rig, m.group(1))
    PRED = (qwords.SCREEN["autostart_what"], qwords.SCREEN["autostart_harm"], "critical", False, False)
    got = (x["what"], x["harm"], x["risk"], x["allowance_offer"]["eligible"], x["repeat_offer"]["eligible"])
    assert got == PRED, (got, x.get("details"))
    assert x["allowance_offer"]["why_not"] == al.AUTOSTART_COPY_WHY
    assert x["action"]["recipient"].startswith("autostart:copy into ")
    assert "cannot see which files it brings" in x["details"] and "never allowed from now on" in x["details"], x["details"]


def test_end_to_end_found_is_refused_and_clean_is_not_autostart(rig):  # noqa: F811
    os.makedirs(os.path.join(rig.proj, "dots"))
    open(os.path.join(rig.proj, "dots", ".bashrc"), "w").close()
    d, why = rig("cp -r dots/. ~")
    PRED = ("deny", True)                                 # the hook answered exists / realpath of proj/dots/<place>: Н4
    assert (d, "FORBIDDEN" in why) == PRED, why
    os.makedirs(os.path.join(rig.proj, "clean"))
    open(os.path.join(rig.proj, "clean", "notes.txt"), "w").close()
    d2, why2 = rig("cp -r clean/. ~")
    assert "FORBIDDEN" not in why2, why2                  # an ordinary write outside the project (as before r0304)
    m = re.search(r"receipt (r_[A-Z2-7]{26})", why2)
    if m:
        assert not _page(rig, m.group(1))["action"]["recipient"].startswith("autostart:"), why2
