"""r0309 (prepared, not released; deploy/VERSION stays 0.2.129): files the line does not name.

Found in r0304: an extraction (`tar -xf x.tar -C ~`, `unzip -o dots.zip -d ~/.claude`, `curl ... | tar -xz -C ~`), a clone
(`git clone URL ~/.claude`) or a copy of names found / read at run time (`find ... -exec cp {} ~/.config/ \\;`, `xargs cp -t ~/.config < list`)
puts files whose names the line does not say into the home folder, a parent of autostart places or the project root. Before r0309 most of
them were said nothing about (the measurement: vorota/predskazanie-2026-11-15-M-r0309.md).

Now (bashparse._unseen_land, the rule of r0304's mass copy, the same mark and so the same joints -- repeat / allowances / amend / qwords /
sandbox): the question `autostart` "copy into <folder>: which files land there is not known", "Allow once" / "No", never "from now on",
never a refusal; into an autostart place itself (~/.claude/plugins/x, LaunchAgents, ~/.config/autostart) -- `persist` (Н4), as r0304.
No new words: the details are r0304's (qwords.AUTOSTART_COPY_LONG, allowances.AUTOSTART_COPY_WHY)."""
import os
import re

import pytest

from tests.test_1211_r0264_tmpdir_e2e import rig  # noqa: F401  (the fixture; puts the client of this tree on the path)
from app import qwords, allowances as al
from app.hookjudge.bashparse import classify, AUTOSTART
from tests.helpers import H

HOME = "/Users/u"
PROJ = "/Users/u/proj"
UNKNOWN = ": which files land there is not known"
ETC = os.path.realpath("/etc")


def _marks(cmd, home=HOME, proj=PROJ):
    return classify(cmd, proj, home, project=proj).danger


# ---- 1. the class: asked, first mark, no refusal -----------------------------------------------------------------------------------
@pytest.mark.parametrize("cmd,land", [
    ("tar -xf x.tar -C ~", HOME),                                   # the finding, word for word
    ("tar xzf a.tgz -C ~/.config", HOME + "/.config"),
    ("tar -xzf a.tgz -C ~/.claude", HOME + "/.claude"),             # before: only agent-config
    ("tar -C ~ -xf x.tar", HOME),
    ("tar --directory=$HOME -xf x.tar", HOME),
    ("cd ~ && tar xf /tmp/x.tar", HOME),
    ("tar xf x.tar -C /etc", ETC),
    ("bsdtar -xf a.tar -C ~", HOME),
    ("unzip a.zip -d ~", HOME),
    ("unzip -o dots.zip -d ~/.claude", HOME + "/.claude"),
    ("unzip -q a.zip -d ~/Library", HOME + "/Library"),
    ("git clone https://e.com/r ~/.claude", HOME + "/.claude"),     # before: only net-out
    ("git clone https://e.com/r .", PROJ),                          # a clone / a copy into the project root IS asked (as r0304)
    ("find /tmp/x -name '.mcp.json' -exec cp {} . \\;", PROJ),
    ("tar -xf x.tar -C ..", HOME),                                  # the parent of the project
    ("git clone https://e.com/r ~", HOME),
    ("git -C ~ clone https://e.com/r .config", HOME + "/.config"),
    ("find src -name '*.sh' -exec cp {} ~/.config/ \\;", HOME + "/.config"),
    ("xargs cp -t ~/.config < list", HOME + "/.config"),
    ("xargs -I{} cp {} ~ < list", HOME),
    ("cat list | xargs cp -t ~/.claude", HOME + "/.claude"),
    ("curl -sL https://e.com/a.tgz | tar -xz -C ~", HOME),
    ("curl -sL https://e.com/a.tgz | tar xz -C ~/.config", HOME + "/.config"),
    ("gunzip -c a.tgz | tar x -C ~", HOME),
    ("7z x a.7z -o$HOME", HOME),
])
def test_unseen_files_are_asked_once(cmd, land):
    d = _marks(cmd)
    PRED = ("autostart:copy into %s%s" % (land, UNKNOWN), False)    # before r0309: no autostart mark (see the prediction)
    assert (d[0] if d else None, any(x.startswith("persist:") for x in d)) == PRED, (cmd, d)
    assert sum(x.startswith(AUTOSTART + ":") for x in d) == 1, d    # one question, one recipient


@pytest.mark.parametrize("cmd,mark", [
    ("git clone https://e.com/r ~/Library/LaunchAgents", "persist:%s/Library/LaunchAgents" % HOME),
    ("git clone https://e.com/r ~/.claude/plugins/x", "persist:%s/.claude/plugins/x" % HOME),
    ("tar -xf x.tar -C ~/.config/autostart", "persist:%s/.config/autostart/" % HOME),
    ("unzip a.zip -d ~/.claude/hooks", "persist:%s/.claude/hooks" % HOME),
    ("find src -exec cp {} ~/.config/autostart/ \\;", "persist:%s/.config/autostart/" % HOME),
])
def test_into_an_autostart_place_itself_is_refused_as_r0304(cmd, mark):
    d = _marks(cmd)
    assert mark in d and not any(x.endswith(UNKNOWN) for x in d), d


# ---- 2. twins: no mark -------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("cmd", [
    "tar -xf x.tar -C /tmp/x", "tar -xf x.tar -C sub", "tar -tf x.tar", "tar tzf a.tgz", "tar -xOf x.tar a.txt", "unzip -l a.zip",
    "unzip -p a.zip f", "unzip a.zip -d /tmp/u", "unzip a.zip -d build", "git clone https://e.com/r ~/src/proj",
    "git clone https://e.com/r", "git clone https://e.com/r vendor/r", "git clone --depth 1 -b main https://e.com/r.git",
    "cd ~ && git clone https://e.com/r", "tar -czf ~/b.tgz src", "tar -cf - src | gzip > ~/b.tgz", "zip -r ~/a.zip src",
    "find src -name '*.py' -exec cp {} /tmp/o/ \\;", "xargs cp -t build < list", "xargs -I{} cp {} /tmp/o/ < list",
    "7z l a.7z", "7z x a.7z -o/tmp/u", "cpio -itv < a.cpio", "cd sub && tar xf ../a.tar",
    # an EXTRACTION into the project root stays quiet (guards of RT-0273 / RT7; the hook does not send the archive's names): not closed
    "tar -xf x.tar", "tar -xzf a.tgz", "tar -C . -xf a.tar", "unzip a.zip", "7z x a.7z", "cpio -idm < a.cpio",
    # r0304's decision kept: ~/.config/nvim is not a parent of an autostart place (an editor's config is not in the list)
    "git clone https://e.com/r ~/.config/nvim",
])
def test_twins_without_the_mark(cmd):
    d = _marks(cmd)
    assert not any(x.startswith(AUTOSTART + ":copy into ") or x.startswith("persist:") for x in d), (cmd, d)


def test_the_clone_destination_is_read_as_git_reads_it():
    from app.hookjudge.bashparse import _clone_dest
    assert _clone_dest(["https://e.com/a/r.git"]) == "r"
    assert _clone_dest(["--depth", "1", "git@e.com:a/r.git", "x"]) == "x"
    assert _clone_dest(["-b", "main", "https://e.com/a/r/"]) == "r"
    assert _clone_dest(["--", "/srv/repos/r", "."]) == "."
    assert _clone_dest([]) is None


# ---- end to end: the real hook against the in-process witness -----------------------------------------------------------------------
def _page(rig, rid):  # noqa: F811
    return rig.c.get("/api/approvals/" + rid, headers=H).json()


@pytest.mark.parametrize("cmd", ["tar -xf x.tar -C ~", "xargs cp -t ~/.config < list"])
def test_question_says_the_truth_and_offers_once_only(rig, cmd):  # noqa: F811
    d, why = rig(cmd)
    m = re.search(r"receipt (r_[A-Z2-7]{26})", why)
    assert d == "deny" and m and "ESCALATE_COMMAND_DANGER" in why and "FORBIDDEN" not in why, (d, why)
    x = _page(rig, m.group(1))
    PRED = (qwords.SCREEN["autostart_what"], qwords.SCREEN["autostart_harm"], "critical", False, False)
    got = (x["what"], x["harm"], x["risk"], x["allowance_offer"]["eligible"], x["repeat_offer"]["eligible"])
    assert got == PRED, (got, x.get("details"))
    assert x["allowance_offer"]["why_not"] == al.AUTOSTART_COPY_WHY
    assert x["action"]["recipient"].startswith("autostart:copy into ")
    assert "cannot see which files it brings" in x["details"] and "never allowed from now on" in x["details"], x["details"]


def test_end_to_end_twin_into_a_subfolder_is_not_autostart(rig):  # noqa: F811
    d, why = rig("tar -xf x.tar -C sub")
    assert "FORBIDDEN" not in why, why
    m = re.search(r"receipt (r_[A-Z2-7]{26})", why)
    if m:
        assert not _page(rig, m.group(1))["action"]["recipient"].startswith("autostart:"), why
