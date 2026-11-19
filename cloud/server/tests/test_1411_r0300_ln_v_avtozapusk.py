"""r0300 (prepared, not released; deploy/VERSION stays 0.2.122): `ln` / `cp` / `mv` / `install` / `rsync` / `tee` / `dd of=` INTO a place that
starts programs by itself is refused (Н4, `persist` -> FORBIDDEN_AUTOSTART), as an ordinary write there is (r0299 report, "found, not fixed").

What was wrong before r0300 (checked on the r0299 tree):
1. `ln -s TARGET ~/.bashrc` (and -sf, -sfn, an absolute path, LaunchAgents/x.plist, .claude/settings.json, systemd, fish, .gitconfig ...):
   the parser remembered the new link BEFORE it judged `ln` itself, so the write of the link was followed to its target: "write /tmp/evil",
   no persist -> a question (outside). And the other way round: `ln -s ~/.bashrc backup` (a link FROM the place, a read) was "write
   ~/.bashrc" -> refused. Now the link is remembered after `ln` is judged; the paths after it still follow it (0.2.90, QA G).
2. Into a DIRECTORY whose entries start programs but which is not one itself (~/.config/systemd/user/, ~/.config/autostart/,
   ~/.config/fish/conf.d/, /etc/cron.d/, /etc/profile.d/), into ~ (`cp .bashrc ~`), into ~/.claude/ (`cp settings.json ~/.claude/`), into
   ~/.ssh/ (`cp authorized_keys ~/.ssh/`): the parser judged the directory only -> no persist. Now DIR/<name> is judged as named.
   A copy OF a home rc file into another folder (`cp ~/.bashrc /tmp/`, a backup) is not a write to an autostart place: unchanged.
Already refused before r0300 (kept by this file): cp / mv / install / tee / dd of= / `ln` without -s onto the place itself, and cp / mv /
install / rsync into ~/Library/LaunchAgents/ (the directory itself is in PERSIST_PATH).

PRED (written before the run): vorota/predskazanie-2026-11-14-M-r0300.md."""
import pytest

from app.hookjudge.bashparse import classify

HOME = "/Users/u"
PROJ = "/Users/u/proj"
LOST = "false && cd /private/tmp\n"
PLACES = (".bashrc", ".zshrc", ".zprofile", ".profile", ".config/fish/config.fish", "Library/LaunchAgents/x.plist",
          "Library/LaunchDaemons/x.plist", ".config/autostart/x.desktop", ".config/systemd/user/x.service", ".claude/settings.json",
          ".claude/settings.local.json", ".claude/hooks/pre.sh", ".claude/plugins/x/hooks.json", ".claude.json", ".mcp.json", ".gitconfig",
          ".config/git/config", ".ssh/authorized_keys", ".config/deus-witness/key")
LINKS = ("ln -s /tmp/evil %s", "ln -sf /tmp/evil %s", "ln -sfn /tmp/evil %s", "ln -s -f /tmp/evil %s", "ln --symbolic /tmp/evil %s",
         "ln -s evil.sh %s", "ln /tmp/evil %s", "ln -f /tmp/evil %s")
COPIES = ("cp a %s", "cp -f a %s", "mv a %s", "install -m 644 a %s", "rsync -a a %s", "tee %s < a", "dd if=a of=%s", "echo x > %s")


def _cats(cmd):
    return [x.split(":")[0] for x in classify(cmd, PROJ, HOME, project=PROJ).danger]


@pytest.mark.parametrize("place", PLACES)
@pytest.mark.parametrize("how", ["~/%s", "$HOME/%s", HOME + "/%s"])
@pytest.mark.parametrize("form", LINKS + COPIES)
def test_a_link_or_copy_onto_the_place_is_refused(place, how, form):
    cmd = form % (how % place)
    # before r0300: every `ln -s` form through ~ or the absolute path -> [] or [secrets] (the write followed to /tmp/evil): a question
    assert "persist" in _cats(cmd), (cmd, _cats(cmd))
    assert "persist" in _cats(LOST + cmd), (LOST + cmd, _cats(LOST + cmd))      # r0299: ~ / absolute do not depend on the folder


@pytest.mark.parametrize("cmd", [
    "ln -s ~/.bashrc backup", "ln -s ~/.bashrc /tmp/b", "ln -s ~/.zshrc ~/zshrc.bak", "ln -s ~/Library/LaunchAgents/x.plist y",
    "ln -s ~/.claude/settings.json settings.json.bak", "ln -s ~/.config/systemd/user/x.service x.service", "ln -sf ~/.gitconfig gitconfig",
    "ln -s ~/.bashrc /tmp/", "cp ~/.bashrc /tmp/", "cp ~/.zshrc ~/backup/", "cp ~/.gitconfig backup/", "cp ~/.bashrc bashrc.bak",
    "cp ~/Library/LaunchAgents/x.plist .", "rsync -a ~/.claude/settings.json /tmp/s.json",
    "cp notes.md ~/", "cp a b ~/", "cp -r src ~/.config/", "cp autostart ~/.config/",
])
def test_a_link_or_copy_FROM_the_place_is_a_read(cmd):
    # before r0300: every `ln -s <place> <name>` of this list (8) was "persist" (the parser followed the new link back to the place):
    # a backup link was refused
    assert "persist" not in _cats(cmd), (cmd, _cats(cmd))


def test_a_HARD_link_of_the_place_is_the_place():
    # r0347 (closed exam 2, EX2-069): `ln ~/.bashrc backup` (no -s) is no backup -- `backup` IS ~/.bashrc (one inode): a later "project"
    # write of it writes the start-up file. Was in the list above (a read) until r0347; now refused as the write it enables (Н4)
    assert "persist" in _cats("ln ~/.bashrc backup")


@pytest.mark.parametrize("cmd", [
    "cp a.service ~/.config/systemd/user/", "cp a.service ~/.config/systemd/user", "mv x.service ~/.config/systemd/user",
    "install -m644 x.service ~/.config/systemd/user/", "rsync -a x/ ~/.config/systemd/user/", "cp -t ~/.config/systemd/user a b",
    "ln -s /tmp/e ~/.config/systemd/user/", "ln -s /tmp/x.desktop ~/.config/autostart/", "cp a ~/.config/autostart",
    "cp a.fish ~/.config/fish/conf.d/", "sudo cp a /etc/cron.d/", "sudo cp a /etc/profile.d", "scp host:a.service ~/.config/systemd/user/",
    "cp .bashrc ~", "cp .bashrc ~/", "cp dotfiles/.zshrc $HOME/", "ln -s /tmp/.bashrc ~/", "cp settings.json ~/.claude/",
    "cp settings.json .claude/", "cp authorized_keys ~/.ssh/", "cp .mcp.json sub/", "cp -R autostart ~/.config/", "rsync -a hooks ~/.claude/",
    "ln -s /tmp/evil.plist ~/Library/LaunchAgents/", "ln -t ~/Library/LaunchAgents -s /tmp/x.plist", "cp x.plist ~/Library/LaunchAgents/",
])
def test_into_a_directory_lands_as_dir_slash_name(cmd):
    # before r0300 (all but the last three): no persist -- the directory alone was judged (a question about writing outside, or nothing)
    assert "persist" in _cats(cmd), (cmd, _cats(cmd))


@pytest.mark.parametrize("cmd,pred", [
    ("ln -s ~/.bashrc b; echo x >> b", True),                # the paths AFTER `ln -s` still follow the new link (0.2.90, QA G)
    ("ln -s ~/Library/LaunchAgents la && cp x.plist la/", True),
    ("ln -s ~/.bashrc b && cat b", False),
    ("install -d ~/.config/systemd/user", False),            # a directory made, no file in it
    ("mkdir -p ~/.config/systemd/user", False),
])
def test_twins(cmd, pred):
    assert ("persist" in _cats(cmd)) is pred, (cmd, _cats(cmd))


def test_the_rm_rf_through_a_new_link_stays():
    d = classify("ln -s ~/Documents ./docs && rm -rf ./docs/", PROJ, HOME, project=PROJ).danger
    assert any(x.startswith("rm-rf:") and "Documents" in x for x in d), d


def test_a_link_in_the_project_is_written_where_it_is():
    r = classify("ln -s ~/.aws src/cfg2", PROJ, HOME, project=PROJ)
    # before r0300: writes == ["/Users/u/.aws"] (the link's target): "a write outside the project" (RESOURCE) for a link made inside it
    assert r.writes == [PROJ + "/src/cfg2"], r.writes
