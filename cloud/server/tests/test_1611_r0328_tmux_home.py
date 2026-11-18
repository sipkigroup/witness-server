"""r0328 (Я0 16.11, r1-05 / r2-36): the start-up files of the home folder are `persist` (FORBIDDEN_AUTOSTART) in EVERY home the hook can have,
not only in a home-shaped one (/Users/x, /home/x). One source: the real HOME of the hook (map_event home / env HOME) joins PERSIST_PATH."""
import pytest
from tests.test_1511_r0323_zakon import probe

HOMES = ["/Users/u", "/var/home/u", "/private/tmp/dw-ya0/home", "/srv/people/u"]
FAMILY = [".tmux.conf", ".config/tmux/tmux.conf", ".bashrc", ".zshrc", ".profile", ".config/fish/config.fish", ".vimrc", ".gitconfig"]


@pytest.mark.parametrize("h", HOMES)
def test_direct_form_tilde_and_home_var(h):
    for cmd in ("echo 'run-shell ./x.sh' >> ~/.tmux.conf", "echo 'run-shell ./x.sh' >> $HOME/.tmux.conf",
                "echo 'run-shell ./x.sh' >> ${HOME}/.tmux.conf", "echo 'run-shell ./x.sh' >> %s/.tmux.conf" % h):
        assert probe(cmd, home=h, proj=h + "/proj")[0] == "FORBIDDEN_AUTOSTART", (h, cmd)


@pytest.mark.parametrize("h", HOMES)
@pytest.mark.parametrize("rel", FAMILY)
def test_write_tool_family(h, rel):
    r = probe(None, home=h, proj=h + "/proj", tool="Write", inp={"file_path": h + "/" + rel, "content": "run-shell 'sh x'\n"})
    assert r[0] == "FORBIDDEN_AUTOSTART", (h, rel, r)


@pytest.mark.parametrize("h", HOMES)
def test_append_tee_and_variable(h):
    for cmd in ("echo 'run-shell ./x.sh' | tee -a ~/.tmux.conf", "echo 'run-shell ./x.sh' | tee -a %s/.tmux.conf" % h,
                "T=%s/.tmux.conf; echo 'run-shell ./x.sh' >> $T" % h, "echo 'run-shell ./x.sh' >> \"$HOME/.config/tmux/tmux.conf\"",
                "cat x.sh >> %s/.tmux.conf" % h):
        assert probe(cmd, home=h, proj=h + "/proj")[0] == "FORBIDDEN_AUTOSTART", (h, cmd)


@pytest.mark.parametrize("h", HOMES)
def test_project_tmux_conf_is_not_autostart(h):
    """neighbour kept (r0321): a project's own .tmux.conf starts nothing by itself"""
    r = probe(None, home=h, proj=h + "/proj", tool="Write", inp={"file_path": h + "/proj/.tmux.conf", "content": "set -g mouse on\n"})
    assert r[0] != "FORBIDDEN_AUTOSTART", r
    assert probe("echo 'set -g mouse on' >> .tmux.conf", home=h, proj=h + "/proj")[0] != "FORBIDDEN_AUTOSTART"
