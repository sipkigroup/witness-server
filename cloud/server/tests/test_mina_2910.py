"""29.10 (RT-BASHRC-2910, the "mine"): the server's default_form refuses '/', the home directory and a folder above it, and POST /v1/trial
refuses a form whose write targets are the whole machine or a whole home directory (what a client older than 0.2.46 sends from ~)."""
import os

import pytest

from app.hookjudge.mapping import ProjectRefused, default_form


def test_default_form_refuses_root_home_and_above(tmp_path):
    h = tmp_path / "u" / "alice"
    (h / "proj").mkdir(parents=True)
    for d in ("/", str(h), str(h.parent), str(tmp_path), "~"):
        with pytest.raises(ProjectRefused):
            default_form(d, home=str(h))
    assert default_form(str(h / "proj"), home=str(h))["delete"]["targets"][0] == os.path.realpath(str(h / "proj")) + "/*"


def test_default_form_refuses_the_real_home():
    with pytest.raises(ProjectRefused):
        default_form(os.path.expanduser("~"))


def _form(target):
    f = default_form(os.path.join(os.path.realpath("/tmp"), "dw-mina-proj"), home="/nonexistent-home")
    f["delete"]["targets"][0] = target
    return f


@pytest.mark.parametrize("target", ["/*", "/Users/*", "/Users/alice/*", "/home/bob/*", "/root/*", "/var/root/*", "/Users/alice/"
                                    "/*"])
def test_trial_refuses_a_whole_home_form(client, target):
    r = client.post("/v1/trial", json={"form": _form(target), "client": {"name": "deus-witness", "version": "0.2.45"}})
    assert r.status_code == 422 and r.json().get("error") == "FORM_INVALID", r.text


@pytest.mark.parametrize("target", ["/Users/alice/proj/*", "/home/bob/src/app/*"])
def test_trial_keeps_a_project_form(client, target):
    r = client.post("/v1/trial", json={"form": _form(target), "client": {"name": "deus-witness", "version": "test"}})
    assert r.status_code == 200, r.text
