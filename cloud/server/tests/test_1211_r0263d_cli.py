"""12.11 (r0263, server 0.2.93 / client 0.2.61, L3 item 8): the fact of a Claude Code started with `--setting-sources project,local
--settings <quiet-mode file>` (the L3 stand's recipe) is judged strict by the witness; the same without the file, or with --add-dir, is not.
The fact is the REAL client's (deus_witness.hook.sandbox_fact), the decision the server's hookjudge/sandbox.evaluate. PRED first."""
import json
import os
import sys

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))

from app.hookjudge import sandbox as hsb  # noqa: E402
from deus_witness.hook import failsafe, sandbox_fact as sf, strict  # noqa: E402


@pytest.mark.parametrize("flags,pred", [
    ("--setting-sources project,local --settings {f}", True),     # 0.2.60 client: doubt -> False
    ("--settings {f}", True),
    ("--setting-sources project,local", False),                   # quiet mode is in the file only: not loaded
    ("--settings {f} --add-dir /tmp", False),                     # more writable folders: a doubt
    ("--settings ./strict.json", False),                          # relative: unread
])
def test_cli_settings_are_judged(tmp_path, monkeypatch, flags, pred):
    home = tmp_path / "h"
    (home / ".claude").mkdir(parents=True)
    (tmp_path / "m").mkdir()
    proj = home / "p"
    proj.mkdir()
    f = tmp_path / "strict.json"
    f.write_text(json.dumps(strict.strict_settings({}, strict.DEFAULT_HOSTS)))
    monkeypatch.setattr(failsafe, "MANAGED_DIR_OVERRIDE", str(tmp_path / "m"))
    monkeypatch.setattr(sf, "ANCESTRY_OVERRIDE", ["/bin/sh -c deus-witness-hook", "claude " + flags.replace("{f}", str(f)), "-zsh"])
    fact = sf.fact({"command": "pytest"}, str(proj), env={"HOME": str(home)}, home=str(home), platform="darwin", permission_mode="default")
    assert hsb.well_formed(fact), fact
    ok, why = hsb.evaluate(fact, ["pytest"], str(home), str(proj))
    PRED = pred
    assert ok is PRED, (flags, why)
