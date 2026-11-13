"""r0274 (open server trial 13.11): a test run with HOME inside /tmp gets the account's home (testshim.home_outside_temp); the server's
temp excuse (execguard._G1_SAFE) is unchanged - the gate still lets a write into /tmp through and still asks for a home path."""
import os

import testshim
from app import execguard as eg

PROJ = "/srv/proj-r0274"


def test_home_of_this_run_is_not_a_temp_path():
    assert not testshim._under_temp(os.environ["HOME"])


def test_home_in_tmp_is_moved_out_and_a_real_home_is_kept():
    for h in ("/tmp/x", "/private/tmp/y", "/var/folders/ab/T/z", ""):
        e = {"HOME": h}
        got = testshim.home_outside_temp(e)
        assert got and e["HOME"] == got and not testshim._under_temp(got), (h, got)
    e = {"HOME": "/home/someone"}
    assert testshim.home_outside_temp(e) is None and e["HOME"] == "/home/someone"


def test_the_gate_still_excuses_temp_and_asks_for_home():
    assert "/tmp" in eg._G1_SAFE and "/var/folders" in eg._G1_SAFE        # the protection the tests no longer trip over: not weakened
    assert eg.gate_text("echo x > /tmp/notes.txt", PROJ) is None
    assert eg.gate_text("echo x > ~/notes-r0274.txt", PROJ) == "G1"
