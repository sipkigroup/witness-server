"""r0274 (open server trial 13.11): with HOME inside /tmp, 10 server tests failed -- the gates excused temp paths, so `~/...` was "temp".
285e397 moved the test run's HOME out of /tmp (testshim); this replaced that work-around by the fix of the gates (bashparse.around_home /
temp_in, execguard._g1_temp): the test run keeps whatever HOME it is given, and a home inside a temp root is still judged as a home."""
import os

from app import execguard as eg

PROJ = "/srv/proj-r0274"


def test_the_gate_still_excuses_temp_and_asks_for_home(monkeypatch):
    assert "/tmp" in eg._G1_SAFE and "/var/folders" in eg._G1_SAFE        # temp stays temp
    for h in (os.environ.get("HOME") or "/nonexistent-home", "/tmp/x-r0274", "/private/tmp/y-r0274", "/var/folders/ab/cd/T/z-r0274"):
        monkeypatch.setenv("HOME", h)
        assert eg.gate_text("echo x > /tmp/notes.txt", PROJ) is None, h
        assert eg.gate_text("echo x > ~/notes-r0274.txt", PROJ) == "G1", h
        assert eg.gate_text("echo x > %s/notes-r0274.txt" % h, PROJ) == "G1", h
        assert eg.gate_text("echo x > /tmp/notes.txt", PROJ, home=h) is None, h


def test_testshim_leaves_home_as_it_is():
    import testshim
    assert not hasattr(testshim, "home_outside_temp")
