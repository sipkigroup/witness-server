"""18.11 (kand8; live run nabor-1 on 0.2.135, S048 / S064): `spctl --status` and `hostname; scutil --get ComputerName; sw_vers` -- the
closed read-only forms of r0335 / r0341 -- were held as ESCALATE_WRITTEN_RUN in the live window (receipts r_FBMKND3K..., r_MEZ4XERC...).
Not the plugin's pin: the window ran client 0.2.79 (its PATH client wins over the plugin's uvx pin, the SessionStart line said so). The
cause: after an unseen write of the session (`scripts/run.sh` by a shell write, `.gitignore` G3), the "once" rule holds the next line that
RUNS CODE (actions.written_run_files), and runners.head_runs_code took every program off NOT_RUNNERS for a run -- spctl and scutil too.

Law: a head the parser gives only to a closed read-only form of a state reader (runners.STATE_FORM_HEADS) runs no code. Any other form of
the same program keeps its name and is a run as before (`spctl --master-disable`, `scutil --set`, `sysctl -w`).

L1: runners, the parser's heads and the gate actions._line_runs_code on the heads the stand journal recorded."""
import pytest

from app.hookjudge import bashparse as bp, runners as R

H, P = "/Users/u", "/Users/u/proj"


@pytest.mark.parametrize("line,head", [("spctl --status", "spctl --status"), ("scutil --get ComputerName", "scutil --get"),
                                       ("sw_vers", "sw_vers"), ("hostname", "hostname"), ("vm_stat", "vm_stat"),
                                       ("top -l 1", "top -l"), ("sysctl -n hw.ncpu", "sysctl read")])
def test_the_closed_form_is_its_head_and_runs_no_code(line, head):
    hs = bp.classify(line, P, H, project=P).heads
    assert hs == [head], hs
    assert not R.head_runs_code(head, line.split())


@pytest.mark.parametrize("line", ["spctl --master-disable", "spctl --add /tmp/x.app", "scutil --set HostName x", "sysctl -w a.b=1",
                                  "top"])
def test_any_other_form_is_a_run_as_before(line):
    hs = bp.classify(line, P, H, project=P).heads
    assert hs and all(h not in R.STATE_FORM_HEADS for h in hs), hs
    assert any(R.head_runs_code(h, line.split()) for h in hs), hs


def test_every_closed_form_of_a_state_reader_is_on_the_list():
    assert set(bp._STATE_IDENT.values()) - {"ruff check"} == R.STATE_FORM_HEADS     # ruff: NOT_RUNNERS already


# the heads the stand journal holds for the two held lines (actions.line_heads of r_FBMKND3K... and r_MEZ4XERC..., 18.11): the "once" rule
# of a risky write (actions.written_run_files) holds a line only when _line_runs_code says it runs code. L1 of that exact gate; an L2
# replay was not reproduced in process (the stand's trial mandate and its journal of writes are not rebuilt here).
@pytest.mark.parametrize("heads,line", [(["spctl --status"], "spctl --status"),
                                        (["hostname", "scutil --get", "sw_vers"], "hostname; scutil --get ComputerName 2>/dev/null; sw_vers")])
def test_the_held_live_lines_run_no_code(heads, line):
    from app import actions
    assert not actions._line_runs_code(heads, line)


@pytest.mark.parametrize("heads,line", [(["spctl"], "spctl --master-disable"), (["scutil"], "scutil --set HostName x"),
                                        (["hostname", "zork"], "hostname; zork"), (["spctl --status", "python3"], "spctl --status; python3 x.py")])
def test_a_line_with_a_run_still_runs_code(heads, line):
    from app import actions
    assert actions._line_runs_code(heads, line)
