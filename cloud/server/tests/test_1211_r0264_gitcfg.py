"""12.11 (r0264, server 0.2.94 / client 0.2.62): reading git settings (L3 "Третий прогон на 0.2.93", q-Z62DVF) -- the REAL hook against the
in-process witness.

L3 measured (client 0.2.61, server 0.2.93): `sed ...; echo ---; git log ...; git config get ...` -> a question "Your agent wants to read
your git settings", Low risk, and under Details: "Only "Allow once" is available here: a dangerous command is never allowed for a project",
"Tool: Bash.danger", "Why Witness asks: agent-config:(hook) git config"; no "from now on".

Cause: the client lock K1 (agent_config_target) sees `git config` in a line that is not read-only AS A WHOLE (sed) and sends the harness
fact; the server then asks it as a dangerous agent-config question (an allowance would not help: 0.2.61 wants an owner-approved receipt).
Now: client 0.2.62 judges each `git config` by its own command (a read-only one does not touch the harness) -> the line goes the normal way
(allowed by the list, or an ordinary unlisted-command question, where "from now on" is offered). For a 0.2.61 hook the question stays, but
without the internal codes and with an honest note why only "Allow once". PRED first; the twins (writes of git config) stay asked."""
import json

import pytest

from tests.test_1211_r0264_tmpdir_e2e import rig  # noqa: F401  (the fixture; puts the client of this tree on the path)
from deus_witness.hook import main as thin
from tests.helpers import H

G1 = "sed -n 1,20p README.md; echo ---; git log --oneline -3; git config user.email"
G2 = ("sed -n 1,5p package.json 2>&1 | tail -3; git status --short; git log --format='%an <%ae>' -1; git config user.name; "
      "git config user.email")
G3 = "sed -n 1,20p README.md && git config get user.name && git config --get user.email"


def _rid(why):
    import re
    m = re.search(r"receipt (r_[A-Z2-7]{26})", why)
    return m.group(1) if m else None


def _page(rig, rid):
    return rig.c.get("/api/approvals/" + rid, headers=H).json()


@pytest.mark.parametrize("cmd", [G1, G2, G3])
def test_git_config_read_is_no_harness_question(rig, cmd):  # noqa: F811
    d, why = rig(cmd)
    PRED = False                       # 0.2.61: deny "waiting ... ESCALATE_COMMAND_DANGER" agent-config:(hook) git config
    assert ("agent-config" in why or "AGENT_CONFIG" in why or "ESCALATE_COMMAND_DANGER" in why) is PRED, why
    if d != "allow":                   # an unlisted command (sed is on no list of the test mandate): the ordinary question, "from now on" offered
        x = _page(rig, _rid(why))
        PRED2 = (True, None)
        assert (x["allowance_offer"]["eligible"], x["allowance_offer"]["why_not"]) == PRED2, (why, x["allowance_offer"])


@pytest.mark.parametrize("cmd", [
    "sed -n 1p README.md; git config core.hooksPath .h",
    "sed -n 1p README.md; git config user.email x@y.z",
    "sed -n 1p README.md; git config --get core.pager",                      # a key git runs
    "sed -n 1p README.md; git config -f ~/.aws/credentials --list",          # another file read as configuration
    "sed -n 1p README.md; git config get user.email > .git/hooks/pre-commit",
    "sed -n 1p README.md && git config --edit",
    "sed -n 1p README.md; git -c core.fsmonitor=./x config get user.name",
])
def test_twins_stay_the_owners(rig, cmd):  # noqa: F811
    d, why = rig(cmd)
    PRED = True                        # never allowed silently; asked as before
    assert (d != "allow") is PRED, (d, why)


def test_old_hook_question_has_no_internal_codes(rig, monkeypatch):  # noqa: F811
    """A 0.2.61 hook (its K1: any `git config` in a line not read-only as a whole): still a Low question, now without the contradictions."""
    monkeypatch.setattr(thin, "_config_word", lambda c: thin._CONFIG_WORDS.search(c))
    d, why = rig(G1)
    rid = _rid(why)
    assert rid and "ESCALATE_COMMAND_DANGER" in why, why
    x = _page(rig, rid)
    det = json.dumps(x, ensure_ascii=False)
    words = json.dumps([x.get("what"), x.get("harm"), x.get("details")], ensure_ascii=False)
    off = x["allowance_offer"]
    PRED = (True, False, False, False, False)
    got = ("read your git settings" in words, "agent-config:" in words, "Bash.danger" in words,
           "dangerous command is never allowed" in str(off.get("why_not")), off["eligible"])
    assert got == PRED, (got, words[:1500], off)
    assert "0.2.62" in str(off.get("why_not")), off
    assert "Tool: Bash" in det and x["risk"] == "low", x["risk"]
