"""12.11 (r0263, server 0.2.93): the question in plain words (owner 05.11 "ВОПРОС -- ПРОСТО"; L3 12.11 ISPYTANIE-L3-0260 Г).

Measured on L3 (headless person, 15 screenshots): the title said the parser's mark ("Your agent wants to run a dangerous command:
exit:/private/tmp/claude-501/-private-tmp-...", "opaque:.: the rest of the line cannot be judged", "net-out:npm install",
"(strict data) email_address") and "This command can damage files or leak data" for `python -m venv`; the command was repeated 3-4 times.
Now: title = the act in words, harm = one short line of THAT act, the mark only under Details; the command once in Details. PRED first."""
import json

import pytest

from app import qwords

MARKS = ("exit:", "opaque:", "net-out:", "(strict", "pipe-to-shell:", "rm-rf:", "secrets:", "loopback-write:")
GENERIC = "This command can damage files or leak data."


def _row(rc, text, tool="Bash.danger", reason="ESCALATE_COMMAND_DANGER", heads=None, cls="command"):
    return {"reason": reason, "tool": tool, "action_json": json.dumps({"class": cls, "recipient": rc}), "text_preview": text,
            "line_heads": json.dumps(heads or []), "cmd_meta": None}


@pytest.mark.parametrize("rc,text,heads,pred_word,pred_risk", [
    ("exit:.venv/bin/python [packages]", "python3 -m venv .venv && .venv/bin/python -m pip install -e .", ["python3 -m venv", ".venv/bin/python [packages]"], "install packages", "medium"),
    ("exit:/private/tmp/claude-501/-x/s1/scratchpad/venv/bin/pip [packages]", "/private/tmp/claude-501/-x/s1/scratchpad/venv/bin/pip install click", [], "install packages", "medium"),
    ("net-out:npm install", "npm install && npm test", ["npm install", "npm test"], "install packages", "medium"),
    ("opaque:.: the rest of the line cannot be judged", "python3 -m venv .venv && . .venv/bin/activate && pip install -e .", ["python3 -m venv", "."], "cannot fully check", "medium"),
    ("opaque:write to $TMPDIR/test-out.txt", "npm test > $TMPDIR/test-out.txt; tail $TMPDIR/test-out.txt", ["npm test", "tail"], "cannot fully check", "medium"),
    ("net-out:git push origin HEAD:main", "git push origin HEAD:main", ["git push"], "send your code", "high"),
    ("net-out:git fetch origin", "git fetch origin", ["git fetch"], "download code", "medium"),
    ("pipe-to-shell:curl -s http://127.0.0.1:8765/setup.sh | sh", "curl -s http://127.0.0.1:8765/setup.sh | sh", ["curl", "sh"], "run it at once", "high"),
    ("rm-rf:/Users/u/victim-dir", "rm -rf /Users/u/victim-dir", ["rm [recursive]"], "delete files", "high"),
    ("loopback-write:curl 127.0.0.1", "curl -X POST --data-binary @x http://127.0.0.1:9/", ["curl"], "program on this computer", "high"),
])
def test_title_is_words_not_the_mark(rc, text, heads, pred_word, pred_risk):
    w = qwords.words(_row(rc, text, heads=heads))
    PRED = (True, False, True, pred_risk)
    # r0299: under Details the mark is said in words (qwords.MARK_WORDS), never by its internal name ("Why Witness asks: exit" before)
    got = (pred_word in w["what"], any(m in w["what"] for m in MARKS) or w["harm"] == GENERIC,
           not any(m in w["details"] for m in MARKS) and ("Why Witness asks: " + rc.split(":")[0]) not in w["details"], w["risk"])
    assert got == PRED, w


@pytest.mark.parametrize("rc,text", [
    ("opaque:.: the rest of the line cannot be judged", ". .venv/bin/activate && pytest -q"),
    ("net-out:npm install", "npm install"),
])
def test_the_command_is_said_once_in_details(rc, text):
    w = qwords.words(_row(rc, text))
    PRED = 1
    assert w["details"].count(text) == PRED, w["details"]


def test_strict_words_for_a_file_tool():
    """r0262: a Write asked under the strict closed list said "a dangerous command: (strict later run) ..." (kind path)."""
    w = qwords.words(_row("(strict later run) /p/.github/workflows/ci.yml", "", tool="Write"))
    PRED = (False, True)
    assert ("dangerous command" in w["what"], "runs later by itself" in w["what"]) == PRED, w


# ---- twins: what stays as it was (fail closed / sharper words)
def test_an_unknown_mark_keeps_the_honest_general_title():
    w = qwords.words(_row("weird-new:thing", "x"))
    PRED = "Your agent wants to run a dangerous command: weird-new:thing"
    assert w["what"] == PRED and w["risk"] == "high"


def test_persistence_stays_critical():
    w = qwords.words(_row("persist:/Users/u/.zshrc", "echo x >> ~/.zshrc"))
    PRED = "critical"
    assert w["risk"] == PRED and "for good" in w["harm"], w


def test_danger_category_unit():
    PRED = [("install", "npm install"), ("push", "git push origin main"), ("fetch", "git clone https://github.com/a/b"),
            ("exit", "ssh host"), ("opaque", "x"), (None, "nomark"), (None, "Weird:x")]
    got = [qwords.danger_category(t) for t in ("net-out:npm install", "net-out:git push origin main", "net-out:git clone https://github.com/a/b",
                                                "exit:ssh host", "opaque:x", "nomark", "Weird:x")]
    assert got == PRED
