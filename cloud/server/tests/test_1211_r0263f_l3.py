"""12.11 (server 0.2.93, not deployed): the L3 repeat on 0.2.61 (ISPYTANIE-L3-0260, "Повтор на 0.2.61"; it ran on the OLD server 0.2.92),
re-checked here on 0.2.93. PRED is written before each check; the outcome on 0.2.92 / db4cca5 is in the comment.

- the commit lines of the L3 sessions (several commands, a heredoc, Co-Authored-By ... <noreply@anthropic.com>): 0.2.92 strict: a
  question "(strict data) email_address"; without strict: DATA_FORBIDDEN. db4cca5 already silent (datarule.py): kept here as the L3 lines.
- the trailer's name was masked ("Co-Authored-By: [masked] Haiku 5.5"): AUTH matched inside AUTHOR (db4cca5 too). Fixed in toolmap.
- `git config user.email` in a line the client lock K1 cannot prove read-only: "a dangerous command: agent-config:(hook) git config",
  "could stay on your computer for good", Critical (db4cca5 too). Fixed in qwords (words, low for a read).
- "(strict data) email_address" in the title (db4cca5 too): the tag in words."""
import json
import random
import subprocess

import pytest

from app import qwords
from app import toolmap as t
from tests import test_redos_2910 as R
from deus_witness.hook import mask as c      # noqa: E402  (test_redos_2910 puts the client on the path)
from tests.test_0611_popravki import _mk, _v
from tests.test_1111_zakrytyy_spisok import _d, _quiet, _refused

C1 = """git add src/a.py README.md && git commit -q -F - <<'EOF'
Add shorten_middle utility

Add click.utils.shorten_middle(s, width).

Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>
EOF
git log --oneline -1 && git status --short && git show --stat HEAD | tail -5"""
C2 = 'git status --short && git add index.js readme.md && git commit -q -m "Return the number\n\nCo-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>" && git log --oneline -1 && git status --short'
C3 = ('./.venv/bin/python -m pytest -q 2>&1 | tail -3 && git status --short && git add src/a.py && '
      'git commit -q -m "feat: x" -m "Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>" && git log --oneline -1')


def _dev(client, owner, tmp_path, monkeypatch, strict):
    d = _d(client, owner, tmp_path, monkeypatch, "w") if strict else _mk(client, owner, tmp_path, "w")
    subprocess.run(["git", "init", "-q", d.proj], check=True)
    return d


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("cmd", [C1, C2])
def test_l3_commit_lines_are_silent(client, owner, tmp_path, monkeypatch, strict, cmd):
    got = _dev(client, owner, tmp_path, monkeypatch, strict).send(cmd)
    PRED = True                       # 0.2.92: strict -> asked "(strict data) email_address"; else deny DATA_FORBIDDEN
    assert _quiet(got) is PRED, (strict, _v(got))


@pytest.mark.parametrize("strict", [False, True])
def test_l3_commit_after_pytest_of_the_venv(client, owner, tmp_path, monkeypatch, strict):
    """The venv's python is not on the list of the test mandate: without strict it is asked for that (a command), never refused for data."""
    got = _dev(client, owner, tmp_path, monkeypatch, strict).send(C3)
    PRED = (False, strict)            # 0.2.92: not strict -> DATA_FORBIDDEN; strict -> asked "(strict data)"
    assert (_refused(got) or any(str(r.get("reason") or "").startswith("DATA") for _, r in got), _quiet(got)) == PRED, _v(got)


# ------------------------------------------------------------------------------------------------ the mask: AUTHOR is a name
@pytest.mark.parametrize("s,pred", [
    ("Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>", "Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>"),
    ("GIT_AUTHOR_NAME=Bob git commit", "GIT_AUTHOR_NAME=Bob git commit"),
    ("author: Jane", "author: Jane"),
    # the twins: still masked
    ("AUTH=s3cr3t", "AUTH=[masked]"),
    ("Authorization: abc123", "Authorization: [masked]"),
    ("AUTHORITY_TOKEN=x", "AUTHORITY_TOKEN=[masked]"),
    ("author_token=zz", "author_token=[masked]"),
    ('{"author_password": "p w"}', '{"author_password": [masked]}'),
    ("X-Api-Key: k-123", "X-Api-Key: [masked]"),
])
def test_author_is_not_a_secret_name(s, pred):
    PRED = pred
    assert t.mask_value(s, {}, 4096, shell=True) == PRED


def test_author_strings_server_masks_a_subset_of_the_client():
    """On every corpus string with an AUTHOR word, the server hides a subset of what the client copy hides (the exec preview of client
    0.2.61 masks more there), and what it shows more lies only in the value of a name whose single key word is AUTHOR."""
    rnd = random.Random(1211)
    corpus = [x for x in R._corpus(4000) if t._AUTHOR_WORD.search(x)]
    corpus += ["".join(rnd.choice(["AUTHOR", "Authored", "-By", ": ", "=", "TOKEN", "x ", "\"", "auth", "_", "Claude", "\n", ";"])
                       for _ in range(rnd.randint(1, 10))) for _ in range(3000)]
    bad = []
    for s in corpus:
        for sh in (False, True):
            srv = {i for a, b in t.assign_spans(s, sh) for i in range(a, b)}
            cli = {i for a, b in c.assign_spans(s, sh) for i in range(a, b)}
            if not srv <= cli:
                bad.append(("more", sh, s))
            names = set()
            for m in list(t.ASSIGN_RE.finditer(s)) + list(t.ASSIGN_SH_RE.finditer(s)):
                if not t._secret_name(m.group(1)):
                    names |= set(range(m.start(3), len(s)))           # the value, and what a shell value runs on to
            for m in list(t.QUOTED_ASSIGN_RE.finditer(s)) + list(t.QUOTED_ASSIGN_SH_RE.finditer(s)):
                if not t._secret_name(m.group("k")):
                    names |= set(range(m.start("v"), len(s)))
            if not (cli - srv) <= names:
                bad.append(("freed", sh, s))
    PRED = []
    assert bad[:5] == PRED and len(corpus) > 3000


# ------------------------------------------------------------------------------------------------ the words of the question
def _row(rc, text, heads, reason="ESCALATE_COMMAND_DANGER"):
    return {"reason": reason, "tool": "Bash.danger", "action_json": json.dumps({"class": "command", "recipient": rc}), "text_preview": text,
            "line_heads": json.dumps(heads), "cmd_meta": None}


G1 = ".venv/bin/python -m pytest -q 2>&1 | tail -3; git status --short; git log --format='%an <%ae>' -1; git config user.name; git config user.email"
MARKS = ("agent-config", "(hook)", "exit:", "email_address", "(strict")


def test_git_config_read_in_a_line():
    w = qwords.words(_row("agent-config:(hook) git config", G1, [".venv/bin/python", "tail", "git status", "git log", "git config get"]))
    PRED = ("Your agent wants to read your git settings", False, "low", False)      # db4cca5: the mark, "for good", critical; r0264 (L3
    #                                                                                   q-Z62DVF): no internal "agent-config:(hook)" under a Low read
    assert (w["what"], "for good" in w["harm"], w["risk"], "Why Witness asks: agent-config:(hook) git config" in w["details"]) == PRED, w


@pytest.mark.parametrize("rc,heads,pred_what", [
    # twins: a write of git settings and the agent's own settings stay critical, in words
    ("agent-config:(hook) git config", ["git config get", "git config"], "Your agent wants to change git settings that run programs"),
    ("agent-config:(hook) git config", [], "Your agent wants to change git settings that run programs"),
    ("agent-config:(hook) /p/.claude/settings.json", [], "Your agent wants to change its own settings"),
    ("agent-config:/Users/u/.mcp.json", [], "Your agent wants to change its own settings"),
])
def test_agent_config_words_twins(rc, heads, pred_what):
    w = qwords.words(_row(rc, "x", heads))
    PRED = (pred_what, "critical", False)
    assert (w["what"], w["risk"], any(m in w["what"] for m in MARKS)) == PRED, w


@pytest.mark.parametrize("tags,pred", [("email_address", "an e-mail address"), ("api_key,email_address", "a key or token, an e-mail address"),
                                       ("new_tag", "a private value")])
def test_strict_data_title_in_words(tags, pred):
    w = qwords.words(_row("(strict data) " + tags, "echo x > f", []))
    PRED = ("Your agent's command contains " + pred, True, "medium")
    assert (w["what"], ("Why Witness asks: (strict data) " + tags) in w["details"], w["risk"]) == PRED, w
