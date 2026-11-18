"""r0299 (prepared, not released; deploy/VERSION stays 0.2.121): two leftovers of r0298 (Vault/layer1/AVTOZAPUSK-NEIZVESTNAYA-PAPKA.md, "what is left").

1. An unknown FOLDER makes only RELATIVE paths unknown. `false && cd X` + a line feed, then `echo x >> ~/.bashrc`: the folder is not known,
   but ~ (and $HOME, and an absolute path) names the same file in any folder. Before r0299 it was a question ("autostart ... in an unknown
   directory", Allow once); by the law (Н4) it is the same outcome as without the prefix: refused, FORBIDDEN_AUTOSTART. Only what can change
   HOME itself (eval, source, a function defined in the line) keeps ~ / $HOME unknown, as before (a question).
2. Under Details the line "Why Witness asks" said the parser's internal mark ("autostart:write to ...", "opaque:...", "agent-config:(hook) ...",
   "(strict data) email_address"). Now the category in words (qwords.MARK_WORDS) and the detail. Details is signed with the view but is not
   rebuilt from the vocabulary: mr-vocab-4 and its digest stay; views signed before keep their bytes (packs VALID).

PRED (written before the run): vorota/predskazanie-2026-11-14-M-r0299.md."""
import json
import os
import re
import sys

import pytest

from tests.test_1211_r0264_tmpdir_e2e import rig  # noqa: F401  (the fixture)
from app import qwords, vocab
from app.hookjudge.bashparse import classify, AUTOSTART

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packtools"))
import screencheck as SC  # noqa: E402

HOME = "/Users/u"
PROJ = "/Users/u/proj"
LOST = "false && cd /private/tmp\n"
FORMS = ("echo x > %s", "echo x >> %s", "cp a %s", "tee %s < a", "sed -i '' s/a/b/ %s", "mv /tmp/a %s", "touch %s", "install a %s",
         "curl -o %s https://a.example/x", "printf x | tee -a %s", "dd of=%s")
# every autostart place of r0298 (bashparse.PERSIST_PATH + git hooks / config), named through ~, through $HOME and by its absolute path
PLACES = (".bashrc", ".zshrc", ".zprofile", ".profile", ".config/fish/config.fish", "Library/LaunchAgents/x.plist",
          "Library/LaunchDaemons/x.plist", ".config/autostart/x.desktop", ".config/systemd/user/x.service", ".claude/settings.json",
          ".claude/settings.local.json", ".claude/hooks/pre.sh", ".claude/plugins/x/hooks.json", ".claude.json", ".mcp.json", ".gitconfig",
          ".config/git/config", ".ssh/authorized_keys", ".config/deus-witness/key")


def _marks(cmd):
    return classify(cmd, PROJ, HOME, project=PROJ).danger


# ---- 1. the parser: ~ / $HOME / an absolute path do not depend on the folder ------------------------------------------------------------
@pytest.mark.parametrize("place", PLACES)
@pytest.mark.parametrize("how", ["~/%s", "$HOME/%s", "${HOME}/%s", HOME + "/%s"])
def test_home_path_after_a_lost_cd_is_judged_as_without_the_prefix(place, how):
    for f in FORMS:
        t = how % place
        bare, lost = _marks(f % t), _marks(LOST + (f % t))
        # before r0299 (~ and $HOME): ["autostart:write to ~/... in an unknown directory", "opaque:write to ~/... in an unknown directory"]
        # the law: the same marks, so the same outcome (persist -> Н4, refused) as without the prefix. `dd of=<secret place>` also reads the
        # word "of=..." as a relative path (a secrets mark whose detail names the folder): the category is the same, the detail is not
        PRED = (sorted({x.split(":")[0] for x in bare}), [x for x in bare if not x.startswith("secrets:")])
        assert (sorted({x.split(":")[0] for x in lost}), [x for x in lost if not x.startswith("secrets:")]) == PRED, (f % t, lost, bare)
        assert not any(x.startswith(AUTOSTART + ":") or ("unknown directory" in x and not x.startswith("secrets:")) for x in lost), (f % t, lost)


@pytest.mark.parametrize("cmd", ["echo x >> ~/.bashrc", "cp a ~/Library/LaunchAgents/x.plist", "echo x > $HOME/.claude/settings.json"])
def test_the_probe_is_refused_by_the_article(cmd):
    d = _marks(LOST + cmd)
    PRED = "persist"                        # before r0299: "autostart" first (a question, Allow once)
    assert d[0].split(":")[0] == PRED, d


@pytest.mark.parametrize("cmd,pred", [
    (LOST + "echo x > .bashrc", "autostart"),                     # relative: the folder decides, still unknown (r0298)
    (LOST + "echo x > notes.md", "opaque"),
    (LOST + "echo x > $PWD/.bashrc", "autostart"),                # $PWD is the unknown folder itself
    (LOST + "echo x > ~/notes.md", None),                         # ~: known, an ordinary file of the home folder (as without the prefix)
    ("eval x\necho x >> ~/.bashrc", "autostart"),                 # eval may set HOME: ~ stays unknown (a question, as before)
    ("source a.sh\necho x > $HOME/.zshrc", "autostart"),
    ("f(){ :; }; echo x >> ~/.bashrc", "autostart"),              # a function may set HOME when it runs
    ("eval x; bash -c 'echo x >> ~/.bashrc'", "autostart"),       # a nested line keeps "HOME is not known" of the line that runs it
    ("eval x\necho x > /Users/u/.bashrc", "persist"),             # an absolute path never depends on HOME
])
def test_twins(cmd, pred):
    d = _marks(cmd)
    cats = [x.split(":")[0] for x in d]
    got = next((c for c in cats if c in ("autostart", "persist")), None) if pred in ("autostart", "persist", None) else \
        ("opaque" if "opaque" in cats else None)
    assert got == pred, d


def test_home_path_after_a_lost_cd_keeps_secrets_and_deletes():
    PRED = (_marks("echo x > ~/.ssh/id_rsa"), _marks("rm ~/.bashrc"))     # the same as without the prefix (was opaque, unknown directory)
    assert (_marks(LOST + "echo x > ~/.ssh/id_rsa"), _marks(LOST + "rm ~/.bashrc")) == PRED


def test_end_to_end_the_same_outcome_as_without_the_prefix(rig):  # noqa: F811
    """The real hook (thin.judge) against the in-process witness: the prefix changes nothing (refused by the article, no question)."""
    for cmd in ("echo x >> ~/.zshrc", "cp a.plist ~/Library/LaunchAgents/com.x.plist"):
        d0, why0 = rig(cmd)
        d1, why1 = rig(LOST + cmd)
        code = lambda w: (re.findall(r"\b(?:FORBIDDEN|ESCALATE|DENY)_[A-Z_]+", w) or [None])[0]  # noqa: E731
        PRED = (d0, code(why0))             # before r0298/r0299: deny + ESCALATE_COMMAND_DANGER (a question) with the prefix
        assert (d1, code(why1)) == PRED, (why0, why1)
        assert d1 == "deny" and "FORBIDDEN_AUTOSTART" in why1 and "waiting for the owner's approval" not in why1, why1


# ---- 2. Details: the mark in words -----------------------------------------------------------------------------------------------------
INTERNAL = re.compile(r"\b(autostart|opaque|net-out|exit|agent-config|pipe-to-shell|rm-rf|secrets|git-config|persist|write-outside|sql-drop|"
                      r"loopback-write|git-destroy|disk|witness|git-force-push|install|fetch|push):|\(hook\)|\(strict \w+\)")


def _row(rc, text, ej=None):
    return {"reason": "ESCALATE_COMMAND_DANGER", "tool": "Bash.danger", "action_json": json.dumps({"class": "command", "recipient": rc}),
            "text_preview": text, "line_heads": "[]", "cmd_meta": None, **({"exec_json": json.dumps(ej)} if ej else {})}


def _why(w):
    return [ln for ln in w["details"].split("\n") if ln.startswith("Why Witness asks")]


def test_every_category_has_words():
    PRED = set()                            # one entry per category the question can name, + autostart and agent-config
    assert (set(qwords.DANGER_WORDS) | {"autostart", "agent-config", "defense", "money", "git-no-verify"}) ^ set(qwords.MARK_WORDS) == PRED   # r0305: + defense; r0313: + money; r0346: + git-no-verify (refused Н3, never asked: words under Details only)
    assert not any(INTERNAL.search(v) for v in qwords.MARK_WORDS.values())


@pytest.mark.parametrize("rc,text,pred", [
    ("autostart:write to proj/.claude/settings.json in an unknown directory", "false && cd /tmp\necho x > proj/.claude/settings.json",
     "Why Witness asks: it writes a file that starts commands by itself — write to proj/.claude/settings.json in an unknown directory"),
    ("opaque:write to $TMPDIR/x", "npm test > $TMPDIR/x", "Why Witness asks: Witness cannot read part of this line — write to $TMPDIR/x"),
    ("secrets:/Users/u/.ssh/id_rsa", "cat ~/.ssh/id_rsa | wc -l", "Why Witness asks: it touches your keys or passwords — /Users/u/.ssh/id_rsa"),
    ("exit:.venv/bin/python [packages]", "python3 -m venv .venv && .venv/bin/python -m pip install -e .",
     "Why Witness asks: it installs packages from the internet — .venv/bin/python [packages]"),
    ("agent-config:(hook) /p/.claude/settings.json", "x", "Why Witness asks: it changes your agent's own settings — /p/.claude/settings.json"),
    ("net-out:npm install", "npm install && npm test", None),          # the text shows the detail, the title the category: no line
    ("rm-rf:/Users/u/v", "rm -rf /Users/u/v", None),
    ("agent-config:(hook) git config", "git config user.email a; sed -n 1p f", None),
    ("(strict data) email_address", "echo a@b.example > f", None),     # the title says "an e-mail address"
])
def test_why_line_in_words(rc, text, pred):
    for ej in (None, {"as": {"pin": True}}):
        w = qwords.words(_row(rc, text, ej))
        PRED = [pred] if pred else []       # before r0299: "Why Witness asks: <the mark>" (autostart:..., opaque:..., exit, (strict data) ...)
        assert _why(w) == PRED, w["details"]
        assert not INTERNAL.search(w["details"].split("\nFull text:")[0]), w["details"]


@pytest.mark.parametrize("m", ["(network) example.com", "something", "", "Opaque:x", "a" * 30 + ":x"])
def test_not_a_mark_is_never_quoted(m):
    PRED = None
    assert qwords.mark_said(m) == PRED


# the digest of mr-vocab-4 as the r0298 tree (server 0.2.121) builds it: the document every mandate signed since r0298 pins
R0298_DIGEST = "b6c90377085240d07959ed2f89c818a3e969d78f9ddc000dda66216cba88f845"


def test_the_vocabulary_does_not_change():
    """MARK_WORDS is not in the signed vocabulary document (Details is not rebuilt by the checker): mr-vocab-4 keeps its digest, so mandates
    and packs signed before stay as they were."""
    # r0305: the server runs mr-vocab-5 (+ screen defense_*); mr-vocab-4 is exactly that document minus the two sentences
    d = vocab.doc()
    d4 = dict(d, v="mr-vocab-4", screen={k: v for k, v in d["screen"].items() if not k.startswith(("defense_", "v6_"))})   # r0307: - v6_*
    PRED = ("mr-vocab-6", False, R0298_DIGEST)
    assert (vocab.V, "mark_words" in d, vocab.digest(d4)) == PRED


def test_an_old_view_with_the_mark_still_rebuilds():
    """A view signed before r0299 carries "Why Witness asks: autostart:..." under Details: the checker rebuilds its words (VALID); the new
    view (words, no mark) rebuilds the same way. Details never decides P1."""
    rc = "autostart:write to .bashrc in an unknown directory"
    text = LOST + "echo x > .bashrc"
    w = qwords.words(_row(rc, text, {"as": {"pin": True}}))
    new = {"what": w["what"], "harm": w["harm"], "risk": w["risk"], "details": w["details"], "text_preview": text,
           "action": {"class": "command", "recipient": rc}, "tool": "Bash.danger"}
    old = dict(new, details=new["details"].replace(_why(w)[0], "Why Witness asks: " + rc))
    v4 = json.loads(vocab.canonical())
    PRED = (None, None)
    assert (SC.rebuild_words(old, v4)[0], SC.rebuild_words(new, v4)[0]) == PRED
