"""r0298 (server 0.2.121, prepared): autostart in an UNKNOWN folder -- a question that says the truth, "Allow once" / "No" only.

Found in r0297 (Vault/layer1/KLIENT-0.2.76-AUTO.md p.4): `false && cd /private/tmp` + a line feed + `echo x > proj/.claude/settings.json`
was asked as "Your agent wants to run a command Witness cannot fully check" / "Part of it is hidden from Witness." (opaque, medium), while
the same write by a known path is refused (Н4 FORBIDDEN_AUTOSTART). The same class: dev corpus #190, real work of the owner.

Decision of Deus (14.11): no refusal without a button (the folder is not known: the article is not certain). The question says:
  1. one line of harm: commands could run on their own (qwords SCREEN autostart_harm, mr-vocab-4; signed = shown);
  2. no "from now on" -- neither an allowance, an amendment nor "approve for later runs", not even by a forged request to the API;
  3. the same for every autostart place the server knows (bashparse.PERSIST_PATH + git hooks / config) in an unknown folder.
Mandates pinned on mr-vocab-3 keep the older sentence ("cannot fully check"): their evidence packs stay VALID.

PRED (written before the run): vorota/predskazanie-2026-11-14-M-r0298.md."""
import base64
import hashlib
import json
import os
import re
import sys
import time

import pytest

from tests.test_1211_r0264_tmpdir_e2e import rig  # noqa: F401  (the fixture; puts the client of this tree on the path)
from app import qwords, vocab, allowances as al, repeat as R, wire
from app.hookjudge.bashparse import classify, AUTOSTART
from tests.helpers import H, ORIGIN, RP
import wa_profile as wa
import wq_profile as wq
from svidetel_v4.state import approval_payload, mandate_hash

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packtools"))
import screencheck as SC  # noqa: E402

PROBE = "false && cd /private/tmp\necho x > proj/.claude/settings.json"
# dev corpus #190 (session a1dba6a7, 23.10, real work of the owner); {P} is the project, the heredoc body cut as in the corpus
ROW190 = ("S=/private/tmp/claude-501/-Users-aa/7fa1abe5-9632-44b1-8466-408b245af5b9/scratchpad/l2; mkdir -p $S/srv $S/proj/.claude $S/out "
          "&& cd $S && printf 'a1%.0s' $(seq 32) > srv/witness_key && printf 'banana\\napple\\ncherry\\n' > proj/notes.txt && "
          "cat > driver.py <<'EOF'\n\"\"\"L2 owner: register (soft passkey), agent claude-code + recommended mandate.\"\"\"\nprint(1)\nEOF\n"
          "sed -e 's#https://witness.sipkigroup.com#http://localhost:8810#' -e 's#\"timeout\": 620#\"timeout\": 60#' "
          "{P}/examples/unattended/settings.unattended.json > proj/.claude/settings.json && cat proj/.claude/settings.json | head -5; "
          "lsof -iTCP:8810 -sTCP:LISTEN -n -P | head -2")
LOST = "false && cd /private/tmp\n"
HOME = "/Users/u"
PROJ = "/Users/u/proj"


def _rid(why):
    m = re.search(r"receipt (r_[A-Z2-7]{26})", why)
    return m.group(1) if m else None


def _page(rig, rid):  # noqa: F811
    return rig.c.get("/api/approvals/" + rid, headers=H).json()


def _marks(cmd):
    return classify(cmd, PROJ, HOME, project=PROJ).danger


# ---- the parser: every autostart place the server knows, in an unknown folder ------------------------------------------------------------
@pytest.mark.parametrize("tail", [
    "proj/.claude/settings.json", ".claude/settings.local.json", ".claude/hooks/pre.sh", ".claude/plugins/x/hooks.json", ".mcp.json",
    ".claude.json", ".bashrc", ".zshrc", ".zprofile", ".profile", ".config/fish/config.fish", "Library/LaunchAgents/x.plist",
    "Library/LaunchDaemons/x.plist", ".config/autostart/x.desktop", ".config/systemd/user/x.service", ".git/hooks/pre-commit",
    ".git/config", ".gitconfig", ".config/git/config", ".ssh/authorized_keys", ".config/deus-witness/key",
])
def test_autostart_tail_in_an_unknown_folder_is_marked_first(tail):
    for w in ("echo x > %s", "cp a %s", "tee %s < a", "sed -i '' s/a/b/ %s"):
        d = _marks(LOST + (w % tail))
        PRED = (True, False)               # before r0298: (False, False) -- only "opaque:write to ... in an unknown directory"
        assert (d[0].startswith(AUTOSTART + ":write to "), any(x.startswith("persist:") for x in d)) == PRED, (w % tail, d)
        assert any(x.startswith("opaque:") for x in d), d          # the opaque mark stays (the line is still unreadable)


@pytest.mark.parametrize("cmd", [
    LOST + "echo x > notes.md", LOST + "echo x > .gitattributes", LOST + "rm .bashrc", LOST + "rm -f .claude/settings.json",
    "echo x > notes.md", "cat .bashrc",
])
def test_twins_without_autostart_mark(cmd):
    d = _marks(cmd)
    PRED = False                           # an ordinary file, a deletion (starts nothing), a read
    assert any(x.startswith(AUTOSTART + ":") for x in d) is PRED, d


def test_known_path_stays_refused_as_before():
    d = _marks("echo x > proj/.claude/settings.json")
    PRED = ("persist", False)              # a write by a KNOWN path: Н4, refused without a question, unchanged
    assert (d[0].split(":")[0], any(x.startswith(AUTOSTART) for x in d)) == PRED, d


def test_row190_marks():
    d = _marks(ROW190.replace("{P}", "/Users/u/cloud"))
    PRED = "autostart:write to proj/.claude/settings.json in an unknown directory"
    assert d[0] == PRED and not any(x.startswith("persist:") for x in d), d


# ---- end to end: the real hook against the in-process witness -------------------------------------------------------------------------
def _question(rig, cmd):  # noqa: F811
    d, why = rig(cmd)
    rid = _rid(why)
    assert d == "deny" and rid and "ESCALATE_COMMAND_DANGER" in why and "FORBIDDEN" not in why, (d, why)
    return rid, _page(rig, rid)


# r0299: "~/.bashrc" / "~/.zshrc" left these lists: a path through ~ names the same file in any folder (refused, Н4: test_1411_r0299_bashrc_metki)
@pytest.mark.parametrize("cmd", [PROBE, "ROW190", LOST + "echo x >> .zshrc", LOST + "cp hook.sh .git/hooks/pre-commit",
                                 LOST + "cp a.plist Library/LaunchAgents/com.x.plist"])
def test_question_says_the_truth_and_offers_once_only(rig, cmd):  # noqa: F811
    cmd = ROW190.replace("{P}", rig.proj) if cmd == "ROW190" else cmd
    rid, x = _question(rig, cmd)
    PRED = (qwords.SCREEN["autostart_what"], qwords.SCREEN["autostart_harm"], "critical", False, False)
    got = (x["what"], x["harm"], x["risk"], x["allowance_offer"]["eligible"], x["repeat_offer"]["eligible"])
    assert got == PRED, (got, x.get("details"))
    assert x["allowance_offer"]["why_not"] == al.AUTOSTART_WHY
    assert "never allowed from now on" in x["details"] and x["action"]["recipient"].startswith("autostart:")


def test_allow_once_runs_it_once(rig):  # noqa: F811
    rid, x = _question(rig, PROBE)
    assert rig.o.approve(rid).status_code == 200
    d, why = rig(PROBE)
    PRED = "allow"                         # the owner's "Allow once": this very call
    assert d == PRED, why
    d2, why2 = rig(PROBE)
    PRED2 = ("deny", True)                 # the next one is asked again
    assert (d2, "waiting for the owner's approval" in why2) == PRED2, why2


def _forged_allowance(rig, rid, commands, project):  # noqa: F811
    g = _page(rig, rid)
    t = int(time.time())
    a = {"v": "deus-aar-0.1", "t": "allowance", "id": "al_" + base64.b32encode(os.urandom(16)).decode().rstrip("=")[:26],
         "mandate": mandate_hash(wire.cbor_form(g["mandate"])), "class": "command", "commands": commands, "project": project,
         "nbf": t, "exp": t + 86400}
    return rig.o.post("/api/allowances", rid=rid, envelope_b64=rig.o.sign(al.TYP, wa.cde(a)))


def test_from_now_on_cannot_be_forged(rig):  # noqa: F811
    rid, x = _question(rig, PROBE)
    rc = x["action"]["recipient"]
    tries = [_forged_allowance(rig, rid, ["echo"], rig.proj), _forged_allowance(rig, rid, ["false", "cd", "echo"], rig.proj),
             _forged_allowance(rig, rid, [rc], rig.proj)]              # an amendment naming the mark itself
    PRED = [(409, "ALLOWANCE_NOT_ELIGIBLE")] * 3
    assert [(r.status_code, r.json().get("error")) for r in tries] == PRED, [r.text for r in tries]
    # "approve for later runs": one passkey prompt over this request and N reserved ids
    exp = int(time.time()) + 24 * 3600
    rids = [R.make_rid(exp) for _ in range(3)]
    g = _page(rig, rid)
    items = [hashlib.sha256(approval_payload(g["mandate"], g["action"], r_, True)).digest() for r_ in [rid] + rids]
    au = rig.o.auth
    ad, cd, der = au.get_assertion(wq.wb_challenge(items), RP, ORIGIN)
    res = rig.o.post("/api/approvals/" + rid, approved=True, envelope_b64=wa.b64u(wq.make_wb(items, au.kid, ad, cd, der)), repeat={"rids": rids})
    PRED2 = (409, "REPEAT_NOT_ELIGIBLE")
    assert (res.status_code, res.json().get("error")) == PRED2, res.text
    db = rig.c.app.state.ctx.db
    PRED3 = (0, 0, "pending_approval")     # nothing recorded; the question still waits
    got3 = (db.one("SELECT COUNT(*) AS n FROM allowances")["n"], db.one("SELECT COUNT(*) AS n FROM repeat_approvals")["n"],
            db.one("SELECT status FROM actions WHERE rid=?", (rid,))["status"])
    assert got3 == PRED3


# ---- vocabulary: mr-vocab-4; receipts under mr-vocab-3 keep verifying ----------------------------------------------------------------
V3_DIGEST = "8e70ef8893dd440b7df70228351390f68c6592dd3cc90f127b76d58dbe249ebc"     # mr-vocab-3 of server 0.2.118-0.2.120


def _v3():
    d = json.loads(vocab.canonical())
    return dict(d, v="mr-vocab-3", screen={k: v for k, v in d["screen"].items() if not k.startswith(("autostart_", "defense_", "v6_"))})   # r0305: - defense_*; r0307: - v6_*


def test_mr_vocab_3_is_the_same_document_minus_the_new_sentences():
    PRED = ("mr-vocab-6", V3_DIGEST)       # (r0305: the server runs mr-vocab-5) the older vocabulary is exactly the one 0.2.118-0.2.120 pinned: old packs keep their file
    assert (vocab.V, vocab.digest(_v3())) == PRED


def test_words_rebuild_offline_under_4_and_not_under_3(rig):  # noqa: F811
    rid, x = _question(rig, PROBE)
    row = rig.c.app.state.ctx.db.one("SELECT * FROM actions WHERE rid=?", (rid,))
    view = {"what": x["what"], "harm": x["harm"], "risk": x["risk"], "details": x["details"], "text_preview": row["text_preview"],
            "action": json.loads(row["action_json"]), "tool": row["tool"]}
    code4, got = SC.rebuild_words(view, json.loads(vocab.canonical()))
    code3, _ = SC.rebuild_words(view, _v3())
    PRED = (None, "screen/autostart_harm", "WORDING_NOT_DERIVED")
    assert (code4, got["harm"] if got else None, code3) == PRED


def test_an_owner_whose_mandate_pinned_mr_vocab_3_sees_its_own_sentence(rig, monkeypatch, tmp_path):  # noqa: F811
    """A mandate signed before r0298 pins mr-vocab-3: the question keeps "cannot fully check" (still no "from now on"); the checker rebuilds
    those words from the pinned vocabulary (VALID)."""
    from tests.test_0216_thin import _server
    from app.hookjudge.mapping import default_form
    real = vocab.doc
    v3 = _v3()
    monkeypatch.setattr(vocab, "doc", lambda: json.loads(json.dumps(v3)))
    c, o = _server(tmp_path, "srv3")
    ag, hdr = o.new_agent("claude-code", "cc3")
    m, r = o.mandate(ag["id"], default_form(rig.proj))         # signed now: pins mr-vocab-3
    assert r.status_code == 200, r.text
    monkeypatch.setattr(vocab, "doc", real)                    # the server runs mr-vocab-4 from here on
    from app.hookjudge.mapping import map_event
    from tests.helpers import act
    env = {"CLAUDE_PROJECT_DIR": rig.proj, "HOME": "/nonexistent-home"}
    rid = None
    for mp in map_event({"tool_name": "Bash", "tool_input": {"command": PROBE}, "cwd": rig.proj}, env=env):
        j = act(c, hdr, mp.tool, mp.args).json()
        if mp.tool == "Bash.danger":
            rid = j["rid"]
    x = c.get("/api/approvals/" + rid, headers=H).json()
    PRED = (qwords.DANGER_WORDS["opaque"][0], qwords.DANGER_WORDS["opaque"][1], False)
    assert (x["what"], x["harm"], x["allowance_offer"]["eligible"]) == PRED, x
    row = c.app.state.ctx.db.one("SELECT * FROM actions WHERE rid=?", (rid,))
    code, _ = SC.rebuild_words({"what": x["what"], "harm": x["harm"], "risk": x["risk"], "details": x["details"],
                                "text_preview": row["text_preview"], "action": json.loads(row["action_json"])}, v3)
    assert code is None


def test_words_without_the_mark_fall_back_to_the_older_sentence():
    """No exec_json "as" (an error while marking): the older vocabulary's words, never an unrebuildable sentence."""
    x = {"reason": "ESCALATE_COMMAND_DANGER", "tool": "Bash.danger", "text_preview": PROBE, "line_heads": "[]", "cmd_meta": None,
         "action_json": json.dumps({"class": "command", "recipient": "autostart:write to .bashrc in an unknown directory"})}
    w = qwords.words(x)
    PRED = (qwords.DANGER_WORDS["opaque"][0], qwords.DANGER_WORDS["opaque"][1])
    assert (w["what"], w["harm"]) == PRED
    w2 = qwords.words(dict(x, exec_json=json.dumps({"as": {"pin": True}})))
    assert (w2["what"], w2["harm"], w2["risk"]) == (qwords.SCREEN["autostart_what"], qwords.SCREEN["autostart_harm"], "critical")


@pytest.mark.parametrize("strict", [False, True])
def test_no_amendment_is_planned_for_an_autostart_line(strict):
    """No narrow "from now on" either -- also under the strict sandbox fact, where only the articles block an amendment."""
    from app import amend
    w = {"danger": ["autostart:write to proj/.claude/hooks/x.sh in an unknown directory",
                    "opaque:write to proj/.claude/hooks/x.sh in an unknown directory", "agent-config:(hook) proj/.claude/hooks/x.sh"],
         "commands": ["false", "cd", "echo"], "project": PROJ}
    if strict:
        w["sandbox"] = {"strict": True}
    args = {"command": LOST + "echo x > proj/.claude/hooks/x.sh", "_witness": w}
    ids, why = amend.plan("Bash.danger", args, [{"class": "command", "recipient": "(strict later run) proj/.claude/hooks/x.sh"}], HOME)
    PRED = (False, None)                   # before r0298 under the strict fact: line_ok True, the LATER id planned
    assert (amend.line_ok("Bash.danger", args, HOME), ids) == PRED, why
