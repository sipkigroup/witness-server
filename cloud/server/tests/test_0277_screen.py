"""r0277 (P1 / P2 of the Mandate Receipt profile): the first screen of a question rebuilt OFFLINE by a third party.

P1: what / harm / risk of every signed view are sentences of the reason vocabulary the mandate pinned (mr-vocab-2), with the call's own
targets in the placeholders: packtools/screencheck.py rebuilds them from the pack alone (no server code). P2: the signed view lists what the
first screen does not show whole ("omitted", rule mr-omit-1); the checker applies the same rule and refuses a list with a member too many or
too few. Old receipts (a mandate that pinned mr-vocab-1, a page that signed no "omitted") are checked as before, with a warning."""
import hashlib
import json
import os

import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packtools"))
import screencheck as SC  # noqa: E402
from app import qwords, signview, vocab  # noqa: E402
from tests.test_0283_shown_views import _signed_pack  # noqa: E402


def _run(folder, *flags):
    from tests.recovery_helpers import run_verify
    return run_verify(folder, "--offline", *flags)


# ------------------------------------------------------------------ positive: the honest pack
def test_honest_pack_rebuilds_words_and_lists_what_was_hidden(app, tmp_path):
    p, a, rid, page, rid_h, rpage, folder = _signed_pack(app, tmp_path)
    vo = json.load(open(os.path.join(folder, "views", rid + ".json"), encoding="utf-8"))
    assert vo["omitted"]["rule"] == "mr-omit-1" and {"m": "details", "how": "folded"} in vo["omitted"]["items"]
    assert hashlib.sha256(signview.jcs(vo)).digest() == page                       # "omitted" is inside the signed hash
    assert os.path.exists(os.path.join(folder, "verify", "screencheck.py"))
    rc, out = _run(folder, "--require-views")
    assert rc == 0 and out.strip().endswith("RESULT: VALID"), out
    assert "screen approval %s: words rebuilt from vocabulary" % rid in out, out
    assert "screen release %s: words rebuilt from vocabulary" % rid_h in out, out
    assert "APPROVED_PARTIAL_VIEW, the first screen did not show whole: " in out and "details:folded" in out, out
    assert "screens: 2 first screen(s) rebuilt from the pinned vocabulary, 0 with words not rebuildable" in out, out


# ------------------------------------------------------------------ negative: words the vocabulary does not hold
def test_agent_text_on_the_first_screen_is_wording_not_derived(app, tmp_path, monkeypatch):
    """A witness (or a bug) that puts free text into `what`: the page signs it, the pack is sealed, the checker refuses it."""
    real = qwords.words

    def fake(x):
        w = real(x)
        if w["what"] != qwords.UNKNOWN_WHAT:
            w["what"] = "Your agent wants to read a harmless file"           # not a sentence of the vocabulary
        return w
    monkeypatch.setattr(qwords, "words", fake)
    p, a, rid, page, rid_h, rpage, folder = _signed_pack(app, tmp_path)
    rc, out = _run(folder)
    assert rc != 0 and "WORDING_NOT_DERIVED" in out and "RESULT: INVALID" in out, out


def test_words_of_another_vocabulary_than_the_pinned_one(app, tmp_path, monkeypatch):
    """The mandate pins vocabulary D; the words shown come from a changed dictionary (another digest): not derived from D."""
    from tests.recovery_helpers import Person
    from tests.test_0224_critique import Agent
    from tests.test_pv2810_view import _approve
    pers = Person(app).register("Pat")
    ag = Agent(pers.c, pers, tmp_path)                        # the mandate is signed here: it pins today's vocabulary
    pinned = vocab.digest()
    envf = ag.proj + "/.env"
    open(envf, "w").write("GH_TOKEN=x\n")
    changed = dict(qwords.REASON_WORDS)
    for k, (w, h) in list(changed.items()):
        changed[k] = (w.replace("Your agent wants to", "Your helper would like to"), h)
    monkeypatch.setattr(qwords, "REASON_WORDS", changed)
    # r0280: a read of a credential file is said in DANGER_WORDS["secrets"] (before: REASON_WORDS ESCALATE_PUBLISH, "send or publish something to
    # secrets:<path>"): the changed dictionary changes those words too
    dchanged = {k: (e[0].replace("Your agent wants to", "Your helper would like to"),) + tuple(e[1:]) for k, e in qwords.DANGER_WORDS.items()}
    monkeypatch.setattr(qwords, "DANGER_WORDS", dchanged)
    assert vocab.digest() != pinned
    [(t, v, reason, rid)] = ag.tool("Read", {"file_path": envf})
    r, page = _approve(pers, rid)
    assert r.status_code == 200, r.text
    from tests.recovery_helpers import export_to
    folder = export_to(pers.c, tmp_path / "pack")
    assert os.path.exists(os.path.join(folder, "vocab", pinned + ".json"))
    rc, out = _run(folder)
    assert rc != 0 and "WORDING_NOT_DERIVED" in out and pinned[:16] in out, out


def test_a_vocabulary_file_with_other_words_under_the_pinned_name_is_invalid(app, tmp_path):
    p, a, rid, page, rid_h, rpage, folder = _signed_pack(app, tmp_path)
    [vf] = [f for f in os.listdir(os.path.join(folder, "vocab"))]
    d = json.load(open(os.path.join(folder, "vocab", vf), encoding="utf-8"))
    d["screen"]["send_request"] = "Your agent wants to read {t}"
    open(os.path.join(folder, "vocab", vf), "wb").write(signview.jcs(d))
    rc, out = _run(folder)
    assert rc != 0 and "RESULT: INVALID" in out and ("vocab: MISMATCH" in out or "MANIFEST" in out.upper()), out


# ------------------------------------------------------------------ negative: the signed list of what was hidden
@pytest.mark.parametrize("how", ["missing", "extra"])
def test_omitted_list_with_a_member_too_few_or_too_many(app, tmp_path, monkeypatch, how):
    real = signview.omitted_of

    def fake(view):
        o = real(view)
        if how == "missing":
            o["items"] = [i for i in o["items"] if i["m"] != "details"]
        else:
            o["items"] = sorted(o["items"] + [{"m": "what", "how": "folded"}], key=lambda i: (i["m"], i["how"]))
        return o
    monkeypatch.setattr(signview, "omitted_of", fake)
    p, a, rid, page, rid_h, rpage, folder = _signed_pack(app, tmp_path)
    rc, out = _run(folder)
    assert rc != 0 and "OMITTED_MISMATCH" in out and "RESULT: INVALID" in out, out


# ------------------------------------------------------------------ backward compatibility
def test_an_older_page_without_omitted_is_accepted_and_reported(app, tmp_path):
    """A page loaded before r0277 hashes the view without "omitted": the server accepts that hash (same rows), the pack is VALID with
    a warning that what was hidden is not signed."""
    from tests.recovery_helpers import Person, export_to
    from tests.test_0224_critique import Agent
    from tests.test_pv2810_view import _approve, _get
    pers = Person(app).register("Pat")
    ag = Agent(pers.c, pers, tmp_path)
    envf = ag.proj + "/.env"
    open(envf, "w").write("GH_TOKEN=x\n")
    [(t, v, reason, rid)] = ag.tool("Read", {"file_path": envf})
    g = _get(pers, rid)
    old = signview.view_hash({k: v for k, v in g.items() if k not in ("view_sha256",)}, legacy=True)
    assert old.hex() != g["view_sha256"]
    r, _ = _approve(pers, rid, sign_view=old, send_view=old)
    assert r.status_code == 200, r.text
    folder = export_to(pers.c, tmp_path / "pack")
    vo = json.load(open(os.path.join(folder, "views", rid + ".json"), encoding="utf-8"))
    assert "omitted" not in vo
    rc, out = _run(folder, "--require-views")
    assert rc == 0 and out.strip().endswith("RESULT: VALID"), out
    assert "warning OMITTED_UNDECLARED" in out and "not signed (a page older than r0277)" in out, out


def test_a_view_that_is_neither_new_nor_legacy_is_still_refused(app, tmp_path):
    from tests.recovery_helpers import Person
    from tests.test_0224_critique import Agent
    from tests.test_pv2810_view import _approve
    pers = Person(app).register("Pat")
    ag = Agent(pers.c, pers, tmp_path)
    envf = ag.proj + "/.env"
    open(envf, "w").write("GH_TOKEN=x\n")
    [(t, v, reason, rid)] = ag.tool("Read", {"file_path": envf})
    r, _ = _approve(pers, rid, sign_view=b"\x11" * 32, send_view=b"\x11" * 32)
    assert r.status_code == 409 and r.json()["error"] == "VIEW_CHANGED", r.text


def test_a_mandate_that_pinned_the_older_vocabulary_is_checked_as_before(app, tmp_path, monkeypatch):
    monkeypatch.setattr(vocab, "V", "mr-vocab-1")
    real_doc = vocab.doc
    monkeypatch.setattr(vocab, "doc", lambda: {k: v for k, v in real_doc().items() if k != "screen"})
    p, a, rid, page, rid_h, rpage, folder = _signed_pack(app, tmp_path)
    rc, out = _run(folder, "--require-views")
    assert rc == 0 and out.strip().endswith("RESULT: VALID"), out
    assert "words not rebuilt (vocabulary mr-vocab-1, before mr-vocab-2)" in out, out


# ------------------------------------------------------------------ unit: the rebuild rule
def _voc():
    return json.loads(vocab.canonical())


def test_every_first_screen_sentence_of_the_server_is_a_vocabulary_template():
    v = _voc()
    assert v["v"] == "mr-vocab-5" and set(qwords.SCREEN) <= set(v["screen"])     # r0298: + autostart_what / autostart_harm; r0305: + defense_*
    leaves = SC.vocab_leaves(v)
    for k, s in qwords.SCREEN.items():
        assert s in leaves, k
    assert not [s for s in leaves if not SC._PH.sub("", s).strip() and SC._PH.search(s)]   # no bare placeholder is used as a sentence


@pytest.mark.parametrize("what,harm,extra,ok", [
    ("Your agent wants to send a request to api.example.com", "Your keys or passwords could be sent to this site.",
     {"action": {"recipient": "(network) api.example.com"}}, True),
    ("Your agent wants to send a request to evil.example", "Your keys or passwords could be sent to this site.",
     {"action": {"recipient": "(network) api.example.com"}}, False),                             # the target is not the call's
    ("Your agent wants to run 3 commands", "It runs a program on your computer.", {"line_commands": ["ls", "make", "pytest"]}, True),
    ("Your agent wants to run 4 commands", "It runs a program on your computer.", {"line_commands": ["ls", "make", "pytest"]}, False),
    ("Your agent wants to delete /tmp/x⟨U+202E⟩y", "Files could be deleted for good.", {"action": {"recipient": "/tmp/x‮y"}}, True),
    ("Your agent wants to delete " + "a" * 119 + "…", "Files could be deleted for good.", {"action": {"recipient": "a" * 400}}, True),
    ("Your agent wants to run a command that is not on your list: ls", "This is fine, trust me.", {"action": {"recipient": "ls"}}, False),
    ("Your agent wants to read a file", "Unknown effect", {}, False),
    ("Your agent wants to read your git settings", "You said No to this 5 min ago; the agent is trying another way.", {}, True),
    ("Your agent wants to read your git settings", "You said No to this yesterday; the agent is trying another way.", {}, False),
])
def test_rebuild_rule(what, harm, extra, ok):
    view = dict({"v": "dw-view-1", "what": what, "harm": harm, "risk": "high"}, **extra)
    code, got = SC.rebuild_words(view, _voc())
    assert (code is None) == ok, (code, got)


def test_risk_outside_the_vocabulary_is_refused():
    code, _ = SC.rebuild_words({"what": qwords.UNKNOWN_WHAT, "harm": qwords.UNKNOWN_HARM, "risk": "negligible"}, _voc())
    assert code == "WORDING_NOT_DERIVED"


def test_omitted_rule_is_the_same_in_the_server_and_the_checker():
    views = [
        {"v": "dw-view-1", "rid": "r", "what": "w", "harm": "h", "risk": "low"},
        {"v": "dw-view-1", "rid": "r", "what": "w", "details": "Tool: Bash\nText (first 1500 of 9000 characters, cut - x):\nab", "text_cut": True,
         "masked_dep": [{"name": "TOKEN"}], "unseen_write": {"paths": ["a"], "secret": False}, "written_run": {"files": ["f"], "writes": [{"file": "f", "cut": True}]},
         "line_full": [{"cmd": "ls"}], "tool": "Bash"},
    ]
    for v in views:
        assert signview.omitted_of(v)["items"] == SC.omitted_expected(v)
        assert signview.omitted_of(v)["rule"] == SC.OMIT_RULE
        signed = dict(v, omitted=signview.omitted_of(v))
        assert SC.check_omitted(signed)[0] is None
        assert SC.check_omitted(dict(v, omitted={"rule": "mr-omit-1", "items": []}))[0] == ("OMITTED_MISMATCH" if SC.omitted_expected(v) else None)
    assert SC.omitted_expected(views[0]) == []
    hows = {(i["m"], i["how"]) for i in SC.omitted_expected(views[1])}
    assert {("text_preview", "cut"), ("details", "cut"), ("masked_dep", "masked"), ("unseen_write", "unseen"), ("written_run", "cut")} <= hows
    assert SC.FIRST_SCREEN == signview.FIRST_SCREEN


def test_screen_vectors_file():
    """packtools/screen-vectors-0277.json: 13 cases of steps 7-8 (honest, a replaced word, agent text as harm, a target not from the call,
    another vocabulary, vocabulary bytes not the committed digest, omitted with a member too few / too many, no omitted, a risk outside the
    levels, a wrong count, another recipient than the receipt)."""
    path = os.path.join(os.path.dirname(SC.__file__), "screen-vectors-0277.json")
    n, bad = SC.run_vectors(path)
    assert n == 34 and bad == []          # r0281: + S-14..S-17 (the file-send sentences; an older receipt under the r0280 vocabulary)
    #                                       r0294: + S-18..S-24 (a run of code from the network under mr-vocab-3; mr-vocab-2 receipts as before)
    #                                       r0298: + S-25..S-29 (autostart in an unknown folder under mr-vocab-4; mr-vocab-3 receipts as before)
    #                                       r0305: + S-30..S-34 (an OS protection switched off under mr-vocab-5; mr-vocab-4 receipts as before)
    d = json.load(open(path, encoding="utf-8"))
    for c in d["cases"]:
        assert hashlib.sha256(signview.jcs(c["view"])).hexdigest() == c["view_sha256"]
        assert hashlib.sha256(d["vocabularies"][c["vocab"]].encode("utf-8")).hexdigest() == c["vocab"]
    want = {"S-03": "INVALID WORDING_NOT_DERIVED", "S-06": "INVALID WORDING_NOT_DERIVED", "S-07": "INVALID VOCAB_MISMATCH",
            "S-08": "INVALID OMITTED_MISMATCH", "S-09": "INVALID OMITTED_MISMATCH", "S-10": "VALID OMITTED_UNDECLARED",
            "S-14": "VALID APPROVED_PARTIAL_VIEW", "S-15": "INVALID WORDING_NOT_DERIVED", "S-16": "VALID APPROVED_PARTIAL_VIEW",
            "S-17": "INVALID WORDING_NOT_DERIVED", "S-18": "VALID APPROVED_PARTIAL_VIEW", "S-19": "VALID APPROVED_PARTIAL_VIEW",
            "S-20": "INVALID WORDING_NOT_DERIVED", "S-21": "VALID APPROVED_PARTIAL_VIEW", "S-22": "VALID APPROVED_PARTIAL_VIEW",
            "S-23": "INVALID WORDING_NOT_DERIVED", "S-24": "INVALID WORDING_NOT_DERIVED", "S-25": "VALID APPROVED_PARTIAL_VIEW",
            "S-26": "INVALID WORDING_NOT_DERIVED", "S-27": "VALID APPROVED_PARTIAL_VIEW", "S-28": "INVALID WORDING_NOT_DERIVED",
            "S-29": "VALID APPROVED_PARTIAL_VIEW", "S-30": "VALID APPROVED_PARTIAL_VIEW", "S-31": "INVALID WORDING_NOT_DERIVED",
            "S-32": "VALID APPROVED_PARTIAL_VIEW", "S-33": "INVALID WORDING_NOT_DERIVED", "S-34": "VALID APPROVED_PARTIAL_VIEW"}
    assert {c["id"]: c["expect"] for c in d["cases"] if c["id"] in want} == want


def test_a_target_only_the_witness_states_is_rebuilt_and_marked():
    """r0260: "Code could publish to github.com in your name." -- the host is the sandbox's, not the call's; it is under Details."""
    v = {"what": "Your agent wants to run a command that is not on your list: npm run release", "harm": "Code could publish to github.com in your name.",
         "risk": "high", "action": {"class": "command", "recipient": "npm run release"},
         "details": "Why it matters: Your sandbox lets programs reach github.com, registry.npmjs.org, and code inside it can read your login keychain."}
    code, got = SC.rebuild_words(v, _voc())
    assert code is None and got["from_details"] == ["harm"], got
    code, _ = SC.rebuild_words(dict(v, details="Tool: Bash"), _voc())
    assert code == "WORDING_NOT_DERIVED"
