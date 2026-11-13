"""r0277: builds packtools/screen-vectors-0277.json (steps 7-8 of the profile: P1 words, P2 omitted). Run from server/:
python packtools/make_screen_vectors_0277.py -> writes packtools/screen-vectors-0277.json and checks every case with screencheck.verdict."""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from app import _paths  # noqa: E402,F401
from app import vocab  # noqa: E402
from app.signview import jcs  # noqa: E402
import screencheck as SC  # noqa: E402

voc = json.loads(vocab.canonical())
vb = vocab.canonical()
vd = hashlib.sha256(vb).hexdigest()
other = json.loads(vocab.canonical())
other["reason_words"] = {k: [w.replace("Your agent wants to", "Your helper would like to"), h] for k, (w, h) in other["reason_words"].items()}
ob = jcs(other)
od = hashlib.sha256(ob).hexdigest()


def view(**kw):
    v = {"v": "dw-view-1", "rid": "r-0277", "status": "pending_approval", "tool": "WebFetch"}
    v.update(kw)
    return v


def omit(v):
    return dict(v, omitted={"rule": SC.OMIT_RULE, "items": SC.omitted_expected(v)})


RA = {"class": "disclosure", "recipient": "(network) api.example.com"}
base = view(action=RA, what="Your agent wants to send a request to api.example.com",
            harm="Your keys or passwords could be sent to this site.", risk="high",
            details="Why it matters: This could send your keys or passwords out of this project folder, to api.example.com.\nTool: WebFetch")
cmd = view(tool="Bash", action={"class": "command", "recipient": "make"}, line_commands=["make", "pytest -q", "git status"],
           what="Your agent wants to run 3 commands", harm="It runs a program on your computer.", risk="medium",
           text_preview="make ; pytest -q ; git status")
cut = dict(cmd, text_cut=True)
cases = []


def case(cid, note, v, expect, pinned=vd, given=vd, ra=None):
    cases.append({"id": cid, "note": note, "pinned": pinned, "vocab": given, "receipt_action": ra if ra is not None else v.get("action"),
                  "view": v, "view_sha256": hashlib.sha256(jcs(v)).hexdigest(), "expect": expect})


case("S-01", "honest: a request to a host quoted from the call", omit(base), "VALID APPROVED_PARTIAL_VIEW")
case("S-02", "honest: a line of three commands, its text cut by the witness", omit(cut), "VALID APPROVED_PARTIAL_VIEW")
case("S-03", "what: one word replaced", omit(dict(base, what="Your agent wants to read a request to api.example.com")), "INVALID WORDING_NOT_DERIVED")
case("S-04", "harm: reassuring text of the agent", omit(dict(base, harm="This is a harmless read; nothing leaves your computer.")), "INVALID WORDING_NOT_DERIVED")
case("S-05", "{t} is not the call's target", omit(dict(base, what="Your agent wants to send a request to docs.python.org")), "INVALID WORDING_NOT_DERIVED")
o2 = omit(view(tool="Read", action={"class": "file", "recipient": "/p/.env"}, what=other["reason_words"]["ESCALATE_SECRET_SEEN"][0].format(t="/p/.env"),
              harm=other["reason_words"]["ESCALATE_SECRET_SEEN"][1], risk="critical"))
case("S-06", "words of another vocabulary than the committed one (the committed one is given)", o2, "INVALID WORDING_NOT_DERIVED")
case("S-07", "the vocabulary given does not hash to the committed digest", omit(base), "INVALID VOCAB_MISMATCH", pinned=vd, given=od)
b8 = omit(base)
b8["omitted"]["items"] = [i for i in b8["omitted"]["items"] if i["m"] != "details"]
case("S-08", "omitted: a folded member missing", b8, "INVALID OMITTED_MISMATCH")
b9 = omit(base)
b9["omitted"]["items"] = sorted(b9["omitted"]["items"] + [{"m": "what", "how": "folded"}], key=lambda i: (i["m"], i["how"]))
case("S-09", "omitted: a first-screen member listed as hidden", b9, "INVALID OMITTED_MISMATCH")
case("S-10", "no omitted (a page older than r0277)", dict(base), "VALID OMITTED_UNDECLARED")
case("S-11", "risk outside the closed levels", omit(dict(base, risk="negligible")), "INVALID WORDING_NOT_DERIVED")
case("S-12", "run {n} commands with a wrong count", omit(dict(cmd, what="Your agent wants to run 2 commands")), "INVALID WORDING_NOT_DERIVED")
case("S-13", "the shown action names another recipient than the signed receipt", omit(base), "INVALID WORDING_NOT_DERIVED",
     ra={"class": "disclosure", "recipient": "(network) evil.example"})
out = {"v": "mr-screen-vectors-1", "vocabularies": {vd: vb.decode("utf-8"), od: ob.decode("utf-8")}, "cases": cases}
for c in cases:
    got = SC.verdict(c["view"], out["vocabularies"][c["vocab"]].encode("utf-8"), c["pinned"], c["receipt_action"])
    assert got == c["expect"], (c["id"], got, c["expect"])
with open(os.path.join(HERE, "screen-vectors-0277.json"), "w", encoding="utf-8") as f:
    json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)
    f.write("\n")
print("screen vectors: %d cases, vocabulary %s" % (len(cases), vd[:16]))
