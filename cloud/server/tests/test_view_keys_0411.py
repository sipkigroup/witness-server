"""04.11 (Hypothesis I2 / I3, tests_prop): "signed != shown" on a long shell line and the unterminated heredoc.
(1) the signing view has ONE list of members: server/app/signview.py KEYS == web/js/signview.js VIEW_KEYS;
(2) GET /api/approvals/{rid} of a shell line lists every command whole (line_full) -- a command after a 4 KB echo is in the answer, in the
    view the page signs, and an approval over that view is accepted; the list goes with the text preview once the action is decided;
(3) a long echo of plain words may fold, an echo whose output feeds a pipe may not;
(4) an unterminated heredoc never softens the refusal of what bash runs before it."""
import json
import os
import re

from app import signview
from app.hookjudge.bashparse import classify, line_texts
from tests.test_0224_critique import Agent, row

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_view_keys_same_in_python_and_js():
    js = open(os.path.join(ROOT, "web", "js", "signview.js"), encoding="utf-8").read()
    m = re.search(r"export const VIEW_KEYS = \[(.*?)\];", js, re.S)
    assert m, "VIEW_KEYS not found in web/js/signview.js"
    keys = tuple(re.findall(r"'([a-z_0-9]+)'", m.group(1)))
    assert keys == signview.KEYS
    assert "line_full" in keys and "text_cut" in keys


def test_line_texts_every_command_whole():
    a = 'echo "%s"' % ("A" * 4053)
    t = line_texts(a + " ; cat file10.txt ; cat ~/.ssh/id_rsa")
    assert [x[0] for x in t] == [a, "cat file10.txt", "cat ~/.ssh/id_rsa"]
    assert [x[1] for x in t] == [True, False, False]               # the long plain echo folds, nothing else
    assert line_texts(a + " | bash")[0][1] is False                 # its output is code: never folded
    assert line_texts('echo "$(rm -rf ~/x)%s"' % ("A" * 400))[0][1] is False
    assert line_texts("echo hi >> ~/.zshrc ; cat <<EOF\ntext\nEOF ; ls") == [("echo hi >> ~/.zshrc ; cat <<EOF\ntext\nEOF ; ls", False)]
    bt = line_texts("bash <<EOF\nrm -rf ~/x\nEOF\nls")
    assert any("rm -rf ~/x" in x[0] for x in bt) and bt[-1][0] == "ls"


def test_approval_page_lists_command_after_4k(client, owner, tmp_path):
    # 06.11 (Н1): `cat ~/.ssh/id_rsa` is refused outright now (no page); ~/.ssh/config stays the owner's question
    a = Agent(client, owner, tmp_path)
    cmd = 'echo "%s" ; cat file10.txt ; cat ~/.ssh/config' % ("A" * 4053)
    verdict, parts = a.line(cmd)
    assert verdict == "ASK", parts
    rids = [rid for _, v, _, rid in parts if v == "defer"]
    g = owner.c.get("/api/approvals/" + rids[0]).json()
    shown = [c["cmd"] for c in g["line_full"]]
    assert "cat ~/.ssh/config" in shown and g["text_cut"] is True
    assert "cat ~/.ssh/config" not in g["text_preview"]            # the reason for the list: the preview is cut at 4 KB
    v = signview.view_of(g)
    assert v["line_full"] == g["line_full"] and v["text_cut"] is True
    assert g["view_sha256"] == signview.view_hash({k: x for k, x in g.items() if k != "view_sha256"}).hex()
    for rid in rids:
        owner.approve(rid)
    for rid in rids:
        assert row(client, rid)["line_text"] is None              # dropped with the text preview once decided


def test_unterminated_heredoc_keeps_the_refusal(tmp_path):
    home = str(tmp_path)
    alone = classify("echo hi >> ~/.zshrc", home, home)
    both = classify("echo hi >> ~/.zshrc ; cat <<EOF\ntext\nEOF ; ls", home, home)
    assert both.opaque
    assert set(alone.writes) <= set(both.writes) and set(alone.danger) <= set(both.danger)
