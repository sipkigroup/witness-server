"""0.2.79 (design): the landing's first screen, the design tokens' contrast (WCAG AA) and the gate re-open on resize in approve.js."""
import os, re

CLOUD = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _r(*p):
    return open(os.path.join(CLOUD, *p), encoding="utf-8").read()


def _lum(h):
    h = h.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (f(int(h[i:i + 2], 16) / 255) for i in (0, 2, 4))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _cr(a, b):
    x, y = sorted((_lum(a), _lum(b)), reverse=True)
    return (x + 0.05) / (y + 0.05)


def _tokens(block):
    return dict(re.findall(r"--([a-z0-9-]+):(#[0-9a-fA-F]{3,6})", block))


def test_0279_landing_first_screen():
    idx = _r("web", "index.html")
    hero = idx[idx.index('class="hero"'):idx.index("</section>")]
    assert '<a class="btn big" href="#tryline">Try it in 2 minutes</a>' in hero
    assert 'href="/demo/">Try the demo - no signup</a>' in hero
    assert 'class="showcase"' in hero and 'role="img"' in hero and "rm -rf ./build" in hero
    assert "Approve" in hero and "Refuse" in hero
    assert 'id="tryline"' in idx and 'id="mcpline"' in idx and 'href="signup.html">Create account' in idx
    assert "quick start below takes about 2 minutes" in idx


def test_0279_tokens_meet_aa_in_both_themes():
    css = _r("web", "css", "app.css")
    light = _tokens(css.split("\n")[1])
    dark = _tokens(css[css.index("@media (prefers-color-scheme:dark){:root{"):].split("\n")[0])
    for t in (light, dark):
        for fg, bg in (("ink", "bg"), ("mute", "bg"), ("mute", "card"), ("mute", "code"), ("acc", "card"), ("acc-ink", "acc"),
                       ("ok", "okbg"), ("warn", "warnbg"), ("bad", "badbg")):
            assert _cr(t[fg], t[bg]) >= 4.5, (fg, bg, t[fg], t[bg])
        assert _cr("#ffffff", t["danger"]) >= 4.5      # Refuse / Freeze: white on the danger red


def test_0279_gate_reopens_on_resize():
    js = _r("web", "js", "approve.js")
    assert "else if (!was && gateOpen) { for (const s of GATED) if ($(s)) $(s).disabled = false; gateApply(); }" in js
