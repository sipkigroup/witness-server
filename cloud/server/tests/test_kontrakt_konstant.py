"""13.11 (Vorota V2, SISTEMA-TESTIROVANIYA-1311 3.3): the numbers that must agree between the parts of Witness.

L3 13.11 with the owner, find 5: the hook waited 15 s and told the agent "refused", while the page counted from its own constant
(HOOK_WAIT_S = 45) and said "14 min 46 s left to decide". Each part was right by its own tests; nothing compared them. Here every number
that lives in two places (hook client, plugin launcher, page, server, docs) is read from its source text and compared.
Static reads only (no server): fast, part of gate V2. The plugin lives outside this repo (release/out/open-repo); missing -> skipped."""
import json
import os
import re

import pytest

from app import actions, allowances, signview, vocab, waiting
from app.config import Config

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
PLUGIN = os.environ.get("DW_PLUGIN_DIR") or os.path.normpath(os.path.join(ROOT, "..", "release", "out", "open-repo", "plugins", "deus-witness"))


def _read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


def _read_or_skip(*p):
    """r0282 (open server CI 13.11): the open tree (release/build-open-server.sh) ships server/web/contract only -- no docs/, no CHANGELOG.md.
    A part that is not in the tree is skipped there with its path; in the full repo it is read and checked."""
    path = os.path.join(ROOT, *p)
    if not os.path.exists(path):
        pytest.skip("%s is not in this tree (open server)" % os.path.join(*p))
    return _read(*p)


def _js_const(src, name):
    m = re.search(r"export const %s\s*=\s*([^;]+);" % re.escape(name), src)
    assert m, "no `export const %s` found" % name
    return m.group(1).strip()


def _plugin(*p):
    path = os.path.join(PLUGIN, *p)
    if not os.path.exists(path):
        pytest.skip("plugin not found at %s (set DW_PLUGIN_DIR)" % path)
    with open(path, encoding="utf-8") as f:
        return f.read()


def _sh_default(src, var):
    m = re.search(r'export %s="\$\{%s:-(\d+)\}"' % (var, var), src)
    assert m, "no default for %s in the launcher" % var
    return int(m.group(1))


# ---- the hook's wait: plugin launcher <-> page <-> hook client <-> hooks.json ----

def test_page_hook_wait_is_the_plugin_default():
    """The page's HOOK_WAIT_S (its guess of how long the agent waits) = the plugin launcher's DEUS_WITNESS_HOOK_WAIT default."""
    page = int(_js_const(_read("web", "js", "approve.js"), "HOOK_WAIT_S"))
    plug = _sh_default(_plugin("scripts", "deus-witness-hook.sh"), "DEUS_WITNESS_HOOK_WAIT")
    assert page == plug, "page HOOK_WAIT_S %d s != plugin DEUS_WITNESS_HOOK_WAIT %d s" % (page, plug)


def test_plugin_wait_fits_its_timeouts():
    """HOOK_WAIT <= HOOK_TIMEOUT - MARGIN_S (the client cuts it otherwise) and hooks.json timeout >= HOOK_TIMEOUT + MARGIN_S."""
    from deus_witness.hook import failsafe
    sh = _plugin("scripts", "deus-witness-hook.sh")
    wait, tout = _sh_default(sh, "DEUS_WITNESS_HOOK_WAIT"), _sh_default(sh, "DEUS_WITNESS_HOOK_TIMEOUT")
    assert wait <= tout - failsafe.MARGIN_S, (wait, tout, failsafe.MARGIN_S)
    hj = json.loads(_plugin("hooks", "hooks.json"))
    pre = [h for g in hj["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert pre and all(h.get("timeout", 60) >= tout + failsafe.MARGIN_S for h in pre), ([h.get("timeout") for h in pre], tout)


def test_docs_wait_fits_timeout():
    """Every docs snippet that sets DEUS_WITNESS_HOOK_WAIT and DEUS_WITNESS_HOOK_TIMEOUT together keeps WAIT <= TIMEOUT - MARGIN_S."""
    from deus_witness.hook import failsafe
    bad, seen = [], 0
    if not os.path.isdir(os.path.join(ROOT, "docs")):
        pytest.skip("docs/ is not in this tree (open server)")
    for dp, _, fs in os.walk(os.path.join(ROOT, "docs")):
        for f in fs:
            if not f.endswith(".md"):
                continue
            for i, line in enumerate(open(os.path.join(dp, f), encoding="utf-8")):
                w = re.search(r'DEUS_WITNESS_HOOK_WAIT"?\s*[:=]\s*"?(\d+)', line)
                t = re.search(r'DEUS_WITNESS_HOOK_TIMEOUT"?\s*[:=]\s*"?(\d+)', line)
                if w and t:
                    seen += 1
                    if int(w.group(1)) > int(t.group(1)) - failsafe.MARGIN_S:
                        bad.append("%s:%d WAIT %s TIMEOUT %s" % (f, i + 1, w.group(1), t.group(1)))
    assert seen >= 1 and not bad, (seen, bad)


def test_page_follows_the_server_not_its_constant():
    """Find 5: when the hook's wait is not the page's guess (DEUS_WITNESS_HOOK_WAIT 15 in quickstart, 600 unattended), only the server
    knows the hook gave up (`gave_up_at`, `agent_waiting` of /api/approvals/{rid}). The page must read both and follow them while open."""
    src = _read("server", "app", "api_web.py")
    assert '"gave_up_at"' in src and "agent_waiting" in src, "the approval detail no longer carries gave_up_at / agent_waiting"
    aj = _read("web", "js", "approve.js")
    assert re.search(r"\.gave_up_at\b", aj), "approve.js never reads gave_up_at: it counts from HOOK_WAIT_S alone"
    # it keeps asking while the page is open (not only when it opened on an already stopped call)
    assert re.search(r"followWait\(\)", aj) or re.search(r"setInterval\([^)]*agent_waiting", aj), "the page does not follow the hook while open"


def test_long_poll_bounds():
    """The client's long poll (wait=1..25) never asks for more than the server holds (waiting.MAX_WAIT), and GRACE_S covers one poll."""
    import inspect
    from deus_witness import client as _client                   # r0282: the client the tests run (mcp/ sources here, the pinned wheel in the open server)
    cl = open(inspect.getsourcefile(_client), encoding="utf-8").read()
    m = re.search(r"wait=int\(min\((\d+),", cl)
    assert m, "client long poll bound not found"
    assert int(m.group(1)) <= waiting.MAX_WAIT < waiting.GRACE_S, (m.group(1), waiting.MAX_WAIT, waiting.GRACE_S)


# ---- "Allow such from now on": the term ----

def test_from_now_on_days():
    """qwords.js LATER_DAYS (what the button signs) <= allowances.MAX_DAYS (what the server accepts) = allowance.js MAX_DAYS = the page's text."""
    later = int(_js_const(_read("web", "js", "qwords.js"), "LATER_DAYS"))
    jsmax = int(_js_const(_read("web", "js", "allowance.js"), "MAX_DAYS"))
    assert later <= allowances.MAX_DAYS == jsmax, (later, allowances.MAX_DAYS, jsmax)
    html = _read("web", "approve.html")
    m = re.search(r"at most (\d+) days", html)
    assert m and int(m.group(1)) == allowances.MAX_DAYS, (m and m.group(1), allowances.MAX_DAYS)
    opts = [int(x) for x in re.findall(r'<option value="(\d+)"[^>]*>\d+ days?</option>', html.split('id="allow_days"', 1)[1].split("</select>", 1)[0])]
    assert opts and max(opts) <= allowances.MAX_DAYS, opts


# ---- the question's life: TTL ----

def test_request_ttl():
    """actions.TTL (the default a deferred request waits) = Config().defer_ttl_s (the page counts down from `expires`)."""
    assert actions.TTL == Config.__dataclass_fields__["defer_ttl_s"].default == 900, (actions.TTL, Config.__dataclass_fields__["defer_ttl_s"].default)


# ---- limits: code <-> public pages ----

def test_limits_on_public_pages():
    agents_cap = None
    for name in ("MAX_AGENTS", "AGENTS_PER_ACCOUNT", "MAX_AGENTS_PER_ACCOUNT"):
        agents_cap = agents_cap or getattr(actions, name, None)
    for page in (("web", "index.html"), ("web", "pricing", "index.html")):
        t = _read(*page)
        m = re.search(r"(\d+) actions per day per account and (\d+) per agent", t)
        assert m, "%s: the limits line is gone" % "/".join(page)
        assert (int(m.group(1)), int(m.group(2))) == (actions.QUOTA_PER_DAY, actions.QUOTA_PER_AGENT_DAY), (page, m.groups())
        mt = re.search(r"quick start account[^.]*?(\d{3,5})", t)
        if mt:
            assert int(mt.group(1)) == Config.__dataclass_fields__["trial_quota"].default, (page, mt.group(1))


# ---- signed view and vocabulary: page <-> server ----

def test_signed_view_keys_and_version():
    js = _read("web", "js", "signview.js")
    v = re.search(r"export const VIEW_V = '([^']+)'", js).group(1)
    keys = re.findall(r"'([a-z_]+)'", re.search(r"export const VIEW_KEYS = \[([^\]]+)\]", js, re.S).group(1))
    assert v == signview.V, (v, signview.V)
    assert tuple(keys) == tuple(signview.KEYS), (keys, signview.KEYS)


def test_vocabulary_version():
    """The pack checker's strict vocabulary = the server's current one."""
    if not os.path.exists(os.path.join(ROOT, "server", "packtools", "screencheck.py")):
        pytest.skip("no pack screen checker (before r0277)")
    sc = _read("server", "packtools", "screencheck.py")
    m = re.search(r'VOCAB_STRICT = "([^"]+)"', sc)
    if not m:
        pytest.skip("screencheck has no VOCAB_STRICT (before r0277)")
    assert m.group(1) == vocab.V, (m.group(1), vocab.V)


# ---- release version: VERSION <-> CHANGELOG ----

def test_version_matches_changelog():
    ver = _read("deploy", "VERSION").strip()
    m = re.search(r"^## (?:[^\n]*? )?server (\d+\.\d+\.\d+)", _read_or_skip("CHANGELOG.md"), re.M)   # r0288: also "## client ... / server X" (0.2.111 heading)
    assert m and m.group(1) == ver, (ver, m and m.group(1))
