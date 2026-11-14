"""r0292 (owner 13.11, p.7): the public constitution (web/constitution.html) lists ONLY laws the code holds today, each with the check
next to it. This file holds the two laws that had no check before (the agent never widens its own rights; safety features are never
behind a paywall) and checks the page itself: every check it names exists, so a law cannot outlive its test silently."""
import inspect
import re
from pathlib import Path

from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
from tests.helpers import ORIGIN
from tests.test_org import CHANGING, USER_LEVEL, api_routes, fill

ROOT = Path(__file__).resolve().parents[2]          # the cloud tree: server/, web/, contract/ ...
PAGE = ROOT / "web" / "constitution.html"

# The agent's own changing routes (its Bearer key). A NEW one fails this test on purpose: review that it cannot widen the agent's
# rights (rules, "from now on", delegation, members, keys, approvals) before adding it here.
AGENT_CHANGING = {("POST", "/v1/actions"), ("POST", "/v1/trial/retire"), ("POST", "/v1/actions/{rid}/present"), ("POST", "/v1/actions/{rid}/report"),
                  ("POST", "/v1/hook/judge"), ("POST", "/v1/hook/run"), ("POST", "/v1/hook/run/start"), ("POST", "/v1/run-context"),
                  ("POST", "/v1/trial"),       # /v1/trial: makes a NEW quick start account (no key yet), never touches an existing one
                  ("POST", "/v1/catalog"), ("POST", "/v1/coverage")}   # app/flow: the agent's tool list / declaration, kept; nothing applies itself
RIGHTS_TABLES = ("mandates", "allowances", "agent_delegations", "org_policies", "members", "credentials", "repeat_approvals", "sig_requests")


def v1_changing(app):
    out = set()

    def walk(routes):
        for r in routes:
            if hasattr(r, "original_router"):
                walk(r.original_router.routes)
                continue
            p = getattr(r, "path", "")
            if p.startswith("/v1/"):
                for m in getattr(r, "methods", ()) or ():
                    if m in CHANGING:
                        out.add((m, p))
    walk(app.routes)
    return out


def test_agent_routes_cannot_widen_rights(app, owner):
    # (1) the agent's changing routes are exactly the known ones
    assert v1_changing(app) == AGENT_CHANGING, v1_changing(app) ^ AGENT_CHANGING
    # (2) the agent's modules write no table that holds rights
    src = "".join((ROOT / "server" / "app" / f).read_text() for f in ("api_agent.py", "flow/api.py", "flow/catalog.py"))
    for t in RIGHTS_TABLES:
        assert not re.search(r"(INSERT|UPDATE|DELETE\s+FROM|REPLACE)[^\"']*\b%s\b" % t, src, re.I), t
    # (3) an agent key opens none of the people's changing routes (they need a person's session)
    ag, hdr = owner.new_agent("demo", "a")
    c = TestClient(app, base_url=ORIGIN)                 # no cookie: only the agent's key
    hits = []
    for m, pth in api_routes(app):
        if m not in CHANGING or pth.startswith("/api/auth/") or pth in USER_LEVEL:
            continue
        r = c.request(m, fill(pth, {"aid": ag["id"], "agent": ag["id"]}), json={}, headers=dict(hdr, Origin=ORIGIN))
        if r.status_code not in (401, 403):
            hits.append((m, pth, r.status_code))
    assert not hits, hits


def test_safety_features_have_no_paywall(app):
    """Stop, freeze, revoke, recovery codes, export, account deletion: no plan, tier or payment condition in their handlers, and no such
    field on an account. (Today nothing is paid; this keeps a future paywall away from these routes.)"""
    db = app.state.ctx.db
    cols = {r["name"] for r in db.q("PRAGMA table_info(accounts)")}
    assert not {c for c in cols if re.search(r"plan|tier|paid|billing|subscription|price", c, re.I)}, cols
    safety = {"/api/agents/{aid}/freeze", "/api/mandates/{mid}/revoke", "/api/allowances/{aid}/revoke", "/api/auth/recovery-codes",
              "/api/export", "/api/account/delete"}
    seen = set()

    def walk(routes):
        for r in routes:
            if hasattr(r, "original_router"):
                walk(r.original_router.routes)
                continue
            if getattr(r, "path", "") in safety:
                seen.add(r.path)
                body = inspect.getsource(r.endpoint)
                assert not re.search(r"\b(plan|tier|paid|billing|subscription|paywall)\b", body, re.I), r.path
    walk(app.routes)
    assert seen == safety, safety - seen


def _checks(html):
    return re.findall(r'<code class="check">([^<]+)</code>', html)


def test_constitution_page_is_versioned_and_every_law_has_a_check():
    html = PAGE.read_text()
    text = re.sub(r"<[^>]+>", " ", html)
    assert re.search(r"Version \d+ \(\d{4}-\d{2}-\d{2}\)", text)
    # the owner's wordings (13.11)
    for w in ("Any weakening comes only as a new version, announced in advance, never retroactively",
              "Safety features are never behind a paywall",
              "We do not try to catch every attack",
              "irreversible action without a person impossible by construction",
              "witness-server"):
        assert w in text, w
    laws = re.findall(r'<li class="law"[^>]*>(.*?)</li>', html, re.S)
    assert len(laws) >= 6, len(laws)
    main = re.findall(r'<li class="law main"', html)
    assert 5 <= len(main) <= 6, len(main)
    for law in laws:
        assert _checks(law), "a law without a check: " + re.sub(r"<[^>]+>", " ", law)[:80]
    # every check the page names exists: the file, and the test function in it
    for ref in _checks(html):
        path, _, name = ref.partition("::")
        f = ROOT / path
        assert f.is_file(), ref
        if name:
            assert re.search(r"def %s\b" % re.escape(name), f.read_text()), ref


def test_constitution_is_linked_from_the_home_page():
    assert 'href="/constitution.html"' in (ROOT / "web" / "index.html").read_text()
