"""r0284, law Z1 (KONSTITUCIYA-I-ROLI-1311): an agent never widens its own rights.

Every route an agent key (Bearer dwk_) can reach is registered in app/api_agent.py (the only router whose auth is `agent_of`). The test lists
them and fails when a route appears that is not on the reviewed list, or whose path names something that changes rights: mandates, allowances,
policy, members, delegation, settings, agents, keys. A new agent route must be reviewed against Z1 and added to AGENT_ROUTES on purpose."""
import re

from app import api_agent

AGENT_ROUTES = {
    ("GET", "/v1/salt"), ("POST", "/v1/actions"), ("POST", "/v1/trial/retire"), ("GET", "/v1/trial/status"),
    ("GET", "/v1/actions/{rid}"), ("POST", "/v1/actions/{rid}/present"), ("POST", "/v1/actions/{rid}/report"),
    ("POST", "/v1/hook/judge"), ("POST", "/v1/hook/run"), ("POST", "/v1/hook/run/start"), ("GET", "/v1/hook/run/{nonce}"),
    ("GET", "/v1/export"), ("POST", "/v1/run-context"), ("GET", "/v1/hook/status"), ("GET", "/v1/hook/scanlist"),
}
RIGHTS_WORDS = re.compile(r"mandate|allowance|polic|member|invite|deleg|setting|config|agents?\b|keys?\b|owner|team|org|ceiling|device|passkey|recover", re.I)


def _agent_routes(app):
    out = set()
    for rt in api_agent.make_router(app.state.ctx).routes:
        for m in rt.methods - {"HEAD", "OPTIONS"}:
            out.add((m, rt.path))
    return out


def test_only_api_agent_reads_agent_keys():
    """The premise of this file: no other module authenticates a request by `Bearer dwk_` (so AGENT_ROUTES is the whole agent surface)."""
    import glob
    import os
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app")
    users = sorted(os.path.basename(f) for f in glob.glob(os.path.join(here, "*.py"))
                   if 'startswith("Bearer dwk_")' in open(f, encoding="utf-8").read())
    assert users == ["api_agent.py"], users


def test_agent_routes_are_the_reviewed_list(app):
    got = _agent_routes(app)
    assert got, "no agent routes found: the test lost its subject"
    assert got == AGENT_ROUTES, "agent routes changed (new: %s, gone: %s): review against law Z1, then update AGENT_ROUTES" % (
        sorted(got - AGENT_ROUTES), sorted(AGENT_ROUTES - got))


def test_no_agent_route_touches_rights(app):
    bad = sorted((m, p) for m, p in _agent_routes(app) if RIGHTS_WORDS.search(p))
    assert not bad, "an agent-key route that looks like it changes rights (law Z1): %s" % bad
