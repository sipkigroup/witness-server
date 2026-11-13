"""0.2.87 (Ц3): the owner's run-context policy (app/runpolicy.py) and the agent-scoped OIDC audience. No network: our own RSA key plays
GitHub (as test_0286). Attacks: a token of a repository outside the list, another ref, the same name with another repository_id /
repository_owner_id (a renamed / re-created repository), no ref claim under a ref rule, a declared record under require_verified, a token
with the origin audience under audience=agent, a token minted for agent A spent by agent B of another account, the policy widened with a
cookie but no passkey step-up. A refused token is not spent and nothing is signed."""
import os
import time

from app import runpolicy
from tests.helpers import H, ORIGIN
from tests.recovery_helpers import run_verify
from tests.test_0285_run_context import SHA, _cc, _declare, _judge, _pack
from tests.test_0286_run_context_oidc import KID, claims, gh_key, jwks, token  # noqa: F401  (fixtures)

POL = "/api/run-context-policy"


def _put(person, **b):
    return person.c.put(POL, json=b, headers=H)


def _n(client):
    return client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM run_contexts")["n"]


def _setup(client, owner, tmp_path):
    p = os.path.realpath(str(tmp_path))
    ag, hdr, tok = _cc(client, owner, tmp_path)
    _judge(client, hdr, p, "ls")
    return ag, hdr, tok


def test_0287_policy_get_put_validation_and_stepup(client, owner):
    g = client.get(POL).json()
    assert g["allow"] == [] and g["require_verified"] is False and g["audience"] == "any"
    for bad in ({"allow": "acme/app"}, {"allow": [{"repository": "acme"}]}, {"allow": [{"repository": "acme/app", "refs": ["main"]}]},
                {"allow": [{"repository": "acme/app", "refs": ["refs/*/main"]}]}, {"allow": [{"repository": "acme/app", "x": 1}]},
                {"allow": [{"repository": "acme/app", "repository_id": "12a"}]}, {"allow": [{"repository": "acme/*", "repository_id": "1"}]},
                {"allow": [{"repository": "acme/.."}]}, {"allow": [{"repository": "acme/app"}, {"repository": "acme/app"}]},
                {"allow": [{"repository": "-x/app"}]}, {"require_verified": "yes"}, {"audience": "all"}, {"extra": 1},
                {"allow": [{"repository": "a/b%d" % i} for i in range(runpolicy.MAX_RULES + 1)]}):
        r = _put(owner, **bad)
        assert r.status_code == 422 and r.json()["error"] == "BAD_RUN_CONTEXT_POLICY", (bad, r.text)
    r = _put(owner, allow=[{"repository": "acme/app", "refs": ["refs/heads/main", "refs/tags/v*"], "repository_id": 42,
                            "repository_owner_id": "7"}], require_verified=True)
    assert r.status_code == 200, r.text
    assert r.json()["allow"][0]["repository_id"] == "42" and client.get(POL).json()["require_verified"] is True
    client.app.state.ctx.db.x("UPDATE sessions SET stepup_at=0")              # a cookie without a fresh passkey cannot change it
    r = _put(owner, allow=[])
    assert r.status_code == 403 and r.json()["error"] == "STEPUP_REQUIRED"
    assert client.get(POL).json()["allow"][0]["repository"] == "acme/app"


def test_0287_allow_list_repo_ref_ids(client, owner, tmp_path, gh_key, jwks):
    ag, hdr, tok = _setup(client, owner, tmp_path)
    c0 = dict(repository_owner_id="7")
    assert _put(owner, allow=[{"repository": "Acme/App", "refs": ["refs/heads/main", "refs/tags/v*"], "repository_id": "42",
                               "repository_owner_id": "7"}]).status_code == 200
    ok = _declare(client, hdr, tok, github_oidc_token=token(gh_key, claims(**c0)))
    assert ok.status_code == 200 and ok.json()["claimed"]["repository_owner_id"] == "7", ok.text           # case does not matter
    tag = _declare(client, hdr, tok, github_oidc_token=token(gh_key, claims(ref="refs/tags/v1.2", **c0)))
    assert tag.status_code == 200, tag.text
    n = _n(client)
    refused = []
    for over in ({"repository": "evil/app"}, {"repository": "acme/app2"}, {"ref": "refs/heads/dev"}, {"ref": "refs/pull/1/merge"},
                 {"ref": "refs/tagsv1"}, {"ref": None},
                 {"repository_id": "43"},                    # the same name, another repository (deleted and re-created, transferred)
                 {"repository_owner_id": "8"},               # the owner name re-registered by someone else
                 {"repository_owner_id": None}):
        t = token(gh_key, claims(**dict(c0, **over)))
        r = _declare(client, hdr, tok, github_oidc_token=t)
        assert r.status_code == 403 and r.json()["error"] == "RUN_CONTEXT_POLICY", (over, r.text)
        refused.append(t)
    assert _n(client) == n                                                   # nothing signed
    assert _put(owner, allow=[]).status_code == 200                          # empty list = as 0.2.86: any repository
    r = _declare(client, hdr, tok, github_oidc_token=refused[0])
    assert r.status_code == 200 and r.json()["claimed"]["repository"] == "evil/app", r.text   # the refused token was not spent


def test_0287_owner_wildcard_with_owner_id(client, owner, tmp_path, gh_key, jwks):
    ag, hdr, tok = _setup(client, owner, tmp_path)
    assert _put(owner, allow=[{"repository": "acme/*", "repository_owner_id": "7"}]).status_code == 200
    assert _declare(client, hdr, tok, github_oidc_token=token(gh_key, claims(repository="acme/other", repository_owner_id="7"))).status_code == 200
    r = _declare(client, hdr, tok, github_oidc_token=token(gh_key, claims(repository="acmex/app", repository_owner_id="7")))
    assert r.status_code == 403 and r.json()["error"] == "RUN_CONTEXT_POLICY"
    r = _declare(client, hdr, tok, github_oidc_token=token(gh_key, claims(repository="acme/app", repository_owner_id="9")))
    assert r.status_code == 403 and r.json()["error"] == "RUN_CONTEXT_POLICY"


def test_0287_require_verified_refuses_declared(client, owner, tmp_path, gh_key, jwks):
    ag, hdr, tok = _setup(client, owner, tmp_path)
    assert _declare(client, hdr, tok, repository="acme/app").status_code == 200        # default: declared still accepted
    assert _put(owner, require_verified=True).status_code == 200
    r = _declare(client, hdr, tok, repository="acme/app")
    assert r.status_code == 403 and r.json()["error"] == "RUN_CONTEXT_POLICY" and "require_verified" in r.json()["detail"]
    assert _declare(client, hdr, tok, github_oidc_token=token(gh_key)).json()["verified"] == "github-oidc"
    assert _declare(client, hdr, None, repository="acme/app").status_code == 401   # the export token is still checked first


def test_0287_agent_scoped_audience(client, owner, owner2, tmp_path, gh_key, jwks):
    ag, hdr, tok = _setup(client, owner, tmp_path)
    scoped = runpolicy.agent_audience(ORIGIN, ag["id"])
    assert scoped == ORIGIN + "/agents/" + ag["id"]
    r = _declare(client, hdr, tok, github_oidc_token=token(gh_key, claims(aud=scoped)))
    assert r.status_code == 200 and r.json()["verified"] == "github-oidc", r.text
    rec = client.app.state.ctx.db.one("SELECT id FROM run_contexts WHERE id=?", (r.json()["id"],))
    assert rec is not None
    # a token minted for this agent is useless to any other agent, in another account too (stolen before use)
    (tmp_path / "b").mkdir()
    ag2, hdr2, tok2 = _setup(owner2.c, owner2, tmp_path / "b")
    stolen = token(gh_key, claims(aud=scoped))
    r = _declare(owner2.c, hdr2, tok2, github_oidc_token=stolen)
    assert r.status_code == 401 and r.json()["error"] == "OIDC_TOKEN_INVALID" and "audience" in r.json()["detail"], r.text
    # audience=agent: the origin audience (good in any account until first use) is refused here
    assert _put(owner, audience="agent").status_code == 200
    r = _declare(client, hdr, tok, github_oidc_token=token(gh_key))
    assert r.status_code == 403 and r.json()["error"] == "RUN_CONTEXT_POLICY" and scoped in r.json()["detail"]
    assert _declare(client, hdr, tok, github_oidc_token=stolen).status_code == 200      # the legitimate job spends it here
    # the pack: the record names the scoped audience and both checkers accept it
    folder = _pack(client, hdr, tok, tmp_path / "pack")
    rc, out = run_verify(folder, "--offline")
    assert rc == 0 and out.strip().endswith("RESULT: VALID") and "aud %s" % scoped in out, out


def test_0287_table_erased_with_the_account():
    from app.account_delete import TABLES_BY_ACCOUNT
    assert "run_context_policy" in TABLES_BY_ACCOUNT


def test_0287_matches_unit():
    r = runpolicy.validate({"allow": [{"repository": "acme/app", "refs": ["refs/heads/release/*"]}]})["allow"][0]
    assert runpolicy.matches(r, {"repository": "acme/app", "ref": "refs/heads/release/1.0"})
    assert not runpolicy.matches(r, {"repository": "acme/app", "ref": "refs/heads/main"})
    assert not runpolicy.matches(r, {"repository": "acme/app/x", "ref": "refs/heads/release/1"})
    assert not runpolicy.matches(r, {"repository": "acme", "ref": "refs/heads/release/1"})
    star = runpolicy.validate({"allow": [{"repository": "acme/app", "refs": ["refs/*"]}]})["allow"][0]
    assert runpolicy.matches(star, {"repository": "acme/app", "ref": "refs/pull/1/merge"})


# ---------- client 0.2.55: deus-witness-verify-pack prints the run context (runs/*.cose) ----------
def test_0287_client_and_server_checker_are_the_same_bytes():
    here = os.path.dirname(os.path.abspath(__file__))
    a = open(os.path.join(here, "..", "packtools", "run_context.py"), "rb").read()
    b = open(os.path.join(here, "..", "..", "mcp", "deus_witness", "verify_pack", "run_context.py"), "rb").read()
    assert a == b


def test_0287_client_prints_verified_and_declared_run_context(client, owner, tmp_path, gh_key, jwks):
    from tests.test_0285_run_context import _client_verify
    p = os.path.realpath(str(tmp_path))
    ag, hdr, tok = _cc(client, owner, tmp_path)
    _judge(client, hdr, p, "ls", "s-1")
    _judge(client, hdr, p, "git status", "s-1")
    v = _declare(client, hdr, tok, github_oidc_token=token(gh_key, claims(repository_owner_id="7")), session_ids=["s-1"])
    assert v.status_code == 200, v.text
    d = _declare(client, hdr, tok, repository="acme/declared", commit="abcdef1", run_id="5", actor="bob", started_at=int(time.time()) - 600)
    assert d.status_code == 200, d.text
    folder = _pack(client, hdr, tok, tmp_path / "pack")
    rc, out = _client_verify(folder, "--offline")
    assert rc == 0 and out.strip().endswith("RESULT: VALID"), out
    vid, did = v.json()["id"], d.json()["id"]
    assert ("run context %s: signed by the witness at seq" % vid) in out and "VERIFIED by the witness from a GitHub OIDC token [TEST JWKS]" in out
    for s in ("repository acme/app, commit %s, run 987654 (attempt 2)" % SHA, "workflow_ref acme/app/.github/workflows/ci.yml@refs/heads/main",
              "actor alice", "ref refs/heads/main, repository id 42, owner id 7", "run context %s: 2 decision(s) linked by session" % vid,
              "warning RUN_CONTEXT_TEST_JWKS", "trust: a VERIFIED CI run context"):
        assert s in out, (s, out)
    assert ("run context %s: signed by the witness at seq" % did) in out and "DECLARED by the CI job: repository acme/declared, commit abcdef1" in out
    assert "trust: the CI run context (repository" in out
    rc2, out2 = run_verify(folder, "--offline")                  # the server's copy says the same
    assert rc2 == 0 and "repository id 42, owner id 7" in out2, out2


def _one_record(client, owner, tmp_path, gh_key):
    p = os.path.realpath(str(tmp_path))
    ag, hdr, tok = _cc(client, owner, tmp_path)
    _judge(client, hdr, p, "ls")
    j = _declare(client, hdr, tok, github_oidc_token=token(gh_key)).json()
    return j["id"], _pack(client, hdr, tok, tmp_path / "pack")


def test_0287_client_unknown_future_fields_warn_not_invalid(client, owner, tmp_path, gh_key, jwks, app):
    import shutil
    import cbor2
    from svidetel_v4 import cose
    from app import runctx
    from tests.test_0285_run_context import _client_verify, _resign
    rid, src = _one_record(client, owner, tmp_path, gh_key)
    raw = open(os.path.join(src, "runs", rid + ".cose"), "rb").read()
    wk = app.state.ctx.wk
    pl = cose.loads(cose.verify1(raw, [wk], runctx.TYP_RUN)[0])
    for i, (change, word) in enumerate(((dict(policy={"sha256": "ab"}), "policy"), (dict(oidc=dict(pl["oidc"], jwk={"n": "x"})), "oidc.jwk"),
                                        (dict(verified="gitlab-oidc"), "verified=gitlab-oidc"))):
        d = str(tmp_path / ("f%d" % i))
        shutil.copytree(src, d)
        _resign(d, "runs/%s.cose" % rid, cose.sign1(wk, cbor2.dumps(dict(pl, **change), canonical=True), runctx.TYP_RUN), wk)
        rc, out = _client_verify(d, "--offline")
        assert rc == 0 and out.strip().endswith("RESULT: VALID"), (change, out)
        assert "warning RUN_CONTEXT_UNKNOWN_FIELD" in out and word in out and "update deus-witness" in out, (change, out)
        if "verified" in change:                                  # an unknown method: its values are not shown as VERIFIED
            assert "VERIFIED by the witness" not in out and "DECLARED by the CI job: repository acme/app" in out, out
        rc, out = run_verify(d, "--offline")                      # the pack's own (strict) copy
        assert rc == 1 and "RUN_CONTEXT_MALFORMED" in out, (change, out)
    # still INVALID for the client: a broken known member, another signer, altered bytes, a broken link
    bad = [(dict(oidc=dict(pl["oidc"], iss="https://evil.example")), wk, "RUN_CONTEXT_MALFORMED"),
           (dict(receipts=[["r_nope", 1]]), wk, "RUN_CONTEXT_LINK"),
           (dict(at_head=b"\0" * 32), wk, "RUN_CONTEXT_CHAIN"),
           ({}, cose.Key.generate(cose.ALG_EDDSA), "RUN_CONTEXT_SIG")]
    for i, (change, key, code) in enumerate(bad):
        d = str(tmp_path / ("b%d" % i))
        shutil.copytree(src, d)
        _resign(d, "runs/%s.cose" % rid, cose.sign1(key, cbor2.dumps(dict(pl, **change), canonical=True), runctx.TYP_RUN), wk)
        rc, out = _client_verify(d, "--offline")
        assert rc == 1 and code in out and out.strip().endswith("RESULT: INVALID"), (code, out)
    d = str(tmp_path / "alt")
    shutil.copytree(src, d)
    open(os.path.join(d, "runs", rid + ".cose"), "wb").write(raw.replace(b"acme/app", b"acme/apq"))
    rc, out = _client_verify(d, "--offline")
    assert rc == 1 and "MISMATCH runs/" in out
