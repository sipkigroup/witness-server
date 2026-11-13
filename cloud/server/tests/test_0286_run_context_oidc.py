"""0.2.86 (Ц3, AIUC-1 E015.2, SOC 2 CC8.1): the witness verifies a GitHub Actions OIDC token itself (app/gh_oidc.py, app/runctx.py).
Our own RSA key plays GitHub: tokens are signed locally and the server reads a substituted JWKS (DW_GH_OIDC_TEST_JWKS); no network.
Attacks: another issuer, another audience, expired, nbf/iat in the future, alg none, HS256 with the public key as the HMAC secret, a kid
not in the JWKS, a claim changed after signing, a key not in the JWKS under a known kid, repeated JSON members, body/token mismatch,
token reuse, the test JWKS on a non-local witness. A verified record: claims from the token, token not stored, VERIFIED in the server
checker, client 0.2.54 still VALID."""
import base64
import hashlib
import hmac
import io
import json
import os
import shutil
import time
import zipfile

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app import gh_oidc, runctx
from tests.helpers import ORIGIN
from tests.recovery_helpers import run_verify
from tests.test_0285_run_context import SHA, _cc, _client_verify, _declare, _judge, _pack, _resign

KID = "test-kid-1"


def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _jwk(key, kid):
    n = key.public_key().public_numbers()
    return {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid, "n": _b64(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")),
            "e": _b64(n.e.to_bytes(3, "big"))}


@pytest.fixture(scope="module")
def gh_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def jwks(gh_key, tmp_path, monkeypatch):
    f = tmp_path / "jwks.json"
    f.write_text(json.dumps({"keys": [_jwk(gh_key, KID)]}))
    monkeypatch.setenv(gh_oidc.TEST_ENV, str(f))
    gh_oidc.reset_cache()
    yield f
    gh_oidc.reset_cache()


def claims(**over):
    t = int(time.time())
    c = {"iss": gh_oidc.ISSUER, "aud": ORIGIN, "iat": t - 10, "nbf": t - 10, "exp": t + 300, "jti": "j-%d" % time.time_ns(),
         "sub": "repo:acme/app:ref:refs/heads/main", "repository": "acme/app", "repository_id": "42", "repository_owner": "acme",
         "sha": SHA, "ref": "refs/heads/main", "run_id": "987654", "run_attempt": "2", "workflow": "ci",
         "workflow_ref": "acme/app/.github/workflows/ci.yml@refs/heads/main", "actor": "alice", "event_name": "push",
         "runner_environment": "github-hosted"}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def token(key, c=None, hdr=None, raw_payload=None):
    h = hdr or {"alg": "RS256", "typ": "JWT", "kid": KID}
    h64 = _b64(json.dumps(h).encode())
    p64 = _b64(raw_payload if raw_payload is not None else json.dumps(c if c is not None else claims()).encode())
    sig = key.sign((h64 + "." + p64).encode(), padding.PKCS1v15(), hashes.SHA256())
    return h64 + "." + p64 + "." + _b64(sig)


def _err(r):
    return r.status_code, r.json().get("error")


def test_0286_verified_record_claims_from_token_both_checkers(client, owner, tmp_path, gh_key, jwks):
    p = os.path.realpath(str(tmp_path))
    ag, hdr, tok = _cc(client, owner, tmp_path)
    _judge(client, hdr, p, "ls", "s-9")
    t = token(gh_key)
    r = _declare(client, hdr, tok, github_oidc_token=t, session_ids=["s-9"], started_at=int(time.time()) - 60)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["verified"] == "github-oidc" and j["kid"] == KID and j["token_sha256"] == hashlib.sha256(t.encode()).hexdigest()
    assert j["claimed"]["repository"] == "acme/app" and j["claimed"]["commit"] == SHA and j["claimed"]["run_attempt"] == "2"
    assert j["claimed"]["workflow_ref"].endswith("ci.yml@refs/heads/main") and j["claimed"]["ref"] == "refs/heads/main"
    assert j["link"] == "session" and j["receipts"] == 1 and j["note"] == runctx.NOTE_OIDC
    db = client.app.state.ctx.db
    sig_part = t.split(".")[2]
    for row in db.q("SELECT cose, claimed_json FROM run_contexts"):          # the token is never stored
        assert sig_part.encode() not in bytes(row["cose"]) and t.split(".")[1] not in row["claimed_json"]
    assert db.one("SELECT COUNT(*) AS n FROM run_context_oidc")["n"] == 1
    folder = _pack(client, hdr, tok, tmp_path / "pack")
    rc, out = run_verify(folder, "--offline")
    assert rc == 0 and out.strip().endswith("RESULT: VALID"), out
    assert "VERIFIED by the witness from a GitHub OIDC token [TEST JWKS]" in out and "kid %s" % KID in out, out
    assert "repository acme/app, commit %s, run 987654 (attempt 2)" % SHA in out and "warning RUN_CONTEXT_TEST_JWKS" in out
    assert "trust: a VERIFIED CI run context" in out and "TEST key set" in out
    assert "trust: the CI run context (repository" not in out              # no declared record in this pack
    rc, out = _client_verify(folder, "--offline")             # client 0.2.54: ignores runs/, the manifest hashes it
    assert rc == 0 and out.strip().endswith("RESULT: VALID"), out


def test_0286_body_matching_token_accepted_mismatch_refused(client, owner, tmp_path, gh_key, jwks):
    p = os.path.realpath(str(tmp_path))
    ag, hdr, tok = _cc(client, owner, tmp_path)
    _judge(client, hdr, p, "ls")
    ok = _declare(client, hdr, tok, github_oidc_token=token(gh_key), repository="acme/app", commit=SHA, run_id="987654", run_attempt="2",
                  actor="alice", workflow="acme/app/.github/workflows/ci.yml@refs/heads/main")
    assert ok.status_code == 200 and ok.json()["verified"] == "github-oidc", ok.text
    for k, v in (("repository", "evil/app"), ("commit", "f" + SHA[1:]), ("commit", SHA[:12]), ("run_id", "1"), ("run_attempt", "1"),
                 ("actor", "mallory"), ("workflow", "release")):
        r = _declare(client, hdr, tok, github_oidc_token=token(gh_key), **{k: v})
        assert _err(r) == (400, "RUN_CONTEXT_MISMATCH") and k in r.json()["detail"], (k, r.text)
    assert client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM run_contexts")["n"] == 1        # nothing signed on a mismatch
    r = _declare(client, hdr, tok, github_oidc_token=token(gh_key), token="x")
    assert _err(r) == (400, "BAD_RUN_CONTEXT")                                                    # other members still checked


def test_0286_forged_tokens_refused(client, owner, tmp_path, gh_key, jwks):
    p = os.path.realpath(str(tmp_path))
    ag, hdr, tok = _cc(client, owner, tmp_path)
    _judge(client, hdr, p, "ls")
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    t = int(time.time())
    good = token(gh_key)
    h64, p64, s64 = good.split(".")
    pub_pem = gh_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    hs_h = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode())
    hs = hs_h + "." + p64 + "." + _b64(hmac.new(pub_pem, (hs_h + "." + p64).encode(), hashlib.sha256).digest())
    none_h = _b64(json.dumps({"alg": "none", "kid": KID}).encode())
    altered = json.loads(base64.urlsafe_b64decode(p64 + "=" * (-len(p64) % 4)))
    altered["repository"] = "evil/app"
    cases = {
        "issuer": token(gh_key, claims(iss="https://token.actions.githubusercontent.com.evil.example")),
        "issuer2": token(gh_key, claims(iss="https://accounts.google.com")),
        "audience": token(gh_key, claims(aud="https://another-witness.example")),
        "audience2": token(gh_key, claims(aud=["https://another-witness.example"])),
        "expired": token(gh_key, claims(exp=t - 120, iat=t - 900, nbf=t - 900)),
        "nbf": token(gh_key, claims(nbf=t + 600)),
        "iat": token(gh_key, claims(iat=t + 600)),
        "no exp": token(gh_key, claims(exp=None)),
        "alg none": none_h + "." + p64 + ".",
        "alg none2": none_h + "." + p64 + "." + s64,
        "HS256": hs,
        "kid": token(gh_key, hdr={"alg": "RS256", "kid": "not-in-jwks"}),
        "no kid": token(gh_key, hdr={"alg": "RS256"}),
        "claim": h64 + "." + _b64(json.dumps(altered).encode()) + "." + s64,
        "other key, known kid": token(other),
        "repeated member": token(gh_key, raw_payload=json.dumps(claims())[:-1].encode() + b', "repository": "evil/app"}'),
        "missing sha": token(gh_key, claims(sha=None)),
        "crit": token(gh_key, hdr={"alg": "RS256", "kid": KID, "crit": ["x"]}),
        "garbage": "a.b",
        "not str": 12345,
    }
    for name, bad in cases.items():
        r = _declare(client, hdr, tok, github_oidc_token=bad)
        assert _err(r) == (401, "OIDC_TOKEN_INVALID"), (name, r.text)
    assert client.app.state.ctx.db.one("SELECT COUNT(*) AS n FROM run_contexts")["n"] == 0
    # a token outside the dedicated member is still refused (0.2.85: too long for actor, or shaped like a secret)
    assert _err(_declare(client, hdr, tok, actor=good)) == (400, "BAD_RUN_CONTEXT")
    assert _err(_declare(client, hdr, tok, actor=good[:90])) == (400, "SECRET_REFUSED")


def test_0286_token_reuse_refused(client, owner, tmp_path, gh_key, jwks):
    p = os.path.realpath(str(tmp_path))
    ag, hdr, tok = _cc(client, owner, tmp_path)
    _judge(client, hdr, p, "ls")
    t = token(gh_key)
    assert _declare(client, hdr, tok, github_oidc_token=t).status_code == 200
    assert _err(_declare(client, hdr, tok, github_oidc_token=t)) == (409, "OIDC_TOKEN_REUSED")


def test_0286_without_token_stays_declared_085_shape(client, owner, tmp_path):
    p = os.path.realpath(str(tmp_path))
    ag, hdr, tok = _cc(client, owner, tmp_path)
    _judge(client, hdr, p, "ls")
    j = _declare(client, hdr, tok, repository="acme/app", commit=SHA, started_at=int(time.time()) - 60).json()
    assert j["verified"] == "declared" and j["note"] == runctx.NOTE
    folder = _pack(client, hdr, tok, tmp_path / "pack")
    from svidetel_v4 import cose
    pl = cose.loads(cose.verify1(open(os.path.join(folder, "runs", j["id"] + ".cose"), "rb").read(), [client.app.state.ctx.wk], runctx.TYP_RUN)[0])
    assert "verified" not in pl and "oidc" not in pl                   # same members as 0.2.85: the 0.2.85 checker still reads it
    rc, out = run_verify(folder, "--offline")
    assert rc == 0 and "DECLARED by the CI job: repository acme/app" in out and "VERIFIED" not in out, out


def test_0286_resigned_verified_record_shape_checked(client, owner, tmp_path, gh_key, jwks, app):
    """A witness-key re-signed record that claims verification with a broken oidc member, or an altered claim without re-signing."""
    from svidetel_v4 import cose
    p = os.path.realpath(str(tmp_path))
    ag, hdr, tok = _cc(client, owner, tmp_path)
    _judge(client, hdr, p, "ls")
    j = _declare(client, hdr, tok, github_oidc_token=token(gh_key)).json()
    src = _pack(client, hdr, tok, tmp_path / "pack")
    f = os.path.join(src, "runs", j["id"] + ".cose")
    raw = open(f, "rb").read()
    wk = app.state.ctx.wk
    payload = cose.loads(cose.verify1(raw, [wk], runctx.TYP_RUN)[0])
    for i, change in enumerate((dict(verified="yes"), dict(oidc=dict(payload["oidc"], iss="https://evil.example")),
                                dict(oidc={k: v for k, v in payload["oidc"].items() if k != "kid"}),
                                dict(oidc=dict(payload["oidc"], token_sha256="zz")), dict(oidc=dict(payload["oidc"], jwks="other")))):
        d = str(tmp_path / ("t%d" % i))
        shutil.copytree(src, d)
        _resign(d, "runs/%s.cose" % j["id"], cose.sign1(wk, cbor2.dumps(dict(payload, **change), canonical=True), runctx.TYP_RUN), wk)
        rc, out = run_verify(d, "--offline")
        assert rc == 1 and "RUN_CONTEXT_MALFORMED" in out, (change, out)
    d = str(tmp_path / "alt")
    shutil.copytree(src, d)
    open(os.path.join(d, "runs", j["id"] + ".cose"), "wb").write(raw.replace(b"acme/app", b"acme/apq"))
    rc, out = run_verify(d, "--offline")
    assert rc == 1 and "INVALID RUN_CONTEXT_SIG" in out
    rc, out = _client_verify(d, "--offline")
    assert rc == 1 and "MISMATCH runs/" in out


def test_0286_test_jwks_refused_on_non_local_witness(gh_key, jwks):
    with pytest.raises(Exception) as e:
        gh_oidc.verify(token(gh_key, claims(aud="https://witness.example")), "https://witness.example")
    assert getattr(e.value, "code", None) == "OIDC_TEST_JWKS_REFUSED"
    v = gh_oidc.verify(token(gh_key), ORIGIN)
    assert v["jwks"] == "test-file" and v["claims"]["sha"] == SHA


def test_0286_jwks_cache_bounded_refetch(gh_key, monkeypatch):
    monkeypatch.delenv(gh_oidc.TEST_ENV, raising=False)
    gh_oidc.reset_cache()
    calls = []
    keys = gh_oidc._parse_jwks(json.dumps({"keys": [_jwk(gh_key, KID)]}).encode())

    def fake(origin):
        calls.append(origin)
        return keys, "github"
    monkeypatch.setattr(gh_oidc, "_fetch", fake)
    try:
        for _ in range(3):
            assert gh_oidc.verify(token(gh_key), ORIGIN)["jwks"] == "github"
        assert len(calls) == 1                                        # cached
        for rnd, want in ((0, 1), (1, 2)):                            # invented kids: at most one fetch per REFETCH_MIN
            if rnd:
                gh_oidc._cache["tried"] -= gh_oidc.REFETCH_MIN
            for i in range(5):
                with pytest.raises(Exception) as e:
                    gh_oidc.verify(token(gh_key, hdr={"alg": "RS256", "kid": "invented-%d-%d" % (rnd, i)}), ORIGIN)
                assert getattr(e.value, "code", None) == "OIDC_TOKEN_INVALID"
            assert len(calls) == want
        gh_oidc._cache["at"] -= gh_oidc.JWKS_TTL + 1                  # stale -> refetched
        gh_oidc.verify(token(gh_key), ORIGIN)
        assert len(calls) == 3

        def down(origin):
            raise OSError("network down")
        monkeypatch.setattr(gh_oidc, "_fetch", down)
        gh_oidc._cache["at"] -= gh_oidc.JWKS_TTL + 1
        with pytest.raises(Exception) as e:
            gh_oidc.verify(token(gh_key), ORIGIN)
        assert getattr(e.value, "code", None) == "OIDC_JWKS_UNAVAILABLE"
    finally:
        gh_oidc.reset_cache()


def test_0286_jwks_parse_limits():
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    big = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    doc = {"keys": [_jwk(small, "small"), dict(_jwk(big, "hs"), kty="oct"), dict(_jwk(big, "enc"), use="enc"), _jwk(big, "ok")]
           + [_jwk(big, "k%d" % i) for i in range(40)]}
    keys = gh_oidc._parse_jwks(json.dumps(doc).encode())
    assert "small" not in keys and "hs" not in keys and "enc" not in keys and "ok" in keys and len(keys) == gh_oidc.MAX_KEYS
    with pytest.raises(Exception):
        gh_oidc._parse_jwks(b" " * (gh_oidc.MAX_JWKS + 1))


def test_0286_table_erased_with_the_account():
    from app.account_delete import TABLES_BY_ACCOUNT
    assert "run_context_oidc" in TABLES_BY_ACCOUNT
