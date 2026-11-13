"""0.2.86 (Ц3, AIUC-1 E015.2, SOC 2 CC8.1): the witness checks a GitHub Actions OIDC token itself (app/runctx.py uses it).

Primary source (read 2026-11-02): docs.github.com "OpenID Connect" (concepts + reference) and the provider's discovery document
https://token.actions.githubusercontent.com/.well-known/openid-configuration:
  issuer   https://token.actions.githubusercontent.com
  jwks_uri https://token.actions.githubusercontent.com/.well-known/jwks
  id_token_signing_alg_values_supported ["RS256"]
  claims: repository, sha, ref, run_id, run_attempt, workflow, workflow_ref, actor, event_name, ... (all strings).
A workflow gets the token with `permissions: id-token: write` and
  curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=<witness origin>".

What is checked (any failure -> 401 OIDC_TOKEN_INVALID with the reason; the token is never stored, only its SHA-256):
  - compact JWS, three base64url parts, at most MAX_TOKEN bytes; header alg == "RS256" exactly (no "none", no HS256 with the public key
    as a secret: there is no code path for any other algorithm), no "crit", a kid;
  - the kid is in GitHub's JWKS (kty RSA, >= 2048 bits); RSASSA-PKCS1-v1_5 / SHA-256 signature over header.payload;
  - iss == ISSUER exactly; aud == the witness origin (a string, or a list that contains it); exp in the future, nbf and iat not in the
    future (LEEWAY seconds of clock skew); repository / sha / run_id / run_attempt / actor present.
JWKS: fetched only by the server (httpx, no redirects, at most MAX_JWKS bytes, at most MAX_KEYS keys), cached JWKS_TTL seconds; an
unknown kid refetches at most once per REFETCH_MIN seconds (a flood of invented kids does not turn into a flood of requests to GitHub).

Tests: DW_GH_OIDC_TEST_JWKS=<path to a JWKS JSON file> replaces the fetch (no network). It is refused unless the witness origin is a
local address (http://localhost / 127.0.0.1), and a record made with it says jwks "test-file" (the checker prints TEST JWKS)."""
import base64
import hashlib
import json
import os
import threading
import time

from app.context import Err

ISSUER = "https://token.actions.githubusercontent.com"
JWKS_URL = ISSUER + "/.well-known/jwks"
TEST_ENV = "DW_GH_OIDC_TEST_JWKS"
MAX_TOKEN = 8192
MAX_JWKS = 65536
MAX_KEYS = 16
JWKS_TTL = 3600
REFETCH_MIN = 60
LEEWAY = 60
FETCH_TIMEOUT = 5
REQUIRED = ("repository", "sha", "run_id", "run_attempt", "actor")
# claims copied into the signed record (all strings in GitHub's tokens), with a length limit each
TAKE = {"repository": 200, "repository_id": 32, "repository_owner_id": 32, "sha": 64, "ref": 255, "run_id": 32, "run_attempt": 16, "workflow": 200,
        "workflow_ref": 400, "actor": 100, "event_name": 64, "runner_environment": 32}

_lock = threading.Lock()
_cache = {"keys": {}, "at": 0.0, "tried": 0.0, "source": None}


class _Bad(Exception):
    pass


def _b64(s):
    if not isinstance(s, str) or not s or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in s):
        raise _Bad("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _uniq_json(raw):
    def hook(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise _Bad("repeated member %s" % k[:40])
            d[k] = v
        return d
    try:
        v = json.loads(raw.decode("utf-8"), object_pairs_hook=hook)
    except _Bad:
        raise
    except Exception:      # noqa: BLE001
        raise _Bad("not JSON")
    if not isinstance(v, dict):
        raise _Bad("not a JSON object")
    return v


def _local(origin):
    return origin.startswith(("http://localhost:", "http://127.0.0.1:")) or origin in ("http://localhost", "http://127.0.0.1")


def _parse_jwks(raw):
    if len(raw) > MAX_JWKS:
        raise _Bad("JWKS too large")
    try:
        doc = json.loads(raw)
    except Exception:      # noqa: BLE001
        raise _Bad("JWKS not JSON")
    from cryptography.hazmat.primitives.asymmetric import rsa
    keys = {}
    for k in (doc.get("keys") if isinstance(doc, dict) else None) or []:
        if len(keys) >= MAX_KEYS:
            break
        if not isinstance(k, dict) or k.get("kty") != "RSA" or not isinstance(k.get("kid"), str) or k.get("alg") not in (None, "RS256") \
                or k.get("use") not in (None, "sig"):
            continue
        try:
            n, e = int.from_bytes(_b64(k["n"]), "big"), int.from_bytes(_b64(k["e"]), "big")
            if n.bit_length() < 2048 or e < 3:
                continue
            pub = rsa.RSAPublicNumbers(e, n).public_key()
        except Exception:      # noqa: BLE001
            continue
        thumb = json.dumps({"e": k["e"], "kty": "RSA", "n": k["n"]}, separators=(",", ":"), sort_keys=True).encode()   # RFC 7638
        keys[k["kid"]] = (pub, base64.urlsafe_b64encode(hashlib.sha256(thumb).digest()).decode().rstrip("="))
    return keys


def _fetch(origin):
    """-> (keys, source). Test file when DW_GH_OIDC_TEST_JWKS is set (local origin only), else GitHub."""
    path = os.environ.get(TEST_ENV)
    if path:
        if not _local(origin):
            raise Err(503, "OIDC_TEST_JWKS_REFUSED", "%s is set on a witness that is not local: refused (tests only)" % TEST_ENV)
        with open(path, "rb") as f:
            return _parse_jwks(f.read(MAX_JWKS + 1)), "test-file"
    import httpx
    with httpx.Client(timeout=FETCH_TIMEOUT, follow_redirects=False) as c:
        with c.stream("GET", JWKS_URL, headers={"Accept": "application/json", "User-Agent": "deus-witness-oidc"}) as r:
            if r.status_code != 200:
                raise _Bad("JWKS HTTP %d" % r.status_code)
            buf = b""
            for chunk in r.iter_bytes():
                buf += chunk
                if len(buf) > MAX_JWKS:
                    raise _Bad("JWKS too large")
    return _parse_jwks(buf), "github"


def _key(kid, origin):
    """-> (public key, RFC 7638 thumbprint, source) for kid; refetches when stale or the kid is unknown (rate-limited)."""
    now = time.time()
    with _lock:
        src_now = "test-file" if os.environ.get(TEST_ENV) else "github"
        stale = now - _cache["at"] > JWKS_TTL or _cache["source"] != src_now
        unknown = kid not in _cache["keys"]
        if stale or (unknown and now - _cache["tried"] >= REFETCH_MIN):
            _cache["tried"] = now
            try:
                keys, src = _fetch(origin)
            except Err:
                raise
            except Exception as e:      # noqa: BLE001  (network, TLS, a bad document)
                if stale or not _cache["keys"]:
                    raise Err(503, "OIDC_JWKS_UNAVAILABLE", "GitHub's key set could not be fetched (%s): try again" % str(e)[:80])
            else:
                _cache.update(keys=keys, at=now, source=src)
        if kid not in _cache["keys"]:
            raise _Bad("kid not in GitHub's key set")
        pub, thumb = _cache["keys"][kid]
        return pub, thumb, _cache["source"]


def reset_cache():
    with _lock:
        _cache.update(keys={}, at=0.0, tried=0.0, source=None)


def verify(token, audience, now=None):
    """-> {"claims": {...taken...}, "kid", "jwk_sha256", "jwks", "token_sha256", "iat", "exp", "aud"}; Err 401 OIDC_TOKEN_INVALID.
    `audience`: the witness origin, or (0.2.87) a tuple of accepted audiences, the origin first (the agent-scoped one second);
    "aud" in the result is the one the token named."""
    try:
        return _verify(token, audience, time.time() if now is None else now)
    except _Bad as e:
        raise Err(401, "OIDC_TOKEN_INVALID", "GitHub OIDC token refused: %s" % e)


def _verify(token, audience, now):
    if not isinstance(token, str) or len(token) > MAX_TOKEN or token.count(".") != 2:
        raise _Bad("not a compact JWT")
    h64, p64, s64 = token.split(".")
    hdr, pay, sig = _uniq_json(_b64(h64)), _b64(p64), _b64(s64)
    if hdr.get("alg") != "RS256":
        raise _Bad("alg %r (only RS256)" % str(hdr.get("alg"))[:20])
    if "crit" in hdr or hdr.get("typ") not in (None, "JWT"):
        raise _Bad("header crit/typ")
    kid = hdr.get("kid")
    if not isinstance(kid, str) or not 0 < len(kid) <= 128:
        raise _Bad("no kid")
    auds = tuple(audience) if isinstance(audience, (tuple, list)) else (audience,)
    pub, thumb, src = _key(kid, auds[0])
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    try:
        pub.verify(sig, (h64 + "." + p64).encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise _Bad("signature")
    c = _uniq_json(pay)
    if c.get("iss") != ISSUER:
        raise _Bad("issuer %r" % str(c.get("iss"))[:80])
    aud = c.get("aud")
    got = [a for a in auds if aud == a or (isinstance(aud, list) and a in aud)]
    if not got:
        raise _Bad("audience %r (expected %s)" % (str(aud)[:80], " or ".join(auds)))
    for k in ("exp", "iat"):
        if not isinstance(c.get(k), (int, float)) or isinstance(c.get(k), bool):
            raise _Bad("no %s" % k)
    if c["exp"] <= now - LEEWAY:
        raise _Bad("expired")
    if c["iat"] > now + LEEWAY or (c.get("nbf") is not None and (not isinstance(c["nbf"], (int, float)) or c["nbf"] > now + LEEWAY)):
        raise _Bad("not yet valid (iat/nbf in the future)")
    taken = {}
    for k, lim in TAKE.items():
        v = c.get(k)
        if v is None:
            continue
        if not isinstance(v, str) or not 0 < len(v) <= lim or not all(0x20 <= ord(ch) <= 0x7e for ch in v):
            raise _Bad("claim %s: not a printable string of 1..%d" % (k, lim))
        taken[k] = v
    miss = [k for k in REQUIRED if k not in taken]
    if miss:
        raise _Bad("claim(s) missing: %s" % ", ".join(miss))
    return {"claims": taken, "kid": kid, "jwk_sha256": thumb, "jwks": src, "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "iat": int(c["iat"]), "exp": int(c["exp"]), "aud": got[-1]}
