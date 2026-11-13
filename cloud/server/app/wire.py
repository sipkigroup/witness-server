"""0.2.4 (draft-deus-aar-05 Section 8.6): the JSON wire form of the one bstr member the cloud keeps in JSON, `toolmap_sha256`.
In CBOR (the signed mandate, the action of a RECEIPT) it is `bstr .size 32`; in JSON (API, database, web pages) it is 64 lower-case hex.
`cbor_form` / `wire_form` convert the top-level member only (the mandate or the action itself); the web client does the same inside its CDE encoder (web/js/cde.js)."""
import hashlib
import re

KEY = "toolmap_sha256"
_HEX = re.compile(r"[0-9a-f]{64}")


def cbor_form(x):
    """Top-level member only (R4-03, 0.2.5): the page's encoder (web/js/cde.js) converts the member only in the top-level map it encodes (the mandate, the action)."""
    if isinstance(x, dict) and isinstance(x.get(KEY), str) and _HEX.fullmatch(x[KEY]):
        return dict(x, **{KEY: bytes.fromhex(x[KEY])})
    return x


def wire_form(x):
    if isinstance(x, dict) and isinstance(x.get(KEY), (bytes, bytearray)):
        return dict(x, **{KEY: bytes(x[KEY]).hex()})
    return x


def doc_hash(cde_bytes):
    return hashlib.sha256(cde_bytes).hexdigest()
