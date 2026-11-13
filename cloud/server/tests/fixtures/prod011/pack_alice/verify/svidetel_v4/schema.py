"""Section 6.1 CDDL of the mandate, as an executable check (draft-deus-aar-02: optional members, absent = null; unknown members rejected).
Also Section 6.3 (ceiling) and Section 7.1 (entry bodies). Returns None or the first offending member."""


MANDATE_KEYS = {"v", "id", "principal", "agent", "nbf", "exp", "currency", "budget_window_s", "permissions", "forbidden_data",
                "named_circle", "key_attestation", "pin_source", "payment_mandate_ref", "permit_ref"}
PERM_KEYS = ("message", "file", "disclosure", "purchase", "sale", "meeting", "refund", "delete", "publish")


def _is_uint(x):
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def _is_strs(x):
    return isinstance(x, list) and all(isinstance(i, str) for i in x)


def _rcpt_ok(p, with_data=False):
    if not isinstance(p, dict) or not (p.get("to") is None or p["to"] == "*" or _is_strs(p["to"])):
        return False
    if p.get("domains") is not None and not _is_strs(p["domains"]):
        return False
    return not with_data or p.get("data") is None or _is_strs(p["data"])


def validate_mandate(m):
    """Section 6.1 CDDL (-01). -> None if well formed, else a short reason (the witness answers MANDATE_MALFORMED)."""
    if not isinstance(m, dict):
        return "not a map"
    for k, ty in (("id", str), ("principal", str), ("agent", str), ("currency", str)):
        if not isinstance(m.get(k), ty):
            return k
    if m.get("v") != "deus-aar-0.1":
        return "v"
    for k in ("nbf", "exp", "budget_window_s"):
        if not _is_uint(m.get(k)):
            return k
    if set(m) - MANDATE_KEYS:
        return "unknown member"
    if not _is_strs(m.get("forbidden_data")) or not (m.get("named_circle") is None or isinstance(m["named_circle"], bool)):
        return "forbidden_data/named_circle"             # -03 (C2-1): `named_circle: null` is allowed (`? "named_circle": bool / null`)
    if not (m.get("pin_source") is None or isinstance(m["pin_source"], str)):
        return "pin_source"
    for k in ("payment_mandate_ref", "permit_ref"):
        h = m.get(k)
        if not (h is None or (isinstance(h, dict) and h.get("alg") == "sha-256" and isinstance(h.get("digest"), bytes)
                              and set(h) <= {"alg", "digest", "uri"} and isinstance(h.get("uri", ""), str))):
            return k
    if m.get("key_attestation") not in ("secure-element", "passkey", "software"):
        return "key_attestation"
    P = m.get("permissions")
    if not isinstance(P, dict) or set(P) - set(PERM_KEYS):
        return "permissions"
    for k, p in P.items():
        if p is None or p is False:
            continue
        ok = {"message": lambda: _rcpt_ok(p), "file": lambda: _rcpt_ok(p), "disclosure": lambda: _rcpt_ok(p, True),
              "meeting": lambda: p is True, "refund": lambda: p is True,
              "purchase": lambda: isinstance(p, dict) and all(p.get(x) is None or _is_uint(p[x]) for x in ("max_per_action", "budget")),
              "sale": lambda: isinstance(p, dict) and (p.get("min_price") is None or _is_uint(p["min_price"])),
              "delete": lambda: isinstance(p, dict) and _is_strs(p.get("targets", [])) and (p.get("allow_irreversible") is None or isinstance(p["allow_irreversible"], bool)),
              "publish": lambda: isinstance(p, dict) and _is_strs(p.get("channels", []))}[k]()
        if not ok:
            return "permissions." + k
        if isinstance(p, dict) and set(p) - SUB_KEYS[k]:
            return "permissions." + k + " unknown member"
    return None


SUB_KEYS = {"message": {"to", "domains"}, "file": {"to", "domains"}, "disclosure": {"to", "domains", "data"},
            "purchase": {"max_per_action", "budget"}, "sale": {"min_price"}, "meeting": set(), "refund": set(),
            "delete": {"targets", "allow_irreversible"}, "publish": {"channels"}}


def validate_ceiling(c):
    """-02 Section 6.3: the CEILING entry body carries the members of the principal-signed map (beside cose / signed_by).
    -> None or the first offending member (the witness answers CEILING_MALFORMED)."""
    if not isinstance(c, dict):
        return "not a map"
    for k in ("id", "currency"):
        if not isinstance(c.get(k), str):
            return k
    if not _is_uint(c.get("amount")):
        return "amount"
    if not _is_uint(c.get("window_s")) or c["window_s"] < 1:
        return "window_s"
    return None


def validate_body(typ, b, own_seq=None):
    """-02 Section 7.1: CDDL of the entry bodies (members not named are ignored). -> None or a reason (verifier: MALFORMED)."""
    if not isinstance(b, dict):
        return "body"
    need = {"MANDATE": ("mandate",), "CEILING": (), "REVOCATION": ("mandate",), "APPROVAL": ("receipt", "approved"),
            "CONSUME": ("receipt",), "RELEASE": ("receipt", "cause"), "REFUND": (), "RECEIPT": ("id", "mandate", "action", "verdict", "reason", "ttl"),
            "CHECKPOINT": ("seq", "head", "root")}
    if typ not in need:
        return "type"
    for k in need[typ]:
        if k not in b:
            return k
    if typ == "RECEIPT":
        if not (isinstance(b["id"], str) and isinstance(b["mandate"], str) and isinstance(b["action"], dict) and isinstance(b["reason"], str)
                and b["verdict"] in ("allow", "defer", "deny") and _is_uint(b["ttl"])):
            return "RECEIPT member type"
        if "audience" in b:
            if not isinstance(b["audience"], str):
                return "audience"
        elif not (b["verdict"] == "deny" and b["reason"] == "NO_MANDATE"):
            return "audience"
    if typ == "CHECKPOINT" and not (_is_uint(b["seq"]) and isinstance(b["head"], (bytes, str)) and isinstance(b["root"], (bytes, str))):
        return "CHECKPOINT member type"
    if typ == "CHECKPOINT" and own_seq is not None and not b["seq"] < own_seq:
        return "CHECKPOINT seq"                          # Section 7.1: seq < own seq
    if typ == "APPROVAL" and not isinstance(b["approved"], bool):
        return "approved"
    return None
