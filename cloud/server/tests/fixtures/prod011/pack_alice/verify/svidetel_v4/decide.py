"""Sections 5-6 of draft-deus-aar-01. Pure functions, no I/O.

Registered action classes: message file disclosure purchase sale meeting refund delete publish.
Any other class: deny CLASS_UNKNOWN (fail closed).

delete  permission: absent/None | False | {"targets": [str...], "allow_irreversible": bool}
        action.recipient = resource id (opaque, byte-exact; NOT canonicalised); action.reversible = bool (default false).
        target match: exact, or an entry of length >= 2 ending in "*" is a prefix match; a wildcard never matches an id with a
        "." or ".." path segment.   absent: reversible -> defer ESCALATE_DELETE, irreversible -> deny IRREVERSIBLE_DELETE.
publish permission: absent/None | False | {"channels": [str...]}   (action.recipient = channel id)
        any protected data -> deny DATA_FORBIDDEN (before everything else in the class rule); absent -> defer ESCALATE_PUBLISH.
Witness time is a PARAMETER of decide() (Section 5.3); action["t"] is only the harness shorthand used by abstract vectors.
"""
import re
import unicodedata

CLASSES = ("message", "file", "disclosure", "purchase", "sale", "meeting", "refund", "delete", "publish")
NON_PROTECTED = ("city",)


_WS = re.compile("[\t-\r \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]")   # Unicode White_Space
MAX_AMOUNT = 10 ** 15
MONETARY = ("purchase", "sale", "refund")


def _nfkc_cf(s):
    """toNFKC_Casefold (Unicode 3.13): NFKC, full case folding, NFKC, drop default-ignorable code points (Cf, variation selectors)."""
    s = unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", str(s)).casefold())
    return "".join(c for c in s if unicodedata.category(c) != "Cf" and not 0xFE00 <= ord(c) <= 0xFE0F)


_MAILBOX = re.compile(r"[^@,;:<>()\[\]\"\\]+@[^@,;:<>()\[\]\"\\]+")


def canon_addr(s):
    """Section 5.4. -> canonical string, or None when the recipient is syntactically invalid (never matches)."""
    s = str(s)
    if "<" in s or ">" in s:
        m = re.fullmatch(r"[^<>]*<([^<>]+)>[^<>]*", s)
        if not m:
            return None
        s = m.group(1)
    s = _WS.sub("", _nfkc_cf(s))
    # ERRATA-04 E1 (review R-01): one mailbox only. Exactly one "@", non-empty local part and domain, no list/quote/comment/route characters.
    return s if _MAILBOX.fullmatch(s) else None


def canon_domain(s):
    return _WS.sub("", _nfkc_cf(s))


def protected(data):
    return sorted({x for x in data if x not in NON_PROTECTED})


def risk(a):
    c = a["class"]
    if c in ("purchase", "sale", "refund"):
        return "monetary"
    if c in ("file", "publish"):
        return "disclosure"
    if c in ("message", "disclosure"):
        return "disclosure" if protected(a.get("data", [])) else "low"
    if c == "meeting":
        return "low" if a.get("principal_present") is True else "irreversible"      # -02 (C-22): only the boolean true counts
    if c == "delete":
        return "low" if a.get("reversible") is True else "irreversible"
    return "irreversible"


def _circle(P):
    out = set()
    for n in ("message", "file", "disclosure"):
        p = P.get(n)
        if isinstance(p, dict) and isinstance(p.get("to"), list):
            out |= {canon_addr(x) for x in p["to"]}
    return out


def _recipient(p, rcpt, circ=frozenset()):
    if p.get("to") == "*":
        return True
    if p.get("to") is None and p.get("domains") is None:      # Section 6.2: unspecified iff `to` null/absent and `domains` absent
        return None
    a = canon_addr(rcpt)
    if a is None:
        return False
    if a in {canon_addr(x) for x in (p.get("to") or [])}:
        return True
    dom = a.rsplit("@", 1)[-1] if "@" in a else None
    if dom is not None and dom in {canon_domain(d) for d in (p.get("domains") or [])}:
        return True
    return "circle" if a in circ else False


def _res_match(entries, target):
    """Section 5.6.1: exact byte match, or entry of length >= 2 ending in "*" = prefix; wildcards never match "." / ".." segments."""
    target = str(target)
    segs = target.split("/")
    for e in entries or []:
        if not isinstance(e, str):
            continue
        if e == target:
            return True
        if len(e) >= 2 and e.endswith("*") and target.startswith(e[:-1]) and "." not in segs and ".." not in segs:
            return True
    return False


def _protected_rule(P, a):
    pd = protected(a.get("data", []))
    if not pd:
        return None
    rp = P.get("disclosure")
    if rp is False:
        return ("deny", "DATA_FORBIDDEN")
    if rp is None or rp.get("data") is None:
        return ("deny", "DATA_NOT_PERMITTED")
    if not set(pd) <= set(rp["data"]):
        return ("deny", "DATA_FORBIDDEN")
    r = _recipient(rp, a.get("recipient", ""))
    if r is None:
        return ("defer", "ESCALATE_DATA")
    return None if r is True else ("deny", "RECIPIENT")


def _per_class(M, P, perm, a, st):
    c, amt = a["class"], a.get("amount", 0)
    circ = _circle(P) if M.get("named_circle") else frozenset()
    if perm is not None and perm is not True and not isinstance(perm, dict) and c not in ("meeting", "refund"):
        return ("deny", "CLASS_DENIED")                 # malformed permission value: fail closed
    if c in ("message", "file", "disclosure") and canon_addr(a.get("recipient", "")) is None:
        return ("deny", "RECIPIENT")                    # -02 (C-8): an invalid recipient matches nothing, whatever the permission ('*', unspecified)
    if c == "meeting":
        return ("allow", "OK" if perm is True else "OK_UNSPECIFIED")
    if c == "delete":
        rev = a.get("reversible") is True
        if perm is None:
            return ("defer", "ESCALATE_DELETE") if rev else ("deny", "IRREVERSIBLE_DELETE")
        if not _res_match(perm.get("targets"), a.get("recipient", "")):
            return ("deny", "RESOURCE")
        if not rev and not perm.get("allow_irreversible"):
            return ("deny", "IRREVERSIBLE_DELETE")
        return ("allow", "OK")
    if c == "publish":
        if protected(a.get("data", [])):
            return ("deny", "DATA_FORBIDDEN")
        if perm is None or perm.get("channels") is None:
            return ("defer", "ESCALATE_PUBLISH")
        return ("allow", "OK") if _res_match(perm["channels"], a.get("recipient", "")) else ("deny", "RESOURCE")
    if c in ("message", "disclosure"):
        p = perm
        if c == "disclosure" and not protected(a.get("data", [])):
            p = P.get("message")
            if p is False:
                return ("deny", "CLASS_DENIED")
        if p is None:
            return ("allow", "OK_UNSPECIFIED")
        r = _recipient(p, a.get("recipient", ""), circ)
        if r is False:
            return ("deny", "RECIPIENT")
        return ("allow", {True: "OK", "circle": "OK_CIRCLE", None: "OK_UNSPECIFIED"}[r])
    if c == "file":
        if perm is None:
            return ("defer", "ESCALATE_FILE")
        r = _recipient(perm, a.get("recipient", ""), circ)
        if r is None:
            return ("defer", "ESCALATE_FILE")
        if r is False:
            return ("deny", "RECIPIENT")
        return ("allow", "OK" if r is True else "OK_CIRCLE")
    if c == "refund":
        return ("allow", "OK") if perm is True else ("defer", "ESCALATE_MONEY")
    if c == "sale":
        if perm is None or perm.get("min_price") is None:
            return ("defer", "ESCALATE_MONEY")
        return ("deny", "PRICE") if amt < perm["min_price"] else ("allow", "OK")
    p = perm or {}
    mx, bd = p.get("max_per_action"), p.get("budget")
    if mx is not None and amt > mx:
        return ("deny", "PER_ACTION_LIMIT")
    if bd is not None and st.get("mandate_committed", 0) + amt > bd:
        return ("deny", "BUDGET")
    ce = st.get("ceiling")
    if ce is not None and st.get("principal_committed", 0) + amt > ce:
        return ("deny", "CEILING")
    if perm is None or mx is None or bd is None:
        return ("defer", "ESCALATE_MONEY")
    return ("allow", "OK")


def decide(M, a, st, now=None):
    """Section 6.4 -> (verdict, reason). M carries '_sig_valid' (bool) and '_revoked' (bool) set by the caller.
    now = witness time (integer seconds); None = harness shorthand a["t"] (abstract decision vectors)."""
    if M is None:
        return ("deny", "NO_MANDATE")
    if not M.get("_sig_valid", True):
        return ("deny", "MANDATE_SIG")
    if a.get("agent") != M["agent"]:
        return ("deny", "AGENT_MISMATCH")
    t = a.get("t", 0) if now is None else now
    if M.get("_revoked") or not (M["nbf"] <= t <= M["exp"]):
        return ("deny", "EXPIRED")
    if a["class"] not in CLASSES:
        return ("deny", "CLASS_UNKNOWN")
    amt = a.get("amount", 0)
    if isinstance(amt, bool) or not isinstance(amt, int) or amt < 0 or amt > MAX_AMOUNT:
        return ("deny", "BAD_AMOUNT")
    if a["class"] in MONETARY and "amount" not in a:      # -02 (C-11): amount is REQUIRED in a monetary action ...
        return ("deny", "BAD_AMOUNT")
    if a["class"] not in MONETARY and amt != 0:            # ... and a non-monetary action carries 0 or no amount
        return ("deny", "BAD_AMOUNT")
    if a["class"] in MONETARY and (a.get("currency") is None or a.get("currency") != M.get("currency")):
        return ("deny", "BAD_AMOUNT")
    if set(a.get("data", [])) & set(M.get("forbidden_data", [])):
        return ("deny", "DATA_FORBIDDEN")
    P = M["permissions"]
    perm = P.get(a["class"])
    if perm is False:
        return ("deny", "CLASS_DENIED")
    if a["class"] == "meeting" and risk(a) == "irreversible":
        return ("deny", "UNATTENDED_MEETING")
    res = _per_class(M, P, perm, a, st)
    if res[0] == "deny":
        return res
    if a["class"] == "publish":
        return res
    d = _protected_rule(P, a)
    if d is not None and (d[0] == "deny" or res[0] == "allow"):
        return d
    return res
