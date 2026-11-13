"""Form (ARHITEKTURA 5.3) -> mandate map of -04 6.1 (validated). Output is byte-identical to cloud/contract/forms.py for valid forms."""
import os
import time
import unicodedata

from app import _paths  # noqa: F401
from svidetel_v4 import httpcanon
from svidetel_v4.schema import validate_mandate
from app.context import Err


# one limit for a money amount of the form (cents): the page field takes up to 9 digits of dollars + 2 decimals (web/js/mandate_form.js MAX_CENTS)
MAX_CENTS = 99_999_999_999


def _hidden(ch):
    """review 5 (R5-01): bidi controls, zero-width and other Cc/Cf/Zl/Zp characters and non-ASCII spaces change what a person sees, not what the core compares."""
    return unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") or (ord(ch) > 127 and unicodedata.category(ch) == "Zs")


def _clean(s, name):
    for ch in s:
        if _hidden(ch):
            raise Err(400, "FORM_INVALID", "%s: the text contains an invisible or direction-control character (U+%04X); the form refuses it" % (name, ord(ch)))
    return s


def _ascii_domain(d, name):
    if not d.isascii():
        raise Err(400, "FORM_INVALID", "%s: a domain must be ASCII; write an international domain in punycode (xn--...)" % name)
    return d


def _domain_of(addr):
    return addr.rsplit("@", 1)[1] if "@" in addr else ""


def _strs(x, name, kind=None):
    if x is None:
        return []
    if not isinstance(x, list) or not all(isinstance(i, str) and 0 < len(i) <= 256 for i in x) or len(x) > 200:
        raise Err(422, "FORM_INVALID", name + " must be a list of non-empty strings")
    for i in x:
        _clean(i, name)
        if kind == "domain":
            _ascii_domain(i, name)
        elif kind == "addr":
            _ascii_domain(_domain_of(i), name)
    return list(x)


def _payees(x, name="purchase.payees"):
    """0.2.84 (R5-P3/P4/P5): a payee id is kept as a list item (it may hold a comma: "Acme, Inc." is one payee); its length is counted in
    UTF-8 bytes (1..256 here, 1..512 in the schema: the one unit of the page, this form, the schema and the Swift verifier); a space at
    either end is refused, as on the page (ids are compared byte for byte, an invisible edge space would make another mandate)."""
    if x is None:
        return []
    if not isinstance(x, list) or len(x) > 200 or not all(isinstance(i, str) and 0 < len(i.encode("utf-8", "surrogatepass")) <= 256 for i in x):
        raise Err(422, "FORM_INVALID", name + " must be a list of at most 200 non-empty payee ids of at most 256 bytes (UTF-8) each")
    for i in x:
        _clean(i, name)
        if i != i.strip():
            raise Err(422, "FORM_INVALID", "%s: %r has a space at the start or end; payee ids are compared byte for byte" % (name, i[:60]))
    return list(x)


def _bool(x, name):
    if not isinstance(x, bool):
        raise Err(422, "FORM_INVALID", name + " must be true or false")
    return x


def _uint(x, name):
    if not isinstance(x, int) or isinstance(x, bool) or x < 0 or x > MAX_CENTS:
        raise Err(422, "FORM_INVALID", name + " must be a non-negative integer")
    return x


def http_perm(h, err=None):
    """form.http {allow: [rule...], unlisted: ask|deny} -> permissions.http with every rule in its CANONICAL text (svidetel_v4/httpcanon.py:
    lower-case host, upper-case method and %-hex, ":443" dropped, unreserved octets decoded). A rule that cannot be made canonical is refused,
    never "fixed" into something wider. unlisted "ask" is left out (absent = ask)."""
    if not isinstance(h, dict) or set(h) - {"allow", "unlisted"}:
        raise Err(422, "FORM_INVALID", "http: an object with allow (list of rules) and unlisted (ask / deny)")
    rules = []
    for r in _strs(h.get("allow"), "http.allow"):
        c = httpcanon.canon_rule(r.strip())
        if c is None:
            raise Err(422, "FORM_INVALID", "http.allow: %r is not a rule. Write METHOD host[:port]/path, e.g. GET api.github.com/repos/acme/app/** "
                                           "(METHOD or *; ASCII host or *.domain, punycode for international names; path segments, * = one segment, "
                                           "a final ** = one or more; no regular expressions, no .. or encoded /)" % r[:120])
        if c not in rules:
            rules.append(c)
    if len(rules) > httpcanon.MAX_RULES:
        raise Err(422, "FORM_INVALID", "http.allow: at most %d rules" % httpcanon.MAX_RULES)
    out = {"allow": rules}
    u = h.get("unlisted")
    if u is not None:
        if u not in ("ask", "deny"):
            raise Err(422, "FORM_INVALID", "http.unlisted must be ask or deny (there is no allow: whoever wants every request to run does not route it to Witness)")
        if u == "deny":
            out["unlisted"] = "deny"
    return out


def mandate_from_form(form, principal, agent, pin_source, now=None, mid=None):
    if not isinstance(form, dict):
        raise Err(422, "FORM_INVALID", "form must be an object")
    now = int(time.time()) if now is None else now
    cur = form.get("currency", "USD")
    if not isinstance(cur, str) or not 3 <= len(cur) <= 8 or not cur.isascii() or not cur.isalpha():
        raise Err(422, "FORM_INVALID", "currency: a currency code of letters (ISO 4217, e.g. USD)")
    cur = cur.upper()                     # 0.2.84 (R5-P2): the same case as the tool map writes into every action (app/toolmap.py)
    days = form.get("valid_days", 30)
    if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 365:
        raise Err(422, "FORM_INVALID", "valid_days 1..365")
    P = {}
    pu = form.get("purchase")
    if pu is not None:
        if not isinstance(pu, dict):
            raise Err(422, "FORM_INVALID", "purchase")
        if "enabled" in pu and not isinstance(pu["enabled"], bool):
            raise Err(422, "FORM_INVALID", "purchase.enabled must be true or false")
        if pu.get("enabled"):
            P["purchase"] = {"max_per_action": _uint(pu.get("max_per_action"), "max_per_action"), "budget": _uint(pu.get("budget"), "budget")}
            if pu.get("min_per_action") is not None:          # 0.2.83: the lower bound of one purchase (absent = no bound, the mandate as before)
                mn = _uint(pu["min_per_action"], "min_per_action")
                if mn > P["purchase"]["max_per_action"]:
                    raise Err(422, "FORM_INVALID", "purchase: min_per_action cannot exceed max_per_action")
                if mn > 0:
                    P["purchase"]["min_per_action"] = mn
            pay = _payees(pu.get("payees"))                       # 0.2.83: the only payees (byte-exact ids); empty = any payee, as before
            if pay:
                if len(set(pay)) != len(pay):
                    raise Err(422, "FORM_INVALID", "purchase.payees: a payee is listed twice")
                P["purchase"]["allowed_payees"] = pay
        else:
            P["purchase"] = False
    ms = form.get("message")
    if ms is not None:
        if not isinstance(ms, dict):
            raise Err(422, "FORM_INVALID", "message")
        dom, to = _strs(ms.get("domains"), "domains", "domain"), _strs(ms.get("to"), "to", "addr")
        P["message"] = {"domains": dom, "to": to} if (dom or to) else False
    d = form.get("delete")
    if d is not None:
        if not isinstance(d, dict):
            raise Err(422, "FORM_INVALID", "delete")
        P["delete"] = {"targets": _strs(d.get("targets"), "targets"), "allow_irreversible": _bool(d.get("allow_irreversible", False), "allow_irreversible")}
    p = form.get("publish")
    if p is not None:
        if not isinstance(p, dict):
            raise Err(422, "FORM_INVALID", "publish")
        P["publish"] = {"channels": _strs(p.get("channels"), "channels")}
    c = form.get("command")              # PROPOSAL-06: absent/null = every shell command asked (ESCALATE_COMMAND); false = forbidden
    if c is False:
        P["command"] = False
    elif c is not None:
        if not isinstance(c, dict) or set(c) - {"allow", "unlisted", "sandboxed"}:
            raise Err(422, "FORM_INVALID", "command: an object with allow (list) and unlisted (ask / allow / deny)")
        P["command"] = {"allow": _strs(c.get("allow"), "command.allow")}
        if c.get("unlisted") is not None:
            if c["unlisted"] not in ("ask", "allow", "deny"):
                raise Err(422, "FORM_INVALID", "command.unlisted must be ask, allow or deny")
            P["command"]["unlisted"] = c["unlisted"]
        if c.get("sandboxed") is not None:       # V3: "allow" = test runners inside a strict Claude Code sandbox run without a question
            if c["sandboxed"] not in ("ask", "allow"):
                raise Err(422, "FORM_INVALID", "command.sandboxed must be ask or allow")
            if c["sandboxed"] == "allow":
                P["command"]["sandboxed"] = "allow"
    h = form.get("http")                 # 0.2.43 PROPOSAL-08-http: absent/null = every HTTP request asked (ESCALATE_HTTP); false = forbidden
    if h is False:
        P["http"] = False
    elif h is not None:
        P["http"] = http_perm(h)
    m = {"v": "deus-aar-0.1", "id": mid or os.urandom(16).hex(), "principal": principal, "agent": agent,
         "nbf": now, "exp": now + days * 86400, "currency": cur,
         "budget_window_s": 86400, "permissions": P, "forbidden_data": _strs(form.get("forbidden_data"), "forbidden_data"),
         "named_circle": False, "key_attestation": "passkey", "pin_source": pin_source}
    bad = validate_mandate(m)
    if bad:
        raise Err(422, "FORM_INVALID", "mandate does not satisfy CDDL: " + str(bad))
    return m
