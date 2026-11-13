"""Form (ARHITEKTURA 5.3) -> mandate map of -04 6.1. Shared by stub.py and the vector generator."""
import os
import time


def mandate_from_form(form, principal, agent, pin_source, now=None, mid=None):
    now = int(time.time()) if now is None else now
    P = {}
    pu = form.get("purchase")
    if pu is not None:
        if pu.get("enabled"):
            P["purchase"] = {"max_per_action": pu["max_per_action"], "budget": pu["budget"]}
        else:
            P["purchase"] = False
    ms = form.get("message")
    if ms is not None:
        if ms.get("domains") or ms.get("to"):
            P["message"] = {"domains": list(ms.get("domains", [])), "to": list(ms.get("to", []))}
        else:
            P["message"] = False
    d = form.get("delete")
    if d is not None:
        P["delete"] = {"targets": list(d.get("targets", [])), "allow_irreversible": bool(d.get("allow_irreversible"))}
    p = form.get("publish")
    if p is not None:
        P["publish"] = {"channels": list(p.get("channels", []))}
    c = form.get("command")                       # PROPOSAL-06: absent = every shell command asked; false = forbidden; {allow, unlisted}
    if c is False:
        P["command"] = False
    elif c is not None:
        P["command"] = {"allow": list(c.get("allow", []))}
        if c.get("unlisted") is not None:
            P["command"]["unlisted"] = c["unlisted"]
        if c.get("sandboxed") == "allow":         # 0.2.56 (V3): only "allow" is kept ("ask" = the default = absent)
            P["command"]["sandboxed"] = "allow"
    h = form.get("http")                          # PROPOSAL-08-http: absent = every request asked; false = forbidden; {allow (canonical rules), unlisted}
    if h is False:
        P["http"] = False
    elif h is not None:
        P["http"] = {"allow": list(h.get("allow", []))}
        if h.get("unlisted") == "deny":
            P["http"]["unlisted"] = "deny"
    return {"v": "deus-aar-0.1", "id": mid or os.urandom(16).hex(), "principal": principal, "agent": agent,
            "nbf": now, "exp": now + form.get("valid_days", 30) * 86400, "currency": form.get("currency", "USD"),
            "budget_window_s": 86400, "permissions": P, "forbidden_data": list(form.get("forbidden_data", [])),
            "named_circle": False, "key_attestation": "passkey", "pin_source": pin_source}
