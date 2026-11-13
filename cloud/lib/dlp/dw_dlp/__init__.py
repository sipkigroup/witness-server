"""dw_dlp — deterministic DLP for Deus Witness Cloud.

scan(text, literals) -> {"tags": [...], "hits": ["L1:<class>", "L2:<format>"]}
    L1: the account's literals (case-insensitive substring) and the built-in secret shapes;
    L2: formats with validators (rules_v1). Sorted, never the matched values.
    Pure: no network, clock, randomness or global state; the same input gives byte-identical output.
    The advisor (dw_dlp.advisor) is never consulted here.
mask(text, literals, limit) -> the text with every L1/L2 match replaced by "[masked]", cut to `limit`.
ruleset_id() -> "dw-dlp-1/<first 8 hex of SHA-256 of rules_v1.py>".
"""
import hashlib
import os

from . import rules_v1

RULESET = "dw-dlp-1"
MASK = "[masked]"
MASK_INPUT_CHARS = 4096     # as toolmap.mask_text: only the head of the text is examined (the preview is short anyway)
MASK_MARGIN = 128           # ...plus a margin, so a value that straddles the cut is still recognised and masked

_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules_v1.py")


def ruleset_id():
    with open(_RULES_PATH, "rb") as f:
        return RULESET + "/" + hashlib.sha256(f.read()).hexdigest()[:8]


def _literal_classes(text, literals):
    low = text.lower()
    return sorted(cls for cls, lits in (literals or {}).items() if any(l and l.lower() in low for l in lits))


def scan(text, literals):
    if not isinstance(text, str):
        raise TypeError("text must be str")
    l1 = rules_v1.secret_names(text)
    l1.update(_literal_classes(text, literals))
    l2 = {fmt for _, _, fmt in rules_v1.find_all(text)}
    return {"tags": sorted(l1 | l2), "hits": sorted(["L1:" + c for c in l1] + ["L2:" + f for f in l2])}


def _literal_spans(text, literals):
    lits = sorted({l.lower() for ls in (literals or {}).values() for l in ls if l}, key=lambda x: (-len(x), x))
    if not lits:
        return []
    low = text.lower()
    if len(low) != len(text):          # lower() changed the length (rare Unicode): fall back to a case-insensitive regex
        import re
        rx = re.compile("|".join(re.escape(l) for l in lits), re.I)
        return [m.span() for m in rx.finditer(text)]
    spans = []
    for l in lits:
        i = low.find(l)
        while i >= 0:
            spans.append((i, i + len(l)))
            i = low.find(l, i + len(l))
    return spans


def mask(text, literals, limit):
    s = text[:max(MASK_INPUT_CHARS, limit) + MASK_MARGIN]
    spans = [m.span() for _, rx in rules_v1.SECRET_RE for m in rx.finditer(s)]
    spans += _literal_spans(s, literals)
    spans += [(a, b) for a, b, _ in rules_v1.find_all(s)]
    out, pos = [], 0
    for a, b in sorted(spans):
        if b <= pos:
            continue
        if a > pos:
            out.append(s[pos:a])
        if a >= pos:
            out.append(MASK)
        pos = b
    out.append(s[pos:])
    return "".join(out)[:limit]
