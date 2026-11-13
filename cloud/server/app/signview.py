"""pv2810: the signing view (presentation hash). What the approval page shows the person -- the action, its recipient, the danger
mark, the previews of the arguments, the text, the code and the changed files, the reason it waits -- is a JSON object taken from
the server's answer to GET /api/approvals/{rid}. Its hash, SHA-256 over the RFC 8785 (JCS) form, is a member `view` of the signed
approval / release payload, so the passkey signature names what was shown. The server rebuilds the view from its own rows when the
signature arrives and refuses a different hash (409 VIEW_CHANGED). The page (web/js/signview.js) builds the same object from the same
answer and hashes it the same way.

Members (absent when the answer has none): v, rid, status, tool, action, args_preview, text_preview, reason, adv, line_commands,
net_code, exec_changed, written_run, masked_dep (29.10 MDEP: the masked names the question depends on; absent = the view as before),
unseen_write (N4 29.10: what an extraction / patch writes, its text unseen; absent = the view as before),
line_full + text_cut (04.11, Hypothesis I2: every command of a shell line, whole and masked; the text preview was cut at 4 KB; absent = as before).
web/js/signview.js VIEW_KEYS is the same list (tests/test_view_keys_0411.py).
Not in the view: the mandate (its hash is already signed), times, offers, levels, who is waiting."""
import hashlib
import json
import math

V = "dw-view-1"
KEYS = ("rid", "status", "tool", "action", "args_preview", "text_preview", "reason", "adv", "line_commands", "net_code",
        "exec_changed", "written_run", "masked_dep", "unseen_write", "line_full", "text_cut", "what", "harm", "risk", "details")


def _num(x):
    """RFC 8785 3.2.2.3 = ECMAScript Number::toString (R5-V6, 0.2.84): the shortest round-trip digits, plain notation from 1e-6
    up to 1e21, exponent form outside; an integer-valued float prints its shortest digits padded with zeros, never its exact binary value."""
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        if abs(x) > 2 ** 53:
            raise ValueError("JCS: integer outside the IEEE-754 exact range")
        return str(x)
    if not math.isfinite(x):
        raise ValueError("JCS: not a finite number")
    if x == 0:
        return "0"
    sign, r = ("-", repr(-x)) if x < 0 else ("", repr(x))
    m, _, e = r.partition("e")
    ip, _, fp = m.partition(".")
    digits = (ip + fp).lstrip("0")
    n = len(ip.lstrip("0")) + int(e or 0) if ip.lstrip("0") else int(e or 0) - (len(fp) - len(fp.lstrip("0")))
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        out = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if n - 1 >= 0 else "-") + str(abs(n - 1))
    return sign + out


def _str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch in "\b\f\n\r\t":
            out.append({"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:     # control characters; a lone surrogate as ECMAScript's well-formed stringify does
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(v) -> bytes:
    """RFC 8785 canonical JSON (UTF-8 bytes): members sorted by their UTF-16 code units, no white space, ECMAScript numbers."""
    def enc(x):
        if x is None:
            return "null"
        if isinstance(x, (bool, int, float)):
            return _num(x)
        if isinstance(x, str):
            return _str(x)
        if isinstance(x, (list, tuple)):
            return "[" + ",".join(enc(i) for i in x) + "]"
        if isinstance(x, dict):
            if not all(isinstance(k, str) for k in x):
                raise ValueError("JCS: member names are strings")
            ks = sorted(x, key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(_str(k) + ":" + enc(x[k]) for k in ks) + "}"
        raise ValueError("JCS: %s is not JSON" % type(x).__name__)
    return enc(v).encode("utf-8", "surrogatepass")


def view_of(answer: dict) -> dict:
    """The signing view of an answer of GET /api/approvals/{rid} (a JSON round trip first: the page hashes what it parsed)."""
    a = json.loads(json.dumps(answer, ensure_ascii=False))
    v = {"v": V}
    for k in KEYS:
        if k in a and a[k] is not None:
            v[k] = a[k]
    return v


def view_hash(answer: dict) -> bytes:
    return hashlib.sha256(jcs(view_of(answer))).digest()


def remember(db, account_id, answer, t):
    """0.2.83 (MR-24): store the shown object whose hash the server has just accepted as signed (api_web._view_match), keyed by that hash.
    -> the hash (hex). The evidence pack (export.shown_view_files) carries it as views/<rid>.json, views/allowance-<id>.json, views/release-<rid>.json."""
    v = view_of(answer)
    h = hashlib.sha256(jcs(v)).hexdigest()
    db.x("INSERT INTO shown_views(account_id, sha256, view_json, t) VALUES(?,?,?,?) ON CONFLICT(account_id, sha256) DO UPDATE SET t=excluded.t",
         (account_id, h, json.dumps(v, ensure_ascii=False, sort_keys=True), int(t)))
    return h
