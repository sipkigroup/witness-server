"""r0277: the first screen of a question, rebuilt OFFLINE by a third party (P1 and P2 of the Mandate Receipt profile).

Standard library only; no code of the server. Input: the shown objects (views/<key>.json, already tied to the passkey signature by
mandate_check.view_checks: SHA-256 over RFC 8785 = the signed `view`) and the reason vocabulary each approval's mandate pinned
(MANDATE.toolmap_sha256 -> toolmaps/<hex>.cbor member "vocab" -> vocab/<digest>.json, its bytes hash to the name).

P1 (words): a vocabulary "mr-vocab-2" or later ("mr-vocab-3", r0294: + a run of code from the network; "mr-vocab-4", r0298: + a file that
starts commands by itself, in a folder the witness cannot tell; "mr-vocab-5", r0305: + a program that switches off a protection of the
operating system) holds EVERY sentence the first
screen may show; each receipt is rebuilt from the version ITS mandate pinned (a sentence added later is not in an older one). For each signed view that carries the words:
  - `what` and `harm` must each be one template of that vocabulary (a string leaf of the document) with its placeholders filled:
      {t}    a quote of the shown call: after the witness's cleaning (invisible characters as <U+XXXX> marks, control characters and
             backquote as a space, trimmed, cut with an ellipsis) it is a substring of a string the view itself carries (the action, the
             tool, the text, the commands of the line, the details); or a vocabulary leaf; or a ", " list of vocabulary leaves (data tags)
      {n}    the number of commands of the line (view.line_commands)
      {when} one of the vocabulary's time phrases ("{n} min ago", "{n} h ago", "earlier")
  - `risk` must be a level of the vocabulary (risk_label).
  - the view's action names the same recipient and class as the receipt the passkey signed.
  Anything else is WORDING_NOT_DERIVED (INVALID): the agent (or a witness that wrote free text) put words on the first screen that the
  person's pinned vocabulary does not contain. A mandate that pinned "mr-vocab-1" (before r0277) or none: the words are reported as not
  rebuildable (warning WORDING_LEGACY), as before.
  Honest limit: the witness chooses the reason code and the parse; P1 proves the sentence is the vocabulary's, not that the code was right.

P2 (omitted): a view may carry {"rule": "mr-omit-1", "items": [{"m", "how"}]}: what the first screen does NOT show whole. The checker applies
  the same closed rule (omitted_expected) and refuses a list with a member too many or too few (OMITTED_MISMATCH, INVALID); the person may
  not have seen the listed members: the line says APPROVED_PARTIAL_VIEW with the list. A view without it (a page older than r0277) is
  warning OMITTED_UNDECLARED.
"""
import functools
import hashlib
import json
import os
import re
import unicodedata

VOCAB_STRICT = "mr-vocab-5"      # the server's current vocabulary (r0294: + a run of code from the network; r0298: + autostart, folder unknown;
#                                  r0305: + an OS protection switched off)
VOCAB_REBUILT = ("mr-vocab-2", "mr-vocab-3", "mr-vocab-4", "mr-vocab-5")    # every version whose words are rebuilt; older mandates check as before
VOCAB_FIRST = VOCAB_REBUILT[0]
OMIT_RULE = "mr-omit-1"
FIRST_SCREEN = ("rid", "status", "what", "harm", "risk")
_PH = re.compile(r"\{(t|n|when)\}")


# ------------------------------------------------------------------ P2
def omitted_expected(view):
    """The closed rule mr-omit-1 (= server app/signview.omitted_of): -> [{"m", "how"}] sorted."""
    it = set()
    for k in view:
        if k not in FIRST_SCREEN and k not in ("v", "omitted"):
            it.add((k, "folded"))
    if view.get("text_cut") is True:
        it.add(("text_preview", "cut"))
    if isinstance(view.get("details"), str) and "\nText (first 1500 of " in "\n" + view["details"]:
        it.add(("details", "cut"))
    if view.get("masked_dep"):
        it.add(("masked_dep", "masked"))
    if isinstance(view.get("unseen_write"), dict):
        it.add(("unseen_write", "unseen"))
    wr = view.get("written_run")
    if isinstance(wr, dict) and any(isinstance(w, dict) and w.get("cut") is True for w in (wr.get("writes") or [])):
        it.add(("written_run", "cut"))
    return [{"m": m, "how": h} for m, h in sorted(it)]


def check_omitted(view):
    """-> (code | None, items | None). code: None (declared and right), "OMITTED_UNDECLARED" (an older page), "OMITTED_MISMATCH"."""
    om = view.get("omitted")
    if om is None:
        return "OMITTED_UNDECLARED", None
    if not (isinstance(om, dict) and om.get("rule") == OMIT_RULE and isinstance(om.get("items"), list) and set(om) == {"rule", "items"}):
        return "OMITTED_MISMATCH", None
    want = omitted_expected(view)
    if om["items"] != want:
        return "OMITTED_MISMATCH", om["items"]
    return None, om["items"]


# ------------------------------------------------------------------ P1
_INVISIBLE = {0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x034F, 0x180B, 0x180C, 0x180D, 0x180E, 0x061C, 0x00AD}
_CTRL = re.compile(r"[\x00-\x1f\x7f`]")


def _hidden(ch):
    cp = ord(ch)
    if cp in _INVISIBLE or 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return True
    c = unicodedata.category(ch)
    return c in ("Cf", "Zl", "Zp", "Co", "Cs", "Cn") or (c == "Zs" and ch != " ")


def _norm(s):
    """The witness's cleaning of a quoted target without the cut: invisible characters as marks, controls and backquote as a space."""
    return _CTRL.sub(" ", "".join("⟨U+%04X⟩" % ord(ch) if _hidden(ch) else ch for ch in str(s)))


def _leaves(x, path=()):
    if isinstance(x, str):
        yield path, x
    elif isinstance(x, list):
        for i, v in enumerate(x):
            if path[:1] == ("path_harm",) and len(path) == 2 and i == 0:
                continue                                        # a regular expression of the vocabulary, never a sentence
            yield from _leaves(v, path + (i,))
    elif isinstance(x, dict):
        for k in sorted(x):
            yield from _leaves(x[k], path + (k,))


def vocab_leaves(vocab):
    """-> {sentence: "path/of/leaf"} of every string of the vocabulary document."""
    out = {}
    for p, s in _leaves({k: v for k, v in vocab.items() if k != "v"}):
        out.setdefault(s, "/".join(str(i) for i in p))
    return out


@functools.lru_cache(maxsize=4096)
def _rx(tpl):
    parts, pos, names = [], 0, []
    for m in _PH.finditer(tpl):
        parts.append(re.escape(tpl[pos:m.start()]))
        nm = m.group(1)
        # r0294: {when} is "<number> <unit> ago" or one word ("earlier"), never a bare "ago": a sentence with {t} right before it
        # ("from {t} {when}") then has one split only (a greedy {t} cannot take "github.com 3 min" and leave "ago")
        parts.append("(?P<%s%d>%s)" % (nm, len(names), r"[0-9]+" if nm == "n" else (r"[0-9]+ \S+ ago|(?!ago(?:\s|$))\S+" if nm == "when" else ".+")))
        names.append(nm)
        pos = m.end()
    parts.append(re.escape(tpl[pos:]))
    return re.compile("".join(parts), re.S), names


CALL_FIELDS = ("action", "tool", "text_preview", "args_preview", "line_commands", "line_full", "net_code")


def _quotes(view, fields=CALL_FIELDS):
    out = []
    for k in fields:
        if k in view:
            out.extend(_norm(s) for _, s in _leaves(view[k]))
    return out


def _slot_ok(name, val, view, leaves, quotes, when_rx):
    if name == "n":
        lc = view.get("line_commands")
        return isinstance(lc, list) and val == str(len([h for h in lc if isinstance(h, str) and h.strip()][:64]))
    if name == "when":                      # a time phrase of the vocabulary; its {n} is a number of minutes / hours, nothing else
        return any(r.fullmatch(val) is not None and all(nm == "n" for nm in ns) for r, ns in when_rx)
    if val in leaves or (", " in val and all(p in leaves for p in val.split(", "))):
        return True
    q = val[:-1] if val.endswith("…") else val
    q = q.strip()
    return bool(q) and any(q in s for s in quotes)


def _match_one(rx, names, s, view, leaves, quotes, when_rx):
    m = rx.fullmatch(s)
    if m is None:
        return False
    return all(_slot_ok(nm, m.group("%s%d" % (nm, i)), view, leaves, quotes, when_rx) for i, nm in enumerate(names))


def rebuild_words(view, vocab):
    """-> (code | None, {"what": leaf path, "harm": leaf path, "risk": level}). code: None, "WORDING_NOT_DERIVED"."""
    leaves = vocab_leaves(vocab)
    scr = vocab.get("screen") if isinstance(vocab.get("screen"), dict) else {}
    when_rx = [_rx(scr[k]) for k in ("when_min", "when_h", "when_earlier") if isinstance(scr.get(k), str)]
    quotes = _quotes(view)
    quotes_d = quotes + _quotes(view, ("details",))     # second try: a fact the witness states only under Details (a sandbox host)
    got = {}
    tpls = [(s, p) for s, p in leaves.items() if _PH.sub("", s).strip()]      # a bare placeholder is not a sentence
    for f in ("what", "harm"):
        if f not in view:
            continue
        s = view[f]
        if not isinstance(s, str):
            return "WORDING_NOT_DERIVED", {f: None}
        hit = None
        for qs in (quotes, quotes_d):
            for tpl, path in tpls:
                rx, names = _rx(tpl)
                if _match_one(rx, names, s, view, leaves, qs, when_rx):
                    hit = path
                    break
            if hit is not None:
                if qs is quotes_d:
                    got.setdefault("from_details", []).append(f)
                break
        if hit is None:
            return "WORDING_NOT_DERIVED", dict(got, **{f: None})
        got[f] = hit
    if "risk" in view:
        rl = vocab.get("risk_label")
        if not (isinstance(view["risk"], str) and isinstance(rl, dict) and view["risk"] in rl):
            return "WORDING_NOT_DERIVED", dict(got, risk=None)
        got["risk"] = view["risk"]
    return None, got


# ------------------------------------------------------------------ the pack
def load_vocabs(root):
    """vocab/<digest>.json whose bytes hash to the name -> {digest: document}."""
    out = {}
    d = os.path.join(root, "vocab")
    if not os.path.isdir(d):
        return out
    for f in sorted(os.listdir(d)):
        if not f.endswith(".json"):
            continue
        b = open(os.path.join(d, f), "rb").read()
        if hashlib.sha256(b).hexdigest() == f[:-5]:
            try:
                doc = json.loads(b.decode("utf-8"))
            except ValueError:
                continue
            if isinstance(doc, dict):
                out[f[:-5]] = doc
    return out


def vocab_by_mandate(root, entries, cbor_loads):
    """-> {mandate id: vocab digest | None}: the vocabulary the signed tool map document of each mandate pins."""
    out = {}
    for e in entries:
        b = e.get("body") if isinstance(e.get("body"), dict) else {}
        m = b.get("mandate") if e.get("type") == "MANDATE" else None
        if not isinstance(m, dict):
            continue
        th = m.get("toolmap_sha256")
        vd = None
        if isinstance(th, (bytes, bytearray)):
            p = os.path.join(root, "toolmaps", th.hex() + ".cbor")
            try:
                raw = open(p, "rb").read()
                if hashlib.sha256(raw).digest() == bytes(th):
                    d = cbor_loads(raw)
                    vd = d.get("vocab") if isinstance(d, dict) and isinstance(d.get("vocab"), str) else None
            except Exception:  # noqa: BLE001 -- an unreadable or broken document pins nothing
                vd = None
        out[m.get("id")] = vd
    return out


def screen_checks(root, entries, views, cbor_loads, require=False, cap=50):
    """-> (lines, invalid code | None, warnings). Call after mandate_check.view_checks answered no invalid code (every view object
    present hashes to the signed presentation hash)."""
    receipts = {}
    for e in entries:
        if e.get("type") == "RECEIPT" and isinstance(e.get("body"), dict):
            receipts[str(e["body"].get("id"))] = e["body"]
    vm = vocab_by_mandate(root, entries, cbor_loads)
    vocabs = load_vocabs(root)
    lines, warns = [], []
    n_words = n_omit = 0
    for key in sorted(views):
        view = views[key]
        if not isinstance(view, dict):
            continue
        rid = key[len("release-"):] if key.startswith("release-") else key
        if key.startswith("allowance-"):         # a project permission signs the view of the approval page that offered it
            rid = str(view.get("rid"))
        label = ("release %s" % rid) if key.startswith("release-") else ("allowance %s" % key[len("allowance-"):] if key.startswith("allowance-") else "approval %s" % rid)
        # P2
        oc, items = check_omitted(view)
        if oc == "OMITTED_MISMATCH":
            want = omitted_expected(view)
            lines.append("%s: OMITTED_MISMATCH (the signed list of what the first screen does not show is not the rule %s: signed %s, rule %s)"
                         % (label, OMIT_RULE, _fmt(items), _fmt(want)))
            return lines, "OMITTED_MISMATCH", warns
        if oc == "OMITTED_UNDECLARED":
            warns.append("OMITTED_UNDECLARED")
        else:
            n_omit += 1
        # P1
        rc = receipts.get(rid)
        wl = ""
        if "what" in view and rc is not None:
            dg = vm.get(rc.get("mandate"))
            voc = vocabs.get(dg) if dg else None
            if dg and voc is None:
                if require:
                    lines.append("%s: WORDING_UNVERIFIABLE (the mandate pins vocabulary %s, the pack does not carry it)" % (label, dg[:16]))
                    return lines, "WORDING_UNVERIFIABLE", warns
                warns.append("WORDING_UNVERIFIABLE")
                wl = "words not rebuilt (vocabulary %s missing)" % dg[:16]
            elif voc is None or voc.get("v") not in VOCAB_REBUILT:
                warns.append("WORDING_LEGACY")
                wl = "words not rebuilt (%s)" % ("no vocabulary pinned" if voc is None else "vocabulary %s, before %s" % (voc.get("v"), VOCAB_FIRST))
            else:
                if not _action_same(view, rc.get("action")):
                    lines.append("%s: WORDING_NOT_DERIVED (the shown action's recipient / class is not the signed receipt's)" % label)
                    return lines, "WORDING_NOT_DERIVED", warns
                code, got = rebuild_words(view, voc)
                if code:
                    bad = [k for k, v in got.items() if v is None]
                    lines.append("%s: WORDING_NOT_DERIVED (%s %r is not a sentence of the pinned vocabulary %s with the call's own targets)"
                                 % (label, bad[0] if bad else "?", view.get(bad[0]) if bad else None, dg[:16]))
                    return lines, "WORDING_NOT_DERIVED", warns
                n_words += 1
                wl = "words rebuilt from vocabulary %s (what: %s, harm: %s, risk: %s)%s" % (
                    dg[:16], got.get("what"), got.get("harm"), got.get("risk"),
                    "; the target of %s is quoted from the witness's Details, not from the call" % "/".join(got["from_details"]) if got.get("from_details") else "")
        if len(lines) < cap and (wl or items is not None):
            parts = [wl] if wl else []
            if items is not None:
                parts.append("APPROVED_PARTIAL_VIEW, the first screen did not show whole: %s" % _fmt(items) if items else "the first screen showed everything")
            else:
                parts.append("warning OMITTED_UNDECLARED (an older page: what it did not show is not signed)")
            lines.append("screen %s: %s" % (label, "; ".join(parts)))
    if views:
        lines.append("screens: %d first screen(s) rebuilt from the pinned vocabulary, %d with words not rebuildable (older vocabulary or "
                     "none); %d signed list(s) of what was not shown, %d without one (older page)"
                     % (n_words, warns.count("WORDING_LEGACY") + warns.count("WORDING_UNVERIFIABLE"), n_omit, warns.count("OMITTED_UNDECLARED")))
    return lines, None, warns


def _action_same(view, receipt_action):
    act_v = view.get("action")
    if isinstance(act_v, dict) and isinstance(receipt_action, dict):
        return all(act_v.get(f) == receipt_action.get(f) for f in ("recipient", "class") if f in receipt_action)
    return True


def verdict(view, vocab_bytes, pinned, receipt_action=None):
    """One case of screen-vectors-0277.json (steps 7-8 of the profile) -> "VALID[ qualifier...]" or "INVALID <code>"."""
    if hashlib.sha256(vocab_bytes).hexdigest() != pinned:
        return "INVALID VOCAB_MISMATCH"
    voc = json.loads(vocab_bytes.decode("utf-8"))
    oc, items = check_omitted(view)
    if oc == "OMITTED_MISMATCH":
        return "INVALID OMITTED_MISMATCH"
    q = []
    if isinstance(voc, dict) and voc.get("v") in VOCAB_REBUILT:
        if "what" in view:
            if not _action_same(view, receipt_action):
                return "INVALID WORDING_NOT_DERIVED"
            code, _ = rebuild_words(view, voc)
            if code:
                return "INVALID " + code
    else:
        q.append("WORDING_LEGACY")
    if oc == "OMITTED_UNDECLARED":
        q.append("OMITTED_UNDECLARED")
    elif items:
        q.append("APPROVED_PARTIAL_VIEW")
    return " ".join(["VALID"] + q)


def run_vectors(path):
    """-> (n, failures [(id, got, expect)])."""
    d = json.load(open(path, encoding="utf-8"))
    bad = []
    for c in d["cases"]:
        vb = d["vocabularies"][c["vocab"]].encode("utf-8")
        got = verdict(c["view"], vb, c["pinned"], c.get("receipt_action"))
        if got != c["expect"]:
            bad.append((c["id"], got, c["expect"]))
    return len(d["cases"]), bad


def _fmt(items):
    if not items:
        return "[]"
    return ", ".join("%s:%s" % (i.get("m"), i.get("how")) if isinstance(i, dict) else repr(i) for i in items)


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "--vectors":
        n, bad = run_vectors(sys.argv[2])
        for i, got, want in bad:
            print("%s: got %s, expected %s" % (i, got, want))
        print("screen vectors: %d/%d as expected" % (n - len(bad), n))
        sys.exit(1 if bad else 0)
    print("usage: screencheck.py --vectors screen-vectors-0277.json   (the pack check runs inside verify_pack.py)")
    sys.exit(2)
