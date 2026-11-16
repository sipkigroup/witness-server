#!/usr/bin/env python3
"""r0312: offline check that the public constitution page is a published, pinned version - not a silent edit.

The page web/constitution.html promises "Any weakening comes only as a new version, announced in advance, never retroactively". This
makes the promise checkable by anyone, without us:

  - web/constitution/versions.json: [{"version", "date", "sha256", "path"}], oldest first; `path` (inside web/) is the immutable copy
    of that version, served at /constitution/v<N>.
  - the hash of a page = SHA-256 of its bytes after ONE normalization: the build tag the server adds to its css/js addresses when it
    serves a page (app/webbuild.py: `href="/css/app.css?v=<16 hex>"`) is removed, and CRLF becomes LF. Nothing else: a changed space
    is a changed page.
  - the witness puts every version into its signed public log (app/tlog.py record_constitution: leaf = tlogcheck.constitution_leaf,
    "deus-witness/constitution/v1\\n<version>\\n<sha256 hex>\\n"), once. A leaf is proven to be under a signed checkpoint with
    `tlogcheck.py inclusion` (GET /tlog/leaf?batch=constitution:<N>, /tlog/proof/inclusion).

check_constitution(page, versions[, journal]) -> (ok, reason). INVALID when: the page hash is not the latest version's hash; the
"Version N (date)" line of the page names another version; versions.json is malformed (numbers not 1, 2, 3..., dates going back, a
hash used twice); a copy file does not match its hash; and, with a journal (an iterable of log leaf bytes): a version is missing from
the log, is there twice, or the log holds another hash for it (a version rewritten after it was published).

r0318: the rule of change is checked, not only promised. From version RULE_FROM (3) an entry also carries
  "laws":     {law id: [the checks named next to it]}, in page order; the page carries the same ids (data-law="<id>" on the element of
              each law, i.e. every <li>/<p> that names a <code class="check">) and the same checks;
  "weakens":  true / false;  "effective": the date it takes effect;
  "corrects": [{"law", "reason", "evidence"}]: a law whose TEXT changed because the previous text said more than the code did;
and the page carries one marker <... data-weakens="..." data-effective="..." data-corrects="<ids>"> equal to them (so the marking is
under the page hash, hence under the signed log, not only in versions.json). Between version N-1 and N (N >= RULE_FROM):
  - a law id, or a check of a law, that disappears is a weakening: INVALID unless weakens=true and effective >= date + 14 days;
  - weakens=false needs effective == date (nothing waits);
  - (with the copies, web_dir) a law whose text changed: INVALID unless weakens=true or the law is in "corrects";
  - a correction keeps the law id and every check of it (else it is a weakening, above), and its "evidence" must be one of the law's
    checks in the new version: the test that shows the code already did what the corrected text says. Whether that test predates the
    previous version is not checkable offline here; the repository history is (tests/test_1511_r0318_constitution_rule.py does it
    with git for version 3).
An entry of an older version may carry "laws" (version 2 does: its page has no data-law, so ids are matched to its laws in page order).

CLI:  constitution_check.py <page.html> <versions.json> [<leaf.json> ...]     (leaf.json = the answer of GET /tlog/leaf)
      exit 0 VALID, 2 INVALID.
"""
import datetime
import hashlib
import html as _html
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tlogcheck as TC  # noqa: E402

_BUILD_TAG = re.compile(rb'\?v=[0-9a-f]{16}(?=")')
_VERSION_LINE = re.compile(r"Version (\d+) \((\d{4}-\d{2}-\d{2})\)")
RULE_FROM = 3                       # r0318: the first version checked by the rule of change
NOTICE_DAYS = 14                    # a weakening takes effect at least this many days after its version is published
_BASE = {"version", "date", "sha256", "path"}
_RULE = {"laws", "weakens", "effective", "corrects"}
_LAW_EL = re.compile(r"<(li|p)\b([^>]*)>(.*?)</\1>", re.S)
_CHECK = re.compile(r'<code class="check">([^<]+)</code>')
_MARK = re.compile(r"<[a-z]+\b[^>]*\bdata-weakens=\"(true|false)\"[^>]*>")


def normalize(page: bytes) -> bytes:
    return _BUILD_TAG.sub(b"", bytes(page).replace(b"\r\n", b"\n"))


def page_hash(page: bytes) -> str:
    return hashlib.sha256(normalize(page)).hexdigest()


def _versions(v):
    if isinstance(v, (bytes, str)):
        v = json.loads(v)
    if not isinstance(v, list) or not v:
        raise ValueError("versions.json must be a non-empty list")
    seen = set()
    for i, e in enumerate(v):
        if not isinstance(e, dict) or not _BASE <= set(e) or not set(e) <= _BASE | _RULE:
            raise ValueError("entry %d: need version, date, sha256, path (and, from version %d, laws, weakens, effective, corrects)" % (i, RULE_FROM))
        if e.get("version", 0) >= RULE_FROM and set(e) != _BASE | _RULE:
            raise ValueError("entry %d: version %d needs laws, weakens, effective, corrects" % (i, e["version"]))
        if "laws" in e:
            _check_laws(e["laws"], i)
        if e["version"] != i + 1:
            raise ValueError("entry %d: version must be %d (numbers go 1, 2, 3 ... with no gap)" % (i, i + 1))
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(e["date"])) or (i and e["date"] < v[i - 1]["date"]):
            raise ValueError("entry %d: bad date or a date before the previous version" % i)
        TC.constitution_leaf(e["version"], e["sha256"])          # 64 lower-case hex
        if e["sha256"] in seen:
            raise ValueError("entry %d: the same text as an earlier version" % i)
        seen.add(e["sha256"])
        if e["version"] >= RULE_FROM:
            if "laws" not in v[i - 1]:
                raise ValueError("entry %d: the previous version has no list of laws to compare with" % i)
            if not isinstance(e["weakens"], bool) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(e["effective"])):
                raise ValueError("entry %d: weakens must be true/false and effective a date" % i)
            datetime.date.fromisoformat(e["date"]), datetime.date.fromisoformat(e["effective"])     # a real day, else ValueError
            c = e["corrects"]
            if not isinstance(c, list) or not all(isinstance(x, dict) and set(x) == {"law", "reason", "evidence"} and
                                                  all(isinstance(x[k], str) and x[k].strip() for k in x) for x in c):
                raise ValueError("entry %d: corrects must be a list of {law, reason, evidence}" % i)
    return v


def _check_laws(laws, i):
    if not isinstance(laws, dict) or not laws or not all(
            re.fullmatch(r"[a-z0-9][a-z0-9-]*", str(k)) and isinstance(c, list) and c and all(isinstance(x, str) for x in c)
            for k, c in laws.items()):
        raise ValueError("entry %d: laws must be {id: [checks]}, every law with a check" % i)


def law_elements(page: bytes):
    """-> [(law id or None, [checks], text)] in page order: every <li>/<p> that names a check; text = without the Check line, tags and
    entities, whitespace collapsed."""
    out = []
    for m in _LAW_EL.finditer(normalize(page).decode("utf-8", "replace")):
        body = m.group(3)
        if 'class="check"' not in body:
            continue
        lid = re.search(r'\bdata-law="([^"]*)"', m.group(2))
        text = re.sub(r'<span class="hint">\s*Check:.*?</span>', " ", body, flags=re.S)
        text = " ".join(_html.unescape(re.sub(r"<[^>]+>", " ", text)).split())
        out.append((lid.group(1) if lid else None, _CHECK.findall(body), text))
    return out


def _page_laws(page: bytes, entry):
    """-> ({id: checks}, {id: text}) of a page, ids from data-law, or (an unmarked page) from the entry's laws in page order."""
    els = law_elements(page)
    ids = [x[0] for x in els]
    if all(x is None for x in ids) and entry.get("version", 0) < RULE_FROM:
        ids = list(entry["laws"])
        if len(ids) != len(els):
            raise ValueError("version %d: %d laws on the page, %d in versions.json" % (entry["version"], len(els), len(ids)))
    if None in ids or len(set(ids)) != len(ids):
        raise ValueError("version %d: a law without a data-law id, or an id twice" % entry["version"])
    return {k: x[1] for k, x in zip(ids, els)}, {k: x[2] for k, x in zip(ids, els)}


def _page_mark(page: bytes):
    tags = [m.group(0) for m in _MARK.finditer(normalize(page).decode("utf-8", "replace"))]
    if len(tags) != 1:
        return None                                               # none, or two markers: not one answer
    t = tags[0]
    eff = re.search(r'\bdata-effective="([^"]*)"', t)
    cor = re.search(r'\bdata-corrects="([^"]*)"', t)
    return 'data-weakens="true"' in t, eff.group(1) if eff else None, sorted((cor.group(1) if cor else "").split())


def _same_as_page(page: bytes, e):
    """None when the page names exactly the laws, checks and change marker of its entry, else why not."""
    try:
        laws, _ = _page_laws(page, e)
    except ValueError as x:
        return str(x)
    if laws != e["laws"]:
        diff = sorted(set(laws) ^ set(e["laws"])) or sorted(k for k in laws if laws[k] != e["laws"][k])
        return "version %d: the page and versions.json name other laws or checks (%s)" % (e["version"], ", ".join(diff))
    if e["version"] >= RULE_FROM and _page_mark(page) != (e["weakens"], e["effective"], sorted({c["law"] for c in e["corrects"]})):
        return "version %d: the page's change marker (data-weakens / data-effective / data-corrects) is not the one in versions.json" % e["version"]
    return None


def _days(a, b):
    return (datetime.date.fromisoformat(b) - datetime.date.fromisoformat(a)).days


def check_rule(prev, cur, prev_texts=None, cur_texts=None):
    """r0318: the rule of change between two adjacent entries -> None or why INVALID."""
    n = cur["version"]
    gone = ["law %s" % k for k in prev["laws"] if k not in cur["laws"]]
    gone += ["the check %s of law %s" % (c, k) for k in prev["laws"] if k in cur["laws"] for c in prev["laws"][k] if c not in cur["laws"][k]]
    if cur["weakens"]:
        if _days(cur["date"], cur["effective"]) < NOTICE_DAYS:
            return "version %d weakens, but takes effect %s, less than %d days after it is published (%s)" % (
                n, cur["effective"], NOTICE_DAYS, cur["date"])
    else:
        if gone:
            return "version %d removes %s without being marked as a weakening (weakens=true, effective >= date + %d days)" % (
                n, gone[0], NOTICE_DAYS)
        if cur["effective"] != cur["date"]:
            return "version %d weakens nothing, so it takes effect on its date %s, not %s" % (n, cur["date"], cur["effective"])
    corrected = set()
    for c in cur["corrects"]:
        k = c["law"]
        if k not in prev["laws"] or k not in cur["laws"]:
            return "version %d corrects law %s, which is not in both versions (a correction keeps the law)" % (n, k)
        if c["evidence"] not in cur["laws"][k]:
            return "version %d corrects law %s, but its evidence %s is not one of the law's checks" % (n, k, c["evidence"])
        if k in corrected:
            return "version %d corrects law %s twice" % (n, k)
        corrected.add(k)
    if prev_texts is not None and cur_texts is not None:
        for k in cur["laws"]:
            if k in prev_texts and prev_texts[k] != cur_texts.get(k):
                if k not in corrected and not cur["weakens"]:
                    return "version %d changes the text of law %s without marking it (corrects, or weakens=true)" % (n, k)
            elif k in corrected and k in prev_texts:
                return "version %d lists law %s as corrected, but its text did not change" % (n, k)
    return None


def check_constitution(page: bytes, versions, journal=None, web_dir=None):
    """-> (True, "VALID: ...") or (False, "INVALID: <reason>"). `web_dir`: also check every copy file named in versions.json."""
    try:
        vs = _versions(versions)
    except (ValueError, TypeError, KeyError, AttributeError) as e:
        return False, "INVALID: versions.json: %s" % e
    last = vs[-1]
    h = page_hash(page)
    if h != last["sha256"]:
        old = [e["version"] for e in vs if e["sha256"] == h]
        if old:
            return False, "INVALID: the page is version %d, not the latest version %d" % (old[0], last["version"])
        return False, "INVALID: the page (sha256 %s) is no published version; the latest, %d, is %s" % (h, last["version"], last["sha256"])
    m = _VERSION_LINE.search(re.sub(r"<[^>]+>", " ", normalize(page).decode("utf-8", "replace")))
    if not m or (int(m.group(1)), m.group(2)) != (last["version"], last["date"]):
        return False, "INVALID: the page's Version line does not say version %d (%s)" % (last["version"], last["date"])
    if "laws" in last:
        why = _same_as_page(page, last)
        if why:
            return False, "INVALID: " + why
    for i in range(1, len(vs)):
        if vs[i]["version"] >= RULE_FROM:
            why = check_rule(vs[i - 1], vs[i])
            if why:
                return False, "INVALID: " + why
    if web_dir is not None:
        texts = {}
        for e in vs:
            p = os.path.realpath(os.path.join(web_dir, e["path"]))
            if not p.startswith(os.path.realpath(web_dir) + os.sep) or not os.path.isfile(p):
                return False, "INVALID: the copy of version %d (%s) is missing" % (e["version"], e["path"])
            with open(p, "rb") as f:
                body = f.read()
            if page_hash(body) != e["sha256"]:
                return False, "INVALID: the copy of version %d (%s) was changed after it was published" % (e["version"], e["path"])
            if "laws" in e:
                why = _same_as_page(body, e)
                if why:
                    return False, "INVALID: " + why
                texts[e["version"]] = _page_laws(body, e)[1]
        for i in range(1, len(vs)):
            if vs[i]["version"] >= RULE_FROM:
                why = check_rule(vs[i - 1], vs[i], texts[vs[i - 1]["version"]], texts[vs[i]["version"]])
                if why:
                    return False, "INVALID: " + why
    if journal is not None:
        logged = {}
        for leaf in journal:
            try:
                n, lh = TC.parse_constitution_leaf(leaf)
            except ValueError:
                continue                                          # a batch leaf: not about the constitution
            logged.setdefault(n, []).append(lh)
        for e in vs:
            got = logged.get(e["version"], [])
            if not got:
                return False, "INVALID: version %d is not in the signed log" % e["version"]
            if len(got) > 1:
                return False, "INVALID: version %d is in the signed log %d times" % (e["version"], len(got))
            if got[0] != e["sha256"]:
                return False, "INVALID: the signed log holds another text for version %d (%s): it was rewritten" % (e["version"], got[0])
    return True, "VALID: version %d (%s), sha256 %s%s" % (last["version"], last["date"], h, ", in the signed log" if journal is not None else "")


def _cli(a):
    if len(a) < 2:
        print(__doc__)
        return 64
    try:
        with open(a[0], "rb") as f:
            page = f.read()
        with open(a[1], "rb") as f:
            versions = f.read()
        journal = None
        if len(a) > 2:
            journal = []
            for p in a[2:]:
                with open(p, "rb") as f:
                    journal.append(TC.b64d(json.loads(f.read())["leaf_b64"]))
    except (OSError, ValueError, KeyError) as e:
        print("INVALID: %s" % e)
        return 2
    ok, why = check_constitution(page, versions, journal)
    print(why)
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
