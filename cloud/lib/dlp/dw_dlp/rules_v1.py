"""dw-dlp-1 rules. ruleset_id() hashes THIS file: any edit here is a new ruleset.

L1 = shapes of secrets (from dogfood/ten.py SECRET_RE; cloud/server/app/toolmap.py carries the first four).
L2 = formats with validators (checksums where the format has one). A regex only proposes a candidate;
the tag exists only if the validator accepts it.

Regex discipline: linear only. No quantifier over a group that holds an unbounded quantifier; every
repeated group consumes a fixed or unambiguous unit; every candidate starts behind a lookbehind that
forbids starting inside a run of its own characters (so a 256 KB run of digits / '@' / letters costs
one attempt, not one per position).
"""
import bisect
import hashlib
import re

# ---------------------------------------------------------------- L1: secret shapes (names are the tags)
SECRET_RE = [
    ("telegram_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b")),
    ("api_key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|xox[abprs]-[A-Za-z0-9-]{10,})\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("secret_assign", re.compile(r"(?i)\b(?:token|password|passwd|secret|api[_-]?key|пароль|токен)\b\s*[:=]\s*[^\s,;|]{8,}")),
    ("seed_phrase", re.compile(r"(?i)\b(?:seed phrase|мнемоник\w*|сид-фраз\w*)\s*[:=]")),
]

# Fast pure pre-checks: a pattern can only match if its gate passes (a gate is a necessary condition, never sufficient).
# ("cs", substrings) - on the text as is; ("ci", substrings) - on text.casefold() (a superset of re.I folding).
SECRET_GATES = {
    "telegram_token": ("cs", (":",)),
    "api_key": ("cs", ("sk-", "gh", "AKIA", "AIza", "xox")),
    "private_key": ("cs", ("-----BEGIN ",)),
    "bearer": ("cs", ("Bearer",)),
    "secret_assign": ("ci", ("token", "password", "passwd", "secret", "api", "пароль", "токен")),
    "seed_phrase": ("ci", ("seed phrase", "мнемоник", "сид-фраз")),
}


def secret_names(text):
    """-> set of L1 secret-shape names present in `text`."""
    folded = None
    out = set()
    for name, rx in SECRET_RE:
        kind, subs = SECRET_GATES[name]
        if kind == "ci":
            if folded is None:
                folded = text.casefold()
            hay = folded
        else:
            hay = text
        if any(x in hay for x in subs) and rx.search(text):
            out.add(name)
    return out


FORMATS = ("card_number", "iban", "ssn", "crypto_address", "phone", "email_address", "postal_address")

# a number must not continue: no word char after it, no "-5", ".5", ",5"
_END = r"(?![\w]|[.,-]\d)"


# ---------------------------------------------------------------- card_number: Luhn + IIN
CARD_RX = re.compile(
    r"\d(?<![\w.+-]\d)(?:\d{12,18}"
    r"|\d{3}([ -])\d{4}\1\d{4}\1\d{4}(\1\d{3})?"
    r"|\d{3}([ -])\d{6}\3\d{4,5})" + _END)

# (low, high, prefix length, allowed lengths)
_IIN = [
    (4, 4, 1, (13, 16, 19)),                    # Visa
    (51, 55, 2, (16,)), (2221, 2720, 4, (16,)),  # Mastercard
    (34, 34, 2, (15,)), (37, 37, 2, (15,)),      # Amex
    (6011, 6011, 4, (16, 17, 18, 19)), (644, 649, 3, (16, 17, 18, 19)), (65, 65, 2, (16, 17, 18, 19)),  # Discover
    (622126, 622925, 6, (16, 17, 18, 19)),
    (3528, 3589, 4, (16, 17, 18, 19)),           # JCB
    (300, 305, 3, (14, 15, 16, 17, 18, 19)), (36, 36, 2, (14, 15, 16, 17, 18, 19)),
    (38, 39, 2, (16, 17, 18, 19)),               # Diners
    (62, 62, 2, (16, 17, 18, 19)),               # UnionPay
    (2200, 2204, 4, (16, 17, 18, 19)),           # Mir
    (5018, 5018, 4, (13, 14, 15, 16, 17, 18, 19)), (5020, 5020, 4, (13, 14, 15, 16, 17, 18, 19)),
    (5038, 5038, 4, (13, 14, 15, 16, 17, 18, 19)), (5893, 5893, 4, (13, 14, 15, 16, 17, 18, 19)),
    (6304, 6304, 4, (13, 14, 15, 16, 17, 18, 19)), (6759, 6759, 4, (13, 14, 15, 16, 17, 18, 19)),
    (6761, 6763, 4, (13, 14, 15, 16, 17, 18, 19)),  # Maestro
]


_LUHN2 = (0, 2, 4, 6, 8, 1, 3, 5, 7, 9)


def luhn_ok(digits):
    r = digits[::-1]
    return (sum(map(int, r[0::2])) + sum(_LUHN2[int(c)] for c in r[1::2])) % 10 == 0


def iin_ok(digits):
    n = len(digits)
    for lo, hi, plen, lens in _IIN:
        if n in lens and lo <= int(digits[:plen]) <= hi:
            return True
    return False


def card_digits_ok(digits):
    return 13 <= len(digits) <= 19 and iin_ok(digits) and luhn_ok(digits)


def _find_cards(text):
    for m in CARD_RX.finditer(text):
        s = m.group(0)
        d = s.replace(" ", "").replace("-", "")
        if card_digits_ok(d):
            yield m.start(), m.end()
        elif m.group(2):            # 4-4-4-4 followed by 3 more digits (e.g. a CVV): try the 16 alone
            end = m.start(2)
            if card_digits_ok(text[m.start():end].replace(" ", "").replace("-", "")):
                yield m.start(), end


# ---------------------------------------------------------------- iban: ISO 13616 length table + mod 97
IBAN_LEN = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 27,
    "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28,
    "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23,
    "GL": 18, "GR": 27, "GT": 28, "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
    "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21,
    "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27, "MT": 31, "MU": 30, "NI": 28,
    "NL": 18, "NO": 15, "OM": 23, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
    "RU": 33, "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25,
    "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}
IBAN_RX = re.compile(r"([A-Z](?<![A-Za-z0-9][A-Z])[A-Z])(\d{2})((?: ?[A-Z0-9]){10,30})")


def iban_mod97_ok(compact):
    r = compact[4:] + compact[:4]
    n = 0
    for ch in r:
        v = ord(ch) - 48 if ch <= "9" else ord(ch) - 55
        n = (n * (100 if v > 9 else 10) + v) % 97
    return n == 1


def _find_ibans(text):
    pos = 0
    while True:
        m = IBAN_RX.search(text, pos)
        if not m:
            return
        L = IBAN_LEN.get(m.group(1))
        pos = m.end()
        if L is None:
            continue
        need, i, start = L - 4, m.start(3), m.start(3)
        end = start
        while need and i < m.end(3):
            if text[i] != " ":
                need -= 1
                end = i + 1
            i += 1
        if need or (end < len(text) and text[end].isalnum()):
            continue
        compact = (text[m.start():end]).replace(" ", "")
        if iban_mod97_ok(compact):
            yield m.start(), end
            pos = end


# ---------------------------------------------------------------- ssn (US)
SSN_RX = re.compile(r"(\d(?<![\w-]\d)\d{2})([- ])(\d{2})\2(\d{4})" + _END)


def ssn_ok(area, group, serial):
    return area != "000" and area != "666" and area[0] != "9" and group != "00" and serial != "0000"


def _find_ssn(text):
    for m in SSN_RX.finditer(text):
        if ssn_ok(m.group(1), m.group(3), m.group(4)):
            yield m.start(), m.end()


# ---------------------------------------------------------------- crypto_address: base58check, bech32/bech32m, ETH
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58I = {c: i for i, c in enumerate(B58)}
BTC58_RX = re.compile(r"[13](?<![A-Za-z0-9][13])[1-9A-HJ-NP-Za-km-z]{25,34}(?![A-Za-z0-9])")
BECH_RX = (re.compile(r"bc1(?<![A-Za-z0-9]bc1)[02-9ac-hj-np-z]{11,71}(?![A-Za-z0-9])"),
           re.compile(r"BC1(?<![A-Za-z0-9]BC1)[02-9AC-HJ-NP-Z]{11,71}(?![A-Za-z0-9])"))
ETH_RX = re.compile(r"0x(?<![A-Za-z0-9]0x)[0-9a-fA-F]{40}(?![A-Za-z0-9])")
BECH_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST, BECH32M_CONST = 1, 0x2BC830A3


def b58check_ok(s):
    n = 0
    for c in s:
        n = n * 58 + _B58I[c]
    lead = len(s) - len(s.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    raw = b"\x00" * lead + body
    if len(raw) != 25 or raw[0] not in (0x00, 0x05):
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def _bech_polymod(values):
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def _convertbits(data, frm, to):
    acc = bits = 0
    out = []
    maxv = (1 << to) - 1
    for v in data:
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if bits >= frm or ((acc << (to - bits)) & maxv):
        return None
    return out


def bech32_ok(s):
    s = s.lower()
    hrp, data = s[:2], [BECH_CHARSET.index(c) for c in s[3:]]
    if len(s) > 90 or len(data) < 7:
        return False
    const = _bech_polymod([ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data)
    ver = data[0]
    if ver > 16 or const != (BECH32_CONST if ver == 0 else BECH32M_CONST):
        return False
    prog = _convertbits(data[1:-6], 5, 8)
    if prog is None or not 2 <= len(prog) <= 40:
        return False
    return ver != 0 or len(prog) in (20, 32)


def _find_crypto(text):
    for m in BTC58_RX.finditer(text):
        if b58check_ok(m.group(0)):
            yield m.start(), m.end()
    for rx in BECH_RX:
        for m in rx.finditer(text):
            if bech32_ok(m.group(0)):
                yield m.start(), m.end()
    for m in ETH_RX.finditer(text):
        yield m.start(), m.end()


# ---------------------------------------------------------------- phone
PHONE_PLUS_RX = re.compile(r"\+(?<![\w+]\+)\d[\d ()-]{6,22}\d(?!\w|[.,-]\d)")
PHONE_RU_RX = re.compile(r"8(?<![\w+-]8)[ -]?(?:\([3-9]\d{2}\)|[3-9]\d{2})[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}" + _END)
PHONE_US_RX = (re.compile(r"\((?<![\w+(-]\()\d{3}\) ?\d{3}-\d{4}" + _END),
               re.compile(r"\d(?<![\w+(-]\d)\d{2}-\d{3}-\d{4}" + _END))
_DATE_DIGITS_RX = re.compile(r"(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])|(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])(?:19|20)\d{2}")


def _plus_shape_ok(s):
    """'+', digits, single separators ' ' / '-', at most one '(digits)' group: '+7 (912) 345-67-89'."""
    if s.count("(") > 1 or s.count("(") != s.count(")"):
        return False
    if "(" in s:
        a, b = s.index("("), s.index(")")
        if b < a or not s[a + 1:b].isdigit() or b - a > 6:
            return False
    prev = "+"
    for c in s[1:]:
        if c in " -" and prev in " -(":
            return False
        prev = c
    return True


def _phone_digits_ok(s, plus):
    d = "".join(c for c in s if c.isdigit())
    if plus:
        if not 8 <= len(d) <= 15 or not _plus_shape_ok(s):
            return False
    elif not 10 <= len(d) <= 15:
        return False
    if (not plus or s[1:].isdigit()) and _DATE_DIGITS_RX.match(d):
        return False                                   # "not a date": compact digits that begin with a calendar date
    # "not a card number": a card span is claimed first (FINDERS order) and the non-'+' forms have <= 12 digits;
    # a '+' number is a phone even when its digits happen to pass Luhn + IIN (no card is written with '+').
    return plus or not card_digits_ok(d)


def _find_phones(text):
    for m in PHONE_PLUS_RX.finditer(text):
        if _phone_digits_ok(m.group(0), True):
            yield m.start(), m.end()
    for rx in (PHONE_RU_RX,) + PHONE_US_RX:
        for m in rx.finditer(text):
            if _phone_digits_ok(m.group(0), False):
                yield m.start(), m.end()


# ---------------------------------------------------------------- email_address
EMAIL_RX = re.compile(
    r"[A-Za-z0-9](?<![A-Za-z0-9._%+-][A-Za-z0-9])[A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9][A-Za-z0-9-]{0,62}"
    r"(?:\.[A-Za-z0-9-]{1,63}){0,8}\.([A-Za-z]{2,24})(?![A-Za-z0-9-]|\.[A-Za-z0-9])")
_IMAGE_TLD = {"png", "jpg", "jpeg", "gif", "svg", "webp"}   # "icon@2x.png" is a file name, not an address


def _find_emails(text):
    if "@" not in text:
        return
    for m in EMAIL_RX.finditer(text):
        if m.group(1).lower() not in _IMAGE_TLD:
            yield m.start(), m.end()


# ---------------------------------------------------------------- postal_address
_US_TYPES = ("Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter|"
             "Parkway|Pkwy|Highway|Hwy|Circle|Cir|Square|Sq|Trail|Trl")
_US_WORD = r"(?:[A-Za-z][A-Za-z.'-]{0,29}|\d{1,3}(?:st|nd|rd|th))"
US_STREET_RX = re.compile(r"\d(?<![\w-]\d)\d{0,5}[A-Z]?(?: " + _US_WORD + r"){1,4} (?=[A-Z])(?:" + _US_TYPES + r")\b\.?")
US_ZIP_RX = re.compile(r"(?<![\d-])\d{5}(?:-\d{4})?(?![\d-])")
RU_STREET_RX = (
    re.compile(r"(?:у(?<![\w-]у)(?:л\.|лица)|п(?<![\w-]п)(?:р-т|роспект)) ?(?:[А-ЯЁа-яё0-9.-]{1,30}[ ,]{1,2}){1,4}(?:д\.|дом) ?\d{1,4}(?!\d)"),
    re.compile(r"[А-ЯЁ](?<![\w-][А-ЯЁ])[а-яё-]{1,30} (?:ул\.|улица|пр-т|проспект),? (?:д\.|дом) ?\d{1,4}(?!\d)"))
RU_INDEX_RX = re.compile(r"\d(?<![\d.,-]\d)\d{5},? (?:г\. ?)?[А-ЯЁ][а-яё]{2,30}(?:-[А-ЯЁа-яё][а-яё]{1,30})?")


_US_TYPE_WORDS = tuple(_US_TYPES.split("|"))
_CYR_UPPER_RX = re.compile(r"[А-ЯЁ]")


def _find_postal(text):
    if any(w in text for w in _US_TYPE_WORDS):
        for m in US_STREET_RX.finditer(text):
            z = US_ZIP_RX.search(text, m.end(), m.start() + 80)
            if z:
                yield m.start(), z.end()
    rxs = RU_STREET_RX if ("ул" in text or "пр" in text) else ()
    if _CYR_UPPER_RX.search(text):
        rxs += (RU_INDEX_RX,)
    for rx in rxs:
        for m in rx.finditer(text):
            yield m.start(), m.end()


# ---------------------------------------------------------------- order = priority: a span claimed earlier is not re-tagged
FINDERS = (
    ("card_number", _find_cards),
    ("iban", _find_ibans),
    ("ssn", _find_ssn),
    ("crypto_address", _find_crypto),
    ("phone", _find_phones),
    ("email_address", _find_emails),
    ("postal_address", _find_postal),
)


def _overlaps(merged, starts, s, e):
    i = bisect.bisect_left(starts, e) - 1          # last claimed interval that starts before e
    return i >= 0 and merged[i][1] > s


def find_all(text):
    """-> sorted list of (start, end, format). Pure function of `text`."""
    merged, starts, out = [], [], []
    for fmt, finder in FINDERS:
        new = [(s, e, fmt) for s, e in finder(text) if not _overlaps(merged, starts, s, e)]
        out.extend(new)
        spans = sorted(merged + [(s, e) for s, e, _ in new])
        merged = []
        for s, e in spans:
            if merged and s <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
            else:
                merged.append((s, e))
        starts = [s for s, _ in merged]
    out.sort()
    return out
