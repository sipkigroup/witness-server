"""Advisor: a second opinion that can only HOLD (defer to a human), never allow and never deny.

advise(text, mode) -> sorted [(label, score)], score in (0, 1]. An empty list means "no opinion", not "clean".
scan() never calls this module; a caller that sees a non-empty list may only escalate the decision to a hold.

Modes:
  off       -> []
  heuristic -> marker words of addresses / personal data (EN/RU), numbers in words next to street/улица,
               base64 blocks >= 40 chars (encoded_blob); beyond the spec (marked in ZAMECHANIYA.md): digits spelled
               in words (spelled_digits), "name at host dot com" (spelled_email), and cheap de-obfuscations of known
               bypasses (spaced characters, rot13, base64 >= 16 chars) re-checked with L2 -> "decoded:<format>".
  ner       -> heuristic + named entities from spaCy (imported on demand; RuntimeError if not installed).
"""
import base64
import binascii
import codecs
import re

from . import rules_v1

MODES = ("off", "heuristic", "ner")

ADDRESS_WORDS = re.compile(
    r"(?i)\b(?:street|avenue|road|boulevard|apartment|apt|suite|zip ?code|postcode|postal code|lives? at|address"
    r"|улиц\w*|проспект\w*|переул\w*|квартир\w*|корпус|индекс|адрес\w*|проживает|живу на)\b")
PERSONAL_WORDS = re.compile(
    r"(?i)\b(?:passport|ssn|social security|date of birth|dob|driver'?s licen[cs]e|card number|cvv|iban|account number|"
    r"routing number|wallet|phone|паспорт\w*|снилс|инн|дата рождения|телефон\w*|номер карты|карт[аыу]|счёт|сч[её]т\w*|кошел[её]к\w*)\b")
NUMBER_WORDS = (r"(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|"
                r"seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|"
                r"один|одна|два|две|три|четыре|пять|шесть|семь|восемь|девять|десять|одиннадцать|двенадцать|"
                r"(?:три|четыр|пят|шест|сем|восем|девят)надцать|двадцать|тридцать|сорок|пятьдесят|шестьдесят|семьдесят|восемьдесят|девяносто|сто|"
                r"двести|триста|четыреста|пятьсот|тысяч\w*)")
NUMBER_WORD_RX = re.compile(r"(?i)\b" + NUMBER_WORDS + r"\b")
STREET_RX = re.compile(r"(?i)\b(?:street|avenue|road|lane|drive|boulevard|st|ave|rd|улиц\w*|проспект\w*|дом|д\.)")
B64_RX = re.compile(r"[A-Za-z0-9+/](?<![A-Za-z0-9+/][A-Za-z0-9+/])[A-Za-z0-9+/]{15,}={0,2}")   # >= 16 to decode, >= 40 to label
SPELLED_EMAIL_RX = re.compile(r"(?i)\b\w{1,30} (?:dot \w{1,30} )?(?:at|собака) \w{1,30} (?:dot|точка) \w{2,10}\b")
ROT13_FORMATS = {"iban", "crypto_address", "postal_address"}      # rot13 keeps e-mail/phone shapes, L2 already sees them
SPACED_RX = re.compile(r"\S(?<!\S\S)(?: \S){7,}(?!\S)")
DIGIT_WORDS = ("zero one two three four five six seven eight nine".split(),
               "ноль один два три четыре пять шесть семь восемь девять".split())
DIGIT_WORD_RX = re.compile(r"(?i)\b(?:" + "|".join(DIGIT_WORDS[0] + DIGIT_WORDS[1]) + r")(?:[ ,-]{1,3}(?:"
                           + "|".join(DIGIT_WORDS[0] + DIGIT_WORDS[1]) + r")){6,}\b")


def _l2(text):
    return {fmt for _, _, fmt in rules_v1.find_all(text)}


def _heuristic(text):
    out = {}
    n_addr = len(ADDRESS_WORDS.findall(text))
    if n_addr:
        out["address_words"] = min(1.0, 0.3 + 0.2 * n_addr)
    n_pers = len(PERSONAL_WORDS.findall(text))
    if n_pers:
        out["personal_words"] = min(1.0, 0.3 + 0.2 * n_pers)
    # numbers in words within 60 chars before a street word: "one hundred twenty Main Street", "дом сорок два"
    for m in STREET_RX.finditer(text):
        win = text[max(0, m.start() - 60):m.end() + 40]
        if len(NUMBER_WORD_RX.findall(win)) >= 1:
            out["spelled_address"] = 0.7
            break
    if DIGIT_WORD_RX.search(text):
        out["spelled_digits"] = 0.6
    found = set()
    for m in B64_RX.finditer(text):
        blob = m.group(0)
        if not (any(c.isupper() for c in blob) and any(c.islower() for c in blob)):
            continue                                   # hex hashes and long words are not base64 blocks
        if len(blob.rstrip("=")) >= 40:
            out["encoded_blob"] = 0.5
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        found |= _l2(dec)
    for m in SPACED_RX.finditer(text):
        found |= _l2(m.group(0).replace(" ", ""))
    found |= (_l2(codecs.encode(text, "rot13")) - _l2(text)) & ROT13_FORMATS
    if SPELLED_EMAIL_RX.search(text):
        out["spelled_email"] = 0.6
    for fmt in found:
        out["decoded:" + fmt] = 0.9
    return out


def _ner(text):
    try:
        import spacy                                   # optional dependency, imported on demand
    except ImportError as e:
        raise RuntimeError("advisor mode 'ner' needs spaCy and a model (en_core_web_sm / ru_core_news_sm)") from e
    lang = "ru" if re.search(r"[А-Яа-яЁё]", text) else "en"
    name = "ru_core_news_sm" if lang == "ru" else "en_core_web_sm"
    try:
        nlp = spacy.load(name)
    except OSError as e:
        raise RuntimeError("spaCy model %s is not installed" % name) from e
    out = {}
    for ent in nlp(text).ents:
        if ent.label_ in ("PERSON", "PER"):
            out["ner:person"] = 0.5
        elif ent.label_ in ("GPE", "LOC", "FAC"):
            out["ner:location"] = 0.5
    return out


SCAN_HEAD = 16 * 1024          # R3-08: the agent chooses the text length, so the work is bounded: head + tail only, the middle is not read
SCAN_TAIL = 16 * 1024


def advise(text, mode):
    if mode not in MODES:
        raise ValueError("mode must be one of %s" % (MODES,))
    if mode == "off":
        return []
    over = len(text) > SCAN_HEAD + SCAN_TAIL
    if over:
        text = text[:SCAN_HEAD] + "\n" + text[-SCAN_TAIL:]
    out = _heuristic(text)
    if over:
        out["oversize_text"] = 0.5                     # a part of the text was not read: the caller holds (a human looks)
    if mode == "ner":
        out.update(_ner(text))
    return sorted((k, round(v, 2)) for k, v in out.items())
