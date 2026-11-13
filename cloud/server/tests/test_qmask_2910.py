"""29.10 QMASK (cloud/OTCHET-QMASK-2910.md): ASSIGN_RE never masked a name in quotes, so `"password": "hunter2"` in the preview of a JSON,
dict or YAML file left the machine open. QUOTED_ASSIGN_RE is a SECOND pass (server toolmap + client hook/mask, one text): its value spans are
added to ASSIGN_RE's (a union on the same string), so it can only ADD masks. Checked here: the leaks, the union never masks less than
ASSIGN_RE alone on the redos corpus (+ quoted units), and the speed on the worst inputs (4 KB / 32 KB < 50 ms, in a child process)."""
import json
import random

import pytest

from app import toolmap
from tests import test_redos_2910 as R
from deus_witness.hook import mask as cmask

M = "[masked]"


def _both(s):
    return toolmap.mask_value(s, {}, 4096), cmask.mask_value(s, 4096)


def test_quoted_server_and_client_share_one_text():
    assert cmask.QUOTED_ASSIGN_RE.pattern == toolmap.QUOTED_ASSIGN_RE.pattern
    assert cmask.ASSIGN_RE.pattern == toolmap.ASSIGN_RE.pattern


LEAKS = [  # (text, secret values that must not survive)
    ('{"password": "hunter2", "user": "bob"}', ["hunter2"]),
    ("{'api_key': 'k-live-1', 'n': 1}", ["k-live-1"]),
    ('db:\n  password: "hunter two words"\n', ["hunter", "two words"]),
    ("password: 'a b c'", ["a b c", "b c"]),
    ('{"Authorization": "Bearer eyJabc.def"}', ["eyJabc.def"]),
    ('"Authorization": Bearer eyJabc.def', ["eyJabc.def"]),
    ('DB_PASSWORD="hunter 2"\nexport API_TOKEN="x y z"', ["2\"", "y z"]),
    ('{\n  "db": {\n    "db_password": "p@ss w0rd",\n    "nested": {"X-Api-Key": "k-123 456"}\n  },\n  "pin_token": 12345\n}',
     ["p@ss", "w0rd", "k-123", "456", "12345"]),
    ('{"token": "a\\"b c"}', ["b c"]),
    ("headers['X-Api-Key'] = 'abc def'", ["abc", "def"]),
    ('{"private-key": "zz top"}', ["zz top"]),
    ('"secret": "unterminated value', ["unterminated value"]),
    (json.dumps({"text": '{"password": "hun ter2", "client_secret": "s 1"}'}), ["hun ter2", "ter2", "s 1"]),
    (json.dumps({"text": 'x = {"token": "q\\"w e"}'}), ["w e"]),
]


@pytest.mark.parametrize("text,secrets", LEAKS)
def test_quoted_values_are_masked(text, secrets):
    for out in _both(text):
        for v in secrets:
            assert v not in out, (v, out)
        assert M in out


def test_mask_args_masks_a_file_text_preview():
    out = toolmap.mask_args({"content": '{"password": "hunter 2"}'}, {})
    assert "hunter" not in out, out


def test_harmless_keys_untouched_and_substring_rule_as_assign():
    for out in _both('{"name": "x", "user": "bob", "count": 3, "auth": {"type": "oauth"}}'):
        assert '"name": "x"' in out and '"user": "bob"' in out and '"count": 3' in out and '"type": "oauth"' in out
    # ASSIGN_RE masks by substring (passport_country=US is masked): the quoted pass follows the same rule, not a softer one
    assert M in toolmap.mask_value("passport_country=US", {}, 300)
    for out in _both('{"passport_country": "US"}'):
        assert out == '{"passport_country": [masked]}'


def test_already_masked_is_left_alone():
    for out in _both('{"token": "[masked]", "password": [masked]}'):
        assert out == '{"token": "[masked]", "password": [masked]}'


def _render(s, spans):
    out, i = [], 0
    for a, b in spans:
        out += [s[i:a], M]
        i = b
    return "".join(out + [s[i:]])


QUNITS = R.UNITS + ['\\"', '\\"password\\": \\"', "'pass': '", '"X-Api-Key": ', "api-key", '"', "\\\\", "]", ": ", '"auth": {', "12345", ","]


def _qcorpus():
    rnd = random.Random(29102)
    c = R._corpus()
    c += ["".join(rnd.choice(QUNITS) for _ in range(rnd.randint(1, 14))) for _ in range(30000)]
    return c


def _pieces(s, spans):
    out, i = [], 0
    for a, b in spans:
        out += [s[i:a], (a, b)]
        i = b
    return out + [s[i:]]


def _plain(out):
    """MTYPE 29.10 (OTCHET-MASKA-TIP-2910): every typed marker read as the plain [masked] (the spans are unchanged, only the text says more)."""
    import re
    return re.sub(toolmap.MASK_MARK, M, out)


def test_quoted_pass_never_masks_less_than_assign():
    softer, stricter, bad = 0, 0, []
    for s in _qcorpus():
        if toolmap._AUTHOR_WORD.search(s):          # 12.11: an AUTHOR name is no secret on the server (test_1211_r0263f_l3.py checks those)
            continue
        old_spans = [m.span(3) for m in toolmap.ASSIGN_RE.finditer(s)]
        old = set(i for a, b in old_spans for i in range(a, b))
        sp = toolmap.assign_spans(s)
        new = set(i for a, b in sp for i in range(a, b))
        if not old <= new:
            softer += 1
            bad.append(s)
        for f in (toolmap.mask_assign, cmask.mask_assign):     # MTYPE 29.10: a URL/command value gets a typed marker; read it as [masked]
            if f(s) != "".join(x if isinstance(x, str) else toolmap.mask_marker(s[x[0]:x[1]]) for x in _pieces(s, sp)):
                bad.append(s)
        if new == old and "[masked " not in s:      # MTYPE: a typed marker in the input stays as it is (already masked)
            assert _plain(toolmap.mask_assign(s)) == R._sub(toolmap.ASSIGN_RE, s), s
        else:
            stricter += 1
    assert softer == 0 and bad == [] and stricter > 0, (softer, bad[:5])


QWORST = [("q*32k", "'\"'*32768"), ("qPASS*8k", "('\"PASS'*8000)[:32768]"), ("pass-colon*4600", "'\"pass\":'*4600"),
          ("esc-unterm32k", "(('\\\\\"pass\\\\\":\\\\\"'+'x\\\\\\\\'*10)*1200)[:32768]"), ("ws32k", "'\"pass\"'+' '*32000"),
          ("bs-q32k", "('\"pass\":\\\\'*4000)[:32768]"), ("esc-token32k", "('\\\\\"token'*5000)[:32768]"),
          ("q4k", "('\"PASS'*1000)[:4096]"), ("mixed4k", "('{\"db_password\": \"a\\\\\\\\\\\\\"'*300)[:4096]")]


@pytest.mark.parametrize("name,expr", QWORST + R.WORST)
def test_quoted_pass_is_fast_on_the_worst_inputs(name, expr):
    ms = R._child_ms("from app import toolmap as t\nfrom deus_witness.hook import mask as c\ns=%s\nt0=time.perf_counter()\n"
                     "t.QUOTED_ASSIGN_RE.findall(s)\nt1=time.perf_counter()\nc.mask_assign(s)\nt.mask_assign(s)\n"
                     "print((t1-t0)*1000)" % expr)
    assert ms < R.LIMIT_MS, (name, ms)
