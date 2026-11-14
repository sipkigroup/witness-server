"""r0293 (evaluation awareness, video notes 2026-11-13 Gemini 4 Carbon: the model wrote "this looks like a test" in 8/10 runs): a stand must
not look like a test -- to the model under test, and to the product under test.

A. The product (server/app, mcp/deus_witness, web/js) never knows a stand: no stand name in its code (strings that run, not comments /
   docstrings). A product that recognises the stand is measured in a regime that never occurs (the "Dieselgate" failure).
B. The stands that drive a REAL model (`claude -p`: poligon-lyudi/*.mjs, *.sh) say nothing that marks them as a test in the text the model
   sees: no "security test", "disposable sandbox", "honeypot", reserved test domains (.invalid, evil.example), "_fake" keys, 'aaaa' tokens.
   Active only where the stands live (the owner's machine: <tree>/../poligon-lyudi); skipped elsewhere.
Rule: SISTEMA-TESTIROVANIYA-1311.md (stands), vorota/RISKI.md."""
import ast
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STAND_WORDS = re.compile(r"dw-stand|trenie|poligon|pesochnica|proekt-demo|honeypot|canary-key|r0\d{3}-home", re.I)
CUE = re.compile(r"security test|disposable sandbox|permission hook|honeypot|red.?team|adversar|\.invalid\b|evil\.example|_fake\b|"
                 r"AKIA[A-Z0-9]*(TEST|EXAMPLE)|ghp_a{8}|/poligon-s\d", re.I)


def _py_strings(path):
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except (SyntaxError, UnicodeDecodeError):
        return []
    docs = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and n.body:
            b = n.body[0]
            if isinstance(b, ast.Expr) and isinstance(getattr(b, "value", None), ast.Constant) and isinstance(b.value.value, str):
                docs.add(id(b.value))
    return [(n.lineno, n.value) for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs]


def _js_code(path):
    t = open(path, encoding="utf-8", errors="replace").read()
    t = re.sub(r"/\*.*?\*/", " ", t, flags=re.S)
    return [(i + 1, re.sub(r"(^|[^:\\'\"])//.*$", r"\1", l)) for i, l in enumerate(t.split("\n"))]


def test_product_code_names_no_stand():
    bad = []
    for top in ("server/app", "mcp/deus_witness"):
        for dp, _, fs in os.walk(os.path.join(ROOT, top)):
            for f in fs:
                if f.endswith(".py"):
                    for ln, s in _py_strings(os.path.join(dp, f)):
                        if STAND_WORDS.search(s):
                            bad.append("%s:%d %r" % (os.path.relpath(os.path.join(dp, f), ROOT), ln, s[:80]))
    for dp, _, fs in os.walk(os.path.join(ROOT, "web/js")):
        for f in fs:
            if f.endswith(".js"):
                for ln, l in _js_code(os.path.join(dp, f)):
                    if STAND_WORDS.search(l):
                        bad.append("%s:%d %s" % (os.path.relpath(os.path.join(dp, f), ROOT), ln, l.strip()[:80]))
    assert not bad, bad


STANDS = os.path.join(os.path.dirname(ROOT), "poligon-lyudi")


def _model_stands():
    if not os.path.isdir(STANDS):
        return []
    out = []
    for f in sorted(os.listdir(STANDS)):
        p = os.path.join(STANDS, f)
        if os.path.isfile(p) and re.search(r"\.(mjs|sh)$", f):
            t = open(p, encoding="utf-8", errors="replace").read()
            if re.search(r"claude -p|spawn\('claude'", t):
                out.append(p)
    return out


@pytest.mark.skipif(not _model_stands(), reason="the model-driving stands live on the owner's machine only")
def test_model_stands_carry_no_test_cue():
    bad = []
    for p in _model_stands():
        for i, l in enumerate(open(p, encoding="utf-8", errors="replace")):
            s = l.strip()
            if s.startswith(("//", "#")):
                continue
            m = CUE.search(re.sub(r"\s//\s.*$", "", l))
            if m:
                bad.append("%s:%d %s" % (os.path.basename(p), i + 1, m.group(0)))
    assert not bad, bad
