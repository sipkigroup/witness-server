"""r0313 (KONSTITUCIYA-KATALOG-1411 s6, step 1): catalog 0.1 as the descriptive source of the action classes.
PRED (before code): the catalog validates; every mark of bashparse.DANGER_CATEGORIES (+ the two marks outside it, autostart / defense)
and every code of constitution.CODES is in exactly one id; no id lacks a source in the code; the catalog's N-verdict agrees with
constitution.check on one probe per code; the list of N-articles built from the catalog equals constitution.CODES. The judge is not touched."""
import copy
import re
from pathlib import Path

import pytest

from app import catalog as cat
from app import constitution as K
from app.hookjudge import bashparse as bp
from app.hookjudge.mapping import map_event

KH, KP = "/Users/u", "/Users/u/proj"
EXTRA_MARKS = set()      # r0313 step 3: autostart / defense are in DANGER_CATEGORIES now (were outside it in step 1)


def kcheck(cmd):
    ev = {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": KP}
    for m in map_event(ev, home=KH, env={"CLAUDE_PROJECT_DIR": KP, "HOME": KH, "DEUS_WITNESS_EXEC_SCAN": "0"}):
        r = K.check(m.tool, m.args)
        if r is not None:
            return r[0]
    return None


def test_a_catalog_valid_by_schema():
    c = cat.load()
    assert cat.validate(c) == []
    assert len(c["classes"]) >= 20


def test_a_bad_catalog_is_rejected():
    c = copy.deepcopy(cat.load())
    c["classes"][0]["axes"]["irrev"] = "bogus"
    del c["classes"][1]["title"]
    c["classes"][2]["verdict"]["default"] = "X"
    errs = cat.validate(c)
    assert len(errs) >= 3, errs


def test_b_every_mark_and_code_in_exactly_one_id():
    for m in tuple(bp.DANGER_CATEGORIES) + tuple(sorted(EXTRA_MARKS)):
        ids = [e["id"] for e in cat.classes() if m in e.get("marks", [])]
        assert len(ids) == 1, (m, ids)
        assert cat.by_mark(m)["id"] == ids[0]
    for code in K.CODES:
        ids = [e["id"] for e in cat.classes() if code in e.get("codes", [])]
        assert len(ids) == 1, (code, ids)
        assert cat.by_code(code)["id"] == ids[0]
    ids = [e["id"] for e in cat.classes()]
    assert len(ids) == len(set(ids))
    assert cat.by_id(ids[0])["id"] == ids[0]


def test_c_no_id_without_a_source_in_code():
    src = Path(bp.__file__).read_text()
    known_marks = set(bp.DANGER_CATEGORIES) | EXTRA_MARKS
    for e in cat.classes():
        assert e.get("marks") or e.get("codes"), e["id"]
        for m in e.get("marks", []):
            assert m in known_marks, (e["id"], m)
            assert re.search(r'"%s"|"%s:' % (re.escape(m), re.escape(m)), src), (e["id"], m)
        for code in e.get("codes", []):
            assert code in K.CODES, (e["id"], code)


@pytest.mark.parametrize("code", K.CODES)
def test_d_catalog_verdict_matches_constitution_check(code):
    e = cat.by_code(code)
    assert e["verdict"]["default"] == "N"          # an N-article is refused (constitution.check -> refuse)
    probes = [v for v in e.get("vectors", {}).get("match", []) if v.get("expect") == "N"]
    assert probes, code
    for v in probes:
        assert kcheck(v["command"]) == code, (code, v)


def test_e_n_articles_from_catalog_equal_constitution_codes():
    assert cat.n_articles() == tuple(K.CODES)


def test_f_jsonschema_agrees_when_installed():
    js = pytest.importorskip("jsonschema")
    js.Draft202012Validator(cat.load_schema()).validate(cat.load())
