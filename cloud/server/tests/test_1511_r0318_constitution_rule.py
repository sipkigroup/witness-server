"""r0318: the rule of change of the public constitution is checked by code, not only promised (packtools/constitution_check.py).

Every law has a permanent id (data-law on the page, "laws" in web/constitution/versions.json with its checks). Between two versions:
a law or a test that disappears is a weakening and needs weakens=true and effective >= date + 14 days; a changed law text needs that
or a listed correction ("corrects": law, reason, evidence = one of the law's checks). The marking is also on the page itself, so it is
under the page hash and the signed log."""
import copy
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from app import tlog  # noqa: F401  (first: puts packtools/ on sys.path)
import constitution_check as CC  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
PAGE = WEB / "constitution.html"
VERSIONS = WEB / "constitution" / "versions.json"
V3_MARK = b'data-weakens="false" data-effective="2026-11-15" data-corrects="by-construction silence-is-a-no"'


def _vs():
    return json.loads(VERSIONS.read_text())


def _last_line_and_mark():
    """the Version line and the change marker of the current page (the latest version), as bytes"""
    e = _vs()[-1]
    return (("Version %d (%s)" % (e["version"], e["date"])).encode(),
            ('data-weakens="%s" data-effective="%s" data-corrects="%s"' % (
                "true" if e["weakens"] else "false", e["effective"], " ".join(c["law"] for c in e["corrects"]))).encode())


def _next(tmp_path, *, drop_law=None, drop_check=None, retext=None, weakens=False, date="2026-12-01", effective=None, corrects=(),
          json_laws=None, mark=None):
    """The next version made from the current page (the latest version) with one change; -> (web dir, page bytes, versions list)."""
    effective = effective or date
    w = tmp_path / "web"
    (w / "constitution").mkdir(parents=True)
    for f in (WEB / "constitution").iterdir():
        shutil.copy(f, w / "constitution" / f.name)
    line, cur_mark = _last_line_and_mark()
    nv = _vs()[-1]["version"] + 1
    page = PAGE.read_bytes().replace(line, ("Version %d (%s)" % (nv, date)).encode())
    laws = copy.deepcopy(_vs()[-1]["laws"])
    if drop_law:
        page, n = re.subn(rb'\n  <li class="law[^"]*" data-law="%s">.*?</li>' % drop_law.encode(), b"", page, flags=re.S)
        assert n == 1
        del laws[drop_law]
    if drop_check:
        law, chk = drop_check
        page, n = re.subn(rb', <code class="check">%s</code>' % re.escape(chk.encode()), b"", page)
        assert n == 1
        laws[law].remove(chk)
    if retext:
        old, new = retext
        assert page.count(old) == 1
        page = page.replace(old, new)
    assert page.count(cur_mark) == 1
    page = page.replace(cur_mark, mark if mark is not None else ('data-weakens="%s" data-effective="%s" data-corrects="%s"' % (
        "true" if weakens else "false", effective, " ".join(c["law"] for c in corrects))).encode())
    (w / "constitution" / ("v%d.html" % nv)).write_bytes(page)
    vs = _vs() + [{"version": nv, "date": date, "sha256": CC.page_hash(page), "path": "constitution/v%d.html" % nv,
                   "laws": json_laws if json_laws is not None else laws, "weakens": weakens, "effective": effective, "corrects": list(corrects)}]
    (w / "constitution" / "versions.json").write_text(json.dumps(vs))
    shutil.copy(w / "constitution" / ("v%d.html" % nv), w / "constitution.html")
    return w, page, vs


def _check(w, page, vs, with_copies=True):
    return CC.check_constitution(page, json.dumps(vs), web_dir=str(w) if with_copies else None)


def test_version_3_is_valid_and_names_every_law_by_id():
    ok, why = CC.check_constitution(PAGE.read_bytes(), VERSIONS.read_bytes(), web_dir=str(WEB))
    assert ok and "version %d" % _vs()[-1]["version"] in why, why
    ids = [e[0] for e in CC.law_elements(PAGE.read_bytes())]
    assert ids == list(_vs()[-1]["laws"]) and None not in ids
    v3 = _vs()[2]                                        # r0336: version 4 is the current page; version 3 is checked on its copy
    assert v3["version"] == 3 and v3["weakens"] is False and v3["effective"] == v3["date"] == "2026-11-15"
    v3page = (WEB / v3["path"]).read_bytes()
    assert V3_MARK in v3page
    ids = [e[0] for e in CC.law_elements(v3page)]
    assert ids == list(v3["laws"]) and len(ids) == 16 and None not in ids
    # version 3 keeps every law and every check of version 2, and adds two laws
    v2 = _vs()[1]["laws"]
    assert all(k in v3["laws"] and set(v2[k]) <= set(v3["laws"][k]) for k in v2)
    assert set(v3["laws"]) - set(v2) == {"os-protections-stay-on", "weakening-is-checked"}


def test_an_unchanged_next_version_is_valid(tmp_path):
    ok, why = _check(*_next(tmp_path))
    assert ok, why


def test_a_law_dropped_without_weakens_is_invalid(tmp_path):
    for kw in ({"drop_law": "trust-has-an-end"},
               {"drop_check": ("silence-is-a-no", "mcp/tests/test_offline_0248.py::test_non_reads_refused")}):
        w, page, vs = _next(tmp_path / str(len(kw) + len(str(kw))), **kw)
        for copies in (True, False):                     # versions.json alone already shows it
            ok, why = _check(w, page, vs, copies)
            assert not ok and "without being marked as a weakening" in why, why


def test_a_weakening_takes_effect_14_days_later(tmp_path):
    ok, why = _check(*_next(tmp_path / "a", drop_law="trust-has-an-end", weakens=True, date="2026-12-01", effective="2026-12-14"))
    assert not ok and "less than 14 days" in why, why
    ok, why = _check(*_next(tmp_path / "b", drop_law="trust-has-an-end", weakens=True, date="2026-12-01", effective="2026-12-15"))
    assert ok, why
    # weakens=false takes effect on its date: no "effective later" without the weakening mark
    ok, why = _check(*_next(tmp_path / "c", date="2026-12-01", effective="2026-12-20"))
    assert not ok and "takes effect on its date" in why, why


def test_a_changed_text_must_be_marked(tmp_path):
    old, new = b"lasts at most 30 days.", b"lasts at most 90 days."
    ok, why = _check(*_next(tmp_path / "a", retext=(old, new)))
    assert not ok and "changes the text of law trust-has-an-end" in why, why
    ev = "server/tests/test_kontrakt_konstant.py::test_from_now_on_days"
    fix = [{"law": "trust-has-an-end", "reason": "the code keeps 90 days", "evidence": ev}]
    ok, why = _check(*_next(tmp_path / "b", retext=(old, new), corrects=fix))
    assert ok, why                    # a listed correction passes the machine; its reason is public on the page and in the log
    bad = [dict(fix[0], evidence="server/tests/test_kontrakt_konstant.py::test_nothing")]
    ok, why = _check(*_next(tmp_path / "c", retext=(old, new), corrects=bad))
    assert not ok and "is not one of the law's checks" in why, why
    ok, why = _check(*_next(tmp_path / "d", corrects=fix))
    assert not ok and "did not change" in why, why
    # a "correction" that also drops a test is a weakening
    ok, why = _check(*_next(tmp_path / "e", retext=(b"Some actions are refused without a question.</strong>",
                                                   b"Some actions are refused.</strong>"),
                           drop_check=("silence-is-a-no", "mcp/tests/test_offline_0248.py::test_non_reads_refused"),
                           corrects=[{"law": "silence-is-a-no", "reason": "x", "evidence": "mcp/tests/test_offline_0248.py::test_read_runs_without_the_witness"}]))
    assert not ok and "without being marked as a weakening" in why, why
    # a correction cannot remove the law it corrects
    ok, why = _check(*_next(tmp_path / "f", drop_law="trust-has-an-end", weakens=True, effective="2026-12-20", corrects=fix))
    assert not ok and "not in both versions" in why, why


def test_versions_json_must_match_the_page(tmp_path):
    vs_laws = dict(_vs()[-1]["laws"], **{"invented-law": ["server/tests/test_x.py::test_y"]})
    ok, why = _check(*_next(tmp_path / "a", json_laws=vs_laws), with_copies=False)
    assert not ok and "other laws or checks" in why, why
    w, page, vs = _next(tmp_path / "b", mark=b'data-weakens="true" data-effective="2026-12-01" data-corrects=""')
    ok, why = _check(w, page, vs)
    assert not ok and "change marker" in why, why
    w, page, vs = _next(tmp_path / "c", mark=b'data-x=""')
    ok, why = _check(w, page, vs)
    assert not ok and "change marker" in why, why
    w, page, vs = _next(tmp_path / "d", retext=(b' data-law="trust-has-an-end"', b""))
    ok, why = _check(w, page, vs)
    assert not ok and "without a data-law id" in why, why
    # from version 3 on, the rule fields are required
    vs = _vs()
    del vs[-1]["weakens"]
    assert not CC.check_constitution(PAGE.read_bytes(), json.dumps(vs))[0]


def test_v1_and_v2_are_unchanged_and_v2_laws_match_its_page():
    pub = {1: "39e384ebd215fc28d22b01470f7f0a6fef83e496914c0de628621ae3f903b4d1",
           2: "2a322f50d5e12243760ffa8c41b62a56cd05fa3e111c1b6eed83fcd30fb0bb73"}
    vs = _vs()
    for n, h in pub.items():
        assert CC.page_hash((WEB / "constitution" / ("v%d.html" % n)).read_bytes()) == h == vs[n - 1]["sha256"]
    assert set(vs[0]) == {"version", "date", "sha256", "path"}
    laws, _ = CC._page_laws((WEB / "constitution" / "v2.html").read_bytes(), vs[1])
    assert laws == vs[1]["laws"]


def test_the_v3_correction_is_true_of_the_code():
    """Version 3 corrects 'Silence is a no': the corrected words must be what mcp/deus_witness/hook/offline.py does, and the evidence
    test must be older than version 2 (else the 'correction' would be a new weakening of the code under the name of a fix)."""
    v3 = _vs()[2]
    assert {c["law"] for c in v3["corrects"]} == {"by-construction", "silence-is-a-no"}
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", PAGE.read_text()))
    assert "If Deus Witness cannot be reached, nothing runs except reading files inside the project; those reads are written to a local journal" in text
    assert "If Deus Witness cannot be reached, the action does not run" not in text
    import sys
    sys.path.insert(0, str(ROOT / "mcp"))
    from deus_witness.hook import offline
    assert set(offline.READ_TOOLS) | set(offline.DIR_TOOLS) == {"Read", "NotebookRead", "Grep", "Glob", "LS"}
    assert {"cat", "grep", "ls"} <= offline.OFFLINE_PROGRAMS and not {"git", "sh", "bash", "python3", "curl"} & offline.OFFLINE_PROGRAMS
    assert offline.enabled({}) and not offline.enabled({offline.ENV: "strict"})
    if not (ROOT / "vorota").is_dir():   # 15.11: the open repository is a fresh export -- its git history says nothing about the evidence
        pytest.skip("not the private repository: the evidence age is checked there")
    for c in v3["corrects"]:
        f, _, name = c["evidence"].partition("::")
        try:
            r = subprocess.run(["git", "log", "--format=%cs", "-S", "def %s(" % name, "--", f], cwd=str(ROOT), capture_output=True,
                               text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            pytest.skip("no git")
        if r.returncode or not r.stdout.strip():
            pytest.skip("no git history here")
        assert min(r.stdout.split()) < _vs()[1]["date"], (c, r.stdout)
