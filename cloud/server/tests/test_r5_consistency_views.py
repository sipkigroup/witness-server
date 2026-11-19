"""R5 (02.11.2026) consistency check of the shown object in the evidence pack (server 0.2.83, MR-24; report cloud/OTCHET-R5-SVERKA-2026-11-02.md).

The same pack, changed in one way and re-sealed with the witness key (the attacker is whoever hands the pack over, the witness included),
goes through BOTH checkers: the server's packtools/verify_pack.py and the client's `python -m deus_witness.verify_pack` (mcp/.venv).
Each test asserts (1) both checkers end with the same RESULT line and (2) the result the product promises (OTCHET-0283, docs/verify.md:
"a signed presentation hash without its object is warning VIEW_UNVERIFIABLE, INVALID with --require-views").
Live gaps are xfail(strict=True) with the severity in the reason: when the product is fixed they turn into XPASS and fail the run, so the
marker has to be removed together with the fix."""
import json
import os
import shutil
import subprocess
import sys

import pytest

from tests.test_0224_critique import Agent
from tests.test_pv2810_view import _approve, _release

MCP = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "mcp")
PACKTOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packtools")


# ---- helpers --------------------------------------------------------------------------------------------------------------------------
def _server_verify(folder, *flags):
    p = subprocess.run([sys.executable, "-I", os.path.join(PACKTOOLS, "verify_pack.py"), folder, *flags], capture_output=True, text=True,
                       timeout=120)
    return p.returncode, p.stdout + p.stderr


def _client_verify(folder, *flags):
    py = os.path.join(MCP, ".venv", "bin", "python")
    if not os.path.exists(py):
        pytest.skip("no mcp/.venv: the client's checker cannot be run here")
    q = subprocess.run([py, "-m", "deus_witness.verify_pack", folder, *flags], capture_output=True, text=True, timeout=120, cwd=MCP)
    return q.returncode, q.stdout + q.stderr


def _result(out):
    lines = [x for x in out.strip().splitlines() if x.startswith("RESULT:")]
    return lines[-1] if lines else "NO RESULT LINE"


def _both(folder, *flags):
    """-> (server rc, server out, client rc, client out); asserts the two checkers agree on the RESULT line and the exit code."""
    rs, os_ = _server_verify(folder, "--offline", *flags)
    rc, oc = _client_verify(folder, "--offline", *flags)
    assert (rs, _result(os_)) == (rc, _result(oc)), "server and client checkers disagree:\n--- server\n%s\n--- client\n%s" % (os_, oc)
    return rs, os_, rc, oc


def _pack(app, tmp_path, release_view="page", rel=True):
    """A pack with one approval (Read of the project .env) and one signed release of a held line (pytest after a secret was seen)."""
    from tests.recovery_helpers import Person, export_to
    p = Person(app).register("Pat")
    a = Agent(p.c, p, tmp_path)
    [(t, v, reason, rid)] = a.tool("Read", {"file_path": a.proj + "/.env"})   # 06.11 (Н1): a private key is refused outright; the project .env stays a question
    r, page = _approve(p, rid)
    assert r.status_code == 200, r.text
    a.tool("Write", {"file_path": a.proj + "/tests/test_new.py", "content": "def test_n():\n    pass\n"})
    v, parts = a.line("pytest -q ")
    rid_h = [x[3] for x in parts if x[2] == "ESCALATE_SECRET_SEEN"][0]
    if release_view is None:                                                   # r0352: only a server before it wrote a release without a view
        from tests import viewkit
        viewkit.legacy_release(p, rid_h, rel)
    else:
        r, rpage = _release(p, rid_h, rel=rel, view=release_view)
        assert r.status_code == 200, r.text
    return rid, rid_h, export_to(p.c, tmp_path / "pack")


def _reseal(app, folder):
    """Re-sign manifest.json / manifest.cose over every file now in the folder (what a dishonest witness can do)."""
    import cbor2
    from app.export import seal
    from svidetel_v4 import cose
    files = {}
    for dp, _, fs in os.walk(folder):
        for n in fs:
            full = os.path.join(dp, n)
            rel = os.path.relpath(full, folder)
            if rel not in ("manifest.json", "manifest.cose"):
                files[rel] = open(full, "rb").read()
    signed = cbor2.loads(cose.parse1(open(os.path.join(folder, "manifest.cose"), "rb").read())[2])
    m = json.load(open(os.path.join(folder, "manifest.json")))
    seal(files, app.state.ctx.wk, m["account"], m["principal"], m["witness"]["iss"], m["created_t"], signed["cp_seq"], signed["cp_head"])
    for n in ("manifest.json", "manifest.cose"):
        open(os.path.join(folder, n), "wb").write(files[n])


def _vp(folder, key):
    return os.path.join(folder, "views", key + ".json")


# ---- baseline: the honest pack ----------------------------------------------------------------------------------------------------------
def test_r5_views_honest_pack_both_valid_with_require_views(app, tmp_path):
    rid, rid_h, folder = _pack(app, tmp_path)
    rs, out, _, _ = _both(folder, "--require-views")
    assert rs == 0 and _result(out) == "RESULT: VALID", out


def test_r5_views_honest_pack_with_a_rejected_release_valid_with_require_views(app, tmp_path):
    """0.2.84 critic check: a signed REJECTION of a held action is walked too; the honest pack keeps its object and stays VALID."""
    rid, rid_h, folder = _pack(app, tmp_path, rel=False)
    assert os.path.exists(_vp(folder, "release-" + rid_h))
    rs, out, _, _ = _both(folder, "--require-views")
    assert rs == 0 and _result(out) == "RESULT: VALID" and "VIEW_EXTRA_FILE" not in out and "warning" not in out, out


def test_r5_views_reformatted_object_is_still_valid_in_both(app, tmp_path):
    """The file need not be canonical: only the parsed object is hashed (indentation, member order, \\u escapes are free).
    Current behaviour, consistent in both checkers; the hash covers the object, not the file bytes."""
    rid, rid_h, folder = _pack(app, tmp_path)
    o = json.load(open(_vp(folder, rid), encoding="utf-8"))
    with open(_vp(folder, rid), "w", encoding="ascii") as f:
        json.dump(dict(reversed(list(o.items()))), f, ensure_ascii=True, indent=7)
    _reseal(app, folder)
    rs, out, _, _ = _both(folder, "--require-views")
    assert rs == 0 and _result(out) == "RESULT: VALID", out


# ---- the object does not match the signed hash -> INVALID VIEW_MISMATCH --------------------------------------------------------------
@pytest.mark.parametrize("which", ["approval", "release"])
@pytest.mark.parametrize("edit", ["value", "extra_member", "drop_member", "nan", "type"])
def test_r5_views_object_not_matching_the_signed_hash_is_invalid_in_both(app, tmp_path, which, edit):
    rid, rid_h, folder = _pack(app, tmp_path)
    key = rid if which == "approval" else "release-" + rid_h
    o = json.load(open(_vp(folder, key), encoding="utf-8"))
    if edit == "value":
        o["args_preview"] = "Read: /tmp/harmless.txt"
    elif edit == "extra_member":
        o["note"] = "unsigned"
    elif edit == "drop_member":
        o.pop("tool", None) if "tool" in o else o.pop("rid")
    elif edit == "type":
        o["rid"] = [o["rid"]]
    text = json.dumps(o)
    if edit == "nan":
        text = text[:-1] + ', "x": NaN}'        # json.loads accepts NaN, JCS refuses it: must be a mismatch, never a crash or VALID
    open(_vp(folder, key), "w", encoding="utf-8").write(text)
    _reseal(app, folder)
    rs, out, _, _ = _both(folder)
    assert rs == 1 and _result(out) == "RESULT: INVALID" and "VIEW_MISMATCH" in out, out


# ---- the object is absent ---------------------------------------------------------------------------------------------------------------
def test_r5_views_approval_object_withheld(app, tmp_path):
    """Approval: without the flag a warning and RESULT VALID; with --require-views INVALID VIEW_UNVERIFIABLE. Both checkers agree."""
    rid, rid_h, folder = _pack(app, tmp_path)
    os.remove(_vp(folder, rid))
    _reseal(app, folder)
    rs, out, _, _ = _both(folder)
    assert rs == 0 and "warning VIEW_UNVERIFIABLE" in out and _result(out) == "RESULT: VALID", out
    rs, out, _, _ = _both(folder, "--require-views")
    assert rs == 1 and "VIEW_UNVERIFIABLE" in out and _result(out) == "RESULT: INVALID", out


def test_r5_views_release_object_withheld_require_views_is_invalid(app, tmp_path):
    rid, rid_h, folder = _pack(app, tmp_path)
    os.remove(_vp(folder, "release-" + rid_h))
    _reseal(app, folder)
    rs, out, _, _ = _both(folder, "--require-views")
    assert rs == 1 and "VIEW_UNVERIFIABLE" in out and _result(out) == "RESULT: INVALID", out


def test_r5_views_release_object_withheld_is_at_least_a_warning(app, tmp_path):
    rid, rid_h, folder = _pack(app, tmp_path)
    os.remove(_vp(folder, "release-" + rid_h))
    _reseal(app, folder)
    rs, out, _, _ = _both(folder)
    assert "VIEW_UNVERIFIABLE" in out and ("release %s" % rid_h) in out, out


def test_r5_views_release_object_withheld_without_flag_is_valid_with_a_trust_line(app, tmp_path):
    """0.2.84 (R5-V1 closed): without the flag the withheld release object is a warning line and a trust: line, RESULT VALID (pack mode),
    the same in both checkers."""
    rid, rid_h, folder = _pack(app, tmp_path)
    os.remove(_vp(folder, "release-" + rid_h))
    _reseal(app, folder)
    rs, out, _, _ = _both(folder)
    assert rs == 0 and _result(out) == "RESULT: VALID" and "release %s: warning VIEW_UNVERIFIABLE" % rid_h in out and "trust:" in out, out


def test_r5_views_release_without_signed_view_require_views_is_invalid(app, tmp_path):
    rid, rid_h, folder = _pack(app, tmp_path, release_view=None)
    assert not os.path.exists(_vp(folder, "release-" + rid_h))
    rs, out, _, _ = _both(folder, "--require-views")
    assert rs == 1 and "VIEW_NOT_SIGNED" in out and _result(out) == "RESULT: INVALID", out
    rs, out, _, _ = _both(folder)
    assert rs == 0 and "release %s: warning VIEW_NOT_SIGNED" % rid_h in out, out


# ---- an unreadable views/ file ----------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("content", [b"", b"   \n", b"{", b"{\"v\": \"dw-view-1\",}", b"\xff\xfe{}", b"null", b"[]", b"\"text\"", b"[" * 100000])
def test_r5_views_empty_or_broken_json_is_invalid_in_both(app, tmp_path, content):
    """Empty / not JSON / not UTF-8 / not an object / nested beyond the recursion limit -> INVALID in both checkers, never VALID, never
    a traceback instead of the RESULT line."""
    rid, rid_h, folder = _pack(app, tmp_path)
    open(_vp(folder, rid), "wb").write(content)
    _reseal(app, folder)
    rs, out, _, _ = _both(folder)
    assert rs == 1 and _result(out) == "RESULT: INVALID" and "Traceback" not in out, out


def test_r5_views_directory_named_like_an_object_is_invalid_in_both(app, tmp_path):
    rid, rid_h, folder = _pack(app, tmp_path)
    os.makedirs(os.path.join(folder, "views", "zz.json"))
    open(os.path.join(folder, "views", "zz.json", "x"), "w").write("{}")
    _reseal(app, folder)
    rs, out, _, _ = _both(folder)
    assert rs == 1 and _result(out) == "RESULT: INVALID" and "Traceback" not in out, out


# ---- duplicate member names inside one object ---------------------------------------------------------------------------------------------
def test_r5_views_duplicate_member_names_are_refused(app, tmp_path):
    rid, rid_h, folder = _pack(app, tmp_path)
    o = json.load(open(_vp(folder, rid), encoding="utf-8"))
    body = json.dumps(o, ensure_ascii=False)
    forged = '{"args_preview": "Read: /tmp/harmless.txt", ' + body[1:]
    open(_vp(folder, rid), "w", encoding="utf-8").write(forged)
    _reseal(app, folder)
    rs, out, _, _ = _both(folder, "--require-views")
    assert rs == 1 and _result(out) == "RESULT: INVALID" and "repeated member name" in out, out
    rs, out, _, _ = _both(folder)                       # not only under the flag
    assert rs == 1 and _result(out) == "RESULT: INVALID", out


# ---- extra files in views/ ----------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["zzz.json", "allowance-nope.json", "release-nope.json"])
def test_r5_views_stray_object_is_invalid_in_both(app, tmp_path, name):
    """A view object for no signed approval / allowance / release -> INVALID VIEW_NOT_SIGNED, the same in both checkers."""
    rid, rid_h, folder = _pack(app, tmp_path)
    open(os.path.join(folder, "views", name), "w").write(json.dumps({"v": "dw-view-1", "rid": "nope"}))
    _reseal(app, folder)
    rs, out, _, _ = _both(folder)
    assert rs == 1 and "VIEW_NOT_SIGNED" in out and _result(out) == "RESULT: INVALID", out


@pytest.mark.parametrize("name", ["notes.txt", "{rid}.jsn", ".{rid}.json", "{rid}.json.bak"])
@pytest.mark.parametrize("sealed", [True, False])
def test_r5_views_extra_files_are_named(app, tmp_path, name, sealed):
    """R5-V4 (closed in 0.2.84 as a warning): a file under views/ that is not `<key>.json` is named (warning VIEW_EXTRA_FILE + a trust:
    line), so is a file the signed manifest does not list; RESULT stays VALID (the honest objects still match), the same in both
    checkers. (`<rid>.JSON` is not tested: on a case-insensitive file system, APFS / NTFS defaults, it REPLACES `<rid>.json`.)"""
    rid, rid_h, folder = _pack(app, tmp_path)
    o = json.load(open(_vp(folder, rid), encoding="utf-8"))
    o["args_preview"] = "Read: /tmp/harmless.txt"
    open(os.path.join(folder, "views", name.format(rid=rid)), "w").write(json.dumps(o))
    if sealed:
        _reseal(app, folder)
    rs, out, _, _ = _both(folder, "--require-views")
    assert rs == 0 and _result(out) == "RESULT: VALID", out
    assert "warning VIEW_EXTRA_FILE" in out and ("views/" + name.format(rid=rid)) in out and "trust: files under views/" in out, out


def test_r5_views_unlisted_object_file_is_named(app, tmp_path):
    """A views/<key>.json that the signed manifest does not list (added after sealing) is named too."""
    rid, rid_h, folder = _pack(app, tmp_path)
    open(os.path.join(folder, "views", "zzz.json"), "w").write(json.dumps({"v": "dw-view-1"}))
    rs, out, _, _ = _both(folder)
    assert rs == 1 and "VIEW_NOT_SIGNED" in out, out          # a stray object is still INVALID (no signed record names it)
    assert "not in the signed manifest: views/zzz.json" in out, out


def test_r5_views_views_is_a_file_not_a_folder(app, tmp_path):
    """views as a plain file: both checkers read no objects (warning without the flag, INVALID VIEW_UNVERIFIABLE with it)."""
    rid, rid_h, folder = _pack(app, tmp_path)
    shutil.rmtree(os.path.join(folder, "views"))
    open(os.path.join(folder, "views"), "w").write("{}")
    _reseal(app, folder)
    rs, out, _, _ = _both(folder)
    assert rs == 0 and "warning VIEW_UNVERIFIABLE" in out, out
    rs, out, _, _ = _both(folder, "--require-views")
    assert rs == 1 and "VIEW_UNVERIFIABLE" in out, out


# ---- duplicate receipt ids (two APPROVAL entries of one receipt) --------------------------------------------------------------------------
def _mc(where):
    import importlib.util
    path = os.path.join(PACKTOOLS if where == "server" else os.path.join(MCP, "deus_witness", "verify_pack"), "mandate_check.py")
    spec = importlib.util.spec_from_file_location("mc_r5_" + where, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_r5_views_duplicate_receipt_id_is_invalid():
    """R5-V5 (closed in 0.2.84). The core (svidetel_v4/ledger.py approve) does not refuse a second APPROVAL of an approved receipt; the export
    keeps ONE object per receipt id, so one object cannot stand for both: INVALID VIEW_DUPLICATE whatever the object, in both copies.
    No product path writes two approvals of one receipt today (a quorum stores one payload)."""
    a, b = {"v": "dw-view-1", "rid": "r1", "status": "pending"}, {"v": "dw-view-1", "rid": "r1", "status": "pending", "reason": "2nd"}
    out = []
    for where in ("server", "client"):
        mc = _mc(where)
        ents = [{"type": "APPROVAL", "body": {"receipt": "r1", "view": mc.view_digest(a)}},
                {"type": "APPROVAL", "body": {"receipt": "r1", "view": mc.view_digest(b)}}]
        out.append((mc.view_checks(ents, {"r1": b}, False), mc.view_checks(ents, {"r1": a}, True), mc.view_checks(ents[:1] * 2, {"r1": a})))
    assert out[0] == out[1]
    for _, why, _ in out[0]:
        assert why == "VIEW_DUPLICATE"


# ---- JCS numbers: the three Python copies agree with each other and with RFC 8785 (0.2.84, R5-V6) ---------------------------------------------
# RFC 8785 3.2.2.3 = ECMAScript Number.prototype.toString: exponent form only below 1e-6 or from 1e21 on (the page: JSON.stringify)
JCS_NUMBERS = [(1e-7, "1e-7"), (0.000001, "0.000001"), (0.00001, "0.00001"), (0.0001, "0.0001"), (0.1, "0.1"), (1e21, "1e+21"), (-0.0, "0"),
               (1.2345678901234568e+20, "123456789012345680000"), (1.25e-6, "0.00000125"), (-1.5e-9, "-1.5e-9"), (5e-324, "5e-324")]


def test_r5_views_jcs_three_python_copies_agree():
    from app import signview
    srv, cli = _mc("server"), _mc("client")
    objs = [{"b": 1, "a": [True, None, "é😀", 0.5]}, {"é": 1, "e": 2, "\U0001F600": 3, "ａ": 4}, " \x00\x1f"]
    objs += [x for x, _ in JCS_NUMBERS]
    for o in objs:
        assert signview.jcs(o) == srv.jcs(o) == cli.jcs(o), o


def test_r5_views_jcs_numbers_follow_rfc8785():
    srv = _mc("server")
    bad = [(x, srv.jcs(x).decode(), want) for x, want in JCS_NUMBERS if srv.jcs(x).decode() != want]
    assert not bad, bad
