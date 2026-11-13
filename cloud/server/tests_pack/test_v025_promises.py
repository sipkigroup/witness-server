"""0.2.5 (R4-01): promises only when they can be kept; a promise that was given and then NOT kept (the stamp failed) is disclosed in the pack, not hidden and not INVALID."""
import glob
import io
import os
import time
import zipfile

from app import export as exp
from app import jobs
from tests.helpers import promises_on, promises_off
from tests.test_pack import run_verify, scenario


def _pack_later(client, dest, monkeypatch, shift):
    real = time.time
    monkeypatch.setattr(exp.time, "time", lambda: real() + shift)
    r = client.get("/api/export")
    monkeypatch.setattr(exp.time, "time", real)
    zipfile.ZipFile(io.BytesIO(r.content)).extractall(dest)
    return str(dest)


def test_promise_gate(app):
    ctx = app.state.ctx
    assert not jobs.promise_allowed(ctx)                       # anchor off
    ctx.cfg.anchor = "on"
    assert not jobs.promise_allowed(ctx)                       # no anchor run yet
    ctx.anchor_state = {"t": time.time(), "ok": False}
    assert not jobs.promise_allowed(ctx)                       # last run failed
    ctx.anchor_state = {"t": time.time() - 3000, "ok": True}
    assert not jobs.promise_allowed(ctx)                       # the loop is stale
    ctx.anchor_state = {"t": time.time() - 100, "ok": True}
    assert jobs.promise_allowed(ctx)


def test_given_promise_with_failed_stamp_is_disclosed_not_invalid(client, owner, app, tmp_path, monkeypatch):
    promises_on(app)
    scenario(client, owner)

    class _Fail:
        @staticmethod
        def stamp(root, out):
            raise SystemExit("calendars unreachable")
    monkeypatch.setattr(jobs, "_anchor_mod", lambda: _Fail)
    jobs.anchor_once(app.state.ctx, tsa=False)                 # cfg.anchor is "on": the stamp fails
    assert not jobs.promise_allowed(app.state.ctx)             # no NEW promise until a good run
    d = _pack_later(client, tmp_path / "p", monkeypatch, 2 * 3600)
    assert glob.glob(os.path.join(d, "promises", "*.promise.cose"))
    rc, out = run_verify(d, "--offline")
    assert rc == 0 and "RESULT: VALID" in out and "PROMISE_UNMET_DISCLOSED" in out and "PROMISE_LATE" not in out, out


def test_late_promise_without_any_disclosure_still_invalidates(client, owner, app, tmp_path, monkeypatch):
    promises_on(app)
    scenario(client, owner)
    promises_off(app)
    jobs.anchor_once(app.state.ctx, tsa=False)                 # off -> batch status "off" ... disclosed too
    d = _pack_later(client, tmp_path / "p", monkeypatch, 2 * 3600)
    for f in glob.glob(os.path.join(d, "anchors", "*.json")):  # a pack with the anchor records stripped: nothing discloses the failure
        os.remove(f)
    from kit import reseal
    reseal(d, app.state.ctx.wk)
    rc, out = run_verify(d, "--offline")
    assert rc == 1 and "PROMISE_LATE" in out, out
