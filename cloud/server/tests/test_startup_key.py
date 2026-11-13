"""Startup guard (restore drill 2026-10-19, finding 1): the witness key must have signed the LAST entry of every journal, else the start is refused."""
import dataclasses
import json
import os

import pytest
from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
from app.hub import KeyFileError
from app.main import KeyMismatch, _last_line, create_app
from tests.helpers import ORIGIN, Owner, act


def one_decision(app):
    o = Owner(TestClient(app, base_url=ORIGIN)).register("Alice")
    ag, hdr = o.new_agent()
    m, r = o.mandate(ag["id"])
    assert r.status_code == 200, r.text
    r = act(o.c, hdr, "send_email", {"to": "bob@partner.example", "subject": "hi", "body": "b"}).json()
    assert r["verdict"] == "allow"


def other_key_cfg(cfg, tmp_path):
    kf = tmp_path / "other_key"
    kf.write_text("c3" * 32)
    return dataclasses.replace(cfg, witness_key_file=str(kf))


def journals(cfg):
    root = os.path.join(cfg.data_dir, "ledgers")
    return [os.path.join(root, d, "ledger.cose") for d in os.listdir(root)]


def test_same_key_restarts(app, cfg):
    one_decision(app)
    app2 = create_app(cfg)                                    # the same key: starts
    assert app2.state.ctx.wk.kid == app.state.ctx.wk.kid


def test_empty_data_dir_starts(cfg):
    create_app(cfg)                                           # no journals yet: nothing to compare with


def test_foreign_key_refuses_to_start(app, cfg, tmp_path, capsys):
    one_decision(app)
    before = [open(p, "rb").read() for p in journals(cfg)]
    with pytest.raises(KeyMismatch) as e:
        create_app(other_key_cfg(cfg, tmp_path))
    assert isinstance(e.value, KeyFileError)                  # main() maps KeyFileError to exit code 2
    msg = str(e.value)
    assert "did not sign the last entry of 1 of 1 journals" in msg and "witness_ed25519" in msg and "DW_ALLOW_KEY_MISMATCH=1" in msg
    assert [open(p, "rb").read() for p in journals(cfg)] == before        # the journal is not touched
    err = [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]
    assert any(r["level"] == "ERROR" and "did not sign" in r["msg"] for r in err)


def test_allow_flag_starts_and_warns(app, cfg, tmp_path, monkeypatch, capsys):
    one_decision(app)
    monkeypatch.setenv("DW_ALLOW_KEY_MISMATCH", "1")
    app2 = create_app(other_key_cfg(cfg, tmp_path))
    assert app2.state.ctx.wk.kid != app.state.ctx.wk.kid
    out = [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]
    warns = [r for r in out if r["level"] == "WARN" and "DW_ALLOW_KEY_MISMATCH=1" in r["msg"]]
    assert warns and not any(r["level"] == "ERROR" for r in out)


@pytest.mark.parametrize("val", ["0", "", "true", "yes"])
def test_only_exactly_one_allows(app, cfg, tmp_path, monkeypatch, val):
    one_decision(app)
    monkeypatch.setenv("DW_ALLOW_KEY_MISMATCH", val)
    with pytest.raises(KeyMismatch):
        create_app(other_key_cfg(cfg, tmp_path))


def test_only_the_last_entry_is_compared_and_a_partial_tail_is_ignored(app, cfg, tmp_path):
    one_decision(app)
    p = journals(cfg)[0]
    with open(p, "ab") as f:
        f.write(b"d28458")                                    # a torn, never acknowledged write: the ledger drops it, so does the guard
    create_app(cfg)                                           # same key: still starts
    with pytest.raises(KeyMismatch):
        create_app(other_key_cfg(cfg, tmp_path))


def test_garbage_last_line_refuses(app, cfg):
    one_decision(app)
    with open(journals(cfg)[0], "ab") as f:
        f.write(b"zz-not-hex\n")
    with pytest.raises(KeyMismatch):
        create_app(cfg)


def test_empty_journal_file_is_fine(app, cfg):
    one_decision(app)
    root = os.path.join(cfg.data_dir, "ledgers")
    d = os.path.join(root, "f" * 32)
    os.makedirs(d)
    open(os.path.join(d, "ledger.cose"), "wb").close()
    create_app(cfg)


def test_a_non_account_dir_is_skipped(app, cfg):
    one_decision(app)
    d = os.path.join(cfg.data_dir, "ledgers", "lost+found")
    os.makedirs(d)
    open(os.path.join(d, "ledger.cose"), "wb").write(b"junk\n")
    create_app(cfg)


def test_last_line_reader(tmp_path):
    p = tmp_path / "l"
    p.write_bytes(b"")
    assert _last_line(str(p)) == b""
    p.write_bytes(b"abc")
    assert _last_line(str(p)) == b""                          # no newline: not acknowledged
    p.write_bytes(b"abc\n")
    assert _last_line(str(p)) == b"abc"
    p.write_bytes(b"abc\ndef\nghi")
    assert _last_line(str(p)) == b"def"
    big = b"".join(b"%d\n" % i for i in range(30000)) + b"x" * 200000 + b"\n" + b"y" * 150000 + b"\n"
    p.write_bytes(big)                                        # longer than the first 64 KiB window
    assert _last_line(str(p)) == b"y" * 150000
