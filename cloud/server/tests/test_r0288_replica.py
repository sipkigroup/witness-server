"""r0288: app.replica (the continuous copy of the files of the data dir; Litestream copies db.sqlite). The full drill with a real server
and a real Litestream: deploy/replica-drill.sh."""
import json
import os

import pytest

from app import replica


def _w(p, b, mode="wb"):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, mode) as f:
        f.write(b)


def test_pass_copies_files_not_the_database_and_mirrors_erases(tmp_path):
    d, r = tmp_path / "data", tmp_path / "rep"
    _w(str(d / "db.sqlite"), b"SQLite format 3\0")
    _w(str(d / "db.sqlite-wal"), b"wal")
    _w(str(d / ".db.sqlite-litestream" / "x"), b"ls")
    _w(str(d / "ledgers" / "a1" / "ledger.cose"), b"line1\n")
    _w(str(d / "anchors" / "b.json"), b"{}")
    st = replica.once(str(d), str(r))
    assert st["copy"] == 2 and st["files"] == 2
    assert not (r / "db.sqlite").exists() and not (r / "db.sqlite-wal").exists() and not (r / ".db.sqlite-litestream").exists()
    _w(str(d / "ledgers" / "a1" / "ledger.cose"), b"line2\n", "ab")                    # append-only: only the tail is copied
    st = replica.once(str(d), str(r))
    assert st["tail"] == 1 and st["same"] == 1 and (r / "ledgers" / "a1" / "ledger.cose").read_bytes() == b"line1\nline2\n"
    _w(str(d / "ledgers" / "a1" / "ledger.cose"), b"LINE1\nline2\nline3\n")            # not a prefix any more: copied whole
    assert replica.once(str(d), str(r))["copy"] == 1 and (r / "ledgers" / "a1" / "ledger.cose").read_bytes() == b"LINE1\nline2\nline3\n"
    os.remove(d / "ledgers" / "a1" / "ledger.cose")                                    # an erased account: its copy goes too
    _w(str(d / "ledgers" / "a1" / "ledger.skeleton.cbor"), b"sk")
    st = replica.once(str(d), str(r))
    assert st["removed"] == 1 and not (r / "ledgers" / "a1" / "ledger.cose").exists() and (r / "ledgers" / "a1" / "ledger.skeleton.cbor").exists()
    s = json.loads((r / ".replica.json").read_text())
    assert s["pass_started"] <= s["pass_done"] and s["pass_started_utc"].endswith("Z")


def test_refuses_a_dir_that_is_not_the_witness_data(tmp_path):
    with pytest.raises(SystemExit):
        replica.once(str(tmp_path / "nothing"), str(tmp_path / "rep"))


def test_restore_needs_a_complete_pass_and_an_empty_target(tmp_path):
    d, r = tmp_path / "data", tmp_path / "rep"
    _w(str(d / "db.sqlite"), b"x")
    _w(str(d / "ledgers" / "a" / "ledger.cose"), b"l\n")
    with pytest.raises(SystemExit):
        replica.restore(str(r), str(tmp_path / "new"))                                  # no pass yet
    replica.once(str(d), str(r))
    with pytest.raises(SystemExit):
        replica.restore(str(r), str(d))                                                # never over live data
    st = replica.restore(str(r), str(tmp_path / "new"))
    assert st["restored_files"] == 1 and (tmp_path / "new" / "ledgers" / "a" / "ledger.cose").read_bytes() == b"l\n"


def test_pick_txid_never_after_the_files_pass():
    ltx = [{"level": 0, "max_txid": "0000000000000001", "timestamp": "2026-11-13T10:00:00Z"},
           {"level": 0, "max_txid": "0000000000000002", "timestamp": "2026-11-13T10:00:05Z"},
           {"level": 1, "max_txid": "0000000000000002", "timestamp": "2026-11-13T10:00:05Z"},
           {"level": 0, "max_txid": "0000000000000003", "timestamp": "2026-11-13T10:00:09Z"}, {"bad": 1}]
    import calendar
    t = calendar.timegm((2026, 11, 13, 10, 0, 6))
    assert replica.pick_txid(ltx, t) == "0000000000000002"
    assert replica.pick_txid(ltx, t - 0.5) == "0000000000000001"                       # 10:00:05 may be up to 10:00:05.999: not taken
    assert replica.pick_txid(ltx, calendar.timegm((2026, 11, 13, 9, 0, 0))) is None
