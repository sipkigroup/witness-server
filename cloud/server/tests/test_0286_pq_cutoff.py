"""r0286 (POSTKVANT-1311 step 1): the long-term (post-quantum) mode of the pack checker, --pq-cutoff=YYYY-MM-DD.
Only a ledger entry under a checkpoint whose batch root is in a Bitcoin block dated before the cutoff counts; a calendar's `pending`
promise does not; a forgery stays INVALID. Vectors: confirmed anchor before the cutoff VALID (exit 0); after it NOT PROVEN (3); pending
NOT PROVEN (3); a tampered pack INVALID (1). Block headers are given with --pq-headers (checked here: Merkle root, proof of work); the
test headers are mined at the regtest target, so the tests lower the work floor with --pq-min-work-bits=0 (and check that the default
floor refuses such a cheap header). Also: normal mode no longer calls `pending` a Bitcoin anchor; the two copies of the code are equal."""
import calendar
import hashlib
import json
import os
import re
import time

import pytest

from tests.recovery_helpers import export_to, run_verify
from tests.test_pack import scenario

pytest.importorskip("opentimestamps")

HERE = os.path.dirname(os.path.abspath(__file__))
CLOUD = os.path.dirname(os.path.dirname(HERE))
HEIGHT = 950000


def _stamp(ctx, bid, bitcoin):
    """Test-side: a well-formed .ots for the batch: a Bitcoin attestation at HEIGHT (directly on the root) or a pending one."""
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.serialize import StreamSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    root = bytes(ctx.db.one("SELECT root FROM anchor_batches WHERE id=?", (bid,))["root"])
    ts = Timestamp(root)
    ts.attestations.add(BitcoinBlockHeaderAttestation(HEIGHT) if bitcoin else PendingAttestation("https://calendar.test"))
    with open(os.path.join(ctx.anchor_dir, bid + ".ots"), "wb") as f:
        DetachedTimestampFile(OpSHA256(), ts).serialize(StreamSerializationContext(f))
    ctx.db.x("UPDATE anchor_batches SET status=? WHERE id=?", ("confirmed" if bitcoin else "pending", bid))
    return root


def _header(merkle, day, bits=0x207fffff):
    """An 80-byte header whose Merkle root field is `merkle` (internal byte order, as the .ots message), time = 12:00 UTC of `day`,
    mined at the regtest target (a couple of tries)."""
    t = calendar.timegm(time.strptime(day + " 12:00", "%Y-%m-%d %H:%M"))
    exp, mant = bits >> 24, bits & 0x7fffff
    target = mant << (8 * (exp - 3))
    for nonce in range(1 << 20):
        h = (2).to_bytes(4, "little") + b"\x11" * 32 + merkle + t.to_bytes(4, "little") + bits.to_bytes(4, "little") + nonce.to_bytes(4, "little")
        if int.from_bytes(hashlib.sha256(hashlib.sha256(h).digest()).digest(), "little") <= target:
            return h
    raise AssertionError("no nonce")


def _pack(client, owner, app, tmp_path, bitcoin=True):
    from app import jobs
    scenario(client, owner)
    bid = jobs.anchor_once(app.state.ctx)
    root = _stamp(app.state.ctx, bid, bitcoin)
    return export_to(client, tmp_path / "pack"), root


def _headers(tmp_path, root, day, name="h.json"):
    p = tmp_path / name
    p.write_text(json.dumps({str(HEIGHT): _header(root, day).hex()}))
    return "--pq-headers=" + str(p)


def test_confirmed_anchor_before_the_cutoff_is_valid_after_it_not_proven(client, owner, app, tmp_path):
    d, root = _pack(client, owner, app, tmp_path)
    hp = _headers(tmp_path, root, "2026-11-01")
    rc, out = run_verify(d, "--offline", "--pq-cutoff=2026-11-13", hp, "--pq-min-work-bits=0")
    assert rc == 0 and out.rstrip().endswith("RESULT: VALID"), out
    assert re.search(r"pq anchor \S+: PROVEN before 2026-11-13 \(bitcoin block %d, 2026-11-01 12:00 UTC; header [0-9a-f]{64} checked" % HEIGHT, out), out
    assert re.search(r"pq: (\d+) of \1 receipt entries under a Bitcoin anchor dated before 2026-11-13", out), out
    assert "trust: --pq-cutoff=2026-11-13: only the hash chain" in out
    # the same block, a cutoff before it: consistent, but not provable after that day
    rc, out = run_verify(d, "--offline", "--pq-cutoff=2026-10-01", hp, "--pq-min-work-bits=0")
    assert rc == 3 and out.rstrip().endswith("RESULT: NOT PROVEN"), out
    assert "not before the cutoff 2026-10-01" in out and "pq: 0 of " in out, out
    # 2 h margin: a block at 12:00 of the day before the cutoff counts, one at 12:00 of the cutoff day does not
    rc, out = run_verify(d, "--offline", "--pq-cutoff=2026-11-01", hp, "--pq-min-work-bits=0")
    assert rc == 3, out


def test_without_a_known_block_date_or_with_a_cheap_header_it_is_not_proven(client, owner, app, tmp_path):
    d, root = _pack(client, owner, app, tmp_path)
    rc, out = run_verify(d, "--offline", "--pq-cutoff=2026-11-13")
    assert rc == 3 and "the date of block %d is not known here" % HEIGHT in out, out
    rc, out = run_verify(d, "--offline", "--pq-cutoff=2026-11-13", _headers(tmp_path, root, "2026-11-01"))     # default work floor 2^74
    assert rc == 3 and "below 2^74 hashes" in out, out
    rc, out = run_verify(d, "--offline", "--pq-cutoff=2026-11-13", _headers(tmp_path, b"\x22" * 32, "2026-11-01"), "--pq-min-work-bits=0")
    assert rc == 3 and "Merkle root is not the one the .ots commits to" in out, out
    # the normal mode is unchanged: the Bitcoin attestation is read and said so
    rc, out = run_verify(d, "--offline")
    assert rc == 0 and "bitcoin block %d (offline" % HEIGHT in out and "1 with a Bitcoin attestation, 0 only promised" in out, out


def test_pending_is_not_a_bitcoin_anchor(client, owner, app, tmp_path):
    d, root = _pack(client, owner, app, tmp_path, bitcoin=False)
    rc, out = run_verify(d, "--offline")
    assert rc == 0 and "pending (promised by an OpenTimestamps calendar, not confirmed in Bitcoin)" in out, out
    assert "0 with a Bitcoin attestation, 1 only promised by an OpenTimestamps calendar" in out, out
    assert "rely on the server (anchor pending)" in out, out
    rc, out = run_verify(d, "--offline", "--pq-cutoff=2026-11-13", _headers(tmp_path, root, "2026-11-01"), "--pq-min-work-bits=0")
    assert rc == 3 and "NOT PROVEN (pending: promised by an OpenTimestamps calendar, not confirmed in Bitcoin)" in out, out
    assert out.rstrip().endswith("RESULT: NOT PROVEN"), out


def test_a_forgery_stays_invalid_in_the_long_term_mode(client, owner, app, tmp_path):
    import shutil
    d, root = _pack(client, owner, app, tmp_path)
    hp, flags = _headers(tmp_path, root, "2026-11-01"), ("--offline", "--pq-cutoff=2026-11-13", "--pq-min-work-bits=0")
    d2 = str(tmp_path / "pack2")                 # a ledger row removed
    shutil.copytree(d, d2)
    p = os.path.join(d2, "ledger", "ledger.cose")
    lines = open(p).read().split("\n")
    del lines[2]
    open(p, "w").write("\n".join(lines))
    rc, out = run_verify(d2, *flags, hp)
    assert rc == 1 and out.rstrip().endswith("RESULT: INVALID") and "CHAIN_BREAK" in out, out
    d3 = str(tmp_path / "pack3")                 # a receipt byte
    shutil.copytree(d, d3)
    rp = os.path.join(d3, "receipts", sorted(os.listdir(os.path.join(d3, "receipts")))[0])
    b = bytearray(open(rp, "rb").read())
    b[-3] ^= 1
    open(rp, "wb").write(bytes(b))
    rc, out = run_verify(d3, *flags, hp)
    assert rc == 1 and out.rstrip().endswith("RESULT: INVALID"), out


@pytest.mark.parametrize("flags", [["--pq-cutoff=13.11.2026"], ["--pq-cutoff=2026-1-5"], ["--pq-headers=x.json"],
                                   ["--pq-cutoff=2026-11-13", "--pq-min-work-bits=x"], ["--pq-cutoff"]])
def test_bad_pq_flags_are_refused(tmp_path, flags):
    rc, out = run_verify(str(tmp_path), *flags)
    assert rc == 2, out


def test_the_two_copies_carry_the_same_long_term_code():
    mcp_copy = os.path.join(CLOUD, "mcp", "deus_witness", "verify_pack", "verify_pack.py")
    if not os.path.isfile(mcp_copy):
        pytest.skip("no mcp/ in this tree (the open server set ships without the client): the second copy is not here")   # r0304
    a = open(os.path.join(CLOUD, "server", "packtools", "verify_pack.py")).read()
    b = open(os.path.join(CLOUD, "mcp", "deus_witness", "verify_pack", "verify_pack.py")).read()

    def part(s, start, end):
        return s[s.index(start):s.index(end)]
    assert part(a, '_last = ""\n', "return out, full") == part(b, '_last = ""\n', "return out, full")
    assert part(a, "    # 4. anchors", "    # 4a.") == part(b, "    # 4. anchors", "    # 4a.")
