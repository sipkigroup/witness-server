#!/usr/bin/env python3
"""Deus Witness, step Ш3: OpenTimestamps anchoring (spec draft-deus-aar-03 §9.2).
Only a 32-byte digest leaves the machine (via a random-nonce commitment, as the stock ots client does).
  anchor.py stamp   <digest_hex> <out.ots>   submit to >=2 public calendars (timeout 30 s each)
  anchor.py upgrade <in.ots>                 fetch Bitcoin attestations (in place)
  anchor.py verify  <in.ots> <digest_hex>    local structure check + Bitcoin header check via public API
  anchor.py digest  <checkpoint.cose>        SHA-256 of the signed checkpoint bytes (what §9.2 anchors)
Run with the venv python: ../.venv/bin/python anchor.py ..."""
import hashlib, json, os, sys, urllib.request
from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile, make_merkle_tree
from opentimestamps.core.op import OpSHA256, OpAppend
from opentimestamps.core.notary import (PendingAttestation, BitcoinBlockHeaderAttestation)
from opentimestamps.core.serialize import StreamSerializationContext, StreamDeserializationContext
from opentimestamps.calendar import RemoteCalendar

CALENDARS = ["https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org",
             "https://finney.calendar.eternitywall.com", "https://btc.calendar.catallaxy.com"]
TIMEOUT = 30
MIN_CAL = 2
MEMPOOL = "https://mempool.space/api"


def _load(path):
    with open(path, "rb") as f:
        return DetachedTimestampFile.deserialize(StreamDeserializationContext(f))


def _save(d, path):
    with open(path, "wb") as f:
        d.serialize(StreamSerializationContext(f))


def stamp(digest_hex, out, calendars=CALENDARS):
    digest = bytes.fromhex(digest_hex)
    if len(digest) != 32:
        raise SystemExit("digest must be 32 bytes (64 hex)")
    file_ts = DetachedTimestampFile(OpSHA256(), Timestamp(digest))
    nonce_ts = file_ts.timestamp.ops.add(OpAppend(os.urandom(16)))   # privacy nonce, like stock client
    tip = nonce_ts.ops.add(OpSHA256())
    ok, res = [], {}
    for url in calendars:
        try:
            ts = RemoteCalendar(url).submit(tip.msg, timeout=TIMEOUT)
            tip.merge(ts)
            ok.append(url); res[url] = "ok"
        except Exception as e:
            res[url] = "FAIL %s: %s" % (type(e).__name__, str(e)[:120])
    for u, r in res.items():
        print("%-48s %s" % (u, r))
    if len(ok) < MIN_CAL:
        raise SystemExit("only %d calendars answered, need >= %d; NOT saved" % (len(ok), MIN_CAL))
    _save(file_ts, out)
    print("saved %s (%d calendars)" % (out, len(ok)))
    return ok


def _walk(ts):
    for att in ts.attestations:
        yield ts, att
    for op, sub in ts.ops.items():
        yield from _walk(sub)


def upgrade(path):
    d = _load(path)
    changed = 0
    for sub, att in list(_walk(d.timestamp)):
        if isinstance(att, PendingAttestation):
            try:
                new = RemoteCalendar(att.uri).get_timestamp(sub.msg, timeout=TIMEOUT)
            except Exception as e:
                print("%s pending: %s" % (att.uri, str(e)[:100])); continue
            if any(isinstance(a, BitcoinBlockHeaderAttestation) for _, a in _walk(new)):
                sub.merge(new); changed += 1
                print("%s -> bitcoin attestation received" % att.uri)
            else:
                print("%s still pending" % att.uri)
    if changed:
        _save(d, path)
    print("upgraded %d" % changed)
    return changed


def verify(path, digest_hex):
    d = _load(path)
    if d.file_digest != bytes.fromhex(digest_hex):
        print("invalid ANCHOR_MISMATCH: proof commits to %s" % d.file_digest.hex()); return 2
    pend, btc = [], []
    for sub, att in _walk(d.timestamp):
        if isinstance(att, PendingAttestation): pend.append(att.uri)
        elif isinstance(att, BitcoinBlockHeaderAttestation):
            bh = urllib.request.urlopen("%s/block-height/%d" % (MEMPOOL, att.height), timeout=TIMEOUT).read().decode()
            blk = json.load(urllib.request.urlopen("%s/block/%s" % (MEMPOOL, bh), timeout=TIMEOUT))
            want = bytes.fromhex(blk["merkle_root"])[::-1]   # header stores it little-endian
            good = sub.msg == want
            btc.append((att.height, blk["timestamp"], good))
    for h, t, g in btc:
        print("bitcoin block %d time %d (unix) merkle-root %s" % (h, t, "MATCH" if g else "MISMATCH"))
    if btc and all(g for _, _, g in btc):
        print("bitcoin (complete)"); return 0
    if btc:
        print("invalid"); return 2
    print("pending (calendar commitments only): %s" % ", ".join(pend)); return 1


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 3 and a[0] == "stamp": stamp(a[1], a[2])
    elif len(a) == 2 and a[0] == "upgrade": upgrade(a[1])
    elif len(a) == 3 and a[0] == "verify": sys.exit(verify(a[1], a[2]))
    elif len(a) == 2 and a[0] == "digest": print(hashlib.sha256(open(a[1], "rb").read()).hexdigest())
    else: print(__doc__); sys.exit(64)
