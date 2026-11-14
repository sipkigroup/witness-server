"""r0288 (NAGRUZKA-I-EKONOMIKA-1311 p.4): a CONTINUOUS copy of the witness' data, next to the daily archive (deploy/backup.sh).

The data dir holds two kinds of state, and they are copied by two tools:
  - db.sqlite (accounts, actions, the public log of batches): Litestream streams its WAL to the replica within seconds
    (docker compose --profile replica: service "litestream", litestream.yml);
  - every other file (ledgers/<account>/ledger.cose and their checkpoints, anchors, the hash skeletons of erased accounts): this loop.

    python -m app.replica run     --data /data --to /replica/files [--every 10]     (the service "replica")
    python -m app.replica once    --data D --to R
    python -m app.replica pick    --from R  < (litestream ltx -level all -json URL)   (the txid to restore, for docker: two images)
    python -m app.replica restore --from R --data D [--litestream URL [--bin litestream]]
                          (files back, then the database AS OF the last complete files pass: `litestream restore -txid`)

A pass: note the time S it starts, then bring every file of the replica up to the data dir: a file that only grew (a ledger is append-only)
gets its new tail, any other change is copied whole (temp file + rename), a file gone from the data dir is removed from the replica (an
erased account's journal must not live on in a copy: privacy.html, crypto-shredding). When the pass is complete, <to>/.replica.json says
{"pass_started": S}. Every file then holds at least what it held at S.

Why S matters (the order of the two copies): the witness appends to a ledger BEFORE it commits the database rows of that entry, and a
ledger AHEAD of the database is a state the server already repairs on start (actions.reconcile_on_start: rows whose id the ledger judged
follow the ledger). A database ahead of its ledger is not (rows that point at entries that do not exist). So the restore takes the
database AS OF S, never newer than the files: the newest Litestream file (LTX, any level) whose timestamp + 1 s is not after S
(the listing gives whole seconds), restored with `litestream restore -txid` (Litestream 0.5.17's `-timestamp` refused every value on a
file replica in the 13.11 drill: "timestamp does not exist"). Honest limit: what happened after S (at most one pass,
about --every seconds, plus Litestream's own lag) is lost; if a batch of the public log was signed in that window, the restored witness
will sign a different leaf at that size: the status page (status/check.py) then says "alarm", and the operator must say so publicly.
Stdlib only; nothing leaves the machine (the replica dir is a second disk, a network mount, or a volume another tool copies off-site).
"""
import argparse
import datetime
import json
import os
import shutil
import sys
import time

TAIL_CHECK = 4096
STATE = ".replica.json"


def skip(rel):
    """Not copied by this loop: the database and its sidecars (Litestream copies it), Litestream's own state, temp files."""
    base = os.path.basename(rel)
    top = rel.split(os.sep, 1)[0]
    return (".sqlite" in base or base.endswith((".db", ".db-wal", ".db-shm", ".tmp")) or "-litestream" in top or top.startswith(".")
            or base.startswith(".replica"))


def _walk(root):
    out = {}
    for dp, dn, fn in os.walk(root):
        rd = os.path.relpath(dp, root)
        dn[:] = [d for d in dn if not skip(os.path.normpath(os.path.join(rd, d)))]
        for f in fn:
            rel = os.path.normpath(os.path.join(rd, f))
            if not skip(rel):
                out[rel] = os.path.join(dp, f)
    return out


def _fsync_dir(d):
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _copy_whole(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + ".replica.tmp"
    with open(src, "rb") as a, open(tmp, "wb") as b:
        shutil.copyfileobj(a, b, 1 << 20)
        b.flush()
        os.fsync(b.fileno())
    shutil.copystat(src, tmp)
    os.replace(tmp, dst)
    _fsync_dir(os.path.dirname(dst))


def _append_tail(src, dst, have):
    """dst is a prefix of src (its last TAIL_CHECK bytes are the same): append the rest. -> False when it is not a prefix."""
    n = min(TAIL_CHECK, have)
    with open(src, "rb") as a, open(dst, "r+b") as b:
        a.seek(have - n)
        b.seek(have - n)
        if a.read(n) != b.read(n):
            return False
        a.seek(have)
        b.seek(have)
        shutil.copyfileobj(a, b, 1 << 20)
        b.flush()
        os.fsync(b.fileno())
    shutil.copystat(src, dst)
    return True


def sync_file(src, dst):
    """-> 'same' | 'tail' | 'copy'."""
    s = os.stat(src)
    try:
        d = os.stat(dst)
    except FileNotFoundError:
        d = None
    if d is not None and d.st_size == s.st_size and d.st_mtime_ns == s.st_mtime_ns:
        return "same"
    if d is not None and 0 < d.st_size < s.st_size and _append_tail(src, dst, d.st_size):
        return "tail"
    _copy_whole(src, dst)
    return "copy"


def once(data, to):
    """One complete pass. -> its counts; <to>/.replica.json written last."""
    data, to = os.path.abspath(data), os.path.abspath(to)
    if not os.path.isfile(os.path.join(data, "db.sqlite")):
        raise SystemExit("replica: %s has no db.sqlite: not the witness data dir (nothing copied)" % data)
    os.makedirs(to, exist_ok=True)
    started = time.time()
    n = {"same": 0, "tail": 0, "copy": 0, "removed": 0, "vanished": 0}
    have = _walk(data)
    for rel, src in sorted(have.items()):
        try:
            n[sync_file(src, os.path.join(to, rel))] += 1
        except FileNotFoundError:
            n["vanished"] += 1                   # removed while we copied it (an erase): the next pass removes our copy too
    for rel, p in _walk(to).items():
        if rel not in have and not os.path.exists(os.path.join(data, rel)):
            os.remove(p)
            n["removed"] += 1
    st = {"v": 1, "pass_started": started, "pass_started_utc": _rfc3339(started), "pass_done": time.time(), "files": len(have), **n}
    tmp = os.path.join(to, STATE + ".tmp")
    with open(tmp, "w") as f:
        json.dump(st, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, os.path.join(to, STATE))
    _fsync_dir(to)
    return st


def _rfc3339(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def restore(src, data):
    """Copy the replica's files into an EMPTY data dir (no db.sqlite yet). -> the state of the last complete pass."""
    src, data = os.path.abspath(src), os.path.abspath(data)
    try:
        with open(os.path.join(src, STATE)) as f:
            st = json.load(f)
    except (OSError, ValueError):
        raise SystemExit("replica: %s has no complete pass (.replica.json): use the daily archive instead (deploy/restore.md)" % src)
    if os.path.exists(os.path.join(data, "db.sqlite")) or (os.path.isdir(os.path.join(data, "ledgers")) and os.listdir(os.path.join(data, "ledgers"))):
        raise SystemExit("replica: %s is not empty: move it aside first (never restore over live data)" % data)
    os.makedirs(data, exist_ok=True)
    k = 0
    for rel, p in _walk(src).items():
        _copy_whole(p, os.path.join(data, rel))
        k += 1
    st["restored_files"] = k
    return st


def pick_txid(ltx, started):
    """-> the newest max_txid (hex) among Litestream's files whose whole-second timestamp + 1 <= started, or None."""
    best = None
    for f in ltx if isinstance(ltx, list) else []:
        try:
            ts = datetime.datetime.strptime(f["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()
            tx = int(f["max_txid"], 16)
        except (KeyError, TypeError, ValueError):
            continue
        if ts + 1 <= started and (best is None or tx > best):
            best = tx
    return None if best is None else "%016x" % best


def restore_db(url, data, started, bin_="litestream"):
    """The database as of the files copy: list Litestream's files, pick the txid, restore it into data/db.sqlite."""
    import subprocess
    out = subprocess.run([bin_, "ltx", "-level", "all", "-json", url], check=True, capture_output=True, text=True, timeout=600).stdout
    tx = pick_txid(json.loads(out or "[]"), started)
    if tx is None:
        raise SystemExit("replica: Litestream has nothing older than the last files pass (%s): use the daily archive" % _rfc3339(started))
    subprocess.run([bin_, "restore", "-txid", tx, "-o", os.path.join(data, "db.sqlite"), url], check=True, timeout=3600)
    return tx


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m app.replica", description=__doc__.split("\n\n")[0])
    sp = ap.add_subparsers(dest="cmd", required=True)
    for c in ("run", "once"):
        p = sp.add_parser(c)
        p.add_argument("--data", default=os.environ.get("DW_DATA_DIR", "/data"))
        p.add_argument("--to", default=os.environ.get("DW_REPLICA_FILES", "/replica/files"))
        p.add_argument("--every", type=float, default=float(os.environ.get("DW_REPLICA_EVERY", "10")))
    p = sp.add_parser("pick", help="read `litestream ltx -level all -json URL` on stdin, print the txid to restore (not after the files pass)")
    p.add_argument("--from", dest="src", required=True)
    p = sp.add_parser("restore")
    p.add_argument("--from", dest="src", required=True)
    p.add_argument("--data", required=True)
    p.add_argument("--litestream", help="the Litestream replica URL (file:///replica/db, s3://bucket/db?endpoint=...): also restore db.sqlite")
    p.add_argument("--bin", default="litestream")
    a = ap.parse_args(argv)
    if a.cmd == "pick":
        try:
            with open(os.path.join(os.path.abspath(a.src), STATE)) as f:
                started = json.load(f)["pass_started"]
        except (OSError, ValueError, KeyError):
            raise SystemExit("replica: %s has no complete pass" % a.src)
        tx = pick_txid(json.loads(sys.stdin.read() or "[]"), started)
        if tx is None:
            raise SystemExit("replica: Litestream has nothing older than the last files pass: use the daily archive")
        print(tx)
        return 0
    if a.cmd == "restore":
        st = restore(a.src, a.data)
        print("replica files restored: %d; last complete pass started %s" % (st["restored_files"], st["pass_started_utc"]))
        if a.litestream:
            tx = restore_db(a.litestream, a.data, st["pass_started"], a.bin)
            print("database restored as of Litestream txid %s (not after the files pass)" % tx)
        else:
            print("now restore db.sqlite NOT NEWER than %s (python -m app.replica restore ... --litestream URL does it)" % st["pass_started_utc"])
        return 0
    if a.cmd == "once":
        print(json.dumps(once(a.data, a.to)))
        return 0
    every = max(1.0, a.every)
    print("replica: %s -> %s every %.0f s" % (a.data, a.to, every), flush=True)
    last_err = None
    while True:
        t0 = time.time()
        try:
            st = once(a.data, a.to)
            if st["copy"] or st["tail"] or st["removed"] or last_err:
                print("replica pass %s: %d files, %d new or changed, %d grew, %d removed" % (st["pass_started_utc"], st["files"], st["copy"], st["tail"], st["removed"]), flush=True)
            last_err = None
        except SystemExit as e:
            print("replica ERROR %s" % e, flush=True)
            last_err = str(e)
        except Exception as e:  # noqa: BLE001 - a bad pass is retried, the loop never dies quietly
            print("replica ERROR %s: %s" % (type(e).__name__, e), flush=True)
            last_err = type(e).__name__
        time.sleep(max(0.0, every - (time.time() - t0)))


if __name__ == "__main__":
    sys.exit(main())
