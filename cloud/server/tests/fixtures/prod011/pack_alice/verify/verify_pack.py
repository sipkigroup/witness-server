#!/usr/bin/env python3
"""Offline checker of a Deus Witness evidence pack.   usage: verify_pack.py <unpacked folder> [--offline] [--use-pack-code]
Needs: python 3.10+, cbor2, cryptography; `opentimestamps` only for the anchor check.
N-05: the checker imports its modules (svidetel_v4, wa_profile, registry_wa) ONLY from beside itself (or, in the source tree, from the
project layout). Code inside the PACK is never imported unless you pass --use-pack-code (then the pack is trusted as much as its author).
Get this script from a source you trust (wheel / published SHA-256), NOT from the pack you are checking; run it with `python -I`.
Output lines: ledger / receipts / checkpoints / registry / anchor ...; last line RESULT: VALID | RESULT: INVALID; exit 0 / 1."""
import glob
import hashlib
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def main(argv):
    """Never raises on bad input: any failure to read or parse the pack ends with a reason line and `RESULT: INVALID`, exit 1."""
    try:
        return _main(argv)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        raise
    except BaseException as e:      # noqa: BLE001  (RecursionError, MemoryError, OSError, ValueError ... on hostile files)
        return _invalid("unreadable or malformed pack (%s)" % type(e).__name__)


def _invalid(why):
    """The reason goes on its own line; the LAST line is always exactly `RESULT: INVALID`."""
    print("pack: %s" % why)
    print("RESULT: INVALID")
    return 1


def _read_json(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def _rb(path):
    with open(path, "rb") as f:
        return f.read()


def _main(argv):
    off = "--offline" in argv
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1 or not os.path.isdir(args[0]):
        print(__doc__)
        return 64
    root = os.path.abspath(args[0])
    dirs = [HERE]
    if "--use-pack-code" in argv:
        print("WARNING: --use-pack-code: executing verifier modules from the pack itself; the result is only as honest as the pack's author")
        dirs.insert(0, os.path.join(root, "verify"))
    else:       # source tree: server/packtools -> cloud/contract (wa_profile), server/app (registry_wa), project root (svidetel_v4)
        cloud = os.path.dirname(os.path.dirname(HERE))
        dirs += [os.path.join(cloud, "contract"), os.path.join(cloud, "server", "app"), os.path.dirname(cloud)]
    for i, d in enumerate(dirs):
        if os.path.isdir(d) and d not in sys.path:
            sys.path.insert(i, d)
    import cbor2  # noqa: F401
    try:        # verify/merklecache.py: same Merkle bytes as svidetel_v4.checkpoint, O(log n) per checkpoint instead of O(n); self-checks first
        import merklecache
        if not merklecache.install() and os.environ.get("DW_MERKLE_FAST", "1").lower() not in ("0", "off", "false", "no"):
            print("merkle: cache self-check FAILED, using the reference implementation (slow)")
    except ImportError:
        print("merkle: merklecache.py not found next to the pack's svidetel_v4, using the reference implementation (slow)")
    from svidetel_v4 import cose
    from svidetel_v4.checkpoint import merkle_root, verify_inclusion
    from svidetel_v4.verify import load_entries, verify_file
    from registry_wa import WaRegistry

    ok = True
    mp = os.path.join(root, "manifest.json")
    if not os.path.isfile(mp):
        print("manifest: MISSING manifest.json")
        return _invalid("no manifest.json")
    man = _read_json(mp)
    if not isinstance(man, dict) or not isinstance(man.get("files"), dict) or not isinstance(man.get("witness"), dict):
        print("manifest: malformed (need an object with files{} and witness{})")
        return _invalid("manifest malformed")
    # 0. manifest: every file hash
    bad = 0
    for p, h in man["files"].items():
        fp = os.path.abspath(os.path.join(root, p)) if isinstance(p, str) else None
        if fp is None or not fp.startswith(root + os.sep):
            print("manifest: PATH OUTSIDE PACK %r" % (p,)); bad += 1
        elif not os.path.isfile(fp):
            print("manifest: MISSING %s" % p); bad += 1
        elif hashlib.sha256(_rb(fp)).hexdigest() != h:
            print("manifest: MISMATCH %s" % p); bad += 1
    print("manifest: %s (%d files)" % ("ok" if not bad else "%d problems" % bad, len(man["files"])))
    ok &= not bad

    wk = cose.Key.public(cose.ALG_EDDSA, bytes.fromhex(man["witness"]["pub_hex"]))
    if wk.kid.hex() != man["witness"]["kid_hex"]:
        print("witness: kid does not match pub"); ok = False
    # N-04: the signed manifest (witness key) fixes the file hashes and the checkpoint the ledger must end with
    signed = None
    sp = os.path.join(root, "manifest.cose")
    if not os.path.isfile(sp):
        print("manifest: NOT SIGNED (manifest.cose missing: nothing says up to which entry the pack is complete)")
        ok = False
    else:
        try:
            signed = cose.loads(cose.verify1(_rb(sp), [wk], "application/deus-witness-pack-manifest+cbor")[0])
            if signed.get("files") != man["files"]:
                raise ValueError("files differ")
            print("manifest: signed by the witness key")
        except Exception:   # noqa: BLE001
            print("manifest: SIGNATURE INVALID (manifest.cose is not a witness signature over manifest.json)")
            signed = None
            ok = False
    rp = os.path.join(root, "registry.json")
    if not os.path.isfile(rp):
        print("registry: MISSING registry.json")
        return _invalid("no registry.json")
    reg_doc = _read_json(rp)
    if not isinstance(reg_doc, dict) or not isinstance(reg_doc.get("log"), list) or "principal" not in reg_doc or "entry" not in reg_doc:
        print("registry: malformed")
        return _invalid("registry malformed")
    principal, entry = reg_doc["principal"], reg_doc["entry"]
    registry = WaRegistry.for_account(principal, entry)

    # 1. registry log chain
    prev = b""
    chain_ok = True
    try:
        for r in reg_doc["log"]:
            if bytes.fromhex(r["prev"]) != prev:
                chain_ok = False
            if "entry_json" in r and hashlib.sha256(bytes.fromhex(r["prev"]) + r["entry_json"].encode()).hexdigest() != r["hash"]:
                chain_ok = False
            prev = bytes.fromhex(r["hash"])
        own = [r for r in reg_doc["log"] if "entry_json" in r]
        if not own or json.loads(own[-1]["entry_json"]) != entry:
            chain_ok = False
    except Exception:       # malformed log row: the chain cannot be confirmed
        chain_ok = False
    print("registry: %s (%d rows, head %s)" % ("chain ok" if chain_ok else "CHAIN BROKEN", len(reg_doc["log"]), (reg_doc.get("head") or "-")[:16]))
    ok &= chain_ok

    # 2. the ledger (A: svidetel_v4 verifier with the WebAuthn registry), against the newest checkpoint
    ledger_path = os.path.join(root, "ledger", "ledger.cose")
    cps = {}
    for p in glob.glob(os.path.join(root, "checkpoints", "*.cose")):
        stem = os.path.basename(p)[:-5]
        try:
            if not (stem.isascii() and stem.isdigit()):
                raise ValueError(stem)
            cps[int(stem)] = _rb(p)
        except (ValueError, OSError):
            print("checkpoint %s: INVALID (unreadable or not named <seq>.cose)" % os.path.basename(p))
            ok = False
    newest = cps[max(cps)] if cps else None
    if not os.path.isfile(ledger_path):
        print("ledger: MISSING ledger/ledger.cose")
        return _invalid("no ledger")
    try:
        r = verify_file(ledger_path, [wk], set(), registry, principal, checkpoint=newest, require_cose=True)
        entries = load_entries(ledger_path, [wk]) or []
    except Exception as e:  # noqa: BLE001  (garbage in the ledger file: hex, CBOR, encoding)
        r, entries = {"result": "invalid", "reason": "UNREADABLE_%s" % type(e).__name__}, []
    if signed is not None:
        last = entries[-1] if entries else None
        want = signed.get("cp_seq")
        if want is None:
            fine = not entries
        else:
            fine = last is not None and last["type"] == "CHECKPOINT" and last["body"].get("seq") == want and last["body"].get("head") == signed.get("cp_head")
        if fine:
            import datetime
            print("complete as of %s UTC (seq %s)" % (datetime.datetime.fromtimestamp(signed["created_t"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), want))
        else:
            print("pack: INCOMPLETE (the ledger does not end with the checkpoint the signed manifest names)")
            ok = False
    if r["result"] == "valid":
        print("ledger: valid (%d entries)" % len(entries))
    else:
        print("ledger: invalid %s@%s" % (r.get("reason"), r.get("at", "-")))
        ok = False
    # other checkpoints: signature, head and root must fit the entries
    for s, cp in sorted(cps.items()):
        try:
            c = cose.loads(cose.verify1(cp, [wk], cose.TYP_CHECKPOINT)[0])
            fine = c["seq"] < len(entries) and c["head"] == entries[c["seq"]]["hash"] and \
                c["root"] == merkle_root([e["hash"] for e in entries[:c["seq"] + 1]])
        except Exception:
            fine = False
        if not fine:
            print("checkpoint %d: INVALID" % s)
            ok = False
    print("checkpoints: %d" % len(cps))

    # 3. receipts: AAR signed by the witness and equal to the RECEIPT entry at chain.seq
    rc = sorted(glob.glob(os.path.join(root, "receipts", "*.aar.cose")))
    inc = 0
    for p in rc:
        rid = os.path.basename(p)[:-len(".aar.cose")]
        try:
            raw = _rb(p)
            aar = cose.loads(cose.verify1(raw, [wk], cose.TYP_AAR)[0])
            sub = cose.parse1(raw)[0][cose.H_CWT][cose.CWT_SUB]
            ch = aar["chain"]
            e = entries[ch["seq"]]
            if sub == rid and e["type"] == "RECEIPT" and e["body"]["id"] == rid and e["hash"] == ch["entry"] and e["witness_sig_valid"]:
                inc += 1
                continue
        except Exception:
            pass
        print("receipt %s: NOT INCLUDED" % rid)
    print("receipts: %d/%d included" % (inc, len(rc)))
    ok &= inc == len(rc)

    # 4. anchors
    leaves_of_cps = {hashlib.sha256(c).hexdigest() for c in cps.values()}
    for jp in sorted(glob.glob(os.path.join(root, "anchors", "*.json"))):
        b = os.path.basename(jp)[:-5]
        try:
            a = _read_json(jp)
            b = a["batch"]
            if not isinstance(b, str) or os.path.basename(b) != b:
                raise ValueError("batch")
            path = [(s, bytes.fromhex(h)) for s, h in a["path"]]
            bytes.fromhex(a["root"])
            good = a["leaf"] in leaves_of_cps and verify_inclusion(bytes.fromhex(a["leaf"]), path, bytes.fromhex(a["root"]), a["leaf_index"], a["size"])
        except Exception:   # anchor file with wrong types / missing keys
            print("anchor %s: MISMATCH (malformed anchor file)" % os.path.basename(jp))
            ok = False
            continue
        if not good:
            print("anchor %s: MISMATCH (checkpoint is not under the batch root)" % b)
            ok = False
            continue
        try:
            print("anchor %s: " % b + _ots(os.path.join(root, "anchors", b + ".ots"), a["root"], off))
        except Exception as e:  # noqa: BLE001  (corrupt .ots)
            print("anchor %s: MISMATCH (unreadable .ots: %s)" % (b, type(e).__name__))
            ok = False
            continue
        if "MISMATCH" in _last:
            ok = False
    print("RESULT: VALID" if ok else "RESULT: INVALID")
    return 0 if ok else 1


_last = ""


def _ots(path, root_hex, off):
    global _last
    if not os.path.exists(path):
        _last = "pending (inclusion in batch root proven; not stamped)"
        return _last
    try:
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
        from opentimestamps.core.serialize import StreamDeserializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile
    except ImportError:
        _last = "pending (opentimestamps not installed: proof file present, not checked)"
        return _last
    with open(path, "rb") as f:
        d = DetachedTimestampFile.deserialize(StreamDeserializationContext(f))
    if d.file_digest != bytes.fromhex(root_hex):
        _last = "MISMATCH (.ots commits to another digest)"
        return _last
    atts = []

    def walk(ts):
        for att in ts.attestations:
            atts.append((ts.msg, att))
        for _, sub in ts.ops.items():
            walk(sub)
    walk(d.timestamp)
    btc = [(m, a.height) for m, a in atts if isinstance(a, BitcoinBlockHeaderAttestation)]
    if not btc:
        _last = "pending"
        return _last
    msg, h = btc[0]
    if off:
        _last = "bitcoin block %d (offline: block header not cross-checked)" % h
        return _last
    res = {}
    for name, base in (("mempool.space", "https://mempool.space/api"), ("blockstream.info", "https://blockstream.info/api")):
        try:
            bh = urllib.request.urlopen("%s/block-height/%d" % (base, h), timeout=30).read().decode().strip()
            blk = json.load(urllib.request.urlopen("%s/block/%s" % (base, bh), timeout=30))
            res[name] = "OK" if bytes.fromhex(blk["merkle_root"])[::-1] == msg else "MISMATCH"
        except Exception:
            res[name] = "UNREACHABLE"
    _last = "bitcoin block %d (%s)" % (h, " ".join("%s=%s" % kv for kv in res.items()))
    if "MISMATCH" in res.values():
        _last = "MISMATCH " + _last
    return _last


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
