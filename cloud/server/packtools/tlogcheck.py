#!/usr/bin/env python3
"""Deus Witness public log of anchor batches (r0269): OFFLINE checks a third party runs without trusting the witness.
Self-contained: Python 3.10+ and `cryptography` only (no import from the server), so it ships next to verify_pack.py in a pack.

What lives here
- RFC 9162 Merkle trees: MTH, inclusion proofs (2.1.3), consistency proofs (2.1.4). Same hashing as svidetel_v4/checkpoint.py
  (leaf = SHA-256(0x00 || data), node = SHA-256(0x01 || l || r), split = largest power of two below n).
- C2SP signed notes (c2sp.org/signed-note) and tlog checkpoints (c2sp.org/tlog-checkpoint): parse, sign, verify; vkeys;
  Ed25519 log signatures (type 0x01) and timestamped Ed25519 checkpoint cosignatures (type 0x04, c2sp.org/tlog-cosignature),
  so a second, independent witness (c2sp.org/tlog-witness) can co-sign later without a format change.
- Strict Ed25519: RFC 8032 decoding (non-canonical A or R rejected, S < L), small-order A or R rejected; NOT ZIP-215.
  OpenSSL (pyca/cryptography) alone accepts a non-canonical A (ed25519-speccheck case 11), hence the pre-checks.
- Split view: two validly signed checkpoints of one origin and one size with different roots = proof of a fork.

CLI (exit 0 = OK, 1 = not proven / pending / not checked (the package `cryptography` is missing: one line says what to install),
     2 = INVALID, 3 = FORK proven, 64 = usage)
  tlogcheck.py checkpoint  <note> <vkey>                          signature of the log over the checkpoint
  tlogcheck.py inclusion   <note> <vkey> <proof.json>             {"index", "size", "leaf_b64", "path": [b64...]}
  tlogcheck.py consistency <old note> <new note> <vkey> <proof.json>  {"old", "new", "path": [b64...]}
  tlogcheck.py fork        <note A> <note B> <vkey>               3 when both verify, same origin and size, different roots
"""
import base64
import hashlib
import json
import sys

# ------------------------------------------------------------------ strict Ed25519 (RFC 8032 5.1.3 decoding + 5.1.7 checks)
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _decode_point(b):
    """RFC 8032 5.1.3: 32 bytes -> (x, y) or None. Rejects y >= p and x = 0 with the sign bit set (both are non-canonical)."""
    if len(b) != 32:
        return None
    n = int.from_bytes(b, "little")
    sign, y = n >> 255, n & ((1 << 255) - 1)
    if y >= _P:
        return None
    u, v = (y * y - 1) % _P, (_D * y * y + 1) % _P
    x2 = u * pow(v, _P - 2, _P) % _P
    if x2 == 0:
        if sign:
            return None
        return 0, y
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
        if (x * x - x2) % _P:
            return None
    if (x & 1) != sign:
        x = _P - x
    return x, y


def _add(p1, p2):
    (x1, y1), (x2, y2) = p1, p2
    t = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, _P - 2, _P) % _P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, _P - 2, _P) % _P
    return x3, y3


def small_order(pt):
    """[8]P == identity (the 8 points of the torsion subgroup: a key or R there makes a signature valid for many messages)."""
    q = pt
    for _ in range(3):
        q = _add(q, q)
    return q == (0, 1)


def ed25519_verify_strict(pub, sig, msg):
    """-> True/False. RFC 8032 strict: |A| = 32, |sig| = 64, S < L, A and R canonical points, neither of small order, then the
    cofactorless equation (OpenSSL). Never raises on hostile input."""
    try:
        pub, sig, msg = bytes(pub), bytes(sig), bytes(msg)
    except (TypeError, ValueError):
        return False
    if len(pub) != 32 or len(sig) != 64:
        return False
    if int.from_bytes(sig[32:], "little") >= _L:
        return False
    a, r = _decode_point(pub), _decode_point(sig[:32])
    if a is None or r is None or small_order(a) or small_order(r):
        return False
    InvalidSignature, Ed25519PublicKey = _ed25519()
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


NEED_CRYPTOGRAPHY = ("tlogcheck.py needs the Python package `cryptography` to check Ed25519 signatures, and it is not installed for "
                     "%s.\nInstall it:   %s -m pip install cryptography\nor run without installing:   uv run --with cryptography "
                     "python3 tlogcheck.py ...")


class MissingCryptography(RuntimeError):
    """r0271 (ISPYTANIE-0266 Н4): `cryptography` is not importable. Not INVALID: nothing was checked."""


def _ed25519():
    # r0271: before, the import sat inside the try whose except named InvalidSignature: without the package the checker died with
    # UnboundLocalError and a traceback. Now: one plain sentence (what to install, how) and exit 1 "not proven" from the CLI.
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as ex:
        raise MissingCryptography(NEED_CRYPTOGRAPHY % (sys.executable, sys.executable)) from ex
    return InvalidSignature, Ed25519PublicKey


# ------------------------------------------------------------------ RFC 9162 Merkle tree
def _h(b):
    return hashlib.sha256(b).digest()


def leaf_hash(data):
    return _h(b"\x00" + bytes(data))


def node_hash(left, right):
    return _h(b"\x01" + left + right)


def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


class Tree:
    """Leaf hashes in memory; subtree roots memoised by (start, end). Proofs per RFC 9162 2.1.3.1 and 2.1.4.1."""

    def __init__(self, leaf_hashes=()):
        self.lh = list(leaf_hashes)
        self._memo = {}

    def append(self, lh):
        self.lh.append(lh)

    def __len__(self):
        return len(self.lh)

    def root(self, start=0, end=None):
        end = len(self.lh) if end is None else end
        n = end - start
        if n == 0:
            return _h(b"")
        if n == 1:
            return self.lh[start]
        key = (start, end)
        r = self._memo.get(key)
        if r is None:
            k = _split(n)
            r = node_hash(self.root(start, start + k), self.root(start + k, end))
            if n & (n - 1) == 0:                     # only complete subtrees are final (a growing right edge changes)
                self._memo[key] = r
        return r

    def inclusion(self, index, size):
        if not 0 <= index < size <= len(self.lh):
            raise ValueError("index/size out of range")

        def path(m, s, e):
            n = e - s
            if n == 1:
                return []
            k = _split(n)
            if m < k:
                return path(m, s, s + k) + [self.root(s + k, e)]
            return path(m - k, s + k, e) + [self.root(s, s + k)]
        return path(index, 0, size)

    def consistency(self, old, new):
        if not 0 <= old <= new <= len(self.lh):
            raise ValueError("sizes out of range")
        if old == 0 or old == new:
            return []

        def sub(m, s, e, b):
            n = e - s
            if m == n:
                return [] if b else [self.root(s, e)]
            k = _split(n)
            if m <= k:
                return sub(m, s, s + k, b) + [self.root(s + k, e)]
            return sub(m - k, s + k, e, False) + [self.root(s, s + k)]
        return sub(old, 0, new, True)


def verify_inclusion(lh, index, size, path, root):
    """RFC 9162 2.1.3.2."""
    if not (isinstance(index, int) and isinstance(size, int)) or index < 0 or index >= size:
        return False
    fn, sn, r = index, size - 1, lh
    for p in path:
        if len(p) != 32 or sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while True:
                    fn >>= 1
                    sn >>= 1
                    if fn & 1 or fn == 0:
                        break
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(old, new, old_root, new_root, path):
    """RFC 9162 2.1.4.2 (old == new: empty proof and equal roots; old == 0: empty proof, anything is an extension of nothing)."""
    if not (isinstance(old, int) and isinstance(new, int)) or old < 0 or old > new:
        return False
    if old == new:
        return not path and old_root == new_root
    if old == 0:
        return not path
    if not path or any(len(p) != 32 for p in path):
        return False
    path = list(path)
    if old & (old - 1) == 0:
        path = [old_root] + path
    fn, sn = old - 1, new - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            if not fn & 1:
                while True:
                    fn >>= 1
                    sn >>= 1
                    if fn & 1 or fn == 0:
                        break
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0


# ------------------------------------------------------------------ C2SP signed note / checkpoint
ALG_ED25519 = 0x01
ALG_COSIG_ED25519 = 0x04
# r0286 (crypto agility, POSTKVANT-1311): the C2SP key types this checker VERIFIES. Any other type byte (e.g. a future ML-DSA key) is
# parsed and kept with supported=False: its signatures are "cannot check" -- never counted as verified, never a crash.
SIG_ALGS = {ALG_ED25519: "Ed25519", ALG_COSIG_ED25519: "Ed25519 timestamped cosignature"}
MAX_NOTE = 1 << 16
MAX_SIGS = 32
EM = "— "


class NoteError(ValueError):
    pass


class NoteUnsupported(NoteError):
    """r0286: the note is signed only by known keys whose algorithm this checker cannot verify: "cannot check", not "verified"."""


def b64e(b):
    return base64.b64encode(bytes(b)).decode()


def b64d(s):
    """Canonical standard base64 with padding (RFC 4648 3.5): decode, re-encode, compare."""
    try:
        b = base64.b64decode(s, validate=True)
    except (ValueError, TypeError):
        raise NoteError("bad base64")
    if base64.b64encode(b).decode() != s:
        raise NoteError("non-canonical base64")
    return b


def _valid_name(n):
    return bool(n) and len(n.encode()) <= 255 and not any(c.isspace() or c == "+" or ord(c) < 0x20 for c in n)


def key_id(name, alg, pub):
    return hashlib.sha256(name.encode() + b"\n" + bytes([alg]) + bytes(pub)).digest()[:4]


def vkey(name, pub, alg=ALG_ED25519):
    return "%s+%s+%s" % (name, key_id(name, alg, pub).hex(), b64e(bytes([alg]) + bytes(pub)))


def parse_vkey(s):
    """-> {name, id (4 bytes), alg, pub}. Raises NoteError."""
    parts = str(s).strip().split("+", 2)
    if len(parts) != 3 or not _valid_name(parts[0]) or len(parts[1]) != 8:
        raise NoteError("bad vkey")
    try:
        kid = bytes.fromhex(parts[1])
    except ValueError:
        raise NoteError("bad vkey id")
    raw = b64d(parts[2])
    if len(raw) < 2 or (raw[0] in SIG_ALGS and len(raw) != 33):
        raise NoteError("bad vkey length")
    if key_id(parts[0], raw[0], raw[1:]) != kid:
        raise NoteError("vkey id does not match its key")
    return {"name": parts[0], "id": kid, "alg": raw[0], "pub": raw[1:], "supported": raw[0] in SIG_ALGS}


def parse_note(note):
    """-> (text, [(name, id4, sigbytes)]). Text ends with a newline; signatures after the LAST blank line. Raises NoteError."""
    if isinstance(note, (bytes, bytearray)):
        if len(note) > MAX_NOTE:
            raise NoteError("note too large")
        try:
            note = bytes(note).decode("utf-8")
        except UnicodeDecodeError:
            raise NoteError("not UTF-8")
    if len(note.encode()) > MAX_NOTE:
        raise NoteError("note too large")
    if any(ord(c) < 0x20 and c != "\n" for c in note):
        raise NoteError("control character")
    i = note.rfind("\n\n")
    if i < 0 or not note.endswith("\n"):
        raise NoteError("no signature block")
    text, block = note[:i + 1], note[i + 2:]
    sigs = []
    for line in block[:-1].split("\n"):
        if not line.startswith(EM):
            raise NoteError("bad signature line")
        name, sep, b = line[len(EM):].rpartition(" ")
        if not sep or not _valid_name(name):
            raise NoteError("bad key name")
        raw = b64d(b)
        if len(raw) < 5:
            raise NoteError("short signature")
        sigs.append((name, raw[:4], raw[4:]))
    if not sigs or len(sigs) > MAX_SIGS:
        raise NoteError("signature count")
    if len({(n, k) for n, k, _ in sigs}) != len(sigs):
        raise NoteError("duplicate key name and id")
    return text, sigs


def sign_line(name, alg, pub, sig):
    return EM + name + " " + b64e(key_id(name, alg, pub) + sig) + "\n"


def make_note(text, lines):
    if not text.endswith("\n"):
        raise NoteError("text must end with a newline")
    return text + "\n" + "".join(lines)


def cosig_message(text, t):
    return ("cosignature/v1\ntime %d\n" % int(t)).encode() + text.encode()


def verify_note(note, vkeys, now=None):
    """c2sp signed-note rules: unknown keys ignored; a known key (name AND id) MUST verify, else the note is rejected; at least one
    known key must verify. -> {"text", "signers": [name...], "cosig_times": {name: t}, "unverifiable": [name...]}. Raises NoteError;
    NoteUnsupported (r0286) when the only known keys that signed have an algorithm this checker does not verify (SIG_ALGS)."""
    text, sigs = parse_note(note)
    keys = [k if isinstance(k, dict) else parse_vkey(k) for k in vkeys]
    signers, times, unverifiable = [], {}, []
    for name, kid, sig in sigs:
        k = next((x for x in keys if x["name"] == name and x["id"] == kid), None)
        if k is None:
            continue
        if k["alg"] not in SIG_ALGS:          # r0286: a known key of an algorithm this checker cannot verify: said, not counted
            unverifiable.append(name)
            continue
        if k["alg"] == ALG_ED25519:
            ok = ed25519_verify_strict(k["pub"], sig, text.encode())
        else:
            if len(sig) != 72:
                raise NoteError("bad cosignature length")
            t = int.from_bytes(sig[:8], "big")
            if now is not None and t > now + 300:
                raise NoteError("cosignature from the future")
            ok = ed25519_verify_strict(k["pub"], sig[8:], cosig_message(text, t))
            if ok:
                times[name] = t
        if not ok:
            raise NoteError("signature of a known key does not verify: " + name)
        signers.append(name)
    if not signers:
        if unverifiable:
            raise NoteUnsupported("cannot check: signed only by key(s) of an algorithm this checker does not verify (%s): %s"
                                  % (", ".join(SIG_ALGS.values()), ", ".join(unverifiable)))
        raise NoteError("no signature of a known key")
    return {"text": text, "signers": signers, "cosig_times": times, "unverifiable": unverifiable}


def checkpoint_text(origin, size, root, ext=()):
    if not _valid_name(origin):
        raise NoteError("bad origin")
    lines = [origin, str(int(size)), b64e(root)] + [e for e in ext]
    if any(not x or "\n" in x for x in lines):
        raise NoteError("empty or multi-line checkpoint line")
    return "\n".join(lines) + "\n"


def parse_checkpoint(text):
    """-> {origin, size, root (32 bytes), ext}. Decimal with no leading zeros, canonical base64 of 32 bytes."""
    lines = text.split("\n")
    if len(lines) < 4 or lines[-1] != "" or any(x == "" for x in lines[:-1]):
        raise NoteError("checkpoint needs >= 3 non-empty lines")
    origin, size, root = lines[0], lines[1], lines[2]
    if not _valid_name(origin):
        raise NoteError("bad origin")
    if not size.isdigit() or (size != "0" and size.startswith("0")) or len(size) > 20:
        raise NoteError("bad tree size")
    r = b64d(root)
    if len(r) != 32:
        raise NoteError("root is not 32 bytes")
    return {"origin": origin, "size": int(size), "root": r, "ext": lines[3:-1]}


def open_checkpoint(note, vkeys, origin=None, now=None):
    """verify_note + parse_checkpoint (+ the expected origin). -> parsed checkpoint with "signers", "cosig_times". Raises NoteError."""
    v = verify_note(note, vkeys, now)
    cp = parse_checkpoint(v["text"])
    if origin is not None and cp["origin"] != origin:
        raise NoteError("origin mismatch")
    cp["signers"], cp["cosig_times"], cp["text"] = v["signers"], v["cosig_times"], v["text"]
    return cp


def fork(cp_a, cp_b):
    """Split view (RFC 9162 11.3 / c2sp tlog-checkpoint): one origin, one size, two roots. Inputs: opened checkpoints."""
    return cp_a["origin"] == cp_b["origin"] and cp_a["size"] == cp_b["size"] and cp_a["root"] != cp_b["root"]


# ------------------------------------------------------------------ batch leaves of the Deus Witness log
LEAF_V = "deus-witness/batch/v1"


def batch_leaf(batch_id, root):
    """The log entry for one anchor batch: text, no account ids (the batch's own leaves stay in the account's pack)."""
    if not batch_id or "\n" in batch_id or len(root) != 32:
        raise ValueError("bad batch")
    return ("%s\n%s\n%s\n" % (LEAF_V, batch_id, bytes(root).hex())).encode()


def parse_batch_leaf(data):
    parts = bytes(data).decode("utf-8").split("\n")
    if len(parts) != 4 or parts[0] != LEAF_V or parts[3] != "":
        raise ValueError("not a batch leaf")
    return parts[1], bytes.fromhex(parts[2])


# r0312: one leaf per published version of the public constitution (web/constitution.html, packtools/constitution_check.py). Same log,
# same signature: a later silent edit of a version's text no longer matches the hash the witness signed into the log.
CONST_LEAF_V = "deus-witness/constitution/v1"


def constitution_leaf(version, sha256_hex):
    v = int(version)
    h = str(sha256_hex)
    if v < 1 or len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
        raise ValueError("bad constitution version")
    return ("%s\n%d\n%s\n" % (CONST_LEAF_V, v, h)).encode()


def parse_constitution_leaf(data):
    """-> (version, sha256 hex); ValueError if the leaf is not a constitution leaf."""
    try:
        parts = bytes(data).decode("utf-8").split("\n")
    except UnicodeDecodeError:
        raise ValueError("not a constitution leaf")
    if len(parts) != 4 or parts[0] != CONST_LEAF_V or parts[3] != "" or not parts[1].isdigit():
        raise ValueError("not a constitution leaf")
    if constitution_leaf(int(parts[1]), parts[2]) != bytes(data):
        raise ValueError("not a canonical constitution leaf")
    return int(parts[1]), parts[2]


def stamp_digest(note_text):
    """What the daily external stamp (OpenTimestamps / RFC 3161) commits to: SHA-256 of the checkpoint TEXT (origin, size, root)."""
    return hashlib.sha256(note_text.encode() if isinstance(note_text, str) else note_text).digest()


# ------------------------------------------------------------------ CLI
def _read(p):
    with open(p, "rb") as f:
        return f.read()


def _cli(a):
    try:
        if len(a) == 3 and a[0] == "checkpoint":
            cp = open_checkpoint(_read(a[1]), [_read(a[2]).decode()])
            print("checkpoint OK: %s size %d root %s signed by %s" % (cp["origin"], cp["size"], cp["root"].hex(), ", ".join(cp["signers"])))
            return 0
        if len(a) == 4 and a[0] == "inclusion":
            cp = open_checkpoint(_read(a[1]), [_read(a[2]).decode()])
            pr = json.loads(_read(a[3]))
            if pr["size"] != cp["size"]:
                print("INVALID: proof is for size %d, checkpoint has %d" % (pr["size"], cp["size"]))
                return 2
            ok = verify_inclusion(leaf_hash(b64d(pr["leaf_b64"])), pr["index"], pr["size"], [b64d(x) for x in pr["path"]], cp["root"])
            print(("inclusion OK: leaf %d of %d" if ok else "INVALID inclusion: leaf %d of %d") % (pr["index"], pr["size"]))
            return 0 if ok else 2
        if len(a) == 5 and a[0] == "consistency":
            k = [_read(a[3]).decode()]
            o, n = open_checkpoint(_read(a[1]), k), open_checkpoint(_read(a[2]), k)
            pr = json.loads(_read(a[4]))
            if o["origin"] != n["origin"] or pr["old"] != o["size"] or pr["new"] != n["size"]:
                print("INVALID: proof sizes or origins do not match the checkpoints")
                return 2
            ok = verify_consistency(o["size"], n["size"], o["root"], n["root"], [b64d(x) for x in pr["path"]])
            print(("consistency OK: %d -> %d" if ok else "FORK or INVALID: no consistency %d -> %d") % (o["size"], n["size"]))
            return 0 if ok else 3
        if len(a) == 4 and a[0] == "fork":
            k = [_read(a[3]).decode()]
            x, y = open_checkpoint(_read(a[1]), k), open_checkpoint(_read(a[2]), k)
            if fork(x, y):
                print("FORK PROVEN: %s size %d has two signed roots %s / %s" % (x["origin"], x["size"], x["root"].hex(), y["root"].hex()))
                return 3
            print("no fork shown by these two checkpoints (different sizes need a consistency proof)")
            return 1
    except MissingCryptography as e:
        print("NOT CHECKED: %s" % e, file=sys.stderr)
        return 1
    except (NoteError, ValueError, KeyError, OSError) as e:
        print("INVALID: %s" % e)
        return 2
    print(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
