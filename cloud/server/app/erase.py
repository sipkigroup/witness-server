"""0.2.34 (PROEKT-CRYPTO-SHREDDING-2026-10-24, scheme V): erase the journal of a deleted account, keep only its hash skeleton.

Deleting an account used to leave data/ledgers/<id>/ledger.cose as it was: recipients, mandate lists and args_sha256 in clear text.
Now, under the account's journal lock and before the database rows go:
  1. the witness writes a last signed CHECKPOINT (the same one the anchor job would write) and the checkpoints row is stored;
  2. ledger.skeleton.cbor = {v, lid, n, hashes[0..n-1], checkpoint (COSE_Sign1), erased_t} replaces the journal (temp file, fsync, rename);
  3. after the database transaction (accounts.erased_at set) ledger.cose and every other file of the directory are removed.
A skeleton proves that entries existed and what their hashes were (inclusion RFC 9162 and consistency for node 2 are built from the hashes),
not what they said. Packs issued earlier are self-contained and stay VALID. A crash between the steps leaves the journal or the skeleton
or both; recover() (start-up) settles it by accounts.erased_at: set = finish the removal, not set = the skeleton is dropped, the journal lives.
The anchor job takes the digest of the erase checkpoint from the checkpoints table (batch_id NULL until anchored)."""
import hashlib
import hmac
import os
import secrets

import cbor2

SKELETON = "ledger.skeleton.cbor"
V = "dw-skeleton-1"


def skeleton_path(hub, aid):
    return os.path.join(hub.ledger_dir(aid), SKELETON)


def load_skeleton(hub, aid):
    """-> the skeleton dict {v, lid, n, hashes, checkpoint, erased_t} or None."""
    try:
        with open(skeleton_path(hub, aid), "rb") as f:
            d = cbor2.loads(f.read())
    except (OSError, ValueError, cbor2.CBORDecodeError):
        return None
    if not isinstance(d, dict) or d.get("v") != V or not isinstance(d.get("hashes"), list) or d.get("n") != len(d["hashes"]):
        return None
    return d


def _fsync_dir(d):
    fd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare(ctx, aid, t):
    """Caller holds hub.lock(aid). Writes the checkpoint and the skeleton (atomically) while the journal still exists.
    -> None (nothing to erase / already erased) or {"cose": checkpoint, "seq", "nseq", "n"} for the checkpoints row."""
    hub = ctx.hub
    if ctx.db.one("SELECT erased_at FROM accounts WHERE id=?", (aid,))["erased_at"] is not None:
        return None
    if not hub.has_entries(aid):
        return None
    from app.actions import materialize_proofs
    from app.jobs import _cp
    materialize_proofs(ctx, aid)
    L = hub.ledger(aid)
    L.sync_now()
    seq, cp = _cp(L)
    sk = {"v": V, "lid": L.lid, "n": len(L.hashes), "hashes": [bytes(h) for h in L.hashes], "checkpoint": cp, "erased_t": t}
    d = hub.ledger_dir(aid)
    tmp = os.path.join(d, SKELETON + ".tmp")
    with open(tmp, "wb") as f:
        f.write(cbor2.dumps(sk, canonical=True))
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, os.path.join(d, SKELETON))
    _fsync_dir(d)
    return {"cose": cp, "seq": seq, "nseq": L.S.nseq, "n": sk["n"]}


def store_checkpoint(db, aid, info, t):
    """Inside the delete transaction: the erase checkpoint, waiting for the next anchor batch."""
    db.x("INSERT INTO checkpoints(account_id,seq,cose,digest,t,batch_id,ledger_nseq) VALUES(?,?,?,?,?,?,?)",
         (aid, info["seq"], info["cose"], hashlib.sha256(info["cose"]).digest(), t, None, info["nseq"]))


def finish(ctx, aid):
    """After the transaction: remove the journal (and the lock file and anything else) next to the skeleton. Idempotent."""
    d = ctx.hub.ledger_dir(aid)
    if not os.path.isfile(os.path.join(d, SKELETON)):
        return
    for name in os.listdir(d):
        if name != SKELETON:
            try:
                os.remove(os.path.join(d, name))
            except IsADirectoryError:
                pass
    _fsync_dir(d)
    ctx.hub.forget(aid)
    scrub_db(ctx)


def scrub_db(ctx):
    """The rows of the deleted account are gone from the tables; fold the WAL into the main file and empty it, so that the deleted pages are
    not left behind in db.sqlite-wal (freed pages themselves are zeroed by PRAGMA secure_delete=ON, set in app/db.py)."""
    try:
        with ctx.db.lock:
            ctx.db.c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except Exception:  # noqa: BLE001  -- best effort: the erase itself is done
        pass


def recover(ctx):
    """Start-up: settle a crash between prepare() and finish(). -> number of directories touched."""
    root, n = ctx.hub.root, 0
    if not os.path.isdir(root):
        return 0
    for aid in sorted(os.listdir(root)):
        d = os.path.join(root, aid)
        if not os.path.isfile(os.path.join(d, SKELETON)) or len(aid) != 32:
            continue
        acc = ctx.db.one("SELECT erased_at FROM accounts WHERE id=?", (aid,))
        has_journal = os.path.isfile(os.path.join(d, "ledger.cose"))
        if acc is not None and acc["erased_at"] is not None:
            if os.listdir(d) != [SKELETON]:
                finish(ctx, aid)
                n += 1
        elif has_journal:                       # the delete did not commit: the journal is the truth, the skeleton goes
            os.remove(os.path.join(d, SKELETON))
            n += 1
    return n


# ---- salt of args_sha256 (DW_ARGS_SALT=on) ----
def account_salt(ctx, aid):
    """32 random bytes of the account (created on first use, destroyed with the account). The hash of the call arguments in the signed
    action is HMAC(salt, canonical [tool, args]) instead of a bare SHA-256, so a guess of the arguments cannot be tested without the salt.
    The salt lives in the database only (accounts.args_salt), never in the journal; deleting the account NULLs it."""
    r = ctx.db.one("SELECT args_salt, erased_at FROM accounts WHERE id=?", (aid,))
    if r is None or r["erased_at"] is not None:
        return None
    if r["args_salt"] is None:
        ctx.db.x("UPDATE accounts SET args_salt=? WHERE id=? AND args_salt IS NULL", (secrets.token_bytes(32), aid))
        r = ctx.db.one("SELECT args_salt FROM accounts WHERE id=?", (aid,))
    return bytes(r["args_salt"])


def salt_for(ctx, aid, capable=True):
    """0.2.35, DW_ARGS_SALT=off|transition|on. `capable`: the client announced header X-DW-Args-Salt (deus-witness >= 0.2.26: it fetches
    GET /v1/salt and hashes with it). off: None (bare SHA-256, what deployed clients check). transition: the salt for a capable client,
    None (bare) for an old one, so nothing breaks while clients are updated. on: the salt; an old client is refused (426) before anything
    is decided or written, since it could never check the receipt."""
    mode = getattr(ctx.cfg, "args_salt", "off")
    if mode == "off":
        return None
    if mode == "transition" and not capable:
        return None
    if mode == "on" and not capable:
        from app.context import Err
        raise Err(426, "ARGS_SALT_REQUIRED", "this witness salts args_sha256; update deus-witness to 0.2.26 or later")
    return account_salt(ctx, aid)


def salted(salt, canonical: bytes) -> str:
    return hmac.new(salt, b"dw-args1\0" + canonical, hashlib.sha256).hexdigest()
