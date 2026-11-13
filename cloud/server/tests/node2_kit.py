"""0.2.27 test kit: node 1 (the real server) + node 2 (the real worker, fake AMD) + the operator adversary who edits the SQLite database
directly with the witness key in hand. Used by tests/test_0227_node2.py and by the L2 stand (cloud/node2/stend/stend_l2.py)."""
import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import time
import zipfile

import cbor2

from app import _paths  # noqa: F401
from svidetel_v4 import cose
from svidetel_v4.checkpoint import merkle_root

from node2 import cosign as C, fakeamd, worker as W

SEED = "a1" * 32                         # the witness key of the test configs (conftest.py, RUN.md): the adversary holds it
TOKEN = "node2-test-token-" + "q" * 32
H = lambda b: hashlib.sha256(b).digest()


def witness_key(seed=SEED):
    return cose.Key.from_seed(cose.ALG_EDDSA, bytes.fromhex(seed))


def client_http(client, token=TOKEN):
    """worker http over a Starlette TestClient (same requests the urllib client sends)."""
    def call(method, path, body=None):
        r = client.request(method, path, json=body, headers={"Authorization": "Bearer " + token})
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, None
    return call


def make_worker(http, node1_pub, amd=None, policy=fakeamd.RESTRICTIVE_POLICY, **kw):
    amd = amd or fakeamd.FakeAmd()
    w = W.Worker(http, node1_pub, amd.provider(policy=policy, **kw), {"policy": policy, "vcek": amd.vcek_der(), "chain": amd.chain_pem()},
                 log=lambda *a: None)
    w.amd = amd
    return w


def unpack(zip_bytes, dest):
    zipfile.ZipFile(io.BytesIO(zip_bytes)).extractall(dest)
    return str(dest)


def verify(folder, *flags, checker=None):
    """python -I <the pack's own checker> <folder> --offline [flags] -> (rc, stdout, node2 line or None)."""
    p = subprocess.run([sys.executable, "-I", checker or os.path.join(folder, "verify", "verify_pack.py"), str(folder), "--offline", *flags],
                       capture_output=True, text=True)
    n2 = next((ln for ln in p.stdout.splitlines() if ln.startswith("node2:") and ("COVERED" in ln or "ALARM" in ln or "cannot" in ln)), None)
    return p.returncode, p.stdout, n2


# ---------------------------------------------------------------- the adversary: node 1's operator, SQLite + the witness key

class Adversary:
    def __init__(self, db_path, seed=SEED):
        self.db_path, self.k = db_path, witness_key(seed)

    def _c(self):
        c = sqlite3.connect(self.db_path, timeout=30)
        c.row_factory = sqlite3.Row
        return c

    def lid(self, account_id):
        with self._c() as c:
            p = c.execute("SELECT principal FROM accounts WHERE id=?", (account_id,)).fetchone()["principal"]
        return H(b"deus-aar/ledger/" + p.encode() + self.k.kid)

    def sign_cp(self, lid, hashes, t=None):
        root = merkle_root(hashes)
        p = cbor2.dumps({"ledger": lid, "seq": len(hashes) - 1, "head": hashes[-1], "t": int(t or time.time()), "root": root}, canonical=True)
        return cose.sign1(self.k, p, cose.TYP_CHECKPOINT)

    def last_t(self):
        with self._c() as c:
            r = c.execute("SELECT MAX(t) AS t FROM anchor_batches").fetchone()
        return max(r["t"] or 0, int(time.time()) - 1)

    def insert_batch(self, items, t=None, extra_leaves=()):
        """items: [(account_id, cp bytes, kind)] -> batch id. Writes checkpoints + anchor_batches rows exactly as jobs._anchor_once does."""
        t = t or self.last_t() + 1
        leaves = [{"account": a, "kind": kind, "leaf": H(cp).hex()} for a, cp, kind in items]
        with self._c() as c:
            head = c.execute("SELECT hash FROM registry_log ORDER BY seq DESC LIMIT 1").fetchone()
            leaves += list(extra_leaves) or ([{"account": None, "kind": "registry", "leaf": bytes(head["hash"]).hex()}] if head else [])
            root = merkle_root([bytes.fromhex(x["leaf"]) for x in leaves])
            bid = "%s-%s" % (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(t)), root.hex()[:8])
            for a, cp, kind in items:
                seq = cose.loads(cose.verify1(cp, [self.k], cose.TYP_CHECKPOINT)[0])["seq"]
                c.execute("INSERT INTO checkpoints(account_id,seq,cose,digest,t,batch_id,ledger_nseq) VALUES(?,?,?,?,?,?,?)",
                          (a, seq, cp, H(cp), t, bid, seq + 1))
            c.execute("INSERT INTO anchor_batches(id,t,root,leaves_json,registry_head,status,block_height,checked_json) VALUES(?,?,?,?,?,?,?,?)",
                      (bid, t, root, json.dumps(leaves), bytes(head["hash"]) if head else None, "off", None, None))
        return bid

    def fork(self, account_id, hashes, size):
        """same size as node 2 co-signed, last entry replaced"""
        forged = list(hashes[:size - 1]) + [os.urandom(32)]
        return self.insert_batch([(account_id, self.sign_cp(self.lid(account_id), forged), "checkpoint")])

    def rollback(self, account_id, hashes, size, cut=2):
        return self.insert_batch([(account_id, self.sign_cp(self.lid(account_id), list(hashes[:size - cut]), t=time.time() + 5), "checkpoint")])

    def hidden_slot(self, account_id, hashes, other_items=()):
        """a rewritten, grown history of the victim hidden in the trailing registry slot; node 2 is not shown the victim at all"""
        forged = list(hashes)
        forged[1] = os.urandom(32)
        forged += [os.urandom(32) for _ in range(3)]
        cp = self.sign_cp(self.lid(account_id), forged)
        with self._c() as c:
            head = c.execute("SELECT hash FROM registry_log ORDER BY seq DESC LIMIT 1").fetchone()
        extra = [{"account": account_id, "kind": "registry", "leaf": H(cp).hex()}, {"account": None, "kind": "registry2", "leaf": bytes(head["hash"]).hex()}]
        t = self.last_t() + 1
        leaves = [{"account": a, "kind": k, "leaf": H(x).hex()} for a, x, k in other_items] + extra
        root = merkle_root([bytes.fromhex(x["leaf"]) for x in leaves])
        bid = "%s-%s" % (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(t)), root.hex()[:8])
        with self._c() as c:
            seq = len(forged) - 1
            c.execute("INSERT INTO checkpoints(account_id,seq,cose,digest,t,batch_id,ledger_nseq) VALUES(?,?,?,?,?,?,?)", (account_id, seq, cp, H(cp), t, bid, seq + 1))
            c.execute("INSERT INTO anchor_batches(id,t,root,leaves_json,registry_head,status,block_height,checked_json) VALUES(?,?,?,?,?,?,?,?)",
                      (bid, t, root, json.dumps(leaves), bytes(head["hash"]), "off", None, None))
        return bid, cp

    def delete_batches(self, bids):
        """drop anchor batches (and the checkpoint rows under them) as if they never happened"""
        with self._c() as c:
            for b in bids:
                c.execute("DELETE FROM checkpoints WHERE batch_id=?", (b,))
                c.execute("DELETE FROM anchor_batches WHERE id=?", (b,))

    def delete_alarms(self):
        with self._c() as c:
            return c.execute("DELETE FROM node2_sigs WHERE kind='alarm'").rowcount

    def snapshot_rows(self):
        with self._c() as c:
            st = c.execute("SELECT * FROM node2_state").fetchone()
            sigs = [dict(r) for r in c.execute("SELECT * FROM node2_sigs ORDER BY id")]
        return dict(st), sigs

    def restore_old_state(self, state, keep_n):
        """put back an OLD node 2 snapshot and drop the co-signatures after it (the operator restarts node 2 from it)"""
        with self._c() as c:
            c.execute("DELETE FROM node2_sigs WHERE kind='cosig' AND n>?", (keep_n,))
            c.execute("UPDATE node2_state SET snapshot=?, last_hash=? WHERE id=1", (state["snapshot"], state["last_hash"]))


def rewrite_ledger_file(path, seed=SEED, at=2, smart=False):
    """Rewrite entry `at` of a journal FILE (its body gets a field) and re-sign every entry after it with the witness key: a journal whose
    signatures and hash chain are valid but whose history differs. smart=True also recomputes the CHECKPOINT entries' head/root after `at`
    (the pack checker would otherwise see CHECKPOINT_HEAD). The server must be stopped (or the hub cache dropped) to read it."""
    k = witness_key(seed)
    lines = [ln for ln in open(path, "rb").read().split(b"\n") if ln]
    out, hs, prev = [], [], None
    for i, ln in enumerate(lines):
        raw = bytes.fromhex(ln.decode())
        e = cose.loads(cose.verify1(raw, [k], cose.TYP_ENTRY)[0])
        if i == at:
            e["body"] = dict(e["body"], rewritten=1)
        if i >= at:
            if smart and e["type"] == "CHECKPOINT" and e["body"]["seq"] >= at:
                b = e["body"]
                e["body"] = dict(b, head=hs[b["seq"]], root=merkle_root(hs[:b["seq"] + 1]))
            e["prev"] = prev
            raw = cose.sign1(k, cbor2.dumps(e, canonical=True), cose.TYP_ENTRY)
        prev = H(raw)
        hs.append(prev)
        out.append(raw.hex().encode())
    with open(path, "wb") as f:
        f.write(b"\n".join(out) + b"\n")
    return hs


def resign_receipts(db_path, account_id, hashes, seed=SEED):
    """The operator re-signs the stored receipts (AAR) so that chain.entry matches the rewritten journal -> number re-signed."""
    k = witness_key(seed)
    n = 0
    with sqlite3.connect(db_path, timeout=30) as c:
        for rid, aar in c.execute("SELECT rid, aar FROM actions WHERE account_id=? AND aar IS NOT NULL", (account_id,)).fetchall():
            prot = cose.parse1(bytes(aar))[0]
            p = cose.loads(cose.verify1(bytes(aar), [k], cose.TYP_AAR)[0])
            s_ = p["chain"]["seq"]
            if s_ < len(hashes) and p["chain"]["entry"] != hashes[s_]:
                p["chain"]["entry"] = hashes[s_]
                new = cose.sign1(k, cbor2.dumps(p, canonical=True), cose.TYP_AAR, cwt=prot[cose.H_CWT])
                c.execute("UPDATE actions SET aar=? WHERE rid=?", (new, rid))
                n += 1
    return n
