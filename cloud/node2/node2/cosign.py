"""Deus Witness node 2: an independent co-signer of node 1's journal heads (deus-node2-cosig-v1).

What it guarantees (and nothing more): for every ledger it has seen, node 2 co-signs a checkpoint only if the new Merkle tree
is an APPEND-ONLY extension of the last one it co-signed (RFC 9162 consistency proof) and the checkpoint is in the batch root.
A second checkpoint for the same ledger that is not an extension (fork, rollback, rewritten history) gets a SIGNED ALARM
carrying both checkpoints: self-contained evidence against node 1, checkable offline by anyone.

Deliberately self-contained (cbor2 + cryptography only, no import from the closed server) so that this file can be opened
for audit and its container image rebuilt by users (the image digest is what the SEV-SNP attestation pins).
Tree hashing = svidetel_v4/checkpoint.py: leaf = SHA256(0x00||entry_hash), node = SHA256(0x01||l||r), split = largest 2^k < n.
"""
import hashlib

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

SCHEME = "deus-node2-cosig-v1"
TYP_CHECKPOINT = "application/aar-checkpoint+cbor"
TYP_COSIG = "application/deus-node2-cosig+cbor"
TYP_ALARM = "application/deus-node2-alarm+cbor"
ALG_EDDSA = -8
H_ALG, H_KID, H_TYP = 1, 4, 16


class Reject(Exception):
    """str(e) = reason code. Rejections of the FEED (malformed, bad signature) are not alarms: node 1 can always send garbage."""


def sha256(b):
    return hashlib.sha256(b).digest()


# ---------- RFC 6962 / 9162 Merkle tree ----------
def _leaf(b): return sha256(b"\x00" + b)
def _node(l, r): return sha256(b"\x01" + l + r)


def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    if not leaves:
        return sha256(b"")
    if len(leaves) == 1:
        return _leaf(leaves[0])
    k = _split(len(leaves))
    return _node(mth(leaves[:k]), mth(leaves[k:]))


def consistency_proof(leaves, m):
    """RFC 6962 2.1.2 PROOF(m, D[n]). Node 1 needs this (server side, ~15 lines); here for tests and as the reference."""
    def sub(m, d, b):
        n = len(d)
        if m == n:
            return [] if b else [mth(d)]
        k = _split(n)
        if m <= k:
            return sub(m, d[:k], b) + [mth(d[k:])]
        return sub(m - k, d[k:], False) + [mth(d[:k])]
    if not 0 < m <= len(leaves):
        raise ValueError("bad m")
    return sub(m, list(leaves), True)


def verify_consistency(first, second, first_hash, second_hash, proof):
    """RFC 9162 2.1.4.2."""
    if first == second:
        return proof == [] and first_hash == second_hash
    if not 0 < first < second or not proof:
        return False
    if first & (first - 1) == 0:
        proof = [first_hash] + list(proof)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = _node(c, fr), _node(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_hash and sr == second_hash


# ---------- COSE_Sign1, Ed25519 only (RFC 9052; same bytes as svidetel_v4/cose.py) ----------
def thumbprint(pub):
    return sha256(cbor2.dumps({1: 1, -1: 6, -2: pub}, canonical=True))


def _sig_structure(pb, payload):
    return cbor2.dumps(["Signature1", pb, b"", payload], canonical=True)


def _plain(x):
    if isinstance(x, (list, tuple)):
        return [_plain(i) for i in x]
    if hasattr(x, "items") and not isinstance(x, (bytes, str)):
        return {k: _plain(v) for k, v in x.items()}
    return x


def cose_verify(data, pub, typ):
    """-> payload map. Pinned key, kid must be its thumbprint, alg EdDSA, typ exact, payload canonical CBOR."""
    try:
        t = cbor2.loads(data)
        assert isinstance(t, cbor2.CBORTag) and t.tag == 18 and len(t.value) == 4
        pb, _un, payload, sig = t.value
        prot = _plain(cbor2.loads(pb))
        assert cbor2.dumps(prot, canonical=True) == pb
    except Exception:  # noqa
        raise Reject("COSE_MALFORMED")
    if prot.get(H_ALG) != ALG_EDDSA or prot.get(H_KID) != thumbprint(pub):
        raise Reject("COSE_KEY")
    if prot.get(H_TYP) != typ:
        raise Reject("COSE_TYP")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, _sig_structure(pb, payload))
    except InvalidSignature:
        raise Reject("COSE_SIG")
    m = _plain(cbor2.loads(payload))
    if cbor2.dumps(m, canonical=True) != payload or not isinstance(m, dict):
        raise Reject("COSE_MALFORMED")
    return m


class Signer:
    """Ed25519 key. In production it is born in memory inside the SEV-SNP guest and never written anywhere (see attest.py)."""

    def __init__(self, priv=None):
        self.priv = priv or ed25519.Ed25519PrivateKey.generate()
        self.pub = self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.kid = thumbprint(self.pub)

    def sign(self, payload_map, typ):
        payload = cbor2.dumps(payload_map, canonical=True)
        pb = cbor2.dumps({H_ALG: ALG_EDDSA, H_KID: self.kid, H_TYP: typ}, canonical=True)
        sig = self.priv.sign(_sig_structure(pb, payload))
        return cbor2.dumps(cbor2.CBORTag(18, [pb, {}, payload, sig]), canonical=True)


# ---------- the co-signer ----------
class Cosigner:
    """State: per ledger the last co-signed (size, root, checkpoint bytes); the co-signature chain head (n, hash).
    feed(batch) -> ("cosig", bytes) | ("alarm", bytes). Raises Reject for a malformed or unsigned feed (no state change)."""

    def __init__(self, node1_pub, signer, state=None):
        self.k1, self.s = node1_pub, signer
        st = state or {}
        self.ledgers = dict(st.get("ledgers", {}))      # lid -> [size, root, cp]
        self.n, self.head = st.get("n", 0), st.get("head", b"\x00" * 32)
        self.last_t = st.get("last_t", 0)
        self.bids = set(st.get("bids", ()))
        self.link = st.get("link")                      # set by resume(): the previous instance this one continues
        self.alarms, self.alarm_head = st.get("alarms", 0), st.get("alarm_head", b"\x00" * 32)   # sticky: in every later cosig

    def _check(self, batch):
        try:
            bid, t, root = str(batch["bid"]), int(batch["t"]), bytes(batch["root"])
            leaves = [bytes(x) for x in batch["leaves"]]
            cps = list(batch["checkpoints"])
            extra = int(batch.get("extra", 0))          # trailing non-checkpoint leaves: registry, registry2 (jobs._anchor_once)
        except Exception:  # noqa
            raise Reject("FEED_MALFORMED")
        if mth(leaves) != root:                         # same tree as jobs._anchor_once / checkpoint.merkle_root
            raise Reject("BATCH_ROOT")
        if bid in self.bids:
            raise Reject("BATCH_REPLAY")
        if t < self.last_t:
            raise Reject("BATCH_TIME")
        if not 0 <= extra <= 2 or len(cps) != len(leaves) - extra:
            raise Reject("CP_MISSING")                  # every checkpoint under the root must be shown, or node 2 would co-sign unseen ones
        lset, seen, out = set(leaves[:len(leaves) - extra]), set(), []
        for c in cps:
            cp = bytes(c["cose"])
            if sha256(cp) not in lset:
                raise Reject("CP_NOT_IN_BATCH")
            m = cose_verify(cp, self.k1, TYP_CHECKPOINT)
            try:
                lid, size, croot, ct = bytes(m["ledger"]), int(m["seq"]) + 1, bytes(m["root"]), int(m["t"])
                proof = [bytes(p) for p in c.get("proof", [])]
            except Exception:  # noqa
                raise Reject("CP_MALFORMED")
            lset.discard(sha256(cp))
            if lid in seen:
                raise Reject("CP_DUPLICATE_LEDGER")
            seen.add(lid)
            out.append((lid, size, croot, cp, proof, ct))
        return bid, t, root, out

    def feed(self, batch):
        bid, t, root, cps = self._check(batch)
        for lid, size, croot, cp, proof, ct in cps:
            old = self.ledgers.get(lid)
            if old is None:
                continue                                # first sight (TOFU per ledger; the tenant's own receipts cover entries before)
            osize, oroot, ocp = old
            if size == osize and croot != oroot:
                why = "FORK"                            # same size, other tree: definitive proof, two signed checkpoints
            elif size < osize and ct >= cose_verify(ocp, self.k1, TYP_CHECKPOINT)["t"]:
                why = "ROLLBACK"                        # a smaller tree signed after a bigger one: definitive
            elif size < osize:                          # an OLDER smaller checkpoint: a replay, or a back-dated rewrite (stand 22.10)
                if verify_consistency(size, osize, croot, oroot, proof):
                    raise Reject("CP_STALE")            # proven prefix of what is already co-signed: garbage, not evidence
                why = "NOT_PROVEN_APPEND_ONLY"          # node 1 owes PROOF(size, osize); without it the pair is the evidence
            elif not verify_consistency(osize, size, oroot, croot, proof):
                why = "NOT_PROVEN_APPEND_ONLY"          # not a proof of a rewrite by itself: node 1 owes a valid proof (plan, sec. 4)
            else:
                continue
            al = self._alarm(bid, lid, ocp, cp, proof, why)
            self.alarms, self.alarm_head = self.alarms + 1, sha256(al)   # node 1 can drop the alarm, not the counter (stand 22.10)
            return "alarm", al
        for lid, size, croot, cp, _, _ in cps:
            self.ledgers[lid] = [size, croot, cp]
        self.bids.add(bid)
        self.last_t = t
        self.n += 1
        body = {"v": SCHEME, "n": self.n, "prev": self.head, "bid": bid, "t": t, "root": root,
                "cps": len(cps), "ledgers": len(self.ledgers), "state": self.state_digest(),
                "alarms": self.alarms, "alarm_head": self.alarm_head}
        if self.link and self.n == self.link["n"] + 1:
            body["link"] = self.link
        cs = self.s.sign(body, TYP_COSIG)
        self.head = sha256(cs)
        return "cosig", cs

    def _alarm(self, bid, lid, ocp, ncp, proof, why):
        return self.s.sign({"v": SCHEME, "alarm": why, "bid": bid, "ledger": lid, "before": ocp, "after": ncp,
                            "proof": proof, "head": self.head}, TYP_ALARM)

    # ---------- restart continuity: the key dies with the instance, the state does not ----------
    def snapshot(self):
        return {"ledgers": {k: list(v) for k, v in self.ledgers.items()}, "n": self.n, "head": self.head,
                "last_t": self.last_t, "bids": sorted(self.bids), "alarms": self.alarms, "alarm_head": self.alarm_head}

    def state_digest(self):
        led = sorted((k, v[0], v[1], sha256(v[2])) for k, v in self.ledgers.items())   # cp bytes too: they go into alarms
        return sha256(cbor2.dumps([led, self.last_t, self.alarms, self.alarm_head], canonical=True))

    @classmethod
    def resume(cls, node1_pub, signer, snap, last_cosig, old_pub):
        """A new instance (new key, new attestation) continues the chain of the old one. The caller has checked that the old
        key's attestation shows the SAME measurement (trust is in the code, not in a key). Node 1 holds the snapshot, so it
        could hand over an OLD one: that forks the co-signature chain at n and is visible to anyone holding a later cosig."""
        m = cose_verify(last_cosig, old_pub, TYP_COSIG)
        c = cls(node1_pub, signer, snap)
        if m["n"] != c.n or sha256(last_cosig) != c.head or m["state"] != c.state_digest():
            raise Reject("RESUME_MISMATCH")
        for lid, (size, root, cp) in c.ledgers.items():  # every stored checkpoint is node 1's and says what the state says
            p = cose_verify(cp, node1_pub, TYP_CHECKPOINT)
            if bytes(p["ledger"]) != lid or int(p["seq"]) + 1 != size or bytes(p["root"]) != root:
                raise Reject("RESUME_MISMATCH")
        c.link = {"n": c.n, "prev_key": old_pub, "prev_head": c.head}
        return c


def verify_cosig(cs, pub):
    return cose_verify(cs, pub, TYP_COSIG)


def covered(cs, node2_pub, leaves, cp):
    """User-side check: is MY checkpoint among the checkpoints node 2 inspected? The batch tree does not tag leaf kinds, so a
    checkpoint hidden in a trailing registry slot would hash into the root unseen: index must be < cps."""
    m = verify_cosig(cs, node2_pub)
    leaves = [bytes(x) for x in leaves]
    if mth(leaves) != m["root"]:
        return False
    h = sha256(cp)
    return any(x == h for x in leaves[:m["cps"]])


def verify_alarm(alarm, node2_pub, node1_pub):
    """Offline check of an alarm: both checkpoints are node 1's, same ledger, and NOT an append-only pair. -> reason."""
    m = cose_verify(alarm, node2_pub, TYP_ALARM)
    a = cose_verify(m["before"], node1_pub, TYP_CHECKPOINT)
    b = cose_verify(m["after"], node1_pub, TYP_CHECKPOINT)
    if a["ledger"] != b["ledger"] or a["ledger"] != m["ledger"]:
        raise Reject("ALARM_LEDGER")
    sa, sb = a["seq"] + 1, b["seq"] + 1
    if sa == sb:
        kind, ok = "FORK", a["root"] != b["root"]
    elif sb < sa and b["t"] >= a["t"]:
        kind, ok = "ROLLBACK", True
    elif sb < sa:                                       # older smaller checkpoint: evidence only if it is NOT a prefix
        kind, ok = "NOT_PROVEN_APPEND_ONLY", not verify_consistency(sb, sa, b["root"], a["root"], m["proof"])
    else:
        kind, ok = "NOT_PROVEN_APPEND_ONLY", not verify_consistency(sa, sb, a["root"], b["root"], m["proof"])
    if not ok or m["alarm"] != kind:
        raise Reject("ALARM_FALSE")
    return m["alarm"]


def verify_chain(chain, genesis, pin=None):
    """Client/auditor check of the co-signature chain (stand 22.10). chain = [(cosig, K2 pub), ...] from n=1 to the cosig that
    covers my checkpoint; genesis = SHA-256 of the first cosig, published once (OTS-stamped) and pinned in the verifier.
    A fresh node 2 instance without state (a genuine binary the operator started anew: TOFU on every ledger again) has no path
    to the genesis. A key change is allowed only with a link from the new instance. pin = (n, sha256(cosig)) the client saw
    earlier: an instance resumed from an OLD snapshot builds a valid-looking chain that differs from the pin (plan R1).
    The K2 keys themselves must be checked against their SEV-SNP attestation (attest.py), this function does not do it."""
    if not chain:
        raise Reject("CHAIN_EMPTY")
    prev = pm = None
    by_n = {}
    for cs, pub in chain:
        m = verify_cosig(cs, pub)
        h = sha256(cs)
        if prev is None:
            if m["n"] != 1 or m["prev"] != b"\x00" * 32 or h != genesis:
                raise Reject("CHAIN_GENESIS")
        else:
            pcs, ppub = prev
            if m["n"] != pm["n"] + 1 or m["prev"] != sha256(pcs):
                raise Reject("CHAIN_BREAK")
            if pub != ppub and m.get("link") != {"n": pm["n"], "prev_key": ppub, "prev_head": sha256(pcs)}:
                raise Reject("CHAIN_LINK")
            if m.get("alarms", 0) < pm.get("alarms", 0):
                raise Reject("CHAIN_ALARMS")
        by_n[m["n"]] = h
        prev, pm = (cs, pub), m
    if pin is not None and by_n.get(pin[0]) != pin[1]:
        raise Reject("CHAIN_PIN")                       # the chain I am shown is not the one I saw before (or is shorter)
    return pm
