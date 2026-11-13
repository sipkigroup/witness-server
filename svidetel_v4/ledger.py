"""Mandate ledger on disk (Section 7): append-only file of hex(COSE_Sign1) lines, SHA-256 hash chain,
linearizable writes via an exclusive file lock (flock) on <dir>/ledger.lock, state rebuilt from the file by every
instance before every operation (no state in process memory that is not derivable from the file).
Crash safety: a trailing partial line (no newline) is a never-acknowledged write and is truncated under the lock."""
import contextlib
import fcntl
import os
import time

import cbor2

from . import cose
from .cose import sha256
from .schema import validate_allowance, validate_ceiling, validate_mandate
from .state import (State, params_hash, allowance_payload, approval_payload, ceiling_payload, mandate_hash, request_hash, request_map,
                    revocation_payload)


class LedgerCorrupt(Exception):
    pass


class Ledger:
    def __init__(self, dirpath, witness_key: cose.Key, registry, principal, clock=time.time,
                 operator="operator-unknown", independence="separate-party", require_cose=False):
        self.dir, self.wk, self.reg, self.principal = dirpath, witness_key, registry, principal
        self.clock, self.operator, self.independence = clock, operator, independence
        self.require_cose = require_cose        # real mode: principal objects MUST arrive as COSE_Sign1 (no symbolic keys)
        self._frozen = None
        os.makedirs(dirpath, exist_ok=True)
        self.path = os.path.join(dirpath, "ledger.cose")
        self.lockpath = os.path.join(dirpath, "ledger.lock")
        open(self.path, "ab").close()
        self.lid = sha256(b"deus-aar/ledger/" + principal.encode() + witness_key.kid)
        self.S, self.off, self.head = State(), 0, None
        self.hashes, self.raws, self.rseq, self.aseq = [], [], {}, {}

    # ---------- plumbing ----------
    @contextlib.contextmanager
    def _tx(self):
        with open(self.lockpath, "a+") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            try:
                self._catch_up()
                self._frozen = int(self.clock())      # one witness timestamp per transaction
                self._sweep()
                yield
            finally:
                self._frozen = None
                fcntl.flock(lk, fcntl.LOCK_UN)

    def _catch_up(self):
        with open(self.path, "r+b") as f:
            f.seek(self.off)
            data = f.read()
            if not data:
                return
            parts = data.split(b"\n")
            tail = parts.pop()
            if tail:                       # partial, never acknowledged
                f.truncate(self.off + len(data) - len(tail))
            for line in parts:
                self._ingest(bytes.fromhex(line.decode()))
                self.off += len(line) + 1

    def _ingest(self, raw: bytes):
        try:
            payload, _ = cose.verify1(raw, [self.wk], cose.TYP_ENTRY)
        except cose.CoseError as e:
            raise LedgerCorrupt("WITNESS_SIG: %s" % e)
        e = cose.loads(payload)
        if e["seq"] != self.S.nseq or e["prev"] != self.head or e["ledger"] != self.lid:
            raise LedgerCorrupt("CHAIN_BREAK at %s" % e["seq"])
        if e["t"] < self.S.last_t:                              # -04 (C3-1): the `t` of an entry is not less than the previous one
            raise LedgerCorrupt("CHAIN_BREAK at %s (t)" % e["seq"])
        if e["type"] == "RECEIPT":
            self.rseq[e["body"]["id"]] = e["seq"]
        if e["type"] == "APPROVAL" and e["body"].get("approved", True):
            self.aseq[e["body"]["receipt"]] = e["seq"]
        self.S.apply(e["type"], e["body"], e["t"])
        self.head = sha256(raw)
        self.hashes.append(self.head)
        self.raws.append(raw)

    def now(self):
        return max(self.S.last_t, self._frozen if self._frozen is not None else int(self.clock()))

    def _sweep(self):
        """Section 7.4: explicit RELEASE (cause expired) for every active reservation whose AAR expired."""
        now = self.now()
        for rid, r in list(self.S.res.items()):
            if r["state"] == "active" and now > r["expires"]:
                self._append("RELEASE", {"receipt": rid, "cause": "expired"})

    def sync_now(self):
        with self._tx():
            return self.now()

    def _append(self, typ, body):
        t = self.now()
        e = {"ledger": self.lid, "seq": self.S.nseq, "prev": self.head, "t": t, "type": typ, "body": body}
        raw = cose.sign1(self.wk, cbor2.dumps(e, canonical=True), cose.TYP_ENTRY)
        line = raw.hex().encode() + b"\n"
        with open(self.path, "ab") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        self.off += len(line)
        if typ == "RECEIPT":
            self.rseq[body["id"]] = self.S.nseq
        if typ == "APPROVAL" and body.get("approved", True):
            self.aseq[body["receipt"]] = self.S.nseq
        self.S.apply(typ, body, t)
        self.head = sha256(raw)
        self.hashes.append(self.head)
        self.raws.append(raw)
        return t

    # ---------- operations (return dicts shaped like the reference model's steps) ----------
    def register_mandate(self, mandate, signed_by=None, cose_bytes=None):
        with self._tx():
            if mandate.get("id") in self.S.mandates:
                return {"result": "reject", "reason": "MANDATE_EXISTS"}
            bad = validate_mandate(mandate)
            if bad or mandate["principal"] != self.principal or (self.S.currency is not None and mandate["currency"] != self.S.currency):
                return {"result": "reject", "reason": "MANDATE_MALFORMED"}      # -03 (C2-10): principal of the ledger, one currency per ledger
            if self.require_cose and cose_bytes is None:
                return {"result": "reject", "reason": "NO_SIGNATURE"}
            why = self.reg.check(mandate["principal"], signed_by, cose_bytes,
                                 cbor2.dumps(mandate, canonical=True) if cose_bytes is not None else None, cose.TYP_MANDATE)
            if why:
                return {"result": "reject", "reason": why}
            body = {"mandate": mandate, "signed_by": signed_by, "pin": {"source": self.reg.source, "principal": mandate["principal"]}}
            if cose_bytes is not None:
                body["cose"] = cose_bytes
            self._append("MANDATE", body)
            return {"result": "accept"}

    def register_ceiling(self, amount, signed_by=None, cose_bytes=None, window_s=None, currency=None, cid=None):
        """-02 Section 6.3: {id, amount, currency, window_s} are REQUIRED (no default window): else CEILING_MALFORMED."""
        with self._tx():
            cid = cid or "ceiling-%d" % self.S.nseq
            if validate_ceiling({"id": cid, "amount": amount, "currency": currency, "window_s": window_s}) or (
                    self.S.currency is None or currency != self.S.currency):
                return {"result": "reject", "reason": "CEILING_MALFORMED"}      # -03 (C2-10): the ceiling is in the currency of the ledger; -04 (C3-2): the ledger has one only after its first MANDATE
            if self.require_cose and cose_bytes is None:
                return {"result": "reject", "reason": "NO_SIGNATURE"}
            why = self.reg.check(self.principal, signed_by, cose_bytes,
                                 ceiling_payload(self.principal, cid, amount, currency, window_s) if cose_bytes is not None else None,
                                 cose.TYP_CEILING)
            if why:
                return {"result": "reject", "reason": why}
            body = {"id": cid, "amount": amount, "currency": currency, "window_s": window_s, "signed_by": signed_by}
            if cose_bytes is not None:
                body["cose"] = cose_bytes
            self._append("CEILING", body)
            return {"result": "accept"}

    def revoke(self, mid, signed_by=None, cose_bytes=None):
        """Section 6.7: REVOCATION entry; outstanding reservations of the mandate are released (cause revoked) right after."""
        with self._tx():
            M = self.S.mandates.get(mid)
            if M is None:
                return {"result": "reject", "reason": "MANDATE_UNKNOWN"}
            if self.require_cose and cose_bytes is None:
                return {"result": "reject", "reason": "NO_SIGNATURE"}
            why = self.reg.check(M["principal"], signed_by, cose_bytes,
                                 revocation_payload(M) if cose_bytes is not None else None, cose.TYP_REVOCATION)
            if why:
                return {"result": "reject", "reason": why}
            body = {"mandate": mid, "signed_by": signed_by}
            if cose_bytes is not None:
                body["cose"] = cose_bytes
            self._append("REVOCATION", body)
            for rid, r in list(self.S.res.items()):
                if r["mandate"] == mid and r["state"] == "active":
                    self._append("RELEASE", {"receipt": rid, "cause": "revoked"})
            return {"result": "accept"}

    def register_allowance(self, mid, allowance, signed_by=None, cose_bytes=None):
        """PROPOSAL-07: ALLOWANCE entry. The principal signs the allowance map (typ application/aar-allowance+cbor); it extends the ACTIVE
        mandate `mid` whose hash it names. -> {"result": "accept", "seq"} | {"result": "reject", "reason"}."""
        with self._tx():
            M = self.S.mandates.get(mid)
            if M is None:
                return {"result": "reject", "reason": "MANDATE_UNKNOWN"}
            if mid in self.S.revoked or not (M["nbf"] <= self.now() <= M["exp"]):
                return {"result": "reject", "reason": "EXPIRED"}
            if validate_allowance(allowance) or allowance["mandate"] != mandate_hash(M) or allowance["id"] in self.S.allowances:
                return {"result": "reject", "reason": "ALLOWANCE_MALFORMED"}
            if self.require_cose and cose_bytes is None:
                return {"result": "reject", "reason": "NO_SIGNATURE"}
            why = self.reg.check(M["principal"], signed_by, cose_bytes, allowance_payload(allowance) if cose_bytes is not None else None,
                                 cose.TYP_ALLOWANCE)
            if why:
                return {"result": "reject", "reason": "ALLOWANCE_SIG" if why == "MANDATE_SIG" else why}
            body = {"allowance": allowance, "mandate": mid, "signed_by": signed_by}
            if cose_bytes is not None:
                body["cose"] = cose_bytes
            self._append("ALLOWANCE", body)
            return {"result": "accept", "seq": self.S.nseq - 1}

    def end_allowance(self, aid, cause="revoked"):
        """PROPOSAL-07: ALLOWANCE_END (the principal revoked it in one click). It only narrows what the mandate allows, so it is the witness's
        record and carries no principal signature (as a RELEASE). -> {"result": "accept", "seq"} | {"result": "reject", "reason"}."""
        with self._tx():
            g = self.S.allowances.get(aid)
            if g is None:
                return {"result": "reject", "reason": "ALLOWANCE_UNKNOWN"}
            if g["ended"]:
                return {"result": "reject", "reason": "ALLOWANCE_ENDED"}
            self._append("ALLOWANCE_END", {"allowance": aid, "cause": cause})
            return {"result": "accept", "seq": self.S.nseq - 1}

    def authorize(self, rid, mid, action, ttl=300, audience="tool"):
        """-> {"verdict","reason","aar": COSE bytes or None}"""
        with self._tx():
            if rid in self.S.receipts:
                raise ValueError("DUPLICATE_RECEIPT_ID")
            now = self.now()
            a, v, why = self.S.decide_for(mid, action, now)
            M = self.S.mandates.get(mid)
            body = {"id": rid, "mandate": mid, "action": a, "verdict": v, "reason": why, "ttl": ttl, "audience": audience}
            currency = M["currency"] if M else None
            if M is None:               # Section 8.2: the refusal is logged; no AAR (nothing to reference)
                self._append("RECEIPT", body)
                return {"verdict": v, "reason": why, "aar": None}
            before = (self.S.committed(now, mid, M.get("budget_window_s", 86400)),
                      self.S.committed(now, None, self.S.ceiling_window))
            t = self._append("RECEIPT", body)
            aar = self._aar(rid, M, a, v, why, ttl, audience, currency, t, before)
            return {"verdict": v, "reason": why, "aar": aar}

    def _principal_kid(self, principal):
        k = self.reg.key(principal)
        return k.kid if k is not None else sha256(principal.encode())

    def _aar(self, rid, M, a, v, why, ttl, audience, currency, t, before):
        from .decide import risk
        pm = M["permissions"].get("purchase") or {}
        monetary = a["class"] == "purchase" and v in ("allow", "defer")
        aar = {"spec": "deus-aar/0.1", "independence": self.independence, "operator": self.operator, "audience": audience,
               "action": {"class": a["class"], "agent": a["agent"], "recipient": a.get("recipient", ""),
                          "data": list(a.get("data", [])), "amount": a.get("amount", 0), "currency": currency,
                          "params_hash": params_hash(a),
                          "binding_request_hash": request_hash(a)},
               "mandate": {"ref": mandate_hash(M), "principal_kid": self._principal_kid(M["principal"]),
                           "key_attestation": M.get("key_attestation", "software")},
               "verdict": {"decision": v, "reason": why, "risk": risk(a)},
               "expires": t + ttl,
               "chain": {"ledger": self.lid, "seq": self.S.nseq - 1, "entry": self.head}}
        if why == "OK_ALLOWANCE":                   # PROPOSAL-07: which principal-signed ALLOWANCE entry let it through (as approved_by names the APPROVAL)
            g = self.S.allowances[a["allowance"]]
            aar["mandate"]["allowed_by"] = {"alg": "sha-256", "digest": self.hashes[g["seq"]], "id": a["allowance"], "exp": g["exp"]}
        if monetary:
            aar["budget"] = {"reservation_id": rid.encode(), "reserved": a["amount"], "committed_before": before[0],
                             "limit": pm.get("budget"), "principal_committed_before": before[1], "ceiling": self.S.ceiling,
                             "window_s": M.get("budget_window_s", 86400)}
        return cose.sign1(self.wk, cbor2.dumps(aar, canonical=True), cose.TYP_AAR,
                          cwt={cose.CWT_ISS: "witness:" + self.wk.kid.hex(), cose.CWT_SUB: rid, cose.CWT_IAT: t})

    def approve(self, rid, signed_by=None, cose_bytes=None, approved=True, issue_aar=False, view=None):
        """Section 6.6: the principal decides over {v, t=approval, mandate hash, action hash, approved}.
        pv2810: view (32 bytes) = the presentation hash the principal signed with it; it is recorded in the APPROVAL body."""
        with self._tx():
            rc = self.S.receipts[rid]
            M = self.S.mandates[rc["mandate"]]
            principal = M["principal"]
            if self.require_cose and cose_bytes is None:
                return {"result": "reject", "reason": "NO_SIGNATURE"}
            why = self.reg.check(principal, signed_by, cose_bytes,
                                 approval_payload(M, rc["action"], rid, approved, view) if cose_bytes is not None else None, cose.TYP_APPROVAL)
            if why:
                return {"result": "reject", "reason": "APPROVAL_SIG"}
            if rc["verdict"] != "defer" or rid in self.S.refused or self.now() > rc["expires"] or rc["mandate"] in self.S.revoked:     # -02 (C-23): also after the deferral timeout
                return {"result": "reject", "reason": "NOT_DEFERRED"}
            body = {"receipt": rid, "approved": approved, "signed_by": signed_by}
            if view is not None:
                body["view"] = view
            if cose_bytes is not None:
                body["cose"] = cose_bytes
            self._append("APPROVAL", body)
            if not approved:
                r = self.S.res.get(rid)
                if r is not None and r["state"] == "active":
                    self._append("RELEASE", {"receipt": rid, "cause": "refused"})
                return {"result": "accept", "verdict": "refused"}
            if issue_aar:
                return {"result": "accept", "verdict": "allow", "aar": self._aar_approved(rid)}
            return {"result": "accept", "verdict": "allow"}

    def _aar_approved(self, rid):
        """-02 Section 6.6 (C-6): the allow AAR after an approval has the SAME sub (= receipt id) and a chain that names the DEFERRED RECEIPT entry;
        `expires` is the RECEIPT's own expires (an approval does not extend it); `approved_by` is the hash of the APPROVAL entry; reason OK_APPROVED."""
        from .decide import risk
        rc = self.S.receipts[rid]
        M = self.S.mandates[rc["mandate"]]
        a = rc["action"]
        s = self.rseq[rid]
        t_r = cose.loads(cose.verify1(self.raws[s], [self.wk], cose.TYP_ENTRY)[0])["t"]
        win = M.get("budget_window_s", 86400)
        res = self.S.res.get(rid)
        aar = {"spec": "deus-aar/0.1", "independence": self.independence, "operator": self.operator, "audience": rc["audience"],
               "action": {"class": a["class"], "agent": a["agent"], "recipient": a.get("recipient", ""),
                          "data": list(a.get("data", [])), "amount": a.get("amount", 0), "currency": M["currency"],
                          "params_hash": params_hash(a), "binding_request_hash": request_hash(a)},
               "mandate": {"ref": mandate_hash(M), "principal_kid": self._principal_kid(M["principal"]),
                           "key_attestation": M.get("key_attestation", "software"),
                           "approved_by": {"alg": "sha-256", "digest": self.hashes[self.aseq[rid]]}},
               "verdict": {"decision": "allow", "reason": "OK_APPROVED", "risk": risk(a)},
               "expires": rc["expires"],
               "chain": {"ledger": self.lid, "seq": s, "entry": self.hashes[s]}}
        if res is not None:
            pm = M["permissions"].get("purchase") or {}
            aar["budget"] = {"reservation_id": rid.encode(), "reserved": a["amount"],
                             "committed_before": self.S.committed(t_r, rc["mandate"], win, before_seq=s), "limit": pm.get("budget"),
                             "principal_committed_before": self.S.committed(t_r, None, self.S.ceiling_window, before_seq=s),
                             "ceiling": self.S.ceiling, "window_s": win}
        return cose.sign1(self.wk, cbor2.dumps(aar, canonical=True), cose.TYP_AAR,
                          cwt={cose.CWT_ISS: "witness:" + self.wk.kid.hex(), cose.CWT_SUB: rid, cose.CWT_IAT: self.now()})

    def tool_present(self, rid, tool=None, request=None):
        with self._tx():
            rc = self.S.receipts.get(rid) if rid is not None else None
            aud_ok = True
            if rc is not None and tool is not None:
                aud_ok = (self._audience(rid) == tool)
            bh = request_hash(request) if request is not None else None
            why = self.S.check_present(rid, self.now(), aud_ok, bh)
            if why:
                return {"result": "reject", "reason": why}
            self._append("CONSUME", {"receipt": rid})
            return {"result": "accept"}

    def _audience(self, rid):
        return self.S.receipts[rid].get("audience") or None

    def tool_report(self, rid, executed):
        with self._tx():
            r = self.S.res.get(rid)
            if not executed and r is not None and self.S._eff(r, self.now()) == "active":
                self._append("RELEASE", {"receipt": rid, "cause": "tool_not_executed"})
                return {"result": "released"}
            return {"result": "ignored"}            # -03 (Appendix A convention 7): nothing active to release

    def agent_report(self, rid, executed):
        return {"result": "ignored"}            # Section 7.4: agent statements never release

    def checkpoint(self):
        """Append a CHECKPOINT entry and return the Section 9.1 checkpoint payload bytes of the head BEFORE it."""
        from .checkpoint import checkpoint_payload
        with self._tx():
            seq, head = self.S.nseq - 1, self.head
            t = self.now()
            from .checkpoint import merkle_root
            self._append("CHECKPOINT", {"seq": seq, "head": head, "root": merkle_root(self.hashes[:seq + 1])})
            return checkpoint_payload(self.lid, seq, head, t)

    # ---------- signed checkpoints and inclusion proofs (Sections 8.4(9), 9.1, 12.6) ----------
    def _checkpoint_locked(self):
        from .checkpoint import checkpoint_payload, merkle_root
        seq, head, t = self.S.nseq - 1, self.head, self.now()
        root = merkle_root(self.hashes[:seq + 1])
        self._append("CHECKPOINT", {"seq": seq, "head": head, "root": root})
        payload = cbor2.dumps({"ledger": self.lid, "seq": seq, "head": head, "t": t, "root": root}, canonical=True)
        return seq, cose.sign1(self.wk, payload, cose.TYP_CHECKPOINT)

    def checkpoint_signed(self):
        """COSE_Sign1 checkpoint {ledger, seq, head, t, root} over entries 0..seq (Merkle root of entry hashes)."""
        with self._tx():
            return self._checkpoint_locked()[1]

    def promise(self, seq, mmd=600):
        """-05 Section 9.5: signed inclusion promise for the entry at `seq` (COSE_Sign1, typ application/aar-inclusion-promise+cbor):
        the witness commits to an anchored checkpoint covering this entry not later than entry t + mmd (mmd <= 3600)."""
        from .state import PROMISE_MAX_MMD
        if not (isinstance(mmd, int) and 0 <= mmd <= PROMISE_MAX_MMD) or not 0 <= seq < len(self.raws):
            raise ValueError("PROMISE_MALFORMED")
        e = cose.loads(cose.verify1(self.raws[seq], [self.wk], cose.TYP_ENTRY)[0])
        p = {"v": "deus-aar-0.1", "t": "promise", "ledger": self.lid, "seq": seq, "entry": self.hashes[seq], "entry_t": e["t"], "mmd": mmd}
        return cose.sign1(self.wk, cbor2.dumps(p, canonical=True), cose.TYP_PROMISE)

    def receipt_proof(self, rid, approval=False):
        """Inclusion proof for the RECEIPT entry of `rid` in a fresh signed checkpoint (an ON-DEMAND inclusion checkpoint, -02 Section 9.1.1),
        or None if never logged. approval=True (AAR issued after an approval): the proof also carries the APPROVAL entry and its path."""
        from .checkpoint import inclusion_path
        with self._tx():
            if rid not in self.rseq or (approval and rid not in self.aseq):
                return None
            s = self.rseq[rid]
            cpseq, cpb = self._checkpoint_locked()
            pr = {"entry": self.raws[s], "path": inclusion_path(self.hashes[:cpseq + 1], s), "checkpoint": cpb}
            if approval:
                a = self.aseq[rid]
                pr["approval"] = {"entry": self.raws[a], "path": inclusion_path(self.hashes[:cpseq + 1], a)}
            return pr
