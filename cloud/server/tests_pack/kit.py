"""Helpers of tests_pack: team keys and policies, quorum/batch envelopes, a ledger written DIRECTLY through the core
(svidetel_v4.Ledger + QuorumRegistry, no server), a pack assembled with the same functions as app/export.py, the checker run."""
import hashlib
import json
import os
import subprocess
import sys

import cbor2

from app import _paths
from app import export
import wa_profile as wa
import wq_profile as q
from registry_wq import QuorumRegistry
from svidetel_v4 import cose
from svidetel_v4.ledger import Ledger

SERVER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKER = os.path.join(SERVER, "packtools", "verify_pack.py")
TSA_PORT = 8812
cde = wa.cde


def auth(name):
    """Deterministic test passkey (same derivation as contract/v02/gen_vectors02.py)."""
    n = int.from_bytes(hashlib.sha256(b"deus-wq-test-key-" + name.encode()).digest(), "big") % (wa.P256_N - 1) + 1
    return wa.SoftAuthenticator(private_int=n, credential_id=hashlib.sha256(b"cred-" + name.encode()).digest())


def member(a, roles, label):
    return {"kid": a.kid, "pub": a.pub, "cred": a.credential_id, "roles": list(roles), "label": label}


def members(*ms):
    return sorted(ms, key=lambda m: m["kid"])


TIERS = [{"if": "money", "role": "budget", "k": 1}, {"if": "money_over", "amount": 50000, "role": "budget", "k": 2},
         {"if": "access", "role": "access", "k": 1}]
RULES = {"policy": {"role": "owner", "k": 1}, "mandate": TIERS, "approval": TIERS,
         "revocation": {"role": "any", "k": 1}, "ceiling": {"role": "owner", "k": 1}}
SOLO_RULES = {"policy": {"role": "owner", "k": 1}, "mandate": [], "approval": [], "revocation": {"role": "any", "k": 1},
              "ceiling": {"role": "owner", "k": 1}}


def pol(principal, ver, prev_map, ms, rules=RULES):
    return {"v": q.V_POLICY, "principal": principal, "ver": ver, "prev": q.policy_hash(prev_map) if prev_map else None,
            "members": ms, "rules": rules}


class Team:
    """Signing side of an organisation: keys by name, rp/origin of the passkeys."""

    def __init__(self, auths, rp_id, origin):
        self.A, self.rp_id, self.origin = auths, rp_id, origin
        self.rp = {"rp_id": rp_id, "origins": [origin]}

    def wa(self, name, typ, payload):
        return self.A[name].sign_object(typ, payload, self.rp_id, self.origin)

    def wsig(self, name, typ, payload):
        a = self.A[name]
        ad, cd, der = a.get_assertion(wa.challenge(typ, payload), self.rp_id, self.origin)
        return q.make_wsig(a.kid, ad, cd, der)

    def wq(self, names, typ, payload, policy_map):
        return q.make_wq(typ, payload, q.policy_hash(policy_map), [self.wsig(n, typ, payload) for n in names])

    def wb(self, name, payloads):
        a = self.A[name]
        items = [hashlib.sha256(p).digest() for p in payloads]
        ad, cd, der = a.get_assertion(q.wb_challenge(items), self.rp_id, self.origin)
        return q.make_wb(items, a.kid, ad, cd, der)

    def chain(self, versions):
        """versions: [(policy_map, signer names, t)] -> (chain [(bytes, env, t)], export_org policies)."""
        chain, pols, prev = [], [], None
        for i, (p, names, t) in enumerate(versions):
            pb = cde(p)
            env = self.wa(names[0], q.TYP_POLICY, pb) if i == 0 else self.wq(names, q.TYP_POLICY, pb, prev)
            chain.append((pb, env, t))
            pols.append({"ver": i + 1, "policy": pb, "envelope": env, "t": t, "registry_seq": None})
            prev = p
        return chain, pols


def team_ledger(dirpath, wk, principal, entry, chain, rp, clock):
    return Ledger(dirpath, wk, QuorumRegistry.for_account(principal, entry, chain, rp), principal, clock=clock, require_cose=True)


def registry_doc(principal, entry):
    ej = json.dumps(entry, sort_keys=True)
    return {"principal": principal, "entry": entry, "head": None,
            "log": [{"seq": 1, "prev": "", "hash": hashlib.sha256(ej.encode()).hexdigest(), "entry_json": ej}]}


def write_pack(dest, wk, principal, entry, L, org=None, extra=None, t=1792000000):
    """Pack of a ledger written through the core, assembled with app.export functions (org_files, verify_files, seal)."""
    with L._tx():
        seq, cp = L._checkpoint_locked()
        payload = cose.loads(cose.verify1(cp, [wk], cose.TYP_CHECKPOINT)[0])
    with open(L.path, "rb") as f:
        led = f.read()
    reg = registry_doc(principal, entry)
    reg["head"] = reg["log"][-1]["hash"]
    files = {"ledger/ledger.cose": led, "checkpoints/%d.cose" % payload["seq"]: cp,
             "registry.json": json.dumps(reg, indent=1).encode(), "README.txt": export.README.encode()}
    files.update(export.org_files(org))
    files.update(extra or {})
    files.update(export.verify_files())
    export.seal(files, wk, "acc-test", principal, "https://witness.test", t, payload["seq"], payload["head"])
    for k, v in files.items():
        p = os.path.join(dest, k)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(v)
    return dest


def run_verify(folder, *flags, checker=None):
    """Runs the checker as a third party would: python -I <checker> <folder>. Default: the pack's own copy (verify/verify_pack.py)."""
    p = subprocess.run([sys.executable, "-I", checker or os.path.join(folder, "verify", "verify_pack.py"), str(folder), *flags],
                       capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout + p.stderr


def lines(out, prefix):
    return [ln for ln in out.splitlines() if ln.startswith(prefix)]


def reseal(folder, wk):
    """After a deliberate edit: recompute manifest.json/manifest.cose with the witness key, so only the edited part can fail."""
    files = {}
    for dp, _, fs in os.walk(folder):
        for f in fs:
            rel = os.path.relpath(os.path.join(dp, f), folder).replace(os.sep, "/")
            if rel not in ("manifest.json", "manifest.cose"):
                with open(os.path.join(dp, f), "rb") as fh:
                    files[rel] = fh.read()
    signed = cose.loads(cose.parse1(open(os.path.join(folder, "manifest.cose"), "rb").read())[2])
    man = json.load(open(os.path.join(folder, "manifest.json")))
    export.seal(files, wk, signed["account"], man["principal"], man["witness"]["iss"], signed["created_t"], signed["cp_seq"], signed["cp_head"])
    for k in ("manifest.json", "manifest.cose"):
        with open(os.path.join(folder, k), "wb") as f:
            f.write(files[k])


__all__ = ["cbor2", "_paths"]
