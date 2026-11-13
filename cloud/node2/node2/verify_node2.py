"""Offline check of node 2 (stage 1, 2026-10-23). Not in the image: this is the USER's tool.

    python -m node2.verify_node2 node2.json [--expect expect.json] [--at 2026-10-23T00:00:00Z] [--json]

node2.json = what node 2 serves at GET /node2 (or /node2/attestation, or a bare attestation document: {"scheme", ...}).
expect.json = {"policy_sha256": hex, "measurement": hex, "node1_pub_hex": hex (optional), "k2_pub_hex": hex (optional)}:
  policy_sha256 = SHA-256 of the rego text that `az confcom acipolicygen` makes from the published image (recompute it yourself),
  measurement   = the Microsoft UVM launch measurement (reference-info of the security context; its COSE signature is NOT checked here).

Checks, in order (each one a line; any FAIL -> exit 1):
  1. AMD: VCEK -> ASK -> ARK, the ARK pinned (Genoa, Milan; amd.ARK_PINS), the report signature, VCEK chip id and TCB = report;
  2. the guest is not DEBUG;
  3. REPORT_DATA = key_hash(K2) || boot_ctx(node1_pub, t)          (K2 was born in THIS guest, for THIS node 1);
  4. HOST_DATA = SHA-256(the policy shown) [= expect.policy_sha256] (the platform enforced exactly this policy);
  5. MEASUREMENT = expect.measurement                                (Microsoft's utility VM);
  6. the policy has none of the known allow-all forms (exec into the container, any image, fragments);
  7. every co-signature in the view is signed by K2 and the chain is unbroken (n + 1, prev = SHA-256(previous), alarms never fall);
  8. every alarm in the view is signed by K2 and is real evidence against node 1 (cosign.verify_alarm with node 1's key).
NOT checked: AMD revocation (CRL) and a minimum TCB; the COSE signature of Microsoft's reference-info; that the policy forbids
exec in the ways a generated policy says it (read it: exec_processes, allow_* flags); that the image digests in the policy are the
published image (recompute the policy from the image yourself -- that is what expect.policy_sha256 is for).
"""
import argparse
import datetime
import json
import sys

from node2 import attest, cosign
from node2.worker import unb64


def _hex(x, n=None):
    b = bytes.fromhex(x)
    if n is not None and len(b) != n:
        raise ValueError("expected %d bytes of hex" % n)
    return b


def load_expect(j):
    if not j:
        return None
    out = {"policy_sha256": _hex(j["policy_sha256"], 32), "measurement": _hex(j["measurement"], 48)}
    for k in ("node1_pub_hex", "k2_pub_hex"):
        if j.get(k):
            out[k] = _hex(j[k], 32)
    return out


def verify(view, expect=None, pins=None, at=None):
    """view: the JSON of GET /node2 (dict), or {"attestation": ...}, or a bare attestation document.
    -> {"ok": bool, "lines": [(OK|FAIL|NOTE, text)], "facts": {...}}. Never raises on a bad document."""
    lines, facts = [], {}

    def ok(t):
        lines.append(("OK", t))

    def fail(t):
        lines.append(("FAIL", t))

    def note(t):
        lines.append(("NOTE", t))

    if not isinstance(view, dict):
        fail("not a JSON object")
        return {"ok": False, "lines": lines, "facts": facts}
    aj = view.get("attestation") if "attestation" in view else view
    try:
        doc = attest.doc_from_json(aj)
    except attest.AttestError as e:
        fail("attestation document: %s" % e)
        return {"ok": False, "lines": lines, "facts": facts}
    exp = None
    if expect:
        exp = {"policy_sha256": expect["policy_sha256"], "measurement": expect["measurement"]}
    r = attest.check_full(doc, exp, pins=pins, at=at)
    facts.update(r["facts"])
    facts["k2_pub_hex"], facts["node1_pub_hex"], facts["t"] = doc["pub"].hex(), doc["node1_pub"].hex(), doc["t"]
    probs = r["problems"]
    att = [p for p in probs if p.startswith("attestation:")]
    amdp = [p for p in probs if p.startswith("AMD signature:")]
    polp = [p for p in probs if p.startswith("policy:")]
    if amdp:
        fail(amdp[0])
    elif att and not facts.get("amd"):
        note("AMD signature: not reached (the attestation check failed first)")
    else:
        ok("AMD: VCEK -> ASK -> ARK-%s (pinned), report signature, chip id and TCB" % facts.get("amd"))
    for p in att:
        fail(p)
    if not att:
        ok("not DEBUG; REPORT_DATA binds K2 %s... to node 1 %s... at t=%d" % (doc["pub"].hex()[:16], doc["node1_pub"].hex()[:16], doc["t"]))
        ok("HOST_DATA = SHA-256(policy) = %s" % facts["policy_sha256"] + (" = expected" if exp else ""))
        if exp:
            ok("MEASUREMENT = expected %s..." % facts["measurement"][:24])
    for p in polp:
        fail(p)
    if not att and not polp:
        ok("policy: none of the known allow-all forms")
    for t in r["trust"]:
        note(t)
    if expect and expect.get("node1_pub_hex") and doc["node1_pub"] != expect["node1_pub_hex"]:
        fail("the attestation names another node 1 key than expected")
    if expect and expect.get("k2_pub_hex") and doc["pub"] != expect["k2_pub_hex"]:
        fail("K2 is not the expected key")
    if view.get("k2_pub_hex") and view["k2_pub_hex"] != doc["pub"].hex():
        fail("the view names another K2 than its attestation")
    # co-signatures and alarms carried by the view
    k2, k1 = doc["pub"], doc["node1_pub"]
    prev = None
    n_ok = 0
    for i, c in enumerate(view.get("cosigs") or []):
        try:
            cs = unb64(c["cose_b64"])
            m = cosign.verify_cosig(cs, k2)
        except (cosign.Reject, KeyError, TypeError, ValueError) as e:
            fail("cosig #%d: not signed by K2 (%s)" % (i, e))
            prev = None
            continue
        if m.get("bid") != c.get("bid") or ("n" in c and m.get("n") != c["n"]):
            fail("cosig #%d: the view's bid/n differ from the signed ones" % i)
        if prev is not None:
            pm, ph = prev
            if m["n"] != pm["n"] + 1 or bytes(m["prev"]) != ph or m.get("alarms", 0) < pm.get("alarms", 0):
                fail("cosig n=%s: the chain breaks after n=%s" % (m.get("n"), pm.get("n")))
        prev = (m, cosign.sha256(cs))
        n_ok += 1
    if n_ok:
        last = prev[0] if prev else None
        ok("%d co-signature(s) signed by K2, chain unbroken%s" % (n_ok, ", last n=%d bid=%s alarms=%d" % (last["n"], last["bid"], last.get("alarms", 0)) if last else ""))
        facts["cosig_last_n"] = last["n"] if last else None
    a_ok = 0
    for i, a in enumerate(view.get("alarms") or []):
        try:
            why = cosign.verify_alarm(unb64(a["cose_b64"]), k2, k1)
            a_ok += 1
            ok("ALARM #%d (%s, batch %s): real evidence against node 1" % (i, why, a.get("bid")))
        except (cosign.Reject, KeyError, TypeError, ValueError) as e:
            fail("alarm #%d: not valid evidence (%s)" % (i, e))
    facts["alarms_valid"] = a_ok
    if "status" in view:
        facts["status"] = view.get("status")
        if view.get("status") == "halted":
            note("node 2 says it is HALTED: %s" % view.get("reason"))
    res_ok = not any(k == "FAIL" for k, _ in lines)
    return {"ok": res_ok, "lines": lines, "facts": facts}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline check of node 2 (AMD SEV-SNP on ACI)")
    ap.add_argument("view", help="node2.json: GET /node2 (or /node2/attestation, or an attestation document)")
    ap.add_argument("--expect", help="expect.json: policy_sha256, measurement [, node1_pub_hex, k2_pub_hex]")
    ap.add_argument("--at", help="check the certificates at this UTC time (ISO 8601), default now")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    a = ap.parse_args(argv)
    try:
        with open(a.view) as f:
            view = json.load(f)
        expect = None
        if a.expect:
            with open(a.expect) as f:
                expect = load_expect(json.load(f))
        at = datetime.datetime.fromisoformat(a.at.replace("Z", "+00:00")) if a.at else None
    except (OSError, ValueError, KeyError) as e:
        print("cannot read the input: %s" % e, file=sys.stderr)
        return 2
    r = verify(view, expect, at=at)
    if a.json:
        print(json.dumps({"ok": r["ok"], "lines": r["lines"], "facts": r["facts"]}, indent=1, sort_keys=True))
    else:
        for k, t in r["lines"]:
            print("%-4s %s" % (k, t))
        print("VERDICT: %s" % ("OK" if r["ok"] else "FAIL"))
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
