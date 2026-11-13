"""Evidence pack (ARHITEKTURA 6; 0.2 sections 2.5, 5.3, 7): a zip that a third party verifies offline with verify/verify_pack.py.
0.2 adds, for an organisation with a policy: org/policy-v<N>.cbor + org/policy-v<N>.env.cbor, org/chain.json; coverage/<agent>.json
(operator-declared); advisory/<rid>.json (release signatures); anchors/<batch>.tsr.<tsa> + anchors/tsa-ca/<tsa>.pem;
verify/wq_profile.py, verify/registry_wq.py, verify/tsa.py. Team data comes ONLY from app.org.export_org (task 01), see org_files()."""
import glob
import hashlib
import io
import json
import os
import time
import zipfile

import cbor2

from app import _paths
from svidetel_v4 import cose
from svidetel_v4.checkpoint import inclusion_path

TYP_MANIFEST = "application/deus-witness-pack-manifest+cbor"
SERVER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WQ_PROFILE = os.path.join(_paths.CONTRACT_DIR, "v02", "wq_profile.py")
TSA_PY = os.path.join(_paths.CLOUD, "lib", "tsa", "tsa.py")
REGISTRY_WQ = os.path.join(SERVER, "packtools", "registry_wq.py")
CORE_MODULES = ("__init__", "aar", "checkpoint", "cose", "decide", "httpcanon", "registry", "schema", "state", "verify")   # 0.2.43: httpcanon (PROPOSAL-08-http), imported by decide and schema
README = """Deus Witness - evidence pack
============================

What this is
  A copy of ONE tenant's append-only ledger (ledger/ledger.cose: one hex COSE_Sign1 entry per line, SHA-256 hash chain,
  every entry signed by the witness key in manifest.json), the signed checkpoints, the signed receipts (AAR) of allowed actions,
  the key registry record of the owner's passkey, and - when present - OpenTimestamps proofs of the checkpoints.

How to check it (offline, Python 3.10+, `pip install cbor2 cryptography`; `opentimestamps` is optional for anchors)
  python -I verify_pack.py .                (add --offline to skip the block-explorer cross-check)
  IMPORTANT: take verify_pack.py (and its modules) from a SOURCE YOU TRUST - the wheel deus-witness or the file whose SHA-256 the
  service publishes - NOT from this pack: a pack can carry a doctored checker. The copy in verify/ is for reference; compare its
  hashes with the published ones. Running it from here needs the flag --use-pack-code and trusts the pack's author.
  Last line: RESULT: VALID or RESULT: INVALID. Exit code 0 / 1. A line "complete as of <UTC> (seq N)" says up to which ledger entry
  the pack is complete (manifest.cose is signed by the witness key; the ledger must end with that checkpoint).
  An independent checker written in Swift: aarc-wa verify-pack <folder>  (does not check anchors).

What it proves
  - the ledger is intact: no entry removed, reordered or altered (hash chain, witness signatures);
  - every mandate and approval in it was signed by the passkey pinned in registry.json (WebAuthn profile of draft-deus-aar-04,
    verify/wa_profile.py) and every decision of the witness is reproducible from the ledger (verify/svidetel_v4);
  - the pack is complete as of the time and checkpoint printed by the checker (nothing after it is shown, nothing before it was cut);
  - each receipt in receipts/ is signed by the witness and is the RECEIPT entry at its position in the ledger;
  - (0.2.4) promises/<rid>.promise.cose is the witness's signed INCLUSION PROMISE for that RECEIPT entry (draft-deus-aar-05 9.5): an anchored
    checkpoint covering it by entry time + 3600 s. The checker prints "promises: N kept, ..."; a promise that is late or broken (PROMISE_LATE,
    PROMISE_BROKEN) makes the pack INVALID, unless the pack itself discloses a batch that was not stamped (anchors/<id>.json with status failed|off): then it is
    reported as PROMISE_UNMET_DISCLOSED (0.2.5); a promise that is not the witness's or not for this ledger is ignored (it is no evidence). Without DW_ANCHOR=on no promises are given;
  - (0.2.4) toolmaps/<sha256>.cbor is the tool map DOCUMENT (CDE) whose SHA-256 is the `toolmap_sha256` inside a mandate signed by the passkey
    (draft-deus-aar-05 8.6): tool classes and argument paths, keyed HMAC tags of the protected literals (0.2.5; the key stays on the server) and the advisor mode at signing;
  - an anchor, once Bitcoin-confirmed, shows that the checkpoint existed before that block.

Team packs (folder org/ present; checker lines "org policy", "quorum", "batch approvals")
  - org/policy-v<N>.cbor is the signed policy of the organisation (members by key id and label, roles, rules), org/policy-v<N>.env.cbor
    its signature: version 1 by the owner's pinned passkey, every next version by the quorum that the PREVIOUS version requires;
    org/chain.json gives for each version the witnessed time it took effect and the registry_log row that recorded it.
  - Proved: the chain is unbroken and starts at the pinned key; every mandate, approval, revocation and ceiling in the ledger carries
    signatures of members that, together, meet the rule of the policy IN FORCE AT THE ENTRY'S TIME (second pass), approval rules taken
    from the action of the matching RECEIPT; a batch approval (one passkey ceremony for up to 20 items) is counted in "batch approvals".
  - A version that only replaces ONE member's key (a lost passkey) may be signed by the rule `recovery` of the previous version
    (k >= 2 OTHER members; the replaced key never counts); the checker prints it as "org recovery: v<N> replaced key ...", and the
    registry_log row of that version names both keys.
  - NOT proved: the TIME at which a policy version took effect rests on the witness's clock and honesty (the same trust as the time
    of any ledger entry); who pressed "reject" before a quorum was reached; observers; the names behind labels.
  - Only the Python checker understands team envelopes (wq, wb): the Swift checker (aarc-wa) answers INVALID WA_MALFORMED on a team
    pack - that is expected in 0.2.
Several passkeys (0.2.2; checker line "keys")
  - registry.json rows with `row_json` {"key_event": ...} record each passkey added to or removed from the account, in the anchored
    registry hash chain. A key added by a CURRENT passkey carries that passkey's signature over the exact new key (checked); a key
    added with a RECOVERY CODE carries none: only the witness vouches for it, and the checker says so ("by recovery code").
  - Every signature in the ledger must come from a key that was active at the entry's witnessed time: a mandate signed by a passkey
    that was later removed (lost phone) stays valid; anything signed by it after the removal is INVALID.
Shown objects (0.2.83; checker lines "views: ...")
  - views/<rid>.json (an approval), views/allowance-<id>.json (a project permission), views/release-<rid>.json (a release of a held
    action): the object the signing page showed (action, recipient, previews of the arguments, text, code, reason it waited). Its
    SHA-256 over the RFC 8785 (JCS) form is the `view` member the passkey signed; the checker recomputes it (VIEW_MISMATCH = INVALID).
    The previews in it are the masked previews of the page. They are kept as long as the previews (30 days by default); an older
    approval has no object here and the checker says VIEW_UNVERIFIABLE (INVALID with --require-views).
CI run context (0.2.85; checker lines "run context ...")
  - runs/<id>.cose: what a CI job DECLARED about its run (repository, commit, run id, attempt, workflow, actor, start, session ids),
    sent with the agent key and the owner's export token (POST /v1/run-context) and signed by the witness key. It names the ledger
    position at which it was recorded (seq + entry hash) and the decisions of the run (RECEIPT entries: by session id when the hook sent
    it, else by time window from the declared start). The checker verifies the signature, the position and every linked RECEIPT
    (RUN_CONTEXT_SIG / _MALFORMED / _CHAIN / _LINK = INVALID) and prints the declared values. It proves that the witness received them
    at that point of the ledger, NOT that they are true: the witness did not check the commit or the run with the CI provider.
    deus-witness <= 0.2.54 does not read runs/ (its manifest check still covers the files); deus-witness 0.2.55 checks and prints them.
  - 0.2.86: a record marked verified "github-oidc" was made from a GitHub Actions OIDC token the witness checked itself (RS256 signature
    against GitHub's key set, issuer, audience = the witness origin, validity); repository, commit, run, attempt, workflow, actor and ref
    come FROM THE TOKEN (a different value in the request is refused) and the checker prints them as VERIFIED with the key id and the
    token's SHA-256. The token is not kept, so offline this rests on the witness's signature, not on GitHub's.
  - 0.2.87: the owner may limit which repositories / refs (pinned by GitHub's numeric repository and owner ids) produce a verified
    record; the line then also shows `repository id` and `owner id`.
Coverage and advice
  - coverage/<agent>.json is what the operator's proxy DECLARED about its own set-up (level C0..C3, bypasses): a statement, not evidence.
  - advisory/<rid>.json: a human's signed decision to release (or reject) an action held by the advisor; the checker verifies the
    signature; the advisor's opinion itself is heuristic and proves nothing.
Time-stamps (RFC 3161, second anchor)
  - anchors/<batch>.tsr.<tsa> is a time-stamp token of a third-party TSA over the same batch root as the Bitcoin anchor; the checker
    verifies it offline against anchors/tsa-ca/<tsa>.pem. A TSA is a TRUSTED third party (unlike Bitcoin): compare the root
    certificates with the ones the TSA publishes, or pass --tsa-ca=<dir> with roots you trust. No revocation check (offline).
    These stamps are NOT qualified time stamps (eIDAS): they show when the TSA saw the root, as far as you trust that TSA.
Public log of batches (r0269; checker lines "tlog ...")
  - tlog/checkpoint.note is a C2SP tlog-checkpoint (signed note) of the witness's public, append-only list of ALL anchor batches;
    tlog/vkey is its verifier key (compare it with https://<service>/tlog/vkey). tlog/inclusion/<batch>.json proves that each batch
    of this pack is leaf <index> of that list (RFC 9162 inclusion proof).
  - The point: the witness cannot show you one batch history and somebody else another. Compare tlog/checkpoint.note with what
    https://<service>/checkpoint (or a monitor, or a co-signing witness) shows: the same size with another root = proven fork;
    a larger size must come with a consistency proof (/tlog/proof/consistency). verify/tlogcheck.py does both offline.
  - tlog/stamps/<size>.note + .ots / .tsr.<tsa>: the daily external stamp of the log checkpoint covering the batch (OpenTimestamps
    and/or an RFC 3161 TSA over SHA-256 of the checkpoint text). A batch newer than the last stamp says "time: queued": its time
    rests on the witness's clock until the next daily stamp.

What it does NOT prove
  - that the witness key in manifest.json is the real service key: compare kid_hex/pub_hex with https://<service>/v1/witness;
  - that the page really displayed the shown object to the human (the page is served by the witness; see section "honest limits" of
    the profile): views/ proves WHICH object the passkey signed, not that the screen rendered it faithfully;
  - that the owner's passkey was pinned to the right person at registration (pin source: webauthn-registration);
  - that an agent did not bypass the proxy; DLP is a literal match and a paraphrase evades it;
  - actions the witness was never asked about.
"""


def sha(b):
    return hashlib.sha256(b).hexdigest()


def _read(p):
    with open(p, "rb") as f:
        return f.read()


def _org(ctx, account_id):
    """Task 01's export (app/org.py: export_org). Absent module or no policy -> None (single-owner pack, as 0.1)."""
    try:
        from app import org
    except ImportError:
        return None
    return _normalize(ctx, account_id, org.export_org(ctx, account_id))


def _table(ctx, name):
    return ctx.db.one("SELECT 1 AS k FROM sqlite_master WHERE type='table' AND name=?", (name,)) is not None


def _normalize(ctx, account_id, o):
    """0.2.0 merge (01 <-> 06): 01's export_org gives policies as base64url ({policy_b64, envelope_b64, ...}); org_files() takes bytes.
    Adds what export_org does not carry: coverage (02: flow_coverage, operator-declared) and advisory releases (01: sig_requests of kind
    'release'; the plain wa-sig is rebuilt from the stored wsig -- the same bytes the member's browser signed)."""
    if not o:
        return o
    import wa_profile as wa
    o = dict(o)
    pols = []
    for p in o.get("policies") or []:
        p = dict(p)
        if "policy" not in p and "policy_b64" in p:
            p["policy"], p["envelope"] = wa.b64u_dec(p["policy_b64"]), wa.b64u_dec(p["envelope_b64"])
        pols.append(p)
    o["policies"] = pols
    if "coverage" not in o and _table(ctx, "flow_coverage"):
        cov = {}
        for r in ctx.db.q("SELECT agent_id, coverage_json FROM flow_coverage WHERE account_id=? ORDER BY agent_id", (account_id,)):
            try:
                cov[r["agent_id"]] = json.loads(r["coverage_json"])
            except ValueError:
                continue
        o["coverage"] = cov
    if "advisory" not in o and _table(ctx, "sig_requests"):
        adv = []
        for r in ctx.db.q("SELECT * FROM sig_requests WHERE account_id=? AND kind='release' AND status='done' ORDER BY created_at, id", (account_id,)):
            x = ctx.db.one("SELECT action_json FROM actions WHERE rid=? AND account_id=?", (r["ref"], account_id))
            sigs = json.loads(r["sigs"] or "[]")
            if not x or not x["action_json"] or len(sigs) != 1:
                continue
            w = {k: bytes.fromhex(v) for k, v in sigs[0].items()}
            env = wa.cde({"v": wa.V, "typ": r["typ"], "kid": w["kid"], "payload": bytes(r["payload"]), "authData": w["authData"],
                          "clientDataJSON": w["clientDataJSON"], "sig": w["sig"]})
            meta = json.loads(r["meta"] or "{}")
            rel = meta.get("release")
            adv.append(dict({"rid": r["ref"], "args_sha256": json.loads(x["action_json"])["args_sha256"], "release": bool(rel), "envelope": env},
                            **({"view_sha256": meta["view"]} if isinstance(meta.get("view"), str) else {})))      # pv2810
        o["advisory"] = adv
    return o


def org_files(org):
    """Files of the team part from export_org's dict:
    {"policies": [{"ver", "policy": bytes CDE, "envelope": bytes, "t": int, "registry_seq": int|None}, ...],
     "coverage": {agent_id: {...}} (optional), "advisory": [{"rid", "args_sha256" hex, "release": bool, "envelope": bytes}] (optional)}."""
    files = {}
    if not org:
        return files
    pols = sorted(org.get("policies") or [], key=lambda p: p["ver"])
    if pols:
        vs = []
        for p in pols:
            n = int(p["ver"])
            files["org/policy-v%d.cbor" % n] = bytes(p["policy"])
            files["org/policy-v%d.env.cbor" % n] = bytes(p["envelope"])
            vs.append({"ver": n, "t": int(p["t"]), "registry_seq": p.get("registry_seq"), "hash": sha(bytes(p["policy"])),
                       "policy": "org/policy-v%d.cbor" % n, "envelope": "org/policy-v%d.env.cbor" % n})
        files["org/chain.json"] = json.dumps({"principal": org.get("principal"), "versions": vs,
                                              "note": "t = witnessed time the version took effect (witness clock, not independently provable)"},
                                             indent=1).encode()
    for agent, cov in sorted((org.get("coverage") or {}).items()):
        if _safe(agent):
            files["coverage/%s.json" % agent] = json.dumps(dict(cov, trust="operator-declared"), indent=1, sort_keys=True).encode()
    for a in org.get("advisory") or []:
        if _safe(a["rid"]):
            files["advisory/%s.json" % a["rid"]] = json.dumps(dict({
                "rid": a["rid"], "args_sha256": a["args_sha256"], "release": bool(a["release"]),
                "envelope_hex": bytes(a["envelope"]).hex(), "typ": "application/dw-release+cbor"},
                **({"view_sha256": a["view_sha256"]} if a.get("view_sha256") else {})), indent=1).encode()      # pv2810: the presentation hash signed
    return files


def shown_view_files(ctx, account_id, ledger_bytes, files):
    """0.2.83 (MR-24): views/<key>.json = the shown object (app/signview.py) whose SHA-256 over its RFC 8785 form a passkey signed, for
    every APPROVAL entry (key = the receipt id), ALLOWANCE entry (key = "allowance-<id>") and signed release (advisory/<rid>.json with
    view_sha256; key = "release-<rid>") whose object the server still holds (app/schema.sql shown_views). The checker (verify_pack,
    mandate_check.view_checks) recomputes the hash: a different object is VIEW_MISMATCH, a missing one VIEW_UNVERIFIABLE."""
    if not _table(ctx, "shown_views"):
        return {}
    held = {r["sha256"]: r["view_json"] for r in ctx.db.q("SELECT sha256, view_json FROM shown_views WHERE account_id=?", (account_id,))}
    if not held:
        return {}
    want = {}
    for line in ledger_bytes.split(b"\n"):
        if not line.strip():
            continue
        try:
            e = cose.loads(cose.parse1(bytes.fromhex(line.decode()))[2])
        except Exception:  # noqa - our own ledger; an unreadable line is the checker's business, not the export's
            continue
        b = e.get("body") if isinstance(e, dict) and isinstance(e.get("body"), dict) else {}
        if e.get("type") == "APPROVAL" and isinstance(b.get("view"), bytes):
            want[str(b.get("receipt"))] = b["view"].hex()
        elif e.get("type") == "ALLOWANCE" and isinstance(b.get("allowance"), dict) and isinstance(b["allowance"].get("view"), bytes):
            want["allowance-%s" % b["allowance"].get("id")] = b["allowance"]["view"].hex()
    for k in sorted(files):
        if k.startswith("advisory/") and k.endswith(".json"):
            try:
                vh = json.loads(files[k]).get("view_sha256")
            except (ValueError, AttributeError):
                continue
            if isinstance(vh, str):
                want["release-" + k[len("advisory/"):-len(".json")]] = vh.lower()
    out = {}
    for key, vh in want.items():
        if vh in held and _safe(key):
            out["views/%s.json" % key] = (json.dumps(json.loads(held[vh]), ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8")
    return out


def _safe(name):
    return isinstance(name, str) and 0 < len(name) <= 80 and all(c.isalnum() or c in "_-" for c in name)


def build_pack(ctx, account_id):
    """-> (zip bytes, file name). Takes a fresh checkpoint and copies the ledger under the ledger lock (atomic)."""
    db, hub = ctx.db, ctx.hub
    acc = db.one("SELECT * FROM accounts WHERE id=?", (account_id,))
    entry = hub.entry_of(account_id)
    t = int(time.time())
    files = {}
    cp_seq = cp_head = None
    with hub.lock(account_id):
        L = hub.ledger(account_id)
        with L._tx():
            if L.S.nseq > 0:
                seq, cp = L._checkpoint_locked()
                payload = cose.loads(cose.verify1(cp, [ctx.wk], cose.TYP_CHECKPOINT)[0])
                files["checkpoints/%d.cose" % payload["seq"]] = cp
                cp_seq, cp_head = payload["seq"], payload["head"]
            ledger_bytes = _read(L.path)
    files["ledger/ledger.cose"] = ledger_bytes
    for c in db.q("SELECT seq, cose FROM checkpoints WHERE account_id=? ORDER BY id", (account_id,)):
        files.setdefault("checkpoints/%d.cose" % c["seq"], bytes(c["cose"]))
    for x in db.q("SELECT rid, aar FROM actions WHERE account_id=? AND aar IS NOT NULL ORDER BY created_at", (account_id,)):
        files["receipts/%s.aar.cose" % x["rid"]] = bytes(x["aar"])
    # 0.2.4 (draft-deus-aar-05 9.5, 8.6): the inclusion promise given with each decision, and the tool map document whose hash is inside each signed mandate
    for x in db.q("SELECT rid, promise FROM actions WHERE account_id=? AND promise IS NOT NULL ORDER BY created_at", (account_id,)):
        files["promises/%s.promise.cose" % x["rid"]] = bytes(x["promise"])
    for m in db.q("SELECT id, gateway_doc FROM mandates WHERE account_id=? AND gateway_doc IS NOT NULL ORDER BY created_at", (account_id,)):
        try:
            doc = json.loads(m["gateway_doc"])
        except ValueError:
            continue
        files["toolmaps/%s.cbor" % hashlib.sha256(cbor2.dumps(doc, canonical=True)).hexdigest()] = cbor2.dumps(doc, canonical=True)
    # anchors that cover this tenant's checkpoints
    # 0.2.5 (R4-01): a batch whose OpenTimestamps stamp FAILED is exported as well (status "failed", no .ots): it discloses that the inclusion promises of the
    # checkpoints under it were not kept in time (the checker reports them as disclosed-unmet, not as a broken witness)
    bids = []
    for b in db.q("SELECT * FROM (SELECT DISTINCT b.* FROM anchor_batches b JOIN checkpoints c ON c.batch_id=b.id WHERE c.account_id=? "
                  "UNION SELECT * FROM anchor_batches WHERE status='failed' AND leaves_json LIKE ?) ORDER BY t",
                  (account_id, '%"account": "' + account_id + '"%')):
        leaves = json.loads(b["leaves_json"])
        mine = [i for i, l in enumerate(leaves) if l["account"] == account_id]
        if not mine:
            continue
        i = mine[-1]
        bids.append(b["id"])
        lv = [bytes.fromhex(l["leaf"]) for l in leaves]
        doc = {"batch": b["id"], "root": bytes(b["root"]).hex(), "leaf_index": i, "size": len(lv), "leaf": leaves[i]["leaf"],
               "path": [[s, h.hex()] for s, h in inclusion_path(lv, i)],
               "registry_head": bytes(b["registry_head"]).hex() if b["registry_head"] else None, "status": b["status"]}
        # 0.2.12 (R7-03/R7-04): the registry heads under the same root, with their paths: the checker finds them in registry.json and
        # reports up to which row the registry (and whose rows are whose) is anchored
        doc["registry_leaves"] = [{"kind": l["kind"], "leaf": l["leaf"], "leaf_index": k, "path": [[s, h.hex()] for s, h in inclusion_path(lv, k)]}
                                  for k, l in enumerate(leaves) if l.get("kind") in ("registry", "registry2")]
        tm = _tee_member(ctx, b["id"], files)       # DW_TEE (cloud/tee/DIZAIN-TDX.md): the batch quote, by hash; off and no quote = no member
        if tm is not None:
            doc["tee"] = tm
        files["anchors/%s.json" % b["id"]] = json.dumps(doc, indent=1).encode()
        ots = os.path.join(ctx.anchor_dir, b["id"] + ".ots")
        if os.path.exists(ots):
            files["anchors/%s.ots" % b["id"]] = _read(ots)
        for tsr in sorted(glob.glob(os.path.join(ctx.anchor_dir, glob.escape(b["id"]) + ".tsr.*"))):
            name = os.path.basename(tsr).partition(".tsr.")[2]
            ca = os.path.join(ctx.anchor_dir, "tsa-ca", name + ".pem")
            if _safe(name) and os.path.isfile(ca):
                files["anchors/" + os.path.basename(tsr)] = _read(tsr)
                files["anchors/tsa-ca/%s.pem" % name] = _read(ca)
    if getattr(ctx, "tee", None) is not None and getattr(ctx.tee, "boot", None):
        files["tee/boot.tdx.json"] = json.dumps(ctx.tee.boot, indent=1).encode()     # the key quote of the running instance
    if any(k.startswith("tee/") for k in files):
        files["tee/README.txt"] = TEE_README.encode()
        files["verify/tdx_quote.py"] = _read(os.path.join(os.path.dirname(os.path.abspath(__file__)), "tdx_quote.py"))
    from app import node2feed                  # 0.2.27: DW_NODE2=on only; off = the pack is what 0.2.26 made
    if node2feed.enabled(ctx):
        nf = node2feed.pack_files(ctx, bids)
        if nf:
            files.update(nf)
            files.update(node2feed.verify_files())
    from app import vocab                      # r0269: every reason vocabulary a mandate's tool map document pins
    vd = []
    for k, v in list(files.items()):
        if k.startswith("toolmaps/") and k.endswith(".cbor"):
            try:
                d = cbor2.loads(v)
                if isinstance(d, dict) and isinstance(d.get("vocab"), str):
                    vd.append(d["vocab"])
            except Exception:  # noqa: BLE001
                pass
    files.update(vocab.pack_files(db, vd))
    from app import tlog                       # r0269: the public log of batches: checkpoint, inclusion of each batch, stamps of the log
    files.update(tlog.pack_files(ctx, bids))
    # registry: own record + the hash chain (other tenants' rows are reduced to seq/prev/hash). 0.2.2: this account's key changes
    # ("keys:<id>": passkey added / removed) and policy rows ("org:<id>") carry their text as `row_json` (a 0.2.1 checker ignores it)
    log = []
    for r in db.q("SELECT * FROM registry_log ORDER BY seq"):
        row = {"seq": r["seq"], "prev": bytes(r["prev"]).hex(), "hash": bytes(r["hash"]).hex()}
        if r["hash2"] is not None:                 # 0.2.12 (R7-04): whose row (tag) in the second chain; foreign rows: only the hash of their text
            row["tag"], row["hash2"] = bytes(r["tag"]).hex(), bytes(r["hash2"]).hex()
        if r["account_id"] == account_id:
            row["entry_json"] = r["entry_json"]
        elif r["account_id"] in ("keys:" + account_id, "org:" + account_id):
            row["row_json"] = r["entry_json"]
        elif r["hash2"] is not None:
            row["body"] = hashlib.sha256((r["entry_json"] or "").encode()).hexdigest()
        log.append(row)
    files["registry.json"] = json.dumps({"principal": acc["principal"], "entry": entry, "log": log,
                                         "head": log[-1]["hash"] if log else None}, indent=1).encode()
    files.update(org_files(_org(ctx, account_id)))
    files.update(shown_view_files(ctx, account_id, ledger_bytes, files))      # 0.2.83 (MR-24): what each signing page showed
    from app import runctx                     # 0.2.85: runs/<id>.cose, the witness-signed CI run contexts (packtools/run_context.py checks them)
    files.update(runctx.pack_files(ctx, account_id))
    files["web_js_sha256.json"] = json.dumps(_js(ctx), indent=1).encode()
    files["README.txt"] = README.encode()
    files.update(verify_files())
    seal(files, ctx.wk, account_id, acc["principal"], ctx.cfg.iss, t, cp_seq, cp_head)
    name = "deus-witness-evidence-%s-%s.zip" % (account_id[:12], time.strftime("%Y%m%d%H%M", time.gmtime(t)))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for k in sorted(files):
            z.writestr(zipfile.ZipInfo(k, (2026, 1, 1, 0, 0, 0)), files[k], zipfile.ZIP_DEFLATED)
    return buf.getvalue(), name


TEE_README = """Deus Witness - TEE part of the evidence pack (Intel TDX, cloud/tee/DIZAIN-TDX.md)
=================================================================================
tee/<batch>.tdx.json  the TDX quote taken for that anchor batch: report_data = key_hash(witness key) || ctx_batch(batch id, batch root)
                      (scheme deus-aar-tee-v1). anchors/<batch>.json names it: "tee": {"quote_sha256": sha256(raw quote), ...}.
tee/boot.tdx.json     the quote of the instance that made this pack: report_data = key_hash(witness key) || ctx_boot(iss, t).
Chain the checker walks: receipt -> ledger entry -> checkpoint -> batch root (Merkle path) -> anchor record -> quote (by hash) ->
report_data -> witness key == the key that signed the receipt. Lines `tee ...` of verify_pack.py; flags:
  --tee-expect=<expect.json>     measurements YOU rebuilt from the published image (mr_td, rtmr0..2, app_events.compose-hash)
  --tee-intel-root=<pem>         the Intel SGX Root CA you pinned (not the one in any pack)
  --tee-collateral=<dir> [--tee-now=<unix t>]   Intel PCS collateral (tdx_quote.py --fetch-collateral) for the TCB status
  --require-tee                  INVALID unless every anchored checkpoint is under a batch with a valid quote
Failures that make the pack INVALID: a quote named by hash but missing or different (TEE_QUOTE_MISSING), a broken quote
(TEE_QUOTE_INVALID), a quote over another key or another batch (TEE_BINDING_MISMATCH), measurements not the expected ones
(TEE_MEASUREMENT_UNKNOWN), one witness key under quotes of different code (TEE_KEY_OUTLIVED_CODE).
A batch without a quote is NOT an error by itself (the quote agent can fail; the server discloses it): its checkpoints are simply not
credited with the TEE claim (with --require-tee: INVALID).
"""


def _tee_member(ctx, bid, files):
    """The `tee` member of a pack anchor record + tee/<bid>.tdx.json, or None (DW_TEE off and no quote for this batch: the old record)."""
    p = os.path.join(ctx.anchor_dir, bid + ".tdx.json")
    if os.path.isfile(p):
        from app import tee
        raw = _read(p)
        att = json.loads(raw)
        files["tee/%s.tdx.json" % bid] = raw
        return {"scheme": att.get("scheme"), "quote_sha256": tee.quote_sha256(att), "quote": "tee/%s.tdx.json" % bid,
                "url": ctx.cfg.iss.rstrip("/") + "/v1/witness/tdx/" + bid}
    if getattr(ctx, "tee", None) is None:
        return None
    err = "no quote for this batch"
    try:
        with open(os.path.join(ctx.anchor_dir, bid + ".json")) as f:
            err = (json.load(f).get("tee") or {}).get("error") or err
    except (OSError, ValueError):
        pass
    return {"scheme": "deus-aar-tee-v1", "quote_sha256": None, "error": str(err)[:160]}


def verify_files():
    """verify/*: the checker and every module it imports, byte copies of the sources (hashes land in manifest.json)."""
    here = os.path.dirname(os.path.abspath(__file__))
    files = {"verify/verify_pack.py": _read(os.path.join(SERVER, "packtools", "verify_pack.py")),
             "verify/wa_profile.py": _read(os.path.join(_paths.CONTRACT_DIR, "wa_profile.py")),
             "verify/registry_wa.py": _read(os.path.join(here, "registry_wa.py")),
             "verify/merklecache.py": _read(os.path.join(here, "merklecache.py")),
             "verify/wq_profile.py": _read(WQ_PROFILE),
             "verify/registry_wq.py": _read(REGISTRY_WQ),
             "verify/tsa.py": _read(TSA_PY),
             "verify/mandate_check.py": _read(os.path.join(SERVER, "packtools", "mandate_check.py")),     # 0.2.83: verdict lines, shown objects
             "verify/run_context.py": _read(os.path.join(SERVER, "packtools", "run_context.py")),         # 0.2.85: runs/<id>.cose
             "verify/tlogcheck.py": _read(os.path.join(SERVER, "packtools", "tlogcheck.py")),             # r0269: tlog/ (C2SP checkpoint, proofs)
             "verify/screencheck.py": _read(os.path.join(SERVER, "packtools", "screencheck.py"))}         # r0277: the first screen rebuilt (P1, P2)
    for m in CORE_MODULES:
        files["verify/svidetel_v4/%s.py" % m] = _read(os.path.join(_paths.CORE_DIR, "svidetel_v4", m + ".py"))
    return files


def seal(files, wk, account_id, principal, iss, t, cp_seq, cp_head):
    """Adds manifest.json (hashes of all files) and manifest.cose (witness signature; N-04: the checker prints "complete as of")."""
    manifest = {"account": account_id, "principal": principal,
                "witness": {"kid_hex": wk.kid.hex(), "pub_hex": wk.pub.hex(), "alg": "EdDSA", "iss": iss},
                "created_t": t, "files": {k: sha(v) for k, v in sorted(files.items())}}
    files["manifest.json"] = json.dumps(manifest, indent=1).encode()
    signed = {"account": account_id, "created_t": t, "cp_seq": cp_seq, "cp_head": cp_head, "files": manifest["files"]}
    files["manifest.cose"] = cose.sign1(wk, cbor2.dumps(signed, canonical=True), TYP_MANIFEST)
    return files


def _js(ctx):
    from app.main import _js_hashes
    web = os.path.abspath(ctx.cfg.web_dir or _paths.WEB_DIR_DEFAULT)
    hs = dict(_js_hashes(web))
    from app import node2feed
    if not node2feed.enabled(ctx):
        hs.pop("node2.html", None)            # 0.2.40: the page answers 404 with DW_NODE2 off, so it is not in the list
    return hs
