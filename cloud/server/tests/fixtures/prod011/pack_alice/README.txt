Deus Witness - evidence pack
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
  - an anchor, once Bitcoin-confirmed, shows that the checkpoint existed before that block.

What it does NOT prove
  - that the witness key in manifest.json is the real service key: compare kid_hex/pub_hex with https://<service>/v1/witness;
  - what the human saw when signing (see section "honest limits" of the profile: the page is served by the witness);
  - that the owner's passkey was pinned to the right person at registration (pin source: webauthn-registration);
  - that an agent did not bypass the proxy; DLP is a literal match and a paraphrase evades it;
  - actions the witness was never asked about.
