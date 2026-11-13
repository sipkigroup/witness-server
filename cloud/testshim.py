"""Test shim of 0.2.4 (draft-deus-aar-05 8.6). The server and the pages keep the one `bstr` member `toolmap_sha256` of a mandate / action as 64 hex in JSON;
the signing page's CDE encoder (web/js/cde.js) turns it into bytes before it signs or hashes. The Python test clients play the page and call
`wa.cde(<json mandate>)` / `approval_payload(<json mandate>, <json action>)` directly, so for the tests the same conversion is applied inside these functions.
The server itself converts explicitly (app/wire.py); the tests of 0.2.4 call `wa.cde_raw` (the unshimmed function) where the difference matters.
Installed by the conftest.py of every server test directory."""
import os
import sys

CLOUD = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(CLOUD, "server")


def install():

    if not os.path.isdir(SERVER):
        return
    try:
        if SERVER not in sys.path:
            sys.path.append(SERVER)
        from app import _paths  # noqa: F401
        from app import wire
        import wa_profile as wa
        from svidetel_v4 import state
    except Exception:  # noqa: BLE001  (a test run that is not the server's: no shim)
        return
    if getattr(wa, "cde_raw", None) is not None:
        return
    wa.cde_raw = wa.cde
    wa.cde = lambda x: wa.cde_raw(wire.cbor_form(x))
    ap, rp = state.approval_payload, state.revocation_payload
    state.approval_payload = lambda mandate, action, rid, approved=True, view=None: ap(wire.cbor_form(mandate), wire.cbor_form(action), rid, approved, view)   # pv2810: view
    state.revocation_payload = lambda mandate: rp(wire.cbor_form(mandate))
