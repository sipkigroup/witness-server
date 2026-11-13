"""Test shim of 0.2.4 (draft-deus-aar-05 8.6). The server and the pages keep the one `bstr` member `toolmap_sha256` of a mandate / action as 64 hex in JSON;
the signing page's CDE encoder (web/js/cde.js) turns it into bytes before it signs or hashes. The Python test clients play the page and call
`wa.cde(<json mandate>)` / `approval_payload(<json mandate>, <json action>)` directly, so for the tests the same conversion is applied inside these functions.
The server itself converts explicitly (app/wire.py); the tests of 0.2.4 call `wa.cde_raw` (the unshimmed function) where the difference matters.
Installed by the conftest.py of every server test directory."""
import os
import sys

CLOUD = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(CLOUD, "server")


# r0274 (open server trial 13.11): with HOME inside /tmp, 10 server tests failed. Not a bug of the server: its gates excuse the temp
# directories (app/execguard._G1_SAFE: /tmp, /private/tmp, /var/folders, ...; sandbox in_temp), so with such a HOME every `~/...` of a test
# is a temp path and "ask for ~/.bashrc / grep -r KEY ~" no longer holds. The tests model a person whose home is a real home: they get
# one here (the account's home from the password database), the gates stay as they are.
TEMP_ROOTS = ("/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders", "/private/var/folders")


def _under_temp(p):
    rp = os.path.realpath(p)
    return any(rp == r or rp.startswith(r + "/") for r in TEMP_ROOTS)


def home_outside_temp(env=None):
    """HOME of this test run outside the temp directories (see above). Returns the HOME it set, or None when it left it as it was."""
    e = os.environ if env is None else env
    h = e.get("HOME") or ""
    if h and not _under_temp(h):
        return None
    try:
        import pwd
        alt = pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, KeyError):
        alt = ""
    if not alt or _under_temp(alt) or not os.path.isdir(alt):
        raise RuntimeError("HOME (%r) is inside a temp directory and the account's home (%r) is too: the server's gates treat temp "
                           "paths as scratch, so the tests' ~ paths would not be a home. Run the tests with HOME outside /tmp." % (h, alt))
    e["HOME"] = alt
    return alt


def install():
    home_outside_temp()
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
