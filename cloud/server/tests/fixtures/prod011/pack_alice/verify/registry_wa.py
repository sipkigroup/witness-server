"""WaRegistry: principal-key registry that understands BOTH signature forms (ARHITEKTURA 3.6):
 - `wa-sig` envelope (first byte 0xA7) -> wa_profile.verify_envelope (profile of draft-deus-aar-04, section 3.5);
 - COSE_Sign1 (0xD2) -> exactly svidetel_v4.registry.Registry.
Entries are the registry records of 3.4: {"alg":"ES256","pub":hex,"webauthn":{...},"pin_source":...}.
Stand-alone on purpose (imports only svidetel_v4.registry and wa_profile): the same file is copied into the evidence pack."""
import wa_profile as wa
from svidetel_v4.registry import Registry


def looks_like_envelope(b):
    """A CBOR map (major type 5) is a wa-sig attempt; anything it gets wrong is a WA_* code, not a COSE error."""
    return len(b) > 0 and (b[0] & 0xE0) == 0xA0


class WaRegistry(Registry):
    def __init__(self, principals, source):
        super().__init__({"source": source, "principals": principals})

    @staticmethod
    def for_account(principal, entry):
        return WaRegistry({principal: entry}, entry.get("pin_source") or "webauthn-registration")

    def check(self, principal, signed_by=None, cose_bytes=None, expect_payload=None, typ=None):
        """-> None if accepted, else a reason code. Envelope failures give the code of 3.5 (MANDATE_SIG/APPROVAL_SIG/KEY_MISMATCH/WA_*)."""
        if cose_bytes is not None and looks_like_envelope(cose_bytes):
            e = self.principals.get(principal)
            if e is None or "pub" not in e:
                return "KEY_NOT_PINNED"
            return wa.verify_envelope(cose_bytes, typ, expect_payload, e)
        return super().check(principal, signed_by, cose_bytes, expect_payload, typ)
