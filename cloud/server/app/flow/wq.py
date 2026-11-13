"""Import of the contract-0.2 reference (cloud/contract/v02/wq_profile.py: verify_wb, wb_challenge, release_payload, requirements, ...).
01 adds cloud/contract/v02 to sys.path in _paths.py; until then this module does it for the flow."""
import os
import sys

from app import _paths

V02 = os.path.join(_paths.CONTRACT_DIR, "v02")
if V02 not in sys.path:
    sys.path.insert(0, V02)
import wq_profile as wq  # noqa: E402,F401
