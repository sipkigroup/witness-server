"""Descriptor regression (05.11): the server holds a constant number of descriptors per data dir however many judge calls run,
and claim_data_dir / release_data_dir give the server.lock descriptor back."""
import os

from app import hub
from tests.helpers import Owner, ORIGIN, RP  # noqa: F401


def nfd():
    return len(os.listdir("/dev/fd"))


def test_claim_release_data_dir(tmp_path):
    before = nfd()
    for _ in range(20):
        hub.claim_data_dir(str(tmp_path))
        hub.release_data_dir(str(tmp_path))
    assert nfd() == before
    hub.claim_data_dir(str(tmp_path))
    assert nfd() == before + 1
    hub.claim_data_dir(str(tmp_path))                 # the same process claims again: no second descriptor
    assert nfd() == before + 1
    hub.release_data_dir(str(tmp_path))
    assert nfd() == before
