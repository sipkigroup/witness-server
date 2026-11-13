"""0.1.3: filesystem preset - write_file can be allowed by a mandate (resource templates like delete), move_file judges source AND destination."""
from tests.helpers import FORM, act
from tests.test_flow import setup_agent

FS = dict(FORM, delete={"targets": ["/box/trash/*"], "allow_irreversible": False})
FSW = dict(FORM, delete={"targets": ["/box/trash/*", "/box/docs/*"], "allow_irreversible": True})


def vr(client, hdr, tool, args):
    j = act(client, hdr, tool, args).json()
    return j["verdict"], j["reason"]


def test_move_file_judges_destination(client, owner):
    ag, hdr, _ = setup_agent(owner, FS, preset="filesystem")
    assert vr(client, hdr, "move_file", {"source": "/box/trash/a", "destination": "/box/trash/b"}) == ("allow", "OK")
    assert vr(client, hdr, "move_file", {"source": "/box/trash/a", "destination": "/etc/outside"}) == ("deny", "RESOURCE")
    assert vr(client, hdr, "move_file", {"source": "/box/keep", "destination": "/box/trash/b"}) == ("deny", "RESOURCE")


def test_write_file_default_denied(client, owner):
    ag, hdr, _ = setup_agent(owner, FS, preset="filesystem")
    v = vr(client, hdr, "write_file", {"path": "/box/docs/x", "content": "c"})
    assert v[0] == "deny"                                    # no allow_irreversible: stays denied
    ag, hdr, _ = setup_agent(owner, dict(FORM, delete=None), preset="filesystem")
    assert vr(client, hdr, "write_file", {"path": "/box/docs/x", "content": "c"})[0] == "deny"


def test_write_file_allowed_by_mandate_paths_only(client, owner):
    ag, hdr, _ = setup_agent(owner, FSW, preset="filesystem")
    assert vr(client, hdr, "write_file", {"path": "/box/docs/x.txt", "content": "c"}) == ("allow", "OK")
    assert vr(client, hdr, "edit_file", {"path": "/box/docs/x.txt", "content": "c"}) == ("allow", "OK")
    assert vr(client, hdr, "write_file", {"path": "/box/secret/x", "content": "c"}) == ("deny", "RESOURCE")
    assert vr(client, hdr, "write_file", {"path": "/box/docs/../secret/x", "content": "c"})[0] == "deny"


def test_move_file_without_delete_permission_is_held_for_owner(client, owner):
    ag, hdr, _ = setup_agent(owner, dict(FORM, delete=None), preset="filesystem")
    j = act(client, hdr, "move_file", {"source": "/box/keep", "destination": "/box/kept"}).json()
    assert (j["verdict"], j["status"]) == ("defer", "pending_approval")
