import os, sys
CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "server"))
from app.hookjudge.mapping import default_form, map_event
from tests.helpers import act
from tests.test_0254_find_sed_awk_jq import _project

FAKE = "/private/tmp/fakehome_rt3"   # HOME outside the project; no real secret touched

def _send(client, hdr, cmd, proj, owner):
    out = []
    for m in map_event({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": proj}):
        r = act(client, hdr, m.tool, m.args).json()
        out.append(r["verdict"])
        if r["verdict"] == "defer":
            owner.approve(r["rid"])
    return out

# all read via `cat` (on the default allow list); post-fix every one must be held
FIXED = [f"cat {FAKE}/.s3cfg", f"cat {FAKE}/.boto", f"cat {FAKE}/.my.cnf",
         f"cat {FAKE}/.config/rclone/rclone.conf", f"cat {FAKE}/.config/hub",
         f"cat {FAKE}/.config/containers/auth.json", f"cat {FAKE}/AuthKey_ABC.p8",
         f"cat {FAKE}/.terraform.d/credentials.tfrc.json", f"cat {FAKE}/.config/sops/age/keys.txt",
         f"cat {FAKE}/.config/doctl/config.yaml", f"cat {FAKE}/.config/fly/config.yml",
         f"cat {FAKE}/key.ppk", f"cat {FAKE}/.authinfo"]
CONTROLS = [f"cat {FAKE}/.ssh/id_rsa", f"cat {FAKE}/.aws/credentials", f"cat {FAKE}/.netrc"]
# must stay allow (no over-match of ordinary project files)
NEG = ["cat src/m.py", "cat a.txt", f"cat {FAKE}/notes.txt", "cat config.yml"]

def test_fix(client, owner, tmp_path):
    proj = _project(tmp_path)
    ag, hdr = owner.new_agent("claude-code", "cc")
    owner.mandate(ag["id"], default_form(proj))
    leak = [c for c in FIXED if "defer" not in _send(client, hdr, c, proj, owner)]
    unctrl = [c for c in CONTROLS if not {"defer", "deny"} & set(_send(client, hdr, c, proj, owner))]   # 06.11 (Н1): refused outright counts
    overmatch = [c for c in NEG if "defer" in _send(client, hdr, c, proj, owner)]
    print("\nstill-leaking:", leak, "\nctrl-fail:", unctrl, "\nover-match:", overmatch)
    assert not leak and not unctrl and not overmatch
