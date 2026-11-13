"""RT-0.2.55c (red team 5): approvals and project allowances. Agent has only its key and tool_input."""
from tests.test_allowance_0210 import Dev, _id, DAY  # noqa: F401
from app import allowances as al
import wa_profile as wa


def _allow(d, cmd):
    [(_, r)] = d.send(cmd)
    assert (r["verdict"], r["reason"]) == ("defer", "ESCALATE_COMMAND"), r
    res, a = d.allowance(r["rid"], days=1)
    assert res.status_code == 200, res.text
    return a


def test_code_from_cli_options_not_covered_by_allowance(client, owner, tmp_path):
    """Allowed `npm test` / `make` / `pylint` must not cover options that run code given on the command line (no file changes, execguard blind)."""
    proj = (tmp_path / "proj"); proj.mkdir(); proj = proj.resolve()
    d = Dev(client, owner, proj)
    _allow(d, "npm test")
    _allow(d, "make")
    _allow(d, "pylint")
    for cmd in ["npm test --node-opt=--import=data:text/javascript,1",     # nopt abbreviation of --node-options (L1: runs the code, npm 11.17)
                "npm test --node-o=--import=data:text/javascript,1",
                "make --ev='x:;id' x",                                       # GNU getopt_long prefix of --eval
                "make -E 'x:;id' x",                                         # GNU make 4.4: -E = --eval
                "make -sE 'x:;id' x",
                "pylint --init-h='import os' x.py"]:                         # argparse prefix of --init-hook
        v = d.verdicts(cmd)
        assert all(x[2] != "OK_ALLOWANCE" for x in v), (cmd, v)


def test_plain_forms_still_covered(client, owner, tmp_path):
    proj = (tmp_path / "proj"); proj.mkdir(); proj = proj.resolve()
    d = Dev(client, owner, proj)
    _allow(d, "npm test")
    _allow(d, "make")
    _allow(d, "pytest")
    for cmd in ["npm test", "npm test --silent", "make -j4", "make -s", "pytest --co", "pytest -q -x"]:
        assert d.verdicts(cmd) == [("Bash", "allow", "OK_ALLOWANCE")], cmd


def test_project_spelling_does_not_carry(client, owner, tmp_path):
    """An allowance for one project string never covers another spelling (case, trailing slash, symlink-free sibling prefix)."""
    proj = (tmp_path / "Proj"); proj.mkdir(); proj = proj.resolve()
    (tmp_path / "Proj2").mkdir()
    d = Dev(client, owner, proj)
    _allow(d, "pytest")
    for p in [str(proj) + "2", str(proj).lower(), str(proj).upper()]:
        try:
            v = d.verdicts("pytest", cwd=p, project=p)
        except Exception:
            continue
        assert all(x[2] != "OK_ALLOWANCE" for x in v), (p, v)


def test_allowance_replay_and_tamper(client, owner, tmp_path):
    proj = (tmp_path / "proj"); proj.mkdir(); proj = proj.resolve()
    d = Dev(client, owner, proj)
    [(_, r1)] = d.send("pytest")
    [(_, r2)] = d.send("make")
    res, a = d.allowance(r1["rid"])
    assert res.status_code == 200
    env = d.o.sign(al.TYP, wa.cde(a))                              # same id again on another request
    assert d.o.post("/api/allowances", rid=r2["rid"], envelope_b64=env).status_code == 409
    for over in [{"commands": ["make", "curl"]}, {"project": "/"}, {"exp": a["nbf"] + 91 * DAY}, {"nbf": a["nbf"] + 3600}]:
        res, _ = d.allowance(r2["rid"], **over) if "nbf" not in over else d.allowance(r2["rid"], nbf=over["nbf"], exp=over["nbf"] + DAY)
        assert res.status_code in (409, 422), (over, res.status_code)
    # the agent's own key cannot create or revoke allowances
    assert client.post("/api/allowances", json={"rid": r2["rid"], "envelope_b64": env}, headers=d.hdr).status_code in (401, 403)


def test_hidden_tail_of_long_line(client, owner, tmp_path):
    """Approve-once page: a second unlisted command after 4 KB of padding is it visible to the owner?"""
    proj = (tmp_path / "proj"); proj.mkdir(); proj = proj.resolve()
    d = Dev(client, owner, proj)
    for tail in ["; git config core.hooksPath h", "; node -e 'require(\"fs\").rmSync(\"src\",{recursive:true})'", "; python3 x.py"]:
        cmd = "pytest" + " " * 5000 + tail
        out = d.send(cmd)
        print("RT5-HIDDEN", [(t, r["verdict"], r["reason"], r["action"].get("recipient")) for t, r in out])
        for t, r in out:
            if r["verdict"] == "defer":
                g = client.get("/api/approvals/" + r["rid"]).json()
                print("RT5-PAGE", t, g["action"].get("recipient"), tail[2:8] in g["text_preview"], len(g["text_preview"]),
                      (g.get("allowance_offer") or {}).get("why_not"))


def test_page_lists_every_command_of_a_long_line(client, owner, tmp_path):
    proj = (tmp_path / "proj"); proj.mkdir(); proj = proj.resolve()
    d = Dev(client, owner, proj)
    [(t, r)] = d.send("pytest" + " " * 5000 + "; python3 x.py")
    g = client.get("/api/approvals/" + r["rid"]).json()
    assert "python3" not in g["text_preview"] and g["line_commands"] == ["pytest", "python3"]


def test_0256_line_commands_kept_without_a_project(client, owner, tmp_path):
    """0.2.56: the commands of the line are stored for every command row, not only when the hook knows the project (cmd_meta)."""
    proj = (tmp_path / "proj"); proj.mkdir(); proj = proj.resolve()
    other = (tmp_path / "elsewhere"); other.mkdir(); other = other.resolve()
    d = Dev(client, owner, proj)
    res = d.send("pytest" + " " * 5000 + "; python3 x.py", cwd=str(other), project=str(other / "nope"))
    rids = [r["rid"] for _, r in res if r.get("verdict") == "defer"]
    assert rids, res
    row = client.app.state.ctx.db.one("SELECT cmd_meta, line_heads FROM actions WHERE rid=?", (rids[0],))
    assert row["cmd_meta"] is None and row["line_heads"]                         # no project, the line is still listed
    g = client.get("/api/approvals/" + rids[0]).json()
    assert g["line_commands"] == ["pytest", "python3"]
