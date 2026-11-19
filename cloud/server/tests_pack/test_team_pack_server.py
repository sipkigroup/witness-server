"""0.2.0 merge (01 <-> 02 <-> 06): the team evidence pack built by the REAL server end to end -- no fixture app.org, no ledger written
around the server. Org of 3 (tests/org_helpers.team: v1 genesis -> v2 'money over 50000: budget k=2'), a mandate signed 2 of 3 through
sig-requests, a money approval by quorum (2 budget signers), a refusal by ONE budget signer (stopping is easy, ZAMECHANIYA 06 p.5),
a batch of 3 publishes approved with ONE wb, an item held by the advisor and released, coverage from the proxy, a revocation by one
access signer; then the anchor job with two test TSAs, GET /api/export, packtools/verify_pack.py --offline -> RESULT: VALID with the
org / quorum / batch / tsa lines."""
import io
import zipfile

from app import jobs
from app.flow import advisor
import wa_profile as wa
import wq_profile as wq
from tests.helpers import ORIGIN, RP, act
from tests.org_helpers import MONEY_FORM, MSG_FORM, team
from kit import run_verify

ADDR = "Meet me, I live at twelve Baker street"


def _draft(p, agent_id, form):
    d = p.post("/api/mandates/draft", agent_id=agent_id, form=form)
    assert d.status_code == 200, d.text
    return d.json()


def _appr_env(p, rid, approved=True):
    from svidetel_v4.state import approval_payload
    g = p.c.get("/api/approvals/" + rid).json()
    v = bytes.fromhex(g["view_sha256"]) if g.get("view_sha256") else None       # r0352: the page signs the view it is offered
    return p.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], rid, approved, v))


def _claim(p, rid):
    g = p.c.get("/api/approvals/" + rid).json()
    return {"view_sha256": g["view_sha256"]} if g.get("view_sha256") else {}


def build(app, dest):
    ctx = app.state.ctx
    owner, bob, carol = team(app)
    # mandate with money: budget k=2 -> owner + bob
    ag, hdr = owner.new_agent("demo", "buyer")
    d = _draft(owner, ag["id"], MONEY_FORM)
    assert owner.sign_req(d["req_id"]).json()["status"] == "collecting"
    assert bob.sign_req(d["req_id"]).json()["mandate_status"] == "active"
    assert act(owner.c, hdr, "purchase", {"vendor": "v.example", "amount_cents": 5000}).json()["verdict"] == "allow"
    # second agent: messages/publish only (one signature), purchases defer; advisor holds addresses
    ag2, hdr2 = owner.new_agent("demo", "clerk")
    form2 = {k: v for k, v in MSG_FORM.items() if k != "publish"}              # no publish section -> publishes defer
    d2 = _draft(owner, ag2["id"], dict(form2, forbidden_data=["postal_address"]))
    assert owner.sign_req(d2["req_id"]).json()["mandate_status"] == "active"
    big = act(owner.c, hdr2, "purchase", {"vendor": "v.example", "amount_cents": 80000}).json()
    assert big["reason"] == "ESCALATE_MONEY"
    assert owner.post("/api/approvals/" + big["rid"], **_claim(owner, big["rid"]), approved=True, envelope_b64=_appr_env(owner, big["rid"])).json()["verdict"] == "collecting"
    assert bob.post("/api/approvals/" + big["rid"], **_claim(bob, big["rid"]), approved=True, envelope_b64=_appr_env(bob, big["rid"])).json()["verdict"] == "allow"
    no = act(owner.c, hdr2, "purchase", {"vendor": "v.example", "amount_cents": 90000}).json()
    assert bob.post("/api/approvals/" + no["rid"], **_claim(bob, no["rid"]), approved=False, envelope_b64=_appr_env(bob, no["rid"], False)).json()["verdict"] == "refused"
    # batch of 3 publishes (the mandate has no publish section) -> one wb by the access signer
    pubs = [act(owner.c, hdr2, "publish", {"channel": "news", "text": "n %d" % i}).json() for i in range(3)]
    assert [p["reason"] for p in pubs] == ["ESCALATE_PUBLISH"] * 3, pubs
    rids = [p["rid"] for p in pubs]
    g = carol.c.get("/api/approvals/groups").json()["groups"]
    assert len(g) == 1 and sorted(g[0]["rids"]) == sorted(rids), g
    items = [wa.b64u_dec(x) for x in g[0]["items_approve_b64"]]
    ad, cd, der = carol.auth.get_assertion(wq.wb_challenge(items), RP, ORIGIN)
    r = carol.post("/api/approvals/batch", rids=g[0]["rids"], views=g[0].get("views"), approved=True, envelope_b64=wa.b64u(wq.make_wb(items, carol.auth.kid, ad, cd, der)))
    assert r.status_code == 200 and [x["verdict"] for x in r.json()["results"]] == ["allow"] * 3, r.text
    # held by the advisor, released by the access signer
    ctx.db.x("INSERT OR REPLACE INTO org_settings(account_id, advisor) VALUES(?, 'heuristic')", (owner.uid,))
    h = act(owner.c, hdr2, "send_email", {"to": "ann@acme.example", "subject": "visit", "body": ADDR}).json()
    assert (h["status"], h["reason"]) == ("held", "ADVISORY_HOLD"), h
    a = h["action"]
    gh = carol.c.get("/api/approvals/" + h["rid"]).json()                    # r0352: the release names the view it is offered
    r = carol.post("/api/approvals/%s/release" % h["rid"], release=True, **_claim(carol, h["rid"]),
                   envelope_b64=carol.sign(wq.TYP_RELEASE, wq.release_payload(h["rid"], a["args_sha256"], True, bytes.fromhex(gh["view_sha256"]))))
    assert r.json()["verdict"] == "allow", r.text
    # coverage declared by the proxy
    assert owner.c.post("/v1/coverage", json={"level": "C1", "unwitnessed": ["Bash"], "tool": "doctor-0.2", "pass_net_tools": []},
                        headers=hdr2).status_code == 200
    # revocation of the money mandate by one access signer
    gm = carol.c.get("/api/mandates/%s/revoke" % d["mandate"]["id"]).json()
    assert carol.post("/api/mandates/%s/revoke" % d["mandate"]["id"],
                      envelope_b64=carol.sign(gm["typ"], wa.b64u_dec(gm["payload_b64"]))).json()["status"] == "revoked"
    bid = jobs.anchor_once(ctx, tsa=True)
    res = owner.c.get("/api/export")
    assert res.status_code == 200, res.text
    zipfile.ZipFile(io.BytesIO(res.content)).extractall(dest)
    return {"dir": str(dest), "bid": bid, "ag2": ag2["id"]}


def test_server_team_pack_valid(app, tmp_path, providers):
    advisor.warm()
    try:
        tp = build(app, tmp_path / "pack")
    finally:
        advisor.reset()
    rc, out = run_verify(tp["dir"], "--offline")
    print(out)
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    assert "org policy: chain ok (v1..v2)" in out
    q = [x for x in out.splitlines() if x.startswith("quorum: ")]
    assert q and q[0].split()[1].split("/")[0] == q[0].split()[1].split("/")[1] and "meet policy-at-time" in q[0], out
    assert "batch approvals: 1 envelopes, 3 items" in out
    assert "tsa %s: OK (tsa-a, tsa-b)" % tp["bid"] in out
    assert "coverage %s: C1 (operator-declared, not verified)" % tp["ag2"] in out
    assert "advisory: 1/1 releases signed" in out
