"""04.11 (CHTO-VIDIT-SERVER D2, D3, D4): what the privacy page promises, held by the code.
D2: the text of a risky write is gone after the look-back (24 h) from the hourly job, even when the agent makes no further call.
D3: "Delete account" also erases the MCP proxy's tables (flow_*: tool catalogs, coverage strings, holds).
D4: rate-limit keys (IP keys included) leave memory once their window is over.
"""
import json
import time

from app import jobs
from app.context import Limiter
from app.flow import store
from tests.org_helpers import Person, ctx_of
from tests.test_0223_delete_account import setup_agent
from tests.test_0224_critique import Agent
from tests.test_r25_s8 import SH_NET


def _texts(db, agent_id):
    n = 0
    for r in db.q("SELECT exec_json FROM actions WHERE agent_id=? AND exec_json LIKE '%\"wrun\"%'", (agent_id,)):
        wr = (json.loads(r["exec_json"]) or {}).get("wrun") or {}
        n += sum(1 for v in wr.values() if isinstance(v, dict) and "text" in v)
    return n


def test_d2_risky_write_text_goes_without_a_new_command(client, owner, tmp_path):
    a = Agent(client, owner, tmp_path, extra_cmds=["python3"])
    a.tool("Write", {"file_path": a.proj + "/f8b.sh", "content": SH_NET})
    db = client.app.state.ctx.db
    assert _texts(db, a.ag["id"]) == 1                                       # kept for the page of a later run
    jobs.prune_previews(client.app.state.ctx)
    assert _texts(db, a.ag["id"]) == 1                                       # still inside the 24 h
    db.x("UPDATE actions SET updated_at=updated_at-?", (24 * 3600 + 60,))   # a day passes, the agent stays quiet
    jobs.prune_previews(client.app.state.ctx)
    assert _texts(db, a.ag["id"]) == 0                                       # the hourly job dropped it; the mark itself stays
    assert db.one("SELECT COUNT(*) n FROM actions WHERE agent_id=? AND exec_json LIKE '%\"wrun\"%'", (a.ag["id"],))["n"] >= 1


def test_d3_delete_account_erases_flow_tables(app):
    p = Person(app).register("Alice")
    ag, hdr, m = setup_agent(p)
    ctx = ctx_of(app)
    store.ensure(ctx)
    t = int(time.time())
    db = ctx.db
    db.x("INSERT INTO flow_catalogs(account_id, agent_id, catalog_json, sha256, t) VALUES(?,?,?,?,?)", (p.uid, ag["id"], '{"tools":[]}', "h", t))
    db.x("INSERT INTO flow_catalog_log(account_id, agent_id, sha256, drift, t) VALUES(?,?,?,?,?)", (p.uid, ag["id"], "h", 0, t))
    db.x("INSERT INTO flow_coverage(agent_id, account_id, coverage_json, t) VALUES(?,?,?,?)", (ag["id"], p.uid, '["MCP server x"]', t))
    db.x("INSERT INTO flow_held(rid, account_id, label, mode, t) VALUES(?,?,?,?,?)", ("r1", p.uid, "l", "m", t))
    db.x("INSERT INTO flow_escalations(rid, account_id, t) VALUES(?,?,?)", ("r1", p.uid, t))
    other = Person(app).register("Bob")
    db.x("INSERT INTO flow_held(rid, account_id, label, mode, t) VALUES(?,?,?,?,?)", ("r2", other.uid, "l", "m", t))
    p.stepup()
    assert p.post("/api/account/delete", confirm_name="Alice").status_code == 200
    for tb in ("flow_catalogs", "flow_catalog_log", "flow_coverage", "flow_held", "flow_escalations"):
        assert db.one("SELECT COUNT(*) n FROM %s WHERE account_id=?" % tb, (p.uid,))["n"] == 0, tb
    assert db.one("SELECT COUNT(*) n FROM flow_held WHERE account_id=?", (other.uid,))["n"] == 1   # nobody else's rows


def test_d4_limiter_drops_keys_after_their_window():
    L = Limiter()
    t = time.time()
    assert L.hit("login:203.0.113.7", 30, 60, now=t)
    assert L.hit("reg:203.0.113.7", 5, 3600, now=t)
    assert L.allowed("trial:198.51.100.0/64", 5, 3600, now=t)                # a look only: an empty key
    L.sweep(now=t + 61)
    assert "login:203.0.113.7" not in L.w and "trial:198.51.100.0/64" not in L.w
    assert "reg:203.0.113.7" in L.w                                          # its hour is not over
    L.sweep(now=t + 3601)
    assert not L.w and not L.win
    # on use, too: no job needed under traffic
    assert L.hit("login:203.0.113.8", 30, 60, now=t + 4000)
    assert L.hit("key:a1", 30, 60, now=t + 4000 + L.SWEEP_EVERY_S)
    assert "login:203.0.113.8" not in L.w and "key:a1" in L.w


def test_d4_hourly_job_sweeps_the_limiter(client):
    ctx = client.app.state.ctx
    ctx.limiter.hit("login:203.0.113.9", 30, 60, now=time.time() - 120)
    ctx.limiter._swept = time.time()
    assert "login:203.0.113.9" in ctx.limiter.w
    jobs.prune_previews(ctx)
    assert "login:203.0.113.9" not in ctx.limiter.w
