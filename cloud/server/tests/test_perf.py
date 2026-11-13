"""2026-10-18 perf: bounded incremental Merkle cache (app/merklecache.py) and limits from the environment."""
import hashlib
import random

import pytest
from fastapi.testclient import TestClient

from app import _paths  # noqa: F401
from app import merklecache as M
from app.config import Config, ConfigError
from app.main import create_app
from svidetel_v4 import checkpoint as C
from tests.helpers import Owner, ORIGIN
from tests.test_flow import act


def leaves(n, tag=b"t"):
    return [hashlib.sha256(tag + b"%d" % i).digest() for i in range(n)]


def test_kernel_untouched_reference_is_what_we_compare_with():
    assert M._ref_root is not M.merkle_root and M._ref_path is not M.inclusion_path
    assert M.self_check()


def test_equals_reference_every_prefix_and_path():
    ls = leaves(300)
    c = M.Cache(10000)
    for n in range(0, 301):
        assert M.merkle_root(ls[:n], c) == M._ref_root(ls[:n]), n
    for n in (1, 2, 3, 7, 8, 9, 16, 17, 100, 255, 256, 257, 300):
        for i in set([0, n - 1, n // 2, n // 3]):
            assert M.inclusion_path(ls[:n], i, c) == M._ref_path(ls[:n], i), (n, i)


def test_equals_reference_with_tiny_cache_eviction():
    rnd = random.Random(7)
    ls = leaves(1500)
    c = M.Cache(5)                                   # constant eviction: still correct, only slower
    for _ in range(60):
        n = rnd.randint(1, 1500)
        i = rnd.randrange(n)
        assert M.merkle_root(ls[:n], c) == M._ref_root(ls[:n])
        assert M.inclusion_path(ls[:n], i, c) == M._ref_path(ls[:n], i)
        assert len(c) <= 5


def test_cache_is_bounded():
    ls = leaves(4000)
    c = M.Cache(100)
    for n in range(1, 4001, 7):
        M.merkle_root(ls[:n], c)
    assert len(c) <= 100


def test_zero_cap_disables_storing():
    ls = leaves(500)
    c = M.Cache(0)
    assert M.merkle_root(ls, c) == M._ref_root(ls) and len(c) == 0


def test_warm_root_costs_log_n_hashes(monkeypatch):
    n = 5000
    ls = leaves(n + 1)
    c = M.Cache(100000)
    M.merkle_root(ls[:n], c)                          # warm
    calls = []
    monkeypatch.setattr(C, "_leaf", lambda b, f=C._leaf: (calls.append(1), f(b))[1])
    monkeypatch.setattr(C, "_node", lambda l, r, f=C._node: (calls.append(1), f(l, r))[1])
    fast = M.merkle_root(ls[:n + 1], c)
    root_calls = len(calls)
    calls.clear()
    M.inclusion_path(ls[:n + 1], 17, c)
    path_calls = len(calls)
    calls.clear()
    assert fast == M._ref_root(ls[:n + 1])
    assert len(calls) > 2 * n - 10                                       # the reference needs ~2n = 10000 hashes
    assert root_calls <= 2 * M.MIN_CACHED + 2 * 13, root_calls
    assert path_calls <= 13 * (2 * M.MIN_CACHED + 13), path_calls


def test_threads_share_one_small_cache_correctly():
    import threading
    ls = leaves(900)
    c = M.Cache(20)
    bad = []

    def work(seed):
        rnd = random.Random(seed)
        for _ in range(60):
            n = rnd.randint(1, 900)
            i = rnd.randrange(n)
            if M.merkle_root(ls[:n], c) != M._ref_root(ls[:n]) or M.inclusion_path(ls[:n], i, c) != M._ref_path(ls[:n], i):
                bad.append((seed, n, i))
    ts = [threading.Thread(target=work, args=(k,)) for k in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not bad and len(c) <= 20


def test_install_routes_kernel_and_verifier_names():
    from svidetel_v4 import state, verify
    assert M.install() in (True, False)
    if M.stats()["installed"]:
        assert C.merkle_root is M.merkle_root and state.merkle_root is M.merkle_root and verify.merkle_root is M.merkle_root


def test_pack_verifies_with_cache_and_with_reference_tree(client, owner, tmp_path):
    """A real book with many checkpoints: verify_pack.py is VALID with the cached tree and with the kernel's reference tree
    (DW_MERKLE_FAST=0), and a ledger byte flipped is INVALID in both."""
    import os
    import subprocess
    import sys
    import zipfile
    from tests.test_flow import setup_agent
    ag, hdr, _ = setup_agent(owner)
    for i in range(30):
        r = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "s", "body": "b%d" % i})
        assert r.status_code == 200 and r.json()["verdict"] == "allow"
        assert client.get("/v1/actions/" + r.json()["rid"], headers=hdr).json()["proof"]      # one checkpoint per action (proof on demand)
    z = tmp_path / "p.zip"
    z.write_bytes(client.get("/api/export").content)
    d = tmp_path / "pack"
    zipfile.ZipFile(z).extractall(d)
    assert (d / "verify" / "merklecache.py").exists()

    def run(fast):
        env = dict(os.environ, DW_MERKLE_FAST="1" if fast else "0")
        p = subprocess.run([sys.executable, "-I", str(d / "verify" / "verify_pack.py"), str(d), "--offline"], capture_output=True, text=True, env=env)
        return p.stdout.strip().splitlines()[-1], p.stdout
    assert run(True)[0] == "RESULT: VALID" and run(False)[0] == "RESULT: VALID"
    assert "reference implementation" not in run(True)[1]
    lp = d / "ledger" / "ledger.cose"
    b = bytearray(lp.read_bytes())
    b[len(b) // 2] ^= 1
    lp.write_bytes(bytes(b))
    assert run(True)[0] == "RESULT: INVALID" and run(False)[0] == "RESULT: INVALID"


# ---------------- limits from the environment ----------------
def base_env(tmp_path):
    kf = tmp_path / "k"
    kf.write_text("a1" * 32)
    return {"DW_DATA_DIR": str(tmp_path / "d"), "DW_WITNESS_KEY_FILE": str(kf), "DW_KEY_PEPPER": "p", "DW_RP_ID": "localhost", "DW_ORIGIN": ORIGIN}


def test_limits_default_to_previous_values(tmp_path):
    c = Config.from_env(base_env(tmp_path))
    assert (c.rate_per_min, c.quota_per_day, c.max_agents, c.reg_per_hour) == (None, None, None, None)


def test_limits_parse_and_reject_garbage(tmp_path):
    e = base_env(tmp_path)
    c = Config.from_env(dict(e, DW_RATE_PER_MIN="5", DW_QUOTA_PER_DAY="7", DW_MAX_AGENTS="2", DW_REG_PER_HOUR="99"))
    assert (c.rate_per_min, c.quota_per_day, c.max_agents, c.reg_per_hour) == (5, 7, 2, 99)
    for bad in ("0", "-1", "x", "1.5"):
        with pytest.raises(ConfigError):
            Config.from_env(dict(e, DW_RATE_PER_MIN=bad))


def _client(cfg, **lim):
    for k, v in lim.items():
        setattr(cfg, k, v)
    return TestClient(create_app(cfg), base_url=ORIGIN)


def test_env_rate_limit(cfg):
    c = _client(cfg, rate_per_min=4)
    o = Owner(c).register("A")
    ag, hdr = o.new_agent()
    codes = [act(c, hdr, "read_file", {"p": i}).status_code for i in range(6)]
    assert codes == [200] * 4 + [429] * 2
    assert act(c, hdr, "read_file", {}).json()["detail"] == "slow down: 4 requests a minute per key; the call did not run"


def test_env_quota_and_agents(cfg):
    c = _client(cfg, quota_per_day=2, max_agents=1)
    o = Owner(c).register("A")
    ag, hdr = o.new_agent()
    assert o.post("/api/agents", name="2nd").json()["error"] == "QUOTA"
    assert [act(c, hdr, "publish", {"p": i}).status_code for i in range(3)] == [200, 200, 429]   # 0.2.45: reads do not count


def test_env_registrations(cfg):
    c = _client(cfg, reg_per_hour=1)
    Owner(c).register("A")
    r = c.post("/api/auth/register/begin", json={"display_name": "B"}, headers={"Origin": ORIGIN})
    assert r.status_code == 429 and r.json()["error"] == "RATE_LIMIT"
