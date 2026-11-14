"""r0285 (NAGRUZKA-I-EKONOMIKA-1311 p.1): a burst of one key waits for a slot of its key instead of 429 at once.

Claude Code runs up to 10 tool calls of one agent at once (CLAUDE_CODE_MAX_TOOL_USE_CONCURRENCY, default 10) and subagents share the key:
with PER_KEY_INFLIGHT = 8, 10 hooks at once got 3 x 429 (r1311 load script par.py, hook 0.2.71). PRED (written before the change): with the
old Shed 32 calls of one key -> 24 x 429; with the queue -> 0 x 429, at most PER_KEY_INFLIGHT of the key in progress at any moment, other
keys still served, and a burst beyond the queue still refused at once."""
import asyncio
import time

from app.main import PER_KEY_INFLIGHT, PER_KEY_QUEUE, Shed


def _run(s, calls):
    got = []
    peak = {"n": 0, "max": 0}

    async def call(key):
        st = {}

        async def send(m):
            if m["type"] == "http.response.start":
                st["status"] = m["status"]

        async def recv():
            return {"type": "http.request", "body": b"", "more_body": False}
        t = time.time()
        await s({"type": "http", "path": "/v1/hook/judge", "method": "POST", "query_string": b"",
                 "headers": [(b"authorization", b"Bearer dwk_" + key)]}, recv, send)
        got.append((key, st["status"], time.time() - t))

    async def main():
        await asyncio.gather(*[call(k) for k in calls])
    asyncio.run(main())
    return got, peak


def _slow(peak, dt=0.05):
    async def app(scope, receive, send):
        peak["n"] += 1
        peak["max"] = max(peak["max"], peak["n"])
        await asyncio.sleep(dt)
        peak["n"] -= 1
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    return app


def test_32_at_once_of_one_key_all_served_never_more_than_the_bound_in_progress():
    peak = {"n": 0, "max": 0}
    s = Shed(_slow(peak), limit=256)
    got, _ = _run(s, [b"agent"] * 32 + [b"other"] * 3)
    assert [c for _, c, _ in got].count(429) == 0, got
    assert peak["max"] <= PER_KEY_INFLIGHT + 3               # the burst never held more than its share of work
    assert s.keys == {} and s.waiters == {} and s.n == 0 and s.key_refused == 0


def test_beyond_the_queue_is_refused_at_once_and_the_bound_stays():
    peak = {"n": 0, "max": 0}
    s = Shed(_slow(peak, 0.3), limit=256)
    n = PER_KEY_INFLIGHT + PER_KEY_QUEUE + 5
    got, _ = _run(s, [b"burst"] * n + [b"other"])
    burst = [(c, dt) for k, c, dt in got if k == b"burst"]
    assert sum(1 for c, _ in burst if c == 429) == 5
    assert all(dt < 0.1 for c, dt in burst if c == 429)       # the overflow is told at once, it does not wait first
    assert [c for k, c, _ in got if k == b"other"] == [200]
    assert s.keys == {} and s.waiters == {} and s.key_refused == 5


def test_a_wait_longer_than_the_limit_is_429_and_frees_its_place():
    peak = {"n": 0, "max": 0}
    s = Shed(_slow(peak, 0.5), limit=256, per_key=1, per_key_queue=4, per_key_wait=0.2)
    got, _ = _run(s, [b"k"] * 3)
    codes = sorted(c for _, c, _ in got)
    assert codes == [200, 429, 429]
    assert s.keys == {} and s.waiters == {}


def test_a_client_that_leaves_while_waiting_does_not_keep_a_slot():
    peak = {"n": 0, "max": 0}
    s = Shed(_slow(peak, 0.2), limit=256, per_key=1)

    async def main():
        async def recv():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(m):
            pass
        sc = {"type": "http", "path": "/v1/hook/judge", "method": "POST", "query_string": b"", "headers": [(b"authorization", b"Bearer dwk_k")]}
        a = asyncio.ensure_future(s(sc, recv, send))
        await asyncio.sleep(0.01)
        b = asyncio.ensure_future(s(sc, recv, send))
        await asyncio.sleep(0.01)
        b.cancel()
        await asyncio.gather(a, b, return_exceptions=True)
    asyncio.run(main())
    assert s.keys == {} and s.waiters == {}
