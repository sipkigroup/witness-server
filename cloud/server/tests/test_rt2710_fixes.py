"""2710rt fixes: per-key long poll cap, waiting.begin guard, exact `wait` parsing in DropWatch."""
import asyncio

from app import waiting
from app.main import Shed, DropWatch, wait_seconds


def _run_polls(n, qs=b"wait=20", cap=3):
    seen = []

    async def slow(scope, receive, send):
        seen.append(scope["query_string"])
        await asyncio.sleep(0.2)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    s = Shed(slow, limit=10, poll_per_key=cap)

    async def call():
        async def send(m):
            pass

        async def recv():
            return {"type": "http.request", "body": b"", "more_body": False}
        await s({"type": "http", "path": "/v1/actions/r_abc", "method": "GET", "query_string": qs,
                 "headers": [(b"authorization", b"Bearer dwk_k")]}, recv, send)

    async def main():
        await asyncio.gather(*[call() for _ in range(n)])
    asyncio.run(main())
    return s, seen


def test_long_polls_of_one_key_are_capped_and_degrade_to_wait0():
    s, seen = _run_polls(20)
    assert seen.count(b"wait=20") == 3                       # only 3 real long polls
    assert seen.count(b"wait=0") == 17                       # the rest answered at once (status, not 429)
    assert s.polls == {} and s.n == 0


def test_exact_wait_parsing():
    assert wait_seconds(b"wait=5") == 5 and wait_seconds(b"x=1&wait=5") == 5
    assert wait_seconds(b"nowait=5") == 0 and wait_seconds(b"wait=0") == 0 and wait_seconds(b"wait=abc") == 0
    assert wait_seconds(b"") == 0


def test_dropwatch_ignores_nowait_substring():
    hit = []

    async def app(scope, receive, send):
        hit.append("dw_dropped" in scope)
    d = DropWatch(app)

    n = []

    async def recv():
        if not n:
            n.append(1)
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(3600)

    async def send(m):
        pass
    for qs, want in ((b"nowait=5", False), (b"wait=5", True)):
        hit.clear()
        n.clear()
        asyncio.run(d({"type": "http", "path": "/v1/actions/r_abc", "method": "GET", "query_string": qs, "headers": []}, recv, send))
        assert hit == [want], qs


def test_waiting_begin_is_capped():
    waiting._open.clear()
    for i in range(waiting.MAX_NOTES + 50):
        waiting.begin("r_F%d" % i)
    assert len(waiting._open) <= waiting.MAX_NOTES
    waiting._open.clear()
