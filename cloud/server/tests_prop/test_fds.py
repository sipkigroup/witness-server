"""Descriptor budget: a World that is closed gives every descriptor back (found 05.11: server.lock leaked one per World,
PROP_N=5000 died with 'Too many open files' after ~70 min)."""
import os

import prop_harness as h


def nfd():
    return len(os.listdir("/dev/fd"))


def test_worlds_do_not_leak_descriptors():
    h.World().close()                              # warm-up: libraries open their own files once
    before = nfd()
    for _ in range(25):
        h.World().close()
    assert nfd() - before <= 3, "descriptors grew by %d over 25 worlds" % (nfd() - before)


def test_judge_does_not_leak_descriptors():
    w = h.World()
    try:
        w.ctx.cfg.rate_per_min = 10 ** 9
        w.judge("ls")
        before = nfd()
        for i in range(300):
            w.judge("echo %d" % i)
        assert nfd() - before <= 3
    finally:
        w.close()
