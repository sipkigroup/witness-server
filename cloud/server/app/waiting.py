"""27.10 (polygon O3): which pending calls an agent is still waiting for.

The hook waits for the owner's answer by long-polling GET /v1/actions/{rid}?wait=N (N <= 25 s, one request after another). Each poll is
noted here, in memory (one server process; nothing is written per poll). A call nobody polled for in GRACE_S is one the agent stopped waiting
for: Claude Code's hook timeout, Ctrl-C, a closed session, or a hook that does not wait at all (DEUS_WITNESS_HOOK_WAIT 0: denied at once
with "approve it in Witness, then retry"). Such a call is NOT cancelled: the owner may still approve it and the agent repeats the call (the
quickstart path relies on that). The approval pages only say it and put the calls an agent waits on now first.
Unknown (None) for a call younger than GRACE_S, and for GRACE_S after the process started (the notes are not kept across restarts).

2710u (polygon series 2, proposal 3): a long poll the CLIENT dropped (http.disconnect: the hook process killed by Claude Code's hook
timeout, Ctrl-C, a closed session) marks the call at once (False), when no other poll of it is open. Safe because the signal only ever says
"stopped" earlier: our hooks and SDKs (Python, TS) never re-poll after a dropped connection (they raise and the call is denied), and any
later poll of the call (a third-party client that reconnects) says True again at once. A network that dies without closing the connection
(Wi-Fi gone, a lid closed) gives no disconnect: such a call is marked after GRACE_S, as before."""
import time

GRACE_S = 35.0                 # a long poll is at most 25 s, then the hook asks again at once
MAX_NOTES = 20000

_polls = {}
_open = {}                     # rid -> long polls of it open now
_gone = {}                     # rid -> when its last open long poll was dropped by the client
_told = {}                     # 0.2.43b (C): rid -> when the hook SAID its last poll ended (?final=1): no FINAL_S grace
_final = {}                    # s7 (Z3): rid -> when a SHORT long poll (wait < MAX_WAIT) ended by time with the call still pending
MAX_WAIT = 25                  # the longest long poll the server holds (api_agent.action_get)
FINAL_S = 2.0                  # a hook that goes on waiting asks again at once; one that gave up does not
_started = time.time()


def _now():
    return time.time()


def note(rid, now=None):
    t = _now() if now is None else now
    if len(_polls) >= MAX_NOTES:
        for k in [k for k, v in _polls.items() if t - v > 3600]:
            _polls.pop(k, None)
        if len(_polls) >= MAX_NOTES:
            _polls.clear()
    _polls[rid] = t
    _gone.pop(rid, None)
    _final.pop(rid, None)


def begin(rid):
    if rid not in _open and len(_open) >= MAX_NOTES:       # 2710rt: the same guard as _polls/_gone
        _open.clear()
    _open[rid] = _open.get(rid, 0) + 1


def end(rid, dropped=False, now=None, final=False, told=False):
    """A long poll of `rid` ended; dropped = the client went away before the answer; final (s7, Z3) = it asked for less than MAX_WAIT and
    ended by time with no answer: our hooks and SDKs ask for less only for the rest of their own deadline (wait = min(25, left)), so this
    is the last poll of a hook that is about to say "nobody approved it within N s". Unless the same call is polled again within FINAL_S,
    it is marked at once, not GRACE_S later: the approval pages then put the call the agent waits on now first (polygon series 7, Z3:
    after a timeout the old call was the first one the owner saw)."""
    n = _open.get(rid, 1) - 1
    if n > 0:
        _open[rid] = n
        return
    _open.pop(rid, None)
    if final and not dropped:
        if len(_final) >= MAX_NOTES:
            _final.clear()
        # 0.2.43b (C): a hook that SAYS this was its last poll (`final=1`, hook 0.2.43+) gave up now, not FINAL_S later
        _final[rid] = _now() if now is None else now
        if told:
            if len(_told) >= MAX_NOTES:
                _told.clear()
            _told[rid] = _final[rid]
        else:
            _told.pop(rid, None)
    if dropped:
        if len(_gone) >= MAX_NOTES:
            _gone.clear()
        _gone[rid] = _now() if now is None else now


def state(rid, created_at, now=None):
    """-> True (polled within GRACE_S), False (not polled within GRACE_S of a call older than GRACE_S), None (cannot tell yet)."""
    t = _now() if now is None else now
    last = _polls.get(rid)
    g = _gone.get(rid)
    if g is not None and (last is None or g >= last):
        return False
    f = _final.get(rid)
    if f is not None and (last is None or f >= last) and (t - f >= FINAL_S or _told.get(rid) == f):
        return False
    if last is not None and t - last <= GRACE_S:
        return True
    if t - _started < GRACE_S or (isinstance(created_at, (int, float)) and t - created_at < GRACE_S):
        return None
    return False


def awaited(row, now=None):
    """N18/N19 0.2.74 (series 10): is the agent's hook waiting for this pending row now? -> True / False / None (cannot tell yet).
    gave_up_at = the hook said it gave up (it is cleared when the same call is sent again: the repeat keeps the rid)."""
    try:
        if row["gave_up_at"]:
            return False
    except (KeyError, IndexError, TypeError):
        pass
    return state(row["rid"], row["created_at"], now)
