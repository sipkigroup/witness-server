"""L3 advisor (ARHITEKTURA-0.2 §4.2): `dw_dlp.advise` in a separate process pool with ONE worker, timeout 300 ms.
It can only HOLD: ("hold", "ADVISORY_HOLD") when the dry verdict of the core is allow AND a label is in the organisation's list.
Dry deny/defer -> no effect. Timeout or error -> no mark (L1/L2 always work). Release = wa-sig over release_payload (typ dw-release+cbor)."""
import concurrent.futures as cf
import importlib
import multiprocessing
import threading

from app.flow import store

CODE_HOLD = "ADVISORY_HOLD"
CODE_REJECTED = "ADVISORY_REJECTED"
TIMEOUT_S = 0.3
FN = None           # "module:function" override of the advise function (resolved inside the worker; tests use it for a slow advisor)

_pool = None
_pool_lock = threading.Lock()


def _resolve():
    if FN:
        mod, name = FN.split(":")
        return getattr(importlib.import_module(mod), name)
    from dw_dlp.advisor import advise          # task 03 (cloud/lib/dlp); 0.2.0: the stand-in dlp_stub is gone
    return advise


# 0.2.0 (merge 02 <-> 03): dw_dlp.advisor names SIGNALS (address_words, spelled_email, decoded:iban ...), the organisation's list holds
# DATA CLASSES of -04/L2 (postal_address, iban ...). A signal holds an item when one of its classes is in the list; "*" = any listed class.
SIGNAL_CLASSES = {
    "address_words": ("postal_address",), "spelled_address": ("postal_address",), "ner:location": ("postal_address",),
    "spelled_email": ("email_address",),
    "spelled_digits": ("card_number", "phone", "ssn", "iban"),
    "personal_words": ("ssn", "card_number", "iban", "phone", "crypto_address"),
    "encoded_blob": ("*",),
    "oversize_text": ("*",),          # R3-08: the advisor read only the head and the tail of a long text
    "advisor_timeout": ("*",),        # R3-08: no answer in time = no second opinion = a human looks (was: fail open)
}


def classes_of(label):
    if label.startswith("decoded:"):
        return (label[len("decoded:"):],)
    return SIGNAL_CLASSES.get(label, (label,))


def _run(fn_name, text, mode):
    global FN
    FN = fn_name
    out = _resolve()(text, mode)
    return [(str(l), float(s)) for l, s in out]


def _noop():
    return True


def pool():
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = cf.ProcessPoolExecutor(max_workers=1, mp_context=multiprocessing.get_context("forkserver"))
        return _pool


def warm(timeout=30):
    """Start the worker ahead of the first real call (process start-up does not fit into 300 ms)."""
    return pool().submit(_noop).result(timeout=timeout)


def reset():
    global _pool
    with _pool_lock:
        p, _pool = _pool, None
    if p is not None:
        p.shutdown(wait=False, cancel_futures=True)


def advise(text, mode, timeout=TIMEOUT_S):
    """-> list of labels, [] on off/error, ["advisor_timeout"] on timeout (a hold, 0.2.2). A timed-out worker is replaced (it may be stuck)."""
    if not text or mode in (None, "off"):
        return []
    try:
        fut = pool().submit(_run, FN, text, mode)
        return sorted({l for l, _ in fut.result(timeout=timeout)})
    except cf.TimeoutError:
        reset()
        return ["advisor_timeout"]
    except Exception:
        return []


def org_labels(ctx, account_id, mandate_row):
    """Labels that hold: the mandate's forbidden_data (the organisation's closed classes) + org_settings.advisor_labels (json list) if 01 adds it."""
    labs = set()
    if mandate_row is not None:
        m = store.jl(mandate_row["mandate_json"], {}) or {}
        labs |= {x for x in m.get("forbidden_data", []) if isinstance(x, str)}
    s = store.settings(ctx, account_id)
    extra = s.get("advisor_labels")
    if isinstance(extra, str):
        labs |= {x for x in (store.jl(extra, []) or []) if isinstance(x, str)}
    return labs


def check(ctx, agent, mandate_row, act, dry_verdict):
    """-> None | ("hold", "ADVISORY_HOLD"). Called only with the text that toolmap.build_action scanned (by args_sha256)."""
    if dry_verdict != "allow" or not isinstance(act, dict):
        return None
    mode = store.settings(ctx, agent["account_id"])["advisor"]
    if mode in (None, "off"):
        return None
    from app import toolmap as tm
    text = tm.last_text(act.get("args_sha256"))
    labs = org_labels(ctx, agent["account_id"], mandate_row)
    if not text or not labs:
        return None
    hit = sorted({c if c != "*" else sorted(labs)[0] for l in advise(text, mode) for c in classes_of(l) if c == "*" or c in labs})
    if not hit:
        return None
    store.ensure(ctx)
    ctx.db.x("INSERT OR REPLACE INTO flow_held(rid,account_id,label,mode,t) VALUES(?,?,?,?,?)",
             ("pending:%s:%s" % (agent["account_id"], act["args_sha256"]), agent["account_id"], hit[0], mode, store.now()))
    return ("hold", CODE_HOLD)


def held_mark(ctx, args_sha256, account_id):
    """R3-14: the key names the account, so the same call in two organisations does not share one mark."""
    store.ensure(ctx)
    r = ctx.db.one("SELECT label, mode FROM flow_held WHERE rid=? AND account_id=?", ("pending:%s:%s" % (account_id, args_sha256), account_id))
    return (r["label"], r["mode"]) if r else (None, None)


def adv_released(mode, label, kid):
    """`adv` member after a release: "<mode>-1:<label>:released:<kid 8 hex>" (strings only, no text values)."""
    return "%s-1:%s:released:%s" % (mode or "heuristic", label or "unknown", kid.hex()[:8])
