"""JSON logs to stdout: ts, level, msg, route, status, ms, account. NEVER bodies, arguments, keys or cookies."""
import json
import sys
import threading
import time

_lock = threading.Lock()


def log(level, msg, **kw):
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "level": level, "msg": msg}
    rec.update({k: v for k, v in kw.items() if v is not None})
    with _lock:
        sys.stdout.write(json.dumps(rec, ensure_ascii=False) + "\n")
        sys.stdout.flush()
