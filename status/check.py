#!/usr/bin/env python3
"""Status page of a witness, built OFF the witness (GitHub Actions + GitHub Pages; .github/workflows/status.yml).

    python status/check.py OUT_DIR            # env: WITNESS_URL (required), PREV (URL or file of the published history.json), KEEP

One run = one check from outside: GET <witness>/healthz (200 and {"ok": true}) and GET <witness>/checkpoint (200, a C2SP signed note:
origin line, tree size, root hash, blank line, at least one signature line). The new check is added to the history the page published
last time (PREV), and OUT_DIR gets index.html (static, no script), history.json and status.json.

States: up (both answer), degraded (healthz answers, the checkpoint does not or an answer took > SLOW_MS), down (healthz does not answer),
alarm (the checkpoint's tree size went DOWN or its origin changed since the last check: the public log must only grow -- tell the
operator, this is not an outage). The exit code is 0 in every case; the state is written to $GITHUB_OUTPUT (the workflow fails the run
after publishing when it is down or alarm, so GitHub notifies the repository's maintainers).

Stdlib only, no secrets: nothing is sent but two GET requests to a public witness and one to the public page itself.
Honest limits: GitHub runs scheduled workflows "best effort" (often 5-20 min late, sometimes skipped), so a gap in the history is not an
outage; one runner region checks, so a network problem between GitHub and the witness looks like "down"; the checkpoint's signature is
not verified here (verify it with the witness key: docs/anchors.md), only that the log does not shrink.
"""
import html
import json
import os
import sys
import time
import urllib.error
import urllib.request

SLOW_MS = 5000
TIMEOUT_S = 15
MAX_BODY = 64 * 1024
KEYS = {"t": int, "state": str, "healthz": int, "healthz_ms": int, "checkpoint": int, "checkpoint_ms": int, "size": int, "origin": str, "note": str}


def fetch(url):
    """-> (http status or 0, milliseconds, body bytes or b'', error name or '')."""
    t0 = time.monotonic()
    req = urllib.request.Request(url, headers={"User-Agent": "witness-status-check/1 (+GitHub Actions)", "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            body = r.read(MAX_BODY)
            return r.status, int((time.monotonic() - t0) * 1000), body, ""
    except urllib.error.HTTPError as e:
        return e.code, int((time.monotonic() - t0) * 1000), b"", "HTTP %d" % e.code
    except Exception as e:  # noqa: BLE001 - every failure is one state of the check
        return 0, int((time.monotonic() - t0) * 1000), b"", type(e).__name__


def parse_checkpoint(body):
    """-> (origin, size) of a C2SP signed note, or (None, None)."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None, None
    head, sep, sigs = text.partition("\n\n")
    lines = head.split("\n")
    if not sep or len(lines) < 3 or not lines[1].isdigit() or not any(s.startswith("— ") for s in sigs.split("\n")):
        return None, None
    return lines[0][:200], int(lines[1])


def clean(prev):
    """The previous history is the page's own output, still: keep only known keys of the right type."""
    out = []
    for e in prev if isinstance(prev, list) else []:
        if isinstance(e, dict) and isinstance(e.get("t"), int) and isinstance(e.get("state"), str):
            out.append({k: e[k] for k, typ in KEYS.items() if isinstance(e.get(k), typ) and not isinstance(e.get(k), bool)})
    return out


def load_prev(src):
    if not src:
        return []
    try:
        if src.startswith("https://"):
            code, _, body, _ = fetch(src + ("&" if "?" in src else "?") + "nocache=%d" % time.time())
            if code != 200:
                return []
            return clean(json.loads(body.decode("utf-8")))
        with open(src, encoding="utf-8") as f:
            return clean(json.load(f))
    except Exception:  # noqa: BLE001 - no usable history: start a new one
        return []


def check(base, last):
    e = {"t": int(time.time())}
    code, ms, body, err = fetch(base + "/healthz")
    ok_h = False
    if code == 200:
        try:
            ok_h = json.loads(body.decode("utf-8")).get("ok") is True
        except Exception:  # noqa: BLE001
            ok_h = False
    e["healthz"], e["healthz_ms"] = code, ms
    code, ms2, body, err2 = fetch(base + "/checkpoint")
    origin, size = parse_checkpoint(body) if code == 200 else (None, None)
    e["checkpoint"], e["checkpoint_ms"] = code, ms2
    if size is not None:
        e["size"], e["origin"] = size, origin
    notes = []
    if not ok_h:
        e["state"] = "down"
        notes.append("healthz: " + (err or "not ok"))
    elif size is None:
        e["state"] = "degraded"
        notes.append("checkpoint: " + (err2 or "not a signed checkpoint"))
    elif max(ms, ms2) > SLOW_MS:
        e["state"] = "degraded"
        notes.append("slow: %d ms" % max(ms, ms2))
    else:
        e["state"] = "up"
    if last is not None and size is not None:
        if isinstance(last.get("size"), int) and size < last["size"]:
            e["state"] = "alarm"
            notes.append("the public log went back: tree size %d -> %d (largest seen %d)" % (last["size"], size, last["size"]))
        if isinstance(last.get("origin"), str) and origin != last["origin"]:
            e["state"] = "alarm"
            notes.append("checkpoint origin changed")
    if notes:
        e["note"] = "; ".join(notes)[:300]
    return e


def uptime(hist, since):
    xs = [e for e in hist if e["t"] >= since]
    if not xs:
        return None
    return round(100.0 * sum(1 for e in xs if e["state"] in ("up", "degraded")) / len(xs), 2)


def utc(t):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t))


WORD = {"up": "Working", "degraded": "Working, partly slow or incomplete", "down": "Not reachable", "alarm": "Working, but its public log went back: the operator is told"}


def page(base, hist, st):
    cur = hist[-1]
    esc = html.escape
    changes = [e for i, e in enumerate(hist) if i == 0 or e["state"] != hist[i - 1]["state"]][-30:]
    rows = "".join("<tr><td>%s</td><td class=s-%s>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
        esc(utc(e["t"])), esc(e["state"]), esc(e["state"]), e.get("healthz", ""), e.get("checkpoint", ""), esc(e.get("note", "")))
        for e in reversed(hist[-100:]))
    ch = "".join("<li>%s: %s%s</li>" % (esc(utc(e["t"])), esc(WORD.get(e["state"], e["state"])), (" (" + esc(e["note"]) + ")") if e.get("note") else "")
                 for e in reversed(changes))
    u24, u7 = st["uptime_24h"], st["uptime_7d"]
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="300"><title>Witness status</title>
<style>
:root{--bg:#fafafa;--fg:#18181b;--mute:#52525b;--line:#e4e4e7;--ok:#15803d;--warn:#a16207;--bad:#b91c1c}
@media (prefers-color-scheme:dark){:root{--bg:#09090b;--fg:#fafafa;--mute:#a1a1aa;--line:#27272a;--ok:#4ade80;--warn:#facc15;--bad:#f87171}}
body{background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;margin:0;padding:16px}main{max-width:860px;margin:auto}
.big{font-size:1.6rem;font-weight:700}.s-up{color:var(--ok)}.s-degraded{color:var(--warn)}.s-down,.s-alarm{color:var(--bad)}
p.mute,li{color:var(--mute)}table{border-collapse:collapse;width:100%%;font-size:.85rem}td,th{border-bottom:1px solid var(--line);padding:4px 6px;text-align:left}
.wrap{overflow-x:auto}</style></head>
<body><main>
<h1>Witness status</h1>
<p>Witness: <code>%s</code></p>
<p class="big s-%s">%s</p>
<p>Last check: %s. Reachable in the last 24 hours: %s; in the last 7 days: %s.</p>
<p class="mute">Checked from outside the witness (GitHub Actions, about every 10 minutes; GitHub may run a check late or skip it, so a gap is
not an outage). What is checked: <code>/healthz</code> answers, and <code>/checkpoint</code> (the signed head of the public log) answers and
never goes back. Machine-readable: <a href="status.json">status.json</a>, <a href="history.json">history.json</a>.
If the witness is not reachable, your agent's calls that need it are refused (nothing runs without the witness); retry when this page
says Working.</p>
<h2>Changes</h2><ul>%s</ul>
<h2>Last checks</h2><div class="wrap"><table><tr><th>Time</th><th>State</th><th>/healthz</th><th>/checkpoint</th><th>Note</th></tr>%s</table></div>
</main></body></html>
""" % (esc(base), esc(cur["state"]), esc(WORD.get(cur["state"], cur["state"])), esc(utc(cur["t"])),
       "%s%%" % u24 if u24 is not None else "no data", "%s%%" % u7 if u7 is not None else "no data", ch, rows)


def main(argv):
    if len(argv) != 2:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    base = (os.environ.get("WITNESS_URL") or "").strip().rstrip("/")
    if not base.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        print("WITNESS_URL must be https:// (or a local http address for a test)", file=sys.stderr)
        return 2
    keep = max(10, min(int(os.environ.get("KEEP") or 1000), 20000))
    hist = load_prev(os.environ.get("PREV") or "")
    # compared with the LARGEST size seen (same origin): a log that went back stays "alarm" until it is larger again
    sizes = [e["size"] for e in hist if isinstance(e.get("size"), int)]
    ref = dict(hist[-1], size=max(sizes)) if hist and sizes else (hist[-1] if hist else None)
    hist.append(check(base, ref))
    hist = hist[-keep:]
    now = hist[-1]["t"]
    st = {"witness": base, "state": hist[-1]["state"], "checked_at": now, "last": hist[-1],
          "uptime_24h": uptime(hist, now - 86400), "uptime_7d": uptime(hist, now - 7 * 86400), "checks_kept": len(hist)}
    out = argv[1]
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "history.json"), "w", encoding="utf-8") as f:
        json.dump(hist, f, separators=(",", ":"))
    with open(os.path.join(out, "status.json"), "w", encoding="utf-8") as f:
        json.dump(st, f, indent=1)
    with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as f:
        f.write(page(base, hist, st))
    with open(os.path.join(out, ".nojekyll"), "w") as f:
        f.write("")
    go = os.environ.get("GITHUB_OUTPUT")
    if go:
        with open(go, "a", encoding="utf-8") as f:
            f.write("state=%s\n" % hist[-1]["state"])
    print("%s %s %s" % (utc(now), hist[-1]["state"], hist[-1].get("note", "")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
