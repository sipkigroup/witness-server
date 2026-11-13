"""0.2.88: the strict-sandbox fact must be FRESH (fail closed). The hook reads Claude Code's settings files at every call; Claude Code read them
when the session started (and may or may not reload them). If they changed during the session, the hook's view and Claude Code's real
configuration can differ, in either direction -- e.g. an agent removes `allowedDomains` from a file: the hook then reports a strict sandbox
while Claude Code still lets that host through. Rule: a session whose settings changed is not strict until a new session.

Per (agent, session) the witness keeps the first view (table sandbox_sessions):
  settings_digest  the hook's digest of the sandbox-relevant part of every layer (client 0.2.56; sent with every call: facts.sandbox for Bash,
                   facts.settings for the other tools, so the first view is the session's first call the hook saw);
  fact key         sandbox.fact_key of the first Bash fact (every settings key of the fact; per-call keys left out);
and marks the session `changed` (sticky) when
  - a later call reports another digest or another fact key;
  - the first view says a settings file was modified after the session started (`since_start`, or the start is unknown);
  - a call of the session writes a settings file (Write / Edit / MultiEdit / NotebookEdit target, a visible write of a Bash line), whatever
    the owner then answers.
No session id (a client <= 0.2.55, or a malformed one): not strict either -- nothing can be compared. Best effort on the store: an error
counts as not fresh. Rows are kept 30 days (pruned per agent when a new session starts)."""
from __future__ import annotations

import posixpath
import time

from . import sandbox as hsb

KEEP_S = 30 * 86400
WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit", "Bash", "Bash.write", "Bash.danger", "Bash.net")


def view(body):
    """-> (settings_digest, fact_key or None, since_start) of this judge request, or None when it carries no usable view."""
    f = body.get("facts") if isinstance(body, dict) else None
    if not isinstance(f, dict):
        return None
    sb = f.get("sandbox")
    if sb is not None:
        if not hsb.well_formed(sb):
            return None
        return sb["settings_digest"], hsb.fact_key(sb), list(sb["since_start"])
    st = f.get("settings")
    if isinstance(st, dict) and isinstance(st.get("settings_digest"), str) and hsb.DIGEST.fullmatch(st["settings_digest"]) \
            and hsb._strs(st.get("since_start"), 64):
        return st["settings_digest"], None, list(st["since_start"])
    return None


def settings_path(p) -> bool:
    """A Claude Code settings layer file: <dir>/.claude/settings.json / settings.local.json, managed-settings.json, managed-settings.d/*."""
    if not isinstance(p, str) or not p:
        return False
    n = posixpath.normpath(p)
    b, d = posixpath.basename(n), posixpath.basename(posixpath.dirname(n))
    return (b in ("settings.json", "settings.local.json") and d == ".claude") or b == "managed-settings.json" or d == "managed-settings.d"


def writes_settings(parts) -> bool:
    for m in parts:
        w = m.args.get("_witness") if isinstance(getattr(m, "args", None), dict) else None
        if m.tool not in WRITE_TOOLS or not isinstance(w, dict):
            continue
        cand = ([w["path"]] if m.tool in ("Write", "Edit", "MultiEdit", "NotebookEdit") and isinstance(w.get("path"), str) else []) + \
            [x for x in (w.get("writes") if isinstance(w.get("writes"), list) else []) if isinstance(x, str)]
        if any(settings_path(x) for x in cand):
            return True
    return False


def note(ctx, agent, sid, body, parts) -> bool:
    """Record this request's view for the session; -> True when the session's settings are fresh (unchanged since its first view)."""
    if not sid:
        return False
    v = view(body)
    wrote = writes_settings(parts)
    now = int(time.time())
    try:
        row = ctx.db.one("SELECT sdig, fkey, changed FROM sandbox_sessions WHERE agent_id=? AND session_id=?", (agent["id"], sid))
        if row is None:
            if v is None and not wrote:
                return False                          # nothing to compare with yet; a later call makes the first view
            changed = 1 if (wrote or (v is not None and v[2])) else 0
            ctx.db.x("DELETE FROM sandbox_sessions WHERE agent_id=? AND t<?", (agent["id"], now - KEEP_S))
            ctx.db.x("INSERT OR IGNORE INTO sandbox_sessions(account_id, agent_id, session_id, sdig, fkey, changed, t) VALUES(?,?,?,?,?,?,?)",
                     (agent["account_id"], agent["id"], sid, v[0] if v else None, v[1] if v else None, changed, now))
            row = ctx.db.one("SELECT sdig, fkey, changed FROM sandbox_sessions WHERE agent_id=? AND session_id=?", (agent["id"], sid))
            if row is None:
                return False
        sdig, fkey, changed = row["sdig"], row["fkey"], row["changed"]
        if v is not None:
            if sdig is None:
                sdig = v[0]
            elif v[0] != sdig:
                changed = 1
            if v[1] is not None:
                if fkey is None:
                    fkey = v[1]
                elif v[1] != fkey:
                    changed = 1
        if wrote:
            changed = 1
        if (sdig, fkey, changed) != (row["sdig"], row["fkey"], row["changed"]):
            ctx.db.x("UPDATE sandbox_sessions SET sdig=?, fkey=?, changed=MAX(changed, ?), t=? WHERE agent_id=? AND session_id=?",
                     (sdig, fkey, changed, now, agent["id"], sid))
        return not changed and v is not None
    except Exception:      # noqa: BLE001  the store failed: not fresh (asked)
        return False


FILE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")


def session_strict(ctx, agent, sid, parts, fresh) -> None:
    """r0261c (д, decision of Deus): Write / Edit get С3 (a file run later outside the sandbox) only under a FRESH strict fact of the
    session. The hook sends the sandbox fact with Bash calls only: a Bash part judged strict marks the session (column `strict`); a file
    part of a fresh session so marked carries `sbx_session` (strict_policy.write_cover). Best effort: an error leaves the mark off (П2)."""
    if not sid or not fresh:
        return
    try:
        ws = [(m, m.args.get("_witness")) for m in parts if isinstance(getattr(m, "args", None), dict)]
        if any(isinstance(w, dict) and m.tool.startswith("Bash") and w.get("sandbox") == {"strict": True} for m, w in ws):
            ctx.db.x("UPDATE sandbox_sessions SET strict=1 WHERE agent_id=? AND session_id=?", (agent["id"], sid))
        fw = [w for m, w in ws if m.tool in FILE_TOOLS and isinstance(w, dict)]
        if fw:
            row = ctx.db.one("SELECT strict FROM sandbox_sessions WHERE agent_id=? AND session_id=?", (agent["id"], sid))
            if row is not None and row["strict"] == 1:
                for w in fw:
                    w["sbx_session"] = True
    except Exception:      # noqa: BLE001
        return


def strip_strict(parts) -> None:
    """The line is judged as without a strict sandbox (byte-equal to a call without the fact)."""
    for m in parts:
        w = m.args.get("_witness") if isinstance(getattr(m, "args", None), dict) else None
        if isinstance(w, dict):
            w.pop("sandbox", None)
            w.pop("harness_held", None)
            w.pop("sbx_home", None)
            w.pop("sbx_sid", None)               # 06.11 (law 2): the held harness mark is a question again without the strict fact
            w.pop("sbx_code", None)              # 10.11 (r0260): code-only marks / hosts are contained only under the strict fact
            w.pop("sbx_listed", None)            # 10.11 (r0260, Р-1011-сеть)
            w.pop("sbx_cred_closed", None)       # 11.11 (r0260)
            w.pop("sbx_session", None)           # r0261c (д)
