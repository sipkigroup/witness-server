"""08: Web Push (RFC 8030 / 8291 / 8292) of approval requests to the owner's phone.

- Subscriptions per account and device (table push_subs); subscribe / unsubscribe need the session, Origin and a fresh passkey (step-up).
- A NEW defer queues one notification; a background worker sends it to every device of the account (pywebpush, VAPID).
  The agent's request never waits for the push service.
- A push is a SIGNAL, not the request (P0-4, 19.10.2026): the payload holds only opaque ids {v:2, k, id, g} - k = kind
  (a approval, s signature, q summary, t test), id = the receipt / signature-request id, g = an opaque per-agent group (tag).
  No agent name, tool, target, amount or count leaves the server, even encrypted (RFC 8291): the service worker shows a fixed text
  and the page loads the request itself after login. Approving is still done only on approve.html with the passkey.
- Anti-bombing (Duo-style): one agent wakes the owner at most once per MIN_GAP_S (15 s); at most N pushes per minute per account
  (DW_PUSH_PER_MIN, default 6); the same (agent, tool, class, target) within COALESCE_S is merged; what was held back is told later
  in ONE summary push. The undelivered pushes of one agent share an RFC 8030 Topic (the push service keeps only the newest).
- "Suspicious" on approve.html (POST /api/push/suspicious): the agent's pushes are muted for MUTE_S (1 hour) and an event row is
  written (push_mutes, + the log); its requests still wait on the approvals page and expire as usual (= not executed).
- Delivery: 429 / 5xx / network error -> up to 3 attempts; 404 / 410 -> the subscription is dead and deleted;
  other 4xx -> failure counted, MAX_FAILS consecutive failures delete it.
- The VAPID private key comes only from DW_VAPID_PRIVATE_KEY_FILE (secret file) or DW_VAPID_PRIVATE_KEY; none = push is off.
- r0276 (SVODKA-1311 p.5): HTTP 201 from the push service is not "delivered". A question's push walks a ladder stored on the question
  (actions.push_state): failed (no push service took it) / sent (taken) -> received (the service worker got it and said so) -> shown
  (the notification is up) -> opened (the person tapped it, the question's page opens). The service worker proves it holds the push with
  `n`, an HMAC of the rid under a server secret that only travels inside the encrypted payload (an agent knows its rid, not `n`, so it
  cannot fake "the owner saw it"). No received within RECV_WAIT_S -> the push is sent ONCE more. The hook's answer for a question that
  is still not opened says so (judge notify: "did not reach your phone: open the link"). /metrics: the share of questions by the last
  state. Only states and times are stored: no device, no endpoint, no text.
"""
import base64
import collections
import hashlib
import hmac
import json
import os
import queue
import re
import threading
import time
from urllib.parse import urlsplit

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from app import auth
from app.config import ConfigError
from app.context import Err, check_json, canon_rid
from app.log import log

DEFAULT_PER_MIN = 6
COALESCE_S = 60                 # the same request shape within this window is merged into the summary
MIN_GAP_S = 15                  # one agent: at most one push per 15 s (later ones go into the summary)
MUTE_S = 3600                   # "suspicious": no pushes from that agent for an hour
SUMMARY_DELAY_S = 30            # a summary is sent no sooner than this after the last push of the account
MAX_SUBS = 10                   # devices per account
MAX_FAILS = 5                   # consecutive non-retryable failures before a subscription is dropped
ATTEMPTS = 3
TTL_S = 900                     # = approval lifetime: a push older than the request is useless
RECV_WAIT_S = 20                # r0276: no "received" from the phone within this -> the push is sent once more
RETRY_LATEST_S = 120            # r0276: ... but not later than this after the first push (after a restart, a long queue): late, it only adds noise
LADDER = ("failed", "sent", "received", "shown", "opened")     # r0276: a question's push, the last state reached
RANK = {k: i for i, k in enumerate(LADDER)}
ACKS = ("received", "shown", "opened")                          # what the service worker may say
DEFAULT_HOSTS = ("fcm.googleapis.com", "push.services.mozilla.com", "push.apple.com", "notify.windows.com")
B64U_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


def now():
    return int(time.time())


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s):
    if not isinstance(s, str) or not B64U_RE.match(s) or len(s) > 200:
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sub_id(endpoint):
    return hashlib.sha256(endpoint.encode()).hexdigest()[:32]


def load_vapid(cfg):
    """Vapid instance or None (push off). A key that is configured but unusable stops the process (like the witness key)."""
    if not cfg.vapid_key_file and not cfg.vapid_key:
        return None
    from py_vapid import Vapid
    try:
        if cfg.vapid_key_file:
            with open(cfg.vapid_key_file, "rb") as f:
                raw = f.read().strip()
            v = Vapid.from_pem(raw) if raw.startswith(b"-----BEGIN") else Vapid.from_string(raw.decode())
        else:
            v = Vapid.from_string(cfg.vapid_key.strip())
        v.public_key                                    # noqa: B018 - raises if the key did not load
    except Exception as e:
        raise ConfigError("VAPID private key unusable (%s)" % type(e).__name__)
    return v


def vapid_public_b64(v):
    from cryptography.hazmat.primitives import serialization
    return b64u(v.public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))


def group_of(acc, agent_id):
    """Opaque per-agent token for the notification tag and the push Topic: equal for one agent, says nothing about it."""
    return hashlib.sha256(("push-group\0%s\0%s" % (acc, agent_id or "")).encode()).hexdigest()[:16]


def build_note(row, agent_name=None, literals=None):
    """Notification for a new defer. Only opaque ids and a general sentence of the reason (never a host, a path or the agent's words) leave the server; the facts are read by the page after login.
    (agent_name / literals: kept for callers of 0.2.0; nothing of them goes into the payload any more.)"""
    act = json.loads(row["action_json"]) if row.get("action_json") else {}
    cls = act.get("class") or row.get("class") or "action"
    shape = json.dumps([row.get("agent_id"), row.get("tool"), cls, act.get("recipient") or ""], ensure_ascii=False)
    key = hashlib.sha256(shape.encode()).hexdigest()
    g = group_of(row["account_id"], row.get("agent_id"))
    from app import qwords
    what, harm = qwords.short(row.get("reason"))      # 05.11 (owner rule): what + harm in two short lines, from the reason code alone
    return {"account": row["account_id"], "agent": row.get("agent_id"), "key": key, "rid": row["rid"], "expires": row.get("expires"),
            "topic": g, "payload": {"v": 2, "k": "a", "id": row["rid"], "g": g, "t": [what, harm]}}


DELIVERY_TEXT = {      # r0276: what the hook's answer says (after "approve it at <link>"); no device, no address
    "not": "phone push - did NOT reach your phone, open the link above",
    "opened-not": "phone push - reached your phone but was not opened, open the link above",
    "last": "phone push - your phone did not confirm the last push, open the link above",
    "neutral": "phone push; if it did not come, open the link above",       # r0276b: no device has ever acked (an older sw.js)
}


def ladder_counts(db, since):
    """/metrics: questions pushed since `since`, by the last state reached. Counts only."""
    by = {r["push_state"]: r["n"] for r in db.q("SELECT push_state, COUNT(*) AS n FROM actions WHERE push_at>? AND push_state IS NOT NULL "
                                                 "GROUP BY push_state", (since,))}
    return {k: by.get(k, 0) for k in LADDER}


def topic_of(key):
    """RFC 8030 Topic: <= 32 base64url characters; a newer undelivered message with the same topic replaces the older one."""
    return b64u(bytes.fromhex(key))[:32]


class Pusher:
    def __init__(self, ctx, vapid=None, sender=None, clock=time.time, retry_delays=(1.0, 4.0)):
        self.ctx, self.db, self.cfg = ctx, ctx.db, ctx.cfg
        self.vapid = vapid
        self.public_key = vapid_public_b64(vapid) if vapid is not None else None
        self.sender = sender or self._webpush_send
        self.clock = clock
        self.retry_delays = retry_delays
        self.per_min = self.cfg.push_per_min or DEFAULT_PER_MIN
        self.hosts = [h.strip().lower().lstrip(".") for h in (self.cfg.push_hosts or "").split(",") if h.strip()] or list(DEFAULT_HOSTS)
        self.q = queue.Queue()
        self._lock = threading.Lock()
        self._sent = collections.defaultdict(collections.deque)      # account -> times of pushes in the last minute
        self._last_key = {}                                          # (account, key) -> time sent
        self._last_any = {}                                          # account -> time of the last push
        self._last_agent = {}                                        # (account, agent) -> time of its last push
        self._owed = collections.Counter()                           # account -> requests merged or held by the limit
        self._worker = None
        self._session = None
        self.stats = collections.Counter()
        pep = getattr(self.cfg, "key_pepper", None)
        self._ack_key = hashlib.sha256(b"dw-push-ack\0" + (pep.encode() if isinstance(pep, str) and pep else os.urandom(32))).digest()

    @property
    def enabled(self):
        return self.public_key is not None

    # ---------- subscriptions ----------
    def check_endpoint(self, ep):
        if not isinstance(ep, str) or len(ep) > 1024:
            raise Err(422, "PUSH_ENDPOINT", "endpoint must be a URL")
        u = urlsplit(ep)
        host = (u.hostname or "").lower()
        if u.scheme != "https" and not (self.cfg.push_allow_http and u.scheme == "http"):
            raise Err(422, "PUSH_ENDPOINT", "endpoint must be https")
        if u.username or u.password or not host or not any(host == h or host.endswith("." + h) for h in self.hosts):
            raise Err(422, "PUSH_ENDPOINT", "not a known push service")        # the server POSTs there: no arbitrary hosts (SSRF)
        return ep

    def subscribe(self, acc, sub, device, user_id=None):
        if not isinstance(sub, dict) or not isinstance(sub.get("keys"), dict):
            raise Err(400, "BAD_REQUEST", "subscription: {endpoint, keys:{p256dh, auth}}")
        ep = self.check_endpoint(sub.get("endpoint"))
        try:
            p256 = b64u_dec(sub["keys"].get("p256dh"))
            au = b64u_dec(sub["keys"].get("auth"))
        except (ValueError, TypeError):
            raise Err(422, "PUSH_KEYS", "keys must be base64url")
        if len(p256) != 65 or p256[0] != 4 or len(au) != 16:
            raise Err(422, "PUSH_KEYS", "p256dh: 65-byte P-256 point, auth: 16 bytes")
        dev = (device if isinstance(device, str) else "")[:80]
        sid = sub_id(ep)
        with self.db.tx():
            if not self.db.one("SELECT 1 FROM push_subs WHERE id=? AND account_id=?", (sid, acc)) and \
                    self.db.one("SELECT COUNT(*) AS n FROM push_subs WHERE account_id=?", (acc,))["n"] >= MAX_SUBS:
                raise Err(429, "QUOTA", "%d devices per account" % MAX_SUBS)
            # one browser = one endpoint: the account that subscribed last owns it (a shared browser stops getting the old account's pushes)
            old = self.db.one("SELECT user_id, p256dh, auth FROM push_subs WHERE endpoint=?", (ep,))
            if old and old["user_id"] != user_id and (old["p256dh"], old["auth"]) != (b64u(p256), b64u(au)):
                # R3-13: knowing an endpoint URL is not enough to take it over; the browser itself re-sends its own keys (a shared browser)
                raise Err(409, "PUSH_ENDPOINT_TAKEN", "this endpoint is subscribed with other keys")
            self.db.x("DELETE FROM push_subs WHERE endpoint=?", (ep,))
            self.db.x("INSERT INTO push_subs(id,account_id,endpoint,p256dh,auth,device,created_at,fail_count,user_id) VALUES(?,?,?,?,?,?,?,0,?)",
                      (sid, acc, ep, b64u(p256), b64u(au), dev, now(), user_id))
        return {"id": sid, "device": dev}

    def unsubscribe(self, acc, ep=None, sid=None):
        if isinstance(ep, str):
            sid = sub_id(ep)
        if not isinstance(sid, str):
            raise Err(400, "BAD_REQUEST", "endpoint or id")
        self.db.x("DELETE FROM push_subs WHERE id=? AND account_id=?", (sid, acc))

    def list(self, acc):
        return [{"id": r["id"], "device": r["device"], "service": urlsplit(r["endpoint"]).hostname, "created_at": r["created_at"],
                 "last_ok_at": r["last_ok_at"]} for r in self.db.q("SELECT * FROM push_subs WHERE account_id=? ORDER BY created_at", (acc,))]

    # ---------- queue ----------
    def notify_defer(self, row, agent_name, literals):
        if not self.enabled:
            return
        try:
            note = build_note(row, agent_name, literals)
        except Exception as e:  # noqa - a push must never break the agent's request
            log("ERROR", "push note failed: " + type(e).__name__)
            return
        self.q.put(note)
        self._ensure_worker()

    def notify_sigreq(self, acc, sid, k="s"):
        """0.2.0: a signature request of the organisation (mandate / approval by quorum / policy) -> the members whose role it needs
        and who have not signed yet. Resolved by the worker (the first signer's wsig is stored by then).
        RT-SUP 29.10: k "v" = the request replaces one whose view changed (sw.js: "the view changed, sign again"); anything else -> "s"."""
        if not self.enabled:
            return
        key = hashlib.sha256(("sigreq:" + sid).encode()).hexdigest()
        self.q.put({"account": acc, "sigreq": sid, "key": key, "rid": None, "topic": key[:16],
                    "payload": {"v": 2, "k": "v" if k == "v" else "s", "id": sid, "g": key[:16]}})
        self._ensure_worker()

    def notify_security(self, user_id, k):
        """0.2.2: a recovery code was used (k "r") or a passkey was added / removed (k "k") -> every device of that person, at once
        (no merging, no per-minute limit: a security signal is never held back). Fixed text in sw.js; the payload carries no id."""
        # 0.2.14: d = a passkey's device class changed; 0.2.15: p = a new phone declared with a recovery code;
        # 0.2.21: c = a passkey's signature counter went back (possible clone; at most one per key per 10 min, app/keyalert.py)
        if not self.enabled or k not in ("r", "k", "d", "p", "c"):
            return
        self.q.put({"account": user_id, "security": True, "users": [user_id], "key": "sec:" + user_id, "rid": None,
                    "topic": "dw-security", "payload": {"v": 2, "k": k}})
        self._ensure_worker()

    def notify_idle(self, user_id):
        """r0288: the account has not been used for a long time and will be erased (app/trial.py idle_due) -> every device of that
        person, at once, like a security signal (fixed text "i" in sw.js; the payload carries no id). Any sign-in or hook call keeps it."""
        if not self.enabled:
            return
        self.q.put({"account": user_id, "security": True, "users": [user_id], "key": "idle:" + user_id, "rid": None,
                    "topic": "dw-idle", "payload": {"v": 2, "k": "i"}})
        self._ensure_worker()

    def _sigreq_users(self, acc, sid):
        """-> (user ids still needed, body text) of an open signature request; ([], "") when nothing is asked any more."""
        r = self.db.one("SELECT * FROM sig_requests WHERE id=? AND account_id=?", (sid, acc))
        if r is None or r["status"] != "collecting":
            return [], ""
        needs = [tuple(x) for x in json.loads(r["needs"] or "[]")] or [("any", 1)]
        roles = {role for role, _ in needs}
        signed = {s.get("kid") for s in json.loads(r["sigs"] or "[]")}
        users = []
        for m in self.db.q("SELECT user_id, roles, kid FROM members WHERE account_id=? AND status='active'", (acc,)):
            mr = set(json.loads(m["roles"] or "[]"))
            if (("any" in roles and mr - {"observer"}) or mr & roles) and (m["kid"] is None or bytes(m["kid"]).hex() not in signed):
                users.append(m["user_id"])
        if r["kind"] == "approval" and json.loads(r["meta"] or "{}").get("approved"):
            op = self.db.one("SELECT d.operator_user_id AS u FROM actions a JOIN agent_delegations d ON d.agent_id=a.agent_id AND d.ended_at IS NULL "
                             "WHERE a.rid=? AND a.account_id=?", (r["ref"], acc))
            if op is not None:
                users = [u for u in users if u != op["u"]]          # 0.2.13: the operator of a delegated agent is not asked to confirm it
        what = {"mandate": "a mandate", "approval": "an approval", "policy": "a team policy change"}.get(r["kind"], "a request")
        if json.loads(r["meta"] or "{}").get("replaces"):
            return users, "The view changed, sign again: %s (%s)" % (what, ", ".join("%s %d" % n for n in needs))
        return users, "Your signature is needed on %s (%s)" % (what, ", ".join("%s %d" % n for n in needs))

    def _ensure_worker(self):
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._loop, name="push", daemon=True)
                self._worker.start()

    def _loop(self):
        while True:
            try:
                note = self.q.get(timeout=5)
            except queue.Empty:
                note = None
            try:
                if note is not None:
                    self.process(note)
                self.tick()
                self.retry_unreceived()             # r0276: a question's push the phone did not confirm: once more
            except Exception as e:  # noqa
                log("ERROR", "push worker: " + type(e).__name__)
            finally:
                if note is not None:
                    self.q.task_done()

    def drain(self, timeout=10):
        """Tests: wait until every queued notification was processed."""
        end = time.time() + timeout
        while self.q.unfinished_tasks and time.time() < end:
            time.sleep(0.01)
        return not self.q.unfinished_tasks

    # ---------- policy ----------
    def _room(self, acc, t):
        d = self._sent[acc]
        while d and d[0] <= t - 60:
            d.popleft()
        return len(d) < self.per_min

    def _mark(self, acc, t):
        self._sent[acc].append(t)
        self._last_any[acc] = t

    # ---------- "suspicious": mute one agent ----------
    def muted_until(self, acc, agent_id, t=None):
        if not agent_id:
            return 0
        r = self.db.one("SELECT MAX(until) AS u FROM push_mutes WHERE account_id=? AND agent_id=?", (acc, agent_id))
        u = (r["u"] if r else None) or 0
        return u if u > (self.clock() if t is None else t) else 0

    def mark_suspicious(self, acc, rid, user_id=None):
        """The person says a request looks wrong: no pushes from its agent for MUTE_S, one event row. -> {agent_id, muted_until}."""
        a = self.db.one("SELECT agent_id FROM actions WHERE rid=? AND account_id=?", (rid, acc)) if isinstance(rid, str) else None
        if a is None:
            raise Err(404, "NOT_FOUND", "no such request")
        t = int(self.clock())
        until = t + MUTE_S
        self.db.x("INSERT INTO push_mutes(account_id, agent_id, rid, user_id, reason, t, until) VALUES(?,?,?,?,?,?,?)",
                  (acc, a["agent_id"], rid, user_id, "suspicious", t, until))
        with self._lock:                            # what was held back for this account is not told about the muted agent either
            self._owed[acc] = 0
        self.stats["muted_by_person"] += 1
        log("WARN", "push: request marked suspicious, agent muted", account=acc, agent=a["agent_id"], rid=rid, until=until)
        return {"agent_id": a["agent_id"], "muted_until": until}

    def mutes(self, acc):
        t = int(self.clock())
        return [{"agent_id": r["agent_id"], "rid": r["rid"], "reason": r["reason"], "t": r["t"], "until": r["until"], "active": r["until"] > t}
                for r in self.db.q("SELECT * FROM push_mutes WHERE account_id=? ORDER BY t DESC LIMIT 50", (acc,))]

    def process(self, note):
        """One new defer -> zero or one push (merged, too soon for this agent or over the limit -> owed, told later by tick())."""
        acc, t = note["account"], self.clock()
        if note.get("security"):
            self.stats["security"] += 1
            self.send_all(acc, dict(note["payload"]), note.get("topic") if note.get("topic") == "dw-idle" else "dw-security", note["users"])
            return "sent"
        users = None
        if note.get("sigreq"):
            users, _ = self._sigreq_users(acc, note["sigreq"])
            if not users:
                return "nothing-asked"
        agent = note.get("agent")
        if agent and self.muted_until(acc, agent, t):
            self.stats["muted"] += 1
            return "muted"                          # the request still waits on the approvals page; no push, no summary
        if not self.subs_for(acc, users):
            return "no-device"                      # nothing to wake: the limit and the merge window are not spent
        with self._lock:
            last = self._last_key.get((acc, note["key"]))
            if last is not None and t - last < COALESCE_S:
                self._owed[acc] += 1
                self.stats["merged"] += 1
                return "merged"
            last = self._last_agent.get((acc, agent)) if agent else None
            if last is not None and t - last < MIN_GAP_S:
                self._owed[acc] += 1
                self.stats["spaced"] += 1
                return "spaced"
            if not self._room(acc, t):
                self._owed[acc] += 1
                self.stats["limited"] += 1
                return "limited"
            self._mark(acc, t)
            self._last_key[(acc, note["key"])] = t
            if agent:
                self._last_agent[(acc, agent)] = t
            self._owed[acc] = 0                     # the page this push opens shows the whole queue
        payload = dict(note["payload"])
        rid = note.get("rid") if payload.get("k") == "a" else None
        # r0276: each device gets its own n: the phone proves it got THIS push, and which subscription acks is known (ack below)
        got = self.send_all(acc, payload, topic_of(note.get("topic") or note["key"]), users, ack_rid=rid)
        if rid:
            self._ladder_sent(rid, acc, got, first=True)
        return "sent"

    def tick(self):
        """Owed requests -> one summary push once the account has room again (only if something is still waiting)."""
        t = self.clock()
        out = []
        with self._lock:
            for acc in [a for a, n in self._owed.items() if n > 0]:
                if t - self._last_any.get(acc, 0) < SUMMARY_DELAY_S or not self._room(acc, t):
                    continue
                self._owed[acc] = 0
                waiting = self.db.one("SELECT COUNT(*) AS n FROM actions WHERE account_id=? AND status='pending_approval' AND expires>? "
                                      "AND agent_id NOT IN (SELECT agent_id FROM push_mutes WHERE account_id=? AND until>?)",
                                      (acc, int(t), acc, int(t)))["n"]
                if waiting:
                    self._mark(acc, t)
                    out.append((acc, waiting))
        for acc, waiting in out:
            self.stats["summary"] += 1
            self.send_all(acc, {"v": 2, "k": "q"}, "dw-summary")    # no count: the page shows the queue
        return len(out)

    # ---------- r0276: the delivery ladder of a question's push ----------
    def ack_token(self, rid, sid):
        """n of the push of question `rid` to subscription `sid`."""
        return b64u(hmac.new(self._ack_key, ("ack\0%s\0%s" % (rid, sid)).encode(), hashlib.sha256).digest()[:16])

    def _ladder_sent(self, rid, acc, got, first):
        ok = "ok" in (got or [])
        t = int(self.clock())
        if first:
            self.db.x("UPDATE actions SET push_state=?, push_at=?, push_state_at=?, push_tries=1 WHERE rid=? AND account_id=? AND push_state IS NULL",
                      ("sent" if ok else "failed", t, t, rid, acc))
        elif ok:
            self.db.x("UPDATE actions SET push_state='sent', push_state_at=? WHERE rid=? AND account_id=? AND push_state='failed'", (t, rid, acc))
        self.stats["ladder_" + ("sent" if ok else "failed")] += 1

    def ack(self, rid, n, state):
        """The service worker: `state` of the push of question `rid`, proved with `n`. Only ever moves up the ladder. -> True if it counted."""
        if state not in ACKS or not isinstance(n, str) or len(n) > 64 or not isinstance(rid, str):
            return False
        a = self.db.one("SELECT account_id FROM actions WHERE rid=?", (rid,))
        if a is None:
            return False
        sid = next((x["id"] for x in self.subs_for(a["account_id"]) if hmac.compare_digest(n.encode(), self.ack_token(rid, x["id"]).encode())), None)
        if sid is None:
            return False
        # r0276b: this subscription's service worker acks (a current sw.js): only for such a phone may the hook say "did NOT reach"
        self.db.x("UPDATE push_subs SET acked=1 WHERE id=? AND acked IS NULL", (sid,))
        lower = [k for k in LADDER if RANK[k] < RANK[state]]
        k = self.db.n("UPDATE actions SET push_state=?, push_state_at=? WHERE rid=? AND push_state IN (%s)" % ",".join("?" * len(lower)),
                      (state, int(self.clock()), rid, *lower))
        if k:
            self.stats["ack_" + state] += 1
        return bool(k)

    def retry_unreceived(self, t=None):
        """No "received" within RECV_WAIT_S of the first push of a question that still waits -> the same push once more (same Topic: a copy
        still queued at the push service is replaced, not doubled). The per-minute limit holds; a question it skips is tried on a later tick."""
        t = int(self.clock() if t is None else t)
        rows = self.db.q("SELECT * FROM actions WHERE push_tries=1 AND push_state IN ('sent','failed') AND push_at<=? AND push_at>? "
                         "AND status IN ('pending_approval','held') AND (expires IS NULL OR expires>?) ORDER BY push_at LIMIT 50",
                         (t - RECV_WAIT_S, t - RETRY_LATEST_S, t))
        n = 0
        for r in rows:
            acc = r["account_id"]
            if self.muted_until(acc, r["agent_id"], t):
                continue
            with self._lock:
                if not self._room(acc, t):
                    continue
                if not self.db.n("UPDATE actions SET push_tries=2 WHERE rid=? AND push_tries=1", (r["rid"],)):
                    continue                        # another tick took it
                self._mark(acc, t)
            note = build_note(dict(r))
            got = self.send_all(acc, dict(note["payload"]), topic_of(note["topic"]), ack_rid=r["rid"])
            self._ladder_sent(r["rid"], acc, got, first=False)
            self.stats["ladder_retry"] += 1
            n += 1
        return n

    def delivery(self, acc, rids, t=None):
        """For the hook's answer (judge notify): -> {"state", "text"} when the phone push of a waiting question did not get through,
        else None. A question of this call that was pushed RECV_WAIT_S ago or more and is not opened yet; or, for a new question, the
        account's last question that was pushed twice and never reached a phone (that phone is not getting pushes now)."""
        t = int(self.clock() if t is None else t)
        st = None
        rids = [x for x in (rids or []) if isinstance(x, str)][:20]
        if rids:
            for r in self.db.q("SELECT push_state, push_at FROM actions WHERE account_id=? AND rid IN (%s) AND push_state IS NOT NULL"
                               % ",".join("?" * len(rids)), (acc, *rids)):
                if r["push_state"] != "opened" and r["push_at"] is not None and t - r["push_at"] >= RECV_WAIT_S:
                    if st is None or RANK[r["push_state"]] < RANK[st]:
                        st = r["push_state"]
        if st is None and rids and not self.db.one("SELECT 1 AS k FROM actions WHERE account_id=? AND rid IN (%s) AND push_state IS NOT NULL"
                                                   % ",".join("?" * len(rids)), (acc, *rids)):
            # the newest question whose push says something about the phone: it got there (received or more), or it was sent twice
            r = self.db.one("SELECT push_state FROM actions WHERE account_id=? AND push_at<=? AND push_at>? AND "
                            "(push_tries=2 OR push_state IN ('received','shown','opened')) ORDER BY push_at DESC LIMIT 1",
                            (acc, t - 2 * RECV_WAIT_S, t - 86400))
            if r is not None and r["push_state"] in ("failed", "sent"):
                return self._said(acc, "last-" + r["push_state"], "last")
        if st is None:
            return None
        return self._said(acc, st, "opened-not" if st in ("received", "shown") else "not")

    def _said(self, acc, state, key):
        """r0276b: a negative sentence only when one of the account's devices has acked a push before (its sw.js acks); a phone with an
        older service worker never acks, and "did NOT reach" would then be false: a neutral sentence instead."""
        if not any(s["acked"] for s in self.subs_for(acc)):
            return {"state": state, "text": DELIVERY_TEXT["neutral"]}
        return {"state": state, "text": DELIVERY_TEXT[key]}

    # ---------- delivery ----------
    def subs_for(self, acc, users=None):
        """Devices to wake for organisation `acc`: users=None -> every device subscribed in this organisation plus the devices of its
        active signing members (0.2: a member subscribed from another organisation still hears about this one); users=[ids] -> only
        those people's devices."""
        if users is None:
            users = [m["user_id"] for m in self.db.q("SELECT user_id, roles FROM members WHERE account_id=? AND status='active'", (acc,))
                     if set(json.loads(m["roles"] or "[]")) - {"observer"}]
            extra = [s for s in self.db.q("SELECT * FROM push_subs WHERE account_id=? ORDER BY rowid", (acc,))
                     if s["user_id"] is None or s["user_id"] in users]          # R3-07: a removed member's device hears nothing
        else:
            extra = []
        mine = self.db.q("SELECT * FROM push_subs WHERE user_id IN (%s) ORDER BY rowid" % ",".join("?" * len(users)), tuple(users)) if users else []
        seen, out = set(), []
        for s in list(extra) + list(mine):
            if s["id"] not in seen:
                seen.add(s["id"])
                out.append(s)
        return out

    def send_all(self, acc, payload, topic, users=None, ack_rid=None):
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        out = []
        for s in self.subs_for(acc, users):
            if ack_rid:
                data = json.dumps(dict(payload, n=self.ack_token(ack_rid, s["id"])), ensure_ascii=False, separators=(",", ":"))
            out.append(self.deliver(s, data, topic))
        return out

    def deliver(self, s, data, topic):
        info = {"endpoint": s["endpoint"], "keys": {"p256dh": s["p256dh"], "auth": s["auth"]}}
        code = 0
        for i in range(ATTEMPTS):
            try:
                code = self.sender(info, data, TTL_S, topic)
            except Exception as e:  # noqa - a network error is retried like a 5xx
                log("WARN", "push send error: " + type(e).__name__)
                code = 0
            if 200 <= code < 300:
                self.db.x("UPDATE push_subs SET last_ok_at=?, fail_count=0 WHERE id=?", (now(), s["id"]))
                self.stats["ok"] += 1
                return "ok"
            if code in (404, 410):
                self.db.x("DELETE FROM push_subs WHERE id=?", (s["id"],))
                self.stats["gone"] += 1
                log("INFO", "push subscription gone", status=code, account=s["account_id"])
                return "gone"
            if not (code == 0 or code == 429 or code >= 500) or i == ATTEMPTS - 1:
                break
            self.stats["retry"] += 1
            time.sleep(self.retry_delays[min(i, len(self.retry_delays) - 1)])
        self.db.x("UPDATE push_subs SET fail_count=COALESCE(fail_count,0)+1 WHERE id=?", (s["id"],))
        self.db.x("DELETE FROM push_subs WHERE id=? AND fail_count>=?", (s["id"], MAX_FAILS))
        self.stats["fail"] += 1
        log("WARN", "push failed", status=code, account=s["account_id"])
        return "fail"

    def _webpush_send(self, info, data, ttl, topic):
        import requests
        from pywebpush import WebPushException, webpush
        if self._session is None:
            self._session = requests.Session()
            self._session.max_redirects = 0              # a push service never redirects; following one could reach an internal host
        claims = {"sub": self.cfg.vapid_sub or self.cfg.origin}
        try:
            r = webpush(subscription_info=info, data=data, vapid_private_key=self.vapid, vapid_claims=claims, ttl=ttl, timeout=10,
                        headers={"Topic": topic, "Urgency": "high"}, requests_session=self._session)
            return r.status_code
        except WebPushException as e:
            return e.response.status_code if e.response is not None else 0


def attach(ctx):
    ctx.push = Pusher(ctx, load_vapid(ctx.cfg))
    return ctx.push


def make_router(ctx):
    r = APIRouter()

    def pusher():
        if not ctx.push.enabled:
            raise Err(503, "PUSH_DISABLED", "push is not configured on this server (VAPID key)")
        return ctx.push

    async def body(req):
        try:
            b = await req.json()
        except Err:
            raise
        except Exception:
            raise Err(400, "BAD_REQUEST", "JSON body expected")
        check_json(b)
        return b if isinstance(b, dict) else {}

    @r.get("/api/push/key")
    def key(req: Request):
        auth.session_account(ctx, req)
        return {"enabled": ctx.push.enabled, "public_key": ctx.push.public_key, "per_min": ctx.push.per_min}

    @r.get("/api/push/subscriptions")
    def subs(req: Request):
        acc = auth.session_account(ctx, req)
        return {"enabled": ctx.push.enabled, "subscriptions": ctx.push.list(acc["id"])}

    @r.post("/api/push/subscribe")
    async def subscribe(req: Request):
        acc = auth.session_account(ctx, req, True)
        auth.require_stepup(ctx, req, acc)              # a stolen cookie cannot route the owner's approvals to another device
        p = pusher()
        b = await body(req)
        return p.subscribe(acc["id"], b.get("subscription"), b.get("device"), getattr(req.state, "user", None))

    @r.post("/api/push/unsubscribe")
    async def unsubscribe(req: Request):
        acc = auth.session_account(ctx, req, True)
        auth.require_stepup(ctx, req, acc)
        b = await body(req)
        ctx.push.unsubscribe(acc["id"], b.get("endpoint"), b.get("id"))
        return {"ok": True}

    @r.post("/api/push/test")
    async def test(req: Request):
        acc = auth.session_account(ctx, req, True)
        p = pusher()
        if not ctx.limiter.hit("pushtest:" + acc["id"], 3, 60):
            raise Err(429, "RATE_LIMIT", "3 test pushes per minute")
        n = len(p.list(acc["id"]))
        if not n:
            raise Err(409, "PUSH_NO_DEVICE", "no device is subscribed")
        await run_in_threadpool(p.send_all, acc["id"], {"v": 2, "k": "t"}, "dw-test")
        return {"devices": len(p.list(acc["id"]))}

    @r.post("/api/push/ack")
    async def ack(req: Request):
        """r0276: the service worker says how far a question's push got (received / shown / opened). No session (the phone may be signed
        out): the proof is `n`, which only the encrypted push carried. The answer is the same whether it counted or not."""
        b = await body(req)
        rid = canon_rid(b.get("id"))
        if not ctx.push.enabled or not isinstance(rid, str) or len(rid) > 60:
            return {"ok": True}
        if ctx.limiter.hit("pushack:" + rid, 12, 60) and ctx.limiter.hit("pushack", 600, 60):
            await run_in_threadpool(ctx.push.ack, rid, b.get("n"), b.get("s"))
        return {"ok": True}

    @r.post("/api/push/suspicious")
    async def suspicious(req: Request):
        """approve.html "This looks suspicious": mute the agent's pushes for an hour + an event. No step-up: it only silences."""
        acc = auth.session_account(ctx, req, True)
        auth.require_stepup(ctx, req, acc)             # R3-12: silencing an agent is not free for a stolen cookie
        b = await body(req)
        if not ctx.limiter.hit("pushsusp:" + acc["id"], 20, 60):
            raise Err(429, "RATE_LIMIT", "20 per minute")
        return ctx.push.mark_suspicious(acc["id"], canon_rid(b.get("rid")), getattr(req.state, "user", None))

    @r.post("/api/push/unmute")
    async def unmute(req: Request):
        """R3-12: the owner lifts a mute (all of the agent's mutes, or one rid)."""
        acc = auth.session_account(ctx, req, True)
        b = await body(req)
        if not isinstance(b.get("agent_id"), str):
            raise Err(422, "BAD_REQUEST", "agent_id")
        if not ctx.db.one("SELECT 1 AS k FROM agents WHERE id=? AND account_id=?", (b["agent_id"], acc["id"])):
            raise Err(404, "NOT_FOUND")
        ctx.db.x("UPDATE push_mutes SET until=? WHERE account_id=? AND agent_id=? AND until>?", (int(ctx.push.clock()), acc["id"], b["agent_id"], int(ctx.push.clock())))
        return {"agent_id": b["agent_id"], "muted_until": 0}

    @r.get("/api/push/mutes")
    def mutes(req: Request):
        acc = auth.session_account(ctx, req)
        return {"mutes": ctx.push.mutes(acc["id"]), "mute_s": MUTE_S, "min_gap_s": MIN_GAP_S}

    return r
