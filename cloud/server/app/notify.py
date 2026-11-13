"""0.2.25 (ZAKRYTIE-GEMINI N1): notification channels besides Web Push: Telegram (the owner's own bot), Slack (incoming webhook), e-mail.

Why: on an iPhone a Web Push arrives only when the site was added to the Home Screen (iOS 16.4+); a background agent at night needs a channel
the owner already reads. A channel is a SIGNAL with a link, never the decision: approving is still done on approve.html with the passkey.
- The message holds no agent name, tool, target or amount (the same rule as push.py): "an agent is waiting" + the link to the request.
- Each person sets channels up on the dashboard (session + Origin + a fresh passkey touch: a stolen cookie cannot route the requests elsewhere).
  Telegram and Slack count as working after a delivered test message; e-mail after the 6-digit code sent to that address is typed back.
- Secrets (the bot token, the webhook URL, the address) are stored encrypted (AES-256-GCM, key derived from DW_KEY_PEPPER, the channel id as
  associated data) and are never returned, logged or put into an error text: the page shows a masked label; a failure is logged with the
  kind, an HTTP status or an exception TYPE, never its message (an HTTP library puts the URL with the token into it).
- Throttle: one approval message per account per MIN_GAP_S; what was held back is told in ONE summary message once the gap has passed
  (only if something is still waiting). An agent marked suspicious (push mute) does not notify. A security event (auto-freeze) is sent at once.
- Network: Telegram only to api.telegram.org, Slack only to hooks.slack.com (https, no redirects): the server never posts to a host the
  user typed. E-mail only when the operator configured SMTP (DW_SMTP_*)."""
import base64
import collections
import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import threading
import time

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from app import auth
from app.context import Err, check_json
from app.log import log

KINDS = ("telegram", "slack", "email")
MAX_CHANNELS = 5
MIN_GAP_S = 30
CODE_TTL_S = 1800
CODE_TRIES = 5
TIMEOUT_S = 10
MAX_FAILS = 20                         # consecutive failures before a channel is switched off (shown on the page)
TG_TOKEN_RE = re.compile(r"^[0-9]{5,12}:[A-Za-z0-9_-]{30,64}$")
TG_CHAT_RE = re.compile(r"^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$")
SLACK_RE = re.compile(r"^https://hooks\.slack\.com/(services|workflows|triggers)/[A-Za-z0-9_/-]{10,200}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


def now():
    return int(time.time())


def _key(cfg):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"deus-witness", info=b"dw-notify-channel-v1").derive(cfg.key_pepper.encode())


def seal(cfg, cid, obj):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    n = os.urandom(12)
    return n + AESGCM(_key(cfg)).encrypt(n, json.dumps(obj, sort_keys=True).encode(), cid.encode())


def unseal(cfg, cid, blob):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    b = bytes(blob)
    return json.loads(AESGCM(_key(cfg)).decrypt(b[:12], b[12:], cid.encode()))


def label_of(kind, s):
    """What the page shows: never the secret itself."""
    if kind == "telegram":
        c = s["chat_id"]
        return "Telegram chat ..." + c[-4:] if len(c) > 4 else "Telegram chat"
    if kind == "slack":
        return "Slack webhook ..." + s["url"][-4:]
    a = s["address"]
    local, _, dom = a.partition("@")
    return "E-mail " + local[:1] + "***@" + dom


def validate(kind, b, email_on):
    """Request body -> the secret object of the channel. Errors never echo the value."""
    if kind == "telegram":
        tok, chat = b.get("token"), b.get("chat_id")
        chat = str(chat) if isinstance(chat, int) and not isinstance(chat, bool) else chat
        if not isinstance(tok, str) or not TG_TOKEN_RE.fullmatch(tok.strip()):
            raise Err(422, "NOTIFY_INVALID", "bot token: the form 123456789:AA... that @BotFather gives")
        if not isinstance(chat, str) or not TG_CHAT_RE.fullmatch(chat.strip()):
            raise Err(422, "NOTIFY_INVALID", "chat id: a number (or @channelname)")
        return {"token": tok.strip(), "chat_id": chat.strip()}
    if kind == "slack":
        u = b.get("url")
        if not isinstance(u, str) or not SLACK_RE.fullmatch(u.strip()):
            raise Err(422, "NOTIFY_INVALID", "an incoming webhook URL of Slack: https://hooks.slack.com/services/...")
        return {"url": u.strip()}
    if kind == "email":
        if not email_on:
            raise Err(503, "NOTIFY_EMAIL_DISABLED", "e-mail is not configured on this server")
        a = b.get("address")
        if not isinstance(a, str) or len(a.strip()) > 254 or not EMAIL_RE.fullmatch(a.strip()):
            raise Err(422, "NOTIFY_INVALID", "an e-mail address")
        return {"address": a.strip()}
    raise Err(422, "NOTIFY_INVALID", "kind: telegram | slack | email")


def approval_text(origin, rid, reason=None):
    """05.11 (owner rule): two short lines first -- what the agent wants and what it can harm (from the reason code alone: no host, no path,
    nothing the agent wrote) -- then the link. The three answers and Details are on the page."""
    from app import qwords
    what, harm = qwords.short(reason)
    return ("Deus Witness: %s.\n%s.\n%s/approve.html?rid=%s\n"
            "Open it and decide there (Allow once / Allow this from now on / Deny); approving needs your passkey." % (what, harm.rstrip("."), origin, rid))


def summary_text(origin):
    return "Deus Witness: more requests are waiting for your approval.\n%s/approve.html" % origin


def frozen_text(origin, n, minutes):
    return ("Deus Witness: an agent was frozen automatically after %d refused approval requests in %d min (a flood of questions). "
            "Its waiting requests were cancelled and its new calls are refused.\nReview and unfreeze: %s/app.html" % (n, minutes, origin))


DIGEST_GAP_S = 600                     # 0.2.30: at most one summary of a kind per account in 10 minutes


def digest_text(kind, n, origin):
    """0.2.30: summaries without content (no arguments, no e-mail, no text)."""
    if kind == "repeat_used":
        return ("Deus Witness: %d call(s) ran without a question under your approvals for later runs. If you did not expect that, "
                "revoke them: %s/allowances.html" % (n, origin))
    if kind == "repeat_ended":
        return ("Deus Witness: %d approval(s) for later runs ended because the agent changed a file the command runs; that call now asks "
                "you again.\n%s/allowances.html" % (n, origin))
    if kind == "policy_delay":
        return ("Deus Witness: a Team policy change was scheduled by the owner and takes effect after the delay. Any member may cancel it "
                "before then: %s/dashboard.html" % origin)
    if kind == "policy_delay_cancelled":
        return "Deus Witness: a scheduled Team policy change was cancelled by a member."
    if kind == "team":
        return ("Deus Witness: %d new Team access request(s). Read them with deploy/voronka.py (GET /internal/stats); one counts for the "
                "criterion only after you confirm it (voronka.py --team-confirm ID)." % n)
    return "Deus Witness: %d new event(s) (%s)." % (n, kind)


class Notifier:
    def __init__(self, ctx, sender=None, clock=time.time):
        self.ctx, self.db, self.cfg = ctx, ctx.db, ctx.cfg
        self.sender = sender or self._send
        self.clock = clock
        self.q = queue.Queue()
        self._lock = threading.Lock()
        self._last = {}                         # account -> time of the last approval message
        self._owed = collections.Counter()
        self._dig = collections.Counter()      # (account, kind) -> events not yet summarised
        self._dlast = {}                        # (account, kind) -> time of the last summary
        self._worker = None
        self.stats = collections.Counter()

    @property
    def email_on(self):
        return bool(self.cfg.smtp_host and self.cfg.smtp_from) if hasattr(self.cfg, "smtp_host") else False

    # ---------- channels ----------
    def list(self, acc):
        return [{"id": r["id"], "kind": r["kind"], "label": r["label"], "verified": bool(r["verified"]), "created_at": r["created_at"],
                 "last_ok_at": r["last_ok_at"], "fail_count": r["fail_count"] or 0, "last_error": r["last_error"]}
                for r in self.db.q("SELECT * FROM notify_channels WHERE account_id=? ORDER BY created_at, id", (acc,))]

    def add(self, acc, user_id, kind, body):
        s = validate(kind, body, self.email_on)
        if self.db.one("SELECT COUNT(*) AS n FROM notify_channels WHERE account_id=?", (acc,))["n"] >= MAX_CHANNELS:
            raise Err(429, "QUOTA", "%d channels per account" % MAX_CHANNELS)
        cid = "nc_" + secrets.token_hex(8)
        code = code_hash = exp = None
        if kind == "email":
            code = "%06d" % secrets.randbelow(10 ** 6)
            code_hash, exp = self._code_hash(cid, code), now() + CODE_TTL_S
        self.db.x("INSERT INTO notify_channels(id,account_id,user_id,kind,label,secret_enc,verified,code_hash,code_exp,code_tries,created_at) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (cid, acc, user_id, kind, label_of(kind, s), seal(self.cfg, cid, s), 0, code_hash, exp, 0, now()))
        if kind == "email":
            ok = self.deliver(self._row(cid), "Deus Witness: your code to turn on e-mail notifications is %s (valid 30 minutes). "
                                                  "If you did not ask for it, ignore this message." % code, count=False)
            return {"channel": self._view(cid), "sent": ok, "needs_code": True}
        ok = self.deliver(self._row(cid), "Deus Witness: this channel will tell you when an agent waits for your approval. "
                                              "Nothing about the request itself is sent here, only a link.", count=False)
        if ok:
            self.db.x("UPDATE notify_channels SET verified=1 WHERE id=?", (cid,))
        return {"channel": self._view(cid), "sent": ok, "needs_code": False}

    def verify(self, acc, cid, code):
        r = self._row(cid, acc)
        if r["verified"]:
            return {"channel": self._view(cid)}
        if not r["code_hash"] or (r["code_exp"] or 0) < now() or (r["code_tries"] or 0) >= CODE_TRIES:
            raise Err(409, "NOTIFY_CODE_EXPIRED", "remove this channel and add it again for a new code")
        self.db.x("UPDATE notify_channels SET code_tries=COALESCE(code_tries,0)+1 WHERE id=?", (cid,))
        if not isinstance(code, str) or not hmac.compare_digest(self._code_hash(cid, code.strip()), r["code_hash"]):
            raise Err(409, "NOTIFY_CODE_WRONG", "wrong code")
        self.db.x("UPDATE notify_channels SET verified=1, code_hash=NULL, code_exp=NULL WHERE id=?", (cid,))
        return {"channel": self._view(cid)}

    def remove(self, acc, cid):
        self._row(cid, acc)
        self.db.x("DELETE FROM notify_channels WHERE id=? AND account_id=?", (cid, acc))

    def test(self, acc, cid):
        r = self._row(cid, acc)
        ok = self.deliver(r, "Deus Witness: test message. Approval requests will come with a link like this one: %s/approve.html" % self.cfg.origin)
        if ok and r["kind"] != "email":
            self.db.x("UPDATE notify_channels SET verified=1 WHERE id=?", (cid,))
        return {"sent": ok, "channel": self._view(cid)}

    def _code_hash(self, cid, code):
        return hashlib.sha256(("dw-notify-code:" + cid + ":" + code).encode()).hexdigest()

    def _row(self, cid, acc=None):
        r = self.db.one("SELECT * FROM notify_channels WHERE id=?" + (" AND account_id=?" if acc else ""), (cid, acc) if acc else (cid,))
        if r is None:
            raise Err(404, "NOT_FOUND")
        return r

    def _view(self, cid):
        return [x for x in self.list(self._row(cid)["account_id"]) if x["id"] == cid][0]

    # ---------- events ----------
    def approval(self, row):
        """A new defer / hold of an agent (actions.py). Queued; the agent's request never waits for a channel."""
        try:
            if not self._has(row["account_id"]):
                return
            self.q.put({"k": "a", "account": row["account_id"], "agent": row.get("agent_id"), "rid": row["rid"], "reason": row.get("reason")})
            self._ensure_worker()
        except Exception as e:  # noqa - a notification must never break the agent's request
            log("ERROR", "notify queue failed: " + type(e).__name__)

    def frozen(self, acc, agent_id, n, minutes):
        try:
            if not self._has(acc):
                return
            self.q.put({"k": "f", "account": acc, "agent": agent_id, "n": n, "min": minutes})
            self._ensure_worker()
        except Exception as e:  # noqa
            log("ERROR", "notify queue failed: " + type(e).__name__)

    def digest(self, acc, kind, n=1):
        """0.2.30: an event the owner should know of, summarised: the first one goes out at once, the next ones of that kind wait until
        DIGEST_GAP_S has passed since the last summary and then go as one message ("N ..."). Queued; never breaks the caller."""
        try:
            if not acc or not self._has(acc):
                return
            self.q.put({"k": "d", "account": acc, "kind": kind, "n": int(n)})
            self._ensure_worker()
        except Exception as e:  # noqa
            log("ERROR", "notify queue failed: " + type(e).__name__)

    def _flush_digests(self, t, only=None):
        out = []
        with self._lock:
            for k in [k for k, n in self._dig.items() if n > 0 and (only is None or k == only)]:
                if t - self._dlast.get(k, -DIGEST_GAP_S - 1) < DIGEST_GAP_S:
                    continue
                out.append((k, self._dig[k]))
                self._dig[k] = 0
                self._dlast[k] = t
        for (acc, kind), n in out:
            self.stats["digest"] += 1
            self.send_all(acc, digest_text(kind, n, self.cfg.origin))
        return len(out)

    def _has(self, acc):
        return self.db.one("SELECT 1 AS k FROM notify_channels WHERE account_id=? AND verified=1 LIMIT 1", (acc,)) is not None

    def process(self, note):
        acc, t = note["account"], self.clock()
        if note["k"] == "d":
            with self._lock:
                self._dig[(acc, note["kind"])] += note["n"]
            return self._flush_digests(t, only=(acc, note["kind"]))
        if note["k"] == "f":
            self.stats["frozen"] += 1
            return self.send_all(acc, frozen_text(self.cfg.origin, note["n"], note["min"]))
        push = getattr(self.ctx, "push", None)
        if note.get("agent") and push is not None and push.muted_until(acc, note["agent"], t):
            self.stats["muted"] += 1
            return 0
        with self._lock:
            last = self._last.get(acc)
            if last is not None and t - last < MIN_GAP_S:
                self._owed[acc] += 1
                self.stats["spaced"] += 1
                return 0
            self._last[acc] = t
            self._owed[acc] = 0
        self.stats["approval"] += 1
        return self.send_all(acc, approval_text(self.cfg.origin, note["rid"], note.get("reason")))

    def tick(self):
        t = self.clock()
        self._flush_digests(t)
        out = []
        with self._lock:
            for acc in [a for a, n in self._owed.items() if n > 0]:
                if t - self._last.get(acc, 0) < MIN_GAP_S:
                    continue
                self._owed[acc] = 0
                w = self.db.one("SELECT COUNT(*) AS n FROM actions WHERE account_id=? AND status IN ('pending_approval','held') AND expires>?",
                                (acc, int(t)))["n"]
                if w:
                    self._last[acc] = t
                    out.append(acc)
        for acc in out:
            self.stats["summary"] += 1
            self.send_all(acc, summary_text(self.cfg.origin))
        return len(out)

    def send_all(self, acc, text):
        n = 0
        for r in self.db.q("SELECT * FROM notify_channels WHERE account_id=? AND verified=1 ORDER BY created_at", (acc,)):
            n += 1 if self.deliver(r, text) else 0
        return n

    def deliver(self, r, text, count=True):
        try:
            s = unseal(self.cfg, r["id"], r["secret_enc"])
        except Exception as e:  # noqa - another pepper: the channel cannot be read, it must be set up again
            self._fail(r, "unreadable (" + type(e).__name__ + ")")
            return False
        try:
            ok, why = self.sender(r["kind"], s, text)
        except Exception as e:  # noqa - the message of a network error may hold the URL with the token: only its type
            ok, why = False, type(e).__name__
        if ok:
            self.db.x("UPDATE notify_channels SET last_ok_at=?, fail_count=0, last_error=NULL WHERE id=?", (now(), r["id"]))
            self.stats["ok"] += 1
            return True
        self._fail(r, why)
        return False

    def _fail(self, r, why):
        why = str(why)[:60]
        self.db.x("UPDATE notify_channels SET fail_count=COALESCE(fail_count,0)+1, last_error=? WHERE id=?", (why, r["id"]))
        self.db.x("UPDATE notify_channels SET verified=0 WHERE id=? AND fail_count>=?", (r["id"], MAX_FAILS))
        self.stats["fail"] += 1
        log("WARN", "notify failed", kind=r["kind"], why=why, account=r["account_id"])

    # ---------- network ----------
    def _send(self, kind, s, text):
        """-> (ok, short reason). Only fixed hosts; no redirects; the reason never holds a URL or a token."""
        if kind == "email":
            return self._smtp(s["address"], text)
        import httpx
        if kind == "telegram":
            url, body = "https://api.telegram.org/bot%s/sendMessage" % s["token"], {"chat_id": s["chat_id"], "text": text, "disable_web_page_preview": True}
        elif kind == "slack":
            if not SLACK_RE.fullmatch(s["url"]):
                return False, "bad url"
            url, body = s["url"], {"text": text}
        else:
            return False, "kind"
        r = httpx.post(url, json=body, timeout=TIMEOUT_S, follow_redirects=False)
        return 200 <= r.status_code < 300, "http %d" % r.status_code

    def _smtp(self, address, text):
        import smtplib
        import ssl
        from email.message import EmailMessage
        c = self.cfg
        if not self.email_on:
            return False, "e-mail off"
        m = EmailMessage()
        m["From"], m["To"], m["Subject"] = c.smtp_from, address, "Deus Witness"
        m.set_content(text)
        pw = None
        if c.smtp_password_file:
            with open(c.smtp_password_file) as f:
                pw = f.read().strip()
        cls = smtplib.SMTP_SSL if c.smtp_tls == "ssl" else smtplib.SMTP
        kw = {"context": ssl.create_default_context()} if c.smtp_tls == "ssl" else {}
        with cls(c.smtp_host, c.smtp_port, timeout=TIMEOUT_S, **kw) as srv:
            if c.smtp_tls == "starttls":
                srv.starttls(context=ssl.create_default_context())
            if c.smtp_user and pw:
                srv.login(c.smtp_user, pw)
            srv.send_message(m)
        return True, "ok"

    def telegram_chats(self, token):
        """The chats that wrote to the owner's bot (getUpdates): helps to find the chat id. Nothing is stored."""
        if not isinstance(token, str) or not TG_TOKEN_RE.fullmatch(token.strip()):
            raise Err(422, "NOTIFY_INVALID", "bot token: the form 123456789:AA... that @BotFather gives")
        import httpx
        try:
            r = httpx.get("https://api.telegram.org/bot%s/getUpdates" % token.strip(), timeout=TIMEOUT_S, follow_redirects=False)
            j = r.json() if r.status_code == 200 else {}
        except Exception as e:  # noqa
            log("WARN", "notify telegram lookup failed: " + type(e).__name__)
            raise Err(502, "NOTIFY_UPSTREAM", "Telegram did not answer")
        out = {}
        for u in (j.get("result") or [])[:100] if isinstance(j, dict) else []:
            ch = ((u.get("message") or u.get("channel_post") or {}).get("chat")) if isinstance(u, dict) else None
            if isinstance(ch, dict) and isinstance(ch.get("id"), int):
                out[str(ch["id"])] = (ch.get("title") or ch.get("username") or ch.get("first_name") or "")[:60]
        return [{"chat_id": k, "name": v} for k, v in out.items()]

    # ---------- worker ----------
    def _ensure_worker(self):
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._loop, name="notify", daemon=True)
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
            except Exception as e:  # noqa
                log("ERROR", "notify worker: " + type(e).__name__)
            finally:
                if note is not None:
                    self.q.task_done()

    def drain(self, timeout=10):
        end = time.time() + timeout
        while self.q.unfinished_tasks and time.time() < end:
            time.sleep(0.01)
        return not self.q.unfinished_tasks


def attach(ctx):
    ctx.notify = Notifier(ctx)
    return ctx.notify


def make_router(ctx):
    r = APIRouter()

    async def body(req):
        try:
            b = await req.json()
        except Err:
            raise
        except Exception:
            raise Err(400, "BAD_REQUEST", "JSON body expected")
        check_json(b)
        return b if isinstance(b, dict) else {}

    @r.get("/api/notify/channels")
    def channels(req: Request):
        acc = auth.session_account(ctx, req)
        return {"email_enabled": ctx.notify.email_on, "kinds": list(KINDS), "channels": ctx.notify.list(acc["id"]),
                "ios_push_note": "iPhone / iPad: Web Push works only after adding Witness to the Home Screen (iOS 16.4+)."}

    @r.post("/api/notify/channels")
    async def add(req: Request):
        acc = auth.session_account(ctx, req, True)
        auth.require_stepup(ctx, req, acc)              # a stolen cookie cannot route the owner's approval links to another chat
        if not ctx.limiter.hit("notifyadd:" + acc["id"], 10, 3600):
            raise Err(429, "RATE_LIMIT", "10 new channels per hour")
        b = await body(req)
        kind = b.get("kind")
        if kind not in KINDS:
            raise Err(422, "NOTIFY_INVALID", "kind: telegram | slack | email")
        return await run_in_threadpool(ctx.notify.add, acc["id"], getattr(req.state, "user", None), kind, b)

    @r.post("/api/notify/channels/{cid}/verify")
    async def verify(cid: str, req: Request):
        acc = auth.session_account(ctx, req, True)
        b = await body(req)
        return ctx.notify.verify(acc["id"], cid, b.get("code"))

    @r.post("/api/notify/channels/{cid}/test")
    async def test(cid: str, req: Request):
        acc = auth.session_account(ctx, req, True)
        if not ctx.limiter.hit("notifytest:" + acc["id"], 3, 60):
            raise Err(429, "RATE_LIMIT", "3 test messages per minute")
        return await run_in_threadpool(ctx.notify.test, acc["id"], cid)

    @r.delete("/api/notify/channels/{cid}")
    def remove(cid: str, req: Request):
        acc = auth.session_account(ctx, req, True)
        auth.require_stepup(ctx, req, acc)
        ctx.notify.remove(acc["id"], cid)
        return {"ok": True}

    @r.post("/api/notify/telegram/chats")
    async def tg_chats(req: Request):
        acc = auth.session_account(ctx, req, True)
        if not ctx.limiter.hit("notifytg:" + acc["id"], 10, 60):
            raise Err(429, "RATE_LIMIT", "10 per minute")
        b = await body(req)
        return {"chats": await run_in_threadpool(ctx.notify.telegram_chats, b.get("token"))}

    return r
