"""0.2.13: confirmation levels -- WHERE an approval may be signed.

Every passkey carries a device class (credentials.device): "phone" (a separate device: the agent's computer cannot show or change what is on
its screen) or "laptop" (a passkey of the computer the agent runs on: Touch ID / Windows Hello). An approval is signed by one or more
passkeys; the server knows which (the envelope names their kids) and refuses (409 DEVICE_LEVEL) an approval of a "phone" action signed by a
"laptop" key. A refusal (No) is accepted from any key: stopping is never harder than going.

Level of a deferred action (level_of):
  laptop  a shell command that is NOT dangerous and does not talk to the network, asked because it is not on the list (ESCALATE_COMMAND)
          or because of the count limit (ESCALATE_COUNT): the cost of a wrong yes stays on this computer and the project. A project
          allowance offered for such a command is confirmed at the same level as the command;
  phone   everything else: money, deleting or overwriting files outside a command, sending outside (message / publish / disclosure,
          a shell line that talks to the network), reading secrets, dangerous commands, protected data, writes to git's hooks/config,
          and a command asked AFTER A FILE IT EXECUTES CHANGED (ESCALATE_EXEC_CHANGED, decision of 20.10: the edited file is the attack).
The owner can tighten it: phone_for = "all" (every approval needs a phone key). Loosening back needs a fresh signature by a phone key.
A key registered before 0.2.13 has no class (NULL) and counts as "phone" (behaviour of 0.2.12) until the owner marks it.
0.2.14 (R8-06): a key that counts as phone is demoted or removed only with a fresh signature of a phone-class key; a laptop key becomes
"phone" only with a phone signature, or by the FIRST marking of an account that never had an explicitly marked phone key (users.phone_ever);
a key added with a recovery code is "laptop" unless the person declares it the new phone inside the recovery flow; a kid the server does
not know counts as laptop. Every class change and every removal pushes to all the person's devices.
0.2.15: a key declared "my new phone" with a recovery code is stored as phone with credentials.phone_nb (not before): until that time
it counts as laptop (keys.py, the delay is 24 h, configurable 24-72 h); the other devices are told at once and can cancel the claim.
Honest limit (docs/internal/coverage.md 7.3): the class is what the owner declared when adding the key; a passkey synced between devices (iCloud
Keychain, Google Password Manager) can be used on the computer too, and WebAuthn does not tell the server which device signed."""
import json
import time

import cbor2

from app import _paths  # noqa: F401
import wq_profile as wq
from app.context import Err

PHONE, LAPTOP = "phone", "laptop"
DEVICES = (PHONE, LAPTOP)
LAPTOP_REASONS = ("ESCALATE_COMMAND", "ESCALATE_COUNT")   # 20.10 Деус: «после правки исполняемого файла» — уровень телефона (цель атаки — вывод ключей)
PHONE_FOR = ("risky", "all")


def level_of(action, reason):
    """-> "laptop" | "phone" for a deferred action (its action map and the core's reason)."""
    a = action if isinstance(action, dict) else {}
    if a.get("class") == "command" and a.get("dangerous") is not True and reason in LAPTOP_REASONS:
        return LAPTOP
    return PHONE


def phone_for(ctx, account_id):
    r = ctx.db.one("SELECT phone_for FROM confirm_rules WHERE account_id=?", (account_id,))
    return r["phone_for"] if r and r["phone_for"] in PHONE_FOR else "risky"


def required(ctx, account_id, action, reason, level_min=None):
    return PHONE if phone_for(ctx, account_id) == "all" or level_min == PHONE else level_of(action, reason)


def _col(row, k):
    try:
        return row[k]
    except (KeyError, IndexError):
        return None


def pending_until(row, now=None):
    """0.2.15: the time a recovery-declared phone starts to count as phone, while that time is in the future; else None."""
    nb = _col(row, "phone_nb")
    return nb if isinstance(nb, int) and nb > (now if now is not None else int(time.time())) else None


def pending_lineage(ctx, row, now=None, _depth=0):
    """0.2.17 (R9-03): pending_until of the key OR of the key that vouched for it (credentials.vouched_by, up the chain): a passkey that a
    waiting "new phone" confirmed inherits the wait. -> the latest such time, or None."""
    if row is None:
        return None
    nb = pending_until(row, now)
    by = _col(row, "vouched_by")
    if by is not None and _depth < 16:
        parent = ctx.db.one("SELECT * FROM credentials WHERE kid=? AND user_id=?", (bytes(by), _col(row, "user_id")))
        up = pending_lineage(ctx, parent, now, _depth + 1)
        if up is not None and (nb is None or up > nb):
            nb = up
    return nb


def device_of(row):
    """credentials row -> its class; an unmarked (pre-0.2.13) key counts as phone; a phone declared with a recovery code counts as
    laptop until its phone_nb (0.2.15)."""
    d = _col(row, "device")
    if d == LAPTOP or pending_until(row) is not None:
        return LAPTOP
    return PHONE


def device_of_kid(ctx, kid):
    r = ctx.db.one("SELECT device, phone_nb FROM credentials WHERE kid=? ORDER BY id DESC LIMIT 1", (kid,)) if isinstance(kid, bytes) else None
    return device_of(r) if r is not None else LAPTOP          # 0.2.14 (R8-06): an unknown kid is never a phone


def env_kids(env):
    """kids of the passkeys that signed an approval envelope (wa: one, wq: each wsig, wb: one)."""
    try:
        m = cbor2.loads(env)
    except Exception:
        return []
    if not isinstance(m, dict):
        return []
    if m.get("v") == wq.V_WQ:
        return [w.get("kid") for w in m.get("sigs") or [] if isinstance(w, dict) and isinstance(w.get("kid"), bytes)]
    return [m["kid"]] if isinstance(m.get("kid"), bytes) else []


def check_signers(ctx, account_id, kids, action, reason, level_min=None):
    """Err(409 DEVICE_LEVEL) when the action needs a phone and a signer is a laptop key. -> the level.
    level_min: the gateway's floor for this row ("phone": a command line that also talks to the network)."""
    need = required(ctx, account_id, action, reason, level_min)
    if need == PHONE:
        if any(not isinstance(k, bytes) or ctx.db.one("SELECT 1 FROM credentials WHERE kid=?", (k,)) is None for k in kids):
            raise Err(409, "KEY_MISMATCH", "this passkey is not known here")      # 0.2.14: an unknown kid is never a phone (nor anything else)
        bad = [k for k in kids if device_of_kid(ctx, k) == LAPTOP]
        if bad:
            raise Err(409, "DEVICE_LEVEL", "this action needs a confirmation on your phone (a separate device): it %s. A passkey of this "
                                           "computer may confirm only ordinary shell commands of the project" % _why(action, reason))
    return need


def _why(action, reason):
    a = action if isinstance(action, dict) else {}
    c = a.get("class")
    if c in ("purchase", "sale", "refund"):
        return "moves money"
    if c == "command" and a.get("dangerous") is True:
        return "is a dangerous command"
    if c in ("message", "publish", "disclosure", "http"):
        return "sends something outside or reads a secret"
    if c in ("delete", "file"):
        return "deletes or overwrites files"
    return "is not an ordinary project command (%s)" % (reason or c or "?")


def get_rules(ctx, account_id):
    return {"phone_for": phone_for(ctx, account_id), "levels": {"laptop": list(LAPTOP_REASONS), "note": __doc__.split("\n\n")[1].strip()}}


def has_phone_key(ctx, user_id, exclude_kid=None):
    return any(device_of(c) == PHONE for c in ctx.db.q("SELECT device, phone_nb, kid FROM credentials WHERE user_id=? AND revoked_at IS NULL", (user_id,))
               if exclude_kid is None or bytes(c["kid"]) != exclude_kid)


def recovery_window(ctx, user_id, now=None):
    """0.2.15: True while a recovery code added a key less than the delay ago, or a declared phone is still waiting: the "first marking"
    shortcut (an account that never had a phone) is closed then, else a recovery code would skip the delay through it."""
    t = now if now is not None else int(time.time())
    d = getattr(ctx.cfg, "recovery_phone_delay_h", 24) * 3600
    return ctx.db.one("SELECT 1 FROM credentials WHERE user_id=? AND ((added_by='recovery-code' AND created_at>?) OR phone_nb>?)",
                      (user_id, t - d, t)) is not None


def phone_ever(ctx, user_id):
    """0.2.14 (R8-06): True once the person has had a key explicitly marked phone (kept even after it is demoted or removed)."""
    r = ctx.db.one("SELECT phone_ever FROM users WHERE id=?", (user_id,))
    if r is not None and r["phone_ever"]:
        return True
    return ctx.db.one("SELECT 1 FROM credentials WHERE user_id=? AND device=?", (user_id, PHONE)) is not None


def mark_phone_ever(db, user_id):
    db.x("UPDATE users SET phone_ever=1 WHERE id=?", (user_id,))


def session_key_is_phone(ctx, cred_row):
    return cred_row is not None and device_of(cred_row) == PHONE


def put_rules(ctx, account_id, user_id, body, session_cred_row):
    v = body.get("phone_for") if isinstance(body, dict) else None
    if v not in PHONE_FOR:
        raise Err(422, "BAD_SETTINGS", "phone_for: risky | all")
    cur = phone_for(ctx, account_id)
    if cur == "all" and v == "risky" and not session_key_is_phone(ctx, session_cred_row):
        # 0.2.14 (R8-06): no exception for "no phone key now": a laptop that got rid of the phone key does not lift the rule
        raise Err(403, "DEVICE_LEVEL", "loosening this rule needs a fresh confirmation with your phone's passkey (step-up on the phone)")
    ctx.db.x("INSERT OR REPLACE INTO confirm_rules(account_id,phone_for,updated_at,updated_by) VALUES(?,?,?,?)", (account_id, v, int(time.time()), user_id))
    return get_rules(ctx, account_id)


def _lm(x):
    try:
        return x["level_min"]
    except (KeyError, IndexError):
        return None


def view(ctx, account_id, x):
    """For the approval page: what this pending action needs."""
    try:
        a = json.loads(x["action_json"]) if x["action_json"] else {}
    except (TypeError, ValueError):
        a = {}
    need = required(ctx, account_id, a, x["reason"], _lm(x))
    return {"level": need, "phone_for": phone_for(ctx, account_id),
            "text": ("Confirm on your phone (a separate device)." if need == PHONE else
                     "May be confirmed with this computer's passkey (Touch ID / Windows Hello) or on your phone.")}
