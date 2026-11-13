"""12.11 (r0263, server 0.2.93): the data rule acts on what LEAVES this computer, not on text that stays on it.

Measured (L3 12.11, ISPYTANIE-L3-0260, Б1): every commit Claude Code makes carries the trailer "Co-Authored-By: Claude ... <noreply@anthropic.com>";
the DLP found `email_address` in the command, the core refused it (DATA_FORBIDDEN, no button) -- 5 of 5 commits failed; under the strict
sandbox the same commit was a "dangerous" question ("(strict data) email_address"); an address in a Write / Edit of AUTHORS or README was a
question too. The stands never saw it: the corpus generators replace every address by <EMAIL> (gen_real.scrub).

Law: text is not an action. A personal-data FORMAT (an e-mail address, a phone number, a postal address, a card number, an IBAN, an SSN, a
crypto address: the L2 formats of dw_dlp.rules_v1.FORMATS) written into a commit message, a file of the project or the arguments of a local
program stays on this computer: no leak happened. A leak is SENDING it; a line that can send (a network part, a publication, a program that
leaves -- strict_policy.no_way_out) keeps the data rule exactly as before. So:
  - a file tool (Write / Edit / MultiEdit / NotebookEdit, any of their parts): the L2 formats are not data of the call (the write itself is
    judged by every other rule: the place, the agent's settings, a file run later);
  - a shell line with NO way out (Bash / Bash.danger / Bash.write parts): the same;
  - a shell line WITH a way out, and every other tool (Bash.net, WebFetch, a message, a publication): unchanged (refused, as before).
Unchanged everywhere: secrets (L1: tokens, private keys -- they act, not only tell), the owner's own protected literals (the account's data
patterns, L1), and a class the owner named in the mandate's `forbidden_data` (an explicit choice: "never in any text").
What remains of "(strict data)": only secrets on a line with no way out (r0261b soften_data, unchanged)."""
from __future__ import annotations

import hashlib

FORMATS = ("card_number", "iban", "ssn", "crypto_address", "phone", "email_address", "postal_address")   # = dw_dlp.rules_v1.FORMATS
FILE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
LOCAL_SHELL_PARTS = ("Bash", "Bash.danger", "Bash.write")


def _base(tool):
    return tool.split(".")[0] if isinstance(tool, str) else ""


def stays_here(tool, args) -> bool:
    """True when nothing this call does can carry its text off the computer (see the module's note). Fail closed: False."""
    if not isinstance(tool, str) or not isinstance(args, dict):
        return False
    if _base(tool) in FILE_TOOLS:
        return True
    if tool not in LOCAL_SHELL_PARTS or not isinstance(args.get("command"), str):
        return False
    from . import strict_policy as sp
    from . import sandbox as hsb
    try:
        v = sp.verdict(tool, args)
        if v.refuse is not None:
            return False                                  # an article: judged as it was (the refusal stands anyway)
        w = sp._witness(args)
        if any(p in (sp.PUBLISH, sp.OUTSIDE) for p, _ in v.ask) or w.get("net"):
            return False
        for h in (w.get("commands") or []):
            if not isinstance(h, str) or (hsb.code_exit(h) and not _git_local(h)):
                return False
        return not hsb.NET_TEXT.search(sp.skeleton(args["command"]))
    except Exception:
        return False


# 12.11 (r0263, the friction stand with the trial mandate, real corpus: 4 harmless commits refused): a git command of the LOCAL kind in
# another folder ("git commit [outside]": the line `cd`s into a sibling repository) is no way out -- sandbox.code_exit counts every git
# variant as one (fail closed, the strict gate's question). A remote subcommand, `-c` / an exec variant / xargs stay a way out.
GIT_LOCAL_TAGS = {"outside", "unsure", "force", "dir", "recursive", "protected"}


def _git_local(head):
    from . import sandbox as hsb
    w = head.split(" ")
    if len(w) < 2 or w[0].rsplit("/", 1)[-1] != "git" or w[1].startswith("[") or w[1] in hsb.GIT_REMOTE:
        return False
    import re
    tags = [t for x in re.findall(r"\[([^\]]*)\]", head) for t in x.replace(" ", "").split(",")]
    return all(t in GIT_LOCAL_TAGS for t in tags) and not any(c in head for c in ("[-c]", "via xargs"))


def local_text(act, tool, args, explicit=()):
    """-> the action with the L2 personal-data formats dropped from `data` / `dlp_hits` when the call keeps its text on this computer
    (stays_here). A format also found by L1 (the owner's literal) or named in the mandate's forbidden_data (`explicit`) stays."""
    if not isinstance(act, dict) or not act.get("data"):
        return act
    hits = set(act.get("dlp_hits") or [])
    drop = {t for t in act["data"] if t in FORMATS and ("L1:" + t) not in hits and t not in set(explicit or ())}
    if not drop or not stays_here(tool, args):
        return act
    return dict(act, data=[t for t in act["data"] if t not in drop], dlp_hits=[h for h in act.get("dlp_hits") or [] if h not in {"L2:" + t for t in drop}])


# 0.2.95 (ISPYTANIE-PERED-LYUDMI-1211 Н3): `git commit -m "..." -m "Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>" && git push`
# -- the line Claude Code writes when asked to commit and push -- was refused DATA_FORBIDDEN with no button: the push can send, so the
# r0263 rule above keeps the address as data, and the model silently dropped the trailer. Law: personal data is data ABOUT A PERSON whom
# sending it can harm. A no-reply address of a service (it reaches nobody: Anthropic's co-author trailer, GitHub's private commit
# address) and the person's own address from their git configuration (what git writes into every commit they push anyway) are not such
# data. So when EVERY address of the call is one of those, `email_address` is no data of the call; whatever else the line does is judged as
# before (a push stays the С1 question, a secret or another format stays refused). One other address anywhere -> unchanged (fail closed).
NOREPLY = ("noreply@anthropic.com", "noreply@github.com")
NOREPLY_SUFFIX = ("@users.noreply.github.com",)


def _addresses(text):
    from dw_dlp import rules_v1 as _r
    return [text[a:b] for a, b in _r._find_emails(text)] if isinstance(text, str) else []


def _sha(a):
    return hashlib.sha256(a.strip().lower().encode("utf-8")).hexdigest()


def own_addresses(cmd, git_self):
    """-> the SHA-256 (hex, sorted) of the addresses in `cmd` that are the person's own git user.email (the hook's fact `git_self`)."""
    own = set(x for x in (git_self or ()) if isinstance(x, str))
    return sorted({_sha(a) for a in _addresses(cmd) if _sha(a) in own})[:4]


def _strings(x, out):
    if isinstance(x, str):
        out.append(x)
    elif isinstance(x, dict):
        for k, v in x.items():
            if k != "exec":
                _strings(v, out)
    elif isinstance(x, list):
        for v in x:
            _strings(v, out)
    return out


def benign_addresses(act, tool, args, explicit=()):
    """-> the action without `email_address` in `data` / `dlp_hits` when every address in the call's arguments is a no-reply address of a
    service or the person's own git address (args._witness.own_addr); else the action as it is. An L1 hit (the owner's own protected
    literal) or a class the mandate names in forbidden_data keeps it."""
    if not isinstance(act, dict) or "email_address" not in (act.get("data") or ()) or not isinstance(args, dict):
        return act
    if "L1:email_address" in set(act.get("dlp_hits") or ()) or "email_address" in set(explicit or ()):
        return act
    w = args.get("_witness") if isinstance(args.get("_witness"), dict) else {}
    own = set(x for x in (w.get("own_addr") or ()) if isinstance(x, str))
    found = [a for t in _strings(args, []) for a in _addresses(t)]
    if not found:
        return act
    for a in found:
        low = a.strip().lower()
        if not (low in NOREPLY or low.endswith(NOREPLY_SUFFIX) or _sha(low) in own):
            return act
    return dict(act, data=[t for t in act["data"] if t != "email_address"],
                dlp_hits=[h for h in act.get("dlp_hits") or [] if h != "L2:email_address"])
