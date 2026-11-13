"""05.11 (owner rule, docs/PRAVILO-VOPROSA.md): every question to a person says in plain words WHAT the agent wants (`what`), WHAT it can
harm (`harm`) and, on request, the facts (`details`: the command / file, where the data goes, what changes, how to undo).
The words come from THIS dictionary by the reason code and the fields the SERVER parsed (host, path, command head) -- never from text the
agent wrote about itself. The three members are part of the signed view (signview.KEYS): signed = shown. A code without an entry gets
the honest general text and harm "Unknown effect" (fail closed: the question is still asked)."""
import json
import re
import unicodedata

UNKNOWN_WHAT = "Your agent wants to run a command Witness could not classify"
UNKNOWN_HARM = "Unknown effect"

# code -> (what, harm). {t} = the server-parsed target (host, path or command name), already cleaned.
# 05.11 (owner at the phone: "too complex, keep only the main thing"): `harm` is ONE short line (<= 12 words, plain words); the full
# explanation of the same risk is LONG_HARM, shown only under Details ("Why it matters").
REASON_WORDS = {
    "ESCALATE_COMMAND": ("Your agent wants to run a command that is not on your list: {t}", "It runs a program on your computer."),
    "ESCALATE_COMMAND_DANGER": ("Your agent wants to run a dangerous command: {t}", "This command can damage files or leak data."),
    "ESCALATE_PUBLISH": ("Your agent wants to send or publish something to {t}", "Information would leave this computer for good."),
    "ESCALATE_DELETE": ("Your agent wants to delete {t}", "Files could be deleted for good."),
    "ESCALATE_MONEY": ("Your agent wants to pay {t}", "Money would be spent and may not come back."),
    "ESCALATE_DATA": ("Your agent wants to send something to {t} that may carry data your mandate protects",
                      "Private data could leave this project."),
    "ESCALATE_FILE": ("Your agent wants to change the file {t}", "A file your rules do not cover would change."),
    "ESCALATE_COUNT": ("Your agent is repeating the same kind of action too often: {t}", "A runaway agent could do a lot of damage fast."),
    "ESCALATE_EXEC_CHANGED": ("Your agent wants to run {t}, and files it runs changed since you last confirmed them",
                              "Code you have not seen would run."),
    "ESCALATE_HTTP": ("Your agent wants to send a web request to {t}", "Information from your computer could be sent to this site."),
    "ESCALATE_WRITTEN_RUN": ("Your agent wants to run a file it wrote itself: {t}", "It runs code you have not read."),
    "ESCALATE_SECRET_COPY": ("Your agent wants to read {t}, a copy it made of a secret", "Your keys or passwords would reach the agent."),
    "ESCALATE_SECRET_SEEN": ("Your agent wants to act on {t} a few minutes after it read a secret", "Your keys or passwords could be sent out."),
    "ESCALATE_NET_UNSEEN": ("Your agent wants to run a network program ({t}) whose destination is not in the line",
                            "It could send data to a place you cannot see."),
    "ESCALATE_TRIAL_CLAIM": ("Your agent wants to make its first use of a trial account", "It binds the trial to this account."),
    "ESCALATE_EGRESS_UNSPECIFIED": ("Your agent wants to reach {t}, outside this computer", "Information could be sent to an unknown site."),
    "ESCALATE_USER_CONTENT_HOST": ("Your agent wants to send data to {t}, a site where anyone can publish or read", "What it sends may become public."),
    "ESCALATE_NOT_LISTED": ("Your agent wants to use something that is not on your list: {t}", "Its effect is not covered by your rules."),
    "ADVISORY_HOLD": ("Your agent wants to do {t}; the data advisor flagged its text", "The text may contain private data."),
}
NET_HARM = "Information from your computer could be sent to this site."

# r0277 (P1 of the profile: the checker rebuilds the words offline): EVERY sentence the first screen shows (what / harm) is a template of
# the closed vocabulary (app/vocab.py "screen", mr-vocab-2). Placeholders: {t} = a target quoted from the call as the server parsed it,
# {n} = the number of commands of the line (line_commands), {when} = how long ago the person said No. Nothing else is variable.
SCREEN = {
    "unnamed": "(unnamed)",
    "send_request": "Your agent wants to send a request to {t}",
    "secret_to_host": "Your keys or passwords could be sent to this site.",
    "persist": "The agent could stay on your computer for good.",
    "sandbox_publish": "Code could publish to {t} in your name.",
    "git_read_what": "Your agent wants to read your git settings",
    "git_read_harm": "It only reads them; nothing is changed or sent.",
    "git_change_what": "Your agent wants to change git settings that run programs",
    "git_change_harm": "Git would run this later without asking you.",
    "own_settings_what": "Your agent wants to change its own settings",
    "own_settings_harm": "It could change how your agent or Witness works next time.",
    "temp_write_what": "Your agent wants to write a file outside the project: {t}",
    "temp_write_harm": "Other programs and users of this computer can read and change it.",
    "quiet_what": "Your agent wants to turn on quiet mode (Claude Code's strict sandbox) for all your projects",
    "quiet_harm": "It changes your Claude Code settings; some tools may need a host added later.",
    "many_commands": "Your agent wants to run {n} commands",
    "refused_before": "You said No to this {when}; the agent is trying another way.",
    "when_min": "{n} min ago",
    "when_h": "{n} h ago",
    "when_earlier": "earlier",
}

# 05.11 (owner, the risk scale): the SERVER puts the level, from the reason code and the parsed target -- never from the agent's words. Four steps
# (no percent: false precision). Signed with the view (signview.KEYS "risk"); the page draws the bar and the word ("High risk").
RISK_ORDER = ("low", "medium", "high", "critical")
RISK_LABEL = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}
RISK_BY_CODE = {
    "ESCALATE_COMMAND": "low",                  # a command that is not on the list, inside the project
    "ESCALATE_NOT_LISTED": "low",
    "ESCALATE_TRIAL_CLAIM": "low",
    "ESCALATE_FILE": "medium",                  # a write the mandate does not cover
    "ESCALATE_COUNT": "medium",
    "ADVISORY_HOLD": "medium",
    "ESCALATE_HTTP": "high",                    # leaves the computer
    "ESCALATE_COMMAND_DANGER": "high",
    "ESCALATE_PUBLISH": "high",
    "ESCALATE_DELETE": "high",
    "ESCALATE_USER_CONTENT_HOST": "high",
    "ESCALATE_NET_UNSEEN": "high",
    "ESCALATE_EGRESS_UNSPECIFIED": "high",
    "ESCALATE_EXEC_CHANGED": "high",
    "ESCALATE_WRITTEN_RUN": "high",
    "ESCALATE_SECRET_COPY": "high",
    "ESCALATE_SECRET_SEEN": "critical",         # secrets out
    "ESCALATE_DATA": "critical",
    "ESCALATE_MONEY": "critical",
}
_INSTALLERS = {"pip", "pip3", "npm", "npx", "yarn", "pnpm", "brew", "apt", "apt-get", "gem", "cargo", "uv", "poetry", "conda"}
_INSTALL_WORD = re.compile(r"\b(install|add|i|upgrade|update)\b")


def risk_max(levels):
    """The highest of several levels (a line of parts: the maximum over the parts); unknown strings count as high (fail closed)."""
    best = 0
    for lv in levels:
        best = max(best, RISK_ORDER.index(lv) if lv in RISK_ORDER else 2)
    return RISK_ORDER[best]

# the full words of the same risks (Details -> "Why it matters")
LONG_HARM = {
    "ESCALATE_COMMAND": "It runs code on your computer. It could change or delete files in this project.",
    "ESCALATE_COMMAND_DANGER": "It can delete or overwrite files, or send data out of this computer.",
    "ESCALATE_PUBLISH": "Data leaves this computer and cannot be taken back. Your mandate names no channel for it.",
    "ESCALATE_DELETE": "Deleted data may be gone for good.",
    "ESCALATE_DATA": "Private data (keys, passwords, personal details) could leave this project.",
    "ESCALATE_FILE": "A file your mandate does not cover would change.",
    "ESCALATE_COUNT": "A loop or a runaway agent could do a lot of damage in a short time.",
    "ESCALATE_EXEC_CHANGED": "Code you have not seen would run on your computer.",
    "ESCALATE_HTTP": "A request can send data out of this project, or fetch something that changes your computer.",
    "ESCALATE_WRITTEN_RUN": "The agent could run code you never read.",
    "ESCALATE_SECRET_COPY": "Earlier the agent copied a credential file here (you allowed the copy). Reading the copy reads the credential.",
    "ESCALATE_SECRET_SEEN": "It could carry your keys or passwords out of this project folder.",
    "ESCALATE_EGRESS_UNSPECIFIED": "Data could be sent to a host your mandate does not name.",
    "ESCALATE_NOT_LISTED": "Its effect is not covered by your mandate.",
}

# sharper harm for what is irreversible or lasting (server-parsed path / host, not agent words): (regex, short harm, long harm)
_PATH_HARM = (
    (re.compile(r"(^|/)\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile)$"),
     "The agent could stay on your computer for good.",
     "It changes a file that runs every time you open a terminal: the agent could stay on your computer for good."),
    (re.compile(r"/LaunchAgents/|/LaunchDaemons/|/crontab|/systemd/"),
     "The agent could stay on your computer for good.",
     "This entry starts at every login: the agent could stay on your computer for good."),
    (re.compile(r"(^|/)\.claude(/|$)|(^|/)\.mcp\.json$|(^|/)\.cursor/"),
     "Witness could be switched off for the next session.",
     "These are your agent's own settings: a change can switch Witness off for its next session."),
    (re.compile(r"(^|/)\.git/(hooks|config)|(^|/)\.gitconfig$"),
     "Git would run this later without asking you.",
     "Git runs this by itself later, without asking you."),
    (re.compile(r"(^|/)\.(ssh|aws|gnupg)(/|$)|(^|/)\.env(\.|$)|id_rsa|id_ed25519|credentials"),
     "This holds your keys or passwords.",
     "This holds your keys or passwords."),
)
_CTRL = re.compile(r"[\x00-\x1f\x7f`]")
# invisible or look-alike characters that category Cf/Zl/Zp/Zs do not all cover (fillers, blank braille, variation selectors)
_INVISIBLE = {0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x034F, 0x180B, 0x180C, 0x180D, 0x180E, 0x061C, 0x00AD}


def _hidden(ch):
    cp = ord(ch)
    if cp in _INVISIBLE or 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return True
    c = unicodedata.category(ch)
    return c in ("Cf", "Zl", "Zp", "Co", "Cs", "Cn") or (c == "Zs" and ch != " ")


def visible(s, keep_nl=False):
    """05.11 (RT hole 2): the text with every invisible character (bidi override U+202E, zero width, U+2028/2029, odd spaces, ...) replaced
    by a visible mark `⟨U+202E⟩`: what the person reads is what the line holds (`git push ‮nigiro‬ main` no longer looks like `origin`).
    keep_nl: a line feed and a tab stay (multi-line text); the other control characters are marked too."""
    out = []
    for ch in str(s if s is not None else ""):
        if _hidden(ch) or (unicodedata.category(ch) == "Cc" and not (keep_nl and ch in "\n\t")):
            out.append("\u27e8U+%04X\u27e9" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def _clean(s, n=120):
    s = _CTRL.sub(" ", visible_keep_ctrl(str(s or ""))).strip()
    return s if len(s) <= n else s[:n - 1] + "…"


def visible_keep_ctrl(s):
    """`visible` for the invisible non-control characters only (the ASCII controls stay for the caller to turn into spaces)."""
    return "".join("\u27e8U+%04X\u27e9" % ord(ch) if _hidden(ch) else ch for ch in s)


def _parse(x, action):
    """-> (kind, target): kind host | path | command | other, from the server's own classification of the call."""
    tool = str(x["tool"] or "")
    base = tool.split(".")[0]
    cls = str((action or {}).get("class") or "")
    rc = str((action or {}).get("recipient") or "")
    if rc.startswith("(network) "):
        return "host", _clean(rc[len("(network) "):])
    if tool == "Bash.net" or base in ("WebFetch", "WebSearch") or cls in ("disclosure", "message", "publish", "purchase"):
        return "host", _clean(rc.split("@", 1)[-1])
    if base in ("Write", "Edit", "MultiEdit", "NotebookEdit", "Read", "NotebookRead") or cls in ("file", "delete"):
        return "path", _clean(rc)
    if cls == "command":
        return "command", _clean(rc)
    return "other", _clean(rc or tool)


def _heads(x):
    """The commands of a shell line as the server parsed them (actions.line_heads), cleaned; [] when the row has none."""
    try:
        hl = json.loads(x["line_heads"]) if "line_heads" in x.keys() and x["line_heads"] else []
    except (TypeError, ValueError):
        hl = []
    return [h for h in hl if isinstance(h, str) and h.strip()][:64] if isinstance(hl, list) else []


def git_config_read(x, t=None) -> bool:
    """12.11 (r0263 / r0264): a question that the client lock K1 raised only for `git config` ("agent-config:(hook) git config"), on a line
    whose every git config the server's own parse names "git config get" (a read: no value, no -f / --blob, no key git runs)."""
    try:
        if t is None:
            a = json.loads(x["action_json"]) if x["action_json"] else {}
            t = str(a.get("recipient") or "")
        if not str(t).startswith("agent-config:"):
            return False
        ad_ = str(t).split(":", 1)[1].strip()
        ad_ = ad_[len(HARNESS_MARK_):].strip() if ad_.startswith(HARNESS_MARK_) else ad_
        gh_ = [h for h in _heads(x) if h == "git config" or h.startswith("git config ")]
        return ad_ == "git config" and bool(gh_) and all(h == "git config get" for h in gh_)
    except (TypeError, ValueError, KeyError, IndexError, AttributeError):
        return False


def _sbx_open(x):
    """cmd_meta.sbx_open of a row (the write hosts that took the strict fact away from the line), [] when absent / malformed."""
    try:
        m = json.loads(x["cmd_meta"]) if "cmd_meta" in x.keys() and x["cmd_meta"] else {}
    except (TypeError, ValueError, KeyError, IndexError):
        return []
    so = m.get("sbx_open") if isinstance(m, dict) else None
    return [h for h in so if isinstance(h, str) and h][:16] if isinstance(so, list) else []


def _sbx_closed(x):
    """11.11 (r0260): cmd_meta.sbx_closed -- the person's credential sources were closed to the sandbox (hookjudge/sandbox.cred_closed)."""
    try:
        m = json.loads(x["cmd_meta"]) if "cmd_meta" in x.keys() and x["cmd_meta"] else {}
    except (TypeError, ValueError, KeyError, IndexError, AttributeError):
        return False
    return isinstance(m, dict) and m.get("sbx_closed") is True


# 11.11 (r0261, closed list of the strict sandbox: hookjudge/strict_policy.py): the asked part's recipient is "<prefix><target>"; the
# words come from the prefix (what / short harm / why it matters / risk). Plain words, one line each (owner 05.11).
STRICT_WORDS = {
    "(strict publish) ": ("Your agent wants to send or publish something outside this computer: {t}",
                          "It leaves your computer and cannot be taken back.",
                          "The sandbox keeps the agent on this computer, but this program writes somewhere else (a repository, a registry, "
                          "a server, an e-mail): what it sends cannot be taken back.", "high"),
    "(strict outside) ": ("Your agent wants to start something outside its sandbox: {t}",
                          "That program runs without the sandbox's limits.",
                          "A browser, another app or an administrator command is not limited by the sandbox: it can reach the internet "
                          "and your files.", "high"),
    "(strict later run) ": ("Your agent wants to change a file that runs later by itself: {t}",
                            "It could run later outside the sandbox.",
                            "Git hooks, direnv, your editor, CI or your agent's next session run this file later, without the sandbox "
                            "and without asking.", "high"),
    "(strict inject) ": ("Your agent wants to load code from outside the project into a program: {t}",
                         "The command would not run what it says.",
                         "This setting makes a program load code from another place, so the command no longer shows what runs.", "medium"),
    "(strict witness) ": ("Your agent wants to touch Witness's own key or settings: {t}",
                          "It is the key of the guard itself.",
                          "This is the key and settings Witness uses to check your agent. The sandbox blocks the files; a key in a "
                          "variable can still be seen.", "high"),
    "(strict irreversible) ": ("Your agent wants to throw away work that cannot be brought back: {t}",
                               "Uncommitted changes, git history or a database are lost for good.",
                               "This stays inside your project, but nothing brings it back: changes not committed yet, a branch or a "
                               "stash git forgets, or a table of a database.", "high"),
    "(strict data) ": ("Your agent's command contains {t}",
                       "It may be a password, a token or personal data.",
                       "Nothing on this command sends it anywhere (no network, no publishing). Usually a test value or a file the "
                       "agent edits; if it is your real secret, say no.", "medium"),
    "(strict doubt) ": ("Your agent's command contains text that looks dangerous: {t}",
                        "Witness is not sure it is only text.",
                        "The command writes or passes text that matches a forbidden action. If it is only text (a document, a test), "
                        "it is harmless; if code runs it, it is not.", "medium"),
}


# 12.11 (L3 repeat on 0.2.61): the "(strict data)" title said the DLP's tag ("a value that looks private (email_address)")
DATA_TAG_WORDS = {"email_address": "an e-mail address", "spelled_email": "an e-mail address", "phone": "a phone number",
                  "spelled_digits": "a phone or card number", "postal_address": "a postal address", "spelled_address": "a postal address",
                  "card_number": "a card number", "iban": "a bank account number", "ssn": "a social security number",
                  "crypto_address": "a crypto wallet address", "seed_phrase": "a wallet recovery phrase", "api_key": "a key or token",
                  "telegram_token": "a key or token", "bearer": "a key or token", "token": "a key or token", "secret": "a password or key",
                  "secret_assign": "a password or key", "password": "a password", "passwd": "a password", "private_key": "a private key",
                  "personal_words": "personal data"}


# 12.11 (r0263, L3 ISPYTANIE-L3-0260 Г): the title said the parser's internal mark ("a dangerous command: exit:/private/tmp/...",
# "opaque:.: the rest of the line cannot be judged", "net-out:npm install") and one harm for all ("can damage files or leak data", for
# `python -m venv`). The owner's rule "ВОПРОС -- ПРОСТО": one line WHAT, one line HARM, the command, three buttons; the rest under Details.
# The danger mark of a Bash.danger part ("<category>:<detail>", hookjudge/bashparse.Classified.add) -> plain words of its category; the
# mark itself goes under Details ("Why Witness asks"). The title names the act only: the command is the next line of the page (no repeat).
# (what, harm, long harm, risk)
DANGER_WORDS = {
    "install": ("Your agent wants to install packages from the internet",
                "Code downloaded from the internet would run on your computer.",
                "Installing runs the packages' own setup code on this computer, outside any sandbox. Usual for development; say no if "
                "you did not expect a new package.", "medium"),
    "fetch": ("Your agent wants to download code from the internet", "It downloads; nothing of yours is sent.",
              "It reads from a remote repository. Nothing of your project is sent.", "medium"),
    "push": ("Your agent wants to send your code to a server", "Your code leaves this computer.",
             "A push publishes commits to the remote repository; others may see them at once.", "high"),
    "exit": ("Your agent wants to run a program that reaches the internet", "It can send data out of this computer.",
             "This program talks to servers outside this computer (or acts as you there).", "high"),
    "opaque": ("Your agent wants to run a command Witness cannot fully check", "Part of it is hidden from Witness.",
               "Part of the line comes from a variable, a sourced file or a form Witness does not read, so it cannot tell what that "
               "part does.", "medium"),
    "secrets": ("Your agent wants to read or use your keys or passwords", "This holds your keys or passwords.",
                "Keys, tokens or passwords could be read or sent out.", "high"),
    "rm-rf": ("Your agent wants to delete files for good", "Files could be deleted for good.",
              "A recursive delete cannot be undone.", "high"),
    "git-config": ("Your agent wants to change git settings that run programs", "Git would run this later without asking you.",
                   "Git runs this by itself later, without asking you.", "high"),
    "pipe-to-shell": ("Your agent wants to download a script and run it at once", "Code nobody has read would run.",
                      "The downloaded text goes straight into a shell; nobody sees it before it runs.", "high"),
    "write-outside": ("Your agent wants to write outside the project", "A file outside your project would change.",
                      "The file is outside your project folder; Witness keeps no copy of it.", "medium"),
    "sql-drop": ("Your agent wants to delete database data", "Data could be lost for good.", "Dropped tables do not come back.", "high"),
    "loopback-write": ("Your agent wants to send data to a program on this computer",
                       "A local service (a browser, Docker) could act on it.",
                       "Local services (a browser's debugging port, Docker, a database) act with your rights.", "high"),
    "git-destroy": ("Your agent wants to throw away git work", "Uncommitted work or history could be lost for good.",
                    "Changes not committed yet, a branch or a stash that git forgets cannot be brought back.", "high"),
    "disk": ("Your agent wants to use a disk tool", "A whole disk could be erased.", "Disk tools work below the files.", "critical"),
    "witness": ("Your agent wants to touch Witness itself", "It could switch your guard off.",
                "This is Witness's own key or settings.", "critical"),
    "git-force-push": ("Your agent wants to overwrite history on the server", "Other people's work could be lost.",
                       "A force-push replaces the branch on the server.", "high"),
}
_INSTALL_MARK = re.compile(r"(?:^|/)(?:pip3?|npm|npx|yarn|pnpm|uv|uvx|poetry|conda|gem|cargo|brew|go|bun|pipx)\b|\[packages\]|-m pip\b")
_GIT_FETCH = re.compile(r"^git (?:pull|fetch|clone|ls-remote|submodule update|remote update)\b")


def danger_category(t):
    """'net-out:npm install' -> ('install', 'npm install'); 'opaque:...' -> ('opaque', '...'); not a mark -> (None, t)."""
    if not isinstance(t, str) or ":" not in t:
        return None, t
    cat, det = t.split(":", 1)
    if not re.fullmatch(r"[a-z][a-z-]{1,20}", cat):
        return None, t
    det = det.strip()
    if cat in ("net-out", "exit"):
        if _INSTALL_MARK.search(det) and not det.startswith("git "):
            return "install", det
        if det.startswith("git push"):
            return "push", det
        if _GIT_FETCH.match(det):
            return "fetch", det
        return "exit", det
    return (cat, det) if cat in DANGER_WORDS else (None, t)


HARNESS_MARK_ = "(hook) "           # = hookjudge.mapping.HARNESS_MARK (client 0.2.59+: the lock K1 found the agent's harness)
QUIET_ON = "(quiet mode on) "      # = hookjudge.bashparse.QUIET_ON (r0262)
TEMP_WRITE = "(write outside the project) "      # = hookjudge.mapping.OUTSIDE_WRITE (r0261f: a Write / Edit in shared temp)


def _strict_words(t):
    for p_, ent in STRICT_WORDS.items():
        if isinstance(t, str) and t.startswith(p_.strip()):
            return p_, ent
    return None, None


def _exec_member(x, k):
    try:
        ej = json.loads(x["exec_json"]) if "exec_json" in x.keys() and x["exec_json"] else None
    except (TypeError, ValueError, KeyError, IndexError, AttributeError):
        return None
    return ej.get(k) if isinstance(ej, dict) else None


def _refused_before(x):
    """r0275: exec_json "rb" of a question row (provenance.refused_before), or None"""
    try:
        ej = json.loads(x["exec_json"]) if "exec_json" in x.keys() and x["exec_json"] else None
    except (TypeError, ValueError, KeyError, IndexError, AttributeError):
        return None
    rb = ej.get("rb") if isinstance(ej, dict) else None
    return rb if isinstance(rb, dict) and isinstance(rb.get("at"), int) else None


def words(x):
    """-> {"what", "harm", "details"} (non-empty strings) for an actions row x (sqlite Row or dict). Never raises."""
    try:
        action = json.loads(x["action_json"]) if x["action_json"] else {}
    except (TypeError, ValueError, KeyError, IndexError):
        action = {}
    if not isinstance(action, dict):
        action = {}
    try:
        reason = x["reason"]
        kind, t = _parse(x, action)
        ent = REASON_WORDS.get(str(reason or ""))
        long_harm = ""
        persist = False
        if ent is None:
            what, harm = UNKNOWN_WHAT, UNKNOWN_HARM
        else:
            what = ent[0].format(t=t or SCREEN["unnamed"])
            harm = ent[1]
            long_harm = LONG_HARM.get(str(reason), "")
            if kind == "path" or (kind == "command" and t.startswith(("persist:", "agent-config:"))):
                for rx, h, hl in _PATH_HARM:              # 05.11 (RT hole 5): a dangerous line that writes a place of persistence says so
                    if rx.search(t):
                        harm, long_harm = h, hl
                        persist = True
                        break
                else:
                    if kind == "command":
                        persist = True
                        harm = SCREEN["persist"]
                        long_harm = "It changes a place that starts by itself later: the agent could stay on your computer for good."
            if kind == "host" and reason in ("ESCALATE_HTTP", "ESCALATE_COMMAND_DANGER") and t:
                harm = NET_HARM
                long_harm = LONG_HARM["ESCALATE_HTTP"] if reason == "ESCALATE_HTTP" else LONG_HARM["ESCALATE_COMMAND_DANGER"]
            if kind == "host" and reason in ("ESCALATE_SECRET_SEEN", "ESCALATE_DATA", "ESCALATE_EGRESS_UNSPECIFIED") and t:
                what = SCREEN["send_request"].format(t=t)
                harm = SCREEN["secret_to_host"]
                long_harm = "This could send your keys or passwords out of this project folder, to %s." % t
        if kind == "host" and ent is not None and reason in ("ESCALATE_HTTP", "ESCALATE_COMMAND_DANGER") and t:
            what = SCREEN["send_request"].format(t=t)
        # r0280 (R-06, rule "signed = shown"): a read of a credential file (Read / Grep / NotebookRead of .env, a key: the tool map gives it
        # class "publish" and the recipient "secrets:<path>") is said as the read it is, in the words of the closed vocabulary (DANGER_WORDS
        # "secrets", already in mr-vocab-2: the vocabulary does not change). Before, the server said "send or publish something to
        # secrets:/p/.env" (a mark of the classifier on the first screen) and the page wrote its own title over it (not signed).
        rc_ = str((action or {}).get("recipient") or "")
        secret_read = ent is not None and kind != "command" and (rc_.startswith("secrets:") or str(x["tool"] or "").endswith(".secret"))
        if secret_read:
            what, harm, long_harm = DANGER_WORDS["secrets"][0], DANGER_WORDS["secrets"][1], DANGER_WORDS["secrets"][2]
            persist = False
            kind = "path"
            t = _clean(rc_[len("secrets:"):] if rc_.startswith("secrets:") else rc_, 300)
        so = _sbx_open(x)
        if so and ent is not None:
            # 10.11 (r0260): the strict sandbox is open to a host where code can write in the person's name, and code in it can read the
            # login keychain (L2 10.11): the line is asked for that, and the person is told so (short on the main screen, full under
            # Details). A sharper harm of the line itself (a secret, persistence, a host) stays on the main screen; the reason goes below.
            if _sbx_closed(x):
                # 11.11 (r0260): the credential sources are closed -- asked because the line NAMES the host or a publication
                sl = ("Your sandbox lets programs reach %s. Your login keychain, browser cookies and credential files are closed to code "
                      "in the sandbox, but this command names that host or a publish step: it could push or publish there, in your name "
                      "if a credential reaches it another way." % ", ".join(_clean(h, 60) for h in so[:6]))
            else:
                sl = ("Your sandbox lets programs reach %s, and code inside it can read your login keychain (git and gh keep their "
                      "credentials there). Code this command runs could push, create a gist or publish a package in your name."
                      % ", ".join(_clean(h, 60) for h in so[:6]))
            if (reason in ("ESCALATE_COMMAND", "ESCALATE_EXEC_CHANGED", "ESCALATE_WRITTEN_RUN") or
                    (reason == "ESCALATE_COMMAND_DANGER" and kind == "command" and str(t).startswith(("net-out:", "exit:")))) \
                    and not persist and kind != "host":
                # 11.11 (r0260): `git push` / `npm publish` (a dangerous line whose mark is leaving the machine) says the same short harm
                harm, long_harm = SCREEN["sandbox_publish"].format(t=_clean(so[0], 60)), sl
            else:
                long_harm = (long_harm + " " if long_harm else "") + sl
        dcat_, ddet_ = danger_category(t) if kind == "command" and reason == "ESCALATE_COMMAND_DANGER" and not persist else (None, t)
        dmark_ = ""
        if dcat_ is not None and not so:
            # 12.11 (r0263): the mark in plain words; the internal mark goes under Details ("Why Witness asks")
            dw_ = DANGER_WORDS[dcat_]
            what, harm, long_harm = dw_[0], dw_[1], dw_[2]
            tp0_ = str(x["text_preview"] if "text_preview" in x.keys() and x["text_preview"] else "")
            cat0_, det0_ = t.split(":", 1)
            dmark_ = _clean(cat0_ if det0_.strip() and det0_.strip() in tp0_ else t, 300)     # the detail once: not when the text has it
        sp_, sent_ = _strict_words(t) if kind in ("command", "path") else (None, None)
        if sent_ is not None:                       # r0261: a reason of the strict closed list (its own words, not "dangerous command")
            tt_ = _clean(t[len(sp_.strip()):].strip(), 160) or SCREEN["unnamed"]
            if sp_ == "(strict data) ":                 # 12.11 (L3): "(email_address)" was the DLP's tag: its words, the tag under Details
                tt_ = ", ".join(dict.fromkeys(DATA_TAG_WORDS.get(g.strip(), "a private value") for g in tt_.split(",") if g.strip()))
                dmark_ = dmark_ or _clean(t, 300)
            what = sent_[0].format(t=tt_)
            harm, long_harm, persist = sent_[1], sent_[2], False
        ac_risk, ac_mark = None, ""
        if kind == "command" and reason == "ESCALATE_COMMAND_DANGER" and t.startswith("agent-config:") and sent_ is None:
            # 12.11 (L3 ISPYTANIE-L3-0260, repeat on 0.2.61): the title said "a dangerous command: agent-config:(hook) git config" and the
            # harm "The agent could stay on your computer for good" (Critical) for `git config user.email` in a line with pytest. The client
            # 0.2.61 lock K1 needs the owner's yes for any line with `git config` it cannot prove read-only, so the question stays; its
            # words now say what the line does. Read only = the server's own parse names every git config of the line "git config get".
            ad_ = t.split(":", 1)[1].strip()
            ad_ = ad_[len(HARNESS_MARK_):].strip() if ad_.startswith(HARNESS_MARK_) else ad_
            ac_mark = _clean(t, 300)
            if git_config_read(x, t):
                what, harm = SCREEN["git_read_what"], SCREEN["git_read_harm"]
                long_harm = ("Witness asks about every line that touches git's settings, because a setting can make git run a program "
                             "later. This line only reads them (for example your name and e-mail for a commit).")
                persist, ac_risk = False, "low"
                ac_mark = ""                        # 12.11 (r0264, L3 q-Z62DVF): no "agent-config:(hook) git config" under a Low read
            elif ad_.startswith("git config") or re.search(r"(^|/)\.git/(hooks|config)|(^|/)\.gitconfig$", ad_):
                what, harm = SCREEN["git_change_what"], SCREEN["git_change_harm"]
                long_harm = "Git runs what its settings and hooks name by itself later, without asking you."
                ac_risk = "high"
            else:
                what = SCREEN["own_settings_what"]
                if not re.search(r"(^|/)\.claude(/|$)|(^|/)\.mcp\.json$|(^|/)\.cursor/", ad_):
                    harm = SCREEN["own_settings_harm"]
                    long_harm = "These files decide how your agent and Witness start next time."
        if kind == "path" and t.startswith(TEMP_WRITE.strip()) and sent_ is None:
            # r0261f (0.2.59): a file the agent writes in the shared temp of this computer (strict_policy.temp_write_ask): plain words
            what = SCREEN["temp_write_what"].format(t=_clean(t[len(TEMP_WRITE.strip()):].strip(), 160) or SCREEN["unnamed"])
            harm = SCREEN["temp_write_harm"]
            long_harm = ("It is a shared temporary folder, not your project and not the agent's own temporary folder. Nothing runs it by "
                         "itself; it is asked each time because it is outside what your mandate lets the agent write.")
        if kind == "command" and t.startswith("witness:" + QUIET_ON) and sent_ is None:
            # 0.2.92 (r0262): the agent's fixed line for quiet mode (client 0.2.60, /deus-witness:try): plain words, built here
            what = SCREEN["quiet_what"]
            harm = SCREEN["quiet_harm"]
            long_harm = ("It writes ~/.claude/settings.json (a backup is kept): commands then run in Claude Code's sandbox with no network "
                         "except the hosts you list, and cannot read your SSH and cloud keys, login keychain or browser cookies; secrets "
                         "in environment variables are hidden from commands and hooks; Claude Code may switch its permission mode to default. "
                         "In return Witness asks only about what could leave this Mac or cannot be undone. It starts with your next "
                         "Claude Code session. Undo: deus-witness-hook --undo-strict in your own terminal. Only you can approve this; it "
                         "is asked every time.")
        heads = _heads(x)
        risk = RISK_BY_CODE.get(str(reason or ""), "high") if sent_ is None else sent_[3]
        if dmark_ and sent_ is None:
            risk = DANGER_WORDS[dcat_][3]
        if so and risk_max([risk, "high"]) != risk:
            risk = "high"                           # 10.11 (r0260): code could publish in the person's name
        if ac_risk is not None and not so:
            risk = ac_risk                          # 12.11: the agent's harness in words (above): a read of git settings is low
        if secret_read and risk_max([risk, DANGER_WORDS["secrets"][3]]) != risk:
            risk = DANGER_WORDS["secrets"][3]          # r0280: a secret read is at least what the vocabulary says of "secrets" (high)
        if persist:
            risk = "critical"                       # ~/.zshrc, LaunchAgents, the agent's own settings, keys: the agent could stay for good
        elif kind == "host" and risk_max([risk, "high"]) != risk:
            risk = "high"                           # anything that reaches a host is at least high
        elif risk == "low" and any(h.split(" ")[0] in _INSTALLERS for h in (heads or [t])) and _INSTALL_WORD.search(str(x["text_preview"] if "text_preview" in x.keys() else "") or t):
            risk = "medium"                         # installing packages
        if kind == "command" and reason == "ESCALATE_COMMAND" and len(heads) > 1:
            # 05.11 (RT hole 3): a line of several commands. The title is short; EVERY command is named on the first screen (the line under the
            # buttons' title) and listed in full under Details ("Commands of the line"), so the first one alone never hides `make deploy`.
            what = SCREEN["many_commands"].format(n=len(heads))
        sc_ = _exec_member(x, "sc")
        if isinstance(sc_, dict) and isinstance(sc_.get("src"), str):
            # r0275: the file is a copy the agent made of a credential: the credential is named under Details (provenance)
            long_harm = (long_harm + " " if long_harm else "") + "It is a copy of %s that the agent made earlier." % _clean(sc_["src"], 200)
        rb_ = _refused_before(x)
        if rb_ is not None:
            # r0275 (Cursor 09.2025, Authorization Drift): the owner refused the same effect through another call in this session: the
            # one short line says so; the harm of the call itself goes under Details. Built by the server from its own rows (provenance).
            from app import provenance as _pv
            long_harm = "%s %s%s" % (_pv.detail(rb_), harm, (" " + long_harm) if long_harm and long_harm != harm else "")
            harm = _pv.words(rb_, x["created_at"] if "created_at" in x.keys() else None) or harm
            if risk_max([risk, "high"]) != risk:
                risk = "high"
        d = []
        if long_harm and long_harm != harm:
            d.append("Why it matters: %s" % long_harm)
        if dmark_ or ac_mark:
            d.append("Why Witness asks: %s" % (dmark_ or ac_mark))
        d.append("Tool: %s" % _clean(str(x["tool"] or "").split(".")[0], 80))     # r0264: "Bash", not the part code "Bash.danger"
        tp = x["text_preview"] if "text_preview" in x.keys() else ""
        if kind == "host":
            d.append("Data goes to host: %s" % (t or "(not shown)"))
        elif kind == "path":
            d.append("File: %s" % (t or "(not shown)"))
        elif t and not dmark_ and not tp:
            d.append("Command: %s" % t)               # 12.11 (r0263): the page's Details card shows the text of the call: not twice
        if len(heads) > 1 and not tp:
            d.append("Commands of the line (%d): %s" % (len(heads), _clean("; ".join(heads), 600)))
        if tp:
            tp = str(tp)
            if len(tp) > 1500:      # 05.11 (RT hole 3): never a silent cut
                d.append("Text (first 1500 of %d characters, cut - full list of commands below):\n%s" % (len(tp), visible(tp[:1500], True)))
                if heads:
                    d.append("All commands of the line:\n%s" % "\n".join("- " + _clean(h, 300) for h in heads))
            else:
                d.append("Full text:\n%s" % visible(tp, True))     # 12.11 (r0263): the ONE full copy (the page hides its own card then)
        reads_ = "Read" in str(x["tool"] or "") or secret_read
        if kind == "path":
            d.append("What changes: this file." if not reads_ else "What changes: nothing is written; the agent reads this file.")
        elif kind == "host":
            d.append("What changes: data is sent to that host. This cannot be taken back.")
        else:
            d.append("What changes: whatever the command does to your files and system.")
        if kind == "path" and not reads_:
            d.append("Undo: a file outside the project gets a shadow copy first; restore it with: deus-witness-hook --undo PATH")
        elif kind == "host":
            d.append("Undo: not possible once sent.")
        else:
            d.append("Undo: not automatic. Files outside the project written by a command get a shadow copy (deus-witness-hook --undo PATH).")
        return {"what": what, "harm": harm, "risk": risk, "details": "\n".join(d)}
    except Exception:    # fail closed in words: still a question, an honest general text
        return {"what": UNKNOWN_WHAT, "harm": UNKNOWN_HARM, "risk": "high", "details": "Witness could not read more about this call. Decide only if you expected it."}


# Push / chat form (05.11, owner at the phone): one short sentence per code, no host, no path (nothing of the call leaves the server), then "Open to decide".
PUSH_WHAT = {
    "ESCALATE_COMMAND": "your agent wants to run a command",
    "ESCALATE_COMMAND_DANGER": "your agent wants to run a risky command",
    "ESCALATE_PUBLISH": "your agent wants to send something out",
    "ESCALATE_DELETE": "your agent wants to delete something",
    "ESCALATE_MONEY": "your agent wants to pay for something",
    "ESCALATE_DATA": "your agent wants to send out something private",
    "ESCALATE_FILE": "your agent wants to change a file",
    "ESCALATE_COUNT": "your agent keeps repeating the same action",
    "ESCALATE_EXEC_CHANGED": "your agent wants to run a file that changed",
    "ESCALATE_HTTP": "your agent wants to use the internet",
    "ESCALATE_WRITTEN_RUN": "your agent wants to run a file it wrote",
    "ESCALATE_SECRET_COPY": "your agent wants to read a copy of a secret",
    "ESCALATE_SECRET_SEEN": "your agent wants to act after it read a secret",
    "ESCALATE_NET_UNSEEN": "your agent wants to use the internet",
    "ESCALATE_TRIAL_CLAIM": "your agent wants to start a trial",
    "ESCALATE_EGRESS_UNSPECIFIED": "your agent wants to use the internet",
    "ESCALATE_USER_CONTENT_HOST": "your agent wants to send data to a public site",
    "ESCALATE_NOT_LISTED": "your agent wants to do something new",
    "ADVISORY_HOLD": "your agent wants to act, and its text was flagged",
}
PUSH_TAIL = "Open to decide"


def short(reason):
    """Push / chat form (<= 2 short lines): what + "Open to decide" from the reason code alone (no host, no path: nothing of the call leaves the server)."""
    w = PUSH_WHAT.get(str(reason or ""))
    lv = RISK_BY_CODE.get(str(reason or ""), "high") if w is not None else "high"
    if w is None:
        w = "your agent wants to do something Witness could not classify"
    return "%s risk: %s" % (RISK_LABEL[lv], w), PUSH_TAIL
