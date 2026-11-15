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
    # r0281 (blind evaluation of 0.2.105, #1 / B5): `curl -d @notes.txt host` SENDS the file, every time: the words name the file and the host
    # (was "Information from your computer could be sent": softer than the act). Both {t} are quotes of the call (file, then host).
    "send_file_what": "Your agent wants to send the file {t} to {t}",
    "send_files_what": "Your agent wants to send files to {t}",
    "send_file_harm": "Its contents would leave this computer for good.",
    "send_files_harm": "Their contents would leave this computer for good.",
    "send_secret_file_harm": "Your keys or passwords would leave this computer for good.",
    # r0294 (mr-vocab-3, law "origin of code"; red team 13.11 "take-home task"): a run of code that came from the network in this session.
    # {t} = the host the server parsed from the line that downloaded it (quoted under Details when not in this call), {when} = how long ago.
    "net_code_run": "Runs code downloaded from {t} {when} — it can do anything you can.",
    "net_code_now": "Runs code from {t} — it can do anything you can.",
    # r0298 (mr-vocab-4, decision of Deus 14.11): a write in a folder Witness cannot tell to a file that starts programs by itself (shell
    # start-up files, LaunchAgents, Claude Code's settings / hooks, git hooks): asked "once" or "no", never "from now on" (bashparse.AUTOSTART)
    "autostart_what": "Your agent wants to change a file that starts commands by itself",
    "autostart_harm": "It could make commands run on their own, without asking you.",
    # r0305 (mr-vocab-5, SHAG0-POLNYY-KONVEYER-1411): a program that switches off a protection of the operating system (Gatekeeper, SIP,
    # TCC, the firewall, SELinux / AppArmor, Defender): refused (Н10) everywhere; these words show only where the strict policy asks a doubt
    "defense_what": "Your agent wants to switch off a protection of your computer",
    "defense_harm": "Harmful programs could then run without any warning.",
}
AUTOSTART_MARK = "autostart:"      # = hookjudge.bashparse.AUTOSTART + ":"
LATER_LONG = ("This file is run later by another program, by itself, outside Witness: direnv runs .envrc when you enter the folder, git "
              "hook managers (.husky, pre-commit) run their scripts on commit, the editor runs its tasks, CI runs its workflows on push. "
              "Only \"Allow once\" is offered: this is never allowed from now on.")     # r0305 (W5)
DEFENSE_MARK = "defense:"          # = hookjudge.bashparse.DEFENSE + ":" (r0305)
DEFENSE_LONG = ("This switches off a protection your computer has against harmful programs: Gatekeeper or the quarantine mark on "
                "downloaded files, System Integrity Protection, privacy permissions, the firewall, SELinux / AppArmor or antivirus. "
                "Programs that run after it are not checked by it any more. Witness refuses this by itself; change such a setting by hand "
                "in your own terminal if you really need to.")
AUTOSTART_LONG = ("Witness cannot tell which folder this line writes in (a cd or a script before it may not have run), but the file it "
                  "names is one that starts programs by itself: a shell start-up file, a LaunchAgent, Claude Code's settings or hooks, "
                  "git's hooks or settings. Whatever is written there would run later without asking you. Only \"Allow once\" is offered: "
                  "this is never allowed from now on.")
# r0304: a mass copy (bashparse._mass_copy: `cp -r dotfiles/. ~`, `rsync -a dotfiles/ ~`, `cp -a cfg/. ~/.config/`): the folder IS known, the
# files are not. "Why it matters" under Details (signed with the view, not rebuilt from the vocabulary): the first screen stays mr-vocab-4's.
AUTOSTART_COPY_MARK = AUTOSTART_MARK + "copy into "
AUTOSTART_COPY_LONG = ("This line copies a whole folder into {t}, and Witness cannot see which files it brings. That folder holds files that "
                       "start programs by themselves: shell start-up files, LaunchAgents, Claude Code's settings or hooks, git's settings. "
                       "A file copied there would run later without asking you. Only \"Allow once\" is offered: this is never allowed from now on.")

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


# r0299 (R0299-BASHRC-I-METKI.md; owner 05.11 "ВОПРОС -- ПРОСТО": no internal names): the line "Why Witness asks" under Details said the
# parser's mark ("autostart:write to ...", "opaque:eval: ...", "agent-config:(hook) git config", "(strict data) email_address"). Now the mark's
# category in words (this table; one entry per DANGER_WORDS category + autostart + agent-config), then the parser's own detail when the text
# of the call does not already show it. Details is signed with the view (signview "details"), never rebuilt from the vocabulary (screencheck
# rebuilds the first screen only): the vocabulary document mr-vocab-4 and its digest do not change; views stored before stay as they were.
MARK_WORDS = {
    "install": "it installs packages from the internet",
    "fetch": "it downloads from a repository",
    "push": "it sends code to a server",
    "exit": "a program in it reaches the internet",
    "opaque": "Witness cannot read part of this line",
    "secrets": "it touches your keys or passwords",
    "rm-rf": "it deletes files for good",
    "git-config": "it changes git settings that run programs",
    "pipe-to-shell": "it runs a downloaded script at once",
    "write-outside": "it writes outside the project",
    "sql-drop": "it deletes database data",
    "loopback-write": "it sends data to a program on this computer",
    "git-destroy": "it throws away git work",
    "disk": "it uses a disk tool",
    "witness": "it touches Witness's own key or settings",
    "git-force-push": "it overwrites history on the server",
    "autostart": "it writes a file that starts commands by itself",
    "defense": "it switches off a protection of your computer",
    "agent-config": "it changes your agent's own settings",
}


def mark_said(m, shown=""):
    """r0299: the internal mark of a danger ("<category>:<detail>") -> the words of the line "Why Witness asks": the category in words, then
    the detail. None when nothing is left to say that the title and the text do not: no detail, or the text of the call shows it (the title
    already says the category in words), or a "(strict data)" tag (the title names it in words). Never the category's internal name: an
    unknown category says only its detail."""
    m = str(m or "")
    if not m or m.startswith("(strict "):
        return None
    cat, sep, det = m.partition(":")
    if not sep or not re.fullmatch(r"[a-z][a-z-]{1,20}", cat):
        return None              # not a mark of the parser: nothing of it is said (it could be an internal name)
    det = det.strip()
    det = det[len(HARNESS_MARK_):].strip() if det.startswith(HARNESS_MARK_) else det
    if cat == "agent-config":
        key = "git-config" if (det.startswith("git config") or re.search(r"(^|/)\.git/(hooks|config)|(^|/)\.gitconfig$", det)) else cat
    elif cat == AUTOSTART_MARK[:-1]:
        key = cat
    else:
        key = danger_category(m)[0] or cat      # net-out / exit -> install, push, fetch or exit
    det = _clean(det, 300) if det and det not in str(shown or "") else ""
    if not det:
        return None              # the title already says the category in words, the text shows the rest: nothing more to say
    words = MARK_WORDS.get(key)
    return det if words is None else words + " — " + det


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


# r0281: the files a single curl / wget command uploads (the server's own parse of the call's text, never the agent's words about it)
_CURL_DATA = ("-d", "--data", "--data-binary", "--data-ascii", "--json", "--data-urlencode")
_CURL_FORM = ("-F", "--form")
_CURL_UP = ("-T", "--upload-file")
_URL = re.compile(r"^(?:https?|ftp)://(?:[^/@\s]*@)?([A-Za-z0-9.\-]+|\[[0-9A-Fa-f:.]+\])(?::\d+)?(?:[/?#]|$)", re.I)
_SECRET_FILE = re.compile(r"(^|/)\.(ssh|aws|gnupg)(/|$)|(^|/)\.env(\.|$)|id_rsa|id_ed25519|credentials|\.pem$|\.key$|(^|/)\.netrc$|(^|/)\.npmrc$|(^|/)\.pypirc$")


def upload_of(text):
    """`curl -s https://h/x -d @notes.txt` -> (["notes.txt"], "h"); None when the text is not ONE curl / wget command that sends files
    to one host (a line of several commands, an unreadable quote, no file, no URL or several hosts)."""
    import shlex
    t = str(text or "")
    if not t or "\n" in t or len(t) > 2000:
        return None
    try:
        lx = shlex.shlex(t, posix=True, punctuation_chars=True)
        lx.whitespace_split = True
        toks = list(lx)
    except ValueError:
        return None
    if not toks or any(k and set(k) <= set(";&|<>()") for k in toks):
        return None
    prog = toks[0].rsplit("/", 1)[-1]
    if prog not in ("curl", "wget"):
        return None
    files, hosts, urls = [], [], []
    i = 1
    while i < len(toks):
        k = toks[i]
        opt, val = k, None
        if k.startswith("--") and "=" in k:
            opt, val = k.split("=", 1)
        elif prog == "curl" and len(k) > 2 and k[0] == "-" and k[1] != "-" and k[:2] in ("-d", "-F", "-T"):
            opt, val = k[:2], k[2:]
        takes = opt in _CURL_DATA + _CURL_FORM + _CURL_UP + ("--post-file", "--body-file")
        if takes and val is None:
            i += 1
            val = toks[i] if i < len(toks) else ""
        if takes and prog == "curl" and opt in _CURL_DATA:
            if val.startswith("@"):
                files.append(val[1:])
            elif opt == "--data-urlencode" and "@" in val and "=" not in val.split("@", 1)[0]:
                files.append(val.split("@", 1)[1])
        elif takes and prog == "curl" and opt in _CURL_FORM:
            v_ = val.split("=", 1)[1] if "=" in val else ""
            if v_[:1] in ("@", "<"):
                files.append(v_[1:].split(";", 1)[0])
        elif takes and prog == "curl" and opt in _CURL_UP:
            files.append(val)
        elif takes and prog == "wget" and opt in ("--post-file", "--body-file"):
            files.append(val)
        else:
            m = _URL.match(k)
            if m:
                hosts.append(m.group(1).lower())
                urls.append(k)
        i += 1
    files = [f for f in dict.fromkeys(files) if f and f != "-"]
    hosts = list(dict.fromkeys(hosts))
    if not files or len(hosts) != 1:
        return None
    return files, hosts[0], urls[0]


def _cwd_of(x):
    """r0281b: the folder the call runs in (the hook's `_witness.cwd` in the stored arguments, else the project of the line), or None."""
    try:
        m = re.search(r'"cwd": ("(?:[^"\\]|\\.)*")', str(x["args_preview"] if "args_preview" in x.keys() and x["args_preview"] else ""))
        c = json.loads(m.group(1)) if m else None
        if not (isinstance(c, str) and c.startswith("/")):
            cm = json.loads(x["cmd_meta"]) if "cmd_meta" in x.keys() and x["cmd_meta"] else {}
            c = cm.get("project") if isinstance(cm, dict) else None
        return c if isinstance(c, str) and c.startswith("/") and "\x00" not in c else None
    except (TypeError, ValueError, KeyError, IndexError, AttributeError):
        return None


def _project_of(x):
    """r0283: the project folder of the call (the hook's `_witness.project`, else the line's `cmd_meta.project`), or None."""
    try:
        m = re.search(r'"project": ("(?:[^"\\]|\\.)*")', str(x["args_preview"] if "args_preview" in x.keys() and x["args_preview"] else ""))
        c = json.loads(m.group(1)) if m else None
        if not (isinstance(c, str) and c.startswith("/")):
            cm = json.loads(x["cmd_meta"]) if "cmd_meta" in x.keys() and x["cmd_meta"] else {}
            c = cm.get("project") if isinstance(cm, dict) else None
        return c if isinstance(c, str) and c.startswith("/") and len(c) > 1 and "\x00" not in c else None
    except (TypeError, ValueError, KeyError, IndexError, AttributeError):
        return None


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
                # r0281 (B4): a request to a host is not "can delete or overwrite files": the network words for both codes
                long_harm = LONG_HARM["ESCALATE_HTTP"]
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
        as_risk = None
        if kind == "command" and reason == "ESCALATE_COMMAND_DANGER" and str(t).startswith(AUTOSTART_MARK):
            # r0298: a file that starts programs by itself, in a folder Witness cannot tell (bashparse.AUTOSTART). exec_json "as" {"pin"}:
            # True = the vocabulary the mandate pinned holds the sentences (mr-vocab-4 or later); anything else (a mandate signed before,
            # no mark) = the nearest sentence of the older vocabulary ("cannot fully check"), so a signed view stays rebuildable (VALID)
            as_ = _exec_member(x, "as")
            if isinstance(as_, dict) and as_.get("pin") is True:
                what, harm, as_risk = SCREEN["autostart_what"], SCREEN["autostart_harm"], "critical"
            else:
                what, harm, as_risk = DANGER_WORDS["opaque"][0], DANGER_WORDS["opaque"][1], DANGER_WORDS["opaque"][3]
            if str(t).startswith(AUTOSTART_COPY_MARK):
                f_ = re.split(r": which files land there is not known$| brings ", str(t)[len(AUTOSTART_COPY_MARK):], maxsplit=1)[0]
                long_harm = AUTOSTART_COPY_LONG.format(t=_clean(f_, 160)) + ((" " + sl) if so else "")
            else:
                long_harm = (AUTOSTART_LONG if "in an unknown directory" in str(t) else LATER_LONG) + ((" " + sl) if so else "")
            dmark_ = _clean(t, 300)
        if kind == "command" and reason == "ESCALATE_COMMAND_DANGER" and str(t).startswith(DEFENSE_MARK):
            # r0305: an OS protection switched off (bashparse.DEFENSE). exec_json "df" {"pin"}: True = mr-vocab-5 or later pinned (or none);
            # anything else = the older vocabulary's own "a dangerous command" sentence (signed = shown, the pack stays VALID)
            df_ = _exec_member(x, "df")
            if isinstance(df_, dict) and df_.get("pin") is True:
                what, harm, as_risk = SCREEN["defense_what"], SCREEN["defense_harm"], "critical"
            else:
                as_risk = "high"                    # what / harm stay the generic ESCALATE_COMMAND_DANGER sentences of every vocabulary
            long_harm = DEFENSE_LONG + ((" " + sl) if so else "")
            dmark_ = _clean(t, 300)
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
        up_ = None
        sec_cmd_ = kind == "command" and str(t).startswith("secrets:") and reason == "ESCALATE_COMMAND_DANGER"   # `curl -d @.env host`: the secret mark
        if ent is not None and (kind == "host" or secret_read or sec_cmd_) and sent_ is None:
            up_ = upload_of(x["text_preview"] if "text_preview" in x.keys() else "")
            if up_ is not None and kind == "host" and t and t.lower() != up_[1]:
                up_ = None                          # the row's host is not the host of the text: say nothing more than before
        if up_ is not None:
            # r0281 (blind evaluation #1 / #2 / B5 / B4): the call SENDS these files to this host; the harm says what leaves, nothing about
            # deleting (B4); "Why it matters" is not repeated under Details (#10): the short line is already exact
            fs_, h_ = [_clean(f, 160) for f in up_[0]], _clean(up_[1], 120)
            secret_f = secret_read or any(_SECRET_FILE.search(f) for f in up_[0])
            if len(fs_) == 1:
                p_ = SCREEN["send_file_what"].split("{t}")
                what = p_[0] + fs_[0] + p_[1] + h_ + p_[2]
            else:
                what = SCREEN["send_files_what"].format(t=h_)
            harm = SCREEN["send_secret_file_harm"] if secret_f else SCREEN["send_file_harm" if len(fs_) == 1 else "send_files_harm"]
            long_harm, persist = "", False
            secret_f = secret_f or sec_cmd_
            if secret_f:
                harm = SCREEN["send_secret_file_harm"]
            kind, t = "host", h_
            dmark_ = ""                             # the secret mark ("secrets:<path>") said the same as the title, in the classifier's words
        heads = _heads(x)
        risk = RISK_BY_CODE.get(str(reason or ""), "high") if sent_ is None else sent_[3]
        if dmark_ and sent_ is None and dcat_ is not None:
            risk = DANGER_WORDS[dcat_][3]
        if as_risk is not None and sent_ is None:
            risk = as_risk                          # r0298: autostart (critical; under an older vocabulary the words and level of "opaque")
        if so and risk_max([risk, "high"]) != risk:
            risk = "high"                           # 10.11 (r0260): code could publish in the person's name
        if ac_risk is not None and not so:
            risk = ac_risk                          # 12.11: the agent's harness in words (above): a read of git settings is low
        if secret_read and risk_max([risk, DANGER_WORDS["secrets"][3]]) != risk:
            risk = DANGER_WORDS["secrets"][3]          # r0280: a secret read is at least what the vocabulary says of "secrets" (high)
        if up_ is not None and harm == SCREEN["send_secret_file_harm"]:
            risk = "critical"                       # r0281: keys or passwords leave the computer
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
        dl_ = _exec_member(x, "dl")
        dl_line_ = None
        if isinstance(dl_, dict) and isinstance(dl_.get("host"), str) and ent is not None and kind != "host" and not persist \
                and not secret_read and up_ is None and sent_ is None:
            # r0294: the line runs code from the network (provenance.net_code): the one short line of harm says it, in place of the general
            # "It runs a program" (not added to it); the host and the downloaded path go under Details
            from app import provenance as _pv
            h_ = _pv.net_code_words(dl_, x["created_at"] if "created_at" in x.keys() else None, dl_.get("pin") is not False)
            if h_:
                harm = h_
                dl_line_ = _pv.net_code_detail(dl_)
                if risk_max([risk, "high"]) != risk:
                    risk = "high"
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
        why_ = mark_said(t if dmark_ else ac_mark, x["text_preview"] if "text_preview" in x.keys() else "") if (dmark_ or ac_mark) else None
        if why_:
            d.append("Why Witness asks: %s" % why_)     # r0299: the mark in words (MARK_WORDS), never its internal name
        if dl_line_:
            d.append(dl_line_)
        d.append("Tool: %s" % _clean(str(x["tool"] or "").split(".")[0], 80))     # r0264: "Bash", not the part code "Bash.danger"
        tp = x["text_preview"] if "text_preview" in x.keys() else ""
        if kind == "host" and up_ is not None:
            # r0281b (second blind evaluation #6, #7): what the title does not say -- the full address and the full path of each file sent
            # r0283 (third blind evaluation #18 / Н-1, #19 / Н-2): nothing is sent before a decision ("Will send", never "File sent"); the
            # file as the person knows it -- its project folder and the path inside it ("proekt/notes.txt") -- and, when that is not already
            # the absolute path, the absolute path on its own line "Full path:" (the page shows it under Technical details: signed = shown)
            import posixpath as _pp
            cwd_, prj_ = _cwd_of(x), _project_of(x)
            d.append("Goes to: %s" % _clean(up_[2], 300))
            fulls_ = []
            for f_ in up_[0][:8]:
                full_ = f_ if f_.startswith("/") else (_pp.normpath(_pp.join(cwd_, f_)) if cwd_ and not f_.startswith("~") else f_)
                known_ = full_
                if prj_ and full_.startswith(prj_.rstrip("/") + "/"):
                    known_ = _pp.basename(prj_.rstrip("/")) + "/" + full_[len(prj_.rstrip("/")) + 1:]
                d.append("Will send: %s" % _clean(known_, 300))
                if known_ != full_ and full_.startswith("/"):
                    fulls_.append(full_)
        elif kind == "host":
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
        elif kind == "host" and up_ is not None:
            # r0283 (#20, #21): "nothing on this computer" beside "Undo: not possible" calmed down a leak; where the copy ends up, and that
            # Witness cannot say who sees it there
            d.append("What changes: nothing on this computer; a copy will be on %s, and who sees it is up to that site." % _clean(up_[1], 120))
        elif kind == "host":
            d.append("What changes: data is sent to that host.")      # r0281 (B3): "cannot be taken back" is said once, by the Undo line
        else:
            d.append("What changes: whatever the command does to your files and system.")
        if kind == "path" and not reads_:
            d.append("Undo: a file outside the project gets a shadow copy first; restore it with: deus-witness-hook --undo PATH")
        elif kind == "host" and up_ is not None:
            d.append("Undo: not possible.")                 # r0281b: the harm line already says it leaves for good
        elif kind == "host":
            d.append("Undo: not possible once sent.")
        else:
            d.append("Undo: not automatic. Files outside the project written by a command get a shadow copy (deus-witness-hook --undo PATH).")
        if up_ is not None and kind == "host":
            for f_ in fulls_:
                d.append("Full path: %s" % _clean(f_, 300))      # r0283: the page puts it under Technical details
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
