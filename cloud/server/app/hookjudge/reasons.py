"""Reason code -> text a person understands (hook messages; the same table is in docs/internal/coverage.md, a test keeps them equal).

`kind` is the decision the code comes with: deny (the call is blocked, no question) or ask (the owner is asked in Witness).
A wire tool of the hook (`Bash.danger`, `Bash.write`, `Bash.net`, `Read.secret`, `Grep.secret`) can refine an `ask`: the core names the
class of the call, the person needs the real thing. Since PROPOSAL-06 (preset 0.3) a shell command is its own class `command`, with
its own codes ESCALATE_COMMAND / ESCALATE_COMMAND_DANGER; an agent created before keeps its -05 tool map, where a dangerous command
is judged like publishing (ESCALATE_PUBLISH), and the refinement below still names the real thing for it."""
from __future__ import annotations

# code: (kind, text)
REASONS = {
    # ask (core verdict defer)
    "ESCALATE_PUBLISH": ("ask", "this action leaves the machine or is hard to undo and the mandate lists no channel for it: the owner decides"),
    "ESCALATE_DELETE": ("ask", "a deletion the mandate does not cover: the owner decides"),
    "ESCALATE_MONEY": ("ask", "a payment the mandate does not settle by itself (above the limit asked, or no price): the owner decides"),
    "ESCALATE_DATA": ("ask", "the call may carry protected data: the owner decides"),
    "ESCALATE_FILE": ("ask", "a file action the mandate does not cover: the owner decides"),
    "ESCALATE_COUNT": ("ask", "too many actions of this kind in a short time: the owner decides"),
    "ESCALATE_COMMAND": ("ask", "a shell command that is not on the owner's list of commands that run without a question: the owner decides, in Witness (not in this window)"),
    "ESCALATE_COMMAND_DANGER": ("ask", "a dangerous shell command (recursive delete, disk tools, force-push, a download piped into a shell, credentials ...): no list covers it, the owner decides each time, in Witness (not in this window)"),
    "ESCALATE_EXEC_CHANGED": ("ask", "a file this command executes (conftest.py, package.json, Makefile, build.rs, .git/hooks ...) changed since the owner last confirmed it: the list and project permissions do not cover it, the owner decides once, in Witness (the page names the file)"),
    "ESCALATE_HTTP": ("ask", "an HTTP request of the sandbox that is not on the owner's list of requests that run without a question (or that cannot be matched safely: dot segments, encoded slashes, a non-ASCII host ...): the owner decides, in Witness"),
    "ESCALATE_WRITTEN_RUN": ("ask", "this command runs a file this agent wrote earlier, and the witness could not read what was written (a shell write, a copy, a download) or what it read talks to the network or builds the code it runs: the owner sees the file before it runs"),
    "ESCALATE_SECRET_SEEN": ("ask", "this agent read a secret (a credential file, or a token in its own call) in the last minutes: its network calls, and commands that run a file it wrote (a script, a test file, a module), are held for the owner, even where the mandate allows it"),
    "ESCALATE_SECRET_COPY": ("ask", "this reads a file this agent made earlier from a credential (a copy of ~/.ssh, ~/.aws ... it wrote into the project): held for the owner, even where the mandate allows reading the file; a copy of a private key or a token store is refused like the original"),
    "ESCALATE_NET_UNSEEN": ("ask", "a network program whose destination the witness cannot read from the line (a config file, a list of URLs, a variable): held for the owner, even where the mandate lists the program"),
    "ESCALATE_TRIAL_CLAIM": ("ask", "a trial account before its first touch: nothing runs that needs the owner until the person who ran `deus-witness try` confirms with a passkey on the page that opened (Touch ID / Windows Hello / phone), not in this window"),
    "ESCALATE_EGRESS_UNSPECIFIED": ("ask", "this call reaches a host outside this machine and the mandate names no destinations at all (no message class): held for the owner; sign a mandate that lists the domains the agent may talk to"),
    "ESCALATE_USER_CONTENT_HOST": ("ask", "a request with data in it (a query string or an upload) to a host where anyone can publish or read what is sent (github.com, gists, pastebins, webhooks), or any request to a request catcher or tunnel: held for the owner, even where the mandate allows the domain"),
    # deny
    "TRIAL_NOT_CLAIMED": ("deny", "this trial account has no passkey yet (nothing ran): open the trial page from `/deus-witness:try` or `uvx --from deus-witness deus-witness try` (or the link it showed you), touch the passkey, then ask again"),     # 0.2.48: client 0.2.34
    "AGENT_FROZEN": ("deny", "this agent is frozen in Witness (by the owner, or automatically after a flood of unanswered approval requests). After an automatic freeze what the mandate allows by itself still runs, but nothing that needs the owner's approval; the owner unfreezes it on the Agents page of Witness (passkey) after answering the waiting requests"),
    "APPROVAL_RATE": ("deny", "too many questions at once; answer the waiting ones first: this agent already has as many unanswered requests waiting for the owner as the limit allows (they may come from an earlier run), so no new question is queued; do not retry now, a place frees when the owner answers or the oldest request times out"),
    "APPROVER_NONE": ("deny", "this agent's actions are confirmed by other people of the team (delegation), and nobody who may confirm this one is available: it is blocked, not let through"),
    "RESOURCE": ("deny", "the target is outside what the owner's mandate allows (writes: only inside the project)"),
    "IRREVERSIBLE_DELETE": ("deny", "the mandate does not allow overwriting or deleting files that cannot be restored"),
    "RECIPIENT": ("deny", "this domain or recipient is not in the owner's mandate"),
    "TOOL_UNMAPPED": ("deny", "this tool is not in the agent's tool map in Witness; the owner can add it"),
    "TOOL_ARGS_UNMAPPED": ("deny", "the call has an argument the tool map does not describe; the owner can map it"),
    "NO_MANDATE": ("deny", "the owner has not signed a mandate for this agent yet"),
    "DATA_NOT_PERMITTED": ("deny", "the call carries protected data (a secret, or a value the owner listed) and can send it off this computer. Text that stays here (a commit message, a file of the project) is not refused: run the part that sends (push, upload, request) as its own command"),
    "DATA_FORBIDDEN": ("deny", "the call carries a secret, a value the owner's mandate names, or personal data (an e-mail address, a card number ...) on a line that can send it off this computer. Text that stays here (a commit message, a file of the project) is not refused: run the local part alone, then the part that sends (push, upload, request) as its own command"),
    # 0.2.73 (N15, polygon series 9): the block is per (tool, class, target), not per call: the text no longer says the owner refused THIS
    # call (judge.py adds which call it was)
    "REFUSED": ("deny", "the owner refused a call of this kind (the same tool and target) recently: such calls are refused without a new question until the owner's window (15 minutes by default) has passed"),
    "APPROVAL_REFUSED": ("deny", "the owner refused this action in Witness"),
    "TOOLMAP_CHANGED": ("deny", "the tool map changed after the mandate was signed; the owner must sign again"),
    "CLASS_DENIED": ("deny", "the owner's mandate forbids this kind of action"),
    "CLASS_UNKNOWN": ("deny", "the witness does not know this kind of action"),
    "BUDGET": ("deny", "the 24-hour budget of the mandate is used up"),
    "PER_ACTION_LIMIT": ("deny", "the amount is above the limit of one action in the mandate"),
    "CEILING": ("deny", "the amount is above the ceiling of the mandate"),
    "PRICE": ("deny", "the price does not fit the mandate"),
    "COUNT_LIMIT": ("deny", "too many actions of this kind: the limit of the mandate is reached"),
    "EXPIRED": ("deny", "the mandate has expired; the owner must sign a new one"),
    "RECEIPT_EXPIRED": ("deny", "the owner's approval expired before the call ran"),
    # N10 0.2.71 (series 8c): the model stopped after FILE_CHANGED; the owner's page already says "you will be asked again"
    "FILE_CHANGED": ("deny", "a file shown on the owner's approval page was written after the owner saw it, so nothing ran. Repeat the same "
                     "call now: the owner is asked again, with the new text"),
    "AGENT_MISMATCH": ("deny", "the mandate was signed for another agent"),
    "MANDATE_SIG": ("deny", "the mandate's signature is not valid"),
    "BAD_AMOUNT": ("deny", "the amount in the call is not valid"),
    "UNATTENDED_MEETING": ("deny", "this needs the owner present"),
    # 06.11: the Constitution v1, immutable articles (app/constitution.py): refused by the witness itself, no question, nobody is notified
    "FORBIDDEN_SECRET_READ": ("deny", "refused by the project's rules (article N1, never asked): reading a private key, a token store, the keychain or browser cookies is identity theft whatever the reason. Instead: tell the user which single value the task needs and let them put it into the project's own configuration (or use a key broker); for a public key read the .pub file"),
    "FORBIDDEN_GIT_HOOKS": ("deny", "refused by the project's rules (article N3, never asked): the agent does not change git hooks (.git/hooks) or core.hooksPath, because git would run them later outside every check. Instead: put the check into a script or a Makefile / package.json target of the project and run it explicitly"),
    "FORBIDDEN_WITNESS_OFF": ("deny", "refused by the project's rules (article N3, never asked): this removes, stops or replaces Deus Witness itself (uninstalls its package, stops its program or process, deletes, moves or overwrites a file of its installation), after which nothing the agent does is checked. Instead: tell the user that Witness blocks it; if they really want Witness off, they remove it themselves in their own terminal"),
    "FORBIDDEN_AUTOSTART": ("deny", "refused by the project's rules (articles N3/N4, never asked): this changes a place that runs at the next login, shell or session (shell rc files, LaunchAgents, cron, services) or the agent's own settings and the witness. Instead: write the script into the project and tell the user the one command to install it themselves"),
    "FORBIDDEN_WIPE": ("deny", "refused by the project's rules (article N5, never asked): a recursive delete or chmod of the root, a system folder, the home folder or a folder that contains the project cannot be undone. Instead: delete the exact path inside the project you mean"),
    "FORBIDDEN_REMOTE_SHELL": ("deny", "refused by the project's rules (article N6, never asked): a script downloaded and piped straight into a shell, a reverse shell or a listening port hands the machine to someone else. Instead: download the script into the project as a file so it can be read, then run that file"),
    "FORBIDDEN_HIDDEN_CHARS": ("deny", "refused by the project's rules (article N7, never asked): the command contains invisible characters (bidirectional controls or zero-width characters inside a word) that make what a person reads differ from what runs. Instead: retype the command in plain characters"),
    "FORBIDDEN_FORCE_PUSH": ("deny", "refused by the project's rules (article N8, never asked): force-push (--force, -f, --force-with-lease, a +refspec, --mirror, --prune) and deleting a branch on the server destroy shared history. Instead: push your work to a NEW branch name (git push origin HEAD:refs/heads/<new-name>) and let the user merge it"),
    "FORBIDDEN_DEFENSE_OFF": ("deny", "refused by the project's rules (article N10, never asked): this switches off a protection of the computer (Gatekeeper or the quarantine mark, System Integrity Protection, privacy permissions, the firewall, SELinux / AppArmor, antivirus, the system logs) or starts another agent with its permission checks off. Instead: tell the user which protection blocks the task and the one command to change it, and let them run it themselves in their own terminal"),     # r0305
    # hook-side (before or around the witness)
    "RESERVED_KEY": ("deny", "the tool input carries the reserved key `_witness`"),
    "EVENT_MALFORMED": ("deny", "Claude Code sent an event the hook cannot read"),
    "EVENT_TOO_LARGE": ("deny", "the tool call is too large to be judged"),
    "WITNESS_NOT_CONFIGURED": ("deny", "the hook has no agent key (set DEUS_WITNESS_KEY)"),
    "WITNESS_UNAVAILABLE": ("deny", "the witness cannot be reached; the call does not run without it"),
    "WITNESS_TIMEOUT": ("deny", "the witness did not answer in time; the call does not run without it"),
    "WITNESS_BUSY": ("deny", "the witness is busy at this moment (too many calls of this agent at once, or the server is full); nothing ran, the witness itself is fine: retry the same call in a few seconds"),     # r0285
    "WITNESS_QUOTA": ("deny", "the daily limit of this account at the witness is used up (the text says when it frees up); nothing ran: reading files of the project still works, tell the user"),     # r0285
    "WITNESS_KEY_CHANGED": ("deny", "the witness key is not the one pinned on this machine"),
    "REQUEST_MISMATCH": ("deny", "the receipt is for a different call than the one being run"),
    "HOOK_ERROR": ("deny", "the hook failed; the call does not run (fail-closed)"),
    "TRIAL_REPLACED": ("deny", "a newer `try` (/deus-witness:try or uvx --from deus-witness deus-witness try) replaced the trial account this call was waiting in (that account is gone, nothing ran): retry the same call, it goes to the new trial account"),     # 0.2.39 (client 0.2.29)
    "AGENT_CONFIG_UNAPPROVED": ("deny", "the call touches the agent's own harness (.claude, .mcp.json, git hooks, the Deus Witness key files or client); it runs only with a receipt the owner approved in Witness, never on the mandate alone"),     # 0.2.44 text (client 0.2.32, K1); 0.2.61: "or client" (client 0.2.40, HN rehearsal 6)
    "WITNESS_URL_UNPINNED": ("deny", "the witness URL is not the one this machine trusts and a new witness is not pinned silently: run `deus-witness try --url URL` or `deus-witness-hook --trust URL` in your own terminal"),     # 0.2.44 text (client 0.2.32, K1)
    "WITNESS_URL_MISMATCH": ("deny", "DEUS_WITNESS_URL differs from the witness the agent key was set up for (agent-key.json); the key is not sent: unset DEUS_WITNESS_URL or run `deus-witness try --url URL` in your own terminal"),     # 0.2.44 text (client 0.2.32, K1)
}

# what a wire tool of the hook means for a person: only for the codes the core really gives for that class of call (under a -05 tool map a dangerous
# command is judged like a publication; a shell write/delete like a deletion). ESCALATE_COMMAND* need no refinement: their own text is the real thing. Any other ask code (ESCALATE_COUNT, ESCALATE_DATA ...) is explained by its own table entry (R5-06).
TOOL_CODES = {"Bash.danger": {"ESCALATE_PUBLISH"}, "Write.danger": {"ESCALATE_PUBLISH", "ESCALATE_COMMAND_DANGER"}, "Bash.net": {"ESCALATE_PUBLISH"}, "Read.secret": {"ESCALATE_PUBLISH", "ESCALATE_FILE", "ESCALATE_DATA"},
              "Bash.write": {"ESCALATE_DELETE", "ESCALATE_FILE"}, "Grep.secret": {"ESCALATE_PUBLISH", "ESCALATE_FILE", "ESCALATE_DATA"},
              "NotebookRead.secret": {"ESCALATE_PUBLISH", "ESCALATE_FILE", "ESCALATE_DATA"}}
# what a wire tool of the hook means for a person (only for `ask` codes; the code itself stays visible)
TOOL_ASK = {
    "Bash.danger": "a dangerous shell command (recursive delete, force-push, a download piped into a shell, credentials ...): the owner decides each time, in Witness (not in this window)",
    "Bash.write": "a shell command that writes or deletes files",
    "Bash.net": "a shell command that talks to the network",
    "Read.secret": "reading a credential file",
    "Grep.secret": "searching a credential file (Grep prints the lines it finds)",
    "NotebookRead.secret": "reading a credential file",
    "Write.danger": "a write to git's configuration or hooks (.git/config, .git/hooks, a .git file): git would run the programs named there on a later git command, so the owner decides each time, in Witness (not in this window)",
}


def explain(code: str, tool: str | None = None) -> str:
    """-> text for a person; the table entry, refined by the wire tool for an ask code; '' for an unknown code."""
    kind, text = REASONS.get(code, ("", ""))
    if kind == "ask" and tool in TOOL_ASK and code in TOOL_CODES.get(tool, ()):
        return TOOL_ASK[tool]
    return text


def kind_of(code: str) -> str:
    return REASONS.get(code, ("", ""))[0]
