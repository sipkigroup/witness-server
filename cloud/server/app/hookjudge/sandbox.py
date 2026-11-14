"""V3 (0.2.56, 26.10.2026): is THIS Bash call contained by a strict Claude Code sandbox?  evaluate(fact, heads, home, project).

The fact comes from the hook (mcp/deus_witness/hook/sandbox_fact.py): Claude Code's merged settings layers and this call's
`dangerouslyDisableSandbox`. Law: a test runner runs code the agent may have written (pytest == python3 agent.py); text parsing cannot
bound it, only containment at execution can. "Strict" = the OS keeps the process from reading the user's secrets and from reaching any
host. Every condition below must be KNOWN and true; anything missing, malformed or unknown -> not strict (fail closed, the owner is asked).

Strict requires:
  platform darwin (Seatbelt) -- or, 13.11 (r0268, client r0268), linux / wsl2 (bubblewrap) with a COMPLETE `linux` fact (linux_why): bwrap
    and socat on PATH, an architecture Claude Code ships its seccomp filter for (x86_64 / arm64: the filter that refuses socket(AF_UNIX),
    i.e. docker.sock, ssh-agent, the D-Bus keyring -- L3 13.11 in a sandboxed command: "Seccomp: 2", socket(AF_UNIX) -> EPERM), and on
    WSL2 Windows interop OFF (a .exe started from Linux runs outside the sandbox) and every Windows home /mnt shows with its key places in
    denyRead. A fact without `linux` (a client before r0268, "wsl" of old clients, wsl1) is not strict, as before;
  every readable layer parsed (no "bad", no unread MDM plist);
  sandbox.enabled true, sandbox.failIfUnavailable true (no silent unsandboxed fallback), filesystem.disabled not true,
  no ignoreViolations, no weakening key (enableWeakerNestedSandbox, enableWeakerNetworkIsolation, allowAppleEvents);
  this call without dangerouslyDisableSandbox AND sandbox.allowUnsandboxedCommands false (0.2.56: the retry outside the sandbox is off);
  sandbox.excludedCommands EMPTY (0.2.56; excluded commands run with no sandbox at all);
  network: allowedDomains (incl. WebFetch(domain:) allow rules) EMPTY -- or, 10.11 (r0260, decision Р-1011-сеть-в-строгой), NARROW host
    names (domain_narrow) that the user / managed layers list themselves (domains_user) while the hook's environment carries no publishing
    token (env_tokens == []); no allowUnixSockets, allowAllUnixSockets / allowLocalBinding not true, no allowMachLookup;
  network LOCKED (0.2.57, L2 OTCHET-V3-L2 a1/a2): sandbox.network.strictAllowlist true in the user or managed layer, or
    allowManagedDomainsOnly in managed settings. Without a lock bypassPermissions lets any host through ("Allowed without a prompt"), auto
    lets the classifier approve hosts the command lists itself, manual/acceptEdits prompt the person; with a lock the proxy "refuses the
    connection in every permission mode" and auto's per-command lists are refused;
  the event's permission_mode one of PERMISSION_MODES_CHECKED (0.2.57; missing / unknown / not checked at L2 -> not strict);
  CLAUDE_CODE_SUBPROCESS_ENV_SCRUB on in the HOOK's own environment (0.2.57: a settings `env` block does not switch it on, L2 b2) --
    or, 12.11 (r0263, client 0.2.60, r0263), env_hidden: the agent key is not in the environment of sandboxed commands (absent, or listed in
    sandbox.credentials.envVars as deny / mask, which Claude Code unsets before each sandboxed command: L2+ 12.11). The scrub is no longer
    needed and no longer asked for: it hid OPENAI_API_KEY & co. from every command (the person's tests broke) and forced the permission
    mode to `default` (L3 12.11, interactive: "manual mode on" with defaultMode acceptEdits). Other secrets in the environment stay
    visible to code and cannot leave: no host but the narrow list, and env_tokens (any credential a listed host could take) must be [];
  denyRead covers every path of SECRETS (or a parent such as ~/) and no allowRead re-opens it with an entry at least as specific
    (assumption: the more specific entry wins -- L3 check pending), and the same for the project's .env files the hook listed;
  0.2.88 (client 0.2.56): no `doubt` (the hook could not collect the fact unambiguously: --settings / --setting-sources / --add-dir,
    ps unreadable, allowWrite / additionalDirectories) and a FRESH session (hookjudge/freshness.py: the settings did not change since the
    session's first view; judged per session by the judge, not here).
"""
from __future__ import annotations

import fnmatch
import posixpath
import re

SECRETS = (".ssh", ".aws", ".config/gh", ".netrc", ".docker", ".kube", ".gnupg", ".npmrc", ".pypirc", ".git-credentials",
           ".config/gcloud", ".azure", ".config/deus-witness", ".claude.json", ".claude/.credentials.json")
# 11.11 (r0260, L2 Deus 10.11: denyRead ["~/Library/Keychains"] -> `security find-generic-password` from the strict sandbox finds nothing,
# KEYCHAIN_BLOCKED rc=44; without it the item was read): the places, readable as FILES, where code would find a credential to act IN THE
# PERSON'S NAME on a forge / a registry. Not required for the strict fact (with no host listed nothing leaves the machine); required for
# cred_closed (below), which lets a write host of allowedDomains stay strict for code. Each entry, and why:
CRED_SOURCES = (
    "Library/Keychains",                # login keychain: git credential-osxkeychain, gh (go-keyring -> security), twine / uv keyring,
    #                                     docker-credential-osxkeychain, Chrome's / Brave's / Edge's "Safe Storage" cookie key (L2 10.11)
    "Library/Cookies",                  # Safari / WebKit cookies (Cookies.binarycookies: plain values, a github.com / pypi.org session)
    "Library/HTTPStorages",             # per-app NSURLSession cookie stores (httpstorages.sqlite)
    "Library/Safari",                   # Safari's own data (sessions, LocalStorage)
    "Library/Containers/com.apple.Safari",                  # sandboxed Safari: Data/Library/Cookies
    "Library/Application Support/Google/Chrome",            # cookies (keychain-encrypted), Login Data, Local Storage
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Microsoft Edge",
    "Library/Application Support/Arc",
    "Library/Application Support/Chromium",
    "Library/Application Support/Vivaldi",
    "Library/Application Support/com.operasoftware.Opera",
    "Library/Application Support/Firefox",                  # cookies.sqlite in PLAIN text; logins.json + key4.db (no primary password)
    "Library/Application Support/Code/User/globalStorage",   # VS Code: extensions' tokens (state.vscdb), GitHub sessions
    "Library/Application Support/Cursor/User/globalStorage",
    ".config/hub",                      # hub's GitHub token
    ".config/glab-cli",                 # glab's GitLab token (XDG)
    "Library/Application Support/glab-cli",                 # glab's GitLab token (macOS default)
    ".config/git/credentials",          # `credential.helper store` with XDG (git reads it besides ~/.git-credentials)
    ".gcm",                             # Git Credential Manager's plaintext store
    ".cargo/credentials",               # crates.io token (old name); read only by cargo publish / login / owner / yank
    ".cargo/credentials.toml",
    ".gem/credentials",                 # rubygems.org API key; read only by gem push / owner / yank
    "Library/Application Support/pypoetry/auth.toml",       # poetry's plaintext fallback when no keyring
)
# 13.11 (r0268): the same places on Linux / WSL2 (client sandbox_fact.CRED_SOURCES_LINUX, --setup-strict writes them): browsers' profiles
# (Chrome / Chromium without a running keyring keep cookies in plain "peanuts" encryption: a server, WSL), Firefox (plain), the GNOME
# keyring's and KDE wallet's files (the daemons themselves are reached over D-Bus = a Unix socket, which the seccomp filter refuses), pass,
# keyrings.alt's plaintext file, editors' token stores, snap / flatpak copies, and the CLI files of CRED_SOURCES.
CRED_SOURCES_LINUX = (".config/google-chrome", ".config/chromium", ".config/BraveSoftware", ".config/microsoft-edge", ".config/vivaldi",
                      ".config/opera", ".mozilla", "snap/chromium", "snap/firefox", ".var/app", ".local/share/keyrings",
                      ".local/share/kwalletd", ".password-store", ".local/share/python_keyring", ".config/Code/User/globalStorage",
                      ".config/Cursor/User/globalStorage", ".config/hub", ".config/glab-cli", ".config/git/credentials", ".gcm",
                      ".cargo/credentials", ".cargo/credentials.toml", ".gem/credentials", ".config/pypoetry/auth.toml")
# 13.11 (r0268): in each Windows home WSL2 shows (/mnt/c/Users/<name>): AppData (browsers, Credential Manager's files, editors) and the CLI
# key places. drvfs is case-insensitive: compared case-insensitively.
WIN_SECRETS = ("AppData", ".ssh", ".aws", ".azure", ".kube", ".docker", ".config/gh", ".git-credentials", ".netrc", ".npmrc", ".pypirc",
               ".gnupg", ".config/gcloud")
LINUX_PLATFORMS = ("linux", "wsl2")
SECCOMP_ARCH = frozenset({"x86_64", "amd64", "aarch64", "arm64"})
_WIN_HOME = re.compile(r"/mnt/[a-z]/Users/[^/\x00]{1,128}", re.I)


def linux_well_formed(lx) -> bool:
    if not isinstance(lx, dict) or lx.get("kind") not in ("linux", "wsl2", "wsl1"):
        return False
    if not all(isinstance(lx.get(k), bool) for k in ("bwrap", "socat")):
        return False
    if not (isinstance(lx.get("arch"), str) and len(lx["arch"]) <= 32):
        return False
    if "interop" in lx and lx["interop"] is not None and not isinstance(lx["interop"], bool):
        return False
    return "win_homes" not in lx or _strs(lx["win_homes"], 8)


def linux_why(f) -> list:
    """13.11 (r0268): what keeps a linux / wsl2 fact from being strict ([] = the Linux part is complete). Fail closed on anything absent."""
    lx = f.get("linux")
    if not linux_well_formed(lx) or lx["kind"] != f["platform"]:
        return ["platform %s: no complete Linux sandbox fact (bubblewrap, socat, architecture; a client before r0268)" % f["platform"][:32]]
    why = []
    if lx["bwrap"] is not True or lx["socat"] is not True:
        why.append("Linux: bubblewrap or socat not installed (Claude Code's sandbox cannot run)")
    if lx["arch"] not in SECCOMP_ARCH:
        why.append("Linux: architecture %s has no seccomp filter from Claude Code (Unix sockets stay open)" % lx["arch"][:32])
    if f["platform"] == "wsl2":
        if lx.get("interop") is not False:
            why.append("WSL2: Windows interop is on or unknown (a .exe runs outside the sandbox)")
        hs = lx.get("win_homes")
        if not isinstance(hs, list):
            why.append("WSL2: the Windows home folders are not reported")
        else:
            for h in hs:
                if not _WIN_HOME.fullmatch(h):
                    why.append("WSL2: a Windows home folder not of the form /mnt/<drive>/Users/<name>")
                    break
                miss = [x for x in WIN_SECRETS if not _denied(posixpath.join(h, x), f["deny_read"], f["allow_read"], True, True)]
                if miss:
                    why.append("denyRead does not cover %s/%s" % (h[:80], miss[0]))
                    break
    return why


def cred_sources(platform) -> tuple:
    return CRED_SOURCES_LINUX if platform in LINUX_PLATFORMS else CRED_SOURCES


# 11.11 (r0260): write hosts whose credentials are known to live ONLY in SECRETS, CRED_SOURCES, the hook's environment (env_tokens) or the
# files the client reads (cred_files). Another write host (example.com, a company GitLab, huggingface.co, a wildcard): its credential may
# be anywhere -> 87facd5 (every line that runs code is asked).
CRED_HOSTS = frozenset({
    "github.com", "api.github.com", "uploads.github.com", "gist.github.com", "ghcr.io", "npm.pkg.github.com",
    "gitlab.com", "registry.gitlab.com", "bitbucket.org", "api.bitbucket.org",
    "registry.npmjs.org", "registry.yarnpkg.com", "upload.pypi.org", "test.pypi.org", "crates.io", "rubygems.org",
})

# Runners that get allow without a question under a strict sandbox (identifiers as the classifier names them; a variant `[...]` never).
# Why these: they run the project's tests / checks / build, and need no network when the dependencies are installed. Not here:
# installers (npm install, pip install -e ., python -m build: need the network -> fail in the sandbox -> retried unsandboxed -> asked anyway),
# servers (npm start), `cargo run` / `go run` / interpreters (`python3 x.py`): same law, next step after L3.
RUNNERS = {"pytest", "py.test", "tox", "nox", "ruff", "black", "isort", "flake8", "pylint", "mypy", "pyright", "jest", "vitest", "mocha",
           "tsc", "eslint", "prettier", "make",
           "npm test", "npm t", "npm run", "npm run-script", "npm build",
           "pnpm test", "pnpm t", "pnpm run", "pnpm build", "pnpm lint",
           "yarn test", "yarn run", "yarn build", "yarn lint",
           "npx jest", "npx vitest", "npx mocha", "npx tsc", "npx eslint", "npx prettier",
           "cargo test", "cargo build", "cargo check", "cargo clippy", "cargo fmt", "cargo bench", "cargo doc",
           "go test", "go build", "go vet", "go fmt"}
# 0.2.57: permission modes in which L2 (OTCHET-V3-L2, real Seatbelt, Claude Code 2.1.310) saw the strict sandbox hold:
#   default (c1), acceptEdits (a3), bypassPermissions (a2, with strictAllowlist: network refused, dangerouslyDisableSandbox calls stayed in
#   Seatbelt). `--dangerously-skip-permissions` is bypassPermissions (the event reports the same permission_mode), so it is the a2 case.
# 12.11 (r0263): + auto. Claude Code 2.1.322 makes auto mode the DEFAULT permission mode of a new user ("Auto mode is now Claude Code's
#   default permission mode", L3 12.11 interactive), so without it quiet mode did nothing for most new people. L2+ 12.11 (real Claude Code
#   2.1.322 + Seatbelt, auto mode, the quiet-mode settings, scripted model): a host off the list refused (curl 000, sandbox_violations),
#   a listed one reached (pypi.org 200), ~/.ssh "Operation not permitted", a write outside the project refused; a call carrying
#   `allowed_domains` (auto's per-command hosts) refused by Claude Code itself ("allowed_domains cannot widen network access in this
#   session: ... strictAllowlist"); `dangerouslyDisableSandbox: true` still ran in Seatbelt (SANDBOX_RUNTIME=1, same refusals).
# Not accepted (fail closed until an L2 run): plan, dontAsk, any other or missing value.
PERMISSION_MODES_CHECKED = ("default", "acceptEdits", "bypassPermissions", "auto")
PY_RUNNER_MODULES = {"pytest", "unittest", "mypy", "ruff", "black", "isort", "flake8", "pylint", "pyright", "tox", "nox"}


def runner(cid) -> bool:
    """0.2.56: a variant `<id> [...]` is never a runner here, including the RT-0.2.55c forms that run code written INTO the line
    (`npm test --node-opt=--import=data:...`, `make --ev=` / `make -E`, `pylint --init-h=`, `node -e`): they stay a question even under a
    strict sandbox. Reason: the sandbox bounds what the code can READ and where it can SEND, not what it does inside the project (rm -rf of
    the sources, a poisoned build output the owner later runs outside the sandbox). A plain runner executes the project's code, which the
    owner can review; code typed into the option is new code the owner has not seen. Cost for fatigue: none in the 240 set (no such forms)."""
    if not isinstance(cid, str) or "[" in cid or "/" in cid.split(" ")[0]:
        return False
    if cid in RUNNERS:
        return True
    w = cid.split(" ")
    if len(w) == 2 and w[0] == "make":
        return True                                   # `make <target>`: a target of the project's Makefile
    return len(w) == 3 and re.fullmatch(r"python[0-9.]*", w[0]) is not None and w[1] == "-m" and w[2] in PY_RUNNER_MODULES


DIGEST = re.compile(r"[0-9a-f]{64}")
# 0.2.88: the keys of a fact that may change between two calls of one session without the settings changing (this call's flag, the mode
# the person switched to, the project's .env listing, the hook's view of time and of its process tree); every other key is the settings
PER_CALL_KEYS = ("disable_flag", "permission_mode", "env_files", "since_start", "doubt")


def fact_key(f) -> str:
    """0.2.88: SHA-256 of the settings part of a well-formed fact (the witness compares it between the calls of one session)."""
    import hashlib
    import json
    return hashlib.sha256(json.dumps({k: v for k, v in f.items() if k not in PER_CALL_KEYS}, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


def _strs(v, n=256):
    return isinstance(v, list) and len(v) <= n and all(isinstance(x, str) and 0 < len(x) <= 1024 for x in v)


def well_formed(f) -> bool:
    if not isinstance(f, dict) or f.get("v") != 1 or not isinstance(f.get("platform"), str):
        return False
    if not isinstance(f.get("sources"), dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in f["sources"].items()):
        return False
    for k in ("excluded", "deny_read", "allow_read", "domains", "unix_sockets", "mach_lookup", "weaker", "env_files"):
        if not _strs(f.get(k)):
            return False
    for k in ("ignore_violations", "env_scrub", "disable_flag", "managed_domains_only"):
        if not isinstance(f.get(k), bool):
            return False
    if "env_hidden" in f and not isinstance(f["env_hidden"], bool):
        return False                                  # 12.11 (r0263): optional (a client before it: the scrub is required, as before)
    if "domains_user" in f and not _strs(f["domains_user"]):
        return False                                  # 10.11 (r0260): optional, never malformed
    if "env_tokens" in f and not _strs(f["env_tokens"], 64):
        return False                                  # 10.11 (r0260, Р-1011-сеть): optional (a client before it does not send it; a list
        #                                               of allowed domains is then not strict), never malformed
    if "linux" in f and not linux_well_formed(f["linux"]):
        return False                                  # 13.11 (r0268): optional (macOS has none), never malformed
    if "cred_files" in f and not _strs(f["cred_files"], 64):
        return False                                  # 11.11 (r0260): optional (a client before it: credentials not known closed)
    if "allow_git_config" in f and f["allow_git_config"] is not None and not isinstance(f["allow_git_config"], bool):
        return False                                  # 06.11 (law 2): optional (a client before r0260 does not read it; its K1 lock then
        #                                               still asks about every `.git/config` word), but never malformed
    pm = f.get("permission_mode")
    if pm is not None and not (isinstance(pm, str) and 0 < len(pm) <= 32):
        return False
    if "strict_allowlist" not in f or "permission_mode" not in f:
        return False                                  # 0.2.57: a fact without them (the 0.2.56 prototype hook) is no fact
    # 0.2.88 (client 0.2.56): the freshness keys; a fact without them (client <= 0.2.55) is no fact (fail closed)
    if not (isinstance(f.get("settings_digest"), str) and DIGEST.fullmatch(f["settings_digest"])):
        return False
    if not (_strs(f.get("since_start"), 64) and _strs(f.get("doubt"), 64)):
        return False
    return all(f.get(k) is None or isinstance(f.get(k), bool) for k in ("enabled", "fail_if_unavailable", "allow_unsandboxed", "fs_disabled",
                                                                       "all_unix_sockets", "local_binding", "strict_allowlist"))


def _cf(s, ci):
    return s.casefold() if ci else s


def _covers(entry, path, ci=False):
    if not isinstance(entry, str) or not entry.startswith("/"):
        return False
    e = posixpath.normpath(entry)
    if any(c in e for c in "*?["):
        return fnmatch.fnmatchcase(_cf(path, ci), _cf(e, ci)) or fnmatch.fnmatchcase(_cf(path, ci), _cf(e + "/*", ci))
    return _cf(path, ci) == _cf(e, ci) or _cf(path, ci).startswith(_cf(e.rstrip("/") + "/", ci))


def _within(entry, path, ci=False):
    """RT-0.2.58: does allowRead `entry` re-open a file INSIDE the secret directory `path` (while denyRead covers `path` itself)?
    A glob entry is cut back to its last non-glob parent (`~/.ssh/**` -> `~/.ssh`); a glob also re-opens the secret when its literal
    prefix is the secret or a PARENT of it (`~/**` re-opens `~/.ssh`). A plain entry equal to / covering the secret is handled by _covers."""
    if not isinstance(entry, str) or not entry.startswith("/"):
        return False
    e = posixpath.normpath(entry)
    glob = any(c in e for c in "*?[")
    while any(c in posixpath.basename(e) for c in "*?[") and "/" in e:
        e = posixpath.dirname(e)
    if any(c in e for c in "*?["):
        return False
    ep, pp = _cf(e, ci), _cf(posixpath.normpath(path).rstrip("/"), ci)
    if glob:
        return ep == pp or ep.startswith(pp + "/") or pp.startswith(ep + "/")
    return ep.startswith(pp + "/")


def _denied(path, deny, allow, ci=False, deny_ci=False):
    """A secret is protected only if denyRead covers it AND no allowRead re-opens it -- neither by covering the path itself with an entry at
    least as specific (L2 OTCHET-V3-L2: a more specific allowRead wins in Seatbelt), NOR by re-opening a file INSIDE a denied secret
    directory (RT-0.2.58: allowRead `~/.ssh/id_rsa` reads the key though denyRead covers `~/.ssh`). On darwin the compare is
    case-insensitive (APFS default: allowRead `~/.SSH` re-opens `~/.ssh`)."""
    d = [e for e in deny if _covers(e, path, deny_ci)]   # 11.11 (r0260): a DENY entry counts only in the file system's own spelling --
    #                                                   Seatbelt matches the path as the file system returns it (`~/library/keychains` is
    #                                                   not `~/Library/Keychains` for it; L2 check listed); an allowRead in any case still
    #                                                   re-opens (fail closed both ways). r0268: deny_ci for WSL2's drvfs
    #                                                   (/mnt/c is case-insensitive: Windows itself reads ~/APPDATA as ~/AppData)
    if not d:
        return False
    best = max(len(e) for e in d)
    if any(_covers(a, path, ci) and len(a) >= best for a in allow):
        return False
    return not any(_within(a, path, ci) for a in allow)


def cred_closed(f, home):
    """11.11 (r0260): -> (closed: bool, why: [str]). Closed = every CRED_SOURCES and SECRETS path of the home is denied (and not re-opened)
    and the client read the config files that must stay readable and found no credential in them (cred_files == []). A client before
    11.11 sends no cred_files: not closed (fail closed; the line is judged by write_open as in 87facd5)."""
    why = []
    if not isinstance(f, dict) or not isinstance(home, str) or not home.startswith("/") or home == "/":
        return False, ["no fact / home unknown"]
    ci = f.get("platform") == "darwin"
    deny, allow = f.get("deny_read"), f.get("allow_read")
    if not (_strs(deny) and isinstance(allow, list)):
        return False, ["denyRead unknown"]
    miss = [s for s in SECRETS + cred_sources(f.get("platform")) if not _denied(posixpath.join(home, s), deny, allow, ci)]
    if miss:
        why.append("denyRead does not cover ~/" + ", ~/".join(miss[:4]) + (" ..." if len(miss) > 4 else ""))
    if f.get("platform") in LINUX_PLATFORMS:          # r0268: the Linux part (bwrap, seccomp, WSL2 interop and Windows homes) complete
        why += [w for w in linux_why(f) if w not in why]
    cf = f.get("cred_files")
    if cf is None:
        why.append("the client does not report credentials in config files")
    elif not _strs(cf, 64) and cf != []:
        why.append("cred_files malformed")
    elif cf:
        why.append("a credential in " + ", ".join(x[:60] for x in cf[:3]))
    tok = f.get("env_tokens")
    if tok != []:
        why.append("the environment may carry a publishing token")
    return (not why), why


# 10.11 (r0260): an allowedDomains entry the strict fact accepts: a host name with a registrable part (`github.com`, `api.github.com`,
# `*.github.com`), not `*`, not a bare top-level domain (`*.com`), not an IP literal, not a local / private name, no port, no path.
_DOMAIN = re.compile(r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]")
LOCAL_TLDS = {"local", "localhost", "internal", "lan", "home", "arpa", "localdomain", "test", "invalid", "example", "onion", "corp", "intranet"}


def domain_narrow(d) -> bool:
    if not isinstance(d, str) or len(d) > 253 or not _DOMAIN.fullmatch(d.lower()):
        return False
    labels = d.lower().split(".")
    if labels[-1] in LOCAL_TLDS:
        return False
    return len([x for x in labels if x != "*"]) >= 2


def evaluate(f, heads, home, project=None):
    """-> (strict: bool, why: [str])  -- why lists every unmet condition (empty when strict)."""
    if not well_formed(f):
        return False, ["no sandbox fact or a malformed one"]
    why = []
    if f["platform"] in LINUX_PLATFORMS:
        why += linux_why(f)                           # 13.11 (r0268): bubblewrap + seccomp, a complete fact only
    elif f["platform"] != "darwin":
        why.append("platform %s: only macOS Seatbelt and Linux / WSL2 bubblewrap are accepted" % f["platform"][:32])
    bad = sorted(k for k, v in f["sources"].items() if v not in ("ok", "absent"))
    if bad:
        why.append("settings not readable: " + ", ".join(bad)[:200])
    if f["enabled"] is not True:
        why.append("sandbox.enabled is not true")
    if f["fail_if_unavailable"] is not True:
        why.append("sandbox.failIfUnavailable is not true")
    if f["fs_disabled"] is True:
        why.append("sandbox.filesystem.disabled")
    if f["ignore_violations"]:
        why.append("sandbox.ignoreViolations")
    if f["weaker"]:
        why.append("weakening keys: " + ", ".join(f["weaker"]))
    if f["disable_flag"]:
        why.append("this call asks dangerouslyDisableSandbox")
    if f.get("allow_git_config") is not None and f.get("allow_git_config") is not False:
        why.append("sandbox.filesystem.allowGitConfig: the sandbox lets code write .git/config (core.hooksPath, filters)")
    for d in f["doubt"][:4]:                          # 0.2.88: the hook could not collect the fact unambiguously (flags, ps, allowWrite ...)
        why.append("not known: " + d[:160])
    # 0.2.56: the retry outside the sandbox must be OFF (allowUnsandboxedCommands false; Claude Code's default is true). L2 (OTCHET-V3-L2)
    # saw `-p` refuse a dangerouslyDisableSandbox call even after the hook's allow, but bypassPermissions / auto modes were not checked:
    # with the retry disabled "Claude Code ignores the dangerouslyDisableSandbox parameter" whatever the mode.
    if f["allow_unsandboxed"] is not False:
        why.append("sandbox.allowUnsandboxedCommands is not false")
    # 0.2.56: excludedCommands must be EMPTY, not merely "not naming a program of this line": an excluded entry runs "outside the sandbox,
    # which means no filesystem restrictions and no network proxy", and the hook's notion of a program can differ from Claude Code's
    # matcher (prefixes, wrappers, `env X=1 cmd`). Fail closed on any entry.
    if f["excluded"]:
        why.append("sandbox.excludedCommands is not empty (%s)" % ", ".join(e[:40] for e in f["excluded"][:3]))
    if f["domains"]:
        # 10.11 (r0260, decision Р-1011-сеть-в-строгой): a NARROW list keeps the fact strict. The kernel refuses every host outside it
        # (strictAllowlist, checked below); a host in it is one the person agreed to in the settings. Fail closed on: a wide entry (`*`,
        # a bare top-level domain, an IP literal, a local name: a way to the machine's own services), and a list while the hook's
        # environment carries a publishing token or the client does not say (env_tokens): code in the sandbox (a test, `npm run release`)
        # could then publish to a listed registry with it, and nothing on the line would show it.
        wide = [x for x in f["domains"] if not domain_narrow(x)]
        if wide:
            why.append("network: allowedDomains has a wide entry (%s)" % ", ".join(x[:40] for x in wide[:3]))
        du = f.get("domains_user")
        if not isinstance(du, list) or not set(f["domains"]) <= set(du):
            why.append("network: allowedDomains names a host the person did not list (a project / local settings layer, or a client "
                       "that does not say)")      # a cloned repository's .claude/settings.json is not the person's consent
        tok = f.get("env_tokens")
        if tok != []:
            why.append("network: allowedDomains listed while the environment carries a publishing token (%s)" %
                       (", ".join(t[:40] for t in tok[:3]) if isinstance(tok, list) else "not reported by this client"))
    if f["unix_sockets"] or f["all_unix_sockets"] is True:
        why.append("network: Unix sockets allowed")
    if f["local_binding"] is True:
        why.append("network: allowLocalBinding")
    if f["mach_lookup"]:
        why.append("network: allowMachLookup")
    if f["strict_allowlist"] is not True and f["managed_domains_only"] is not True:
        why.append("network: sandbox.network.strictAllowlist is not true in user or managed settings" +
                   (" (bypassPermissions: any host is allowed)" if f["permission_mode"] == "bypassPermissions" else ""))
    if f["permission_mode"] not in PERMISSION_MODES_CHECKED:
        why.append("permission mode %s: not checked for the strict sandbox" % (f["permission_mode"] or "unknown")[:32])
    if not f["env_scrub"] and f.get("env_hidden") is not True:
        why.append("the agent key may be visible to sandboxed commands (no CLAUDE_CODE_SUBPROCESS_ENV_SCRUB, no "
                   "sandbox.credentials.envVars deny for it)")
    if not isinstance(home, str) or not home.startswith("/") or home == "/":
        why.append("home unknown")
    else:
        ci = f["platform"] == "darwin"
        miss = [s for s in SECRETS if not _denied(posixpath.join(home, s), f["deny_read"], f["allow_read"], ci)]
        if miss:
            why.append("denyRead does not cover ~/" + ", ~/".join(miss[:6]) + (" ..." if len(miss) > 6 else ""))
    for p in f["env_files"]:
        if not (isinstance(project, str) and _covers(project, p)) or not _denied(p, f["deny_read"], f["allow_read"], f["platform"] == "darwin"):
            why.append("denyRead does not cover the project's %s" % posixpath.basename(p)[:64])
            break
    return (not why), why


# ---- 0.2.82: the irreversibility gate (mandate option "Code in Claude Code's strict sandbox: run without asking") ----------------------
# Law: the strict sandbox (above) bounds where code can SEND (L2 OTCHET-L3-PESOCHNICA: TCP, UDP and DNS refused by the kernel, 14/14
# hidden-network probes reached nothing) and what it can WRITE outside the project / into the agent's settings, git hooks and .git/config
# (EPERM). It does not bound: reads of secrets OUTSIDE ~ (denyRead "~/" is a path rule), writes into the shared tmp (/private/tmp/claude-<uid>),
# writes into .git/ other than hooks/config, and what the code does inside the project. So, with the option, code runs without a question
# (interpreters, scripts, files the agent wrote, obfuscated one-liners: what they do is contained), and a line the parser SEES doing one of
# those things -- or leaving the machine -- is still asked. Every test is fail-closed: an unknown class or an unreadable target is asked.
EXIT_PROGRAMS = {
    # network / sending (the parser often already adds net / an opaque network danger; this list does not rely on that)
    "curl", "wget", "aria2c", "http", "https", "httpie", "xh", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "telnet",
    "ftp", "tftp", "lftp", "smbclient", "mosh", "gh", "glab", "hub", "aws", "gcloud", "gsutil", "bq", "az", "kubectl", "oc", "terraform",
    "tofu", "pulumi", "docker", "podman", "nerdctl", "helm", "ngrok", "cloudflared", "tailscale", "wireguard", "wg", "openvpn", "vercel",
    "netlify", "heroku", "fly", "flyctl", "firebase", "wrangler", "supabase", "railway", "twine", "rclone", "s3cmd",
    "mail", "mailx", "sendmail", "mutt", "msmtp", "npx", "uvx", "pipx", "bunx", "pnpx", "dig", "nslookup", "host", "ping", "traceroute",
    "whois", "nmap", "websocat", "grpcurl", "openssl", "gpg-connect-agent", "sendmail", "mosquitto_pub", "redis-cli", "psql", "mysql", "mongosh", "mongo", "sqlcmd",
    # leaves the sandbox / acts as the user outside it
    "osascript", "open", "launchctl", "sudo", "su", "doas", "pkexec", "security", "keychain", "defaults", "crontab", "at", "systemctl",
    "screencapture", "pbcopy", "pbpaste",
    # money
    "stripe", "paypal", "bitcoin-cli", "lightning-cli", "lncli", "elements-cli", "solana", "spl-token", "cast", "near", "aptos", "sui",
}
GIT_REMOTE = {"push", "fetch", "pull", "clone", "ls-remote", "remote", "submodule", "credential", "send-email", "request-pull", "svn", "send-pack", "fetch-pack", "http-fetch",
              "p4", "daemon", "http-backend", "http-push", "imap-send", "archive", "upload-pack", "receive-pack", "bundle", "lfs", "config"}
PKG_TOOLS = {"npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "pipenv", "conda", "mamba", "micromamba", "brew", "port", "apt",
             "apt-get", "yum", "dnf", "pacman", "apk", "gem", "cargo", "go", "composer", "bundle", "deno", "swift", "dotnet", "nuget",
             "mvn", "gradle", "sbt", "lein", "mix", "hex", "cabal", "stack", "opam", "rustup", "nvm", "pyenv", "asdf", "mise", "volta"}
PKG_NET = {"install", "i", "in", "add", "ci", "publish", "unpublish", "update", "upgrade", "up", "login", "logout", "adduser", "fetch",
           "get", "pull", "push", "deploy", "sync", "owner", "dist-tag", "outdated", "search", "info", "view", "download", "dlx", "exec",
           "x", "create", "init", "tap", "release", "upload", "register", "auth", "token", "whoami", "audit", "pip", "tool", "self"}
# text backstop over the whole line: a host / URL / network API visible anywhere (inside quotes, heredocs, `find -exec curl`) -> asked
NET_TEXT = re.compile(r"(?i)\b(?:https?|ftp|wss?|ssh|git|s3|gs)://|/dev/(?:tcp|udp)\b|\b(?:urlopen|urllib|http\.client|httplib|requests\.|"
                      r"aiohttp|httpx|websocket|socket\.|create_connection|getaddrinfo|smtplib|ftplib|paramiko|fetch\(|XMLHttpRequest|"
                      r"net\.connect|https?\.(?:get|request)|Net::HTTP|LWP::|IO::Socket|open-uri|TCPSocket)|"
                      r"(?:^|[\s;&|(`'\"])(?:curl|wget|ssh|scp|sftp|rsync|nc|ncat|socat|telnet|ftp|gh|aws|gcloud|az|kubectl|docker|"
                      r"osascript|sudo|security|stripe|bitcoin-cli)(?=[\s;&|)`'\"]|$)")
# opaque reasons that name an exit (network, a host, a secret, an unknown path that may be a credential, git config) -> asked
# Not here (contained, decided 01.11 on the measure): a read or a path the parser cannot resolve (`cat $f`, `< $f`, `cp $a $b`) and a
# recursive read outside the project. A script run under the option reads the same files without the parser seeing it; asking the
# one-liner would be a question for show (11.8 per 100 lines in setup D). A credential path the line SHOWS is still asked (`secrets`).
ASK_OPAQUE = re.compile(r"(?i)network|remote service|host|socket|/dev/tcp|config-env|hard link|links than|outside the extraction|"
                        r"reserved|secret|credential|environ|code injected")
# 10.11 (r0260): "code injected through VAR=..." (bashparse._env_inject / _env_more: LD_PRELOAD, DYLD_*, NODE_OPTIONS=--require, a pager /
# editor / git config / search path that makes a program run other code than the line shows) stays asked in the strict sandbox too:
# the kernel would hold what that code does, but the line then no longer says what runs (`LD_PRELOAD=./x.so git status` reads as a status).
# 10.11 (r0260, dev questions group 4) -- ONE narrow exception, CODE_SEARCH_OWN: a module search path (PYTHONPATH / NODE_PATH) or
# NODE_OPTIONS --require / --import whose every value is a plain RELATIVE path (`.`, `src`, `./n.js`: no `..`, no `/`, `~`, `$` at the
# start). It loads code from the line's own folder -- what `python3 ./x.py` / `node ./n.js` run without a question in the same sandbox
# (law 2): the dev corpus asked it every day (`PYTHONPATH=. python3`, `NODE_OPTIONS=--require ./n.js node` in the agent's scratch).
# Everything else of the class stays asked: LD_PRELOAD / DYLD_*, a pager / editor / git configuration, an absolute or `~` path (code
# from another place), a proxy / TLS trust ("network route or trust changed": its own mark).
_REL = r"(?!\.\.(?:/|$|:| ))(?:\./)?[\w-][\w.-]*(?:/(?!\.\.(?:/|$))[\w.-]+)*/?|\."
CODE_SEARCH_OWN = re.compile(r"^code injected through (?:(?:PYTHONPATH|NODE_PATH)=(?:%s)(?::(?:%s))* \(search path\)|"
                             r"NODE_OPTIONS=(?:--(?:require|import)[= ](?:%s)(?: |$))+)$" % (_REL, _REL, _REL))
# 06.11 (r0260, law 2): the network named by CODE stays asked even under the strict fact, although the kernel refuses the connection:
# the probes corpus (proby n6/n7, "naruzhu": README.md posted by `python3 -c` / a heredoc) labels it a danger to catch, and its labels are
# not changed for a result. A fork for the owner (report r0260): law 2 says "held, not asked"; the corpus says "catch".
GIT_DESTROY_CONTAINED = False     # `git reset --hard`, `git clean -fd`, `git checkout .`, `branch -D`, `stash drop`: inside the project, but
                                  # they destroy uncommitted work for good -- the gate is about irreversibility: still asked (measured cost
                                  # in OTCHET-0282)


def _glob_dir(p):
    """10.11 (r0260): "/a/b/*.log" -> "/a/b" when the glob characters stand only in the LAST word (no `$`, backtick, `..`), else None.
    A glob expands to names inside that folder: what it writes stays there (a symlink out of the project / temp: the kernel holds it)."""
    if not isinstance(p, str) or not p.startswith("/") or re.search(r"[$`{}]", p):
        return None
    d, _, last = p.rstrip("/").rpartition("/")
    if not d or not re.search(r"[*?\[]", last) or re.search(r"[*?\[\]]", d) or last in (".", "..") or "/../" in d + "/":
        return None
    return d


def _rel_in_project(path, project):
    """-> the path relative to the project (POSIX, no leading slash) when `path` is a concrete absolute path strictly inside it, else None."""
    if not isinstance(path, str) or not path.startswith("/") or re.search(r"[$`*?\[\]{}]", path) or not isinstance(project, str):
        return None
    p, pr = posixpath.normpath(path), posixpath.normpath(project).rstrip("/")
    if not pr or not p.startswith(pr + "/"):
        return None
    return p[len(pr) + 1:]


def _protected_rel(rel):
    """A path inside the project the gate keeps asked: anything under .git/ (git's own commands do not show up as writes), the agent's
    settings and hooks (.claude/, .mcp.json, .husky/, .githooks/), .gitattributes / .gitmodules (filters and remotes)."""
    segs = rel.split("/")
    return any(s == ".git" for s in segs) or segs[0] in (".claude", ".mcp.json", ".husky", ".githooks", ".gitattributes", ".gitmodules",
                                                         ".gitconfig", ".vscode", ".idea", ".devcontainer", ".envrc")


UV_PIP_READ_HEAD = "uv pip"
PULL_LINE_HEADS = {"git pull", "git fetch", "git status", "git log", "git diff", "git show", "git rev-parse", "git branch"}
STASH_HEAD = "git stash"
NPX_OFFLINE_TOOLS = ("jest", "vitest", "mocha", "tsc", "eslint", "prettier")      # allowances.NPX_TOOLS


def npx_offline(head) -> bool:
    """0611 (r0260): `npx tsc --noEmit` with the tool not in node_modules is "npx tsc [fetch]" (npx would download it). Under the STRICT
    fact (the only caller is code_line_ok) the OS refuses every connection, so nothing is downloaded: npx runs the project's or the cache's
    copy, or fails -- code inside the sandbox, as the code option allows (v1 П3). Only the known checkers, only the [fetch] variant."""
    w = head.split(" ") if isinstance(head, str) else []
    return len(w) == 3 and w[0] == "npx" and w[1] in NPX_OFFLINE_TOOLS and w[2] == "[fetch]"


def code_exit(head) -> bool:
    """0.2.82: does this command identifier (as the classifier names it) leave the sandbox / send / pay? Unknown shapes: no (the text
    backstop NET_TEXT and the danger classes catch the rest); an empty or non-string head: yes (fail closed)."""
    if not isinstance(head, str) or not head.strip():
        return True
    if head == RSYNC_PLAIN_HEAD:
        return False                                  # 0611: a plain local rsync (bashparse.rsync_plain): a copy; any other form is tagged
    w = head.split(" ")
    base = w[0].rsplit("/", 1)[-1].lower()
    if base in EXIT_PROGRAMS or any(t in head for t in ("[packages]", "[fetch]", "[via xargs]", "[protected]")):
        return True
    if base == "git":
        if w[1:] == ["archive"]:
            return False                              # 10.11 (r0260): `git archive HEAD x | tar -x`: local; --remote / --exec is the danger
            #                                           net-out of the parser (bashparse._git), never contained
        return len(w) < 2 or w[1] in GIT_REMOTE or w[1].startswith("[") or "[" in head
    if re.fullmatch(r"python[0-9.]*", base) and len(w) >= 3 and w[1] == "-m" and w[2].split("[")[0] in ("pip", "http.server", "smtpd", "ensurepip", "twine", "venv"):
        return w[2] != "venv"
    return base in PKG_TOOLS and len(w) > 1 and w[1] in PKG_NET


# 0.2.90 (standing mandate, FABLE-NOL 03.11 G2): under `unlisted: "allow"` the exits of the 0.2.82 gate are the gate itself: a program
# that sends, fetches, pays or acts as the user outside the session is the danger `exit` (asked), whatever the list says. Narrower than
# code_exit: `[via xargs]` / `[protected]` variants and `git config` / `git archive` / `git bundle` are not exits here (their own rules apply).
GIT_LOCAL = {"config", "archive", "bundle", "lfs"}
EXIT_SKIP = {"pbpaste", "screencapture", "defaults", "pbcopy", "launchctl", "crontab", "at", "security", "systemctl",
             # local programs / clients the 0.2.82 sandbox gate lists as "acts as the user outside the sandbox": not a network exit by
             # themselves (a DB client to localhost, `open f.md`, `sudo ls`, a local package runner `uvx --from .`); npx keeps its [fetch] tag
             "open", "osascript", "sudo", "su", "doas", "pkexec", "psql", "mysql", "mongosh", "mongo", "sqlcmd", "redis-cli", "uvx", "pipx", "bunx", "pnpx", "npx"}
GIT_LOCAL_STANDING = {"config", "archive", "bundle", "lfs", "submodule", "credential"}   # submodule update: bashparse._git names it net-out
                                                                       # forms are the gates persist / secrets of bashparse._gates (`launchctl list`, `crontab -l` read)


# 0611: the parser names an rsync that copies between two local paths with plain options "rsync" (bashparse.rsync_plain); every other
# form is "rsync [remote]" / "rsync [option]" / "rsync [via xargs]" / a path ("/usr/bin/rsync"): an exit as before
RSYNC_PLAIN_HEAD = "rsync"


def standing_exit(head) -> bool:
    if not isinstance(head, str) or not head.strip():
        return False
    if head == RSYNC_PLAIN_HEAD:
        return False
    if head == UV_PIP_READ_HEAD:
        return False                                  # 0611 (r0260): plain "uv pip" is only list / freeze / show / tree (bashparse._ro_tags tags
        #                                               every other form: "uv pip [install]", "uv pip [unsure]"): a read of the local environment
    w = head.split(" ")
    base = w[0].rsplit("/", 1)[-1].lower()
    if base in EXIT_SKIP:
        return False
    if base in EXIT_PROGRAMS or any(t in head for t in ("[packages]", "[fetch]")):
        return True
    if base == "git":
        if len(w) >= 2 and w[1] == "remote":
            return "[net]" in head                    # 0.2.91 (friction 04.11): `git remote` / `-v` / `get-url` list the configuration (the parser
            #                                           tags `remote show` [net]; `remote update` is the danger net-out; add / set-url are [write])
        return len(w) >= 2 and w[1] in GIT_REMOTE and w[1] not in GIT_LOCAL_STANDING
    if re.fullmatch(r"python[0-9.]*", base) and len(w) >= 3 and w[1] == "-m" and w[2].split("[")[0] in ("pip", "http.server", "smtpd", "ensurepip", "twine"):
        return True
    return base in PKG_TOOLS and len(w) > 1 and w[1] in PKG_NET


def contained(d, project, home=None, sid=None) -> bool:
    """0.2.82: is the danger string `d` ("class:detail") contained by the strict sandbox, so that the option may let it run?"""
    if not isinstance(d, str):
        return False
    cat, _, det = d.partition(":")
    if cat == "rm-rf":
        rel = _rel_in_project(det, project)
        if rel is None and not in_temp(det, project, home, sid):
            g = _glob_dir(det)                        # 11.11 (r0260): `rm -rf $SCRATCH/out/*`: the folder before the glob word (as a write)
            rg = _rel_in_project(g, project) if g else None
            return g is not None and ((rg is not None and not _protected_rel(rg)) or in_temp(g, project, home, sid))
        return (rel is not None and not _protected_rel(rel)) or in_temp(det, project, home, sid)
    if cat == "git-destroy":
        return GIT_DESTROY_CONTAINED
    if cat == "autostart":
        # r0298: a relative write in an unknown directory to a place that starts programs by itself: the same write the opaque mark next
        # to it names. The sandbox lets a write land only in the project or the temp folders, and Seatbelt refuses .claude/settings*.json,
        # .mcp.json and .git/hooks|config there; the places it does NOT hold (strict_policy.HOOK_UNHELD: .claude/hooks, .husky ...) stay asked.
        from .strict_policy import HOOK_UNHELD
        return not HOOK_UNHELD.search(det)
    if cat != "opaque":
        return False                                  # secrets, git-config, agent-config, git-force-push, pipe-to-shell, sql-drop, disk, new
    if CODE_SEARCH_OWN.match(det) and len(re.sub(r" \(search path\)$", "", det).split("=", 1)[1]) < 60:
        return True                                   # 10.11 (r0260): code of the line's own folder, run in the sandbox (see above); the
        #                                               parser cuts a value at 60 characters -- a value that long is never judged here
    if ASK_OPAQUE.search(det):
        return False
    if det.startswith("write to ") and " in an unknown directory" not in det:
        t = det[len("write to "):]
        if t.startswith("/"):
            rel = _rel_in_project(t, project)
            if rel is None and not in_temp(t, project, home, sid):
                t = _glob_dir(t)                      # 10.11 (r0260): `> $S/out/*` -- the folder before the first glob word
                rel = _rel_in_project(t, project) if t else None
                return t is not None and ((rel is not None and not _protected_rel(rel)) or in_temp(t, project, home, sid))
            return (rel is not None and not _protected_rel(rel)) or in_temp(t, project, home, sid)
        if t.startswith("~"):
            return False
    return True


# ---- 06.11 (r0260): two shapes of line that name the network but, under the STRICT fact, cannot reach it ---------------------------------
# Law: the strict fact means the OS refuses every connection of the line (allowedDomains empty + strictAllowlist; L2 a2, L3 X01: raw TCP to
# 127.0.0.1 refused by the kernel). So a plain loopback GET and a package install by the project's manifest run with NO network inside the
# sandbox: the question about them could only be answered with a run that fails anyway -- a question for show. Kept asked (each check below
# fails closed): any other option, an operand (a package name), a registry / index / proxy / config / token in the line, `npm publish` /
# `login` / `adduser`, a debugging / admin local service (bashparse.loopback_harm: also a danger of its own), anything the parser of this
# narrow grammar does not know. What the install's own scripts (postinstall) run is code in the same sandbox, as `npm test` already is (v1 П3).
_SEP = {"|", "||", "&&", ";", "&", "\n"}
_TRIM = re.compile(r"\s(?:[12]?>\s*/dev/null|2>&1)(?=\s|$|[|;&])")
_GLOB = re.compile(r"[{}*?\[\]~]")                     # outside quotes: brace / glob / tilde expansion would change the words
_PLAIN_WORD = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,511}")


def _quotes(t):
    """-> (unquoted characters, characters inside "...") of `t`, or None for an unterminated quote. What stands in '...' is literal; what
    stands in "..." is literal too except for `$`, backtick and backslash (the caller forbids those there)."""
    unq, dq, q = [], [], None
    for ch in t:
        if q is None and ch in "'\"":
            q = ch
        elif q is not None and ch == q:
            q = None
        elif q is None:
            unq.append(ch)
        elif q == '"':
            dq.append(ch)
    return None if q is not None else ("".join(unq), "".join(dq))


def _unquoted(t):
    """the characters of `t` outside '...' and "..." (an unterminated quote: None)."""
    r = _quotes(t)
    return None if r is None else r[0]


def _segments(text, redirects=False):
    """-> [[token, ...], ...] split on | || && ; & (shlex, posix, punctuation as tokens), or None when the line is not that simple: an
    expansion (`$`, backtick, backslash) outside single quotes, a parenthesis / redirection / newline / glob / tilde outside quotes, a URL
    with a user name. 10.11 (r0260): quoted text may hold any other character (`python3 -c "print('x')"`); with `redirects`, an output
    redirection to a plain word (`> out.json`, `>> log.txt`, `2> err`) is dropped -- the parser records it as a write, judged on its own."""
    import shlex
    if not isinstance(text, str) or len(text) > 2000:
        return None
    t = _TRIM.sub(" ", " " + text)
    r = _quotes(t.replace("[::1]", ""))
    if r is None:
        return None
    unq, dq = r
    if re.search(r"[$`\\]", unq + dq) or re.search(r"[()\n]", unq) or _GLOB.search(unq) or re.search(r"://[^\s/]*@", t):
        return None
    if not redirects and re.search(r"[<>]", unq):
        return None
    try:
        lx = shlex.shlex(t, posix=True, punctuation_chars="|&;<>")
        lx.whitespace_split = True
        toks = list(lx)
    except ValueError:
        return None
    segs, cur, k = [], [], 0
    while k < len(toks):
        x = toks[k]
        if x in (">", ">>") and redirects:
            if k + 1 >= len(toks) or not _PLAIN_WORD.fullmatch(toks[k + 1]) or ".." in toks[k + 1].split("/"):
                return None
            if cur and cur[-1] in ("1", "2") and re.search(r"(?:^|\s)%s>{1,2}\s*%s(?=\s|$|[|;&])" % (cur[-1], re.escape(toks[k + 1])), t):
                cur.pop()                             # `2> err.txt`: the descriptor, not an argument
            k += 2
            continue
        if x in _SEP:
            segs.append(cur)
            cur = []
        elif set(x) <= set("|&;<>"):
            return None                               # `;;`, `|&`, `&>`, `<`: not this grammar
        else:
            cur.append(x)
        k += 1
    segs.append(cur)
    return segs if all(segs) else None


CURL_FLAGS = set("sSfiIvkN46gLO")                     # -s -S -f -i -I -v -k -N -4 -6 -g -L -O and their bundles (-fsSL)
CURL_LONG = {"--silent", "--show-error", "--fail", "--fail-with-body", "--include", "--head", "--verbose", "--insecure", "--compressed",
             "--no-buffer", "--globoff", "--http1.1", "--http2", "--ipv4", "--ipv6", "--no-progress-meter", "--location", "--remote-name"}
CURL_VALUE = {"-o", "--output", "-w", "--write-out", "-m", "--max-time", "--connect-timeout", "--retry", "--retry-delay", "-H", "--header",
              "-A", "--user-agent", "-X", "--request", "--url", "--max-redirs"}
_HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")


def url_host(x):
    """-> the lowercase host of an http(s) URL with no user name, no glob / brace and a plain host name, else None."""
    from urllib.parse import urlsplit
    if not isinstance(x, str) or not re.match(r"(?i)https?://", x) or re.search(r"[\[\]{}\s\\]", x):
        return None
    try:
        u = urlsplit(x)
        h = u.hostname
    except ValueError:
        return None
    if not h or "@" in u.netloc or not _HOSTNAME.fullmatch(h):
        return None
    return h.rstrip(".")


def _curl_get(argv, loopback_only=True):
    """argv = ["curl", ...]: a GET / HEAD with options of the list above, no data, no file read (a header / write-out from `@file`), no
    proxy / socket / resolve / config / cookie / credential / `--next`. Loopback URLs: no harmful local service (bashparse.loopback_harm).
    10.11 (r0260, Р-1011-сеть): any other host only with `loopback_only=False` (the strict sandbox: the kernel refuses a host outside
    allowedDomains, the person listed the rest), and only an http(s) URL with a plain host name. -> True / False."""
    from .bashparse import loopback_harm, loopback_url
    urls, k = [], 1
    while k < len(argv):
        a = argv[k]
        if a.startswith("--") and "=" in a:
            o, v = a.split("=", 1)
        elif a in CURL_VALUE:
            if k + 1 >= len(argv):
                return False
            o, v = a, argv[k + 1]
            k += 1
        else:
            o, v = a, None
        k += 1
        if v is not None:
            if o not in CURL_VALUE or v.startswith("@"):
                return False
            if o in ("-X", "--request") and v.upper() not in ("GET", "HEAD"):
                return False
            if o == "--url":
                urls.append(v)
            continue
        if o.startswith("--"):
            if o not in CURL_LONG:
                return False
        elif o.startswith("-") and len(o) > 1:
            if not set(o[1:]) <= CURL_FLAGS:
                return False
        else:
            urls.append(o)
    if not urls:
        return False
    for x in urls:
        if re.search(r"[\[\]{}]", x.replace("[::1]", "")):
            return False
        u = loopback_url(x)
        if u is not None:
            if u[1] is not None or loopback_harm(u) is not None:
                return False
            continue
        if loopback_only or url_host(x) is None:
            return False
    return True


WGET_FLAGS = {"-q", "--quiet", "-nv", "--no-verbose", "-S", "--server-response", "--spider", "-c", "--continue", "-N", "--timestamping",
              "--no-check-certificate", "--https-only", "-nc", "--no-clobber", "-4", "-6", "--inet4-only", "--inet6-only"}
WGET_VALUE = {"-O": "path", "--output-document": "path", "-P": "path", "--directory-prefix": "path", "-T": "n", "--timeout": "n",
              "-t": "n", "--tries": "n", "--max-redirect": "n", "-U": "any", "--user-agent": "any"}
WGET_BUNDLE = set("qcNS46")


def _out_path(v):
    """a file / folder a fetcher writes: `-` (standard output) or a plain relative path that does not climb out (`..`)."""
    return v == "-" or (_PLAIN_WORD.fullmatch(v) is not None and ".." not in v.split("/"))


def _wget_get(argv):
    """argv = ["wget", ...]: a plain download of http(s) URLs (no --post-*, --body-*, --method, --header, -e / --execute, -i, config)."""
    urls, k = [], 1

    def val(o, v):
        kind = WGET_VALUE[o]
        return _out_path(v) if kind == "path" else re.fullmatch(r"\d{1,5}", v) is not None if kind == "n" else len(v) <= 200
    while k < len(argv):
        a = argv[k]
        k += 1
        if a in WGET_FLAGS:
            continue
        if a.startswith("--"):
            o, eq, v = a.partition("=")
            if o not in WGET_VALUE:
                return False
            if not eq:
                if k >= len(argv):
                    return False
                v, k = argv[k], k + 1
            if not val(o, v):
                return False
            continue
        if a.startswith("-") and len(a) > 1:
            body = a[1:]
            while body and body[0] in WGET_BUNDLE:
                body = body[1:]
            if not body:
                continue
            o = "-" + body[0]
            if o not in WGET_VALUE:
                return False
            v = body[1:]
            if not v:
                if k >= len(argv):
                    return False
                v, k = argv[k], k + 1
            if not val(o, v):
                return False
            continue
        urls.append(a)
    return bool(urls) and all(url_host(x) is not None for x in urls)


GH_READS = {"pr": {"list", "view", "status", "diff", "checks"}, "issue": {"list", "view", "status"}, "run": {"list", "view", "watch"},
            "workflow": {"list", "view"}, "release": {"list", "view"}, "repo": {"view"}, "label": {"list"},
            "search": {"repos", "issues", "prs", "code", "commits"}}
GH_SHORT = {"-R", "-L", "-s", "-q", "-t", "-l", "-a", "-A", "-B", "-H", "-S", "-c", "-e", "-b", "-j", "-u", "-i"}
GH_LONG_NEVER = {"--web", "--body-file", "--input", "--field", "--raw-field", "--attach", "--hostname", "--editor", "--method"}
GH_API_FLAGS = {"--paginate", "--slurp", "-i", "--include", "--silent", "--verbose"}
GH_API_VALUE = {"--jq", "-q", "--cache", "--template", "-t", "-H", "--header", "-p", "--preview", "-X", "--method"}


def _gh_read(argv):
    """argv = ["gh", noun, verb, ...]: a read sub-command (GH_READS) with no flag that opens a browser, uploads, sends fields or points
    gh at another host; `gh api PATH` only as a GET (no -X / --method other than GET, no -f / -F / --field / --input, never graphql)."""
    if len(argv) < 3 or any(x.startswith("@") for x in argv):
        return False
    noun = argv[1]
    if noun == "api":
        k, path = 2, []
        while k < len(argv):
            a = argv[k]
            k += 1
            o, eq, v = a.partition("=") if a.startswith("--") else (a, "", "")
            if o in GH_API_FLAGS and not eq:
                continue
            if o in GH_API_VALUE:
                if not eq:
                    if k >= len(argv):
                        return False
                    v, k = argv[k], k + 1
                if o in ("-X", "--method") and v.upper() != "GET":
                    return False
                continue
            if a.startswith("-"):
                return False                          # -f / -F / --field / --raw-field / --input / -XPOST / anything unknown
            path.append(a)
        return len(path) == 1 and re.fullmatch(r"/?[A-Za-z0-9_.{}/?=&%,:-]{1,300}", path[0]) is not None \
            and not path[0].lstrip("/").startswith("graphql")
    if noun not in GH_READS or argv[2] not in GH_READS[noun]:
        return False
    for a in argv[3:]:
        if a.startswith("--"):
            if a.split("=", 1)[0] in GH_LONG_NEVER:
                return False
        elif a.startswith("-") and a not in GH_SHORT:
            return False                              # a bundle or an unknown short flag (-w = --web)
    return True


PKG_READS = {"npm": {"view", "info", "show", "v", "search", "outdated"}, "pnpm": {"view", "info", "outdated"}, "yarn": {"info", "outdated"}}
_PKG_NEVER = re.compile(r"^--?(?:registry|userconfig|globalconfig|prefix|cache|before|_auth|otp|auth-type|scope)\b|^//")


def _pkg_read(argv):
    return len(argv) >= 2 and argv[1] in PKG_READS.get(argv[0], ()) and not any(_PKG_NEVER.search(a) for a in argv[2:])


PIP_DL_FLAGS = {"--no-deps", "-q", "--quiet", "--pre", "--no-build-isolation", "--disable-pip-version-check", "--no-input"}
PIP_DL_VALUE = {"-d": "path", "--dest": "path", "--only-binary": "any", "--no-binary": "any", "--platform": "any", "--python-version": "any",
                "--implementation": "any", "--abi": "any", "-r": "req", "--requirement": "req"}
_PIP_SPEC = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}(?:\[[A-Za-z0-9_,.-]{1,100}\])?(?:(?:==|>=|~=|!=)[A-Za-z0-9.*+!_-]{1,40})?")


def _pip_read(argv):
    """`pip download SPEC ...` from the default index into a plain relative folder (no index / proxy / config / URL / local path)."""
    if len(argv) < 3 or argv[0] not in ("pip", "pip3") or argv[1] != "download":
        return False
    k, specs = 2, 0
    while k < len(argv):
        a = argv[k]
        k += 1
        if a in PIP_DL_FLAGS:
            continue
        o, eq, v = a.partition("=") if a.startswith("--") else (a, "", "")
        if o in PIP_DL_VALUE:
            if not eq:
                if k >= len(argv):
                    return False
                v, k = argv[k], k + 1
            kind = PIP_DL_VALUE[o]
            if (kind == "path" and not _out_path(v)) or (kind == "req" and not REQ_FILE.match(v)) or \
                    (kind == "any" and not re.fullmatch(r"[A-Za-z0-9_.:,-]{1,64}", v)):
                return False
            specs += kind == "req"
            continue
        if a.startswith("-") or not _PIP_SPEC.fullmatch(a):
            return False
        specs += 1
    return specs > 0


GIT_READ_FLAGS = {
    "fetch": {"--all", "--prune", "-p", "--tags", "-t", "--no-tags", "-q", "--quiet", "-v", "--verbose", "--unshallow", "--prune-tags",
              "-P", "--dry-run", "--no-recurse-submodules"},
    "pull": {"--ff-only", "--ff", "--no-ff", "--rebase", "--no-rebase", "-r", "-q", "--quiet", "-v", "--verbose", "--autostash",
             "--no-autostash", "--no-edit", "--prune", "-p", "--tags", "--no-tags", "--no-recurse-submodules", "--stat", "--no-stat"},
    "clone": {"-q", "--quiet", "--single-branch", "--no-single-branch", "--no-checkout", "-n", "--sparse", "--no-tags", "--shallow-submodules"},
    "ls-remote": {"--heads", "--tags", "-h", "-t", "--refs", "-q", "--quiet", "--symref"}}
_GIT_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}")


def _git_read(argv):
    """`git fetch|pull [opts] [remote [branch...]]`, `git clone [opts] https://host/path [dir]`, `git ls-remote [opts] url|remote [pattern]`:
    no option before the sub-command (`-c`, `-C`, `--exec-path`), no option that runs a program (--upload-pack, --template, -c, --config),
    no refspec (`:`, `+`), no URL other than https (ext::, file://, ssh)."""
    if len(argv) < 2 or argv[1] not in GIT_READ_FLAGS:
        return False
    sub, pos, k = argv[1], [], 2
    while k < len(argv):
        a = argv[k]
        k += 1
        if a in GIT_READ_FLAGS[sub]:
            continue
        if re.fullmatch(r"--depth=\d{1,6}", a) or (sub == "clone" and re.fullmatch(r"--filter=(?:blob:none|tree:0)", a)):
            continue
        if a in ("--depth", "-b", "--branch") and (a == "--depth" or sub == "clone"):
            if k >= len(argv) or not (re.fullmatch(r"\d{1,6}", argv[k]) if a == "--depth" else _GIT_NAME.fullmatch(argv[k])):
                return False
            k += 1
            continue
        if a.startswith("-"):
            return False
        pos.append(a)
    if sub in ("fetch", "pull"):
        return all(_GIT_NAME.fullmatch(x) and ".." not in x for x in pos)
    if sub == "clone":
        return 1 <= len(pos) <= 2 and url_host(pos[0]) is not None and (len(pos) == 1 or _out_path(pos[1]) and pos[1] != "-")
    return 1 <= len(pos) and (url_host(pos[0]) is not None or _GIT_NAME.fullmatch(pos[0]) is not None) and \
        all(_GIT_NAME.fullmatch(x) for x in pos[1:])


def net_read_argv(argv) -> bool:
    """10.11 (r0260, Р-1011-сеть): is this simple command an ordinary network READ (it changes nothing outside this machine and sends no
    data of the project but its own request)? An allow-list of programs, sub-commands and options; anything else: False."""
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        return False
    p = argv[0]
    if p == "curl":
        return _curl_get(argv, loopback_only=False)
    if p == "wget":
        return _wget_get(argv)
    if p == "gh":
        return _gh_read(argv)
    if p in PKG_READS:
        return _pkg_read(argv)
    if p in ("pip", "pip3"):
        return _pip_read(argv)
    if p == "git":
        return _git_read(argv)
    return False


def _read_head(argv):
    """the classifier's command identifier of a read (bashparse.command_id for these plain forms)."""
    p = argv[0]
    if p in ("curl", "wget"):
        return p
    return "%s %s" % (p, argv[1]) if len(argv) > 1 else p


def _read_hosts(argv):
    if argv[0] in ("curl", "wget"):
        out = set()
        for x in argv[1:]:
            h = url_host(x)
            if h is not None:
                out.add(h)
            else:
                from .bashparse import loopback_url
                u = loopback_url(x)
                if u is not None:
                    out.add(u[2].strip("[]"))
        return out
    if argv[0] == "git" and len(argv) > 1 and argv[1] in ("clone", "ls-remote"):
        return {h for h in (url_host(x) for x in argv[2:]) if h}
    return set()


NET_PROGS = ("curl", "wget", "gh", "npm", "pnpm", "yarn", "pip", "pip3", "git")


def net_read_line(text):
    """-> {"rest": the line without its reads, "heads": read heads, "hosts": hosts the reads name, "marks": callable(mark) -> True when the
    mark is a read's own} when the line has at least one network read (net_read_argv) and every word that names one of these programs
    stands at the start of a simple command of the line (nothing hidden in an argument, a quote, `env`, `xargs`, `find -exec`); else None.
    A head is a read's only when EVERY command of the line with that head is a read (`gh pr view && gh pr merge`: not)."""
    segs = _segments(text, redirects=True)
    if segs is None:
        return None
    reads = [s for s in segs if net_read_argv(s)]
    if not reads:
        return None
    if len(_FETCH_WORD.findall(text)) != sum(1 for s in segs if s[0] in ("curl", "wget")):
        return None
    for p in {s[0] for s in reads}:
        if len(re.findall(r"(?<![\w.-])%s(?![\w./:-])" % re.escape(p), text)) != sum(1 for s in segs if s[0] == p):
            return None
    by_head = {}
    for s in segs:
        if s[0] in NET_PROGS:
            by_head.setdefault(_read_head(s), []).append(net_read_argv(s))
    heads = {h for h, v in by_head.items() if all(v)}
    progs = {p for p in NET_PROGS if any(s[0] == p for s in reads) and all(net_read_argv(s) for s in segs if s[0] == p)}
    hosts = set()
    for s in reads:
        hosts |= _read_hosts(s)

    def own(d):
        if not isinstance(d, str):
            return False
        cat, _, det = d.partition(":")
        if cat == "exit":
            return det in heads
        if cat == "net-out":
            return any(det == h or det.startswith(h + " ") for h in heads)
        if d.startswith("opaque:remote service CLI: "):
            return d[len("opaque:remote service CLI: "):] in progs
        return False
    import shlex
    return {"rest": " ; ".join(shlex.join(s) for s in segs if not net_read_argv(s)), "heads": heads, "hosts": hosts, "marks": own}


_FETCH_WORD = re.compile(r"(?<![\w./:-])(?:curl|wget|aria2c|xh|httpie|https?)(?![\w./:-])")


def loopback_get_line(text):
    """-> the line without its curl GETs when every fetcher of the line is a plain loopback GET (_curl_get), else None."""
    segs = _segments(text)
    if segs is None:
        return None
    fetch = [s for s in segs if s[0] == "curl"]
    if not fetch or len(_FETCH_WORD.findall(text)) != len(fetch) or not all(_curl_get(s) for s in fetch):
        return None
    return " ; ".join(" ".join(s) for s in segs if s[0] != "curl")


# a manifest install: the program, its install word, the options that do not change WHERE it fetches from or WHAT it installs
INSTALL_FORMS = {
    ("npm", "install"), ("npm", "i"), ("npm", "ci"), ("pnpm", "install"), ("pnpm", "i"), ("yarn", None), ("yarn", "install"),
    ("uv", "sync"), ("pip", "install"), ("pip3", "install"), ("poetry", "install")}
INSTALL_FLAGS = {
    "npm": {"--ignore-scripts", "--no-audit", "--no-fund", "--prefer-offline", "--offline", "--silent", "-s", "--quiet", "-q",
            "--legacy-peer-deps", "--include=dev", "--omit=dev", "--omit=optional", "--production", "--no-progress"},
    "pnpm": {"--frozen-lockfile", "--ignore-scripts", "--prefer-offline", "--offline", "--silent", "-s"},
    "yarn": {"--frozen-lockfile", "--immutable", "--ignore-scripts", "--prefer-offline", "--offline", "--silent", "-s"},
    "uv": {"--frozen", "--locked", "--no-install-project", "--all-extras", "--dev", "--no-dev", "--all-groups", "--inexact", "--offline",
           "-q", "--quiet", "--no-build"},
    "pip": {"-q", "--quiet", "--no-deps", "--require-hashes", "--only-binary=:all:", "--no-input", "--disable-pip-version-check", "--no-build-isolation"},
    "poetry": {"--no-root", "--sync", "-q", "--quiet", "--no-interaction", "-n"}}
INSTALL_VALUE = {"uv": {"--extra", "--group"}, "pip": {"-r", "--requirement"}, "poetry": {"--only", "--with", "--without"}}
REQ_FILE = re.compile(r"^(?!/)(?!.*\.\.)[\w./-]{1,200}\.(?:txt|in)$")
_PKG_WORD = re.compile(r"(?<![\w./-])(?:npm|pnpm|yarn|uv|pip3?|poetry|npx|pnpx|bunx|bun|uvx|pipx)(?![\w./-])")


def _install(argv):
    """argv = one simple command: an install by the project's manifest / lock file / requirements file, nothing named, nowhere else."""
    prog = argv[0]
    sub = argv[1] if len(argv) > 1 and not argv[1].startswith("-") else None
    if (prog, sub) not in INSTALL_FORMS:
        return False
    fam = "pip" if prog in ("pip", "pip3") else prog
    rest = argv[2:] if sub is not None else argv[1:]
    k, req = 0, 0
    while k < len(rest):
        a = rest[k]
        if a in INSTALL_VALUE.get(fam, ()):
            if k + 1 >= len(rest) or rest[k + 1].startswith("-"):
                return False
            v = rest[k + 1]
            if fam == "pip":
                if not REQ_FILE.match(v):
                    return False
                req += 1
            elif not re.fullmatch(r"[\w.-]{1,64}", v):
                return False
            k += 2
            continue
        if a.startswith("--loglevel=") and fam == "npm" and re.fullmatch(r"--loglevel=[a-z]{1,10}", a):
            k += 1
            continue
        if a not in INSTALL_FLAGS.get(fam, ()):
            return False                              # an operand (a package), a registry / index / config / global / prefix / target ...
        k += 1
    return fam != "pip" or req > 0                    # `pip install` alone installs nothing; `pip install -r f.txt` is the manifest


def install_line(text):
    """-> the line without its installs when every package-manager word of the line is a manifest install (_install), else None."""
    segs = _segments(text)
    if segs is None:
        return None
    ins = [s for s in segs if _install(s)]
    if not ins or len(_PKG_WORD.findall(text)) != len(ins):
        return None
    return " ; ".join(" ".join(s) for s in segs if not _install(s))


INSTALL_HEADS = {"npm install", "npm i", "npm ci", "pnpm install", "pnpm i", "yarn", "yarn install", "uv sync", "pip install", "pip3 install",
                 "poetry install"}


def code_line_ok(w, project, text=None, skip=()):
    """0.2.82: may a Bash line run under the option? -> (ok, why). `w` = the hook's _witness of the line (danger, writes, net, commands),
    `text` = the command line. Every condition must hold; anything malformed -> not ok."""
    if not isinstance(w, dict) or not isinstance(project, str) or not project.startswith("/"):
        return False, "no witness / project"
    heads, danger, writes, net = w.get("commands"), w.get("danger"), w.get("writes"), w.get("net")
    if not all(isinstance(x, list) for x in (heads, danger, writes, net)):
        return False, "malformed witness"
    cmarks, chosts = code_only(w)
    net = [n for n in net if _rcpt_host(n) not in chosts]          # 10.11 (r0260, Р-1011 А): a host only interpreter code names: held
    # 10.11 (r0260, Р-1011-сеть-в-строгой): the line's network READS (curl / wget GET, gh reads, npm view, pip download, git fetch / pull /
    # clone / ls-remote; net_read_line) run in the sandbox: a host outside allowedDomains is refused by the kernel, a listed one is the
    # person's. They replace the 06.11 loopback-GET rule (a loopback GET is one of them). Publication, a body, a file, a method other than
    # GET / HEAD, ssh / scp / rsync: not reads -- they leave the sandbox (code_exit) and stay asked.
    nr = net_read_line(text) if isinstance(text, str) else None
    rhosts = nr["hosts"] if nr is not None else set()
    net = [n for n in net if _rcpt_host(n) not in rhosts]
    # 10.11 (r0260, Р-1011-сеть): a loopback host is refused by the kernel in the strict sandbox whatever the method (allowLocalBinding is
    # false, localhost is never a narrow allowedDomains entry; L3 X01: TCP to 127.0.0.1 refused) -- also on a line the read grammar cannot
    # read (`for i in $(seq 1 50); do curl -s http://localhost:8810/healthz ...`). A fetcher of such a line is exempt only when nothing on
    # the line can bring it another host or data from elsewhere (a config file, an input file, `--next`, a proxy: FETCH_INDIRECT).
    lb = [n for n in net if _loopback_rcpt(n)]
    net = [n for n in net if not _loopback_rcpt(n)]
    lb_fetch = bool(lb) and not net and isinstance(text, str) and not any(FETCH_INDIRECT.search(x) for x in fetch_texts(text))
    listed = w.get("sbx_listed") is True
    # 06.11 (r0260): a manifest install (see above): judged on the text; `rest` = the line without it
    inst = install_line(text) if any(isinstance(h, str) and h in INSTALL_HEADS for h in heads) else None
    if net:
        return False, "network: " + ", ".join(str(n) for n in net[:3])
    for h in heads:
        if code_exit(h) and not npx_offline(h) and not (nr is not None and h in nr["heads"]) and not (inst is not None and h in INSTALL_HEADS) \
                and not (lb_fetch and h in ("curl", "wget")):
            return False, "leaves the sandbox: %s" % str(h)[:80]
    held = w.get("harness_held") if isinstance(w.get("harness_held"), str) else None
    sbx_home = w.get("sbx_home") if isinstance(w.get("sbx_home"), str) else None
    sbx_sid = w.get("sbx_sid") if isinstance(w.get("sbx_sid"), str) else None
    for d in danger:
        if held is not None and d == held and w.get("sandbox") == {"strict": True}:
            continue                                  # 06.11 (law 2): the hook's K1 words only where Seatbelt holds the place (mapping.py)
        if inst is not None and isinstance(d, str) and d.partition(":")[0] in ("net-out", "exit") and \
                any(d.partition(":")[2] == x or d.partition(":")[2].startswith(x + " ") for x in INSTALL_HEADS):
            continue                                  # the install's own mark (bashparse._gates net-out, mapping exit): judged by install_line
        if d in skip:
            continue                                  # 10.11 (r0260): a mark the owner's amendment covers (amend.covered_marks)
        if nr is not None and nr["marks"](d):
            continue                                  # 10.11 (r0260, Р-1011-сеть): a network read's own mark (exit / net-out / gh CLI)
        if d in cmarks and code_contained(d, project, sbx_home, sid=sbx_sid):
            continue                                  # 10.11 (r0260, law 2): a delete / network mark of interpreter code: held by the kernel
        if not contained(d, project, sbx_home, sid=sbx_sid):
            return False, "not contained: %s" % str(d)[:120]
    for p in writes:
        if heads == [STASH_HEAD] and isinstance(p, str) and posixpath.normpath(p) == posixpath.normpath(project).rstrip("/"):
            continue                                  # 0611 (r0260): `git stash` / `pop` / `apply` alone on the line: git puts the project's own
            #                                           tracked changes aside or back (drop / clear are the danger git-destroy); clean / smudge
            #                                           filters it may run are code in this sandbox like any other
        if nr is not None and "git pull" in nr["heads"] and set(heads) <= PULL_LINE_HEADS and isinstance(p, str) and \
                posixpath.normpath(p) == posixpath.normpath(project).rstrip("/"):
            continue                                  # 10.11 (r0260, Р-1011-сеть): `git pull` merges the remote's tracked files into the
            #                                           project (the parser: a write of the project root); a protected place it would
            #                                           write (.git/hooks, .git/config, .claude/settings*.json) gets EPERM from Seatbelt
        rel = _rel_in_project(p, project)
        if rel is None:
            rel = find_root_glob(p, project)          # 10.11 (r0260): `find <project> -name '*.orig' -delete` (bashparse._find_root_glob)
        if (rel is None or _protected_rel(rel)) and not in_temp(p, project, sbx_home, sbx_sid):
            return False, "write outside the project and temp, or into .git / the agent's settings: %s" % str(p)[:120]
    if not isinstance(text, str):
        return False, "no command text"
    rest = text
    for r_ in (nr["rest"] if nr is not None else None, inst):
        if r_ is not None:
            rest = r_ if rest is text else None       # both at once: not this grammar (judged as before)
    sk = _LOOPBACK_URL.sub(" ", skeleton(rest)) if rest is not None else None
    if sk is not None and lb_fetch:
        sk = _FETCH_WORD.sub(" ", sk)                 # the line's fetchers reach only loopback hosts (judged above): not "network named"
    if sk is None or NET_TEXT.search(sk):
        return False, "network named in the line"
    if listed:
        # 10.11 (r0260, Р-1011-сеть): with a non-empty allowedDomains a listed host IS reachable from the sandbox, so a program the parser
        # could not see may publish there (`C=git; $C push`, an unparsable line, `eval`, a function): asked. A path or a folder the parser
        # could not resolve (`cat $f`, `HOME=$H pytest`) hides no program: judged as before (measured: asking every unreadable line put
        # the dev corpus at 10.9 a day). Publication words anywhere in the text (a quoted `npm publish`) are asked too.
        hid = [d for d in danger if isinstance(d, str) and d not in cmarks and HIDES_PROGRAM.match(d) and not _interp_var(d, text)]
        if hid and w.get("sbx_cred_closed") is True and not PUBLISH_WORD.search(text):
            # 11.11 (r0260): every credential source of the person is closed and every listed write host keeps its credentials there
            # (mapping: sbx_cred_closed): a hidden program is code like any other -- it cannot act in the person's name. Asked still when
            # the line carries a publication word (`C=git; $C push`, `f() { npm publish; }; f`)
            hid = []
        if hid:
            return False, "a program the parser cannot see, and the sandbox lets listed hosts through: %s" % hid[0][:80]
        if PUBLISH_TEXT.search(nr["rest"] if nr is not None else text):     # the line without its reads (`gh pr view` is one)
            return False, "publication named in the line"
    return True, ""


# ---- 10.11 (r0260, decision of Deus after the L2 fact of 10.11): WRITE hosts in allowedDomains -----------------------------------------
# L2 (real Claude Code, strict sandbox, allowedDomains=[example.com]): the macOS login KEYCHAIN is readable from the sandbox (`security
# find-generic-password` returned a dummy value; denyRead "~/" does not cover it -- securityd answers). So a host in the list where a
# request can WRITE in the person's name (github.com: git push with git-credential-osxkeychain, gh's token; the npm registry; PyPI's
# upload host) is a way out for ANY code the line runs -- a test, `npm run release`, `make`, `python3 x.py`, a lifecycle script, a git
# hook -- and nothing on the line shows it. Such a line is not contained by the strict sandbox: mapping drops the strict fact for it (the
# line is judged as outside the sandbox: a question, "from now on" where one exists) and records the hosts (`sbx_open`) for the words
# of the question. Kept strict: a line of INERT programs (no interpreter, no runner, no git / gh / package manager, nothing opaque) whose
# network is plain GETs of READ-ONLY hosts and that names no write host -- it cannot use a credential.
# Why not "a write host listed = not strict for the whole session": measured on the friction stand (typical list), the inert lines kept
# here are the reads and deletes the strict fact exists for; the code lines are asked by both rules (report r0260, 10.11).
# Not known to be read-only = a write host (fail closed): example.com, a wildcard (`*.githubusercontent.com`: any name below it), gitlab.com.
READ_ONLY_HOSTS = frozenset({
    "codeload.github.com",              # archives of a repository (GET only)
    "objects.githubusercontent.com",    # release assets, LFS objects (signed GET URLs)
    "raw.githubusercontent.com",        # raw files of a repository (GET only)
    "files.pythonhosted.org",           # PyPI's file host (uploads go to upload.pypi.org)
    "pypi.org",                         # /simple and /pypi/*/json (uploads: upload.pypi.org; the web login asks 2FA, no keychain token)
    "proxy.golang.org", "sum.golang.org",    # Go module mirror and checksum database (read-only protocols)
    "index.crates.io", "static.crates.io",   # crates.io sparse index and downloads (publishing: crates.io itself)
})
INERT_HEADS = frozenset({
    "cd", "pwd", "ls", "cat", "head", "tail", "wc", "grep", "egrep", "fgrep", "rg", "echo", "printf", "mkdir", "rm", "rmdir", "cp", "mv",
    "touch", "ln", "sort", "uniq", "cut", "tr", "date", "sleep", "true", "false", "test", "[", "diff", "cmp", "stat", "file", "which",
    "basename", "dirname", "realpath", "readlink", "du", "df", "tee", "nl", "paste", "comm", "seq", "shasum", "md5", "jq", "tree", "find",
    "sed", "awk"})    # sed `e` / `s///e`, awk system() / pipes, find -exec: the parser's [exec] variant (bashparse 0.2.54), never inert
_HOSTISH = re.compile(r"(?i)(?<![\w.-])((?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*)(?![\w-])")


def write_hosts(domains):
    """-> the entries of allowedDomains NOT known to be read-only (lowercase, no trailing dot), in their order."""
    out = []
    for d in domains if isinstance(domains, list) else []:
        if not isinstance(d, str):
            continue
        h = d.strip().lower().rstrip(".")
        if h and h not in READ_ONLY_HOSTS and h not in out:
            out.append(h)
    return out


def _below(h, base):
    base = base[2:] if base.startswith("*.") else base
    return h == base or h.endswith("." + base)


# 12.11 (r0263, L3: quiet mode's own host list asked `git clone https://github.com/a/b` EVERY time, "a dangerous command is never allowed
# for a project", while `git fetch` / `git pull` of the same host were silent). With every credential source of the person closed
# (cred_closed: keychain, git credential stores, GH_TOKEN & co. hidden), a git READ names a forge host only to read from it: it cannot
# authenticate as the person, and the URL is on the line for anyone to see. Its URL words are left out of the "named host" search; a
# git read with options that run a program or set configuration (--upload-pack, -u, -c, --config, --template) keeps them. A curl GET of
# the same host stays "named = asked" (the owner's rule).
_GIT_READS = {"clone", "fetch", "pull", "ls-remote"}
_GIT_RUN_OPTS = re.compile(r"^(?:--upload-pack|-u|--config|-c|--template|--recurse-submodules|--recursive)(?:=|$)")


def _without_git_reads(text):
    if not isinstance(text, str):
        return text
    try:
        segs = _segments(text.rstrip("\n"), redirects=True)    # _words_and_bodies ends the words with a newline (no bodies: nothing after)
    except Exception:      # noqa: BLE001
        return text
    if not segs:
        return text
    keep, dropped = [], False
    for s in segs:
        a = list(s)
        if a and a[0] == "git":
            k = 1
            while k < len(a) and a[k] in ("-C", "--git-dir", "--work-tree") and k + 1 < len(a):
                k += 2
            sub = a[k] if k < len(a) else ""
            if sub in _GIT_READS and not any(_GIT_RUN_OPTS.match(x) for x in a[1:]) and "$" not in " ".join(a) and "`" not in " ".join(a):
                dropped = True
                continue
        keep.append(a)
    if not dropped:
        return text
    import shlex
    return " ; ".join(shlex.join(x) for x in keep)


def write_open(domains, heads, danger, net, text, code_marks=(), code_hosts=(), closed=False):
    """-> the write hosts of the list when THIS line could use them (it is then judged as outside the strict sandbox), else [].
    A line keeps the strict fact only when every program is inert (INERT_HEADS, no variant), the fetchers are plain GETs (net_read_line)
    of READ-ONLY or loopback hosts, nothing comes from interpreter code, no part is opaque, and no write host (or a name below one) is
    written anywhere in the text (`curl https://API.github.com`, a host in a variable's value)."""
    wh = write_hosts(domains)
    if not wh:
        return []
    if not isinstance(text, str) or not isinstance(heads, list) or not isinstance(danger, list) or not isinstance(net, list):
        return wh
    from .inline import runs_text
    rt = runs_text(text, heads, ext=closed is True)  # r0261c (а): text an edit-only program only writes names no host it uses
    #                                                  r0261d: with every credential closed, also TEXT literals of the project's own Python
    named = rt
    if closed is True and not NET_TEXT.search(_URL_SCHEME.sub(" ", rt)):
        # r0261c (б): every credential source closed and no network word on the line (no fetcher, no network API in its code): a host
        # inside a quoted argument / a heredoc body (`.venv/bin/python -c "print(write_hosts(['github.com']))"`, `grep 'api.github.com'`)
        # is a word, not a use; the line's own words are still searched, and so is a heredoc body that remains in the text that runs
        # (`cat >> notes <<'EOF' github.com EOF; python3 tools/x.py`: the file it writes may be read by the program that runs)
        named = _words_and_bodies(rt)
    if closed is True:
        named = _without_git_reads(named)
    for m in _HOSTISH.finditer(named):
        n_ = m.group(1).lower().rstrip(".")
        if n_ not in READ_ONLY_HOSTS and any(_below(n_, w) for w in wh):      # codeload.github.com is below github.com, and read-only
            return wh
    if closed is True and all(w in CRED_HOSTS for w in wh):
        # 11.11 (r0260): every credential source of the person is closed to the sandbox (cred_closed) and every write host of the list is one
        # whose credentials live only there: code cannot act in the person's name, so code alone does not take the strict fact. Asked: a
        # write host NAMED in the line (above) and a publication named in it (git push, gh writes, npm / yarn / pnpm / uv publish, twine
        # ...; the line without its reads). What code the line does not show may still send data to a listed host with a credential
        # it brings itself -- Р-1011-сеть-в-строгой accepts that for every listed host (secrets are denied; written in the report).
        nr = net_read_line(rt)
        if PUBLISH_TEXT.search(nr["rest"] if nr is not None else rt):
            return wh
        return []
    if code_marks or code_hosts:
        return wh
    nr = None
    # only loopback hosts, and nothing on a fetcher that can bring another host or data (as code_line_ok's lb_fetch): refused by the kernel
    lb_only = bool(net) and all(_loopback_rcpt(n) for n in net) and not any(FETCH_INDIRECT.search(x) for x in fetch_texts(text))
    for h in heads:
        if not isinstance(h, str):
            return wh
        if h in ("curl", "wget"):
            nr = nr or net_read_line(text)
            if (nr is None or h not in nr["heads"]) and not lb_only:
                return wh
        elif h not in INERT_HEADS and not (re.fullmatch(r"/(?:usr/)?bin/[a-z]+", h) and h.rsplit("/", 1)[1] in INERT_HEADS) \
                and not (h.endswith(" [write]") and h[:-8] in INERT_HEADS):
            return wh                                 # `/usr/bin/grep`: the system's own inert program (a project path is not);
            #                                           `sed [write]` (sed -i): writes a file, runs nothing ([exec] is its own tag)
    rd = nr["hosts"] if nr is not None else set()
    listed = [d.strip().lower().rstrip(".") for d in domains if isinstance(d, str)]
    for x in list(rd) + [_rcpt_host(n) for n in net]:
        if not (x in READ_ONLY_HOSTS or _loopback_rcpt(x) or not any(_below(x, d) for d in listed)):
            return wh                                 # a listed (reachable) host that is not read-only; an unlisted one: refused by the kernel
    for d in danger:
        if not isinstance(d, str):
            return wh
        if d.startswith("opaque:") and not (nr is not None and nr["marks"](d)):
            m = _PATH_EXP.match(d)
            if d.startswith("opaque:write to "):
                continue                              # a write the hook could not place: judged on its own (code_line_ok), runs nothing
            if m is None or m.group(1) not in INERT_HEADS:
                return wh                             # opacity may hide a program; `cat $f`: a path of an inert program hides none
    return []


_PATH_EXP = re.compile(r"^opaque:path from expansion: (\S+) ")
def _words_and_bodies(text):
    """r0261c: the line's words (skeleton: quoted text blanked) followed by every heredoc body it still has; the text when unreadable."""
    sk = skeleton(text)
    if sk is text or not isinstance(text, str):
        return text
    try:
        from .bashparse import _normalize
        _one, docs, _bal, _uns = _normalize(text)
    except Exception:      # noqa: BLE001
        return text
    return sk + "\n" + "\n".join(d[1] for d in docs or [] if isinstance(d, (tuple, list)) and len(d) >= 2 and isinstance(d[1], str))


_URL_SCHEME = re.compile(r"(?i)\b(?:https?|ftp|wss?|ssh|git|s3|gs)://")


# 10.11 (r0260): opaque reasons that may hide a PROGRAM of the line (not only a path): with listed domains such a line is asked
HIDES_PROGRAM = re.compile(r"^opaque:(?:unparsable|brace expansion|command name|empty command|function defined|more than|nesting deeper|"
                           r"heredoc body with an unreadable|command of \d+ characters|operator |not a string|pushd|"
                           r".{0,80}: the rest of the line cannot be judged)")
def fetch_texts(text):
    """10.11 (r0260): the text of each fetcher command of the line -- from the fetcher's word to the next separator outside quotes
    (`;`, `&`, `|`, a newline, `)`, a backtick): FETCH_INDIRECT judges a fetcher's own options, not `python3 -c` next to it."""
    out = []
    for m in _FETCH_WORD.finditer(text if isinstance(text, str) else ""):
        i, q, buf = m.start(), None, []
        while i < len(text):
            ch = text[i]
            if q:
                if ch == q:
                    q = None
                elif ch == "\\" and q == '"' and i + 1 < len(text):
                    buf.append(ch)
                    i += 1
                    ch = text[i]
            elif ch in "'\"":
                q = ch
            elif ch == "\\" and i + 1 < len(text):
                buf.append(ch)
                i += 1
                ch = text[i]
            elif ch in ";&|\n)`":
                break
            buf.append(ch)
            i += 1
        out.append("".join(buf))
    return out


_VAR_CMD = re.compile(r"^opaque:command name from expansion: \$\{?([A-Za-z_][A-Za-z0-9_]{0,40})\}?$")
_INTERP_BASE = re.compile(r"python[0-9.]*|node|pytest|py\.test|ruby|perl|deno|bun")


def _interp_var(d, text):
    """`PY=.venv/bin/python; [ -x $PY ] || PY=cloud/server/.venv/bin/python; $PY -m pytest`: the command name is a variable the line
    itself sets, every time to a literal path of an interpreter / test runner (code, held like `python3 x.py`), never anything else."""
    m = _VAR_CMD.match(d) if isinstance(d, str) else None
    if m is None or not isinstance(text, str):
        return False
    vals = re.findall(r"(?:^|[\s;&|(])(?:export\s+)?%s=([^\s;&|()]*)" % re.escape(m.group(1)), text)
    return bool(vals) and all(re.fullmatch(r"[\w./-]{1,300}", v) and _INTERP_BASE.fullmatch(v.rsplit("/", 1)[-1]) for v in vals) and \
        not re.search(r"(?:^|[\s;&|(])(?:read|for|local|declare|typeset|readonly|mapfile|getopts)\b[^;&|\n]*\b%s\b" % re.escape(m.group(1)), text)


# 10.11 (r0260): what can make a fetcher reach a host or send data the line does not show; and publication named anywhere in the text
FETCH_INDIRECT = re.compile(r"(?:^|\s)(?:-K|--config|--next|-:|-x|--proxy|--preproxy|--socks\d?h?|--connect-to|--resolve|--unix-socket|"
                            r"--abstract-unix-socket|--url-query|--variable|-i|--input-file|-e|--execute|--post-file|--body-file|"
                            r"-u|--user|-b|--cookie|-c|--cookie-jar|--netrc|--netrc-file|-n|-E|--cert|--key|--oauth2-bearer|"
                            r"-[a-zA-Z]*[Kx:])(?=[\s=]|$)|(?:^|\s)-[a-zA-Z]*[bHu](?=\S)|=@|\s@|(?:localhost|127\.0\.0\.1)[^\s]*[{}\[\]]")
PUBLISH_TEXT = re.compile(r"(?i)\bgit\b[^\n;&|]{0,200}?\bpush\b|\b(?:npm|pnpm|yarn|cargo|uv|poetry|twine|gem|flit|hatch)\s+(?:[\w-]+\s+)?"
                          r"(?:publish|upload|push)\b|\b(?:docker|podman|helm)\s+push\b|\bgh\s+(?:pr|issue|release|repo|gist|api|secret)\b|"
                          r"\b(?:vercel|netlify|wrangler|flyctl|fly|firebase|heroku)\s+(?:deploy|publish|release)\b")
PUBLISH_WORD = re.compile(r"(?i)(?<![\w-])(?:push|publish|upload|gist|release|deploy)(?![\w-])")     # 11.11 (r0260)
_LOOPBACK_URL = re.compile(r"(?i)\bhttps?://(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d{1,5})?(?=[/\s'\"?#]|$)")



# ---- 10.11 (r0260, law 2 / Р-1011 А): marks of INTERPRETER CODE under the strict fact -----------------------------------------------
# The parser records where each mark comes from (bashparse.Command.code_only_marks / code_only_hosts; mapping puts them into the witness
# as `sbx_code` only under the strict fact). Code runs inside the sandbox: a network call it makes is refused by the kernel (L2 a2, L3 X01:
# TCP, UDP, DNS, loopback); a delete it makes outside the project and Claude Code's temp root gets EPERM. So these two kinds of mark are
# not a question there -- the same code saved to a file and run (`python3 tool.py`) already runs without one (Р-0611-D8). Kept asked:
# a delete into the SHARED temp root outside this project's session folders (writable by the sandbox, read by other sessions), into the
# project's protected places (.git, the agent's settings, hooks), of the home folder or above it; every other mark of code (secrets,
# persistence, agent-config, git-config, a program the code runs that leaves the machine: judged on its own head).
_CODE_NET = re.compile(r"^opaque:(?:network from .{1,80} code: |obfuscated code \()")
_CODE_RM_PATH = re.compile(r"\((/[^()]*)\)$")


# 10.11 (r0260): a held mark of a line may be SPLIT into its own sandboxed part (allowances.held_mark_cover, amend._held: the rest of the
# line is judged part by part) only on an ALLOW-list -- before it was a deny-list of unreadable reasons (UNREADABLE), and the friction
# stand found the hole it guards (real #970: `ssh vps ...` after a `$(...)` loop ran silently next to an amended gh read). Two lists:
#   READABLE: the parser read the WHOLE line -- every danger mark is of a concrete class (it names a path, a program, a host) or an opaque
#     reason that names a concrete thing; any other opaque reason, known today or added tomorrow, is opacity: the line is judged whole;
#   SPLIT: the kinds of held mark that may stand alone -- a delete inside the project / the own temp folders, a write to a literal path
#     there, a delete / network mark of interpreter code (code_contained), the hook's held K1 word.
READABLE_KINDS = {"rm-rf", "sql-drop", "git-force-push", "git-destroy", "git-config", "agent-config", "pipe-to-shell", "secrets", "disk",
                  "persist", "witness", "exit", "write-outside", "net-out", "loopback-write"}
READABLE_OPAQUE = re.compile(r"^opaque:(?:write to /(?!.* in an unknown directory$)|code injected through |remote service CLI: [\w.-]+$|"
                             r"recursive \S+ outside the project: |git grep outside the project: )")
SPLIT_WRITE = re.compile(r"^opaque:write to /(?!.* in an unknown directory$)")


def readable(w) -> bool:
    """True when every danger mark of the line is READABLE (or a mark of interpreter code: the code is quoted, the shell around it read)."""
    if not isinstance(w, dict):
        return False
    cm = code_only(w)[0]
    for d in w.get("danger") or []:
        if not isinstance(d, str):
            return False
        if d in cm:
            continue
        cat = d.partition(":")[0]
        if cat == "opaque":
            if not READABLE_OPAQUE.match(d):
                return False
        elif cat not in READABLE_KINDS:
            return False
    return True


def splittable(d, w) -> bool:
    """May the held mark `d` of the line `w` (the witness, with `project`) be its own sandboxed part? Only under the strict fact, only for a
    READABLE line, only for a mark of the SPLIT kinds that the sandbox holds."""
    if not isinstance(d, str) or not isinstance(w, dict) or w.get("sandbox") != {"strict": True} or not isinstance(w.get("project"), str):
        return False
    if not readable(w) or d not in (w.get("danger") or []):
        return False
    h, sid = w.get("sbx_home"), w.get("sbx_sid")
    if d == w.get("harness_held"):
        return True
    if d in code_only(w)[0]:
        return code_contained(d, w["project"], h, sid=sid)
    if d.partition(":")[0] == "rm-rf" or SPLIT_WRITE.match(d):
        return contained(d, w["project"], h, sid=sid)
    return False


def code_only(w):
    """-> (marks, hosts) of the witness's `sbx_code` (lists of strings), empty when absent / malformed."""
    sc = w.get("sbx_code") if isinstance(w, dict) else None
    if not isinstance(sc, dict):
        return [], []
    m, h = sc.get("marks"), sc.get("hosts")
    m = [x for x in m if isinstance(x, str)] if isinstance(m, list) else []
    h = [x for x in h if isinstance(x, str)] if isinstance(h, list) else []
    return m, h


def _rcpt_host(n):
    """`webfetch@host` / `webfetch@host:port` / a URL -> the bare lowercase host."""
    h = str(n).rsplit("@", 1)[-1].split("//", 1)[-1].split("/", 1)[0]
    h = h[1:-1] if h.startswith("[") and h.endswith("]") else re.sub(r":\d+$", "", h)
    return h.lower().rstrip(".")


def code_contained(d, project, home=None, sid=None) -> bool:
    if not isinstance(d, str):
        return False
    if _CODE_NET.match(d):
        return True
    cat, _, det = d.partition(":")
    if cat == "secrets":
        # 10.11 (r0260, dev #483): a secret PATH interpreter code names, under one of SECRETS of the home: the strict fact requires denyRead
        # over each of them (evaluate), so the code's read is refused by Seatbelt. Not here: the keychain (`security`, Keychains: readable
        # from the sandbox, L2 10.11), a key file elsewhere (a .pem in the project), the environment, anything that is not an absolute path.
        if not isinstance(home, str) or not home.startswith("/") or home == "/" or not det.startswith("/") or ".." in det.split("/"):
            return False
        p = posixpath.normpath(det)
        return any(_covers(posixpath.join(home, s_), p) for s_ in SECRETS)
    if cat != "rm-rf":
        return False
    m = _CODE_RM_PATH.search(det)
    if m is None:
        return "(" not in det and "/" not in det       # the backstop word itself (`rm -r`, `shutil.rmtree`): the target stays in the code
    p = posixpath.normpath(m.group(1))
    if not isinstance(project, str) or not isinstance(home, str) or not home.startswith("/") or home == "/":
        return False
    if p == "/" or (posixpath.normpath(home) + "/").startswith(p.rstrip("/") + "/"):
        return False                                  # the home folder or above it (Н5's ground): never quiet
    rel = _rel_in_project(p, project)
    if rel is not None:
        return not _protected_rel(rel)
    if p == posixpath.normpath(project):
        return False                                  # the whole project
    if CLAUDE_TMP.match(p):
        return in_temp(p, project, home, sid)         # the shared temp root: only this project's session folders
    return True                                       # outside the project and the temp root: EPERM


# 10.11 (r0260): `find <project root> -name PATTERN [-o -name P2] [-type f] -delete` deletes matching files under the project. bashparse
# records it as the write "<project>/**/PATTERN" (a glob only in that last word, `**` for the recursion), so the mandate's delete target
# "<project>/*" covers it (before: the project root itself -> RESOURCE, real stand proby #24) and this gate sees a delete INSIDE.
def find_root_glob(p, project):
    """-> the pattern as a project-relative name when `p` is exactly "<project>/**/<pattern>" with a pattern that names something (not
    only wildcards, no `/`), else None."""
    if not isinstance(p, str) or not isinstance(project, str) or not project.startswith("/"):
        return None
    pre = posixpath.normpath(project).rstrip("/") + "/**/"
    if not p.startswith(pre):
        return None
    pat = p[len(pre):]
    if not pat or "/" in pat or not re.search(r"[^*?\[\]]", pat) or pat in (".", ".."):
        return None
    if any(fnmatch.fnmatchcase(x, pat) for x in (".git", ".claude", ".mcp.json", ".husky", ".githooks", ".gitattributes", ".gitmodules",
                                               ".gitconfig", ".vscode", ".idea", ".devcontainer", ".envrc", "hooks", "config")):
        return ".git"                                 # the pattern also matches a protected place: judged as that place (asked)
    return pat


# ---- 06.11 (r0260, law 2 of the Constitution: what the strict OS sandbox holds is not asked) ------------------------------------------
# Temp. Claude Code 2.1.319 (read from the binary 06.11): the sandbox may write "." and Claude Code's temp root <tmp>/claude-<uid>/ -- "the
# shared per-uid temp root", the folders of EVERY session of this user (L2 OTCHET-L3-PESOCHNICA A3: a session wrote another's folder).
# So: a write in /tmp or /private/tmp OUTSIDE claude-<uid>/ is refused by the kernel (EPERM): held, not asked. A write in THIS session's
# own folder <tmp>/claude-<uid>/<project slug>/<session id>/ (its scratchpad) is the agent's own scratch: contained (10.11: and every
# session folder of the same project, see cc_slug). Anything else in the shared root (another project's session folder, the root itself,
# a folder of no session) is NOT held: a channel to another session that may run
# unsandboxed (test_0282 shared tmp) -- asked as before. A temp path that names a harness place (`.git`, `.claude`, `.mcp.json` ...) or
# lies around the home folder / the project (a home kept under /tmp: CI, the fatigue stand) is never temp. Unknown home / project: not temp.
CLAUDE_TMP = re.compile(r"^(?:/private)?/tmp/claude-\d+(?:/|$)")
SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{7,127}")
# 10.11 (r0260): a session of Claude Code has MORE than one folder in the temp root: the scratchpad stays under the id the session was
# started with, background task output goes under the current id (a resumed session: <old-id>/scratchpad and <new-id>/tasks in one
# session, seen on the owner's machine 10.11), and the hook's session_id names only one of them. The folder above them is the PROJECT's:
# Claude Code 2.1.322 (read from the binary 10.11) builds <tmp>/claude-<uid>/<slug>/<session id>/{scratchpad,tasks} with
# slug = the session's launch directory (= CLAUDE_PROJECT_DIR) with every character outside [A-Za-z0-9] replaced by "-" (cut at 200 and a
# hash appended above that). So: any session folder under THIS project's slug is the project's own scratch, like the project itself.
# Channel: a sandboxed agent may write a file another session of the same project later reads or runs outside the sandbox -- the same
# channel the project's own files already are (conftest.py, package.json scripts, a script under tools/), and a run of an agent-written
# file outside the sandbox is held by the witness either way (ESCALATE_WRITTEN_RUN). Another project's slug stays foreign (asked): its
# sessions may be unsandboxed and its files are not the agent's to write. The encoding is lossy: two paths that differ only in
# separators (`a-b` / `a_b` / `a/b` / `a.b`) share a slug -- residual risk accepted for ASCII; a path with any other character
# (Cyrillic: every letter is "-", so equal-length names collide) or longer than 200 gets no slug (fail closed: only the own session id).
CC_SLUG_MAX = 200
_SLUG_SAFE = re.compile(r"/[A-Za-z0-9/._-]*")


def cc_slug(project):
    """-> Claude Code's folder name for `project` in its temp root, or None (non-ASCII-safe characters, too long, not absolute)."""
    if not isinstance(project, str) or not _SLUG_SAFE.fullmatch(project) or project == "/":
        return None
    s = re.sub(r"[^A-Za-z0-9]", "-", posixpath.normpath(project))
    return s if len(s) <= CC_SLUG_MAX else None


def in_temp(p, project=None, home=None, sid=None, noproj=False) -> bool:
    """noproj (11.11, a session started in the home folder: no project): only THIS session's own folder <root>/<any slug>/<sid>/... of
    Claude Code's temp root counts (the hook's session id; no slug match: the home's slug is every home session's); any other temp
    folder outside the root as before. Without noproj an unknown project is never temp (every caller before 11.11)."""
    from .bashparse import TEMP_IN
    if not isinstance(p, str) or not p.startswith("/") or re.search(r"[$`*?\[\]{}]", p):
        return False
    if noproj and project is None:
        if not (isinstance(home, str) and home.startswith("/") and home != "/") or ".." in p.split("/"):
            return False
    elif not all(isinstance(x, str) and x.startswith("/") and x != "/" for x in (project, home)):
        return False
    q = posixpath.normpath(p)
    from .bashparse import around_home
    for x in (project, home):
        if x is not None and around_home(q, x):     # r0274: firmlink-insensitive (/private/tmp/u = /tmp/u)
            return False
    if not TEMP_IN.match(q + ("/" if not q.endswith("/") else "")):
        return False
    if any(_protected_rel(s) for s in q.split("/")[1:]):
        return False
    if CLAUDE_TMP.match(q):
        segs = q.split("/")
        k = next(i for i, s_ in enumerate(segs) if re.fullmatch(r"claude-\d+", s_))
        if len(segs) <= k + 3 or SESSION_ID.fullmatch(segs[k + 2]) is None:
            return False                              # the root, a project folder itself, a folder of no session: foreign
        own_sid = isinstance(sid, str) and SESSION_ID.fullmatch(sid) is not None and segs[k + 2] == sid
        if noproj and project is None:
            return own_sid
        slug = cc_slug(project)
        return own_sid or (slug is not None and segs[k + 1] == slug)
    return True


_QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")


def skeleton(text):
    """The line as the shell reads its WORDS: heredoc bodies cut out (bashparse._normalize) and the text inside quotes blanked. A host or a
    network API named only inside a body / a quoted argument is code or data the strict sandbox runs with NO network (the kernel refuses
    every connection, L2 a2 / X01): not a question there. A program the line runs (curl, ssh, gh ...) is judged on the parsed heads
    (code_exit), never on this text. A line the normalizer cannot read: the whole text (fail closed)."""
    if not isinstance(text, str):
        return ""
    try:
        from .bashparse import _normalize
        one, _docs, balanced, unsure = _normalize(text)
    except Exception:      # noqa: BLE001
        return text
    if not balanced or unsure is not None or not isinstance(one, str):
        return text
    return _QUOTED.sub("''", one)


def _loopback_rcpt(n):
    """a Bash.net recipient of the hook (`webfetch@localhost`, `http://127.0.0.1` ...) that is this machine."""
    from .bashparse import LOOPBACK
    h = str(n).rsplit("@", 1)[-1].split("//", 1)[-1].split("/", 1)[0]
    h = h[1:-1] if h.startswith("[") and h.endswith("]") else re.sub(r":\d+$", "", h)
    return bool(LOOPBACK.match(h))


# ---- 11.11 (r0260, class (б) of the dev hold-out): a session started in the HOME folder -------------------------------------------------
# Claude Code started in ~ has no project (mapping.project_of: the home is never one), so no strict fact was judged at all and every line in
# the session's own temp folder was asked (a delete of its scratch `rm -rf $T/out/*`: the danger). Its sandbox writes "." = the WHOLE home:
# code run there is NOT held (it may write ~/Documents), so nothing that runs code is quiet here. Quiet only: a line of inert programs
# (INERT_HEADS, no [exec] / xargs / network variant), no network, whose every write and delete lands in THIS session's own temp folder
# (<root>/<any slug>/<hook's session id>/..., no `..`), checked again on the realpath the hook resolves (a symlink planted in the scratch
# that points into the home is not the scratch), under the strict fact with an EMPTY allowedDomains. Another session's folder, the root,
# the home itself: asked as before.
HOME_TMP_BAD_TAG = re.compile(r"exec|xargs|protected|net|packages|fetch|remote|via")


def home_tmp_target(p, home, sid, realpath=None):
    """-> True when `p` (a write / delete target, a glob only in its last word) is inside the own temp folder of session `sid`."""
    if not isinstance(p, str) or not p.startswith("/") or ".." in p.split("/"):
        return False
    g = _glob_dir(p) if re.search(r"[*?\[\]]", p) else p
    if g is None or not in_temp(g, None, home, sid, noproj=True):
        return False
    if realpath is None:
        return True
    segs = posixpath.normpath(g).split("/")
    k = next((i for i, s_ in enumerate(segs) if re.fullmatch(r"claude-\d+", s_)), None)
    if k is None or len(segs) < k + 3:
        return False
    root = "/".join(segs[:k + 3])
    try:
        rr = realpath(root)
        rg, rd = realpath(g), realpath(posixpath.dirname(g))
    except (OSError, ValueError):
        return False
    rr = posixpath.normpath(rr).rstrip("/")
    return all(isinstance(x, str) and (posixpath.normpath(x) == rr or posixpath.normpath(x).startswith(rr + "/")) for x in (rg, rd))


def home_tmp_line(w, text, home, sid, realpath=None):
    """-> (ok, why) for a line of a home-started session (see above). `w`: danger / writes / net / commands of the hook."""
    if not isinstance(w, dict) or not isinstance(sid, str) or SESSION_ID.fullmatch(sid) is None:
        return False, "no session"
    heads, danger, writes, net = w.get("commands"), w.get("danger"), w.get("writes"), w.get("net")
    if not all(isinstance(x, list) for x in (heads, danger, writes, net)) or net or not heads:
        return False, "network or malformed"
    for h in heads:
        if not isinstance(h, str) or h.split(" ")[0] not in INERT_HEADS or HOME_TMP_BAD_TAG.search(h.partition(" ")[2]):
            return False, "not an inert program: %s" % str(h)[:60]
    if not isinstance(text, str) or NET_TEXT.search(skeleton(text)):
        return False, "network named"
    for d in danger:
        cat, _, det = d.partition(":") if isinstance(d, str) else ("", "", "")
        if cat != "rm-rf" or not home_tmp_target(det, home, sid, realpath):
            return False, "not contained: %s" % str(d)[:80]
    for p in writes:
        if not home_tmp_target(p, home, sid, realpath):
            return False, "write outside the session's temp folder: %s" % str(p)[:80]
    return bool(danger or writes), "nothing to cover"
