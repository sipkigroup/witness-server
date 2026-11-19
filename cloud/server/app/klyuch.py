"""r0348 (ARHIV-RESHENIY-OPUS-1611 §3 laws 1-7, §6 step 2; decision Р-1611-белый-список): the person's "from now on" keyed by the
CONSEQUENCE of a call, not by its text.

Before r0348 a rule ("allowance" / "amendment") named exact command identifiers or a narrow kind of ONE part of a line, and a line the
classifier marked dangerous was "only once" for ever: the owner answered the same consequence in other words again and again (replay of
the owner's corpus, 16.11: 21 of 31 questions "a dangerous command is never allowed"). Here the key of a call is the set of its
consequences, computed from the consequence vector (app/vektor.py) and the facts of the hook, never from the spelling of the line:

  "(key) write <folder>/"            files written in this folder and its sub-folders, outside the project (a real folder under the home;
                                      not hidden, not ~/Library / ~/bin / ~/Applications, not the home itself; the path as the hook resolved it)
  "(key) GET <scheme>://<host>[:port]"  a request with no data, no identity, to exactly this host (ASCII, no user@, no other port / scheme)
  "(key) service gh <noun> <verb> [-R owner/repo]" / "(key) service az <path>"   a READ of the person's cloud service, exactly this operation
  "(key) run <realpath>"             the person's own program outside the project, by the file it is (no link, not written by the agent)

A call is keyable only when EVERY consequence of it is one of these (or stays in the project / the temp folder). Never keyed (law §3 and
Р-1611 п.1): money, publication (any change of an outside service), an identity or a secret leaving, a secret read, the agent's code
(written in this session, code in the line, downloaded), carriers and anything opaque, autostart, the agent's / Witness's configuration,
a switched-off protection, an article Н1-Н10, a delete outside the project and the temp folder. Such a call keeps "Allow once".

When (Р-1611 п.3, the owner's decision 16.11; r0349 restores it -- r0348 had "from the second" for every shelf): the shelf "form / core"
(write / GET / service: the witness computes the consequence, the rule names exactly it) offers the button at the FIRST question, term 7 days;
the shelf "trust" (running a program: its consequence is the program's, not computed) only at the SECOND question with the same key within
7 days, answered yes (one answer is not yet a habit), term 1 day. At most 20 live rules per project (allowances.MAX_PER_PROJECT), no masks.
A signed folder amendment "(write outside the project) <dir>/" (amend.TEXT: "files directly in this folder") covers the key of a write in
exactly that folder (covers()): the same consequence by a computed program (closed Python, sed -i) is not asked again; a sub-folder is.

Signed = shown (law r0327): the text of a key rule is built by the witness from the dictionary below (version kl-1) and names the AREA in
plain words; the passkey signs it with the page. packtools/screencheck.py rebuilds it offline (a test keeps both copies equal).
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import posixpath
import re

V = "kl-1"
PREFIX = "(key) "
WRITE = PREFIX + "write "
GET = PREFIX + "GET "
SERVICE = PREFIX + "service "
RUN = PREFIX + "run "
KINDS = (WRITE, GET, SERVICE, RUN)
TERM_DAYS = {WRITE: 7, GET: 7, SERVICE: 7, RUN: 1}
FORM_SHELF = (WRITE, GET, SERVICE)       # r0349 (Р-1611 п.3): computed by the witness -> the button at the first question; RUN: from the second
WINDOW_S = 7 * 86400                     # the earlier question with the same key must be this recent
MAX_ATOMS = 8                            # = svidetel_v4 ALLOWANCE_MAX_COMMANDS
ID_MAX = 200

# the dictionary of the text (kl-1). HEAD / TAIL whole, one line per consequence from AREA (the template of its kind). A change of any of
# these strings is a new version (kl-2 ...): the checker keeps the SHA-256 of each version's dictionary.
HEAD = "Allow from now on, for this agent in this project, for {days}:"
AREA = {WRITE: "- write and change files in the folder {arg} and its sub-folders (not a hidden file, not through a link that leads elsewhere)",
        GET: "- read {arg} without sending data or your login",
        SERVICE: "- read with your account: {arg} (no change, no publication)",
        RUN: "- run your program {arg} (as it is now; a changed or replaced file is asked again)"}
TAIL = ("Only exactly this. A line that also does anything else (sends data, publishes, pays, runs code the agent wrote, reads a secret, "
        "touches start-up files or settings) is asked as before. Revoke it in one tap under Settings -> Allowances.")


def dictionary():
    return {"v": V, "head": HEAD, "area": {k.strip(): v for k, v in AREA.items()}, "tail": TAIL}


def dictionary_sha256():
    from app.signview import jcs
    return hashlib.sha256(jcs(dictionary())).hexdigest()


def _days_word(d):
    return "1 day" if d == 1 else "%d days" % d


def render(atoms, days):
    """-> the text of a key rule (kl-1): what the person signs, whole."""
    lines = [HEAD.format(days=_days_word(int(days)))]
    for a in atoms:
        k = next((k for k in KINDS if a.startswith(k)), None)
        if k is None:
            raise ValueError("not a key: %r" % a)
        lines.append(AREA[k].format(arg=a[len(k):].rstrip("/") if k == WRITE else a[len(k):]))
    lines.append(TAIL)
    return "\n".join(lines)


def term_days(atoms):
    return min(TERM_DAYS[next(k for k in KINDS if a.startswith(k))] for a in atoms)


def key_hash(atoms):
    return hashlib.sha256(json.dumps(sorted(atoms), ensure_ascii=False).encode("utf-8")).hexdigest()[:32]


# ------------------------------------------------------------------------------------------------------------------------- computing
_HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
_URL = re.compile(r"(?i)([a-z][a-z0-9+.-]*)://([^/\s'\"?#<>|;&)]*)")
_IP = re.compile(r"^[0-9.]+$|:")
_NEVER_DIRS = ("Library", "bin", "Applications", "Downloads")
_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_AZ_WORD = re.compile(r"[a-z][a-z0-9-]{0,40}")


def _clean_abs(p):
    return isinstance(p, str) and p.startswith("/") and 1 < len(p) <= 900 and "\x00" not in p and "*" not in p and \
        posixpath.normpath(p) == p and not re.search(r"[\x00-\x1f\x7f]", p)


def _unpriv(p):
    return p[len("/private"):] if isinstance(p, str) and p.startswith("/private/") else p


def _under(p, d):
    return isinstance(p, str) and isinstance(d, str) and (p == d or p.startswith(d.rstrip("/") + "/"))


def folder_atom(path, home, project, rp):
    """A file written outside the project -> (atom, None) or (None, why). The folder is the file's own folder, as the hook resolved it."""
    if not _clean_abs(path):
        return None, "the path of a written file is not a plain absolute path"
    if not _clean_abs(home) or home == "/":
        return None, "the home folder of this call is not known"
    if isinstance(project, str) and _under(path, project):
        return None, None                                 # the project's own file: no key needed
    d, name = posixpath.split(path)
    if not name or name.startswith("."):
        return None, "a hidden file (%s) is never allowed from now on" % name[:60]
    if not d.startswith(home + "/"):
        return None, "a file outside your home folder is never allowed from now on"
    rel = d[len(home) + 1:].split("/")
    if any(s.startswith(".") for s in rel) or rel[0] in _NEVER_DIRS:
        return None, "a hidden or system folder (%s) is never allowed from now on" % ("~/" + "/".join(rel))[:80]
    # law (link): the folder must be where it says it is. The hook's realpath fact of the file (or of its folder) must name the same place;
    # with no fact a link cannot be ruled out -> no key.
    real = None
    if isinstance(rp, dict):
        for q in (path, d):
            if isinstance(rp.get(q), str):
                real = (rp[q], q)
                break
    if real is None:
        return None, "Witness has no fact of where %s really is (a link is not ruled out)" % ("~/" + "/".join(rel))[:80]
    r, q = real
    if _unpriv(r.rstrip("/")) != _unpriv(q.rstrip("/")):
        return None, "the folder is a link to another place"
    return WRITE + d + "/", None


def _host_atoms(cmd, hosts):
    """The literal URLs of the line -> {host: atom}; None when any URL is not plain (user@, IP, non-ASCII, a variable, another scheme)."""
    out = {}
    if not isinstance(cmd, str):
        return None
    for m in _URL.finditer(cmd):
        scheme, auth = m.group(1).lower(), m.group(2)
        if scheme not in ("http", "https"):
            return None
        if "@" in auth or "$" in auth or "`" in auth or "\\" in auth or "%" in auth or not auth.isascii():
            return None                                   # user:password@, a variable, an escape: not the host it reads as
        host, _, port = auth.lower().partition(":")
        host = host.rstrip(".")
        if not _HOSTNAME.fullmatch(host) or _IP.search(host) or host.endswith((".local", ".localhost")) or host == "localhost":
            return None
        if port and not re.fullmatch(r"[0-9]{1,5}", port):
            return None
        if port and ((scheme == "https" and port == "443") or (scheme == "http" and port == "80")):
            port = ""
        a = GET + scheme + "://" + host + (":" + port if port else "")
        if host in out and out[host] != a:
            return None                                   # two schemes / ports of one host on one line
        out[host] = a
    if not set(hosts) <= set(out):
        return None                                       # a host the classifier found that is not a literal URL of the line
    return out


def _gh_atom(e):
    args = [a for a in (e.get("args") or []) if isinstance(a, str)]
    if e.get("nargs", 0) > len(args):
        return None
    pos, repo, k = [], None, 0
    while k < len(args):
        a = args[k]
        k += 1
        if a in ("-R", "--repo"):
            if k >= len(args):
                return None
            repo, k = args[k], k + 1
            continue
        if a.startswith("--repo="):
            repo = a.split("=", 1)[1]
            continue
        if a.startswith("-"):
            continue
        pos.append(a)
    if len(pos) < 2 or pos[0] == "api" or not all(re.fullmatch(r"[a-z][a-z-]{0,30}", x) for x in pos[:2]):
        return None                                       # `gh api PATH`: any read of the API -- too wide for one key
    if repo is not None and not _REPO.fullmatch(repo):
        return None
    return SERVICE + "gh %s %s" % (pos[0], pos[1]) + (" -R %s" % repo if repo else "")


def _az_atom(e):
    args = [a for a in (e.get("args") or []) if isinstance(a, str)]
    if e.get("nargs", 0) > len(args):
        return None
    path = []
    for a in args:
        if a.startswith("-"):
            break
        path.append(a)
    if not path or len(path) > 5 or not all(_AZ_WORD.fullmatch(x) for x in path):
        return None
    return SERVICE + "az " + " ".join(path)


def _run_atoms(place, home, project):
    from app import vektor as vk
    rp = vk.run_paths(place, home)
    if rp is None:
        return None
    paths, names, opaque = rp
    if names or opaque:
        return None
    out = []
    rmap = place.get("rp") if isinstance(place, dict) else None
    for p in sorted(paths):
        if isinstance(project, str) and _under(p, project):
            continue
        real = rmap.get(p) if isinstance(rmap, dict) else None
        if not isinstance(real, str) or _unpriv(real) != _unpriv(p) or not _clean_abs(p) or not p.isascii():
            return None
        out.append(RUN + p)
    return out




def compute(parts, vec, place=None):
    """-> (atoms, None) for a keyable call, (None, why) for one that never gets a key, (None, None) when there is nothing to key."""
    if not isinstance(vec, dict) or vec.get("oshibka"):
        return None, "the consequence of this call could not be computed"
    if vec.get("uroven") == "U3":
        return None, "the call breaks an article of the Constitution"
    if vec.get("neprozr"):
        return None, "part of this call is opaque to Witness (%s): it is never allowed from now on" % ", ".join(vec["neprozr"])[:80]
    if vec.get("dengi"):
        return None, "money: never allowed from now on"
    if vec.get("publ"):
        return None, "a publication or a change of an outside service: never allowed from now on (only once, or a rule for exactly that target)"
    if vec.get("zashch"):
        return None, "a protection is switched off: never allowed from now on"
    if vec.get("chtenie") == "sekret":
        return None, "a secret is read: never allowed from now on"
    kod = vec.get("kod")
    if kod not in ("net", "chelovek"):
        return None, {"agent": "it runs code the agent wrote", "skachannyy": "it runs downloaded code",
                      "proekt": "it runs the project's code (a project rule covers that)"}.get(kod, "it runs code Witness cannot see") + \
            ": never allowed from now on by its consequence"
    zon = set((vec.get("zapis") or {}).get("zony") or [])
    bad = zon - {"proekt", "vremennaya", "vne_proekta", "sistema"}
    if bad:
        return None, "it writes to %s: never allowed from now on" % ", ".join(sorted(bad))
    pl = place if isinstance(place, dict) else {}
    atoms = []
    writes, deletes, net_hosts, cmd, home, project = [], [], [], None, pl.get("home"), pl.get("project")
    for tool, args in parts:
        w = args.get("_witness") if isinstance(args, dict) and isinstance(args.get("_witness"), dict) else {}
        home = w.get("home") if isinstance(w.get("home"), str) else home
        project = w.get("project") if isinstance(w.get("project"), str) else project
        if tool.startswith("Bash"):
            cmd = args.get("command") if isinstance(args.get("command"), str) else cmd
            writes += [p for p in (w.get("outside_writes") or []) + (w.get("writes") or []) if isinstance(p, str)]
            deletes += [p for p in (w.get("deletes") or []) if isinstance(p, str)]
            net_hosts += [n.rsplit("@", 1)[-1].lower() for n in (w.get("net") or []) if isinstance(n, str)]
            if any(isinstance(d, str) and d.split(":", 1)[0] in ("rm-rf", "sql-drop", "git-destroy", "write-outside", "disk")
                   for d in w.get("danger") or []):
                return None, "a delete or a write the classifier marked dangerous: never allowed from now on"
        elif tool.split(".", 1)[0] in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            p = w.get("path") if isinstance(w.get("path"), str) else (args.get("file_path") if isinstance(args, dict) else None)
            if isinstance(p, str):
                writes.append(p)
        elif tool.split(".", 1)[0] in ("Read", "Grep", "Glob", "LS"):
            continue
        else:
            return None, "a tool Witness has no key for (%s)" % tool[:40]
    from app.vektor import _temp
    for p in deletes:
        if not ((isinstance(project, str) and _under(p, project)) or _temp(p, home)):
            return None, "a delete outside the project: never allowed from now on"
    for p in dict.fromkeys(writes):
        if (isinstance(project, str) and _under(p, project)) or _temp(p, home):
            continue
        a, why = folder_atom(p, home, project, pl.get("rp"))
        if a is None:
            if why is None:
                continue
            return None, why
        if a not in atoms:
            atoms.append(a)
    # law §3 p.2: a carrier never passes a key on -- whatever it carries (bash -c, env, xargs, eval, a wrapper) is not keyed even when the
    # parser unwrapped it; a Bash line with no record of its simple commands is not keyed either (what runs is not known)
    vk_ = pl.get("vk") if isinstance(pl.get("vk"), dict) and not pl["vk"].get("cut") else None
    if cmd is not None:
        if vk_ is None or not isinstance(vk_.get("cmds"), list):
            return None, "the commands of this line were not recorded: asked each time"
        from app.hookjudge import runners as R
        for e in vk_["cmds"]:
            nm = e.get("name") if isinstance(e, dict) else None
            if not isinstance(nm, str) or nm in R.SHELLS or nm in R.CARRIERS or nm in R.WRAPPER_WORDS or \
                    nm in ("xargs", "eval", "command", "builtin", "parallel", "watch", "find", "awk", "gawk", "vim", "vi", "nvim", "emacs") \
                    or e.get("remote"):
                return None, "a carrier (%s) runs what it is given: never allowed from now on" % (nm or "?")[:30]
    # network: every destination of the vector must be a plain read we can name
    svc = []
    for e in vec.get("set") or []:
        prog = e.get("prog")
        if prog in ("gh", "az") and e.get("metod") == "chtenie":
            svc.append(prog)
            continue
        if e.get("metod") != "chtenie" or e.get("lichnost") != "net" or e.get("idn") or not isinstance(e.get("host"), str):
            return None, "data, a file or your login goes to the network: never allowed from now on"
    if any((e.get("host") or "") for e in vec.get("set") or [] if e.get("prog") not in ("gh", "az")):
        ha = _host_atoms(cmd, [e["host"] for e in vec.get("set") or [] if e.get("prog") not in ("gh", "az") and e.get("host")])
        if ha is None:
            return None, "an address of this line is not plain (a user@ part, a number, another script, a variable): asked each time"
        for h in sorted({e["host"] for e in vec["set"] if e.get("prog") not in ("gh", "az") and e.get("host")}):
            if ha[h] not in atoms:
                atoms.append(ha[h])
    if set(net_hosts) - {e.get("host") for e in vec.get("set") or []} - {"api.github.com", "management.azure.com"}:
        return None, "a host of this line has no computed consequence"
    if svc:
        if vk_ is None:
            return None, "the service call was not recorded: asked each time"
        es = [e for e in vk_.get("cmds") or [] if isinstance(e, dict) and e.get("name") in ("gh", "az") and not e.get("remote")]
        if not es:
            return None, "the service call was not recorded: asked each time"
        for e in es:
            a = _gh_atom(e) if e["name"] == "gh" else _az_atom(e)
            if a is None:
                return None, "this %s call is not one operation Witness can name: asked each time" % e["name"]
            if a not in atoms:
                atoms.append(a)
    if kod == "chelovek":
        ra = _run_atoms(pl, home, project)
        if not ra:
            return None, "the program this line runs is not known by its file: asked each time"
        atoms += [a for a in ra if a not in atoms]
    if not atoms:
        return None, None
    if len(atoms) > MAX_ATOMS or any(len(a) > ID_MAX or "*" in a for a in atoms):
        return None, "too many different consequences in one call"
    return sorted(atoms), None


# --------------------------------------------------------------------------------------------------------------- the call's key (gate)
CALL = contextvars.ContextVar("dw_klyuch_call", default=None)       # (atoms | None, why | None) of the call being judged (hook judge)


def of_call(ctx, agent, parts, place):
    """The key of one hook call, computed BEFORE its parts are judged (the same vector the shadow keeps). Never raises."""
    try:
        from app import vektor
        vec = vektor.call_vector(ctx, agent, [(m.tool, m.args) for m in parts], [], place)
        return compute([(m.tool, m.args) for m in parts], vec, place)
    except Exception as e:  # noqa: BLE001  an error is no key (asked as before), never silence
        return None, "the key could not be computed (%s)" % type(e).__name__


AMEND_DIR = "(write outside the project) "      # = amend.DIR: an amendment "files directly in this folder" (signed text amend.TEXT)


def covers(rule_atom, atom):
    if rule_atom == atom:
        return True
    if rule_atom.startswith(AMEND_DIR) and rule_atom.endswith("/"):
        # r0349: the person's folder amendment says "files directly in this folder" (amend.TEXT), whatever program writes them: it covers
        # the key of a write in EXACTLY that folder (not a sub-folder) -- the same consequence by a computed program (`python3 - <<'EOF'`,
        # `sed -i`); the rest of the call must be covered too (cover())
        return atom == WRITE + rule_atom[len(AMEND_DIR):]
    return rule_atom.startswith(WRITE) and atom.startswith(WRITE) and atom.startswith(rule_atom) and rule_atom.endswith("/")


def _live(L, mid, project, now):
    for gid, g in sorted(L.S.allowances.items(), key=lambda kv: -kv[1]["seq"]):
        if g["mandate"] == mid and not g["ended"] and g["nbf"] <= now <= g["exp"] and g["project"] == project and \
                all(isinstance(c, str) and (c.startswith(KINDS) or (c.startswith(AMEND_DIR) and c.endswith("/"))) for c in g["commands"]):
            yield gid, g


def cover(L, mid, a, meta, now, key=None):
    """Gateway step: the core would ask about this part (defer) and EVERY consequence of the whole call is covered by the person's live
    key rules of this mandate and project -> the part goes to the core as covered by the rule (recipient = the rule's key, `dangerous`
    cleared, `allowance` + `project`); the core must answer OK_ALLOWANCE. Anything else: unchanged. A deny is never turned."""
    key = CALL.get() if key is None else key
    if meta is None or not isinstance(a, dict) or a.get("class") != "command" or "allowance" in a or a.get("sandboxed") is True:
        return a
    atoms = key[0] if isinstance(key, tuple) else None
    if not atoms:
        return a
    if L.S.decide_for(mid, a, now)[1] != "defer":
        return a
    rules = list(_live(L, mid, meta["project"], now))
    first = None
    for at in atoms:
        hit = next(((gid, c) for gid, g in rules for c in g["commands"] if covers(c, at)), None)
        if hit is None:
            return a
        first = first or hit
    gid, c = first
    b = dict(a, recipient=c, dangerous=False, allowance=gid, project=meta["project"])
    return b if L.S.decide_for(mid, b, now)[1:] == ("allow", "OK_ALLOWANCE") else a


# ----------------------------------------------------------------------------------------------------------------------- the offer
ONCE_FIRST = ("\"from now on\" for running a program is offered from the second same question within 7 days (it is about: %s): "
              "allow this one once")
SAME_LIVE = "a rule for exactly this is already allowed from now on: approve once (the agent's next call runs under it)"


def offer(ctx, acc, x, meta, out):
    """allowances.offer, when its own way gives no rule: the key rule of this question (cmd_meta["klyuch"], stored when it was asked)."""
    atoms = meta.get("klyuch") if isinstance(meta, dict) else None
    h = meta.get("klyuch_h") if isinstance(meta, dict) else None
    if not (isinstance(atoms, list) and atoms and all(isinstance(a, str) and a.startswith(KINDS) for a in atoms) and isinstance(h, str)
            and h == key_hash(atoms)):
        return out
    from app import allowances as al
    if al.team(ctx, acc["id"]):
        return out
    m = ctx.db.one("SELECT * FROM mandates WHERE id=?", (x["mandate_id"],))
    if m is None or m["status"] != "active":
        return out
    t0 = x["created_at"] if "created_at" in x.keys() and isinstance(x["created_at"], int) else al._now()
    gid = (x["line_lead"] if "line_lead" in x.keys() else None) or x["rid"]
    # r0349 (Р-1611 п.3): the shelf "form / core" -- every consequence is one the witness computes -- gets the button at once
    prior = "form" if all(a.startswith(FORM_SHELF) for a in atoms) else None
    # the earlier question: another call (not a part of this one), the same key, within 7 days, ANSWERED YES by the person (a question still
    # waiting, refused, expired or replaced is not a habit -- an agent cannot earn the button by asking twice)
    prior = prior or ctx.db.one("SELECT rid FROM actions WHERE account_id=? AND agent_id=? AND rid<>? AND rid<>? AND (line_lead IS NULL OR line_lead<>?) "
                       "AND created_at>=? AND created_at<=? AND cmd_meta IS NOT NULL AND instr(cmd_meta, ?)>0 AND status NOT IN "
                       "('pending_approval','held','denied','refused','expired','superseded','cancelled','failed','mismatch') LIMIT 1",
                       (acc["id"], x["agent_id"], x["rid"], gid, gid, t0 - WINDOW_S, t0, '"klyuch_h": "%s"' % h))
    if prior is None:
        return dict(out, why_not=ONCE_FIRST % "; ".join(a[len(PREFIX):] for a in atoms)[:200], klyuch=atoms)
    L = ctx.hub.ledger(acc["id"])
    now = L.sync_now()
    if any(all(any(covers(c, at) for c in g["commands"]) for at in atoms) for _, g in _live(L, m["id"], meta.get("project"), now)):
        return dict(out, why_not=SAME_LIVE)
    days = term_days(atoms)
    o = dict(out, eligible=True, why_not=None, commands=list(atoms), project=meta["project"], mandate_id=m["id"], kind="klyuch",
             text=render(atoms, days), text_v=V, days=[days], default_days=days, max_days=days, klyuch=atoms)
    return al._narrow(ctx, acc, x, meta, o)


def text_of_rule(commands, nbf, exp):
    """The text a key rule signed (listing): rebuilt from its keys and term (the term offered: the text names it)."""
    return render(commands, term_days(commands))
