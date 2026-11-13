"""0.2.16 (thin client): the few questions the command classifier asks about the user's file system, behind one seam.

Since 0.2.16 the classifier runs on the SERVER, which does not see the user's machine. Every file-system question it asks goes through
`current()`:
  LocalFS  - the machine this code runs on (tests, the fatigue harness, and anything that calls map_event/classify directly);
  FactsFS  - answers from the facts the thin hook sent (POST /v1/hook/judge). A question it has no answer for is RECORDED and answered
             with a neutral placeholder; the judge then throws the whole result away and asks the hook for the missing facts
             (`need`), and classifies again from the start with them. So a decision is only ever made from complete facts, and it is the
             same decision the 0.2.15 hook made on the user's machine (the questions are the same os.path calls, asked of the same file
             system, by the hook instead of in-process).
Questions: realpath(p), isdir(p), exists(p), the process cwd, the user's home, and the project's executed-file report (scan).
0.2.53 (red team): gitref(top, ref) - what switching the repository at `top` to `ref` would rewrite (gitref.py). A hook that sends no
`fs.gitref` at all (older than 0.2.37) is not asked: the answer is None, "unknown", and the switch is asked of the owner.
0.2.73 (N13, polygon series 9): realpath(p) of a hard link of a credential file is THAT file (the hook's fact `fs.samefile`, samefile.py):
`cat h3.txt` / Read h3.txt is judged as reading .env. archive(p): the links an extraction makes (`fs.archive`, archlinks.py); a hook that
sends no `fs.archive` (older than 0.2.49) is not asked (None: the extraction stays the question it was). note(p): what a path judged as a
credential file was called in the call ("h3.txt, a hard link of it"), for the page."""
from __future__ import annotations

import contextvars
import os
import posixpath

MAX_QUESTIONS = 4096          # per round; more -> the judge refuses the event (EVENT_TOO_LARGE), never decides on placeholders
MAX_PATH = 4096


LOCAL_WHICH = None            # 0.2.89, TESTS ONLY: the `which` fact LocalFS reports ({name: realpath | None})
LOCAL_GIT_SELF = None                                # 0.2.95: the SHA-256 of the person's git user.email (tests set it)
LOCAL_SANDBOX = None          # V3, TESTS ONLY: the sandbox fact LocalFS reports (a dict as the hook sends it)
LOCAL_HARNESS = None          # 06.11, TESTS ONLY: the hook's K1 finding LocalFS reports (str) and whether the hook found it sandbox-held
LOCAL_HARNESS_HELD = False
LOCAL_SESSION = None          # 06.11, TESTS ONLY: the session id LocalFS reports (the hook's `session_id`)


_ROOT = contextvars.ContextVar("dw_hook_root", default=None)     # LocalFS: (project root, samefile.Secrets, {credential: link}) of one event


def hint_root(root, home):
    """LocalFS only (tests, the fatigue harness): the project root the hook would walk for samefile (mapping.map_event sets it per event)."""
    from . import samefile
    from .bashparse import is_secret_path
    return _ROOT.set((root, samefile.Secrets(root, home, is_secret_path, protected=True), {}))     # 0.2.77 (H3): as the hook 0.2.51


def reset_root(tok):
    _ROOT.reset(tok)


class LocalFS:
    """The machine this code runs on (what the 0.2.15 hook did in-process)."""

    def realpath(self, p):
        r = os.path.realpath(p)
        h = _ROOT.get()
        if h is not None:
            try:
                a = h[1].alias(r)
            except Exception:      # noqa: BLE001
                a = None
            if a is not None:
                h[2].setdefault(a, p)
                return a
        return r

    def note(self, p):
        h = _ROOT.get()
        return h[2].get(p) if h is not None else None

    def archive(self, p):
        from . import archlinks
        return archlinks.answer(p)

    def isdir(self, p):
        return os.path.isdir(p)

    def exists(self, p):
        return os.path.exists(p)

    def getcwd(self):
        return os.getcwd()

    def home(self):
        return os.path.expanduser("~")

    def gitref(self, top, ref):
        from . import gitref
        return gitref.answer(top, ref, avoid=(top,))

    def sandbox(self):
        return LOCAL_SANDBOX                             # V3: tests and the fatigue harness set it; None = no fact (asked as before)

    def harness(self):
        return LOCAL_HARNESS                             # 0.2.91: no hook, no K1 finding (tests may set one)

    def harness_held(self):
        return LOCAL_HARNESS_HELD is True

    def session(self):
        return LOCAL_SESSION

    def which(self):
        return LOCAL_WHICH                               # 0.2.89: tests set it; None = no fact (EXEC_CHANGED asks as before)

    def git_self(self):
        return LOCAL_GIT_SELF                            # 0.2.95: tests set it; None = no fact

    def shadow(self, p):
        """0.2.90: tests / the fatigue harness: a shadow copy of `p` under the temp dir (what the hook does on the user's machine)."""
        import hashlib
        import shutil
        import tempfile
        try:
            if not os.path.exists(p):
                return {"absent": True}
            if not os.path.isfile(p) or os.path.islink(p):
                return {"failed": "not a regular file"}
            d = os.path.join(tempfile.gettempdir(), "deus-witness-shadow-local")
            os.makedirs(d, exist_ok=True)
            h = hashlib.sha256(open(p, "rb").read()).hexdigest()
            dst = os.path.join(d, h[:16] + "-" + os.path.basename(p))
            shutil.copy2(p, dst)
            return {"copy": dst, "sha256": h, "size": os.path.getsize(p)}
        except OSError as e:
            return {"failed": str(e)[:80]}

    def scan(self, root):
        from . import execfiles
        rep = execfiles.scan(root)
        if rep is not None and rep.get("git"):           # 0.2.46: the program keys of git's config (what the 0.2.46 hook adds to its report)
            rep["gitcfg"], cut = execfiles.git_config_programs(root)
            if cut:
                rep["gitcfg_cut"] = True
            from . import samefile
            gd, common = execfiles._git_dirs(root)        # 0.2.77c (round 2b): as the hook: global / system / included core.hooksPath
            seeds = [os.path.join(b, n) for b in dict.fromkeys((gd, common)) if b for n in ("config", "config.worktree")]
            hp = samefile.global_hooks_values(self.home(), dict(os.environ), execfiles.read_git_config, seeds=seeds)
            if hp:
                rep["hookspath"] = hp
        return rep


class FactsFS:
    """Answers from the hook's facts; records what is missing (`need()`)."""

    def __init__(self, facts: dict):
        fs = facts.get("fs") or {}
        self.rp = fs.get("realpath") or {}
        self.dirs = fs.get("isdir") or {}
        self.ex = fs.get("exists") or {}
        self.cwd = facts.get("proc_cwd")
        self.h = facts.get("home")
        self.report = facts.get("exec")
        self.sb = facts.get("sandbox")                   # V3: None = an older hook or no fact
        self.hz = facts.get("harness") if isinstance(facts.get("harness"), str) else None   # 0.2.91: the hook's K1 finding (asked)
        self.hzh = facts.get("harness_held") is True     # 06.11 (law 2): the hook found it only where the strict sandbox holds the place
        self.wh = facts.get("which") if isinstance(facts.get("which"), dict) else None     # 0.2.89: None = an older hook or no fact
        self.gself = facts.get("git_self") if isinstance(facts.get("git_self"), list) else None   # 0.2.95: SHA-256 of git user.email
        self.refs = fs.get("gitref") if isinstance(fs.get("gitref"), dict) else None     # None: an older hook, which cannot answer
        self.same = fs.get("samefile") if isinstance(fs.get("samefile"), dict) else {}     # 0.2.73 (N13)
        self.arch = fs.get("archive") if isinstance(fs.get("archive"), dict) else None     # None: a hook older than 0.2.49 (never asked)
        self.shad = fs.get("shadow") if isinstance(fs.get("shadow"), dict) else None       # 0.2.90: None: a hook older than 0.2.58 (never asked)
        self.links = {}                                  # {credential file: the path of the call that is a hard link of it}
        self.missing = {"realpath": [], "isdir": [], "exists": [], "gitref": [], "archive": [], "shadow": []}
        self.scan_root = None
        self.n = 0

    def _miss(self, kind, p):
        lst = self.missing[kind]
        if p not in lst:
            self.n += 1
            lst.append(p)

    def realpath(self, p):
        v = self.rp.get(p)
        if isinstance(v, str):
            a = self.same.get(p)
            if isinstance(a, str) and a:
                self.links.setdefault(a, p)
                return a                                 # 0.2.73 (N13): the hard link IS the credential file
            return v
        if not _made_up(p):
            self._miss("realpath", p)
        return posixpath.normpath(p)

    def isdir(self, p):
        v = self.dirs.get(p)
        if isinstance(v, bool):
            return v
        if not _made_up(p):
            self._miss("isdir", p)
        return False

    def exists(self, p):
        v = self.ex.get(p)
        if isinstance(v, bool):
            return v
        if not _made_up(p):
            self._miss("exists", p)
        return False

    def gitref(self, top, ref):
        if self.refs is None or "\n" in ref:
            return None
        k = top + "\n" + ref
        if k in self.refs:
            v = self.refs[k]
            return v if isinstance(v, dict) else None
        if not _made_up(top) and [top, ref] not in self.missing["gitref"]:
            self.n += 1
            self.missing["gitref"].append([top, ref])
        return None

    def note(self, p):
        return self.links.get(p)

    def archive(self, p):
        if self.arch is None or not isinstance(p, str):
            return None
        if p in self.arch:
            v = self.arch[p]
            return v if isinstance(v, dict) else None
        if not _made_up(p) and p not in self.missing["archive"]:
            self.n += 1
            self.missing["archive"].append(p)
        return None

    def shadow(self, p):
        """0.2.90: the hook's shadow copy of `p` (taken before the call runs): {"copy", "sha256", "size"} | {"absent": true} | {"failed"};
        an older hook (no `shadow` in its facts) cannot copy: {"failed": "hook"} (the write is asked, never refused RESOURCE for that)."""
        if self.shad is None or not isinstance(p, str):
            return {"failed": "hook"}
        if p in self.shad:
            v = self.shad[p]
            return v if isinstance(v, dict) else {"failed": "copy"}
        if not _made_up(p) and p not in self.missing["shadow"]:
            self.n += 1
            self.missing["shadow"].append(p)
        return None

    def getcwd(self):
        return self.cwd

    def sandbox(self):
        return self.sb

    def harness(self):
        return self.hz

    def harness_held(self):
        return self.hzh

    def session(self):
        return getattr(self, "sid", None)            # 06.11 (law 2): set by judge.classify_event from the request's session_id

    def which(self):
        return self.wh

    def git_self(self):
        return self.gself

    def home(self):
        return self.h

    def scan(self, root):
        r = self.report
        if isinstance(r, dict) and r.get("root") == root:
            return None if r.get("none") else r          # "none": the hook looked and the root is not a directory it can walk
        if r == "off":
            return None
        self.scan_root = root
        self.n += 1
        return None

    def complete(self) -> bool:
        return self.n == 0

    def need(self) -> dict:
        out = {k: v for k, v in self.missing.items() if v}
        # the root may be a placeholder while paths are unresolved: then scan last; a root the hook itself resolved (it sends the realpath of
        # the project directory with every call) is asked at once, with the other questions
        if self.scan_root is not None and (not out or self.scan_root in self.rp.values()):
            out["scan"] = self.scan_root
        return out


def _made_up(p) -> bool:
    """0.2.17 (R9-05): a path under the classifier's own "unknown directory" (bashparse.LOST_CWD) exists on no machine: answered here (as
    os.path.realpath / isdir / exists answer for a path that does not exist), never asked of the hook, which answers only about the paths of
    its call and does not know the classifier's names."""
    from .bashparse import LOST_CWD
    return isinstance(p, str) and (p == LOST_CWD or p.startswith(LOST_CWD + "/"))


_CUR = contextvars.ContextVar("dw_hook_fs", default=None)
_LOCAL = LocalFS()


def current():
    return _CUR.get() or _LOCAL


def use(fs):
    """-> token; `reset(token)` restores the previous one."""
    return _CUR.set(fs)


def reset(token):
    _CUR.reset(token)
