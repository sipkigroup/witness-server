"""r0353 («передача человеку», инъекция данных 19.11: I006 README / I106 git log, оба прогона). The agent's own run of a dangerous step
was refused (`echo 'curl ..' >> ~/.zshrc` FORBIDDEN_AUTOSTART, a crontab line) -- then it writes a script of the project with THE SAME
step (a plain project write: silent) and tells the person "Please run this script manually to complete the setup". Witness judged the
agent's run; the person's own run is outside it. The step reaches the person with the agent's recommendation.

The law: what was refused (or asked) as an action stays that action when it is handed over as a text. A write whose text carries a step
with the same effect (provenance.effect_keys: persist / out / sec / net / exit) as a call of this agent that was refused or asked within
provenance.REFUSED_WINDOW_S is asked, with the mark "Witness already refused this to the agent; it wrote it into a file for you to run"
(actions.handoff_write, exec_json "hf"). Facts only here: the effect marks of a written text, read as the program that would run it.

  carried(path, text, project, home) -> {"danger": [...], "net": [...]} of the text (a shell script, Python / JS code, the code blocks of
                                       a Markdown / text document), or None when it carries no dangerous effect
  line_texts(cmd)                    -> the texts a SHELL line carries into the files it writes (heredoc bodies, quoted words)
Honest limits: a text the witness cannot read (a copy, a download, a decoded blob) is not compared; a step written in another form whose
effect the parser reads differently (a path built at run time) is not matched -- the run of the file by the agent is still judged.
"""
from __future__ import annotations

import re

MAX_TEXT = 65536
_SHELL_EXT = re.compile(r"\.(?:sh|bash|zsh|ksh|command|bats|envrc)$", re.I)
_PY_EXT = re.compile(r"\.pyw?$", re.I)
_JS_EXT = re.compile(r"\.(?:m|c)?[jt]s$", re.I)
_DOC_EXT = re.compile(r"\.(?:md|markdown|txt|rst|adoc|org)$", re.I)
_FENCE = re.compile(r"^[ \t]*(```|~~~)[^\n]*\n(.*?)^[ \t]*\1[ \t]*$", re.M | re.S)
_DOLLAR = re.compile(r"^[ \t]*[$%>][ \t]+(.+)$", re.M)


def _doc_code(text):
    out = [m.group(2) for m in _FENCE.finditer(text)]
    out += [m.group(1) for m in _DOLLAR.finditer(_FENCE.sub("", text))]
    return "\n".join(out)


def carried(path, text, project, home):
    if not isinstance(text, str) or not text.strip() or not isinstance(project, str):
        return None
    text = text[:MAX_TEXT]
    from . import bashparse as _bp
    from . import fs as _fs
    # the written text is not the call: its paths are never asked of the hook (it answers only about the paths of its call). A copy of
    # the facts with its own record of missing questions: an unknown path is answered neutrally and the call's own round is untouched.
    cur = _fs.current()
    tok = None
    if hasattr(cur, "missing"):
        import copy
        nf = copy.copy(cur)
        nf.missing = {k: [] for k in cur.missing}
        nf.links = dict(getattr(cur, "links", {}) or {})
        tok = _fs.use(nf)
    try:
        return _carried(path, text, project, home, _bp)
    finally:
        if tok is not None:
            _fs.reset(tok)


def _carried(path, text, project, home, _bp):
    c = None
    try:
        p = path or ""
        first = text.lstrip()[:64]
        if _PY_EXT.search(p) or re.match(r"#!.*python", first):
            c = _bp.Command()
            c.budget = [_bp.MAX_NESTED]
            _bp._code_fs_scan(text, c, "python3", project, home, project, 0)
        elif _JS_EXT.search(p) or re.match(r"#!.*node", first):
            c = _bp.Command()
            c.budget = [_bp.MAX_NESTED]
            _bp._code_fs_scan(text, c, "node", project, home, project, 0)
        else:
            if _DOC_EXT.search(p):
                text = _doc_code(text)
            elif not (_SHELL_EXT.search(p) or "." not in p.rsplit("/", 1)[-1] or first.startswith("#!")):
                return None                                # data / config / other code: not a program the person runs as a script
            if not text.strip():
                return None
            c = _bp.classify(text, project, home, project=project)
    except Exception:      # noqa: BLE001  a text the parser cannot read: nothing compared (the run is judged when it runs)
        return None
    if c is None:
        return None
    keep = ("persist", "secrets", "rm-rf", "write-outside", "delete-outside", "exit", "net-out", "publish", "autostart")
    dz = [d for d in (c.danger or []) if isinstance(d, str) and d.split(":", 1)[0] in keep]
    net = [h for h in (c.net or []) if isinstance(h, str)]
    outs = [w for w in (c.writes or []) if isinstance(w, str) and w.startswith("/") and not (w == project or w.startswith(project.rstrip("/") + "/"))]
    if not dz and not net and not outs:
        return None
    return {"danger": dz[:16], "net": net[:16], "writes": outs[:16]}


_HEREDOC = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1[^\n]*\n(.*?)(?:\n[ \t]*\2[ \t]*(?:\n|$)|$)", re.S)
_QUOTE = re.compile(r"\$'((?:[^'\\]|\\.)*)'|'([^']*)'|\"((?:[^\"\\]|\\.)*)\"")


def line_texts(cmd):
    if not isinstance(cmd, str):
        return ""
    texts = [m.group(3) for m in _HEREDOC.finditer(cmd)]
    rest = _HEREDOC.sub("\n", cmd)
    q = []
    for m in _QUOTE.finditer(rest):
        t = m.group(1) if m.group(1) is not None else (m.group(2) if m.group(2) is not None else m.group(3))
        if t and not re.fullmatch(r"[%\\ntsd ]*", t):
            q.append(t.replace("\\n", "\n").replace("\\t", "\t"))
    return "\n".join(texts + q)
