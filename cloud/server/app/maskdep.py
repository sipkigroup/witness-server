"""29.10 MDEP (cloud/RT-MASKA-UKRYTIE-2910.md p.3, OTCHET-MASKA-TIP-2910.md "p.4"): the witness asks a person BECAUSE it could not resolve
an address or a command (a curl to a host from a variable, an eval, a host built at run time, a file the agent wrote and now runs, a git hook,
an argument of the account's own tool map), and the value that would answer it sits under a name the preview masks (AUTH_URL, token_url,
passthrough_cmd, oauth_redirect_uri ...). The page then says so in one line: "This decision depends on a masked value: AUTH_URL".

masked_dep(tool, recipient, answer) -> the masked NAMES (never values) the question depends on, in the order they appear, or [].
It reads only what the page shows (the masked previews of the answer), so it reveals nothing the page does not already show (the names are
on the page) and the page's view binds it like any other member (signview.KEYS "masked_dep"; absent when empty = the view as before).

  * code the person must read (the text of a Bash question whose reason is opaque:/secrets:/[eval], net_code, the text of a *.danger
    write such as a git hook, the agent's writes a held run executes, the hook's previews of changed executed files): a name assigned a
    masked value (NAME=[masked...], NAME = [masked...], "NAME": "[masked...]") AND used elsewhere in the same text ($NAME, ${NAME},
    $(NAME), NAME as a word);
  * the arguments of any other tool (an MCP / own map): a key whose value is masked whole and is an address or a command (a typed marker
    `[masked URL host=...]` / `[masked command: ...]`, or a key named like one: url, uri, endpoint, host, redirect, callback, hook, cmd ...).
A name is reported only when it is masked BY ITS NAME (password/secret/token/key/auth), as the masking rule does."""
import re

from .toolmap import MASK_MARK, SECRET_KEY_RE, shell_tool

MAX_NAMES = 16
_ASSIGN = re.compile(r"""(?<![A-Za-z0-9_.\-])(?:\\"|["'])?([A-Za-z_][A-Za-z0-9_]{0,63})(?:\\"|["'])?\]?[ \t]*[=:][ \t]*(?:\\"|["'])?"""
                     + MASK_MARK)
_ARG = re.compile(r'(?<![\\A-Za-z0-9_.\-])"([A-Za-z_][A-Za-z0-9_.\-]{0,63})": ?"(' + MASK_MARK + r')"')
_ADDR_KEY = re.compile(r"(?i)(url|uri|endpoint|host|domain|redirect|callback|hook|cmd|command|exec|script)")
_TYPED = re.compile(r"\[masked (?:URL|command)")


def _uses(text):
    """-> the masked-by-name names assigned in `text` that the same text also uses."""
    out, spans = [], {}
    for m in _ASSIGN.finditer(text):
        n = m.group(1)
        if SECRET_KEY_RE.search(n):
            spans.setdefault(n, []).append(m.span(1))
    for n, own in spans.items():
        for u in re.finditer(r"(?<![A-Za-z0-9_])" + re.escape(n) + r"(?![A-Za-z0-9_])", text):
            if u.span() not in own:
                out.append((own[0][0], n))
                break
    return [n for _, n in sorted(out)]


def masked_dep(tool, recipient, ans):
    texts = []
    rc = recipient if isinstance(recipient, str) else ""
    if shell_tool(tool):
        if rc.startswith(("opaque:", "secrets:")) or rc.endswith("[eval]"):
            texts.append(ans.get("text_preview"))
    elif isinstance(tool, str) and tool.endswith(".danger"):
        texts.append(ans.get("text_preview"))
    texts.append(ans.get("net_code"))
    wr = ans.get("written_run")
    if isinstance(wr, dict):
        texts += [w.get("text") for w in wr.get("writes") or [] if isinstance(w, dict)]
    rk = (ans.get("exec_changed") or {}).get("risk") if isinstance(ans.get("exec_changed"), dict) else None
    if isinstance(rk, dict):
        texts += [f.get("preview") for f in rk.get("files") or [] if isinstance(f, dict)]
    names = []
    for t in texts:
        if isinstance(t, str) and "[masked" in t:
            names += _uses(t)
    ap = ans.get("args_preview")
    if not shell_tool(tool) and isinstance(ap, str) and "[masked" in ap:
        for m in _ARG.finditer(ap):
            k = m.group(1)
            if SECRET_KEY_RE.search(k) and (_TYPED.match(m.group(2)) or _ADDR_KEY.search(k)):
                names.append(k)
    out = []
    for n in names:
        if n not in out:
            out.append(n)
    return out[:MAX_NAMES]
