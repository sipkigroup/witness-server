"""0.2.25 (OTCHET-0.2.24, objection 2): a server-side safety net for mandates signed with the older default domains (github.com,
raw.githubusercontent.com were listed until 0.2.24, the client prints its own copy of the list).

A call the mandate ALLOWS is HELD for the owner (ESCALATE_USER_CONTENT_HOST, released with a passkey like any hold) when it goes to:
  - a host where anyone can PUBLISH content or read what was sent (github.com, gists, raw.githubusercontent.com, pastebins, webhooks ...)
    and the call carries data in the request: a query string, or (a shell line) an upload / body flag of curl / wget / httpie;
  - a request catcher or a tunnel (webhook.site, *.ngrok.io, *.oast.fun, *.workers.dev ...): any request, the path alone carries data there.
Only tightens: the core's deny stays deny, a defer stays the owner's question. The host lists live only on the server (not sent to clients)."""
import re
from urllib.parse import urlsplit

# exact host or any subdomain of it ("github.com" also covers "gist.github.com"; docs.github.com is excluded below)
USER_CONTENT = ("github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "codeberg.org", "pastebin.com", "paste.ee",
                "hastebin.com", "toptal.com", "dpaste.org", "dpaste.com", "rentry.co", "rentry.org", "ghostbin.co", "termbin.com",
                "ix.io", "0x0.st", "transfer.sh", "file.io", "catbox.moe", "discord.com", "discordapp.com", "hooks.slack.com",
                "api.telegram.org", "docs.google.com", "forms.gle", "sheets.googleapis.com", "notion.so", "huggingface.co")
NOT_USER_CONTENT = ("docs.github.com", "docs.gitlab.com")         # documentation only: nobody can publish there
CATCHERS = ("webhook.site", "requestbin.com", "requestbin.net", "pipedream.net", "requestcatcher.com", "beeceptor.com", "mockbin.org",
            "hookbin.com", "interact.sh", "oast.fun", "oast.live", "oast.me", "oast.online", "oast.pro", "oast.site", "oastify.com",
            "burpcollaborator.net", "canarytokens.com", "dnslog.cn", "ceye.io", "ngrok.io", "ngrok.app", "ngrok-free.app", "ngrok.dev",
            "trycloudflare.com", "loca.lt", "localtunnel.me", "serveo.net", "localhost.run", "workers.dev", "pages.dev", "github.io",
            "gitlab.io", "vercel.app", "netlify.app", "herokuapp.com", "glitch.me", "repl.co", "replit.dev", "deno.dev", "fly.dev",
            "onrender.com", "surge.sh")
CODE = "ESCALATE_USER_CONTENT_HOST"
CODE_UNSEEN = "ESCALATE_NET_UNSEEN"
CODE_UNSPECIFIED = "ESCALATE_EGRESS_UNSPECIFIED"       # 0.2.90: the mandate names no destinations at all (no message class): held
_LOOPBACK = re.compile(r"^(localhost|127(\.\d{1,3}){3}|::1|\[::1\]|0\.0\.0\.0|[^.]+\.local(host)?)$", re.I)


def non_loopback(recipient) -> bool:
    """`webfetch@<host>` / `websearch@<host>` of a disclosure action -> True when the host is not the machine itself."""
    if not isinstance(recipient, str) or "@" not in recipient:
        return False
    host = recipient.rsplit("@", 1)[-1].strip("[]").lower()
    return bool(host) and _LOOPBACK.match(host) is None
# 0.2.25: network programs; a listed one whose destination the line does not show (curl -K cfg, wget -i urls.txt) is held (CODE_UNSEEN)
NET_TOOLS = ("curl", "wget", "http", "https", "xh", "xhs", "aria2c", "nc", "ncat", "netcat", "socat", "telnet")
# curl / wget / httpie flags that put data into the request (a body, a form, an uploaded file, a non-GET method)
_UPLOAD = re.compile(r"(?:^|\s)(?:-d|--data(?:-[a-z]+)?|-F|--form(?:-string)?|-T|--upload-file|--json|--post-data|--post-file|--body-data|"
                     r"--body-file|-X\s*(?:POST|PUT|PATCH)|--request\s*(?:POST|PUT|PATCH)|--method=(?:POST|PUT|PATCH))(?=[\s=@'\"]|$)", re.I)
_HTTPIE_DATA = re.compile(r"(?:^|\s)(?:https?|http)\s+(?:POST|PUT|PATCH)\b|(?:^|\s)[\w.-]+(?:=|:=|@)\S", re.I)


def _suffix(host, names):
    return any(host == n or host.endswith("." + n) for n in names)


def kind_of_host(host):
    """-> "catcher" | "user" | None for a lower-case host name."""
    if not isinstance(host, str) or not host:
        return None
    h = host.lower().rstrip(".")
    if _suffix(h, CATCHERS):
        return "catcher"
    if _suffix(h, NOT_USER_CONTENT):
        return None
    return "user" if _suffix(h, USER_CONTENT) else None


def _host_of(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def web_hold(url):
    """WebFetch: the URL -> True when it must be held."""
    if not isinstance(url, str):
        return False
    k = kind_of_host(_host_of(url))
    if k == "catcher":
        return True
    if k == "user":
        try:
            return bool(urlsplit(url).query)
        except ValueError:
            return True
    return False


def bash_hold(args):
    """Bash.net: the hosts the classifier found (`_witness.net` = ["webfetch@host"]) and the command line -> True when it must be held.
    The line is not split per URL: a `?` anywhere in a line that talks to a user-content host is enough (a hold, not a refusal)."""
    w = args.get("_witness") if isinstance(args, dict) else None
    net = w.get("net") if isinstance(w, dict) else None
    if not isinstance(net, list):
        return False
    kinds = {kind_of_host(n.split("@", 1)[1] if isinstance(n, str) and "@" in n else n) for n in net}
    if "catcher" in kinds:
        return True
    if "user" not in kinds:
        return False
    cmd = args.get("command") if isinstance(args.get("command"), str) else ""
    heads = w.get("commands") if isinstance(w.get("commands"), list) else []
    httpie = any(isinstance(h, str) and h.split()[0].rsplit("/", 1)[-1] in ("http", "https", "xh", "xhs") for h in heads if h)
    return "?" in cmd or bool(_UPLOAD.search(cmd)) or (httpie and bool(_HTTPIE_DATA.search(cmd)))


def unseen_net(args):
    """A shell line that runs a network program while the classifier found no destination in it (the URL comes from a file or a variable
    the line does not show): the witness cannot judge where the data goes."""
    w = args.get("_witness") if isinstance(args, dict) else None
    if not isinstance(w, dict) or w.get("net"):
        return False
    heads = w.get("commands") if isinstance(w.get("commands"), list) else []
    return any(isinstance(h, str) and h.split() and h.split()[0].rsplit("/", 1)[-1] in NET_TOOLS for h in heads)


# 06.11 (Constitution v1, П6 / Н2): a request the mandate's domains allow is still held when
#  - it carries data AND follows redirects (curl -L / --location, wget by default, httpie --follow): a 307 / 308 sends the same body to a
#    host the line does not name, "a redirect to another host = a new address" (П6) -> CODE_UNSEEN;
#  - it uploads a FILE (curl -d @f, -F k=@f, -T f, --data-urlencode k@f, wget --post-file): the witness never reads that content, so the
#    secret scan every exit needs (Н2) cannot run on it -> ESCALATE_DATA (the owner sees the file name).
_FOLLOW = re.compile(r"(?:^|\s)(?:-[a-zA-Z]*L[a-zA-Z]*|--location(?:-trusted)?)(?=\s|$)")         # curl
_FOLLOW_HTTPIE = re.compile(r"(?:^|\s)(?:--follow|-[a-zA-Z]*F[a-zA-Z]*)(?=\s|$)")                     # httpie / xh
_FILE_UP = re.compile(r"(?:^|\s)(?:(?:-d|--data(?:-binary|-ascii)?|--json)(?:\s+|=)?['\"]?@|(?:-F|--form)(?:\s+|=)?['\"]?[^\s'\"=]*=[@<]|"
                      r"--data-urlencode(?:\s+|=)?['\"]?[^\s'\"=@]*@|-T\s*\S|--upload-file[\s=]|--post-file[\s=]|--body-file[\s=])")
CODE_DATA = "ESCALATE_DATA"


def bash_upload_hold(args):
    """Bash.net allowed by the domains -> None, CODE_UNSEEN (data + redirects) or CODE_DATA (a file upload the witness cannot scan)."""
    w = args.get("_witness") if isinstance(args, dict) else None
    cmd = args.get("command") if isinstance(args, dict) and isinstance(args.get("command"), str) else ""
    heads = w.get("commands") if isinstance(w, dict) and isinstance(w.get("commands"), list) else []
    names = {h.split()[0].rsplit("/", 1)[-1] for h in heads if isinstance(h, str) and h.split()}
    data = bool(_UPLOAD.search(cmd)) or ("http" in names or "https" in names or "xh" in names) and bool(_HTTPIE_DATA.search(cmd))
    if not data:
        return None
    if _FILE_UP.search(cmd):
        return CODE_DATA
    follows = ("curl" in names and bool(_FOLLOW.search(cmd))) or bool(names & {"http", "https", "xh", "xhs"} and _FOLLOW_HTTPIE.search(cmd))
    if "wget" in names and not re.search(r"--max-redirect[=\s]+0\b", cmd):
        follows = True
    return CODE_UNSEEN if follows else None


def hold(tool, act, args):
    """-> None or the code with which a call the mandate would allow must be held for the owner."""
    if not isinstance(args, dict):
        return None
    if tool == "WebFetch":
        return CODE if web_hold(args.get("url")) else None
    if tool == "Bash.net":
        return CODE if bash_hold(args) else bash_upload_hold(args)
    if tool == "Bash" and isinstance(act, dict) and act.get("class") == "command" and unseen_net(args):
        return CODE_UNSEEN
    return None
