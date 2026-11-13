"""13.11 (r0280, vorota stage 1b, task 3): od / hexdump / strings / xxd are on the read-only list (r0265, 95 commands; web
readonly.test.mjs). They only read (xxd IN OUT writes OUT: tagged "write" and asked, test_1211_r0265). Reading a SECRET through them is
another layer: the line must be judged as a read of a secret, exactly as `cat` of the same file -- never silent because the program is
listed. PRED is written before each check."""
import pytest

from tests.test_0611_popravki import _mk, _v
from tests.test_1211_r0263e_bez_tihogo import _dangers, _send


def _out(got):
    if any(r["verdict"] == "deny" for _, r in got):
        return "refused"
    return "silent" if all(r["verdict"] == "allow" for _, r in got) else "asked"


def _dev(client, owner, tmp_path):
    d = _mk(client, owner, tmp_path, "dump")
    open(str(d.proj) + "/.env", "w").write("API_KEY=fake-0280-1234567890abcdef\n")
    open(str(d.proj) + "/README.md", "w").write("hello\n")
    return d


DUMPS = ["xxd .env", "od -c .env", "hexdump -C .env", "strings .env", "xxd -l 64 .env | head", "strings .env | head -3",
         "od -An -tx1 .env | tr -d ' '"]


@pytest.mark.parametrize("cmd", DUMPS)
def test_dump_of_a_secret_is_a_secret_read(client, owner, tmp_path, cmd):
    d = _dev(client, owner, tmp_path)
    PRED = True                                       # the parser marks the line as a read of a secret
    assert any(str(x).startswith("secrets:") for x in _dangers(d, cmd)) == PRED, _dangers(d, cmd)
    got = _send(d, cmd)
    PRED = "silent"
    assert _out(got) != PRED, (cmd, _v(got))          # never silent because the program is on the read-only list
    PRED = _out(_send(d, "cat .env"))                 # judged exactly as `cat` of the same file
    assert _out(got) == PRED, (cmd, _v(got))


@pytest.mark.parametrize("cmd", ["xxd README.md | head", "strings README.md | head -3", "od -c README.md", "hexdump -C README.md"])
def test_dump_of_a_plain_file_stays_silent(client, owner, tmp_path, cmd):
    d = _dev(client, owner, tmp_path)
    PRED = "silent"                                   # the twin: a plain project file through the same programs (r0265 Н4)
    assert _out(_send(d, cmd)) == PRED, (cmd, _v(_send(d, cmd)))
