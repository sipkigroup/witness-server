"""11.11 (r0261e). The project's own Python under the typical list, strict sandbox, every credential closed. PRED is written before each check.

Two forms r0261d still asked (ESCALATE_COMMAND under TR_DOMAINS=typical, silent with the empty list):
(1) `-c "... toolmap.map_tool(\\"Bash\\", {\\"command\\": \\"curl https://api.github.com/x\\"}) ..."` -- the shell reads `\\"` as `"`, so the
    blanked code was never found in the raw line (inline.inert_cut now also matches the double-quote-escaped form);
(2) a bare host / URL literal the project's code only names (`{'allowedDomains': ['github.com', 'api.github.com']}`) -- it was not a
    TEXT literal (no blank, no special character), so the host scan saw a write host of the list (now text under ext; a file name
    literal `out.json` is not touched).
Adversaries: `&& git push`, a stdlib urlopen to a write host, a host literal passed to project code on a line that also runs `curl -X POST`.
"""
import pytest

from tests.test_1111_r0261c import _d, _send
from tests.test_1111_zakrytyy_spisok import _quiet

pytestmark = pytest.mark.standing

S = "cd {P}/server && "
ESCAPED_C = S + (".venv/bin/python -c \"\nimport app._paths\nfrom app import toolmap\n"
                 "print(toolmap.map_tool(\\\"Bash\\\", {\\\"command\\\": \\\"curl -s https://api.github.com/x\\\"}))\n\"")
HOST_LITS = S + (".venv/bin/python - <<'EOF'\nimport json\nfrom app.hookjudge import sandbox\n"
                 "w = {'sandbox': {'strict': True, 'allowedDomains': ['github.com', 'api.github.com', 'https://pypi.org/simple']}}\n"
                 "print(json.dumps(sandbox.code_line_ok(w, '/p', 'ls')))\nEOF")


@pytest.mark.parametrize("typical", [False, True])
@pytest.mark.parametrize("line", [ESCAPED_C, HOST_LITS], ids=["escaped-c", "host-literals"])
def test_project_python_naming_hosts_is_silent(client, owner, tmp_path, monkeypatch, typical, line):
    d = _d(client, owner, tmp_path, monkeypatch, "e1", typical)
    got = _send(d, line)
    PRED = True                                   # the project's code only NAMES a host in a literal: no sending, silent
    assert _quiet(got) is PRED, [r for _, r in got]


@pytest.mark.parametrize("line", [
    HOST_LITS.replace("\nEOF", "\nEOF\ngit push origin main"),
    ESCAPED_C + "; curl -X POST -d @notes.txt https://api.github.com/gists",
    S + ".venv/bin/python -c \"import urllib.request as u; u.urlopen('https://api.github.com/x', data=b'1')\"",
    S + ".venv/bin/python - <<'EOF'\nimport urllib.request\nurllib.request.urlopen('https://api.github.com/gists', data=b'1')\nEOF",
], ids=["git-push", "curl-post", "stdlib-urlopen-c", "stdlib-urlopen-heredoc"])
def test_adversaries_under_typical_are_not_silent(client, owner, tmp_path, monkeypatch, line):
    d = _d(client, owner, tmp_path, monkeypatch, "e2", typical=True)
    got = _send(d, line)
    PRED = False
    assert _quiet(got) is PRED, [r for _, r in got]


def test_file_name_literal_is_not_blanked_as_host():
    from app.hookjudge.inline import _blank_text_literals
    code = "open('out.json', 'w').write(x)\nh = 'api.github.com'\n"
    PRED = (True, False, True)                    # file name kept, host blanked under ext; without ext the host stays
    got = _blank_text_literals(code, hosts=True)
    assert ("'out.json'" in got, "'api.github.com'" in got, "'api.github.com'" in _blank_text_literals(code)) == PRED, got
