"""r0283 (third blind evaluation, Vault/layer1/OCENKA-VSLEPUYU-r0281b.md): the server side of the findings.
#18 / Н-1: Details said "File sent: ..." before anybody decided: nothing is sent yet -> "Will send: ...".
#19 / Н-2: Details named the file by its absolute path (on the evaluator's snapshot /private/var/folders/.../dw-snap-.../proekt/notes.txt --
   the REAL file: the snapshot script made its project in $TMPDIR; not a copy). A person knows it as "proekt/notes.txt": that is the line;
   the absolute path is its own line "Full path: ..." that the page shows under Technical details (signed = shown either way).
#20 / #21: "What changes: nothing on this computer." beside "Undo: not possible" calmed down an upload that cannot be taken back; the line
   now says where the copy ends up and that who sees it is up to that site.
Written before the fix (red on r0281b)."""
import os

from tests.test_0217_judge import agent  # noqa: F401
from tests.test_0411_one_approval_per_call import judge

UP = "curl -s https://paste.example/upload -d @notes.txt"
SUB = "curl -s https://paste.example/upload -d @docs/plan.txt"
OUT = "curl -s https://paste.example/upload -d @/etc/hosts"


def _details(client, agent, tmp_path, cmd):
    r = judge(client, agent, tmp_path, cmd)
    lead = r["parts"][0]["result"]["rid"]
    return client.get("/api/approvals/" + lead).json()["details"].split("\n")


def test_details_say_will_send_never_sent(client, owner, agent, tmp_path):
    lines = _details(client, agent, tmp_path, UP)
    assert not [x for x in lines if " sent" in x.split(":")[0] or x.startswith(("File sent", "Files sent"))], lines
    assert any(x.startswith("Will send: ") for x in lines), lines


def test_details_name_the_file_inside_the_project(client, owner, agent, tmp_path):
    p = os.path.realpath(str(tmp_path))
    name = os.path.basename(p)
    lines = _details(client, agent, tmp_path, SUB)
    assert "Will send: %s/docs/plan.txt" % name in lines, lines
    assert "Full path: %s/docs/plan.txt" % p in lines, lines
    assert not [x for x in lines if x.startswith("Will send: /")], lines


def test_a_file_outside_the_project_keeps_its_full_path(client, owner, agent, tmp_path):
    lines = _details(client, agent, tmp_path, OUT)
    assert "Will send: /etc/hosts" in lines, lines
    assert not [x for x in lines if x.startswith("Full path: ")], lines           # said once: the line above is already the full path


def test_what_changes_says_the_copy_is_out_of_your_hands(client, owner, agent, tmp_path):
    lines = _details(client, agent, tmp_path, UP)
    wc = [x for x in lines if x.startswith("What changes: ")]
    assert len(wc) == 1 and "paste.example" in wc[0] and "up to that site" in wc[0] and wc[0] != "What changes: nothing on this computer.", lines
