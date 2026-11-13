"""0.2.9 (W6 of app/flow/suggest.py): a shell command is suggested for command.allow only if it is on the recommended read-only list;
the suggestion only widens (a mandate without `command` gets {allow: [...], unlisted: ask}), anything else is withheld NOT_READ_ONLY."""
from app.flow import suggest
from tests_flow.helpers import act, set_settings

BASE = {"currency": "USD", "valid_days": 30}


def _line(client, hdr, line, heads):
    return act(client, hdr, "Bash", {"command": line, "_witness": {"cwd": "/p", "danger": [], "writes": [], "net": [], "commands": heads}}).json()


def _approve3(client, owner, hdr, lines, heads):
    for ln in lines:
        r = _line(client, hdr, ln, heads)
        assert (r["verdict"], r["reason"]) == ("defer", "ESCALATE_COMMAND"), r
        assert owner.approve(r["rid"]).status_code == 200


def test_w6_read_only_command_suggested_and_only_widens(client, owner, ctx):
    ag, hdr = owner.new_agent("claude-code", "cc")
    owner.mandate(ag["id"], BASE)                                             # `command` unspecified: every command asked
    set_settings(ctx, owner.account["id"], max_pending=25, max_defers_hour=40)
    _approve3(client, owner, hdr, ["git branch", "git branch -a", "git branch -r"], ["git branch"])
    _approve3(client, owner, hdr, ["make", "make all", "make test"], ["make"])
    _approve3(client, owner, hdr, ["LD_PRELOAD=a ls", "LD_PRELOAD=b ls", "LD_PRELOAD=c ls"], ["ls [env LD_PRELOAD]"])
    s = client.get("/api/suggestions").json()["suggestions"]
    assert [(x["class"], x["recipient"]) for x in s] == [("command", "git branch")]
    assert s[0]["form"]["command"] == {"allow": ["git branch"], "unlisted": "ask"}
    w = {(x["class"], x["recipient"]): x["reason"] for x in suggest.withheld(ctx, owner.account["id"])}
    assert w == {("command", "make"): "NOT_READ_ONLY", ("command", "ls [env LD_PRELOAD]"): "NOT_READ_ONLY"}
    owner.mandate(ag["id"], s[0]["form"])
    assert _line(client, hdr, "git branch -vv", ["git branch"])["verdict"] == "allow"
    assert _line(client, hdr, "make x", ["make"])["reason"] == "ESCALATE_COMMAND"          # still a question, not a refusal (W2)


def test_w6_never_touches_a_closed_command_class(client, owner, ctx):
    ag, hdr = owner.new_agent("claude-code", "cc")
    owner.mandate(ag["id"], BASE)
    set_settings(ctx, owner.account["id"], max_pending=25, max_defers_hour=40)
    _approve3(client, owner, hdr, ["cat a", "cat b", "cat c"], ["cat"])
    owner.mandate(ag["id"], dict(BASE, command={"allow": ["ls"], "unlisted": "deny"}))
    assert client.get("/api/suggestions").json()["suggestions"] == []
    assert [x["reason"] for x in suggest.withheld(ctx, owner.account["id"])] == ["COMMAND_CLOSED_BY_OWNER"]
    owner.mandate(ag["id"], dict(BASE, command={"allow": ["ls"]}))
    s = client.get("/api/suggestions").json()["suggestions"]
    assert s[0]["form"]["command"] == {"allow": ["ls", "cat"]}


def test_w6_stays_on_the_0_2_9_list(client, owner, ctx):
    """0.2.51: `sort` is in the default mandate now, but the learning digest keeps its own narrow list (W6_READONLY_COMMANDS)."""
    from app.toolmap import CC_READONLY_COMMANDS
    assert "sort" in CC_READONLY_COMMANDS and "sort" not in suggest.W6_READONLY_COMMANDS
    ag, hdr = owner.new_agent("claude-code", "cc")
    owner.mandate(ag["id"], BASE)
    set_settings(ctx, owner.account["id"], max_pending=25, max_defers_hour=40)
    _approve3(client, owner, hdr, ["sort a", "sort b", "sort -r c"], ["sort"])
    assert client.get("/api/suggestions").json()["suggestions"] == []
    w = {(x["class"], x["recipient"]): x["reason"] for x in suggest.withheld(ctx, owner.account["id"])}
    assert w == {("command", "sort"): "NOT_READ_ONLY"}
