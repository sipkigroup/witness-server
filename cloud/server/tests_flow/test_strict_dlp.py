"""Strict tool schema (§6) and DLP wiring (§4.2). Required (5) and (7)."""
import re

import pytest

from app import toolmap as tm
from tests_flow.helpers import FORM, act


def test_5a_send_email_unmapped_reply_to(client, owner):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    r = act(client, hdr, "send_email", {"to": "bob@partner.example", "reply_to": "evil@x.example"}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "TOOL_ARGS_UNMAPPED")


def test_5b_publish_unmapped_webhook(client, owner):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"], dict(FORM, publish={"channels": ["#team"]}))
    r = act(client, hdr, "publish", {"channel": "#team", "text": "hi", "webhook": "https://evil.example/h"}).json()
    assert (r["verdict"], r["reason"]) == ("deny", "TOOL_ARGS_UNMAPPED")
    r = act(client, hdr, "publish", {"channel": "#team", "text": "hi"}).json()
    assert (r["verdict"], r["reason"]) == ("allow", "OK")


@pytest.mark.parametrize("cls", ["message", "publish", "file", "disclosure"])
def test_strict_classes_unit(cls):
    t = {"version": 1, "default": "deny", "tools": {"x": {"class": cls, "recipient": "$.to", "text": ["$.body"]}}}
    assert tm.unmapped_args(t, "x", {"to": "a", "body": "b", "extra": 1}) == ["extra"]
    assert tm.unmapped_args(t, "x", {"to": "a", "body": "b"}) == []


def test_strict_flag_for_other_classes():
    t = {"version": 1, "default": "deny", "tools": {
        "m": {"class": "meeting", "recipient": "$.to"},
        "ms": {"class": "meeting", "recipient": "$.to", "strict": True},
        "p": {"class": "purchase", "recipient": "$.vendor", "amount": "$.cents", "strict": True}}}
    tm.check_toolmap(t)
    assert tm.unmapped_args(t, "m", {"to": "a", "where": "x"}) == []
    assert tm.unmapped_args(t, "ms", {"to": "a", "where": "x"}) == ["where"]
    assert tm.unmapped_args(t, "p", {"vendor": "v", "cents": 1}) == []           # the amount path counts as mapped
    assert tm.unmapped_args(t, "p", {"vendor": "v", "cents": 1, "ship_to": "x"}) == ["ship_to"]


def test_strict_must_be_boolean():
    with pytest.raises(tm.ToolmapInvalid):
        tm.check_toolmap({"version": 1, "default": "deny", "tools": {"x": {"class": "meeting", "strict": "yes"}}})


def test_presets_strict_everywhere():
    for name, p in tm.PRESETS.items():
        tm.check_toolmap(p)
        for n, t in p["tools"].items():
            assert t["class"] == "pass" or tm.is_strict(t), (name, n)


def test_nested_object_under_mapped_path_not_inspected():
    t = tm.preset("demo")
    assert tm.unmapped_args(t, "send_email", {"to": "a@b.c", "body": {"bcc": "x@y.z"}}) == []      # documented limit (§6)


def test_7_iban_in_text(client, owner):
    ag, hdr = owner.new_agent()
    owner.mandate(ag["id"])
    r = act(client, hdr, "send_email", {"to": "bob@partner.example", "subject": "pay", "body": "IBAN DE89370400440532013000 please"}).json()
    assert "iban" in r["action"]["data"]
    assert r["action"]["dlp_hits"] == ["L2:iban"]
    assert re.fullmatch(r"dw-dlp-1/[0-9a-f]{8}", r["action"]["dlp_rs"])
    assert r["action"]["adv"] == ""
    assert (r["verdict"], r["reason"]) == ("deny", "DATA_FORBIDDEN")


def _a(args, tool="send_email", lits=None):
    return tm.build_action("ag", tm.preset("demo"), tool, args, lits or {})


def test_iban_bad_checksum_not_tagged():
    a = _a({"to": "bob@partner.example", "body": "DE89370400440532013001"})
    assert "iban" not in a["data"] and a["dlp_hits"] == []


def test_recipient_address_is_not_email_data():
    a = _a({"to": "bob@partner.example", "subject": "hello"})
    assert a["data"] == [] and a["dlp_hits"] == []
    a = _a({"to": "bob@partner.example", "body": "write to carol@else.example"})
    assert a["dlp_hits"] == ["L2:email_address"]


def test_card_luhn():
    assert _a({"to": "b@p.e", "body": "card 4111 1111 1111 1111"})["dlp_hits"] == ["L2:card_number"]
    assert _a({"to": "b@p.e", "body": "card 4111 1111 1111 1112"})["dlp_hits"] == []


def test_l1_literal_and_secret():
    a = _a({"to": "b@p.e", "body": "I live at 12 Elm Corner, key sk-" + "abcdefghijklmnopqrstuvwxyz"}, lits={"home_address": ["12 Elm Corner"]})
    assert a["dlp_hits"] == ["L1:api_key", "L1:home_address"]
    assert {"home_address", "api_key"} <= set(a["data"])


def test_dlp_members_carry_no_values():
    import random
    rnd = random.Random(7)
    alphabet = "0123456789 abcdefDE@.-+()xyz"
    for _ in range(300):
        s = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 80)))
        a = _a({"to": "b@p.e", "body": s})
        assert all(isinstance(h, str) and re.fullmatch(r"L[12]:[a-z_]+", h) for h in a["dlp_hits"])
        assert isinstance(a["dlp_rs"], str) and a["adv"] == ""


def test_deeply_nested_args_no_crash():
    """Found by cloud/fuzz: the L2 view of the arguments must not recurse over their depth."""
    deep = "x"
    for _ in range(5000):
        deep = {"a": deep}
    a = _a({"to": "b@p.e", "body": "hi", "a": deep})
    assert a["dlp_hits"] == []
    t = {"version": 1, "default": "deny", "tools": {"x": {"class": "meeting", "recipient": "$.a.b.c"}}}
    args = {"a": {"b": {"c": "carol@x.example", "d": "IBAN DE89370400440532013000"}}}
    a = tm.build_action("ag", t, "x", args, {})
    assert a["dlp_hits"] == ["L2:iban"] and args["a"]["b"]["c"] == "carol@x.example"     # the caller's arguments are not modified
