"""Review 5 (0.2.8): the form -> mandate map refuses disguised text, non-ASCII domains, non-boolean flags and over-limit budgets (unit level, no HTTP)."""
import pytest
from app.context import Err
from app.mandates import MAX_CENTS, mandate_from_form


def mk(form):
    return mandate_from_form(form, "p" * 8, "ag_1", "src")


def refused(form, status=None):
    with pytest.raises(Err) as e:
        mk(form)
    assert e.value.code == "FORM_INVALID"
    if status:
        assert e.value.status == status
    return e.value.detail


@pytest.mark.parametrize("cp", [0x202A, 0x202E, 0x2066, 0x2069, 0x200E, 0x200F, 0x061C, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x0007, 0x2028, 0x00A0, 0xE0041])
def test_hidden_characters_refused_everywhere(cp):
    c = chr(cp)
    for form in ({"message": {"domains": ["a" + c + ".org"]}}, {"message": {"to": ["a" + c + "@b.org"]}}, {"delete": {"targets": ["/a" + c]}},
                 {"publish": {"channels": ["x" + c]}}, {"forbidden_data": ["y" + c]}):
        refused(form, 400)


def test_non_ascii_domain_needs_punycode():
    assert "punycode" in refused({"message": {"domains": ["gіthub.com"]}}, 400)
    refused({"message": {"to": ["a@gіthub.com"]}}, 400)
    m = mk({"message": {"domains": ["xn--gthub-5wa.com", "*.example.org"], "to": ["böb@xn--gthub-5wa.com"]}})
    assert m["permissions"]["message"]["domains"][0] == "xn--gthub-5wa.com"


def test_booleans_are_booleans():
    for v in ("false", "true", 0, 1, None, [], {}):
        refused({"purchase": {"enabled": v, "budget": 1, "max_per_action": 1}})
    for v in ("false", 1, None):
        refused({"delete": {"targets": ["/a"], "allow_irreversible": v}})
    assert mk({"purchase": {"enabled": False}})["permissions"]["purchase"] is False


def test_budget_limit_is_the_page_limit():
    assert MAX_CENTS == 99999999999
    mk({"purchase": {"enabled": True, "budget": MAX_CENTS, "max_per_action": MAX_CENTS}})
    refused({"purchase": {"enabled": True, "budget": MAX_CENTS + 1, "max_per_action": 1}})
