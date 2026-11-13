"""27.10 polygon "people", O9: a waiting hook (DEUS_WITNESS_HOOK_WAIT > 0, a night CI) that got no answer in time says the call was
REFUSED (nobody approved within N s, the receipt, approve then rerun), not "is waiting for the owner's approval". The quickstart path
(WAIT 0) keeps "is waiting ... retry the SAME call": there the call is held on purpose for the owner."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "mcp"))

from deus_witness.client import ActionResult  # noqa: E402
from deus_witness.hook import judge  # noqa: E402
from deus_witness.hook.main import Settings  # noqa: E402
from tests.hookfake import FakeW  # noqa: E402

E_RM = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf build"}, "cwd": "/tmp", "session_id": "s"}


def _why(out):
    h = out["hookSpecificOutput"]
    return h["permissionDecision"], h["permissionDecisionReason"]


def _still_pending():
    return ActionResult(rid="r_1", verdict="defer", reason="ESCALATE_COMMAND_DANGER", status="pending_approval", action=None,
                        approval_url="https://w/approve.html?rid=r_1")


def test_o9_ci_timeout_says_refused_not_waiting():
    w = FakeW("defer", "pending_approval", "ESCALATE_COMMAND_DANGER", later=_still_pending())
    d, why = _why(judge(E_RM, Settings({"DEUS_WITNESS_KEY": "k", "DEUS_WITNESS_HOOK_WAIT": "1"}), w))
    assert d == "deny"
    assert "is waiting for the owner" not in why, why
    assert why.startswith("Deus Witness refused ") and "nobody approved it in Witness within 1 s" in why, why
    assert "receipt r_1" in why and "approve.html?rid=r_1" in why and "rerun" in why, why


def test_o9_quickstart_wait0_keeps_held_text():
    w = FakeW("defer", "pending_approval", "ESCALATE_COMMAND_DANGER")
    d, why = _why(judge(E_RM, Settings({"DEUS_WITNESS_KEY": "k"}), w))
    assert d == "deny" and "is waiting for the owner's approval in Witness" in why and "retry the SAME call" in why, why
    assert "refused" not in why and "nobody approved" not in why, why


def test_o9_ask_mode_after_wait_is_not_called_refused():
    w = FakeW("defer", "pending_approval", "ESCALATE_COMMAND_DANGER", later=_still_pending())
    d, why = _why(judge(E_RM, Settings({"DEUS_WITNESS_KEY": "k", "DEUS_WITNESS_HOOK_WAIT": "1", "DEUS_WITNESS_HOOK_ON_DEFER": "ask"}), w))
    assert d == "ask" and "refused" not in why.split("Answering yes")[0] and "No answer from the owner within 1 s" in why, why
