"""0.2.78: newcomer-path texts (trial page, approval page wait line, docs)."""
import pathlib
W = pathlib.Path(__file__).resolve().parents[2] / "web"
D = pathlib.Path(__file__).resolve().parents[2] / "docs"


def test_trial_button_and_header():
    h = (W / "trial.html").read_text()
    assert ">Confirm with Face ID</button>" in h and "Approve with passkey" not in h      # r0283 (decision 8): the device's word; trial.js sets it per device
    j = (W / "js" / "trial.js").read_text()
    assert "Waiting for your rules (nothing is allowed yet)" in j and "mountNav(false, { noSignup: true })" in j
    u = (W / "js" / "ui.js").read_text()
    assert "opts.noSignup" in u and "Create account" in u      # other pages keep the button


def test_approve_page_wait_line_uses_hook_wait():
    a = (W / "js" / "approve.js").read_text()
    # r0281 (blind evaluation B1): the agent's wait is part of the ONE time line by the buttons (timeText), not a second line under Details
    assert "HOOK_WAIT_S = 45" in a and "timeText(" in a and "Your agent waits " in a and "If it asks again within " in a      # r0283 (decision 3)
    hook = (pathlib.Path(__file__).resolve().parents[2].parent / "release/out/open-repo/plugins/deus-witness/scripts/deus-witness-hook.sh")
    if hook.exists():
        assert "HOOK_WAIT:-45" in hook.read_text()


def test_docs_numbers():
    assert "never offered \"Allow for 24 h\"" in (D / "coverage-public.md").read_text()
    from app import actions
    assert actions.QUOTA_PER_AGENT_DAY == 4000          # r0285: was 2000 (PARALLEL-I-KVOTA-1311)
    for p in (W / "pricing" / "index.html", W / "index.html"):
        t = p.read_text()
        assert "10000 actions per day per account and 4000 per agent" in t and "quick start account before its passkey, 2000 a day" in t
