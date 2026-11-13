# 0.2.55 (RT V3-g): a project allowance must not cover commands that bring in unseen commits (they can rewrite .claude/settings.json)
from app import allowances as a


def test_merge_like_git_commands_are_never_project_allowed():
    for sub in ("pull", "merge", "cherry-pick", "revert", "rebase", "am"):
        assert a.why_not("git " + sub), sub


def test_own_tree_and_read_commands_stay_allowable():
    for cid in ("git status", "git stash", "git add", "git commit", "pytest"):
        assert a.why_not(cid) is None, cid
