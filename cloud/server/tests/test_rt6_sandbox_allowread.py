"""RT-0.2.58 red team #6: an allowRead that re-opens a secret must make the sandbox NOT strict.
L2-confirmed in real Seatbelt (Claude Code 2.1.310, APFS): a more-specific allowRead of ~/.ssh/id_rsa, and a case variant ~/.SSH,
both read the fake key while denyRead covered ~/.ssh. The hook must then refuse to call the sandbox strict."""
from app.hookjudge.sandbox import evaluate

HOME = "/Users/tester"


def _fact(allow_read):
    return {"v": 1, "platform": "darwin", "sources": {"user": "ok", "project": "ok"},
            "enabled": True, "fail_if_unavailable": True, "allow_unsandboxed": False, "excluded": [],
            "ignore_violations": False, "fs_disabled": False,
            "deny_read": [HOME], "allow_read": allow_read, "domains": [], "unix_sockets": [],
            "all_unix_sockets": False, "mach_lookup": [], "local_binding": False, "weaker": [],
            "env_scrub": True, "disable_flag": False, "env_files": [],
            "strict_allowlist": True, "managed_domains_only": False, "permission_mode": "default",
          "settings_digest": "ab" * 32, "since_start": [], "doubt": []}


def test_baseline_strict():
    assert evaluate(_fact([]), ["pytest"], HOME)[0] is True


def test_specific_file_allowread_breaks_strict():
    # L2: allowRead of the exact file inside a denied dir reads the key -> must not be strict
    assert evaluate(_fact([HOME + "/.ssh/id_rsa"]), ["pytest"], HOME)[0] is False
    assert evaluate(_fact([HOME + "/.aws/credentials"]), ["pytest"], HOME)[0] is False


def test_case_variant_allowread_breaks_strict():
    # L2: on APFS allowRead ~/.SSH re-opens ~/.ssh
    assert evaluate(_fact([HOME + "/.SSH"]), ["pytest"], HOME)[0] is False
    assert evaluate(_fact([HOME + "/.AWS/Credentials"]), ["pytest"], HOME)[0] is False


def test_glob_allowread_inside_secret_breaks_strict():
    assert evaluate(_fact([HOME + "/.ssh/**"]), ["pytest"], HOME)[0] is False


def test_legit_allowread_stays_strict():
    # an allowRead that touches no secret must not spuriously break strict
    assert evaluate(_fact(["/usr/lib"]), ["pytest"], HOME)[0] is True
    assert evaluate(_fact(["/Users/tester/proj/build"]), ["pytest"], HOME)[0] is True
