#!/usr/bin/env python3
"""Install check of the Deus Witness client as a new person meets it (`pip install deus-witness`). No network, no secrets.
  client_checks.py installed [--expect VERSION]   commands start, version is printed, the hook answers a made-up PreToolUse event
                                                   with a clear "witness cannot be reached" deny (never a traceback) when no server is there
  client_checks.py gone                            after `pip uninstall`: no command left, no package left
Exit 0 = all checks passed. Every line "ok" / "FAIL" is the journal."""
import json, os, shutil, subprocess, sys, tempfile
from importlib import metadata


def step(ok, msg):
    print(("ok    " if ok else "FAIL  ") + msg, flush=True)
    if not ok:
        sys.exit(1)


def run(cmd, stdin=None, env=None):
    exe = shutil.which(cmd[0])
    step(exe is not None, "%s is on PATH (%s)" % (cmd[0], exe))
    return subprocess.run([exe] + cmd[1:], input=stdin, capture_output=True, text=True, env=env, timeout=120)


def installed(expect):
    v = metadata.version("deus-witness")
    print("      installed version %s, python %s, platform %s" % (v, sys.version.split()[0], sys.platform))
    step(not expect or v == expect, "version is %s (expected %s)" % (v, expect or "any"))
    p = run(["deus-witness", "--help"])
    step(p.returncode == 0 and "audit" in p.stdout and "Traceback" not in p.stderr, "deus-witness --help (rc %s)" % p.returncode)
    p = run(["deus-witness-hook", "--help"])
    step(p.returncode == 0 and "PreToolUse" in p.stdout, "deus-witness-hook --help (rc %s)" % p.returncode)
    p = run(["deus-witness-verify-pack", "--help"])
    step(p.returncode == 0 and "Traceback" not in p.stderr, "deus-witness-verify-pack --help (rc %s)" % p.returncode)
    p = run(["deus-witness", "audit", "--json", "--project", tempfile.gettempdir()])
    step(p.returncode == 0 and "Traceback" not in p.stderr, "deus-witness audit --json (read only, no network; rc %s)" % p.returncode)
    # the hook with no server: port 9 (discard) refuses the connection at once
    home = tempfile.mkdtemp(prefix="dwci-")
    proj = os.path.join(home, "project")
    os.makedirs(proj)
    env = dict(os.environ, DEUS_WITNESS_URL="http://127.0.0.1:9", DEUS_WITNESS_KEY="dwk_ci_offline", DEUS_WITNESS_HOME=home,
               CLAUDE_PROJECT_DIR=proj, HOME=home, USERPROFILE=home)
    ev = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "echo hi"}, "cwd": proj, "session_id": "ci"}
    p = run(["deus-witness-hook"], stdin=json.dumps(ev), env=env)
    step("Traceback" not in p.stdout + p.stderr, "hook without a server: no traceback")
    out = json.loads(p.stdout.strip().splitlines()[-1])["hookSpecificOutput"]
    step(out["permissionDecision"] == "deny" and "WITNESS_UNAVAILABLE" in out["permissionDecisionReason"] and "cannot be reached" in out["permissionDecisionReason"],
         "hook without a server: deny WITNESS_UNAVAILABLE, says it cannot reach the witness (rc %s)" % p.returncode)
    print("CLIENT CHECKS OK")


def gone():
    try:
        v = metadata.version("deus-witness")
        step(False, "package still installed: %s" % v)
    except metadata.PackageNotFoundError:
        step(True, "package deus-witness is gone")
    for c in ("deus-witness", "deus-witness-hook", "deus-witness-mcp", "deus-witness-verify-pack", "deus-witness-demo-tools"):
        step(shutil.which(c) is None, "command %s is gone" % c)
    print("UNINSTALL OK")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["installed"]:
        installed(a[a.index("--expect") + 1] if "--expect" in a else "")
    elif a[:1] == ["gone"]:
        gone()
    else:
        sys.exit("usage: client_checks.py installed [--expect V] | gone")
