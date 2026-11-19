#!/usr/bin/env python3
"""CI full circle (install check): agent -> hook (the client installed from PyPI) -> witness server (this repo) -> verdict.
usage: python full_circle.py --base http://127.0.0.1:8787 --hook PATH_TO_deus-witness-hook --client PATH_TO_deus-witness --workdir DIR
Run with the SERVER venv python (needs httpx, cbor2, cryptography, the repo's wa_profile / svidetel_v4 / testshim).
Registers a throw-away account with a software passkey (same as cloud/selfhost/e2e_check.py), signs the client's own default
mandate form (`deus-witness-hook --print-form`), then feeds two PreToolUse events to the hook:
  Bash `echo hi`   -> permissionDecision allow
  Bash `rm -rf ~`  -> permissionDecision deny   (the command is only JUDGED; the hook never runs it)
Exit 0 = both as expected."""
import argparse, json, os, subprocess, sys, time

ap = argparse.ArgumentParser()
ap.add_argument("--base", required=True)
ap.add_argument("--hook", required=True)
ap.add_argument("--client-python", required=True, help="python of the venv the client is installed in")
ap.add_argument("--workdir", required=True)
ap.add_argument("--repo", default=os.getcwd(), help="root of the witness-server tree (has cloud/, svidetel_v4/)")
o = ap.parse_args()
cloud = os.path.join(o.repo, "cloud")
sys.path[:0] = [os.path.join(cloud, "contract"), o.repo, cloud]
import httpx  # noqa: E402
import wa_profile as wa  # noqa: E402
import testshim  # noqa: E402
testshim.install()


def step(ok, msg):
    print(("ok    " if ok else "FAIL  ") + msg, flush=True)
    if not ok:
        sys.exit(1)


base = o.base.rstrip("/")
rp = httpx.URL(base).host
hdr = {"Origin": base}
c = httpx.Client(base_url=base, timeout=60)
step(c.get("/healthz").status_code == 200, "server /healthz")
auth = wa.SoftAuthenticator()
post = lambda p, **j: c.post(p, json=j, headers=hdr)  # noqa: E731
j = post("/api/auth/register/begin", display_name="install-ci-%d" % time.time()).json()
cred = auth.create_credential(wa.b64u_dec(j["options"]["challenge"]), rp, base)
step(post("/api/auth/register/finish", flow_id=j["flow_id"], credential=cred).status_code == 200, "register (software passkey)")
r = post("/api/agents", name="install-ci", preset="claude-code")
step(r.status_code == 200, "create agent")
agent, key = r.json()["agent"], r.json()["api_key"]
proj = os.path.join(o.workdir, "project")
os.makedirs(proj, exist_ok=True)
form = json.loads(subprocess.run([o.hook, "--print-form", proj], capture_output=True, text=True, check=True).stdout)
m = post("/api/mandates/draft", agent_id=agent["id"], form=form)
step(m.status_code == 200, "mandate draft from the client's own --print-form (%s)" % m.status_code)
m = m.json()["mandate"]
env = wa.b64u(auth.sign_object(wa.TYP_MANDATE, wa.cde(m), rp, base))
step(post("/api/mandates", mandate=m, envelope_b64=env).status_code == 200, "mandate signed")

home = os.path.join(o.workdir, "dwhome")
os.makedirs(home, exist_ok=True)
e = dict(os.environ, DEUS_WITNESS_URL=base, DEUS_WITNESS_KEY=key, DEUS_WITNESS_HOME=home, CLAUDE_PROJECT_DIR=proj,
         DEUS_WITNESS_HOOK_ALLOW="allow")


# What `deus-witness-hook --trust URL` does after the person types yes (it refuses a script, on purpose): pin the witness key with the
# client's own code. In CI there is no person; this is the one step the runner does for the human.
PIN = ("import sys; from deus_witness.client import Witness; w = Witness(sys.argv[1], None, pin_new=True); i = w._call('GET', '/v1/witness'); "
       "p = w._read_pins(); p[w.url] = {'kid_hex': i['kid_hex'], 'pub_hex': i['pub_hex']}; w._write_pins(p); print('pinned', i['kid_hex'])")
p = subprocess.run([o.client_python, "-c", PIN, base], capture_output=True, text=True, env=e)
print("      " + (p.stdout + p.stderr).strip()[-300:])
step(p.returncode == 0, "witness key pinned (the human's `--trust yes`)")


def ask(cmd):
    ev = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": proj, "session_id": "ci"}
    p = subprocess.run([o.hook], input=json.dumps(ev), capture_output=True, text=True, env=e, timeout=120)
    print("      hook rc=%s stderr=%s" % (p.returncode, p.stderr.strip()[:300]))
    out = json.loads(p.stdout.strip().splitlines()[-1])["hookSpecificOutput"]
    return out["permissionDecision"], out.get("permissionDecisionReason", "")


d, why = ask("echo hi")
step(d == "allow", "echo hi -> %s %s" % (d, why[:120]))
d, why = ask("rm -rf ~")
step(d == "deny" and ("ESCALATE_COMMAND_DANGER" in why or "FORBIDDEN_" in why),   # 18.11: с 0.2.139 rm -rf ~ = FORBIDDEN_WIPE (строже)
     "rm -rf ~ -> %s %s" % (d, why[:160]))
print("FULL CIRCLE OK")
