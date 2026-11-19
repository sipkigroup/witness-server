#!/usr/bin/env python3
"""CI: the same consequence must get the same verdict, whatever the OS writes it as.
Corpus (windows_semantika_korpus.jsonl): Windows PowerShell / cmd forms and busybox / Alpine / uutils forms, each with its macOS/bash
twin (same consequence). The judge of THIS tree judges the form and its twin (nothing is executed, no model, no network:
the server app runs in-process behind TestClient). weaker = the form's verdict is below its twin's (allow < ask < deny).
Level L2: the client deus_witness (requirements-test.lock) -> hook -> TestClient -> create_app, as cloud/server/tests do.
Level L1 (no client installed): app.hookjudge.mapping.map_event + app.constitution only.
usage: python windows_semantika.py --repo . [--korpus FILE] [--out res.jsonl] [--level L2|L1] [--baseline FILE] [--strict]
exit: 0; with --strict 1 when a form is ALLOWED while its twin is DENIED and the form is not in --baseline (a new hole)."""
import argparse, collections, json, os, re, shutil, sys, tempfile, time

RANK = {"allow": 0, "ask": 1, "deny": 2}
HERE = os.path.dirname(os.path.abspath(__file__))


def locate(repo):
    for s in (os.path.join(repo, "cloud", "server"), os.path.join(repo, "server"), repo):
        if os.path.isfile(os.path.join(s, "app", "hookjudge", "judge.py")):
            return s
    raise SystemExit("no app/hookjudge/judge.py under %s (cloud/server, server or the root)" % repo)


def stand():
    d = tempfile.mkdtemp(prefix="ws-stand-")
    H = os.path.join(d, "home")
    P = os.path.join(H, "proj", "demo")
    os.makedirs(os.path.join(P, "src"))
    open(os.path.join(P, "README.md"), "w").write("# x\n")
    for f, body in {".local/bin/deus-witness-hook": "#!/bin/sh\n", ".deus-witness/state.json": "{}",
                    ".claude/plugins/cache/deus-witness/plugin.json": "{}",
                    ".claude/settings.json": '{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"deus-witness-hook"}]}]}}'}.items():
        p = os.path.join(H, *f.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(body)
    return d, H, P


class Judge:
    def __init__(self, srv, level):
        root = os.path.dirname(srv)
        for p in (root, srv, os.path.join(root, "contract")):
            if p not in sys.path:
                sys.path.insert(0, p)
        self.scr, self.H, self.P = stand()
        os.environ["HOME"] = os.environ["USERPROFILE"] = self.H
        os.environ.pop("DEUS_WITNESS_URL", None)
        try:
            import testshim
            testshim.install()
        except ImportError:
            pass
        from app import _paths  # noqa: F401
        if level == "L2":
            try:
                import deus_witness.hook.main  # noqa: F401
                from tests.helpers import Owner  # noqa: F401
            except ImportError as e:
                print("L2 unavailable (%s) -> L1" % e, file=sys.stderr)
                level = "L1"
        self.level, self.n = level, 0
        if level == "L1":
            from app import constitution
            from app.hookjudge.mapping import map_event
            self.K, self.map_event = constitution, map_event
            return
        from fastapi.testclient import TestClient
        from app.config import Config
        from app.main import create_app
        from tests.helpers import Owner, ORIGIN, RP
        try:
            from tests_flow.helpers import set_settings
        except ImportError:
            set_settings = None
        from deus_witness import client as dwc
        from deus_witness.hook import main as thin, form
        self.dwc, self.thin, self.form = dwc, thin, form
        open(os.path.join(self.scr, "wk"), "w").write("a1" * 32)
        cfg = Config(data_dir=os.path.join(self.scr, "data"), witness_key_file=os.path.join(self.scr, "wk"), key_pepper="ci-pepper",
                     rp_id=RP, origin=ORIGIN, iss="https://witness.test", anchor="off", web_dir=os.path.join(self.scr, "web"),
                     rate_per_min=1000000, quota_per_day=1000000, max_agents=10000000)
        self.app = create_app(cfg)
        self.tc = TestClient(self.app, base_url=ORIGIN)
        self.owner = Owner(self.tc).register("Alice")
        if set_settings:
            set_settings(self.app.state.ctx, self.owner.account["id"], max_pending=10000000, max_defers_hour=10000000)
        self.transcript = os.path.join(self.scr, "transcript.jsonl")
        open(self.transcript, "w").close()

    class Via:
        def __init__(self, tc):
            self.tc = tc

        def handle_request(self, request):
            import httpx
            hd = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length", "transfer-encoding")}
            r = self.tc.request(request.method, str(request.url), headers=hd, content=request.read())
            return httpx.Response(r.status_code, headers={"content-type": r.headers.get("content-type", "application/json")}, content=r.content)

        def close(self):
            pass

    def verdict(self, cmd, unlisted="allow"):
        self.n += 1
        if self.level == "L1":
            ev = {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": self.P}
            try:
                parts = list(self.map_event(ev, home=self.H, env={"CLAUDE_PROJECT_DIR": self.P, "HOME": self.H, "DEUS_WITNESS_EXEC_SCAN": "0"}))
            except Exception as e:      # noqa: BLE001
                return "deny", type(e).__name__
            danger = []
            for m in parts:
                r = self.K.check(m.tool, m.args)
                if r is not None:
                    return "deny", r[0]
                w = m.args.get("_witness") if isinstance(m.args, dict) else None
                danger += list((w or {}).get("danger") or [])
            return ("ask", danger[0].split(":")[0]) if danger else ("allow", "")
        ag, hdr = self.owner.new_agent("claude-code", "cc")          # a fresh agent per command: no history between lines
        f = self.form.default_form(self.P, home=self.H)
        f["command"]["unlisted"] = unlisted
        _, r = self.owner.mandate(ag["id"], f)
        if r.status_code != 200:
            raise RuntimeError("mandate: " + r.text[:200])
        key = hdr["Authorization"][7:]
        dwh = os.path.join(self.scr, "dw", str(self.n))
        s = self.thin.Settings({"DEUS_WITNESS_KEY": key, "CLAUDE_PROJECT_DIR": self.P, "HOME": self.H, "DEUS_WITNESS_HOOK_WAIT": "0",
                                "DEUS_WITNESS_HOOK_ON_DEFER": "ask", "DEUS_WITNESS_HOME": dwh})
        wi = self.dwc.Witness("http://localhost:8810", key, pin_path=os.path.join(dwh, "pins.json"), transport=self.Via(self.tc))
        ev = {"tool_name": "Bash", "tool_input": {"command": cmd, "description": "probe"}, "cwd": self.P, "session_id": "ws-%d" % self.n,
              "tool_use_id": "t%d" % self.n, "hook_event_name": "PreToolUse", "permission_mode": "default", "transcript_path": self.transcript}
        try:
            o = self.thin.judge(ev, s, witness=wi).get("hookSpecificOutput", {})
        except Exception as e:      # noqa: BLE001
            return "deny", "HARNESS_" + type(e).__name__
        d = o.get("permissionDecision", "none")
        mm = re.findall(r"\b(?:ESCALATE_[A-Z_]+|FORBIDDEN_[A-Z_]+|[A-Z][A-Z_]{4,})\b", o.get("permissionDecisionReason", "") or "")
        return ("allow" if d in ("none", "allow") else "deny" if d == "deny" else "ask"), (mm[0] if mm else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=os.getcwd())
    ap.add_argument("--korpus", default=os.path.join(HERE, "windows_semantika_korpus.jsonl"))
    ap.add_argument("--out", default="windows-semantika-res.jsonl")
    ap.add_argument("--level", choices=("L2", "L1"), default="L2")
    ap.add_argument("--mandate", choices=("allow", "ask"), default="allow")
    ap.add_argument("--baseline", default=os.path.join(HERE, "windows_semantika_baseline.json"))
    ap.add_argument("--strict", action="store_true")
    a = ap.parse_args()
    t0 = time.time()
    import io, contextlib, logging
    logging.disable(logging.CRITICAL)
    rows = [json.loads(l) for l in open(a.korpus, encoding="utf-8") if l.strip()]
    with contextlib.redirect_stdout(io.StringIO()):
        J = Judge(locate(os.path.abspath(a.repo)), a.level)
    V = {}
    for c in sorted({r["forma"] for r in rows} | {r["bliznec"] for r in rows}):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            V[c] = J.verdict(c, a.mandate)
    base = set()
    if os.path.isfile(a.baseline):
        base = set(json.load(open(a.baseline, encoding="utf-8")).get("allow_at_deny", []))
    cls, new_holes, n_sl, n_na = collections.Counter(), [], 0, 0
    with open(a.out, "w", encoding="utf-8") as fo:
        for r in rows:
            (vf, kf), (vt, kt) = V[r["forma"]], V[r["bliznec"]]
            sl, na = RANK[vf] < RANK[vt], vf == "allow" and vt != "allow"
            n_sl += sl; n_na += na
            if sl:
                cls[(r["os"], r["klass"])] += 1
            if vf == "allow" and vt == "deny" and r["id"] not in base:
                new_holes.append(r)
            fo.write(json.dumps(dict(r, verdikt_forma=vf, kod_forma=kf, verdikt_bliznec=vt, kod_bliznec=kt, slabee=sl, neizv_allow=na,
                                     platform=sys.platform), ensure_ascii=False) + "\n")
    harness = sum(1 for v in V.values() if v[1].startswith("HARNESS_"))
    print("platform %s, level %s, mandate unlisted=%s: forms %d, weaker than twin %d (%.0f%%), form allow while twin ask/deny %d, "
          "classes %d, harness errors %d, %.0f s" % (sys.platform, J.level, a.mandate, len(rows), n_sl, 100.0 * n_sl / max(1, len(rows)), n_na,
                                                     len(cls), harness, time.time() - t0))
    for (o, k), n in sorted(cls.items(), key=lambda kv: -kv[1]):
        print("  weaker %-12s %-14s %d" % (o, k, n))
    for r in new_holes:
        print("NEW HOLE %s %s | twin %s" % (r["id"], r["forma"], r["bliznec"]))
    if a.strict and J.level != "L2":           # L1 has no mandate stage (an unknown program is asked there): its numbers are not comparable
        print("--strict needs L2 (the client deus_witness from requirements-test.lock)", file=sys.stderr)
        sys.exit(1)
    if a.strict and (new_holes or harness):
        sys.exit(1)


if __name__ == "__main__":
    main()
