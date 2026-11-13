"""0.2.16: a duck-typed witness for the thin hook's decision tests. It answers POST /v1/hook/judge with the REAL server-side classifier
(app/hookjudge, facts from this machine) and a scripted verdict per part, so the hook's flow (verify, consume, defer, deny texts) is tested
with the real parts and the real texts, without a ledger. `act(tool, args)` gives the scripted result of one part (override it)."""
from deus_witness.client import ActionResult, AARError, args_sha256

from app.hookjudge import judge as hj
from app.hookjudge import reasons


class FakeW:
    verify = True
    _pub = b"fake"          # 0.2.17: the statement is not signed here (judge_statement returns it as is); the signature: test_0217_judge.py

    def __init__(self, verdict, status, reason="OK", action=None, present="accept", later=None):
        self.r = dict(verdict=verdict, status=status, reason=reason, action=action)
        self.later, self.presented, self.sent = later, [], None
        self.p = present
        self.calls = []
        self.rounds = 0

    # what the server's judge does, with act() in place of the core
    def hook_judge(self, body):
        self.rounds = getattr(self, "rounds", 0) + 1
        r = hj.classify_event(body)
        if r[0] == "need":
            return {"v": 1, "need": r[1], "scan_rev": hj.scan_list()["rev"]}
        if r[0] == "refuse":
            return {"v": 1, "refuse": r[1], "detail": r[2], "texts": hj.texts_for([r[1]])}
        parts, only, out = r[1], body.get("part"), []
        for i, m in enumerate(parts):
            if only is not None and i != only:
                continue
            res = self.act(m.tool, m.args)
            d = _json(res)
            out.append({"i": i, "tool": m.tool, "args": m.args, "summary": m.summary, "result": d, "why": reasons.explain(str(d.get("reason") or ""), m.tool)})
            if d["verdict"] == "deny" or d["status"] in ("refused", "expired"):
                break
        return {"v": 1, "n_parts": len(parts), "parts": out, "texts": hj.texts_for([p["result"].get("reason") for p in out]),
                "statement_b64": hj.statement_payload(body, only, parts, out)}

    def args_hash(self, tool, args):
        return args_sha256(tool, args)

    def judge_statement(self, st):
        if not isinstance(st, dict):
            raise AARError("MALFORMED")
        return st

    def scan_list(self, rev=None, cached_only=False):
        return hj.scan_list()

    def act(self, tool, args, client=None, verify=None):
        self.sent = (tool, args)
        self.calls.append(tool)
        a = self.r["action"] if self.r["action"] is not None else {"args_sha256": args_sha256(tool, args)}
        return ActionResult(rid="r_1", action=a, approval_url="https://w/approve.html?rid=r_1", **{k: v for k, v in self.r.items() if k != "action"})

    def get(self, rid, wait=0):
        return self.later

    def check(self, res, sent=None):
        if res.action.get("args_sha256") != args_sha256(*sent):
            raise AARError("REQUEST_MISMATCH")

    def present(self, rid):
        self.presented.append(rid)
        return {"result": self.p, "reason": "ALREADY_CONSUMED" if self.p != "accept" else "OK"}

    def close(self):
        pass


def _json(res):
    if isinstance(res, dict):
        return res
    return {"rid": res.rid, "verdict": res.verdict, "reason": res.reason, "status": res.status, "action": res.action, "expires": res.expires,
            "aar_b64": res.aar_b64, "proof": res.proof, "approval_url": res.approval_url}
