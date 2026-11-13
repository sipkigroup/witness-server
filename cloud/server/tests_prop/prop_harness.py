"""Property-testing harness for the Deus Witness hook judge (POST /v1/hook/judge).
A World = a fresh app + owner + agent with the default mandate form; the judge is called the way tests/test_0411 does it."""
import hashlib
import json
import os
import shutil
import tempfile

import cbor2  # noqa: F401
from fastapi.testclient import TestClient
from hypothesis import strategies as st

from app import _paths  # noqa: F401
import wa_profile as wa
from app.config import Config
from app.main import create_app
from app.flow.wq import wq
from svidetel_v4.state import approval_payload
from tests.helpers import Owner, ORIGIN, RP
from tests.test_0217_judge import _body

COUNT = {}
RANK = {"allow": 0, "defer": 1, "deny": 2}


def tick(name):
    COUNT[name] = COUNT.get(name, 0) + 1


class Spy:
    enabled = False

    def __init__(self):
        self.calls = []

    def notify_defer(self, row, name, lits):
        self.calls.append(row["rid"])

    def approval(self, row):
        self.calls.append(row["rid"])


class World:
    def __init__(self, raise_exc=True):
        from tests_flow.helpers import set_settings
        from app.hookjudge.mapping import default_form
        self.dir = tempfile.mkdtemp(prefix="prop_")
        kf = os.path.join(self.dir, "witness_key")
        open(kf, "w").write("a1" * 32)
        cfg = Config(data_dir=os.path.join(self.dir, "data"), witness_key_file=kf, key_pepper="test-pepper", rp_id=RP, origin=ORIGIN,
                     iss="https://witness.test", anchor="off", web_dir=os.path.join(self.dir, "web"))
        self.app = create_app(cfg)
        self.client = TestClient(self.app, base_url=ORIGIN, raise_server_exceptions=raise_exc)
        self.ctx = self.app.state.ctx
        self.owner = Owner(self.client).register("Alice")
        self.proj = os.path.join(self.dir, "proj")
        os.makedirs(self.proj)
        self.proj = os.path.realpath(self.proj)
        set_settings(self.ctx, self.owner.account["id"], max_pending=100000, max_defers_hour=100000)
        ag, self.hdr = self.owner.new_agent("claude-code", "cc")
        _m, _r = self.owner.mandate(ag["id"], default_form(self.proj))
        assert _r.status_code == 200, _r.text
        self.push, self.chan = Spy(), Spy()
        self.ctx.push, self.ctx.notify = self.push, self.chan

    def close(self):
        """Every descriptor of the World goes back: the TestClient, the Db connections, the data dir claim (server.lock)."""
        from app import hub
        for f in (self.client.close, self.ctx.db.close, lambda: hub.release_data_dir(self.ctx.cfg.data_dir)):
            try:
                f()
            except Exception:
                pass
        shutil.rmtree(self.dir, ignore_errors=True)

    # --- judge
    def raw(self, cmd):
        """-> the final judge answer (fact rounds answered like the hook does); HTTP errors are returned as {'http': code}."""
        rp = {self.proj: self.proj, "/home/u": "/home/u"}
        for _ in range(40):
            resp = self.client.post("/v1/hook/judge", json=_body(cmd, self.proj, fs={"realpath": dict(rp)}), headers=self.hdr)
            if resp.status_code != 200:
                return {"http": resp.status_code, "body": resp.text[:300]}
            r = resp.json()
            if "need" not in r:
                return r
            n = r["need"]
            if "realpath" not in n:
                return {"http": 0, "body": "need " + json.dumps(n)[:200]}
            rp.update({x: x for x in n.get("realpath", [])})
        return {"http": 0, "body": "too many fact rounds"}

    def decision(self, r):
        """-> 0 allow / 1 ask / 2 deny; anything that is not an answer with parts (refuse, http error) is a refusal."""
        if "parts" not in r:
            return 2
        return max([RANK.get(p["result"].get("verdict"), 2) for p in r["parts"]] or [0])

    def judge(self, cmd):
        r = self.raw(cmd)
        return r, self.decision(r)

    def pending(self):
        return [x["rid"] for x in self.ctx.db.q("SELECT rid FROM actions WHERE status='pending_approval' ORDER BY created_at, rowid")]

    def visible(self):
        return self.client.get("/api/approvals").json()

    def view(self, rid):
        return self.client.get("/api/approvals/" + rid).json()

    # --- the owner
    def approve_line(self, lead):
        """The owner signs the lead's page: one batch over the lead and its linked parts (or the single page). -> http result."""
        g = self.view(lead)
        rids = [lead] + [x["rid"] for x in g.get("line_group", [])]
        if len(rids) == 1:
            return self.owner.approve(lead)
        items, hexes = [], []
        for rid in rids:
            gg = self.view(rid)
            hexes.append(gg.get("view_sha256"))
            items.append(hashlib.sha256(approval_payload(gg["mandate"], gg["action"], rid, True,
                                                         bytes.fromhex(gg["view_sha256"]) if gg.get("view_sha256") else None)).digest())
        ad, cd, der = self.owner.auth.get_assertion(wq.wb_challenge(items), RP, ORIGIN)
        env = wa.b64u(wq.make_wb(items, self.owner.auth.kid, ad, cd, der))
        if all(hexes):                                        # 04.11 red team: the parts of one call are approved over the view of every part
            return self.owner.post("/api/approvals/batch", rids=rids, approved=True, envelope_b64=env, views=hexes)
        return self.owner.post("/api/approvals/batch", rids=rids, approved=True, envelope_b64=env)

    def present_all(self, r):
        """What the hook does with an approved answer: present each receipt once. -> list of 'accept'/other."""
        out = []
        for p in r["parts"]:
            rid = p["result"].get("rid")
            if rid and p["result"].get("status") == "approved":
                out.append(self.client.post("/v1/actions/%s/present" % rid, headers=self.hdr).json().get("result"))
        return out


def leaves(o, skip=("mandate",)):
    """every string in a JSON value (keys named in `skip` at the top level are left out: the mandate lists 'ls', 'cat', ... by itself)."""
    out = []

    def walk(x, top=False):
        if isinstance(x, str):
            out.append(x)
        elif isinstance(x, dict):
            for k, v in x.items():
                if top and k in skip:
                    continue
                walk(v)
        elif isinstance(x, (list, tuple)):
            for v in x:
                walk(v)
    walk(o, True)
    return out


# ------------------------------------------------------------------ the oracle: the standalone verdict of one part (cached)
_ORACLE = {}


def oracle(text):
    """-> rank of `text` judged alone in a throw-away world (0 allow / 1 ask / 2 deny)."""
    if text not in _ORACLE:
        w = World()
        try:
            _ORACLE[text] = w.judge(text)[1]
        finally:
            w.close()
    return _ORACLE[text]


# ------------------------------------------------------------------ strategies
N_ = st.integers(0, 9999)
SAFE = st.one_of(
    st.sampled_from(["ls", "pwd", "git status", "cat README.md", "pytest -q", "echo hello", 'echo "a b"', "date", "wc -l file.txt"]),
    st.builds(lambda n: "cat file%d.txt" % n, N_),
    st.builds(lambda s: 'echo "%s"' % s, st.text("abc XYZ019_-", max_size=30)),
    st.builds(lambda n: "ls dir%d" % n, N_),
)
NET = st.one_of(
    st.builds(lambda n: "curl -s https://host%d.example/p" % n, N_),
    st.builds(lambda n: "wget http://h%d.example/f.sh" % n, N_),
    st.builds(lambda n: "pip install pkg%d" % n, N_),
    st.builds(lambda n: "curl -sI https://example.com/%d" % n, N_),
)
DANGER = st.one_of(
    st.builds(lambda n: "rm -rf ~/x%d" % n, N_),
    st.just("make deploy-prod"),
    st.builds(lambda n: "chmod -R 777 ~/d%d" % n, N_),
    st.just("echo hi >> ~/.zshrc"),
    st.just("cat ~/.ssh/id_rsa"),
    st.builds(lambda n: "git push --force origin br%d" % n, N_),
)
WRITTEN = st.builds(lambda n: "python3 x%d.py" % n, N_)
# distortions that keep the line "innocent-looking"
NOISE_LEN = st.integers(0, 10000)
SEPS = st.sampled_from([" ; ", ";", " && ", "&&", " || ", " | ", "\n", " \n ", "  ;  ", "\t&&\t", ";\n"])


@st.composite
def noise(draw):
    kind = draw(st.sampled_from(["long", "quote", "sub", "bq", "heredoc", "uni", "long_sq"]))
    if kind == "long":
        return 'echo "%s"' % ("A" * draw(st.integers(4000, 10000)))
    if kind == "long_sq":
        return "echo '%s'" % ("B" * draw(NOISE_LEN))
    if kind == "quote":
        return "echo " + draw(st.sampled_from(["'it'\"'\"'s'", "\"a'b\"", "'a\"b'", "\"\\\"q\\\"\"", "$'x\\ty'"]))
    if kind == "sub":
        return "echo $(%s)" % draw(st.sampled_from(["date", "pwd", "echo hi", "ls"]))
    if kind == "bq":
        return "echo `%s`" % draw(st.sampled_from(["date", "pwd", "echo hi"]))
    if kind == "heredoc":
        return "cat <<EOF\n%s\nEOF" % draw(st.sampled_from(["text", "a b c", "$HOME", "rm -rf not_really"]))
    return "echo " + draw(st.sampled_from(["héllo", "привет", "日本語", "✓✓", "‮evil", "a​b", "😀"]))


@st.composite
def wrapped_risky(draw, base):
    t = draw(base)
    w = draw(st.sampled_from(["plain", "plain", "plain", "sub", "bq", "bash_c", "pad"]))
    if w == "sub":
        return "echo $(%s)" % t, t
    if w == "bq":
        return "echo `%s`" % t, t
    if w == "bash_c":
        return "bash -c '%s'" % t, t
    if w == "pad":
        return "  %s   " % t, t
    return t, t


@st.composite
def part(draw):
    """-> (text, risky_core or None): risky_core is the substring the owner must be able to see if the part asks."""
    k = draw(st.sampled_from(["safe", "safe", "net", "danger", "written", "noise"]))
    if k == "safe":
        return draw(SAFE), None
    if k == "noise":
        return draw(noise()), None
    base = {"net": NET, "danger": DANGER, "written": WRITTEN}[k]
    return draw(wrapped_risky(base))


@st.composite
def line(draw, min_parts=1, max_parts=5):
    """-> (line_text, [(part_text, core)...])"""
    n = draw(st.integers(min_parts, max_parts))
    ps = [draw(part()) for _ in range(n)]
    s = ps[0][0]
    for p in ps[1:]:
        s = glue(s, draw(SEPS), p[0])
    return s, ps


def glue(a, sep, b):
    """a heredoc is closed by its own line: whatever follows it starts on a new line (else the next part would be heredoc BODY)."""
    if a.endswith("\nEOF"):
        sep = "\n"
    return a + sep + b
