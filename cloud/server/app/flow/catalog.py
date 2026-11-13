"""Tool catalog from the MCP JSON schema (ARHITEKTURA-0.2 §6): the proxy sends `tools/list` -> POST /v1/catalog; the server keeps the
catalog of the agent and its hash, reports drift, and proposes a tool map (`suggest_toolmap`, deterministic heuristic over names and
property types; anything else -> UNKNOWN). A draft with UNKNOWN cannot be applied (422 CATALOG_UNRESOLVED); applying = PUT toolmap
(01, step-up) -> TOOLMAP_CHANGED -> new signed mandate. Nothing here applies itself."""
import hashlib
import json
import re

from app import toolmap as tm
from app.context import Err
from app.flow import store

UNKNOWN = "UNKNOWN"
MAX_TOOLS = 500
RECIPIENT_PROPS = {"to", "cc", "bcc", "recipient", "recipients", "email", "channel", "path", "resource"}
TEXT_PROPS = {"subject", "body", "text", "content", "message", "html"}
AMOUNT_PROPS = {"amount", "price", "total"}
NET_RE = re.compile(r"fetch|http|url|browse|request|webhook|download|upload", re.I)
# class of a tool by words of its name (first match wins); no match -> UNKNOWN (the owner decides)
CLASS_WORDS = [
    ("message", re.compile(r"(?:^|_)(?:send|email|mail|message|reply|forward|sms|dm)(?:_|$)", re.I)),
    ("publish", re.compile(r"(?:^|_)(?:publish|post|tweet|toot|broadcast|announce)(?:_|$)", re.I)),
    ("delete", re.compile(r"(?:^|_)(?:delete|remove|drop|destroy|purge|trash|write|edit|move|rename)(?:_|$)", re.I)),
    ("purchase", re.compile(r"(?:^|_)(?:purchase|buy|pay|order|checkout|charge)(?:_|$)", re.I)),
    ("refund", re.compile(r"(?:^|_)refund(?:_|$)", re.I)),
    ("meeting", re.compile(r"(?:^|_)(?:meeting|invite|schedule|calendar)(?:_|$)", re.I)),
    ("pass", re.compile(r"(?:^|_)(?:read|get|list|search|find|query|describe|show|view|fetch|lookup|status)(?:_|$)", re.I)),
]


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def check_catalog(b):
    tools = b.get("tools") if isinstance(b, dict) else None
    if not isinstance(tools, list) or len(tools) > MAX_TOOLS:
        raise Err(422, "CATALOG_INVALID", "tools: list of at most %d" % MAX_TOOLS)
    names = set()
    for t in tools:
        if not isinstance(t, dict) or not isinstance(t.get("name"), str) or not 0 < len(t["name"]) <= 200 or t["name"] in names:
            raise Err(422, "CATALOG_INVALID", "each tool: unique name (string)")
        if t.get("description") is not None and not isinstance(t["description"], str):
            raise Err(422, "CATALOG_INVALID", "description must be a string")
        if t.get("inputSchema") is not None and not isinstance(t["inputSchema"], dict):
            raise Err(422, "CATALOG_INVALID", "inputSchema must be an object")
        names.add(t["name"])
    return [{"name": t["name"], "description": t.get("description") or "", "inputSchema": t.get("inputSchema") or {}} for t in tools]


def catalog_sha256(tools):
    return hashlib.sha256(canon(sorted(tools, key=lambda t: t["name"])).encode()).hexdigest()


# R3-15: the catalog is sent by the agent or its MCP server. A "read-looking" name is not enough for class `pass` (no owner review at all):
# a name with an action word, or a schema that takes code/command/SQL, is UNKNOWN and the owner decides.
RISKY_WORDS = re.compile(r"(?:^|[_\W]|(?<=[a-z])(?=[A-Z]))(?:run|exec|execute|eval|shell|bash|sh|sql|script|cmd|command|deploy|wipe|kill|reset|restart|"
                         r"apply|install|upload|write|call|invoke|launch|start|stop|sync|set|update|create|grant|revoke|enable|disable)(?:$|[_\W]|(?=[A-Z]))", re.I)
RISKY_PROPS = {"command", "cmd", "sql", "script", "code", "statement", "shell", "expression", "query_string", "args", "argv"}


def guess_class(name, schema=None):
    for cls, rx in CLASS_WORDS:
        if rx.search(name):
            if cls == "pass":
                props = schema.get("properties") if isinstance(schema, dict) and isinstance(schema.get("properties"), dict) else {}
                if RISKY_WORDS.search(name) or any(str(p).lower() in RISKY_PROPS for p in props):
                    return UNKNOWN
            return cls
    return UNKNOWN


def _props(schema):
    p = schema.get("properties") if isinstance(schema, dict) else None
    return p if isinstance(p, dict) else {}


def _types(ps):
    t = ps.get("type") if isinstance(ps, dict) else None
    return set(t) if isinstance(t, list) else ({t} if isinstance(t, str) else set())


def role_of_prop(name, ps):
    n = name.lower()
    if n in RECIPIENT_PROPS:
        return "recipient"
    if n in TEXT_PROPS:
        return "text"
    if n in AMOUNT_PROPS and "integer" in _types(ps):
        return "amount"
    return UNKNOWN


def suggest_toolmap(catalog):
    """-> {"toolmap": {...version 1, default deny, every non-pass tool strict...}, "unknown": [{"tool", "arg"}], "args": {tool: {arg: role}}}.
    arg None in `unknown` = the class of the tool is unknown. Pass tools get no argument mapping."""
    tools, unknown, roles = {}, [], {}
    for t in sorted(catalog, key=lambda x: x["name"]):
        n = t["name"]
        cls = guess_class(n, t.get("inputSchema"))
        entry = {"class": cls}
        roles[n] = {}
        if cls == UNKNOWN:
            unknown.append({"tool": n, "arg": None})
        if cls != "pass":
            entry["strict"] = True
            rec, txt, amt = [], [], None
            for p, ps in sorted(_props(t["inputSchema"]).items()):
                r = role_of_prop(p, ps)
                roles[n][p] = r
                if r == "recipient":
                    rec.append("$." + p)
                elif r == "text":
                    txt.append("$." + p)
                elif r == "amount" and amt is None:
                    amt = "$." + p
                else:
                    if r == "amount":
                        roles[n][p] = r = UNKNOWN
                    unknown.append({"tool": n, "arg": p})
            if rec:
                entry["recipient"] = rec[0] if len(rec) == 1 else _rec_order(rec)
            if txt:
                entry["text"] = txt
            if amt:
                entry["amount"] = amt
                entry["currency"] = "USD"
        tools[n] = entry
    return {"toolmap": {"version": 1, "default": "deny", "tools": tools}, "unknown": unknown, "args": roles}


def _rec_order(rec):
    """First recipient path is the required one: `to` > `recipient(s)` > `channel` > `path` > `resource` > `email` > cc > bcc."""
    order = ["to", "recipient", "recipients", "channel", "path", "resource", "email", "cc", "bcc"]
    return sorted(rec, key=lambda p: order.index(p[2:].lower()) if p[2:].lower() in order else 99)[:8]


DECISIONS = ("recipient", "text", "extra_keys", "deny_tool")


def apply_decisions(sug, decisions):
    """Owner's decisions over a suggestion: {"tool": {"class": C, "args": {arg: recipient|text|extra_keys|deny_tool}}} -> (toolmap, unknown)."""
    tmap = json.loads(json.dumps(sug["toolmap"]))
    unknown = []
    decisions = decisions if isinstance(decisions, dict) else {}
    for u in sug["unknown"]:
        n, arg = u["tool"], u["arg"]
        d = decisions.get(n) if isinstance(decisions.get(n), dict) else {}
        e = tmap["tools"].get(n)
        if e is None:
            continue
        if d.get("deny_tool") is True:
            tmap["tools"].pop(n, None)          # not in the map -> default deny (TOOL_UNMAPPED)
            continue
        if arg is None:
            c = d.get("class")
            if c in tm.CLASSES:
                e["class"] = c
                if c == "pass":
                    for k in ("recipient", "text", "amount", "currency", "strict"):
                        e.pop(k, None)
            else:
                unknown.append(u)
            continue
        if e.get("class") == "pass":
            continue
        a = (d.get("args") or {}).get(arg) if isinstance(d.get("args"), dict) else None
        if a == "recipient":
            rc = e.get("recipient")
            lst = ([rc] if isinstance(rc, str) else list(rc or [])) + ["$." + arg]
            e["recipient"] = lst[0] if len(lst) == 1 else lst[:8]
        elif a == "text":
            e.setdefault("text", []).append("$." + arg)
        elif a == "extra_keys":
            e.setdefault("extra_keys", []).append(arg)
        elif a == "deny_tool":
            tmap["tools"].pop(n, None)
        else:
            unknown.append(u)
    for n, e in tmap["tools"].items():
        if e["class"] in ("purchase", "sale", "refund") and "amount" not in e:
            unknown.append({"tool": n, "arg": "amount"})
    unknown = [u for u in unknown if u["tool"] in tmap["tools"]]
    return tmap, unknown


def pass_net_tools(catalog, toolmap):
    """Tools of class `pass` in the agent's map (or unlisted under default pass) whose name/description/schema speak of the network."""
    out = []
    for t in catalog:
        e = toolmap["tools"].get(t["name"])
        is_pass = (e is not None and e.get("class") == "pass") or (e is None and toolmap.get("default") == "pass")
        if is_pass and NET_RE.search(t["name"] + " " + t["description"] + " " + canon(t["inputSchema"])):
            out.append(t["name"])
    return sorted(out)


def store_catalog(ctx, agent, tools):
    """-> {catalog_sha256, drift, pass_net_tools}. drift = a previous catalog exists and its hash differs."""
    store.ensure(ctx)
    h = catalog_sha256(tools)
    t = store.now()
    with ctx.db.lock:
        prev = ctx.db.one("SELECT sha256 FROM flow_catalogs WHERE agent_id=?", (agent["id"],))
        drift = prev is not None and prev["sha256"] != h
        ctx.db.x("INSERT OR REPLACE INTO flow_catalogs(account_id,agent_id,catalog_json,sha256,prev_sha256,drift,t) VALUES(?,?,?,?,?,?,?)",
                 (agent["account_id"], agent["id"], canon(tools), h, prev["sha256"] if prev else None, 1 if drift else 0, t))
        ctx.db.x("INSERT INTO flow_catalog_log(account_id,agent_id,sha256,drift,t) VALUES(?,?,?,?,?)", (agent["account_id"], agent["id"], h, 1 if drift else 0, t))
    return {"catalog_sha256": h, "drift": drift, "pass_net_tools": pass_net_tools(tools, json.loads(agent["toolmap_json"]))}


def get_catalog(ctx, agent):
    """0.2.0 merge (02 <-> 05): the CatalogView of openapi-0.2 (agent_id, catalog_sha256|null, tools, drift, suggested_toolmap|null,
    unknown, coverage|null) + 02's own members (suggestion, prev_sha256, t, pass_net_tools). No catalog yet -> 200 with nulls (as stub02)."""
    store.ensure(ctx)
    r = ctx.db.one("SELECT * FROM flow_catalogs WHERE agent_id=?", (agent["id"],))
    cov = coverage_of(ctx, agent)
    if r is None:
        return {"agent_id": agent["id"], "catalog_sha256": None, "tools": [], "drift": False, "suggested_toolmap": None, "unknown": [],
                "coverage": cov}
    tools = json.loads(r["catalog_json"])
    sug = suggest_toolmap(tools)
    return {"agent_id": agent["id"], "catalog_sha256": r["sha256"], "prev_sha256": r["prev_sha256"], "drift": bool(r["drift"]), "t": r["t"],
            "tools": tools, "suggestion": sug, "suggested_toolmap": sug["toolmap"], "unknown": sug["unknown"], "coverage": cov,
            "pass_net_tools": pass_net_tools(tools, json.loads(agent["toolmap_json"]))}


def coverage_of(ctx, agent):
    store.ensure(ctx)
    r = ctx.db.one("SELECT coverage_json FROM flow_coverage WHERE agent_id=?", (agent["id"],))
    if r is None:
        return None
    d = json.loads(r["coverage_json"])
    return dict(d, operator_declared=True)


def _require_catalog(ctx, agent):
    c = get_catalog(ctx, agent)
    if c["catalog_sha256"] is None:
        raise Err(404, "NOT_FOUND", "no catalog for this agent")
    return c


def draft(ctx, agent, decisions):
    """Draft tool map from the stored catalog + the owner's decisions. Any UNKNOWN left -> 422 CATALOG_UNRESOLVED. Never applied here."""
    c = _require_catalog(ctx, agent)
    if not decisions:                  # openapi-0.2: the draft to decide on (the page shows it), applicable only without UNKNOWN
        return {"toolmap_draft": c["suggested_toolmap"], "unknown": c["unknown"], "applicable": not c["unknown"],
                "catalog_sha256": c["catalog_sha256"]}
    tmap, unknown = apply_decisions(c["suggestion"], decisions)
    if unknown:
        raise Err(422, "CATALOG_UNRESOLVED", json.dumps(unknown, ensure_ascii=False))
    try:
        tm.check_toolmap(tmap)
    except tm.ToolmapInvalid as e:
        raise Err(422, "CATALOG_UNRESOLVED", str(e))
    return {"toolmap": tmap, "toolmap_draft": tmap, "unknown": [], "applicable": True, "toolmap_sha256": tm.toolmap_hash(tmap), "catalog_sha256": c["catalog_sha256"],
            "apply": "PUT /api/agents/%s/toolmap (step-up), then a new signed mandate" % agent["id"]}


def store_coverage(ctx, agent, b):
    """POST /v1/coverage (04): the operator's declaration, kept as the latest per agent (marked operator-declared, not proof)."""
    if not isinstance(b, dict) or b.get("level") not in ("C0", "C1", "C2", "C3"):
        raise Err(422, "COVERAGE_INVALID", "level C0..C3")
    unw, pnt = b.get("unwitnessed", []), b.get("pass_net_tools", [])
    if not (isinstance(unw, list) and all(isinstance(x, str) and len(x) <= 300 for x in unw) and len(unw) <= 200):
        raise Err(422, "COVERAGE_INVALID", "unwitnessed: list of strings")
    if not (isinstance(pnt, list) and all(isinstance(x, str) and len(x) <= 200 for x in pnt) and len(pnt) <= 500):
        raise Err(422, "COVERAGE_INVALID", "pass_net_tools: list of strings")
    tool = b.get("tool") if isinstance(b.get("tool"), str) else ""
    store.ensure(ctx)
    doc = {"level": b["level"], "unwitnessed": unw, "tool": tool[:64], "pass_net_tools": pnt, "trust": "operator-declared", "t": store.now()}
    ctx.db.x("INSERT OR REPLACE INTO flow_coverage(agent_id,account_id,coverage_json,t) VALUES(?,?,?,?)",
             (agent["id"], agent["account_id"], canon(doc), doc["t"]))
    return {"stored": True, "level": doc["level"], "trust": doc["trust"]}
