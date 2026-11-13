"""R5 (02.11.2026) consistency check of purchase.allowed_payees / purchase.min_per_action (server 0.2.83, client 0.2.53, ERRATA-05 E5-8;
report cloud/OTCHET-R5-SVERKA-2026-11-02.md).

Three deciders get the same inputs: the server's core (svidetel_v4/decide.py), the client's copy (mcp/deus_witness/verify_pack/aar_ref/decide.py)
and the independent Swift verifier (cloud/verifier_c_wa, built here from src/*.swift into a temporary folder, run on abstract decision vectors).
Each case asserts all three agree AND the answer E5-8 prescribes (recipient byte for byte, no canonical form; the bounds inclusive; payee before
the amount; the currency of the mandate). The schema of the new members is compared too (Python validate_mandate vs Swift register_mandate).
Live gaps are xfail(strict=True) with the severity in the reason."""
import copy
import importlib.util
import json
import os
import shutil
import subprocess

import pytest

CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SWIFT_SRC = os.path.join(CLOUD, "verifier_c_wa", "src")
CLIENT_CORE = os.path.join(CLOUD, "mcp", "deus_witness", "verify_pack")
WEB_JS = os.path.join(CLOUD, "web", "js")

DEL = object()
PAYEES = ["merchant-1", "café-paris", "https://shop.example/pay"]          # NFC "café"
M0 = {"v": "deus-aar-0.1", "id": "m1", "principal": "p", "agent": "agent-1", "nbf": 0, "exp": 86400, "currency": "USD",
      "budget_window_s": 86400, "forbidden_data": [], "named_circle": False, "key_attestation": "software",
      "permissions": {"purchase": {"max_per_action": 40000, "budget": 100000, "min_per_action": 10000, "allowed_payees": PAYEES}}}


def _a(**kw):
    a = {"class": "purchase", "agent": "agent-1", "amount": 27999, "currency": "USD", "recipient": "merchant-1", "data": []}
    for k, v in kw.items():
        if v is DEL:
            a.pop(k, None)
        else:
            a[k] = v
    return a


def _m(**pu):
    m = copy.deepcopy(M0)
    for k, v in pu.items():
        if v is DEL:
            m["permissions"]["purchase"].pop(k, None)
        else:
            m["permissions"]["purchase"][k] = v
    return m


A, D_RCPT, D_PAL, D_AMT = ("allow", "OK"), ("deny", "RECIPIENT"), ("deny", "PER_ACTION_LIMIT"), ("deny", "BAD_AMOUNT")
# id -> (mandate, action, ledger state, E5-8 answer)
CASES = {
    "exact": (M0, _a(), {}, A),
    "case_upper_first": (M0, _a(recipient="Merchant-1"), {}, D_RCPT),
    "case_all_upper": (M0, _a(recipient="MERCHANT-1"), {}, D_RCPT),
    "space_lead": (M0, _a(recipient=" merchant-1"), {}, D_RCPT),
    "space_trail": (M0, _a(recipient="merchant-1 "), {}, D_RCPT),
    "tab_trail": (M0, _a(recipient="merchant-1\t"), {}, D_RCPT),
    "nbsp_trail": (M0, _a(recipient="merchant-1 "), {}, D_RCPT),
    "zero_width": (M0, _a(recipient="merchant​-1"), {}, D_RCPT),
    "unicode_hyphen": (M0, _a(recipient="merchant‐1"), {}, D_RCPT),
    "cyrillic_e": (M0, _a(recipient="mеrchant-1"), {}, D_RCPT),
    "fullwidth": (M0, _a(recipient="ｍerchant-1"), {}, D_RCPT),
    "nfc_vs_nfc": (M0, _a(recipient="café-paris"), {}, A),
    "nfd_vs_nfc_list": (M0, _a(recipient="café-paris"), {}, D_RCPT),
    "nfd_list_nfd": (_m(allowed_payees=["café-paris"]), _a(recipient="café-paris"), {}, A),
    "nfd_list_nfc": (_m(allowed_payees=["café-paris"]), _a(recipient="café-paris"), {}, D_RCPT),
    "url_exact": (M0, _a(recipient="https://shop.example/pay"), {}, A),
    "url_slash": (M0, _a(recipient="https://shop.example/pay/"), {}, D_RCPT),
    "url_scheme_case": (M0, _a(recipient="HTTPS://shop.example/pay"), {}, D_RCPT),
    "url_host_case": (M0, _a(recipient="https://SHOP.example/pay"), {}, D_RCPT),
    "url_default_port": (M0, _a(recipient="https://shop.example:443/pay"), {}, D_RCPT),
    "url_query": (M0, _a(recipient="https://shop.example/pay?x=1"), {}, D_RCPT),
    "url_no_scheme": (M0, _a(recipient="shop.example/pay"), {}, D_RCPT),
    "url_pct": (M0, _a(recipient="https://shop.example/%70ay"), {}, D_RCPT),
    "url_fragment": (M0, _a(recipient="https://shop.example/pay#x"), {}, D_RCPT),
    "rcpt_empty": (M0, _a(recipient=""), {}, D_RCPT),
    "rcpt_int": (M0, _a(recipient=5), {}, D_RCPT),
    "rcpt_null": (M0, _a(recipient=None), {}, D_RCPT),
    "rcpt_absent": (M0, _a(recipient=DEL), {}, D_RCPT),
    "rcpt_list": (M0, _a(recipient=["merchant-1"]), {}, D_RCPT),
    "amount_min_minus_1": (M0, _a(amount=9999), {}, D_PAL),
    "amount_min": (M0, _a(amount=10000), {}, A),
    "amount_max": (M0, _a(amount=40000), {}, A),
    "amount_max_plus_1": (M0, _a(amount=40001), {}, D_PAL),
    "amount_zero": (M0, _a(amount=0), {}, D_PAL),
    "amount_float": (M0, _a(amount=10000.0), {}, D_AMT),
    "amount_str": (M0, _a(amount="10000"), {}, D_AMT),
    "amount_bool": (M0, _a(amount=True), {}, D_AMT),
    "amount_negative": (M0, _a(amount=-1), {}, D_AMT),
    "amount_absent": (M0, _a(amount=DEL), {}, D_AMT),
    "currency_other": (M0, _a(currency="EUR"), {}, D_AMT),
    "currency_lower": (M0, _a(currency="usd"), {}, D_AMT),
    "currency_space": (M0, _a(currency=" USD"), {}, D_AMT),
    "currency_null": (M0, _a(currency=None), {}, D_AMT),
    "currency_absent": (M0, _a(currency=DEL), {}, D_AMT),
    "currency_other_and_bad_payee": (M0, _a(currency="EUR", recipient="x"), {}, D_AMT),     # step 6 before step 10
    "payee_before_amount": (M0, _a(amount=5, recipient="x"), {}, D_RCPT),
    "payee_before_max": (M0, _a(amount=45000, recipient="x"), {}, D_RCPT),
    "budget_edge": (M0, _a(amount=10000), {"mandate_committed": 90000}, A),
    "budget_edge_plus_1": (M0, _a(amount=10001), {"mandate_committed": 90000}, ("deny", "BUDGET")),
    "payees_null": (_m(allowed_payees=None), _a(recipient="anyone"), {}, A),
    "payees_absent": (_m(allowed_payees=DEL), _a(recipient="anyone"), {}, A),
    "min_null": (_m(min_per_action=None), _a(amount=1), {}, A),
    "min_absent": (_m(min_per_action=DEL), _a(amount=1), {}, A),
    "min_zero_amount_zero": (_m(min_per_action=0), _a(amount=0), {}, A),
    "min_eq_max": (_m(min_per_action=40000), _a(amount=40000), {}, A),
    "list_narrows_never_widens": (_m(max_per_action=DEL, budget=DEL), _a(amount=20000), {}, ("defer", "ESCALATE_MONEY")),
}
# schema-invalid mandates (MANDATE_MALFORMED in both schemas): what decide() alone does with them
BAD_SCHEMA = {
    "payees_str_substring": (_m(allowed_payees="merchant-1"), _a(recipient="chant")),
    "payees_str_other": (_m(allowed_payees="merchant-1"), _a(recipient="evil")),
    "payees_int_rcpt_int": (_m(allowed_payees=[5]), _a(recipient=5)),
    "payees_empty": (_m(allowed_payees=[]), _a()),
    "min_float": (_m(min_per_action=30000.5), _a()),
    "min_str": (_m(min_per_action="30000"), _a()),
}


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _client_decide():
    """aar_ref/decide.py of the client, imported under its own package name (it imports aar_ref.*)."""
    import sys
    if CLIENT_CORE not in sys.path:
        sys.path.append(CLIENT_CORE)
    from aar_ref.decide import decide
    return decide


def _py(decide, m, a, st):
    try:
        return tuple(decide(m, a, st, now=100))
    except Exception as e:      # noqa: BLE001  (a crash is an answer too: it is compared)
        return ("EXCEPTION", type(e).__name__)


@pytest.fixture(scope="module")
def swift(tmp_path_factory):
    if shutil.which("swiftc") is None:
        pytest.skip("no swiftc: the Swift verifier cannot be built here")
    d = tmp_path_factory.mktemp("aarc")
    exe = str(d / "aarc-wa")
    q = subprocess.run(["swiftc", "-O", "-swift-version", "5", *sorted(os.path.join(SWIFT_SRC, f) for f in os.listdir(SWIFT_SRC)
                                                                         if f.endswith(".swift")), "-o", exe],
                       capture_output=True, text=True, timeout=500)
    assert q.returncode == 0, q.stderr[-2000:]
    return exe


def _swift_decisions(exe, cases, tmp):
    """{id: (mandate, action, state)} -> {id: (verdict, reason)} from one run of `aarc-wa --vectors` (abstract decision vectors)."""
    os.makedirs(os.path.join(tmp, "cose"), exist_ok=True)
    for cid, (m, a, st) in cases.items():
        v = {"id": cid, "kind": "decision", "class": "x", "input": {"mandate": m, "action": a, "now": 100, "ledger_state": st},
             "expected": {"verdict": "?", "reason": "?"}}
        with open(os.path.join(tmp, cid + ".json"), "w", encoding="utf-8") as f:
            json.dump(v, f, ensure_ascii=False)
    md = os.path.join(tmp, "out.md")
    subprocess.run([exe, "--vectors", tmp, "--md", md, "--quiet"], capture_output=True, text=True, timeout=120)
    out = {}
    for line in open(md, encoding="utf-8"):
        p = [x.strip() for x in line.split("|")]
        if len(p) > 8 and p[1] in cases:
            d = dict(kv.split("=", 1) for kv in p[8].split(","))
            out[p[1]] = (d.get("verdict"), d.get("reason"))
    return out


@pytest.fixture(scope="module")
def swift_answers(swift, tmp_path_factory):
    allc = {k: v[:3] for k, v in CASES.items()}
    allc.update({"BAD_" + k: (m, a, {}) for k, (m, a) in BAD_SCHEMA.items()})
    return _swift_decisions(swift, allc, str(tmp_path_factory.mktemp("vec")))


# ---- 1. the three deciders on valid mandates ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("cid", list(CASES))
def test_r5_purchase_three_deciders_agree_with_e5_8(cid, swift_answers):
    from svidetel_v4.decide import decide as server_decide
    m, a, st, want = CASES[cid]
    s, c, w = _py(server_decide, m, a, st), _py(_client_decide(), m, a, st), swift_answers.get(cid)
    assert (s, c, w) == (want, want, want), "server %s, client %s, swift %s, E5-8 %s" % (s, c, w, want)


def test_r5_purchase_valid_mandate_passes_both_schemas(swift, tmp_path):
    from svidetel_v4.schema import validate_mandate
    assert validate_mandate(M0) is None
    assert _swift_register(swift, {"ok": M0}, str(tmp_path)) == {"ok": "accept"}


# ---- 2. schema of the new members: Python and Swift refuse the same shapes -------------------------------------------------------------
def _swift_register(exe, mandates, tmp):
    """{id: mandate} -> {id: 'accept' | reason} from register_mandate in abstract sequence vectors."""
    os.makedirs(os.path.join(tmp, "cose"), exist_ok=True)
    for cid, m in mandates.items():
        m = dict(m, principal="pk-principal")
        v = {"id": cid, "kind": "sequence", "class": "x", "input": {"pinned_principal_key": "pk-principal",
             "ops": [{"op": "register_mandate", "mandate": m, "signed_by": "pk-principal"}]}, "expected": {"steps": [{"result": "accept"}]}}
        with open(os.path.join(tmp, cid + ".json"), "w", encoding="utf-8") as f:
            json.dump(v, f, ensure_ascii=False)
    md = os.path.join(tmp, "out.md")
    subprocess.run([exe, "--vectors", tmp, "--md", md, "--quiet"], capture_output=True, text=True, timeout=120)
    out = {}
    for line in open(md, encoding="utf-8"):
        p = [x.strip() for x in line.split("|")]
        if len(p) > 8 and p[1] in mandates:
            d = dict(kv.split("=", 1) for kv in p[8].split(","))
            out[p[1]] = "accept" if d.get("result") == "accept" else d.get("reason")
    return out


SCHEMA = {
    "payees_str": (_m(allowed_payees="merchant-1"), False),
    "payees_int": (_m(allowed_payees=[5]), False),
    "payees_empty": (_m(allowed_payees=[]), False),
    "payees_dup": (_m(allowed_payees=["a", "a"]), False),
    "payees_201": (_m(allowed_payees=["p%d" % i for i in range(201)]), False),
    "payees_200": (_m(allowed_payees=["p%d" % i for i in range(200)]), True),
    "payees_empty_str": (_m(allowed_payees=[""]), False),
    "payees_513": (_m(allowed_payees=["a" * 513]), False),
    "payees_512_bytes_emoji": (_m(allowed_payees=["\U0001F600" * 128]), True),     # 0.2.84 (R5-P4): the unit is UTF-8 bytes: 128 x 4 = 512
    "payees_516_bytes_emoji": (_m(allowed_payees=["\U0001F600" * 129]), False),    # 129 code points, 516 bytes: refused (was accepted by code points)
    "payees_512_bytes_e_acute": (_m(allowed_payees=["\u00e9" * 256]), True),
    "payees_514_bytes_e_acute": (_m(allowed_payees=["\u00e9" * 257]), False),
    "payees_nfc_and_nfd": (_m(allowed_payees=["café", "café"]), True),   # two entries that look the same (see R5-P4)
    "min_float": (_m(min_per_action=30000.5), False),
    "min_str": (_m(min_per_action="30000"), False),
    "min_negative": (_m(min_per_action=-1), False),
    "min_gt_max": (_m(min_per_action=40001), False),
    "min_without_max": (_m(max_per_action=DEL, min_per_action=99999999), True),
    "unknown_member": (_m(payees=["x"]), False),
}


def test_r5_purchase_schema_python_and_swift_agree(swift, tmp_path):
    from svidetel_v4.schema import validate_mandate
    sw = _swift_register(swift, {k: v[0] for k, v in SCHEMA.items()}, str(tmp_path))
    bad = []
    for k, (m, ok) in SCHEMA.items():
        py_ok = validate_mandate(m) is None
        sw_ok = sw.get(k) == "accept"
        if not (py_ok == sw_ok == ok):
            bad.append((k, "python", py_ok, "swift", sw.get(k), "want", ok))
    assert not bad, bad


# ---- 3. decide() alone on schema-invalid mandates (defence in depth) --------------------------------------------------------------------
@pytest.mark.parametrize("cid", list(BAD_SCHEMA))
def test_r5_purchase_bad_schema_python_server_and_client_agree(cid):
    from svidetel_v4.decide import decide as server_decide
    m, a = BAD_SCHEMA[cid]
    assert _py(server_decide, m, a, {}) == _py(_client_decide(), m, a, {})


@pytest.mark.parametrize("cid", ["payees_str_other", "payees_int_rcpt_int", "min_float", "min_str"])
@pytest.mark.xfail(strict=True, reason="R5-P1 НИЗКАЯ: on a schema-invalid purchase permission decide() differs between Python and Swift: a string "
                   "allowed_payees is a SUBSTRING test in Python (`recipient in 'merchant-1'`) and no restriction in Swift; [5] lets an integer "
                   "recipient 5 through in Python only; a float min_per_action binds in Python and is ignored in Swift; a string one is a TypeError "
                   "in Python. Unreachable today: both schemas refuse these mandates first (MANDATE_MALFORMED), see the schema test. Сознательно оставлено в 0.2.84: "
                   "closing it changes decide() of the core and of Swift for inputs no valid ledger can carry; defence in depth, a later pass")
def test_r5_purchase_bad_schema_python_and_swift_agree(cid, swift_answers):
    from svidetel_v4.decide import decide as server_decide
    m, a = BAD_SCHEMA[cid]
    assert _py(server_decide, m, a, {}) == swift_answers.get("BAD_" + cid)


# ---- 4. the paths that BUILD the payee list and the purchase action (server form, page, tool map) ----------------------------------------
def _form_mandate(**form):
    from app.mandates import mandate_from_form
    base = {"purchase": {"enabled": True, "max_per_action": 40000, "budget": 100000}}
    base.update(form)
    return mandate_from_form(base, "p", "agent-1", "webauthn-registration", now=1000)


def test_r5_purchase_form_keeps_payees_byte_exact():
    """The server form does not trim, case-fold or normalise payees: what the owner typed is what is compared (E5-8)."""
    m = _form_mandate(purchase={"enabled": True, "max_per_action": 40000, "budget": 100000,
                                "payees": ["merchant-1", "Merchant-1", "café-paris", "Acme, Inc."]})
    assert m["permissions"]["purchase"]["allowed_payees"] == ["merchant-1", "Merchant-1", "café-paris", "Acme, Inc."]


def test_r5_purchase_form_currency_case_is_the_tool_maps():
    """R5-P2 (0.2.84): the form upper-cases the code, the tool map upper-cases what it writes into the action: 'usd' on either side meets."""
    from app import toolmap as tm
    assert _form_mandate(currency="usd")["currency"] == "USD"
    assert _form_mandate(currency="Eur")["currency"] == "EUR"
    from app.context import Err
    for bad in ("US", "U$D", "\u00dcSD", "", 5):
        with pytest.raises(Err):
            _form_mandate(currency=bad)
    src = open(tm.__file__, encoding="utf-8").read()
    assert 'act["currency"] = cur.upper() if isinstance(cur, str) and cur.isascii() else cur' in src


@pytest.mark.xfail(strict=True, reason="R5-P2 НИЗКАЯ, сознательно оставлено (0.2.84): a mandate in EUR is accepted by the form, because a custom tool map "
                   "may write currency EUR; with the built-in maps (USD) every purchase is BAD_AMOUNT and nothing tells the owner. Closing it needs "
                   "the form to know the agent's tool map (a warning on the page), not a refusal of the code")
def test_r5_purchase_form_currency_matches_what_actions_carry():
    from app.context import Err
    with pytest.raises(Err):
        _form_mandate(currency="EUR")


def _node(script):
    if shutil.which("node") is None:
        pytest.skip("no node")
    q = subprocess.run(["node", "--input-type=module", "-e", script], capture_output=True, text=True, timeout=60, cwd=WEB_JS)
    assert q.returncode == 0, q.stderr[-2000:]
    return json.loads(q.stdout.strip().splitlines()[-1])


def _page_round_trip(payees):
    """The mandate page: Import from JSON -> the form fields (0.2.84: inputsFromMandate puts one payee per line) -> the form the page posts
    (lines() splits on line breaks and trims each line)."""
    return _node("""
import { importForm } from '%s/mandate_import.js';
import { lines } from '%s/ui.js';
const r = importForm(JSON.stringify({purchase: {enabled: true, budget: 100000, max_per_action: 40000, payees: %s}}), 'agent-1', 1000);
console.log(JSON.stringify({errors: r.errors, field: r.values && r.values.pu_payees, posted: r.values ? lines(r.values.pu_payees) : null}));
""" % (WEB_JS, WEB_JS, json.dumps(payees)))


def test_r5_purchase_page_round_trip_keeps_payee_with_comma():
    r = _page_round_trip(["Acme, Inc.", "merchant-1"])
    assert r["errors"] == [] and r["posted"] == ["Acme, Inc.", "merchant-1"], r
    srv = _form_mandate(purchase={"enabled": True, "max_per_action": 40000, "budget": 100000, "payees": r["posted"]})
    assert srv["permissions"]["purchase"]["allowed_payees"] == ["Acme, Inc.", "merchant-1"]
    d = _node("""
import { describeMandate } from '%s/describe.js';
console.log(JSON.stringify(Object.fromEntries(describeMandate(%s))));
""" % (WEB_JS, json.dumps(srv)))
    assert d["Payees"] == 'only 2: "Acme, Inc.", "merchant-1" (any other payee is denied)', d    # the signing page: exactly the signed list


def test_r5_purchase_edge_spaces_refused_on_page_and_server():
    """R5-P5 (0.2.84): a payee id with a space at either end is refused by the page import AND by the server form (it was trimmed by the
    page and kept by the server: one input, two mandates)."""
    from app.context import Err
    for pay in ([" merchant-1"], ["shop "]):
        r = _page_round_trip(pay)
        assert r["errors"] and "space at the start or end" in r["errors"][0], r
        with pytest.raises(Err):
            _form_mandate(purchase={"enabled": True, "max_per_action": 40000, "budget": 100000, "payees": pay})


@pytest.mark.parametrize("pay,ok", [(["\U0001F600" * 64], True), (["\U0001F600" * 65], False), (["\u00e9" * 128], True), (["\u00e9" * 129], False),
                                    (["a" * 256], True), (["a" * 257], False)])
def test_r5_purchase_payee_length_unit_is_the_same_on_page_and_server(pay, ok):
    """R5-P4 (0.2.84): page import and server form count UTF-8 bytes, both at most 256 (the schema allows 512 bytes)."""
    from app.context import Err
    r = _page_round_trip(pay)
    try:
        _form_mandate(purchase={"enabled": True, "max_per_action": 40000, "budget": 100000, "payees": pay})
        srv_ok = True
    except Err:
        srv_ok = False
    assert (r["errors"] == []) == srv_ok == ok, (r, srv_ok)


def test_r5_purchase_toolmap_non_string_vendor_current_behaviour():
    """Current (НИЗКАЯ, documented): the tool map turns a non-string `vendor` into str() (app/toolmap.recipient_values), so a JSON number 12345
    matches the payee "12345". The comment there says 'the core denies it', which holds only without a payee list."""
    from app import toolmap as tm
    t = {"class": "purchase", "recipient": "$.vendor", "amount": "$.amount_cents", "currency": "USD", "strict": True}
    assert tm.recipient_values(t, {"vendor": 12345, "amount_cents": 20000}) == ["12345"]
    from svidetel_v4.decide import decide
    m = _m(allowed_payees=["12345"])
    assert decide(m, _a(recipient="12345"), {}, now=100) == A
