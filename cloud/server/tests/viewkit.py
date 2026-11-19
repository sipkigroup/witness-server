"""r0352 (KAND-ACH-1): every decision on a request whose view the witness can build names that view (409 VIEW_REQUIRED otherwise).
The tests' honest page: it signs the view the witness offers in GET /api/approvals/{rid} (view_sha256), as web/js/approve.js does."""
import hashlib

X = ("view_sha256", "view_signed", "view_signed_sha256")


def answer(c, rid):
    return c.get("/api/approvals/" + rid).json()


def page_view(g):
    """-> the 32 bytes the page signs (the view the witness offers), or None (no view: a decided call)."""
    v = g.get("view_sha256") if isinstance(g, dict) else None
    return bytes.fromhex(v) if isinstance(v, str) and len(v) == 64 else None


def claim(g):
    """-> the request members that claim the view ({} without one)."""
    v = page_view(g)
    return {"view_sha256": v.hex()} if v is not None else {}


def allow_view(g):
    """r0327: the hash a project permission signs: the page view AND the text of trust of the offer (web/js/allowance.js allowViewHash)."""
    from app import allowances as al
    from app import signview
    o = g.get("allowance_offer") or {}
    if page_view(g) is None or not o.get("text_v") or not isinstance(o.get("text"), str):
        return None
    obj = al.allow_view(signview.view_of({k: v for k, v in g.items() if k not in X}), o["text_v"], o["text"])
    return hashlib.sha256(signview.jcs(obj)).digest()


def with_allow_view(a, g):
    """A permission map `a` signed over the view of `g` -> (a with "view", request members)."""
    v = allow_view(g)
    if v is not None:
        a = dict(a, view=v)
        return a, claim(g)
    return a, {}


def release(owner, rid, sha, yes):
    """A release / reject signed over the view the witness offers (the page's decideHeld)."""
    from app.flow.wq import wq
    g = answer(owner.c, rid)
    pay = wq.release_payload(rid, sha, yes, page_view(g))
    return owner.post("/api/approvals/%s/release" % rid, release=yes, envelope_b64=owner.sign(wq.TYP_RELEASE, pay), **claim(g))


def approve(owner, rid, approved=True, g=None):
    """An approval / refusal signed over the view the witness offers."""
    import wa_profile as wa
    from svidetel_v4.state import approval_payload
    g = g or answer(owner.c, rid)
    pay = approval_payload(g["mandate"], g["action"], rid, approved, page_view(g))
    return owner.post("/api/approvals/" + rid, approved=approved, envelope_b64=owner.sign(wa.TYP_APPROVAL, pay), **claim(g))


def allow(owner, rid, a, typ=None, **extra):
    """A project permission `a` signed over the page view + the text of trust (the page's allowance.js) -> (response, the map signed)."""
    import wa_profile as wa
    from app import allowances as al
    a2, cl = with_allow_view(a, answer(owner.c, rid))
    return owner.post("/api/allowances", rid=rid, envelope_b64=owner.sign(typ or al.TYP, wa.cde(a2)), **cl, **extra), a2


# ---- what a server before r0352 accepted: a decision that names no view (packs made then still hold such entries) --------------------
def _acc(owner):
    ctx = owner.c.app.state.ctx
    return ctx, ctx.db.one("SELECT * FROM accounts WHERE id=?", (owner.account["id"],))


def legacy_approve(owner, rid, approved=True):
    """An approval without a view, written by the decision path itself (as a server before r0352 wrote it for an older page)."""
    import wa_profile as wa
    from app import actions as A
    from svidetel_v4.state import approval_payload
    g = answer(owner.c, rid)
    env = wa.b64u_dec(owner.sign(wa.TYP_APPROVAL, approval_payload(g["mandate"], g["action"], rid, approved)))
    ctx, acc = _acc(owner)
    return A.approve_with_envelope(ctx, acc, rid, approved, env)


def legacy_release(owner, rid, rel=True):
    """A release without a view, written by the decision path itself (as a server before r0352 wrote it)."""
    import wa_profile as wa
    from app import actions as A
    from app.flow.wq import wq
    g = answer(owner.c, rid)
    env = wa.b64u_dec(owner.sign(wq.TYP_RELEASE, wq.release_payload(rid, g["action"]["args_sha256"], rel)))
    ctx, acc = _acc(owner)
    return A.release(ctx, acc, owner.account["id"], rid, rel, env)          # a solo account: the user is the account
