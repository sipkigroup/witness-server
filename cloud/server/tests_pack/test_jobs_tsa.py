"""app/jobs.py: RFC 3161 in the anchor batch, after OTS; a TSA failure never fails the batch; only providers with take=true."""
import json
import os

from app import jobs
from tests.test_pack import scenario


def test_anchor_once_stamps_two_tsa(client, owner, app, providers, capsys):
    scenario(client, owner)
    ctx = app.state.ctx
    bid = jobs.anchor_once(ctx, tsa=True)
    out = capsys.readouterr().out
    assert "batch %s: recorded (DW_ANCHOR=off, not stamped)" % bid in out and "batch %s: tsa=2 ok\n" % bid in out, out
    for n in ("tsa-a", "tsa-b"):
        assert os.path.getsize(os.path.join(ctx.anchor_dir, "%s.tsr.%s" % (bid, n))) > 500
        assert os.path.isfile(os.path.join(ctx.anchor_dir, "tsa-ca", n + ".pem"))
    assert ctx.db.one("SELECT status FROM anchor_batches WHERE id=?", (bid,))["status"] == "off"


def test_tsa_failure_does_not_fail_the_batch(client, owner, app, providers, tsas, capsys, tmp_path, monkeypatch):
    scenario(client, owner)
    doc = json.loads(providers.read_text())
    doc["providers"].append({"name": "down", "url": "http://127.0.0.1:9/tsr", "ca": "tsa-a.pem", "take": True, "terms": "allowed"})
    doc["providers"].append({"name": "wrong-root", "url": doc["providers"][0]["url"], "ca": "tsa-b.pem", "take": True, "terms": "allowed"})
    doc["providers"].append({"name": "not-taken", "url": doc["providers"][0]["url"], "ca": "tsa-a.pem", "take": False})
    providers.write_text(json.dumps(doc))
    ctx = app.state.ctx
    bid = jobs.anchor_once(ctx, tsa=True)
    out = capsys.readouterr().out
    assert "batch %s: tsa=2 ok failed=down,wrong-root" % bid in out, out
    assert not os.path.exists(os.path.join(ctx.anchor_dir, "%s.tsr.wrong-root" % bid))      # unverifiable reply is not kept
    assert not os.path.exists(os.path.join(ctx.anchor_dir, "%s.tsr.not-taken" % bid))
    assert ctx.db.one("SELECT id FROM anchor_batches WHERE id=?", (bid,)) is not None
    assert os.path.isfile(os.path.join(ctx.anchor_dir, bid + ".json"))


def test_repo_providers_are_not_taken_until_terms_checked(client, owner, app, capsys, monkeypatch):
    """lib/tsa/providers.json (P0-3, 19.10.2026): FreeTSA take=true/allowed but its root is not in the repository yet -> skipped;
    DigiCert off (terms unconfirmed); Sectigo / Apple / GlobalSign not listed at all. DW_TSA=on asks nobody, says why."""
    monkeypatch.delenv("DW_TSA_PROVIDERS", raising=False)
    doc = json.load(open(os.path.join(jobs.TSA_DIR, "providers.json")))
    by = {p["name"]: p for p in doc["providers"]}
    assert set(by) == {"freetsa", "digicert"}
    assert by["freetsa"]["take"] is True and by["freetsa"]["terms"] == "allowed"
    assert by["digicert"]["take"] is False and by["digicert"]["terms"] == "unconfirmed"
    assert not any(jobs._excluded(p) for p in doc["providers"])
    for p in doc["providers"]:                                    # never sold as qualified / eIDAS
        assert not any(w in json.dumps(p).lower().replace("not qualified", "") for w in ("qualified", "eidas", "legally"))
    if not os.path.isfile(os.path.join(jobs.TSA_DIR, by["freetsa"]["ca"])):
        assert jobs.tsa_providers() == []
        assert "tsa freetsa skipped: root ca/freetsa.pem missing" in capsys.readouterr().out
    monkeypatch.setenv("DW_TSA", "on")
    scenario(client, owner)
    bid = jobs.anchor_once(app.state.ctx)
    out = capsys.readouterr().out
    assert "batch %s: tsa=0 ok (no TSA with take=true and no DW_TSA_URL: see lib/tsa/USLOVIYA.md)" % bid in out, out


def test_tsa_off_by_default(client, owner, app, providers, capsys, monkeypatch):
    monkeypatch.delenv("DW_TSA", raising=False)
    scenario(client, owner)
    bid = jobs.anchor_once(app.state.ctx)
    assert "tsa=" not in capsys.readouterr().out
    assert not [f for f in os.listdir(app.state.ctx.anchor_dir) if ".tsr." in f and f.startswith(bid)]


def test_tsa_module_missing_is_reported_not_hidden(client, owner, app, providers, capsys, monkeypatch):
    def boom():
        raise ModuleNotFoundError("asn1crypto")
    monkeypatch.setattr(jobs, "_tsa_mod", boom)
    scenario(client, owner)
    bid = jobs.anchor_once(app.state.ctx, tsa=True)
    assert "batch %s: tsa=0 ok failed=tsa-a,tsa-b" % bid in capsys.readouterr().out


def test_excluded_and_unconfirmed_providers_are_never_queried(tmp_path, tsas, capsys):
    """Even with take=true: Sectigo / Apple / GlobalSign / Entrust (by name or by URL host) and anything without terms=allowed."""
    (tmp_path / "r.pem").write_bytes(tsas["tsa-a"].root_pem)
    ps = [{"name": "sectigo", "url": "http://timestamp.sectigo.com", "ca": "r.pem", "take": True, "terms": "allowed"},
          {"name": "mine", "url": "http://timestamp.apple.com/ts01", "ca": "r.pem", "take": True, "terms": "allowed"},
          {"name": "gs", "url": "http://timestamp.globalsign.com/tsa/r6advanced1", "ca": "r.pem", "take": True, "terms": "allowed"},
          {"name": "entrust", "url": "http://example.test/tsr", "ca": "r.pem", "take": True, "terms": "allowed"},
          {"name": "digicert", "url": "http://timestamp.digicert.com", "ca": "r.pem", "take": True, "terms": "unconfirmed"},
          {"name": "noterms", "url": "http://example.test/tsr", "ca": "r.pem", "take": True},
          {"name": "noroot", "url": "http://example.test/tsr", "ca": "missing.pem", "take": True, "terms": "allowed"},
          {"name": "ok", "url": "http://example.test/tsr", "ca": "r.pem", "take": True, "terms": "allowed"}]
    path = tmp_path / "providers.json"
    path.write_text(json.dumps({"providers": ps}))
    assert [p["name"] for p in jobs.tsa_providers(str(path))] == ["ok"]
    out = capsys.readouterr().out
    for n in ("sectigo", "mine", "gs", "entrust", "digicert", "noterms", "noroot"):
        assert "tsa %s skipped" % n in out, (n, out)
