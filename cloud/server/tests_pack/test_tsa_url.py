"""0.2.9: DW_TSA_URL (+ DW_TSA_CA, DW_TSA_NAME) = the second time anchor from one RFC 3161 TSA the operator names. Off by default.
No network at all: a fake TSA (lib/tsa/testtsa.TestTSA) answers in process through a replaced urllib.request.urlopen."""
import io
import os
import shutil
import urllib.request

import pytest

from app import jobs
from app.config import Config, ConfigError
from kit import run_verify
from tests.test_pack import scenario, unpack

import testtsa

ENV = {"DW_DATA_DIR": "/tmp/x", "DW_WITNESS_KEY_FILE": "/tmp/k", "DW_KEY_PEPPER": "p", "DW_RP_ID": "localhost", "DW_ORIGIN": "http://localhost:8810"}


class FakeNet:
    """urllib.request.urlopen replacement: a POST to `url` is answered by `tsa.respond(body)`; anything else (or a second URL) fails loudly."""
    def __init__(self, url, tsa):
        self.url, self.tsa, self.calls = url, tsa, 0

    def __call__(self, req, timeout=None):
        assert req.full_url == self.url and req.get_method() == "POST", req.full_url
        assert req.get_header("Content-type") == "application/timestamp-query"
        self.calls += 1
        return io.BytesIO(self.tsa.respond(req.data))


@pytest.fixture(scope="module")
def fake_tsa():
    return testtsa.TestTSA("Fake TSA (tests)", kind="ec")


@pytest.fixture()
def root(tmp_path, fake_tsa):
    p = tmp_path / "fake-root.pem"
    p.write_bytes(fake_tsa.root_pem)
    return str(p)


def test_config_reads_and_checks_dw_tsa_url(root, tmp_path):
    c = Config.from_env(dict(ENV, DW_TSA_URL="https://tsa.example.org/tsr", DW_TSA_CA=root))
    assert (c.tsa_url, c.tsa_ca, c.tsa_name) == ("https://tsa.example.org/tsr", root, "tsa-example-org")
    assert Config.from_env(dict(ENV, DW_TSA_URL="http://tsa.example/x", DW_TSA_CA=root, DW_TSA_NAME="mytsa")).tsa_name == "mytsa"
    assert Config.from_env(dict(ENV)).tsa_url == ""                                            # off by default
    (tmp_path / "junk.pem").write_text("not a certificate")
    for bad, why in ((dict(DW_TSA_URL="https://tsa.example/x"), "DW_TSA_CA"),                              # no root: nothing could be verified
                     (dict(DW_TSA_URL="https://tsa.example/x", DW_TSA_CA=str(tmp_path / "none.pem")), "not a file"),
                     (dict(DW_TSA_URL="https://tsa.example/x", DW_TSA_CA=str(tmp_path / "junk.pem")), "certificate"),
                     (dict(DW_TSA_URL="ftp://tsa.example/x", DW_TSA_CA=root), "http"),
                     (dict(DW_TSA_URL="https://u:pw@tsa.example/x", DW_TSA_CA=root), "user:password"),
                     (dict(DW_TSA_URL="http://timestamp.sectigo.com", DW_TSA_CA=root), "excluded"),
                     (dict(DW_TSA_URL="https://tsa.example/x", DW_TSA_CA=root, DW_TSA_NAME="Apple"), "DW_TSA_NAME"),
                     (dict(DW_TSA_URL="https://tsa.example/x", DW_TSA_CA=root, DW_TSA_NAME="apple"), "excluded")):
        with pytest.raises(ConfigError) as e:
            Config.from_env(dict(ENV, **bad))
        assert why in str(e.value), (bad, str(e.value))


def _on(app, root, url="https://tsa.example.org/tsr"):
    app.state.ctx.cfg.tsa_url, app.state.ctx.cfg.tsa_ca, app.state.ctx.cfg.tsa_name = url, root, "faketsa"


def test_batch_gets_a_token_next_to_the_ots_and_the_pack_verifies_offline(client, owner, app, root, fake_tsa, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("DW_TSA", raising=False)
    net = FakeNet("https://tsa.example.org/tsr", fake_tsa)
    monkeypatch.setattr(urllib.request, "urlopen", net)
    _on(app, root)
    scenario(client, owner)
    ctx = app.state.ctx
    bid = jobs.anchor_once(ctx)                                     # tsa=None: DW_TSA_URL alone turns it on
    assert "batch %s: tsa=1 ok\n" % bid in capsys.readouterr().out and net.calls == 1
    tsr = os.path.join(ctx.anchor_dir, "%s.tsr.faketsa" % bid)       # beside <bid>.json / <bid>.ots in the anchors folder
    assert os.path.getsize(tsr) > 300 and os.path.isfile(os.path.join(ctx.anchor_dir, "tsa-ca", "faketsa.pem"))
    pack = unpack(client, tmp_path / "pack")
    assert os.path.isfile(pack / "anchors" / ("%s.tsr.faketsa" % bid)) and os.path.isfile(pack / "anchors" / "tsa-ca" / "faketsa.pem")
    rc, out = run_verify(str(pack), "--offline")
    assert rc == 0 and out.strip().splitlines()[-1] == "RESULT: VALID", out
    assert "tsa %s: OK (faketsa)" % bid in out
    assert "tsa-ca faketsa: sha256" in out                           # the root came from the pack: its fingerprint is printed
    pinned = tmp_path / "pinned"
    pinned.mkdir()
    shutil.copyfile(root, pinned / "faketsa.pem")
    rc, out = run_verify(str(pack), "--offline", "--tsa-ca=%s" % pinned)
    assert rc == 0 and "tsa %s: OK (faketsa)" % bid in out and "tsa-ca faketsa" not in out
    other = testtsa.TestTSA("someone else", kind="ec")              # a root the verifier trusts that did not sign: MISMATCH
    (pinned / "faketsa.pem").write_bytes(other.root_pem)
    rc, out = run_verify(str(pack), "--offline", "--tsa-ca=%s" % pinned)
    assert rc != 0 and "tsa %s: MISMATCH (faketsa: TSA_CHAIN)" % bid in out, out


def test_token_over_another_root_is_not_kept(client, owner, app, root, fake_tsa, monkeypatch, capsys):
    class Liar(testtsa.TestTSA):
        def respond(self, q, gen_time=None, imprint=None):
            return fake_tsa.respond(q, imprint=b"\x00" * 32)
    monkeypatch.setattr(urllib.request, "urlopen", FakeNet("https://tsa.example.org/tsr", Liar("liar")))
    _on(app, root)
    scenario(client, owner)
    bid = jobs.anchor_once(app.state.ctx)
    assert "batch %s: tsa=0 ok failed=faketsa" % bid in capsys.readouterr().out          # the batch itself is recorded
    assert not os.path.exists(os.path.join(app.state.ctx.anchor_dir, "%s.tsr.faketsa" % bid))
    assert app.state.ctx.db.one("SELECT id FROM anchor_batches WHERE id=?", (bid,)) is not None


def test_off_by_default_no_request(client, owner, app, monkeypatch, capsys):
    monkeypatch.delenv("DW_TSA", raising=False)
    def no_net(*a, **k):
        raise AssertionError("a TSA was asked although DW_TSA_URL is not set")
    monkeypatch.setattr(urllib.request, "urlopen", no_net)
    assert app.state.ctx.cfg.tsa_url == ""
    scenario(client, owner)
    bid = jobs.anchor_once(app.state.ctx)
    assert bid and "tsa=" not in capsys.readouterr().out
    assert not [f for f in os.listdir(app.state.ctx.anchor_dir) if ".tsr." in f]


def test_explicit_tsa_false_wins_over_the_url(client, owner, app, root, monkeypatch, capsys):
    def no_net(*a, **k):
        raise AssertionError("tsa=False must not ask")
    monkeypatch.setattr(urllib.request, "urlopen", no_net)
    _on(app, root)
    scenario(client, owner)
    bid = jobs.anchor_once(app.state.ctx, tsa=False)
    assert bid and "tsa=" not in capsys.readouterr().out
