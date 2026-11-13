"""Regression catalog for is_secret_path (RT-0.2.55 + common credential files). A path here must stay caught; ordinary files must not be."""
import os, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.hookjudge.bashparse import is_secret_path

H = "/Users/dev/"
SECRET = [
    # RT-0.2.55 (13 found gaps)
    "~/.s3cfg", "~/.boto", "~/.config/rclone/rclone.conf", "~/.terraform.d/credentials.tfrc.json", "~/.config/sops/age/keys.txt",
    "~/AuthKey_ABC123XYZ.p8", "~/.config/hub", "~/.config/containers/auth.json", "~/.config/doctl/config.yaml",
    "~/.config/fly/config.yml", "~/.my.cnf", "~/key.ppk", "~/.authinfo",
    # common
    "~/.authinfo.gpg", "~/.ssh/id_rsa", "~/.ssh/id_rsa.pub", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa", "~/.ssh/id_dsa", "~/.ssh/config",
    "~/.ssh/known_hosts", "~/.ssh/authorized_keys", "~/.aws/credentials", "~/.aws/config", "~/.config/gh/hosts.yml",
    "~/.docker/config.json", "~/.kube/config", "~/.netrc", "~/.npmrc", "~/.pypirc", "~/.pgpass", "~/.git-credentials",
    "~/.vault-token", "~/.terraformrc", "~/.config/git/credentials", "~/.gnupg/secring.gpg", "~/.gnupg/private-keys-v1.d/abc.key",
    "~/.azure/accessTokens.json", "~/.azure/azureProfile.json", "~/.config/gcloud/credentials.db",
    "~/.config/gcloud/application_default_credentials.json", "~/.config/op/config", "~/.config/doctl/x", "~/.config/fly/x",
    "~/Library/Keychains/login.keychain-db", "~/Library/Keychains/x/y",
    "~/proj/.env", "~/proj/.env.local", "~/proj/.env.production", "~/proj/.envrc", "~/proj/secrets.yaml", "~/proj/secrets.yml",
    "~/proj/secret.json", "~/proj/secrets.toml", "~/proj/secrets.env", "~/.zsh_history", "~/.bash_history",
    "~/vpn/client.ovpn", "~/certs/server.pem", "~/certs/server.key", "~/certs/c.p12", "~/certs/c.pfx", "~/certs/app.jks",
    "~/certs/app.keystore", "~/vault/db.kdbx", "~/keys/putty.ppk", "~/AuthKey_X.p8", "~/proj/credentials", "~/proj/.credentials",
    "~/proj/credentials.json", "/etc/ssl/private/site.key", "/abs/.ssh/id_rsa", "rel/dir/.env", ".env",
]
SECRET = [(H + p[2:]) if p.startswith("~/") else p for p in SECRET]

# known gaps: path -> reason (xfail, strict=False so a fix flips to XPASS without breaking)
GAPS = {}

PLAIN = [
    "src/main.py", "README.md", "config.yml", "package.json", "package-lock.json", ".gitignore", "Makefile", "docs/keys.md",
    "notes/credentials-howto.md", "tests/test_keys.py", "src/environment.py", "src/env.py", "docs/environment.txt",
    "requirements.txt", "Dockerfile", "pyproject.toml", "~/notes.txt", "a.txt", "src/secret_sauce.py", "src/auth/login.py",
    "src/tokenizer.py", "LICENSE", "docs/ssh-guide.md", "assets/logo.png", "app/config.json", "src/passwords_policy.md",
    "data/keyboard.csv", "scripts/build.sh",
]
PLAIN = [(H + p[2:]) if p.startswith("~/") else p for p in PLAIN]


def test_catalog_size():
    assert len(SECRET) >= 60 and len(PLAIN) >= 20


@pytest.mark.parametrize("p", SECRET)
def test_secret_caught(p):
    if p in GAPS:
        pytest.xfail(GAPS[p])
    assert is_secret_path(p), p


@pytest.mark.parametrize("p", PLAIN)
def test_plain_not_secret(p):
    # notes/credentials-howto.md: the name is not exactly `credentials`, so segment matching leaves it alone (expected, not a false positive)
    assert not is_secret_path(p), p
