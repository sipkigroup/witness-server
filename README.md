# Deus Witness server: run your own witness

Deus Witness stands between an AI agent (Claude Code, an MCP client, your own code) and what the agent does. Every call is
judged against a mandate you signed with your passkey; what needs a person is asked on your phone or laptop; every decision
is written as a signed receipt into an append-only journal that anyone can check offline.

This repository is the **witness server**: the same code and the same Dockerfile as the hosted service at
witness.sipkigroup.com (version in `cloud/deploy/VERSION`). Run it and the commands, paths and file names your agent sends
never leave your machine or your network.

* Server: **AGPL-3.0** (`LICENSE`). Format, verifier and everything copied into evidence packs: **Apache-2.0** (see `NOTICE`).
* Client, Claude Code hook and plugin: `pip install deus-witness` / https://github.com/sipkigroup/witness (Apache-2.0).

---

## 1. Your own witness in 2 minutes (one machine)

Needs Docker Engine 24+ with the Compose plugin. Nothing is pulled from a Deus registry: the image is built here.

```sh
git clone <this repository> deus-witness-server && cd deus-witness-server
docker compose up -d --build        # then: docker compose ps  ->  witness "healthy"
curl -s http://localhost:8787/healthz
```

Measured on a 2-core VPS: image build 29 s (base image already pulled, no layer cache), healthy 5 s later; from
`docker compose up` to the first approved question, client steps included, 37 s plus your two passkey touches.

The first start creates **your** signing key and pepper (service `keys`, it never overwrites them) and the witness listens
on `http://localhost:8787`, on this machine only (127.0.0.1).

Point the client at it, in the project you want to protect:

```sh
export DEUS_WITNESS_URL=http://localhost:8787
uvx --from deus-witness deus-witness try --url http://localhost:8787
```

`try` makes a trial account on YOUR witness, saves the agent key (`~/.config/deus-witness/agent-key.json`, it remembers the
URL) and opens the witness page: two passkey touches (Touch ID, Windows Hello or your phone) make the account yours and sign
the drafted mandate. Then install the hook or the plugin as in the client README; the hook reads the URL from the key file,
and `DEUS_WITNESS_URL` may only repeat it (a different value is refused, so an agent cannot quietly re-point it).

The client pins the witness public key (`GET /v1/witness`) on first use: keep the `secrets` volume, or clients will refuse
a witness that comes back with a new key.

Another port: put `DW_PORT=18080` and `DW_PUBLIC_URL=http://localhost:18080` into `.env` (copy `env.example`).
On a server you reach over SSH: `ssh -L 8787:127.0.0.1:8787 yourhost` and use `http://localhost:8787` on your laptop
(passkeys accept `localhost` without HTTPS; the port must be the same on both sides).

Run `try` yourself in a terminal: it shows the claim link only to a terminal (never to an agent's output), and without one
it withdraws the trial and saves nothing.

### Without Docker (a try-out on your laptop)

Python 3.12 and the same hash-locked dependencies as the image; the witness reads the same variables the compose file sets.
Keep `secrets/` private and out of the repository.

```sh
python3.12 -m venv .venv && . .venv/bin/activate
pip install --require-hashes --no-deps -r cloud/deploy/requirements.lock
mkdir -p data secrets && chmod 700 secrets
python3 -c 'import secrets as s; open("secrets/witness_ed25519","w").write(s.token_hex(32)+"\n"); open("secrets/key_pepper","w").write(s.token_hex(32))'
chmod 400 secrets/*
export DW_DATA_DIR=$PWD/data DW_WITNESS_KEY_FILE=$PWD/secrets/witness_ed25519 DW_KEY_PEPPER_FILE=$PWD/secrets/key_pepper \
       DW_RP_ID=localhost DW_ORIGIN=http://localhost:8787 DW_ISS=http://localhost:8787 DW_SECURE_COOKIE=0 DW_TRIAL=on DW_ANCHOR=off
(cd cloud/server && python -m app.main --host 127.0.0.1 --port 8787)
```

Anchor batches (and so the public log behind `GET /checkpoint`) are made every 30 minutes; to make one now, with the same
variables: `(cd cloud/server && python -m app.jobs anchor-once)`. This is not a production setup: no process supervisor,
no log rotation, and the keys are ordinary files in your working directory.

## 2. Your domain with HTTPS

The kit has Caddy (`Caddyfile`, profile `https`): it gets a Let's Encrypt certificate for your name automatically.

```sh
cp env.example .env
# in .env:
#   DW_DOMAIN=witness.example.org
#   DW_PUBLIC_URL=https://witness.example.org
#   DW_SECURE_COOKIE=1
#   DW_TRIAL=off            # see section 3 before you open the witness to the internet
docker compose --profile https up -d --build
curl -sI https://witness.example.org/healthz
```

* The name must resolve to the host and ports 80/443 must be reachable. Own CA or a closed network: see the comments in
  `Caddyfile` (`tls /certs/...` or `tls internal`).
* **Passkeys are bound to `DW_DOMAIN`.** Choose the final name before the first sign-up: changing it later invalidates
  every passkey and every client pin.
* The witness port stays on 127.0.0.1; only Caddy is public. Caddy overwrites `X-Real-IP`, and the witness believes that
  header only from Caddy's fixed address on the compose network (`DW_NET`.2).
* Clients: `deus-witness try --url https://witness.example.org` or `DEUS_WITNESS_URL=https://witness.example.org`.

## 3. Accounts: trial accounts and your own

`DW_TRIAL=on` (the default in this kit) lets **anyone who reaches the witness** make an account with one passkey, no e-mail.
Right for `localhost` and a closed network; this is what `deus-witness try` uses.

To have only accounts you make yourself:

1. Set `DW_TRIAL=off` in `.env` and `docker compose up -d` (accounts already made stay).
2. Open `https://<your witness>/signup.html`, make the account with your passkey (`DW_REG_PER_HOUR` limits sign-ups per
   address).
3. On the Agents page create an agent (preset `claude-code`) and copy its key `dwk_...`.
4. Give it a mandate: `uvx --from deus-witness deus-witness-hook --print-form /path/to/project` prints the recommended one;
   on the Mandate page choose "Import from JSON", review and sign it with your passkey.
5. On your machine: `export DEUS_WITNESS_URL=https://<your witness>` and `export DEUS_WITNESS_KEY=dwk_...`
   (or keep using the key file of `try`).

A trial account you already claimed with a passkey is a normal account: it stays. An unclaimed trial account and everything
in it is erased after `DW_TRIAL_TTL_DAYS` (7 by default). To drop a trial account for good: Devices page, "Delete account".

Limits per account: `DW_RATE_PER_MIN`, `DW_QUOTA_PER_DAY`, `DW_MAX_AGENTS` (`env.example`).

## 4. What the witness sees, where it keeps it, how to delete it

**What the client sends** for each call the hook sees:
* the tool name and its full input: shell commands, file paths, URLs. The text written by Write/Edit is kept only as a short
  masked preview while the call waits for you;
* the working directory and the project directory;
* answers to the witness's questions about the paths of that call (does it exist, where does a link point) and SHA-256
  fingerprints of the project files a command executes;
* nothing else: no e-mail, no name (a trial account has none; a sign-up account has the name you type).

**What the witness keeps**, all in the Docker volume `<project>_data` (`/data` in the container):
* `db.sqlite`: accounts, passkey public keys, agents (only a peppered hash of each agent key), mandates, requests and
  decisions. Secrets and your "closed data" words are masked in previews; a decided request keeps its short masked
  excerpt for `DW_PREVIEW_KEEP_DAYS` (30) days, then only the hash of its arguments.
* `ledgers/<account>/ledger.cose`: the signed receipts (decisions, tool names, recipients, hashes of arguments).
* `anchors/`: checkpoints; with `DW_ANCHOR=on` their digests (only hashes) go to public OpenTimestamps calendars.
* Container logs (`docker compose logs witness`): request metadata (method, path, status, time), not call bodies; they
  rotate at 10 MB x 5.

The signing key and pepper are in the volume `<project>_secrets`, readable only by the witness user.

**Nothing goes out** unless you turn it on: `DW_ANCHOR=on` (hashes to OpenTimestamps), `DW_TSA_URL` (hashes to your TSA),
Web Push (needs a VAPID key, then notifications go through the browser vendor's push service), e-mail (`DW_SMTP_*`),
Telegram/Slack (only when a user adds them), GitHub's public OIDC keys (only when a CI run sends a GitHub token).
The server has no telemetry and makes no call to Sipki LLC.

**How to delete:**
* one account: Devices page, "Delete account" (your passkey confirms). Its journal is replaced by a hash skeleton (it proves
  entries existed, not what they said); evidence packs downloaded earlier keep verifying;
* everything: `docker compose --profile https down -v` removes the containers and the volumes `data`, `secrets` (your
  witness key!) and `caddy`. This cannot be undone; copy the key first if you want old receipts to stay attributable to this witness.

## 5. Back up, update, check

```sh
# back up (a short stop gives a consistent copy; volume names are <DW_PROJECT>_data / _secrets)
docker compose stop witness
docker run --rm -v deus-witness_data:/data -v "$PWD":/out alpine tar czf /out/witness-data.tgz -C /data .
docker run --rm -v deus-witness_secrets:/s -v "$PWD":/out alpine tar czf /out/witness-secrets.tgz -C /s .   # once; keep it OFFLINE
docker compose start witness

# update
git pull && docker compose up -d --build      # read the release notes first; the volumes are kept

# end-to-end self-check of a running witness: throw-away account (software passkey), allowed + denied action,
# evidence pack -> RESULT: VALID, one flipped byte -> INVALID (works with DW_TRIAL=off; needs python3 with httpx, cbor2, cryptography)
python3 cloud/selfhost/e2e_check.py --base http://localhost:8787
# with --key-file it also checks that /v1/witness serves YOUR key:
#   docker run --rm -v deus-witness_secrets:/s alpine cat /s/witness_ed25519 > /tmp/k && python3 cloud/selfhost/e2e_check.py --base ... --key-file /tmp/k && rm /tmp/k

# check an evidence pack (downloaded from the dashboard) on any machine, no network
unzip deus-witness-evidence-*.zip -d pack && python3 pack/verify/verify_pack.py pack --offline
```

## 6. Run the tests

```sh
python3.12 -m venv .venv && . .venv/bin/activate
pip install --require-hashes --no-deps -r cloud/deploy/requirements.lock
pip install --require-hashes --no-deps -r cloud/server/requirements-test.lock
cd cloud/server && python -m pytest -q tests tests_flow tests_pack tests_prop
```

Some tests run the published client (`deus-witness`, pinned in `requirements-test.lock`) against this server.
The same runs in CI (`.github/workflows/ci.yml`, in four parallel parts), together with `docker compose build`, `up -d` and
`curl /healthz` and `/checkpoint` on a clean Linux runner.

## 7. Limits of this version

* One process, one host: SQLite in `/data`, a lock refuses a second process. No replication.
* The landing page (`cloud/web/index.html`), `terms.html` and `privacy.html` describe the hosted service of Sipki LLC;
  replace them before other people use your witness. Some links there (`/demo/`) lead nowhere in this repository.
* TEE mode (`DW_TEE=on`) and node 2 (`DW_NODE2=on`) are in the code but not covered by this kit.
* Draft specification, not yet submitted to the IETF; early 0.x software; not reviewed by outside parties.

Security reports: see `SECURITY.md` (e-mail, not public issues). Contributing: `CONTRIBUTING.md`.
