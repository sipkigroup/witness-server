"""Configuration: ONLY environment variables (no files, no defaults for secrets)."""
import os
import re
from dataclasses import dataclass
from typing import Optional


class ConfigError(Exception):
    pass


@dataclass
class Config:
    data_dir: str
    witness_key_file: str
    key_pepper: str
    rp_id: str
    origin: str
    iss: str = "https://witness.sipkigroup.com"
    anchor: str = "off"            # on | off
    secure_cookie: bool = False
    web_dir: str = ""              # static site (cloud/web); empty = default location
    trusted_proxy: str = ""        # R-11: comma list of IPs/CIDRs whose X-Real-IP is believed; empty = loopback/private peers
    # limits per account / key; None = the built-in default (300 requests/min per key, 5000 actions/day, 3 agents, 10 registrations/hour per IP)
    rate_per_min: Optional[int] = None
    quota_per_day: Optional[int] = None
    max_agents: Optional[int] = None
    reg_per_hour: Optional[int] = None
    threads: Optional[int] = None         # 0.2.18: worker threads of the request handlers (None = main.THREADS = 8)
    max_inflight: Optional[int] = None    # 0.2.18: requests in progress at once; above it -> 503 OVERLOADED + Retry-After at once (None = main.MAX_INFLIGHT = 256, 0 = off)
    poll_per_key: Optional[int] = None    # 2710rt: long polls of one key open at once; beyond -> answered at once as wait=0 (None = main.POLL_PER_KEY = 8, 0 = off)
    # 08 push: the VAPID private key comes ONLY from a secret file (or the environment); none = push is off
    vapid_key_file: str = ""
    vapid_key: str = ""
    vapid_sub: str = ""            # VAPID "sub" claim (mailto: or https:); empty = the origin
    push_per_min: Optional[int] = None   # pushes per minute per account (None = 6)
    push_hosts: str = ""           # comma list of push-service host suffixes; empty = the built-in list (FCM, Mozilla, Apple, Windows)
    push_allow_http: bool = False  # local tests only: http:// endpoints on push_hosts
    # TEE mode (cloud/tee/DIZAIN-TDX.md): off by default. on = key born in the CVM at <data_dir>/tee/witness_key + TDX quotes
    tee: str = "off"
    tee_provider_name: str = ""    # auto | dstack | tappd | configfs
    tee_intel_root: str = ""       # pinned Intel SGX Root CA (PEM) for the self-check; empty = chain not anchored ("NOT VERIFIED")
    tee_provider: object = None    # code only (tests): an object with .quote(report_data64) -> (quote bytes, event log | None)
    # 0.2.9: second time anchor from ONE RFC 3161 TSA named by the operator (off unless DW_TSA_URL is set; app/jobs.py tsa_env_provider)
    tsa_url: str = ""              # DW_TSA_URL: http(s) URL of the TSA (no user:password in it)
    tsa_ca: str = ""               # DW_TSA_CA: the TSA's root certificate (PEM/DER file): without it no reply can be verified, so it is required
    recovery_phone_delay_h: int = 24   # 0.2.15: DW_RECOVERY_PHONE_DELAY_H (24..72): a key declared "my new phone" with a recovery code counts as phone only after this
    tsa_name: str = ""             # DW_TSA_NAME: short name in file names (<batch>.tsr.<name>); empty = from the URL host
    # 0.2.24 (critique B): days a decided action keeps its short masked excerpt (DW_PREVIEW_KEEP_DAYS, 1..3650); after that only the hash of its arguments
    preview_keep_days: int = 30
    # 0.2.24 (critique T3): minutes after an agent saw a secret during which its outgoing calls are held for the owner (DW_SECRET_TAINT_MIN, 1..1440)
    secret_taint_min: int = 30
    # 0.2.25: writes this many minutes before the secret still make a command of the marked agent a hold (DW_WRITTEN_LOOKBACK_MIN, 1..10080)
    written_lookback_min: int = 1440
    # 0.2.25: auto-freeze after DW_AUTOFREEZE_N (0..1000, 0 = off) APPROVAL_RATE refusals within DW_AUTOFREEZE_MIN (1..1440) minutes
    autofreeze_n: int = 10
    autofreeze_min: int = 10
    # 0.2.29: seconds a deferred request waits for the owner (DW_DEFER_TTL_S, 30..3600; 900 by default). Below 900 only for local tests:
    # a short limit lets a live test see "the request expired, the next run still passes under an approval for later runs"
    defer_ttl_s: int = 900
    # 0.2.25: e-mail channel of notifications (off unless DW_SMTP_HOST and DW_SMTP_FROM are set); the password only from a secret file
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password_file: str = ""
    smtp_from: str = ""
    smtp_tls: str = "starttls"      # starttls | ssl | off (off: local test relays only)
    # 0.2.27: node 2 (independent co-signer of journal heads, cloud/node2, app/node2feed.py): off unless DW_NODE2=on.
    # on = /internal/node2/* (Bearer token from DW_NODE2_TOKEN_FILE, >= 32 characters) and the public /v1/node2/*; packs carry node2/
    node2: str = "off"
    node2_token_sha256: bytes = b""
    # 0.2.32: the public live feed of ONE demo account (app/demo_live.py, cloud/demo-live): off unless DW_DEMO_ACCOUNT = its id (32 hex)
    demo_account: str = ""
    # 0.2.34: DW_ARGS_SALT=on -> args_sha256 in the signed action is HMAC(account salt, [tool, args]); off (default) = bare SHA-256 that the deployed
    # clients (deus-witness <= 0.2.24, REQUEST_MISMATCH check) recompute. Turn on only with a client that gets the salt.
    args_salt: str = "off"
    # 0.2.38: anonymous trial accounts ("account on the first touch", app/trial.py). DW_TRIAL=on|off (default on); DW_TRIAL_PER_HOUR new
    # trials per sender network per hour (1..100, default 10); DW_TRIAL_PER_DAY all senders together (1..100000, default 2000);
    # DW_TRIAL_TTL_DAYS (1..30, default 7): an unkept trial account and everything in it is erased after that; DW_TRIAL_QUOTA actions a day (10..5000, 2000)
    trial: str = "on"
    trial_per_hour: int = 10   # 0.2.48: 3 -> 10 for the Show HN day (offices / NAT / retries)
    trial_per_day: int = 2000
    trial_ttl_days: int = 7
    trial_quota: int = 2000
    # 0.2.45: ceiling of allowed reads (class pass), which do not spend the action quotas: per agent and per account in 24 h (DW_PASS_PER_AGENT_DAY, DW_PASS_PER_ACCOUNT_DAY)
    pass_per_agent_day: int = 50000
    pass_per_account_day: int = 200000
    # 0.2.38: our own networks (CIDR list, DW_STATS_INTERNAL_NETS): accounts and trials made from them are marked internal and never counted
    internal_nets: str = ""

    @staticmethod
    def from_env(env=None):
        e = os.environ if env is None else env
        pepper = e.get("DW_KEY_PEPPER")
        if not pepper and e.get("DW_KEY_PEPPER_FILE"):          # R-14: a secret file instead of an environment variable
            try:
                with open(e["DW_KEY_PEPPER_FILE"]) as f:
                    pepper = f.read().strip()
            except OSError as ex:
                raise ConfigError("DW_KEY_PEPPER_FILE unreadable: %s" % type(ex).__name__)
        tee = (e.get("DW_TEE") or "off").lower()
        if tee not in ("on", "off"):
            raise ConfigError("DW_TEE must be on|off")
        need = ("DW_DATA_DIR", "DW_RP_ID", "DW_ORIGIN") if tee == "on" else ("DW_DATA_DIR", "DW_WITNESS_KEY_FILE", "DW_RP_ID", "DW_ORIGIN")
        miss = [k for k in need if not e.get(k)] + ([] if pepper else ["DW_KEY_PEPPER (or DW_KEY_PEPPER_FILE)"])
        if miss:
            raise ConfigError("missing environment: " + ", ".join(miss))
        lim = {}
        for field, var in (("rate_per_min", "DW_RATE_PER_MIN"), ("quota_per_day", "DW_QUOTA_PER_DAY"),
                           ("max_agents", "DW_MAX_AGENTS"), ("reg_per_hour", "DW_REG_PER_HOUR"), ("push_per_min", "DW_PUSH_PER_MIN"),
                           ("max_inflight", "DW_MAX_INFLIGHT"), ("threads", "DW_THREADS"), ("poll_per_key", "DW_POLL_PER_KEY")):
            v = (e.get(var) or "").strip()
            if v:
                try:
                    lim[field] = int(v)
                except ValueError:
                    lim[field] = 0
                if lim[field] < 1:
                    raise ConfigError("%s must be a positive integer" % var)
        dh = (e.get("DW_RECOVERY_PHONE_DELAY_H") or "").strip()
        if dh:
            try:
                lim["recovery_phone_delay_h"] = int(dh)
            except ValueError:
                lim["recovery_phone_delay_h"] = 0
            if not 24 <= lim["recovery_phone_delay_h"] <= 72:
                raise ConfigError("DW_RECOVERY_PHONE_DELAY_H must be 24..72 (hours)")
        for field, var, lo, hi in (("preview_keep_days", "DW_PREVIEW_KEEP_DAYS", 1, 3650), ("secret_taint_min", "DW_SECRET_TAINT_MIN", 1, 1440),
                                   ("written_lookback_min", "DW_WRITTEN_LOOKBACK_MIN", 1, 10080), ("autofreeze_n", "DW_AUTOFREEZE_N", 0, 1000),
                                   ("autofreeze_min", "DW_AUTOFREEZE_MIN", 1, 1440), ("smtp_port", "DW_SMTP_PORT", 1, 65535),
                                   ("defer_ttl_s", "DW_DEFER_TTL_S", 30, 3600),
                                   ("trial_per_hour", "DW_TRIAL_PER_HOUR", 1, 100), ("trial_per_day", "DW_TRIAL_PER_DAY", 1, 100000),
                                   ("trial_ttl_days", "DW_TRIAL_TTL_DAYS", 1, 30), ("trial_quota", "DW_TRIAL_QUOTA", 10, 5000),
                                   ("pass_per_agent_day", "DW_PASS_PER_AGENT_DAY", 100, 10000000), ("pass_per_account_day", "DW_PASS_PER_ACCOUNT_DAY", 100, 100000000)):
            v = (e.get(var) or "").strip()
            if v:
                try:
                    lim[field] = int(v)
                except ValueError:
                    lim[field] = 0
                if not lo <= lim[field] <= hi:
                    raise ConfigError("%s must be %d..%d" % (var, lo, hi))
        smtp_tls = (e.get("DW_SMTP_TLS") or "starttls").lower()
        if smtp_tls not in ("starttls", "ssl", "off"):
            raise ConfigError("DW_SMTP_TLS must be starttls|ssl|off")
        smtp_kw = {"smtp_host": (e.get("DW_SMTP_HOST") or "").strip(), "smtp_user": (e.get("DW_SMTP_USER") or "").strip(),
                   "smtp_password_file": (e.get("DW_SMTP_PASSWORD_FILE") or "").strip(), "smtp_from": (e.get("DW_SMTP_FROM") or "").strip(),
                   "smtp_tls": smtp_tls}
        if bool(smtp_kw["smtp_host"]) != bool(smtp_kw["smtp_from"]):
            raise ConfigError("DW_SMTP_HOST and DW_SMTP_FROM go together")
        demo_acc = (e.get("DW_DEMO_ACCOUNT") or "").strip()
        if demo_acc and not re.fullmatch(r"[0-9a-f]{32}", demo_acc):
            raise ConfigError("DW_DEMO_ACCOUNT must be an account id (32 lowercase hex) or empty")
        node2 = (e.get("DW_NODE2") or "off").lower()
        if node2 not in ("on", "off"):
            raise ConfigError("DW_NODE2 must be on|off")
        node2_kw = {}
        if node2 == "on":
            # file wins over the environment (an explicit path is the deliberate choice; env is the Phala/ACI secret route).
            # empty / whitespace-only value = no token. The token itself is never put into a message.
            tf = (e.get("DW_NODE2_TOKEN_FILE") or "").strip()
            if tf:
                try:
                    with open(tf) as f:
                        tok = f.read().strip()
                except OSError as ex:
                    raise ConfigError("DW_NODE2_TOKEN_FILE unreadable: %s" % type(ex).__name__)
                src = "DW_NODE2_TOKEN_FILE"
            else:
                tok = (e.get("DW_NODE2_TOKEN") or "").strip()
                src = "DW_NODE2_TOKEN"
                if not tok:
                    raise ConfigError("DW_NODE2=on needs DW_NODE2_TOKEN_FILE (a secret file) or DW_NODE2_TOKEN (the feed token, >= 32 characters)")
            if len(tok) < 32:
                raise ConfigError("%s: the token must be at least 32 characters" % src)
            import hashlib as _h
            node2_kw = {"node2": "on", "node2_token_sha256": _h.sha256(tok.encode()).digest()}
        anchor = (e.get("DW_ANCHOR") or "off").lower()
        if anchor not in ("on", "off"):
            raise ConfigError("DW_ANCHOR must be on|off")
        args_salt = (e.get("DW_ARGS_SALT") or "off").lower()
        if args_salt not in ("on", "off", "transition"):
            raise ConfigError("DW_ARGS_SALT must be on|off|transition")
        trial = (e.get("DW_TRIAL") or "on").lower()
        if trial not in ("on", "off"):
            raise ConfigError("DW_TRIAL must be on|off")
        nets = (e.get("DW_STATS_INTERNAL_NETS") or "").strip()
        if nets:
            import ipaddress as _ip
            for n in nets.split(","):
                try:
                    _ip.ip_network(n.strip(), strict=False)
                except ValueError:
                    raise ConfigError("DW_STATS_INTERNAL_NETS: not a network: %r" % n.strip()[:60])
        kf = e.get("DW_WITNESS_KEY_FILE") or ""
        tsa_kw = {}
        if (e.get("DW_TSA_URL") or "").strip():
            from app.jobs import tsa_env_provider
            try:
                p = tsa_env_provider(e["DW_TSA_URL"].strip(), (e.get("DW_TSA_CA") or "").strip(), (e.get("DW_TSA_NAME") or "").strip())
            except ValueError as ex:
                raise ConfigError("DW_TSA_URL: %s" % ex)
            tsa_kw = {"tsa_url": p["url"], "tsa_ca": p["ca"], "tsa_name": p["name"]}
        tee_kw = {}
        if tee == "on":
            # the key path is fixed by the (measured) code: a key file pointed to from outside would not be "born in the CVM"
            own = os.path.join(e["DW_DATA_DIR"], "tee", "witness_key")
            if kf and os.path.abspath(kf) != os.path.abspath(own):
                raise ConfigError("DW_TEE=on: the witness key is created inside the CVM at %s; DW_WITNESS_KEY_FILE must be unset or equal to it" % own)
            kf = own
            tee_kw = {"tee": "on", "tee_provider_name": (e.get("DW_TEE_PROVIDER") or "auto").lower(),
                      "tee_intel_root": e.get("DW_TEE_INTEL_ROOT") or ""}
        return Config(data_dir=e["DW_DATA_DIR"], witness_key_file=kf, key_pepper=pepper,
                      rp_id=e["DW_RP_ID"], origin=e["DW_ORIGIN"].rstrip("/"),
                      iss=e.get("DW_ISS") or "https://witness.sipkigroup.com", anchor=anchor,
                      secure_cookie=(e.get("DW_SECURE_COOKIE") or "").lower() in ("1", "true", "on", "yes"),
                      web_dir=e.get("DW_WEB_DIR") or "", trusted_proxy=e.get("DW_TRUSTED_PROXY") or "",
                      vapid_key_file=e.get("DW_VAPID_PRIVATE_KEY_FILE") or "", vapid_key=e.get("DW_VAPID_PRIVATE_KEY") or "",
                      vapid_sub=e.get("DW_VAPID_SUB") or "", push_hosts=e.get("DW_PUSH_HOSTS") or "",
                      push_allow_http=(e.get("DW_PUSH_ALLOW_HTTP") or "").lower() in ("1", "true", "on", "yes"), **tee_kw, **tsa_kw, **smtp_kw, **node2_kw, demo_account=demo_acc, args_salt=args_salt, trial=trial, internal_nets=nets, **lim)
