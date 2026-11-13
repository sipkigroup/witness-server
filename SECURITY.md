# Security policy

## Reporting a vulnerability

Email **support@sipkigroup.com** with the subject `SECURITY (server)`. Please do not open a public issue for a vulnerability.
We aim to acknowledge within 3 business days and to give you a first assessment within 10.
Include: affected component and version (`cloud/deploy/VERSION`), what an attacker gains, steps or a proof of concept.
Encrypted mail is not set up yet; if you need it, ask for a channel in your first message (without details).

The client, the Claude Code hook, the plugin and the specification have the same contact and their own policy:
`SECURITY.md` in https://github.com/sipkigroup/witness.

## Scope

In scope, in this repository:
* anything that lets someone get a receipt, an approval or a mandate the owner did not sign with their passkey, or makes the
  witness answer `allow` where the signed mandate says `deny` or `defer`;
* anything that alters or drops journal entries, checkpoints or the public batch log without the offline verifiers
  (`cloud/server/packtools/verify_pack.py`, `tlogcheck.py`) reporting `INVALID` or a fork;
* account takeover, cross-account access, bypass of the passkey step, of trial-account limits or of `DW_TRIAL=off`;
* leaks of call contents beyond what README section 4 says the witness keeps;
* the compose kit (`docker-compose.yml`, `Dockerfile`, `Caddyfile`) as shipped: for example a port exposed beyond
  127.0.0.1, or `X-Real-IP` spoofing past the proxy.

Out of scope: a witness you run with settings this README warns against (for example `DW_TRIAL=on` on the open internet),
social engineering, denial of service by volume, a stolen owner device or passkey, and a host already controlled by the attacker.
Please test against your own witness (README section 1), not the hosted service at witness.sipkigroup.com.

## Supported versions

Only the latest released version gets fixes (this is a young project, 0.x).

## Our commitments

Coordinated disclosure: we fix, release, then publish an advisory crediting you (if you want), normally within 90 days of
your report. We do not run a paid bounty program at this time. We will not take legal action against good-faith research
that follows this policy.
