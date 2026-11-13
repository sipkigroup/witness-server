# Contributing

Thanks for looking. This project is young; the most useful contributions are, in this order:

1. **A way to make the witness decide wrongly**: an `allow` the signed mandate does not permit, a receipt or journal entry
   the offline verifier accepts but should not. Security-relevant ones go by e-mail (see `SECURITY.md`), not as issues.
2. **Reports from running your own witness**: what in README sections 1-5 did not work on your machine, with the exact
   command and output.
3. Bug fixes with a test, docs, integration examples.

## Ground rules

- Open an issue before a large change. Small fixes: send a pull request.
- Every change to behaviour needs a test. Run the suites of README section 6 before you push.
- The files listed under "Apache-2.0" in `NOTICE` (the format and everything that checks a witness) are shared with the
  client repository https://github.com/sipkigroup/witness: a change there must keep old evidence packs verifying.
- Sign off your commits (`git commit -s`, Developer Certificate of Origin 1.1). By contributing you agree that your work is
  licensed under the license of the file you change (AGPL-3.0 or Apache-2.0, see `NOTICE`).
- Be civil. Be specific. Say what you tested and how.

## Local checks

```sh
python3.12 -m venv .venv && . .venv/bin/activate
pip install --require-hashes --no-deps -r cloud/deploy/requirements.lock
pip install -r cloud/server/requirements-test.txt
cd cloud/server && python -m pytest -q tests tests_flow tests_pack tests_prop
python3 ../selfhost/e2e_check.py --base http://localhost:8787      # against a running witness
```
