# Contributing

Thanks for looking. This project is young; the most useful contributions are, in this order:

1. **A way to make the witness decide wrongly**: an `allow` the signed mandate does not permit, a receipt or journal entry
   the offline verifier accepts but should not. Security-relevant ones go by e-mail (see `SECURITY.md`), not as issues.
2. **Reports from running your own witness**: what in README sections 1-5 did not work on your machine, with the exact
   command and output.
3. Bug fixes with a test, docs, integration examples.

## Ground rules

- Open an issue before a large change. Small fixes: send a pull request.
- Every change to behaviour needs a test. Run the suites of README section 6 before you push; CI (`.github/workflows/ci.yml`)
  runs them and the Docker path on every push and pull request.
- The files listed under "Apache-2.0" in `NOTICE` (the format and everything that checks a witness) are shared with the
  client repository https://github.com/sipkigroup/witness: a change there must keep old evidence packs verifying.
- Sign off every commit (`git commit -s`), see "Developer Certificate of Origin" below. By contributing you agree that your
  work is licensed under the license of the file you change (AGPL-3.0 or Apache-2.0, see `NOTICE`).
- Be civil. Be specific. Say what you tested and how.

## Local checks

```sh
python3.12 -m venv .venv && . .venv/bin/activate
pip install --require-hashes --no-deps -r cloud/deploy/requirements.lock
pip install --require-hashes --no-deps -r cloud/server/requirements-test.lock
cd cloud/server && python -m pytest -q tests tests_flow tests_pack tests_prop
python3 ../selfhost/e2e_check.py --base http://localhost:8787      # against a running witness
```

## Developer Certificate of Origin

Every commit in a pull request must end with a line

```
Signed-off-by: Your Name <the e-mail of the commit author>
```

`git commit -s` adds it. With it you certify the Developer Certificate of Origin 1.1 (the file `DCO` in this
repository, text of https://developercertificate.org/): you wrote the change, or you have the right to submit it under
the license of the file you change. Use your real name or a name you are known by; no anonymous contributions.

If you used an AI tool to write part of the change, you may still sign off, but you remain responsible for the change:
check that the tool's terms let you contribute its output, and say in the pull request which parts it wrote.

The `dco` check (`.github/workflows/dco.yml`) fails a pull request with a commit that has no such line.
Fix it with `git rebase --signoff <base>` (or `git commit --amend -s` for the last commit) and push again.
