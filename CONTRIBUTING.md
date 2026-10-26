# Contributing to Aurora IR Web

Thanks for your interest in improving Aurora IR Web. It is an independent, Apache-2.0
project — a multi-user web edition of the Aurora Incident Response case format. Please
read this guide before opening an issue or a pull request.

## Scope

Keep changes within what the project is meant to be (see the README's *What it is* / *What
it is not*). In short: a shared, Aurora-compatible case workspace and report generator with
a REST API, meant to run on a team server behind a TLS reverse proxy. It is **not** a
forensic/evidence store and not an internet-facing server on its own.
Feature work that changes that scope should start as an issue for discussion first.

## Reporting bugs and requesting features

- **Security vulnerabilities: do not open a public issue.** Follow
  [SECURITY.md](SECURITY.md) (GitHub private vulnerability reporting).
- For everything else, open an issue with: what you did, what you expected, what happened,
  the application version / commit, and relevant **redacted** logs
  (`docker compose logs aurora-web`). Never paste secrets — see *Secrets* below.

## Development setup

The tests need a MariaDB/MySQL database they may wipe, plus the `mariadb-dump`, `mariadb`
and `gpg` tools on `PATH`:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
TEST_DB_HOST=127.0.0.1 TEST_DB_USER=aurora TEST_DB_PASSWORD=... TEST_DB_NAME=aurora_test pytest -q tests
```

A quick full-stack check with the bundled database:

```bash
cp .env.example .env     # set ADMIN_PASSWORD, SECRET_KEY, DB_PASSWORD
docker compose up -d --build
curl -s http://127.0.0.1:8083/healthz     # {"ok": true}
```

After changing `app/schema.py`, `app/db.py` or the API, regenerate the committed docs (a
test enforces this):

```bash
python3 tools/gen_docs.py
```

## Dependencies and supply chain

The container installs **hash-pinned** dependencies from `requirements.lock`
(`pip install --require-hashes`), so a changed or typosquatted distribution cannot be
installed. When you change a Python dependency:

1. Edit the pin in `requirements.txt` (direct dependencies only).
2. Regenerate the lock with hashes, on the image's Python version:

   ```bash
   docker run --rm -v "$PWD:/w" -w /w python:3.14-slim \
     bash -c 'pip install -q pip-tools && pip-compile --generate-hashes --strip-extras -o requirements.lock requirements.txt'
   ```

3. Commit `requirements.txt` **and** `requirements.lock` together. The `security` workflow
   fails if a direct dependency in `requirements.txt` is missing from the lock.

Base images are pinned by **digest** in the `Dockerfile` and `docker-compose.yml`; update
the digest (not just the tag) to move to a patched base. Dependabot proposes dependency,
digest and GitHub-Actions bumps automatically.

If you change a bundled front-end library under `app/static/vendor/`, update its recorded
checksum in `app/static/vendor/vendor.sha256` (the `security` workflow verifies it) and the
entry in [NOTICE](NOTICE).

## Continuous integration

Every push and pull request runs the `security` workflow, which must pass:

- **OSV** scan of the exact hash-pinned set in `requirements.lock`, plus `pip-audit` as a
  second source;
- **vendored-JS integrity** (`sha256sum -c vendor.sha256`);
- **lock consistency** (each direct dependency is present in the lock).

Add or update tests for any behaviour you change, and make sure `pytest -q tests` and
`tools/gen_docs.py` are clean before you open the PR.

## Pull requests

- Keep PRs small and focused; one logical change per PR.
- Write a clear description: what changed, why, and how you tested it.
- Match the style and conventions of the surrounding code; don't reformat unrelated lines.
- Update the relevant docs under `docs/` (or the source they are generated from).
- Do not bump the project version or create release tags in a PR; the maintainer does that.

## Commit sign-off (DCO)

Contributions are accepted under the Developer Certificate of Origin. Sign off each commit
to certify you wrote it or have the right to submit it under the project's license:

```bash
git commit -s -m "Your message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line. Cryptographically **signing**
commits (`git commit -S`) is encouraged; the maintainer's release commit and the version tag
are GPG-signed.

## Secrets

Never commit or paste secrets — `.env`, `SECRET_KEY`, database passwords, session cookies, or
MISP/VirusTotal API keys — into the repository, issues, PRs or logs. `.env` is git-ignored;
use `.env.example` for configuration examples. MISP/VirusTotal keys are write-only in the
application by design and must never be added to exports, `.fox` files or test fixtures.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), consistent with the rest of the project (see [NOTICE](NOTICE)).
