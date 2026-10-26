# Aurora IR Web

A multi-user web application for incident-response teams to document cases together, built on the case format of
**[Aurora Incident Response](https://github.com/cyb3rfox/Aurora-Incident-Response)**. Cases
are exported to the "spreadsheet of doom" (Excel), PDF, LaTeX and the `.fox` file that opens in the Aurora
desktop application.

Aurora IR Web is an independent project, not affiliated with or endorsed by the Aurora authors. See
[Credits](#credits).

## What it is

- **A shared case workspace.** Several analysts edit the same case in the browser at the same time: Timeline,
  Investigated Systems, Malware/Tools, Accounts, Network Indicators, Exfiltration, OSInt, Systems, Investigators,
  Evidence, Action Items and Case Notes, exactly as in Aurora. Concurrent edits merge field by field; same-field
  collisions are shown, never overwritten. Every change is in an activity log.
- **Aurora-compatible.** `.fox` import and export keep the desktop format, so a case can move between the two.
- **A report generator.** Excel (cover, report, one sheet per section), PDF and LaTeX with the
  Visual Timeline, Lateral Movement and Activity Plot charts. A Report page (executive summary, context,
  conclusions, lessons learned) feeds the reports.
- **Scriptable.** A REST API with application API keys can create cases, read and write case data, run the
  MISP / VirusTotal actions and download every export.
- **Per-case access.** Access is granted per case, not globally: a new account sees no cases. Whoever creates
  or imports a case owns it and invites others as editors or viewers with limited-use invite codes; owners and
  admins manage membership. Administrators see every case.
- **Built for a team server.** Argon2id passwords, TOTP two-factor authentication, per-user and per-key IP
  allowlists, a MariaDB/MySQL database, daily snapshots (optionally PGP-encrypted) with restore.
  MISP and VirusTotal keys are write-only: never shown again and never exported.

## What it is not

- Not the original Aurora and not a replacement for it: the desktop app remains the reference for the format.
- Not a forensic or evidence store. It records findings; it does not hold images, logs or malware samples.
- Not an internet-facing server on its own. It speaks plain HTTP and expects a TLS reverse proxy in front.

## Quick start

Docker with Compose v2.20+:

```bash
git clone https://github.com/setecstuff/aurorair-web.git aurora-web && cd aurora-web
cp .env.example .env     # set ADMIN_PASSWORD, SECRET_KEY and DB_PASSWORD
docker compose up -d --build
docker compose logs -f aurora-web   # wait for "Aurora web ready"
```

This starts the application and a MariaDB container. The app listens on `127.0.0.1:8083`: put a TLS reverse
proxy in front of it and sign in with the admin account from `.env`. For a quick local test without a proxy, set
`COOKIE_SECURE=false` and open `http://127.0.0.1:8083/`.

An external or managed database, the reverse proxy and the first steps after sign-in are covered in
[docs/installation.md](docs/installation.md).

## Documentation

| document | contents |
|---|---|
| [docs/installation.md](docs/installation.md) | Install (single instance or external database), reverse proxy, upgrades |
| [docs/deployment.md](docs/deployment.md) | Configuration reference, MFA and admin recovery, integrations, backup & restore, troubleshooting |
| [docs/user-guide.md](docs/user-guide.md) | Using the application |
| [docs/api.md](docs/api.md) | REST API: authentication, conventions, endpoints, examples |
| [docs/security.md](docs/security.md) | Security model |
| [docs/data-model.md](docs/data-model.md), [docs/schema.sql](docs/schema.sql), [docs/openapi.json](docs/openapi.json) | Generated from the code |

## Development

The tests need a MariaDB/MySQL database they may wipe, plus the `mariadb-dump`, `mariadb` and `gpg` tools:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
TEST_DB_HOST=127.0.0.1 TEST_DB_USER=aurora TEST_DB_PASSWORD=... TEST_DB_NAME=aurora_test pytest -q tests
python3 tools/gen_docs.py    # after changing app/schema.py, app/db.py or the API (a test checks this)
```

The container installs hash-pinned dependencies from `requirements.lock` (`pip install --require-hashes`).
After editing `requirements.txt`, regenerate the lock:

```bash
docker run --rm -v "$PWD:/w" -w /w python:3.14-slim \
  bash -c 'pip install -q pip-tools && pip-compile --generate-hashes --strip-extras -o requirements.lock requirements.txt'
```

Base images are pinned by digest in the `Dockerfile` and `docker-compose.yml`; Dependabot and the `security`
workflow (pip-audit, OSV, vendored-JS checksums) keep them current.

## Contributing & security

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, dependency and
supply-chain rules, CI expectations and the commit sign-off (DCO). To report a vulnerability, **do not open a
public issue**; follow [SECURITY.md](SECURITY.md) (GitHub private vulnerability reporting).

## Credits

**[Aurora Incident Response](https://github.com/cyb3rfox/Aurora-Incident-Response)** was created by
**Mathias Fuchs** ([cyb3rfox](https://cyberfox.blog)) and its contributors, "developed by Incident Responders for
Incident Responders". Its case format, data model, the sections and their layout, the organization of the
screens and menus, and the Visual Timeline, Lateral Movement and Activity Plot reports are their work; Aurora IR
Web reproduces them and adds multi-user collaboration. Thank you
for an amazing tool. Get the desktop application from the
[Aurora releases page](https://github.com/cyb3rfox/Aurora-Incident-Response/releases).

- Aurora Incident Response: © 2018–2021 Mathias Fuchs, [Apache License 2.0](app/static/vendor/licenses/aurora-LICENSE-APACHE-2.0.txt).
- Bundled front-end libraries (vis-timeline/network/data, Chart.js, Moment.js) and the Python packages of the
  container image are listed in [NOTICE](NOTICE); license texts are in `app/static/vendor/licenses/`.

### Built with Claude

Aurora IR Web was developed with **[Claude](https://www.anthropic.com/claude)** (Anthropic), working through
[Claude Code](https://claude.com/claude-code) as an AI pair programmer that wrote most of the code, tests and
documentation. The code was reviewed and the application was tested manually.

- Report problems through the repository's issues or
  [security advisories](https://github.com/setecstuff/aurorair-web/security/advisories/new).
- Copyright and the license are unchanged by this: see [License](#license).

## License

Aurora IR Web is © 2026–present the Aurora IR Web contributors, licensed under the
[Apache License 2.0](LICENSE). See [NOTICE](NOTICE).

## Disclaimer — no warranty

**Aurora IR Web is provided "AS IS", without warranty of any kind**, express or implied, including but not
limited to the warranties of merchantability, fitness for a particular purpose and non-infringement. **You use
it entirely at your own risk.**

To the maximum extent permitted by law, the authors and contributors accept **no liability** for any claim,
damages or other loss — including, without limitation, loss of or damage to data, loss of cases or evidence,
corruption, downtime, or any direct, indirect, incidental, special or consequential damages — arising from the
use of, or inability to use, this software, even if advised of the possibility of such damage.

This is incident-response tooling that **creates, imports, overwrites and deletes case data and restores entire
databases**. Before using it on anything you care about: **run it on test data first, keep verified off-host
backups, and confirm you can restore them.** See [Backup & restore](docs/deployment.md#backup--restore).

This plain-language notice does not replace the licence: the binding terms are the **Disclaimer of Warranty
(Section 7)** and **Limitation of Liability (Section 8)** of the [Apache License 2.0](LICENSE), which govern.
