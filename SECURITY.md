# Security Policy

Aurora IR Web stores incident-response case data, so security is a priority. Thank you for
helping keep it and its users safe.

## Supported versions

| Version | Supported |
|---|---|
| 1.0 (latest release) | ✅ |
| `main` (latest commit) | ✅ |

Security fixes are made against the latest release and `main`. Run a current version and
keep the base image and dependencies up to date (Dependabot and the `security` workflow
help with this).

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a security problem.**

Report it privately through GitHub:

1. Go to the repository's **Security** tab → **Report a vulnerability**, or open
   <https://github.com/setecstuff/aurorair-web/security/advisories/new>.
2. This creates a private advisory visible only to you and the maintainer.

Please include, as far as you can:

- the affected version or commit, and the deployment shape (e.g. reverse proxy, bundled vs.
  external database);
- a description of the issue and its impact (what an attacker can do);
- clear steps or a proof of concept to reproduce it;
- any suggested remediation.

**Do not include real secrets** (API keys, `SECRET_KEY`, passwords, session cookies, real
case data) in your report — redact or use placeholders.

## What to expect

This is a small, maintainer-led project, so timelines are best-effort:

- **Acknowledgement:** within about 5 business days.
- **Assessment & plan:** we will confirm the issue, determine severity and share a rough
  timeline.
- **Fix & disclosure:** coordinated. We prefer to release a fix before public details, and
  will credit you in the advisory and release notes unless you ask us not to.

Please give us reasonable time to remediate before any public disclosure.

## Scope

In scope: the application code in this repository, its REST API, and the default
deployment configuration (`Dockerfile`, `docker-compose.yml`, `.env.example`).

Out of scope (report upstream instead): vulnerabilities in third-party dependencies or
base images themselves (we track and patch these via Dependabot/OSV), the original Aurora
*desktop* application, and issues that require a pre-existing compromise of the host,
database or reverse proxy. Findings that depend on an insecure deployment contrary to the
documentation (for example exposing the plain-HTTP port directly to the internet without a
TLS reverse proxy, or a weak `SECRET_KEY`/`ADMIN_PASSWORD`) are configuration problems, not
application vulnerabilities — but a documentation gap that invites them is worth reporting.

## Safe harbor

We welcome good-faith security research. If you make a good-faith effort to comply with this
policy, we will not pursue or support legal action against you for your research. Act only
against your own test deployment, avoid privacy violations and service disruption, and do
not access, modify or retain data that is not yours.

## Security model and hardening (for reference)

Aurora IR Web is built to run on a team server behind a TLS-terminating reverse proxy, and
ships with:

- **Authentication:** Argon2id password hashing (per-user salts), optional/enforced TOTP
  two-factor, per-user and per-API-key IP allowlists, roles, login throttling and lockout.
- **Secrets at rest:** TOTP secrets and MISP/VirusTotal keys are encrypted (AES-256-GCM via
  a key derived from `SECRET_KEY`); integration keys are write-only and never returned,
  logged or exported.
- **Supply chain:** hash-pinned Python dependencies (`--require-hashes`), digest-pinned base
  images, vendored-JS checksums, and a CI `security` workflow (OSV + pip-audit + integrity
  checks). Release commits and version tags are GPG-signed.
- **Runtime:** container runs as a non-root user with a read-only root filesystem, dropped
  capabilities and `no-new-privileges`.

See [docs/security.md](docs/security.md) for the full security model.
