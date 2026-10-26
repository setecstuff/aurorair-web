# Security model

## Authentication

**Passwords**:
- Argon2id (`argon2-cffi`, time cost 3, 64 MiB, parallelism 4) with a random 16-byte salt per password, stored
  as a PHC string, rehashed at sign-in when the parameters change.
- Minimum `MIN_PASSWORD_LENGTH` (12) characters.
- Unknown usernames are verified against a dummy hash, so timing does not reveal which accounts exist.

**Browser sessions**:
- 256-bit random token, stored as a SHA-256 hash.
- Cookie `__Host-aurora_session`: `HttpOnly`, `Secure`, `SameSite=Strict`.
- Idle timeout 8 h, absolute 24 h.
- Every state-changing request needs the CSRF token, which is renewed when sign-in completes.

**Staged sign-in**: password, then each stage that applies; no data is reachable before the last one.
- `mfa`: TOTP code (RFC 6238, ±1 step). Each code is accepted once (replay protection).
- `password`: forced change set by an administrator.
- `mfa_setup`: enrolment, when `MFA_ENFORCED=true`.

**MFA**:
- A signed-in session cannot replace an existing authenticator. The user turns MFA off first (password and a
  current code), or an administrator resets it.
- `MFA_ENFORCED` also applies to sessions that are already open.

**IP allowlists**:
- Per user and per API key: IPv4/IPv6 addresses and CIDR ranges; empty = any address.
- Users are checked at sign-in and on every request. A refused sign-in gets the same answer as a wrong
  password.
- Keys are checked on every request (`403`).
- An administrator cannot save an allowlist that excludes their own current address.
- The client address is the one the reverse proxy reports, so the proxy must overwrite `X-Forwarded-For`.

**Throttling**:
- `LOGIN_MAX_FAILURES` failed passwords or codes per username, and 4× that per client IP, within
  `LOGIN_LOCKOUT_MINUTES` (`429`).
- The counters are in the database, so they hold across workers and instances.

**Session ending**:
- A password change ends the user's other sessions.
- An admin password reset, deactivation, MFA reset or deletion ends all of them.

**Admin recovery**: `ADMIN_FORCE_RESET=true` removes the admin's MFA and IP allowlist and sets the password
from `.env` on every start, logged as a warning. `ADMIN_PASSWORD` is otherwise used only to create the admin on
the first start.

## Authorization

Two global roles, **user** and **admin**. Access to case data is **per case**, not global: a new account can
see no case until it is granted access to one, and a case it cannot access is invisible — those routes answer
**404**, never 403, so case ids cannot be probed.

- A case's per-case permission is **viewer** (read) or **editor** (read + write). The case's **owner** (its
  creator or importer) additionally manages membership: issuing invite codes, changing permissions, removing
  members and transferring ownership. Editors and viewers can do none of that, so no one can raise their own
  access.
- **Administrators** have full access to every case, see every owner, add or remove members directly, and
  manage users, API keys, backups and the server-wide settings.

| on a case it can access | viewer / `read` key | editor / `readwrite` key | owner | admin |
|---|---|---|---|---|
| Read records, search, reports, all exports | ✓ | ✓ | ✓ | ✓ |
| Create / edit / delete records, case details, Report page, MISP / VirusTotal actions | | ✓ | ✓ | ✓ |
| Manage members, invites and ownership | | | ✓ | ✓ |
| Delete / import / replace cases; users; API keys; backups and restore | | | | ✓ |

Notes:
- Creating a case or importing a `.fox` is open to any user, who becomes the new case's owner.
- Administration (users, keys, backups, server settings) is refused to API keys; those endpoints serve the GUI only.
- API keys carry a **kind** and **scope**: an *admin* key is a full administrator; a *case* key is data-only
  (`read` → viewer, `readwrite` → editor) over **all** cases or a **single** case, and can never manage membership.
- Every rule is checked on the server, for every endpoint.

**API keys**:
- Belong to the application, not to a user; created and changed only by administrators in the GUI.
- 256-bit random secret, shown once and stored as a SHA-256 hash.
- Optional expiry, enable/disable, IP allowlist and secret rotation; last use (time, IP) is recorded.
- A restore replaces users and keys with those in the snapshot.

## Secrets

- `SECRET_KEY` is expanded with HKDF-SHA256 into an AES-256-GCM key. It encrypts TOTP secrets and the MISP /
  VirusTotal API keys (per case and server-wide), so a database dump alone reveals neither.
- The MISP and VirusTotal keys are write-only. They are never returned by the API (to admins either), and are
  written as `""` in the `.fox`, left out of Excel, PDF and LaTeX, and shown as `***` in the activity log.
- MISP and VirusTotal are called by the server; the browser never receives a key.
- The server-wide MISP key is only ever sent to the server-wide MISP URL. A case that uses its own MISP must set
  both its own URL and its own key, so nobody can redirect the shared key to another host.
- Only administrators change the server-wide settings. Each case chooses between them and its own (switches in
  Case Details), and `.fox` exports never contain the server-wide URL.

## Input and output

**Input**:
- Strict request models (unknown properties rejected, bounded lengths) and per-field validation
  ([data-model.md](data-model.md)).
- References must exist. Record text is single-line, and control characters are rejected.
- `.fox` imports use strict JSON (no `NaN`/`Infinity`), a size limit (`MAX_IMPORT_MB`) and a nesting-depth limit
  (64 levels, so an unknown key carried through for Aurora forward-compatibility cannot be a nesting bomb), and
  are fully validated before anything is written.
- Every SQL query is parameterised.

**Web UI**:
- Case data is only ever set as text, never as HTML; URLs are shown as text, not links.
- Strict CSP: `default-src 'self'`, no inline script or style, `frame-ancestors 'none'`.
- `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on `/api`.

**Exports**:
- Excel writes text cells as strings, so `=cmd|…` never becomes a formula.
- PDF escapes markup.
- LaTeX escapes every special character, so `\input{…}` or `\write18{…}` is printed, never executed.

**Integrations**:
- *Send to MISP* sends only values proposed from the record, at most 10 per request.
- TLS is verified and HTTPS is required (unless `MISP_ALLOW_HTTP`). No redirects, a 4 MB response cap and
  timeouts.
- Before each MISP request the host is resolved and checked: loopback, link-local (incl. the `169.254.169.254`
  cloud-metadata address), multicast, unspecified and reserved addresses are always refused. Private RFC1918 /
  unique-local ranges are treated differently by the URL's source, to contain server-side request forgery
  (CWE-918): the **server-wide** MISP is configured by an administrator, so it may use a private address unless
  `MISP_ALLOW_PRIVATE=false`; a **case's own** MISP URL is supplied by an editor, so it may **not** reach a
  private address even when `MISP_ALLOW_PRIVATE=true` — the administrator must list the host in
  `MISP_ALLOWED_HOSTS` to permit it. `MISP_ALLOWED_HOSTS` (when set) also restricts every request to the named
  hosts. The connection then re-resolves the hostname by name (so a MISP that legitimately moves IP keeps
  working), which trades strict DNS-rebinding protection for that flexibility.

## Integrity and concurrency

- Every write is an InnoDB transaction under a database-wide named lock, so validation, reference checks,
  cascades and the write are atomic across workers and instances. Bulk creates and imports are all-or-nothing.
- Updates use optimistic locking (record `version`, or the field values the client started from). Edits to
  different fields merge; the same field gives `409` with both values. Nothing is overwritten silently.
- Exports are built from one consistent snapshot and re-validated; a `.fox` exported here re-imports and
  re-exports byte-for-byte identically.
- Activity log: every change, row action and export, with actor (`username` or `api:<key name>`), UTC time and
  before/after values. Pruning is optional (`AUDIT_RETENTION_WEEKS`).

## Backups

- Snapshots are written to a temporary file and then renamed, so no half-written file is ever left behind.
- Database credentials reach the dump tools through a private file, never the command line.
- With `BACKUP_ENCRYPT=true` the dump is streamed through `gpg` to the configured public key, and no unencrypted
  copy touches the disk. The key is checked at start-up.
- Restore is admin-only and needs a typed confirmation. It refuses encrypted or foreign files, takes a
  `pre-restore` snapshot and ends every session.

## Container

- Non-root (uid 10001), read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, PID and memory limits.
- Port bound to loopback by default.
- The bundled MariaDB publishes no port and has a random root password. The application connects with its own
  user, whose rights are limited to the application database.

## Known limits

- Someone who knows a username can lock it for `LOGIN_LOCKOUT_MINUTES`.
- IP checks depend on the reverse proxy reporting the real client address.

## Reporting vulnerabilities

Privately, through the repository's
[security advisories](https://github.com/setecstuff/aurorair-web/security/advisories/new), not in public issues
and not to the original Aurora project.
