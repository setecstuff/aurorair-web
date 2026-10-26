# Operations

Installing, the reverse proxy and upgrades: [installation.md](installation.md).

## Configuration (`.env`)

| variable | default | meaning |
|---|---|---|
| `ADMIN_USERNAME` | `admin` | Administrator created on the first start |
| `ADMIN_PASSWORD` | required | Its password on the first start (≥12 characters). Not applied again, except with `ADMIN_FORCE_RESET` |
| `ADMIN_FORCE_RESET` | `false` | Recovery: on **every** start while `true`, removes the admin's MFA and IP allowlist and sets the password from `ADMIN_PASSWORD` |
| `SECRET_KEY` | required | ≥32 characters. Encrypts TOTP secrets and MISP/VirusTotal keys. Keep it unchanged: restored backups need it |
| `MFA_ENFORCED` | `false` | Read on every start. `true`: users without MFA must enrol right after signing in |
| `MFA_ISSUER` | `Aurora IR Web` | Name shown in authenticator apps |
| `COMPOSE_PROFILES` | `bundled-db` | `bundled-db` starts the MariaDB container; empty for an external database |
| `DB_HOST` / `DB_PORT` | `db` / `3306` | Database server; unset = the bundled container |
| `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `aurora` / `aurora` / required | Database, user, password |
| `DB_SSL_CA` | none | CA file: connect with TLS and verify the server |
| `DB_POOL_SIZE` | `10` | Connections per worker |
| `COOKIE_SECURE` | `true` | Secure session cookie. `false` only for local HTTP testing |
| `FORWARDED_ALLOW_IPS` | `*` | Peers allowed to set `X-Forwarded-*`. `*` is safe only while the port is reachable by the proxy alone |
| `BIND_ADDRESS` / `PORT` | `127.0.0.1` / `8083` | Address and port published by Docker |
| `WEB_WORKERS` | `2` | Worker processes |
| `SESSION_IDLE_MINUTES` / `SESSION_MAX_HOURS` | `480` / `24` | Browser session lifetime |
| `MAX_BODY_KB` / `MAX_IMPORT_MB` / `MAX_RESTORE_MB` | `1024` / `25` / `2048` | Request size limits (normal / `.fox` import and bulk / restore) |
| `MAX_RECORDS_PER_CASE` | `200000` | Max total records (all sections) per case; `0` = unlimited |
| `EXPORT_RATE_PER_MIN` / `BACKUP_RATE_PER_HOUR` | `60` / `12` | Per-principal rate limit on exports and on-demand backups; `0` = unlimited |
| `MIN_PASSWORD_LENGTH` | `12` | Password policy |
| `LOGIN_MAX_FAILURES` / `LOGIN_LOCKOUT_MINUTES` | `5` / `15` | Failed passwords or MFA codes per username before a lockout (per client IP: 4×) |
| `AUDIT_RETENTION_WEEKS` | `0` | Delete activity-log entries older than this, daily. `0` keeps everything |
| `BACKUP_ENABLED` / `BACKUP_TIME_UTC` / `BACKUP_KEEP` | `true` / `02:00` / `30` | Daily snapshot, its time (UTC) and how many snapshots are kept |
| `BACKUP_ENCRYPT` / `BACKUP_PGP_PUBLIC_KEY` | `false` / none | Encrypt snapshots with a PGP public key (last variable of `.env`) |
| `INTEGRATIONS_ENABLED` | `true` | Allow calls to MISP and VirusTotal |
| `INTEGRATIONS_TIMEOUT` | `15` | Seconds per outbound request |
| `INTEGRATIONS_CA_FILE` | system CAs | Extra CA bundle, e.g. an internal CA for MISP |
| `MISP_VERIFY_TLS` / `MISP_ALLOW_HTTP` | `true` / `false` | MISP transport rules |
| `MISP_ALLOW_PRIVATE` | `true` | Allow the **server-wide** MISP on a private network (`10/8`, `172.16/12`, `192.168/16`). `false` refuses it; loopback / link-local / cloud-metadata are always refused. A **case's own** MISP URL (set by an editor) may never use a private address regardless — allowlist its host to permit it |
| `MISP_ALLOWED_HOSTS` | any | Comma-separated MISP host names allowed (also the only way to permit a private case MISP host) |

Files mounted into the container (CA files) go under `volumes:` in `docker-compose.yml`, e.g.
`- ./internal-ca.pem:/run/certs/internal-ca.pem:ro`.

## Database and scaling

Everything (cases, executive summaries, activity log, users, sessions, API keys, login throttling) is in one
database ([schema.sql](schema.sql)). Snapshots are files in `/data/backups` (the `aurora-data` volume).

Sessions, throttling and the write lock live in the database, so several workers (`WEB_WORKERS`) or several
containers can share one database. Only one instance takes the daily snapshot. With several hosts, put
`/data/backups` on shared storage or back up the database server directly.

## MFA and account recovery

* `MFA_ENFORCED=false`: users may turn MFA on and off under **Account**.
* `MFA_ENFORCED=true`: users without MFA must enrol (QR code or typed key) before anything else, including open
  sessions at their next request.
* Any TOTP app works (SHA-1, 6 digits, 30 s).
* The app's icon: FreeOTP shows the application logo (the QR code carries its address). Authy, 1Password,
  2FAS, Aegis and similar apps pick an icon from their own catalogue by matching the issuer name, and Google or
  Microsoft Authenticator show a generic icon; the server cannot change that. A different `MFA_ISSUER` changes
  the name they match on (for new enrolments only).
* A user lost their authenticator: **Administration → Users → Reset MFA**.
* The admin lost the authenticator or password, or locked themselves out with an IP allowlist:
  1. set `ADMIN_FORCE_RESET=true` and a new `ADMIN_PASSWORD` in `.env`, run `docker compose up -d`;
  2. sign in;
  3. set `ADMIN_FORCE_RESET=false` and run `docker compose up -d` again (while it is `true`, every restart
     resets the admin).

## MISP and VirusTotal

*Send to MISP*, *Check VT* and the connection tests run on the server, so the container needs outbound HTTPS to
`www.virustotal.com` and your MISP. VirusTotal's free API allows 4 lookups per minute and 500 per day. Set
`INTEGRATIONS_ENABLED=false` on air-gapped deployments.

Where the settings come from:

* **Server-wide** (**Administration → MISP & VirusTotal**): a MISP URL with its API key, and a VirusTotal key.
* **Per case** (**Case Details**):
  * The MISP event ID is always the case's own.
  * *Use the server-wide MISP* (on by default) chooses the server-wide MISP. Off, the case uses its own URL and
    API key, both of which are needed. The server-wide key is only ever sent to the server-wide URL.
  * *Use the server-wide VirusTotal key* (on by default) chooses the server-wide key. Off, the case uses its own.
  * While a switch is on, the case's own values are kept but unused and cannot be edited.
* **Exports and imports:**
  * A `.fox` export contains only the case's own MISP URL and its event ID, so it is empty for a case that uses
    the server-wide MISP, and never contains a key.
  * Importing a `.fox` whose URL equals the server-wide one makes the case use the server-wide MISP.
  * A `.fox` with another URL makes the case use its own MISP (switch off). It then still needs its own API key.

## Backup & restore

### Snapshots

A snapshot is a gzip-compressed dump of the whole database (`mariadb-dump --single-transaction`, no locking),
named `aurora-<UTC time>-<reason>.sql.gz`. They are taken:

* daily at `BACKUP_TIME_UTC` (or later that day if the application was down at that time);
* on demand: **Administration → Backups & Restore → Back up now**;
* automatically before a case delete, a case replace and a restore.

The newest `BACKUP_KEEP` are kept. Download them from the same page or with
`docker compose cp aurora-web:/data/backups ./aurora-backups`. They contain all case data, password hashes and the
encrypted secrets: store them like the database, and off the host.

### Encrypting snapshots (PGP)

1. On an admin workstation, not the server: `gpg --quick-gen-key "Aurora backups <ir@example.org>" default default never`.
   Keep the private key offline.
2. Put the public key (`gpg --armor --export ir@example.org`) at the end of `.env`, between double quotes:

   ```dotenv
   BACKUP_ENCRYPT=true
   BACKUP_PGP_PUBLIC_KEY="-----BEGIN PGP PUBLIC KEY BLOCK-----

   mDMEZ...
   -----END PGP PUBLIC KEY BLOCK-----"
   ```

   On one line with `\n` in place of the line breaks also works.
3. `docker compose up -d`. The log shows the key fingerprint; the application refuses to start if the key cannot
   encrypt. Snapshots are now `.sql.gz.gpg`, and no unencrypted copy is written.

### Restore

A restore **replaces the whole database** with the snapshot: cases, users, API keys and activity logs. A
`pre-restore` snapshot is taken first, and everyone is signed out.

1. If the snapshot is encrypted, decrypt it where the private key is:
   `gpg --output aurora-….sql.gz --decrypt aurora-….sql.gz.gpg`. The application only accepts unencrypted files.
2. Check that `SECRET_KEY` is the one in use when the snapshot was taken. Otherwise users need an MFA reset and
   the MISP/VirusTotal keys must be entered again.
3. **Administration → Backups & Restore → Restore**: choose the file, type `RESTORE`, confirm.
4. Sign in again. If the snapshot predates your admin account or password, use `ADMIN_FORCE_RESET`.

A file too large for the browser or proxy can be loaded directly (bundled database shown; take a snapshot first):

```bash
gunzip -c aurora-….sql.gz | docker compose exec -T db sh -c 'mariadb -u"$MARIADB_USER" -p"$MARIADB_PASSWORD" "$MARIADB_DATABASE"'
docker compose restart aurora-web
```

## Health and logs

* `GET /healthz` returns `{"ok": true}` when the database answers (no authentication); Docker's health check uses
  it.
* `docker compose logs aurora-web` (UTC): **sign-ins (success, failure, MFA, lockout) with username and client
  IP**, user, key and MFA administration, admin resets, snapshots, restores, case deletions, errors. Passwords,
  tokens and API keys are never logged. Changes to case data are in each case's **Activity Log**.
  Forward these logs to your SIEM to alert on brute-force (`failed sign-in` / `throttled`) and anomalous sign-ins.

## Troubleshooting

| symptom | cause / fix |
|---|---|
| `cannot connect to the database` at start | Wrong `DB_*`, server unreachable, or (external) database / user not created yet. Bundled: `docker compose logs db` |
| `table '…' is missing and cannot be created` | External database without the schema: the DBA loads `docs/schema.sql` |
| `SECRET_KEY must be set` | Add `SECRET_KEY` (≥32 characters) to `.env` |
| `BACKUP_PGP_PUBLIC_KEY …` at start | Not an armored public key, or a sign-only / expired key |
| Stuck on "Loading…" | A proxy injects scripts (e.g. Cloudflare Rocket Loader): disable it. Hard-refresh after upgrades |
| Sign-in works locally but not through the domain | `COOKIE_SECURE=true` needs HTTPS as seen by the browser |
| Everyone gets "Too many failed attempts" | `FORWARDED_ALLOW_IPS` does not trust the proxy, so all clients look like one address |
| A user cannot sign in from a new place | Their IP allowlist (Administration → Users). Admin: `ADMIN_FORCE_RESET` |
| `401` with an API key | Key disabled, expired, rotated or deleted, or the header is not `Authorization: Bearer aurora_…` |
| `403 This API key may not be used from this IP address` | The key's IP allowlist |
| Authenticator codes refused | The phone's clock is off; each code works once, within ±30 s |
| *Check VT* / MISP "Cannot connect" or TLS errors | No outbound route or DNS; for an internal CA set `INTEGRATIONS_CA_FILE` |
| `413` | Body over `MAX_BODY_KB` / `MAX_IMPORT_MB` / `MAX_RESTORE_MB`, or the proxy's own limit |
