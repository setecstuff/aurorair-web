# Installation

> **No warranty.** Aurora IR Web is provided "AS IS", with **no warranty** and **no liability for data loss** or
> other damages (Apache-2.0, Sections 7–8). It creates, imports, overwrites and deletes case data and restores
> whole databases — **test on sample data and keep verified off-host backups before trusting it with real
> cases.** Full text: see the Disclaimer section of the README, or the Apache License §7–§8.

Two setups:

* **A. Single instance**: the application and a MariaDB container on one Docker host.
* **B. External / managed database**: the application on Docker, the database on a MariaDB/MySQL server you or
  your DBA run.

Both need Docker Engine with Compose v2.20+ and a TLS reverse proxy (below). Tested with MariaDB 10.11; the
bundled container uses `mariadb:11.4`. MySQL 8.0 should work but has not been tested.

```bash
git clone https://github.com/setecstuff/aurorair-web.git aurora-web && cd aurora-web
cp .env.example .env
```

Always set in `.env`:

* `ADMIN_PASSWORD`: the first administrator's password (≥12 characters, used on the first start only);
* `SECRET_KEY`: ≥32 random characters (`openssl rand -base64 48`). Keep it: it decrypts MFA secrets and
  MISP/VirusTotal keys, also in restored backups;
* `DB_PASSWORD`.

## A. Single instance (bundled database)

```dotenv
COMPOSE_PROFILES=bundled-db
# DB_HOST not set: the internal database container is used
DB_NAME=aurora
DB_USER=aurora
DB_PASSWORD=<long random password>
```

```bash
docker compose up -d --build
docker compose logs -f aurora-web
```

On the first start MariaDB finds an empty `db-data` volume and creates the database and user from `.env`; the
application then creates its tables. On later deploys both find everything in place and change nothing.

## B. External / managed database

### 1. The DBA prepares the server, once, before the first deploy

```sql
CREATE DATABASE aurora CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'aurora'@'10.0.5.%' IDENTIFIED BY '<long random password>';   -- the application host(s)
GRANT ALL PRIVILEGES ON aurora.* TO 'aurora'@'10.0.5.%';
```

```bash
mariadb -h db.corp.lan -u aurora -p aurora < docs/schema.sql      # or: mysql …
```

`ALL PRIVILEGES` on this one database is needed for a restore (it drops and re-creates the tables). No
server-wide privileges are needed.

### 2. Point the application at it

```dotenv
COMPOSE_PROFILES=
DB_HOST=db.corp.lan
DB_PORT=3306
DB_NAME=aurora
DB_USER=aurora
DB_PASSWORD=<the password from step 1>
# DB_SSL_CA=/run/certs/db-ca.pem    # TLS to the database (mount the CA file into the container)
```

```bash
docker compose up -d --build
```

With `COMPOSE_PROFILES` empty no database container is started.

## What happens at start-up

The application waits up to a minute for the database, then checks the schema:

* all tables present: nothing is executed;
* empty database: the tables are created;
* some tables missing (e.g. a new version adds one): only those are created, or, if the user lacks the right,
  the application refuses to start and names the table.

It never drops a table and never creates the database.

## Reverse proxy

The container speaks plain HTTP on `127.0.0.1:8083`. The proxy terminates TLS, forwards everything unchanged and
must **overwrite** `X-Forwarded-For` with the client address (IP allowlists and login throttling depend on it).
No WebSockets or sticky sessions are needed.

nginx:

```nginx
server {
    listen 443 ssl;
    server_name air.example.com;
    ssl_certificate     /etc/letsencrypt/live/air.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/air.example.com/privkey.pem;
    client_max_body_size 2g;              # snapshot restores; 25m is enough otherwise
    proxy_read_timeout 600s;

    location / {
        proxy_pass http://127.0.0.1:8083;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Apache (`a2enmod proxy proxy_http headers ssl`):

```apache
<VirtualHost *:443>
    ServerName air.example.com
    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/air.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/air.example.com/privkey.pem
    ProxyPreserveHost On
    ProxyPass         /  http://127.0.0.1:8083/
    ProxyPassReverse  /  http://127.0.0.1:8083/
    RequestHeader set X-Forwarded-For   "%{REMOTE_ADDR}s"
    RequestHeader set X-Forwarded-Proto "https"
    Header always set Strict-Transport-Security "max-age=31536000"
</VirtualHost>
```

* Proxy on another host: set `BIND_ADDRESS` to the interface it reaches and `FORWARDED_ALLOW_IPS` to its address
  as seen from the container.
* Cloudflare: disable *Rocket Loader* (the CSP blocks it and the UI stays on "Loading…"); with Apache use
  `mod_remoteip` (`RemoteIPHeader CF-Connecting-IP`, trusting only Cloudflare's ranges) so `REMOTE_ADDR` is the
  real client.

## First steps

1. Open `https://air.example.com/` and sign in as `ADMIN_USERNAME` (enrol an authenticator if
   `MFA_ENFORCED=true`).
2. **Administration → Users**: create the team's accounts. **Administration → API Keys**: keys for programs.
3. **+ New case**, or **Administration → Cases → Import** a `.fox`.
4. **Administration → Backups & Restore → Back up now**, and copy snapshots off the host regularly.

## Upgrades

```bash
git pull && docker compose up -d --build
```

Take a snapshot first. Data stays in the `db-data` volume or on your server. `docker compose down -v` deletes the
volumes, including the bundled database: never use `-v` unless you mean it.

Every setting, MFA, backups and restore, troubleshooting: [deployment.md](deployment.md).
