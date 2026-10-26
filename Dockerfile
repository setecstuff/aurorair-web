# Pinned by digest for reproducible, tamper-evident builds. Update the digest to pull a patched base
# (python:3.14-slim). Dependabot (.github/dependabot.yml) proposes digest bumps automatically.
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

LABEL org.opencontainers.image.title="Aurora IR Web" \
      org.opencontainers.image.source="https://github.com/setecstuff/aurorair-web" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MPLCONFIGDIR=/tmp/matplotlib \
    DATA_DIR=/data \
    TZ=UTC

# mariadb-client: mariadb-dump / mariadb for snapshots and restore; gnupg: optional backup encryption
RUN apt-get update \
 && apt-get install -y --no-install-recommends mariadb-client gnupg \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
# requirements.lock is hash-pinned (pip-compile --generate-hashes); --require-hashes refuses any package
# whose download does not match a recorded SHA-256, so a compromised/typosquatted dist cannot be installed.
COPY requirements.lock .
RUN pip install --require-hashes -r requirements.lock \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin aurora \
 && mkdir -p /data/backups && chown -R aurora:aurora /data

COPY app ./app
COPY docs ./docs
COPY LICENSE NOTICE ./

USER aurora
VOLUME ["/data"]
EXPOSE 8083

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8083/healthz', timeout=4).status == 200 else 1)"

# All shared state (sessions, throttling, write lock) lives in the database, so several workers - or several
# containers behind a load balancer - can serve the same database. WEB_WORKERS defaults to 2.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8083 --workers ${WEB_WORKERS:-2} --proxy-headers --no-server-header --no-date-header --timeout-graceful-shutdown 20"]
