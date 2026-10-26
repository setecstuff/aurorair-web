import os
import re
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    v = os.environ.get(name)
    return int(v) if v not in (None, "") else default


def _secret(name: str) -> str:
    """Read NAME or NAME_FILE (docker secrets)."""
    path = os.environ.get(name + "_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return os.environ.get(name, "")


def _hhmm(name: str, default: str) -> tuple[int, int]:
    v = (os.environ.get(name) or default).strip()
    m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", v)
    if not m:
        raise SystemExit(f"{name} must be HH:MM (UTC), got {v!r}")
    return int(m[1]), int(m[2])


class Settings:
    def __init__(self):
        self.data_dir = Path(os.environ.get("DATA_DIR", "/data"))
        self.backup_dir = self.data_dir / "backups"

        # Database (MariaDB / MySQL). With the bundled container DB_HOST is "db".
        self.db_host = os.environ.get("DB_HOST", "db").strip()
        self.db_port = _int("DB_PORT", 3306)
        self.db_name = os.environ.get("DB_NAME", "aurora").strip()
        self.db_user = os.environ.get("DB_USER", "aurora").strip()
        self.db_password = _secret("DB_PASSWORD")
        self.db_ssl_ca = os.environ.get("DB_SSL_CA", "").strip()     # PEM CA to require TLS to an external server
        self.db_pool_size = _int("DB_POOL_SIZE", 10)

        # Encrypts TOTP secrets and the MISP/VirusTotal API keys stored in the database.
        self.secret_key = _secret("SECRET_KEY")

        self.admin_username = os.environ.get("ADMIN_USERNAME", "admin").strip()
        self.admin_password = _secret("ADMIN_PASSWORD")
        # Every start with this set: remove the admin's MFA and IP allowlist and set the password from .env.
        self.admin_force_reset = _bool("ADMIN_FORCE_RESET", False)
        # Read on every start: users without MFA must enrol right after their password.
        self.mfa_enforced = _bool("MFA_ENFORCED", False)
        self.mfa_issuer = os.environ.get("MFA_ISSUER", "Aurora IR Web").strip() or "Aurora IR Web"

        self.cookie_secure = _bool("COOKIE_SECURE", True)
        self.session_idle_minutes = _int("SESSION_IDLE_MINUTES", 480)
        self.session_max_hours = _int("SESSION_MAX_HOURS", 24)

        self.max_body_kb = _int("MAX_BODY_KB", 1024)
        self.max_import_mb = _int("MAX_IMPORT_MB", 25)
        self.max_restore_mb = _int("MAX_RESTORE_MB", 2048)
        # Maximum total records (all sections) a single case may hold; 0 = unlimited. Guards against an
        # authenticated client filling storage. Applies to create, bulk, .fox import and replace.
        self.max_records_per_case = _int("MAX_RECORDS_PER_CASE", 200_000)
        # Per-principal rate limits on expensive operations (0 = unlimited). Exports build PDFs/spreadsheets
        # from a consistent snapshot; on-demand backups fork mysqldump/gzip/gpg.
        self.export_rate_per_min = _int("EXPORT_RATE_PER_MIN", 60)
        self.backup_rate_per_hour = _int("BACKUP_RATE_PER_HOUR", 12)

        # Daily database snapshots (mysqldump), optionally PGP-encrypted.
        self.backup_enabled = _bool("BACKUP_ENABLED", True)
        self.backup_time = _hhmm("BACKUP_TIME_UTC", "02:00")
        self.backup_keep = _int("BACKUP_KEEP", 30)
        self.backup_encrypt = _bool("BACKUP_ENCRYPT", False)
        self.backup_pgp_public_key = _secret("BACKUP_PGP_PUBLIC_KEY").replace("\\n", "\n")

        # Activity-log pruning: entries older than this many weeks are deleted daily (0 = keep forever).
        self.audit_retention_weeks = _int("AUDIT_RETENTION_WEEKS", 0)

        self.min_password_len = _int("MIN_PASSWORD_LENGTH", 12)
        self.login_max_failures = _int("LOGIN_MAX_FAILURES", 5)
        self.login_lockout_minutes = _int("LOGIN_LOCKOUT_MINUTES", 15)

        # Outbound integrations (MISP, VirusTotal), called by the server, never by the browser
        self.integrations_enabled = _bool("INTEGRATIONS_ENABLED", True)
        self.integrations_timeout = _int("INTEGRATIONS_TIMEOUT", 15)
        self.integrations_ca_file = os.environ.get("INTEGRATIONS_CA_FILE", "").strip()
        self.misp_verify_tls = _bool("MISP_VERIFY_TLS", True)
        self.misp_allow_http = _bool("MISP_ALLOW_HTTP", False)
        # Internal MISP servers are the norm, so private ranges are allowed by default. Set false to refuse
        # RFC1918 / unique-local addresses (loopback / link-local / cloud-metadata are always refused).
        self.misp_allow_private = _bool("MISP_ALLOW_PRIVATE", True)
        self.misp_allowed_hosts = {h.strip().lower() for h in os.environ.get("MISP_ALLOWED_HOSTS", "").split(",")
                                   if h.strip()}


settings = Settings()
