"""
MariaDB / MySQL plumbing.

One database holds everything: case data (one JSON document per Aurora record), executive summaries, the audit
log, users, sessions, API keys and login throttling. The application code keeps writing portable SQL with `?`
placeholders; `Conn` translates them for PyMySQL and returns rows that work both by name and by position.

Writes go through `write_tx`: it takes a database-wide named lock (GET_LOCK) before the transaction, so
"check references -> modify" sequences are atomic even with several application instances (replicas) behind a
load balancer. Reads that need a consistent view of several tables use `read_tx` (consistent snapshot).
"""
from __future__ import annotations

import queue
import time
from contextlib import contextmanager

import pymysql

from .config import settings

# --------------------------------------------------------------------------- #
# Schema (InnoDB, utf8mb4). Also published as docs/schema.sql by tools/gen_docs.py.
# --------------------------------------------------------------------------- #

TABLES = [
    ("cases", """
CREATE TABLE IF NOT EXISTS cases (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    uuid         CHAR(36) NOT NULL DEFAULT '' COMMENT 'stable external id, shared with invite codes',
    owner_id     BIGINT UNSIGNED NULL COMMENT 'the case owner (a user); NULL = owner-less, admin only',
    meta         LONGTEXT NOT NULL COMMENT 'JSON: case fields, lookup lists, passthrough .fox keys',
    revision     BIGINT UNSIGNED NOT NULL DEFAULT 1 COMMENT 'bumped on every change, polled by clients',
    created_at   BIGINT NOT NULL,
    updated_at   BIGINT NOT NULL,
    updated_by   VARCHAR(160) NOT NULL DEFAULT '',
    UNIQUE KEY cases_uuid (uuid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""),
    ("records", """
CREATE TABLE IF NOT EXISTS records (
    case_pk      BIGINT UNSIGNED NOT NULL,
    section      VARCHAR(40) NOT NULL,
    recid        BIGINT UNSIGNED NOT NULL,
    position     BIGINT NOT NULL DEFAULT 0,
    data         LONGTEXT NOT NULL COMMENT 'JSON object exactly as written to the .fox',
    version      BIGINT UNSIGNED NOT NULL DEFAULT 1,
    updated_at   BIGINT NOT NULL,
    updated_by   VARCHAR(160) NOT NULL DEFAULT '',
    PRIMARY KEY (case_pk, section, recid),
    CONSTRAINT fk_records_case FOREIGN KEY (case_pk) REFERENCES cases(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""),
    ("case_reports", """
CREATE TABLE IF NOT EXISTS case_reports (
    case_pk           BIGINT UNSIGNED NOT NULL PRIMARY KEY,
    executive_summary LONGTEXT NOT NULL,
    conclusions       LONGTEXT NOT NULL,
    lessons_learned   LONGTEXT NOT NULL,
    updated_at        BIGINT NOT NULL,
    updated_by        VARCHAR(160) NOT NULL DEFAULT '',
    CONSTRAINT fk_reports_case FOREIGN KEY (case_pk) REFERENCES cases(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Report page: executive summary, context, conclusions, lessons learned (never in the .fox)'"""),
    ("audit", """
CREATE TABLE IF NOT EXISTS audit (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    case_pk      BIGINT UNSIGNED NOT NULL,
    ts           BIGINT NOT NULL,
    username     VARCHAR(160) NOT NULL,
    action       VARCHAR(60) NOT NULL,
    section      VARCHAR(40) NULL,
    recid        BIGINT UNSIGNED NULL,
    before_data  LONGTEXT NULL,
    after_data   LONGTEXT NULL,
    KEY audit_case (case_pk, id),
    KEY audit_ts (ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""),
    ("users", """
CREATE TABLE IF NOT EXISTS users (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(32) NOT NULL COMMENT 'unique, case-insensitive (collation)',
    pw_hash         VARCHAR(255) NOT NULL COMMENT 'Argon2id with a random per-user salt (PHC string)',
    role            ENUM('admin','user') NOT NULL COMMENT 'global role; per-case rights live in case_members',
    active          TINYINT(1) NOT NULL DEFAULT 1,
    investigator    VARCHAR(20) NOT NULL DEFAULT '' COMMENT 'default analyst/owner short name',
    is_env_admin    TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'the bootstrap admin from .env',
    must_change_pw  TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'set by an admin: new password required at next login',
    mfa_secret      VARCHAR(255) NULL COMMENT 'TOTP secret, AES-256-GCM encrypted with SECRET_KEY',
    mfa_enabled     TINYINT(1) NOT NULL DEFAULT 0,
    mfa_last_step   BIGINT NOT NULL DEFAULT 0 COMMENT 'last accepted TOTP time step (replay protection)',
    ip_allowlist    TEXT NOT NULL COMMENT 'JSON list of IPs / CIDRs; empty list = any address',
    created_at      BIGINT NOT NULL,
    pw_changed_at   BIGINT NOT NULL,
    UNIQUE KEY users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""),
    ("sessions", """
CREATE TABLE IF NOT EXISTS sessions (
    token_hash   CHAR(64) NOT NULL PRIMARY KEY COMMENT 'sha256 of the cookie value',
    user_id      BIGINT UNSIGNED NOT NULL,
    csrf         VARCHAR(64) NOT NULL,
    stage        VARCHAR(16) NOT NULL DEFAULT 'full' COMMENT 'mfa | password | mfa_setup | full',
    created_at   BIGINT NOT NULL,
    last_seen    BIGINT NOT NULL,
    ip           VARCHAR(45) NOT NULL DEFAULT '',
    mfa_pending  VARCHAR(255) NULL COMMENT 'encrypted TOTP secret offered during enrolment',
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""),
    ("api_keys", """
CREATE TABLE IF NOT EXISTS api_keys (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name         VARCHAR(64) NOT NULL COMMENT 'the key''s identity in the activity log',
    profile      ENUM('read','readwrite') NOT NULL,
    kind         ENUM('admin','case') NOT NULL DEFAULT 'case' COMMENT 'admin = full admin API; case = case data only',
    scope        ENUM('all','single') NOT NULL DEFAULT 'all' COMMENT 'case keys: every case, or one case',
    case_pk      BIGINT UNSIGNED NULL COMMENT 'the single case a scope=single key is limited to',
    prefix       VARCHAR(16) NOT NULL COMMENT 'first characters, for display only',
    secret_hash  CHAR(64) NOT NULL COMMENT 'sha256 of the secret; the secret itself is never stored',
    enabled      TINYINT(1) NOT NULL DEFAULT 1,
    expires_at   BIGINT NULL COMMENT 'NULL = never',
    ip_allowlist TEXT NOT NULL COMMENT 'JSON list of IPs / CIDRs; empty list = any address',
    created_at   BIGINT NOT NULL,
    created_by   VARCHAR(32) NOT NULL,
    rotated_at   BIGINT NULL,
    last_used_at BIGINT NULL,
    last_used_ip VARCHAR(45) NOT NULL DEFAULT '',
    UNIQUE KEY api_keys_name (name),
    UNIQUE KEY api_keys_secret (secret_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"""),
    ("login_failures", """
CREATE TABLE IF NOT EXISTS login_failures (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    k            VARCHAR(100) NOT NULL COMMENT 'u:<username> or ip:<address>',
    ts           BIGINT NOT NULL,
    KEY login_failures_k (k, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='brute-force throttling, shared by all instances'"""),
    ("settings", """
CREATE TABLE IF NOT EXISTS settings (
    k            VARCHAR(64) NOT NULL PRIMARY KEY,
    v            TEXT NOT NULL COMMENT 'API keys are stored encrypted (v1:...)',
    updated_at   BIGINT NOT NULL,
    updated_by   VARCHAR(160) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='server-wide settings: default MISP server/key, VirusTotal key'"""),
    ("case_members", """
CREATE TABLE IF NOT EXISTS case_members (
    case_pk      BIGINT UNSIGNED NOT NULL,
    user_id      BIGINT UNSIGNED NOT NULL,
    permission   ENUM('editor','viewer') NOT NULL,
    added_at     BIGINT NOT NULL,
    added_by     VARCHAR(160) NOT NULL DEFAULT '',
    PRIMARY KEY (case_pk, user_id),
    KEY case_members_user (user_id),
    CONSTRAINT fk_cm_case FOREIGN KEY (case_pk) REFERENCES cases(id) ON DELETE CASCADE,
    CONSTRAINT fk_cm_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='per-case access: which users may view/edit a case'"""),
    ("case_invites", """
CREATE TABLE IF NOT EXISTS case_invites (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    case_pk      BIGINT UNSIGNED NOT NULL,
    code_hash    CHAR(64) NOT NULL COMMENT 'sha256 of the invite code; the code itself is never stored',
    prefix       VARCHAR(16) NOT NULL COMMENT 'first characters, for display only',
    permission   ENUM('editor','viewer') NOT NULL,
    max_redeems  INT NOT NULL DEFAULT 1 COMMENT '0 = unlimited',
    redeems_used INT NOT NULL DEFAULT 0,
    expires_at   BIGINT NULL COMMENT 'NULL = never',
    enabled      TINYINT(1) NOT NULL DEFAULT 1,
    created_at   BIGINT NOT NULL,
    created_by   VARCHAR(160) NOT NULL DEFAULT '',
    UNIQUE KEY case_invites_code (code_hash),
    KEY case_invites_case (case_pk),
    CONSTRAINT fk_ci_case FOREIGN KEY (case_pk) REFERENCES cases(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='owner/admin-issued codes that let a user join a case'"""),
]

TABLE_NAMES = [name for name, _ in TABLES]


def schema_sql() -> str:
    return "\n".join(ddl.strip() + ";\n" for _, ddl in TABLES)


# --------------------------------------------------------------------------- #
# Connections
# --------------------------------------------------------------------------- #

class Row(dict):
    """A result row usable as row["name"] and row[0]."""
    __slots__ = ("_vals",)

    def __init__(self, cols, vals):
        super().__init__(zip(cols, vals))
        self._vals = vals

    def __getitem__(self, k):
        if isinstance(k, int):
            return self._vals[k]
        return dict.__getitem__(self, k)

    def keys(self):
        return list(dict.keys(self))


class Cursor:
    def __init__(self, cur):
        self._cur = cur
        self.lastrowid = cur.lastrowid
        self.rowcount = cur.rowcount
        self._cols = [d[0] for d in cur.description] if cur.description else []

    def _row(self, t):
        return None if t is None else Row(self._cols, t)

    def fetchone(self):
        return self._row(self._cur.fetchone())

    def fetchall(self):
        return [Row(self._cols, t) for t in self._cur.fetchall()]

    def __iter__(self):
        return iter(self.fetchall())


class Conn:
    """Thin wrapper: `?` placeholders, Row results, explicit transactions (autocommit otherwise)."""

    def __init__(self, raw: pymysql.connections.Connection):
        self.raw = raw

    @staticmethod
    def _sql(sql: str) -> str:
        return sql.replace("%", "%%").replace("?", "%s")

    def execute(self, sql: str, args=()) -> Cursor:
        cur = self.raw.cursor()
        cur.execute(self._sql(sql), tuple(args) if args else None)
        return Cursor(cur)

    def close(self):
        try:
            self.raw.close()
        except Exception:
            pass


def _connect(database: bool = True) -> pymysql.connections.Connection:
    raw = pymysql.connect(
        host=settings.db_host, port=settings.db_port, user=settings.db_user, password=settings.db_password,
        database=settings.db_name if database else None, charset="utf8mb4", autocommit=True,
        connect_timeout=10, read_timeout=300, write_timeout=300,
        ssl={"ca": settings.db_ssl_ca} if settings.db_ssl_ca else None,
        init_command="SET SESSION sql_mode='STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ENGINE_SUBSTITUTION', "
                     "time_zone='+00:00'")
    with raw.cursor() as cur:
        cur.execute("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")
    return raw


class _Pool:
    def __init__(self, size: int):
        self._q: queue.LifoQueue = queue.LifoQueue(maxsize=size)

    def get(self) -> Conn:
        try:
            c = self._q.get_nowait()
            try:
                c.raw.ping(reconnect=False)
                return c
            except Exception:
                c.close()
        except queue.Empty:
            pass
        return Conn(_connect())

    def put(self, c: Conn, broken: bool = False) -> None:
        if broken:
            c.close()
            return
        try:
            self._q.put_nowait(c)
        except queue.Full:
            c.close()

    def clear(self) -> None:
        while True:
            try:
                self._q.get_nowait().close()
            except queue.Empty:
                return


_pool = _Pool(settings.db_pool_size)


@contextmanager
def db():
    conn = _pool.get()
    broken = False
    try:
        yield conn
    except pymysql.err.OperationalError:
        broken = True
        raise
    finally:
        _pool.put(conn, broken)


# Backwards-compatible names used across the code base (one database now holds everything).
cases_db = db
users_db = db


def reset_pool() -> None:
    """Drop pooled connections (after a restore replaced every table)."""
    _pool.clear()


WRITE_LOCK = "aurora_ir_web_write"


class Busy(Exception):
    pass


@contextmanager
def write_tx(conn: Conn):
    """Serialised read-modify-write transaction (database-wide named lock, works across instances)."""
    got = conn.execute("SELECT GET_LOCK(?, ?)", (WRITE_LOCK, 30)).fetchone()[0]
    if got != 1:
        raise Busy("the database is busy, try again")
    try:
        conn.execute("START TRANSACTION")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")
    finally:
        conn.execute("SELECT RELEASE_LOCK(?)", (WRITE_LOCK,))


@contextmanager
def read_tx(conn: Conn):
    """Consistent snapshot for multi-statement reads (e.g. export)."""
    conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
    conn.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
    try:
        yield conn
    finally:
        conn.execute("COMMIT")


def init_db(retries: int = 30) -> list[str]:
    """Check the schema and create only what is missing. Never drops or re-creates anything, and never creates
    the database itself (the bundled container or the DBA does). Waits for the database to come up (the bundled
    container starts in parallel). Returns the names of the tables it created."""
    import logging
    log = logging.getLogger("aurora.db")
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    last = None
    for _ in range(max(1, retries)):
        try:
            raw = _connect()
            break
        except pymysql.err.OperationalError as e:
            last = e
            time.sleep(2)
    else:
        raise RuntimeError(f"cannot connect to the database {settings.db_host}:{settings.db_port}/"
                           f"{settings.db_name}: {last}")
    c = Conn(raw)
    try:
        present = {r[0].lower() for r in c.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()").fetchall()}
        missing = [(name, ddl) for name, ddl in TABLES if name not in present]
        if not missing:
            log.info("database schema present (%d tables), nothing to create", len(TABLES))
            return []
        if len(missing) == len(TABLES):
            log.info("empty database: creating the schema (%d tables)", len(TABLES))
        else:
            log.warning("database schema incomplete: creating missing tables %s", ", ".join(n for n, _ in missing))
        for name, ddl in missing:
            try:
                c.execute(ddl)
            except pymysql.err.MySQLError as e:
                raise RuntimeError(f"table '{name}' is missing and cannot be created ({e.args[-1]}). Ask the DBA to "
                                   f"create the schema from docs/schema.sql, or grant CREATE on {settings.db_name}.")
        return [n for n, _ in missing]
    finally:
        c.close()


def migrate() -> None:
    """Idempotent, in-place upgrades of tables that already existed before a feature was added. Safe to run on
    every start; each step is a no-op once applied. Adds the per-case access-control columns (cases.uuid /
    owner_id, api_keys.kind/scope/case_pk), backfills them, and collapses the old global editor/viewer roles to
    the single 'user' role (per-case rights now live in case_members). New tables are created by init_db()."""
    import logging
    import uuid as _uuid
    log = logging.getLogger("aurora.db")
    c = Conn(_connect())
    try:
        def col_type(table: str, column: str) -> str | None:
            r = c.execute("SELECT column_type FROM information_schema.columns "
                          "WHERE table_schema=DATABASE() AND table_name=? AND column_name=?",
                          (table, column)).fetchone()
            return (r[0].decode() if isinstance(r[0], (bytes, bytearray)) else r[0]) if r else None

        # 1. Add the new columns if they are missing (MariaDB supports IF NOT EXISTS for ADD COLUMN).
        adds = [
            "ALTER TABLE cases ADD COLUMN IF NOT EXISTS uuid CHAR(36) NOT NULL DEFAULT '' AFTER id",
            "ALTER TABLE cases ADD COLUMN IF NOT EXISTS owner_id BIGINT UNSIGNED NULL AFTER uuid",
            "ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS kind ENUM('admin','case') NOT NULL DEFAULT 'case' AFTER profile",
            "ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scope ENUM('all','single') NOT NULL DEFAULT 'all' AFTER kind",
            "ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS case_pk BIGINT UNSIGNED NULL AFTER scope",
        ]
        for ddl in adds:
            c.execute(ddl)

        # 2. Backfill a uuid for every case that has none, then enforce uniqueness.
        rows = c.execute("SELECT id FROM cases WHERE uuid = '' OR uuid IS NULL").fetchall()
        for row in rows:                       # Row is a dict subclass: index by name, not by unpacking
            c.execute("UPDATE cases SET uuid=? WHERE id=?", (str(_uuid.uuid4()), row["id"]))
        if rows:
            log.warning("migrate: assigned a uuid to %d existing case(s)", len(rows))
        has_uuid_key = c.execute("SELECT 1 FROM information_schema.statistics WHERE table_schema=DATABASE() "
                                 "AND table_name='cases' AND index_name='cases_uuid'").fetchone()
        if not has_uuid_key:
            c.execute("ALTER TABLE cases ADD UNIQUE KEY cases_uuid (uuid)")

        # 3. Greenfield: give owner-less existing cases to the bootstrap admin so they are not orphaned.
        admin = c.execute("SELECT id FROM users WHERE is_env_admin=1 ORDER BY id LIMIT 1").fetchone()
        if admin:
            upd = c.execute("UPDATE cases SET owner_id=? WHERE owner_id IS NULL", (admin[0],))
            if getattr(upd, "rowcount", 0):
                log.warning("migrate: set the bootstrap admin as owner of %d owner-less case(s)", upd.rowcount)

        # 4. Collapse the old global roles: editor/viewer -> user (per-case rights now live in case_members).
        rtype = col_type("users", "role") or ""
        if "'editor'" in rtype or "'viewer'" in rtype:
            c.execute("ALTER TABLE users MODIFY role ENUM('admin','editor','viewer','user') NOT NULL")
            moved = c.execute("UPDATE users SET role='user' WHERE role IN ('editor','viewer')")
            c.execute("ALTER TABLE users MODIFY role ENUM('admin','user') NOT NULL")
            if getattr(moved, "rowcount", 0):
                log.warning("migrate: converted %d editor/viewer account(s) to the 'user' role", moved.rowcount)
    finally:
        c.close()
