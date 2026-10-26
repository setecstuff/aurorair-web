-- Aurora IR Web database schema (MariaDB 10.6+ / MySQL 8.0+, InnoDB, utf8mb4).
-- Generated from app/db.py by tools/gen_docs.py. Do not edit by hand.
-- The application creates these tables itself on start-up (CREATE TABLE IF NOT EXISTS). Use this file
-- to review the schema or to pre-create the tables on an external server.

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS case_reports (
    case_pk           BIGINT UNSIGNED NOT NULL PRIMARY KEY,
    executive_summary LONGTEXT NOT NULL,
    conclusions       LONGTEXT NOT NULL,
    lessons_learned   LONGTEXT NOT NULL,
    updated_at        BIGINT NOT NULL,
    updated_by        VARCHAR(160) NOT NULL DEFAULT '',
    CONSTRAINT fk_reports_case FOREIGN KEY (case_pk) REFERENCES cases(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Report page: executive summary, context, conclusions, lessons learned (never in the .fox)';

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_failures (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    k            VARCHAR(100) NOT NULL COMMENT 'u:<username> or ip:<address>',
    ts           BIGINT NOT NULL,
    KEY login_failures_k (k, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='brute-force throttling, shared by all instances';

CREATE TABLE IF NOT EXISTS settings (
    k            VARCHAR(64) NOT NULL PRIMARY KEY,
    v            TEXT NOT NULL COMMENT 'API keys are stored encrypted (v1:...)',
    updated_at   BIGINT NOT NULL,
    updated_by   VARCHAR(160) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='server-wide settings: default MISP server/key, VirusTotal key';

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='per-case access: which users may view/edit a case';

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='owner/admin-issued codes that let a user join a case';
