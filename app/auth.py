"""
Accounts, sessions, MFA (TOTP), IP allowlists, application API keys, CSRF and login throttling.

Sign-in is staged. A session starts at the first stage that applies and only reaches `full` (access to the
application) when every stage is done:

    mfa        - the user has MFA: enter the current TOTP code
    password   - an admin required a new password: choose one
    mfa_setup  - MFA_ENFORCED and the user has no MFA yet: enrol an authenticator
    full       - signed in

API keys belong to the application (not to a user) and only admins create them. A key's name is its identity
in the activity log. A key is either an `admin` key (full admin-equivalent) or a `case` key that reaches case
data only (`read` -> viewer, `readwrite` -> editor) over every case (`scope=all`) or one case (`scope=single`).
Per-case view/edit rights for interactive users live in `case_members` (see access.py).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass

from fastapi import HTTPException, Request

from . import security as sec
from .config import settings
from .db import db, write_tx

log = logging.getLogger("aurora.auth")

ROLES = ("admin", "user")          # global roles; per-case rights (editor/viewer) live in case_members
PROFILES = ("read", "readwrite")
KEY_KINDS = ("admin", "case")      # admin key = full admin API; case key = case data only
KEY_SCOPES = ("all", "single")     # case key reaches every case, or one case
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
INVESTIGATOR_RE = re.compile(r"^[^\x00-\x1f\x7f]{0,20}$")
KEY_NAME_RE = re.compile(r"^[A-Za-z0-9._:@/-]{1,64}$")
MAX_PASSWORD_LEN = 256
KEY_PREFIX = "aurora_"

SESSION_COOKIE = "__Host-aurora_session" if settings.cookie_secure else "aurora_session"
STAGES = ("mfa", "password", "mfa_setup", "full")


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #

def check_password_policy(password: str) -> None:
    if not isinstance(password, str) or len(password) < settings.min_password_len:
        raise HTTPException(400, f"Password must be at least {settings.min_password_len} characters")
    if len(password) > MAX_PASSWORD_LEN:
        raise HTTPException(400, "Password too long")
    if password.strip() != password or not password.isprintable():
        raise HTTPException(400, "Password must not start/end with spaces or contain control characters")


def validate_username(username: str) -> str:
    if not isinstance(username, str) or not USERNAME_RE.match(username):
        raise HTTPException(400, "Username must be 3-32 characters: letters, digits, . _ -")
    return username


def validate_investigator(v: str) -> str:
    if not isinstance(v, str) or not INVESTIGATOR_RE.match(v):
        raise HTTPException(400, "Investigator short name must be at most 20 printable characters")
    return v.strip()


def validate_allowlist(entries) -> list[str]:
    try:
        return sec.normalise_allowlist(entries)
    except sec.AllowlistError as e:
        raise HTTPException(400, f"IP allowlist: {e}")


def _allowlist(raw: str | None) -> list[str]:
    try:
        v = json.loads(raw or "[]")
        return v if isinstance(v, list) else []
    except ValueError:
        return []


def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


# --------------------------------------------------------------------------- #
# Bootstrap admin from the environment
# --------------------------------------------------------------------------- #

def bootstrap_admin() -> None:
    """First start: create the admin from ADMIN_USERNAME / ADMIN_PASSWORD. Later starts leave the password
    alone, unless ADMIN_FORCE_RESET is set: then MFA and the IP allowlist are removed and the password is set
    from .env again (on every start while the flag stays set)."""
    username, password = settings.admin_username, settings.admin_password
    validate_username(username)
    now = int(time.time())
    with db() as conn, write_tx(conn):
        row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if row is None:
            if not password:
                raise SystemExit("ADMIN_PASSWORD (or ADMIN_PASSWORD_FILE) must be set on first start")
            if len(password) < settings.min_password_len:
                raise SystemExit(f"ADMIN_PASSWORD must be at least {settings.min_password_len} characters")
            conn.execute(
                "INSERT INTO users (username, pw_hash, role, active, is_env_admin, ip_allowlist, created_at, "
                "pw_changed_at) VALUES (?, ?, 'admin', 1, 1, '[]', ?, ?)",
                (username, sec.hash_password(password), now, now))
            log.info("bootstrap admin %r created", username)
        else:
            conn.execute("UPDATE users SET role='admin', active=1, is_env_admin=1 WHERE id=?", (row["id"],))
            if settings.admin_force_reset:
                if not password or len(password) < settings.min_password_len:
                    raise SystemExit("ADMIN_FORCE_RESET needs ADMIN_PASSWORD (at least "
                                     f"{settings.min_password_len} characters)")
                conn.execute("UPDATE users SET pw_hash=?, pw_changed_at=?, must_change_pw=0, mfa_secret=NULL, "
                             "mfa_enabled=0, mfa_last_step=0, ip_allowlist='[]' WHERE id=?",
                             (sec.hash_password(password), now, row["id"]))
                conn.execute("DELETE FROM sessions WHERE user_id=?", (row["id"],))
                log.warning("ADMIN_FORCE_RESET: password of %r set from .env, MFA and IP allowlist removed. "
                            "Set ADMIN_FORCE_RESET=false and redeploy, or this happens on every start.", username)
        conn.execute("UPDATE users SET is_env_admin=0 WHERE username <> ?", (username,))


# --------------------------------------------------------------------------- #
# Login throttling (in the database, so it holds across application instances)
# --------------------------------------------------------------------------- #

class Throttle:
    def _window(self) -> int:
        return settings.login_lockout_minutes * 60

    def blocked(self, key: str, limit: int) -> bool:
        with db() as conn:
            n = conn.execute("SELECT count(*) FROM login_failures WHERE k=? AND ts>?",
                             (key[:100], int(time.time()) - self._window())).fetchone()[0]
        return n >= limit

    def fail(self, key: str) -> None:
        now = int(time.time())
        with db() as conn:
            conn.execute("INSERT INTO login_failures (k, ts) VALUES (?, ?)", (key[:100], now))
            if secrets.randbelow(50) == 0:
                conn.execute("DELETE FROM login_failures WHERE ts < ?", (now - 86400,))

    def reset(self, key: str) -> None:
        with db() as conn:
            conn.execute("DELETE FROM login_failures WHERE k=?", (key[:100],))


throttle = Throttle()


def rate_limit(action: str, who: str, limit: int, window_sec: int) -> None:
    """Per-principal sliding-window limit on expensive operations (reuses the login_failures event table).
    `limit` <= 0 disables it. Raises 429 once `limit` requests happened within `window_sec`."""
    if limit <= 0:
        return
    now, k = int(time.time()), f"rl:{action}:{who}"[:100]
    with db() as conn:
        n = conn.execute("SELECT count(*) FROM login_failures WHERE k=? AND ts>?", (k, now - window_sec)).fetchone()[0]
        if n >= limit:
            per = "minute" if window_sec == 60 else ("hour" if window_sec == 3600 else f"{window_sec}s")
            raise HTTPException(429, f"Too many {action} requests; slow down (limit {limit} per {per}).")
        conn.execute("INSERT INTO login_failures (k, ts) VALUES (?, ?)", (k, now))
        if secrets.randbelow(50) == 0:
            conn.execute("DELETE FROM login_failures WHERE ts < ?", (now - 86400,))


def _check_throttle(ukey: str, ikey: str) -> None:
    if throttle.blocked(ukey, settings.login_max_failures) or throttle.blocked(ikey, settings.login_max_failures * 4):
        log.warning("sign-in throttled: too many recent failures for %s / %s", ukey, ikey)
        raise HTTPException(429, "Too many failed attempts. Try again later.")


def _failed(ukey: str, ikey: str, detail: str = "Invalid username or password") -> HTTPException:
    throttle.fail(ukey)
    throttle.fail(ikey)
    # Security event: failed authentication (never log the password). Username as attempted, so credential
    # stuffing / brute force is visible in the logs and can be alerted on.
    log.warning("failed sign-in: %s from %s (%s)", ukey, ikey, detail)
    return HTTPException(401, detail)


# --------------------------------------------------------------------------- #
# Sessions and the staged sign-in
# --------------------------------------------------------------------------- #

def public_user(row) -> dict:
    return {"id": row["id"], "username": row["username"], "role": row["role"], "active": bool(row["active"]),
            "investigator": row["investigator"], "is_env_admin": bool(row["is_env_admin"]),
            "mfa_enabled": bool(row["mfa_enabled"]), "must_change_password": bool(row["must_change_pw"]),
            "ip_allowlist": _allowlist(row["ip_allowlist"])}


def next_stage(user_row, after: str | None = None) -> str:
    """The first stage still to do, after `after` (None = from the start)."""
    order = STAGES.index(after) + 1 if after else 0
    for st in STAGES[order:]:
        if st == "mfa" and user_row["mfa_enabled"]:
            return st
        if st == "password" and user_row["must_change_pw"]:
            return st
        if st == "mfa_setup" and settings.mfa_enforced and not user_row["mfa_enabled"]:
            return st
        if st == "full":
            return st
    return "full"


def login(request: Request, username: str, password: str) -> tuple[str, dict]:
    ip = client_ip(request)
    if not isinstance(username, str) or not isinstance(password, str):
        raise HTTPException(401, "Invalid username or password")
    ukey, ikey = "u:" + username.lower()[:64], "ip:" + ip
    _check_throttle(ukey, ikey)
    if len(password) > MAX_PASSWORD_LEN or len(username) > 64:
        raise _failed(ukey, ikey)
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        ok = sec.verify_password(password, row["pw_hash"] if row else sec.DUMMY_HASH)
        if not row or not ok or not row["active"]:
            raise _failed(ukey, ikey)
        if not sec.ip_allowed(ip, _allowlist(row["ip_allowlist"])):
            # Same answer as a wrong password: a correct password must not be confirmed from a refused address.
            log.warning("sign-in of %r refused: %s is not in the user's IP allowlist", row["username"], ip)
            raise _failed(ukey, ikey)
        if sec.needs_rehash(row["pw_hash"]):
            conn.execute("UPDATE users SET pw_hash=? WHERE id=?", (sec.hash_password(password), row["id"]))
        stage = next_stage(row)
        if stage != "mfa":
            throttle.reset(ukey)
        token, csrf, now = secrets.token_urlsafe(32), secrets.token_urlsafe(32), int(time.time())
        with write_tx(conn):
            conn.execute("DELETE FROM sessions WHERE last_seen < ? OR created_at < ?",
                         (now - settings.session_idle_minutes * 60, now - settings.session_max_hours * 3600))
            conn.execute("INSERT INTO sessions (token_hash, user_id, csrf, stage, created_at, last_seen, ip) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?)", (_th(token), row["id"], csrf, stage, now, now, ip))
    log.info("sign-in: %r from %s (role %s, next stage: %s)", row["username"], ip, row["role"], stage)
    return token, {"csrf": csrf, "stage": stage, "user": public_user(row),
                   "mfa_enforced": settings.mfa_enforced}


def _set_stage(conn, p: "Principal", stage: str) -> None:
    conn.execute("UPDATE sessions SET stage=?, mfa_pending=NULL WHERE token_hash=?", (stage, p.token_hash))
    if stage == "full":
        # A fresh CSRF value once fully signed in (the partial session's value is not reused).
        p.csrf = secrets.token_urlsafe(32)
        conn.execute("UPDATE sessions SET csrf=? WHERE token_hash=?", (p.csrf, p.token_hash))
    p.stage = stage


def verify_mfa_login(request: Request, p: "Principal", code: str) -> str:
    ukey, ikey = "u:" + p.username.lower(), "ip:" + client_ip(request)
    _check_throttle(ukey, ikey)
    with db() as conn, write_tx(conn):
        row = conn.execute("SELECT * FROM users WHERE id=?", (p.id,)).fetchone()
        step = sec.totp_verify(sec.decrypt(row["mfa_secret"]), code, row["mfa_last_step"])
        if step is None:
            raise _failed(ukey, ikey, "Invalid authentication code")
        conn.execute("UPDATE users SET mfa_last_step=? WHERE id=?", (step, p.id))
        throttle.reset(ukey)
        _set_stage(conn, p, next_stage(row, "mfa"))
    log.info("MFA verified at sign-in: %r from %s (next stage: %s)", p.username, client_ip(request), p.stage)
    return p.stage


def set_new_password(p: "Principal", new: str, current: str | None = None) -> None:
    """Forced change (stage `password`) or a voluntary change (needs the current password)."""
    check_password_policy(new)
    with db() as conn, write_tx(conn):
        row = conn.execute("SELECT * FROM users WHERE id=?", (p.id,)).fetchone()
        if current is not None and not sec.verify_password(current, row["pw_hash"]):
            raise HTTPException(400, "Current password is wrong")
        if sec.verify_password(new, row["pw_hash"]):
            raise HTTPException(400, "Choose a password different from the current one")
        conn.execute("UPDATE users SET pw_hash=?, pw_changed_at=?, must_change_pw=0 WHERE id=?",
                     (sec.hash_password(new), int(time.time()), p.id))
        conn.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (p.id, p.token_hash))
        if p.stage == "password":
            row = conn.execute("SELECT * FROM users WHERE id=?", (p.id,)).fetchone()
            _set_stage(conn, p, next_stage(row, "password"))


def _refuse_if_enrolled(conn, p: "Principal") -> None:
    """A signed-in session must not swap an existing authenticator (that would let a stolen session take over
    the second factor). Turn MFA off first (password + current code), or ask an administrator to reset it."""
    if conn.execute("SELECT mfa_enabled FROM users WHERE id=?", (p.id,)).fetchone()[0]:
        raise HTTPException(400, "MFA is already set up for this account")


def mfa_begin(p: "Principal", image_url: str) -> dict:
    """New TOTP secret for enrolment, kept (encrypted) on the session until confirmed with a code."""
    with db() as conn:
        _refuse_if_enrolled(conn, p)
    secret = sec.new_totp_secret()
    uri = sec.otpauth_uri(secret, p.username, image_url)
    with db() as conn:
        conn.execute("UPDATE sessions SET mfa_pending=? WHERE token_hash=?", (sec.encrypt(secret), p.token_hash))
    import base64
    return {"secret": secret, "otpauth_uri": uri,
            "qr_png": "data:image/png;base64," + base64.b64encode(sec.qr_png_with_logo(uri)).decode(),
            "issuer": settings.mfa_issuer, "account": p.username}


def mfa_confirm(request: Request, p: "Principal", code: str) -> str:
    ukey, ikey = "u:" + p.username.lower(), "ip:" + client_ip(request)
    _check_throttle(ukey, ikey)
    with db() as conn, write_tx(conn):
        _refuse_if_enrolled(conn, p)
        pending = conn.execute("SELECT mfa_pending FROM sessions WHERE token_hash=?", (p.token_hash,)).fetchone()
        if not pending or not pending["mfa_pending"]:
            raise HTTPException(400, "Start the MFA setup first")
        secret = sec.decrypt(pending["mfa_pending"])
        step = sec.totp_verify(secret, code)
        if step is None:
            raise _failed(ukey, ikey, "Invalid authentication code - check the phone's clock and try again")
        conn.execute("UPDATE users SET mfa_secret=?, mfa_enabled=1, mfa_last_step=? WHERE id=?",
                     (sec.encrypt(secret), step, p.id))
        conn.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (p.id, p.token_hash))
        row = conn.execute("SELECT * FROM users WHERE id=?", (p.id,)).fetchone()
        _set_stage(conn, p, next_stage(row, "mfa_setup") if p.stage == "mfa_setup" else p.stage)
    log.info("MFA enabled for %s", p.username)
    return p.stage


def mfa_disable_self(p: "Principal", password: str, code: str) -> None:
    if settings.mfa_enforced:
        raise HTTPException(400, "MFA is mandatory on this server")
    with db() as conn, write_tx(conn):
        row = conn.execute("SELECT * FROM users WHERE id=?", (p.id,)).fetchone()
        if not row["mfa_enabled"]:
            raise HTTPException(400, "MFA is not enabled")
        if not sec.verify_password(password, row["pw_hash"]) or \
                sec.totp_verify(sec.decrypt(row["mfa_secret"]), code, row["mfa_last_step"]) is None:
            raise HTTPException(400, "Wrong password or authentication code")
        conn.execute("UPDATE users SET mfa_secret=NULL, mfa_enabled=0, mfa_last_step=0 WHERE id=?", (p.id,))
    log.info("MFA disabled by %s", p.username)


def logout(p: "Principal") -> None:
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (p.token_hash,))


# --------------------------------------------------------------------------- #
# Principal and request authentication
# --------------------------------------------------------------------------- #

@dataclass
class Principal:
    id: int
    username: str
    role: str                  # admin | user  (API key: 'admin' for an admin key, else 'user')
    investigator: str
    is_env_admin: bool
    csrf: str
    token_hash: str
    stage: str = "full"
    via_key: bool = False      # authenticated with an application API key
    key_name: str = ""
    key_id: int | None = None
    key_profile: str = ""      # read | readwrite (case keys)
    key_kind: str = ""         # admin | case
    key_scope: str = ""        # all | single (case keys)
    key_case_pk: int | None = None   # the single case a scope=single key is limited to

    @property
    def rl_key(self) -> str:
        """Stable per-principal key for rate limiting (an API key, or a signed-in user)."""
        return f"k:{self.key_id}" if self.via_key else f"u:{self.id}"

    @property
    def is_admin(self) -> bool:
        """Full administrator: a browser session admin, or an admin API key (full admin-equivalent)."""
        return self.role == "admin"

    @property
    def key_can_write(self) -> bool:
        """A case API key's data-write capability (irrelevant for sessions)."""
        return self.key_profile == "readwrite"

    @property
    def actor(self) -> str:
        """Name recorded in the activity log and as "last change by"."""
        return f"api:{self.key_name}" if self.via_key else self.username


def bearer_token(request: Request) -> str | None:
    h = request.headers.get("authorization", "")
    if h[:7].lower() == "bearer ":
        return h[7:].strip()
    return None


def _key_principal(request: Request, token: str) -> Principal:
    unauthorized = HTTPException(401, "Invalid, disabled or expired API key", headers={"WWW-Authenticate": "Bearer"})
    if not token.startswith(KEY_PREFIX) or len(token) > 128:
        raise unauthorized
    now, ip = int(time.time()), client_ip(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM api_keys WHERE secret_hash = ?", (_th(token),)).fetchone()
        if not row or not row["enabled"] or (row["expires_at"] and row["expires_at"] < now):
            raise unauthorized
        if not sec.ip_allowed(ip, _allowlist(row["ip_allowlist"])):
            log.warning("API key %r refused from %s (not in its IP allowlist)", row["name"], ip)
            raise HTTPException(403, "This API key may not be used from this IP address")
        if not row["last_used_at"] or now - row["last_used_at"] > 60 or row["last_used_ip"] != ip:
            conn.execute("UPDATE api_keys SET last_used_at=?, last_used_ip=? WHERE id=?", (now, ip[:45], row["id"]))
    kind = row["kind"] or "case"
    role = "admin" if kind == "admin" else "user"     # an admin key is a full administrator
    return Principal(0, f"api:{row['name']}", role, "", False, "", "", via_key=True, key_name=row["name"],
                     key_id=row["id"], key_profile=row["profile"], key_kind=kind,
                     key_scope=row["scope"] or "all", key_case_pk=row["case_pk"])


def _session_principal(request: Request, stages: tuple[str, ...]) -> Principal:
    token = request.cookies.get(SESSION_COOKIE)
    if not token or len(token) > 128:
        raise HTTPException(401, "Not authenticated")
    th, now, ip = _th(token), int(time.time()), client_ip(request)
    with db() as conn:
        row = conn.execute(
            "SELECT s.csrf, s.stage, s.created_at AS s_created, s.last_seen, u.* FROM sessions s "
            "JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?", (th,)).fetchone()
        if not row:
            raise HTTPException(401, "Not authenticated")
        expired = (now - row["last_seen"] > settings.session_idle_minutes * 60
                   or now - row["s_created"] > settings.session_max_hours * 3600)
        if expired or not row["active"] or not sec.ip_allowed(ip, _allowlist(row["ip_allowlist"])):
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
            raise HTTPException(401, "Session expired")
        if now - row["last_seen"] > 60:
            conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now, th))
    stage = row["stage"]
    # MFA_ENFORCED switched on while this session was open: finish enrolment before anything else.
    if stage == "full" and settings.mfa_enforced and not row["mfa_enabled"]:
        stage = "mfa_setup"
    if stage not in stages:
        raise HTTPException(403 if stage == "full" else 401,
                            "Sign-in not complete" if stage != "full" else "Not available for this session",
                            headers={"X-Auth-Stage": stage})
    p = Principal(row["id"], row["username"], row["role"], row["investigator"], bool(row["is_env_admin"]),
                  row["csrf"], th, stage=stage)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.headers.get("x-csrf-token", "")
        if not sent or not hmac.compare_digest(sent, p.csrf):
            raise HTTPException(403, "CSRF token missing or invalid")
    return p


def current_principal(request: Request) -> Principal:
    bt = bearer_token(request)
    if bt is not None:
        # Key requests carry no ambient credentials (no cookies), so CSRF checks do not apply.
        return _key_principal(request, bt)
    return _session_principal(request, ("full",))


def require_user(request: Request) -> Principal:
    return current_principal(request)


def require_session(request: Request) -> Principal:
    """Browser session only (account and administration operations are never available to API keys)."""
    if bearer_token(request) is not None:
        raise HTTPException(403, "This operation requires an interactive login, not an API key")
    return _session_principal(request, ("full",))


def require_stage(*stages: str):
    def dep(request: Request) -> Principal:
        if bearer_token(request) is not None:
            raise HTTPException(403, "This operation requires an interactive login, not an API key")
        return _session_principal(request, stages)
    return dep


def require_session_admin(request: Request) -> Principal:
    """Administrator through the browser (no API key). For the few operations that must be interactive."""
    p = require_session(request)
    if not p.is_admin:
        raise HTTPException(403, "Administrator only")
    return p


def require_admin(request: Request) -> Principal:
    """Full administrator: a browser session admin, or an admin API key (full admin-equivalent)."""
    p = current_principal(request)
    if not p.is_admin:
        raise HTTPException(403, "Administrator only")
    return p


def require_case_creator(request: Request) -> Principal:
    """Create / import a case (the creator becomes the owner). Any signed-in user; an admin API key; or an
    all-cases readwrite case API key. A read key or a single-case key may not create cases."""
    p = current_principal(request)
    if p.is_admin:
        return p
    if p.via_key:
        if p.key_kind == "case" and p.key_scope == "all" and p.key_can_write:
            return p
        raise HTTPException(403, "This API key may not create cases")
    return p


def require_importer(request: Request) -> Principal:
    """Import a .fox as a new case: any signed-in user (becomes owner) or an admin API key. A case API key
    manages existing case data only, so it may not import (create) cases."""
    p = current_principal(request)
    if p.via_key and not p.is_admin:
        raise HTTPException(403, "A case API key cannot import a case; sign in or use an admin key")
    return p


# --------------------------------------------------------------------------- #
# Application API keys (admin only)
# --------------------------------------------------------------------------- #

def public_key(row) -> dict:
    now = time.time()
    return {"id": row["id"], "name": row["name"], "profile": row["profile"], "prefix": row["prefix"],
            "kind": row["kind"] or "case", "scope": row["scope"] or "all", "case_pk": row["case_pk"],
            "enabled": bool(row["enabled"]), "expires_at": row["expires_at"],
            "expired": bool(row["expires_at"] and row["expires_at"] < now),
            "ip_allowlist": _allowlist(row["ip_allowlist"]), "created_at": row["created_at"],
            "created_by": row["created_by"], "rotated_at": row["rotated_at"],
            "last_used_at": row["last_used_at"], "last_used_ip": row["last_used_ip"]}


def _new_secret() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def list_keys() -> list[dict]:
    with db() as conn:
        return [public_key(r) for r in conn.execute("SELECT * FROM api_keys ORDER BY name")]


def create_key(name: str, profile: str, expires_at: int | None, allowlist: list[str], by: str,
               kind: str = "case", scope: str = "all", case_pk: int | None = None) -> tuple[str, dict]:
    if not isinstance(name, str) or not KEY_NAME_RE.match(name):
        raise HTTPException(400, "API key name: 1-64 characters (letters, digits . _ : @ / -), no spaces")
    if profile not in PROFILES:
        raise HTTPException(400, "profile must be read or readwrite")
    if kind not in KEY_KINDS:
        raise HTTPException(400, "kind must be admin or case")
    if kind == "admin":
        scope, case_pk = "all", None          # an admin key is full-access; a case scope is meaningless
    else:
        if scope not in KEY_SCOPES:
            raise HTTPException(400, "scope must be all or single")
        if scope == "all":
            case_pk = None
        elif not isinstance(case_pk, int):
            raise HTTPException(400, "a single-case key needs a case")
    secret, now = _new_secret(), int(time.time())
    with db() as conn, write_tx(conn):
        if conn.execute("SELECT 1 FROM api_keys WHERE name=?", (name,)).fetchone():
            raise HTTPException(409, f"An API key named '{name}' already exists")
        if case_pk is not None and not conn.execute("SELECT 1 FROM cases WHERE id=?", (case_pk,)).fetchone():
            raise HTTPException(404, "Case not found")
        cur = conn.execute(
            "INSERT INTO api_keys (name, profile, kind, scope, case_pk, prefix, secret_hash, enabled, expires_at, "
            "ip_allowlist, created_at, created_by) VALUES (?,?,?,?,?,?,?,1,?,?,?,?)",
            (name, profile, kind, scope, case_pk, secret[:12], _th(secret), expires_at,
             json.dumps(allowlist), now, by))
        row = conn.execute("SELECT * FROM api_keys WHERE id=?", (cur.lastrowid,)).fetchone()
    return secret, public_key(row)


def update_key(key_id: int, changes: dict) -> dict:
    sets, args = [], []
    if "profile" in changes:
        if changes["profile"] not in PROFILES:
            raise HTTPException(400, "profile must be read or readwrite")
        sets.append("profile=?"); args.append(changes["profile"])
    if "enabled" in changes:
        sets.append("enabled=?"); args.append(int(bool(changes["enabled"])))
    if "expires_at" in changes:
        sets.append("expires_at=?"); args.append(changes["expires_at"])
    if "ip_allowlist" in changes:
        sets.append("ip_allowlist=?"); args.append(json.dumps(changes["ip_allowlist"]))
    with db() as conn, write_tx(conn):
        if not conn.execute("SELECT 1 FROM api_keys WHERE id=?", (key_id,)).fetchone():
            raise HTTPException(404, "API key not found")
        if sets:
            conn.execute(f"UPDATE api_keys SET {', '.join(sets)} WHERE id=?", (*args, key_id))
        return public_key(conn.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone())


def rotate_key(key_id: int) -> tuple[str, dict]:
    secret = _new_secret()
    with db() as conn, write_tx(conn):
        if not conn.execute("SELECT 1 FROM api_keys WHERE id=?", (key_id,)).fetchone():
            raise HTTPException(404, "API key not found")
        conn.execute("UPDATE api_keys SET prefix=?, secret_hash=?, rotated_at=? WHERE id=?",
                     (secret[:12], _th(secret), int(time.time()), key_id))
        return secret, public_key(conn.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone())


def delete_key(key_id: int) -> str:
    with db() as conn, write_tx(conn):
        row = conn.execute("SELECT name FROM api_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            raise HTTPException(404, "API key not found")
        conn.execute("DELETE FROM api_keys WHERE id=?", (key_id,))
    return row["name"]
