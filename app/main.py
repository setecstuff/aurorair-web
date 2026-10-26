"""Aurora IR web - collaborative editing of Aurora .fox case files."""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field as PField
from starlette.concurrency import run_in_threadpool

from . import access, auth, backups, exports
from . import security as SEC
from . import integrations as I
from . import server_settings as SS
from . import cases as C
from . import schema as S
from .config import settings
from .db import Busy, cases_db, init_db, migrate, read_tx, users_db, write_tx

logging.Formatter.converter = time.gmtime          # log timestamps in UTC
logging.basicConfig(level=logging.INFO, format="%(asctime)sZ %(levelname)s %(name)s: %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger("aurora")
STATIC_DIR = Path(__file__).parent / "static"

_stop = threading.Event()


@asynccontextmanager
async def lifespan(app: FastAPI):
    SEC.check_secret_key()
    fpr = backups.check_config()
    init_db()
    auth.bootstrap_admin()
    migrate()                      # in-place upgrades for pre-existing tables (per-case access control)
    backups.start_scheduler(_stop)
    log.info("Aurora web ready (database %s:%s/%s, MFA %s, backups %s%s)", settings.db_host, settings.db_port,
             settings.db_name, "enforced" if settings.mfa_enforced else "optional",
             "daily at %02d:%02d UTC" % settings.backup_time if settings.backup_enabled else "off",
             f", encrypted to {fpr}" if fpr else "")
    yield
    _stop.set()


API_VERSION = "1.0"
API_DESCRIPTION = """
REST API of **Aurora IR Web**, a multi-user web edition of
[Aurora Incident Response](https://github.com/cyb3rfox/Aurora-Incident-Response).

* Authenticate programs with an application API key: `Authorization: Bearer aurora_...`
  (administrators create keys under *Administration → API Keys*; profile `read` or `readwrite`).
* All times are UTC. All writes are validated and referentially checked.
* Full documentation: `docs/api.md` in the repository.
"""
TAGS = [
    {"name": "users", "description": "User administration (admin, browser session only)."},
    {"name": "cases", "description": "Cases: list, create, import/replace/delete .fox, details, export."},
    {"name": "records", "description": "Records of a case section (timeline, systems, ...): CRUD, bulk, query."},
    {"name": "analysis", "description": "Read-only views: search, incident summary, report data, activity log."},
    {"name": "actions", "description": "Row actions as in Aurora: send to timeline / investigated systems, "
                                       "send to MISP, check VirusTotal (server-side; API keys never leave the server)."},
]

app = FastAPI(title="Aurora IR Web API", version=API_VERSION, description=API_DESCRIPTION, openapi_tags=TAGS,
              license_info={"name": "Apache-2.0", "identifier": "Apache-2.0"},
              docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


# --------------------------------------------------------------------------- #
# Middleware: body size limit + security headers
# --------------------------------------------------------------------------- #

class _TooLarge(Exception):
    pass


class BodyLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        is_import = path.endswith(("/import", "/import.csv", "/replace", "/bulk"))
        if path == "/api/backups/restore":
            limit = settings.max_restore_mb * 1024 * 1024
        else:
            limit = settings.max_import_mb * 1024 * 1024 if is_import else settings.max_body_kb * 1024
        for k, v in scope.get("headers", []):
            if k == b"content-length":
                try:
                    if int(v) > limit:
                        return await _send_413(send)
                except ValueError:
                    return await _send_413(send)
        seen = 0
        started = False

        async def limited_receive():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > limit:
                    raise _TooLarge()
            return msg

        async def tracking_send(msg):
            nonlocal started
            if msg["type"] == "http.response.start":
                started = True
            await send(msg)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            if not started:
                await _send_413(send)


async def _send_413(send):
    body = b'{"detail":"Request body too large"}'
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    h = resp.headers
    h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    if request.url.path.startswith("/api/"):
        h["Cache-Control"] = "no-store"
    elif "cache-control" not in h:
        # UI files: browsers must revalidate (cheap 304 via ETag), so a redeploy is picked up immediately
        h["Cache-Control"] = "no-cache"
    return resp


app.add_middleware(BodyLimitMiddleware)


# --------------------------------------------------------------------------- #
# Error mapping
# --------------------------------------------------------------------------- #

@app.exception_handler(S.ValidationError)
async def _validation(request, exc: S.ValidationError):
    return JSONResponse({"detail": "Validation failed", "errors": exc.errors,
                         "missing_refs": getattr(exc, "missing_refs", [])}, status_code=422)


@app.exception_handler(C.ConflictError)
async def _conflict(request, exc: C.ConflictError):
    return JSONResponse({"detail": str(exc), **exc.payload}, status_code=409)


@app.exception_handler(C.NotFound)
async def _notfound(request, exc: C.NotFound):
    return JSONResponse({"detail": str(exc)}, status_code=404)


@app.exception_handler(I.IntegrationError)
async def _integration(request, exc: I.IntegrationError):
    return JSONResponse({"detail": str(exc)}, status_code=exc.status)


@app.exception_handler(Busy)
async def _busy(request, exc: Busy):
    return JSONResponse({"detail": str(exc)}, status_code=503)


@app.exception_handler(backups.BackupError)
async def _backup_error(request, exc: backups.BackupError):
    return JSONResponse({"detail": str(exc)}, status_code=400)


@app.exception_handler(Exception)
async def _unhandled(request, exc: Exception):
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


def _section(section: str) -> str:
    if section not in S.SECTIONS:
        raise HTTPException(404, f"Unknown section '{section}'. Valid: {', '.join(S.SECTION_ORDER)}")
    return section


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- #
# Session & identity
# --------------------------------------------------------------------------- #

class LoginIn(Strict):
    username: str = PField(max_length=64)
    password: str = PField(max_length=auth.MAX_PASSWORD_LEN)


class CodeIn(Strict):
    code: str = PField(max_length=10, description="6-digit code from the authenticator app")


class NewPasswordIn(Strict):
    new: str = PField(max_length=auth.MAX_PASSWORD_LEN)


def _session_out(p: auth.Principal) -> dict:
    with users_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (p.id,)).fetchone()
    return {"csrf": p.csrf, "stage": p.stage, "user": auth.public_user(row), "mfa_enforced": settings.mfa_enforced}


@app.post("/api/login", include_in_schema=False, summary="Browser sign-in, step 1: username and password")
def api_login(body: LoginIn, request: Request):
    """Sets the session cookie. `stage` says what is still needed: `mfa` (POST /api/login/mfa), `password`
    (POST /api/login/password), `mfa_setup` (GET + POST /api/mfa/setup) or `full` (signed in).
    Programs use API keys instead."""
    token, out = auth.login(request, body.username, body.password)
    resp = JSONResponse(out)
    resp.set_cookie(auth.SESSION_COOKIE, token, httponly=True, secure=settings.cookie_secure, samesite="strict",
                    path="/", max_age=settings.session_max_hours * 3600)
    return resp


@app.post("/api/login/mfa", include_in_schema=False, summary="Sign-in step: TOTP code")
def api_login_mfa(body: CodeIn, request: Request, p: auth.Principal = Depends(auth.require_stage("mfa"))):
    auth.verify_mfa_login(request, p, body.code)
    return _session_out(p)


@app.post("/api/login/password", include_in_schema=False, summary="Sign-in step: new password required by an admin")
def api_login_password(body: NewPasswordIn, p: auth.Principal = Depends(auth.require_stage("password"))):
    auth.set_new_password(p, body.new)
    return _session_out(p)


@app.get("/api/mfa/setup", include_in_schema=False, summary="Start MFA enrolment: new TOTP secret and QR code")
def api_mfa_begin(request: Request, p: auth.Principal = Depends(auth.require_stage("mfa_setup", "full"))):
    """Returns the secret, the otpauth:// URI and a QR code (PNG data URL with the application logo). The
    secret is only stored once confirmed with POST /api/mfa/setup."""
    base = str(request.base_url).rstrip("/")
    image = f"{base}/logo.png" if base.startswith("https://") else ""
    return auth.mfa_begin(p, image)


@app.post("/api/mfa/setup", include_in_schema=False, summary="Confirm MFA enrolment with a code from the app")
def api_mfa_confirm(body: CodeIn, request: Request,
                    p: auth.Principal = Depends(auth.require_stage("mfa_setup", "full"))):
    auth.mfa_confirm(request, p, body.code)
    return _session_out(p)


class MfaDisableIn(Strict):
    password: str = PField(max_length=auth.MAX_PASSWORD_LEN)
    code: str = PField(max_length=10)


@app.post("/api/me/mfa/disable", include_in_schema=False, summary="Turn off own MFA (only when MFA is not enforced)")
def api_mfa_disable(body: MfaDisableIn, p: auth.Principal = Depends(auth.require_session)):
    auth.mfa_disable_self(p, body.password, body.code)
    return {"ok": True}


@app.post("/api/logout", include_in_schema=False, summary="End the browser session")
def api_logout(p: auth.Principal = Depends(auth.require_stage(*auth.STAGES))):
    auth.logout(p)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.SESSION_COOKIE, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict")
    return resp


@app.get("/api/session", include_in_schema=False, summary="State of the browser session (any sign-in stage)")
def api_session(p: auth.Principal = Depends(auth.require_stage(*auth.STAGES))):
    return _session_out(p)


@app.get("/api/me", include_in_schema=False, summary="Who am I (a signed-in user or an API key)")
def api_me(p: auth.Principal = Depends(auth.require_user)):
    if p.via_key:
        # Friendly capability name for clients: admin key -> admin, else the case-data capability.
        role = "admin" if p.key_kind == "admin" else ("editor" if p.key_can_write else "viewer")
        return {"api_key": {"id": p.key_id, "name": p.key_name, "profile": p.key_profile,
                            "kind": p.key_kind, "scope": p.key_scope, "case_pk": p.key_case_pk}, "role": role}
    return _session_out(p)


class PasswordIn(Strict):
    current: str = PField(max_length=auth.MAX_PASSWORD_LEN)
    new: str = PField(max_length=auth.MAX_PASSWORD_LEN)


@app.post("/api/me/password", include_in_schema=False, summary="Change own password (browser session only)")
def api_change_password(body: PasswordIn, p: auth.Principal = Depends(auth.require_session)):
    """Signs out the user's other sessions."""
    auth.set_new_password(p, body.new, current=body.current)
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Application API keys: managed by administrators in the GUI only. These endpoints serve the GUI (browser
# session + CSRF), are refused to API keys and are not part of the published API.
# --------------------------------------------------------------------------- #

Profile = Literal["read", "readwrite"]


def _expiry(v: str | None) -> int | None:
    """Expiry (UTC) as epoch seconds; None/'' = never. Accepts a plain date 'YYYY-MM-DD' (-> end of that day,
    for backwards compatibility) or a precise instant 'YYYY-MM-DDTHH:MM[:SS]' (datetime-local)."""
    if not v:
        return None
    v = v.strip().replace(" ", "T")
    for fmt, pad in (("%Y-%m-%dT%H:%M:%S", 0), ("%Y-%m-%dT%H:%M", 0), ("%Y-%m-%d", 86399)):
        try:
            d = datetime.strptime(v, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        return int(d.timestamp()) + pad
    raise HTTPException(400, "expires must be YYYY-MM-DD or YYYY-MM-DDTHH:MM[:SS] (UTC), or null")


KeyKind = Literal["admin", "case"]
KeyScope = Literal["all", "single"]


class KeyIn(Strict):
    name: str = PField(min_length=1, max_length=64, description="Identity of the key in the activity log, e.g. 'plaso-importer'")
    profile: Profile = PField(description="read = view and export; readwrite = also change case data")
    kind: KeyKind = PField("case", description="admin = full admin API; case = case data only")
    scope: KeyScope = PField("all", description="case keys: 'all' every case, or 'single' one case")
    case_pk: int | None = PField(None, description="the case a scope='single' key is limited to")
    expires: str | None = PField(None, description="Last valid day, YYYY-MM-DD (UTC); null = never expires")
    ip_allowlist: list[str] = PField(default_factory=list, max_length=100,
                                     description="IPv4/IPv6 addresses or CIDR ranges; empty = any address")


class KeyPatch(Strict):
    profile: Profile | None = None
    enabled: bool | None = None
    expires: str | None = PField(None, description="YYYY-MM-DD, or \"\" to remove the expiry")
    ip_allowlist: list[str] | None = PField(None, max_length=100)


@app.get("/api/keys", include_in_schema=False, summary="List API keys")
def api_keys_list(p: auth.Principal = Depends(auth.require_admin)):
    return auth.list_keys()


@app.post("/api/keys", include_in_schema=False, summary="Create an API key (the secret is shown only once)")
def api_key_create(body: KeyIn, p: auth.Principal = Depends(auth.require_admin)):
    secret, info = auth.create_key(body.name, body.profile, _expiry(body.expires),
                                   auth.validate_allowlist(body.ip_allowlist), p.username,
                                   kind=body.kind, scope=body.scope, case_pk=body.case_pk)
    log.info("API key %r (%s %s/%s) created by %s", body.name, body.kind, body.profile, body.scope, p.actor)
    return {"secret": secret, "key": info}


@app.patch("/api/keys/{key_id}", include_in_schema=False, summary="Change profile, enabled, expiry or IP allowlist")
def api_key_update(key_id: int, body: KeyPatch, p: auth.Principal = Depends(auth.require_admin)):
    changes = body.model_dump(exclude_unset=True)
    if "expires" in changes:
        changes["expires_at"] = _expiry(changes.pop("expires"))
    if "ip_allowlist" in changes:
        changes["ip_allowlist"] = auth.validate_allowlist(changes["ip_allowlist"] or [])
    info = auth.update_key(key_id, changes)
    log.info("API key %r changed by %s: %s", info["name"], p.username, sorted(changes))
    return info


@app.post("/api/keys/{key_id}/rotate", include_in_schema=False, summary="Replace the key's secret (the old one stops working)")
def api_key_rotate(key_id: int, p: auth.Principal = Depends(auth.require_admin)):
    secret, info = auth.rotate_key(key_id)
    log.info("API key %r rotated by %s", info["name"], p.username)
    return {"secret": secret, "key": info}


@app.delete("/api/keys/{key_id}", include_in_schema=False, summary="Delete an API key")
def api_key_delete(key_id: int, p: auth.Principal = Depends(auth.require_admin)):
    name = auth.delete_key(key_id)
    log.info("API key %r deleted by %s", name, p.username)
    return {"ok": True}


# --------------------------------------------------------------------------- #
# User administration (administrators, browser session only)
# --------------------------------------------------------------------------- #

Role = Literal["admin", "user"]


class UserIn(Strict):
    username: str = PField(max_length=32)
    password: str = PField(max_length=auth.MAX_PASSWORD_LEN)
    role: Role = "user"
    investigator: str = PField(default="", max_length=20)
    must_change_password: bool = PField(True, description="the user must choose a new password at first sign-in")
    ip_allowlist: list[str] = PField(default_factory=list, max_length=100)


class UserPatch(Strict):
    role: Role | None = None
    active: bool | None = None
    password: str | None = PField(default=None, max_length=auth.MAX_PASSWORD_LEN)
    investigator: str | None = PField(default=None, max_length=20)
    must_change_password: bool | None = PField(None, description="force a new password at next sign-in")
    ip_allowlist: list[str] | None = PField(None, max_length=100,
                                            description="IPv4/IPv6 addresses or CIDR ranges; empty = any address")


@app.get("/api/users", tags=["users"], summary="List users (by username)")
def api_users(q: str = Query("", max_length=64, description="filter on username or investigator (case-insensitive)"),
              p: auth.Principal = Depends(auth.require_admin)):
    with users_db() as conn:
        users = [auth.public_user(r) for r in conn.execute("SELECT * FROM users ORDER BY username, id")]
    ql = q.strip().casefold()
    return [u for u in users if not ql or ql in u["username"].casefold() or ql in (u.get("investigator") or "").casefold()]


@app.post("/api/users", tags=["users"], summary="Create a user")
def api_user_create(body: UserIn, p: auth.Principal = Depends(auth.require_admin)):
    auth.validate_username(body.username)
    auth.check_password_policy(body.password)
    inv = auth.validate_investigator(body.investigator)
    allow = auth.validate_allowlist(body.ip_allowlist)
    now = int(time.time())
    with users_db() as conn, write_tx(conn):
        if conn.execute("SELECT 1 FROM users WHERE username=?", (body.username,)).fetchone():
            raise HTTPException(409, "Username already exists")
        cur = conn.execute(
            "INSERT INTO users (username, pw_hash, role, active, investigator, must_change_pw, ip_allowlist, "
            "created_at, pw_changed_at) VALUES (?,?,?,1,?,?,?,?,?)",
            (body.username, SEC.hash_password(body.password), body.role, inv, int(body.must_change_password),
             json.dumps(allow), now, now))
        row = conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    log.info("user %r (%s) created by %s", body.username, body.role, p.username)
    return auth.public_user(row)


@app.patch("/api/users/{user_id}", tags=["users"],
           summary="Change role, active, investigator, password, forced password change or IP allowlist")
def api_user_update(user_id: int, body: UserPatch, request: Request,
                    p: auth.Principal = Depends(auth.require_admin)):
    """A password reset or deactivation signs the user out everywhere."""
    with users_db() as conn, write_tx(conn):
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        if row["is_env_admin"] and (body.role not in (None, "admin") or body.active is False):
            raise HTTPException(400, "The bootstrap admin cannot be demoted or deactivated")
        if user_id == p.id and (body.role not in (None, "admin") or body.active is False):
            raise HTTPException(400, "You cannot demote or deactivate yourself")
        sets, args = [], []
        if body.role is not None:
            sets.append("role=?"); args.append(body.role)
        if body.active is not None:
            sets.append("active=?"); args.append(int(body.active))
        if body.investigator is not None:
            sets.append("investigator=?"); args.append(auth.validate_investigator(body.investigator))
        if body.must_change_password is not None:
            sets.append("must_change_pw=?"); args.append(int(body.must_change_password))
        if body.ip_allowlist is not None:
            allow = auth.validate_allowlist(body.ip_allowlist)
            if user_id == p.id and not SEC.ip_allowed(auth.client_ip(request), allow):
                raise HTTPException(400, f"This allowlist does not include your current address "
                                         f"({auth.client_ip(request)}); you would lock yourself out")
            sets.append("ip_allowlist=?"); args.append(json.dumps(allow))
        if body.password:
            auth.check_password_policy(body.password)
            sets += ["pw_hash=?", "pw_changed_at=?"]; args += [SEC.hash_password(body.password), int(time.time())]
        if sets:
            conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", (*args, user_id))
        if body.password or body.active is False:
            conn.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user_id, p.token_hash))
            log.info("user %s: %s by %s; sessions revoked", row["username"],
                     "password reset" if body.password else "deactivated", p.username)
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return auth.public_user(row)


@app.post("/api/users/{user_id}/reset-mfa", tags=["users"],
          summary="Remove a user's MFA (they enrol again; required at next sign-in when MFA is enforced)")
def api_user_reset_mfa(user_id: int, p: auth.Principal = Depends(auth.require_admin)):
    with users_db() as conn, write_tx(conn):
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        conn.execute("UPDATE users SET mfa_secret=NULL, mfa_enabled=0, mfa_last_step=0 WHERE id=?", (user_id,))
        conn.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user_id, p.token_hash))
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    log.warning("MFA of %s reset by %s", row["username"], p.username)
    return auth.public_user(row)


@app.delete("/api/users/{user_id}", tags=["users"], summary="Delete a user (and their sessions)")
def api_user_delete(user_id: int, p: auth.Principal = Depends(auth.require_admin)):
    if user_id == p.id:
        raise HTTPException(400, "You cannot delete yourself")
    with users_db() as conn, write_tx(conn):
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        if row["is_env_admin"]:
            raise HTTPException(400, "The bootstrap admin cannot be deleted")
        # Their memberships cascade (FK); cases they own become owner-less (admin-only) until reassigned.
        orphaned = conn.execute("UPDATE cases SET owner_id=NULL WHERE owner_id=?", (user_id,))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    if getattr(orphaned, "rowcount", 0):
        log.warning("user %s deleted by %s; %d owned case(s) are now owner-less", row["username"], p.actor,
                    orphaned.rowcount)
    log.info("user %s deleted by %s", row["username"], p.actor)
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Meta
# --------------------------------------------------------------------------- #

@app.get("/api/version", include_in_schema=False, summary="API and .fox storage-format versions")
def api_version(p: auth.Principal = Depends(auth.require_user)):
    return {"app": "aurora-ir-web", "api_version": API_VERSION, "storage_format_version": S.STORAGE_FORMAT_VERSION,
            "timezone": "UTC"}


@app.get("/api/schema", include_in_schema=False, summary="Sections, fields, types and validation limits")
def api_schema(p: auth.Principal = Depends(auth.require_user)):
    """Field `kind` values: text, longtext, bool, datetime (UTC `YYYY-MM-DD HH:MM:SS`), date, ip, port, int,
    hash, email, url, enum (value from a lookup list, see /options), ref (must name an existing record of
    `ref` section), auto_ms (server-set epoch ms), readonly."""
    return {"sections": [S.SECTIONS[k].to_public() for k in
                         ["timeline", "investigated_systems", "malware", "compromised_accounts",
                          "network_indicators", "exfiltration", "osint", "systems",
                          "investigators", "evidence", "actions", "casenotes"]],
            "case_fields": [f.to_public() for f in S.CASE_FIELDS.values()],
            "report_fields": [f.to_public() for f in S.REPORT_FIELDS.values()],
            "secret_case_fields": sorted(S.SECRET_CASE_FIELDS)}


@app.get("/api/openapi.json", include_in_schema=False, summary="OpenAPI 3 description of this API")
def api_openapi(p: auth.Principal = Depends(auth.require_user)):
    return app.openapi()


# --------------------------------------------------------------------------- #
# Cases
# --------------------------------------------------------------------------- #

@app.get("/api/cases", tags=["cases"], summary="List cases (newest Case ID first)")
def api_cases(q: str = Query("", max_length=200, description="filter on Case ID or client (case-insensitive)"),
              p: auth.Principal = Depends(auth.require_user)):
    """Ordered by Case ID descending, comparing numbers naturally (IR-609 before IR-608). A user sees only the
    cases they own or were invited to; an administrator (or an all-scope key) sees every case."""
    with cases_db() as conn:
        visible = access.visible_case_ids(conn, p)
        return C.list_cases(conn, q, visible=visible, with_owner=p.is_admin)


class NewCaseIn(Strict):
    case_id: str = PField(min_length=1, max_length=100)
    client: str = PField(default="", max_length=200)


def _owner_for(conn, p: auth.Principal) -> int | None:
    """Who owns a case this principal creates/imports: the signed-in user themselves, or - for an API key,
    which is not a user - the bootstrap admin (so the case is owned by a real account, not the key)."""
    if not p.via_key:
        return p.id
    row = conn.execute("SELECT id FROM users WHERE is_env_admin = 1 ORDER BY id LIMIT 1").fetchone()
    return row[0] if row else None


@app.post("/api/cases", tags=["cases"], summary="Create an empty case (you become its owner)")
def api_case_new(body: NewCaseIn, p: auth.Principal = Depends(auth.require_case_creator)):
    try:
        cid = S.validate_value(S.CASE_FIELDS["case_id"], body.case_id).strip()
        client = S.validate_value(S.CASE_FIELDS["client"], body.client)
    except S.FieldError as e:
        raise HTTPException(400, str(e))
    if not cid:
        raise HTTPException(400, "Case ID required")
    with cases_db() as conn, write_tx(conn):
        pk = C.new_empty_case(conn, cid, client, p.actor, owner_id=_owner_for(conn, p))
    return {"id": pk}


async def _read_fox(request: Request, declare_missing: bool):
    raw = await request.body()
    if not raw:
        raise HTTPException(400, "Empty upload")
    meta, sections, warnings = C.parse_fox(raw, declare_missing=declare_missing)
    note = I.adopt_server_misp(meta)
    if note:
        warnings.append(note)
    return meta, sections, warnings


@app.post("/api/cases/import", tags=["cases"], summary="Import a .fox file as a new case (you become its owner)")
async def api_case_import(request: Request, declare_missing: bool = False,
                          p: auth.Principal = Depends(auth.require_importer)):
    """Request body: the raw .fox JSON. `declare_missing=true` auto-creates referenced but undeclared
    systems/investigators/malware and lookup values instead of rejecting the file. Importing a .fox is the
    equivalent of creating and populating a case, so the importer becomes its owner."""
    meta, sections, warnings = await _read_fox(request, declare_missing)

    def work():
        with cases_db() as conn, write_tx(conn):
            return C.create_case(conn, meta, sections, p.actor, owner_id=_owner_for(conn, p))
    pk = await run_in_threadpool(work)
    return {"id": pk, "warnings": warnings}


@app.post("/api/cases/{case_pk}/replace", tags=["cases"],
          summary="Replace all data of a case from a .fox (owner/admin; a database snapshot is written first)")
async def api_case_replace(case_pk: int, request: Request, declare_missing: bool = False,
                           p: auth.Principal = Depends(access.case_manager)):
    meta, sections, warnings = await _read_fox(request, declare_missing)

    def work():
        with cases_db() as conn:
            C.get_case_row(conn, case_pk)
        backups.make_backup("pre-replace")
        with cases_db() as conn, write_tx(conn):
            C.replace_case(conn, case_pk, meta, sections, p.actor)
    await run_in_threadpool(work)
    return {"id": case_pk, "warnings": warnings}


class DeleteCaseIn(Strict):
    confirm: str = PField(max_length=100, description="Must equal the case's Case ID")


@app.post("/api/cases/{case_pk}/delete", tags=["cases"],
          summary="Delete a case (owner/admin; a database snapshot is written first)")
def api_case_delete(case_pk: int, body: DeleteCaseIn, p: auth.Principal = Depends(access.case_manager)):
    with cases_db() as conn:
        meta = C.get_meta(conn, case_pk)
    if body.confirm != meta.get("case_id"):
        raise HTTPException(400, "Type the exact Case ID to confirm deletion")
    backups.make_backup("pre-delete")
    with cases_db() as conn, write_tx(conn):
        C.delete_case(conn, case_pk)
    log.warning("case %s (%s) deleted by %s", case_pk, meta.get("case_id"), p.actor)
    return {"ok": True}


@app.get("/api/cases/{case_pk}", tags=["cases"], summary="Case details, revision and per-section counts")
def api_case(case_pk: int, p: auth.Principal = Depends(access.case_viewer)):
    with cases_db() as conn, read_tx(conn):
        row = C.get_case_row(conn, case_pk)
        meta = json.loads(row["meta"])
        counts = C.section_counts(conn, case_pk)
        owner = conn.execute("SELECT username FROM users WHERE id=?", (row["owner_id"],)).fetchone() \
            if row["owner_id"] else None
        lvl, _ = access.level(conn, p, case_pk)
    return {"id": case_pk, "uuid": row["uuid"], "owner_id": row["owner_id"],
            "owner": owner["username"] if owner else "", "access": lvl,
            "can_manage": lvl in ("admin", "owner"), "can_edit": lvl in ("admin", "owner", "editor"),
            "revision": row["revision"], "updated_by": row["updated_by"],
            "updated_at": row["updated_at"], "meta": C.public_meta(meta),
            "counts": counts, "integrations": I.status(meta)}


class ChangesIn(Strict):
    changes: dict[str, Any] = PField(description="field -> new value")
    expected: dict[str, Any] | None = PField(None, description="field -> value you started from (field-level merge)")
    version: int | None = PField(None, description="record version you read (whole-record lock); alternative to expected")


class MetaChangesIn(Strict):
    changes: dict[str, Any]
    expected: dict[str, Any] | None = PField(None, description="omit to overwrite without conflict detection")


@app.patch("/api/cases/{case_pk}", tags=["cases"], summary="Update case details (case_id, client, summary, ...)")
def api_case_update(case_pk: int, body: MetaChangesIn, p: auth.Principal = Depends(access.case_editor)):
    with cases_db() as conn, write_tx(conn):
        meta = C.update_meta(conn, case_pk, body.changes, body.expected, p.actor)
        rev = conn.execute("SELECT revision FROM cases WHERE id=?", (case_pk,)).fetchone()[0]
    return {"meta": C.public_meta(meta), "revision": rev}


# --------------------------------------------------------------------------- #
# Case membership, invites and ownership (owner or administrator)
# --------------------------------------------------------------------------- #

Permission = Literal["editor", "viewer"]


class InviteIn(Strict):
    permission: Permission = PField(description="what redeemers get: editor (view + change) or viewer (read-only)")
    max_redeems: int = PField(1, ge=0, le=access.MAX_REDEEMS, description="how many users may use it; 0 = unlimited")
    expires: str | None = PField(None, description="last valid day, YYYY-MM-DD (UTC); null = never")


class MemberPatchIn(Strict):
    permission: Permission


class OwnerIn(Strict):
    user_id: int = PField(description="the user to make owner (owner: a current member; admin: any active user)")


class JoinIn(Strict):
    uuid: str = PField(max_length=36, description="the case's id (uuid) shared by the owner")
    code: str = PField(max_length=128, description="the invite code shared by the owner")


def _owner_id(conn, case_pk: int) -> int | None:
    return C.get_case_row(conn, case_pk)["owner_id"]


@app.get("/api/cases/{case_pk}/members", tags=["cases"], summary="List the users with access to a case (owner/admin)")
def api_members(case_pk: int, p: auth.Principal = Depends(access.case_manager)):
    with cases_db() as conn:
        return {"members": access.member_rows(conn, case_pk, _owner_id(conn, case_pk))}


class MemberAddIn(Strict):
    user_id: int
    permission: Permission = "editor"


@app.post("/api/cases/{case_pk}/members", tags=["cases"],
          summary="Add a user to a case directly (administrator only; owners use invite codes)")
def api_member_add(case_pk: int, body: MemberAddIn, p: auth.Principal = Depends(auth.require_admin)):
    with cases_db() as conn, write_tx(conn):
        row = C.get_case_row(conn, case_pk)       # 404 if the case is gone
        access.add_member(conn, case_pk, row["owner_id"], body.user_id, body.permission, p.actor)
        C._audit(conn, case_pk, p.actor, "member_add", after={"user_id": body.user_id, "permission": body.permission})
    log.info("case %s: user %s added as %s by %s", case_pk, body.user_id, body.permission, p.actor)
    return {"ok": True}


@app.patch("/api/cases/{case_pk}/members/{user_id}", tags=["cases"],
           summary="Change a member's permission (owner/admin)")
def api_member_update(case_pk: int, user_id: int, body: MemberPatchIn,
                      p: auth.Principal = Depends(access.case_manager)):
    with cases_db() as conn, write_tx(conn):
        access.set_permission(conn, case_pk, _owner_id(conn, case_pk), user_id, body.permission, p.actor)
        C._audit(conn, case_pk, p.actor, "member_permission", after={"user_id": user_id, "permission": body.permission})
    log.info("case %s: permission of user %s set to %s by %s", case_pk, user_id, body.permission, p.actor)
    return {"ok": True}


@app.delete("/api/cases/{case_pk}/members/{user_id}", tags=["cases"],
            summary="Remove a member from a case (owner/admin)")
def api_member_remove(case_pk: int, user_id: int, p: auth.Principal = Depends(access.case_manager)):
    with cases_db() as conn, write_tx(conn):
        access.remove_member(conn, case_pk, _owner_id(conn, case_pk), user_id)
        C._audit(conn, case_pk, p.actor, "member_remove", after={"user_id": user_id})
    log.info("case %s: user %s removed by %s", case_pk, user_id, p.actor)
    return {"ok": True}


@app.post("/api/cases/{case_pk}/leave", tags=["cases"], summary="Leave a case you are a member of")
def api_case_leave(case_pk: int, p: auth.Principal = Depends(access.case_viewer)):
    if p.via_key:
        raise HTTPException(403, "API keys cannot leave cases")
    with cases_db() as conn, write_tx(conn):
        if _owner_id(conn, case_pk) == p.id:
            raise HTTPException(400, "The owner cannot leave; transfer ownership first")
        if not conn.execute("SELECT 1 FROM case_members WHERE case_pk=? AND user_id=?", (case_pk, p.id)).fetchone():
            raise HTTPException(400, "You are not a member of this case")
        conn.execute("DELETE FROM case_members WHERE case_pk=? AND user_id=?", (case_pk, p.id))
        C._audit(conn, case_pk, p.actor, "member_leave", after={"user_id": p.id})
    return {"ok": True}


@app.patch("/api/cases/{case_pk}/owner", tags=["cases"], summary="Transfer case ownership (owner/admin)")
def api_case_owner(case_pk: int, body: OwnerIn, p: auth.Principal = Depends(access.case_manager)):
    with cases_db() as conn, write_tx(conn):
        access.transfer_owner(conn, case_pk, _owner_id(conn, case_pk), body.user_id, p.actor, allow_any=p.is_admin)
        C._audit(conn, case_pk, p.actor, "owner_transfer", after={"owner_id": body.user_id})
        C._bump(conn, case_pk, p.actor)
    log.info("case %s: ownership transferred to user %s by %s", case_pk, body.user_id, p.actor)
    return {"ok": True}


@app.get("/api/cases/{case_pk}/invites", tags=["cases"], summary="List a case's invite codes (owner/admin)")
def api_invites(case_pk: int, p: auth.Principal = Depends(access.case_manager)):
    with cases_db() as conn:
        return {"invites": access.list_invites(conn, case_pk)}


@app.post("/api/cases/{case_pk}/invites", tags=["cases"],
          summary="Create an invite code for a case (owner/admin; the code is shown only once)")
def api_invite_create(case_pk: int, body: InviteIn, p: auth.Principal = Depends(access.case_manager)):
    with cases_db() as conn, write_tx(conn):
        code, info = access.create_invite(conn, case_pk, body.permission, body.max_redeems,
                                           _expiry(body.expires), p.actor)
        uuid = C.get_case_row(conn, case_pk)["uuid"]
        C._audit(conn, case_pk, p.actor, "invite_create",
                 after={"invite_id": info["id"], "permission": body.permission, "max_redeems": body.max_redeems})
    log.info("case %s: %s invite created by %s", case_pk, body.permission, p.actor)
    return {"code": code, "uuid": uuid, "invite": info}


@app.delete("/api/cases/{case_pk}/invites/{invite_id}", tags=["cases"],
            summary="Revoke an invite code (owner/admin)")
def api_invite_revoke(case_pk: int, invite_id: int, p: auth.Principal = Depends(access.case_manager)):
    with cases_db() as conn, write_tx(conn):
        access.revoke_invite(conn, case_pk, invite_id)
        C._audit(conn, case_pk, p.actor, "invite_revoke", after={"invite_id": invite_id})
    return {"ok": True}


@app.post("/api/cases/join", tags=["cases"], summary="Join a case with its id (uuid) and an invite code")
def api_case_join(body: JoinIn, p: auth.Principal = Depends(auth.require_session)):
    """A signed-in user adds themselves to a case using the case uuid and an invite code shared offline by the
    owner. The permission (editor/viewer) is the one the owner set on the invite."""
    auth.rate_limit("join", p.rl_key, 20, 60)
    with cases_db() as conn, write_tx(conn):
        case_pk, permission = access.redeem_invite(conn, p.id, body.uuid.strip(), body.code.strip())
        C._audit(conn, case_pk, p.actor, "member_join", after={"user_id": p.id, "permission": permission})
    log.info("user %s joined case %s as %s", p.actor, case_pk, permission)
    return {"id": case_pk, "permission": permission}


@app.get("/api/cases/{case_pk}/revision", tags=["cases"], summary="Change counter (poll this to detect changes)")
def api_revision(case_pk: int, p: auth.Principal = Depends(access.case_viewer)):
    with cases_db() as conn:
        row = C.get_case_row(conn, case_pk)
    return {"revision": row["revision"], "updated_by": row["updated_by"], "updated_at": row["updated_at"]}


@app.get("/api/cases/{case_pk}/options", tags=["cases"], summary="Allowed values: lookup lists and reference names")
def api_options(case_pk: int, p: auth.Principal = Depends(access.case_viewer)):
    with cases_db() as conn:
        return C.options(conn, case_pk)


@app.get("/api/cases/{case_pk}/export", tags=["cases"], summary="Download the case as an Aurora .fox file")
def api_export(case_pk: int, locked: bool = False, p: auth.Principal = Depends(access.case_viewer)):
    auth.rate_limit("export", p.rl_key, settings.export_rate_per_min, 60)
    with cases_db() as conn:
        data, doc, rev = C.export_fox(conn, case_pk, locked=locked)
        with write_tx(conn):
            C._audit(conn, case_pk, p.actor, "export", after={"revision": rev, "bytes": len(data)})
    fname = f"{backups.safe_name(doc.get('case_id', 'case'))}.fox"
    return Response(data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"',
                             "X-Case-Revision": str(rev)})


def _export(case_pk: int, p: auth.Principal, fmt: str):
    auth.rate_limit("export", p.rl_key, settings.export_rate_per_min, 60)
    with cases_db() as conn:
        data = exports.collect(conn, case_pk, p.actor)
    if fmt == "xlsx":
        from .xlsx_export import build_workbook
        blob, mime = build_workbook(data), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    elif fmt == "pdf":
        blob, mime = exports.build_pdf(data), "application/pdf"
    else:
        blob, mime = exports.build_latex(data), "application/x-tex"
    with cases_db() as conn, write_tx(conn):
        C._audit(conn, case_pk, p.actor, f"export_{fmt}", after={"revision": data["revision"], "bytes": len(blob)})
    fname = f"{backups.safe_name(data['doc'].get('case_id', 'case'))}.{fmt}"
    return Response(blob, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{fname}"',
                                                    "X-Case-Revision": str(data["revision"])})


@app.get("/api/cases/{case_pk}/export.xlsx", tags=["cases"], summary="Download the case as an Excel workbook (SOD)")
def api_export_xlsx(case_pk: int, p: auth.Principal = Depends(access.case_viewer)):
    """The "spreadsheet of doom": a Cover sheet (application, logo, case presentation, who exported it and when,
    case metadata), a Report sheet (executive summary, context, conclusions, lessons learned), then one sheet per section in the default order. Built from the
    same verified snapshot as the .fox. Times are UTC; text is never stored as formulas (formula-injection
    safe); MISP/VirusTotal API keys are not included."""
    return _export(case_pk, p, "xlsx")


@app.get("/api/cases/{case_pk}/export.pdf", tags=["cases"], summary="Download the case as a PDF report")
def api_export_pdf(case_pk: int, p: auth.Principal = Depends(access.case_viewer)):
    """Cover, executive summary, the Visual Timeline / Lateral Movement / Activity Plot charts and every section
    as a table (A4 landscape)."""
    return _export(case_pk, p, "pdf")


@app.get("/api/cases/{case_pk}/export.tex", tags=["cases"], summary="Download the case as a LaTeX report (.tex)")
def api_export_tex(case_pk: int, p: auth.Principal = Depends(access.case_viewer)):
    """The same content as the PDF as one self-contained .tex file (charts drawn with TikZ / pgfplots). Compile
    with `xelatex`. All case text is escaped."""
    return _export(case_pk, p, "tex")


# --------------------------------------------------------------------------- #
# Report page: executive summary, context, conclusions, lessons learned (never part of the .fox)
# --------------------------------------------------------------------------- #

class ReportChangesIn(Strict):
    changes: dict[str, Any] = PField(description="executive_summary, context, conclusions, lessons_learned -> text")
    expected: dict[str, Any] | None = PField(None, description="values you started from (field-level merge); omit to overwrite")


@app.get("/api/cases/{case_pk}/report", tags=["cases"], summary="Report page (executive summary, context, conclusions, lessons learned)")
def api_report_get(case_pk: int, p: auth.Principal = Depends(access.case_viewer)):
    """`executive_summary`, `conclusions` and `lessons_learned` are never written to the .fox; `context` is the
    case's Summary field (exported to the .fox as one line). Multi-line text is allowed in all four."""
    with cases_db() as conn, read_tx(conn):
        out = C.get_report(conn, case_pk)
        out["revision"] = C.get_case_row(conn, case_pk)["revision"]
    return out


@app.patch("/api/cases/{case_pk}/report", tags=["cases"], summary="Update the Report page")
def api_report_update(case_pk: int, body: ReportChangesIn, p: auth.Principal = Depends(access.case_editor)):
    """Recorded in the activity log (`update_report`). With `expected`, a field changed meanwhile by someone
    else returns 409 with the current values."""
    with cases_db() as conn, write_tx(conn):
        return C.update_report(conn, case_pk, body.changes, body.expected, p.actor)


# --------------------------------------------------------------------------- #
# Analysis (read-only)
# --------------------------------------------------------------------------- #

@app.get("/api/cases/{case_pk}/audit", tags=["analysis"], summary="Activity log (newest first)")
def api_audit(case_pk: int, limit: int = Query(200, ge=1, le=1000), before_id: int | None = None,
              p: auth.Principal = Depends(access.case_viewer)):
    with cases_db() as conn:
        C.get_case_row(conn, case_pk)
        return C.audit_log(conn, case_pk, limit, before_id)


@app.get("/api/cases/{case_pk}/search", tags=["analysis"], summary="Full-text search across sections")
def api_search(case_pk: int, q: str = Query(..., min_length=1, max_length=500),
               sections: str | None = Query(None, description="comma-separated section keys"),
               limit: int = Query(50, ge=1, le=500), p: auth.Principal = Depends(access.case_viewer)):
    with cases_db() as conn, read_tx(conn):
        C.get_case_row(conn, case_pk)
        hits = C.search(conn, case_pk, q, [x.strip() for x in sections.split(",")] if sections else None, limit)
    return {"q": q, "count": len(hits), "results": hits}


@app.get("/api/cases/{case_pk}/summary", tags=["analysis"], summary="Incident summary (figures behind the reports)")
def api_summary(case_pk: int, p: auth.Principal = Depends(access.case_viewer)):
    with cases_db() as conn, read_tx(conn):
        return C.incident_summary(conn, case_pk)


REPORT_SECTIONS = ("timeline", "systems", "investigated_systems", "compromised_accounts", "malware",
                   "network_indicators", "exfiltration", "investigators")


@app.get("/api/cases/{case_pk}/report-data", tags=["analysis"], summary="Snapshot used by the reporting views")
def api_report_data(case_pk: int, p: auth.Principal = Depends(access.case_viewer)):
    """Read-only snapshot for the reporting views. Never writes (no audit entry, no export)."""
    with cases_db() as conn, read_tx(conn):
        row = C.get_case_row(conn, case_pk)
        meta = json.loads(row["meta"])
        sections = {s: [r["data"] | {"recid": r["recid"]} for r in C.list_records(conn, case_pk, s)]
                    for s in REPORT_SECTIONS}
    return {"revision": row["revision"], "meta": C.public_meta(meta),
            "lookups": {k: C.lookup_texts(meta, k) for k in ("event_types", "killchain", "system_types")},
            "sections": sections}


# --------------------------------------------------------------------------- #
# Backups and restore (administrators, browser session only)
# --------------------------------------------------------------------------- #

@app.get("/api/backups", include_in_schema=False, summary="List database snapshots and the backup settings")
def api_backups(p: auth.Principal = Depends(auth.require_admin)):
    return {"backups": backups.list_backups(),
            "settings": {"daily": settings.backup_enabled, "time_utc": "%02d:%02d" % settings.backup_time,
                         "keep": settings.backup_keep, "encrypted": settings.backup_encrypt,
                         "audit_retention_weeks": settings.audit_retention_weeks}}


@app.post("/api/backups", include_in_schema=False, summary="Write a database snapshot now")
async def api_backup_now(p: auth.Principal = Depends(auth.require_admin)):
    auth.rate_limit("backup", p.rl_key, settings.backup_rate_per_hour, 3600)
    b = await run_in_threadpool(backups.make_backup, "manual")
    log.info("snapshot %s written on demand by %s", b["name"], p.username)
    return b


@app.get("/api/backups/{name}", include_in_schema=False, summary="Download a snapshot")
def api_backup_get(name: str, p: auth.Principal = Depends(auth.require_admin)):
    try:
        path = backups.backup_path(name)
    except FileNotFoundError:
        raise HTTPException(404, "Backup not found")
    return FileResponse(path, media_type="application/octet-stream", filename=name)


@app.post("/api/backups/restore", include_in_schema=False, summary="Replace the whole database with an uploaded dump")
async def api_restore(request: Request, confirm: str = Query("", description="must be RESTORE"),
                      p: auth.Principal = Depends(auth.require_admin)):
    """Body: an unencrypted dump (.sql or .sql.gz from this application). Encrypted snapshots must be decrypted
    first (`gpg --decrypt`). Every table is dropped and re-created from the file (cases, users, API keys, activity
    log): everybody, including you, must sign in again. A snapshot of the current database is written first."""
    if confirm != "RESTORE":
        raise HTTPException(400, "Add ?confirm=RESTORE to confirm that the whole database will be replaced")
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".restore-", dir=settings.backup_dir)
    size = 0
    try:
        with os.fdopen(fd, "wb") as fh:
            async for chunk in request.stream():
                size += len(chunk)
                fh.write(chunk)
        if not size:
            raise HTTPException(400, "Empty upload")
        await run_in_threadpool(backups.restore, Path(tmp))
    finally:
        Path(tmp).unlink(missing_ok=True)
    log.warning("database restored by %s from an upload of %d bytes", p.username, size)
    resp = JSONResponse({"ok": True, "bytes": size})
    resp.delete_cookie(auth.SESSION_COOKIE, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict")
    return resp


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #

class RecordIn(Strict):
    data: dict[str, Any] = PField(description="field -> value; see /api/schema")


class BulkIn(Strict):
    records: list[dict[str, Any]] = PField(description=f"up to {C.MAX_BULK} objects (field -> value)")


class DeleteIn(Strict):
    version: int | None = None


def _parse_filters(filters: list[str] | None) -> dict:
    out = {}
    for f in filters or []:
        if ":" not in f:
            raise HTTPException(400, "filter must look like field:value")
        k, v = f.split(":", 1)
        out[k] = v
    return out


@app.get("/api/cases/{case_pk}/sections/{section}", tags=["records"], summary="List / filter / page records")
def api_records(case_pk: int, section: str,
                q: str = Query("", max_length=500, description="case-insensitive text search over all fields"),
                filter: list[str] | None = Query(None, description="exact match, repeatable: field:value"),
                sort: str | None = Query(None, description="field name or recid"),
                order: Literal["asc", "desc"] = "asc",
                limit: int | None = Query(None, ge=1, le=10000), offset: int = Query(0, ge=0),
                p: auth.Principal = Depends(access.case_viewer)):
    """Without `sort`, records come in the section's default order (`default_order` in /api/schema, e.g. the
    timeline newest first). `total` is the count before paging."""
    _section(section)
    with cases_db() as conn, read_tx(conn):
        rev = C.get_case_row(conn, case_pk)["revision"]
        total, recs = C.query_records(conn, case_pk, section, q, limit, offset, sort, order, _parse_filters(filter))
    return {"revision": rev, "total": total, "records": recs}


@app.get("/api/cases/{case_pk}/sections/{section}/export.csv", tags=["records"],
         summary="Export a section's records as CSV (RFC 4180, UTF-8)")
def api_section_export_csv(case_pk: int, section: str, p: auth.Principal = Depends(access.case_viewer)):
    _section(section)
    auth.rate_limit("export", p.rl_key, settings.export_rate_per_min, 60)
    with cases_db() as conn, read_tx(conn):
        data = C.export_csv(conn, case_pk, section)
    fname = f"{backups.safe_name(S.SECTIONS[section].label)}.csv"
    return Response(data, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@app.post("/api/cases/{case_pk}/sections/{section}/import.csv", tags=["records"],
          summary="Import records into a section from a validated CSV (all-or-nothing)")
async def api_section_import_csv(case_pk: int, section: str, request: Request, declare_missing: bool = False,
                                 p: auth.Principal = Depends(access.case_editor)):
    """Request body: raw CSV (RFC 4180, UTF-8). The header names the columns (a section's editable fields);
    every cell is validated like the API / .fox import and the whole file is rejected if any value is invalid."""
    _section(section)
    raw = await request.body()
    if not raw:
        raise HTTPException(400, "Empty upload")

    def work():
        with cases_db() as conn, write_tx(conn):
            return C.import_csv(conn, case_pk, section, raw, p.actor, declare_missing=declare_missing)
    recs = await run_in_threadpool(work)
    return {"created": len(recs)}


@app.get("/api/cases/{case_pk}/sections/{section}/{recid}", tags=["records"], summary="Get one record")
def api_record_get(case_pk: int, section: str, recid: int, p: auth.Principal = Depends(access.case_viewer)):
    _section(section)
    with cases_db() as conn:
        return C.get_record(conn, case_pk, section, recid)


@app.post("/api/cases/{case_pk}/sections/{section}", tags=["records"], summary="Create a record")
def api_record_create(case_pk: int, section: str, body: RecordIn, declare_missing: bool = False,
                      p: auth.Principal = Depends(access.case_editor)):
    """`declare_missing=true`: referenced systems / investigators / malware that do not exist yet are
    created (name only) instead of failing with 422."""
    _section(section)
    with cases_db() as conn, write_tx(conn):
        return C.create_record(conn, case_pk, section, body.data, p.actor, declare_missing=declare_missing)


@app.post("/api/cases/{case_pk}/sections/{section}/bulk", tags=["records"], summary="Create many records atomically")
def api_record_bulk(case_pk: int, section: str, body: BulkIn, declare_missing: bool = False,
                    p: auth.Principal = Depends(access.case_editor)):
    """All or nothing: if any record is invalid, nothing is written and the error carries its `index`."""
    _section(section)
    with cases_db() as conn, write_tx(conn):
        recs = C.bulk_create(conn, case_pk, section, body.records, p.actor, declare_missing=declare_missing)
    return {"created": len(recs), "records": recs}


@app.patch("/api/cases/{case_pk}/sections/{section}/{recid}", tags=["records"], summary="Update fields of a record")
def api_record_update(case_pk: int, section: str, recid: int, body: ChangesIn, declare_missing: bool = False,
                      p: auth.Principal = Depends(access.case_editor)):
    """Send `changes` plus either `version` (fails with 409 if anyone changed the record since you read it) or
    `expected` (field-level merge: fails only if someone changed the *same* fields)."""
    _section(section)
    with cases_db() as conn, write_tx(conn):
        return C.update_record(conn, case_pk, section, recid, body.changes, body.expected, p.actor,
                               version=body.version, declare_missing=declare_missing)


@app.delete("/api/cases/{case_pk}/sections/{section}/{recid}", tags=["records"], summary="Delete a record")
def api_record_delete_verb(case_pk: int, section: str, recid: int,
                           version: int | None = Query(None, description="fail with 409 if the record changed"),
                           p: auth.Principal = Depends(access.case_editor)):
    _section(section)
    with cases_db() as conn, write_tx(conn):
        C.delete_record(conn, case_pk, section, recid, version, p.actor)
    return {"ok": True}


@app.post("/api/cases/{case_pk}/sections/{section}/{recid}/delete", tags=["records"],
          summary="Delete a record (POST alias used by the web UI)")
def api_record_delete(case_pk: int, section: str, recid: int, body: DeleteIn,
                      p: auth.Principal = Depends(access.case_editor)):
    _section(section)
    with cases_db() as conn, write_tx(conn):
        C.delete_record(conn, case_pk, section, recid, body.version, p.actor)
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Row actions and integrations (MISP, VirusTotal)
# --------------------------------------------------------------------------- #

class MispAttributeIn(Strict):
    type: str = PField(max_length=40, description="MISP attribute type, e.g. ip-dst, domain, md5")
    value: str = PField(max_length=5000, description="one of the values proposed by GET .../misp-attributes")
    comment: str = PField("", max_length=I.MAX_COMMENT)


class MispSendIn(Strict):
    attributes: list[MispAttributeIn] | None = PField(
        None, max_length=I.MAX_MISP_ATTRIBUTES, description="omit to send every proposed attribute")


@app.get("/api/cases/{case_pk}/integrations", tags=["actions"],
         summary="Which integrations are configured (never returns the API keys)")
def api_integrations(case_pk: int, p: auth.Principal = Depends(access.case_viewer)):
    with cases_db() as conn:
        meta = C.get_meta(conn, case_pk)
    return {**I.status(meta), "misp_types": I.MISP_TYPES}


@app.post("/api/cases/{case_pk}/integrations/misp/test", tags=["actions"],
          summary="Test the MISP connection with the case's server, API key and event")
def api_misp_test(case_pk: int, p: auth.Principal = Depends(access.case_editor)):
    with cases_db() as conn:
        meta = C.get_meta(conn, case_pk)
    return I.misp_test(meta)


@app.post("/api/cases/{case_pk}/integrations/virustotal/test", tags=["actions"],
          summary="Test the VirusTotal API key of the case")
def api_vt_test(case_pk: int, p: auth.Principal = Depends(access.case_editor)):
    with cases_db() as conn:
        meta = C.get_meta(conn, case_pk)
    return I.vt_test(I.vt_key(meta))


# --------------------------------------------------------------------------- #
# Server-wide integration settings (Administration -> Integrations)
# --------------------------------------------------------------------------- #

class ServerIntegrationsIn(Strict):
    misp_url: str | None = PField(None, max_length=2000, description="default MISP server; \"\" removes it")
    misp_apikey: str | None = PField(None, max_length=200, description="write-only; \"\" removes it")
    vt_apikey: str | None = PField(None, max_length=200, description="write-only; \"\" removes it")


@app.get("/api/settings/integrations", include_in_schema=False, summary="Server-wide MISP / VirusTotal defaults")
def api_settings_get(p: auth.Principal = Depends(auth.require_admin)):
    """The API keys are never returned: `secrets_set` only says whether one is stored."""
    with users_db() as conn:
        return SS.public(conn)


@app.patch("/api/settings/integrations", include_in_schema=False, summary="Change the server-wide MISP / VirusTotal defaults")
def api_settings_patch(body: ServerIntegrationsIn, p: auth.Principal = Depends(auth.require_admin)):
    """Cases use these unless they define their own MISP server + key or VirusTotal key, or switch the server
    settings off. The MISP event ID is always set per case. Keys are stored encrypted."""
    changes = {k: v for k, v in body.model_dump().items() if v is not None}
    with users_db() as conn, write_tx(conn):
        return SS.update(conn, changes, p.actor)


@app.post("/api/settings/integrations/misp/test", include_in_schema=False, summary="Test the server-wide MISP URL and key")
def api_settings_misp_test(p: auth.Principal = Depends(auth.require_admin)):
    return I.misp_server_test(SS.load())


@app.post("/api/settings/integrations/virustotal/test", include_in_schema=False, summary="Test the server-wide VirusTotal key")
def api_settings_vt_test(p: auth.Principal = Depends(auth.require_admin)):
    srv = SS.load()
    if not srv["vt_apikey"]:
        raise HTTPException(400, "Set the server-wide VirusTotal API key and save first")
    return I.vt_test(SS.secret(srv, "vt_apikey"))


@app.get("/api/cases/{case_pk}/sections/{section}/{recid}/actions", tags=["actions"],
         summary="Row actions available for a record (and why an action is unavailable)")
def api_record_actions(case_pk: int, section: str, recid: int, p: auth.Principal = Depends(access.case_viewer)):
    _section(section)
    with cases_db() as conn, read_tx(conn):
        meta = C.get_meta(conn, case_pk)
        rec = C.get_record(conn, case_pk, section, recid)
    return {"actions": I.available_actions(section, rec["data"], meta)}


@app.post("/api/cases/{case_pk}/sections/{section}/{recid}/to-timeline", tags=["actions"],
          summary="Add a timeline event from an investigated system, malware or exfiltration record")
def api_to_timeline(case_pk: int, section: str, recid: int, p: auth.Principal = Depends(access.case_editor)):
    """Field mapping as in Aurora: investigated system → first compromise + summary; malware → creation date,
    "Malware created (path)"; exfiltration → exfil time, staging system → destination, type Exfil.
    The new event has *Followup* ticked. Returns the created timeline record."""
    _section(section)
    with cases_db() as conn, write_tx(conn):
        return I.to_timeline(conn, case_pk, section, recid, p.actor)


@app.post("/api/cases/{case_pk}/sections/{section}/{recid}/to-investigated-systems", tags=["actions"],
          summary="Add the host of a malware record to Investigated Systems (Aurora's 'To hosts')")
def api_to_hosts(case_pk: int, section: str, recid: int, p: auth.Principal = Depends(access.case_editor)):
    """Refused (409) if the host is already listed in Investigated Systems."""
    _section(section)
    with cases_db() as conn, write_tx(conn):
        return I.to_investigated_systems(conn, case_pk, section, recid, p.actor)


@app.get("/api/cases/{case_pk}/sections/{section}/{recid}/misp-attributes", tags=["actions"],
         summary="MISP attributes proposed for a malware or network-indicator record")
def api_misp_attributes(case_pk: int, section: str, recid: int, p: auth.Principal = Depends(access.case_viewer)):
    _section(section)
    if section not in I.ACTION_SECTIONS["send_to_misp"]:
        raise HTTPException(400, "Send to MISP is only available for Malware/Tools and Network Indicators")
    with cases_db() as conn, read_tx(conn):
        meta = C.get_meta(conn, case_pk)
        rec = C.get_record(conn, case_pk, section, recid)
    return {"attributes": I.misp_proposals(section, rec["data"]), "misp_types": I.MISP_TYPES,
            "misp": I.status(meta)["misp"]}


@app.post("/api/cases/{case_pk}/sections/{section}/{recid}/send-to-misp", tags=["actions"],
          summary="Send attributes of a record to the case's MISP event")
def api_send_to_misp(case_pk: int, section: str, recid: int, body: MispSendIn,
                     p: auth.Principal = Depends(access.case_editor)):
    """The server calls `POST <MISP server>/attributes/add/<event id>` with the case's MISP API key. Values must
    come from `misp-attributes`; type and comment may be changed. Recorded in the activity log."""
    _section(section)
    attrs = None if body.attributes is None else [a.model_dump() for a in body.attributes]
    return I.send_to_misp(case_pk, section, recid, attrs, p.actor)


@app.post("/api/cases/{case_pk}/sections/{section}/{recid}/check-virustotal", tags=["actions"],
          summary="Look up the hash of a malware record on VirusTotal and store the verdict in 'vt'")
def api_check_vt(case_pk: int, section: str, recid: int, p: auth.Principal = Depends(access.case_editor)):
    """Verdict: `infected` (at least one engine flags it), `clean`, or `noresult` (unknown to VirusTotal).
    Requires a hash in the record and a VirusTotal API key in Case Details."""
    _section(section)
    return I.check_virustotal(case_pk, section, recid, p.actor)


# --------------------------------------------------------------------------- #
# Health, fallbacks
# --------------------------------------------------------------------------- #


@app.get("/healthz", include_in_schema=False)
def healthz():
    with users_db() as conn:
        conn.execute("SELECT 1")
    return {"ok": True}


@app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
def api_404(rest: str):
    raise HTTPException(404, "Not found")


app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
