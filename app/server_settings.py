"""
Server-wide integration settings (Administration -> Integrations): a default MISP server with its API key, and a
default VirusTotal API key. Cases use them unless they define their own (see integrations.py for the rules).
The MISP event ID is never server-wide: it always belongs to the case.

API keys are encrypted at rest (AES-GCM with SECRET_KEY) and write-only: they are never returned to anybody.
"""
import logging
import time
from urllib.parse import urlsplit

from . import schema as S
from . import security
from .config import settings as cfg
from .db import db

log = logging.getLogger("aurora")

FIELDS: dict[str, S.Field] = {f.name: f for f in [
    S.Field("misp_url", "MISP server URL", "url"),
    S.Field("misp_apikey", "MISP API key", "text", max_len=200),
    S.Field("vt_apikey", "VirusTotal API key", "text", max_len=200),
]}
SECRET_FIELDS = {"misp_apikey", "vt_apikey"}


def check_misp_url(url: str) -> str | None:
    """Why a MISP server URL cannot be used, or None."""
    u = urlsplit(url)
    if u.scheme != "https" and not (u.scheme == "http" and cfg.misp_allow_http):
        return "must use https:// (an administrator can allow plain http with MISP_ALLOW_HTTP=true)"
    if not u.hostname:
        return "must contain a host name"
    if u.username or u.password or u.query or u.fragment:
        return "must not contain credentials, a query or a fragment"
    return None


def _rows(conn) -> dict:
    return {r["k"]: r for r in conn.execute("SELECT k, v, updated_at, updated_by FROM settings")}


def load(conn=None) -> dict:
    """Stored values ("" when unset). API keys stay encrypted here; use secret() for an outbound call."""
    if conn is None:
        with db() as c:
            return load(c)
    rows = _rows(conn)
    return {k: (rows[k]["v"] if k in rows else "") for k in FIELDS}


def secret(values: dict, k: str) -> str:
    return security.decrypt(values.get(k) or "")


def public(conn) -> dict:
    rows = _rows(conn)
    last = max(rows.values(), key=lambda r: r["updated_at"], default=None)
    return {"misp_url": rows["misp_url"]["v"] if "misp_url" in rows else "",
            "secrets_set": {k: bool(rows.get(k) and rows[k]["v"]) for k in sorted(SECRET_FIELDS)},
            "updated_at": last["updated_at"] if last else None, "updated_by": last["updated_by"] if last else "",
            "integrations_enabled": cfg.integrations_enabled}


def update(conn, changes: dict, user: str) -> dict:
    """Set or clear ("" removes) any of the fields. Must run inside write_tx."""
    errors, clean = [], {}
    for k, v in changes.items():
        f = FIELDS.get(k)
        if f is None:
            errors.append({"field": k, "message": "unknown field"})
            continue
        try:
            nv = S.validate_value(f, v).strip()
        except S.FieldError as e:
            errors.append({"field": k, "message": str(e)})
            continue
        if k == "misp_url" and nv:
            nv = nv.rstrip("/")
            why = check_misp_url(nv)
            if why:
                errors.append({"field": k, "message": why})
                continue
        clean[k] = security.encrypt(nv) if (k in SECRET_FIELDS and nv) else nv
    if errors:
        raise S.ValidationError(errors)
    now = int(time.time())
    for k, v in clean.items():
        conn.execute("INSERT INTO settings (k, v, updated_at, updated_by) VALUES (?, ?, ?, ?) "
                     "ON DUPLICATE KEY UPDATE v = VALUES(v), updated_at = VALUES(updated_at), "
                     "updated_by = VALUES(updated_by)", (k, v, now, user))
    log.info("server integration settings changed by %s: %s", user,
             ", ".join(f"{k} {'set' if v else 'removed'}" if k in SECRET_FIELDS else f"{k}={v or '(none)'}"
                       for k, v in clean.items()) or "nothing")
    return public(conn)
