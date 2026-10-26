"""
Database snapshots (mysqldump), daily and on demand, optionally PGP-encrypted; restore; activity-log pruning.

Files in BACKUP_DIR (DATA_DIR/backups):
    aurora-<UTC timestamp>-<reason>.sql.gz        plain snapshot (gzip-compressed SQL dump)
    aurora-<UTC timestamp>-<reason>.sql.gz.gpg    the same, encrypted to BACKUP_PGP_PUBLIC_KEY

With encryption on, the dump is streamed through gzip into gpg: no unencrypted copy is written to disk.
A restore drops every table of the application database and loads an uploaded, unencrypted dump
(.sql or .sql.gz). Encrypted files must be decrypted by the administrator first (gpg --decrypt).
"""
from __future__ import annotations

import gzip
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import zlib
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .config import settings
from .db import TABLE_NAMES, db, init_db, reset_pool

log = logging.getLogger("aurora.backup")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
NAME_RE = re.compile(r"^aurora-(\d{8}T\d{6}Z)-([a-z-]{1,20})\.sql\.gz(\.gpg)?$")
_local_lock = threading.Lock()
BACKUP_LOCK = "aurora_ir_web_backup"


class BackupError(Exception):
    pass


def safe_name(s: str) -> str:
    s = _SAFE.sub("_", s or "case").strip("._")
    return (s or "case")[:80]


def _bin(*names: str) -> str:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    raise BackupError(f"{' / '.join(names)} not found - install the MariaDB/MySQL client tools")


@contextmanager
def _client_defaults():
    """Credentials for the mysql/mysqldump clients in a private file (never on the command line)."""
    fd, path = tempfile.mkstemp(prefix="aurora-my-", suffix=".cnf")
    try:
        with os.fdopen(fd, "w") as fh:
            esc = settings.db_password.replace("\\", "\\\\").replace('"', '\\"')
            fh.write(f'[client]\nhost="{settings.db_host}"\nport={settings.db_port}\nuser="{settings.db_user}"\n'
                     f'password="{esc}"\ndefault-character-set=utf8mb4\n')
            if settings.db_ssl_ca:
                fh.write(f'ssl-ca="{settings.db_ssl_ca}"\n')
        os.chmod(path, 0o600)
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# PGP
# --------------------------------------------------------------------------- #

@contextmanager
def _gpg_home():
    home = tempfile.mkdtemp(prefix="aurora-gpg-")
    os.chmod(home, 0o700)
    try:
        yield home
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _import_key(home: str) -> str:
    """Import BACKUP_PGP_PUBLIC_KEY into a throw-away keyring; returns the encryption key's fingerprint."""
    key = settings.backup_pgp_public_key.strip()
    if "BEGIN PGP PUBLIC KEY BLOCK" not in key:
        raise BackupError("BACKUP_PGP_PUBLIC_KEY must be an ASCII-armored PGP public key")
    gpg = _bin("gpg")
    r = subprocess.run([gpg, "--batch", "--homedir", home, "--import"], input=key.encode(), capture_output=True)
    if r.returncode != 0:
        raise BackupError("cannot import BACKUP_PGP_PUBLIC_KEY: " + r.stderr.decode(errors="replace")[-300:])
    r = subprocess.run([gpg, "--batch", "--homedir", home, "--with-colons", "--list-keys"], capture_output=True)
    lines = r.stdout.decode().splitlines()
    for i, ln in enumerate(lines):
        f = ln.split(":")
        # primary key line: field 2 = validity (r = revoked, e = expired), field 12 = capabilities of the whole key
        if f[0] == "pub" and len(f) > 11 and "E" in f[11] and f[1] not in ("r", "e"):
            fpr = next((x.split(":")[9] for x in lines[i + 1:] if x.startswith("fpr:")), "")
            if fpr:
                return fpr
    raise BackupError("BACKUP_PGP_PUBLIC_KEY has no valid encryption key (it must be able to encrypt, "
                      "not only sign, and must not be expired or revoked)")


def check_config() -> str | None:
    """Validate the encryption settings at start-up; returns the key fingerprint when encryption is on."""
    if not settings.backup_encrypt:
        return None
    with _gpg_home() as home:
        return _import_key(home)


# --------------------------------------------------------------------------- #
# Snapshots
# --------------------------------------------------------------------------- #

def _dump_cmd(defaults: str) -> list[str]:
    return [_bin("mariadb-dump", "mysqldump"), f"--defaults-extra-file={defaults}", "--single-transaction",
            "--quick", "--no-tablespaces", "--skip-lock-tables", "--hex-blob", "--add-drop-table",
            "--default-character-set=utf8mb4", settings.db_name, *TABLE_NAMES]


def list_backups() -> list[dict]:
    d = settings.backup_dir
    out = []
    for p in d.glob("aurora-*.sql.gz*") if d.exists() else []:
        m = NAME_RE.match(p.name)
        if not m:
            continue
        st = p.stat()
        out.append({"name": p.name, "size": st.st_size, "created": m[1], "reason": m[2],
                    "encrypted": bool(m[3]), "mtime": int(st.st_mtime)})
    return sorted(out, key=lambda b: b["name"], reverse=True)


def backup_path(name: str) -> Path:
    if not NAME_RE.match(name or ""):
        raise FileNotFoundError(name)
    p = settings.backup_dir / name
    if not p.is_file():
        raise FileNotFoundError(name)
    return p


def make_backup(reason: str = "manual") -> dict:
    """Write one snapshot of the whole database. Raises BackupError on failure."""
    if not re.fullmatch(r"[a-z-]{1,20}", reason):
        raise ValueError("bad reason")
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    final = settings.backup_dir / f"aurora-{ts}-{reason}.sql.gz{'.gpg' if settings.backup_encrypt else ''}"
    tmp = final.with_name("." + final.name + ".part")
    with _local_lock, _client_defaults() as defaults, _gpg_home() as home:
        gpg_proc = None
        out_fh = open(tmp, "wb")
        os.chmod(tmp, 0o600)
        try:
            sink = out_fh
            if settings.backup_encrypt:
                fpr = _import_key(home)
                gpg_proc = subprocess.Popen(
                    [_bin("gpg"), "--batch", "--yes", "--homedir", home, "--trust-model", "always",
                     "--recipient", fpr, "--compress-algo", "none", "--encrypt"],
                    stdin=subprocess.PIPE, stdout=out_fh, stderr=subprocess.PIPE)
                sink = gpg_proc.stdin
            dump = subprocess.Popen(_dump_cmd(defaults), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            z = zlib.compressobj(6, zlib.DEFLATED, 31)            # gzip container
            try:
                for chunk in iter(lambda: dump.stdout.read(1 << 16), b""):
                    sink.write(z.compress(chunk))
                sink.write(z.flush())
            except BrokenPipeError:
                dump.kill()
                raise BackupError("gpg encryption failed: " + gpg_proc.stderr.read().decode(errors="replace")[-400:])
            dump_err = dump.stderr.read().decode(errors="replace")
            if dump.wait() != 0:
                raise BackupError("mysqldump failed: " + dump_err[-400:])
            if gpg_proc:
                gpg_proc.stdin.close()
                gpg_err = gpg_proc.stderr.read().decode(errors="replace")
                if gpg_proc.wait() != 0:
                    raise BackupError("gpg encryption failed: " + gpg_err[-400:])
            out_fh.flush()
            os.fsync(out_fh.fileno())
            out_fh.close()
            os.replace(tmp, final)
        except BaseException:
            if gpg_proc and gpg_proc.poll() is None:
                gpg_proc.kill()
            out_fh.close()
            tmp.unlink(missing_ok=True)
            raise
    _prune()
    log.info("database snapshot written: %s (%d bytes)", final.name, final.stat().st_size)
    return next(b for b in list_backups() if b["name"] == final.name)


def _prune() -> None:
    if settings.backup_keep <= 0:
        return
    for b in list_backups()[settings.backup_keep:]:
        (settings.backup_dir / b["name"]).unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# Restore
# --------------------------------------------------------------------------- #

_PGP_ARMOR = b"-----BEGIN PGP MESSAGE"


def inspect_upload(path: Path) -> bool:
    """Checks an uploaded dump; returns True if gzip-compressed. Refuses encrypted or foreign files."""
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head.startswith(_PGP_ARMOR[:4]) or (head and head[0] in (0x84, 0x85, 0x8C, 0xC1, 0xC3)):
        raise BackupError("This file is PGP-encrypted. Decrypt it first (gpg --decrypt), then upload the result.")
    gz = head[:2] == b"\x1f\x8b"
    opener = gzip.open if gz else open
    found_header, tables = False, set()
    try:
        with opener(path, "rb") as fh:
            first = fh.read(4096)
            found_header = b"-- MariaDB dump" in first or b"-- MySQL dump" in first
            rest = first
            while rest:
                for m in re.finditer(rb"CREATE TABLE `([a-z_]+)`", rest):
                    tables.add(m.group(1).decode())
                rest = fh.read(1 << 20)
    except (OSError, EOFError, gzip.BadGzipFile) as e:
        raise BackupError(f"Cannot read the file: {e}")
    if not found_header:
        raise BackupError("Not a mysqldump / mariadb-dump file")
    missing = {"cases", "records", "users"} - tables
    if missing:
        raise BackupError("This dump is not an Aurora IR Web database (missing tables: " + ", ".join(sorted(missing)) + ")")
    return gz


def restore(path: Path) -> None:
    """Replace the whole database with the dump at `path` (a pre-restore snapshot is taken first)."""
    gz = inspect_upload(path)
    try:
        make_backup("pre-restore")
    except Exception as e:
        raise BackupError(f"Safety snapshot before the restore failed, nothing was changed: {e}")
    with _local_lock, db() as conn, _client_defaults() as defaults:
        if conn.execute("SELECT GET_LOCK('aurora_ir_web_write', 60)").fetchone()[0] != 1:
            raise BackupError("The database is busy; try again")
        try:
            conn.execute("SET FOREIGN_KEY_CHECKS=0")
            for t in [r[0] for r in conn.execute("SHOW TABLES").fetchall()]:
                conn.execute(f"DROP TABLE IF EXISTS `{t.replace('`', '``')}`")
            conn.execute("SET FOREIGN_KEY_CHECKS=1")
            cmd = [_bin("mariadb", "mysql"), f"--defaults-extra-file={defaults}", "--binary-mode", settings.db_name]
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with (gzip.open(path, "rb") if gz else open(path, "rb")) as src:
                try:
                    shutil.copyfileobj(src, proc.stdin, 1 << 16)
                finally:
                    proc.stdin.close()
            err = proc.stderr.read().decode(errors="replace")
            if proc.wait() != 0:
                raise BackupError("Loading the dump failed (restore the pre-restore snapshot): " + err[-400:])
        finally:
            conn.execute("SELECT RELEASE_LOCK('aurora_ir_web_write')")
    reset_pool()
    init_db(retries=1)                       # tables missing from an older dump
    with db() as conn:
        conn.execute("DELETE FROM sessions")     # everybody signs in again against the restored accounts
        conn.execute("DELETE FROM login_failures")
    from . import auth
    auth.bootstrap_admin()
    log.warning("database restored from an uploaded dump (%d bytes)", path.stat().st_size)


# --------------------------------------------------------------------------- #
# Activity-log pruning and the daily scheduler
# --------------------------------------------------------------------------- #

def prune_audit() -> int:
    if settings.audit_retention_weeks <= 0:
        return 0
    cutoff = int(time.time()) - settings.audit_retention_weeks * 7 * 86400
    with db() as conn:
        n = conn.execute("DELETE FROM audit WHERE ts < ?", (cutoff,)).rowcount
        conn.execute("DELETE FROM login_failures WHERE ts < ?", (int(time.time()) - 86400,))
    if n:
        log.info("activity log: %d entries older than %d weeks pruned", n, settings.audit_retention_weeks)
    return n


def _daily_due(now: datetime) -> bool:
    h, m = settings.backup_time
    if (now.hour, now.minute) < (h, m):
        return False
    day = now.strftime("%Y%m%d")
    return not any(b["created"].startswith(day) and b["reason"] == "daily" for b in list_backups())


def run_daily_tasks(now: datetime | None = None) -> None:
    """Once per day after BACKUP_TIME_UTC: snapshot + pruning. Only one instance does it (named lock)."""
    now = now or datetime.now(timezone.utc)
    if not (settings.backup_enabled and _daily_due(now)):
        return
    with db() as conn:
        if conn.execute("SELECT GET_LOCK(?, 0)", (BACKUP_LOCK,)).fetchone()[0] != 1:
            return
        try:
            if _daily_due(datetime.now(timezone.utc)):
                prune_audit()
                make_backup("daily")
        except Exception:
            log.exception("daily snapshot failed")
        finally:
            conn.execute("SELECT RELEASE_LOCK(?)", (BACKUP_LOCK,))


def start_scheduler(stop: threading.Event) -> threading.Thread:
    def loop():
        while not stop.wait(60):
            try:
                run_daily_tasks()
                if not settings.backup_enabled:
                    _maybe_prune_only()
            except Exception:
                log.exception("scheduler error")

    t = threading.Thread(target=loop, name="backup", daemon=True)
    t.start()
    return t


_last_prune_day = ""


def _maybe_prune_only() -> None:
    global _last_prune_day
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    if day != _last_prune_day:
        _last_prune_day = day
        prune_audit()

