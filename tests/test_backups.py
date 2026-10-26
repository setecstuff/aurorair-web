"""Database snapshots (mysqldump), PGP encryption, restore, activity-log pruning, daily schedule."""
import gzip
import json
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.test_app import ADMIN_PW, FIXTURE, login
from app import backups as B
from app.config import settings
from app.db import db
from app.main import app

pytestmark = pytest.mark.skipif(not (shutil.which("mariadb-dump") or shutil.which("mysqldump"))
                                or not shutil.which("gpg"), reason="needs mysqldump/mariadb-dump and gpg")


@pytest.fixture(scope="module")
def admin():
    with TestClient(app) as c:
        yield login(c)


@pytest.fixture(scope="module")
def gpg_key():
    """A throw-away key pair: (armored public key, GNUPGHOME holding the private key)."""
    home = tempfile.mkdtemp(prefix="aurora-test-gpg-")
    subprocess.run(["gpg", "--batch", "--homedir", home, "--passphrase", "", "--quick-gen-key",
                    "backup-test@example.org", "default", "default", "never"], check=True, capture_output=True)
    pub = subprocess.run(["gpg", "--batch", "--homedir", home, "--armor", "--export", "backup-test@example.org"],
                         check=True, capture_output=True).stdout.decode()
    yield pub, home
    shutil.rmtree(home, ignore_errors=True)


def test_snapshot_on_demand_list_download(admin):
    r = admin.post("/api/backups")
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["reason"] == "manual" and b["encrypted"] is False and b["name"].endswith(".sql.gz")
    listing = admin.get("/api/backups").json()
    assert listing["settings"]["encrypted"] is False and any(x["name"] == b["name"] for x in listing["backups"])
    raw = admin.get(f"/api/backups/{b['name']}").content
    sql = gzip.decompress(raw)
    assert (b"-- MariaDB dump" in sql[:200] or b"-- MySQL dump" in sql[:200]) and b"CREATE TABLE `cases`" in sql
    assert b"CREATE TABLE `users`" in sql and b"CREATE DATABASE" not in sql
    for bad in ("../users.db", "aurora-x.sql.gz", "x"):
        assert admin.get(f"/api/backups/{bad}").status_code == 404


def test_encrypted_snapshot(admin, gpg_key, monkeypatch):
    pub, home = gpg_key
    monkeypatch.setattr(settings, "backup_encrypt", True)
    monkeypatch.setattr(settings, "backup_pgp_public_key", pub)
    assert B.check_config()                                         # fingerprint
    b = admin.post("/api/backups").json()
    assert b["encrypted"] and b["name"].endswith(".sql.gz.gpg")
    raw = admin.get(f"/api/backups/{b['name']}").content
    assert raw[:2] != b"\x1f\x8b" and b"CREATE TABLE" not in raw     # not readable without the key
    plain = subprocess.run(["gpg", "--batch", "--homedir", home, "--decrypt"], input=raw, check=True,
                           capture_output=True).stdout
    assert b"CREATE TABLE `cases`" in gzip.decompress(plain)
    leftovers = [p.name for p in settings.backup_dir.iterdir() if not p.name.startswith("aurora-")]
    assert not [n for n in leftovers if n.endswith(".part")]        # no plaintext left behind


def test_bad_pgp_key_is_refused(monkeypatch):
    monkeypatch.setattr(settings, "backup_encrypt", True)
    monkeypatch.setattr(settings, "backup_pgp_public_key", "not a key")
    with pytest.raises(B.BackupError):
        B.check_config()
    home = tempfile.mkdtemp(prefix="aurora-test-gpg-")                  # a sign-only key cannot encrypt
    subprocess.run(["gpg", "--batch", "--homedir", home, "--passphrase", "", "--quick-gen-key",
                    "sign-only@example.org", "rsa2048", "sign", "never"], check=True, capture_output=True)
    pub = subprocess.run(["gpg", "--batch", "--homedir", home, "--armor", "--export"], check=True,
                         capture_output=True).stdout.decode()
    shutil.rmtree(home, ignore_errors=True)
    monkeypatch.setattr(settings, "backup_pgp_public_key", pub)
    with pytest.raises(B.BackupError, match="no valid encryption key"):
        B.check_config()


def test_restore_round_trip(admin, gpg_key):
    fx = json.loads(json.dumps(FIXTURE))
    fx["case_id"] = "RESTORE-ME"
    pk = admin.post("/api/cases/import", content=json.dumps(fx)).json()["id"]
    admin.patch(f"/api/cases/{pk}/report", json={"changes": {"conclusions": "kept by the restore"}})
    snap = admin.post("/api/backups").json()["name"]
    plain = admin.get(f"/api/backups/{snap}").content
    assert admin.post(f"/api/cases/{pk}/delete", json={"confirm": "RESTORE-ME"}).status_code == 200
    assert admin.get(f"/api/cases/{pk}").status_code == 404
    # guards: confirmation, encrypted files, foreign files
    assert admin.post("/api/backups/restore", content=plain).status_code == 400
    pub, home = gpg_key
    enc = subprocess.run(["gpg", "--batch", "--homedir", home, "--trust-model", "always", "--recipient",
                          "backup-test@example.org", "--encrypt"], input=plain, check=True, capture_output=True).stdout
    r = admin.post("/api/backups/restore?confirm=RESTORE", content=enc)
    assert r.status_code == 400 and "Decrypt it first" in r.text
    r = admin.post("/api/backups/restore?confirm=RESTORE", content=b"-- MariaDB dump\nDROP TABLE x;")
    assert r.status_code == 400 and "not an Aurora IR Web database" in r.text
    assert admin.get(f"/api/cases/{pk}").status_code == 404                     # nothing changed by refusals
    # the real thing (plain .sql.gz as downloaded)
    r = admin.post("/api/backups/restore?confirm=RESTORE", content=plain)
    assert r.status_code == 200, r.text
    assert admin.get("/api/cases").status_code == 401                            # everyone signs in again
    again = login(TestClient(app), "admin", ADMIN_PW)
    assert again.get(f"/api/cases/{pk}").json()["meta"]["case_id"] == "RESTORE-ME"
    assert again.get(f"/api/cases/{pk}/report").json()["conclusions"] == "kept by the restore"
    assert any(b["reason"] == "pre-restore" for b in again.get("/api/backups").json()["backups"])
    # an uncompressed .sql works too
    r = again.post("/api/backups/restore?confirm=RESTORE", content=gzip.decompress(plain))
    assert r.status_code == 200, r.text


def test_audit_pruning(monkeypatch):
    with db() as conn:
        pk = conn.execute("SELECT id FROM cases ORDER BY id LIMIT 1").fetchone()[0]
        old = int(time.time()) - 10 * 7 * 86400
        conn.execute("INSERT INTO audit (case_pk, ts, username, action) VALUES (?,?,?,?)", (pk, old, "x", "old"))
        conn.execute("INSERT INTO audit (case_pk, ts, username, action) VALUES (?,?,?,?)",
                     (pk, int(time.time()), "x", "recent"))
    monkeypatch.setattr(settings, "audit_retention_weeks", 0)
    assert B.prune_audit() == 0                                                  # 0 = keep forever
    monkeypatch.setattr(settings, "audit_retention_weeks", 8)
    assert B.prune_audit() >= 1
    with db() as conn:
        actions = {r[0] for r in conn.execute("SELECT action FROM audit WHERE username='x'")}
    assert actions == {"recent"}


def test_daily_schedule_once_per_day(monkeypatch):
    monkeypatch.setattr(settings, "backup_enabled", True)
    monkeypatch.setattr(settings, "backup_time", (2, 0))
    day = datetime.now(timezone.utc).replace(hour=1, minute=59)
    B.run_daily_tasks(day)                                                       # before the time: nothing
    assert not [b for b in B.list_backups() if b["reason"] == "daily"]
    B.run_daily_tasks(datetime.now(timezone.utc).replace(hour=23, minute=59))
    B.run_daily_tasks(datetime.now(timezone.utc).replace(hour=23, minute=59))
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    assert len([b for b in B.list_backups() if b["reason"] == "daily" and b["created"].startswith(today)]) == 1


def test_retention_keeps_newest(monkeypatch):
    monkeypatch.setattr(settings, "backup_keep", 2)
    for _ in range(3):
        B.make_backup("manual")
        time.sleep(1.05)
    assert len(B.list_backups()) == 2


def test_startup_schema_check_never_drops(admin):
    """init_db creates only missing tables; existing tables and their data are left alone."""
    from app.db import TABLE_NAMES, init_db
    with db() as conn:
        before = conn.execute("SELECT count(*) FROM cases").fetchone()[0]
    assert init_db(retries=1) == []                                   # complete schema: nothing executed
    with db() as conn:
        conn.execute("DROP TABLE login_failures")
    assert init_db(retries=1) == ["login_failures"]                   # only the missing one
    with db() as conn:
        assert conn.execute("SELECT count(*) FROM cases").fetchone()[0] == before
        tables = {r[0] for r in conn.execute("SHOW TABLES").fetchall()}
    assert set(TABLE_NAMES) <= tables
