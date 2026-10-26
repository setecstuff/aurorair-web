"""
Test environment. The tests need a MariaDB/MySQL server and a database they may wipe:

    TEST_DB_HOST=127.0.0.1 TEST_DB_PORT=3306 TEST_DB_USER=aurora TEST_DB_PASSWORD=... TEST_DB_NAME=aurora_test \\
        pytest -q tests

Every table of TEST_DB_NAME is dropped at the start of the run. Backup/restore tests also need the
mariadb-dump / mysqldump and mariadb / mysql client tools and gpg on PATH.
"""
import os
import tempfile

os.environ["DB_HOST"] = os.environ.get("TEST_DB_HOST", "127.0.0.1")
os.environ["DB_PORT"] = os.environ.get("TEST_DB_PORT", "3306")
os.environ["DB_USER"] = os.environ.get("TEST_DB_USER", "aurora")
os.environ["DB_PASSWORD"] = os.environ.get("TEST_DB_PASSWORD", "aurora-test-pw")
os.environ["DB_NAME"] = os.environ.get("TEST_DB_NAME", "aurora_test")
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="aurora-test-")
os.environ["SECRET_KEY"] = "test-secret-key-0123456789abcdefghijklmnop"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "correct-horse-battery"
os.environ["COOKIE_SECURE"] = "false"
os.environ["BACKUP_ENABLED"] = "false"
os.environ.setdefault("EXPORT_RATE_PER_MIN", "0")   # disable rate limits in tests; the dedicated test enables them
os.environ.setdefault("BACKUP_RATE_PER_HOUR", "0")
os.environ.pop("MFA_ENFORCED", None)
os.environ.pop("ADMIN_FORCE_RESET", None)

import pymysql  # noqa: E402


def _wipe():
    conn = pymysql.connect(host=os.environ["DB_HOST"], port=int(os.environ["DB_PORT"]), user=os.environ["DB_USER"],
                           password=os.environ["DB_PASSWORD"], database=os.environ["DB_NAME"], autocommit=True)
    with conn.cursor() as cur:
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        cur.execute("SHOW TABLES")
        for (t,) in cur.fetchall():
            cur.execute(f"DROP TABLE `{t}`")
        cur.execute("SET FOREIGN_KEY_CHECKS=1")
    conn.close()


_wipe()
