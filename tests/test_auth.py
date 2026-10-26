"""Sign-in stages, MFA (TOTP), forced password change, per-user IP allowlists, admin reset from .env, hashing."""
import re
import time

import pytest
from fastapi.testclient import TestClient

from tests.test_app import ADMIN_PW, login
from app import auth
from app import security as SEC
from app.config import settings
from app.db import db
from app.main import app

PW = "a-long-password-123"


@pytest.fixture(scope="module")
def admin():
    with TestClient(app) as c:
        yield login(c)


def new_user(admin, name, **extra):
    body = {"username": name, "password": PW, "role": "user", "must_change_password": False} | extra
    r = admin.post("/api/users", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def start(name, pw=PW, ip=None):
    c = TestClient(app, client=(ip, 50000)) if ip else TestClient(app)
    r = c.post("/api/login", json={"username": name, "password": pw})
    if r.status_code == 200:
        c.headers["X-CSRF-Token"] = r.json()["csrf"]
    return c, r


def enrol(c) -> str:
    setup = c.get("/api/mfa/setup").json()
    assert setup["qr_png"].startswith("data:image/png;base64,") and setup["otpauth_uri"].startswith("otpauth://totp/")
    r = c.post("/api/mfa/setup", json={"code": SEC.totp_now(setup["secret"])})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf"]
    return setup["secret"]


def next_code(secret):
    """A code for the next time step (the current one was just used: replay protection)."""
    return SEC.totp_now(secret, time.time() + SEC.TOTP_PERIOD)


# ------------------------------------------------------------------ hashing and primitives

def test_passwords_argon2id_with_per_user_salt(admin):
    new_user(admin, "hash1")
    new_user(admin, "hash2")
    with db() as conn:
        h1, h2 = [r["pw_hash"] for r in conn.execute(
            "SELECT pw_hash FROM users WHERE username IN ('hash1','hash2') ORDER BY username")]
    assert h1.startswith("$argon2id$v=19$m=65536,t=3,p=4$") and h2.startswith("$argon2id$")
    salt = lambda h: h.split("$")[4]
    assert salt(h1) != salt(h2) and len(salt(h1)) >= 22          # 16-byte random salt per user
    assert h1 != h2 and PW not in h1


def test_totp_rfc6238_vector_and_replay():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"           # RFC 6238 test key "12345678901234567890"
    assert SEC.totp_now(secret, 59) == "287082" and SEC.totp_now(secret, 1111111109) == "081804"
    step = SEC.totp_verify(secret, "081804", 0, at=1111111109)
    assert step == 1111111109 // 30
    assert SEC.totp_verify(secret, "081804", step, at=1111111109) is None              # same code twice: refused


def test_qr_contains_logo_and_image_param():
    uri = SEC.otpauth_uri("JBSWY3DPEHPK3PXP", "alice", "https://air.example.com/logo.png")
    assert uri.startswith("otpauth://totp/Aurora%20IR%20Web:alice?secret=JBSWY3DPEHPK3PXP&issuer=Aurora%20IR%20Web")
    assert uri.endswith("&image=https://air.example.com/logo.png")
    assert "algorithm" not in uri and "digits" not in uri and "period" not in uri      # otpauth defaults: SHA1/6/30
    import qrcode
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H)
    q.add_data(SEC.otpauth_uri("A" * 32, "admin", "https://aurora.dfir.pt/logo.png")); q.make(fit=True)
    assert q.version <= 11                                 # was version 13 (69x69) with the defaults spelled out
    png = SEC.qr_png_with_logo(uri)
    from PIL import Image
    import io
    img = Image.open(io.BytesIO(png)).convert("RGB")
    cx, cy = img.size[0] // 2, img.size[1] // 2
    r, g, b = img.getpixel((cx - img.size[0] // 12, cy - img.size[1] // 12))
    assert (r, g, b) != (255, 255, 255)           # logo drawn in the centre


# ------------------------------------------------------------------ MFA

def test_voluntary_mfa_then_login_needs_code(admin):
    new_user(admin, "mfa1")
    c, r = start("mfa1")
    assert r.json()["stage"] == "full"
    secret = enrol(c)
    c2, r = start("mfa1")
    assert r.json()["stage"] == "mfa"
    assert c2.get("/api/cases").status_code == 401                                   # not signed in yet
    assert c2.post("/api/login/mfa", json={"code": "000000"}).status_code == 401
    r = c2.post("/api/login/mfa", json={"code": next_code(secret)})
    assert r.status_code == 200 and r.json()["stage"] == "full"
    c2.headers["X-CSRF-Token"] = r.json()["csrf"]
    assert c2.get("/api/cases").status_code == 200
    # the code just used cannot be replayed
    c3, _ = start("mfa1")
    assert c3.post("/api/login/mfa", json={"code": next_code(secret)}).status_code == 401


def test_signed_in_session_cannot_replace_authenticator(admin):
    new_user(admin, "mfa7")
    c, _ = start("mfa7")
    enrol(c)
    assert c.get("/api/mfa/setup").status_code == 400
    assert c.post("/api/mfa/setup", json={"code": "123456"}).status_code == 400


def test_admin_resets_mfa(admin):
    u = new_user(admin, "mfa2")
    c, _ = start("mfa2")
    enrol(c)
    assert admin.get("/api/users").json()[[x["username"] for x in admin.get("/api/users").json()].index("mfa2")]["mfa_enabled"]
    r = admin.post(f"/api/users/{u['id']}/reset-mfa")
    assert r.status_code == 200 and r.json()["mfa_enabled"] is False
    assert c.get("/api/cases").status_code == 401                                    # sessions ended
    _, r = start("mfa2")
    assert r.json()["stage"] == "full"


def test_mfa_enforced_forces_setup(admin, monkeypatch):
    new_user(admin, "mfa3")
    monkeypatch.setattr(settings, "mfa_enforced", True)
    c, r = start("mfa3")
    assert r.json()["stage"] == "mfa_setup" and r.json()["mfa_enforced"] is True
    assert c.get("/api/cases").status_code == 401                                    # cannot go on without MFA
    assert c.post("/api/me/mfa/disable", json={"password": PW, "code": "1"}).status_code in (401, 403)
    enrol(c)
    assert c.get("/api/cases").status_code == 200
    # an already open full session of a user without MFA is held at enrolment when enforcement starts
    monkeypatch.setattr(settings, "mfa_enforced", False)
    new_user(admin, "mfa4")
    c4, _ = start("mfa4")
    assert c4.get("/api/cases").status_code == 200
    monkeypatch.setattr(settings, "mfa_enforced", True)
    assert c4.get("/api/cases").status_code == 401
    assert c4.get("/api/session").json()["stage"] == "mfa_setup"


def test_disable_own_mfa_when_not_enforced(admin):
    new_user(admin, "mfa5")
    c, _ = start("mfa5")
    secret = enrol(c)
    assert c.post("/api/me/mfa/disable", json={"password": PW, "code": "123456"}).status_code == 400
    assert c.post("/api/me/mfa/disable", json={"password": PW, "code": next_code(secret)}).status_code == 200
    _, r = start("mfa5")
    assert r.json()["stage"] == "full"


def test_mfa_secret_encrypted_at_rest(admin):
    new_user(admin, "mfa6")
    c, _ = start("mfa6")
    secret = enrol(c)
    with db() as conn:
        stored = conn.execute("SELECT mfa_secret FROM users WHERE username='mfa6'").fetchone()[0]
    assert stored.startswith("v1:") and secret not in stored and SEC.decrypt(stored) == secret


# ------------------------------------------------------------------ forced password change

def test_forced_password_change(admin):
    u = new_user(admin, "pw1", must_change_password=True)
    c, r = start("pw1")
    assert r.json()["stage"] == "password"
    assert c.get("/api/cases").status_code == 401
    assert c.post("/api/login/password", json={"new": "short"}).status_code == 400
    assert c.post("/api/login/password", json={"new": PW}).status_code == 400            # must differ
    r = c.post("/api/login/password", json={"new": "brand-new-password-1"})
    assert r.status_code == 200 and r.json()["stage"] == "full"
    c.headers["X-CSRF-Token"] = r.json()["csrf"]
    assert c.get("/api/cases").status_code == 200
    # admin can force it again later
    admin.patch(f"/api/users/{u['id']}", json={"must_change_password": True})
    _, r = start("pw1", "brand-new-password-1")
    assert r.json()["stage"] == "password"


def test_stage_order_mfa_then_password_then_setup(admin, monkeypatch):
    u = new_user(admin, "pw2")
    c, _ = start("pw2")
    secret = enrol(c)
    admin.patch(f"/api/users/{u['id']}", json={"must_change_password": True})
    c, r = start("pw2")
    assert r.json()["stage"] == "mfa"
    r = c.post("/api/login/mfa", json={"code": next_code(secret)})
    assert r.json()["stage"] == "password"
    r = c.post("/api/login/password", json={"new": "another-password-99"})
    assert r.json()["stage"] == "full"


# ------------------------------------------------------------------ per-user IP allowlists

def test_user_ip_allowlist(admin):
    u = new_user(admin, "ip1", ip_allowlist=["198.51.100.0/24", "2001:db8:1::/48"])
    assert u["ip_allowlist"] == ["198.51.100.0/24", "2001:db8:1::/48"]
    assert start("ip1", ip="198.51.100.20")[1].status_code == 200
    assert start("ip1", ip="2001:db8:1::5")[1].status_code == 200
    assert start("ip1", ip="203.0.113.9")[1].status_code == 401          # same answer as a wrong password
    assert start("ip1", ip="2001:db8:2::5")[1].status_code == 401
    # a session moving to a refused address is ended
    c, _ = start("ip1", ip="198.51.100.20")
    moved = TestClient(app, client=("203.0.113.9", 50000), cookies=c.cookies)
    assert moved.get("/api/cases").status_code == 401
    admin.patch(f"/api/users/{u['id']}", json={"ip_allowlist": []})             # empty = any address
    assert start("ip1", ip="203.0.113.9")[1].status_code == 200
    assert admin.patch(f"/api/users/{u['id']}", json={"ip_allowlist": ["not-an-ip"]}).status_code == 400


def test_admin_cannot_lock_themselves_out(admin):
    me = admin.get("/api/session").json()["user"]
    r = admin.patch(f"/api/users/{me['id']}", json={"ip_allowlist": ["203.0.113.0/24"]})
    assert r.status_code == 400 and "lock yourself out" in r.text
    r = admin.patch(f"/api/users/{me['id']}", json={"ip_allowlist": ["testclient", "203.0.113.0/24"]})
    assert r.status_code == 400


# ------------------------------------------------------------------ bootstrap admin and ADMIN_FORCE_RESET (keep last)

def test_admin_password_only_at_first_deploy_and_force_reset(admin, monkeypatch):
    me = admin.get("/api/session").json()["user"]
    # set MFA and an allowlist on the admin, then "redeploy" with a different ADMIN_PASSWORD but no reset flag
    c, _ = start("admin", ADMIN_PW)
    secret = enrol(c)
    with db() as conn:
        conn.execute("UPDATE users SET ip_allowlist='[\"198.51.100.1\"]' WHERE id=?", (me["id"],))
    monkeypatch.setattr(settings, "admin_password", "a-different-env-password")
    auth.bootstrap_admin()
    _, r = start("admin", "a-different-env-password", ip="198.51.100.1")
    assert r.status_code == 401                                        # .env password not applied again
    # now with ADMIN_FORCE_RESET: MFA, allowlist removed and password set from .env
    monkeypatch.setattr(settings, "admin_force_reset", True)
    auth.bootstrap_admin()
    c, r = start("admin", "a-different-env-password", ip="203.0.113.50")
    assert r.status_code == 200 and r.json()["stage"] == "full"
    u = r.json()["user"]
    assert u["mfa_enabled"] is False and u["ip_allowlist"] == [] and secret
    # restore the original admin password for later test modules
    monkeypatch.setattr(settings, "admin_password", ADMIN_PW)
    auth.bootstrap_admin()
    monkeypatch.setattr(settings, "admin_force_reset", False)
    assert start("admin", ADMIN_PW)[1].status_code == 200


def test_auth_events_are_logged(caplog):
    """Security logging (A09): sign-in success, failure and lockout are logged; the password never is."""
    import logging
    from app.main import app
    with TestClient(app) as admin_c:                    # fresh admin (this test is appended after the reset test)
        admin = login(admin_c)
        new_user(admin, "logme")
        ip = "198.51.100.77"                            # unique IP: isolate this test's throttle counters
        with db() as conn:
            conn.execute("DELETE FROM login_failures WHERE k IN (?, ?)", ("u:logme", "ip:" + ip))
        with caplog.at_level(logging.INFO, logger="aurora"):
            assert start("logme", PW, ip=ip)[1].status_code == 200
            for _ in range(7):                          # fail enough to trip the per-username lockout
                start("logme", "the-wrong-password-9", ip=ip)
        t = caplog.text
        assert "sign-in:" in t and "logme" in t                     # success event logged, with username + role
        assert "failed sign-in" in t                                # failure event logged
        assert "throttled" in t                                     # lockout event logged
        assert PW not in t and "the-wrong-password-9" not in t      # password NEVER logged
